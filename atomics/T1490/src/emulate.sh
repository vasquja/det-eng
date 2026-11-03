#!/usr/bin/env bash
# TRR9029 - behavioral emulation for T1490 (Inhibit System Recovery), Kubernetes.
#
# An actor with delete rights destroys a cluster's recovery means through the API
# server, so the API server writes the delete/create audit events the paired Sigma rule
# (detections/sigma/T1490/k8s_snapshot_or_backup_destroyed.yml) keys on. Everything
# happens in a throwaway namespace trr9029 with uniquely named trr9029- objects, so a
# validator matches the emulation's own events.
#
# SAFE BY DESIGN. The objects are inert and this runs on a throwaway kind cluster (or a
# local API-server lab), never a production cluster:
#   * the snapshot CRs reference a non-existent PVC and a fake snapshot handle, and the
#     VolumeSnapshotContent sets deletionPolicy Retain, so even a running
#     snapshot-controller would delete no physical storage;
#   * the Velero Schedule, BackupStorageLocation and DeleteBackupRequest live in the
#     trr9029 namespace, which no real Velero server watches (Velero watches its own
#     namespace), so no backup or snapshot is ever deleted;
#   * the atomic installs the snapshot and Velero CustomResourceDefinitions (vendored in
#     src/crds/) only when they are absent, and on cleanup removes ONLY the CRDs it
#     installed and ONLY its own trr9029- objects, so it never disturbs a real install.
#
# Run ONE procedure:
#   ./emulate.sh a       delete a VolumeSnapshot (snapshot.storage.k8s.io)
#   ./emulate.sh b       delete a VolumeSnapshotContent (cluster-scoped)
#   ./emulate.sh c       delete a Velero Schedule (stop future backups)
#   ./emulate.sh d       delete a Velero BackupStorageLocation (orphan the bucket)
#   ./emulate.sh e       create a Velero DeleteBackupRequest (the backup-deletion path)
#   ./emulate.sh dryrun  server-side dry runs (?dryRun=All) that must NOT fire the rule
#   ./emulate.sh all     every item, in order, then clean up
#
# Prerequisites: a reachable throwaway cluster (kubectl works) and audit logging (see
# detections/k8s/kind-apiserver-cluster.yaml). The CRDs are applied from src/crds/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRD_DIR="$SCRIPT_DIR/crds"
NS="${TRR9029_NAMESPACE:-trr9029}"
NS_DRY="trr9029-dryrun-ns"   # the dry-run control's own namespace (cleanup deletes it)
SNAP_GROUP="snapshot.storage.k8s.io"
VELERO_GROUP="velero.io"

log() { printf '[trr9029] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping ---------------------------------------
# `must CMD` runs an action and returns its exit code (stderr shown on failure).
# `run_proc P` times procedure_P, appends one ledger line to $DETENG_LEDGER (set by CI;
# unset = no ledger) and records a failure without stopping the run, so `all` attempts
# every procedure and then exits 1 naming the failures.
TRR="TRR9029"
FAILED=()
INSTALLED_CRDS=()
now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }
must() {
  local out rc=0
  out="$("$@" 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    log "FAILED (exit $rc): $*"
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
  return "$rc"
}
run_proc() {
  local p="$1" start end rc=0
  start="$(now_utc)"
  "procedure_$p" || rc=$?
  end="$(now_utc)"
  if [ -n "${DETENG_LEDGER:-}" ]; then
    printf '{"trr":"%s","procedure":"%s","start":"%s","end":"%s","exit":%d,"expect":0}\n' \
      "$TRR" "$p" "$start" "$end" "$rc" >> "$DETENG_LEDGER"
  fi
  if [ "$rc" -ne 0 ]; then
    FAILED+=("$p")
    [ -n "${GITHUB_ACTIONS:-}" ] && \
      echo "::error title=${TRR} procedure ${p}::procedure ${p} failed (exit ${rc})"
  fi
  return 0
}

# Install the vendored CRDs, but only the ones that are absent, so a real snapshot or
# Velero install is left untouched (and never removed by cleanup).
ensure_crds() {
  local f name
  for f in "$CRD_DIR"/*.yaml; do
    # The CRD's own metadata.name (the first "  name:" after the top-level "metadata:",
    # before "spec:"): parsed from the vendored file, not from the API server.
    name="$(awk '/^metadata:/{m=1;next} m&&/^  name:/{print $2;exit} /^spec:/{exit}' "$f")"
    if [ -z "$name" ]; then
      log "ensure_crds: cannot read the CRD name from $f"; return 1
    fi
    if kubectl get crd "$name" >/dev/null 2>&1; then
      log "CRD $name already present - leaving it in place"
    else
      must kubectl create -f "$f" || return 1
      INSTALLED_CRDS+=("$name")
    fi
  done
  # Wait for the CRDs the atomic installed to be served.
  for name in "${INSTALLED_CRDS[@]:-}"; do
    [ -n "$name" ] && must kubectl wait --for=condition=Established "crd/$name" --timeout=60s || true
  done
}

ensure_ns() { kubectl get namespace "$NS" >/dev/null 2>&1 || must kubectl create namespace "$NS"; }

# Inert snapshot CRs (Retain, fake handle, non-existent PVC) in namespace $1 with the
# name stem $2 (trr9029 or trr9029-dryrun).
make_snapshot_objects() {
  local ns="$1" stem="$2"
  must kubectl apply -f - <<EOF
apiVersion: ${SNAP_GROUP}/v1
kind: VolumeSnapshot
metadata: {name: ${stem}-vs, namespace: ${ns}}
spec:
  source: {persistentVolumeClaimName: ${stem}-data}
---
apiVersion: ${SNAP_GROUP}/v1
kind: VolumeSnapshotContent
metadata: {name: ${stem}-vsc}
spec:
  deletionPolicy: Retain
  driver: trr9029.example.com
  source: {snapshotHandle: ${stem}-inert-handle}
  volumeSnapshotRef: {name: ${stem}-vs, namespace: ${ns}}
EOF
}

# Inert Velero Schedule and BackupStorageLocation in namespace $1 with name stem $2.
make_velero_objects() {
  local ns="$1" stem="$2"
  must kubectl apply -f - <<EOF
apiVersion: ${VELERO_GROUP}/v1
kind: Schedule
metadata: {name: ${stem}-schedule, namespace: ${ns}}
spec:
  schedule: "0 7 * * *"
  template: {}
---
apiVersion: ${VELERO_GROUP}/v1
kind: BackupStorageLocation
metadata: {name: ${stem}-bsl, namespace: ${ns}}
spec:
  provider: aws
  objectStorage: {bucket: ${stem}-bucket}
EOF
}

# Procedure A - delete a VolumeSnapshot (the restore point of a PVC).
procedure_a() {
  ensure_crds || return; ensure_ns || return
  make_snapshot_objects "$NS" trr9029 || return
  log "A: delete VolumeSnapshot trr9029-vs (an accepted delete)"
  must kubectl -n "$NS" delete volumesnapshot.${SNAP_GROUP} trr9029-vs
}

# Procedure B - delete a VolumeSnapshotContent (cluster-scoped binding to the physical
# snapshot). trr9029-vsc has deletionPolicy Retain, so no storage is removed.
procedure_b() {
  ensure_crds || return; ensure_ns || return
  make_snapshot_objects "$NS" trr9029 || return
  log "B: delete VolumeSnapshotContent trr9029-vsc (cluster-scoped, an accepted delete)"
  must kubectl delete volumesnapshotcontent.${SNAP_GROUP} trr9029-vsc
}

# Procedure C - delete a Velero Schedule (stops future scheduled backups).
procedure_c() {
  ensure_crds || return; ensure_ns || return
  make_velero_objects "$NS" trr9029 || return
  log "C: delete Velero Schedule trr9029-schedule (an accepted delete)"
  must kubectl -n "$NS" delete schedule.${VELERO_GROUP} trr9029-schedule
}

# Procedure D - delete a Velero BackupStorageLocation (orphans the backup bucket).
procedure_d() {
  ensure_crds || return; ensure_ns || return
  make_velero_objects "$NS" trr9029 || return
  log "D: delete Velero BackupStorageLocation trr9029-bsl (an accepted delete)"
  must kubectl -n "$NS" delete backupstoragelocation.${VELERO_GROUP} trr9029-bsl
}

# Procedure E - create a Velero DeleteBackupRequest, the real backup-deletion path
# (`velero backup delete` creates one with generateName '<backup>-'). Its own controller
# would delete the object-store backup and its snapshots; in this throwaway namespace no
# Velero server watches it, so nothing is deleted. The create is the actor's record.
procedure_e() {
  ensure_crds || return; ensure_ns || return
  log "E: create DeleteBackupRequest (generateName trr9029-dbr-) in $NS"
  must kubectl -n "$NS" create -f - <<EOF
apiVersion: ${VELERO_GROUP}/v1
kind: DeleteBackupRequest
metadata: {generateName: trr9029-dbr-, namespace: ${NS}}
spec: {backupName: trr9029-backup}
EOF
}

# Dry run - a control, not a procedure: server-side dry runs persist nothing, so the
# rule must NOT fire on them (the validator's MISS_MANIFEST). These CRDs log at the
# Metadata catch-all, so the dry run is never in a request body; it must be in the query
# (?dryRun=All). For the four deletes the step sends kubectl delete --raw of the object
# URL with ?dryRun=All and no body (what kubernetes-client/python and kubectl delete
# --raw send). For the create the step sends kubectl create --dry-run=server, which puts
# CreateOptions dryRun=All in the query. Every object name starts with trr9029-dryrun-,
# and so does the namespace; no positive gate selects such a record.
procedure_dryrun() {
  ensure_crds || return
  local phase
  phase="$(kubectl get namespace "$NS_DRY" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" = "Terminating" ]; then
    log "dryrun: namespace $NS_DRY is terminating; wait for it to go"
    kubectl wait --for=delete "namespace/$NS_DRY" --timeout=120s >/dev/null 2>&1 || true
  fi
  kubectl get namespace "$NS_DRY" >/dev/null 2>&1 || must kubectl create namespace "$NS_DRY" || return
  make_snapshot_objects "$NS_DRY" trr9029-dryrun || return
  make_velero_objects "$NS_DRY" trr9029-dryrun || return
  log "dryrun: ?dryRun=All deletes of the VolumeSnapshot, VolumeSnapshotContent, Schedule and BackupStorageLocation"
  must kubectl delete --raw "/apis/${SNAP_GROUP}/v1/namespaces/${NS_DRY}/volumesnapshots/trr9029-dryrun-vs?dryRun=All" || return
  must kubectl delete --raw "/apis/${SNAP_GROUP}/v1/volumesnapshotcontents/trr9029-dryrun-vsc?dryRun=All" || return
  must kubectl delete --raw "/apis/${VELERO_GROUP}/v1/namespaces/${NS_DRY}/schedules/trr9029-dryrun-schedule?dryRun=All" || return
  must kubectl delete --raw "/apis/${VELERO_GROUP}/v1/namespaces/${NS_DRY}/backupstoragelocations/trr9029-dryrun-bsl?dryRun=All" || return
  log "dryrun: --dry-run=server create of a DeleteBackupRequest (CreateOptions dryRun=All in the query)"
  must kubectl -n "$NS_DRY" create --dry-run=server -f - <<EOF || return
apiVersion: ${VELERO_GROUP}/v1
kind: DeleteBackupRequest
metadata: {generateName: trr9029-dryrun-dbr-, namespace: ${NS_DRY}}
spec: {backupName: trr9029-backup}
EOF
  # A server-side dry run persists nothing: every deleted object must still be there.
  must kubectl -n "$NS_DRY" get volumesnapshot.${SNAP_GROUP} trr9029-dryrun-vs || return
  must kubectl get volumesnapshotcontent.${SNAP_GROUP} trr9029-dryrun-vsc || return
  must kubectl -n "$NS_DRY" get schedule.${VELERO_GROUP} trr9029-dryrun-schedule || return
  must kubectl -n "$NS_DRY" get backupstoragelocation.${VELERO_GROUP} trr9029-dryrun-bsl || return
}

cleanup() {
  log "cleanup: deleting namespaces $NS and $NS_DRY (cascades the namespaced CRs)"
  kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete namespace "$NS_DRY" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  # Cluster-scoped VolumeSnapshotContents the atomic made (by name; never a wildcard).
  kubectl delete volumesnapshotcontent.${SNAP_GROUP} trr9029-vsc trr9029-dryrun-vsc \
    --ignore-not-found >/dev/null 2>&1 || true
  # Remove ONLY the CRDs this run installed (a pre-existing real install is left alone).
  local name
  for name in "${INSTALLED_CRDS[@]:-}"; do
    [ -n "$name" ] && kubectl delete crd "$name" --ignore-not-found >/dev/null 2>&1 || true
  done
}

run_one() {
  case "$1" in
    a|b|c|d|e|dryrun) run_proc "$1" ;;
    *) log "unknown item: $1 (use a|b|c|d|e|dryrun|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d e dryrun; do run_proc "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  if [ "${#FAILED[@]}" -gt 0 ]; then
    log "emulation FAILED: procedure(s) ${FAILED[*]}"
    exit 1
  fi
  log "emulation complete: $which"
}

main "$@"
