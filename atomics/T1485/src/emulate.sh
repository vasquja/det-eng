#!/usr/bin/env bash
# TRR9028 — behavioral emulation for T1485 (Data Destruction), Kubernetes.
#
# Each procedure destroys application storage through the API server, so the API
# server writes the delete / deletecollection / patch audit events the paired Sigma
# rules key on. Everything happens in a throwaway namespace trr9028 with uniquely
# named objects (trr9028-*), so a validator matches the emulation's own events. The
# objects are INERT: a PersistentVolume is a no-provisioner, Retain hostPath reference
# to a scratch path the emulation makes under /tmp on the node; nothing writes real
# data to it, and no dynamic provisioner backs it, so deleting a PVC or PV destroys no
# real volume. Each procedure creates what it deletes, and the create must succeed (a
# 404 delete of an object whose create failed proves nothing), as in TRR9010.
#
# Run ONE procedure:
#   ./emulate.sh a      delete a bound PersistentVolumeClaim (releases its PV)
#   ./emulate.sh b      delete a PersistentVolume
#   ./emulate.sh c      bulk-wipe a namespace's PVCs with deletecollection
#   ./emulate.sh d      flip a PV's reclaim policy Retain -> Delete (the destructive step)
#   ./emulate.sh dryrun server-side dry-run deletes that must NOT fire the rules (control)
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) and audit logging (see
# detections/k8s/kind-apiserver-cluster.yaml). SAFETY: no procedure deletes a PV or PVC
# that the emulation did not create, and the PVs are inert hostPath references with
# reclaim policy Retain, so no backing volume and no real data is destroyed.
set -euo pipefail

NS="${TRR9028_NAMESPACE:-trr9028}"
NS_DRY="trr9028-dryrun-ns"   # the dry-run control's own namespace (cleanup deletes it)
SC="trr9028-manual"          # a storageClassName with no provisioner, so binding is static

log() { printf '[trr9028] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs a procedure's action and returns its exit code (stderr shown on
# failure; the command string is logged, so never put a credential on a command line).
# `run_proc P` times procedure_P, appends one ledger line to $DETENG_LEDGER (set by CI;
# unset = no ledger) and records a failure without stopping the run, so `all` attempts
# every procedure and then exits 1 naming the failures. Cleanup keeps `|| true`.
TRR="TRR9028"
FAILED=()
# UTC time to the microsecond, from bash (EPOCHREALTIME, bash 5) and not from `date +%6N`:
# date of uutils coreutils 0.10.0 drops the leading zeros of %6N. An older bash uses date %N.
now_utc() {
  local t="${EPOCHREALTIME:-}"
  if [ -n "$t" ]; then TZ=UTC0 printf '%(%Y-%m-%dT%H:%M:%S)T.%sZ\n' "${t%[.,]*}" "${t#*[.,]}"
  else t="$(date -u +%Y-%m-%dT%H:%M:%S.%N)"; printf '%sZ\n' "${t:0:26}"; fi
}
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

ensure_ns() { kubectl get namespace "$NS" >/dev/null 2>&1 || must kubectl create namespace "$NS"; }

# An inert, no-provisioner PV: a hostPath reference (the directory is not written to),
# storageClassName trr9028-manual (no provisioner, so no dynamic backing), reclaim
# policy as given ($2). $1 is the PV name. A PVC binds to it by volumeName (make_pvc).
make_pv() {
  local name="$1" reclaim="$2"
  kubectl create -f - <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ${name}
spec:
  capacity:
    storage: 1Mi
  accessModes: ["ReadWriteOnce"]
  persistentVolumeReclaimPolicy: ${reclaim}
  storageClassName: ${SC}
  hostPath:
    path: /tmp/trr9028-inert-${name}
    type: DirectoryOrCreate
EOF
}

make_pvc() {
  local name="$1" ns="$2" volume="${3:-}"
  local vol_block=""
  [ -n "$volume" ] && vol_block="  volumeName: ${volume}"
  kubectl create -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${name}
  namespace: ${ns}
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: ${SC}
  resources:
    requests:
      storage: 1Mi
${vol_block}
EOF
}

cleanup() {
  log "cleanup: deleting namespace $NS (cascades PVCs) and the trr9028 PVs"
  kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete namespace "$NS_DRY" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  # Cluster-scoped PVs are not in any namespace; delete the emulation's own by name.
  for pv in trr9028-pv-a trr9028-pv-b trr9028-pv-d trr9028-dryrun-pv; do
    kubectl delete pv "$pv" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
}

# Procedure A — delete a bound PersistentVolumeClaim. The PVC binds to a Retain PV the
# emulation created, so the actor's delete releases the PV and destroys no real data,
# but the audit record (verb delete, resource persistentvolumeclaims, name
# trr9028-pvc-a) is the chokepoint. The create of both must succeed, and the PVC must
# bind, so the delete is of a real bound claim.
procedure_a() {
  ensure_ns || return
  must make_pv trr9028-pv-a Retain || return
  must make_pvc trr9028-pvc-a "$NS" trr9028-pv-a || return
  # Wait for the claim to bind to the pre-created PV (static binding by the PV binder).
  must kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Bound \
    pvc/trr9028-pvc-a --timeout=60s || return
  log "A: delete bound PVC trr9028-pvc-a (releases its PV; Retain keeps the volume)"
  must kubectl -n "$NS" delete persistentvolumeclaim trr9028-pvc-a
}

# Procedure B — delete a PersistentVolume directly.
procedure_b() {
  log "B: create then delete PV trr9028-pv-b (an accepted PV delete)"
  must make_pv trr9028-pv-b Retain || return
  must kubectl delete persistentvolume trr9028-pv-b
}

# Procedure C — bulk-wipe a namespace's PVCs with a collection DELETE. kubectl delete
# pvc --all lists and deletes each by name (verb delete); to send a real
# deletecollection the step sends a DELETE to the collection URL with kubectl delete
# --raw (kubectl rawhttp, v1.36.4), recorded as verb deletecollection whatever the
# count. The step first creates two PVCs (each create must succeed), then wipes them,
# then checks both are gone.
procedure_c() {
  local left ref
  ensure_ns || return
  must make_pvc trr9028-pvc-c1 "$NS" "" || return
  must make_pvc trr9028-pvc-c2 "$NS" "" || return
  log "C: deletecollection of PersistentVolumeClaims in $NS (bulk destruction)"
  must kubectl delete --raw "/api/v1/namespaces/${NS}/persistentvolumeclaims" || return
  # A PVC gets the kubernetes.io/pvc-protection finalizer synchronously on create
  # (StorageObjectInUseProtection admission, default-on in kube-apiserver:
  # pkg/kubeapiserver/options/plugins.go defaultOnPlugins), so a deletecollection only
  # sets deletionTimestamp; the pvc-protection controller removes the finalizer
  # asynchronously after a live pod List (pvcprotection/pvc_protection_controller.go
  # processPVC). `kubectl delete --raw` returns before that, so wait for the objects to
  # actually go rather than checking at once (an immediate get is a race under runner
  # load). `--for=delete` ignores a not-found (already-gone) object (wait.go RunWait
  # IgnoreErrors(IsNotFound)), so it is safe whether removal is slow or instant.
  must kubectl -n "$NS" wait --for=delete \
    pvc/trr9028-pvc-c1 pvc/trr9028-pvc-c2 --timeout=120s || return
  # Belt and braces: after the wait both PVCs must be gone.
  for ref in persistentvolumeclaim/trr9028-pvc-c1 persistentvolumeclaim/trr9028-pvc-c2; do
    if ! left="$(kubectl -n "$NS" get "$ref" --ignore-not-found -o name)"; then
      log "C: cannot check that ${ref} is gone (kubectl get failed)"; return 1
    fi
    if [ -n "$left" ]; then log "C: ${ref} is still there after the wipe"; return 1; fi
  done
}

# Procedure D — the destructive step: flip a PV's reclaim policy from Retain to Delete,
# so a later release destroys the backing volume. A strategic-merge patch; the audit
# record (verb patch, requestObject.spec.persistentVolumeReclaimPolicy Delete) is what
# the grader keys on. The PV is inert (no provisioner), so nothing is destroyed here.
procedure_d() {
  log "D: create PV trr9028-pv-d (Retain), then patch its reclaim policy to Delete"
  must make_pv trr9028-pv-d Retain || return
  must kubectl patch persistentvolume trr9028-pv-d \
    -p '{"spec":{"persistentVolumeReclaimPolicy":"Delete"}}' || return
  # Confirm the flip took effect (the grader reads the request body, but the check
  # proves the patch was accepted and applied, not refused).
  local got
  got="$(kubectl get persistentvolume trr9028-pv-d \
    -o jsonpath='{.spec.persistentVolumeReclaimPolicy}' 2>&1)" || {
      log "D: cannot read trr9028-pv-d reclaim policy: ${got}"; return 1; }
  [ "$got" = "Delete" ] || { log "D: reclaim policy is '${got}', not Delete"; return 1; }
}

# Dry run — a control, not a procedure: server-side dry-run requests that persist
# nothing, so the rules must NOT fire on them (the validator's MISS_MANIFEST). The step
# creates its own namespace trr9028-dryrun-ns with two PVCs and a cluster-scoped PV
# trr9028-dryrun-pv, then sends kubectl delete --dry-run=server for the PVC and the PV
# (dryRun ["All"] in the DeleteOptions body; the lab policy logs these deletes at
# Request), a deletecollection of the PVCs with kubectl delete --raw and the same
# DeleteOptions body, and a kubectl patch --dry-run=server that would flip the PV's
# reclaim policy to Delete (for a PATCH the dryRun flag is a query parameter, ?dryRun=All,
# not a body field, so the grader must filter it by the query, not the body). Then it
# checks every object is still there and the PV's reclaim policy is unchanged. Every name
# begins with trr9028-dryrun-, and so does the namespace; no positive gate selects such a
# record.
procedure_dryrun() {
  local phase left reclaim
  phase="$(kubectl get namespace "$NS_DRY" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" = "Terminating" ]; then
    log "dryrun: namespace $NS_DRY is terminating; wait for it to go"
    kubectl wait --for=delete "namespace/$NS_DRY" --timeout=120s >/dev/null 2>&1 || true
  fi
  log "dryrun: create namespace $NS_DRY with two PVCs and a PV trr9028-dryrun-pv"
  kubectl get namespace "$NS_DRY" >/dev/null 2>&1 || must kubectl create namespace "$NS_DRY" || return
  phase="$(kubectl get namespace "$NS_DRY" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" != "Active" ]; then
    log "dryrun: namespace $NS_DRY is not active (phase '${phase:-absent}')"; return 1
  fi
  must make_pvc trr9028-dryrun-pvc1 "$NS_DRY" "" || return
  must make_pvc trr9028-dryrun-pvc2 "$NS_DRY" "" || return
  must make_pv trr9028-dryrun-pv Retain || return
  log "dryrun: kubectl delete --dry-run=server of a PVC and the PV, then a deletecollection"
  must kubectl -n "$NS_DRY" delete persistentvolumeclaim trr9028-dryrun-pvc1 --dry-run=server || return
  must kubectl delete persistentvolume trr9028-dryrun-pv --dry-run=server || return
  must kubectl delete --raw "/api/v1/namespaces/${NS_DRY}/persistentvolumeclaims" -f - <<'EOF' || return
{"kind":"DeleteOptions","apiVersion":"v1","dryRun":["All"]}
EOF
  log "dryrun: kubectl patch pv --dry-run=server flipping reclaim to Delete (the grader must not fire)"
  must kubectl patch persistentvolume trr9028-dryrun-pv \
    -p '{"spec":{"persistentVolumeReclaimPolicy":"Delete"}}' --dry-run=server || return
  # A server-side dry run persists nothing: every object must still be there.
  for ref in persistentvolumeclaim/trr9028-dryrun-pvc1 persistentvolumeclaim/trr9028-dryrun-pvc2; do
    if ! left="$(kubectl -n "$NS_DRY" get "$ref" --ignore-not-found -o name)"; then
      log "dryrun: cannot check that ${ref} is still there (kubectl get failed)"; return 1
    fi
    if [ -z "$left" ]; then log "dryrun: ${ref} is gone after the dry run"; return 1; fi
  done
  if ! left="$(kubectl get persistentvolume trr9028-dryrun-pv --ignore-not-found -o name)"; then
    log "dryrun: cannot check PV trr9028-dryrun-pv (kubectl get failed)"; return 1
  fi
  [ -n "$left" ] || { log "dryrun: PV trr9028-dryrun-pv is gone after the dry run"; return 1; }
  # The dry-run reclaim patch persisted nothing: the PV's policy must still be Retain.
  reclaim="$(kubectl get persistentvolume trr9028-dryrun-pv \
    -o jsonpath='{.spec.persistentVolumeReclaimPolicy}' 2>&1)" || {
      log "dryrun: cannot read trr9028-dryrun-pv reclaim policy: ${reclaim}"; return 1; }
  [ "$reclaim" = "Retain" ] || {
    log "dryrun: reclaim policy is '${reclaim}', not Retain after the dry-run patch"; return 1; }
}

run_one() {
  case "$1" in
    a|b|c|d|dryrun) run_proc "$1" ;;
    *) log "unknown item: $1 (use a|b|c|d|dryrun|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d dryrun; do run_proc "$p"; done
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
