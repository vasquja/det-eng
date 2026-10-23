#!/usr/bin/env bash
# TRR9010 — behavioral emulation for T1070 (Indicator Removal), Kubernetes.
#
# Each procedure destroys evidence through the API server, so the API server writes
# the delete/deletecollection audit events the paired Sigma rules key on. Everything
# happens in a throwaway namespace trr9010 with uniquely named objects, so a
# validator matches the emulation's own events. The deleted Events and the deleted
# pod are ones the emulation itself created; the bulk deletecollection is on the
# throwaway namespace only. Procedure F deletes a whole namespace, so it uses its own
# throwaway namespace trr9010-ns-f, never trr9010 or any other; the dry-run control
# uses its own namespace trr9010-dryrun-ns.
#
# Note: a delete request is audited even when the object does not exist (a 404), but a
# 404 delete proves nothing about the procedure, so the validator needs each delete to
# be accepted (200). Each procedure therefore creates the object it deletes, and the
# create must succeed: a failed create fails the procedure. Each Event names an
# involvedObject in the Event's own namespace, which the API server's Event validation
# requires outside the default namespace.
#
# Run ONE procedure:
#   ./emulate.sh a      delete a single Event (core group)
#   ./emulate.sh b      bulk-wipe Events with deletecollection
#   ./emulate.sh c      delete an Event via the events.k8s.io group
#   ./emulate.sh d      delete a Pod (destroy the running-workload record)
#   ./emulate.sh f      delete a whole namespace (trr9010-ns-f) with an Event in it
#   ./emulate.sh dryrun server-side dry-run deletes and deletecollections that must NOT
#                       fire the rules (control)
#   ./emulate.sh gap    node-local audit-log clearing demonstration (read-only)
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) and audit logging (see
# detections/k8s/kind-apiserver-cluster.yaml). The gap test needs node access
# (docker exec on kind); set TRR9010_NODE for a non-kind lab.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${TRR9010_NAMESPACE:-trr9010}"
NS_F="trr9010-ns-f"   # Procedure F's own throwaway namespace, deleted whole
NS_DRY="trr9010-dryrun-ns"   # the dry-run control's own namespace (cleanup deletes it)
NODE="${TRR9010_NODE:-apiserver-control-plane}"
PROXY_PORT="${TRR9010_PROXY_PORT:-8911}"

log() { printf '[trr9010] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs a procedure's action and returns its exit code (stderr shown on
# failure). `run_proc P` times procedure_P, appends one ledger line to $DETENG_LEDGER
# (set by CI; unset = no ledger) and records a failure without stopping the run, so
# `all` attempts every procedure and then exits 1 naming the failures. Cleanup and the
# read-only gap print keep `|| true`.
TRR="TRR9010"
FAILED=()
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

ensure_ns() { kubectl get namespace "$NS" >/dev/null 2>&1 || must kubectl create namespace "$NS"; }
cleanup() {
  log "cleanup: deleting namespace $NS (cascades events and pods)"
  kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete namespace "$NS_F" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete namespace "$NS_DRY" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

# Procedure A — delete a single core v1 Event.
procedure_a() {
  ensure_ns || return
  must kubectl apply -f "$SCRIPT_DIR/k8s-event-core.yaml" || return
  log "A: create, then delete core Event trr9010-evt-a (an accepted delete)"
  must kubectl -n "$NS" delete event trr9010-evt-a
}

# Procedure B — bulk-wipe Events with a collection DELETE. Uses kubectl proxy + a
# raw DELETE on the events collection, which is recorded as verb=deletecollection
# regardless of how many events match (version-independent).
procedure_b() {
  ensure_ns || return
  log "B: deletecollection on Events in $NS (bulk cover-up)"
  kubectl proxy --port="$PROXY_PORT" >/dev/null 2>&1 &
  local proxy_pid=$! rc=0
  sleep 2
  # -fsS: curl fails on an HTTP error, so a refused or unreachable deletecollection
  # fails the step instead of being swallowed (the audited verb is deletecollection).
  must curl -fsS -X DELETE "http://127.0.0.1:${PROXY_PORT}/api/v1/namespaces/${NS}/events" || rc=$?
  kill "$proxy_pid" >/dev/null 2>&1 || true
  return "$rc"
}

# Procedure C — delete an Event via the events.k8s.io group.
procedure_c() {
  ensure_ns || return
  must kubectl apply -f "$SCRIPT_DIR/k8s-event-eventsk8s.yaml" || return
  log "C: create, then delete events.k8s.io Event trr9010-evt-c (an accepted delete)"
  must kubectl -n "$NS" delete events.events.k8s.io trr9010-evt-c
}

# Procedure D — delete a Pod to destroy the running-workload record.
procedure_d() {
  ensure_ns || return
  log "D: create then delete pod trr9010-workload (evidence removal)"
  must kubectl -n "$NS" run trr9010-workload --image=busybox:1.36 --restart=Never \
    --command -- sleep 3600 || return
  sleep 2
  must kubectl -n "$NS" delete pod trr9010-workload --force --grace-period=0
}

# Procedure F — delete a whole namespace to destroy its Events. The emulation creates
# its own throwaway namespace trr9010-ns-f and one Event in it (the create must succeed,
# so the namespace really holds an Event), then deletes the namespace. The actor's
# record is the namespace delete (verb delete, resource namespaces, 200); the namespace
# controller then deletes the Events with a deletecollection that the Events rule
# filters as teardown.
procedure_f() {
  log "F: create namespace $NS_F with an Event, then delete the whole namespace"
  kubectl get namespace "$NS_F" >/dev/null 2>&1 || must kubectl create namespace "$NS_F" || return
  must kubectl create -f - <<EOF || return
apiVersion: v1
kind: Event
metadata:
  name: trr9010-evt-f
  namespace: ${NS_F}
involvedObject:
  apiVersion: v1
  kind: ConfigMap
  name: trr9010-anchor
  namespace: ${NS_F}
reason: Trr9010Benign
message: benign TRR9010 namespace-delete emulation
type: Normal
source:
  component: trr9010-emulation
firstTimestamp: "2026-10-16T00:00:00Z"
lastTimestamp: "2026-10-16T00:00:00Z"
count: 1
EOF
  must kubectl delete namespace "$NS_F" --ignore-not-found --wait=false
}

# Dry run — a control, not a procedure: server-side dry-run deletes that persist
# nothing, so the rules must NOT fire on them (the validator's MISS_MANIFEST). The step
# creates its own namespace trr9010-dryrun-ns with an Event, a pod and a suspended Job
# (no pod runs), then sends kubectl delete --dry-run=server for the Event (core group,
# then the same Event through events.k8s.io), the pod, the Job and the namespace.
# kubectl sends the dry run in the DeleteOptions body (dryRun ["All"]; cli-runtime
# resource.Helper DeleteWithOptions, v1.36.4) and does not wait for a dry-run delete;
# the lab policy logs these deletes at Request, so the body is in the record. kubectl
# delete never sends a deletecollection, so the step sends one for the Events and one
# for the pods of its namespace with kubectl delete --raw of the collection URL and the
# same DeleteOptions body (-f sends the file as the body; kubectl rawhttp, v1.36.4).
# Then the step checks that every object is still there, so a dry run that deleted
# something fails the step. Every name starts with trr9010-dryrun-, and so does the
# namespace; no positive gate selects such a record. The requests that delete them are
# sent from cleanup, after this step's ledger window.
procedure_dryrun() {
  local phase deleting
  # Cleanup deletes the namespace without a wait. While it is Terminating, the API
  # server refuses every create in it (NamespaceLifecycle admission), so a run soon
  # after an earlier cleanup waits for it to go.
  phase="$(kubectl get namespace "$NS_DRY" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" = "Terminating" ]; then
    log "dryrun: namespace $NS_DRY is terminating; wait for it to go"
    kubectl wait --for=delete "namespace/$NS_DRY" --timeout=120s >/dev/null 2>&1 || true
  fi
  log "dryrun: create namespace $NS_DRY with an Event, a pod and a suspended Job"
  kubectl get namespace "$NS_DRY" >/dev/null 2>&1 || must kubectl create namespace "$NS_DRY" || return
  phase="$(kubectl get namespace "$NS_DRY" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" != "Active" ]; then
    log "dryrun: namespace $NS_DRY is not active (phase '${phase:-absent}'); the dry runs cannot run"
    return 1
  fi
  must kubectl create -f - <<EOF || return
apiVersion: v1
kind: Event
metadata:
  name: trr9010-dryrun-evt
  namespace: ${NS_DRY}
involvedObject:
  apiVersion: v1
  kind: ConfigMap
  name: trr9010-anchor
  namespace: ${NS_DRY}
reason: Trr9010Benign
message: benign TRR9010 dry-run control
type: Normal
source:
  component: trr9010-emulation
firstTimestamp: "2026-10-23T00:00:00Z"
lastTimestamp: "2026-10-23T00:00:00Z"
count: 1
EOF
  # A pod create in a new namespace is refused until the service account controller has
  # made its default service account; wait for it (kubectl 1.31+). The pod has a
  # termination grace period of 0 (an override merged into the generated pod): its
  # sleep is PID 1 and ignores SIGTERM, so with the default 30 s a real delete (the
  # cleanup's namespace teardown) would keep the namespace Terminating for at least
  # 30 s, while the next atomics run. With 0, the API server removes the pod at once.
  must kubectl -n "$NS_DRY" wait --for=create serviceaccount/default --timeout=60s || return
  must kubectl -n "$NS_DRY" run trr9010-dryrun-pod --image=busybox:1.36 --restart=Never \
    --overrides='{"apiVersion":"v1","spec":{"terminationGracePeriodSeconds":0}}' \
    --command -- sleep 3600 || return
  must kubectl create -f - <<EOF || return
apiVersion: batch/v1
kind: Job
metadata:
  name: trr9010-dryrun-job
  namespace: ${NS_DRY}
spec:
  suspend: true
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: noop
          image: busybox:1.36
          command: ["true"]
EOF
  log "dryrun: kubectl delete --dry-run=server of the Event (core, events.k8s.io), the pod, the Job and $NS_DRY"
  must kubectl -n "$NS_DRY" delete event trr9010-dryrun-evt --dry-run=server || return
  must kubectl -n "$NS_DRY" delete events.events.k8s.io trr9010-dryrun-evt --dry-run=server || return
  must kubectl -n "$NS_DRY" delete pod trr9010-dryrun-pod --dry-run=server || return
  must kubectl -n "$NS_DRY" delete job trr9010-dryrun-job --dry-run=server || return
  must kubectl delete namespace "$NS_DRY" --dry-run=server || return
  log "dryrun: deletecollection of the Events, then of the pods, of $NS_DRY (DeleteOptions body dryRun [All])"
  must kubectl delete --raw "/api/v1/namespaces/${NS_DRY}/events" -f - <<'EOF' || return
{"kind":"DeleteOptions","apiVersion":"v1","dryRun":["All"]}
EOF
  must kubectl delete --raw "/api/v1/namespaces/${NS_DRY}/pods" -f - <<'EOF' || return
{"kind":"DeleteOptions","apiVersion":"v1","dryRun":["All"]}
EOF
  # A server-side dry run persists nothing: every object must still be there. A real
  # delete of this pod (grace period 0) removes it at once; a delete with a grace
  # period would leave it Terminating, so the pod must also have no deletionTimestamp.
  must kubectl -n "$NS_DRY" get event trr9010-dryrun-evt || return
  must kubectl -n "$NS_DRY" get job trr9010-dryrun-job || return
  if ! deleting="$(kubectl -n "$NS_DRY" get pod trr9010-dryrun-pod \
      -o jsonpath='{.metadata.deletionTimestamp}' 2>&1)"; then
    log "dryrun: pod trr9010-dryrun-pod is gone after the dry run: ${deleting}"
    return 1
  fi
  if [ -n "$deleting" ]; then
    log "dryrun: pod trr9010-dryrun-pod is being deleted (deletionTimestamp ${deleting})"
    return 1
  fi
  phase="$(kubectl get namespace "$NS_DRY" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" != "Active" ]; then
    log "dryrun: namespace $NS_DRY is '${phase:-absent}' after the dry run, not Active"
    return 1
  fi
}

# Gap — the node-local bypass. Clearing or truncating the API server audit log file
# on the node, or disabling the audit sink, destroys evidence with NO API call, so
# the audit layer is blind. Read-only demonstration.
procedure_gap() {
  if [ -n "${TRR9010_NODE_EXEC:-}" ]; then
    log "gap: show the audit log path on the node (custom exec, read-only)"
    $TRR9010_NODE_EXEC 'ls -l /var/log/kubernetes/kube-apiserver-audit.log 2>/dev/null || true' || true
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "gap: show the audit log path on node $NODE (read-only)"
    docker exec "$NODE" sh -c 'ls -l /var/log/kubernetes/kube-apiserver-audit.log 2>/dev/null || true' || true
  else
    log "gap: no node access (docker/TRR9010_NODE_EXEC) — skipping the audit-clearing demonstration"
    return 0
  fi
  log "gap: truncating that file on the node emits NO API audit event -> node file sensor only"
}

run_one() {
  case "$1" in
    a|b|c|d|f|dryrun|gap) run_proc "$1" ;;
    *) log "unknown item: $1 (use a|b|c|d|f|dryrun|gap|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d f dryrun gap; do run_proc "$p"; done
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
