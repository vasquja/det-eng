#!/usr/bin/env bash
# TRR9010 — behavioral emulation for T1070 (Indicator Removal), Kubernetes.
#
# Each procedure destroys evidence through the API server, so the API server writes
# the delete/deletecollection audit events the paired Sigma rules key on. Everything
# happens in a throwaway namespace trr9010 with uniquely named objects, so a
# validator matches the emulation's own events. The deleted Events and the deleted
# pod are ones the emulation itself created; the bulk deletecollection is on the
# throwaway namespace only.
#
# Note: a delete request is audited even when the object does not exist (the request
# is recorded with its objectRef.name and a 404), so the chokepoint telemetry exists
# whether or not the create succeeded first.
#
# Run ONE procedure:
#   ./emulate.sh a      delete a single Event (core group)
#   ./emulate.sh b      bulk-wipe Events with deletecollection
#   ./emulate.sh c      delete an Event via the events.k8s.io group
#   ./emulate.sh d      delete a Pod (destroy the running-workload record)
#   ./emulate.sh gap    node-local audit-log clearing demonstration (read-only)
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) and audit logging (see
# detections/k8s/kind-apiserver-cluster.yaml). The gap test needs node access
# (docker exec on kind); set TRR9010_NODE for a non-kind lab.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${TRR9010_NAMESPACE:-trr9010}"
NODE="${TRR9010_NODE:-apiserver-control-plane}"
PROXY_PORT="${TRR9010_PROXY_PORT:-8911}"

log() { printf '[trr9010] %s\n' "$*" >&2; }

ensure_ns() { kubectl get namespace "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS" >/dev/null 2>&1 || true; }
cleanup() {
  log "cleanup: deleting namespace $NS (cascades events and pods)"
  kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A — delete a single core v1 Event.
procedure_a() {
  ensure_ns
  kubectl apply -f "$SCRIPT_DIR/k8s-event-core.yaml" >/dev/null 2>&1 || true
  log "A: delete core Event trr9010-evt-a (the delete is audited regardless)"
  kubectl -n "$NS" delete event trr9010-evt-a >/dev/null 2>&1 || true
}

# Procedure B — bulk-wipe Events with a collection DELETE. Uses kubectl proxy + a
# raw DELETE on the events collection, which is recorded as verb=deletecollection
# regardless of how many events match (version-independent).
procedure_b() {
  ensure_ns
  log "B: deletecollection on Events in $NS (bulk cover-up)"
  kubectl proxy --port="$PROXY_PORT" >/dev/null 2>&1 &
  local proxy_pid=$!
  sleep 2
  curl -s -X DELETE "http://127.0.0.1:${PROXY_PORT}/api/v1/namespaces/${NS}/events" >/dev/null 2>&1 || true
  kill "$proxy_pid" >/dev/null 2>&1 || true
}

# Procedure C — delete an Event via the events.k8s.io group.
procedure_c() {
  ensure_ns
  kubectl apply -f "$SCRIPT_DIR/k8s-event-eventsk8s.yaml" >/dev/null 2>&1 || true
  log "C: delete events.k8s.io Event trr9010-evt-c"
  kubectl -n "$NS" delete events.events.k8s.io trr9010-evt-c >/dev/null 2>&1 || true
}

# Procedure D — delete a Pod to destroy the running-workload record.
procedure_d() {
  ensure_ns
  log "D: create then delete pod trr9010-workload (evidence removal)"
  kubectl -n "$NS" run trr9010-workload --image=busybox:1.36 --restart=Never \
    --command -- sleep 3600 >/dev/null 2>&1 || true
  sleep 2
  kubectl -n "$NS" delete pod trr9010-workload --force --grace-period=0 >/dev/null 2>&1 || true
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
    a) procedure_a ;;
    b) procedure_b ;;
    c) procedure_c ;;
    d) procedure_d ;;
    gap) procedure_gap ;;
    *) log "unknown item: $1 (use a|b|c|d|gap|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d gap; do run_one "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
