#!/usr/bin/env bash
# TRR9027 — behavioral emulation for T1565.001 (Stored Data Manipulation), Kubernetes
# cluster DNS poisoning via the CoreDNS ConfigMap.
#
# Each procedure writes a cluster DNS ConfigMap in kube-system, so the API server writes
# the configmaps audit event the paired Sigma rules key on. The poison carries the
# sentinel token 'trr9027' (a forward to a sentinel .invalid zone that no workload
# resolves) so a validator matches the emulation's own events.
#
# SAFETY:
#   * Procedure A captures the real coredns Corefile, appends an INERT sentinel server
#     block (forward of trr9027poison.example.invalid. to a TEST-NET IP), and RESTORES
#     the original Corefile at once. Real resolution is never changed.
#   * Procedures B and C write ConfigMaps a CoreDNS kind cluster does not read
#     (kube-dns, coredns-custom), so they are inert, and are deleted on cleanup.
#
# Run ONE procedure:
#   ./emulate.sh a      repoint the coredns Corefile (sentinel forward), then restore
#   ./emulate.sh b      create a kube-dns ConfigMap with a stubDomains redirect (inert)
#   ./emulate.sh c      create a coredns-custom ConfigMap with a forward snippet (inert)
#   ./emulate.sh gap    node-local etcd/disk bypass demonstration (read-only)
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights on kube-system
# ConfigMaps, audit logging at Request level for kube-system ConfigMaps (see
# detections/k8s/audit-policy-apiserver.yaml), and python3 (to build the merge patch).
set -euo pipefail

NS="kube-system"
NODE="${TRR9027_NODE:-apiserver-control-plane}"
SENTINEL_IP="198.51.100.53"   # RFC 5737 TEST-NET-2, non-routable
# An inert sentinel zone block: a rewrite (exercises the grader's plugin clause) and a
# forward to a TEST-NET IP (exercises the forward-to-IP clause). It answers only the
# sentinel .invalid zone, so real resolution is unaffected.
SENTINEL_BLOCK=$'\ntrr9027poison.example.invalid:53 {\n    errors\n    rewrite name trr9027poison.example.invalid sink.trr9027.example.invalid\n    forward . '"$SENTINEL_IP"$'\n}\n'

log() { printf '[trr9027] %s\n' "$*" >&2; }

# Build a strategic/merge patch body {"data":{"Corefile": <stdin>}} with correct JSON
# escaping of the multi-line Corefile.
_corefile_patch() { python3 -c 'import json,sys; print(json.dumps({"data":{"Corefile": sys.stdin.read()}}))'; }

cleanup() {
  log "cleanup: deleting trr9027 inert ConfigMaps (coredns is restored in procedure a)"
  kubectl -n "$NS" delete configmap kube-dns --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete configmap coredns-custom --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A — repoint the coredns Corefile, then restore it. The poison appends an
# inert sentinel zone; resolution for every real name is unchanged, and the original
# Corefile is put back immediately. The restore is armed on a signal BEFORE the poison
# is applied (so an interrupt between the two patches cannot leave the sentinel in
# place) and verified afterward.
procedure_a() {
  local orig
  orig="$(kubectl -n "$NS" get configmap coredns -o jsonpath='{.data.Corefile}' 2>/dev/null || true)"
  if [ -z "$orig" ]; then
    log "A: coredns ConfigMap has no Corefile (not a CoreDNS cluster?) — skipping"
    return 0
  fi
  _restore_coredns() {
    kubectl -n "$NS" patch configmap coredns --type=merge \
      -p "$(printf '%s' "$orig" | _corefile_patch)" >/dev/null 2>&1 || true
  }
  trap '_restore_coredns' INT TERM
  log "A: patch coredns Corefile with a sentinel rewrite + forward (trr9027poison.example.invalid -> ${SENTINEL_IP})"
  kubectl -n "$NS" patch configmap coredns --type=merge \
    -p "$(printf '%s' "${orig}${SENTINEL_BLOCK}" | _corefile_patch)" >/dev/null 2>&1 || true
  log "A: restore the original coredns Corefile"
  _restore_coredns
  trap - INT TERM
  if kubectl -n "$NS" get configmap coredns -o jsonpath='{.data.Corefile}' 2>/dev/null | grep -q 'trr9027'; then
    log "::error:: coredns Corefile still carries the trr9027 sentinel after restore — restoring again"
    _restore_coredns
  fi
}

# Procedure B — legacy kube-dns ConfigMap with a stubDomains redirect (JSON). Inert on a
# CoreDNS cluster; created only to emit the chokepoint audit event.
procedure_b() {
  log "B: create kube-dns ConfigMap with a stubDomains redirect (inert)"
  kubectl -n "$NS" create configmap kube-dns \
    --from-literal=stubDomains='{"trr9027.poison.example.invalid":["'"$SENTINEL_IP"'"]}' \
    >/dev/null 2>&1 || true
}

# Procedure C — coredns-custom import ConfigMap with a forward snippet. Inert unless the
# base Corefile imports it (a kind Corefile does not); created only for the chokepoint.
procedure_c() {
  log "C: create coredns-custom ConfigMap with a forward snippet (inert)"
  kubectl -n "$NS" create configmap coredns-custom \
    --from-literal=trr9027.server='trr9027poison.example.invalid:53 { forward . '"$SENTINEL_IP"' }' \
    >/dev/null 2>&1 || true
}

# Gap — the node-local bypass. An adversary with control-plane node access can edit
# CoreDNS's mounted config on disk or in etcd with NO API write and NO audit event.
# Read-only demonstration.
procedure_gap() {
  if [ -n "${TRR9027_NODE_EXEC:-}" ]; then
    log "gap: show the etcd data path on the node (custom exec, read-only)"
    $TRR9027_NODE_EXEC 'ls -ld /var/lib/etcd 2>/dev/null || true' || true
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "gap: show the etcd data path on node $NODE (read-only)"
    docker exec "$NODE" sh -c 'ls -ld /var/lib/etcd 2>/dev/null || true' || true
  else
    log "gap: no node access (docker/TRR9027_NODE_EXEC) — skipping the node-bypass demonstration"
    return 0
  fi
  log "gap: a direct etcd/disk edit of the Corefile emits NO configmaps audit event -> node/etcd sensor only"
}

run_one() {
  case "$1" in
    a) procedure_a ;;
    b) procedure_b ;;
    c) procedure_c ;;
    gap) procedure_gap ;;
    *) log "unknown item: $1 (use a|b|c|gap|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c gap; do run_one "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
