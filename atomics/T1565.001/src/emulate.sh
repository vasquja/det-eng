#!/usr/bin/env bash
# TRR9027 — behavioral emulation for T1565.001 (Stored Data Manipulation), Kubernetes
# cluster DNS poisoning via the CoreDNS ConfigMap.
#
# Each procedure writes a cluster DNS ConfigMap in kube-system, so the API server writes
# the configmaps audit event the paired Sigma rules key on. Every write carries the
# sentinel token 'trr9027' (a forward to a sentinel .invalid zone that no workload
# resolves). Every write is a PATCH by name: procedure A patches coredns, and B and C
# create kube-dns and coredns-custom with server-side apply (kubectl apply
# --server-side), which is a PATCH to the named object even when it does not exist yet.
# The audit policy logs a named write to these three ConfigMaps at Request, so each
# write reaches the log with its body and its sentinel, and the validator proves A, B
# and C. (A plain create -- kubectl create configmap -- is a POST to the collection,
# which names no object when the policy is evaluated, so the policy logs it at Metadata
# with no body; only the chokepoint rule sees that form.)
#
# SAFETY:
#   * Procedure A captures the real coredns Corefile, appends an INERT sentinel server
#     block (forward of trr9027poison.example.invalid. to a TEST-NET IP), and RESTORES
#     the original Corefile at once. Real resolution is never changed.
#   * Procedures B and C write ConfigMaps a CoreDNS kind cluster does not read
#     (kube-dns, coredns-custom), so they are inert. Each runs ONLY when its ConfigMap
#     does not exist yet (a GKE cluster's real kube-dns, an AKS cluster's real
#     coredns-custom is never touched), and labels what it creates
#     app.kubernetes.io/part-of=trr9027; cleanup deletes only ConfigMaps with that label.
#
# Run ONE procedure:
#   ./emulate.sh a      repoint the coredns Corefile (sentinel forward), then restore
#   ./emulate.sh b      create a kube-dns ConfigMap with a stubDomains redirect (inert, SSA)
#   ./emulate.sh c      create a coredns-custom ConfigMap with a forward snippet (inert, SSA)
#   ./emulate.sh gap    node-local etcd/disk bypass demonstration (read-only)
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works, server-side apply: Kubernetes
# 1.22+) with rights on kube-system ConfigMaps, the audit policy in
# detections/k8s/audit-policy-apiserver.yaml (it logs named writes to the coredns,
# kube-dns and coredns-custom ConfigMaps at Request by resourceNames), and python3 (to
# build the merge patch and the applied objects).
set -euo pipefail

NS="kube-system"
NODE="${TRR9027_NODE:-apiserver-control-plane}"
SENTINEL_IP="198.51.100.53"   # RFC 5737 TEST-NET-2, non-routable
# An inert sentinel zone block: a rewrite (exercises the grader's plugin clause) and a
# forward to a TEST-NET IP. It answers only the sentinel .invalid zone, so real
# resolution is unaffected. The grader's forward-to-IP clause grades only the root
# block's forward, which the emulation never changes (that would redirect real cluster
# DNS); the sidecar cases prove that clause instead.
SENTINEL_BLOCK=$'\ntrr9027poison.example.invalid:53 {\n    errors\n    rewrite name trr9027poison.example.invalid sink.trr9027.example.invalid\n    forward . '"$SENTINEL_IP"$'\n}\n'

log() { printf '[trr9027] %s\n' "$*" >&2; }

# Build a strategic/merge patch body {"data":{"Corefile": <stdin>}} with correct JSON
# escaping of the multi-line Corefile.
_corefile_patch() { python3 -c 'import json,sys; print(json.dumps({"data":{"Corefile": sys.stdin.read()}}))'; }

# The label on every ConfigMap B and C create; cleanup deletes only ConfigMaps that carry
# it, so a cluster's own kube-dns or coredns-custom is never deleted.
PART_OF="app.kubernetes.io/part-of=trr9027"

# Server-side apply of an inert ConfigMap ($1 name, $2 data key, $3 data value), only
# when no ConfigMap of that name exists. SSA sends a PATCH to the named object, which
# creates it; the audit policy logs that named write at Request, with the body.
_apply_inert_configmap() {
  local name="$1" key="$2" value="$3"
  if kubectl -n "$NS" get configmap "$name" >/dev/null 2>&1; then
    log "configmap $NS/$name already exists (a real cluster DNS config?) -- not touching it, skipping"
    return 0
  fi
  python3 -c 'import json,sys; n,k,v,ns=sys.argv[1:5]; print(json.dumps({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":n,"namespace":ns,"labels":{"app.kubernetes.io/part-of":"trr9027"}},"data":{k:v}}))' \
    "$name" "$key" "$value" "$NS" \
    | kubectl apply --server-side --field-manager=trr9027-emulation -f - >/dev/null 2>&1 || true
}

cleanup() {
  log "cleanup: deleting the trr9027-labelled inert ConfigMaps (coredns is restored in procedure a)"
  kubectl -n "$NS" delete configmap -l "$PART_OF" --ignore-not-found >/dev/null 2>&1 || true
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
# CoreDNS cluster; written only to emit the chokepoint audit event.
procedure_b() {
  log "B: server-side apply a kube-dns ConfigMap with a stubDomains redirect (inert)"
  _apply_inert_configmap kube-dns stubDomains \
    '{"trr9027.poison.example.invalid":["'"$SENTINEL_IP"'"]}'
}

# Procedure C — coredns-custom import ConfigMap with a forward snippet. Inert unless the
# base Corefile imports it (a kind Corefile does not); written only for the chokepoint.
procedure_c() {
  log "C: server-side apply a coredns-custom ConfigMap with a forward snippet (inert)"
  # Multi-line, as CoreDNS's Caddyfile parser requires: a '}' on the forward's own line
  # is a syntax error ("Unexpected '}'"), so a one-line block would not load if imported.
  _apply_inert_configmap coredns-custom trr9027.server \
    $'trr9027poison.example.invalid:53 {\n    forward . '"$SENTINEL_IP"$'\n}\n'
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
