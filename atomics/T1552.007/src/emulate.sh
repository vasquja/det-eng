#!/usr/bin/env bash
# TRR9006 — behavioral emulation for T1552.007 (Unsecured Credentials: Container
# API), Kubernetes Secrets and service-account tokens.
#
# Procedures A-D perform a HARMLESS credential-access action through the API
# server, so the API server writes the audit events the paired Sigma rules key
# on. Procedure E reads an already-mounted token off the node filesystem to show
# the detection gap: it makes NO API call, so the audit log gains no event.
#
# A FIXED namespace `trr9006` and unique names (trr9006-cred, trr9006-sa) let a
# validator gate on the namespace and the non-system caller, so the emulation's
# own reads are told apart from the controller reads that also hit the namespace,
# and a pre-emulation baseline (which has no trr9006 namespace) cannot pass.
#
# SAFETY: the Secret holds a benign literal, not a real credential. The minted
# token (Procedure D) is for a throwaway service account that holds no RBAC, so it
# grants nothing, and it expires on its own. Procedure E only reads the first few
# bytes of a token file, read-only, and discards them.
#
# Run ONE procedure:
#   ./emulate.sh a      list Secrets in the namespace
#   ./emulate.sh b      get one Secret by name
#   ./emulate.sh c      watch Secrets (streaming read, 5s)
#   ./emulate.sh d      mint a token via the TokenRequest API
#   ./emulate.sh e      read a mounted token off the node (the gap: no audit event)
#   ./emulate.sh all    every procedure, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to read Secrets
# and mint tokens. Procedure E needs node access (docker exec into the kind node),
# the same approach as TRR9002 Procedure E; set TRR9006_NODE for a non-kind lab.
set -euo pipefail

NS="${TRR9006_NAMESPACE:-trr9006}"
SECRET="trr9006-cred"
SA="trr9006-sa"
NODE="${TRR9006_NODE:-apiserver-control-plane}"

log() { printf '[trr9006] %s\n' "$*" >&2; }

ensure_setup() {
  kubectl get namespace "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS" >/dev/null
  kubectl -n "$NS" get secret "$SECRET" >/dev/null 2>&1 || \
    kubectl -n "$NS" create secret generic "$SECRET" \
      --from-literal=token=benign-not-a-real-credential >/dev/null
  kubectl -n "$NS" get serviceaccount "$SA" >/dev/null 2>&1 || \
    kubectl -n "$NS" create serviceaccount "$SA" >/dev/null
}

cleanup() {
  log "cleanup: deleting namespace $NS (cascades the secret and service account)"
  kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A — list Secrets in the namespace (verb=list, no objectRef.name).
procedure_a() {
  ensure_setup
  log "A: list Secrets in $NS (verb=list)"
  kubectl -n "$NS" get secrets >/dev/null 2>&1 || true
}

# Procedure B — get one Secret by name (verb=get). The only value returned is the
# benign literal the test created.
procedure_b() {
  ensure_setup
  log "B: get Secret $SECRET in $NS (verb=get)"
  kubectl -n "$NS" get secret "$SECRET" -o yaml >/dev/null 2>&1 || true
}

# Procedure C — watch Secrets (verb=watch). The client disconnects after 5s.
procedure_c() {
  ensure_setup
  log "C: watch Secrets in $NS for 5s (verb=watch)"
  kubectl -n "$NS" get secrets --watch --request-timeout=5s >/dev/null 2>&1 || true
}

# Procedure D — mint a short-lived token for the throwaway SA (TokenRequest).
# The SA holds no RBAC, so the token grants nothing; it expires on its own.
procedure_d() {
  ensure_setup
  log "D: mint a token for $SA via the TokenRequest API (verb=create, subresource=token)"
  kubectl -n "$NS" create token "$SA" --duration=10m >/dev/null 2>&1 || true
}

# Procedure E — the gap. Read an already-mounted service-account token off the
# node filesystem, read-only, and show the API server audit log gains no event.
# No API call is made, so the chokepoint cannot see it (mirrors TRR9002 e).
procedure_e() {
  if [ -n "${TRR9006_NODE_EXEC:-}" ]; then
    log "E: reading a projected token file on the node (custom exec)"
    $TRR9006_NODE_EXEC 'f=$(find /var/lib/kubelet/pods -path "*kubernetes.io~projected*/token" 2>/dev/null | head -1); [ -n "$f" ] && head -c 20 "$f" >/dev/null && echo read-ok || echo no-token-file' || true
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "E: reading a projected token file on node $NODE (read-only)"
    docker exec "$NODE" sh -c '
      f=$(find /var/lib/kubelet/pods -path "*kubernetes.io~projected*/token" 2>/dev/null | head -1)
      [ -n "$f" ] && head -c 20 "$f" >/dev/null 2>&1 && echo read-ok || echo no-token-file
    ' || true
  else
    log "E: no node access (docker/TRR9006_NODE_EXEC) — skipping the gap demonstration"
    return 0
  fi
  log "E: done — expect NO secrets/serviceaccounts audit event for this read"
}

run_one() {
  case "$1" in
    a) procedure_a ;;
    b) procedure_b ;;
    c) procedure_c ;;
    d) procedure_d ;;
    e) procedure_e ;;
    *) log "unknown procedure: $1 (use a|b|c|d|e|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d e; do run_one "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
