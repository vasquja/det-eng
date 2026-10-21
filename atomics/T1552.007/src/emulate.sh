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

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs a procedure's action and returns its exit code (stderr shown on
# failure). `create_ok CMD` is `must` for a create that treats AlreadyExists as
# success (so a shared ensure_setup is idempotent without a prior GET). `run_proc P`
# times procedure_P, appends one ledger line to $DETENG_LEDGER (set by CI; unset = no
# ledger) and records a failure without stopping the run. Cleanup keeps `|| true`.
TRR="TRR9006"
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
create_ok() {
  local out rc=0
  out="$("$@" 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -eq 0 ] || printf '%s' "$out" | grep -qi 'AlreadyExists'; then
    return 0
  fi
  log "FAILED (exit $rc): $*"
  [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' >&2
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

# Create the namespace, Secret and SA, treating AlreadyExists as success, so no GET
# precedes Procedure B's read (the GET used to look like B's own request; C1-3/C1-4).
ensure_setup() {
  create_ok kubectl create namespace "$NS" || return
  create_ok kubectl -n "$NS" create secret generic "$SECRET" \
    --from-literal=token=benign-not-a-real-credential || return
  create_ok kubectl -n "$NS" create serviceaccount "$SA"
}

cleanup() {
  log "cleanup: deleting namespace $NS (cascades the secret and service account)"
  kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A — list Secrets in the namespace (verb=list, no objectRef.name).
procedure_a() {
  ensure_setup || return
  log "A: list Secrets in $NS (verb=list)"
  must kubectl -n "$NS" get secrets
}

# Procedure B — get one Secret by name (verb=get). The only value returned is the
# benign literal the test created.
procedure_b() {
  ensure_setup || return
  log "B: get Secret $SECRET in $NS (verb=get)"
  must kubectl -n "$NS" get secret "$SECRET" -o yaml
}

# Procedure C — watch Secrets (verb=watch). The client disconnects after 5s (the
# request-timeout ends the watch with a clean exit).
procedure_c() {
  ensure_setup || return
  log "C: watch Secrets in $NS for 5s (verb=watch)"
  must kubectl -n "$NS" get secrets --watch --request-timeout=5s
}

# Procedure D — mint a short-lived token for the throwaway SA (TokenRequest).
# The SA holds no RBAC, so the token grants nothing; it expires on its own.
procedure_d() {
  ensure_setup || return
  log "D: mint a token for $SA via the TokenRequest API (verb=create, subresource=token)"
  must kubectl -n "$NS" create token "$SA" --duration=10m
}

# Procedure E — the gap. Read an already-mounted token off the node filesystem; it makes
# NO API call, so the audit log gains no event (C2-4's absence check proves it). The read
# must actually happen: E FAILS unless the node read printed 'read-ok' (a 'no-token-file'
# result, or no node access, is a failure, not a silent pass).
procedure_e() {
  local out
  if [ -n "${TRR9006_NODE_EXEC:-}" ]; then
    log "E: reading a projected token file on the node (custom exec)"
    out="$($TRR9006_NODE_EXEC 'f=$(find /var/lib/kubelet/pods -path "*kubernetes.io~projected*/token" 2>/dev/null | head -1); [ -n "$f" ] && head -c 20 "$f" >/dev/null && echo read-ok || echo no-token-file' 2>/dev/null || true)"
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "E: reading a projected token file on node $NODE (read-only)"
    out="$(docker exec "$NODE" sh -c '
      f=$(find /var/lib/kubelet/pods -path "*kubernetes.io~projected*/token" 2>/dev/null | head -1)
      [ -n "$f" ] && head -c 20 "$f" >/dev/null 2>&1 && echo read-ok || echo no-token-file
    ' 2>/dev/null || true)"
  else
    log "E: no node access (docker/TRR9006_NODE_EXEC) — cannot read a token off disk"
    return 1
  fi
  printf '%s\n' "$out"
  if ! printf '%s' "$out" | grep -qx 'read-ok'; then
    log "E: the on-disk token read did not return 'read-ok' (got: ${out:-<empty>})"
    return 1
  fi
  log "E: done — expect NO secrets/serviceaccounts audit event for this read"
}

run_one() {
  case "$1" in
    a|b|c|d|e) run_proc "$1" ;;
    *) log "unknown procedure: $1 (use a|b|c|d|e|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d e; do run_proc "$p"; done
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
