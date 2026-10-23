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
# grants nothing, and it expires on its own. Procedure E reads one projected token
# file read-only through a marked copy of cat and discards the bytes to /dev/null;
# the token never reaches a command line or a log line.
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
# the same approach as TRR9002 Procedure E; set TRR9006_NODE for a non-kind lab, and
# TRR9006_TOKEN_FILE to choose the token file E reads.
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
  # The server's reason token (AlreadyExists) is in kubectl's message for a namespace,
  # but `create secret generic` and `create serviceaccount` print only the text
  # ("... already exists"), so match both.
  if [ "$rc" -eq 0 ] || printf '%s' "$out" | grep -qiE 'AlreadyExists|already exists'; then
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
# NO API call, so the API server audit log gains no event (C2-4's absence check proves
# it). The read goes through a MARKED copy of cat ($READER): a node file-event sensor
# (in CI, an auditd read watch on the token file) records the open with that exe, so
# the Strategy 3 file-event rule gets a live gate (C2-7). The marked reader is told
# apart from the node's own workloads, which re-read their tokens. The copy goes to
# /usr/local/bin, not /tmp: on a kind node /tmp is a tmpfs that Docker mounts noexec
# (kind v0.33.0 provision.go "--tmpfs /tmp"), so a copy there cannot run.
# TRR9006_TOKEN_FILE (optional) names the token file to read, as the node sees it
# (CI sets it to the file its sensor watches); without it, E reads the first projected
# token that `find` lists. The token's bytes go to /dev/null and never reach a command
# line or a log line. The read must actually happen: E FAILS unless the node read
# printed 'read-ok' (a 'no-token-file', 'no-reader', 'reader-cannot-run', or no node
# access is a failure, not a silent pass).
READER="/usr/local/bin/trr9006-reader"
procedure_e() {
  local out pick
  if [ -n "${TRR9006_TOKEN_FILE:-}" ]; then
    # A path, not a credential. Accept only a projected token path with no quote or
    # space, so it can go into the node snippet in single quotes.
    case "$TRR9006_TOKEN_FILE" in
      *\'*|*' '*|*'"'*)
        log "E: TRR9006_TOKEN_FILE has a quote or a space; refusing it"; return 1 ;;
      /var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/token) ;;
      *)
        log "E: TRR9006_TOKEN_FILE is not a projected token under /var/lib/kubelet/pods"
        return 1 ;;
    esac
    pick="f='$TRR9006_TOKEN_FILE'"
  else
    pick='f=$(find /var/lib/kubelet/pods -path "*kubernetes.io~projected*/token" 2>/dev/null | head -1)'
  fi
  # The node snippet: pick the token file, copy cat to the marked path, check that the
  # copy runs (it reads /dev/null), read the token through it (output discarded), then
  # remove the marked copy.
  local read_snippet="$pick
    r='$READER'"'
    [ -n "$f" ] && [ -e "$f" ] || { echo no-token-file; exit 0; }
    cp "$(command -v cat)" "$r" 2>/dev/null || { echo no-reader; exit 0; }
    if ! "$r" /dev/null >/dev/null 2>&1; then
      echo reader-cannot-run; rm -f "$r" 2>/dev/null; exit 0
    fi
    "$r" "$f" >/dev/null 2>&1 && echo read-ok || echo read-failed
    rm -f "$r" 2>/dev/null
  '
  if [ -n "${TRR9006_NODE_EXEC:-}" ]; then
    log "E: reading a projected token file on the node through $READER (custom exec)"
    out="$($TRR9006_NODE_EXEC "$read_snippet" 2>/dev/null || true)"
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "E: reading a projected token file on node $NODE through $READER (read-only)"
    out="$(docker exec "$NODE" sh -c "$read_snippet" 2>/dev/null || true)"
  else
    log "E: no node access (docker/TRR9006_NODE_EXEC) — cannot read a token off disk"
    return 1
  fi
  printf '%s\n' "$out"
  if ! printf '%s' "$out" | grep -qx 'read-ok'; then
    log "E: the on-disk token read did not return 'read-ok' (got: ${out:-<empty>})"
    return 1
  fi
  log "E: done — expect NO secrets/serviceaccounts audit event for this read; a node"
  log "E: file-event sensor, if one runs, should record an open by $READER (the"
  log "E: validator's 9006 E file gate checks it)"
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
