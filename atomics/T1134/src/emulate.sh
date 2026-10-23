#!/usr/bin/env bash
# TRR9009 — behavioral emulation for T1134 (Access Token Manipulation), Kubernetes
# user impersonation.
#
# Each procedure makes a read-only API request under impersonation, so the API
# server stamps impersonatedUser onto the audit event the paired Sigma rules key
# on. Every borrowed identity carries the token 'trr9009' that no real principal
# uses, so a validator matches the emulation's own events. Nothing is changed:
# every request is a `get`/`list`, run as the lab's cluster-admin impersonating a
# throwaway identity. The service account impersonated in Procedure C holds no
# RBAC, so the borrowed token grants nothing.
#
# Run ONE procedure:
#   ./emulate.sh a      impersonate a user (--as)
#   ./emulate.sh b      impersonate a group (--as-group), incl. system:masters (severity)
#   ./emulate.sh c      impersonate a service account (--as=system:serviceaccount:...)
#   ./emulate.sh d      impersonate a uid (--as-uid)
#   ./emulate.sh gap    a forbidden impersonation (decision=forbid, still stamped)
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with impersonate rights (the
# lab cluster-admin has them) and audit logging (see
# detections/k8s/kind-apiserver-cluster.yaml). There is no node-sensor fallback:
# impersonation is wholly API-server-internal.
set -euo pipefail

NS="${TRR9009_NAMESPACE:-trr9009}"
SA="trr9009-sa"

log() { printf '[trr9009] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs an action that must succeed (stderr shown on failure). The borrowed
# identities hold no RBAC, so most probes are DENIED by design: `expect_forbidden WHO CMD`
# passes only when CMD fails with the RBAC denial of the BORROWED identity's own request
# ('User "WHO" cannot ...', the API server's forbidden message), so the impersonation was
# authorized and the impersonated request was then refused. It fails on an unexpected
# success (a throwaway identity that gained rights), on a refusal of the impersonation
# itself ('cannot impersonate': no impersonated request was ever made), and on any other
# error, so the refusal is proven instead of swallowed. `run_proc P` times procedure_P, writes one ledger line
# to $DETENG_LEDGER (set by CI; unset = no ledger) and records a failure without
# stopping the run. Cleanup keeps `|| true`.
TRR="TRR9009"
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
expect_forbidden() {
  local who="$1" out rc=0
  shift
  out="$("$@" 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    log "UNEXPECTED SUCCESS (expected a 403 for $who): $*"
    return 1
  fi
  if printf '%s' "$out" | grep -qi 'cannot impersonate'; then
    log "FAILED: the caller may not impersonate, so no request as $who was authorized: $*"
  elif printf '%s' "$out" | grep -qF "User \"${who}\" cannot "; then
    return 0
  else
    log "FAILED (exit $rc; expected the 403 of $who's own request, got another error): $*"
  fi
  [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' >&2
  return 1
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

cleanup() {
  log "cleanup: deleting namespace $NS (cascades the service account)"
  kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A — impersonate a user. Read-only list.
procedure_a() {
  log "A: list namespaces impersonating a throwaway user (--as=trr9009-impersonated) -> expect 403"
  expect_forbidden trr9009-impersonated kubectl get namespaces --as=trr9009-impersonated
}

# Procedure B — impersonate a group. Once with a throwaway group, once with
# system:masters to exercise the privileged-target severity rule (read-only, so
# the borrowed cluster-admin does nothing but list namespaces).
procedure_b() {
  log "B: list namespaces impersonating a throwaway group (--as-group=trr9009-group) -> expect 403"
  expect_forbidden trr9009-impersonated \
    kubectl get namespaces --as=trr9009-impersonated --as-group=trr9009-group || return
  log "B: list namespaces impersonating system:masters (severity; read-only, ALLOWED 200)"
  must kubectl get namespaces --as=trr9009-impersonated --as-group=system:masters
}

# Procedure C — impersonate a service account that holds no RBAC (DENIED by design).
procedure_c() {
  # Best-effort setup: the SA need not exist for the impersonated list to be refused.
  kubectl get namespace "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS" >/dev/null 2>&1 || true
  kubectl -n "$NS" get serviceaccount "$SA" >/dev/null 2>&1 || kubectl -n "$NS" create serviceaccount "$SA" >/dev/null 2>&1 || true
  log "C: list namespaces impersonating system:serviceaccount:${NS}:${SA} -> expect 403"
  expect_forbidden "system:serviceaccount:${NS}:${SA}" \
    kubectl get namespaces --as="system:serviceaccount:${NS}:${SA}"
}

# Procedure D — impersonate a uid (and a throwaway user); DENIED by design.
procedure_d() {
  log "D: list namespaces impersonating a user + uid (--as-uid) -> expect 403"
  expect_forbidden trr9009-impersonated \
    kubectl get namespaces --as=trr9009-impersonated --as-uid=trr9009-uid-0001
}

# Gap/demonstration — a FORBIDDEN impersonated request. The caller may impersonate
# (authz passes), but the borrowed identity has no rights to read secrets, so the
# request is denied (decision=forbid). impersonatedUser is stamped either way, so
# the presence chokepoint catches it where an allow-only rule would not.
procedure_gap() {
  log "gap: forbidden impersonated read (get secrets as trr9009-impersonated -> decision=forbid, still stamped)"
  expect_forbidden trr9009-impersonated kubectl get secrets -A --as=trr9009-impersonated
}

run_one() {
  case "$1" in
    a|b|c|d|gap) run_proc "$1" ;;
    *) log "unknown item: $1 (use a|b|c|d|gap|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d gap; do run_proc "$p"; done
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
