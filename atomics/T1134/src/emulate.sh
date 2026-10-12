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

cleanup() {
  log "cleanup: deleting namespace $NS (cascades the service account)"
  kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A — impersonate a user. Read-only list.
procedure_a() {
  log "A: list namespaces impersonating a throwaway user (--as=trr9009-impersonated)"
  kubectl get namespaces --as=trr9009-impersonated >/dev/null 2>&1 || true
}

# Procedure B — impersonate a group. Once with a throwaway group, once with
# system:masters to exercise the privileged-target severity rule (read-only, so
# the borrowed cluster-admin does nothing but list namespaces).
procedure_b() {
  log "B: list namespaces impersonating a throwaway group (--as-group=trr9009-group)"
  kubectl get namespaces --as=trr9009-impersonated --as-group=trr9009-group >/dev/null 2>&1 || true
  log "B: list namespaces impersonating system:masters (severity; read-only)"
  kubectl get namespaces --as=trr9009-impersonated --as-group=system:masters >/dev/null 2>&1 || true
}

# Procedure C — impersonate a service account that holds no RBAC.
procedure_c() {
  kubectl get namespace "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS" >/dev/null 2>&1 || true
  kubectl -n "$NS" get serviceaccount "$SA" >/dev/null 2>&1 || kubectl -n "$NS" create serviceaccount "$SA" >/dev/null 2>&1 || true
  log "C: list namespaces impersonating system:serviceaccount:${NS}:${SA}"
  kubectl get namespaces --as="system:serviceaccount:${NS}:${SA}" >/dev/null 2>&1 || true
}

# Procedure D — impersonate a uid (and a throwaway user).
procedure_d() {
  log "D: list namespaces impersonating a user + uid (--as-uid)"
  kubectl get namespaces --as=trr9009-impersonated --as-uid=trr9009-uid-0001 >/dev/null 2>&1 || true
}

# Gap/demonstration — a FORBIDDEN impersonated request. The caller may impersonate
# (authz passes), but the borrowed identity has no rights to read secrets, so the
# request is denied (decision=forbid). impersonatedUser is stamped either way, so
# the presence chokepoint catches it where an allow-only rule would not.
procedure_gap() {
  log "gap: forbidden impersonated read (get secrets as trr9009-impersonated -> decision=forbid, still stamped)"
  kubectl get secrets -A --as=trr9009-impersonated >/dev/null 2>&1 || true
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
