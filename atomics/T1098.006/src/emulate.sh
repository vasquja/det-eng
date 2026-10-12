#!/usr/bin/env bash
# TRR9004 — behavioral emulation for T1098.006 (Account Manipulation: Additional
# Container Cluster Roles), Kubernetes RBAC.
#
# Each procedure performs a HARMLESS RBAC write through the API server, so the
# API server writes the audit events the paired Sigma rules key on. Every object
# is named with the unique prefix `trr9004-` so a validator can match the
# emulation's OWN events and a pre-emulation baseline (the many bootstrap/reconcile
# RBAC writes a kubeadm cluster makes) cannot.
#
# SAFETY: every binding points at the READ-ONLY built-in `view` ClusterRole, so
# nothing gains write power. The one wildcard role (Procedure C, trr9004-cr-wild)
# is NEVER bound to any subject, so it grants nothing -- it exists only to emit
# the "dangerous rule" telemetry. The group binding (Procedure D) uses a throwaway
# group `trr9004-nogroup` that no principal belongs to, not system:authenticated.
# No command runs inside any container; this technique is about the control plane.
#
# Run ONE procedure:
#   ./emulate.sh a      ClusterRoleBinding to a built-in ClusterRole
#   ./emulate.sh b      namespaced RoleBinding whose roleRef is a ClusterRole
#   ./emulate.sh c      create a benign role AND a wildcard role (never bound)
#   ./emulate.sh d      bind a group subject (mass-grant shape, harmless group)
#   ./emulate.sh e      patch an existing role to add a rule
#   ./emulate.sh all    every procedure, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to write RBAC --
# the same rights an operator uses, so the point is the behavior, not a privilege
# the test grants itself. Cleanup removes every trr9004- object.
set -euo pipefail

NS="${TRR9004_NAMESPACE:-default}"
SA="trr9004-sa"

log() { printf '[trr9004] %s\n' "$*" >&2; }

cleanup() {
  log "cleanup: removing every trr9004- RBAC object and the service account"
  kubectl delete clusterrolebinding trr9004-crb-view trr9004-crb-grp --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete rolebinding trr9004-rb-view --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete clusterrole trr9004-cr-benign trr9004-cr-wild --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete serviceaccount "$SA" --ignore-not-found >/dev/null 2>&1 || true
}

ensure_sa() {
  kubectl -n "$NS" get serviceaccount "$SA" >/dev/null 2>&1 || \
    kubectl -n "$NS" create serviceaccount "$SA" >/dev/null
}

# Procedure A — ClusterRoleBinding to a built-in ClusterRole (cluster-wide grant).
# Binds the READ-ONLY `view` role (an attacker would name cluster-admin here).
procedure_a() {
  ensure_sa
  log "A: create clusterrolebinding trr9004-crb-view -> ClusterRole/view (read-only)"
  kubectl create clusterrolebinding trr9004-crb-view \
    --clusterrole=view --serviceaccount="${NS}:${SA}" >/dev/null 2>&1 || true
}

# Procedure B — namespaced RoleBinding whose roleRef is a ClusterRole.
# The binding lives in one namespace but reaches a cluster-wide role (the tell is
# requestObject.roleRef.kind=ClusterRole).
procedure_b() {
  ensure_sa
  log "B: create rolebinding trr9004-rb-view -n ${NS} -> ClusterRole/view"
  kubectl -n "$NS" create rolebinding trr9004-rb-view \
    --clusterrole=view --serviceaccount="${NS}:${SA}" >/dev/null 2>&1 || true
}

# Procedure C — write roles. A benign read-only role (used by Procedure E's patch)
# and a wildcard "god" role that is NEVER bound, so it grants nothing. The wildcard
# role is the harmless high-severity telemetry (requestObject.rules has "*").
procedure_c() {
  log "C: create clusterrole trr9004-cr-benign (read-only get/list pods)"
  kubectl create clusterrole trr9004-cr-benign \
    --verb=get,list --resource=pods >/dev/null 2>&1 || true
  log "C: create clusterrole trr9004-cr-wild (verbs/resources '*', NEVER bound)"
  kubectl create clusterrole trr9004-cr-wild \
    --verb='*' --resource='*' >/dev/null 2>&1 || true
}

# Procedure D — bind a GROUP subject (the mass-grant shape).
# Uses throwaway group trr9004-nogroup (no principal belongs to it). An attacker
# would name system:authenticated to grant every authenticated user at once; that
# is a real grant even in a throwaway cluster, so it is documentation only, never run.
procedure_d() {
  log "D: create clusterrolebinding trr9004-crb-grp -> view, group=trr9004-nogroup"
  kubectl create clusterrolebinding trr9004-crb-grp \
    --clusterrole=view --group=trr9004-nogroup >/dev/null 2>&1 || true
}

# Procedure E — patch an existing role to add a rule (verb=patch, not create).
# Amends the benign role from Procedure C, so detections that watch only `create`
# miss it.
procedure_e() {
  kubectl get clusterrole trr9004-cr-benign >/dev/null 2>&1 || procedure_c
  log "E: patch clusterrole trr9004-cr-benign to append a read rule (verb=patch)"
  kubectl patch clusterrole trr9004-cr-benign --type=json \
    -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":[""],"resources":["configmaps"],"verbs":["get"]}}]' \
    >/dev/null 2>&1 || true
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
