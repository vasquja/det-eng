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
# The sensitive-grant roles (Procedure G) are NEVER bound either. The aws-auth
# procedure (F) FAILS CLOSED: it writes only after it reads kube-system/aws-auth and
# sees that it is absent (or a leftover that is exactly what this emulation writes).
# Its patch carries the resourceVersion of its own create as a precondition, so the
# API server refuses the patch (409 Conflict) if any other writer changed the object
# in between. It deletes the object only while the stored data is exactly one of the
# two bodies it writes, with the resourceVersion it just read as a delete
# precondition. So it never overwrites or deletes another writer's mapping. Its one
# added mapping is to a throwaway group, not system:masters.
# No command runs inside any container; this technique is about the control plane.
#
# Run ONE procedure:
#   ./emulate.sh a      ClusterRoleBinding to a built-in ClusterRole
#   ./emulate.sh b      namespaced RoleBinding whose roleRef is a ClusterRole
#   ./emulate.sh c      create a benign role AND a wildcard role (never bound)
#   ./emulate.sh d      bind a group subject (mass-grant shape, harmless group)
#   ./emulate.sh e      patch an existing role to add a rule
#   ./emulate.sh f      write the EKS aws-auth ConfigMap (create + patch + delete)
#   ./emulate.sh g      write sensitive-but-not-wildcard roles (exec, token, secrets)
#   ./emulate.sh cleanup  remove every trr9004- object (and this emulation's own aws-auth)
#   ./emulate.sh cleanup-f  remove only this emulation's own aws-auth (Procedure F)
#   ./emulate.sh all    every procedure, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to write RBAC --
# the same rights an operator uses, so the point is the behavior, not a privilege
# the test grants itself. Cleanup removes every trr9004- object.
set -euo pipefail

NS="${TRR9004_NAMESPACE:-default}"
SA="trr9004-sa"

# Procedure F's two aws-auth bodies (data.mapRoles): the sentinel that the create writes,
# and the sentinel plus the backdoor that the patch writes. The script deletes
# kube-system/aws-auth only while its data is EXACTLY one of these two strings.
AWS_AUTH_SENTINEL=$'- groups:\n  - system:bootstrappers\n  - system:nodes\n  rolearn: arn:aws:iam::123456789012:role/trr9004-aws-auth-sentinel-NodeInstanceRole\n  username: system:node:{{EC2PrivateDNSName}}\n'
AWS_AUTH_BACKDOOR="${AWS_AUTH_SENTINEL}"$'- groups:\n  - trr9004-unbound-group\n  rolearn: arn:aws:iam::123456789012:role/trr9004-aws-auth-backdoor\n  username: trr9004-backdoor\n'

log() { printf '[trr9004] %s\n' "$*" >&2; }

# Print a DeleteOptions body for the aws-auth ConfigMap given as JSON in $1, with that
# object's resourceVersion as the delete precondition, but ONLY when the object is
# exactly one this emulation wrote: its one data key is mapRoles, it has no binaryData,
# and mapRoles is the sentinel alone or the sentinel plus the backdoor, byte for byte.
# Print nothing in any other case (another writer's entry, a real EKS aws-auth, no
# python3, a parse error).
aws_auth_own_delete_body() {
  printf '%s' "$1" | AWS_AUTH_SENTINEL="$AWS_AUTH_SENTINEL" AWS_AUTH_BACKDOOR="$AWS_AUTH_BACKDOOR" \
    python3 -c '
import json, os, sys
obj = json.load(sys.stdin)
data = obj.get("data") or {}
rv = (obj.get("metadata") or {}).get("resourceVersion") or ""
own = (os.environ["AWS_AUTH_SENTINEL"], os.environ["AWS_AUTH_BACKDOOR"])
if rv and not obj.get("binaryData") and list(data) == ["mapRoles"] and data["mapRoles"] in own:
    print(json.dumps({"kind": "DeleteOptions", "apiVersion": "v1",
                      "preconditions": {"resourceVersion": rv}}))
' 2>/dev/null || true
}

# Delete kube-system/aws-auth ONLY when it is exactly an object this emulation wrote
# (see aws_auth_own_delete_body). The DELETE carries the resourceVersion just read as a
# precondition, so the API server refuses it (409 Conflict) if any writer changed the
# object after the read. Return 0 when the object is absent or deleted, 1 when it stays.
aws_auth_delete_own() {
  local json body
  if ! json="$(kubectl -n kube-system get configmap aws-auth --ignore-not-found -o json)"; then
    log "F: cannot read kube-system/aws-auth (see the kubectl error above) — NOT deleting it"
    return 1
  fi
  [ -n "$json" ] || return 0
  body="$(aws_auth_own_delete_body "$json")"
  if [ -z "$body" ]; then
    log "F: kube-system/aws-auth is not exactly what this emulation wrote — NOT deleting it (if it holds a trr9004 entry, remove that entry by hand)"
    return 1
  fi
  if printf '%s\n' "$body" \
      | kubectl delete --raw /api/v1/namespaces/kube-system/configmaps/aws-auth -f - >/dev/null; then
    return 0
  fi
  log "F: the guarded delete of kube-system/aws-auth was refused (changed since the read?) — NOT deleting it"
  return 1
}

cleanup() {
  log "cleanup: removing every trr9004- RBAC object and the service account"
  kubectl delete clusterrolebinding trr9004-crb-view trr9004-crb-grp --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete rolebinding trr9004-rb-view --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete clusterrole trr9004-cr-benign trr9004-cr-wild trr9004-cr-secrets --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete role trr9004-role-exec trr9004-role-token --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete serviceaccount "$SA" --ignore-not-found >/dev/null 2>&1 || true
  # The aws-auth ConfigMap, but ONLY while it is exactly this emulation's own object
  # (never a real EKS aws-auth, and never ours after another writer added an entry).
  aws_auth_delete_own || true
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

# Procedure F — write the EKS aws-auth ConfigMap (create, patch, delete).
# On an EKS cluster in CONFIG_MAP or API_AND_CONFIG_MAP mode the IAM authenticator maps
# the IAM principals in kube-system/aws-auth to RBAC identities, so an adversary who can
# write it maps a role they control to cluster-admin. On a kind cluster nothing reads the
# object, so this is inert; it exists to emit the configmaps audit event the chokepoint
# keys on.
#
# SAFETY: it FAILS CLOSED, and it never overwrites or deletes another writer's mapping.
# 1. It proceeds only when it can read kube-system/aws-auth and see that it is absent, or
#    that it is a leftover that is exactly what this emulation writes. Any error reading
#    the object (a TLS timeout, Forbidden, the wrong context, throttling) counts as "do
#    not touch", NOT as "absent".
# 2. The patch runs only after the create succeeds, and it carries the create's
#    resourceVersion as a precondition (metadata.resourceVersion in the merge patch). If
#    any other writer (eksctl, the EKS control plane) changed the object after the create,
#    the API server refuses the patch with 409 Conflict, so their entry is not replaced.
# 3. The delete runs only while the stored data is exactly the sentinel, or the sentinel
#    plus the backdoor, and it carries the resourceVersion of that read as a delete
#    precondition (409 Conflict on any write in between). If another writer added an
#    entry, the object stays, with the inert sentinel entry in it, and the log says so.
# The one added mapping points at a throwaway group trr9004-unbound-group that no binding
# grants, NOT system:masters, so even on an EKS cluster the entry would grant nothing.
procedure_f() {
  if ! command -v python3 >/dev/null 2>&1; then
    log "F: python3 is needed to build and check the ConfigMap body — skipping"
    return 0
  fi
  local verb
  for verb in create patch delete; do
    if [ "$(kubectl auth can-i "$verb" configmaps -n kube-system 2>/dev/null || true)" != "yes" ]; then
      log "F: this identity may not $verb configmaps in kube-system — skipping"
      return 0
    fi
  done
  # FAIL CLOSED. --ignore-not-found makes a clean NotFound exit 0 with empty output; any
  # other error (connection, auth) exits non-zero, so a transient failure is never
  # mistaken for "absent". Only stdout is captured; kubectl's error goes to stderr.
  local existing
  if ! existing="$(kubectl -n kube-system get configmap aws-auth --ignore-not-found -o json)"; then
    log "F: cannot read kube-system/aws-auth (see the kubectl error above) — NOT touching it, skipping"
    return 0
  fi
  if [ -n "$existing" ]; then
    # The object exists. Only a leftover that is exactly what this emulation writes may
    # be removed; a real aws-auth, or ours with another writer's entry, is never touched.
    if [ -z "$(aws_auth_own_delete_body "$existing")" ]; then
      log "F: kube-system/aws-auth already exists and is not this emulation's (a real EKS cluster?) — NOT touching it, skipping"
      return 0
    fi
    log "F: a leftover trr9004 aws-auth from an interrupted run — deleting it (guarded), then recreating"
    if ! aws_auth_delete_own; then
      log "F: the leftover aws-auth was not deleted — skipping"
      return 0
    fi
  fi
  # The initial object: one inert node-role mapping carrying the trr9004 sentinel.
  log "F: create kube-system/aws-auth with a trr9004 sentinel mapRoles entry"
  # FAIL CLOSED: patch the object ONLY if this create succeeds. An AlreadyExists here
  # means a real aws-auth appeared between the read and the create, so do nothing more.
  local rv patchbody
  if ! rv="$(AWS_AUTH_SENTINEL="$AWS_AUTH_SENTINEL" python3 -c 'import json,os; print(json.dumps({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"aws-auth","namespace":"kube-system"},"data":{"mapRoles":os.environ["AWS_AUTH_SENTINEL"]}}))' \
      | kubectl create -f - -o jsonpath='{.metadata.resourceVersion}')"; then
    log "F: create of kube-system/aws-auth did not succeed — NOT patching or deleting, skipping"
    return 0
  fi
  if [ -z "$rv" ]; then
    # Without the create's resourceVersion the patch cannot be a compare-and-swap.
    log "F: the create returned no resourceVersion — NOT patching"
  else
    # Append a backdoor role mapped to a throwaway group (not system:masters): a merge
    # patch whose metadata.resourceVersion is the create's, so it applies only to the
    # object exactly as this emulation created it.
    patchbody="$(RV="$rv" AWS_AUTH_BACKDOOR="$AWS_AUTH_BACKDOOR" python3 -c 'import json,os; print(json.dumps({"metadata":{"resourceVersion":os.environ["RV"]},"data":{"mapRoles":os.environ["AWS_AUTH_BACKDOOR"]}}))')"
    log "F: patch aws-auth (precondition: resourceVersion $rv) to append a backdoor role mapped to trr9004-unbound-group (NOT system:masters)"
    if ! kubectl -n kube-system patch configmap aws-auth --type=merge -p "$patchbody" >/dev/null; then
      log "F: the patch was refused (another writer changed aws-auth after the create?) — NOT overwriting it"
    fi
  fi
  # The teardown: delete only while the object is exactly this emulation's own.
  log "F: delete aws-auth if it is still exactly this emulation's object (the recreate path and the teardown)"
  aws_auth_delete_own || true
}

# Procedure G — write roles that grant sensitive-but-not-wildcard permissions. None is
# bound to any subject, so nothing gains power; they emit the medium severity telemetry
# the sensitive-grant rule keys on (pods/exec, serviceaccounts/token, cluster-wide
# secret reads).
procedure_g() {
  log "G: create clusterrole trr9004-cr-secrets (secrets get,list — cluster-wide reads, NEVER bound)"
  kubectl create clusterrole trr9004-cr-secrets \
    --verb=get,list --resource=secrets >/dev/null 2>&1 || true
  log "G: create role trr9004-role-exec -n ${NS} (create pods/exec, NEVER bound)"
  kubectl -n "$NS" create role trr9004-role-exec \
    --verb=create --resource=pods/exec >/dev/null 2>&1 || true
  log "G: create role trr9004-role-token -n ${NS} (create serviceaccounts/token, NEVER bound)"
  kubectl -n "$NS" create role trr9004-role-token \
    --verb=create --resource=serviceaccounts/token >/dev/null 2>&1 || true
}

run_one() {
  case "$1" in
    a) procedure_a ;;
    b) procedure_b ;;
    c) procedure_c ;;
    d) procedure_d ;;
    e) procedure_e ;;
    f) procedure_f ;;
    g) procedure_g ;;
    cleanup) cleanup ;;
    cleanup-f) aws_auth_delete_own || true ;;
    *) log "unknown procedure: $1 (use a|b|c|d|e|f|g|cleanup|cleanup-f|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d e f g; do run_one "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
