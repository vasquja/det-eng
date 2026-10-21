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

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# A procedure's ACTION must succeed. `must CMD` runs it, prints its stderr on failure,
# and returns the command's exit code. `run_proc P` times procedure_P, appends one
# ledger line to $DETENG_LEDGER (set by CI; unset = no ledger) and records a failure
# without stopping the run, so every procedure is attempted and `all` then exits 1
# naming the failures with a ::error:: annotation each. Cleanup keeps `|| true`: a
# failed cleanup must not hide a result.
TRR="TRR9004"
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
    must kubectl -n "$NS" create serviceaccount "$SA"
}

# Procedure A — ClusterRoleBinding to a built-in ClusterRole (cluster-wide grant).
# Binds the READ-ONLY `view` role (an attacker would name cluster-admin here).
procedure_a() {
  ensure_sa || return
  log "A: create clusterrolebinding trr9004-crb-view -> ClusterRole/view (read-only)"
  must kubectl create clusterrolebinding trr9004-crb-view \
    --clusterrole=view --serviceaccount="${NS}:${SA}"
}

# Procedure B — namespaced RoleBinding whose roleRef is a ClusterRole.
# The binding lives in one namespace but reaches a cluster-wide role (the tell is
# requestObject.roleRef.kind=ClusterRole).
procedure_b() {
  ensure_sa || return
  log "B: create rolebinding trr9004-rb-view -n ${NS} -> ClusterRole/view"
  must kubectl -n "$NS" create rolebinding trr9004-rb-view \
    --clusterrole=view --serviceaccount="${NS}:${SA}"
}

# Procedure C — write roles. A benign read-only role (used by Procedure E's patch)
# and a wildcard "god" role that is NEVER bound, so it grants nothing. The wildcard
# role is the harmless high-severity telemetry (requestObject.rules has "*").
procedure_c() {
  log "C: create clusterrole trr9004-cr-benign (read-only get/list pods)"
  must kubectl create clusterrole trr9004-cr-benign \
    --verb=get,list --resource=pods || return
  log "C: create clusterrole trr9004-cr-wild (verbs/resources '*', NEVER bound)"
  must kubectl create clusterrole trr9004-cr-wild \
    --verb='*' --resource='*'
}

# Procedure D — bind a GROUP subject (the mass-grant shape).
# Uses throwaway group trr9004-nogroup (no principal belongs to it). An attacker
# would name system:authenticated to grant every authenticated user at once; that
# is a real grant even in a throwaway cluster, so it is documentation only, never run.
procedure_d() {
  log "D: create clusterrolebinding trr9004-crb-grp -> view, group=trr9004-nogroup"
  must kubectl create clusterrolebinding trr9004-crb-grp \
    --clusterrole=view --group=trr9004-nogroup
}

# Procedure E — patch an existing role to add a rule (verb=patch, not create).
# Amends the benign role from Procedure C, so detections that watch only `create`
# miss it.
procedure_e() {
  kubectl get clusterrole trr9004-cr-benign >/dev/null 2>&1 || procedure_c || return
  log "E: patch clusterrole trr9004-cr-benign to append a read rule (verb=patch)"
  must kubectl patch clusterrole trr9004-cr-benign --type=json \
    -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":[""],"resources":["configmaps"],"verbs":["get"]}}]'
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
#
# RESULT: F skips (exit 0, no write sent) only for a lab condition that makes the write
# unsafe or impossible by design: no python3, an identity that may not write
# kube-system ConfigMaps (`kubectl auth can-i` answers "no"), or an aws-auth that another
# writer owns. Every error -- a failed read or can-i call, a refused create, patch or
# delete -- fails the procedure (exit 1), still without touching another writer's object.
procedure_f() {
  if ! command -v python3 >/dev/null 2>&1; then
    log "F: python3 is needed to build and check the ConfigMap body — skipping"
    return 0
  fi
  local verb answer
  for verb in create patch delete; do
    # can-i prints "yes" or "no"; an error (no answer) is a failure, not a skip.
    answer="$(kubectl auth can-i "$verb" configmaps -n kube-system 2>/dev/null || true)"
    if [ "$answer" = "no" ]; then
      log "F: this identity may not $verb configmaps in kube-system — skipping"
      return 0
    fi
    if [ "$answer" != "yes" ]; then
      log "F: kubectl auth can-i $verb configmaps -n kube-system gave no answer — NOT touching aws-auth"
      return 1
    fi
  done
  # FAIL CLOSED. --ignore-not-found makes a clean NotFound exit 0 with empty output; any
  # other error (connection, auth) exits non-zero, so a transient failure is never
  # mistaken for "absent". Only stdout is captured; kubectl's error goes to stderr.
  local existing
  if ! existing="$(kubectl -n kube-system get configmap aws-auth --ignore-not-found -o json)"; then
    log "F: cannot read kube-system/aws-auth (see the kubectl error above) — NOT touching it"
    return 1
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
      log "F: the leftover aws-auth was not deleted — NOT recreating it"
      return 1
    fi
  fi
  # The initial object: one inert node-role mapping carrying the trr9004 sentinel.
  log "F: create kube-system/aws-auth with a trr9004 sentinel mapRoles entry"
  # FAIL CLOSED: patch the object ONLY if this create succeeds. An AlreadyExists here
  # means a real aws-auth appeared between the read and the create, so do nothing more.
  local rv patchbody rc=0
  if ! rv="$(AWS_AUTH_SENTINEL="$AWS_AUTH_SENTINEL" python3 -c 'import json,os; print(json.dumps({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"aws-auth","namespace":"kube-system"},"data":{"mapRoles":os.environ["AWS_AUTH_SENTINEL"]}}))' \
      | kubectl create -f - -o jsonpath='{.metadata.resourceVersion}')"; then
    # The create is the procedure's action, so a refused create fails F. Fail closed:
    # no patch and no delete, so another writer's object is never touched.
    log "F: create of kube-system/aws-auth did not succeed — NOT patching or deleting"
    return 1
  fi
  if [ -z "$rv" ]; then
    # Without the create's resourceVersion the patch cannot be a compare-and-swap.
    log "F: the create returned no resourceVersion — NOT patching"
    rc=1
  else
    # Append a backdoor role mapped to a throwaway group (not system:masters): a merge
    # patch whose metadata.resourceVersion is the create's, so it applies only to the
    # object exactly as this emulation created it.
    patchbody="$(RV="$rv" AWS_AUTH_BACKDOOR="$AWS_AUTH_BACKDOOR" python3 -c 'import json,os; print(json.dumps({"metadata":{"resourceVersion":os.environ["RV"]},"data":{"mapRoles":os.environ["AWS_AUTH_BACKDOOR"]}}))')"
    log "F: patch aws-auth (precondition: resourceVersion $rv) to append a backdoor role mapped to trr9004-unbound-group (NOT system:masters)"
    if ! kubectl -n kube-system patch configmap aws-auth --type=merge -p "$patchbody" >/dev/null; then
      log "F: the patch was refused (another writer changed aws-auth after the create?) — NOT overwriting it"
      rc=1
    fi
  fi
  # The teardown: delete only while the object is exactly this emulation's own. A failed
  # teardown leaves the inert sentinel object behind, so it fails F too.
  log "F: delete aws-auth if it is still exactly this emulation's object (the recreate path and the teardown)"
  if ! aws_auth_delete_own; then
    log "F: kube-system/aws-auth was not deleted (see above)"
    rc=1
  fi
  return "$rc"
}

# Procedure G — write roles that grant sensitive-but-not-wildcard permissions. None is
# bound to any subject, so nothing gains power; they emit the medium severity telemetry
# the sensitive-grant rule keys on (pods/exec, serviceaccounts/token, cluster-wide
# secret reads).
procedure_g() {
  log "G: create clusterrole trr9004-cr-secrets (secrets get,list — cluster-wide reads, NEVER bound)"
  must kubectl create clusterrole trr9004-cr-secrets \
    --verb=get,list --resource=secrets || return
  log "G: create role trr9004-role-exec -n ${NS} (create pods/exec, NEVER bound)"
  must kubectl -n "$NS" create role trr9004-role-exec \
    --verb=create --resource=pods/exec || return
  log "G: create role trr9004-role-token -n ${NS} (create serviceaccounts/token, NEVER bound)"
  must kubectl -n "$NS" create role trr9004-role-token \
    --verb=create --resource=serviceaccounts/token
}

run_one() {
  case "$1" in
    a|b|c|d|e|f|g) run_proc "$1" ;;
    cleanup) cleanup ;;
    cleanup-f) aws_auth_delete_own || true ;;
    *) log "unknown procedure: $1 (use a|b|c|d|e|f|g|cleanup|cleanup-f|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d e f g; do run_proc "$p"; done
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
