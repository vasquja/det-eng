#!/usr/bin/env bash
# TRR9008 — behavioral emulation for T1685 (Disable or Modify
# Tools), Kubernetes admission control. (The Linux io_uring telemetry-evasion atomic
# for T1685 is the separate C program in this folder; this is the Kubernetes
# admission-control half.)
#
# Each procedure DISABLES a harmless, throwaway admission object (NEVER a real
# Gatekeeper/Kyverno/Falco webhook), so the API server writes the audit events the
# paired Sigma rules key on. Every object the tests create is named trr9008-* (the
# namespace of procedure d is trr9008) so a validator matches the emulation's own
# events. The one exception is the kyverno namespace: d2 creates it only when it is
# absent, labels it trr9008-created=true, and deletes it again. Its records carry no
# trr9008 marker, so the validator does not gate them. The webhooks are no-ops
# (failurePolicy Ignore, rules scoped to a bogus apiGroup) that cannot affect any
# real admission request.
#
# Run ONE procedure:
#   ./emulate_k8s.sh a      delete a ValidatingWebhookConfiguration
#   ./emulate_k8s.sh b      delete a MutatingWebhookConfiguration
#   ./emulate_k8s.sh c      neuter a webhook config in place (failurePolicy Ignore, rules []), then
#                           four more neuters of their own configs: a merge patch and a JSON
#                           patch that replace the webhooks list and drop rules, a constant
#                           matchCondition, and a namespaceSelector that matches no namespace
#   ./emulate_k8s.sh d      scale-to-zero (kubectl scale, then patch) and delete a stand-in enforcer Deployment
#   ./emulate_k8s.sh d2     the same removal in the kyverno namespace (a policy engine's default
#                           namespace): a stand-in Deployment scaled to zero by two kubectl scale
#                           shapes (an update of deployments/scale, then a patch), then deleted;
#                           the kyverno namespace is created (labelled trr9008-created=true) and
#                           deleted only when it is absent
#   ./emulate_k8s.sh gap    node-local bypass demonstration (read-only)
#   ./emulate_k8s.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to write
# admissionregistration objects and apps workloads, and audit logging at Request
# level for admission-object creates and deletes and the apps group, and at
# RequestResponse for admission-object updates and patches (the C merge and json
# variants are graded only from responseObject); see
# detections/k8s/audit-policy-apiserver.yaml. The gap test needs node
# access (docker exec on kind); set TRR9008_NODE for a non-kind lab.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${TRR9008_NAMESPACE:-trr9008}"
NODE="${TRR9008_NODE:-apiserver-control-plane}"
# Procedure D2's namespace: Kyverno's default install namespace. Fixed, because the
# precise rule and the validator gate list only the engines' default namespaces.
ENFORCER_NS="kyverno"

log() { printf '[trr9008] %s\n' "$*" >&2; }

cleanup() {
  log "cleanup: removing every trr9008- object"
  kubectl delete validatingwebhookconfiguration trr9008-vwc trr9008-neuter trr9008-neuter-merge \
    trr9008-neuter-json trr9008-neuter-const trr9008-neuter-nssel --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete mutatingwebhookconfiguration trr9008-mwc --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$ENFORCER_NS" delete deployment trr9008-enforcer-standin --ignore-not-found >/dev/null 2>&1 || true
  # Only a namespace that d2 created carries this label; a kyverno namespace that
  # existed before the test has no such label and is kept.
  kubectl delete namespace -l trr9008-created=true --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A — delete a ValidatingWebhookConfiguration.
procedure_a() {
  log "A: apply then delete validatingwebhookconfiguration trr9008-vwc"
  kubectl apply -f "$SCRIPT_DIR/k8s-vwc.yaml" >/dev/null 2>&1 || true
  kubectl delete validatingwebhookconfiguration trr9008-vwc --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure B — delete a MutatingWebhookConfiguration.
procedure_b() {
  log "B: apply then delete mutatingwebhookconfiguration trr9008-mwc"
  kubectl apply -f "$SCRIPT_DIR/k8s-mwc.yaml" >/dev/null 2>&1 || true
  kubectl delete mutatingwebhookconfiguration trr9008-mwc --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure C — neuter a webhook config in place. Apply an "enforcing" (failurePolicy
# Fail) harmless config, then merge-patch it to failurePolicy Ignore + rules [] so the
# request body carries the neuter markers the severity rule grades (verb=patch).
procedure_c() {
  log "C: apply trr9008-neuter (enforcing), then neuter it (failurePolicy Ignore, rules [])"
  kubectl apply -f "$SCRIPT_DIR/k8s-neuter-vwc.yaml" >/dev/null 2>&1 || true
  kubectl patch validatingwebhookconfiguration trr9008-neuter --type=merge -p \
    '{"webhooks":[{"name":"w.trr9008.example.com","admissionReviewVersions":["v1"],"sideEffects":"None","failurePolicy":"Ignore","clientConfig":{"service":{"namespace":"trr9008","name":"trr9008-nosvc","path":"/nope","port":443}},"rules":[]}]}' \
    >/dev/null 2>&1 || true
  kubectl delete validatingwebhookconfiguration trr9008-neuter --ignore-not-found >/dev/null 2>&1 || true
  procedure_c_variants
}

# The same harmless enforcing config under another name ($1), for one neuter variant.
_apply_neuter_copy() {
  sed "s/^  name: trr9008-neuter\$/  name: $1/" "$SCRIPT_DIR/k8s-neuter-vwc.yaml" \
    | kubectl apply -f - >/dev/null 2>&1 || true
}

# Procedure C, more request shapes of the same in-place neuter. Each runs on its own
# harmless config (rules match only the bogus trr9008.example.com group), so the
# validator proves each shape on its own object name. The audit policy logs these
# patches at RequestResponse, so responseObject carries the stored object after each.
#   merge  - a JSON merge patch replaces the whole webhooks list with a webhook that
#            has no rules key: the request body shows no neuter marker; only the
#            stored object shows that the webhook lost its rules.
#   json   - a JSON patch replaces the whole list, keeping rules on one webhook and
#            dropping them from a second one.
#   const  - a matchConditions entry whose CEL expression names no variable and is
#            false (1 == 2), so the webhook skips every request.
#   nssel  - a namespaceSelector that requires kubernetes.io/metadata.name to be
#            absent; the API server sets that label on every namespace.
procedure_c_variants() {
  local w='{"name":"w.trr9008.example.com","admissionReviewVersions":["v1"],"sideEffects":"None","clientConfig":{"service":{"namespace":"trr9008","name":"trr9008-nosvc","path":"/nope","port":443}}'
  local r='"rules":[{"apiGroups":["trr9008.example.com"],"apiVersions":["v1"],"operations":["CREATE"],"resources":["widgets"],"scope":"Namespaced"}]'
  log "C: merge patch replaces the webhooks list of trr9008-neuter-merge with a webhook without rules"
  _apply_neuter_copy trr9008-neuter-merge
  kubectl patch validatingwebhookconfiguration trr9008-neuter-merge --type=merge \
    -p "{\"webhooks\":[${w}}]}" >/dev/null 2>&1 || true
  log "C: JSON patch replaces the webhooks list of trr9008-neuter-json, dropping rules from one webhook"
  _apply_neuter_copy trr9008-neuter-json
  kubectl patch validatingwebhookconfiguration trr9008-neuter-json --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/webhooks\",\"value\":[${w},${r}},${w/w.trr9008/w2.trr9008}}]}]" >/dev/null 2>&1 || true
  log "C: add a constant-false matchCondition (1 == 2) to trr9008-neuter-const"
  _apply_neuter_copy trr9008-neuter-const
  kubectl patch validatingwebhookconfiguration trr9008-neuter-const --type=merge \
    -p '{"webhooks":[{"name":"w.trr9008.example.com","admissionReviewVersions":["v1"],"sideEffects":"None","clientConfig":{"service":{"namespace":"trr9008","name":"trr9008-nosvc","path":"/nope","port":443}},"rules":[{"apiGroups":["trr9008.example.com"],"apiVersions":["v1"],"operations":["CREATE"],"resources":["widgets"],"scope":"Namespaced"}],"matchConditions":[{"name":"never","expression":"1 == 2"}]}]}' \
    >/dev/null 2>&1 || true
  log "C: set a namespaceSelector on trr9008-neuter-nssel that matches no namespace"
  _apply_neuter_copy trr9008-neuter-nssel
  kubectl patch validatingwebhookconfiguration trr9008-neuter-nssel \
    -p '{"webhooks":[{"name":"w.trr9008.example.com","namespaceSelector":{"matchExpressions":[{"key":"kubernetes.io/metadata.name","operator":"DoesNotExist"}]}}]}' \
    >/dev/null 2>&1 || true
  kubectl delete validatingwebhookconfiguration trr9008-neuter-merge trr9008-neuter-json \
    trr9008-neuter-const trr9008-neuter-nssel --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure D — remove a stand-in for the enforcer's workload (delete + scale-to-zero).
# Uses a harmless pause pod, NEVER a real Gatekeeper/Kyverno/Falco workload. Two
# scale-to-zero shapes: kubectl scale writes the deployments/scale subresource (the audit
# policy lists it at Request, so its body is logged), and kubectl patch writes
# spec.replicas on the deployments resource.
procedure_d() {
  kubectl get namespace "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS" >/dev/null 2>&1 || true
  log "D: create stand-in deployment trr9008-deploy, scale it to zero (scale, then patch), then delete it"
  kubectl -n "$NS" create deployment trr9008-deploy \
    --image=registry.k8s.io/pause:3.9 --replicas=1 >/dev/null 2>&1 || true
  kubectl -n "$NS" scale deployment trr9008-deploy --replicas=0 >/dev/null 2>&1 || true
  kubectl -n "$NS" patch deployment trr9008-deploy -p '{"spec":{"replicas":0}}' >/dev/null 2>&1 || true
  kubectl -n "$NS" delete deployment trr9008-deploy --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure D, in a policy engine's default namespace (kyverno), for the precise rule
# k8s_enforcer_workload_removed.yml. The stand-in is a harmless pause Deployment named
# trr9008-enforcer-standin; this NEVER touches a real Kyverno workload. Two kubectl scale
# shapes: --current-replicas=1 makes kubectl read the Scale object and write it back with
# an update (PUT) of deployments/scale, whose audit record holds the Scale encoded again
# (spec.replicas is omitempty, so the 0 is not in the record); the plain form then writes
# a merge patch of spec.replicas 0. The atomic creates the kyverno namespace only when it
# is absent, and deletes it only when it created it: that delete is the precise rule's
# namespace branch. A cluster that already has a kyverno namespace keeps it. The
# namespace the atomic creates carries the label trr9008-created=true, so cleanup (and
# the Atomic Red Team cleanup_command) can remove it after an interrupted run.
procedure_d2() {
  local created_ns=0 phase
  # A kyverno namespace that an earlier run deleted can still be terminating. Wait for
  # it to go, so that this run creates (and deletes) its own namespace.
  phase="$(kubectl get namespace "$ENFORCER_NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" = "Terminating" ]; then
    log "D2: namespace $ENFORCER_NS is terminating; wait for it to go"
    kubectl wait --for=delete "namespace/$ENFORCER_NS" --timeout=120s >/dev/null 2>&1 || true
  fi
  if ! kubectl get namespace "$ENFORCER_NS" >/dev/null 2>&1; then
    kubectl create -f - >/dev/null 2>&1 <<EOF && created_ns=1 || true
apiVersion: v1
kind: Namespace
metadata:
  name: $ENFORCER_NS
  labels:
    trr9008-created: "true"
EOF
  fi
  phase="$(kubectl get namespace "$ENFORCER_NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" != "Active" ]; then
    log "D2: namespace $ENFORCER_NS is not active (phase '${phase:-absent}'); D2 skipped"
    return 0
  fi
  log "D2: create stand-in deployment trr9008-enforcer-standin in namespace $ENFORCER_NS, scale it to zero (update, then patch), then delete it"
  kubectl -n "$ENFORCER_NS" create deployment trr9008-enforcer-standin \
    --image=registry.k8s.io/pause:3.9 --replicas=1 >/dev/null 2>&1 || true
  kubectl -n "$ENFORCER_NS" scale deployment trr9008-enforcer-standin \
    --current-replicas=1 --replicas=0 >/dev/null 2>&1 || true
  kubectl -n "$ENFORCER_NS" scale deployment trr9008-enforcer-standin --replicas=0 >/dev/null 2>&1 || true
  kubectl -n "$ENFORCER_NS" delete deployment trr9008-enforcer-standin --ignore-not-found >/dev/null 2>&1 || true
  if [ "$created_ns" = 1 ]; then
    log "D2: delete namespace $ENFORCER_NS (the atomic created it)"
    kubectl delete namespace "$ENFORCER_NS" --ignore-not-found --timeout=60s >/dev/null 2>&1 || true
  else
    log "D2: namespace $ENFORCER_NS existed before the atomic; it is kept"
  fi
}

# Gap — the node-local bypass. An attacker with control-plane node access can disable
# admission WITHOUT an admissionregistration write (edit the kube-apiserver static
# manifest --disable-admission-plugins, or tamper with the webhook TLS material). None
# of that is an API write, so the audit chokepoint is blind. Read-only demonstration.
procedure_gap() {
  if [ -n "${TRR9008_NODE_EXEC:-}" ]; then
    log "gap: show the kube-apiserver manifest path on the node (custom exec, read-only)"
    $TRR9008_NODE_EXEC 'ls -l /etc/kubernetes/manifests/kube-apiserver.yaml 2>/dev/null || true' || true
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "gap: show the kube-apiserver manifest path on node $NODE (read-only)"
    docker exec "$NODE" sh -c 'ls -l /etc/kubernetes/manifests/kube-apiserver.yaml 2>/dev/null || true' || true
  else
    log "gap: no node access (docker/TRR9008_NODE_EXEC) — skipping the bypass demonstration"
    return 0
  fi
  log "gap: editing that manifest to drop admission plugins emits NO admissionregistration audit event -> node sensor only"
}

run_one() {
  case "$1" in
    a) procedure_a ;;
    b) procedure_b ;;
    c) procedure_c ;;
    d) procedure_d ;;
    d2) procedure_d2 ;;
    gap) procedure_gap ;;
    *) log "unknown item: $1 (use a|b|c|d|d2|gap|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d d2 gap; do run_one "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
