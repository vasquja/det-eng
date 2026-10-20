#!/usr/bin/env bash
# TRR9008 — behavioral emulation for T1685 (Disable or Modify
# Tools), Kubernetes admission control. (The Linux io_uring telemetry-evasion atomic
# for T1685 is the separate C program in this folder; this is the Kubernetes
# admission-control half.)
#
# Each procedure DISABLES a harmless, throwaway admission object (NEVER a real
# Gatekeeper/Kyverno/Falco webhook), so the API server writes the audit events the
# paired Sigma rules key on. Every object is named trr9008-* so a validator matches
# the emulation's own events. The webhooks are no-ops (failurePolicy Ignore, rules
# scoped to a bogus apiGroup) that cannot affect any real admission request.
#
# Run ONE procedure:
#   ./emulate_k8s.sh a      delete a ValidatingWebhookConfiguration
#   ./emulate_k8s.sh b      delete a MutatingWebhookConfiguration
#   ./emulate_k8s.sh c      neuter a webhook config in place (failurePolicy Ignore, rules []), then
#                           four more neuters of their own configs: a merge patch and a JSON
#                           patch that replace the webhooks list and drop rules, a constant
#                           matchCondition, and a namespaceSelector that matches no namespace
#   ./emulate_k8s.sh d      scale-to-zero (kubectl scale, then patch) and delete a stand-in enforcer Deployment
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

log() { printf '[trr9008] %s\n' "$*" >&2; }

cleanup() {
  log "cleanup: removing every trr9008- object"
  kubectl delete validatingwebhookconfiguration trr9008-vwc trr9008-neuter trr9008-neuter-merge \
    trr9008-neuter-json trr9008-neuter-const trr9008-neuter-nssel --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete mutatingwebhookconfiguration trr9008-mwc --ignore-not-found >/dev/null 2>&1 || true
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
