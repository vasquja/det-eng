#!/usr/bin/env bash
# Benign Kubernetes operator workload for the live false-positive slice.
#
# Runs on the kind cluster in validate-apiserver-detections right BEFORE the
# pre-emulation audit log is captured, so that log holds a fresh cluster's own
# bootstrap traffic PLUS ordinary operator activity. score_benign.py then scores
# it as a live benign slice (shadow only), and the validator's --expect-miss
# negative control runs over it too.
#
# The activity is deliberately ADJACENT to the Kubernetes rules, through the
# commands an operator, a CI pipeline or a developer really runs:
#   T1053.007 batch write       a CronJob, and a one-off Job created from it
#   T1098.006 RBAC write        a RoleBinding of the read-only `view` ClusterRole
#                               to a CI service account (never admin/edit, never a
#                               group, never a wildcard)
#   T1552.007 secret read/token  kubectl writes and reads a Secret in its own
#                               namespace; a short-lived token for the CI account
#   T1611 controller template   a plain Deployment (no host access), rollout
#                               restart, set env, scale
#   T1546/T1685 admission       a ValidatingWebhookConfiguration that calls an
#                               IN-CLUSTER Service, failurePolicy Ignore, scoped by
#                               namespaceSelector to the benign namespace only;
#                               created, exercised once, then DELETED
#   T1572 port-forward          a developer port-forward to the Deployment
#   T1609 exec                  an operator `kubectl exec` to look around
#   T1070 deletion              the Job and finally the whole namespace are deleted
#
# Isolation from the emulations that follow (the validator's gates key on them):
#   * every object lives in namespace `shop` (or is the one cluster-scoped webhook
#     `shop-policy.example.com`, deleted before the script exits);
#   * no name, namespace or value uses an emulation marker: nothing starts with
#     `trr90`, the namespaces trr9006/trr9010 are never touched, the kube-system DNS
#     ConfigMaps are only read, and nothing impersonates (no --as / --as-group);
#   * the webhook is deleted, and the namespace deleted and waited for, before exit.
# Every kubectl call runs under a timeout and its failure is logged, never fatal:
# the workload must never fail or slow down the emulation steps after it.
#
#   bash detections/benign/k8s/workload.sh
set -u

NS="shop"
WEBHOOK="shop-policy.example.com"
SA="ci-deployer"
IMG="busybox:1.36"
PF_PORT="18081"

log() { printf '[benign-k8s] %s\n' "$*"; }

# k SECONDS ARGS...: kubectl with a timeout; log a failure, never fail.
k() {
  local secs="$1"
  shift
  timeout --kill-after=5 "$secs" kubectl "$@" >/dev/null 2>&1 || log "  kubectl $1 ${2:-} exited $?"
}

delete_webhook() {
  timeout 30 kubectl delete validatingwebhookconfiguration "$WEBHOOK" \
    --ignore-not-found >/dev/null 2>&1 || true
}

# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
  log "cleanup: delete the webhook and namespace $NS (and wait for it)"
  [ -n "${PF_PID:-}" ] && kill "$PF_PID" >/dev/null 2>&1
  delete_webhook
  timeout 180 kubectl delete namespace "$NS" --ignore-not-found --wait=true \
    --timeout=170s >/dev/null 2>&1 || log "  namespace $NS not fully gone yet"
  return 0
}
trap cleanup EXIT
# A cancelled or timed-out step sends TERM/INT: exit so the EXIT trap cleans up.
trap 'exit 143' TERM INT

look_around() {
  log "look around the cluster (reads)"
  k 30 get nodes -o wide
  k 30 get pods -A
  k 30 get deployments,daemonsets -A
  k 30 api-resources
  k 30 auth can-i --list
  k 30 -n kube-system get configmap coredns -o yaml   # read only; never written here
  k 30 get validatingwebhookconfigurations,mutatingwebhookconfigurations
}

deploy_app() {
  log "namespace $NS, a web Deployment and its Service"
  k 30 create namespace "$NS"
  k 30 label namespace "$NS" team=storefront env=ci --overwrite
  # A tiny static site; the shell traps TERM so the pods stop promptly on delete.
  k 30 -n "$NS" create deployment web --image="$IMG" --replicas=2 --port=8080 \
    -- sh -c 'echo ok > /tmp/index.html; trap "exit 0" TERM; httpd -f -p 8080 -h /tmp & wait'
  k 30 -n "$NS" expose deployment web --port=80 --target-port=8080
  k 150 -n "$NS" rollout status deployment/web --timeout=140s
}

config_and_secrets() {
  log "config and secrets, written and read by kubectl in $NS"
  k 30 -n "$NS" create configmap web-config --from-literal=LOG_LEVEL=info \
    --from-literal=FEATURE_CHECKOUT_V2=false
  k 30 -n "$NS" create secret generic web-db --from-literal=DB_USER=shop \
    --from-literal=DB_PASSWORD=placeholder-not-a-real-secret
  k 30 -n "$NS" get secrets
  k 30 -n "$NS" get secret web-db
  k 30 -n "$NS" describe secret web-db
  k 30 -n "$NS" patch configmap web-config --type=merge -p '{"data":{"LOG_LEVEL":"debug"}}'
}

day2_ops() {
  log "day-2 operations: set env, rollout restart, scale, logs, events"
  k 30 -n "$NS" set env deployment/web LOG_LEVEL=debug
  k 150 -n "$NS" rollout status deployment/web --timeout=140s
  k 30 -n "$NS" rollout restart deployment/web
  k 150 -n "$NS" rollout status deployment/web --timeout=140s
  k 30 -n "$NS" scale deployment/web --replicas=1
  k 30 -n "$NS" rollout history deployment/web
  k 30 -n "$NS" logs deployment/web --tail=20
  k 30 -n "$NS" get events --sort-by=.lastTimestamp
  k 30 -n "$NS" describe deployment web
}

ci_access() {
  log "CI access: service account, read-only RoleBinding to view, short-lived token"
  k 30 -n "$NS" create serviceaccount "$SA"
  k 30 -n "$NS" create rolebinding "${SA}-view" --clusterrole=view \
    --serviceaccount="${NS}:${SA}"
  k 30 auth can-i list pods -n "$NS"
  # The token is minted and discarded (stdout goes to /dev/null).
  k 30 -n "$NS" create token "$SA" --duration=10m
}

batch_work() {
  log "batch work: a nightly CronJob and one manual run of it"
  k 30 -n "$NS" create cronjob nightly-report --image="$IMG" \
    --schedule="17 3 * * *" -- /bin/sh -c 'date; echo report done'
  k 30 -n "$NS" create job report-manual --from=cronjob/nightly-report
  k 90 -n "$NS" wait --for=condition=complete job/report-manual --timeout=80s
  k 30 -n "$NS" logs job/report-manual
  k 60 -n "$NS" delete job report-manual --wait=true
}

admission_webhook() {
  log "admission: an in-cluster ValidatingWebhookConfiguration scoped to $NS, then delete it"
  timeout 30 kubectl apply -f - >/dev/null 2>&1 <<EOF || log "  webhook apply failed"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: ${WEBHOOK}
  labels:
    team: storefront
webhooks:
  - name: ${WEBHOOK}
    clientConfig:
      service:
        namespace: ${NS}
        name: policy-webhook
        path: /validate
        port: 443
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["configmaps"]
        scope: "Namespaced"
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: ${NS}
    failurePolicy: Ignore
    sideEffects: None
    admissionReviewVersions: ["v1"]
    timeoutSeconds: 2
EOF
  # Exercise it once: the Service has no backend, and failurePolicy Ignore admits.
  k 30 -n "$NS" create configmap web-flags --from-literal=BANNER=on
  delete_webhook
}

developer_access() {
  log "developer access: port-forward to the Deployment, and an exec to look around"
  if command -v kubectl >/dev/null 2>&1; then
    kubectl -n "$NS" port-forward deployment/web "${PF_PORT}:8080" >/dev/null 2>&1 &
    PF_PID=$!
    sleep 3
    timeout 10 curl -sS -o /dev/null "http://127.0.0.1:${PF_PORT}/" >/dev/null 2>&1 || true
    kill "$PF_PID" >/dev/null 2>&1 || true
    wait "$PF_PID" 2>/dev/null || true
    PF_PID=""
  fi
  k 30 -n "$NS" exec deployment/web -- ls /tmp
  k 30 -n "$NS" exec deployment/web -- cat /etc/hostname
}

main() {
  command -v kubectl >/dev/null 2>&1 || { log "kubectl not found; nothing to do"; exit 0; }
  log "start $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  delete_webhook  # a leftover from an earlier run must not linger
  look_around
  deploy_app
  config_and_secrets
  day2_ops
  ci_access
  batch_work
  admission_webhook
  developer_access
  log "done $(date -u +%Y-%m-%dT%H:%M:%SZ); cleanup follows"
}

main "$@"
exit 0
