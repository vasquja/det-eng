#!/usr/bin/env bash
# TRR9002 — behavioral emulation for T1609 (Command Execution in a Running
# Container), Kubernetes.
#
# Each procedure runs a HARMLESS command (`id`) through a different Kubernetes
# control path, so the API server writes the audit events that the paired Sigma
# rules key on. No exploit, no persistence, no data access. The cluster is a
# throwaway kind cluster and is deleted after the run.
#
# Run ONE procedure:
#   ./emulate.sh a    exec through the API server (WebSocket, then SPDY)
#   ./emulate.sh b    attach through the API server
#   ./emulate.sh c    ephemeral debug container
#   ./emulate.sh d    exec through the API server node proxy
#   ./emulate.sh e    direct kubelet access (detection-gap demonstration)
#   ./emulate.sh all  every procedure, in order
#
# Prerequisites: a reachable cluster (kubectl works) with the TRR9002 target
# pod applied (atomics/T1609/src/target-pod.yaml), and cluster-admin rights —
# the same rights an operator uses, so the point is the behavior, not a
# privilege the test grants itself.
set -euo pipefail

NS="${TRR9002_NAMESPACE:-default}"
POD="${TRR9002_POD:-trr9002-target}"
CONTAINER="${TRR9002_CONTAINER:-app}"
CMD=(id)   # the one benign command every procedure runs

log() { printf '[trr9002] %s\n' "$*" >&2; }

ensure_target() {
  if ! kubectl -n "$NS" get pod "$POD" >/dev/null 2>&1; then
    log "target pod $NS/$POD not found — apply atomics/T1609/src/target-pod.yaml"
    exit 1
  fi
  kubectl -n "$NS" wait --for=condition=Ready "pod/$POD" --timeout=90s >/dev/null
}

# Procedure A — exec through the API server.
# Run once over WebSocket (the kubectl default since v1.31; recorded verb=get)
# and once over SPDY (recorded verb=create). Showing both verbs for the same
# action is the key finding of the TRR.
procedure_a() {
  log "A: exec over WebSocket (default) -> audit verb should be 'get'"
  KUBECTL_REMOTE_COMMAND_WEBSOCKETS=true \
    kubectl -n "$NS" exec "$POD" -c "$CONTAINER" -- "${CMD[@]}" >/dev/null || true
  log "A: exec over SPDY (fallback) -> audit verb should be 'create'"
  KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false \
    kubectl -n "$NS" exec "$POD" -c "$CONTAINER" -- "${CMD[@]}" >/dev/null || true
}

# Procedure B — attach to the running main process. No new process starts; the
# stream connects to the container's existing `sh`. A short timeout ends it.
procedure_b() {
  log "B: attach to the running container"
  # `attach` with no stdin returns once streams are set up; cap it anyway.
  timeout 15 kubectl -n "$NS" attach "$POD" -c "$CONTAINER" >/dev/null 2>&1 || true
}

# Procedure C — add an ephemeral debug container to the running pod.
procedure_c() {
  log "C: add an ephemeral debug container (kubectl debug)"
  kubectl -n "$NS" debug "$POD" \
    --image=busybox:1.36 --container=trr9002-debug \
    -- "${CMD[@]}" >/dev/null 2>&1 || true
}

# Procedure D — exec through the API server node proxy.
# The request goes to nodes/<node>/proxy and names the kubelet /run endpoint.
# The audit record shows objectRef resource=nodes subresource=proxy, with the
# exec path in requestURI — NOT pods/exec. Uses the read-side kubectl raw API
# with a benign command.
procedure_d() {
  local node uid path
  node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"
  uid="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.uid}')"
  # kubelet /run endpoint: /run/<namespace>/<podName>/<containerName>?cmd=...
  path="/api/v1/nodes/${node}/proxy/run/${NS}/${POD}/${CONTAINER}?cmd=id"
  log "D: run via node proxy -> nodes/proxy, requestURI has /run/"
  kubectl get --raw "$path" >/dev/null 2>&1 || true
  log "D: (node=$node pod-uid=$uid)"
}

# Procedure E — direct kubelet access (detection-gap demonstration).
# This does NOT go through the API server, so the API server audit log cannot
# record it. To show the gap safely, call the kubelet's READ-ONLY /pods
# endpoint directly from inside the control-plane node, using the node's
# existing kubelet client certificate. A command-execution call to the same
# kubelet API would be just as invisible to the API server audit log — which is
# why Strategy 4 needs a node-level sensor, not the audit log.
procedure_e() {
  local container="${TRR9002_CP_CONTAINER:-trr9002-control-plane}"
  if ! command -v docker >/dev/null 2>&1; then
    log "E: docker not available — skipping the kind-local gap demonstration"
    return 0
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx "$container"; then
    log "E: control-plane container $container not found — skipping"
    return 0
  fi
  log "E: read-only call straight to the kubelet API (not via the API server)"
  # The apiserver-kubelet-client cert exists on the control-plane node already;
  # it is what the API server itself uses to reach the kubelet.
  docker exec "$container" sh -c '
    curl -sS --max-time 10 \
      --cacert /etc/kubernetes/pki/ca.crt \
      --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt \
      --key /etc/kubernetes/pki/apiserver-kubelet-client.key \
      https://127.0.0.1:10250/pods >/dev/null 2>&1 || true
  ' || true
  log "E: done — expect NO API server audit event for this call"
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
  ensure_target
  if [ "$which" = "all" ]; then
    for p in a b c d e; do run_one "$p"; done
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
