#!/usr/bin/env bash
# TRR9002 — behavioral emulation for T1609 (Command Execution in a Running
# Container), Kubernetes.
#
# Procedures A to D run a HARMLESS command (`id`) through a different Kubernetes
# control path, so the API server writes the audit events that the paired Sigma
# rules key on. Procedure E makes one read-only kubelet call. Procedure F runs no
# command: it creates a temporary service account that holds only `get` on
# nodes/proxy, reads two kubelet pod lists through the node proxy (the output is
# discarded), and deletes the RBAC objects. No exploit, no persistence; no data
# is kept. The cluster is a throwaway kind cluster and is deleted after the run.
#
# Run ONE procedure:
#   ./emulate.sh a    exec through the API server (WebSocket, then SPDY)
#   ./emulate.sh b    attach through the API server
#   ./emulate.sh c    ephemeral debug container
#   ./emulate.sh d    exec through the API server node proxy
#   ./emulate.sh e    direct kubelet access (detection-gap demonstration)
#   ./emulate.sh f    kubelet pod read through the API server node proxy
#   ./emulate.sh all  every procedure, in order
#
# Prerequisites: a reachable cluster (kubectl works) with the TRR9002 target
# pod applied (atomics/T1609/src/target-pod.yaml), and cluster-admin rights —
# the same rights an operator uses, so the point is the behavior. Only
# Procedure F grants a privilege (nodes/proxy get, to its own temporary service
# account), and it deletes that grant before it returns.
set -euo pipefail

NS="${TRR9002_NAMESPACE:-default}"
POD="${TRR9002_POD:-trr9002-target}"
CONTAINER="${TRR9002_CONTAINER:-app}"
CMD=(id)   # the one benign command procedures A to D run

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

# Procedure F — kubelet pod read or checkpoint through the API server node proxy.
# A service account that holds only `get` on nodes/proxy reads the kubelet
# /runningpods/ and /pods endpoints through the API server node proxy. This is
# the main step of Stratus Red Team k8s.privilege-escalation.nodes-proxy. The
# audit record shows objectRef resource=nodes, subresource=proxy, verb=get, with
# the kubelet endpoint in requestURI — not pods/exec, and not pods list/get.
#
# The reads use a token minted for the service account (kubectl create token),
# sent with no client certificate, so user.username in the audit record is the
# service account. A client certificate would authenticate first and hide the SA.
#
# /checkpoint (a POST, audit verb create) is NOT called: it writes a container
# memory and file-system dump to disk on the node. It is covered by the sidecar
# cases for k8s_node_proxy_kubelet_api.yml instead. See TRR9002 Procedure F.
procedure_f() {
  local node sa="trr9002-node-reader" token server ca_file p
  local tls_args
  node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"
  log "F: create ServiceAccount, ClusterRole (nodes/proxy get) and binding for $sa"
  kubectl -n "$NS" create serviceaccount "$sa" >/dev/null 2>&1 || true
  kubectl create clusterrole "$sa" \
    --verb=get --resource=nodes/proxy >/dev/null 2>&1 || true
  kubectl create clusterrolebinding "$sa" \
    --clusterrole="$sa" --serviceaccount="${NS}:${sa}" >/dev/null 2>&1 || true

  token="$(kubectl -n "$NS" create token "$sa" 2>/dev/null || true)"
  server="$(kubectl config view --minify --raw \
    -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"
  ca_file="$(mktemp)"
  kubectl config view --minify --raw \
    -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' 2>/dev/null \
    | base64 -d > "$ca_file" 2>/dev/null || true
  if [ -s "$ca_file" ]; then
    tls_args="--certificate-authority=$ca_file"
  else
    tls_args="--insecure-skip-tls-verify=true"
  fi

  for p in "/api/v1/nodes/${node}/proxy/runningpods/" \
           "/api/v1/nodes/${node}/proxy/pods"; do
    log "F: read kubelet ${p##*/proxy/} via nodes/proxy as $sa"
    kubectl --kubeconfig=/dev/null --server="$server" "$tls_args" \
      --token="$token" --request-timeout=30s get --raw "$p" >/dev/null 2>&1 || true
  done

  log "F: delete the RBAC objects"
  kubectl delete clusterrolebinding "$sa" >/dev/null 2>&1 || true
  kubectl delete clusterrole "$sa" >/dev/null 2>&1 || true
  kubectl -n "$NS" delete serviceaccount "$sa" >/dev/null 2>&1 || true
  rm -f "$ca_file"
  log "F: (node=$node) — checkpoint not called live; see TRR9002 Procedure F"
}

run_one() {
  case "$1" in
    a) procedure_a ;;
    b) procedure_b ;;
    c) procedure_c ;;
    d) procedure_d ;;
    e) procedure_e ;;
    f) procedure_f ;;
    *) log "unknown procedure: $1 (use a|b|c|d|e|f|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  ensure_target
  if [ "$which" = "all" ]; then
    for p in a b c d e f; do run_one "$p"; done
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
