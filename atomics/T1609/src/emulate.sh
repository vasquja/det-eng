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

# ---- procedure bookkeeping (shared shape across the det-eng Kubernetes atomics) ----
# A procedure's ACTION must succeed. `must` runs it, shows its stderr on failure,
# and returns its exit code. `run_proc` times each procedure, appends one ledger
# line (DETENG_LEDGER, set by CI; unset = no ledger) and records a failure without
# stopping the run, so every procedure is attempted and the run exits 1 at the end
# naming the failures. Cleanup stays best-effort (`|| true`): a failed cleanup must
# not hide a result, and a retried write would hide the first failure, so writes are
# never retried (readiness comes from the workflow instead).
TRR="TRR9002"
FAILED=()
now() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }
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
  start="$(now)"
  "procedure_$p" || rc=$?
  end="$(now)"
  if [ -n "${DETENG_LEDGER:-}" ]; then
    printf '{"trr":"%s","procedure":"%s","start":"%s","end":"%s","exit":%d,"expect":0}\n' \
      "$TRR" "$(printf '%s' "$p" | tr '[:lower:]' '[:upper:]')" "$start" "$end" "$rc" \
      >> "$DETENG_LEDGER"
  fi
  if [ "$rc" -ne 0 ]; then
    FAILED+=("$p")
    [ -n "${GITHUB_ACTIONS:-}" ] && \
      echo "::error title=${TRR} procedure ${p}::procedure ${p} failed (exit ${rc})"
  fi
  return 0
}

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
  must env KUBECTL_REMOTE_COMMAND_WEBSOCKETS=true \
    kubectl -n "$NS" exec "$POD" -c "$CONTAINER" -- "${CMD[@]}" || return 1
  log "A: exec over SPDY (fallback) -> audit verb should be 'create'"
  must env KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false \
    kubectl -n "$NS" exec "$POD" -c "$CONTAINER" -- "${CMD[@]}" || return 1
}

# Procedure B — attach to the running main process. No new process starts; the
# stream connects to the output of the container's existing main process.
# `kubectl attach` without -i asks for stdout and stderr with no TTY, so the
# target container must have tty: false (target-pod.yaml): the kubelet takes the
# TTY setting from the container spec, and the runtime refuses a TTY attach that
# also asks for stderr, at once and with a non-zero kubectl exit. A connected
# attach streams until the container stops, and the audit code (101) does not
# show whether the stream was set up (the API server stamps 101 at the hijack).
# So this holds the attach for a moment and then stops it: an attach still
# running at the hold has connected and is killed (success); one that exits
# non-zero before the hold did not connect (a failure: forbidden, the pod is
# gone, or the runtime refused the stream).
procedure_b() {
  log "B: attach to the running container (hold the stream, then stop it)"
  kubectl -n "$NS" attach "$POD" -c "$CONTAINER" >/dev/null 2>&1 &
  local pid=$! rc=0
  sleep 2
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 0
  fi
  wait "$pid" || rc=$?
  [ "$rc" -eq 0 ] && return 0
  log "B: attach exited (code $rc) before it connected: no attach stream was set up"
  return "$rc"
}

# Procedure C — add an ephemeral debug container to the running pod.
procedure_c() {
  log "C: add an ephemeral debug container (kubectl debug)"
  must kubectl -n "$NS" debug "$POD" \
    --image=busybox:1.36 --container=trr9002-debug \
    -- "${CMD[@]}" || return 1
}

# Procedure D — exec through the API server node proxy.
# The request goes to nodes/<node>/proxy and names the kubelet /run endpoint,
# which the kubelet registers for POST only (pkg/kubelet/server/server.go). So
# the request is a POST: `kubectl create --raw` POSTs (kubectl create.go RawPost),
# the empty -f body is the command's stdin. A GET would get 405 and never run the
# command. The audit record shows objectRef resource=nodes subresource=proxy,
# verb=create, with the run path in requestURI — NOT pods/exec. The kubelet runs
# the benign command and returns its output, which for `id` holds 'uid='.
procedure_d() {
  local node uid path out
  node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')" || return 1
  uid="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.uid}')" || return 1
  # kubelet /run endpoint: /run/<namespace>/<podName>/<containerName>?cmd=...
  path="/api/v1/nodes/${node}/proxy/run/${NS}/${POD}/${CONTAINER}?cmd=id"
  log "D: run via node proxy (POST to the kubelet /run) -> nodes/proxy, requestURI has /run/"
  if ! out="$(kubectl create --raw "$path" -f /dev/null 2>&1)"; then
    log "D: create --raw failed: $out"
    return 1
  fi
  if ! printf '%s\n' "$out" | grep -q 'uid='; then
    log "D: the kubelet /run output has no 'uid=' (the command did not run): $out"
    return 1
  fi
  log "D: (node=$node pod-uid=$uid) ran id via POST /run; output has uid="
}

# Procedure E — direct kubelet access (detection-gap demonstration).
# This does NOT go through the API server, so the API server audit log cannot
# record it. To show the gap safely, call the kubelet's READ-ONLY /pods
# endpoint directly from inside the control-plane node, using the node's
# existing kubelet client certificate. A command-execution call to the same
# kubelet API would be just as invisible to the API server audit log — which is
# why Strategy 4 needs a node-level sensor, not the audit log.
procedure_e() {
  local container="${TRR9002_CP_CONTAINER:-trr9002-control-plane}" skip=""
  if ! command -v docker >/dev/null 2>&1; then
    skip="docker is not available"
  elif ! docker ps --format '{{.Names}}' | grep -qx "$container"; then
    skip="the control-plane container $container is not running (set TRR9002_CP_CONTAINER)"
  fi
  if [ -n "$skip" ]; then
    # Under CI or with a ledger, a skip is a failure: the ledger row would
    # otherwise claim the gap was tested (exit 0) when no call reached the kubelet.
    if [ -n "${DETENG_LEDGER:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ]; then
      log "E: FAILED — $skip; the gap was NOT tested (no call reached the kubelet)"
      return 3
    fi
    log "E: $skip — skipping the kind-local gap demonstration (not tested)"
    return 0
  fi
  log "E: read-only call straight to the kubelet API (not via the API server)"
  # The apiserver-kubelet-client cert exists on the control-plane node already;
  # it is what the API server itself uses to reach the kubelet. curl -f fails on a
  # non-2xx, so a changed cert path or a kubelet that is down is a failure, not a
  # silent pass: the Procedure E gap claim is only meaningful if the call reached
  # the kubelet and got an answer.
  #
  # Server TLS: kind sets no serverTLSBootstrap and no tlsCertFile, so the kubelet
  # serves a self-signed certificate (cmd/kubelet/app/server.go InitializeTLS):
  # /var/lib/kubelet/pki/kubelet.crt holds that certificate followed by its own
  # CA, and its only name is the node's host name (DNS SAN, no IP). It is not
  # signed by the cluster CA and does not name 127.0.0.1, so the call checks the
  # kubelet against that bundle, by the host name, pinned to 127.0.0.1 with
  # --resolve. --noproxy keeps a proxy setting in the node from taking the call.
  must docker exec "$container" sh -c '
    h="$(uname -n | tr "[:upper:]" "[:lower:]")"
    bundle=/var/lib/kubelet/pki/kubelet.crt
    [ -s "$bundle" ] || { echo "no kubelet serving certificate at $bundle" >&2; exit 3; }
    curl -fsS --noproxy "*" --max-time 10 \
      --cacert "$bundle" --resolve "${h}:10250:127.0.0.1" \
      --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt \
      --key /etc/kubernetes/pki/apiserver-kubelet-client.key \
      "https://${h}:10250/pods" >/dev/null
  ' || return 1
  log "E: done — the kubelet answered; expect NO API server audit event for this call"
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
  local node sa="trr9002-node-reader" token server ca_file p rc=0
  local tls_line tok_file kc
  node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')" || return 1
  log "F: create ServiceAccount, ClusterRole (nodes/proxy get) and binding for $sa"
  must kubectl -n "$NS" create serviceaccount "$sa" || rc=1
  must kubectl create clusterrole "$sa" \
    --verb=get --resource=nodes/proxy || rc=1
  must kubectl create clusterrolebinding "$sa" \
    --clusterrole="$sa" --serviceaccount="${NS}:${sa}" || rc=1

  token="$(kubectl -n "$NS" create token "$sa" 2>/dev/null)" || rc=1
  server="$(kubectl config view --minify --raw \
    -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)" || rc=1
  ca_file="$(mktemp)"
  kubectl config view --minify --raw \
    -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' 2>/dev/null \
    | base64 -d > "$ca_file" 2>/dev/null || true
  if [ -s "$ca_file" ]; then
    tls_line="certificate-authority: $ca_file"
  else
    tls_line="insecure-skip-tls-verify: true"
  fi

  # Read as the service account only when the setup held and a token was minted;
  # otherwise the reads would fail for the wrong reason. The token is never on a
  # command line or in a log line: a 0600 kubeconfig reads it from a 0600 tokenFile,
  # so `must` (which logs the failed command) and `ps` show only the file paths.
  if [ "$rc" -eq 0 ] && [ -n "$token" ]; then
    tok_file="$(umask 077; mktemp)"
    kc="$(umask 077; mktemp)"
    printf '%s' "$token" > "$tok_file"
    cat > "$kc" <<KUBECONFIG
apiVersion: v1
kind: Config
clusters:
- name: lab
  cluster:
    server: $server
    $tls_line
users:
- name: $sa
  user:
    tokenFile: $tok_file
contexts:
- name: lab
  context:
    cluster: lab
    user: $sa
current-context: lab
KUBECONFIG
    for p in "/api/v1/nodes/${node}/proxy/runningpods/" \
             "/api/v1/nodes/${node}/proxy/pods"; do
      log "F: read kubelet ${p##*/proxy/} via nodes/proxy as $sa"
      must kubectl --kubeconfig="$kc" --request-timeout=30s get --raw "$p" || rc=1
    done
    rm -f "$kc" "$tok_file"
  else
    log "F: setup did not complete (rc=$rc, token $([ -n "$token" ] && echo set || echo empty)); skipping the reads"
  fi
  token=""

  log "F: delete the RBAC objects"
  kubectl delete clusterrolebinding "$sa" >/dev/null 2>&1 || true
  kubectl delete clusterrole "$sa" >/dev/null 2>&1 || true
  kubectl -n "$NS" delete serviceaccount "$sa" >/dev/null 2>&1 || true
  rm -f "$ca_file"
  log "F: (node=$node) — checkpoint not called live; see TRR9002 Procedure F"
  return "$rc"
}

run_one() {
  case "$1" in
    a|b|c|d|e|f) run_proc "$1" ;;
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
  if [ "${#FAILED[@]}" -gt 0 ]; then
    log "emulation FAILED: procedure(s) ${FAILED[*]}"
    exit 1
  fi
  log "emulation complete: $which"
}

main "$@"
