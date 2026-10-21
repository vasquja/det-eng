#!/usr/bin/env bash
# TRR9026 — behavioral emulation for T1572 (Protocol Tunneling), Kubernetes pod
# port-forward.
#
# Procedures A and B open a port-forward tunnel to a throwaway pod through the API
# server, so the API server writes the pods/portforward audit event the paired Sigma
# rule keys on. Procedure C sends one un-upgraded GET to the kubelet /portForward
# endpoint through nodes/proxy: it opens no tunnel (the kubelet refuses the request),
# but the API server writes a nodes/proxy audit record that carries the requestURI the
# node-proxy rule keys on. Procedure D is a statement only (no call is made). The
# target pod is named trr9026-target so a validator matches the emulation's own events.
# The A/B tunnel is harmless: it opens a local listener, holds it for a moment, and
# closes it; no traffic is sent to the pod.
#
# Procedures A and B differ only in transport, which decides the audit verb:
#   A = SPDY (POST upgrade -> verb=create), B = WebSocket (GET upgrade -> verb=get).
# The env var KUBECTL_PORT_FORWARD_WEBSOCKETS forces the transport where the kubectl
# version honors it; whichever path fires, the verb-agnostic rule matches it.
#
# Run ONE procedure:
#   ./emulate.sh a      port-forward over SPDY      (verb=create)
#   ./emulate.sh b      port-forward over WebSocket (verb=get)
#   ./emulate.sh c      port-forward through nodes/proxy to the kubelet /portForward
#   ./emulate.sh d      direct-kubelet port-forward demonstration (read-only)
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights on pods/portforward
# (A, B) and get on nodes/proxy (C), and audit logging (see
# detections/k8s/kind-apiserver-cluster.yaml).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POD="trr9026-target"
NS="${TRR9026_NAMESPACE:-default}"

log() { printf '[trr9026] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs a procedure's action and returns its exit code (stderr shown on
# failure). `run_proc P` times procedure_P, appends one ledger line to $DETENG_LEDGER
# (set by CI; unset = no ledger) and records a failure without stopping the run, so
# `all` attempts every procedure and then exits 1 naming the failures. Cleanup keeps
# `|| true`.
TRR="TRR9026"
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

ensure_pod() {
  kubectl -n "$NS" get pod "$POD" >/dev/null 2>&1 || \
    must kubectl apply -f "$SCRIPT_DIR/target-pod.yaml" || return
  # Readiness, not the gate-matched action: it may time out without failing the step.
  kubectl -n "$NS" wait --for=condition=Ready "pod/$POD" --timeout=120s >/dev/null 2>&1 || true
}

cleanup() {
  log "cleanup: deleting pod $POD"
  kubectl -n "$NS" delete pod "$POD" --ignore-not-found --force --grace-period=0 >/dev/null 2>&1 || true
}

# Open a port-forward in the background, hold it long enough for the API server to
# write the ResponseStarted audit event, then tear it down. Its stderr goes to a
# temporary file, which is shown when the tunnel does not establish.
_portforward() {
  local localport="$1" errf
  errf="$(mktemp)"
  kubectl -n "$NS" port-forward "pod/$POD" "${localport}:8080" >/dev/null 2>"$errf" &
  local pid=$!
  sleep 3
  # The tunnel must still be up after the hold: if port-forward exited early it never
  # established, so the ResponseStarted audit record the rule keys on was not written.
  if ! kill -0 "$pid" 2>/dev/null; then
    log "port-forward exited before the 3s hold (the tunnel did not establish)"
    wait "$pid" >/dev/null 2>&1 || true
    if [ -s "$errf" ]; then sed 's/^/    /' "$errf" >&2; fi
    rm -f "$errf"
    return 1
  fi
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  rm -f "$errf"
  return 0
}

# Procedure A — SPDY transport (POST upgrade -> verb=create).
procedure_a() {
  ensure_pod || return
  log "A: port-forward to $POD over SPDY (verb=create)"
  KUBECTL_PORT_FORWARD_WEBSOCKETS=false _portforward 18080
}

# Procedure B — WebSocket transport (GET upgrade -> verb=get).
procedure_b() {
  ensure_pod || return
  log "B: port-forward to $POD over WebSocket (verb=get)"
  KUBECTL_PORT_FORWARD_WEBSOCKETS=true _portforward 18081
}

# Procedure C — port-forward through the API server node proxy (nodes/proxy).
# The request goes to nodes/<node>/proxy and names the kubelet /portForward endpoint,
# NOT pods/portforward. The audit record shows objectRef.resource=nodes,
# subresource=proxy, with the /proxy/portForward/ path (and the target pod) in
# requestURI; objectRef.name is the node, so the pod rides in requestURI. kubectl
# port-forward never uses this path; a raw client (kubeletctl, or kubectl get --raw)
# does. This GET carries no upgrade header, so the kubelet refuses the un-upgraded
# request (the tunnel does not establish and no traffic reaches the pod), but the API
# server still writes the nodes/proxy audit record the paired rule keys on. A real
# tunnel writes the same requestURI. The call is allowed to fail under set -e.
procedure_c() {
  ensure_pod || return
  local node path out rc=0
  node="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
  node="${node:-apiserver-control-plane}"
  path="/api/v1/nodes/${node}/proxy/portForward/${NS}/${POD}?port=8080"
  log "C: port-forward via node proxy -> nodes/proxy, requestURI has /proxy/portForward/ (node=$node)"
  out="$(kubectl get --raw "$path" 2>&1 >/dev/null)" || rc=$?
  # The un-upgraded GET is REFUSED by the kubelet (it requires an upgrade), and that
  # refusal is the expected outcome: the API server still writes the nodes/proxy audit
  # record the rule keys on. Encode the expectation rather than swallow it: the kubelet's
  # refusal (or an unexpected success) is fine; any other failure is not. In v1.36.4 the
  # kubelet's proxy answers an un-upgraded stream request with a 500 whose text body is
  # "Upgrade request required" (UpgradeAwareHandler with upgradeRequired, the kubelet
  # responder), which client-go reports as 'Error from server (InternalError): an error on
  # the server ("Upgrade request required") ...'; a handshake refusal is a 400 ('the
  # server rejected our request'). Only an answer that came back from the server counts:
  # kubectl's own connection errors ('Unable to connect to the server', 'The connection to
  # the server ... was refused') never reached the API server, so nothing was audited.
  if [ "$rc" -eq 0 ]; then
    log "C: the node-proxy GET unexpectedly succeeded (the nodes/proxy record is still audited)"
    return 0
  fi
  if printf '%s' "$out" | grep -qiE 'Unable to connect to the server|connection to the server'; then
    log "C: the node-proxy GET never reached the API server (a client connection error)"
  elif printf '%s' "$out" | grep -q 'Error from server' \
      && printf '%s' "$out" | grep -qiE 'Upgrade request required|unable to upgrade|rejected our request|an error on the server'; then
    log "C: the kubelet refused the un-upgraded GET as expected (nodes/proxy record still audited)"
    return 0
  else
    log "C: the node-proxy GET failed with an error that is not the kubelet's upgrade refusal"
  fi
  [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' >&2
  return 1
}

# Procedure D — the direct-kubelet tunnel. A port-forward straight to the kubelet on
# :10250 (for example with kubeletctl) leaves NO API audit event, so the API-audit
# chokepoint is blind -- the TRR9002 direct-kubelet gap, restated. Read-only
# demonstration: no kubelet call is made.
procedure_d() {
  log "d: a port-forward direct to the kubelet :10250 /portForward (e.g. kubeletctl) bypasses the API server"
  log "d: it writes NO API audit event -> node/kubelet sensor only (see TRR9002 direct-kubelet gap)"
}

run_one() {
  case "$1" in
    a|b|c|d) run_proc "$1" ;;
    *) log "unknown item: $1 (use a|b|c|d|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d; do run_proc "$p"; done
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
