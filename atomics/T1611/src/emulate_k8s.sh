#!/usr/bin/env bash
# TRR9007 — behavioral emulation for T1611 (Escape to Host), Kubernetes pod-spec
# surface. (The Linux setns syscall atomic for T1611 is the separate C program in
# this folder; this script is the Kubernetes admission-time half.)
#
# Each procedure creates a pod (or controller, or static pod) whose SPEC requests
# host access, so the API server writes the Request-level audit event the paired
# Sigma rules key on. SAFETY: every container only runs `sleep 3600` -- the host
# access is requested but never used; no exploit, no escape. Every object is named
# trr9007-* so a validator matches the emulation's own events, not the baseline
# privileged pods a kind cluster starts (kube-proxy, kindnet, control plane).
#
# Run ONE procedure:
#   ./emulate_k8s.sh a      privileged container
#   ./emulate_k8s.sh b      hostPath mount of the node root
#   ./emulate_k8s.sh c      host namespaces (hostPID + hostIPC)
#   ./emulate_k8s.sh d      added dangerous capabilities
#   ./emulate_k8s.sh e      seccomp and AppArmor Unconfined, on two pods and a Deployment
#   ./emulate_k8s.sh ctrl   the same host access through a Deployment (controller)
#   ./emulate_k8s.sh jp     JSON-patch delivery (kubectl patch --type=json) of host access
#                           to a Deployment template and a pod's ephemeral container (K18;
#                           the ephemeral container also sets seccomp Unconfined)
#   ./emulate_k8s.sh gap    a dangerous STATIC POD on the node (node sensor + mirror create)
#   ./emulate_k8s.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to create pods
# and workloads, and a namespace with no restrictive Pod Security Admission (the
# default namespace on kind). The gap test needs node access (docker exec into the
# kind node), the same approach as TRR9003; set TRR9007_NODE for a non-kind lab.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${TRR9007_NAMESPACE:-default}"
NODE="${TRR9007_NODE:-apiserver-control-plane}"
MANIFEST_DIR="${TRR9007_MANIFEST_DIR:-/etc/kubernetes/manifests}"

log() { printf '[trr9007] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs a procedure's action and returns its exit code (stderr shown on
# failure). `run_proc P` times procedure_P, appends one ledger line to $DETENG_LEDGER
# (set by CI; unset = no ledger) and records a failure without stopping the run, so
# `all` attempts every procedure and then exits 1 naming the failures. Cleanup, and the
# node poll in the gap, keep `|| true`.
TRR="TRR9007"
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

apply_pod() {
  local file="$1" name="$2"
  log "apply $name (host access requested; container only sleeps)"
  must kubectl apply -f "$SCRIPT_DIR/$file"
}

cleanup() {
  log "cleanup: removing every trr9007- object"
  kubectl -n "$NS" delete pod trr9007-priv trr9007-hostpath trr9007-hostns trr9007-caps \
    trr9007-unconfined trr9007-unconfined-aa trr9007-jp-pod \
    --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete deployment trr9007-depl trr9007-unconfined-depl trr9007-jp-depl \
    --ignore-not-found >/dev/null 2>&1 || true
}

procedure_a() { apply_pod k8s-priv-pod.yaml trr9007-priv ; }
procedure_b() { apply_pod k8s-hostpath-pod.yaml trr9007-hostpath ; }
procedure_c() { apply_pod k8s-hostns-pod.yaml trr9007-hostns ; }
procedure_d() { apply_pod k8s-caps-pod.yaml trr9007-caps ; }

# Procedure E: confinement removed (seccomp and AppArmor Unconfined), no host access.
# One object per setting, so each validator row proves its own record: a pod with a
# pod-level seccomp Unconfined, a pod with a container AppArmor Unconfined, and a
# Deployment whose template sets seccomp Unconfined. Every container only sleeps.
procedure_e() {
  log "e: apply pod trr9007-unconfined (pod-level seccomp Unconfined; no host access; container only sleeps)"
  must kubectl apply -f "$SCRIPT_DIR/k8s-unconfined-pod.yaml" || return
  log "e: apply pod trr9007-unconfined-aa (container AppArmor Unconfined; no host access; container only sleeps)"
  must kubectl apply -f "$SCRIPT_DIR/k8s-unconfined-apparmor-pod.yaml" || return
  log "e: apply deployment trr9007-unconfined-depl (seccomp Unconfined template)"
  must kubectl apply -f "$SCRIPT_DIR/k8s-unconfined-deployment.yaml"
}

# K18 (JSON-patch grading): kubectl patch --type=json logs requestObject as the operation
# list, which the strategic-merge selections cannot read. Create two plain trr9007- objects,
# then backdoor them with a JSON patch so the pod rules' requestObject|re branches fire
# live: a Deployment template made privileged, and a privileged ephemeral container added
# to a pod (the pods/ephemeralcontainers subresource). The ephemeral container also sets
# seccompProfile Unconfined, so the same record proves the confinement rule's JSON-patch
# branch (Procedure E by a JSON patch). The containers only sleep.
procedure_jp() {
  log "jp: apply plain trr9007-jp-depl and trr9007-jp-pod (non-privileged, sleep only)"
  must kubectl apply -f "$SCRIPT_DIR/k8s-jsonpatch-deployment.yaml" || return
  must kubectl apply -f "$SCRIPT_DIR/k8s-jsonpatch-pod.yaml" || return
  # Readiness, not the gate-matched action: it may time out without failing the step.
  kubectl -n "$NS" wait --for=condition=Ready pod/trr9007-jp-pod --timeout=90s >/dev/null 2>&1 || true
  log "jp: JSON patch the Deployment template to privileged (--type=json)"
  must kubectl -n "$NS" patch deployment trr9007-jp-depl --type=json \
    -p '[{"op":"add","path":"/spec/template/spec/containers/0/securityContext","value":{"privileged":true}}]' \
    || return
  log "jp: JSON patch a privileged, seccomp-Unconfined ephemeral container onto trr9007-jp-pod (--subresource=ephemeralcontainers --type=json)"
  must kubectl -n "$NS" patch pod trr9007-jp-pod --subresource=ephemeralcontainers --type=json \
    -p '[{"op":"add","path":"/spec/ephemeralContainers","value":[{"name":"trr9007-dbg","image":"busybox:1.36","command":["sleep","3600"],"securityContext":{"privileged":true,"seccompProfile":{"type":"Unconfined"}},"terminationMessagePolicy":"File","imagePullPolicy":"IfNotPresent"}]}]'
}

# Controller delivery — the dangerous spec on a Deployment's template. The
# Deployment create is the adversary's real admission-moment event (explicit name,
# real identity); the controller fallback rule keys on it.
procedure_ctrl() {
  log "ctrl: apply deployment trr9007-depl (privileged template)"
  must kubectl apply -f "$SCRIPT_DIR/k8s-host-deployment.yaml"
}

# Static-pod delivery. The kubelet runs the dangerous pod from a node-local
# manifest, then registers a mirror pod so the API shows it. The node runtime sees
# the running container; the mirror create is audited as system:node, carrying the
# spec at Request level, so the chokepoint catches it there too (links to TRR9003).
# The mirror pod the kubelet registers for a static pod is named <pod>-<node>, so the
# '9007 static' validator gate keys on the trr9007-escape-static- prefix and a
# system:node:<node> caller. Poll up to 60 s for it and FAIL if it never appears (its
# create is the audited record the gate needs); the fixed `sleep 8` used to race it.
procedure_gap() {
  local dst="$MANIFEST_DIR/trr9007-escape-static.yaml" mirror="trr9007-escape-static-${NODE}"
  local rc=0
  if [ -n "${TRR9007_NODE_EXEC:-}" ]; then
    log "static: write a dangerous static pod via custom node exec"
    $TRR9007_NODE_EXEC "cat > $dst" < "$SCRIPT_DIR/k8s-static-pod-escape.yaml"
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "static: write a dangerous static pod to $NODE:$dst"
    docker exec -i "$NODE" sh -c "cat > $dst" < "$SCRIPT_DIR/k8s-static-pod-escape.yaml"
  else
    log "static: no node access (docker/TRR9007_NODE_EXEC) — cannot deliver the static pod"
    return 1
  fi
  log "static: poll up to 60s for the kubelet's mirror pod $mirror (its system:node create is audited)"
  for _ in $(seq 1 60); do
    if kubectl get pod "$mirror" -n "$NS" >/dev/null 2>&1; then
      log "static: the kubelet registered mirror pod $mirror -> a system:node pods-create is audited"
      log "static: (at Request level that create carries the spec, so the chokepoint matches it)"
      break
    fi
    sleep 1
  done
  if ! kubectl get pod "$mirror" -n "$NS" >/dev/null 2>&1; then
    log "static: the mirror pod $mirror never appeared within 60s"
    rc=1
  fi
  log "static: the node runtime SEES the running container (crictl):"
  docker exec "$NODE" sh -c "crictl pods --name trr9007-escape-static 2>/dev/null || true" >&2 2>/dev/null || true
  log "static: clean up — remove the static pod manifest"
  docker exec "$NODE" sh -c "rm -f $dst" >/dev/null 2>&1 || true
  if [ -n "${TRR9007_NODE_EXEC:-}" ]; then
    $TRR9007_NODE_EXEC "rm -f $dst" >/dev/null 2>&1 || true
  fi
  log "static: the node sensor is the only view under a Metadata-only audit policy (requestObject absent)"
  return "$rc"
}

run_one() {
  case "$1" in
    a|b|c|d|e|ctrl|jp|gap) run_proc "$1" ;;
    *) log "unknown item: $1 (use a|b|c|d|e|ctrl|jp|gap|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d e ctrl jp gap; do run_proc "$p"; done
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
