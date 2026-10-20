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

apply_pod() {
  local file="$1" name="$2"
  log "apply $name (host access requested; container only sleeps)"
  kubectl apply -f "$SCRIPT_DIR/$file" >/dev/null 2>&1 || true
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
  kubectl apply -f "$SCRIPT_DIR/k8s-unconfined-pod.yaml" >/dev/null 2>&1 || true
  log "e: apply pod trr9007-unconfined-aa (container AppArmor Unconfined; no host access; container only sleeps)"
  kubectl apply -f "$SCRIPT_DIR/k8s-unconfined-apparmor-pod.yaml" >/dev/null 2>&1 || true
  log "e: apply deployment trr9007-unconfined-depl (seccomp Unconfined template)"
  kubectl apply -f "$SCRIPT_DIR/k8s-unconfined-deployment.yaml" >/dev/null 2>&1 || true
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
  kubectl apply -f "$SCRIPT_DIR/k8s-jsonpatch-deployment.yaml" >/dev/null 2>&1 || true
  kubectl apply -f "$SCRIPT_DIR/k8s-jsonpatch-pod.yaml" >/dev/null 2>&1 || true
  kubectl -n "$NS" wait --for=condition=Ready pod/trr9007-jp-pod --timeout=90s >/dev/null 2>&1 || true
  log "jp: JSON patch the Deployment template to privileged (--type=json)"
  kubectl -n "$NS" patch deployment trr9007-jp-depl --type=json \
    -p '[{"op":"add","path":"/spec/template/spec/containers/0/securityContext","value":{"privileged":true}}]' \
    >/dev/null 2>&1 || true
  log "jp: JSON patch a privileged, seccomp-Unconfined ephemeral container onto trr9007-jp-pod (--subresource=ephemeralcontainers --type=json)"
  kubectl -n "$NS" patch pod trr9007-jp-pod --subresource=ephemeralcontainers --type=json \
    -p '[{"op":"add","path":"/spec/ephemeralContainers","value":[{"name":"trr9007-dbg","image":"busybox:1.36","command":["sleep","3600"],"securityContext":{"privileged":true,"seccompProfile":{"type":"Unconfined"}},"terminationMessagePolicy":"File","imagePullPolicy":"IfNotPresent"}]}]' \
    >/dev/null 2>&1 || true
}

# Controller delivery — the dangerous spec on a Deployment's template. The
# Deployment create is the adversary's real admission-moment event (explicit name,
# real identity); the controller fallback rule keys on it.
procedure_ctrl() {
  log "ctrl: apply deployment trr9007-depl (privileged template)"
  kubectl apply -f "$SCRIPT_DIR/k8s-host-deployment.yaml" >/dev/null 2>&1 || true
}

# Static-pod delivery. The kubelet runs the dangerous pod from a node-local
# manifest, then registers a mirror pod so the API shows it. The node runtime sees
# the running container; the mirror create is audited as system:node, carrying the
# spec at Request level, so the chokepoint catches it there too (links to TRR9003).
procedure_gap() {
  local dst="$MANIFEST_DIR/trr9007-escape-static.yaml"
  if [ -n "${TRR9007_NODE_EXEC:-}" ]; then
    log "static: write a dangerous static pod via custom node exec"
    $TRR9007_NODE_EXEC "cat > $dst" < "$SCRIPT_DIR/k8s-static-pod-escape.yaml" || true
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "static: write a dangerous static pod to $NODE:$dst"
    docker exec -i "$NODE" sh -c "cat > $dst" < "$SCRIPT_DIR/k8s-static-pod-escape.yaml" || true
    sleep 8
    log "static: the node runtime SEES the running container (crictl):"
    docker exec "$NODE" sh -c "crictl pods --name trr9007-escape-static 2>/dev/null || true" || true
    if kubectl get pods -A 2>/dev/null | grep -q trr9007-escape-static; then
      log "static: the kubelet registered a mirror pod -> a system:node pods-create is audited"
      log "static: (at Request level that create carries the spec, so the chokepoint matches it)"
    else
      log "static: no mirror pod object yet (it may still be registering)"
    fi
    log "static: clean up — remove the static pod manifest"
    docker exec "$NODE" sh -c "rm -f $dst" || true
    sleep 3
  else
    log "static: no node access (docker/TRR9007_NODE_EXEC) — skipping the static-pod delivery"
    return 0
  fi
  log "static: the node sensor is the only view under a Metadata-only audit policy (requestObject absent)"
}

run_one() {
  case "$1" in
    a) procedure_a ;;
    b) procedure_b ;;
    c) procedure_c ;;
    d) procedure_d ;;
    e) procedure_e ;;
    ctrl) procedure_ctrl ;;
    jp) procedure_jp ;;
    gap) procedure_gap ;;
    *) log "unknown item: $1 (use a|b|c|d|e|ctrl|jp|gap|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d e ctrl jp gap; do run_one "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
