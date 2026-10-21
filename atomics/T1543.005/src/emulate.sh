#!/usr/bin/env bash
# TRR9003 — behavioral emulation for T1543.005 (Create or Modify System Process:
# Container Service), Kubernetes static pods.
#
# A static pod is a pod the kubelet runs from a node-local manifest (or a URL)
# WITHOUT the API server. It needs node file access, not a Kubernetes
# permission, and it survives restarts — a persistence primitive. These tests run
# a HARMLESS busybox pod (it only sleeps) through that path, so the node
# telemetry and the one API-server trace (the mirror-pod create) exist for the
# paired detections. No exploit, no host mounts, no privilege. Each test removes
# the manifest it wrote, which makes the kubelet stop the pod. The cluster is a
# throwaway kind cluster and is deleted after the run.
#
# Run ONE procedure:
#   ./emulate.sh a      Procedure A: drop a manifest in the static-pod directory
#   ./emulate.sh gap    Procedure A, evasion: invalid namespace -> no API trace
#   ./emulate.sh b      Procedure B: show the kubelet static source (read-only)
#   ./emulate.sh all    every test, in order
#
# Prerequisites: a kind cluster whose node runs as a Docker container (the
# default), with kubectl working. Writing a static pod manifest is inherently a
# node-local action, so the lab reaches the node with `docker exec`, the same way
# TRR9002 Procedure E does. On a non-kind cluster, set NODE_EXEC to a command
# that runs a shell on the node.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE="${TRR9003_NODE:-trr9003-control-plane}"
MANIFEST_DIR="${TRR9003_MANIFEST_DIR:-/etc/kubernetes/manifests}"
STATIC_NAME="trr9003-static"
GHOST_NAME="trr9003-ghost"
GHOST_NS="trr9003-nonexistent"

log() { printf '[trr9003] %s\n' "$*" >&2; }

# ---- procedure bookkeeping (shared shape across the det-eng Kubernetes atomics) ----
# `run_proc` times each procedure, appends one ledger line (DETENG_LEDGER, set by
# CI; unset = no ledger) and records a failure without stopping the run, so every
# procedure is attempted and the run exits 1 at the end naming the failures. A
# static pod is written once and never retried: a retried write would hide the
# first failure, and readiness comes from polling the node, not from a re-drop.
TRR="TRR9003"
FAILED=()
now() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }
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

# Run a command on the node. Default: docker exec into the kind node container.
# Override with TRR9003_NODE_EXEC for a different lab (it receives a shell -c arg).
node_sh() {
  if [ -n "${TRR9003_NODE_EXEC:-}" ]; then
    $TRR9003_NODE_EXEC "$@"
  else
    docker exec "$NODE" sh -c "$*"
  fi
}

# Copy a manifest file from the repo onto the node's static-pod directory.
node_put_manifest() {
  local src="$1" dst="$2"
  if [ -n "${TRR9003_NODE_EXEC:-}" ]; then
    $TRR9003_NODE_EXEC "cat > $dst" < "$src"
  else
    docker exec -i "$NODE" sh -c "cat > $dst" < "$src"
  fi
}

ensure_node() {
  if [ -n "${TRR9003_NODE_EXEC:-}" ]; then
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    log "docker not available and TRR9003_NODE_EXEC unset — cannot reach the node."
    log "Static pods need node file access; set TRR9003_NODE_EXEC for a non-kind lab."
    exit 1
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "node container '$NODE' not found. Set TRR9003_NODE to your kind node."
    exit 1
  fi
}

# Procedure A — drop a manifest in the kubelet's static-pod directory.
# The kubelet starts the pod with no API server involvement, then registers a
# read-only mirror pod. The mirror-pod create is the Strategy 2 audit event.
procedure_a() {
  local dst="$MANIFEST_DIR/${STATIC_NAME}.yaml"
  local mirror="${STATIC_NAME}-${NODE}"
  local rc=0 i
  log "A: write static pod manifest to the node ($dst)"
  if ! node_put_manifest "$SCRIPT_DIR/static-pod.yaml" "$dst"; then
    log "A: could not write the manifest to the node"
    return 1
  fi

  log "A: wait for the kubelet to register the mirror pod ($mirror)"
  for i in $(seq 1 30); do
    if kubectl -n default get pod "$mirror" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  if kubectl -n default get pod "$mirror" >/dev/null 2>&1; then
    local src
    src="$(kubectl -n default get pod "$mirror" \
      -o jsonpath='{.metadata.annotations.kubernetes\.io/config\.source}' 2>/dev/null || true)"
    log "A: mirror pod present — config.source='${src:-?}' (expect 'file', never 'api')"
    log "A: the API server audit log now has a 'create pods' by system:node:${NODE}"
    if [ "$src" != "file" ]; then
      log "A: FAILED — config.source is '${src:-?}', not 'file' (not a static pod?)"
      rc=1
    fi
  else
    log "A: FAILED — mirror pod did not appear within the timeout (check node $NODE)"
    rc=1
  fi

  log "A: clean up — remove the manifest so the kubelet stops the static pod"
  node_sh "rm -f '$dst'" || true
  kubectl -n default wait --for=delete "pod/$mirror" --timeout=30s >/dev/null 2>&1 || true
  return "$rc"
}

# Procedure A, evasion variant — the detection gap.
# Same path, but the manifest names a namespace that does not exist. The pod
# still runs on the node; the kubelet cannot register a mirror pod, so the pod
# never appears in the API and produces NO audit event. This is why Strategy 1
# needs a node runtime sensor, not the audit log.
procedure_gap() {
  local dst="$MANIFEST_DIR/${GHOST_NAME}.yaml"
  local rc=0 seen=0
  log "gap: write a static pod manifest with a non-existent namespace ($GHOST_NS)"
  if ! node_put_manifest "$SCRIPT_DIR/static-pod-evasion.yaml" "$dst"; then
    log "gap: could not write the manifest to the node"
    return 1
  fi

  # Poll crictl for the ghost sandbox instead of a fixed sleep: the kubelet starts
  # it asynchronously, and its createdAt must fall inside this procedure's ledger
  # window, so the window stays open until the node runtime actually reports it.
  log "gap: poll the node runtime (crictl) for the ghost pod sandbox"
  for _ in $(seq 1 30); do
    if node_sh "crictl pods --name '$GHOST_NAME' --state ready -q 2>/dev/null | grep -q ." ; then
      seen=1
      break
    fi
    sleep 2
  done
  if [ "$seen" -eq 1 ]; then
    log "gap: the node runtime SEES the pod sandbox (crictl):"
    node_sh "crictl pods --name '$GHOST_NAME' 2>/dev/null || true" || true
  else
    log "gap: FAILED — the ghost pod sandbox never became ready on the node ($NODE)"
    rc=1
  fi

  log "gap: the API server has NO pod OBJECT for it (kubectl get pods -A):"
  # List first: a kubectl that fails (API server unreachable) must not read as
  # "no object" — that would claim the gap with nothing checked.
  local pods
  if ! pods="$(kubectl get pods -A --no-headers 2>&1)"; then
    log "gap: FAILED — cannot list pods, so the missing API object is not checked: $pods"
    rc=1
  elif grep -q "$GHOST_NAME" <<<"$pods"; then
    log "gap: UNEXPECTED — a '$GHOST_NAME' pod object is visible in the API"
    rc=1
  else
    log "gap: confirmed — '$GHOST_NAME' has no pod object in 'kubectl get pods -A'"
    log "gap: the kubelet's mirror-pod ATTEMPT is still audited (as a FAILED create,"
    log "gap: non-2xx, namespace not found) — but the RUNNING pod above is not."
    log "gap: only the node runtime sees the workload; the audit log sees the attempt."
  fi

  log "gap: clean up — remove the manifest"
  node_sh "rm -f '$dst'" || true
  # Give the kubelet a moment to tear the sandbox down (best-effort; a read-only wait).
  sleep 3
  return "$rc"
}

# Procedure B — reconfigure the kubelet static source (read-only demonstration).
# Changing staticPodPath/staticPodURL and restarting the kubelet mid-run could
# wedge the single-node lab, so this test does NOT restart the kubelet. It shows
# WHERE the reconfiguration happens — the same safe-demonstration approach as
# TRR9002 Procedure E. The chokepoint telemetry for B is identical to A.
procedure_b() {
  log "B: current kubelet static source configuration (read-only):"
  node_sh "grep -E 'staticPod(Path|URL)' /var/lib/kubelet/config.yaml 2>/dev/null \
            || echo '(no staticPod* in /var/lib/kubelet/config.yaml; default path applies)'" || true
  log "B: the watched static-pod directory holds the control-plane static pods:"
  node_sh "ls -1 '$MANIFEST_DIR' 2>/dev/null || true" || true
  log "B: an attacker with write access to the kubelet config would set"
  log "B:   staticPodPath: <attacker dir>   or   staticPodURL: http://<attacker>/pod.yaml"
  log "B: then restart the kubelet. This test does NOT restart it (keeps the lab stable)."
  log "B: the resulting pod start is the SAME chokepoint as Procedure A (config.source file/http)."
}

run_one() {
  case "$1" in
    a|gap|b) run_proc "$1" ;;
    *)       log "unknown procedure: $1 (use a|gap|b|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  ensure_node
  if [ "$which" = "all" ]; then
    for p in a gap b; do run_one "$p"; done
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
