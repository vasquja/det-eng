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
# the manifest it wrote, which makes the kubelet stop the pod. The live Procedure B
# (TRR9003_RECONFIGURE=1 only) also changes the worker node's kubelet config: it
# runs an HTTP listener on the runner's kind bridge for the run of B, sets
# staticPodURL, restarts the worker kubelet, then restores the config and restarts
# the kubelet again. The cluster is a throwaway kind cluster and is deleted after
# the run.
#
# Run ONE procedure:
#   ./emulate.sh a      Procedure A: drop a manifest in the static-pod directory
#   ./emulate.sh gap    Procedure A, evasion: invalid namespace -> no API trace
#   ./emulate.sh b      Procedure B: kubelet static source (read-only; live on a
#                       worker node with TRR9003_RECONFIGURE=1)
#   ./emulate.sh all    every test, in order
#
# Prerequisites: a kind cluster whose node runs as a Docker container (the
# default), with kubectl working. Writing a static pod manifest is inherently a
# node-local action, so the lab reaches the node with `docker exec`, the same way
# TRR9002 Procedure E does. On a non-kind cluster, set TRR9003_NODE_EXEC to a
# command that runs a shell on the node.
#
# Environment:
#   TRR9003_NODE         control-plane node container (default trr9003-control-plane)
#   TRR9003_NODE_EXEC    a command that runs a shell on the node (non-kind labs; A, gap
#                        and the read-only B only)
#   TRR9003_RECONFIGURE  1 = run Procedure B LIVE: set staticPodURL on the worker kubelet,
#                        restart it, prove the URL static pod, then restore the config.
#                        Needs a kind cluster with a worker node, docker and python3 on
#                        the machine that runs this script (CI sets it). Unset = B is a
#                        read-only demonstration, and its ledger row says
#                        "mode":"read-only" (the strict validator then misses B).
#   TRR9003_WORKER       worker node container for the live B (default trr9003-worker)
#   TRR9003_URL_PORT     port of the live B's HTTP listener (default 18090)
#   DETENG_LEDGER        append one JSON line per procedure (CI sets it)
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
# A procedure that ran in a reduced mode sets PROC_MODE (Procedure B: "read-only"); the
# ledger row then carries "mode", so the validator can say why that procedure's gates miss.
PROC_MODE=""
now() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }
run_proc() {
  local p="$1" start end rc=0 mode=""
  PROC_MODE=""
  start="$(now)"
  "procedure_$p" || rc=$?
  end="$(now)"
  [ -n "$PROC_MODE" ] && mode=",\"mode\":\"${PROC_MODE}\""
  if [ -n "${DETENG_LEDGER:-}" ]; then
    printf '{"trr":"%s","procedure":"%s","start":"%s","end":"%s","exit":%d,"expect":0%s}\n' \
      "$TRR" "$(printf '%s' "$p" | tr '[:lower:]' '[:upper:]')" "$start" "$end" "$rc" "$mode" \
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

# Copy a manifest file from the repo onto the node's static-pod directory, through a
# MARKED copy of tee ($MARKED_TEE). A node file-event sensor (an auditd write watch
# on the kubelet static-pod directory) records the create with that exe, so the
# Strategy 3 file-event rule gets a live gate (C2-7) that tells this write apart from
# kubeadm's own control-plane writes (the rule's filter_install excludes those). tee
# reads the manifest from stdin ($src); the content never appears on a command line.
# The copy goes to /usr/local/bin, not /tmp: on a kind node /tmp is a tmpfs that
# Docker mounts noexec (kind v0.33.0 provision.go "--tmpfs /tmp"; moby gives every
# --tmpfs mount noexec,nosuid,nodev), so a copy there cannot run (exit 126). The
# snippet checks that the copy runs (tee to /dev/null, with no input) before it
# writes, and removes the copy after the write, in every branch.
MARKED_TEE="/usr/local/bin/trr9003-tee"
node_put_manifest() {
  local src="$1" dst="$2"
  local cmd="m='$MARKED_TEE'; cp \"\$(command -v tee)\" \"\$m\" || exit 1
    if ! \"\$m\" /dev/null </dev/null >/dev/null; then
      echo \"\$m cannot run on the node (a noexec mount?)\" >&2; rm -f \"\$m\"; exit 126
    fi
    \"\$m\" '$dst' >/dev/null; rc=\$?; rm -f \"\$m\"; exit \$rc"
  if [ -n "${TRR9003_NODE_EXEC:-}" ]; then
    $TRR9003_NODE_EXEC "$cmd" < "$src"
  else
    docker exec -i "$NODE" sh -c "$cmd" < "$src"
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

# Procedure B — reconfigure the kubelet static source.
# Two modes. By default (read-only demonstration), changing the static source and
# restarting the kubelet is only described, never done, so a local or single-node
# lab stays stable — the same safe-demonstration approach as TRR9002 Procedure E.
# The ledger row then says "mode":"read-only": B makes no telemetry, so a strict
# validator run misses B's gates and names this mode as the reason.
# When TRR9003_RECONFIGURE=1 (CI sets it, with a dedicated worker node), the LIVE
# path runs: it points the WORKER kubelet at a staticPodURL, restarts the kubelet,
# proves the URL static pod starts (config.source=http) and its mirror pod is
# registered, then restores the config and proves the pod and the mirror pod go away.
# Either way the chokepoint telemetry for B is the same as A (config.source
# file/http, plus the kubelet's mirror-pod create).
procedure_b() {
  if [ "${TRR9003_RECONFIGURE:-}" = "1" ]; then
    procedure_b_live
    return
  fi
  PROC_MODE="read-only"
  log "B: current kubelet static source configuration (read-only):"
  node_sh "grep -E 'staticPod(Path|URL)' /var/lib/kubelet/config.yaml 2>/dev/null \
            || echo '(no staticPod* in /var/lib/kubelet/config.yaml; default path applies)'" || true
  log "B: the watched static-pod directory holds the control-plane static pods:"
  node_sh "ls -1 '$MANIFEST_DIR' 2>/dev/null || true" || true
  log "B: an attacker with write access to the kubelet config would set"
  log "B:   staticPodPath: <attacker dir>   or   staticPodURL: http://<attacker>/pod.yaml"
  log "B: then restart the kubelet. This test does NOT restart it (keeps the lab stable)."
  log "B: the resulting pod start is the SAME chokepoint as Procedure A (config.source file/http)."
  log "B: read-only mode makes no telemetry; set TRR9003_RECONFIGURE=1 (kind, with a worker"
  log "B: node) to run B live."
}

# Procedure B, live (TRR9003_RECONFIGURE=1) — reconfigure the WORKER kubelet's
# static source to a staticPodURL and prove the URL static pod runs.
#
# The worker node means the kubelet restart never touches the control plane. The
# kind node image (Debian trixie) has no python3, so the manifest is served from
# the runner, on the kind bridge gateway, reachable from the worker container. The
# kubelet fetches it every http-check-frequency (20 s default at v1.36.4,
# pkg/kubelet/apis/config/v1beta1/defaults.go), starts the pod with
# config.source=http, and registers a mirror pod named trr9003-url-<worker> (the
# same CreateMirrorPod path as a file static pod, since IsStaticPod is true for any
# non-API source: pkg/kubelet/kubelet.go tryReconcileMirrorPods). The atomic waits
# for that mirror pod, because the validator gates B on its create.
#
# Once the config is edited, it is always restored and the kubelet restarted, also
# on a failure and on SIGINT/SIGTERM/SIGHUP (finalize_b_live). The restore is
# checked: B fails when the restored config still sets staticPodURL, when the
# kubelet does not restart or the worker does not come back Ready, when a Ready
# trr9003-url sandbox is still on the worker, or when the mirror pod is not deleted.
# (After the restart the kubelet kills the runtime pod no config source names and
# deletes the orphaned mirror pod: pkg/kubelet/kubelet_pods.go HandlePodCleanups.)
TRR9003_WORKER="${TRR9003_WORKER:-trr9003-worker}"
TRR9003_URL_PORT="${TRR9003_URL_PORT:-18090}"
URL_NAME="trr9003-url"
KUBELET_CFG=/var/lib/kubelet/config.yaml
KUBELET_CFG_BAK=/var/lib/kubelet/config.yaml.trr9003.bak
# State for finalize_b_live (globals, so the signal trap sees them too).
B_LIVE_EDITED=0     # 1 once the worker's kubelet config may hold staticPodURL
B_LIVE_HTTPPID=""
B_LIVE_SERVEDIR=""

worker_sh() { docker exec "$TRR9003_WORKER" sh -c "$*"; }

# Stop the listener, restore the worker kubelet, and check that the URL static pod
# and its mirror pod are gone. Returns 0 only when the worker is back as it was.
finalize_b_live() {
  local worker="$TRR9003_WORKER" mirror="${URL_NAME}-${TRR9003_WORKER}"
  local frc=0 edited="$B_LIVE_EDITED" out gone=0
  trap - INT TERM HUP
  if [ "$edited" = 1 ]; then
    log "B-live: restore the kubelet config and restart the kubelet on $worker"
    if ! worker_sh "[ -f '$KUBELET_CFG_BAK' ] && mv -f '$KUBELET_CFG_BAK' '$KUBELET_CFG'"; then
      log "B-live: FAILED — could not restore $KUBELET_CFG from $KUBELET_CFG_BAK on $worker"
      frc=1
    fi
    if worker_sh "grep -q '^staticPodURL:' '$KUBELET_CFG'"; then
      log "B-live: FAILED — $KUBELET_CFG on $worker still sets staticPodURL after the restore"
      frc=1
    fi
    if ! docker exec "$worker" systemctl restart kubelet; then
      log "B-live: FAILED — systemctl restart kubelet failed on $worker"
      frc=1
    fi
    B_LIVE_EDITED=0
  fi
  if [ -n "$B_LIVE_HTTPPID" ]; then
    kill "$B_LIVE_HTTPPID" 2>/dev/null || true
    wait "$B_LIVE_HTTPPID" 2>/dev/null || true
    B_LIVE_HTTPPID=""
  fi
  if [ -n "$B_LIVE_SERVEDIR" ]; then
    rm -rf "$B_LIVE_SERVEDIR"
    B_LIVE_SERVEDIR=""
  fi
  [ "$edited" = 1 ] || return "$frc"

  if ! kubectl wait --for=condition=Ready "node/$worker" --timeout=120s >/dev/null; then
    log "B-live: FAILED — node $worker is not Ready within 120 s after the restore"
    frc=1
  fi
  # The pod is gone when the runtime holds no READY trr9003-url sandbox (a stopped
  # sandbox stays NotReady until container GC removes it). A crictl error is "not
  # confirmed", never "gone".
  for _ in $(seq 1 30); do
    if out="$(docker exec "$worker" crictl pods --name "$URL_NAME" --state ready -q 2>/dev/null)" \
       && [ -z "$out" ]; then
      gone=1
      break
    fi
    sleep 2
  done
  if [ "$gone" -eq 1 ]; then
    log "B-live: confirmed — no ready $URL_NAME sandbox is left on $worker"
  else
    log "B-live: FAILED — a ready $URL_NAME sandbox is still on $worker 60 s after the restore," \
        "or crictl failed (last output: '${out:-}')"
    frc=1
  fi
  if kubectl -n default wait --for=delete "pod/$mirror" --timeout=90s >/dev/null; then
    log "B-live: confirmed — the mirror pod $mirror is gone"
  else
    log "B-live: FAILED — the mirror pod $mirror was not deleted within 90 s after the restore"
    frc=1
  fi
  return "$frc"
}

b_live_interrupted() {
  log "B-live: interrupted — restore the worker kubelet before exit"
  finalize_b_live || true
  exit 1
}

procedure_b_live() {
  local worker="$TRR9003_WORKER" port="$TRR9003_URL_PORT"
  local mirror="${URL_NAME}-${TRR9003_WORKER}"
  local gw="" url="" rc=0 seen=0 src="" i

  if [ -n "${TRR9003_NODE_EXEC:-}" ] || ! command -v docker >/dev/null 2>&1; then
    log "B-live: the live reconfiguration needs docker and the kind network (it serves the"
    log "B-live: manifest on the kind bridge gateway) — set TRR9003_RECONFIGURE only on kind."
    return 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    log "B-live: python3 is not on this machine (it serves the manifest and reads the gateway)"
    return 1
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx "$worker"; then
    log "B-live: worker node container '$worker' not found (set TRR9003_WORKER)"
    return 1
  fi
  # Refuse to touch a kubelet config that already sets staticPodURL: that is a
  # leftover (restore it from $KUBELET_CFG_BAK first) or a setting this lab does not own.
  if worker_sh "grep -q '^staticPodURL:' '$KUBELET_CFG'"; then
    log "B-live: FAILED — $KUBELET_CFG on $worker already sets staticPodURL; restore it"
    log "B-live: (e.g. from $KUBELET_CFG_BAK) before a live run"
    return 1
  fi

  # Find the kind bridge IPv4 gateway (the runner's address the worker can reach).
  gw="$(docker network inspect kind 2>/dev/null \
        | python3 -c 'import json,sys
cfgs=(json.load(sys.stdin)[0].get("IPAM") or {}).get("Config") or []
print(next((c["Gateway"] for c in cfgs if c.get("Gateway") and ":" not in c["Gateway"]), ""))' 2>/dev/null || true)"
  if [ -z "$gw" ]; then
    log "B-live: could not find the kind network IPv4 gateway (docker network inspect kind)"
    return 1
  fi
  url="http://${gw}:${port}/static-pod-url.yaml"

  # From here on, every exit path runs finalize_b_live (also on a signal).
  trap b_live_interrupted INT TERM HUP

  # Serve ONLY the one manifest, from a temp dir, bound to the gateway (not 0.0.0.0).
  B_LIVE_SERVEDIR="$(mktemp -d)"
  cp "$SCRIPT_DIR/static-pod-url.yaml" "$B_LIVE_SERVEDIR/static-pod-url.yaml"
  log "B-live: serve the manifest at ${url} (python3 http.server on the runner, bound to the kind gateway)"
  python3 -m http.server "$port" --bind "$gw" --directory "$B_LIVE_SERVEDIR" >/dev/null 2>&1 &
  B_LIVE_HTTPPID=$!

  # Confirm that the worker can fetch the manifest (up to 10 s for the listener to start).
  local served=0
  for i in $(seq 1 10); do
    if ! kill -0 "$B_LIVE_HTTPPID" 2>/dev/null; then
      break
    fi
    if worker_sh "command -v curl >/dev/null 2>&1 && curl -fsS --max-time 5 '$url' >/dev/null" \
         2>/dev/null; then
      served=1
      break
    fi
    sleep 1
  done
  if [ "$served" -ne 1 ]; then
    log "B-live: FAILED — the worker cannot fetch ${url} (the listener exited, or it is not"
    log "B-live: reachable on the kind bridge)"
    finalize_b_live || true
    return 1
  fi

  # Back up the (clean) kubelet config, then add staticPodURL and restart the kubelet.
  # The backup always copies the current, clean config: a stale backup from an
  # earlier run is overwritten, never restored.
  if ! worker_sh "cp -f '$KUBELET_CFG' '$KUBELET_CFG_BAK'"; then
    log "B-live: FAILED — could not back up $KUBELET_CFG on $worker"
    finalize_b_live || true
    return 1
  fi
  B_LIVE_EDITED=1
  if ! worker_sh "printf '\nstaticPodURL: %s\n' '$url' >> '$KUBELET_CFG'"; then
    log "B-live: FAILED — could not edit $KUBELET_CFG on $worker"
    finalize_b_live || true
    return 1
  fi
  log "B-live: set staticPodURL and restart the kubelet on $worker"
  if ! docker exec "$worker" systemctl restart kubelet; then
    log "B-live: FAILED — systemctl restart kubelet failed on $worker"
    finalize_b_live || true
    return 1
  fi

  # Poll crictl up to 90 s for the URL static pod sandbox with config.source=http.
  log "B-live: poll the worker runtime (crictl) for the $URL_NAME sandbox (config.source=http)"
  for i in $(seq 1 45); do
    if docker exec "$worker" crictl pods --name "$URL_NAME" --namespace default --state ready -q \
         2>/dev/null | grep -q . ; then
      if docker exec "$worker" crictl pods --name "$URL_NAME" --namespace default --state ready \
           -o json 2>/dev/null | grep -q '"kubernetes.io/config.source": *"http"'; then
        seen=1
        break
      fi
    fi
    sleep 2
  done
  if [ "$seen" -eq 1 ]; then
    log "B-live: the worker runtime SEES the URL static pod with config.source=http:"
    docker exec "$worker" crictl pods --name "$URL_NAME" 2>/dev/null || true
  else
    log "B-live: FAILED — the $URL_NAME static pod (config.source=http) did not appear on $worker within 90 s"
    rc=1
  fi

  # The validator gates B on the mirror-pod create, so wait for the mirror pod (up
  # to 60 s): mirror creation can lag the pod start after a kubelet restart (node
  # registration and informer sync, pkg/kubelet/kubelet.go). config.source must be http.
  if [ "$seen" -eq 1 ]; then
    log "B-live: wait for the kubelet to register the mirror pod ($mirror)"
    for i in $(seq 1 30); do
      src="$(kubectl -n default get pod "$mirror" \
        -o jsonpath='{.metadata.annotations.kubernetes\.io/config\.source}' 2>/dev/null || true)"
      [ -n "$src" ] && break
      sleep 2
    done
    if [ "$src" = "http" ]; then
      log "B-live: mirror pod present — config.source='http'; the audit log has its 'create pods'"
      log "B-live: by system:node:${worker}"
    else
      log "B-live: FAILED — mirror pod $mirror: config.source='${src:-<no mirror pod after 60 s>}', not 'http'"
      rc=1
    fi
  fi

  finalize_b_live || rc=1
  return "$rc"
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
