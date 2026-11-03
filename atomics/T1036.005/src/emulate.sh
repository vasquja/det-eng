#!/usr/bin/env bash
# TRR9031 — behavioral emulation for T1036.005 (Masquerading: Match Legitimate Name or
# Location), Kubernetes lookalike pod names.
#
# An adversary creates a bare pod with an EXPLICIT name in the shape a workload
# controller generates, so it reads as a replica of a real workload. The API server
# writes a pods create audit record whose objectRef.name carries the chosen name, which
# no controller create has (controllers set metadata.generateName only, so their records
# carry no objectRef.name). The paired Sigma rule keys on that name shape.
#
#   A (TRR9031.K8S.A) — ReplicaSet/Deployment shape in an application namespace:
#       payments-api-6f6b679f8f-x7k2q in namespace trr9031 (base-<hash 6-10>-<suffix 5>).
#   C (TRR9031.K8S.C) — DaemonSet/Job shape in a control-plane namespace:
#       kube-proxy-x7k2q in kube-system (base-<suffix 5>).
#
# The pods are inert (registry.k8s.io/pause, no command, no host access) and are deleted
# on cleanup; the namespace trr9031 is created and deleted. The emulation's marker is the
# trr9031 namespace (A) and the label trr=trr9031 (A and C): NOT the pod name, which must
# keep the controller shape for the rule and the rename test. The masquerade is the whole
# technique, so the name is attacker-chosen by design; the pods carry no command and
# reach nothing. There is no generateName procedure (B): a controller and an adversary
# send a byte-identical generateName, so the audit chokepoint cannot tell them apart
# without a per-site controller-identity allowlist (RULE_DEFECTS.md KTBD-K1); it is a
# documented gap, not a procedure.
#
# Run ONE procedure:
#   ./emulate.sh a      ReplicaSet-shaped explicit name in an application namespace
#   ./emulate.sh c      DaemonSet-shaped explicit name in kube-system
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to create pods in the
# trr9031 and kube-system namespaces, as a non-node identity, and audit logging (see
# detections/k8s/kind-apiserver-cluster.yaml).
set -euo pipefail

log() { printf '[trr9031] %s\n' "$*" >&2; }

NS_APP="${TRR9031_NAMESPACE:-trr9031}"
NS_SYS="kube-system"
POD_A="payments-api-6f6b679f8f-x7k2q"   # ReplicaSet shape: base-<hash 10>-<suffix 5>
POD_C="kube-proxy-x7k2q"                # DaemonSet shape: base-<suffix 5>
LABEL_KEY="trr"
LABEL_VAL="trr9031"
IMAGE="registry.k8s.io/pause:3.10"

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs an action and returns its exit code (stderr shown on failure).
# `run_proc P` times procedure_P, appends one ledger line to $DETENG_LEDGER (set by CI;
# unset = no ledger) and records a failure without stopping the run, so `all` attempts
# every procedure and then exits 1 naming the failures. Cleanup keeps `|| true`.
TRR="TRR9031"
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

# Create a bare pod named $2 in namespace $1 with the trr9031 label. A create is the
# gate-matched action: it must succeed (the API server writes the record the rule keys
# on). stdin manifest keeps the name and label exact.
create_pod() {
  local ns="$1" name="$2"
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${ns}
  labels:
    ${LABEL_KEY}: ${LABEL_VAL}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  containers:
    - name: pause
      image: ${IMAGE}
EOF
}

cleanup() {
  log "cleanup: deleting the lookalike pods and the trr9031 namespace"
  kubectl -n "$NS_SYS" delete pod "$POD_C" --ignore-not-found --force --grace-period=0 >/dev/null 2>&1 || true
  kubectl -n "$NS_APP" delete pod "$POD_A" --ignore-not-found --force --grace-period=0 >/dev/null 2>&1 || true
  kubectl delete namespace "$NS_APP" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

# Procedure A — ReplicaSet/Deployment-shaped explicit name in an application namespace.
procedure_a() {
  must kubectl get namespace "$NS_APP" >/dev/null 2>&1 \
    || must kubectl create namespace "$NS_APP" || return
  log "A: create bare pod $POD_A in namespace $NS_APP (ReplicaSet-shaped explicit name)"
  must create_pod "$NS_APP" "$POD_A"
}

# Procedure C — DaemonSet/Job-shaped explicit name in a control-plane namespace.
# The pod is inert and carries the trr9031 label (the gate's marker); it is NOT selected
# by the real kube-proxy DaemonSet (different labels) and runs nothing.
procedure_c() {
  log "C: create bare pod $POD_C in namespace $NS_SYS (DaemonSet-shaped explicit name)"
  must create_pod "$NS_SYS" "$POD_C"
}

run_one() {
  case "$1" in
    a|c) run_proc "$1" ;;
    *) log "unknown item: $1 (use a|c|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a c; do run_proc "$p"; done
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
