#!/usr/bin/env bash
# TRR9034 — behavioral emulation for T1204.003 (Malicious Image), Kubernetes: a workload
# whose image a cluster ValidatingAdmissionPolicy (VAP) judges a violation, surfaced by
# the server-computed verdict the API server writes into the audit record.
#
# The emulation installs a REFERENCE VAP (atomics/T1204.003/src/vap-image-provenance.yaml,
# authored by det-eng, NOT a production image policy) with two namespace-scoped bindings,
# then creates inert pods that trip them. The "malicious image" is a benign placeholder
# (registry.k8s.io/pause by tag, not digest-pinned); the reference policy flags it by a
# chosen condition, not by being malware. Every pod carries a nodeSelector no node matches
# (trr9034-unschedulable=true), so it never schedules, pulls or runs.
#
# Procedures (one audit verdict per pod, split by the pod's trr9034-mode label):
#   ./emulate.sh a      create a pod the Audit binding flags -> ADMITTED + the
#                       validation.policy.admission.k8s.io/validation_failure annotation
#   ./emulate.sh b      create a pod the Deny binding flags -> REFUSED (422) with the
#                       "ValidatingAdmissionPolicy '...' denied request" message
#   ./emulate.sh c      create a Deployment the Audit binding flags -> the replicaset
#                       controller's own pods create carries the annotation (indirect)
#   ./emulate.sh allow  create a pod with a digest-pinned image the policy allows
#                       (benign control: no verdict, the rule must not fire)
#   ./emulate.sh all    install the policy, run every item in order, then clean up
#
# Side effects, expected and harmless: creating the VAP and its bindings fires TRR9025's
# admission-controller create chokepoint (k8s_admission_webhook_created.yml), and deleting
# them on cleanup fires TRR9008's disable chokepoint (k8s_admission_webhook_disabled.yml).
# Both are documented in the TRR.
#
# Prerequisites: a reachable cluster (kubectl works) with rights to write
# admissionregistration ValidatingAdmissionPolicy/Binding objects and pods, and audit
# logging of pod creates at Metadata or higher (the shipped lab policy logs them at
# Request; the markers this emulation produces are at Metadata).
set -euo pipefail

NS="trr9034"
POLICY_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vap-image-provenance.yaml"
# A benign placeholder image by TAG (not digest-pinned): the reference policy flags it.
BAD_IMAGE="registry.k8s.io/pause:3.10"
# The same family, DIGEST-pinned: the reference policy allows it. The digest is a
# syntactically valid placeholder; the pod is unschedulable, so it is never pulled.
OK_IMAGE="registry.k8s.io/pause@sha256:0000000000000000000000000000000000000000000000000000000000000000"

log() { printf '[trr9034] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs an action and returns its exit code (stderr shown on failure).
# `apply_stdin ARGS` is `kubectl ARGS -f -` for a body on stdin, showing the API server's
# reason on refusal. `run_proc P` times procedure_P, appends one ledger line to
# $DETENG_LEDGER (set by CI; unset = no ledger) and records a failure without stopping the
# run. No credential is ever placed on a command line or in a log line.
TRR="TRR9034"
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
apply_stdin() {
  local out rc=0
  out="$(kubectl "$@" -f - 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    log "FAILED (exit $rc): kubectl $* -f - (stdin)"
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

# A pod manifest: $1 name, $2 trr9034-mode label (audit/deny), $3 image.
pod_manifest() {
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: ${NS}
  labels:
    app.kubernetes.io/part-of: trr9034
    trr9034-mode: "$2"
spec:
  nodeSelector:
    trr9034-unschedulable: "true"
  terminationGracePeriodSeconds: 0
  containers:
    - name: c
      image: "$3"
EOF
}

deployment_manifest() {
  cat <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: trr9034-deploy
  namespace: ${NS}
  labels:
    app.kubernetes.io/part-of: trr9034
spec:
  replicas: 1
  selector:
    matchLabels:
      app: trr9034-deploy
  template:
    metadata:
      labels:
        app: trr9034-deploy
        app.kubernetes.io/part-of: trr9034
        trr9034-mode: "audit"
    spec:
      nodeSelector:
        trr9034-unschedulable: "true"
      terminationGracePeriodSeconds: 0
      containers:
        - name: c
          image: "${BAD_IMAGE}"
EOF
}

# Install the reference VAP + bindings and WAIT until the Deny binding is enforcing, by
# attempting a real create of a throwaway violating pod (labelled deny) until it is
# refused with the denied-request message. A create admitted before the policy is active
# leaves a stray inert pod with NO verdict marker (the rule does not fire on it); it is
# deleted and retried. Both bindings belong to one policy, so a live Deny binding proves
# the Audit binding is live too.
setup() {
  log "setup: label namespace ${NS} and install the reference VAP + two bindings"
  must kubectl create namespace "${NS}" || true
  must kubectl label namespace "${NS}" trr9034=enabled --overwrite || return 1
  must kubectl apply -f "${POLICY_FILE}" || return 1
  local out
  for _ in $(seq 1 60); do
    if out="$(pod_manifest trr9034-probe deny "${BAD_IMAGE}" | kubectl create -f - 2>&1)"; then
      # Admitted: the policy is not enforcing yet. Remove the stray pod and retry.
      kubectl delete pod trr9034-probe -n "${NS}" --ignore-not-found >/dev/null 2>&1 || true
      sleep 1
      continue
    fi
    if printf '%s' "$out" | grep -q "denied request"; then
      log "setup: Deny binding is enforcing (probe refused)"
      return 0
    fi
    # Refused for another reason (RBAC, etc.): surface it and fail.
    log "setup: probe refused but not by the VAP: ${out}"
    return 1
  done
  log "setup: the VAP did not begin enforcing within the timeout"
  return 1
}

# Procedure A — a violating pod under the Audit binding: ADMITTED and annotated.
procedure_a() {
  log "A: create pod trr9034-web (mode=audit, tag image) -> admitted + validation_failure annotation"
  pod_manifest trr9034-web audit "${BAD_IMAGE}" | apply_stdin create
}

# Procedure B — a violating pod under the Deny binding: REFUSED. The expected outcome is a
# refusal, so the procedure SUCCEEDS when the create is denied with the VAP message and
# FAILS if the create is admitted (the deny verdict did not fire).
procedure_b() {
  log "B: create pod trr9034-deny-web (mode=deny, tag image) -> expect refusal"
  local out
  if out="$(pod_manifest trr9034-deny-web deny "${BAD_IMAGE}" | kubectl create -f - 2>&1)"; then
    log "B: the pod was ADMITTED; the Deny binding did not refuse it"
    kubectl delete pod trr9034-deny-web -n "${NS}" --ignore-not-found >/dev/null 2>&1 || true
    return 1
  fi
  if printf '%s' "$out" | grep -q "denied request"; then
    log "B: correctly refused by the VAP Deny binding"
    return 0
  fi
  log "B: refused, but not by the VAP: ${out}"
  return 1
}

# Procedure C — a Deployment whose pod template violates the Audit binding. The Deployment
# itself is not matched (the VAP matches pods); the replicaset controller's own pods create
# carries the annotation. Wait for the controller to create the pod before returning, so
# the record falls inside this procedure's ledger window.
procedure_c() {
  log "C: create deployment trr9034-deploy (template mode=audit, tag image)"
  deployment_manifest | apply_stdin create || return 1
  local n
  for _ in $(seq 1 60); do
    n="$(kubectl get pods -n "${NS}" -l app=trr9034-deploy \
         --no-headers 2>/dev/null | wc -l | tr -d ' ')"
    if [ "${n:-0}" -ge 1 ]; then
      log "C: the replicaset controller created $n pod(s) under the Audit binding"
      return 0
    fi
    sleep 1
  done
  log "C: the replicaset controller created no pod within the timeout"
  return 1
}

# Allowed — a digest-pinned image the policy admits with NO verdict (benign control).
procedure_allow() {
  log "allow: create pod trr9034-web-ok (mode=audit, digest-pinned image) -> admitted, no verdict"
  pod_manifest trr9034-web-ok audit "${OK_IMAGE}" | apply_stdin create
}

cleanup() {
  log "cleanup: remove every trr9034 object (namespace, VAP, bindings)"
  kubectl delete -f "${POLICY_FILE}" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete namespace "${NS}" --ignore-not-found >/dev/null 2>&1 || true
}

run_one() {
  case "$1" in
    a|b|c|allow) run_proc "$1" ;;
    *) log "unknown item: $1 (use a|b|c|allow|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    setup || { log "setup failed; aborting"; cleanup; exit 1; }
    for p in a b c allow; do run_proc "$p"; done
    cleanup
  else
    setup || { log "setup failed; aborting"; cleanup; exit 1; }
    run_one "$which"
    cleanup
  fi
  if [ "${#FAILED[@]}" -gt 0 ]; then
    log "emulation FAILED: procedure(s) ${FAILED[*]}"
    exit 1
  fi
  log "emulation complete: $which"
}

main "$@"
