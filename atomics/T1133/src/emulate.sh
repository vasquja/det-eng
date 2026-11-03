#!/usr/bin/env bash
# TRR9033 — behavioral emulation for T1133 (External Remote Services), Kubernetes
# service exposure through a NodePort or LoadBalancer Service.
#
# An adversary with write access to Services exposes an internal interface outside the
# cluster by setting spec.type to NodePort or LoadBalancer -- an API enum the API server
# validates (kubernetes v1.36.4 staging/src/k8s.io/api/core/v1/types.go ServiceType:
# ClusterIP, NodePort, LoadBalancer, ExternalName; only NodePort and LoadBalancer expose
# pods). So the API server writes the audit event the paired Sigma rule keys on:
# objectRef.resource services, verb create/update/patch, and the exposing type in
# requestObject.spec.type (a full-object write) or responseObject.spec.type (the stored
# object, which also catches a JSON patch of /spec/type whose request body is an
# operation list, not a Service).
#
# Every object the emulation writes lives in the inert namespace trr9033 and carries the
# name prefix trr9033- and the label app.kubernetes.io/part-of=trr9033, so the validator
# gates tell the emulation's own writes apart from a cluster's real Services.
#
# Procedures:
#   A  create a NodePort Service      trr9033-np   (exposing: fires)
#   B  create a LoadBalancer Service  trr9033-lb   (exposing: fires)
#   C  JSON-patch an existing ClusterIP Service (trr9033-jp) /spec/type -> LoadBalancer
#      (exposing through the stored object; Elastic's request-only shape misses it)
#   D  create a ClusterIP Service      trr9033-cip  (benign baseline: MUST NOT fire)
#   E  patch the /status subresource of trr9033-lb (confounder: MUST NOT fire; the
#      service and cloud controllers patch only /status, which the rule filters and
#      which the lab policy keeps at Metadata, so the status body is not even logged)
#
# SAFETY:
#   * Every Service is INERT: it selects app=trr9033, which no pod carries, so it routes
#     to nothing (no real backend is needed). kind has no cloud provider, so a
#     LoadBalancer's external IP stays <pending>; the object and its audit record are
#     written all the same. The status patch sets an RFC 5737 TEST-NET IP.
#   * Everything is created in the namespace trr9033, which the emulation creates when it
#     is absent and labels app.kubernetes.io/part-of=trr9033. If a namespace trr9033
#     exists WITHOUT that label (not this emulation's), every procedure skips before any
#     write, so a real namespace of that name is never touched.
#   * Cleanup deletes the namespace trr9033 only when the emulation created it (our
#     label), which deletes every Service in it; otherwise it deletes only the
#     trr9033-labelled Services. No cluster Service outside this namespace is touched.
#
# Run ONE procedure:
#   ./emulate.sh a      create a NodePort Service (exposing)
#   ./emulate.sh b      create a LoadBalancer Service (exposing)
#   ./emulate.sh c      JSON-patch a ClusterIP Service's /spec/type to LoadBalancer
#   ./emulate.sh d      create a ClusterIP Service (benign baseline)
#   ./emulate.sh e      patch a LoadBalancer Service's /status subresource (confounder)
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to create and patch
# Services and to create a namespace, the audit policy in
# detections/k8s/audit-policy-apiserver.yaml (it logs core Service create/update/patch at
# RequestResponse), and python3 (to build the JSON bodies).
set -euo pipefail

NS="trr9033"                  # the inert namespace (created and labelled if absent)
PART_OF="app.kubernetes.io/part-of=trr9033"
STATUS_IP="198.51.100.10"     # RFC 5737 TEST-NET-2, non-routable (the inert LB ingress)

log() { printf '[trr9033] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping ---------------------------------------
# `must CMD` runs a write and returns its exit code (its stderr shown on failure).
# `apply_stdin ARGS` is `must kubectl ARGS -f -` for a body piped on stdin (pipefail is
# on, so the pipeline reports the write's exit, and the API server's reason is shown).
# `run_proc P` times procedure_P, appends one ledger line to $DETENG_LEDGER (set by CI;
# unset = no ledger) and records a failure without stopping the run, so `all` attempts
# every procedure and then exits 1 naming the failures.
TRR="TRR9033"
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

# Build a Service object JSON ($1 name, $2 type). Inert selector app=trr9033 (no pod has
# it). Labelled so cleanup finds it. python3 does the JSON escaping.
_service_json() {
  python3 -c 'import json,sys
name,ns,typ=sys.argv[1:4]
print(json.dumps({"apiVersion":"v1","kind":"Service",
  "metadata":{"name":name,"namespace":ns,"labels":{"app.kubernetes.io/part-of":"trr9033"}},
  "spec":{"type":typ,"selector":{"app":"trr9033"},
          "ports":[{"port":8080,"targetPort":8080}]}}))' "$1" "$NS" "$2"
}

# Create namespace trr9033 (labelled) when absent. Fail closed: a read that errors (not a
# clean NotFound) is a failure. A namespace of that name WITHOUT our label is not ours:
# every procedure then skips (return 2 -> SKIP, no write). Sets NS_READY to 1/0.
NS_READY=0
ensure_ns() {
  local found label
  if ! found="$(kubectl get namespace "$NS" --ignore-not-found -o name)"; then
    log "cannot read namespace $NS (see the kubectl error above) -- not touching it"
    return 1
  fi
  if [ -z "$found" ]; then
    log "creating the inert namespace $NS (labelled $PART_OF)"
    kubectl create namespace "$NS" >/dev/null 2>&1 \
      || { log "could not create namespace $NS"; return 1; }
    kubectl label namespace "$NS" "$PART_OF" --overwrite >/dev/null 2>&1 \
      || { log "could not label namespace $NS"; return 1; }
    NS_READY=1
    return 0
  fi
  label="$(kubectl get namespace "$NS" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}' 2>/dev/null || true)"
  if [ "$label" != "trr9033" ]; then
    log "namespace $NS exists WITHOUT the $PART_OF label (not this emulation's) -- not touching it"
    NS_READY=0
    return 0
  fi
  log "reusing the emulation's existing namespace $NS"
  NS_READY=1
}

# Ensure the LoadBalancer Service trr9033-lb exists (for Procedure E's status patch),
# OUTSIDE E's ledger window, so E's window holds only the /status patch (the rule fires
# on an exposing create, not on the status patch). Idempotent: a clean NotFound creates
# it; any other read error fails.
ensure_lb() {
  local found
  if ! found="$(kubectl -n "$NS" get service trr9033-lb --ignore-not-found -o name)"; then
    log "cannot read service $NS/trr9033-lb -- not creating it"
    return 1
  fi
  [ -n "$found" ] && return 0
  log "pre-create the LoadBalancer Service $NS/trr9033-lb for the status confounder"
  _service_json trr9033-lb LoadBalancer | apply_stdin -n "$NS" create \
    || { log "could not pre-create $NS/trr9033-lb"; return 1; }
}

# Procedure A — create a NodePort Service (exposing).
procedure_a() {
  [ "$NS_READY" = 1 ] || { log "A: namespace $NS not ready -- skipping"; return 0; }
  log "A: create the NodePort Service $NS/trr9033-np (spec.type NodePort)"
  _service_json trr9033-np NodePort | apply_stdin -n "$NS" create \
    || { log "A: the NodePort create was refused"; return 1; }
}

# Procedure B — create a LoadBalancer Service (exposing).
procedure_b() {
  [ "$NS_READY" = 1 ] || { log "B: namespace $NS not ready -- skipping"; return 0; }
  log "B: create the LoadBalancer Service $NS/trr9033-lb (spec.type LoadBalancer)"
  local found
  if ! found="$(kubectl -n "$NS" get service trr9033-lb --ignore-not-found -o name)"; then
    log "B: cannot read $NS/trr9033-lb"; return 1
  fi
  if [ -n "$found" ]; then
    log "B: $NS/trr9033-lb already exists (a standalone 'e' pre-created it); recreating"
    must kubectl -n "$NS" delete service trr9033-lb --wait >/dev/null 2>&1 || true
  fi
  _service_json trr9033-lb LoadBalancer | apply_stdin -n "$NS" create \
    || { log "B: the LoadBalancer create was refused"; return 1; }
}

# Procedure C — JSON-patch an existing ClusterIP Service's /spec/type to LoadBalancer.
# The request body is a JSON-patch operation list (no requestObject.spec.type), so only
# responseObject.spec.type catches it; this is the Elastic request-only miss. Creates the
# ClusterIP Service trr9033-jp first (a ClusterIP create does not fire), then patches.
procedure_c() {
  [ "$NS_READY" = 1 ] || { log "C: namespace $NS not ready -- skipping"; return 0; }
  local found
  if ! found="$(kubectl -n "$NS" get service trr9033-jp --ignore-not-found -o name)"; then
    log "C: cannot read $NS/trr9033-jp"; return 1
  fi
  [ -n "$found" ] && { log "C: deleting a stale $NS/trr9033-jp"; must kubectl -n "$NS" delete service trr9033-jp --wait >/dev/null 2>&1 || true; }
  log "C: create the ClusterIP Service $NS/trr9033-jp (not exposing yet)"
  _service_json trr9033-jp ClusterIP | apply_stdin -n "$NS" create \
    || { log "C: the ClusterIP create was refused"; return 1; }
  log "C: JSON-patch $NS/trr9033-jp /spec/type -> LoadBalancer (the exposing write)"
  must kubectl -n "$NS" patch service trr9033-jp --type=json \
    -p '[{"op":"replace","path":"/spec/type","value":"LoadBalancer"}]' \
    || { log "C: the JSON patch of /spec/type was refused"; return 1; }
}

# Procedure D — create a ClusterIP Service (benign baseline: MUST NOT fire).
procedure_d() {
  [ "$NS_READY" = 1 ] || { log "D: namespace $NS not ready -- skipping"; return 0; }
  local found
  if ! found="$(kubectl -n "$NS" get service trr9033-cip --ignore-not-found -o name)"; then
    log "D: cannot read $NS/trr9033-cip"; return 1
  fi
  [ -n "$found" ] && { log "D: deleting a stale $NS/trr9033-cip"; must kubectl -n "$NS" delete service trr9033-cip --wait >/dev/null 2>&1 || true; }
  log "D: create the ClusterIP Service $NS/trr9033-cip (baseline; the rule must not fire)"
  _service_json trr9033-cip ClusterIP | apply_stdin -n "$NS" create \
    || { log "D: the ClusterIP create was refused"; return 1; }
}

# Procedure E — patch the /status subresource of the LoadBalancer Service trr9033-lb
# (confounder: MUST NOT fire). The service and cloud controllers patch only /status
# (cloud-provider service/helpers/helper.go PatchService, the trailing "status"); the
# rule filters objectRef.subresource == status, and the lab policy keeps services/status
# at the Metadata catch-all, so the stored object is not even logged.
procedure_e() {
  [ "$NS_READY" = 1 ] || { log "E: namespace $NS not ready -- skipping"; return 0; }
  log "E: patch $NS/trr9033-lb /status (loadBalancer ingress ${STATUS_IP}; the rule must not fire)"
  must kubectl -n "$NS" patch service trr9033-lb --subresource=status --type=merge \
    -p '{"status":{"loadBalancer":{"ingress":[{"ip":"'"$STATUS_IP"'"}]}}}' \
    || { log "E: the /status patch was refused"; return 1; }
}

cleanup() {
  local label
  label="$(kubectl get namespace "$NS" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}' 2>/dev/null || true)"
  if [ "$label" = "trr9033" ]; then
    log "cleanup: deleting the emulation's namespace $NS (removes every trr9033- Service)"
    kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true
  else
    log "cleanup: namespace $NS is not the emulation's; deleting only trr9033-labelled Services"
    kubectl -n "$NS" delete service -l "$PART_OF" --ignore-not-found >/dev/null 2>&1 || true
  fi
}

run_one() {
  case "$1" in
    a|b|c|d) run_proc "$1" ;;
    e) ensure_lb || true; run_proc e ;;
    *) log "unknown item: $1 (use a|b|c|d|e|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  ensure_ns || { log "could not prepare the namespace $NS"; exit 1; }
  if [ "$which" = "all" ]; then
    for p in a b c d; do run_proc "$p"; done
    ensure_lb || true          # outside E's window
    run_proc e
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
