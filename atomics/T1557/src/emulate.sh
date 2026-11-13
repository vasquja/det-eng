#!/usr/bin/env bash
# TRR9039 — behavioral emulation for T1557 (Adversary-in-the-Middle), secondary T1565
# (Data Manipulation), Kubernetes Service traffic hijack through Endpoints / EndpointSlice
# manipulation.
#
# An Endpoints (core) or EndpointSlice (discovery.k8s.io) object names the IP:port backends
# a Service routes to. An adversary with write access who creates or repoints these objects
# for a selectorless Service sends the Service's traffic to an attacker-chosen address. So
# the API server writes the audit event the paired Sigma rule keys on: objectRef.resource
# endpoints (core) or endpointslices (discovery.k8s.io), verb create / update / patch, by a
# principal that is not an endpoint controller.
#
# Every object the emulation writes lives in the inert namespace trr9039 and carries the
# name prefix trr9039- and the label app.kubernetes.io/part-of=trr9039, so the validator
# gates tell the emulation's own writes apart from a cluster's real Endpoints. The Services
# are SELECTORLESS (spec has no selector), so no endpoint controller manages their backing
# objects -- the emulation writes them by hand, which is both the attack path and the
# honest false positive this rule carries (a legitimate manual Endpoints write looks the
# same on a Metadata record; see the TRR and RULE_DEFECTS.md K69).
#
# Procedures:
#   A  create a selectorless Service trr9039-ep and a core Endpoints trr9039-ep pointing at
#      an RFC 5737 TEST-NET IP            (the hijack write the rule fires on)
#   B  create a selectorless Service trr9039-slice and a discovery.k8s.io EndpointSlice
#      trr9039-slice-manual pointing at the same IP  (the discovery branch; fires)
#   C  deletecollection the trr9039 namespace's endpoints  (control: the rule must NOT fire,
#      the verb a namespace teardown uses; validate_apiserver_detections.py ABSENCE 9039 C)
#
# SAFETY:
#   * Every Service is INERT and SELECTORLESS: it selects no pods and kind has no cloud
#     provider, so it routes nowhere. The written address is 198.51.100.10 (RFC 5737
#     TEST-NET-2, non-routable), so even the "repointed" Service reaches a black hole; no
#     real backend, pod or host is touched.
#   * Everything is created in the namespace trr9039, which the emulation creates when it is
#     absent and labels app.kubernetes.io/part-of=trr9039. If a namespace trr9039 exists
#     WITHOUT that label (not this emulation's), every procedure skips before any write, so
#     a real namespace of that name is never touched.
#   * Cleanup deletes the namespace trr9039 only when the emulation created it (our label),
#     which deletes every Service, Endpoints and EndpointSlice in it; otherwise it deletes
#     only the trr9039-labelled objects. No cluster object outside this namespace is
#     touched. Procedure C's deletecollection is scoped to the trr9039 namespace.
#
# Run ONE procedure:
#   ./emulate.sh a      create a selectorless Service + a manual core Endpoints (hijack)
#   ./emulate.sh b      create a selectorless Service + a manual EndpointSlice (hijack)
#   ./emulate.sh c      deletecollection the namespace's endpoints (control: must not fire)
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to create a namespace,
# Services, Endpoints and EndpointSlices in it, the audit policy in
# detections/k8s/audit-policy-apiserver.yaml (endpoints/endpointslices writes fall to the
# Metadata catch-all, which the rule reads), and python3 (to build the JSON bodies). Every
# object is inert (a selectorless Service that routes nowhere, an RFC 5737 address), so this
# runs directly in CI on the kind lab -- there is no real/live variant to gate.
set -euo pipefail

NS="trr9039"                  # the inert namespace (created and labelled if absent)
PART_OF="app.kubernetes.io/part-of=trr9039"
HIJACK_IP="198.51.100.10"     # RFC 5737 TEST-NET-2, non-routable (the inert hijack target)

log() { printf '[trr9039] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping ---------------------------------------
# `must CMD` runs a write and returns its exit code (its stderr shown on failure).
# `apply_stdin ARGS` is `kubectl ARGS -f -` for a body piped on stdin (pipefail is on, so
# the pipeline reports the write's exit, and the API server's reason is shown).
# `run_proc P` times procedure_P, appends one ledger line to $DETENG_LEDGER (set by CI;
# unset = no ledger) and records a failure without stopping the run, so `all` attempts
# every procedure and then exits 1 naming the failures. Never put a credential on a command
# line (none is used here).
TRR="TRR9039"
FAILED=()
# UTC time to the microsecond, from bash (EPOCHREALTIME, bash 5) and not from `date +%6N`:
# date of uutils coreutils 0.10.0 drops the leading zeros of %6N. An older bash uses date %N.
now_utc() {
  local t="${EPOCHREALTIME:-}"
  if [ -n "$t" ]; then TZ=UTC0 printf '%(%Y-%m-%dT%H:%M:%S)T.%sZ\n' "${t%[.,]*}" "${t#*[.,]}"
  else t="$(date -u +%Y-%m-%dT%H:%M:%S.%N)"; printf '%sZ\n' "${t:0:26}"; fi
}
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

# Build a selectorless Service JSON ($1 name). No selector, so no endpoint controller
# manages its Endpoints/EndpointSlices -- the emulation writes them by hand. Labelled so
# cleanup finds it. python3 does the JSON escaping.
_service_json() {
  python3 -c 'import json,sys
name,ns=sys.argv[1:3]
print(json.dumps({"apiVersion":"v1","kind":"Service",
  "metadata":{"name":name,"namespace":ns,"labels":{"app.kubernetes.io/part-of":"trr9039"}},
  "spec":{"ports":[{"port":80,"targetPort":80}]}}))' "$1" "$NS"
}

# Build a core Endpoints JSON ($1 name) pointing at the inert RFC 5737 address. Same name as
# its Service (a core Endpoints binds to a Service by name).
_endpoints_json() {
  python3 -c 'import json,sys
name,ns,ip=sys.argv[1:4]
print(json.dumps({"apiVersion":"v1","kind":"Endpoints",
  "metadata":{"name":name,"namespace":ns,"labels":{"app.kubernetes.io/part-of":"trr9039"}},
  "subsets":[{"addresses":[{"ip":ip}],"ports":[{"port":80,"protocol":"TCP"}]}]}))' \
    "$1" "$NS" "$HIJACK_IP"
}

# Build a discovery.k8s.io EndpointSlice JSON ($1 name, $2 owning Service). Associated to
# the Service by the kubernetes.io/service-name label; addresses is a list of IP strings.
_endpointslice_json() {
  python3 -c 'import json,sys
name,ns,svc,ip=sys.argv[1:5]
print(json.dumps({"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice",
  "metadata":{"name":name,"namespace":ns,
    "labels":{"app.kubernetes.io/part-of":"trr9039","kubernetes.io/service-name":svc}},
  "addressType":"IPv4",
  "endpoints":[{"addresses":[ip]}],
  "ports":[{"name":"","port":80,"protocol":"TCP"}]}))' \
    "$1" "$NS" "$2" "$HIJACK_IP"
}

# Create namespace trr9039 (labelled) when absent. Fail closed: a read that errors (not a
# clean NotFound) is a failure. A namespace of that name WITHOUT our label is not ours:
# every procedure then skips (NS_READY=0, no write). A real namespace is never touched.
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
  if [ "$label" != "trr9039" ]; then
    log "namespace $NS exists WITHOUT the $PART_OF label (not this emulation's) -- not touching it"
    NS_READY=0
    return 0
  fi
  log "reusing the emulation's existing namespace $NS"
  NS_READY=1
}

# Recreate an object we own: delete a stale trr9039- object of our own before creating it,
# so a rerun does not fail on AlreadyExists. $1 kind, $2 name. Only ever our own labelled
# objects in our own namespace (ensure_ns guarantees the namespace is ours).
_recreate_guard() {
  local kind="$1" name="$2" found
  if ! found="$(kubectl -n "$NS" get "$kind" "$name" --ignore-not-found -o name)"; then
    log "cannot read $NS/$kind/$name"; return 1
  fi
  [ -n "$found" ] && { log "deleting a stale $NS/$kind/$name"; must kubectl -n "$NS" delete "$kind" "$name" --wait >/dev/null 2>&1 || true; }
  return 0
}

# Procedure A — create a selectorless Service and a manual core Endpoints that repoints it
# at the inert RFC 5737 address (the hijack write the rule fires on). An Endpoints binds to
# its Service by name, so both are trr9039-ep.
procedure_a() {
  [ "$NS_READY" = 1 ] || { log "A: namespace $NS not ready -- skipping"; return 0; }
  _recreate_guard services trr9039-ep || return
  _recreate_guard endpoints trr9039-ep || return
  log "A: create the selectorless Service $NS/trr9039-ep"
  _service_json trr9039-ep | apply_stdin -n "$NS" create \
    || { log "A: the Service create was refused"; return 1; }
  log "A: create the core Endpoints $NS/trr9039-ep -> ${HIJACK_IP} (the hijack write)"
  _endpoints_json trr9039-ep | apply_stdin -n "$NS" create \
    || { log "A: the Endpoints create was refused"; return 1; }
}

# Procedure B — create a selectorless Service and a manual discovery.k8s.io EndpointSlice
# that repoints it at the inert address (the discovery branch of the chokepoint).
procedure_b() {
  [ "$NS_READY" = 1 ] || { log "B: namespace $NS not ready -- skipping"; return 0; }
  _recreate_guard services trr9039-slice || return
  _recreate_guard endpointslices trr9039-slice-manual || return
  log "B: create the selectorless Service $NS/trr9039-slice"
  _service_json trr9039-slice | apply_stdin -n "$NS" create \
    || { log "B: the Service create was refused"; return 1; }
  log "B: create the EndpointSlice $NS/trr9039-slice-manual -> ${HIJACK_IP} (the hijack write)"
  _endpointslice_json trr9039-slice-manual trr9039-slice | apply_stdin -n "$NS" create \
    || { log "B: the EndpointSlice create was refused"; return 1; }
}

# Procedure C — control (the rule must NOT fire): a deletecollection of the namespace's
# endpoints, the verb a namespace teardown uses. The rule matches only create/update/patch,
# so this stays quiet (validate_apiserver_detections.py ABSENCE 9039 C). kubectl delete
# --raw sends a real DELETE to the collection URL, recorded as verb deletecollection.
procedure_c() {
  [ "$NS_READY" = 1 ] || { log "C: namespace $NS not ready -- skipping"; return 0; }
  log "C: deletecollection of endpoints in $NS (control; the rule must stay quiet)"
  must kubectl delete --raw "/api/v1/namespaces/${NS}/endpoints" \
    || { log "C: the endpoints deletecollection was refused"; return 1; }
}

cleanup() {
  local label
  label="$(kubectl get namespace "$NS" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}' 2>/dev/null || true)"
  if [ "$label" = "trr9039" ]; then
    log "cleanup: deleting the emulation's namespace $NS (removes every trr9039- object)"
    kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true
  else
    log "cleanup: namespace $NS is not the emulation's; deleting only trr9039-labelled objects"
    kubectl -n "$NS" delete endpointslices,endpoints,services -l "$PART_OF" \
      --ignore-not-found >/dev/null 2>&1 || true
  fi
}

run_one() {
  case "$1" in
    a|b|c) run_proc "$1" ;;
    *) log "unknown item: $1 (use a|b|c|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  ensure_ns || { log "could not prepare the namespace $NS"; exit 1; }
  if [ "$which" = "all" ]; then
    for p in a b c; do run_proc "$p"; done
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
