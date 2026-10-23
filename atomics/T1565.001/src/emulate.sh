#!/usr/bin/env bash
# TRR9027 — behavioral emulation for T1565.001 (Stored Data Manipulation), Kubernetes
# cluster DNS poisoning via the CoreDNS ConfigMap.
#
# Each procedure writes a cluster DNS ConfigMap in kube-system, so the API server writes
# the configmaps audit event the paired Sigma rules key on. Every write carries the
# sentinel token 'trr9027' (a forward to a sentinel .invalid zone that no workload
# resolves). A, B and C write by name (a PATCH): procedure A patches coredns, and B and C
# create kube-dns and coredns-custom with server-side apply (kubectl apply
# --server-side), which is a PATCH to the named object even when it does not exist yet.
# The audit policy logs a named write to these three ConfigMaps at RequestResponse, so
# each write reaches the log with its body and its sentinel, and the validator proves A,
# B and C. Procedure D deletes coredns and creates it again with a plain create (a POST
# to the collection, which names no object when the policy is evaluated); the policy
# logs every ConfigMap create in kube-system at Request, so that create carries its body
# too.
#
# SAFETY:
#   * Procedure A captures the real coredns Corefile (byte for byte, trailing line break
#     included), appends an INERT sentinel server block (forward of
#     trr9027poison.example.invalid. to a TEST-NET IP), and RESTORES the original
#     Corefile at once. It then checks that the stored Corefile equals the saved one and
#     exits 1 with a ::error:: line if it does not. Real resolution is never changed.
#   * Procedure D deletes the real coredns ConfigMap and creates it again at once with
#     the original Corefile plus an INERT sentinel stub zone (trr9027stub.example.invalid,
#     forwarded to a TEST-NET IP), then restores the original Corefile. Running CoreDNS
#     pods keep their loaded config while the ConfigMap is briefly absent. It runs only
#     when coredns has no owner, no addon-manager label and no EKS add-on label
#     (eks.amazonaws.com/component: a managed cluster's reconciler owns it), and only
#     when `kubectl auth can-i` says this identity may create, patch and delete
#     ConfigMaps in kube-system. It recreates the original object if the create fails,
#     and then checks that coredns exists with the saved Corefile byte for byte; if not,
#     it prints a ::error:: line with the saved object and exits 1.
#   * Procedures B and C write ConfigMaps a CoreDNS kind cluster does not read
#     (kube-dns, coredns-custom), so they are inert. Each runs ONLY when its ConfigMap
#     does not exist yet (a GKE cluster's real kube-dns, an AKS cluster's real
#     coredns-custom is never touched), and labels what it creates
#     app.kubernetes.io/part-of=trr9027; cleanup deletes only ConfigMaps with that label.
#
# Run ONE procedure:
#   ./emulate.sh a      repoint the coredns Corefile (sentinel forward), then restore
#   ./emulate.sh b      create a kube-dns ConfigMap with a stubDomains redirect (inert, SSA)
#   ./emulate.sh c      create a coredns-custom ConfigMap with a forward snippet (inert, SSA)
#   ./emulate.sh d      delete coredns and create it again (POST) with a sentinel stub zone, then restore
#   ./emulate.sh gap    node-local etcd/disk bypass demonstration (read-only)
#   ./emulate.sh all    every item, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works, server-side apply: Kubernetes
# 1.22+) with rights on kube-system ConfigMaps, the audit policy in
# detections/k8s/audit-policy-apiserver.yaml (it logs named writes to the coredns,
# kube-dns and coredns-custom ConfigMaps at RequestResponse by resourceNames, and every
# kube-system ConfigMap create at Request), and python3 (to
# build the merge patch and the applied objects).
set -euo pipefail

NS="kube-system"
NODE="${TRR9027_NODE:-apiserver-control-plane}"
SENTINEL_IP="198.51.100.53"   # RFC 5737 TEST-NET-2, non-routable
# An inert sentinel zone block: a rewrite (exercises the grader's plugin clause) and a
# forward to a TEST-NET IP. It answers only the sentinel .invalid zone, so real
# resolution is unaffected. The grader's public-forward clause also grades this block's
# forward (a TEST-NET IP is not private). Its root-block clause grades only the root
# block's forward, which the emulation never changes (that would redirect real cluster
# DNS); the sidecar cases prove that clause instead.
SENTINEL_BLOCK=$'\ntrr9027poison.example.invalid:53 {\n    errors\n    rewrite name trr9027poison.example.invalid sink.trr9027.example.invalid\n    forward . '"$SENTINEL_IP"$'\n}\n'

log() { printf '[trr9027] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs a procedure's action and returns its exit code (stderr shown on
# failure); `apply_stdin ARGS` is `must kubectl ARGS -f -` for a body on stdin, from a
# producer piped into it (pipefail is on, so the pipeline reports the write's exit), and
# it shows the API server's reason when the write is refused.
# `run_proc P` times procedure_P, appends one ledger line to $DETENG_LEDGER (set by CI;
# unset = no ledger) and records a failure without stopping the run, so `all` attempts
# every procedure and then exits 1 naming the failures. A procedure returns non-zero
# when its gate-matched write was refused; the SAFETY restore of coredns still runs, and
# a FAILED restore still hard-exits 1 (coredns must not be left changed). The SAFETY
# restore writes keep `|| true` (`_corefile_equals` then checks the result), and so do
# cleanup and the read-only gap print.
TRR="TRR9027"
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

# Build a strategic/merge patch body {"data":{"Corefile": <stdin>}} with correct JSON
# escaping of the multi-line Corefile.
_corefile_patch() { python3 -c 'import json,sys; print(json.dumps({"data":{"Corefile": sys.stdin.read()}}))'; }

# The label on every ConfigMap B and C create; cleanup deletes only ConfigMaps that carry
# it, so a cluster's own kube-dns or coredns-custom is never deleted.
PART_OF="app.kubernetes.io/part-of=trr9027"

# Server-side apply of an inert ConfigMap ($1 name, $2 data key, $3 data value), only
# when no ConfigMap of that name exists. SSA sends a PATCH to the named object, which
# creates it; the audit policy logs that named write at RequestResponse, with the body.
# Fail closed: a read that errors (not a clean NotFound) is a failure, never "absent",
# so a transient error can never lead to a write over a real cluster's ConfigMap.
_apply_inert_configmap() {
  local name="$1" key="$2" value="$3" found
  if ! found="$(kubectl -n "$NS" get configmap "$name" --ignore-not-found -o name)"; then
    log "cannot read configmap $NS/$name (see the kubectl error above) -- not touching it"
    return 1
  fi
  if [ -n "$found" ]; then
    log "configmap $NS/$name already exists (a real cluster DNS config?) -- not touching it, skipping"
    return 0
  fi
  python3 -c 'import json,sys; n,k,v,ns=sys.argv[1:5]; print(json.dumps({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":n,"namespace":ns,"labels":{"app.kubernetes.io/part-of":"trr9027"}},"data":{k:v}}))' \
    "$name" "$key" "$value" "$NS" \
    | apply_stdin apply --server-side --field-manager=trr9027-emulation \
    || { log "server-side apply of configmap $NS/$name was refused"; return 1; }
}

cleanup() {
  log "cleanup: deleting the trr9027-labelled inert ConfigMaps (coredns is restored in procedure a)"
  kubectl -n "$NS" delete configmap -l "$PART_OF" --ignore-not-found >/dev/null 2>&1 || true
}

# The coredns ConfigMap as JSON, or nothing when it does not exist (a clean NotFound).
# A read that errors returns non-zero (its kubectl error shown), so the caller can tell
# "absent" (a non-CoreDNS cluster: skip) from "could not read" (a failure).
_get_coredns_json() {
  kubectl -n "$NS" get configmap coredns --ignore-not-found -o json
}

# The Corefile of the coredns JSON on stdin, exactly as stored (trailing line break
# included; "$(...)" alone strips trailing line breaks, so the caller appends a guard
# character and removes it). Prints nothing when there is no Corefile.
_corefile_of() {
  python3 -c 'import json,sys
t=sys.stdin.read()
sys.stdout.write(((json.loads(t).get("data") or {}).get("Corefile","")) if t.strip() else "")'
}

# True when the coredns ConfigMap exists and its Corefile equals $1 byte for byte.
_corefile_equals() {
  kubectl -n "$NS" get configmap coredns -o json 2>/dev/null \
    | EXPECTED="$1" python3 -c 'import json,os,sys; d=json.load(sys.stdin); sys.exit(0 if (d.get("data") or {}).get("Corefile") == os.environ["EXPECTED"] else 1)' 2>/dev/null
}

# Procedure A — repoint the coredns Corefile, then restore it. The poison appends an
# inert sentinel zone; resolution for every real name is unchanged, and the original
# Corefile is put back immediately. The restore is armed on a signal BEFORE the poison
# is applied (so an interrupt between the two patches cannot leave the sentinel in
# place) and verified afterward: the stored Corefile must equal the saved one byte for
# byte (trailing line break included), or the run stops with an error.
procedure_a() {
  local saved orig rc=0
  if ! saved="$(_get_coredns_json)"; then
    log "A: cannot read the coredns ConfigMap (see the kubectl error above) — not touching it"
    return 1
  fi
  if ! orig="$(printf '%s' "$saved" | _corefile_of && printf x)"; then
    log "A: cannot parse the coredns ConfigMap — not touching it"
    return 1
  fi
  orig="${orig%x}"
  if [ -z "$orig" ]; then
    log "A: no coredns ConfigMap with a Corefile (not a CoreDNS cluster?) — skipping"
    return 0
  fi
  _restore_coredns() {
    kubectl -n "$NS" patch configmap coredns --type=merge \
      -p "$(printf '%s' "$orig" | _corefile_patch)" >/dev/null 2>&1 || true
  }
  trap '_restore_coredns' INT TERM
  log "A: patch coredns Corefile with a sentinel rewrite + forward (trr9027poison.example.invalid -> ${SENTINEL_IP})"
  must kubectl -n "$NS" patch configmap coredns --type=merge \
    -p "$(printf '%s' "${orig}${SENTINEL_BLOCK}" | _corefile_patch)" \
    || { log "A: the sentinel poison patch was refused"; rc=1; }
  log "A: restore the original coredns Corefile"
  _restore_coredns
  trap - INT TERM
  if ! _corefile_equals "$orig"; then
    log "A: the coredns Corefile differs from the saved one after restore — restoring again"
    _restore_coredns
    if ! _corefile_equals "$orig"; then
      echo "::error::TRR9027 A: the coredns Corefile is not the saved original after restore; put it back by hand" >&2
      exit 1
    fi
  fi
  return "$rc"
}

# Procedure D — delete the coredns ConfigMap and create it again (a POST to the
# collection, verb create) with the original Corefile plus an inert sentinel stub zone
# that forwards to a TEST-NET IP (no rewrite: the grader's public-forward clause is what
# grades it), then restore the original Corefile by a patch. The original object is
# saved first; if the create fails, it is created again from the saved copy. Before the
# delete it checks that this identity may create, patch and delete ConfigMaps in
# kube-system (a delete without the right to create would leave the cluster without
# coredns), and it never touches a coredns that a reconciler owns (an ownerReference,
# the addon-manager label, or the EKS add-on label eks.amazonaws.com/component). After
# the restore, coredns must exist with the saved Corefile byte for byte, or the run
# stops with an error.
STUB_BLOCK=$'\ntrr9027stub.example.invalid:53 {\n    errors\n    forward . '"$SENTINEL_IP"$'\n}\n'
procedure_d() {
  local saved orig verb answer rc=0
  if ! saved="$(_get_coredns_json)"; then
    log "D: cannot read the coredns ConfigMap (see the kubectl error above) — not deleting it"
    return 1
  fi
  if ! orig="$(printf '%s' "$saved" | _corefile_of && printf x)"; then
    log "D: cannot parse the coredns ConfigMap — not deleting it"
    return 1
  fi
  orig="${orig%x}"
  if [ -z "$orig" ]; then
    log "D: no coredns ConfigMap with a Corefile (not a CoreDNS cluster?) — skipping"
    return 0
  fi
  if printf '%s' "$saved" | python3 -c 'import json,sys
m=json.load(sys.stdin)["metadata"]; labels=m.get("labels") or {}
sys.exit(0 if m.get("ownerReferences") or "addonmanager.kubernetes.io/mode" in labels or "eks.amazonaws.com/component" in labels else 1)'; then
    log "D: coredns is owned or reconciled (ownerReference, addon-manager or EKS add-on label) — not deleting it, skipping"
    return 0
  fi
  for verb in create patch delete; do
    # can-i prints "yes" or "no"; an error (no answer) is a failure, not a skip.
    answer="$(kubectl auth can-i "$verb" configmaps -n "$NS" 2>/dev/null || true)"
    if [ "$answer" = "no" ]; then
      log "D: this identity may not $verb configmaps in $NS — not deleting coredns, skipping"
      return 0
    fi
    if [ "$answer" != "yes" ]; then
      log "D: kubectl auth can-i $verb configmaps -n $NS gave no answer — not deleting coredns"
      return 1
    fi
  done
  # The object to create: the saved one without server-set fields, Corefile + stub block;
  # and the saved one alone, to put back if the create fails.
  local poisoned pristine
  poisoned="$(printf '%s' "$saved" | STUB="$STUB_BLOCK" python3 -c 'import json,os,sys
d=json.load(sys.stdin); m=d["metadata"]
for k in ("uid","resourceVersion","creationTimestamp","managedFields","selfLink","generation"): m.pop(k,None)
d["data"]["Corefile"]=d["data"]["Corefile"]+os.environ["STUB"]; print(json.dumps(d))')"
  pristine="$(printf '%s' "$saved" | python3 -c 'import json,sys
d=json.load(sys.stdin); m=d["metadata"]
for k in ("uid","resourceVersion","creationTimestamp","managedFields","selfLink","generation"): m.pop(k,None)
print(json.dumps(d))')"
  _recreate_pristine() {
    kubectl -n "$NS" get configmap coredns >/dev/null 2>&1 \
      || printf '%s' "$pristine" | kubectl create -f - >/dev/null 2>&1 || true
    kubectl -n "$NS" patch configmap coredns --type=merge \
      -p "$(printf '%s' "$orig" | _corefile_patch)" >/dev/null 2>&1 || true
  }
  trap '_recreate_pristine' INT TERM
  log "D: delete coredns, then create it again (POST) with a sentinel stub zone (trr9027stub.example.invalid -> ${SENTINEL_IP})"
  # The recreate (POST) is the gate-matched record; a refused delete or create fails the
  # procedure. After a refused delete, coredns is still there, so the create is not sent
  # (it could only fail with AlreadyExists).
  if ! must kubectl -n "$NS" delete configmap coredns; then
    log "D: delete of coredns was refused — not sending the create"; rc=1
  elif ! printf '%s' "$poisoned" | apply_stdin create; then
    log "D: create (POST) of coredns with the sentinel stub zone was refused — putting the saved ConfigMap back"
    rc=1
  fi
  log "D: restore the original coredns Corefile"
  _recreate_pristine
  trap - INT TERM
  if ! _corefile_equals "$orig"; then
    log "D: coredns is missing or its Corefile differs from the saved one after restore — restoring again"
    _recreate_pristine
    if ! _corefile_equals "$orig"; then
      echo "::error::TRR9027 D: coredns is missing or not the saved original after restore; recreate it by hand from the saved object" >&2
      printf '%s\n' "$pristine" >&2
      exit 1
    fi
  fi
  return "$rc"
}

# Procedure B — legacy kube-dns ConfigMap with a stubDomains redirect (JSON). Inert on a
# CoreDNS cluster; written only to emit the chokepoint audit event.
procedure_b() {
  log "B: server-side apply a kube-dns ConfigMap with a stubDomains redirect (inert)"
  _apply_inert_configmap kube-dns stubDomains \
    '{"trr9027.poison.example.invalid":["'"$SENTINEL_IP"'"]}'
}

# Procedure C — coredns-custom import ConfigMap with a forward snippet. Inert unless the
# base Corefile imports it (a kind Corefile does not); written only for the chokepoint.
procedure_c() {
  log "C: server-side apply a coredns-custom ConfigMap with a forward snippet (inert)"
  # Multi-line, as CoreDNS's Caddyfile parser requires: a '}' on the forward's own line
  # is a syntax error ("Unexpected '}'"), so a one-line block would not load if imported.
  _apply_inert_configmap coredns-custom trr9027.server \
    $'trr9027poison.example.invalid:53 {\n    forward . '"$SENTINEL_IP"$'\n}\n'
}

# Gap — the node-local bypass. An adversary with control-plane node access can edit
# CoreDNS's mounted config on disk or in etcd with NO API write and NO audit event.
# Read-only demonstration.
procedure_gap() {
  if [ -n "${TRR9027_NODE_EXEC:-}" ]; then
    log "gap: show the etcd data path on the node (custom exec, read-only)"
    $TRR9027_NODE_EXEC 'ls -ld /var/lib/etcd 2>/dev/null || true' || true
  elif command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$NODE"; then
    log "gap: show the etcd data path on node $NODE (read-only)"
    docker exec "$NODE" sh -c 'ls -ld /var/lib/etcd 2>/dev/null || true' || true
  else
    log "gap: no node access (docker/TRR9027_NODE_EXEC) — skipping the node-bypass demonstration"
    return 0
  fi
  log "gap: a direct etcd/disk edit of the Corefile emits NO configmaps audit event -> node/etcd sensor only"
}

run_one() {
  case "$1" in
    a|b|c|d|gap) run_proc "$1" ;;
    *) log "unknown item: $1 (use a|b|c|d|gap|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d gap; do run_proc "$p"; done
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
