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

# Build a strategic/merge patch body {"data":{"Corefile": <stdin>}} with correct JSON
# escaping of the multi-line Corefile.
_corefile_patch() { python3 -c 'import json,sys; print(json.dumps({"data":{"Corefile": sys.stdin.read()}}))'; }

# The label on every ConfigMap B and C create; cleanup deletes only ConfigMaps that carry
# it, so a cluster's own kube-dns or coredns-custom is never deleted.
PART_OF="app.kubernetes.io/part-of=trr9027"

# Server-side apply of an inert ConfigMap ($1 name, $2 data key, $3 data value), only
# when no ConfigMap of that name exists. SSA sends a PATCH to the named object, which
# creates it; the audit policy logs that named write at RequestResponse, with the body.
_apply_inert_configmap() {
  local name="$1" key="$2" value="$3"
  if kubectl -n "$NS" get configmap "$name" >/dev/null 2>&1; then
    log "configmap $NS/$name already exists (a real cluster DNS config?) -- not touching it, skipping"
    return 0
  fi
  python3 -c 'import json,sys; n,k,v,ns=sys.argv[1:5]; print(json.dumps({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":n,"namespace":ns,"labels":{"app.kubernetes.io/part-of":"trr9027"}},"data":{k:v}}))' \
    "$name" "$key" "$value" "$NS" \
    | kubectl apply --server-side --field-manager=trr9027-emulation -f - >/dev/null 2>&1 || true
}

cleanup() {
  log "cleanup: deleting the trr9027-labelled inert ConfigMaps (coredns is restored in procedure a)"
  kubectl -n "$NS" delete configmap -l "$PART_OF" --ignore-not-found >/dev/null 2>&1 || true
}

# The coredns Corefile exactly as stored, trailing line break included ("$(...)" alone
# strips trailing line breaks, so the caller appends a guard character and removes it).
# Prints nothing when coredns or its Corefile is absent.
_get_corefile() {
  kubectl -n "$NS" get configmap coredns -o json 2>/dev/null \
    | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin).get("data",{}).get("Corefile",""))' 2>/dev/null \
    || true
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
  local orig
  orig="$(_get_corefile; printf x)"; orig="${orig%x}"
  if [ -z "$orig" ]; then
    log "A: coredns ConfigMap has no Corefile (not a CoreDNS cluster?) — skipping"
    return 0
  fi
  _restore_coredns() {
    kubectl -n "$NS" patch configmap coredns --type=merge \
      -p "$(printf '%s' "$orig" | _corefile_patch)" >/dev/null 2>&1 || true
  }
  trap '_restore_coredns' INT TERM
  log "A: patch coredns Corefile with a sentinel rewrite + forward (trr9027poison.example.invalid -> ${SENTINEL_IP})"
  kubectl -n "$NS" patch configmap coredns --type=merge \
    -p "$(printf '%s' "${orig}${SENTINEL_BLOCK}" | _corefile_patch)" >/dev/null 2>&1 || true
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
  local saved orig verb
  saved="$(kubectl -n "$NS" get configmap coredns -o json 2>/dev/null || true)"
  orig="$(printf '%s' "$saved" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.stdout.write((d.get("data") or {}).get("Corefile",""))' 2>/dev/null; printf x)"
  orig="${orig%x}"
  if [ -z "$orig" ]; then
    log "D: coredns ConfigMap has no Corefile (not a CoreDNS cluster?) — skipping"
    return 0
  fi
  if printf '%s' "$saved" | python3 -c 'import json,sys
m=json.load(sys.stdin)["metadata"]; labels=m.get("labels") or {}
sys.exit(0 if m.get("ownerReferences") or "addonmanager.kubernetes.io/mode" in labels or "eks.amazonaws.com/component" in labels else 1)'; then
    log "D: coredns is owned or reconciled (ownerReference, addon-manager or EKS add-on label) — not deleting it, skipping"
    return 0
  fi
  for verb in create patch delete; do
    if [ "$(kubectl auth can-i "$verb" configmaps -n "$NS" 2>/dev/null || true)" != "yes" ]; then
      log "D: this identity may not $verb configmaps in $NS — not deleting coredns, skipping"
      return 0
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
  kubectl -n "$NS" delete configmap coredns >/dev/null 2>&1 || true
  if ! printf '%s' "$poisoned" | kubectl create -f - >/dev/null 2>&1; then
    log "D: create failed — putting the saved coredns ConfigMap back"
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
    a) procedure_a ;;
    b) procedure_b ;;
    c) procedure_c ;;
    d) procedure_d ;;
    gap) procedure_gap ;;
    *) log "unknown item: $1 (use a|b|c|d|gap|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d gap; do run_one "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
