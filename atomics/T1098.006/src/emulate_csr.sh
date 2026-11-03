#!/usr/bin/env bash
# TRR9035 — behavioral emulation for T1098.006 / T1136 (CSR client-certificate
# persistence), Kubernetes CertificateSigningRequest API. Separate from the TRR9004
# RBAC/aws-auth emulation (emulate.sh) in this same folder; it touches none of its
# objects.
#
# The procedures mint a long-lived x509 client credential the way an attacker with
# the right RBAC would: create a CertificateSigningRequest whose signerName is
# kubernetes.io/kube-apiserver-client (the signer that issues certificates a client
# uses to authenticate to kube-apiserver), then approve it. The API server writes the
# two audit records the paired Sigma rule keys on (the create at Request, with
# requestObject.spec.signerName; the approval update of the approval subresource at
# Metadata). The CSR is named with the unique prefix `trr9035-` so a validator matches
# the emulation's OWN records and a pre-emulation baseline (the node bootstrap CSRs a
# kubeadm cluster auto-approves) cannot.
#
# SAFETY: the requested subject is CN=trr9035-persist, O=trr9035-group — an identity
# that NO RoleBinding or ClusterRoleBinding in the cluster references, so the issued
# certificate authenticates as a user and group with ZERO permissions. No privilege is
# granted. The CertificateSubjectRestriction admission plugin (on by default) refuses a
# kubernetes.io/kube-apiserver-client CSR that requests the system:masters group, so
# that escalation cannot be requested through this signer anyway; this emulation does
# not try it. The script never retrieves or uses the issued certificate, and never
# writes the private key anywhere a log can reach (the key stays in a mode-600 temp
# file that cleanup removes; only the public CSR, which carries no key, is sent to the
# API server). Cleanup deletes the CSR. The technique does NOT succeed on EKS (the
# managed control plane will not issue the certificate even once approved — Stratus Red
# Team), so a real credential is only minted on self-managed / kind clusters; the
# create and approve records exist on EKS too.
#
# Run ONE procedure:
#   ./emulate_csr.sh a        create a kubernetes.io/kube-apiserver-client CSR (inert subject)
#   ./emulate_csr.sh b        approve that CSR (approval subresource update)
#   ./emulate_csr.sh cleanup  delete the trr9035- CSR and remove temp files
#   ./emulate_csr.sh all      a then b, then clean up
#
# No command runs inside any container; this technique is about the control plane.
set -euo pipefail

CSR_NAME="trr9035-persist"
SUBJECT="/CN=trr9035-persist/O=trr9035-group"
SIGNER="kubernetes.io/kube-apiserver-client"
WORKDIR=""

log() { printf '[trr9035] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (mirrors emulate.sh) ------------------
TRR="TRR9035"
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

# A private temp dir for the key and CSR PEM, mode 700, removed on exit and by cleanup.
ensure_workdir() {
  [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ] && return 0
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/trr9035.XXXXXX")"
  chmod 700 "$WORKDIR"
}
remove_workdir() { [ -n "$WORKDIR" ] && rm -rf "$WORKDIR" 2>/dev/null || true; }
trap remove_workdir EXIT

cleanup() {
  log "cleanup: delete csr ${CSR_NAME} and remove temp files"
  kubectl delete certificatesigningrequest "$CSR_NAME" --ignore-not-found >/dev/null 2>&1 || true
  remove_workdir
}

# Procedure A — create a kube-apiserver-client CSR for the inert trr9035 identity.
# The server injects spec.username/uid/groups from the requester (strategy.go
# PrepareForCreate), so the record attributes the request to whoever kubectl is; the
# attacker needs the RBAC to create CSRs and (for B) to approve them.
procedure_a() {
  ensure_workdir || { log "A: cannot make a temp dir"; return 1; }
  # Generate a 2048-bit key (mode 600) and a PKCS#10 CSR for the inert subject. The key
  # never leaves WORKDIR; only the public CSR PEM is sent to the API server.
  if ! openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$WORKDIR/tls.key" -subj "$SUBJECT" -out "$WORKDIR/csr.pem" 2>"$WORKDIR/openssl.err"; then
    log "A: openssl could not generate the key/CSR:"; sed 's/^/    /' "$WORKDIR/openssl.err" >&2
    return 1
  fi
  chmod 600 "$WORKDIR/tls.key"
  local req; req="$(base64 -w0 < "$WORKDIR/csr.pem")"
  # Remove any leftover from an earlier run so the create is a true create (201).
  kubectl delete certificatesigningrequest "$CSR_NAME" --ignore-not-found >/dev/null 2>&1 || true
  cat > "$WORKDIR/csr-object.yaml" <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${CSR_NAME}
spec:
  request: ${req}
  signerName: ${SIGNER}
  usages:
    - client auth
EOF
  log "A: create certificatesigningrequest ${CSR_NAME} (signerName ${SIGNER}, inert subject ${SUBJECT})"
  must kubectl create -f "$WORKDIR/csr-object.yaml"
}

# Procedure B — approve the CSR (an update of the approval subresource). Runs only if
# the caller holds approve rights (on kind the kubeconfig is cluster-admin). The issued
# certificate authenticates an identity with no RBAC, so nothing is granted.
procedure_b() {
  log "B: approve certificatesigningrequest ${CSR_NAME} (approval subresource update)"
  must kubectl certificate approve "$CSR_NAME"
}

run_one() {
  case "$1" in
    a|b) run_proc "$1" ;;
    cleanup) cleanup ;;
    *) log "unknown procedure: $1 (use a|b|cleanup|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b; do run_proc "$p"; done
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
