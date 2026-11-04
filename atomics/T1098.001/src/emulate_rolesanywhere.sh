#!/usr/bin/env bash
# TRR9037 (T1098.001, secondary T1199) behavioral emulation: IAM Roles Anywhere
# trust-anchor abuse in CloudTrail. An adversary with the IAM permissions
# rolesanywhere:CreateTrustAnchor (+ rolesanywhere:CreateProfile) registers a certificate
# authority THEY control as a trusted root. Any X.509 client certificate that CA signs then
# exchanges (rolesanywhere:CreateSession) for temporary AWS credentials of whatever role the
# attacker attaches a profile to -- standing, certificate-based persistence that survives
# IAM user/role and access-key clean-up.
#
# This emulation is a SEPARATE TRR from the TRR9013/TRR9015/TRR9018 OIDC-federation
# emulations under the same ATT&CK ID (emulate_entra.sh / emulate_aws_oidc.sh /
# emulate_gcp_wif.sh in this same directory). It is proven by the committed CloudTrail
# fixtures in detections/cloud/fixtures/trr9037/ via detections/validate_cloud_detections.py,
# and is NOT run in CI.
#
# Two honest halves:
#   * DRY (default): print the calls and the CloudTrail chokepoint each procedure writes.
#   * LIVE (TRR9037_LIVE=1, or --live): make the REAL writes in YOUR OWN AWS account against
#     DISPOSABLE resources you name, then REVERT them at once (disable + delete) via an EXIT
#     trap. Requires your own account; NOT run in CI.
#   * --show-fixture prints the committed, schema-faithful CloudTrail fixtures.
#
# Rules: detections/sigma/T1098.001/aws_rolesanywhere_trust_anchor_external_ca.yml  (graded)
#        detections/sigma/T1098.001/aws_rolesanywhere_trust_anchor_write.yml        (chokepoint)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9037"

PROC="${1:-a}"
if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  echo "# Recorded CloudTrail attack fixture the CI validator runs the rules over:"
  cat "$FIXDIR/attack.json"
  exit 0
fi

case "$PROC" in
  a) SOURCE_TYPE="CERTIFICATE_BUNDLE"
     DESC="a caller-supplied external PEM certificate bundle" ;;
  b) SOURCE_TYPE="SELF_SIGNED_REPOSITORY"
     DESC="a self-signed external repository" ;;
  *) echo "usage: emulate_rolesanywhere.sh {a|b} [--live|--show-fixture]"; exit 1 ;;
esac

echo "== TRR9037.AWS.${PROC^^} — IAM Roles Anywhere external-CA trust anchor =="
echo "An IAM principal with rolesanywhere:CreateTrustAnchor (+ CreateProfile) registers a CA"
echo "it controls ($DESC) as a trusted root, then attaches a profile naming the role a"
echo "session may assume. Certificates that CA signs exchange for that role's credentials."
echo
echo "  aws rolesanywhere create-trust-anchor --name <anchor> --enabled \\"
echo "      --source sourceType=$SOURCE_TYPE,sourceData={x509CertificateData=<PEM>}"
echo "  aws rolesanywhere create-profile --name <profile> --enabled \\"
echo "      --role-arns arn:aws:iam::<acct>:role/<role>"
echo
echo "Chokepoint (CloudTrail): eventSource rolesanywhere.amazonaws.com, eventName"
echo "CreateTrustAnchor, requestParameters.source.sourceType $SOURCE_TYPE (an EXTERNAL CA,"
echo "not AWS_ACM_PCA), no errorCode. The graded rule fires on the external source type; the"
echo "surface chokepoint fires on any trust-anchor/profile write."

if [[ "${TRR9037_LIVE:-0}" != "1" && "${2:-}" != "--live" ]]; then
  echo
  echo "(dry) set TRR9037_LIVE=1 and export TRR9037_ROLE_ARN (a DISPOSABLE role you control)"
  echo "      and TRR9037_CERT_PEM (a throwaway self-signed CA PEM) to make the real writes in"
  echo "      your own account and revert them at once, or pass --show-fixture for the"
  echo "      recorded telemetry."
  exit 0
fi

# ---- LIVE: real writes against disposable resources, reverted at once -------------------
command -v aws >/dev/null || { echo "aws CLI not found"; exit 1; }
ROLE_ARN="${TRR9037_ROLE_ARN:-}"
CERT_PEM="${TRR9037_CERT_PEM:-}"
if [[ -z "$ROLE_ARN" || -z "$CERT_PEM" ]]; then
  echo "[live] refusing to run: export TRR9037_ROLE_ARN (a DISPOSABLE IAM role you fully"
  echo "       control, not a human or a production role) and TRR9037_CERT_PEM (a path to a"
  echo "       throwaway self-signed CA certificate PEM). This briefly trusts that CA to mint"
  echo "       credentials for the named role."
  exit 1
fi
if [[ ! -f "$CERT_PEM" ]]; then
  echo "[live] TRR9037_CERT_PEM is not a readable file: $CERT_PEM"; exit 1
fi

ANCHOR_NAME="trr9037-ext-ca-anchor-$$"
PROFILE_NAME="trr9037-persist-profile-$$"

echo
echo "[live] !!! SAFETY: this registers an external CA as a Roles Anywhere trust anchor and"
echo "[live]     attaches a profile for $ROLE_ARN, then reverts. Use throwaway resources in a"
echo "[live]     non-production account."

TA_ID=""
PR_ID=""
revert() {
  echo "[live] reverting (delete profile + trust anchor)..."
  [[ -n "$PR_ID" ]] && aws rolesanywhere delete-profile --profile-id "$PR_ID" >/dev/null 2>&1 || true
  [[ -n "$TA_ID" ]] && aws rolesanywhere delete-trust-anchor --trust-anchor-id "$TA_ID" >/dev/null 2>&1 || true
  echo "[live] revert done."
}
trap revert EXIT

echo "[live] create-trust-anchor ($SOURCE_TYPE)..."
TA_ID="$(aws rolesanywhere create-trust-anchor --name "$ANCHOR_NAME" --enabled \
    --source "sourceType=$SOURCE_TYPE,sourceData={x509CertificateData=$(cat "$CERT_PEM")}" \
    --query 'trustAnchor.trustAnchorId' --output text)"
echo "[live] create-profile ($ROLE_ARN)..."
PR_ID="$(aws rolesanywhere create-profile --name "$PROFILE_NAME" --enabled \
    --role-arns "$ROLE_ARN" --query 'profile.profileId' --output text)"
echo "[live] trust anchor $TA_ID + profile $PR_ID written. Review CloudTrail for the"
echo "[live] CreateTrustAnchor event (source.sourceType $SOURCE_TYPE)."
# The EXIT trap reverts both next.
