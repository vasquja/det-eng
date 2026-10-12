#!/usr/bin/env bash
# TRR9016 (T1078.004) behavioral emulation: abusing an Amazon Cognito identity pool that
# allows UNAUTHENTICATED (guest) identities — the pool hands AWS IAM credentials to any
# anonymous caller, who then uses them.
#
#   * DOCUMENT/LIVE: with TRR9016_LIVE=1 and AWS creds, creates a THROWAWAY identity pool
#     with AllowUnauthenticatedIdentities=true (+ AllowClassicFlow=true), requests guest
#     credentials with NO logins, and deletes the pool. Your own AWS account. NOT run in CI.
#   * FIXTURE: --show-fixture prints the committed CloudTrail fixtures the CI validator
#     runs the detections over.
#
# Rules:
#   detections/sigma/T1078.004/aws_cognito_unauthenticated_identity_use.yml   (B classic, C use)
#   detections/sigma/T1078.004/aws_cognito_identity_pool_unauth_enabled.yml   (D enabling config)
set -euo pipefail

PROC="${1:-c}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9016"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  cat "$FIXDIR/attack.json"; exit 0
fi

POOL="${TRR9016_POOL_NAME:-trr9016Pool}"
REGION="${AWS_REGION:-us-east-1}"

echo "== TRR9016.AWS.$PROC — Cognito unauthenticated identity pool abuse =="
case "$PROC" in
  a) echo "A: enhanced (simplified) flow guest issuance — GetId + GetCredentialsForIdentity."
     echo "   NOTE: these are Cognito Identity DATA events, OFF BY DEFAULT — no log unless"
     echo "   an advanced event selector (eventCategory=Data, AWS::Cognito::IdentityPool) is set." ;;
  b) echo "B: classic flow — sts:AssumeRoleWithWebIdentity directly against the unauth role"
     echo "   (a MANAGEMENT event, present in the default trail)." ;;
  c) echo "C: downstream use — the issued AssumedRole session calls an AWS API"
     echo "   (sessionIssuer.userName = Cognito_<pool>Unauth_Role; default trail)." ;;
  d) echo "D: enabling misconfiguration — CreateIdentityPool with"
     echo "   allowUnauthenticatedIdentities=true (+ allowClassicFlow=true)." ;;
  e) echo "E: pool-ID discovery — harvest the pool ID from client JS / a mobile binary."
     echo "   GAP: leaves no AWS CloudTrail record (detection starts at B/C)." ;;
  *) echo "usage: emulate_aws_cognito.sh {a|b|c|d|e} [--live|--show-fixture]"; exit 1 ;;
esac

if [[ "${TRR9016_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v aws >/dev/null || { echo "aws CLI not found"; exit 1; }
  echo
  echo "[live] creating throwaway identity pool '$POOL' (unauthenticated identities allowed)..."
  PID="$(aws cognito-identity create-identity-pool \
          --identity-pool-name "$POOL" \
          --allow-unauthenticated-identities \
          --allow-classic-flow \
          --region "$REGION" \
          --query IdentityPoolId --output text)"
  echo "[live] pool: $PID  — review CloudTrail for CreateIdentityPool (allowUnauthenticatedIdentities=true)."
  echo "[live] requesting a GUEST identity id (no logins)..."
  GID="$(aws cognito-identity get-id --identity-pool-id "$PID" --region "$REGION" \
          --query IdentityId --output text 2>/dev/null || echo '(get-id needs a role mapping; see the TRR)')"
  echo "[live] guest identityId: $GID"
  echo "[live] cleaning up (delete pool)..."
  aws cognito-identity delete-identity-pool --identity-pool-id "$PID" --region "$REGION"
  echo "[live] done. The guest-issuance events are DATA events; enable data-event selectors to see A."
else
  echo
  echo "(dry) set TRR9016_LIVE=1 with AWS creds to run the throwaway pool create+issue+delete,"
  echo "      or pass --show-fixture for the recorded telemetry."
fi
