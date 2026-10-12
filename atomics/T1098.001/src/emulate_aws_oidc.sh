#!/usr/bin/env bash
# TRR9015 (T1098.001) behavioral emulation: installing an over-broad GitHub Actions
# OIDC trust on an AWS IAM role, so a fork/any-repo can assume it.
#
#   * DOCUMENT/LIVE: with TRR9015_LIVE=1 and AWS creds, creates a THROWAWAY role with a
#     wildcard-sub GitHub-OIDC trust, then deletes it. Requires the GitHub OIDC provider
#     to exist (or creates it). Your own AWS account. NOT run in CI.
#   * FIXTURE: --show-fixture prints the committed CloudTrail fixtures the CI validator
#     runs the detection over.
#
# Rule: detections/sigma/T1098.001/aws_github_oidc_role_trust_abuse.yml
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9015"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  cat "$FIXDIR/attack.json"; exit 0
fi

ACCT="${TRR9015_ACCOUNT:-123456789012}"
ROLE="trr9015-github-deploy"
read -r -d '' TRUST <<JSON || true
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
"Principal":{"Federated":"arn:aws:iam::${ACCT}:oidc-provider/token.actions.githubusercontent.com"},
"Action":"sts:AssumeRoleWithWebIdentity",
"Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
"StringLike":{"token.actions.githubusercontent.com:sub":"repo:trr9015-example/*:*"}}}]}
JSON

echo "== TRR9015.AWS.$PROC — GitHub Actions OIDC role-trust abuse =="
case "$PROC" in
  a) echo "A: over-broad sub (wildcard repo:org/*) via iam:update-assume-role-policy." ;;
  b) echo "B: missing-sub grant (only aud pinned)." ;;
  c) echo "C: create-time grant via iam:create-role." ;;
  d) echo "D: create the GitHub OIDC provider (precursor)." ;;
  e) echo "E: use via sts:assume-role-with-web-identity (needs a GitHub OIDC token)." ;;
  *) echo "usage: emulate_aws_oidc.sh {a|b|c|d|e} [--live|--show-fixture]"; exit 1 ;;
esac
echo
echo "Over-broad trust policy (decoded):"
echo "$TRUST"

if [[ "${TRR9015_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v aws >/dev/null || { echo "aws CLI not found"; exit 1; }
  echo
  echo "[live] creating throwaway role $ROLE with the over-broad trust, then deleting..."
  aws iam create-role --role-name "$ROLE" --assume-role-policy-document "$TRUST" >/dev/null
  echo "[live] role created; review CloudTrail for the iam:CreateRole/UpdateAssumeRolePolicy event. Cleaning up..."
  aws iam delete-role --role-name "$ROLE"
  echo "[live] done."
else
  echo
  echo "(dry) set TRR9015_LIVE=1 with AWS creds to run the throwaway create+delete,"
  echo "      or pass --show-fixture for the recorded telemetry."
fi
