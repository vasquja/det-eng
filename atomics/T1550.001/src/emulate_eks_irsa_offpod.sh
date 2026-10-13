#!/usr/bin/env bash
# TRR9022 (T1550.001 / T1078.004) behavioral emulation: EKS IRSA credentials used
# off-cluster. The detectable step is the OFF-CLUSTER USE of an IRSA projected
# service-account token or the temporary role credentials it mints -- both land in
# CloudTrail. Lifting the projected token off the pod's volume leaves no AWS API trace.
#
# Cloud has no free CI target, so this script has two honest halves:
#   * DOCUMENT/LIVE: with TRR9022_LIVE=1 and AWS credentials configured (ideally an IRSA
#     projected token or its minted creds carried off the cluster), it runs the real,
#     READ-ONLY off-cluster calls. Requires your own AWS account / EKS cluster. NOT run in CI.
#   * FIXTURE: with --show-fixture it prints the committed, schema-faithful CloudTrail
#     fixtures the CI validator runs the detections over.
#
# The paired detections key on the EKS IRSA provenance (oidc.eks OIDC provider in
# responseElements.provider on the exchange, or in webIdFederationData.federatedProvider
# on subsequent use) combined with a sourceIPAddress outside the cluster's egress.
# Rules: detections/sigma/T1550.001/aws_eks_irsa_web_identity_assumed_off_cluster.yml  (A)
#        detections/sigma/T1550.001/aws_eks_irsa_role_session_used_off_cluster.yml     (B)
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9022"

if [[ "${2:-}" == "--show-fixture" || "${1:-}" == "--show-fixture" ]]; then
  echo "# Recorded CloudTrail fixtures the CI validator runs the rules over:"
  cat "$FIXDIR/attack.json"
  exit 0
fi

ROLE_ARN="${TRR9022_ROLE_ARN:-arn:aws:iam::123456789012:role/trr9022-eks-irsa-role}"
TOKEN_FILE="${AWS_WEB_IDENTITY_TOKEN_FILE:-/var/run/secrets/eks.amazonaws.com/serviceaccount/token}"

echo "== TRR9022.AWS.$PROC — EKS IRSA credentials used off-cluster =="
case "$PROC" in
  a) echo "A: exchange leg -- a stolen IRSA projected SA token is replayed OFF-CLUSTER:"
     echo "   aws sts assume-role-with-web-identity --role-arn <irsa-role> \\"
     echo "       --role-session-name offcluster --web-identity-token file://<stolen-projected-token>"
     echo "   Chokepoint: sts:AssumeRoleWithWebIdentity, responseElements.provider contains oidc.eks,"
     echo "   subjectFromWebIdentityToken system:serviceaccount:*, sourceIPAddress outside cluster egress." ;;
  b) echo "B: use leg -- the minted ASIA... session is used OFF-CLUSTER (sts:GetCallerIdentity, etc.):"
     echo "   Chokepoint: userIdentity.type AssumedRole, sessionContext.webIdFederationData."
     echo "   federatedProvider contains oidc.eks, sourceIPAddress outside cluster egress." ;;
  c) echo "C: EKS Pod Identity is OUT OF SCOPE -- it uses eks-auth:AssumeRoleForPodIdentity and its"
     echo "   sessions carry an EMPTY webIdFederationData (no oidc.eks), so the IRSA rules do not fire." ;;
  d) echo "D: GAPs -- a token replayed from WITHIN cluster egress (compromised node) looks allowlisted;"
     echo "   data-plane-only use (s3:GetObject) needs CloudTrail data events; cross-account IRSA role"
     echo "   use lands in the resource account's trail." ;;
  *) echo "usage: emulate_eks_irsa_offpod.sh {a|b|c|d} [--live|--show-fixture]"; exit 1 ;;
esac

echo
echo "Off-cluster USE (the detectable step), run with the stolen IRSA token / minted creds:"
echo "   aws sts assume-role-with-web-identity --role-arn $ROLE_ARN --role-session-name offcluster \\"
echo "       --web-identity-token file://$TOKEN_FILE"
echo "   aws sts get-caller-identity"

if [[ "${TRR9022_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v aws >/dev/null || { echo "aws CLI not found"; exit 1; }
  echo
  echo "[live] running READ-ONLY calls with the configured credentials..."
  if [[ -r "$TOKEN_FILE" ]]; then
    echo "[live] exchanging the projected token (read-only STS)..."
    aws sts assume-role-with-web-identity --role-arn "$ROLE_ARN" \
      --role-session-name trr9022-offcluster \
      --web-identity-token "file://$TOKEN_FILE" >/dev/null && echo "[live] AssumeRoleWithWebIdentity ok"
  fi
  aws sts get-caller-identity
  echo "[live] done. Review CloudTrail for the oidc.eks provider + sourceIPAddress on these events."
else
  echo
  echo "(dry) set TRR9022_LIVE=1 (with an IRSA token / minted creds configured off-cluster) to run the"
  echo "      read-only calls in your own account, or pass --show-fixture for the recorded telemetry."
fi
