#!/usr/bin/env bash
# TRR9032 (T1098.006, secondary T1098.003) behavioral emulation: EKS access-entry
# backdoor in CloudTrail. An adversary with the IAM permissions eks:CreateAccessEntry and
# eks:AssociateAccessPolicy -- and NO Kubernetes access -- grants an IAM principal standing
# access to the Kubernetes control plane entirely through the EKS control-plane API. The
# grant lives in the EKS control plane, so the Kubernetes audit log never sees it; the only
# control-plane trace is CloudTrail (eventSource eks.amazonaws.com).
#
# This emulation is a SEPARATE TRR from the TRR9004 Kubernetes RBAC emulation in
# emulate.sh in this same directory (a different TRR under the same ATT&CK ID). It is
# proven by the committed CloudTrail fixtures in detections/cloud/fixtures/trr9032/ via
# detections/validate_cloud_detections.py, and is NOT run in CI.
#
# Two honest halves:
#   * DRY (default): print the calls and the CloudTrail chokepoint each procedure writes.
#   * LIVE (TRR9032_LIVE=1, or --live): make the REAL writes in YOUR OWN AWS account against
#     a DISPOSABLE principal you name, then REVERT them at once (disassociate + delete) via
#     an EXIT trap. Requires your own account / EKS cluster; NOT run in CI.
#   * --show-fixture prints the committed, schema-faithful CloudTrail fixtures.
#
# Rules: detections/sigma/T1098.006/aws_eks_access_entry_cluster_admin_policy.yml  (graded)
#        detections/sigma/T1098.006/aws_eks_access_entry_write.yml                 (chokepoint)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9032"
ARN_PREFIX="arn:aws:eks::aws:cluster-access-policy"

PROC="${1:-a}"
if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  echo "# Recorded CloudTrail attack fixture the CI validator runs the rules over:"
  cat "$FIXDIR/attack.json"
  exit 0
fi

case "$PROC" in
  a) POLICY="AmazonEKSClusterAdminPolicy"
     DESC="cluster administrator (full */*/*) at cluster scope" ;;
  b) POLICY="AmazonEKSSecretReaderPolicy"
     DESC="reads every Kubernetes Secret cluster-wide at cluster scope" ;;
  *) echo "usage: emulate_eks_access_entry.sh {a|b} [--live|--show-fixture]"; exit 1 ;;
esac
POLICY_ARN="$ARN_PREFIX/$POLICY"

echo "== TRR9032.AWS.${PROC^^} — EKS access-entry backdoor =="
echo "An IAM principal with eks:CreateAccessEntry + eks:AssociateAccessPolicy grants a"
echo "principal it controls $DESC, entirely through the EKS API."
echo
echo "  aws eks create-access-entry    --cluster-name <cluster> --principal-arn <role>"
echo "  aws eks associate-access-policy --cluster-name <cluster> --principal-arn <role> \\"
echo "      --policy-arn $POLICY_ARN \\"
echo "      --access-scope type=cluster"
echo
echo "Chokepoint (CloudTrail): eventSource eks.amazonaws.com, eventName AssociateAccessPolicy,"
echo "requestParameters.policyArn ending $POLICY, requestParameters.accessScope.type cluster,"
echo "no errorCode. The grant does NOT appear in the Kubernetes audit log."

if [[ "${TRR9032_LIVE:-0}" != "1" && "${2:-}" != "--live" ]]; then
  echo
  echo "(dry) set TRR9032_LIVE=1 and export TRR9032_CLUSTER + TRR9032_PRINCIPAL_ARN (a"
  echo "      DISPOSABLE role you control) to make the real writes in your own account and"
  echo "      revert them at once, or pass --show-fixture for the recorded telemetry."
  exit 0
fi

# ---- LIVE: real writes against a disposable principal, reverted at once ----------------
command -v aws >/dev/null || { echo "aws CLI not found"; exit 1; }
CLUSTER="${TRR9032_CLUSTER:-}"
PRINCIPAL="${TRR9032_PRINCIPAL_ARN:-}"
if [[ -z "$CLUSTER" || -z "$PRINCIPAL" ]]; then
  echo "[live] refusing to run: export TRR9032_CLUSTER and TRR9032_PRINCIPAL_ARN first."
  echo "       TRR9032_PRINCIPAL_ARN MUST be a DISPOSABLE IAM principal you fully control"
  echo "       (not a human or a production role); this grants it cluster access briefly."
  exit 1
fi

echo
echo "[live] !!! SAFETY: this grants $PRINCIPAL '$POLICY' on cluster '$CLUSTER' for a few"
echo "[live]     seconds, then reverts. Use a throwaway principal in a non-production cluster."

revert() {
  echo "[live] reverting (disassociate + delete access entry)..."
  aws eks disassociate-access-policy --cluster-name "$CLUSTER" --principal-arn "$PRINCIPAL" \
      --policy-arn "$POLICY_ARN" >/dev/null 2>&1 || true
  aws eks delete-access-entry --cluster-name "$CLUSTER" --principal-arn "$PRINCIPAL" \
      >/dev/null 2>&1 || true
  echo "[live] revert done."
}
trap revert EXIT

echo "[live] create-access-entry..."
aws eks create-access-entry --cluster-name "$CLUSTER" --principal-arn "$PRINCIPAL" \
    --type STANDARD >/dev/null
echo "[live] associate-access-policy ($POLICY at cluster scope)..."
aws eks associate-access-policy --cluster-name "$CLUSTER" --principal-arn "$PRINCIPAL" \
    --policy-arn "$POLICY_ARN" --access-scope type=cluster >/dev/null
echo "[live] grant written. Review CloudTrail for the AssociateAccessPolicy event."
# The EXIT trap reverts the grant next.
