#!/usr/bin/env bash
# TRR9019 (T1537) behavioral emulation: exposing an AWS resource to the public (or a
# foreign account) — a resource-based policy naming Principal "*", a snapshot/AMI shared
# with group=all, or S3 Block Public Access turned off.
#
#   * DOCUMENT/LIVE: with TRR9019_LIVE=1 and AWS creds, performs one THROWAWAY exposure in
#     your own account and immediately reverts it. Your own AWS account. NOT run in CI.
#   * FIXTURE: --show-fixture prints the committed CloudTrail fixtures the CI validator
#     runs the detections over.
#
# Rules:
#   detections/sigma/T1537/aws_resource_policy_made_public.yml       (A resource policy)
#   detections/sigma/T1537/aws_snapshot_or_ami_made_public.yml       (B snapshot/AMI)
#   detections/sigma/T1537/aws_s3_block_public_access_disabled.yml   (C BPA)
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9019"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  cat "$FIXDIR/attack.json"; exit 0
fi

BUCKET="${TRR9019_BUCKET:-trr9019-exposed-bucket}"
read -r -d '' PUBLIC_POLICY <<JSON || true
{"Version":"2012-10-17","Statement":[{"Sid":"trr9019-public","Effect":"Allow",
"Principal":"*","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::${BUCKET}/*"}]}
JSON

echo "== TRR9019.AWS.$PROC — public / cross-account resource exposure =="
case "$PROC" in
  a) echo "A: resource-based policy -> public. PutBucketPolicy (S3) / SetRepositoryPolicy (ECR) /"
     echo "   PutKeyPolicy (KMS) / PutResourcePolicy (Secrets) / SetTopicAttributes (SNS) /"
     echo "   SetQueueAttributes (SQS) / AddPermission (Lambda), Principal \"*\", no scoping Condition." ;;
  b) echo "B: public disk-image / snapshot share. ModifyImageAttribute (AMI) /"
     echo "   ModifySnapshotAttribute (EBS) / ModifyDBSnapshotAttribute (RDS), group=all / valuesToAdd=all." ;;
  c) echo "C: disable S3 Block Public Access. PutBucketPublicAccessBlock (flag=false) /"
     echo "   PutAccountPublicAccessBlock / DeletePublicAccessBlock." ;;
  d) echo "D: public bucket ACL (AllUsers). PutBucketAcl grantee .../groups/global/AllUsers."
     echo "   Default-logged management event; not covered by a committed rule yet (backlog)." ;;
  e) echo "E: object-level ACL / data-plane exposure. PutObjectAcl / PutObject x-amz-acl=public-read."
     echo "   GAP: S3 DATA event (off by default); the public READ is never logged in the victim account." ;;
  *) echo "usage: emulate_aws_public_exposure.sh {a|b|c|d|e} [--live|--show-fixture]"; exit 1 ;;
esac
echo
echo "Public bucket policy (the A exemplar; Principal \"*\", no Condition):"
echo "$PUBLIC_POLICY"

if [[ "${TRR9019_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v aws >/dev/null || { echo "aws CLI not found"; exit 1; }
  echo
  echo "[live] turning OFF Block Public Access on $BUCKET, applying the public policy, then reverting..."
  aws s3api put-public-access-block --bucket "$BUCKET" \
    --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
  aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$PUBLIC_POLICY"
  echo "[live] exposed; review CloudTrail for PutBucketPublicAccessBlock + PutBucketPolicy. Reverting..."
  aws s3api delete-bucket-policy --bucket "$BUCKET"
  aws s3api put-public-access-block --bucket "$BUCKET" \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
  echo "[live] reverted (BPA re-enabled, policy removed). Done."
else
  echo
  echo "(dry) set TRR9019_LIVE=1 with AWS creds (and an existing \$TRR9019_BUCKET you own) to run the"
  echo "      throwaway expose+revert, or pass --show-fixture for the recorded telemetry."
fi
