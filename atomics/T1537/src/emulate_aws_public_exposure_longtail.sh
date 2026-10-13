#!/usr/bin/env bash
# TRR9021 (T1537) behavioral emulation: public / cross-account AWS resource exposure via the
# S3 bucket-ACL path and the service long-tail (EventBridge, EFS, Glue, SSM) that TRR9019
# (resource policies / snapshots / BPA) did not cover.
#
#   * DOCUMENT/LIVE: with TRR9021_LIVE=1 and AWS creds, performs one THROWAWAY exposure in your
#     own account and immediately reverts it. Your own AWS account. NOT run in CI.
#   * FIXTURE: --show-fixture prints the committed CloudTrail fixtures the CI validator runs over.
#
# Rules (all detections/sigma/T1537/):
#   aws_s3_bucket_acl_made_public.yml (A) ; aws_eventbridge_bus_made_public.yml (B) ;
#   aws_efs_file_system_policy_made_public.yml (C) ; aws_glue_resource_policy_made_public.yml (D) ;
#   aws_ssm_document_shared_publicly.yml (E)
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9021"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  cat "$FIXDIR/attack.json"; exit 0
fi

BUCKET="${TRR9021_BUCKET:-trr9021-exposed-bucket}"
BUS="${TRR9021_BUS:-trr9021-bus}"
DOC="${TRR9021_DOC:-trr9021-doc}"

echo "== TRR9021.AWS.$PROC — public resource exposure (ACL + service long-tail) =="
case "$PROC" in
  a) echo "A: S3 bucket ACL -> public. PutBucketAcl grantee http://acs.amazonaws.com/groups/global/AllUsers"
     echo "   (or x-amz-acl public-read). Requires success (ACLs disabled under bucket-owner-enforced)." ;;
  b) echo "B: EventBridge bus -> public. PutPermission principal \"*\" with no Condition." ;;
  c) echo "C: EFS file-system policy -> public. PutFileSystemPolicy Principal \"*\" with no scope." ;;
  d) echo "D: Glue Data Catalog resource policy -> public. PutResourcePolicy (glue) Principal \"*\"." ;;
  e) echo "E: SSM document -> public. ModifyDocumentPermission accountIdsToAdd All." ;;
  *) echo "usage: emulate_aws_public_exposure_longtail.sh {a|b|c|d|e} [--live|--show-fixture]"; exit 1 ;;
esac

if [[ "${TRR9021_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v aws >/dev/null || { echo "aws CLI not found"; exit 1; }
  echo
  case "$PROC" in
    a) echo "[live] granting public-read ACL on $BUCKET, then reverting to private..."
       aws s3api put-bucket-acl --bucket "$BUCKET" --acl public-read
       echo "[live] review CloudTrail for PutBucketAcl (AllUsers). Reverting..."
       aws s3api put-bucket-acl --bucket "$BUCKET" --acl private ;;
    b) echo "[live] granting Principal '*' PutEvents on bus $BUS, then revoking..."
       aws events put-permission --event-bus-name "$BUS" --action events:PutEvents \
         --principal '*' --statement-id trr9021-open-bus
       echo "[live] review CloudTrail for PutPermission. Revoking..."
       aws events remove-permission --event-bus-name "$BUS" --statement-id trr9021-open-bus ;;
    e) echo "[live] sharing SSM document $DOC publicly, then un-sharing..."
       aws ssm modify-document-permission --name "$DOC" --permission-type Share --account-ids-to-add All
       echo "[live] review CloudTrail for ModifyDocumentPermission. Un-sharing..."
       aws ssm modify-document-permission --name "$DOC" --permission-type Share --account-ids-to-remove All ;;
    *) echo "[live] procedure $PROC (EFS/Glue) needs an existing throwaway file system / catalog;"
       echo "       see the fixture for the exact PutFileSystemPolicy / PutResourcePolicy shape." ;;
  esac
  echo "[live] done."
else
  echo
  echo "(dry) set TRR9021_LIVE=1 with AWS creds (and the relevant throwaway resource you own) to run"
  echo "      the expose+revert, or pass --show-fixture for the recorded telemetry."
fi
