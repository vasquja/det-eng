#!/usr/bin/env bash
# TRR9012 (T1078.004) behavioral emulation: using a leaked long-term IAM-user access
# key for initial access — the orientation (whoami) + account enumeration burst.
#
#   * DOCUMENT/LIVE: with TRR9012_LIVE=1 and a configured long-term IAM-user key
#     (ideally a throwaway, low-privilege key), runs the real READ-ONLY calls. Needs
#     your own AWS account. NOT run in CI.
#   * FIXTURE: --show-fixture prints the committed CloudTrail attack burst the CI
#     validator runs the detection over.
#
# Rule: detections/sigma/T1078.004/aws_leaked_access_key_recon.yml
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9012"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  cat "$FIXDIR/attack.json"; exit 0
fi

echo "== TRR9012.AWS.$PROC — leaked long-term access key =="
case "$PROC" in
  a) echo "A: direct API use + enumeration with a leaked AKIA key." ;;
  b) echo "B: data-plane recon (s3:GetObject, dynamodb, ...) — needs CloudTrail data events (gap)." ;;
  c) echo "C: STS pivot — sts:GetSessionToken with the key (caught at the pivot)." ;;
  *) echo "usage: emulate.sh {a|b|c} [--live|--show-fixture]"; exit 1 ;;
esac

echo
echo "Orientation + enumeration burst (the detectable step):"
echo "   aws sts get-caller-identity"
echo "   aws iam get-account-authorization-details --max-items 1"
echo "   aws iam list-users --max-items 5 ; aws s3api list-buckets"

if [[ "${TRR9012_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v aws >/dev/null || { echo "aws CLI not found"; exit 1; }
  echo
  echo "[live] running the READ-ONLY orientation + enumeration with the configured key..."
  aws sts get-caller-identity
  aws iam list-users --max-items 5 >/dev/null 2>&1 && echo "[live] iam:ListUsers ok" || echo "[live] iam:ListUsers denied (still a recon signal)"
  aws s3api list-buckets >/dev/null 2>&1 && echo "[live] s3:ListBuckets ok" || echo "[live] s3:ListBuckets denied"
  echo "[live] done. Review CloudTrail for IAMUser/AKIA events from this source IP."
else
  echo
  echo "(dry) set TRR9012_LIVE=1 with a throwaway long-term key configured to run the"
  echo "      read-only calls, or pass --show-fixture for the recorded telemetry."
fi
