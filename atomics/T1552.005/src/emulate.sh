#!/usr/bin/env bash
# TRR9011 (T1552.005) behavioral emulation: EC2 instance-role credentials used
# off-instance. The detectable step is the OFF-INSTANCE USE of instance-role
# credentials, which lands in CloudTrail; the IMDS theft itself leaves no API trace.
#
# Cloud has no free CI target, so this script has two honest halves:
#   * DOCUMENT/LIVE: with TRR9011_LIVE=1 and AWS credentials configured (ideally
#     instance-role credentials carried off the instance), it runs the real,
#     READ-ONLY off-instance calls (sts:GetCallerIdentity, ec2:DescribeInstances).
#     Requires your own AWS account. NOT run in CI.
#   * FIXTURE: with --show-fixture it prints the committed, schema-faithful
#     CloudTrail fixture the CI validator runs the detection over.
#
# The paired detection keys on an EC2 instance-role session (ec2RoleDelivery present,
# or an /i-<instanceid> session name) used from a source outside the account's egress.
# Rule: detections/sigma/T1552.005/aws_imds_creds_used_off_instance.yml
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9011"

if [[ "${2:-}" == "--show-fixture" || "${1:-}" == "--show-fixture" ]]; then
  echo "# Recorded CloudTrail fixtures the CI validator runs the rule over:"
  cat "$FIXDIR/attack.json"
  exit 0
fi

echo "== TRR9011.AWS.$PROC — EC2 instance-role credentials used off-instance =="
case "$PROC" in
  a) echo "A: SSRF to IMDSv1, then off-instance use."
     echo "   Theft (unlogged):  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>" ;;
  b) echo "B: SSRF to IMDSv2, then off-instance use."
     echo "   Theft (unlogged):  TOKEN=\$(curl -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')"
     echo "                      curl -H \"X-aws-ec2-metadata-token: \$TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>" ;;
  c) echo "C: On-host read (webshell/RCE) then off-instance use — same chokepoint as A/B." ;;
  d) echo "D: Retrieval via ssm:SendCommand (AWS-RunShellScript curl 169.254.169.254) then off-instance use." ;;
  e) echo "E: Off-instance use from ANOTHER AWS account (InsideAWS) — GuardDuty .InsideAWS only." ;;
  *) echo "usage: emulate.sh {a|b|c|d|e} [--live|--show-fixture]"; exit 1 ;;
esac

echo
echo "Off-instance USE (the detectable step), run with the stolen instance-role creds:"
echo "   aws sts get-caller-identity"
echo "   aws ec2 describe-instances --max-items 5"

if [[ "${TRR9011_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v aws >/dev/null || { echo "aws CLI not found"; exit 1; }
  echo
  echo "[live] running the READ-ONLY off-instance calls with the configured credentials..."
  aws sts get-caller-identity
  aws ec2 describe-instances --max-items 5 >/dev/null && echo "[live] ec2:DescribeInstances ok"
  echo "[live] done. Review CloudTrail for the AssumedRole/ec2RoleDelivery events' sourceIPAddress."
else
  echo
  echo "(dry) set TRR9011_LIVE=1 (with instance-role creds configured off-instance) to run the"
  echo "      read-only calls in your own account, or pass --show-fixture for the recorded telemetry."
fi
