#!/usr/bin/env bash
# TRR9014 (T1098.003) behavioral emulation: public IAM exposure via allUsers /
# allAuthenticatedUsers on a GCP resource.
#
#   * DOCUMENT/LIVE: with TRR9014_LIVE=1, TRR9014_BUCKET / TRR9014_SERVICE set and
#     gcloud authed, grants allUsers then REVOKES it on a throwaway resource. Needs
#     your own project. NOT run in CI.
#   * FIXTURE: --show-fixture prints the committed Cloud Audit Log fixtures the CI
#     validator runs the detection over.
#
# Rule: detections/sigma/T1098.003/gcp_public_iam_member_grant.yml
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9014"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  cat "$FIXDIR/attack.json"; exit 0
fi

echo "== TRR9014.GCP.$PROC — public IAM exposure (allUsers / allAuthenticatedUsers) =="
case "$PROC" in
  a) echo "A: grant allUsers objectViewer on a bucket (delta path: storage.setIamPermissions)."
     echo "   gcloud storage buckets add-iam-policy-binding gs://\$BUCKET --member=allUsers --role=roles/storage.objectViewer" ;;
  b) echo "B: grant allUsers run.invoker on a Cloud Run service (request path)."
     echo "   gcloud run services add-iam-policy-binding \$SERVICE --member=allUsers --role=roles/run.invoker --region=\$REGION" ;;
  c) echo "C: non-IAM exposure (legacy ACL / --no-invoker-iam-check / BigQuery access) — detection gap." ;;
  *) echo "usage: emulate.sh {a|b|c} [--live|--show-fixture]"; exit 1 ;;
esac

if [[ "${TRR9014_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v gcloud >/dev/null || { echo "gcloud not found"; exit 1; }
  echo
  if [[ "$PROC" == "a" ]]; then
    : "${TRR9014_BUCKET:?set TRR9014_BUCKET to a throwaway bucket name}"
    echo "[live] granting allUsers on gs://$TRR9014_BUCKET, then revoking..."
    gcloud storage buckets add-iam-policy-binding "gs://$TRR9014_BUCKET" --member=allUsers --role=roles/storage.objectViewer
    gcloud storage buckets remove-iam-policy-binding "gs://$TRR9014_BUCKET" --member=allUsers --role=roles/storage.objectViewer
  elif [[ "$PROC" == "b" ]]; then
    : "${TRR9014_SERVICE:?set TRR9014_SERVICE}"; : "${TRR9014_REGION:?set TRR9014_REGION}"
    echo "[live] granting allUsers on service $TRR9014_SERVICE, then revoking..."
    gcloud run services add-iam-policy-binding "$TRR9014_SERVICE" --member=allUsers --role=roles/run.invoker --region="$TRR9014_REGION"
    gcloud run services remove-iam-policy-binding "$TRR9014_SERVICE" --member=allUsers --role=roles/run.invoker --region="$TRR9014_REGION"
  fi
  echo "[live] done. Review the Admin Activity log SetIamPolicy event for the public member."
else
  echo
  echo "(dry) set TRR9014_LIVE=1 (with a throwaway bucket/service) to run grant+revoke,"
  echo "      or pass --show-fixture for the recorded telemetry."
fi
