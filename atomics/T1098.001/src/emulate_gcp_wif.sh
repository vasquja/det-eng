#!/usr/bin/env bash
# TRR9018 (T1098.001) behavioral emulation: Workload Identity Federation backdoor in GCP —
# trust an external OIDC/AWS/SAML issuer and bind its principalSet to a service account so
# an external identity can impersonate the SA.
#
#   * DOCUMENT/LIVE: with TRR9018_LIVE=1 (or --live) and gcloud signed in, makes a THROWAWAY
#     workload-identity pool + provider, binds a principalSet to a service account
#     (roles/iam.workloadIdentityUser), then reverts each change. Your own project. NOT run
#     in CI. Needs TRR9018_PROJECT (your project ID); it stops before any change if it is not
#     set. When TRR9018_SA is not set the run makes a throwaway service account and removes it;
#     set TRR9018_SA to bind an existing service account instead (the run then removes only the
#     binding). When TRR9018_POOL is not set, the pool name is unique for each run, because
#     Google blocks the name of a deleted pool for 30 days. A pool or provider name that you
#     set must start with trr9018-. Only procedures a and c have a live run; b, d and e stop
#     with exit 1. A stop signal (Ctrl-C) or a command that fails reverts the changes that
#     were made. A change whose command was stopped in the middle can stay: the run names it.
#   * FIXTURE: --show-fixture prints the committed Cloud Audit Log fixtures the CI
#     validator runs the detections over.
#
# Rules:
#   detections/sigma/T1098.001/gcp_workload_identity_federation_sa_binding.yml   (A/C binding)
#   detections/sigma/T1098.001/gcp_workload_identity_pool_provider_created.yml   (A/B provider)
set -euo pipefail

PROC="${1:-c}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9018"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  cat "$FIXDIR/attack.json"; exit 0
fi

# Fixture-safe defaults. They are only for the text of the dry mode. A live run needs the
# real project ID in TRR9018_PROJECT (see the check in the live branch). The default issuer
# is an external issuer under example.com, and the provider is created with no attribute
# condition, which is what the rule reads. That Google accepts this issuer with no condition
# is not confirmed by a live run. (The GitHub issuer was the default before; the reason for
# the change is that Google asks for a condition for it.)
PROJECT="${TRR9018_PROJECT:-trr9018-prod}"
POOL="${TRR9018_POOL:-trr9018-ext-pool}"
PROVIDER="${TRR9018_PROVIDER:-trr9018-oidc}"   # 12 chars; a provider ID must be 4 to 32
ISSUER="${TRR9018_ISSUER:-https://attacker.example.com}"

LIVE=0
if [[ "${TRR9018_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then LIVE=1; fi

# A live run that did not get a pool name makes a unique one. It still starts with trr9018-.
if [[ "$LIVE" == "1" && -z "${TRR9018_POOL:-}" ]]; then
  POOL="trr9018-$(date +%Y%m%d%H%M%S)-${RANDOM}"
fi

echo "== TRR9018.GCP.$PROC — Workload Identity Federation abuse =="
case "$PROC" in
  a) echo "A: full backdoor — create pool + external provider, bind principalSet to an SA"
     echo "   (SetIAMPolicy adds roles/iam.workloadIdentityUser to principalSet://.../workloadIdentityPools/...)." ;;
  b) echo "B: loosen an existing provider's trust — UpdateWorkloadIdentityPoolProvider"
     echo "   (change issuerUri / broaden attributeMapping / blank the attributeCondition)." ;;
  c) echo "C: bind a principalSet to an already-trusted pool's SA (no provider change)." ;;
  d) echo "D: workforce-pool variant — bind principalSet://.../workforcePools/ directly to a"
     echo "   project/folder/org role (cloudresourcemanager SetIamPolicy). Sibling technique." ;;
  e) echo "E: data-plane USE — STS ExchangeToken -> iamcredentials GenerateAccessToken."
     echo "   GAP: both are Data Access / ADMIN_READ, OFF BY DEFAULT." ;;
  *) echo "usage: emulate_gcp_wif.sh {a|b|c|d|e} [--live|--show-fixture]"; exit 1 ;;
esac
echo
echo "The member that defines the chokepoint (vs benign GKE Workload Identity):"
echo "  principalSet://iam.googleapis.com/projects/<n>/locations/global/workloadIdentityPools/${POOL}/*"
echo "  role: roles/iam.workloadIdentityUser   issuer: ${ISSUER}"

if [[ "$LIVE" == "1" ]]; then
  # Only A and C have a live run (C is the binding leg of A). B (loosen a provider), D (the
  # workforce-pool sibling) and E (data-plane use) have no live run: the script makes no
  # change and causes no record, so it does not end with exit 0.
  case "$PROC" in
    a|c) ;;
    *) echo "[live] procedure $PROC has no live run: no record was caused. The script made no change. Use a or c." >&2
       exit 1 ;;
  esac
  command -v gcloud >/dev/null || { echo "gcloud not found" >&2; exit 1; }
  # No placeholder in a live run. The run needs your real project ID. Stop before the first
  # change when it is not set.
  if [[ -z "${TRR9018_PROJECT:-}" ]]; then
    echo "[live] TRR9018_PROJECT is not set. Set it to your own Google Cloud project ID." >&2
    echo "[live] Stopping before any change." >&2
    exit 2
  fi
  # Each throwaway object has a name that starts with trr9018-, so that the check for
  # leftovers finds it. Stop before any change when a name that you set does not.
  if [[ "$POOL" != trr9018-* ]]; then
    echo "[live] TRR9018_POOL must start with trr9018- (it is '$POOL'). Stopping before any change." >&2
    exit 2
  fi
  if [[ "$PROVIDER" != trr9018-* ]]; then
    echo "[live] TRR9018_PROVIDER must start with trr9018- (it is '$PROVIDER'). Stopping before any change." >&2
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
  echo
  echo "[live] project number lookup for '$PROJECT'..."
  PNUM="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
  # Stop before any change when the lookup gave no number (an empty or non-numeric answer),
  # or the member would name 'projects//...' and nothing could be reverted cleanly.
  if [[ ! "$PNUM" =~ ^[0-9]+$ ]]; then
    echo "[live] no project number for '$PROJECT'. Stopping before any change." >&2
    exit 1
  fi
  MEMBER="principalSet://iam.googleapis.com/projects/${PNUM}/locations/global/workloadIdentityPools/${POOL}/*"
  # The service account is the FIRST change on the throwaway path: a new SA needs some time to
  # propagate before another call uses it, and the two pool/provider creates give it that time.
  # Its address is read from the create command, so it is right even for an unusual project ID.
  if [[ -z "${TRR9018_SA:-}" ]]; then
    SA_ID="trr9018-sa-$(date +%Y%m%d%H%M%S)"
    echo "[live] creating throwaway service account '$SA_ID'..."
    change_next "service account $SA_ID in the project $PROJECT"
    SA="$(gcloud iam service-accounts create "$SA_ID" --project="$PROJECT" \
      --display-name="trr9018 throwaway target" --format='value(email)')"
    # The answer must be one line: the address of a trr9018-sa- account. With all other
    # answers the account exists (the command gave exit 0) but its address is not known, so
    # the run cannot register its undo. Say that it stays and how to remove it.
    SA_RE='^trr9018-sa-[A-Za-z0-9-]*@[A-Za-z0-9.-]+\.gserviceaccount\.com$'
    if [[ ! "$SA" =~ $SA_RE ]]; then
      echo "[live] service-accounts create did not return the address of the new account." >&2
      echo "[live] LEFT BEHIND: the service account '$SA_ID' in the project '$PROJECT'. Find its address with" >&2
      echo "[live]   gcloud iam service-accounts list --project=$PROJECT --filter=\"email~^${SA_ID}@\"" >&2
      echo "[live] and remove it with: gcloud iam service-accounts delete <address> --project=$PROJECT" >&2
      exit 1
    fi
    undo gcloud iam service-accounts delete "$SA" --project="$PROJECT" --quiet
  else
    SA="$TRR9018_SA"
    echo "[live] binding the service account you set: $SA"
  fi
  echo "[live] creating throwaway WIF pool '$POOL' and OIDC provider '$PROVIDER'..."
  change_next "workload identity pool $POOL in the project $PROJECT"
  gcloud iam workload-identity-pools create "$POOL" --project="$PROJECT" --location=global \
    --display-name="trr9018 ext pool" >/dev/null
  undo gcloud iam workload-identity-pools delete "$POOL" --project="$PROJECT" --location=global --quiet
  change_next "provider $PROVIDER of the workload identity pool $POOL"
  gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" --project="$PROJECT" \
    --location=global --workload-identity-pool="$POOL" --issuer-uri="$ISSUER" \
    --attribute-mapping="google.subject=assertion.sub" >/dev/null
  undo gcloud iam workload-identity-pools providers delete "$PROVIDER" --project="$PROJECT" \
    --location=global --workload-identity-pool="$POOL" --quiet
  echo "[live] binding the pool principalSet to $SA (roles/iam.workloadIdentityUser)..."
  # --condition=None: the run must say that it adds no condition. Without the option, when
  # the service account policy already holds a binding with a condition, gcloud asks a
  # question on a terminal and stops with an error when there is no terminal.
  change_next "binding of $MEMBER to roles/iam.workloadIdentityUser on the service account $SA"
  gcloud iam service-accounts add-iam-policy-binding "$SA" --project="$PROJECT" \
    --role=roles/iam.workloadIdentityUser --member="$MEMBER" --condition=None >/dev/null
  undo gcloud iam service-accounts remove-iam-policy-binding "$SA" --project="$PROJECT" \
    --role=roles/iam.workloadIdentityUser --member="$MEMBER" --condition=None
  echo "[live] review Cloud Audit Logs (Admin Activity) for SetIAMPolicy + CreateWorkloadIdentityPoolProvider. Reverting..."
  undo_now
  echo "[live] done."
else
  echo
  echo "(dry) set TRR9018_LIVE=1 (and TRR9018_PROJECT) with gcloud signed in to run the throwaway"
  echo "      pool/provider/binding create+revert, or pass --show-fixture for the recorded telemetry."
fi
