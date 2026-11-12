#!/usr/bin/env bash
# TRR9013 (T1098.001) behavioral emulation: federated identity credential (FIC)
# backdoor on an Entra application (Procedure A) and a user-assigned managed identity
# (Procedure C). Adding a FIC that trusts an attacker-controlled OIDC issuer lets an
# external workload mint tokens as the identity, passwordless.
#
#   * DOCUMENT/LIVE: with TRR9013_LIVE=1 (or --live) and the Azure CLI signed in, the run
#     creates THROWAWAY objects in your own tenant, adds a no-op FIC with an example.com
#     issuer, then removes each object it made. Procedure A uses a throwaway app
#     registration. An app registration with the same display name that is already there is
#     used again and deleted, so remove a leftover trr9013-victim-app first. The delete of an
#     app is a soft delete: Entra keeps the app in "Deleted applications" for about 30 days,
#     where it can be restored, and the check that lists live apps does not show it.
#     Procedure C makes a throwaway resource group and user-assigned managed identity (names
#     start with trr9013-, a unique suffix for each run) in the region TRR9013_LOCATION
#     (default eastus). The subject is an exact value: Entra does not read a "*" in a subject
#     as a wildcard. NOT run in CI. A stop signal (Ctrl-C) or a command that fails reverts
#     each change that was made; a change whose command was stopped in the middle can stay.
#   * FIXTURE: --show-fixture prints the committed Entra-audit / Azure-Activity fixtures
#     the CI validator runs the detections over.
#
# Rules: detections/sigma/T1098.001/entra_app_federated_credential_backdoor.yml (A/B)
#        detections/sigma/T1098.001/azure_managed_identity_federated_credential_backdoor.yml (C)
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9013"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  echo "# app FIC (Entra audit):"; cat "$FIXDIR/attack.json"
  echo; echo "# managed-identity FIC (Azure Activity Log):"; cat "$FIXDIR/attack_mi.json"
  exit 0
fi

ISSUER="https://oidc.trr9013-attacker.example.com"   # RFC 2606 example.com: never a real tenant issuer
# An exact subject. Microsoft documents that a wildcard is not supported in a federated
# credential property value, so a "*" in the subject would match no token. An incorrect
# subject is still CREATED without error; the mismatch shows only when a token exchange
# fails. The rule reads the issuer, not the subject, so an exact value drives the same record.
SUBJECT="repo:trr9013-attacker/emulation:ref:refs/heads/main"

echo "== TRR9013.AZR.$PROC — federated identity credential backdoor =="
case "$PROC" in
  a) echo "A: add a FIC to an app registration (issuer $ISSUER)."
     echo "   az ad app federated-credential create --id <objectId> --parameters \\"
     echo "     '{\"name\":\"trr9013-backdoor\",\"issuer\":\"$ISSUER\",\"subject\":\"$SUBJECT\",\"audiences\":[\"api://AzureADTokenExchange\"]}'" ;;
  c) echo "C: add a FIC to a user-assigned managed identity (Azure Activity Log)."
     echo "   Live mode makes a throwaway resource group and managed identity (trr9013- names,"
     echo "   a unique suffix for each run), adds the FIC, then removes all three."
     echo "   az identity federated-credential create --name trr9013-mi-backdoor \\"
     echo "     --identity-name <mi> --resource-group <rg> --issuer $ISSUER \\"
     echo "     --subject $SUBJECT --audiences api://AzureADTokenExchange" ;;
  *) echo "usage: emulate_entra.sh {a|c} [--live|--show-fixture]"; exit 1 ;;
esac

if [[ "${TRR9013_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v az >/dev/null || { echo "az CLI not found" >&2; exit 1; }
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
  if [[ "$PROC" == "a" ]]; then
    echo "[live] creating a throwaway app, adding a no-op FIC with an unapproved issuer, then removing it..."
    # Use the application object ID (id) for the delete. For a GUID, az looks for it as an
    # appId with a list request first and falls back to the object ID when the list is empty;
    # the object ID avoids that lookup, which a just-created app may not yet answer.
    change_next "the throwaway application trr9013-victim-app"
    APP_ID=$(az ad app create --display-name trr9013-victim-app --query id -o tsv)
    # The answer must be the object ID: letters, digits, "-" and "_" only (it is a GUID). An
    # answer that is empty, or that holds a blank, a tab, a line break or "/" is not an ID:
    # the run cannot register the undo.
    [[ "$APP_ID" =~ ^[A-Za-z0-9_-]{1,200}$ ]] || { echo "[live] az ad app create did not return one object ID. Do the check that nothing stays behind (LEFT BEHIND: the application trr9013-victim-app)." >&2; exit 1; }
    undo az ad app delete --id "$APP_ID"
    change_next "the federated credential trr9013-backdoor on the application trr9013-victim-app"
    az ad app federated-credential create --id "$APP_ID" --parameters \
      "{\"name\":\"trr9013-backdoor\",\"issuer\":\"$ISSUER\",\"subject\":\"$SUBJECT\",\"audiences\":[\"api://AzureADTokenExchange\"]}"
    undo az ad app federated-credential delete --id "$APP_ID" --federated-credential-id trr9013-backdoor
    echo "[live] FIC added; review the Entra audit 'Update application' event. Reverting..."
    undo_now
    echo "[live] done."
  else
    # Procedure C: a throwaway resource group and user-assigned managed identity, then the FIC.
    LOCATION="${TRR9013_LOCATION:-eastus}"
    STAMP="$(date +%Y%m%d%H%M%S)"
    RG="trr9013-rg-${STAMP}"
    MI="trr9013-mi-${STAMP}"
    echo "[live] creating throwaway resource group '$RG' in $LOCATION..."
    change_next "the resource group $RG"
    az group create --name "$RG" --location "$LOCATION" >/dev/null
    undo az group delete --name "$RG" --yes
    echo "[live] creating throwaway managed identity '$MI'..."
    change_next "the managed identity $MI in the resource group $RG"
    az identity create --name "$MI" --resource-group "$RG" >/dev/null
    undo az identity delete --name "$MI" --resource-group "$RG"
    echo "[live] adding a no-op FIC with an unapproved issuer..."
    change_next "the federated credential trr9013-mi-backdoor on the managed identity $MI"
    az identity federated-credential create --name trr9013-mi-backdoor \
      --identity-name "$MI" --resource-group "$RG" --issuer "$ISSUER" \
      --subject "$SUBJECT" --audiences api://AzureADTokenExchange >/dev/null
    undo az identity federated-credential delete --name trr9013-mi-backdoor \
      --identity-name "$MI" --resource-group "$RG" --yes
    echo "[live] FIC added; review the Activity Log .../federatedIdentityCredentials/write event. Reverting..."
    undo_now
    echo "[live] done."
  fi
else
  echo
  echo "(dry) set TRR9013_LIVE=1 with az signed in to run the throwaway add+cleanup,"
  echo "      or pass --show-fixture for the recorded telemetry."
fi
