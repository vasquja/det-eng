#!/usr/bin/env bash
# TRR9017 (T1528) behavioral emulation: illicit OAuth consent grant and device-code
# phishing against Microsoft Entra ID.
#
#   * DOCUMENT/LIVE: with TRR9017_LIVE=1 (or --live as the second argument) and, for a/b/c/e,
#     the Azure CLI (`az`) signed in to YOUR OWN tenant, the script is written to cause the
#     audit or sign-in record that the paired rule reads, and it runs an undo command for
#     each change it made. No run against a tenant was done (docs/setup/cloud-azure.md).
#     It calls Microsoft Graph with `az rest`; the device-code flow (D) uses only `curl`
#     against the Microsoft identity platform (no az). There is no Graph extension and no `mgc`.
#     NOT run in CI. The live run needs TRR9017_TENANT (your tenant ID); it stops before
#     any change (exit 2) when that is not set, and when TRR9017_APP_NAME is set to a name
#     that does not start with trr9017- (a, b, c, e).
#       A  browser consent screen (only a person can cause the record) -> audit
#          "Consent to application". After the person presses Enter, the run reads the
#          grant that the person made and removes it; if the run stops before that, it
#          names the grant as a change that can stay.
#       B  POST /oauth2PermissionGrants, ConsentType AllPrincipals (tenant-wide) ->
#          audit "Add delegated permission grant".
#       C  POST /servicePrincipals/{graph}/appRoleAssignedTo -> audit "Add app role
#          assignment to service principal".
#       D  device-code flow with curl and a public client; every token is discarded and
#          never printed; the device code (the secret that the token request redeems) goes
#          to curl on its standard input, not on a command line, and is never printed; the
#          shell's signed-in account is NOT changed -> sign-in
#          authenticationProtocol=deviceCode.
#       E  POST /oauth2PermissionGrants, ConsentType Principal -> audit "Add delegated
#          permission grant".
#     The throwaway application has no credential. The undo removes the grant / the app
#     role assignment, the service principal and the application. A run exits 0 only when
#     each command and each undo command was successful and the script does not know that
#     the record was not caused. When it knows that (a that no person accepted, an app role
#     that Microsoft Graph does not have, d that did not record a successful sign-in), it
#     reverts what it made, says so, and exits 1. A create command that does not give one
#     ID stops the run (exit 1): the run sends no delete request with an answer that is not
#     an ID (letters, digits, "-" and "_" only), and it names the change that can stay. A stop signal (Ctrl-C) or a
#     command that fails runs the undo command of each change that was made; a change whose
#     command was stopped in the middle can stay, and an undo command that fails leaves its
#     change.
#   * FIXTURE: --show-fixture prints the committed Entra audit/sign-in fixtures the CI
#     validator runs the detections over (--show-fixture signin for the device-code set).
#
# Rules:
#   detections/sigma/T1528/entra_illicit_oauth_consent_grant.yml   (A/B/C/E consent)
#   detections/sigma/T1528/entra_device_code_authentication.yml    (D device code)
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9017"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  if [[ "${2:-}" == "signin" || "${3:-}" == "signin" ]]; then
    cat "$FIXDIR/attack_signin.json"
  else
    cat "$FIXDIR/attack.json"
  fi
  exit 0
fi

APP="${TRR9017_APP_NAME:-trr9017-illicit-consent-app}"
# High-risk delegated scopes that define the chokepoint (offline_access + mailbox).
SCOPES="${TRR9017_SCOPES:-offline_access Mail.ReadWrite Mail.Send Files.ReadWrite.All}"
# High-risk application permission (app role) for procedure C.
APPROLE="${TRR9017_APPROLE:-Mail.Read}"
# Microsoft Graph, the resource of every grant here.
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
# Procedure D public client. Azure CLI is a pre-consented first-party public client, so
# a person can run the device-code flow with it. It is a published ID, not a secret.
DC_CLIENT="${TRR9017_DEVICECODE_CLIENT_ID:-04b07795-8ddb-461a-bbee-02f9e1bf7b46}"
DC_SCOPE="${TRR9017_DEVICECODE_SCOPE:-openid profile offline_access https://graph.microsoft.com/User.Read}"

echo "== TRR9017.AZR.$PROC — Entra illicit OAuth consent / device-code phishing =="
case "$PROC" in
  a) echo "A: end-user delegated consent (ConsentType=Principal) to high-privilege scopes."
     echo "   LIVE: register a throwaway app, print the consent URL, wait for the person to"
     echo "   sign in and Accept. The browser consent writes audit 'Consent to application'." ;;
  b) echo "B: tenant-wide consent (ConsentType=AllPrincipals)."
     echo "   LIVE: POST /oauth2PermissionGrants (AllPrincipals) creates the grant directly, so"
     echo "   the audit event is 'Add delegated permission grant' with ConsentType AllPrincipals"
     echo "   and the high-privilege Scope list (IsAdminConsent=True appears only on the portal"
     echo "   admin-consent variant, which the rule also catches by the scope)." ;;
  c) echo "C: application-permission (app role) grant to a service principal."
     echo "   LIVE: POST /servicePrincipals/{graph}/appRoleAssignedTo; writes audit"
     echo "   'Add app role assignment to service principal' (AppRole.Value)." ;;
  d) echo "D: device-code phishing — start the OAuth device-authorization grant; the person"
     echo "   enters the user_code at microsoft.com/devicelogin; the token is discarded."
     echo "   LIVE: curl against the identity platform with a public client. The shell's"
     echo "   signed-in account is NOT changed. LOGGED in the sign-in log:"
     echo "   authenticationProtocol=deviceCode." ;;
  e) echo "E: direct Graph creation of the grant (POST /oauth2PermissionGrants,"
     echo "   ConsentType=Principal) by an already-authorized identity — same audit event"
     echo "   as A, no interactive UI." ;;
  *) echo "usage: emulate_entra_consent.sh {a|b|c|d|e} [--live|--show-fixture [signin]]"; exit 1 ;;
esac
echo
echo "High-risk delegated scopes (the discriminator vs benign SSO consent):"
echo "  $SCOPES"

if [[ "${TRR9017_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  if [[ "$PROC" == "d" ]]; then
    command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }
  else
    command -v az >/dev/null || { echo "az CLI not found" >&2; exit 1; }
  fi
  # No placeholder in a live run. The run needs your own tenant ID. Stop before the first
  # change when it is not set.
  if [[ -z "${TRR9017_TENANT:-}" ]]; then
    echo "[live] TRR9017_TENANT is not set. Set it to your own Microsoft Entra tenant ID." >&2
    echo "[live] Stopping before any change." >&2
    exit 2
  fi
  # The name of the throwaway application starts with trr9017-. The check for leftovers
  # (docs/setup/cloud-azure.md) looks for that start of the name. And the undo then never
  # deletes an application of yours: if one application with the same display name is in
  # the tenant, az uses it again (with two or more, az stops with an error). Stop before any change when a name that you set does not
  # start with trr9017-.
  if [[ "$PROC" != "d" && "$APP" != trr9017-* ]]; then
    echo "[live] TRR9017_APP_NAME must start with trr9017- (it is '$APP'). Stopping before any change." >&2
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

  # Read one string value out of a flat JSON object, by key. Used for the device-code
  # response only. Never used on a token value.
  json_get() { printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n1; }
  json_num() { printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p" | head -n1; }
  # An ID goes into the URL of a delete request, so the run accepts only the characters of
  # an Entra ID: letters, digits, "-" and "_" (an object ID is a GUID; the ID of a grant or
  # of an app role assignment is base64url text). An answer that is empty, or that holds a
  # blank, a tab, a line break, a carriage return, "/", "?" or "." is not an ID.
  is_id() { [[ "$1" =~ ^[A-Za-z0-9_-]{1,200}$ ]]; }

  # Register the throwaway application and its service principal, and the undo of each.
  # Sets APPID (client appId) and CLIENT_SP_ID (client service-principal object id).
  setup_app_sp() {
    echo "[live] registering throwaway app '$APP' and its service principal..."
    change_next "the throwaway application $APP"
    # One create call gives both IDs, with no second request. For a list of two values
    # (--query '[id, appId]'), the tsv format prints each value on its own line. Microsoft
    # Learn ("Set shell variables from Azure CLI output") reads such an answer with
    # read -d '': read then splits at each blank, tab and newline, so a tab between the two
    # IDs is good too. An ID holds none of these. The delete undo uses the OBJECT id: az
    # resolves an appId with a list request that a just-created app may not yet answer, so
    # the object id is safer. The appId is what 'az ad sp create --id' and the consent URL
    # need.
    local _ids _app_obj _more
    _ids="$(az ad app create --display-name "$APP" --sign-in-audience AzureADMyOrg \
      --web-redirect-uris http://localhost --query '[id, appId]' -o tsv)"
    _app_obj=""; APPID=""; _more=""
    # read -d '' gives a non-zero status at the end of the text (the text has no NUL
    # character). That is normal, so the status is not a failure of the run.
    read -r -d '' _app_obj APPID _more <<< "$_ids" || true
    if ! is_id "$_app_obj" || ! is_id "$APPID" || [[ -n "$_more" ]]; then
      echo "[live] az ad app create did not return the object id and the appId (two values)." >&2
      echo "[live] LEFT BEHIND: the application '$APP'. Find its object id, then remove it:" >&2
      echo "[live]   az ad app list --display-name '$APP' --query \"[].id\" -o tsv" >&2
      echo "[live]   az ad app delete --id <the object id that the first command printed>" >&2
      exit 1
    fi
    undo az ad app delete --id "$_app_obj"
    change_next "the service principal of the application $APP"
    CLIENT_SP_ID="$(az ad sp create --id "$APPID" --query id -o tsv)"
    # Not one object id: the run cannot register the undo of this change. The exit path
    # names the change and says that it can stay.
    if ! is_id "$CLIENT_SP_ID"; then
      echo "[live] az ad sp create did not return one object id. Stopping." >&2
      exit 1
    fi
    undo az ad sp delete --id "$CLIENT_SP_ID"
  }

  echo
  case "$PROC" in
    a)
      setup_app_sp
      SCOPE_ENC="${SCOPES// /%20}"
      AUTH_URL="https://login.microsoftonline.com/${TRR9017_TENANT}/oauth2/v2.0/authorize?client_id=${APPID}&response_type=code&redirect_uri=http%3A%2F%2Flocalhost&response_mode=query&scope=${SCOPE_ENC}&prompt=consent"
      echo "[live] end-user consent needs a person in a browser. Open this URL, sign in, and"
      echo "[live] choose Accept (do not select 'Consent on behalf of your organization'):"
      echo
      echo "    $AUTH_URL"
      echo
      echo "[live] Sign in as a user who can accept these scopes. On a new tenant, the default"
      echo "[live] consent policy of Microsoft refuses Mail.ReadWrite and Files.ReadWrite.All for a"
      echo "[live] user who is not an administrator. Thus sign in as an administrator, or stop"
      echo "[live] (Ctrl-C) and run again with TRR9017_SCOPES='offline_access Mail.Send' for a user"
      echo "[live] who is not an administrator."
      echo "[live] The browser then redirects to http://localhost (it will not load; that is"
      echo "[live] normal — the 'Consent to application' record is written when you Accept)."
      _caused=0
      if [ -t 0 ]; then
        echo "[live] If you accept the consent and then stop the run at this prompt (Ctrl-C), the grant that"
        echo "[live] you made has no undo. Press Enter: the run then finds the grant and removes it."
        read -r -p "[live] Press Enter after you accepted the consent (Ctrl-C to abort)... " _ignore || true
        # From here to the `undo` line (or to the line that finds no grant), a grant of the
        # person possibly exists and has no undo. If the read fails or a stop signal comes,
        # the exit path names it; a stop signal waits for the registration of the undo.
        change_next "a delegated grant to the application $APP, if a person accepted the consent"
        GRANT_ID="$(az rest --method get \
          --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$filter=clientId eq '${CLIENT_SP_ID}'" \
          --query "value[0].id" -o tsv)"
        if [[ -n "$GRANT_ID" ]] && ! is_id "$GRANT_ID"; then
          # The answer is not empty and is not one id: the run cannot know the grant.
          echo "[live] the read of the delegated grants did not return one id. A grant possibly" >&2
          echo "[live] exists, and this run has no undo for it: do the check that nothing stays behind." >&2
          exit 1
        fi
        if [ -n "$GRANT_ID" ]; then
          _caused=1
          echo "[live] a delegated grant now exists ($GRANT_ID): the 'Consent to application' record was caused."
          # Remove the grant the person created, explicitly and before the service principal,
          # rather than relying on a delete cascade.
          undo az rest --method delete \
            --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/${GRANT_ID}"
        else
          change_next ""        # the read found no grant: no change is in progress
          echo "[live] no delegated grant was found. You did not accept, so no 'Consent to application' record was caused." >&2
        fi
      else
        echo "[live] No person is here to accept in a browser, so no 'Consent to application'" >&2
        echo "[live] record was caused. Re-run in a terminal, or use the committed fixture." >&2
      fi
      undo_now
      # Exit 0 only when the record was caused. When it was not, the throwaway objects are
      # reverted above and the run reports that no record was caused (exit 1).
      if [ "$_caused" = 1 ]; then
        echo "[live] done."
      else
        echo "[live] the throwaway app and service principal were removed; no record was caused." >&2
        exit 1
      fi
      ;;

    b|e)
      setup_app_sp
      echo "[live] resolving the Microsoft Graph service principal in your tenant..."
      GRAPH_SP_ID="$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)"
      if [[ "$PROC" == "b" ]]; then
        echo "[live] creating a tenant-wide (AllPrincipals) delegated grant to the high-risk scopes..."
        BODY="$(printf '{"clientId":"%s","consentType":"AllPrincipals","resourceId":"%s","scope":"%s"}' \
          "$CLIENT_SP_ID" "$GRAPH_SP_ID" "$SCOPES")"
      else
        echo "[live] resolving your signed-in user..."
        USER_ID="$(az ad signed-in-user show --query id -o tsv)"
        echo "[live] creating a single-user (Principal) delegated grant to the high-risk scopes..."
        BODY="$(printf '{"clientId":"%s","consentType":"Principal","resourceId":"%s","principalId":"%s","scope":"%s"}' \
          "$CLIENT_SP_ID" "$GRAPH_SP_ID" "$USER_ID" "$SCOPES")"
      fi
      change_next "the delegated permission grant to Microsoft Graph"
      GRANT_ID="$(az rest --method post --uri https://graph.microsoft.com/v1.0/oauth2PermissionGrants \
        --headers Content-Type=application/json --body "$BODY" --query id -o tsv)"
      # Not one id: the run cannot register the undo of this change. The exit path names
      # the change and says that it can stay.
      if ! is_id "$GRANT_ID"; then
        echo "[live] the POST to /oauth2PermissionGrants did not return one id. Stopping." >&2
        exit 1
      fi
      undo az rest --method delete --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/${GRANT_ID}"
      echo "[live] grant $GRANT_ID created. Review the Entra audit log for 'Add delegated"
      echo "[live] permission grant' with the high-risk Scope list. Reverting..."
      undo_now
      echo "[live] done."
      ;;

    c)
      setup_app_sp
      echo "[live] resolving the Microsoft Graph service principal and the '$APPROLE' app role..."
      GRAPH_SP_ID="$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)"
      APPROLE_ID="$(az ad sp show --id "$GRAPH_APP_ID" --query "appRoles[?value=='$APPROLE'].id | [0]" -o tsv)"
      if [ -z "$APPROLE_ID" ]; then
        echo "[live] Microsoft Graph exposes no app role '$APPROLE'. Stopping." >&2
        exit 1
      fi
      echo "[live] assigning the '$APPROLE' application permission to the throwaway service principal..."
      BODY="$(printf '{"principalId":"%s","resourceId":"%s","appRoleId":"%s"}' \
        "$CLIENT_SP_ID" "$GRAPH_SP_ID" "$APPROLE_ID")"
      change_next "the app role assignment of $APPROLE to the throwaway service principal"
      ASSIGN_ID="$(az rest --method post \
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${GRAPH_SP_ID}/appRoleAssignedTo" \
        --headers Content-Type=application/json --body "$BODY" --query id -o tsv)"
      # Not one id: the run cannot register the undo of this change. The exit path names
      # the change and says that it can stay.
      if ! is_id "$ASSIGN_ID"; then
        echo "[live] the POST to /appRoleAssignedTo did not return one id. Stopping." >&2
        exit 1
      fi
      undo az rest --method delete \
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${GRAPH_SP_ID}/appRoleAssignedTo/${ASSIGN_ID}"
      echo "[live] assignment $ASSIGN_ID created. Review the Entra audit log for 'Add app role"
      echo "[live] assignment to service principal' with AppRole.Value=$APPROLE. Reverting..."
      undo_now
      echo "[live] done."
      ;;

    d)
      echo "[live] starting the device-code flow (public client $DC_CLIENT). No change to your"
      echo "[live] CLI session; the token is discarded and never printed."
      DRESP="$(curl -sS -X POST "https://login.microsoftonline.com/${TRR9017_TENANT}/oauth2/v2.0/devicecode" \
        --data-urlencode "client_id=${DC_CLIENT}" --data-urlencode "scope=${DC_SCOPE}")" \
        || { echo "[live] could not reach the device-code endpoint. No sign-in was started." >&2; exit 1; }
      USER_CODE="$(json_get "$DRESP" user_code)"
      VERIFY_URI="$(json_get "$DRESP" verification_uri)"
      DEVICE_CODE="$(json_get "$DRESP" device_code)"
      INTERVAL="$(json_num "$DRESP" interval)"; [ -n "$INTERVAL" ] || INTERVAL=5
      if [ -z "$USER_CODE" ] || [ -z "$DEVICE_CODE" ]; then
        echo "[live] the device-code request returned no code (error: $(json_get "$DRESP" error))." >&2
        echo "[live] No sign-in was started, so no device-code sign-in record was caused." >&2
        exit 1
      fi
      echo "[live] Open $VERIFY_URI and enter the code:  $USER_CODE"
      echo "[live] (Sign in as the victim test user on another device or browser.)"
      # The rule reads only a SUCCESSFUL device-code sign-in (errorCode 0). A refused, declined
      # or expired attempt can leave a FAILED sign-in record, which the rule does not read. So
      # the script exits 0 only when it recorded a successful sign-in, and exits 1 otherwise.
      if [ -t 0 ] || [ "${TRR9017_DEVICECODE_POLL:-0}" = "1" ]; then
        echo "[live] waiting for the sign-in to finish..."
        _ok=0
        _i=0
        while [ "$_i" -lt 60 ]; do
          _i=$((_i + 1))
          # The device code is the secret that this request redeems. It goes to curl on its
          # standard input (--data-urlencode "name@-" reads the value there and URL-encodes
          # it), so it is not on a command line. It is never printed.
          TRESP="$(printf '%s' "$DEVICE_CODE" | curl -sS -X POST "https://login.microsoftonline.com/${TRR9017_TENANT}/oauth2/v2.0/token" \
            --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
            --data-urlencode "client_id=${DC_CLIENT}" \
            --data-urlencode "device_code@-")" \
            || { echo "[live] could not reach the token endpoint. No successful device-code sign-in was recorded." >&2; exit 1; }
          if printf '%s' "$TRESP" | grep -q '"access_token"'; then
            TRESP=
            _ok=1
            echo "[live] device-code sign-in SUCCEEDED. The sign-in log now records"
            echo "[live] authenticationProtocol=deviceCode with errorCode 0 — the record the rule reads."
            break
          fi
          _ERR="$(json_get "$TRESP" error)"; _EDESC="$(json_get "$TRESP" error_description)"; TRESP=
          case "$_ERR" in
            authorization_pending|slow_down) sleep "$INTERVAL" ;;
            "") echo "[live] unexpected token response (no access_token, no error). No successful" >&2
                echo "[live] device-code sign-in was recorded. Stopping." >&2
                exit 1 ;;
            *) echo "[live] the device-code sign-in did NOT succeed (error: $_ERR)."
               echo "[live] No successful device-code sign-in was recorded. The rule reads only a"
               echo "[live] successful device-code sign-in (errorCode 0); a refused or declined attempt"
               echo "[live] can leave a FAILED sign-in record, which the rule does not read."
               # The device-code flow is blocked by default in a new tenant (security defaults);
               # the exact error text of that block is not verified, so only hint on a block.
               if printf '%s' "$_EDESC" | grep -qiE 'blocked|security default|conditional access'; then
                 echo "[live] A tenant created on 2026-07-01 or later blocks the device-code flow by default"
                 echo "[live] (security defaults). Then you see an error like this and no successful sign-in."
                 echo "[live] The exact error text of that block is not verified."
               fi
               echo "[live] Use the committed fixture for the record the rule reads."
               exit 1 ;;
          esac
        done
        # Print "gave up" only when the loop ended with no successful sign-in (a time-out
        # after 60 polls). The flag _ok says that, not the counter: the 60th poll can be the
        # one that succeeds. (A refusal stops the run in the loop.)
        if [ "$_ok" != 1 ]; then
          echo "[live] gave up waiting (stopped after about 5 minutes; the code is valid for about" >&2
          echo "[live] 15 minutes, so you can re-run). No successful device-code sign-in was recorded;" >&2
          echo "[live] the rule reads only a successful one." >&2
          exit 1
        fi
      else
        echo "[live] No person is here to finish the sign-in, so no successful device-code sign-in" >&2
        echo "[live] was recorded. Re-run in a terminal, or set TRR9017_DEVICECODE_POLL=1 when the" >&2
        echo "[live] person signs in elsewhere, or use the committed fixture." >&2
        exit 1
      fi
      ;;
  esac
else
  echo
  echo "(dry) set TRR9017_LIVE=1 and TRR9017_TENANT=<your tenant ID> to cause the real record"
  echo "      and revert it (a, b, c, e need az signed in; d needs only curl),"
  echo "      or pass --show-fixture [signin] for the recorded telemetry."
fi
