#!/usr/bin/env bash
# TRR9023 (T1078.004 / T1550.001) behavioral emulation: USE of a federated identity credential --
# a service principal signs in to Entra with a workload-identity-federation token exchange, which
# surfaces in the Entra service-principal sign-in log (FederatedCredentialId populated).
#
#   * DOCUMENT/LIVE: with TRR9023_LIVE=1 (or --live), an external OIDC token, and the target
#     appId/tenant, Procedure A runs a real WIF client-credentials token exchange against Entra.
#     Your own tenant/app. It reads the HTTP status: it prints "done" only for a success, and for
#     a refusal it prints the Entra error code and description and exits non-zero. It never prints
#     or keeps the access token, and the token is carried on stdin, not on a command line. This
#     script changes nothing in the tenant, so it holds no undo block. NOT run in CI. A full live
#     run needs an external OIDC issuer the app's FIC trusts, which a person has no easy way to
#     produce; see step 7.5 of the Azure page for a different way to get a real record. Only
#     procedure a has a live run; b, c and d make no request and stop with exit 1.
#   * FIXTURE: --show-fixture prints the committed Entra SP sign-in fixtures the CI validator
#     runs the detection over.
#
# Rule: detections/sigma/T1078.004/entra_service_principal_federated_credential_signin.yml
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9023"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  cat "$FIXDIR/attack.json"; exit 0
fi

# A live run needs your real tenant and appId in TRR9023_TENANT and TRR9023_APPID (see the
# checks in the live branch). The dry mode prints no placeholder ID, so none is set here.

echo "== TRR9023.AZR.$PROC — federated service-principal sign-in (FIC use) =="
case "$PROC" in
  a) echo "A: SP signs in with the planted federated credential (WIF token exchange)."
     echo "   LOGGED: AADServicePrincipalSignInLogs, properties.federatedCredentialId present,"
     echo "   clientCredentialType clientAssertion, resultType 0 -- for an SP whose baseline is a secret/cert." ;;
  b) echo "B: first-seen overlay for an SP that legitimately federates (new FIC id / IP / ASN / resource)."
     echo "   Stateful -- a hunting overlay, not a stateless Sigma rule." ;;
  c) echo "C: managed-identity FIC use -- lands in AADManagedIdentitySignInLogs (a companion table)." ;;
  d) echo "D: cross-log correlation -- FIC write (audit) then first federated use (sign-in). GAP/future." ;;
  *) echo "usage: emulate_entra_sp_fic_signin.sh {a|b|c|d} [--live|--show-fixture]"; exit 1 ;;
esac
echo
echo "Chokepoint field: properties.federatedCredentialId (present only on a federated sign-in)."
echo "Telemetry gate: Entra P1/P2 + the ServicePrincipalSignInLogs diagnostic category (opt-in)."

if [[ "${TRR9023_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  echo
  # Only A has a live run. B (a stateful overlay), C (a different log table) and D (a gap)
  # have none: the script makes no request and causes no record, so it does not end with
  # exit 0.
  if [[ "$PROC" != "a" ]]; then
    echo "[live] procedure $PROC has no live run: no record was caused. The script made no request." >&2
    exit 1
  fi
  command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }
  # No placeholder in a live run. The run needs your real tenant, appId and an external OIDC
  # token the app's FIC trusts. Stop before any request when one is not set.
  if [[ -z "${TRR9023_TENANT:-}" ]]; then
    echo "[live] TRR9023_TENANT is not set. Set it to your own Entra tenant ID." >&2
    echo "[live] Stopping before any request." >&2
    exit 2
  fi
  if [[ -z "${TRR9023_APPID:-}" ]]; then
    echo "[live] TRR9023_APPID is not set. Set it to your own app (client) ID." >&2
    echo "[live] Stopping before any request." >&2
    exit 2
  fi
  if [[ -z "${TRR9023_OIDC_TOKEN:-}" ]]; then
    echo "[live] TRR9023_OIDC_TOKEN is not set. Set it to an external-IdP OIDC JWT the app's FIC trusts." >&2
    echo "[live] Stopping before any request." >&2
    exit 2
  fi
  echo "[live] exchanging the external OIDC token for an app-only Entra token (client_credentials, FIC)..."
  # The token is read from stdin, never put on a command line. --data-urlencode "name@-" reads the
  # assertion value from stdin and URL-encodes it. -w appends the HTTP status as the last line of
  # the output; the body (which holds the access token on success) stays in a variable, is never
  # printed, and is parsed for error fields only on a refusal.
  set +e
  RESPONSE="$(printf '%s' "${TRR9023_OIDC_TOKEN}" | curl -sS -w $'\n%{http_code}' -X POST \
    "https://login.microsoftonline.com/${TRR9023_TENANT}/oauth2/v2.0/token" \
    --data-urlencode "client_id=${TRR9023_APPID}" \
    --data-urlencode "scope=https://graph.microsoft.com/.default" \
    --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_assertion@-")"
  CURL_RC=$?
  set -e
  if [[ $CURL_RC -ne 0 ]]; then
    echo "[live] the request to Entra could not be sent (curl exit $CURL_RC)." >&2
    exit 1
  fi
  STATUS="${RESPONSE##*$'\n'}"
  # The last line must be the three-digit HTTP status that -w appended. When it is not (the
  # output had no status line, or the code is on the same line as the body), the body — which
  # on success holds the access token — is NOT printed. Drop the response and stop.
  if [[ ! "$STATUS" =~ ^[0-9][0-9][0-9]$ ]]; then
    unset RESPONSE STATUS
    echo "[live] curl gave no HTTP status line. The answer is not printed (it can hold a token)." >&2
    exit 1
  fi
  if [[ "$STATUS" == "200" ]]; then
    BODY="${RESPONSE%$'\n'*}"; unset RESPONSE
    # A 200 with no access_token is not a sign-in. Require the token key (then drop the body,
    # never print it) before the run reports success.
    if ! printf '%s' "$BODY" | grep -q '"access_token"'; then
      unset BODY
      echo "[live] HTTP 200 with no access_token in the body: no sign-in. The body is not printed." >&2
      exit 1
    fi
    unset BODY   # the success body holds the access token; drop it now, never print it
    echo "[live] sign-in succeeded (HTTP 200). Review AADServicePrincipalSignInLogs for"
    echo "       federatedCredentialId on appId ${TRR9023_APPID}."
    echo "[live] done."
  else
    # An error body carries no access token. Report the Entra error code and description.
    BODY="${RESPONSE%$'\n'*}"; unset RESPONSE
    ERRCODE="$(printf '%s' "$BODY" | sed -n 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    ERRDESC="$(printf '%s' "$BODY" | sed -n 's/.*"error_description"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    echo "[live] Entra refused the token exchange (HTTP ${STATUS})." >&2
    [[ -n "$ERRCODE" ]] && echo "[live] error: ${ERRCODE}" >&2
    [[ -n "$ERRDESC" ]] && echo "[live] error_description: ${ERRDESC}" >&2
    exit 1
  fi
else
  echo
  if [[ "$PROC" == "a" ]]; then
    echo "(dry) set TRR9023_LIVE=1 (with TRR9023_OIDC_TOKEN, TRR9023_TENANT, TRR9023_APPID) to run"
    echo "      the token exchange, or pass --show-fixture for the recorded telemetry."
  else
    echo "(dry) procedure $PROC has no live run. Pass --show-fixture for the recorded telemetry."
  fi
fi
