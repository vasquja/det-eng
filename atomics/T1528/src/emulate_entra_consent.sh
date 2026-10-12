#!/usr/bin/env bash
# TRR9017 (T1528) behavioral emulation: illicit OAuth consent grant and device-code
# phishing against Microsoft Entra ID.
#
#   * DOCUMENT/LIVE: with TRR9017_LIVE=1 and the Microsoft Graph CLI (`az`/`mgc`) signed
#     in, registers a THROWAWAY app, requests high-privilege delegated scopes, records the
#     consent/grant, then deletes the app. Your own tenant. NOT run in CI.
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

echo "== TRR9017.AZR.$PROC — Entra illicit OAuth consent / device-code phishing =="
case "$PROC" in
  a) echo "A: end-user delegated consent (ConsentType=Principal) to high-privilege scopes."
     echo "   LOGGED: audit 'Consent to application' + 'Add delegated permission grant'." ;;
  b) echo "B: admin / tenant-wide consent (IsAdminConsent=True, ConsentType=AllPrincipals)." ;;
  c) echo "C: application-permission (app role) grant to a service principal"
     echo "   (audit 'Add app role assignment to service principal', AppRole.Value)." ;;
  d) echo "D: device-code phishing — start the OAuth device-authorization grant; victim"
     echo "   enters the user_code at microsoft.com/devicelogin; capture the tokens."
     echo "   LOGGED ONLY in the sign-in log: authenticationProtocol=deviceCode." ;;
  e) echo "E: direct Graph creation of the grant (POST /oauth2PermissionGrants) by an"
     echo "   already-authorized identity — same audit events, no interactive UI." ;;
  *) echo "usage: emulate_entra_consent.sh {a|b|c|d|e} [--live|--show-fixture [signin]]"; exit 1 ;;
esac
echo
echo "High-risk delegated scopes (the discriminator vs benign SSO consent):"
echo "  $SCOPES"

if [[ "${TRR9017_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v az >/dev/null || { echo "az CLI (with the Microsoft Graph extension) not found"; exit 1; }
  echo
  if [[ "$PROC" == "d" ]]; then
    echo "[live] starting a device-code sign-in (Azure CLI, a first-party app) — enter the code shown:"
    az login --use-device-code --allow-no-subscriptions >/dev/null || true
    echo "[live] done; review the Entra sign-in log for authenticationProtocol=deviceCode."
  else
    echo "[live] registering throwaway app '$APP' and requesting delegated scopes, then deleting..."
    APPID="$(az ad app create --display-name "$APP" --query appId -o tsv)"
    echo "[live] appId: $APPID — grant consent in the portal or with 'az ad app permission admin-consent'."
    echo "[live] review the Entra audit log for 'Consent to application' with the high-risk Scope list."
    az ad app delete --id "$APPID"
    echo "[live] cleaned up."
  fi
else
  echo
  echo "(dry) set TRR9017_LIVE=1 (signed in with az + the Graph extension) to run the throwaway"
  echo "      app register+consent+delete (or a device-code sign-in for D),"
  echo "      or pass --show-fixture [signin] for the recorded telemetry."
fi
