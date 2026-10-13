#!/usr/bin/env bash
# TRR9023 (T1078.004 / T1550.001) behavioral emulation: USE of a federated identity credential --
# a service principal signs in to Entra with a workload-identity-federation token exchange, which
# surfaces in the Entra service-principal sign-in log (FederatedCredentialId populated).
#
#   * DOCUMENT/LIVE: with TRR9023_LIVE=1, an external OIDC token, and the target appId/tenant,
#     performs a real WIF client-credentials token exchange against Entra. Your own tenant/app.
#     NOT run in CI. (A full live run needs an external OIDC issuer; see the TRR.)
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

TENANT="${TRR9023_TENANT:-a17c0ff3-11aa-4bb2-8cc3-99ddeeff0011}"
APPID="${TRR9023_APPID:-c4d5e6f7-9023-4a0b-9c1d-2e3f4a5b6c7d}"

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
  if [[ -z "${TRR9023_OIDC_TOKEN:-}" ]]; then
    echo "[live] set TRR9023_OIDC_TOKEN to an external-IdP OIDC JWT the app's FIC trusts, then re-run."
    echo "       (A real run exchanges it at the Entra token endpoint for the tenant/app below.)"
    exit 0
  fi
  echo "[live] exchanging the external OIDC token for an app-only Entra token (client_credentials, FIC)..."
  curl -sS -X POST "https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token" \
    -d "client_id=${APPID}" \
    -d "scope=https://graph.microsoft.com/.default" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    -d "client_assertion=${TRR9023_OIDC_TOKEN}" \
    -d "grant_type=client_credentials" >/dev/null && \
    echo "[live] done; review AADServicePrincipalSignInLogs for federatedCredentialId on this appId."
else
  echo
  echo "(dry) set TRR9023_LIVE=1 (with TRR9023_OIDC_TOKEN, TRR9023_TENANT, TRR9023_APPID) to run the"
  echo "      token exchange, or pass --show-fixture for the recorded telemetry."
fi
