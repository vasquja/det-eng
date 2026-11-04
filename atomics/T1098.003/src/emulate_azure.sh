#!/usr/bin/env bash
# TRR9036 (T1098.003) behavioral emulation: Azure ARM RBAC privileged role assignment
# at subscription (A) or management-group (B) scope. Assigning Owner / Contributor /
# User Access Administrator / Role Based Access Control Administrator at that scope is a
# durable privilege-escalation + persistence foothold, recorded in the Azure Activity Log
# as Microsoft.Authorization/roleAssignments/write (role + scope on the Start record, in
# properties.requestbody).
#
#   * DOCUMENT/LIVE: with TRR9036_LIVE=1 and the Azure CLI signed in, assigns a privileged
#     built-in role to a THROWAWAY principal at the given scope, then REVOKES it. Needs
#     your own tenant and an object id you control. NOT run in CI.
#   * FIXTURE: --show-fixture prints the committed Azure Activity Log fixtures the CI
#     validator runs the detection over.
#
# Rule: detections/sigma/T1098.003/azure_privileged_role_assignment.yml
set -euo pipefail

PROC="${1:-a}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXDIR="$HERE/../../../detections/cloud/fixtures/trr9036"

if [[ "${1:-}" == "--show-fixture" || "${2:-}" == "--show-fixture" ]]; then
  echo "# attack (Owner @ subscription scope, Start + completion):"; cat "$FIXDIR/attack.json"
  echo; echo "# hard benign (Key Vault Secrets User @ Key Vault scope):"; cat "$FIXDIR/benign.json"
  exit 0
fi

# Owner is the headline; User Access Administrator is the management-group example.
OWNER="8e3af657-a8ff-443c-a75c-2fe8c4bcb635"            # Owner
UAA="18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"              # User Access Administrator

echo "== TRR9036.AZR.$PROC — privileged built-in role assigned at a high scope =="
case "$PROC" in
  a) echo "A: assign Owner at SUBSCRIPTION scope to a principal you control."
     echo "   az role assignment create --role Owner \\"
     echo "     --assignee-object-id <objectId> --assignee-principal-type User \\"
     echo "     --scope /subscriptions/<subId>" ;;
  b) echo "B: assign User Access Administrator at MANAGEMENT-GROUP scope."
     echo "   az role assignment create --role \"User Access Administrator\" \\"
     echo "     --assignee-object-id <objectId> --assignee-principal-type User \\"
     echo "     --scope /providers/Microsoft.Management/managementGroups/<mgId>" ;;
  c) echo "C: custom-role / exporter evasion of the body grade — detection gap"
     echo "   (KTBD-AZ1 custom role GUID not allowlisted; KTBD-AZ2 requestbody absent)." ;;
  *) echo "usage: emulate_azure.sh {a|b|c} [--live|--show-fixture]"; exit 1 ;;
esac

if [[ "${TRR9036_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v az >/dev/null || { echo "az CLI not found"; exit 1; }
  echo
  if [[ "$PROC" == "a" || "$PROC" == "b" ]]; then
    : "${TRR9036_ASSIGNEE_OBJECT_ID:?set TRR9036_ASSIGNEE_OBJECT_ID to a throwaway principal object id}"
    if [[ "$PROC" == "a" ]]; then
      : "${TRR9036_SUBSCRIPTION_ID:?set TRR9036_SUBSCRIPTION_ID}"
      ROLE="$OWNER"; SCOPE="/subscriptions/$TRR9036_SUBSCRIPTION_ID"
    else
      : "${TRR9036_MANAGEMENT_GROUP_ID:?set TRR9036_MANAGEMENT_GROUP_ID}"
      ROLE="$UAA"; SCOPE="/providers/Microsoft.Management/managementGroups/$TRR9036_MANAGEMENT_GROUP_ID"
    fi
    echo "[live] assigning role $ROLE at $SCOPE, then revoking..."
    az role assignment create --role "$ROLE" \
      --assignee-object-id "$TRR9036_ASSIGNEE_OBJECT_ID" --assignee-principal-type User \
      --scope "$SCOPE"
    echo "[live] assigned; review the Activity Log roleAssignments/write Start record. Cleaning up..."
    az role assignment delete --role "$ROLE" \
      --assignee "$TRR9036_ASSIGNEE_OBJECT_ID" --scope "$SCOPE"
    echo "[live] revoked."
  else
    echo "[live] Procedure C is a documented detection gap; nothing to run."
  fi
else
  echo
  echo "(dry) set TRR9036_LIVE=1 with az signed in (and a throwaway object id) to run the"
  echo "      assign+revoke, or pass --show-fixture for the recorded telemetry."
fi
