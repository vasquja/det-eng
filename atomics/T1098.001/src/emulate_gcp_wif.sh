#!/usr/bin/env bash
# TRR9018 (T1098.001) behavioral emulation: Workload Identity Federation backdoor in GCP —
# trust an external OIDC/AWS/SAML issuer and bind its principalSet to a service account so
# an external identity can impersonate the SA.
#
#   * DOCUMENT/LIVE: with TRR9018_LIVE=1 and gcloud authenticated, creates a THROWAWAY
#     workload-identity pool + provider and binds a principalSet to a throwaway SA, then
#     deletes them. Your own project. NOT run in CI.
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

PROJECT="${TRR9018_PROJECT:-trr9018-prod}"
POOL="${TRR9018_POOL:-trr9018-ext-pool}"
PROVIDER="${TRR9018_PROVIDER:-gh}"
SA="${TRR9018_SA:-trr9018-deployer@${PROJECT}.iam.gserviceaccount.com}"
ISSUER="${TRR9018_ISSUER:-https://token.actions.githubusercontent.com}"

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

if [[ "${TRR9018_LIVE:-0}" == "1" || "${2:-}" == "--live" ]]; then
  command -v gcloud >/dev/null || { echo "gcloud not found"; exit 1; }
  echo
  echo "[live] creating throwaway WIF pool '$POOL' and OIDC provider '$PROVIDER'..."
  gcloud iam workload-identity-pools create "$POOL" --project="$PROJECT" --location=global \
    --display-name="trr9018 ext pool" >/dev/null
  gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" --project="$PROJECT" \
    --location=global --workload-identity-pool="$POOL" --issuer-uri="$ISSUER" \
    --attribute-mapping="google.subject=assertion.sub" >/dev/null
  echo "[live] binding the pool principalSet to $SA (roles/iam.workloadIdentityUser)..."
  PNUM="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
  gcloud iam service-accounts add-iam-policy-binding "$SA" --project="$PROJECT" \
    --role=roles/iam.workloadIdentityUser \
    --member="principalSet://iam.googleapis.com/projects/${PNUM}/locations/global/workloadIdentityPools/${POOL}/*" >/dev/null
  echo "[live] review Cloud Audit Logs (Admin Activity) for SetIAMPolicy + CreateWorkloadIdentityPoolProvider. Cleaning up..."
  gcloud iam workload-identity-pools providers delete "$PROVIDER" --project="$PROJECT" \
    --location=global --workload-identity-pool="$POOL" --quiet >/dev/null || true
  gcloud iam workload-identity-pools delete "$POOL" --project="$PROJECT" --location=global --quiet >/dev/null || true
  echo "[live] done."
else
  echo
  echo "(dry) set TRR9018_LIVE=1 with gcloud authenticated to run the throwaway pool/provider/binding"
  echo "      create+delete, or pass --show-fixture for the recorded telemetry."
fi
