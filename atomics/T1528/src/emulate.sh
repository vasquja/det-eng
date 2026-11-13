#!/usr/bin/env bash
# TRR9030 -- behavioral emulation for T1528 (Steal Application Access Token), use-side,
# on Kubernetes: a POD-BOUND service-account token replayed against kube-apiserver from a
# source the cluster does not expect for that pod. The k8s sibling of TRR9022 (EKS IRSA
# used off-cluster) and the use-side sibling of TRR9006 (which stops at the token read).
#
# Procedures (benign actions that make the API server write the audit events the paired
# Sigma rule keys on):
#   a   OFF-SOURCE use (positive): mint a pod-bound token for the inert trr9030-sa bound
#       to the pod trr9030-user, then use it with `kubectl auth whoami` (a create of
#       selfsubjectreviews, allowed for every authenticated identity) FROM THE RUNNER. The
#       API server records the runner as the docker-bridge gateway (172.18.0.1 on kind),
#       outside the pod CIDR, so the last sourceIPs entry is off-source and the rule fires.
#   b   IN-POD use (benign baseline, must NOT fire): the SAME call from INSIDE the pod,
#       with the pod's own mounted projected token, so the API server records the pod IP
#       (10.244.x) as the last source. The rule's in-cluster-source filter suppresses it.
#       This is the hard benign baseline that differs from a only on the last sourceIPs
#       entry (the validator's 9030 B absence check proves the rule matches none of it).
#       The in-pod call runs with curl --fail, so a REJECTED call (a non-2xx answer that
#       would leave no trr9030-sa record) fails B loudly instead of passing it vacuously.
#
# A FIXED namespace trr9030-ns and unique names (trr9030-sa, trr9030-user) let the
# validator gate on the service account and the pod-name marker, so the emulation's own
# off-source use is told apart from the cluster's baseline pod-bound traffic, and a
# pre-emulation snapshot (no trr9030-ns) cannot pass it.
#
# SAFETY: the service account holds NO RBAC, so neither the minted token nor the pod's
# own token grants anything; `kubectl auth whoami` only reflects the caller's identity.
# The minted token lasts 10m and expires on its own. No credential ever reaches a command
# line or a log line: the minted token is captured from stdout into a variable and written
# to a mode-0600 tokenFile referenced by a throwaway kubeconfig (never passed as --token);
# the in-pod call reads the pod's mounted token into a curl config file by redirect (never
# as an argument). Cleanup deletes the namespace (cascading the SA and pod).
#
# Run ONE procedure:
#   ./emulate.sh a      off-source use from the runner (positive)
#   ./emulate.sh b      in-pod use from the pod IP (benign baseline)
#   ./emulate.sh all    both, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) whose pod CIDR is 10.244.0.0/16
# (kind's default) and whose node/host sees the API server as an off-pod source; rights to
# create a namespace, a service account, a pod, and to mint a token and exec into the pod
# (the kind admin credential has them). TRR9030_IMAGE overrides the sleeper/curl image.
set -euo pipefail

NS="${TRR9030_NAMESPACE:-trr9030-ns}"
SA="trr9030-sa"
POD="trr9030-user"
IMG="${TRR9030_IMAGE:-curlimages/curl:8.11.1}"

log() { printf '[trr9030] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs an action and returns its exit code (stderr shown on failure, stdout
# discarded -- never used for a step whose stdout carries a credential). `create_ok CMD`
# is `must` for a create that treats AlreadyExists as success. `run_proc P` times
# procedure_P, appends one ledger line to $DETENG_LEDGER (set by CI; unset = no ledger)
# and records a failure without stopping the run. Cleanup keeps `|| true`.
TRR="TRR9030"
FAILED=()
# UTC time to the microsecond, from bash (EPOCHREALTIME, bash 5) and not from `date +%6N`:
# date of uutils coreutils 0.10.0 drops the leading zeros of %6N. An older bash uses date %N.
now_utc() {
  local t="${EPOCHREALTIME:-}"
  if [ -n "$t" ]; then TZ=UTC0 printf '%(%Y-%m-%dT%H:%M:%S)T.%sZ\n' "${t%[.,]*}" "${t#*[.,]}"
  else t="$(date -u +%Y-%m-%dT%H:%M:%S.%N)"; printf '%sZ\n' "${t:0:26}"; fi
}
must() {
  local out rc=0
  out="$("$@" 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    log "FAILED (exit $rc): $*"
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
  return "$rc"
}
create_ok() {
  local out rc=0
  out="$("$@" 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -eq 0 ] || printf '%s' "$out" | grep -qiE 'AlreadyExists|already exists'; then
    return 0
  fi
  log "FAILED (exit $rc): $*"
  [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' >&2
  return "$rc"
}
run_proc() {
  local p="$1" start end rc=0
  start="$(now_utc)"
  "procedure_$p" || rc=$?
  end="$(now_utc)"
  if [ -n "${DETENG_LEDGER:-}" ]; then
    printf '{"trr":"%s","procedure":"%s","start":"%s","end":"%s","exit":%d,"expect":0}\n' \
      "$TRR" "$p" "$start" "$end" "$rc" >> "$DETENG_LEDGER"
  fi
  if [ "$rc" -ne 0 ]; then
    FAILED+=("$p")
    [ -n "${GITHUB_ACTIONS:-}" ] && \
      echo "::error title=${TRR} procedure ${p}::procedure ${p} failed (exit ${rc})"
  fi
  return 0
}

# Create the namespace, the inert SA (no RBAC) and a sleeper pod that uses the SA, treating
# AlreadyExists as success, then wait until the pod is Ready so its mounted token exists and
# the pod is scheduled (so a token minted for it can carry node claims too).
ensure_setup() {
  create_ok kubectl create namespace "$NS" || return
  # Wait for the namespace's default SA (the token controller creates it); a pod create
  # before it fails with 'serviceaccount "default" not found'.
  must kubectl -n "$NS" wait --for=create serviceaccount/default --timeout=60s || return
  create_ok kubectl -n "$NS" create serviceaccount "$SA" || return
  create_ok kubectl -n "$NS" apply -f - <<YAML || return
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  namespace: $NS
  labels: {app: trr9030}
spec:
  serviceAccountName: $SA
  automountServiceAccountToken: true
  restartPolicy: Never
  containers:
    - name: c
      image: $IMG
      imagePullPolicy: IfNotPresent
      command: ["sleep", "3600"]
YAML
  must kubectl -n "$NS" wait --for=condition=Ready "pod/$POD" --timeout=90s
}

cleanup() {
  log "cleanup: deleting namespace $NS (cascades the service account and pod)"
  kubectl delete namespace "$NS" --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A -- OFF-SOURCE use from the runner (positive).
# Mint a pod-bound token (bound to the running pod, so the API server sets the pod-name
# extra when it is used), then call `kubectl auth whoami` with it from the runner. The
# token is captured from stdout and written to a mode-0600 file that a throwaway kubeconfig
# references as a tokenFile; it is never passed on a command line or logged.
procedure_a() {
  ensure_setup || return
  local uid tok tf cfg server cadata rc=0
  uid="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.uid}')"
  if [ -z "$uid" ]; then log "A: could not read the pod UID"; return 1; fi
  # Mint the pod-bound token. stdout is the token; do not log it. A mint failure fails A.
  if ! tok="$(kubectl -n "$NS" create token "$SA" \
                --bound-object-kind=Pod --bound-object-name="$POD" --bound-object-uid="$uid" \
                --duration=10m 2>/dev/null)" || [ -z "$tok" ]; then
    log "A: could not mint a pod-bound token for $SA"
    return 1
  fi
  tf="$(mktemp)"; cfg="$(mktemp)"
  chmod 600 "$tf"
  printf '%s' "$tok" > "$tf"; unset tok
  server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
  cadata="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
  if [ -z "$server" ] || [ -z "$cadata" ]; then
    log "A: could not read the cluster server/CA from the current kubeconfig"
    rm -f "$tf" "$cfg"; return 1
  fi
  # A kubeconfig whose user reads the token from the file (no --token on any command line).
  cat > "$cfg" <<YAML
apiVersion: v1
kind: Config
clusters:
  - name: trr9030
    cluster:
      server: $server
      certificate-authority-data: $cadata
contexts:
  - name: trr9030
    context: {cluster: trr9030, user: trr9030}
current-context: trr9030
users:
  - name: trr9030
    user:
      tokenFile: $tf
YAML
  log "A: using the pod-bound token from the runner (kubectl auth whoami, off-source)"
  must kubectl --kubeconfig "$cfg" auth whoami || rc=$?
  rm -f "$tf" "$cfg"
  return "$rc"
}

# Procedure B -- IN-POD use from the pod IP (benign baseline, must NOT fire).
# Exec into the pod and make the same selfsubjectreviews call with the pod's OWN mounted
# token, so the API server records the pod IP as the last source. The token is read into a
# curl config file by redirect (never an argument), and that file is removed afterwards.
procedure_b() {
  ensure_setup || return
  log "B: in-pod use of the pod's own mounted token (kubectl auth whoami equivalent, pod IP)"
  # shellcheck disable=SC2016
  must kubectl -n "$NS" exec "$POD" -- sh -c '
    set -e
    T=/var/run/secrets/kubernetes.io/serviceaccount/token
    CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    cfg="$(mktemp)"
    # Write the bearer header into a curl config WITHOUT the token on a command line.
    { printf "header = \"Authorization: Bearer "; cat "$T"; printf "\"\n"; } > "$cfg"
    # --fail makes curl exit non-zero on a non-2xx status, so a REJECTED in-pod call
    # (an expired or absent token answered 401/403, or a transient 5xx) fails B LOUDLY
    # instead of reporting a silent success. A silent success would produce NO trr9030-sa
    # record yet leave the ledger row at exit 0, so the paired 9030 B absence control would
    # pass vacuously; a non-zero exit instead makes that control MISS (the gap not proven).
    rc=0
    curl -sS --fail -o /dev/null -w "in-pod selfsubjectreview http=%{http_code}\n" \
      --cacert "$CA" -K "$cfg" \
      -H "Content-Type: application/json" -X POST --data-binary @- \
      https://kubernetes.default.svc/apis/authentication.k8s.io/v1/selfsubjectreviews <<JSON || rc=$?
{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}
JSON
    rm -f "$cfg"
    [ "$rc" -eq 0 ] || echo "B: in-pod call failed (curl exit $rc); the benign baseline was not exercised" >&2
    exit "$rc"
  '
}

run_one() {
  case "$1" in
    a|b) run_proc "$1" ;;
    *) log "unknown procedure: $1 (use a|b|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b; do run_proc "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  if [ "${#FAILED[@]}" -gt 0 ]; then
    log "emulation FAILED: procedure(s) ${FAILED[*]}"
    exit 1
  fi
  log "emulation complete: $which"
}

main "$@"
