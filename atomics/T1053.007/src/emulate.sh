#!/usr/bin/env bash
# TRR9005 — behavioral emulation for T1053.007 (Scheduled Task/Job: Container
# Orchestration Job), Kubernetes.
#
# Each procedure performs a HARMLESS write to a batch/v1 Job or CronJob through
# the API server, so the API server writes the audit events the paired Sigma
# rules key on. Every object is named with the unique prefix `trr9005-` so a
# validator matches the emulation's OWN events, not the many Jobs and Pods the
# controllers create for legitimate CronJobs.
#
# SAFETY: the CronJob (Procedure A) uses a never-firing schedule (Feb 31 never
# occurs), so it spawns no child Job or Pod. The one-shot Job (Procedure B) runs
# `id` and sleeps briefly so the node runtime sensor can observe its pod, then is
# removed. The host-access Job (Procedure C) runs `/bin/true` -- no exploit; the
# point is the privileged/hostPath fields in the Request-level audit event. Every
# object is deleted at the end.
#
# Run ONE procedure:
#   ./emulate.sh a      create a CronJob (never-firing schedule, no child pods)
#   ./emulate.sh b      create a one-shot Job (runs id; node sensor observes it)
#   ./emulate.sh c      create a host-access Job (privileged + hostPath, /bin/true)
#   ./emulate.sh d      patch the CronJob (suspend; the modification path)
#   ./emulate.sh all    every procedure, in order, then clean up
#
# Prerequisites: a reachable cluster (kubectl works) with rights to write batch
# objects. Cleanup removes every trr9005- object.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${TRR9005_NAMESPACE:-default}"
IMG="${TRR9005_IMAGE:-busybox:1.36}"

log() { printf '[trr9005] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (C1-4) --------------------------------
# `must CMD` runs a procedure's action, prints its stderr on failure, and returns its
# exit code. `run_proc P` times procedure_P, appends one ledger line to $DETENG_LEDGER
# (set by CI; unset = no ledger) and records a failure without stopping the run, so
# `all` attempts every procedure and then exits 1 naming the failures. Cleanup keeps
# `|| true`: a failed cleanup must not hide a result.
TRR="TRR9005"
FAILED=()
now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }
must() {
  local out rc=0
  out="$("$@" 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    log "FAILED (exit $rc): $*"
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
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

cleanup() {
  log "cleanup: removing every trr9005- batch object"
  kubectl -n "$NS" delete cronjob trr9005-cron --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" delete job trr9005-job trr9005-hostjob \
    --cascade=foreground --ignore-not-found >/dev/null 2>&1 || true
}

# Procedure A — create a CronJob with a never-firing schedule.
# "0 0 31 2 *" (Feb 31) is a valid cron expression that never matches, so the
# cronjob controller creates no Job and no Pod -- the emulation stays to exactly
# one gate-matchable event.
procedure_a() {
  log "A: create cronjob trr9005-cron (schedule 0 0 31 2 * -- never fires)"
  must kubectl -n "$NS" create cronjob trr9005-cron \
    --image="$IMG" --schedule="0 0 31 2 *" -- /bin/true
}

# Procedure B — create a one-shot Job that runs `id` then sleeps briefly, so the
# node runtime sensor can observe the pod sandbox (label batch.kubernetes.io/
# job-name=trr9005-job) before cleanup removes it.
procedure_b() {
  log "B: create one-shot job trr9005-job (runs id, then sleeps for the sensor)"
  must kubectl -n "$NS" create job trr9005-job \
    --image="$IMG" -- sh -c 'id; sleep 30' || return
  log "B: wait for the job pod to start so the node sensor records it"
  # Readiness, not the gate-matched action: it may time out without failing the step.
  kubectl -n "$NS" wait --for=condition=Ready pod \
    -l batch.kubernetes.io/job-name=trr9005-job --timeout=60s >/dev/null 2>&1 || true
  sleep 3
}

# Procedure C — create a Job whose Pod template requests host access.
# The container runs /bin/true (no exploit); the privileged/hostPath/hostPID
# fields appear in the Request-level audit event for triage.
procedure_c() {
  log "C: apply host-access job trr9005-hostjob (privileged + hostPath, /bin/true)"
  must kubectl apply -f "$SCRIPT_DIR/hostjob.yaml"
}

# Procedure D — modify the existing CronJob (suspend it). The modification path
# the chokepoint must catch (verb=patch, not create).
procedure_d() {
  kubectl -n "$NS" get cronjob trr9005-cron >/dev/null 2>&1 || procedure_a || return
  log "D: patch cronjob trr9005-cron (suspend: true) -> verb=patch"
  must kubectl -n "$NS" patch cronjob trr9005-cron --type=merge \
    -p '{"spec":{"suspend":true}}'
}

run_one() {
  case "$1" in
    a|b|c|d) run_proc "$1" ;;
    *) log "unknown procedure: $1 (use a|b|c|d|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d; do run_proc "$p"; done
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
