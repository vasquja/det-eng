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
  kubectl -n "$NS" create cronjob trr9005-cron \
    --image="$IMG" --schedule="0 0 31 2 *" -- /bin/true >/dev/null 2>&1 || true
}

# Procedure B — create a one-shot Job that runs `id` then sleeps briefly, so the
# node runtime sensor can observe the pod sandbox (label batch.kubernetes.io/
# job-name=trr9005-job) before cleanup removes it.
procedure_b() {
  log "B: create one-shot job trr9005-job (runs id, then sleeps for the sensor)"
  kubectl -n "$NS" create job trr9005-job \
    --image="$IMG" -- sh -c 'id; sleep 30' >/dev/null 2>&1 || true
  log "B: wait for the job pod to start so the node sensor records it"
  kubectl -n "$NS" wait --for=condition=Ready pod \
    -l batch.kubernetes.io/job-name=trr9005-job --timeout=60s >/dev/null 2>&1 || true
  sleep 3
}

# Procedure C — create a Job whose Pod template requests host access.
# The container runs /bin/true (no exploit); the privileged/hostPath/hostPID
# fields appear in the Request-level audit event for triage.
procedure_c() {
  log "C: apply host-access job trr9005-hostjob (privileged + hostPath, /bin/true)"
  kubectl apply -f "$SCRIPT_DIR/hostjob.yaml" >/dev/null 2>&1 || true
}

# Procedure D — modify the existing CronJob (suspend it). The modification path
# the chokepoint must catch (verb=patch, not create).
procedure_d() {
  kubectl -n "$NS" get cronjob trr9005-cron >/dev/null 2>&1 || procedure_a
  log "D: patch cronjob trr9005-cron (suspend: true) -> verb=patch"
  kubectl -n "$NS" patch cronjob trr9005-cron --type=merge \
    -p '{"spec":{"suspend":true}}' >/dev/null 2>&1 || true
}

run_one() {
  case "$1" in
    a) procedure_a ;;
    b) procedure_b ;;
    c) procedure_c ;;
    d) procedure_d ;;
    *) log "unknown procedure: $1 (use a|b|c|d|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a b c d; do run_one "$p"; done
    cleanup
  else
    run_one "$which"
  fi
  log "emulation complete: $which"
}

main "$@"
