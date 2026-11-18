#!/usr/bin/env bash
# TRR9040 — behavioral emulation for T1190 (Exploit Public-Facing Application),
# the on-host artifact of a HotSpot JVM memory-corruption crash such as
# CVE-2026-114938 ("Java4Shell", C2 Base64 decode intrinsic).
#
# Procedure A makes a JVM die with a VM fatal error, so HotSpot's error handler
# creates hs_err_pid<pid>.log in the JVM's working directory: the same file a crash
# in compiled code writes. The paired rule
# (detections/sigma/T1190/linux_jvm_fatal_error_log_create.yml) keys on the create
# of that file.
#
# SAFETY: no exploit, no Base64 input, no memory corruption. A 16 MiB heap fills
# until OutOfMemoryError, and -XX:+CrashOnOutOfMemoryError turns that error into a
# fatal error. Core dumps are off (-XX:-CreateCoredumpOnCrash and ulimit -c 0). The
# JVM runs from a fixed work directory (TRR9040_DIR, default /tmp/trr9040-crash) that
# the emulation creates and, in cleanup, deletes.
#
# Run ONE procedure:
#   ./emulate.sh a      crash a JVM in the work directory (writes hs_err_pid<pid>.log)
#   ./emulate.sh all    every procedure, in order, then clean up
#
# Prerequisites: a JDK 11 or later (`java` on PATH, or JAVA_HOME): the source-file
# launcher runs Trr9040Crash.java without a separate compile step. To record the
# file event, a file sensor must watch TRR9040_DIR for writes (CI adds an auditd
# `-F dir=... -F perm=wa` watch with the key k8s_node_file before it runs this).
# Set TRR9040_KEEP=1 to keep the work directory (and the hs_err file) after `all`.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="${TRR9040_DIR:-/tmp/trr9040-crash}"
SRC="${HERE}/Trr9040Crash.java"

log() { printf '[trr9040] %s\n' "$*" >&2; }

# ---- fail-loud procedure bookkeeping (C1-4), as the other emulations do --------
TRR="TRR9040"
FAILED=()
# UTC time to the microsecond, from bash (EPOCHREALTIME, bash 5) and not from `date +%6N`:
# date of uutils coreutils 0.10.0 drops the leading zeros of %6N. An older bash uses date %N.
now_utc() {
  local t="${EPOCHREALTIME:-}"
  if [ -n "$t" ]; then TZ=UTC0 printf '%(%Y-%m-%dT%H:%M:%S)T.%sZ\n' "${t%[.,]*}" "${t#*[.,]}"
  else t="$(date -u +%Y-%m-%dT%H:%M:%S.%N)"; printf '%sZ\n' "${t:0:26}"; fi
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

# The java to run: `java` on PATH, else JAVA_HOME, else a JDK the GitHub runner image
# names in JAVA_HOME_<major>_X64 (newest first).
find_java() {
  local home
  if command -v java >/dev/null 2>&1; then command -v java; return 0; fi
  for home in "${JAVA_HOME:-}" "${JAVA_HOME_25_X64:-}" "${JAVA_HOME_21_X64:-}" \
              "${JAVA_HOME_17_X64:-}" "${JAVA_HOME_11_X64:-}"; do
    if [ -n "$home" ] && [ -x "$home/bin/java" ]; then echo "$home/bin/java"; return 0; fi
  done
  return 1
}

cleanup() {
  if [ "${TRR9040_KEEP:-0}" = "1" ]; then
    log "cleanup: TRR9040_KEEP=1, keeping $DIR"
    return 0
  fi
  log "cleanup: deleting $DIR"
  rm -rf -- "$DIR" 2>/dev/null || true
}

# Procedure A — a JVM fatal error writes hs_err_pid<pid>.log in its working directory.
# The JVM's exit status is not the proof (a fatal error ends it with a non-zero code);
# the proof is a new hs_err_pid<pid>.log for this JVM's pid in the work directory.
procedure_a() {
  local java out pid file
  java="$(find_java)" || { log "A: no java on PATH and no JAVA_HOME/bin/java"; return 1; }
  [ -f "$SRC" ] || { log "A: missing $SRC"; return 1; }
  mkdir -p -- "$DIR"
  log "A: crashing a JVM in $DIR with $java (OutOfMemoryError -> fatal error)"
  # JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS of the caller are cleared so no option of the
  # host (an -XX:ErrorFile, a larger heap) changes where or whether the log is written.
  out="$(cd "$DIR" && ulimit -c 0 && env -u JAVA_TOOL_OPTIONS -u JDK_JAVA_OPTIONS \
    "$java" -Xmx16m -XX:+CrashOnOutOfMemoryError -XX:-CreateCoredumpOnCrash \
    "$SRC" 2>&1)" || true
  pid="$(printf '%s\n' "$out" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -1)"
  if [ -z "$pid" ]; then
    log "A: the JVM printed no fatal error header (no pid=): it did not crash"
    printf '%s\n' "$out" | head -20 | sed 's/^/    /' >&2
    return 1
  fi
  file="$DIR/hs_err_pid${pid}.log"
  if [ ! -s "$file" ]; then
    log "A: the JVM (pid $pid) crashed but wrote no $file"
    printf '%s\n' "$out" | head -20 | sed 's/^/    /' >&2
    return 1
  fi
  log "A: done — $file created by the JVM (pid $pid); a file sensor that watches"
  log "A: $DIR should record its create (the validator's 9040 A file gate checks it)"
}

run_one() {
  case "$1" in
    a) run_proc "$1" ;;
    *) log "unknown procedure: $1 (use a|all)"; exit 2 ;;
  esac
}

main() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    for p in a; do run_proc "$p"; done
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
