#!/usr/bin/env python3
"""
Record a live benign Linux slice: ordinary runner activity under the det-eng
audit rules, normalized to the exact event shape the Linux Sigma rules read.

    load detections/audit/atomic.rules -> run workload.sh (admin, developer and
    service activity deliberately ADJACENT to the Linux rules) -> read the audit
    log window -> normalize with validate_detections.normalize -> JSONL

The capture is scored in shadow mode by score_benign.py --extra-slice (the
`benign-linux-live` job in .github/workflows/detection-quality.yml). It never
gates a rule; it shows how the rules behave on a real host. A human may later
sanitize a capture and promote it into a recorded slice under
detections/benign/slices/.

Everything the det-eng audit rules see during the window is kept, not only the
workload's own process tree: the runner agent, systemd, containerd and the
kernel's own helpers are part of what a real host looks like.

The audit helpers (audit_available, load_audit_rules, unload_audit_rules,
audit_log_lines, normalize) are imported from validate_detections.py, so the
capture and the hard gate share one pipeline. The audit rules are always
unloaded afterwards, even when the workload fails.

Usage (root, with auditd running):
    sudo python3 detections/benign/linux/capture.py --out /tmp/linux-benign.jsonl
    sudo python3 detections/benign/linux/capture.py --out X --require-audit   # CI
    ... --workload PATH        run another workload script instead
    ... --workload-timeout N   stop the workload after N seconds (default 900)

Without root or auditd the script SKIPS (exit 0, nothing written) unless
--require-audit is given, like the validator.
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DETECTIONS = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, DETECTIONS)
import validate_detections as vd  # noqa: E402

DEFAULT_WORKLOAD = os.path.join(HERE, "workload.sh")
TOP = 25


def audit_status():
    """`auditctl -s` as a dict (enabled, pid, lost, backlog, ...); {} if unreadable."""
    try:
        r = subprocess.run(["auditctl", "-s"], capture_output=True, text=True)
    except OSError:
        return {}
    out = {}
    for line in r.stdout.splitlines():
        m = re.match(r"\s*(\w+)\s+(\S+)", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def run_workload(path, timeout):
    """Run the workload; its own failures never fail the capture."""
    print(f"== workload: {path} (timeout {timeout}s) ==", flush=True)
    start = time.time()
    try:
        r = subprocess.run(["bash", path], timeout=timeout)
        code = r.returncode
    except subprocess.TimeoutExpired:
        code = "timeout"
    except OSError as e:
        code = f"could not start: {e}"
    took = time.time() - start
    print(f"== workload finished in {took:.0f}s (exit {code}) ==", flush=True)
    return code, took


def summarize(events):
    by_syscall = collections.Counter(e["syscall"] for e in events)
    by_exe = collections.Counter(e.get("exe") or e.get("comm") or "<unknown>" for e in events)
    failed = sum(1 for e in events if e.get("success") != "yes")
    print(f"\nCaptured {len(events)} det-eng SYSCALL event(s) "
          f"({failed} rejected by the kernel, success != yes).")
    print("\nPer syscall:")
    for name, n in sorted(by_syscall.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {name:<18} {n:>8}")
    print(f"\nPer exe (top {TOP} of {len(by_exe)}):")
    for exe, n in by_exe.most_common(TOP):
        print(f"  {n:>8}  {exe}")
    return by_syscall, by_exe


def main():
    ap = argparse.ArgumentParser(
        description="Record a live benign Linux auditd slice (shadow scoring input).")
    ap.add_argument("--out", required=True, metavar="PATH",
                    help="write the normalized events here as JSONL")
    ap.add_argument("--require-audit", action="store_true",
                    help="fail (instead of skip) when auditd is unavailable or the "
                    "capture holds no det-eng events")
    ap.add_argument("--workload", default=DEFAULT_WORKLOAD, metavar="PATH",
                    help="workload script to run (default: workload.sh beside this file)")
    ap.add_argument("--workload-timeout", type=int, default=900, metavar="SECONDS",
                    help="stop the workload after this many seconds (default 900)")
    ap.add_argument("--summary-json", metavar="PATH",
                    help="also write per-syscall / per-exe counts as JSON")
    args = ap.parse_args()

    ok, why = vd.audit_available()
    if not ok:
        if args.require_audit:
            print(f"ERROR: audit capture unavailable ({why}) and --require-audit set.")
            return 1
        print(f"== SKIP: audit capture unavailable ({why}); nothing written ==")
        return 0

    before_status = audit_status()
    vd.load_audit_rules()
    try:
        offset = len(vd.audit_log_lines())
        code, took = run_workload(args.workload, args.workload_timeout)
        time.sleep(2)  # let auditd flush the last records
        lines = vd.audit_log_lines()
    finally:
        vd.unload_audit_rules()
    after_status = audit_status()

    if len(lines) >= offset:
        window = lines[offset:]
    else:
        # The log rotated during the workload: what is left is all post-start.
        print(f"WARNING: {vd.AUDIT_LOG} rotated during the workload "
              f"({offset} -> {len(lines)} lines); the capture is incomplete.")
        window = lines
    events = vd.normalize(window)

    with open(args.out, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, sort_keys=True) + "\n")
    os.chmod(args.out, 0o644)  # written as root; the scorer and upload read it

    by_syscall, by_exe = summarize(events)
    try:
        lost = int(after_status.get("lost", 0)) - int(before_status.get("lost", 0))
    except ValueError:
        lost = None
    if lost:
        print(f"\nWARNING: the kernel dropped {lost} audit record(s) during the window "
              "(backlog limit); the capture under-counts.")
    print(f"\nWrote {len(events)} event(s) to {args.out} "
          f"(workload exit {code}, {took:.0f}s, {len(window)} audit line(s) in the window).")

    if args.summary_json:
        with open(args.summary_json, "w", encoding="utf-8") as fh:
            json.dump({"events": len(events), "workload_exit": str(code),
                       "workload_seconds": round(took), "lost_records": lost,
                       "per_syscall": dict(by_syscall), "per_exe": dict(by_exe)},
                      fh, indent=2, sort_keys=True)

    if not events and args.require_audit:
        print("ERROR: no det-eng audit events in the window: the audit rules did not "
              "load, or records did not reach the log.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
