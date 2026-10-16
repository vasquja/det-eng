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
AUDIT_LOG, normalize) are imported from validate_detections.py, so the capture
and the hard gate share one pipeline. The audit rules are always unloaded
afterwards, even when the workload fails.

The window starts at the audit log's byte size, and the file is identified by its
inode and first bytes, so a rotation during the workload (auditd renames
audit.log to audit.log.1 and opens a new one) is detected: the window is then the
rotated file from the saved offset plus every newer file, and a warning says so.

The workload runs in its own session. On timeout every process in it gets
SIGTERM (each step's `timeout` passes it on, and workload.sh's EXIT trap removes
what it created), then, after a grace period, SIGKILL.

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
import glob
import json
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DETECTIONS = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, DETECTIONS)
import validate_detections as vd  # noqa: E402

DEFAULT_WORKLOAD = os.path.join(HERE, "workload.sh")
TOP = 25
STOP_GRACE = 30  # seconds the workload gets after SIGTERM to run its EXIT trap
HEAD_BYTES = 4096  # with the inode, tells "the same file" from a new one that reused it


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


def _head(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(HEAD_BYTES)
    except OSError:
        return None


def log_position():
    """(inode, size, first bytes) of the audit log now: where the capture window starts."""
    try:
        st = os.stat(vd.AUDIT_LOG)
    except OSError:
        return None, 0, b""
    return st.st_ino, st.st_size, _head(vd.AUDIT_LOG) or b""


def _is_start_file(path, inode, head):
    try:
        if os.stat(path).st_ino != inode:
            return False
    except OSError:
        return False
    now = _head(path)
    return now is not None and now[:len(head)] == head


def _read_from(path, offset):
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            return fh.read().decode("utf-8", errors="replace").splitlines(keepends=True)
    except OSError:
        return []


def read_window(start):
    """Audit log lines written since `start` (log_position()), and a warning or None.

    auditd rotates by renaming audit.log to audit.log.1 (older files shift to .2,
    .3, ...) and opening a new audit.log. So: still the start file (same inode and
    first bytes), read on from the saved byte offset. Otherwise find the rotated
    file that is the start file, read it from the offset, then every newer rotated
    file and the new audit.log.
    """
    inode, offset, head = start
    path = vd.AUDIT_LOG
    if inode is None:
        return _read_from(path, 0), (f"{path} did not exist when the window started; "
                                     "read all of it.")
    if _is_start_file(path, inode, head) and os.path.getsize(path) >= offset:
        return _read_from(path, offset), None
    rotated = sorted((p for p in glob.glob(path + ".*") if p.rsplit(".", 1)[1].isdigit()),
                     key=lambda p: int(p.rsplit(".", 1)[1]))  # .1 is the newest
    for i, older in enumerate(rotated):
        if not _is_start_file(older, inode, head):
            continue
        lines = _read_from(older, offset)
        for newer in rotated[:i][::-1]:
            lines += _read_from(newer, 0)
        lines += _read_from(path, 0)
        return lines, (f"{path} rotated during the workload; the window was read from "
                       f"{older} (from byte {offset}) through the new {path}.")
    return _read_from(path, 0), (f"{path} was rotated, truncated or replaced during the "
                                 "workload and the file the window started in is gone; "
                                 "the capture is incomplete.")


def _session_pids(sid):
    """PIDs of every process in session `sid` (from /proc)."""
    pids = []
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            with open(f"/proc/{name}/stat", encoding="utf-8", errors="replace") as fh:
                fields = fh.read().rsplit(")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if len(fields) > 3 and fields[3] == str(sid):  # state ppid pgrp session
            pids.append(int(name))
    return pids


def signal_workload(sid, sig):
    """Send sig to the workload's process group and every other process in its session.

    GNU `timeout` (every workload step runs under it) moves itself into a process
    group of its own, so the session, not the group, is what holds the whole tree.
    """
    targets = set(_session_pids(sid))
    try:
        os.killpg(sid, sig)
    except OSError:
        pass
    for pid in targets:
        try:
            os.kill(pid, sig)
        except OSError:
            pass


def stop_workload(proc):
    """SIGTERM the workload, give its EXIT trap STOP_GRACE seconds, then SIGKILL."""
    signal_workload(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=STOP_GRACE)
    except subprocess.TimeoutExpired:
        print(f"WARNING: the workload did not exit {STOP_GRACE}s after SIGTERM; killing "
              "it, so its EXIT-trap cleanup may not have run.", flush=True)
    signal_workload(proc.pid, signal.SIGKILL)  # and any straggler it left behind
    proc.wait()


def run_workload(path, timeout):
    """Run the workload; its own failures never fail the capture."""
    print(f"== workload: {path} (timeout {timeout}s) ==", flush=True)
    start = time.time()
    try:
        # Its own session (and process group), so a timeout can stop the whole tree.
        proc = subprocess.Popen(["bash", path], start_new_session=True)
    except OSError as e:
        proc, code = None, f"could not start: {e}"
    if proc is not None:
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f"== workload timed out after {timeout}s; stopping it (SIGTERM, then "
                  f"SIGKILL after {STOP_GRACE}s) ==", flush=True)
            stop_workload(proc)
            code = "timeout"
        except BaseException:
            stop_workload(proc)
            raise
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
        start = log_position()
        code, took = run_workload(args.workload, args.workload_timeout)
        time.sleep(2)  # let auditd flush the last records
        window, warning = read_window(start)
    finally:
        vd.unload_audit_rules()
    after_status = audit_status()

    if warning:
        print(f"WARNING: {warning}")
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
