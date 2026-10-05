#!/usr/bin/env python3
"""
Validate that each behavioral atomic actually makes its paired Sigma rule fire.

The atomic is the stimulus: it emits the syscall pattern. This script closes
the loop by proving the telemetry really appears AND matches what the Sigma
rule keys on:

    compile atomic -> run it -> read the resulting auditd events ->
    assert every SYSCALL selection in the paired Sigma rule matches one

What it checks (and does not):
  * It confirms the POSITIVE match — the required syscall(s) and their a0/a1/a2
    argument constraints show up in the audit log for the process that ran.
  * It does NOT re-implement a rule's process allowlist (`... and not comm`).
    The validator's binaries use a `deteng_` comm that is in no allowlist, so
    the negative side never changes the "does it fire" answer. Tuning the
    allowlist against your fleet is a separate, operational task.

Requires (for a real run): root, a running auditd, and the audit userspace
tools (auditctl, ausearch, ausyscall). Without them the script SKIPS cleanly
(exit 0) rather than failing, so it is safe to wire into CI on hosts that have
no auditd. gcc is always required.

Usage:
    sudo python3 detections/validate_detections.py          # full validation
    python3 detections/validate_detections.py --dry-run     # compile + parse only
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Each Sigma rule paired with the atomic source that is meant to trigger it,
# and the runtime args to pass. Paths are repo-relative.
MANIFEST = [
    ("detections/sigma/T1068/copyfail_af_alg_authencesn.yml",
     "atomics/T1068/src/copyfail_behavioral.c", ["/tmp/deteng_copyfail_target"]),
    ("detections/sigma/T1068/dirtyfrag_xfrm_unshare_netlink.yml",
     "atomics/T1068/src/dirtyfrag_xfrm_behavioral.c", []),
    ("detections/sigma/T1068/dirtyfrag_rxrpc_socket.yml",
     "atomics/T1068/src/dirtyfrag_rxrpc_behavioral.c", []),
    ("detections/sigma/T1068/dirtypipe_splice_readonly.yml",
     "atomics/T1068/src/dirtypipe_behavioral.c", ["/tmp/deteng_dirtypipe_target"]),
    ("detections/sigma/T1068/userfaultfd_syscall.yml",
     "atomics/T1068/src/userfaultfd_behavioral.c", []),
    ("detections/sigma/T1068/keyring_add_key_burst.yml",
     "atomics/T1068/src/keyring_stuffing_behavioral.c", ["50"]),
    ("detections/sigma/T1068/perf_event_open_non_profiler.yml",
     "atomics/T1068/src/perf_event_open_behavioral.c", []),
    ("detections/sigma/T1040/afpacket_raw_socket.yml",
     "atomics/T1040/src/afpacket_rawsocket_behavioral.c", []),
    # TRR0001.LIN.B — the PACKET_RX_RING/mmap atomic also opens an AF_PACKET
    # socket, so the Strategy 1 rule must fire on it too.
    ("detections/sigma/T1040/afpacket_raw_socket.yml",
     "atomics/T1040/src/afpacket_mmap_ring_behavioral.c", []),
    # TRR0001.LIN.C — AF_INET raw socket, Strategy 2 rule.
    ("detections/sigma/T1040/afinet_raw_socket.yml",
     "atomics/T1040/src/afinet_raw_socket_behavioral.c", []),
    # TRR0001.LIN.D — AF_XDP socket (the bpf half is covered by T1014).
    ("detections/sigma/T1040/afxdp_socket.yml",
     "atomics/T1040/src/afxdp_socket_behavioral.c", []),
    ("detections/sigma/T1562.001/io_uring_setup.yml",
     "atomics/T1562.001/src/io_uring_bypass_behavioral.c", []),
    ("detections/sigma/T1014/bpf_prog_load.yml",
     "atomics/T1014/src/ebpf_prog_load_behavioral.c", []),
    ("detections/sigma/T1620/memfd_create_execveat.yml",
     "atomics/T1620/src/memfd_exec_behavioral.c", ["/bin/true"]),
    ("detections/sigma/T1622/ptrace_traceme.yml",
     "atomics/T1622/src/ptrace_traceme_behavioral.c", []),
    ("detections/sigma/T1611/setns_namespace_join.yml",
     "atomics/T1611/src/setns_namespace_join_behavioral.c", ["1"]),
]

AUDIT_RULES = os.path.join(REPO, "detections/audit/atomic.rules")
ARG_KEY = re.compile(r"^a([0-3])(\|contains)?$")

# ---- Sigma parsing -------------------------------------------------------


class Selection:
    """One SYSCALL selection block: a set of syscall names + arg constraints."""

    def __init__(self, name, block):
        self.name = name
        self.syscalls = block["syscall"]
        if isinstance(self.syscalls, str):
            self.syscalls = [self.syscalls]
        self.args = []  # list of (index:int, contains:bool, values:[str])
        for key, val in block.items():
            m = ARG_KEY.match(key)
            if not m:
                continue
            idx = int(m.group(1))
            contains = bool(m.group(2))
            values = val if isinstance(val, list) else [val]
            self.args.append((idx, contains, [str(v).lower() for v in values]))

    def matches(self, rec, name_to_nr):
        wanted = {name_to_nr.get(s) for s in self.syscalls}
        wanted.discard(None)
        if rec["nr"] not in wanted:
            return False
        for idx, contains, values in self.args:
            got = rec["args"].get(idx)
            if got is None:
                return False
            if contains:
                if not any(v in got for v in values):
                    return False
            else:
                # numeric equality so leading zeros / width do not matter
                try:
                    if not any(int(got, 16) == int(v, 16) for v in values):
                        return False
                except ValueError:
                    if got not in values:
                        return False
        return True


def parse_rule(path):
    """Return (list[Selection], mode) where mode is 'any' or 'all'."""
    doc = yaml.safe_load(open(path))
    det = doc["detection"]
    selections = []
    for name, block in det.items():
        if name in ("condition", "timeframe"):
            continue
        if isinstance(block, dict) and "syscall" in block:
            selections.append(Selection(name, block))
    # Decide combine mode from the condition, ignoring any `and not <allowlist>`.
    cond = str(det.get("condition", "")).lower()
    trigger_names = [s.name.lower() for s in selections]
    cond_wo_not = re.sub(r"and\s+not\s+\w+", "", cond)
    joiner_or = " or " in cond_wo_not and all(n in cond_wo_not for n in trigger_names)
    mode = "any" if (joiner_or and len(selections) > 1) else "all"
    return selections, mode


# ---- audit helpers -------------------------------------------------------


def have(cmd):
    return shutil.which(cmd) is not None


def audit_available():
    if os.geteuid() != 0:
        return False, "not root"
    for c in ("auditctl", "ausearch", "ausyscall", "gcc"):
        if not have(c):
            return False, f"missing tool: {c}"
    r = subprocess.run(["auditctl", "-s"], capture_output=True, text=True)
    if r.returncode != 0 or "enabled" not in r.stdout:
        return False, "auditd not reachable"
    return True, ""


_NR_CACHE = {}


def syscall_nr(name):
    if name in _NR_CACHE:
        return _NR_CACHE[name]
    r = subprocess.run(["ausyscall", name], capture_output=True, text=True)
    nr = None
    if r.returncode == 0:
        m = re.search(r"(\d+)", r.stdout)
        if m:
            nr = int(m.group(1))
    _NR_CACHE[name] = nr
    return nr


def name_to_nr_map(selections):
    m = {}
    for sel in selections:
        for s in sel.syscalls:
            m[s] = syscall_nr(s)
    return m


def read_events(since_ts):
    """Parse SYSCALL records from `ausearch -k det-eng` since since_ts."""
    r = subprocess.run(
        ["ausearch", "-k", "det-eng", "-ts", since_ts],
        capture_output=True, text=True,
    )
    recs = []
    for line in r.stdout.splitlines():
        if "type=SYSCALL" not in line:
            continue
        nr = re.search(r"\bsyscall=(\d+)", line)
        if not nr:
            continue
        rec = {"nr": int(nr.group(1)), "args": {}}
        for i in range(4):
            a = re.search(rf"\ba{i}=([0-9a-fA-F]+)", line)
            if a:
                rec["args"][i] = a.group(1).lower()
        recs.append(rec)
    return recs


# ---- main ----------------------------------------------------------------


def compile_atomic(src, workdir):
    out = os.path.join(workdir, "deteng_" + os.path.basename(src)[:-2])
    r = subprocess.run(
        ["gcc", "-O0", "-Wall", "-o", out, os.path.join(REPO, src)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"compile failed for {src}:\n{r.stderr}")
    return out


def load_audit_rules():
    subprocess.run(["auditctl", "-R", AUDIT_RULES], capture_output=True, text=True)


def unload_audit_rules():
    for line in open(AUDIT_RULES):
        line = line.strip()
        if not line.startswith("-a "):
            continue
        args = line.split()
        args[0] = "-d"  # delete exactly this rule
        subprocess.run(["auditctl"] + args, capture_output=True, text=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="compile sources and parse rules only; no auditd")
    args = ap.parse_args()

    ok, why = (True, "") if args.dry_run else audit_available()
    dry = args.dry_run or not ok
    if args.dry_run:
        print("== DRY RUN: compiling atomics and parsing rules (no auditd) ==")
    elif not ok:
        print(f"== SKIP: audit validation unavailable ({why}) ==")
        print("   Run as root on a host with auditd to validate for real.")

    workdir = tempfile.mkdtemp(prefix="deteng_val_")
    results = []
    if not dry:
        load_audit_rules()
    try:
        for sigma, src, run_args in MANIFEST:
            rid = os.path.basename(sigma)
            try:
                selections, mode = parse_rule(os.path.join(REPO, sigma))
                binary = compile_atomic(src, workdir)
            except Exception as e:  # noqa: BLE001
                results.append((rid, "ERROR", str(e)))
                continue

            if dry:
                syscalls = sorted({s for sel in selections for s in sel.syscalls})
                results.append((rid, "PARSED",
                                f"{len(selections)} sel ({mode}) -> {syscalls}"))
                continue

            since = time.strftime("%H:%M:%S")
            subprocess.run([binary] + run_args, capture_output=True, text=True)
            time.sleep(1.0)  # let auditd flush
            recs = read_events(since)
            nmap = name_to_nr_map(selections)
            hit = [bool([r for r in recs if sel.matches(r, nmap)])
                   for sel in selections]
            fired = any(hit) if mode == "any" else all(hit)
            detail = ", ".join(f"{s.name}={'yes' if h else 'NO'}"
                               for s, h in zip(selections, hit))
            results.append((rid, "PASS" if fired else "FAIL", detail))
    finally:
        if not dry:
            unload_audit_rules()
        shutil.rmtree(workdir, ignore_errors=True)

    print()
    width = max(len(r[0]) for r in results)
    bad = 0
    for rid, status, detail in results:
        if status in ("FAIL", "ERROR"):
            bad += 1
        print(f"  [{status:^6}] {rid:<{width}}  {detail}")
    print()

    if dry:
        print(f"Dry run complete: {len(results)} rules parsed, atomics compiled.")
        return 0 if bad == 0 else 1

    passed = sum(1 for r in results if r[1] == "PASS")
    print(f"{passed}/{len(results)} detections fired on their paired atomic.")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
