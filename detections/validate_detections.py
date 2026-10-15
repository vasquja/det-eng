#!/usr/bin/env python3
"""
Validate that each behavioral atomic makes its paired Sigma rule fire, as a real
Sigma backend evaluates the rule, on events the atomic itself produced:

    compile atomic -> run it -> read the auditd SYSCALL records of that window ->
    normalize them to the event schema the rules assume -> run the rule's
    pySigma-compiled query over them -> require a hit from the atomic

A case PASSES only if all of these hold:
  * the rule, compiled by pySigma's SQLite backend (a plain rule or a
    correlation), matches the events. That is Sigma's own semantics, not a
    hand-written approximation of them;
  * every event behind the hit came from the atomic's process tree, so nothing
    else running in the window (the validator included) can satisfy the rule;
  * those syscalls succeeded (success=yes). A syscall the kernel rejected is an
    attempt, not an execution of the technique.

A case is SKIPPED only when an independent kernel-feature probe, run before the
test, shows the kernel lacks what the technique needs (no AF_ALG, no AF_RXRPC,
io_uring disabled, ...). Every other miss is a FAIL and fails the run.

Controls then test the test. Each must FAIL; one that passes fails the run:
  * a no-op binary, evaluated against every rule;
  * the mutants in detections/controls/, which keep the surface of a technique
    but break it (half a correlation, a rejected syscall, a wrong argument);
  * each atomic re-run under a name from its rule's process allowlist, so the
    rule's `not <allowlist>` filter has to suppress it.

Event schema the rules assume (one event per auditd SYSCALL record):
  type=SYSCALL, syscall=<name>, success, exit, a0..a3 (raw hex, as auditd logs
  them), pid, ppid, comm, exe, timestamp. auditd's ENRICHED log format carries
  the syscall name (SYSCALL=); for RAW format it is resolved with ausyscall. A
  log pipeline that feeds these rules to a SIEM must deliver the same shape.

Requires (for a real run): root, a running auditd, auditctl, ausyscall, gcc,
and detections/requirements.txt. Without root or auditd the script SKIPS
(exit 0), unless --require-audit is given; CI passes it so a broken audit
setup cannot pass silently.

Every result is explained beneath its line (sigma_explain.py), so a red run can
be fixed without guessing:
  * each case's kernel-feature probe result (present, or why it is missing);
  * a detection FAIL lists the audited syscalls the stimulus tree made (name,
    count, success or errno) and grades the tree's events against the rule, item
    by item (succeeded and rejected events alike; each is labelled);
  * a BROKEN control shows the events that satisfied the rule and why, with what
    a pass of that control means;
  * a HELD mutant is graded against the rule ("held: near-miss on
    afinet_raw_socket.a1"); a grade that differs from the atoms the mutant is
    built to break (its CONTROLS entry) prints a WARNING, never a failure.
--json PATH also writes all of it as a machine-readable report.

Usage:
    sudo python3 detections/validate_detections.py                  # validate + controls
    sudo python3 detections/validate_detections.py --require-audit  # CI
    python3 detections/validate_detections.py --dry-run             # compile atomics + rules
    ... --json PATH                                                 # also a JSON report
"""

import argparse
import ctypes
import errno
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install -r detections/requirements.txt")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402
import sigma_explain  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---- kernel-feature probes ----------------------------------------------
#
# Each probe returns None when the feature is present, or the reason it is
# missing. They only ever ask the kernel "do you have this?"; they never run the
# technique, and they run before the audit rules are loaded. `probe.what` names
# the feature for the report.

_LIBC = ctypes.CDLL(None, use_errno=True)
AF_RXRPC, AF_XDP = 33, 44  # not exported by Python's socket module
NETLINK_XFRM = 6


def socket_family(family, type_, proto, label):
    def probe():
        try:
            socket.socket(family, type_, proto).close()
        except OSError as e:
            if e.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT,
                           errno.ESOCKTNOSUPPORT):
                return f"kernel lacks {label} ({errno.errorcode[e.errno]})"
        return None
    probe.what = label if "socket" in label else f"{label} sockets"
    return probe


def syscall_exists(name, *args):
    """Call `name` with arguments the kernel rejects; only ENOSYS means absent."""
    def probe():
        nr = syscall_nr(name)
        if nr is None:
            return f"{name} is not a syscall on this architecture"
        ctypes.set_errno(0)
        r = _LIBC.syscall(nr, *args)
        if r >= 0:
            os.close(r)
        elif ctypes.get_errno() == errno.ENOSYS:
            return f"kernel lacks {name} (ENOSYS)"
        return None
    probe.what = f"{name}()"
    return probe


def sysctl_is(path, value, label):
    def probe():
        try:
            with open(path) as fh:
                if fh.read().strip() == value:
                    return f"{label} ({path} = {value})"
        except OSError:
            pass
        return None
    probe.what = f"sysctl {path[len('/proc/sys/'):].replace('/', '.')} != {value}"
    return probe


# Each Sigma rule paired with the atomic that is meant to trigger it, the
# runtime args, and the probes that decide whether a miss may be a SKIP.
MANIFEST = [
    ("detections/sigma/T1068/copyfail_af_alg_authencesn.yml",
     "atomics/T1068/src/copyfail_behavioral.c", ["/tmp/deteng_copyfail_target"],
     [socket_family(socket.AF_ALG, socket.SOCK_SEQPACKET, 0, "AF_ALG")]),
    ("detections/sigma/T1068/dirtyfrag_xfrm_unshare_netlink.yml",
     "atomics/T1068/src/dirtyfrag_xfrm_behavioral.c", [],
     [socket_family(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM,
                    "NETLINK_XFRM")]),
    ("detections/sigma/T1068/dirtyfrag_rxrpc_socket.yml",
     "atomics/T1068/src/dirtyfrag_rxrpc_behavioral.c", [],
     [socket_family(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET, "AF_RXRPC")]),
    ("detections/sigma/T1068/dirtypipe_splice_readonly.yml",
     "atomics/T1068/src/dirtypipe_behavioral.c", ["/tmp/deteng_dirtypipe_target"],
     []),
    ("detections/sigma/T1068/userfaultfd_syscall.yml",
     "atomics/T1068/src/userfaultfd_behavioral.c", [],
     [syscall_exists("userfaultfd", 0xFFFF)]),
    ("detections/sigma/T1068/keyring_add_key_burst.yml",
     "atomics/T1068/src/keyring_stuffing_behavioral.c", ["50"],
     [syscall_exists("add_key", None, None, None, 0, 0)]),
    ("detections/sigma/T1068/perf_event_open_non_profiler.yml",
     "atomics/T1068/src/perf_event_open_behavioral.c", [],
     [syscall_exists("perf_event_open", None, 0, -1, -1, 0)]),
    ("detections/sigma/T1040/afpacket_raw_socket.yml",
     "atomics/T1040/src/afpacket_rawsocket_behavioral.c", [],
     [socket_family(socket.AF_PACKET, socket.SOCK_RAW, 0, "AF_PACKET")]),
    # TRR0001.LIN.B — the PACKET_RX_RING/mmap atomic also opens an AF_PACKET
    # socket, so the Strategy 1 rule must fire on it too.
    ("detections/sigma/T1040/afpacket_raw_socket.yml",
     "atomics/T1040/src/afpacket_mmap_ring_behavioral.c", [],
     [socket_family(socket.AF_PACKET, socket.SOCK_RAW, 0, "AF_PACKET")]),
    # TRR0001.LIN.C — AF_INET raw socket, Strategy 2 rule.
    ("detections/sigma/T1040/afinet_raw_socket.yml",
     "atomics/T1040/src/afinet_raw_socket_behavioral.c", [],
     [socket_family(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP,
                    "raw IPv4 sockets")]),
    # TRR0001.LIN.D — AF_XDP socket (the bpf half is covered by T1014).
    ("detections/sigma/T1040/afxdp_socket.yml",
     "atomics/T1040/src/afxdp_socket_behavioral.c", [],
     [socket_family(AF_XDP, socket.SOCK_RAW, 0, "AF_XDP")]),
    ("detections/sigma/T1685/io_uring_setup.yml",
     "atomics/T1685/src/io_uring_bypass_behavioral.c", [],
     [syscall_exists("io_uring_setup", 0, None),
      sysctl_is("/proc/sys/kernel/io_uring_disabled", "2", "io_uring disabled")]),
    ("detections/sigma/T1014/bpf_prog_load.yml",
     "atomics/T1014/src/ebpf_prog_load_behavioral.c", [],
     [syscall_exists("bpf", 5, None, 0)]),
    ("detections/sigma/T1620/memfd_create_execveat.yml",
     "atomics/T1620/src/memfd_exec_behavioral.c", ["/bin/true"],
     [sysctl_is("/proc/sys/vm/memfd_noexec", "2", "exec from memfd disabled")]),
    ("detections/sigma/T1622/ptrace_traceme.yml",
     "atomics/T1622/src/ptrace_traceme_behavioral.c", [],
     [sysctl_is("/proc/sys/kernel/yama/ptrace_scope", "3", "ptrace disabled by Yama")]),
    ("detections/sigma/T1611/setns_namespace_join.yml",
     "atomics/T1611/src/setns_namespace_join_behavioral.c", ["1"],
     []),
]

# Mutants that keep the surface of a technique but break it. Each must FAIL;
# the note says what a PASS would mean. The last field is what the mutant is
# built to break: the rule's condition atoms (`rule_cases.py --atoms RULE`), or
# SUCCESS_GATE for the validator's own success=yes check. Each held mutant is
# graded against the rule; a different grade prints a WARNING (not a failure).
SUCCESS_GATE = "success"
NOOP = "detections/controls/noop.c"
CONTROLS = [
    ("detections/sigma/T1068/dirtypipe_splice_readonly.yml",
     "detections/controls/splice_without_pipe.c", [],
     "another process's pipe completed the correlation",
     ["base:dirtypipe_pipe_create"]),
    ("detections/sigma/T1620/memfd_create_execveat.yml",
     "detections/controls/memfd_fexecve_in_child.c", [],
     "halves from different pids were correlated",
     ["group-by"]),
    ("detections/sigma/T1014/bpf_prog_load.yml",
     "detections/controls/bpf_prog_load_fails.c", [],
     "a syscall the kernel rejected counted as an execution",
     [SUCCESS_GATE]),
    ("detections/sigma/T1040/afinet_raw_socket.yml",
     "detections/controls/afinet_stream_socket.c", [],
     "the a1 (SOCK_RAW) argument constraint was not enforced",
     ["afinet_raw_socket.a1"]),
]

AUDIT_RULES = os.path.join(REPO, "detections/audit/atomic.rules")
AUDIT_LOG = "/var/log/audit/audit.log"

# ---- audit helpers -------------------------------------------------------


def have(cmd):
    return shutil.which(cmd) is not None


def audit_available():
    if os.geteuid() != 0:
        return False, "not root"
    for c in ("auditctl", "ausyscall", "gcc"):
        if not have(c):
            return False, f"missing tool: {c}"
    r = subprocess.run(["auditctl", "-s"], capture_output=True, text=True)
    if r.returncode != 0 or not re.search(r"^enabled [12]$", r.stdout, re.M):
        return False, "kernel auditing is not enabled"
    if not re.search(r"^pid [1-9]\d*$", r.stdout, re.M):
        return False, "auditd is not running (records would not reach the log)"
    return True, ""


_DUMP = None


def _dump_syscalls():
    """name -> number for the running arch, from `ausyscall --dump` (one call)."""
    global _DUMP
    if _DUMP is None:
        _DUMP = {}
        r = subprocess.run(["ausyscall", "--dump"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            m = re.match(r"\s*(\d+)\s+(\S+)", line)  # "41\tsocket"; skips header
            if m:
                _DUMP[m.group(2)] = int(m.group(1))
    return _DUMP


def syscall_nr(name):
    return _dump_syscalls().get(name)


def audit_log_lines():
    """All lines of the audit log ([] if it cannot be read).

    Read directly rather than through `ausearch`: on some hosts (notably
    GitHub-hosted runners) `ausearch` resolves its default log path to nothing
    and reports no matches even though the records are in the file.
    """
    try:
        with open(AUDIT_LOG, errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


_FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')
_STAMP = re.compile(r"audit\((\d+)\.(\d+):")


def normalize(lines):
    """auditd SYSCALL records keyed det-eng -> events in the rules' schema."""
    names = {nr: name for name, nr in _dump_syscalls().items()}
    events = []
    for line in lines:
        if 'key="det-eng"' not in line:
            continue
        raw, _, enriched = line.partition("\x1d")
        f = {k: v.strip('"') for k, v in _FIELD.findall(raw)}
        if f.get("type") != "SYSCALL" or "syscall" not in f:
            continue
        name = dict(_FIELD.findall(enriched)).get("SYSCALL")
        stamp = _STAMP.search(f.get("msg", ""))
        when = datetime.fromtimestamp(int(stamp.group(1)) + int(stamp.group(2)) / 1000,
                                      timezone.utc)
        events.append({
            "type": "SYSCALL",
            "syscall": name or names.get(int(f["syscall"]), f["syscall"]),
            "success": f.get("success"),
            "exit": f.get("exit"),
            **{f"a{i}": f.get(f"a{i}") for i in range(4)},
            "pid": int(f["pid"]),
            "ppid": int(f["ppid"]),
            "comm": f.get("comm"),
            "exe": f.get("exe"),
            "timestamp": when.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        })
    return events


def process_tree(root, events):
    """The stimulus pid plus every descendant seen in the events."""
    tree, grew = {root}, True
    while grew:
        grew = False
        for e in events:
            if e["ppid"] in tree and e["pid"] not in tree:
                tree.add(e["pid"])
                grew = True
    return tree


def load_audit_rules():
    r = subprocess.run(["auditctl", "-R", AUDIT_RULES], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"auditctl -R failed: {r.stderr.strip()[:300]}")
    listed = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
    rules = [ln for ln in listed.stdout.splitlines() if ln.strip().startswith("-")]
    print(f"[diag] {len(rules)} audit rules loaded; "
          f"ausyscall mapped {len(_dump_syscalls())} syscalls")


def unload_audit_rules():
    for line in open(AUDIT_RULES):
        line = line.strip()
        if not line.startswith("-a "):
            continue
        args = line.split()
        args[0] = "-d"  # delete exactly this rule
        subprocess.run(["auditctl"] + args, capture_output=True, text=True)


# ---- one stimulus --------------------------------------------------------


def compile_atomic(src, workdir, name=None):
    name = name or "deteng_" + os.path.basename(src)[:-2]
    os.makedirs(workdir, exist_ok=True)
    out = os.path.join(workdir, name)
    r = subprocess.run(
        ["gcc", "-O0", "-Wall", "-o", out, os.path.join(REPO, src)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"compile failed for {src}:\n{r.stderr}")
    return out


def run(binary, args):
    """Run one stimulus: (events of its window, its process tree, stderr tail)."""
    start = len(audit_log_lines())
    proc = subprocess.Popen([binary] + args, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True)
    try:
        _, err = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
    time.sleep(1.5)  # let auditd flush to the log
    events = normalize(audit_log_lines()[start:])
    tail = (err or "").strip().splitlines()
    return events, process_tree(proc.pid, events), tail[-1] if tail else ""


def _errno_name(exit_code):
    try:
        return errno.errorcode.get(-int(exit_code), exit_code)
    except (TypeError, ValueError):
        return exit_code


def stimulus_hits(sql, events, tree, succeeded_only=True):
    """The rule's hits whose every event came from the stimulus tree.

    By default only syscalls that succeeded count (what judge() gates on).
    """
    pool = [e for e in events if e["success"] == "yes"] if succeeded_only else events
    return [h for h in sigma_eval.evaluate(sql, pool) if all(e["pid"] in tree for e in h)]


def judge(sql, events, tree, missing=None, stderr=""):
    """PASS / SKIP / FAIL for one stimulus run, and why."""
    done = stimulus_hits(sql, events, tree)
    if done:
        calls = "+".join(dict.fromkeys(e["syscall"] for e in done[0]))
        pids = ",".join(str(p) for p in sorted({e["pid"] for e in done[0]}))
        return "PASS", f"{len(done)} hit(s), e.g. {calls} by pid {pids}"
    if missing:
        return "SKIP", missing
    tried = stimulus_hits(sql, events, tree, succeeded_only=False)
    if tried:
        failed = sorted({f"{e['syscall']}: {_errno_name(e['exit'])}"
                         for h in tried for e in h if e["success"] != "yes"})
        return "FAIL", ("fired only on syscalls the kernel rejected "
                        f"({'; '.join(failed)}): an attempt, not an execution")
    detail = f"no hit from the stimulus ({len(events)} events in window)"
    return "FAIL", detail + (f"; stderr: {stderr}" if stderr else "")


def allowlist(rule_path):
    """(block, comm): the rule's `not <allowlist>` block and a name it must suppress.

    (None, None) when the rule has no such block.
    """
    with open(os.path.join(REPO, rule_path), encoding="utf-8") as fh:
        doc = next(yaml.safe_load_all(fh))
    det = doc.get("detection") or {}
    cond = str(det.get("condition", ""))
    for name, block in det.items():
        if (isinstance(block, dict) and list(block) == ["comm"]
                and re.search(rf"\bnot\s+{re.escape(name)}\b", cond)):
            values = block["comm"] if isinstance(block["comm"], list) else [block["comm"]]
            for v in values:
                if len(v) <= 15 and "/" not in v:  # comm = exe basename, 15 chars max
                    return name, v
    return None, None


def allowlisted_comm(rule_path):
    """A process name the rule's `not <allowlist>` filter must suppress, or None."""
    return allowlist(rule_path)[1]


# ---- explanations (sigma_explain) ------------------------------------------


def describe_event(e):
    """syscall, pid, comm, a0..a3 and whether the kernel accepted it."""
    args = ",".join(str(e.get(f"a{i}")) for i in range(4))
    result = ("succeeded" if e.get("success") == "yes"
              else f"REJECTED {_errno_name(e.get('exit'))}")
    return (f"{e.get('syscall')} pid={e.get('pid')} ppid={e.get('ppid')} comm={e.get('comm')} "
            f"a0..a3={args} -> {result}")


def tree_syscalls(events, tree):
    """'socket x2 (yes x1, EPERM x1), ...': the audited syscalls of the stimulus tree."""
    calls = {}
    for e in events:
        if e["pid"] in tree:
            outcome = "yes" if e["success"] == "yes" else _errno_name(e["exit"])
            per = calls.setdefault(e["syscall"], {})
            per[outcome] = per.get(outcome, 0) + 1
    return ", ".join(f"{name} x{sum(per.values())} ("
                     + ", ".join(f"{o} x{n}" if len(per) > 1 else str(o) for o, n in per.items())
                     + ")" for name, per in calls.items())


def explain_fail(rule, events, tree):
    """Why a detection FAILed: what the stimulus tree did, and how close it came."""
    idx = [i for i, e in enumerate(events) if e["pid"] in tree]
    comms = sorted({str(e["comm"]) for e in events if e["pid"] in tree})
    lines = [f"stimulus tree: pid(s) {','.join(str(p) for p in sorted(tree))}"
             + (f" (comm {', '.join(comms)})" if comms else "")
             + f"; {len(idx)} of the {len(events)} audited event(s) in the window are its own"]
    label = describe_event
    if not idx:
        lines.append("the stimulus tree made no audited syscall: the audit rules "
                     "(detections/audit/atomic.rules) may not cover it, the atomic exited "
                     "early (see stderr), or auditd dropped records")
        if not events:
            return lines
        lines.append("closest event in the whole window (NOT from the stimulus tree):")
        return lines + sigma_explain.explain_miss(rule, events, k=1, label=label)
    lines.append(f"audited syscalls from the tree: {tree_syscalls(events, tree)}")
    lines.append("the tree's events graded against the rule (succeeded and rejected alike; "
                 "each is labelled):")
    return lines + sigma_explain.explain_miss(rule, events, k=2, candidates=idx, label=label)


def explain_broken(rule, sql, events, tree, meaning):
    """A control PASSED: the events that satisfied the rule, why, and what that means."""
    hits = stimulus_hits(sql, events, tree)
    noop = "the rule matched a no-op: something other than the technique satisfies it"
    lines = [f"meaning: {meaning or noop}"]
    for hit in hits[:3]:
        for e in hit:
            lines.append(f"hit: {describe_event(e)}")
        why = (sigma_explain.judge_events(rule, hit)[0].lines if rule.is_correlation
               else sigma_explain.explain_hit(rule, hit[0]))
        lines.extend(why)
    if len(hits) > 3:
        lines.append(f"... and {len(hits) - 3} more hit(s)")
    return lines


def grade_control(rule, sql, events, tree, expected):
    """Grade a held mutant against the rule: (graded atoms, summary, warning, lines).

    The mutant's closest event (or, for a correlation, its whole event set) says
    which part of the rule held it. A grade other than `expected` is a WARNING:
    the mutant may no longer test what its CONTROLS entry says it does.
    """
    own = [e for e in events if e["pid"] in tree]
    lines = []
    if not own:
        graded, kind = [], "no audited syscall"
        text = ("held: the control's process tree made no audited syscall -- it proves "
                "nothing about the rule")
    elif stimulus_hits(sql, events, tree, succeeded_only=False):
        rejected = sorted({f"{e['syscall']}: {_errno_name(e['exit'])}"
                           for e in own if e["success"] != "yes"})
        graded, kind = [SUCCESS_GATE], "rejected"
        text = ("held: the rule's logic matches, but only syscalls the kernel rejected "
                f"({'; '.join(rejected)}); the success=yes gate held it")
    else:
        verdicts = sigma_explain.judge_events(rule, own)
        v = min(verdicts, key=lambda x: (sigma_explain.KIND_RANK[x.kind], -x.closeness))
        lines, kind = v.lines, v.kind
        graded = list(v.atoms) if v.kind in sigma_explain.NON_TRIVIAL else []
        text = {"near-miss": f"held: near-miss on {', '.join(v.atoms)}",
                "filtered": f"held: filtered on {', '.join(v.atoms)}",
                "distant": "held: distant -- the mutant may not exercise the chokepoint",
                "trivial": "held: trivial -- the mutant does not reach the rule's surface",
                }.get(v.kind, f"held, though the rule's logic grades it {v.kind}")
    warning = None
    if expected is not None and sorted(graded) != sorted(expected):
        warning = (f"WARNING: built to break {', '.join(expected)}, but graded "
                   f"{', '.join(graded) or kind}: the control may no longer test what its "
                   "CONTROLS entry says (not a failure)")
    return graded, text, warning, lines


def explained(fn, rule, *args):
    """Run an explanation helper on a rule; an explanation must never change a verdict."""
    if rule is None:
        return ["(no explanation: sigma_explain could not load the rule)"]
    try:
        return fn(rule, *args)
    except Exception as e:  # noqa: BLE001
        return [f"(no explanation: {type(e).__name__}: {e})"]


def load_rule(rule_path):
    try:
        return sigma_explain.load(os.path.join(REPO, rule_path))
    except Exception as e:  # noqa: BLE001
        print(f"[diag] sigma_explain could not load {rule_path}: {e} (no explanations)")
        return None


def write_json(path, report):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")


# ---- main ----------------------------------------------------------------


def print_table(title, rows):
    """Rows are (status, label, detail[, explanation lines printed beneath])."""
    print(f"\n{title}")
    width = max((len(r[1]) for r in rows), default=0)
    for status, label, detail, *extra in rows:
        print(f"  [{status:^6}] {label:<{width}}  {detail}")
        for line in (extra[0] if extra else []):
            print("           " + line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="compile atomics, controls and rules only; no auditd")
    ap.add_argument("--require-audit", action="store_true",
                    help="fail (instead of skip) when auditd is unavailable")
    ap.add_argument("--json", metavar="PATH",
                    help="also write a machine-readable report (results, controls, "
                    "explanations) to PATH")
    args = ap.parse_args()
    report = {"validator": "linux-auditd", "mode": "dry-run" if args.dry_run else "validate",
              "results": [], "controls": []}
    code = validate(args, report)
    if args.json:
        report["exit"] = code
        write_json(args.json, report)
    return code


def validate(args, report):
    """The validation run behind main(); fills `report` for --json."""
    ok, why = (True, "") if args.dry_run else audit_available()
    if not ok and args.require_audit:
        print(f"ERROR: audit validation unavailable ({why}) and --require-audit set.")
        report.update(mode="error", reason=why)
        return 1
    dry = args.dry_run or not ok
    if args.dry_run:
        print("== DRY RUN: compiling atomics, controls and rules (no auditd) ==")
    elif not ok:
        print(f"== SKIP: audit validation unavailable ({why}) ==")
        print("   Run as root on a host with auditd to validate for real.")
        report.update(mode="skip", reason=why)

    workdir = tempfile.mkdtemp(prefix="deteng_val_")
    rule_paths = list(dict.fromkeys([m[0] for m in MANIFEST] + [c[0] for c in CONTROLS]))
    queries, errors = {}, []
    for path in rule_paths:
        try:
            queries[path] = sigma_eval.compile_rule(os.path.join(REPO, path))
        except Exception as e:  # noqa: BLE001
            errors.append((os.path.basename(path), f"rule did not compile: {e}"))
    binaries = {}
    for src in dict.fromkeys([m[1] for m in MANIFEST] + [c[1] for c in CONTROLS] + [NOOP]):
        try:
            binaries[src] = compile_atomic(src, workdir)
        except Exception as e:  # noqa: BLE001
            errors.append((os.path.basename(src), str(e)))

    if dry or errors:
        for label, detail in errors:
            print(f"  [ERROR ] {label}  {detail}")
        report["results"] = ([{"rule": label, "status": "ERROR", "detail": detail,
                               "explanation": []} for label, detail in errors]
                             + [{"rule": path, "status": "OK", "detail": "compiles",
                                 "explanation": []} for path in queries])
        shutil.rmtree(workdir, ignore_errors=True)
        if not errors:
            print(f"OK: {len(queries)} rules compiled by pySigma, "
                  f"{len(binaries)} atomics/controls compiled.")
        return 1 if errors else 0

    # Every probe of every case (the first missing feature is the SKIP reason).
    probes = {i: [(getattr(p, "what", "probe"), p()) for p in m[3]]
              for i, m in enumerate(MANIFEST)}
    missing = {i: next((w for _, w in probes[i] if w), None) for i in probes}
    print("Kernel-feature probes (asked before the audit rules load; a missing feature "
          "turns a miss into a SKIP):")
    for i, (rule, src, _args, _probes) in enumerate(MANIFEST):
        found = "; ".join(f"{what}: {'present' if w is None else 'MISSING -- ' + w}"
                          for what, w in probes[i]) or "no probe (a miss is always a FAIL)"
        print(f"  {os.path.basename(rule)} <- {os.path.basename(src)}: {found}")
    rules = {path: load_rule(path) for path in rule_paths}
    results, controls = [], []
    load_audit_rules()
    try:
        positive = {}
        for i, (rule, src, run_args, _probes) in enumerate(MANIFEST):
            events, tree, err = run(binaries[src], run_args)
            status, detail = judge(queries[rule], events, tree, missing[i], err)
            positive.setdefault(rule, (src, run_args, status))
            lines = (explained(explain_fail, rules[rule], events, tree)
                     if status == "FAIL" else [])
            results.append((status, os.path.basename(rule), detail, lines))
            report["results"].append({
                "rule": rule, "atomic": src, "status": status, "detail": detail,
                "probes": [{"what": what, "missing": w} for what, w in probes[i]],
                "explanation": lines})

        # Controls: every one must FAIL.
        def control(status, label, detail, meaning, rule, events, tree, expected):
            """Record one control; explain a pass, grade a held mutant."""
            info = {"control": label, "rule": rule, "judge": status, "detail": detail,
                    "meaning": meaning, "expected": expected, "explanation": []}
            if status == "PASS":
                info["explanation"] = explained(explain_broken, rules[rule], queries[rule],
                                                events, tree, meaning)
            elif expected is not None:
                graded = explained(grade_control, rules[rule], queries[rule], events, tree,
                                   expected)
                if isinstance(graded, tuple):
                    info["graded"], info["grade"], info["warning"], info["verdict"] = graded
                else:
                    info["grade"] = graded[0]
            controls.append((status, label, detail, meaning, info))

        events, tree, _ = run(binaries[NOOP], [])
        for rule in rule_paths:
            status, detail = judge(queries[rule], events, tree)
            control(status, f"noop -> {os.path.basename(rule)}", detail, "", rule, events,
                    tree, None)
        for rule, src, run_args, meaning, expected in CONTROLS:
            events, tree, _ = run(binaries[src], run_args)
            status, detail = judge(queries[rule], events, tree)
            control(status, f"{os.path.basename(src)} -> {os.path.basename(rule)}", detail,
                    meaning, rule, events, tree, expected)
        for rule, (src, run_args, pos_status) in positive.items():
            block, comm = allowlist(rule)
            if not comm:
                continue
            label = f"{os.path.basename(src)} as '{comm}' -> {os.path.basename(rule)}"
            if pos_status != "PASS":
                controls.append(("N/A", label, "atomic did not pass under its own "
                                 "name, so the allowlist is not exercised", "",
                                 {"control": label, "rule": rule, "judge": "N/A",
                                  "explanation": []}))
                continue
            binary = compile_atomic(src, os.path.join(workdir, "allow"), name=comm)
            events, tree, _ = run(binary, run_args)
            status, detail = judge(queries[rule], events, tree)
            control(status, label, detail, "the allowlist filter did not suppress an "
                    "allowlisted process", rule, events, tree, [f"{block}.comm"])
    finally:
        unload_audit_rules()
        shutil.rmtree(workdir, ignore_errors=True)

    print_table("Detections (atomic -> auditd -> pySigma backend):", results)
    shown, warnings = [], 0
    for status, label, detail, meaning, info in controls:
        if status == "PASS":
            shown.append(("BROKEN", label, f"passed: {meaning or 'matched a no-op'}",
                          info["explanation"]))
        elif status == "N/A":
            shown.append(("N/A", label, detail))
        else:
            lines = [info["grade"]] if info.get("grade") else []
            if info.get("warning"):
                warnings += 1
                lines += [info["warning"]] + info.get("verdict", [])
            info["explanation"] = lines
            shown.append(("held", label, detail, lines))
        report["controls"].append(dict(info, status=shown[-1][0]))
    print_table("Controls (each must FAIL; one that passes means the check is unsound):",
                shown)

    count = {s: sum(1 for r in results if r[0] == s) for s in ("PASS", "SKIP", "FAIL")}
    broken = sum(1 for r in shown if r[0] == "BROKEN")
    if warnings:
        print(f"\n{warnings} held control(s) graded differently from what they are built "
              "to break (WARNING above; not a failure).")
    print(f"\n{count['PASS']} passed, {count['SKIP']} skipped (kernel feature "
          f"missing), {count['FAIL']} failed; {broken} control(s) broken.")
    return 1 if (count["FAIL"] or broken) else 0


if __name__ == "__main__":
    sys.exit(main())
