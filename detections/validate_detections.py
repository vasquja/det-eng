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

Controls then test the test. The rule must stay quiet on each control; a control
on which its rule fires fails the run:
  * the no-op baseline (detections/controls/noop.c), evaluated against every
    rule: a process that is not a technique. It makes one audited syscall that
    no rule matches, and it must own a record: a baseline that left no record
    proves nothing, and fails the run. It is never the live negative control of
    a rule;
  * the mutants in detections/controls/ (the CONTROLS table), which keep the
    surface of a technique and break one thing: a wrong argument, the two
    halves of a correlation in different pids, or a call the kernel rejects;
  * each atomic re-run under a name from its rule's process allowlist, so the
    rule's `not <allowlist>` filter has to suppress it.

A mutant and a re-run are BUILT controls: each declares what holds it. That is
one required item of the rule (an argument item, the group-by of a correlation,
the allowlist filter), or, for a call that the kernel rejects, the success gate
of this validator. The validator grades each built control against its rule, and
the control must be held by what it declares. One whose process tree made no
audited syscall (vacuous), or that is held for another reason, is BROKEN and
fails the run. So each built control that prints `held` is a LIVE negative
control: the rule would fire if the declared item changed (for the success gate:
if the kernel accepted the call). Each rule of MANIFEST needs a built control: a
rule with none is BROKEN.

Two rules read no argument (userfaultfd_syscall.yml, io_uring_setup.yml), so no
argument value can keep them quiet. Their control is the rule's own syscall with
arguments that the kernel rejects. It tests the success gate of this validator,
not an item of the rule: the rule's logic matches the rejected call.

When the kernel-feature probe turned the emulation of a rule into a SKIP, the
rule is not proven on this host, and its controls are not required there. Its
re-run does not run (as for each atomic that did not pass), and its mutant is
N/A, not BROKEN, when it is not held as declared. On every host, a control on
which the rule fires, or one that left no record, is BROKEN.

Event schema the rules assume (one event per auditd SYSCALL record):
  type=SYSCALL, syscall=<name>, success, exit, a0..a3 (raw hex, as auditd logs
  them), pid, ppid, uid, euid, auid (decimal text, as auditd logs them; an unset
  auid is 4294967295), comm, exe, timestamp. auditd's ENRICHED log format carries
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
  * a BROKEN control on which the rule fired shows the events that satisfied the
    rule and why, with what a pass of that control means;
  * a held control prints its grade ("held: near-miss on afinet_raw_socket.a1");
  * a BROKEN control that is not held as declared prints what it is built to
    break, its grade, and its nearest event graded item by item.
--json PATH also writes all of it as a machine-readable report (`controls`, and
`negatives`: for each rule of MANIFEST, its live negative controls).

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
try:
    # sigma_explain explains a verdict, and it grades the built controls. Without it
    # the verdict of a detection is the same (an explanation never changes it). But
    # a built control that an item of the rule holds cannot be graded, so nothing
    # shows that it is held as declared: it is BROKEN, and the run fails.
    import sigma_explain  # noqa: E402
except Exception as _e:  # noqa: BLE001
    sigma_explain = None
    print(f"[diag] sigma_explain failed to import ({type(_e).__name__}: {_e}): no "
          "explanations, and the controls that an item of a rule holds cannot be graded")

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

# ---- controls -----------------------------------------------------------------
#
# NOOP is the baseline, not a mutant: a process that is not a technique, with one
# audited syscall that no rule matches. It runs against every rule. It must own a
# record (else it is VACUOUS and the run fails), and it is never the live negative
# control of a rule.
#
# CONTROLS holds the mutants. A mutant keeps the surface of a technique and breaks
# ONE thing. A row is (rule, C source, arguments, what a PASS of the control would
# mean, what the mutant is built to break). The last field is a list in these
# words:
#   `<block>.<field>`         one item of a plain rule (`rule_cases.py --atoms RULE`
#                             lists them): a wrong argument;
#   `base:<name>/<item>`      one item of one base of a correlation: a wrong argument
#                             in the call that would be that base's event (a control
#                             that makes no such call is graded `base:<name>`);
#   `group-by`                the halves of a correlation, in different pids;
#   SUCCESS_GATE              a call that the kernel rejects. Such a mutant breaks NO
#                             item of the rule: the rule's logic matches the call,
#                             and only this validator's success=yes check holds it.
#                             It is the only possible control for a rule that reads
#                             no argument (userfaultfd_syscall.yml,
#                             io_uring_setup.yml).
#
# The validator grades each mutant against its rule (grade_control), and the grade
# must be equal to that field. A mutant that is held for another reason is BROKEN
# and fails the run, as is one whose process tree made no audited syscall. The
# same holds for the re-run of an atomic under an allowlisted name, which declares
# `<allowlist block>.comm`. Each rule of MANIFEST needs a row here or an allowlist
# that allowlist() can re-run: a rule with no built control is BROKEN, so a new
# rule cannot be added without one.
SUCCESS_GATE = "success"
VACUOUS = "vacuous"     # a control that made no audited syscall proves nothing
BASELINE = "baseline"   # the grade of the no-op when it owns a record
UNGRADED = "not graded"  # the grade could not be made (sigma_explain failed)
NOOP = "detections/controls/noop.c"
CONTROLS = [
    ("detections/sigma/T1068/dirtypipe_splice_readonly.yml",
     "detections/controls/splice_without_pipe.c", [],
     "a pipe() in one process and a splice() in another were correlated",
     ["group-by"]),
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
    ("detections/sigma/T1068/copyfail_af_alg_authencesn.yml",
     "detections/controls/copyfail_unix_socket_splice.c", [],
     "the a0 (AF_ALG) argument constraint of the socket base was not enforced",
     ["base:copyfail_af_alg_socket/af_alg_socket.a0"]),
    ("detections/sigma/T1068/dirtyfrag_xfrm_unshare_netlink.yml",
     "detections/controls/dirtyfrag_netlink_route_socket.c", [],
     "the a2 (NETLINK_XFRM) argument constraint of the socket base was not enforced",
     ["base:dirtyfrag_xfrm_netlink_xfrm_socket/netlink_xfrm_socket.a2"]),
    ("detections/sigma/T1068/dirtyfrag_rxrpc_socket.yml",
     "detections/controls/rxrpc_netlink_socket.c", [],
     "the a0 (AF_RXRPC) argument constraint was not enforced",
     ["rxrpc_socket.a0"]),
    ("detections/sigma/T1040/afxdp_socket.yml",
     "detections/controls/afxdp_netlink_socket.c", [],
     "the a0 (AF_XDP) argument constraint was not enforced",
     ["afxdp_socket.a0"]),
    ("detections/sigma/T1622/ptrace_traceme.yml",
     "detections/controls/ptrace_attach_child.c", [],
     "the a0 (PTRACE_TRACEME) argument constraint was not enforced",
     ["ptrace_traceme.a0"]),
    # The next two rules read no argument. Their control tests the success gate of
    # this validator, not an item of the rule (see SUCCESS_GATE above).
    ("detections/sigma/T1068/userfaultfd_syscall.yml",
     "detections/controls/userfaultfd_bad_flags.c", [],
     "a userfaultfd() that the kernel rejected counted as an execution (or the kernel "
     "accepted the call of the control)",
     [SUCCESS_GATE]),
    ("detections/sigma/T1685/io_uring_setup.yml",
     "detections/controls/io_uring_setup_zero_entries.c", [],
     "an io_uring_setup() that the kernel rejected counted as an execution (or the "
     "kernel accepted the call of the control)",
     [SUCCESS_GATE]),
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
# The SYSCALL record's credential fields that a rule may read. uid is the real
# user, euid the effective user that the kernel checks for privilege, auid the
# login uid that pam_loginuid sets at login and every child inherits (sudo and su
# keep it). suid, fsuid and the group ids are in the record too, but no rule
# reads them.
CRED_FIELDS = ("uid", "euid", "auid")
_STAMP = re.compile(r"audit\((\d+)\.(\d+):")
_HEX = re.compile(r"(?:[0-9A-F]{2})+")


def untrusted_string(value, quoted):
    """An auditd 'untrusted string' field (comm, exe) as text.

    The kernel logs such a value in double quotes when it is plain printable
    text, and as unquoted uppercase HEX when it holds a space, a quote or a
    non-printable byte (audit_log_untrustedstring): comm 'Attach Listener' is
    logged as comm=417474616368204C697374656E6572. Decode that form, so a rule or
    an allowlist that names the process sees its real name.
    """
    if value is None or quoted or not _HEX.fullmatch(value):
        return value
    return bytes.fromhex(value).decode("utf-8", "replace")


def normalize(lines):
    """auditd SYSCALL records keyed det-eng -> events in the rules' schema."""
    names = {nr: name for name, nr in _dump_syscalls().items()}
    events = []
    for line in lines:
        if 'key="det-eng"' not in line:
            continue
        raw, _, enriched = line.partition("\x1d")
        pairs = _FIELD.findall(raw)
        f = {k: v.strip('"') for k, v in pairs}
        quoted = {k for k, v in pairs if v.startswith('"')}
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
            # Credentials as text, exactly as the kernel logs them: decimal ids in
            # the initial user namespace (from_kuid(&init_user_ns, ...)), so root in
            # a rootless container reads as the host user. An unset login uid is
            # auid=4294967295 ((u32)-1, AUDIT_UID_UNSET): daemons and their children.
            **{k: f.get(k) for k in CRED_FIELDS},
            "comm": untrusted_string(f.get("comm"), "comm" in quoted),
            "exe": untrusted_string(f.get("exe"), "exe" in quoted),
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
    noop = ("the rule fired on the no-op baseline: something other than the technique "
            "satisfies it")
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


def base_items(rule, events, atom):
    """The items of one base of a correlation that an event set breaks.

    `atom` is `base:<ref>`: a base that no event of the set matches, and whose
    absence alone keeps the correlation quiet. Each event that no base matches and
    that misses this base by one item (a near-miss or a filtered event of the base
    rule) is marked as the base's match, and the compiled correlation runs on the
    set. If it fires, that event is in the right group and window, and the item is
    what holds the set: `base:<ref>/<item>`. The result is [] when no event of the
    set is one item away from the base (for example, when the set holds no socket
    call at all for a socket base).

    check_sufficiency.py makes the same test on a sidecar case
    (base_negative_items).
    """
    base = rule.bases[atom[len("base:"):]]
    table = sigma_eval.EventTable(events)
    matched = {i for other in rule.bases.values() for hit in table.hit_indices(other.sql)
               for i in hit}
    rows, _ = base.truth_table(table)
    items = []
    for i, event in enumerate(events):
        if i in matched:
            continue
        v = base.verdict(event, rows[i], False)
        if v.mismatch or v.kind not in sigma_explain.NON_TRIVIAL or not v.atoms:
            continue
        marked = [dict(e, **{sigma_explain.REPAIR_FIELD: atom}) if j == i else e
                  for j, e in enumerate(events)]
        if rule._fires(marked, rule._variant(atom)):
            items += [f"{atom}/{a}" for a in v.atoms if f"{atom}/{a}" not in items]
    return items


def grade_control(rule, sql, events, tree, expected):
    """Grade a control on which its rule did not fire: (graded, kind, why, lines).

    `graded` says what holds the control, in the words of a CONTROLS entry: the
    items of the rule of which one flip fires it, or [SUCCESS_GATE]. It is [] when
    no single item holds the control. `kind` names the grade, `why` is one line for
    the report, and `lines` grade the nearest event item by item.

    The grade uses the control's own SUCCEEDED syscalls, the same pool judge()
    gates on: a syscall the kernel rejected never reaches the rule, so it cannot
    be what held the control. The closest event (or, for a correlation, the whole
    set) says which part of the rule held it. For a correlation that lacks one
    base, base_items() then names the item of that base that an event of the
    control breaks.

    A control whose process tree made no audited syscall at all is VACUOUS. The
    no-op baseline (`expected` is None) declares no item: it is graded only for
    that, and its grade is BASELINE when it owns a record.
    """
    own = [e for e in events if e["pid"] in tree]
    if not own:
        return [], VACUOUS, ("VACUOUS: the control's process tree made no audited syscall "
                             "-- it proves nothing about the rule"), []
    if expected is None:
        return [], BASELINE, (f"the baseline owns {tree_syscalls(events, tree)}, and the "
                              "rule stays quiet"), []
    accepted = [e for e in own if e["success"] == "yes"]
    rejected = sorted({f"{e['syscall']}: {_errno_name(e['exit'])}"
                       for e in own if e["success"] != "yes"})
    if stimulus_hits(sql, events, tree, succeeded_only=False):
        return [SUCCESS_GATE], "rejected", (
            "the rule's logic matches, but only syscalls the kernel rejected "
            f"({'; '.join(rejected)}); the success=yes gate held it"), []
    if not accepted:
        return [], "all rejected", (
            "every audited syscall the control made was rejected by the kernel "
            f"({'; '.join(rejected)}), so it never reaches the rule"), []
    if rule is None:
        return [], UNGRADED, "not graded: sigma_explain could not load the rule", []
    verdicts = sigma_explain.judge_events(rule, accepted)
    v = min(verdicts, key=lambda x: (sigma_explain.KIND_RANK[x.kind], -x.closeness))
    graded = list(v.atoms) if v.kind in sigma_explain.NON_TRIVIAL else []
    if rule.is_correlation:
        graded = [item for atom in graded
                  for item in ((base_items(rule, accepted, atom) if atom.startswith("base:")
                                else []) or [atom])]
    why = {"near-miss": f"near-miss on {', '.join(graded)}",
           "filtered": f"filtered on {', '.join(graded)}",
           "distant": "distant -- no single item of the rule holds the control, so it "
                      "does not exercise the chokepoint",
           "trivial": "trivial -- the control does not reach the rule's surface",
           }.get(v.kind, f"the rule's logic grades it {v.kind}")
    if rejected:
        why += f" (rejected syscalls not graded: {'; '.join(rejected)})"
    return graded, v.kind, why, v.lines


def control_row(label, detail, meaning, info, skipped):
    """One row of the control table for a control that ran: (status, label, detail,
    lines). Sets `status`, `live` and `explanation` in `info`.

    held    the rule stayed quiet, and for the reason the control declares (for
            the no-op baseline: it owns a record). A built control that is held
            is a live negative control of its rule.
    BROKEN  the rule fired on the control; or the control made no audited
            syscall; or the rule stayed quiet for another reason than the
            declared one; or the grade could not be made.
    N/A     the control is not held as declared, and the kernel-feature probe
            turned the emulation of its rule into a SKIP (`skipped`): the rule is
            not proven on this host, so its control is not required there.
    """
    expected, kind, why = info["expected"], info.get("kind"), info.get("grade", "")
    more = [f"stderr of the control: {info['stderr']}"] if info.get("stderr") else []
    if info["judge"] == "PASS":
        row = ("BROKEN", label, f"passed: {meaning or 'the rule fired on the no-op baseline'}",
               info["explanation"])
    elif kind == VACUOUS:
        row = ("BROKEN", label, "vacuous: the control made no audited syscall", [why] + more)
    elif kind == BASELINE or (expected is not None and kind != UNGRADED
                              and sorted(info["graded"]) == sorted(expected)):
        info["grade"] = f"held: {why}"
        row = ("held", label, detail, [info["grade"]])
    elif kind == UNGRADED:
        row = ("BROKEN", label, "not graded: nothing shows that the control is held as "
               "declared", [why] + more)
    else:
        got = ", ".join(info["graded"]) or kind
        lines = ([f"the rule stayed quiet, but not for the declared reason: {why}",
                  "meaning: the control does not test what its entry declares, so it is "
                  "not a live negative control of the rule"] + info.get("verdict", []) + more)
        if info["rule"] in skipped:
            row = ("N/A", label, f"not held as declared (built to break {', '.join(expected)}, "
                   f"graded {got}), and the emulation of this rule was SKIPPED (kernel "
                   "feature missing): the control is not exercised on this host", lines)
        else:
            row = ("BROKEN", label, f"not held as declared: built to break "
                   f"{', '.join(expected)}, but graded {got}", lines)
    info["status"] = row[0]
    info["live"] = row[0] == "held" and expected is not None
    info["explanation"] = row[3]
    return row


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
        return sigma_explain.load(os.path.join(REPO, rule_path)).stripped()  # no null guards
    except Exception as e:  # noqa: BLE001
        print(f"[diag] sigma_explain could not load {rule_path}: {e} (no explanations, "
              "and no grade by item for its controls)")
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
                    "the live negative controls of each rule, explanations) to PATH")
    args = ap.parse_args()
    report = {"validator": "linux-auditd", "mode": "dry-run" if args.dry_run else "validate",
              "results": [], "controls": [], "negatives": []}
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
        positive, statuses = {}, {}
        for i, (rule, src, run_args, _probes) in enumerate(MANIFEST):
            events, tree, err = run(binaries[src], run_args)
            status, detail = judge(queries[rule], events, tree, missing[i], err)
            positive.setdefault(rule, (src, run_args, status))
            statuses.setdefault(rule, []).append(status)
            lines = (explained(explain_fail, rules[rule], events, tree)
                     if status == "FAIL" else [])
            results.append((status, os.path.basename(rule), detail, lines))
            report["results"].append({
                "rule": rule, "atomic": src, "status": status, "detail": detail,
                "probes": [{"what": what, "missing": w} for what, w in probes[i]],
                "explanation": lines})

        # Controls: the rule must stay quiet on every one.
        def control(status, label, detail, meaning, rule, events, tree, expected, stderr=""):
            """Record one control; explain a pass, grade a control that held."""
            info = {"control": label, "rule": rule, "judge": status, "detail": detail,
                    "meaning": meaning, "expected": expected, "explanation": []}
            if status == "PASS":
                info["explanation"] = explained(explain_broken, rules[rule], queries[rule],
                                                events, tree, meaning)
            else:
                # The grade is a verdict, not an explanation: a control that cannot be
                # graded is not shown to be held as declared (UNGRADED is BROKEN).
                try:
                    grade = grade_control(rules[rule], queries[rule], events, tree, expected)
                except Exception as e:  # noqa: BLE001
                    grade = [], UNGRADED, f"not graded: {type(e).__name__}: {e}", []
                info["graded"], info["kind"], info["grade"], info["verdict"] = grade
                info["stderr"] = stderr
            controls.append((label, detail, meaning, info))

        events, tree, err = run(binaries[NOOP], [])
        for rule in rule_paths:
            status, detail = judge(queries[rule], events, tree)
            control(status, f"noop -> {os.path.basename(rule)}", detail, "", rule, events,
                    tree, None, err)
        for rule, src, run_args, meaning, expected in CONTROLS:
            events, tree, err = run(binaries[src], run_args)
            status, detail = judge(queries[rule], events, tree)
            control(status, f"{os.path.basename(src)} -> {os.path.basename(rule)}", detail,
                    meaning, rule, events, tree, expected, err)
        for rule, (src, run_args, pos_status) in positive.items():
            block, comm = allowlist(rule)
            if not comm:
                continue
            label = f"{os.path.basename(src)} as '{comm}' -> {os.path.basename(rule)}"
            if pos_status != "PASS":
                controls.append((label, "atomic did not pass under its own name, so the "
                                 "allowlist is not exercised", "",
                                 {"control": label, "rule": rule, "judge": "N/A",
                                  "expected": [f"{block}.comm"], "explanation": []}))
                continue
            binary = compile_atomic(src, os.path.join(workdir, "allow"), name=comm)
            events, tree, err = run(binary, run_args)
            status, detail = judge(queries[rule], events, tree)
            control(status, label, detail, "the allowlist filter did not suppress an "
                    "allowlisted process", rule, events, tree, [f"{block}.comm"], err)
    finally:
        unload_audit_rules()
        shutil.rmtree(workdir, ignore_errors=True)

    print_table("Detections (atomic -> auditd -> pySigma backend):", results)
    # A rule is skipped when the probe turned each of its emulations into a SKIP.
    skipped = {rule for rule, seen in statuses.items() if set(seen) == {"SKIP"}}
    shown = []
    for label, detail, meaning, info in controls:
        if info["judge"] == "N/A":      # a re-run that did not run
            info.update(status="N/A", live=False)
            shown.append(("N/A", label, detail))
        else:
            shown.append(control_row(label, detail, meaning, info, skipped))
        report["controls"].append(info)

    # Each rule of MANIFEST needs a live negative control: a built control (a mutant
    # or a re-run; never the no-op) that is held by what it declares. A rule whose
    # built controls are all BROKEN or N/A has its rows above. A rule for which no
    # control is built at all has no row there, so it gets one here.
    report["negatives"] = []
    for rule in dict.fromkeys(m[0] for m in MANIFEST):
        built = [info for _l, _d, _m, info in controls
                 if info["rule"] == rule and info["expected"] is not None]
        live = [info["control"] for info in built if info["live"]]
        if live:
            state = "live"
        elif not built:
            state = "BROKEN"
            shown.append(("BROKEN", os.path.basename(rule), "no live negative control: no "
                          "control is built for this rule (a row of CONTROLS that declares "
                          "the item it breaks, or an allowlist to re-run)"))
        else:
            state = "BROKEN" if any(info["status"] == "BROKEN" for info in built) else "N/A"
        report["negatives"].append({"rule": rule, "status": state, "live": live})
    print_table("Controls (the rule must stay quiet on each one; a mutant or a re-run must be "
                "held by what it declares):", shown)
    without = [n for n in report["negatives"] if n["status"] != "live"]
    print(f"\nLive negative control (a mutant or a re-run that is held as declared): "
          f"{len(report['negatives']) - len(without)} of {len(report['negatives'])} rule(s).")
    for n in without:
        print(f"  none for {os.path.basename(n['rule'])}: "
              + ("see the BROKEN row(s) above" if n["status"] == "BROKEN" else
                 "not applicable on this host (its emulation did not pass; see the N/A "
                 "row(s) above)"))

    count = {s: sum(1 for r in results if r[0] == s) for s in ("PASS", "SKIP", "FAIL")}
    broken = sum(1 for r in shown if r[0] == "BROKEN")
    print(f"\n{count['PASS']} passed, {count['SKIP']} skipped (kernel feature "
          f"missing), {count['FAIL']} failed; {broken} control(s) broken.")
    return 1 if (count["FAIL"] or broken) else 0


if __name__ == "__main__":
    sys.exit(main())
