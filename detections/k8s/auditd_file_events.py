#!/usr/bin/env python3
"""
Turn Linux audit records into Sigma `linux` / `file_event` JSON lines, for the two
node file-event rules the kind CI node sensor gates (C2-7):

  * T1552.007/linux_k8s_sa_token_read.yml  (TRR9006 Procedure E) -- a read of a
    projected service-account token off the node, caught by a per-file read
    watch on the one token file E reads, added through the node's root
    (`-F path=/proc/<node pid>/root<resolved token file> -F perm=r`). The token
    is on a tmpfs that the kubelet mounts inside the node's own mount namespace,
    so a directory-tree watch added from the host (`-w DIR` or `-F dir=DIR`, the
    same recursive rule) on the node's /var volume does not see it: a tree rule
    tags only the mounts that the auditctl caller's namespace can see.
  * T1543.005/linux_static_pod_manifest_write.yml (TRR9003 Procedure A) -- a
    write in the kubelet static-pod directory, caught by a write/attribute tree
    watch on the host directory that is bind-mounted there, in the checkout
    (`-F dir=${GITHUB_WORKSPACE}/.kind/trr9003-manifests -F perm=wa`).
Both use the key k8s_node_file.

A kind node is a Docker container on the runner's kernel, and the audit
subsystem is not namespaced, so the runner's auditd sees the syscalls the node's
processes make. The `exe` of a SYSCALL record is rendered relative to the task's
own root, and the `name` of a PATH record is the path string the process passed,
so both are the paths the node process saw -- the container paths
(`/usr/local/bin/trr9006-reader`, `/var/lib/kubelet/pods/.../token`,
`/etc/kubernetes/manifests/...`), not the host's volume/overlay/bind path. Those
are exactly the `Image` and `TargetFilename` the two rules read, so no host-path
translation is needed.

Each emitted record carries the fields the rules read and the gate needs:
  TargetFilename  the file the syscall touched (PATH name; a relative name is
                  made absolute with CWD only when the syscall resolved it from
                  the CWD, see _target)
  Image           the process executable (SYSCALL exe)
  ProcessId       the process id (SYSCALL pid)
  EventType       create / delete / open, derived from the PATH nametype (a
                  sensor-agnostic best effort; the current rules do not key on it,
                  see detections/RULE_DEFECTS.md L15)
  Timestamp       the event time (from the audit message), UTC ISO 8601 with
                  microseconds, so a validator can place it in a procedure's
                  ledger window

Input is the raw audit log (`/var/log/audit/audit.log`, or `ausearch -k KEY --raw`
output): one record per line, records of one event sharing the same
`msg=audit(<epoch.frac>:<serial>)`. With --key, only events whose SYSCALL names
that audit key are converted (the rest of the host's audit traffic is dropped).

Usage:
    python3 detections/k8s/auditd_file_events.py AUDIT_LOG [--key k8s_node_file] \
        > node-file-events.jsonl

The reader never trusts the log's own byte offsets: it groups by the audit event
id, skips a record it cannot parse, and emits nothing for an event with no SYSCALL
or no usable PATH, so a truncated last line or an unrelated record cannot make it
fail or emit a half record.

Limit: a relative PATH name of a *at syscall with a real directory fd (openat(fd,
"token"), as fts/find traversal or os.open(name, dir_fd=...) make) is relative to
that directory, which the audit record does not name. The converter does not guess
it from the CWD: it skips that item and counts it on stderr.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone

# `msg=audit(1697030400.123:4567)`: the event's time (epoch seconds.fraction) and
# its serial. Records of one syscall event share this whole token.
_MSG = re.compile(r"msg=audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\):")
# A `key=value` field. The value is a double-quoted string, a bare hex blob (how
# the kernel encodes a path or comm with a space or other awkward byte), or an
# unquoted token. Order matters: try quoted, then the fields we read as hex, then
# a bare token.
_FIELD = re.compile(r'(\w+)=(?:"([^"]*)"|([0-9A-F]{2,}(?![\w=]))|(\S+))')

# The PATH nametype -> a coarse EventType. CREATE and DELETE are unambiguous; a
# plain NORMAL reference (an open for read, or a write to a file that already
# exists) is reported as "open". The rules do not match on this field (L15); it is
# here so a downstream rule that gains an event-type item has one to read.
_NAMETYPE_EVENT = {"CREATE": "create", "DELETE": "delete", "NORMAL": "open"}
# PATH items that name a containing directory, not the object the syscall acted
# on. They are dropped so a create does not also emit its parent directory.
_PARENT_NAMETYPES = {"PARENT", "UNKNOWN"}


def _unhex(blob):
    """Decode a bare-hex audit field (a path/comm with an awkward byte) to text,
    or return it unchanged if it is not clean hex."""
    try:
        return bytes.fromhex(blob).decode("utf-8", "replace")
    except ValueError:
        return blob


# Fields the kernel writes as an "untrusted string": quoted when printable, else
# bare hex. `key` is one of them: several keys of one event are joined by 0x01, a
# control byte, so such a key is always hex.
_HEX_FIELDS = ("name", "exe", "comm", "cwd", "proctitle", "key")


def parse_fields(rest):
    """{key: value} for the `k=v` part of one audit record, decoding hex blobs for
    the untrusted-string fields (_HEX_FIELDS); numeric and flag fields are left as
    their text."""
    fields = {}
    # re.findall gives '' (never None) for a group that did not take part. A quoted
    # value wins, also an empty one ("" with no hex and no bare part).
    for key, quoted, hexblob, bare in _FIELD.findall(rest):
        if quoted != "" or (hexblob == "" and bare == ""):
            value = quoted
        elif hexblob:
            value = _unhex(hexblob) if key in _HEX_FIELDS else hexblob
        else:
            value = bare
        # A field can repeat (several a0.. args); keep the first, which is the one
        # the fields we read (name within a PATH record) use.
        fields.setdefault(key, value)
    return fields


def _iso(epoch):
    """`1697030400.123` -> `2023-10-11T...Z` (UTC, microseconds), so a ledger
    window (also UTC) can place the event."""
    t = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _key_match(syscall_fields, key):
    """Whether the SYSCALL record names the audit `key`. Several keys are joined
    with 0x01 in the one `key` field (hex-encoded, decoded by parse_fields); match
    any of them."""
    if key is None:
        return True
    raw = syscall_fields.get("key")
    if raw is None:
        return False
    return key in raw.split("\x01")


def group_events(lines):
    """{event id: {"epoch": str, "syscall": {...}|None, "paths": [{...}, ...], "cwd": str|None}}
    from raw audit lines, in first-seen order. A line that has no audit msg token,
    or whose record type is one we do not read, is skipped."""
    events = {}
    for line in lines:
        m = _MSG.search(line)
        if not m:
            continue
        tm = re.search(r"\btype=(\w+)", line)
        if not tm:
            continue
        rtype = tm.group(1)
        if rtype not in ("SYSCALL", "PATH", "CWD"):
            continue
        eid = (m.group("epoch"), m.group("serial"))
        ev = events.setdefault(eid, {"epoch": m.group("epoch"), "syscall": None,
                                     "paths": [], "cwd": None})
        rest = line[m.end():]
        fields = parse_fields(rest)
        if rtype == "SYSCALL":
            ev["syscall"] = fields
        elif rtype == "PATH":
            ev["paths"].append(fields)
        elif rtype == "CWD":
            ev["cwd"] = fields.get("cwd")
    return events


# AT_FDCWD (-100) as the audit record prints a 32-bit int argument (a0=ffffff9c),
# or sign-extended to 64 bits.
_AT_FDCWD = {"ffffff9c", "ffffffffffffff9c"}
# Syscalls that take a directory fd, by name, with the argument(s) that hold it:
# a relative name is relative to that fd, and to the CWD only when the fd is AT_FDCWD.
_DIRFD_ARGS = {name: ("a0",) for name in (
    "openat", "openat2", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat",
    "fstatat64", "unlinkat", "readlinkat", "fchmodat", "fchmodat2", "faccessat",
    "faccessat2", "utimensat", "name_to_handle_at", "execveat", "statx", "open_tree")}
_DIRFD_ARGS.update({"renameat": ("a0", "a2"), "renameat2": ("a0", "a2"),
                    "linkat": ("a0", "a2"), "move_mount": ("a0", "a2"),
                    "symlinkat": ("a1",)})
# Syscalls that resolve a relative name from the CWD (no directory fd).
_CWD_SYSCALLS = {"open", "creat", "unlink", "rename", "mkdir", "rmdir", "link",
                 "symlink", "chmod", "chown", "lchown", "truncate", "stat", "lstat",
                 "access", "readlink", "utime", "utimes", "execve", "mknod", "chdir",
                 "chroot", "setxattr", "lsetxattr", "getxattr", "lgetxattr",
                 "listxattr", "llistxattr", "removexattr", "lremovexattr", "statfs"}
# x86_64 (arch=c000003e) syscall numbers, for a log without the ENRICHED SYSCALL= name.
_X86_64 = {2: "open", 85: "creat", 87: "unlink", 82: "rename", 83: "mkdir", 84: "rmdir",
           86: "link", 88: "symlink", 90: "chmod", 92: "chown", 94: "lchown",
           76: "truncate", 4: "stat", 6: "lstat", 21: "access", 89: "readlink",
           132: "utime", 235: "utimes", 59: "execve", 133: "mknod", 80: "chdir",
           161: "chroot", 188: "setxattr", 189: "lsetxattr", 191: "getxattr",
           192: "lgetxattr", 194: "listxattr", 195: "llistxattr", 197: "removexattr",
           198: "lremovexattr", 137: "statfs", 257: "openat", 258: "mkdirat",
           259: "mknodat", 260: "fchownat", 261: "futimesat", 262: "newfstatat",
           263: "unlinkat", 264: "renameat", 265: "linkat", 266: "symlinkat",
           267: "readlinkat", 268: "fchmodat", 269: "faccessat", 280: "utimensat",
           303: "name_to_handle_at", 316: "renameat2", 322: "execveat", 332: "statx",
           428: "open_tree", 429: "move_mount", 437: "openat2", 439: "faccessat2",
           452: "fchmodat2"}


def _syscall_name(syscall):
    """The syscall's name: the ENRICHED `SYSCALL=` field, or the x86_64 number."""
    name = syscall.get("SYSCALL")
    if name:
        return name
    if syscall.get("arch") == "c000003e":
        try:
            return _X86_64.get(int(syscall.get("syscall")))
        except (TypeError, ValueError):
            return None
    return None


def _cwd_relative(syscall):
    """Whether a relative PATH name of this syscall is relative to the CWD."""
    name = _syscall_name(syscall)
    if name in _CWD_SYSCALLS:
        return True
    if name in _DIRFD_ARGS:
        return all(str(syscall.get(a, "")).lower() in _AT_FDCWD for a in _DIRFD_ARGS[name])
    return False  # an unknown syscall: do not guess


def _target(name, cwd, syscall):
    """An absolute TargetFilename from a PATH `name`, or None. An absolute name is
    used as is. A relative name is joined with the CWD only when the syscall
    resolved it from the CWD; a name relative to a directory fd cannot be placed."""
    if not name:
        return None
    if name.startswith("/"):
        return name
    if not cwd or not _cwd_relative(syscall):
        return None
    base = cwd.rstrip("/")
    return f"{base}/{name}" if base else "/" + name


def event_records(ev, key, skipped=None):
    """The file_event record(s) for one audit event, or [] if it is not a keyed
    file syscall with a usable PATH. One record per PATH item the syscall acted on
    (not the parent directory of a create). A PATH item whose relative name cannot
    be placed is counted in `skipped` (a one-item list), not emitted."""
    syscall = ev.get("syscall")
    if not syscall or not _key_match(syscall, key):
        return []
    exe = syscall.get("exe")
    pid = syscall.get("pid")
    if not exe:
        return []
    out = []
    for path in ev["paths"]:
        nametype = path.get("nametype")
        if nametype in _PARENT_NAMETYPES:
            continue
        target = _target(path.get("name"), ev.get("cwd"), syscall)
        if not target:
            if path.get("name") and skipped is not None:
                skipped[0] += 1
            continue
        rec = {"TargetFilename": target, "Image": exe,
               "EventType": _NAMETYPE_EVENT.get(nametype, "access"),
               "Timestamp": _iso(ev["epoch"])}
        try:
            rec["ProcessId"] = int(pid)
        except (TypeError, ValueError):
            pass
        out.append(rec)
    return out


def convert(lines, key=None, skipped=None):
    """Every file_event record from the raw audit `lines`, in event order."""
    out = []
    for ev in group_events(lines).values():
        out.extend(event_records(ev, key, skipped))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Convert Linux audit records to Sigma "
                                             "linux/file_event JSON lines.")
    ap.add_argument("audit_log", help="raw audit log (one record per line)")
    ap.add_argument("--key", default=None,
                    help="only convert events whose SYSCALL names this audit key "
                         "(e.g. k8s_node_file); default: every file syscall")
    args = ap.parse_args(argv)
    skipped = [0]
    with open(args.audit_log, encoding="utf-8", errors="replace") as fh:
        records = convert(fh, args.key, skipped)
    for rec in records:
        sys.stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
    if skipped[0]:
        sys.stderr.write(f"auditd_file_events: skipped {skipped[0]} PATH item(s) whose "
                         "relative name is relative to a directory fd (not placeable)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
