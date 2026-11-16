"""
One raw auditd SYSCALL record (one line of audit.log) as an event of the rules' schema.

The Linux validator (validate_detections.normalize) reads the live kernel log with
this function, and the external-records gate (external_records.py) reads a raw
auditd dataset with it, so both build the same event from the same line. The
caller gives the table of syscall names: the validator takes it from the host
(`ausyscall --dump`), the gate from detections/external/syscalls_x86_64.json.

A line with the ENRICHED fields after a GS byte (0x1d) gives the name of the
syscall in its `SYSCALL=` field; no other field after the GS byte goes into the
event. A line whose ENRICHED fields follow with no GS byte (`key="x"ARCH=x86_64
SYSCALL=unshare AUID="ubuntu" UID="ubuntu"`) gives them as more fields of the
record. The event takes only the lower-case fields of the kernel record below, so
no upper-case field of such a line is in the event, and the name of the syscall
comes from the table.
"""

import re
from datetime import datetime, timezone

FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')
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


def syscall_event(line, names):
    """The event of one SYSCALL record, or None for a record of another type.

    names: {syscall number: name}. A number that the table does not hold stays
    the number (as text). The caller checks the form of the line first: a SYSCALL
    record without msg=audit(...), pid or ppid raises an exception here.
    """
    raw, _, enriched = line.partition("\x1d")
    pairs = FIELD.findall(raw)
    f = {k: v.strip('"') for k, v in pairs}
    quoted = {k for k, v in pairs if v.startswith('"')}
    if f.get("type") != "SYSCALL" or "syscall" not in f:
        return None
    name = dict(FIELD.findall(enriched)).get("SYSCALL")
    stamp = _STAMP.search(f.get("msg", ""))
    when = datetime.fromtimestamp(int(stamp.group(1)) + int(stamp.group(2)) / 1000,
                                  timezone.utc)
    return {
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
    }
