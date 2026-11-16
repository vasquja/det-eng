#!/usr/bin/env python3
"""
Validate the TRR9003 (static pod, T1543.005) detection loop on the telemetry the
emulation produced. Sibling of validate_k8s_detections.py.

Three rules are match-gated, one per sensor:

  * Strategy 1, the chokepoint — node runtime sensor (CRI pod sandboxes):
        drop a static pod manifest on a node -> the kubelet starts the pod with
        `kubernetes.io/config.source: file` -> the CRI rule matches the sandbox.
    It must match the emulation's injected static pod AND the invalid-namespace
    variant (`trr9003-ghost`), the pod that runs on the node while the API
    server stores no object for it. That second match is the gap this rule
    closes. It must also match Procedure B's URL static pod on the worker node
    (`trr9003-url-<worker>` in namespace default, `config.source: http`).

  * Strategy 2, the fallback — API server audit log:
        the kubelet registers a mirror pod -> the API server writes a
        `create pods` event by a node identity -> the audit rule matches it.
    It must match the injected pod's stored mirror pod (code 2xx) AND the
    invalid-namespace pod's mirror-create attempt, which the API server
    refuses with 404 (namespace not found) but still audits. It must also
    match Procedure B's stored mirror pod `trr9003-url-<worker>` (namespace
    default), created by `system:node:<worker>`.

The worker node name is TRR9003_WORKER (default trr9003-worker), as in
atomics/T1543.005/src/emulate.sh. The B gates need the LIVE Procedure B
(TRR9003_RECONFIGURE=1, which CI sets, on a cluster with a worker node): a
read-only B makes no telemetry, so a strict run misses B, and the MISS says so.

The CRI and audit rules also match the control-plane static pods every kubeadm
node starts, by design (a documented false positive). So a match alone proves nothing about
the emulation: a rule PASSES only if it matches the emulation's own pods. The
validator reports the baseline separately. For the CRI rule it also runs a
false-positive control: the rule must not match any sandbox the API server
scheduled (`config.source: api`), and there must be some in the log, so the
control is not vacuous.

Each log is flattened to dotted field names and each rule runs through its
pySigma-compiled query (see sigma_eval.py).

The third rule, Strategy 3, reads the node file-event sensor (C2-7):

  * the kubelet static-pod directory is watched for writes (auditd `-p wa`):
        the emulation drops its manifest through a marked copy of tee
        (/usr/local/bin/trr9003-tee) -> a linux/file_event record -> the
        file-event rule matches it. CI adds the watch before the cluster is
        created, so the file log also holds kubeadm's own control-plane manifest
        writes. A false-positive control runs on them: the file-event rule must
        match none of kubeadm's writes (its filter_install excludes them by full
        path), and there must be some in the log, so the control is not vacuous.

Logs:
    --audit-log PATH   API server audit log (JSON lines).
    --cri-log PATH     node runtime sensor log: one `crictl pods -o json`
                       snapshot per line, as detections/k8s/cri-pod-sensor.sh
                       writes it. Each sandbox counts once, at first sighting.
    --file-log PATH    node file-event sensor log: linux/file_event JSON lines
                       (TargetFilename, Image, ProcessId, EventType, Timestamp),
                       as detections/k8s/auditd_file_events.py writes them from
                       the runner's auditd records.

    A record of each log (RECORDS): an audit event is a JSON object with "kind":
    "Event" and an apiVersion of the group audit.k8s.io; a pod sandbox has an "id"
    and a "metadata" object with a "name" (a snapshot of the CRI log holds them in
    "items", a list); a file event has a "TargetFilename" and an "Image". A blank
    line, and a line that a capture cut, are not records. A capture can cut only the
    last line of a log: that line is skipped when json refuses it, it has no line
    feed at its end, and it starts with "{" (cut_line()). Each other line, or item
    of a snapshot, that is not a record fails every run that reads the log (a strict
    run, --report and --expect-miss) after the logs are read, and no rule is judged:
    a line that is not JSON (also NUL bytes or U+200B before a record), JSON that is
    not an object (`[]`), a JSON object that is not a record of the log (`{}`), a
    snapshot whose "items" is not a list, bytes that are not UTF-8, the byte order
    mark of UTF-8 at the start of a line, JSON that the validator cannot read (too
    deep, or a number that is too long), and an object that holds one key two times
    (json keeps only the last value). One ERROR line names the log, the
    line (and the item) and the problem (at most 10 for each log, then the number
    of the others), and a FAILED line ends the run with exit 1. With --expect-miss
    the failed control lines of the pre-emulation logs (a log that is not given, an
    audit log without a record, and a CRI log or a file log without a record, with
    the line of the CRI control or the file control) come before the FAILED line,
    and the --json control of those logs says FAILED; --json gets `log_problems` (with
    the same limit) when a log holds such a line. A log that is a directory, or
    that the run cannot open, is an ERROR (exit 1) at once.

Modes:
    python3 detections/validate_staticpod_detections.py --dry-run
        Compile the rules only. No cluster or log needed.

    python3 detections/validate_staticpod_detections.py --audit-log A --cri-log C \
            --file-log F
        Full validation. Default strict: a rule that misses a required
        emulation pod, or a failed control, fails the run (exit 1). In a strict
        run a rule whose log is not given is skipped; without --audit-log the
        run reads /tmp/kube-apiserver-audit.log, and when it finds no log at all
        it prints SKIP and exits 0 (for a local run without a cluster). An empty
        value (--audit-log '') is an audit log that does not exist: the default
        is only for a run without the option.

    ... --ledger PATH
        The emulation ledger (atomics/T1543.005/src/emulate.sh appends one JSON
        line per procedure to $DETENG_LEDGER: trr, procedure, start, end, exit,
        expect, and "mode": "read-only" for a read-only Procedure B; the
        invalid-namespace variant is procedure GAP). With it, a gate also needs
        its record inside its procedure's [start, end] (an audit event by
        requestReceivedTimestamp, a CRI sandbox by createdAt, a node file event
        by Timestamp), and the
        procedure's exit to equal its expect; a procedure with no row did not
        run, and its gates fail, as do the gates of a read-only row. Without
        --ledger the gates use the record fields only (local runs, old logs).
        A ledger line that is not a row (not JSON, no trr or procedure, bytes
        that are not UTF-8), a row whose start is after its end, and a ledger
        that is a directory fail the run with an ERROR line, and no rule is
        judged. No record can be in a window whose start is after its end: the
        clock that wrote the ledger is wrong, and each gate of the procedure
        would miss a rule that matched (2026-11-13). Its ERROR line names the
        procedure and the two times as the ledger holds them. A start equal to
        the end is a window.

    ... --expect-miss
        Negative control, for logs captured BEFORE the emulation ran: exit 1 if
        any one gate of any rule matches. Proves the baseline alone cannot pass.
        It uses the field gates only (--ledger is ignored).
        A negative control that read no record cannot fail, so it proves
        nothing. Thus each rule must have its pre-emulation log. A log that is
        not given is a failed control, and the run exits 1 (the row of its
        rule is a SKIP; --audit-log has no default in this mode, and an empty
        value of it counts as not given). An audit log that does not exist and
        an audit log that holds no audit event are failed controls too. The
        count is the number that the `Loaded N audit event(s)` line prints: the
        records of the log (see "A record of each log" above). The CRI control
        and the file control fail a CRI log without an API-scheduled sandbox and
        a file log without a kubeadm write, so an empty CRI or file log fails there;
        the line of that failure names the log and the number of records that
        it holds. The run does not fail an audit log whose records hold no
        mirror-pod create of the control-plane baseline.

    ... --report
        Report misses in the summary instead of failing on them.

    ... --json PATH
        Also write a machine-readable report (status, detail, explanation lines,
        and the results of the CRI control, the file control and, with
        --expect-miss, the control of the pre-emulation logs) to PATH. A PATH
        that the run cannot write (a directory) is an ERROR, and the run exits 1.

A MISS is explained beneath its line (sigma_explain.py), per missed emulation
pod: what the gate requires, how many events carry the marker, and the one that
came closest to the rule, item by item; or, when none does, that the emulation
may not have run. A failed CRI control shows the API-scheduled sandbox(es) the
rule matched and why, or which config.source values the sensor recorded. A
failed file control shows the kubeadm write(s) the rule matched and why, or which
Image values the sensor recorded. A failed --expect-miss shows the emulation
event(s) the rule matched and why.

The module-level PROCEDURES map gives, per (TRR, procedure letter), the rule
files whose MANIFEST entry gates that procedure with a gate of its own
(research/tools/coverage_report.py reads it). Procedure B is a read-only
demonstration by default; with TRR9003_RECONFIGURE=1 (CI, on a worker node) it
runs live, pointing the worker kubelet at a staticPodURL, so both rules also gate
B: the CRI rule on the config.source=http sandbox trr9003-url-<worker> and the
mirror-create rule on that pod's mirror create by system:node:<worker>.
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402
try:  # explanations are optional: a broken sigma_explain must never break a verdict
    import sigma_explain  # noqa: E402
except Exception as _e:  # noqa: BLE001
    sigma_explain = None
    print(f"[diag] no explanations: sigma_explain failed to import "
          f"({type(_e).__name__}: {_e})")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO, "detections", "sigma", "T1543.005")

# The emulation's own static pod (Procedure A) and its evasion variant (the gap).
INJECTED_PREFIX = "trr9003-static"
GHOST_NAME = "trr9003-ghost"
# Procedure B's live URL static pod (TRR9003_RECONFIGURE=1): the WORKER kubelet
# fetches it from a staticPodURL, so its CRI sandbox carries config.source=http and
# the kubelet names it (and its mirror pod) trr9003-url-<worker>, in namespace
# default. The worker is the kind node container (TRR9003_WORKER, as emulate.sh).
URL_PREFIX = "trr9003-url"
WORKER = os.environ.get("TRR9003_WORKER") or "trr9003-worker"
URL_POD = f"{URL_PREFIX}-{WORKER}"
B_LIVE_HINT = ("Procedure B's gates need the LIVE run (TRR9003_RECONFIGURE=1 on a kind "
               "cluster with a worker node, detections/k8s/kind-staticpod-cluster.yaml) on "
               f"the worker that TRR9003_WORKER names (here {WORKER!r}); a read-only B "
               "makes no telemetry")

# Node file sensor (C2-7): Procedure A writes the manifest through a marked copy of
# tee, so the Strategy 3 file-event rule has a live gate. The copy is in an
# exec-capable node directory (a kind node's /tmp is a noexec tmpfs). The gate is
# the marked writer creating the injected manifest; kubeadm's own writes are
# filtered by the rule itself, and the file control below checks that on the log.
TEE_IMAGE = "/usr/local/bin/trr9003-tee"
INJECTED_MANIFEST = "/etc/kubernetes/manifests/trr9003-static"
# kubeadm as a kind node runs it (kind installs it at /usr/bin/kubeadm in the node
# image, pkg/build/nodeimage/buildcontext.go). kubeadm init writes the control-plane
# manifests with os.WriteFile (cmd/kubeadm/app/util/staticpod/utils.go).
KUBEADM_IMAGE = "/usr/bin/kubeadm"
MANIFESTS_DIR = "/etc/kubernetes/manifests/"

CONFIG_SOURCE = "annotations.kubernetes.io/config.source"
TRR = "TRR9003"


def _starts(field, prefix):
    def gate(e):
        return (e.get(field) or "").startswith(prefix)
    gate.describe = f"{field} begins with {prefix!r}"  # for the MISS explanation
    return gate


def _eq(field, value):
    def gate(e):
        return e.get(field) == value
    gate.describe = f"{field} == {value!r}"
    return gate


def _code_in(*codes):
    def gate(e):
        try:
            return int(e.get("responseStatus.code")) in codes
        except (TypeError, ValueError):
            return False
    gate.describe = f"responseStatus.code in {list(codes)}"
    return gate


def _field_is(field, value):
    def gate(e):
        return e.get(field) == value
    gate.describe = f"{field} == {value!r}"
    return gate


def mark(*preds, window=None, procedure=None, time="requestReceivedTimestamp", hint=None):
    """A gate for one procedure's own record: every predicate holds. `window` is
    the (TRR, procedure) key of its ledger row, `time` the record field the window
    reads, and `procedure` the (TRR, letter) the gate proves (default: window).
    `hint` is printed under a MISS when no event carries the marker."""
    def gate(e):
        return all(p(e) for p in preds)
    gate.describe = " and ".join(p.describe for p in preds)
    gate.window = window
    gate.procedure = procedure or window
    gate.time_field = time
    gate.hint = hint
    return gate


STORED = tuple(range(200, 300))  # a mirror pod the API server stored

# Each match-gated rule: the log it reads, the procedures it covers, a note, and
# the emulation records it must match (all of them, one gate each). The
# invalid-namespace variant of Procedure A runs as its own ledger procedure (GAP).
# The Strategy 3 file-event rule is gated on the node file-event sensor ('file').
MANIFEST = [
    ("k8s_cri_static_pod_start.yml", "cri", "A/B",
     "kubelet starts a pod from a non-API source (Strategy 1 chokepoint); A from a "
     "file, B from a staticPodURL (config.source=http) when TRR9003_RECONFIGURE=1",
     [("injected static pod", mark(_starts("metadata.name", INJECTED_PREFIX),
                                   window=(TRR, "A"), time="createdAt")),
      ("invalid-namespace static pod (the audit-log gap)",
       mark(_starts("metadata.name", GHOST_NAME), window=(TRR, "GAP"),
            procedure=(TRR, "A"), time="createdAt")),
      ("URL static pod, config.source=http (Procedure B)",
       mark(_field_is("metadata.name", URL_POD), _field_is("metadata.namespace", "default"),
            _field_is(CONFIG_SOURCE, "http"), window=(TRR, "B"), time="createdAt",
            hint=B_LIVE_HINT))]),
    ("k8s_static_pod_mirror_create.yml", "audit", "A/B",
     "mirror pod create by a node identity (Strategy 2 fallback); the kubelet posts "
     "a mirror pod for a URL static pod too (IsStaticPod is true for any non-API source)",
     [("injected static pod", mark(_starts("objectRef.name", INJECTED_PREFIX),
                                   _code_in(*STORED), window=(TRR, "A"))),
      ("invalid-namespace mirror-create attempt (refused, 404)",
       mark(_starts("objectRef.name", GHOST_NAME), _code_in(404), window=(TRR, "GAP"),
            procedure=(TRR, "A"))),
      ("URL static pod mirror create (Procedure B)",
       mark(_field_is("objectRef.name", URL_POD), _field_is("objectRef.namespace", "default"),
            _field_is("user.username", f"system:node:{WORKER}"), _code_in(*STORED),
            window=(TRR, "B"), hint=B_LIVE_HINT))]),
    # Strategy 3, the node file sensor (C2-7): auditd watches the kubelet static-pod
    # directory with write permission; Procedure A drops its manifest through the
    # marked copy TEE_IMAGE, so the file-event rule fires on that write and the gate
    # tells it apart from kubeadm's own control-plane writes (which the rule's
    # filter_install excludes; the file control checks that). The window field is
    # the event's audit time (auditd_file_events.py emits `Timestamp`, UTC).
    ("linux_static_pod_manifest_write.yml", "file", "A",
     "static-pod manifest write on the node (Strategy 3 file-event rule; Procedure B "
     "serves its manifest over HTTP and writes no manifest file)",
     [("marked writer drops the injected manifest",
       mark(_eq("Image", TEE_IMAGE), _starts("TargetFilename", INJECTED_MANIFEST),
            window=(TRR, "A"), time="Timestamp"))]),
]


def _procedures(manifest, folder):
    """{(TRR, letter): sorted rule paths}: the rules whose MANIFEST entry gates that
    procedure with a gate of its own."""
    out = {}
    for fname, _source, _proc, _note, required in manifest:
        for _label, gate in required:
            key = getattr(gate, "procedure", None)
            if key:
                out.setdefault(key, set()).add(f"{folder}/{fname}")
    return {key: sorted(paths) for key, paths in sorted(out.items())}


PROCEDURES = _procedures(MANIFEST, os.path.basename(RULES_DIR))

# Control-plane static pods a kubeadm/kind node starts — the baseline both rules
# also match, by design.
CONTROL_PLANE_PREFIXES = ("kube-apiserver-", "etcd-", "kube-controller-manager-",
                          "kube-scheduler-")


# ---- what a record of each log is ---------------------------------------------
# The table of the log reader below. For each source of MANIFEST: the name of its
# log, the name of one record, the test of one JSON object, and what the test needs.
# Each test is the smallest identity that the code that reads the log needs (see
# detections/README.md, "A record of each log").


def _text(value):
    """True for a string that is not empty."""
    return isinstance(value, str) and value != ""


RECORDS = {
    "audit": {
        "log": "audit log", "record": "audit event", "a": "an audit event",
        "test": lambda doc: (doc.get("kind") == "Event"
                             and isinstance(doc.get("apiVersion"), str)
                             and doc["apiVersion"].startswith("audit.k8s.io/")),
        "needs": 'an audit event has "kind": "Event" and an apiVersion of the group '
                 "audit.k8s.io",
        "snapshot": False, "once_by": None},
    "cri": {
        "log": "CRI log", "record": "pod sandbox", "a": "a pod sandbox",
        "test": lambda doc: (_text(doc.get("id")) and isinstance(doc.get("metadata"), dict)
                             and _text(doc["metadata"].get("name"))),
        "needs": 'a sandbox has an "id" and a "metadata" object with a "name"',
        "snapshot": True, "once_by": "id"},
    "file": {
        "log": "file log", "record": "file event", "a": "a file event",
        "test": lambda doc: _text(doc.get("TargetFilename")) and _text(doc.get("Image")),
        "needs": 'a file event has a "TargetFilename" and an "Image"',
        "snapshot": False, "once_by": None},
}


# ---- the log reader ----------------------------------------------------------
# The same text in validate_k8s_detections.py, validate_staticpod_detections.py and
# validate_apiserver_detections.py; each validator stays standalone. Only the table
# RECORDS above differs: it holds the sources of the MANIFEST of the validator. The
# gate tests compare the three texts (test_validators.py, class LogReaderText).


class LogError(Exception):
    """A log that the validator cannot read: a directory, or a file that the run
    cannot open. The run names it and exits 1, and it judges no rule."""


SHOWN = 10  # the ERROR lines of one log; the problems after them are only counted
BYTE_ORDER_MARK = chr(0xFEFF)  # the text of the bytes EF BB BF of UTF-8


def _kind(value):
    """The JSON type of a value, for a message: an object, a list, a string, ..."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return {dict: "an object", list: "a list", str: "a string"}.get(type(value), "a number")


def _cannot_read(error):
    """The text of a problem of JSON that json.loads() or flatten() cannot read."""
    text = str(error).split("\n")[0]
    return (f"JSON that the validator cannot read ({type(error).__name__}: "
            + (text if len(text) <= 100 else text[:100] + "...") + ")")


def record_problem(source, doc):
    """None when `doc` (the JSON value of one line, or of one item of a CRI snapshot)
    is a record of the log of `source`; else the problem, as text."""
    if not isinstance(doc, dict):
        return f"JSON that is not an object ({_kind(doc)})"
    spec = RECORDS[source]
    if not spec["test"](doc):
        return f"a JSON object that is not {spec['a']} ({spec['needs']})"
    return None


def table_problem(source, record):
    """None when one event table of the rules (sigma_eval.EventTable) can hold the
    flat record; else the problem, as text. The test is the test of the table
    itself (sigma_eval.event_problem()): two keys of the record that differ only in
    the letter case of their ASCII letters, a key that hides a row id that the
    queries read or that no column name can hold, a value that SQLite does not hold
    as it is (an integer outside 64 bits, NaN, a lone surrogate). Two records of a
    log whose keys differ only in letter case are no problem: their keys share one
    column."""
    problem = sigma_eval.event_problem(record)
    if problem is None:
        return None
    return f"{RECORDS[source]['a']} that one event table cannot hold: {problem[1]}"


def cut_line(text, n, last):
    """True for line `n` (from 1) of a log of `last` lines when a capture can have
    cut it, so that json refuses it and it is no problem: the last line of the log,
    without a line feed at its end, that starts with "{". CI copies each log with
    `cat` while its writer adds one line for each record (the CRI sensor writes one
    snapshot on each line), and the writer writes the line feed of a line last. So
    only the last line can be cut, the cut removes its end, and its line feed is
    not there. Each other line that json refuses (NUL bytes or U+200B before a
    record, a cut line before other lines) is a problem."""
    return n == last and not text.endswith("\n") and text.strip().startswith("{")


def _not_json(text, error):
    """The text of the problem of a line that json refuses: `error` is the
    json.JSONDecodeError of the line without its blanks. The character counts from
    1, in the line as the log holds it."""
    at = error.colno + len(text) - len(text.lstrip())
    why = f"not JSON ({error.msg}, at character {at})"
    if text.strip().startswith("{"):
        why += ("; a capture can cut only the last line of a log, and a cut line has no "
                "line feed")
    return why


def read_log(path, source):
    """(records, problems): the records of the log of `source` at `path`, flattened to
    the dotted field names of the rules (sigma_eval.flatten), and the problems.

    The records are what each rule of that source is run on. The `Loaded N ...` line
    prints their number. A line of a CRI log is a `crictl pods -o json` snapshot
    ({"items": [...]}) or one sandbox; a sandbox counts once, at the first line that
    holds its id.

    A problem is a line, or an item of a snapshot, that is not a record of the log:
    bytes that are not UTF-8, the byte order mark of UTF-8 at the start of a line,
    a line that is not JSON (cut_line() tells the one exception), JSON that the
    validator cannot read (too deep, or a number that is too long), an object that
    holds one key two times (json keeps only the last value, so a record of the rule
    could hide under a second value of its key), JSON that is not an object, a JSON
    object that is not a record of the log, a record that one event table cannot hold
    (table_problem()), and a snapshot whose "items" is not a list. Each problem is
    (line, item, text): lines and items count from 1, and item is None for a line.
    A blank line, and a line that a capture cut (cut_line()), are no record and no
    problem. Raises LogError for a log that is a directory or cannot be read.
    """
    spec = RECORDS[source]
    if os.path.isdir(path):
        raise LogError(f"the {spec['log']} {path} is a directory, not a file")
    records, problems, seen = [], [], set()
    try:
        # newline="": each line keeps its end as the log holds it, so cut_line() can
        # tell a line that ends with a line feed.
        with open(path, encoding="utf-8", errors="surrogateescape", newline="") as fh:
            lines = fh.readlines()
    except OSError as e:
        raise LogError(f"the {spec['log']} {path} cannot be read ({e.strerror or e})") from None
    for n, text in enumerate(lines, 1):
        line = text.strip()
        if not line:
            continue
        bad = next((i for i, ch in enumerate(text) if 0xDC80 <= ord(ch) <= 0xDCFF), None)
        if bad is not None:
            problems.append((n, None, f"bytes that are not UTF-8 (the byte "
                                      f"0x{ord(text[bad]) - 0xdc00:02x} at character "
                                      f"{bad + 1} of the line)"))
            continue
        # json refuses a line that starts with the byte order mark: the mark is a
        # problem at the start of each line (two logs joined hold it at a later line
        # too), with a text that names it.
        if line.startswith(BYTE_ORDER_MARK):
            problems.append((n, None, "the line starts with the byte order mark of "
                                      "UTF-8 (EF BB BF)"))
            continue
        try:
            doc = json.loads(line, object_pairs_hook=sigma_eval.pairs)
        except json.JSONDecodeError as e:
            if not cut_line(text, n, len(lines)):
                problems.append((n, None, _not_json(text, e)))
            continue
        except (ValueError, RecursionError) as e:
            problems.append((n, None, _cannot_read(e)))
            continue
        key = sigma_eval.key_twice(doc)
        if key is not None:
            problems.append((n, None, sigma_eval.twice_text(key)))
            continue
        items = [(None, doc)]
        if spec["snapshot"] and isinstance(doc, dict) and "items" in doc:
            if not isinstance(doc["items"], list):
                problems.append((n, None, 'a snapshot whose "items" is not a list '
                                          f"({_kind(doc['items'])})"))
                continue
            items = list(enumerate(doc["items"], 1))
        for item, value in items:
            why = record_problem(source, value)
            if why is None:
                try:
                    record = sigma_eval.flatten(value)
                except RecursionError as e:
                    why = _cannot_read(e)
                else:
                    why = table_problem(source, record)
            if why is not None:
                problems.append((n, item, why))
                continue
            if spec["once_by"]:
                if value[spec["once_by"]] in seen:
                    continue
                seen.add(value[spec["once_by"]])
            records.append(record)
    return records, problems


def show_log_problems(source, path, problems, report):
    """Print one ERROR line for each problem of one log (at most SHOWN, then the
    number of the others), and add the log to report["log_problems"] (--json, with
    the same limit). Returns the number of lines of the log that hold a problem."""
    if not problems:
        return 0
    name = RECORDS[source]["log"]
    texts = [f"line {n}" + (f", item {item} of the snapshot" if item else "") + f": {why}"
             for n, item, why in problems]
    for text in texts[:SHOWN]:
        print(f"ERROR: the {name} {path}, {text}")
    if len(texts) > SHOWN:
        print(f"ERROR: the {name} {path}: {len(texts) - SHOWN} more problem(s), not shown")
    lines = len({n for n, _, _ in problems})
    report.setdefault("log_problems", []).append(
        {"log": name, "path": path, "lines": lines, "problems": len(texts),
         "shown": texts[:SHOWN]})
    return lines


def log_problems_failed(lines):
    """The verdict of a run whose logs hold lines that are not records: no rule is
    judged on such a log."""
    return (f"FAILED: {lines} line(s) of the logs are not records of their log (see the "
            "ERROR lines above). No rule is judged on a log that holds such a line.")


# ---- end of the log reader ---------------------------------------------------


def nonblank_lines(path):
    """The number of lines of a log that are not blank. The message about a log
    without a record gives it: 0 records from 0 lines is a capture that recorded
    nothing, and 0 records from N lines is a capture that did not parse."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return sum(1 for line in fh if line.strip())


# The audit log of a strict run that names none (the path where the workflow and
# detections/README.md put the log of a live run). --expect-miss has no default:
# this log is the one that holds the emulation.
DEFAULT_AUDIT_LOG = "/tmp/kube-apiserver-audit.log"


# --expect-miss: the control of the pre-emulation logs (report_inputs()), in --json.
INPUTS_CONTROL = "each rule has its pre-emulation log, and the audit log holds a record"


def report_inputs(args, logs, only_failures=False):
    """--expect-miss: each rule had a pre-emulation log to run on, and the audit log
    holds a record. A negative control that read no record cannot fail, so it proves
    nothing. Returns a list of control failures (empty when the control holds).

    The audit log must be given, must exist and must hold one or more audit events.
    The count is what read_log() returned: the records that the audit rule is run
    on. The CRI log and the file log must be given (one that is given and does not
    exist ended the run before this point). report_cri() and report_file() fail a CRI
    or file log that holds no baseline record, so this control does not count them.
    only_failures: print the failures only (for a run that a line of a log that is
    not a record ends: the control does not hold, and it has no line that says so).
    That run does not get to report_cri() and report_file(), so this control then
    also gives the line of their control for a CRI log or a file log that holds no
    record.
    """
    failures = []
    if not args.audit_log:
        failures.append("no pre-emulation audit log was given (--audit-log), so the negative "
                        "control read no audit event and proves nothing for the audit rule")
    elif "audit" not in logs:
        failures.append(f"the pre-emulation audit log {args.audit_log} was not found, so the "
                        "negative control read no audit event and proves nothing for the "
                        "audit rule")
    elif not logs["audit"]:
        failures.append(f"no audit event in the pre-emulation audit log {args.audit_log} "
                        f"(0 records read from {nonblank_lines(args.audit_log)} non-blank "
                        "line(s)), so the negative control proves nothing for the audit rule")
    for source, name, option in (("cri", "CRI", "--cri-log"), ("file", "file", "--file-log")):
        if source not in logs:
            failures.append(f"no pre-emulation {name} log was given ({option}), so the "
                            f"negative control read no record for the {name} rule and "
                            "proves nothing for it")
        elif only_failures and not logs[source]:
            failures.append(no_api_sandbox(args.cri_log, 0) if source == "cri"
                            else no_kubeadm_write(args.file_log, 0))
    if only_failures and not failures:
        return failures
    print("\nPre-emulation logs — a negative control that read no record cannot fail:")
    if failures:
        for f in failures:
            print(f"  CONTROL FAILED: {f}")
    else:
        print(f"  control held: each rule has its log, and the audit log holds "
              f"{len(logs['audit'])} audit event(s).")
    return failures


def dedup_by_audit_id(matches):
    seen, out = set(), []
    for e in matches:
        aid = e.get("auditID")
        if aid and aid in seen:
            continue
        if aid:
            seen.add(aid)
        out.append(e)
    return out


def node_created_pods(events):
    """(name, namespace, user, code) for each create-pods by a system:node identity.

    `code` is responseStatus.code: 2xx for a mirror pod that was stored, non-2xx
    for a mirror-create the API server rejected (e.g. an invalid-namespace
    evasion static pod). The create attempt is audited either way.
    """
    out = []
    for e in events:
        user = e.get("user.username") or ""
        if (e.get("verb") == "create" and e.get("objectRef.resource") == "pods"
                and "system:node:" in str(user)):
            out.append((e.get("objectRef.name"), e.get("objectRef.namespace"),
                        user, e.get("responseStatus.code")))
    return out


def classify(name):
    name = name or ""
    if name.startswith(INJECTED_PREFIX):
        return "injected"
    if name.startswith(GHOST_NAME):
        return "ghost"
    if name.startswith(URL_PREFIX):
        return "url"
    if name.startswith(CONTROL_PLANE_PREFIXES):
        return "baseline"
    return "other"


def report_audit(events):
    """Separate the emulation's mirror-pod creates from the control-plane baseline."""
    created = node_created_pods(events)
    kinds = {k: [p for p in created if classify(p[0]) == k]
             for k in ("baseline", "injected", "ghost", "url", "other")}
    print(f"\nAudit log — node-created pods (mirror-pod creates) seen: {len(created)}")
    if kinds["baseline"]:
        print(f"  baseline (control-plane static pods): "
              f"{', '.join(sorted({p[0] for p in kinds['baseline']}))}")
    for name, ns, user, code in kinds["injected"]:
        print(f"  INJECTED (Procedure A): {name} in ns={ns} by {user} (code={code})")
    if not kinds["injected"]:
        print("  note: no 'trr9003-static-*' mirror pod seen.")
    for name, ns, user, code in kinds["url"]:
        print(f"  URL static pod (Procedure B): {name} in ns={ns} by {user} (code={code})")
    if kinds["other"]:
        print(f"  other node-created pods (triage): "
              f"{', '.join(sorted(p[0] or '?' for p in kinds['other']))}")
    ghost = kinds["ghost"]
    if ghost:
        codes = sorted({str(p[3]) for p in ghost})
        print(f"  EVASION ({GHOST_NAME}): mirror-create attempted, responseStatus "
              f"code(s) {', '.join(codes)}. A non-2xx create means the API server "
              "rejected the mirror pod (namespace not found): no pod object, but "
              "the attempt is audited and the Strategy 2 rule matches it. The pod "
              "RUNNING is not in the audit log; the CRI rule sees that.")
    else:
        print(f"  note: no '{GHOST_NAME}' mirror-create seen.")


def no_api_sandbox(path, sandboxes):
    """The failure of the CRI control for a CRI log (`path`) of `sandboxes` sandboxes
    of which none is API-scheduled: the control proves nothing."""
    return ("no API-scheduled sandbox (config.source=api) in the CRI "
            "log, so the false-positive control proves nothing; does "
            "the sensor record carry the pod annotations? (the CRI log "
            f"{path} holds {sandboxes} pod sandbox(es))")


def no_kubeadm_write(path, events):
    """The failure of the file control for a file log (`path`) of `events` file events
    of which none is a kubeadm manifest write: the control proves nothing."""
    return (f"no {KUBEADM_IMAGE} write under {MANIFESTS_DIR} in the file log, so "
            "the false-positive control proves nothing; was the watch added "
            f"before the cluster was created? (the file log {path} holds "
            f"{events} file event(s))")


def report_cri(sandboxes, cri_hits, path):
    """The static sandboxes the sensor saw, and the API-pod false-positive control.

    Returns a list of control failures (empty when the control holds). The failure
    for a log without an API-scheduled sandbox names the log (`path`) and the number
    of sandboxes that it holds.
    """
    static = [s for s in sandboxes if s.get(CONFIG_SOURCE) in ("file", "http")]
    api = [s for s in sandboxes if s.get(CONFIG_SOURCE) == "api"]
    print(f"\nNode runtime sensor — pod sandboxes seen: {len(sandboxes)} "
          f"({len(static)} from file/http, {len(api)} from the API server)")
    for kind, label in (("baseline", "baseline (control-plane static pods)"),
                        ("injected", "INJECTED (Procedure A)"),
                        ("ghost", "EVASION (invalid namespace, no API object)"),
                        ("url", "URL static pod (Procedure B, config.source=http)"),
                        ("other", "other static pods (triage)")):
        names = sorted({f"{s.get('metadata.name')} in ns={s.get('metadata.namespace')}"
                        for s in static if classify(s.get("metadata.name")) == kind})
        if names:
            print(f"  {label}: {', '.join(names)}")

    failures = []
    api_hits = [s for s in cri_hits if s.get(CONFIG_SOURCE) == "api"]
    if not api:
        failures.append(no_api_sandbox(path, len(sandboxes)))
    if api_hits:
        failures.append("the CRI rule matched API-scheduled sandbox(es): "
                        + ", ".join(sorted(s.get("metadata.name") or "?" for s in api_hits)))
    if failures:
        for f in failures:
            print(f"  CONTROL FAILED: {f}")
    else:
        print(f"  control held: the CRI rule matched none of the {len(api)} "
              "API-scheduled sandbox(es).")
    return failures


def _kubeadm_writes(events):
    """kubeadm's control-plane manifest writes in a file log (Image, TargetFilename)."""
    return [e for e in events if e.get("Image") == KUBEADM_IMAGE
            and str(e.get("TargetFilename") or "").startswith(MANIFESTS_DIR)]


def report_file(events, file_hits, path):
    """The file-event rule's false-positive control on kubeadm's own writes.

    CI adds the static-pod directory watch before `kind create cluster`, so kubeadm
    init's manifest writes (etcd, kube-apiserver, ...) are in the file log. The rule
    must match none of them (filter_install), and there must be some, so the control
    tests the rule on real bootstrap writes and the sensor's exe spelling. Returns a
    list of control failures (empty when the control holds). The failure for a log
    without such a write names the log (`path`) and the number of file events that
    it holds.
    """
    boot = _kubeadm_writes(events)
    print(f"\nNode file-event sensor — file events seen: {len(events)} "
          f"({len(boot)} kubeadm control-plane manifest write(s))")
    names = sorted({str(e.get("TargetFilename")) for e in boot})
    if names:
        print(f"  baseline (kubeadm): {', '.join(names)}")
    failures = []
    boot_ids = {id(e) for e in boot}
    boot_hits = [e for e in file_hits if id(e) in boot_ids]
    if not boot:
        failures.append(no_kubeadm_write(path, len(events)))
    if boot_hits:
        failures.append("the file-event rule matched kubeadm's control-plane manifest "
                        "write(s): " + ", ".join(sorted(str(e.get("TargetFilename"))
                                                        for e in boot_hits)))
    if failures:
        for f in failures:
            print(f"  CONTROL FAILED: {f}")
    else:
        print(f"  control held: the file-event rule matched none of the {len(boot)} "
              "kubeadm control-plane manifest write(s).")
    return failures


# ---- failure explanations (sigma_explain) --------------------------------
# The same helpers as validate_apiserver_detections.py; each validator stays standalone.

TAG = "trr9003"  # every emulation pod name carries it; used when no event passes a gate


def summary(e):
    """One line naming an audit event, a CRI pod sandbox, or a node file event."""
    if "verb" not in e and "TargetFilename" in e:
        return (f"Image={e.get('Image')} TargetFilename={e.get('TargetFilename')} "
                f"EventType={e.get('EventType')} pid={e.get('ProcessId')}")
    if "verb" not in e and "metadata.name" in e:
        return (f"pod={e.get('metadata.name')} ns={e.get('metadata.namespace')} "
                f"config.source={e.get(CONFIG_SOURCE)}")
    return (f"verb={e.get('verb')} resource={e.get('objectRef.resource')} "
            f"name={e.get('objectRef.name')} ns={e.get('objectRef.namespace')} "
            f"user={e.get('user.username')}"
            + (f" code={e['responseStatus.code']}" if e.get("responseStatus.code") else ""))


def labeller(events):
    index = {id(e): i for i, e in enumerate(events)}
    return lambda e: f"#{index.get(id(e), '?')} [{summary(e)}]"


def absent_hint(rule, events):
    """A line naming rule fields that no event carries (a sensor or audit-level gap)."""
    fields = dict.fromkeys(f for a in rule.positive_atoms() for f in rule.fields(a))
    absent = [f for f in fields if all(e.get(f) is None for e in events)]
    if not absent:
        return []
    return [f"rule field(s) no event in the log carries: {', '.join(absent)}; the sensor or "
            "audit policy does not record them, or the field is named differently"]


def explain_gated_miss(rule_path, events, gate, matched):
    """Why a required emulation pod was not matched: the gate, then its closest event."""
    rule = sigma_explain.load(rule_path).stripped()  # no null guards or copies
    label = labeller(events)
    marked = [i for i, e in enumerate(events) if gate(e)]
    lines = [f"gate: {getattr(gate, 'describe', 'see its MANIFEST entry')}"]
    candidates, where = marked, "the marked event(s)"
    if marked:
        lines.append(f"{len(marked)} event(s) carry the marker and the rule matches none of them")
    else:
        lines.append("NO event carries the marker: the emulation may not have run (or not "
                     "on the node the sensor watches), or it named the pod differently")
        if getattr(gate, "hint", None):
            lines.append(gate.hint)
        candidates = [i for i, e in enumerate(events) if any(TAG in str(v) for v in e.values())]
        where = f"the event(s) mentioning {TAG!r}"
        hit = {id(e) for e in matched}
        if candidates:
            lines.append(f"{len(candidates)} event(s) mention {TAG!r} but fail the gate, e.g.:")
            lines.extend(f"  {label(events[i])}" for i in candidates[:3])
            fired = sum(1 for i in candidates if id(events[i]) in hit)
            if fired:
                lines.append(f"the rule DOES match {fired} of them: the rule works, the gate "
                             "does not recognise the pod as the emulation's")
        elif matched:
            lines.append(f"no event mentions {TAG!r} at all, while the rule matches "
                         f"{len(matched)} other event(s) (e.g. the control-plane baseline): "
                         "the emulation's own pods are missing")
        else:
            lines.append(f"no event mentions {TAG!r} at all")
            candidates, where = None, "the events of the whole log"
    lines += absent_hint(rule, events)
    if candidates or candidates is None:
        lines.append(f"per block over {where}, then the closest event, item by item:")
        lines += sigma_explain.explain_miss(rule, events, k=1, candidates=candidates,
                                            label=label)
    return lines


def explain_unexpected(rule_path, events, ours):
    """--expect-miss failed: the emulation event(s) the rule matched, and why it fired."""
    rule = sigma_explain.load(rule_path)
    label = labeller(events)
    lines = [f"the pre-emulation log already holds {len(ours)} emulation match(es); a log "
             f"captured before the emulation should hold no {TAG!r} record (captured late, or "
             "a manifest left on the node by an earlier run?):"]
    for e in ours[:3]:
        lines.append(f"  {label(e)}")
        lines.extend("  " + ln for ln in sigma_explain.explain_hit(rule, e))
    if len(ours) > 3:
        lines.append(f"  ... and {len(ours) - 3} more")
    return lines


def explain_cri_control(rule_path, sandboxes, cri_hits):
    """Why the CRI false-positive control failed."""
    lines = []
    if not any(s.get(CONFIG_SOURCE) == "api" for s in sandboxes):
        seen = {}
        for s in sandboxes:
            value = str(s.get(CONFIG_SOURCE, "<absent>"))
            seen[value] = seen.get(value, 0) + 1
        lines.append(f"{CONFIG_SOURCE} values across the {len(sandboxes)} sandbox(es): "
                     + (", ".join(f"{v} x{n}" for v, n in sorted(seen.items())) or "none"))
    api_hits = [s for s in cri_hits if s.get(CONFIG_SOURCE) == "api"]
    if api_hits:
        rule = sigma_explain.load(rule_path)
        label = labeller(sandboxes)
        lines.append("an API-scheduled pod must never look like a static pod; the rule "
                     "matched:")
        for s in api_hits[:3]:
            lines.append(f"  sandbox {label(s)}")
            lines.extend("  " + ln for ln in sigma_explain.explain_hit(rule, s))
        if len(api_hits) > 3:
            lines.append(f"  ... and {len(api_hits) - 3} more")
    return lines


def explain_file_control(rule_path, events, file_hits):
    """Why the file-event false-positive control failed."""
    lines = []
    boot = _kubeadm_writes(events)
    if not boot:
        seen = {}
        for e in events:
            value = str(e.get("Image", "<absent>"))
            seen[value] = seen.get(value, 0) + 1
        lines.append(f"Image values across the {len(events)} file event(s): "
                     + (", ".join(f"{v} x{n}" for v, n in sorted(seen.items())) or "none"))
    boot_ids = {id(e) for e in boot}
    boot_hits = [e for e in file_hits if id(e) in boot_ids]
    if boot_hits:
        rule = sigma_explain.load(rule_path)
        label = labeller(events)
        lines.append("kubeadm's own bootstrap write must never look like a dropped manifest; "
                     "the rule matched:")
        for e in boot_hits[:3]:
            lines.append(f"  {label(e)}")
            lines.extend("  " + ln for ln in sigma_explain.explain_hit(rule, e))
        if len(boot_hits) > 3:
            lines.append(f"  ... and {len(boot_hits) - 3} more")
    return lines


def explained(fn, *args):
    """Run an explanation helper; an explanation must never break the gate."""
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001
        return [f"(no explanation: {type(e).__name__}: {e})"]


def write_json(path, report):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")


# ---- the emulation ledger (procedure windows) ------------------------------
# The same contract as validate_apiserver_detections.py and
# validate_k8s_detections.py; each validator stays standalone. Each emulation run
# appends one JSON line per procedure:
#   {"trr": "TRR9003", "procedure": "A", "start": "...Z", "end": "...Z",
#    "exit": 0, "expect": 0}
# plus "mode": "read-only" on a read-only Procedure B row (its gates then fail).
# start and end are UTC ISO 8601 with microseconds. The kind node is a container
# on the runner, so the audit timestamps, the CRI createdAt and the ledger read
# the same kernel clock.


def _ts(value):
    """A UTC datetime from an ISO 8601 timestamp (any number of fraction digits,
    'Z' or an offset) or from a CRI createdAt (nanoseconds since the epoch, an
    integer or a digit string); None when it does not parse."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    text = str(value).strip()
    if text.isdigit():
        sec, nsec = divmod(int(text), 10**9)
        return datetime.fromtimestamp(sec, tz=timezone.utc) + timedelta(microseconds=nsec // 1000)
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    head, dot, rest = text.partition(".")
    if dot:  # fromisoformat takes at most 6 fraction digits on older Pythons
        digits = ""
        for ch in rest:
            if not ch.isdigit():
                break
            digits += ch
        text = f"{head}.{digits[:6].ljust(6, '0')}{rest[len(digits):]}"
    try:
        t = datetime.fromisoformat(text)
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc)


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ledger_key(trr, procedure):
    """('TRR9003', 'A') from 'TRR9003'/'9003' and 'A'/'a'."""
    t = str(trr or "").strip().upper()
    if t.isdigit():
        t = "TRR" + t
    return (t, str(procedure or "").strip().upper())


def load_ledger(path):
    """({(TRR, PROCEDURE): row}, [problem, ...]); a later row for the same procedure wins
    (a re-run). A line that is not a JSON object with trr and procedure is a problem, and
    the caller fails the run on any problem, as validate_apiserver_detections.py does: a
    truncated or corrupt ledger must not pass quietly. A line with bytes that are not
    UTF-8 is a problem, and so is a row whose start is after its end (the clock that
    wrote the ledger is wrong). An OSError of open() goes to the caller."""
    rows, problems = {}, []
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        for n, text in enumerate(fh, 1):
            line = text.strip()
            if not line:
                continue
            bad = next((i for i, ch in enumerate(text) if 0xDC80 <= ord(ch) <= 0xDCFF), None)
            if bad is not None:
                problems.append(f"line {n}: bytes that are not UTF-8 (the byte "
                                f"0x{ord(text[bad]) - 0xdc00:02x} at character {bad + 1} of the "
                                "line)")
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                problems.append(f"line {n}: not valid JSON ({e.msg}): {line[:80]!r}")
                continue
            if not isinstance(row, dict) or not row.get("trr") or not row.get("procedure"):
                problems.append(f"line {n}: not a ledger row (needs trr and procedure): "
                                f"{line[:80]!r}")
                continue
            key = _ledger_key(row.get("trr"), row.get("procedure"))
            start, end = _ts(row.get("start")), _ts(row.get("end"))
            if start is not None and end is not None and start > end:
                # A window of no time at all is a window (start equal to end); a window
                # whose start is after its end holds no record, so each gate of the
                # procedure would miss a rule that matched (2026-11-13).
                problems.append(f"line {n} ({key[0]}.{key[1]}): the window of the procedure "
                                f"starts after it ends (start {row.get('start')!r}, end "
                                f"{row.get('end')!r}), so no record can be in it: the clock "
                                "that wrote the ledger is wrong")
                continue
            rows[key] = {
                "start": start, "end": end,
                "exit": row.get("exit"), "expect": row.get("expect", 0),
                "mode": row.get("mode")}
    return rows, problems


def _same_int(a, b):
    try:
        return int(a) == int(b)
    except (TypeError, ValueError):
        return False


def ledger_state(ledger, key):
    """(ok, text): whether the procedure's row lets a record count, and why not."""
    row = ledger.get(key)
    if row is None:
        return False, "no ledger row: the procedure did not run"
    if row["start"] is None or row["end"] is None:
        return False, "the ledger row has no readable start or end"
    if not _same_int(row["exit"], row["expect"]):
        return False, f"the procedure exited {row['exit']}, expected {row['expect']}"
    if row.get("mode") == "read-only":
        return False, ("the procedure ran read-only (TRR9003_RECONFIGURE unset), so it made "
                       "no telemetry; a strict run needs the live B: TRR9003_RECONFIGURE=1 "
                       "on a kind cluster with a worker node")
    return True, f"window [{_iso(row['start'])}, {_iso(row['end'])}]"


def windowed(gate, ledger):
    """The gate, also bound to its procedure's ledger row when a ledger is given."""
    key = getattr(gate, "window", None)
    if ledger is None or key is None:
        return gate
    ok, state = ledger_state(ledger, key)
    row = ledger.get(key)
    field = getattr(gate, "time_field", "requestReceivedTimestamp")

    def bound(e):
        if not ok:
            return False
        t = _ts(e.get(field))
        return t is not None and row["start"] <= t <= row["end"] and gate(e)
    bound.describe = (f"{gate.describe}; ledger {key[0]}.{key[1]}: "
                      + (f"{field} in the {state}" if ok else state))
    bound.window = key
    bound.procedure = getattr(gate, "procedure", key)
    bound.ledger = state
    bound.hint = getattr(gate, "hint", None)
    return bound


def main():
    ap = argparse.ArgumentParser(description="Validate TRR9003 static-pod detections.")
    ap.add_argument("--audit-log",
                    help="Path to the API server audit log (JSON lines). A strict run "
                         f"without it reads {DEFAULT_AUDIT_LOG}; --expect-miss needs it.")
    ap.add_argument("--cri-log",
                    help="Path to the node runtime sensor log (crictl pods snapshots).")
    ap.add_argument("--file-log",
                    help="Path to the node file-event sensor log (linux/file_event JSON "
                         "lines, as detections/k8s/auditd_file_events.py writes them).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compile rules only; no cluster or log needed.")
    ap.add_argument("--expect-miss", action="store_true",
                    help="Negative control: fail if any rule passes, if a log is not "
                         "given, or if the audit log is missing or holds no audit event.")
    ap.add_argument("--report", action="store_true",
                    help="Report misses instead of failing on them.")
    ap.add_argument("--json", metavar="PATH",
                    help="Also write a machine-readable report (results + explanations).")
    ap.add_argument("--ledger", metavar="PATH",
                    help="Emulation ledger (JSON lines, one per procedure): bind each gate "
                         "to its procedure's window and exit status.")
    args = ap.parse_args()
    report = {"validator": "staticpod",
              "mode": "dry-run" if args.dry_run else
              "expect-miss" if args.expect_miss else "validate",
              "results": [], "procedures": {}, "controls": []}
    code = validate(args, report)
    if args.json:
        report["exit"] = code
        try:
            write_json(args.json, report)
        except OSError as e:
            # A --json path that is a directory, or that the run cannot write: the
            # report that the caller asked for does not exist, so the run fails.
            print(f"ERROR: the --json report cannot be written to {args.json} "
                  f"({e.strerror or e}).")
            return code or 1
    return code


def validate(args, report):
    """The validation run behind main(); fills `report` for --json."""
    results = report["results"]
    # Compile the rules first; a compile error always fails.
    queries = {}
    parse_errors = 0
    for fname, source, proc, note, _ in MANIFEST:
        try:
            queries[fname] = sigma_eval.compile_rule(os.path.join(RULES_DIR, fname))
            print(f"OK (compile)  {fname}  [{proc}, {source}] {note}")
        except Exception as e:  # noqa: BLE001
            parse_errors += 1
            print(f"ERROR compile {fname}: {e}")
            results.append({"rule": fname, "source": source, "status": "ERROR",
                            "detail": f"compile: {e}", "explanation": []})
    # Compile any other rule in the folder too (none today: all three T1543.005
    # rules are match-gated above, one per sensor).
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
        if os.path.basename(path) not in queries:
            try:
                sigma_eval.compile_rule(path)
                print(f"OK (compile)  {os.path.basename(path)}  "
                      f"not match-gated here")
            except Exception as e:  # noqa: BLE001
                parse_errors += 1
                print(f"ERROR compile {os.path.basename(path)}: {e}")
                results.append({"rule": os.path.basename(path), "status": "ERROR",
                                "detail": f"compile: {e}", "explanation": []})

    if args.dry_run:
        results.extend({"rule": fname, "status": "OK", "detail": "compiles",
                        "explanation": []} for fname in queries)
        print()
        if parse_errors:
            print(f"Dry run FAILED: {parse_errors} compile error(s).")
            return 1
        print(f"Dry run OK: {len(queries)} match-gated rule(s) compile with pySigma.")
        return 0

    logs = {}
    # A negative control must name the log that was captured before the emulation:
    # the default is the log of a live run, and an empty value counts as a log that
    # is not given. A strict run takes the default only when the option is absent:
    # an empty value (--audit-log '') is then a log that does not exist, as it was
    # before the negative control got its checks.
    if args.expect_miss:
        audit_log = args.audit_log or None
    else:
        audit_log = DEFAULT_AUDIT_LOG if args.audit_log is None else args.audit_log
    # A log that is a directory, or that the run cannot open, ends the run at once.
    # A line that is not a record of its log ends it after the three logs are read:
    # no rule is judged on such a log (a strict run, --report and --expect-miss).
    bad = 0
    try:
        if audit_log is None:
            print("\nNo audit log given (--audit-log).")
        elif os.path.exists(audit_log):
            print()
            logs["audit"], problems = read_log(audit_log, "audit")
            print(f"Loaded {len(logs['audit'])} audit event(s) from {audit_log}")
            bad += show_log_problems("audit", audit_log, problems, report)
        else:
            print(f"\nAudit log not found: {audit_log}")
        if args.cri_log:
            if not os.path.exists(args.cri_log):
                print(f"ERROR: CRI sensor log not found: {args.cri_log}")
                return 1
            logs["cri"], problems = read_log(args.cri_log, "cri")
            print(f"Loaded {len(logs['cri'])} pod sandbox(es) from {args.cri_log}")
            bad += show_log_problems("cri", args.cri_log, problems, report)
        if args.file_log:
            if not os.path.exists(args.file_log):
                print(f"ERROR: node file-event log not found: {args.file_log}")
                return 1
            logs["file"], problems = read_log(args.file_log, "file")
            print(f"Loaded {len(logs['file'])} file event(s) from {args.file_log}")
            bad += show_log_problems("file", args.file_log, problems, report)
    except LogError as e:
        print(f"ERROR: {e}.")
        if args.expect_miss:
            report["controls"].append({"control": INPUTS_CONTROL, "status": "FAILED",
                                       "detail": str(e), "explanation": []})
        return 1
    if bad:
        if args.expect_miss:
            # The lines of the control of the pre-emulation logs that failed (a log
            # that is not given, an audit log without a record, and a CRI log or a
            # file log without a record, with the line of its control), and its
            # --json entry.
            failures = report_inputs(args, logs, only_failures=True)
            report["controls"].append({
                "control": INPUTS_CONTROL, "status": "FAILED",
                "detail": "; ".join(failures + [f"{bad} line(s) of the pre-emulation logs "
                                                "are not records of their log"]),
                "explanation": []})
        print(f"\n{log_problems_failed(bad)}")
        return 1
    if not logs and not args.expect_miss:
        print("SKIP: no log to validate against (exit 0).")
        return 0 if not parse_errors else 1
    ledger = None
    if args.ledger and args.expect_miss:
        print("--ledger is ignored with --expect-miss: the negative control uses the field "
              "gates only.")
    elif args.ledger:
        if not os.path.exists(args.ledger):
            print(f"ERROR: ledger not found: {args.ledger} (the emulation wrote no ledger "
                  "row; did it run, with DETENG_LEDGER set?)")
            return 1
        if os.path.isdir(args.ledger):
            print(f"ERROR: ledger {args.ledger} is a directory, not a file.")
            return 1
        try:
            ledger, problems = load_ledger(args.ledger)
        except OSError as e:
            print(f"ERROR: ledger {args.ledger} cannot be read ({e.strerror or e}).")
            return 1
        if problems:
            for p in problems:
                print(f"ERROR: ledger {args.ledger} {p}")
            return 1
        mine = sorted(k for k in ledger if k[0] == TRR)
        print(f"Loaded {len(ledger)} ledger row(s) from {args.ledger}; {TRR}: "
              + (", ".join(f"{k[1]} exit {ledger[k]['exit']}" for k in mine) or "none"))
    print()

    passes = misses = skipped = 0
    hits_by_source = {}
    for fname, source, proc, note, required in MANIFEST:
        if fname not in queries:
            continue
        if source not in logs:
            skipped += 1
            print(f"SKIP  [{proc}] {fname}: no {source} log given")
            results.append({"rule": fname, "source": source, "status": "SKIP",
                            "detail": f"no {source} log given", "explanation": []})
            continue
        matched = [hit[0] for hit in sigma_eval.evaluate(queries[fname], logs[source])]
        if source == "audit":
            matched = dedup_by_audit_id(matched)
        hits_by_source[source] = matched
        preds = [(label, windowed(pred, ledger)) for label, pred in required]
        found = [(label, [e for e in matched if pred(e)]) for label, pred in preds]
        ours = len({id(e) for _, events in found for e in events})
        other = len(matched) - ours
        rule_path = os.path.join(RULES_DIR, fname)
        every, some = all(events for _, events in found), any(events for _, events in found)
        passed = some if args.expect_miss else every
        explanation = []
        # A file event is a record of the emulation's write, not a pod.
        what, base = (("emulation record", "") if source == "file"
                      else ("emulation pod", ", e.g. control-plane baseline"))
        if passed:
            passes += 1
            detail = (f"matched every {what} (+{other} other{base})"
                      if every else f"matched an {what} (+{other} other)")
            print(f"PASS  [{proc}] {fname}: {detail}")
        else:
            misses += 1
            detail = (f"missed an {what}"
                      + (f" ({other} baseline/unrelated match(es) ignored)" if other else ""))
            print(f"MISS  [{proc}] {fname}: {detail}")
        for (label, events), (_, pred) in zip(found, preds):
            mark_ = "ok  " if events else "MISS"
            state = getattr(pred, "ledger", None)
            print(f"        {mark_} {label}: {len(events)} match(es)"
                  + (f" [ledger: {state}]" if state and not events else ""))
            key = getattr(pred, "procedure", None)
            if key:
                entry = report["procedures"].setdefault(f"{key[0]}.{key[1]}",
                                                        {"status": "ok", "gates": {}})
                entry["gates"][f"{fname}: {label}"] = len(events)
                if not events:
                    entry["status"] = "MISS"
            if not events and not args.expect_miss:
                lines = [f"{label}:"] + ["  " + ln for ln in explained(
                    explain_gated_miss, rule_path, logs[source], pred, matched)]
                explanation += lines
                for line in lines[1:]:
                    print("          " + line)
        if passed and args.expect_miss:
            explanation = explained(explain_unexpected, rule_path, logs[source],
                                    [e for _, events in found for e in events])
            for line in explanation:
                print("        " + line)
        if source == "file" and args.expect_miss:
            # Say what the file gate saw: the gate selects the marked writer only, so
            # the file control (below) is what tests the rule on kubeadm's writes.
            print(f"        file log: {len(logs[source])} file event(s), the rule matches "
                  f"{len(matched)}")
        results.append({"rule": fname, "source": source, "status": "PASS" if passed else "MISS",
                        "detail": detail,
                        "pods": {label: len(events) for label, events in found},
                        "explanation": explanation})

    controls = []
    file_controls = []
    input_controls = []
    if "audit" in logs:
        report_audit(logs["audit"])
    if args.expect_miss:
        input_controls = report_inputs(args, logs)
        report["controls"].append({"control": INPUTS_CONTROL,
                                   "status": "FAILED" if input_controls else "held",
                                   "detail": "; ".join(input_controls), "explanation": []})
    if "cri" in logs:
        controls = report_cri(logs["cri"], hits_by_source.get("cri", []), args.cri_log)
        cri_rule = next((os.path.join(RULES_DIR, m[0]) for m in MANIFEST if m[1] == "cri"),
                        None)
        lines = explained(explain_cri_control, cri_rule, logs["cri"],
                          hits_by_source.get("cri", [])) if controls else []
        for line in lines:
            print("    " + line)
        report["controls"].append({"control": "the CRI rule matches no API-scheduled sandbox",
                                   "status": "FAILED" if controls else "held",
                                   "detail": "; ".join(controls), "explanation": lines})
    if "file" in logs:
        file_rule = next((os.path.join(RULES_DIR, m[0]) for m in MANIFEST if m[1] == "file"),
                         None)
        file_controls = report_file(logs["file"], hits_by_source.get("file", []),
                                    args.file_log)
        lines = explained(explain_file_control, file_rule, logs["file"],
                          hits_by_source.get("file", [])) if file_controls else []
        for line in lines:
            print("    " + line)
        report["controls"].append({"control": "the file-event rule matches no kubeadm "
                                              "control-plane manifest write",
                                   "status": "FAILED" if file_controls else "held",
                                   "detail": "; ".join(file_controls), "explanation": lines})
    controls = input_controls + controls + file_controls

    print()
    if parse_errors:
        print(f"FAILED: {parse_errors} compile error(s).")
        return 1
    if controls:
        print(f"FAILED: {len(controls)} control(s) failed.")
        return 1
    if args.expect_miss:
        if passes:
            print(f"NEGATIVE CONTROL FAILED: {passes} rule(s) passed on logs "
                  "captured before the emulation ran (a gate matched).")
            return 1
        print("Negative control held: the baseline alone does not pass any rule.")
        return 0
    if misses and not args.report:
        print(f"FAILED: {misses} rule(s) missed an emulation pod. "
              f"(Use --report to treat misses as non-fatal.)")
        return 1
    if misses:
        print(f"Reported {misses} miss(es); not gated (--report).")
        return 0
    if skipped:
        print(f"The rule(s) with a log fired on the emulated telemetry; {skipped} "
              "rule(s) skipped for lack of a log.")
        return 0
    print("All TRR9003 match-gated detections fired on the emulated telemetry, "
          "including the invalid-namespace pod the audit log cannot see running"
          + (", every record inside its procedure's ledger window." if ledger is not None
             else " (field gates only, no ledger)."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
