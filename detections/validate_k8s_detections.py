#!/usr/bin/env python3
"""
Validate that each TRR9002 Sigma rule fires on the API server audit events that
the emulation produced. The Kubernetes counterpart of validate_detections.py.

The loop this proves:

    emulate a procedure -> API server writes an audit event ->
    the paired Sigma rule, run by a real Sigma backend, matches that event

It parses the API server audit log (JSON lines), flattens each event to the
dotted field names the rules use (objectRef.resource, user.username, ...), and
runs each rule's pySigma-compiled query over them (see sigma_eval.py). A rule
PASSES only if it matches an event from the emulation itself, not merely some
event in the log. Each MANIFEST entry lists one gate per procedure (and per
variant of a procedure), and the entry passes only when EVERY gate matches a
record of its own:

    A websocket   pods/exec on the target pod, verb get, code 101
    A spdy        pods/exec on the target pod, verb create, code 101
    B attach      pods/attach on the target pod, container=app, code 101
    C attach      pods/attach on the target pod, container=trr9002-debug-attach
                  (the attach step of kubectl debug --attach=true), code 101
    C             pods/ephemeralcontainers on the target pod, code 200
    D             nodes/proxy, verb create (POST), requestURI holds
                  /proxy/run/<namespace>/<target pod>/, code 200
    F runningpods nodes/proxy get of the kubelet /runningpods/ by the
                  trr9002-node-reader service account, code 200
    F pods        the same for the kubelet /pods endpoint

Code 101 is what the audit log records for a streaming request: the API server
stamps 101 when it hijacks the connection for the protocol switch, even when
the kubelet then refuses the stream (apiserver endpoints/filters/audit.go,
Hijack; apimachinery util/proxy/upgradeaware.go forwards a kubelet error after
the hijack). So the code shows that the API server authorized and proxied the
request; the emulation ledger (--ledger) shows that the client got its answer:
emulate.sh b holds the attach stream and fails when kubectl exits before the
hold, and emulate.sh c fails when kubectl debug did not attach (it prints no
"If you don't see a command prompt" line, or it falls back to streaming logs).

Modes:
    python3 detections/validate_k8s_detections.py --dry-run
        Compile the rules only. No cluster or log needed. Exits 0 unless a
        rule fails to compile.

    python3 detections/validate_k8s_detections.py --audit-log PATH
        Full validation against the given audit log. Default strict: a rule
        with no matching emulation event fails the run (exit 1). The emulation
        in kind is deterministic, so a miss is a real regression. Without
        --audit-log a strict run reads /tmp/kube-apiserver-audit.log. When the
        log does not exist, a strict run prints SKIP and exits 0 (for a local
        run without a cluster). An empty value (--audit-log '') is a log that
        does not exist: the default is only for a run without the option.

    ... --ledger PATH
        The emulation ledger (atomics/T1609/src/emulate.sh appends one JSON
        line per procedure to $DETENG_LEDGER: trr, procedure, start, end,
        exit, expect). With it, a gate also needs the record's
        requestReceivedTimestamp inside its procedure's [start, end], and the
        procedure's exit to equal its expect; a procedure with no row did not
        run, and its gates fail. It also asserts the Procedure E gap: E must
        have a row with exit 0 (the kubelet answered), and no TRR9002 rule may
        match an audit event inside E's window. Without --ledger the gates use
        the record fields only (local runs, old logs).
        A ledger line that is not a row (not JSON, no trr or procedure, bytes
        that are not UTF-8), a row whose start is after its end, and a ledger
        that is a directory fail the run with an ERROR line, and no rule is
        judged. No record can be in a window whose start is after its end: the
        clock that wrote the ledger is wrong, and each gate of the procedure
        would miss a rule that matched (2026-11-13). Its ERROR line names the
        procedure and the two times as the ledger holds them. A start equal to
        the end is a window.

    ... --expect-miss
        Negative control, for a log captured BEFORE the emulation ran: exit 1
        if any one procedure gate matches. Proves a pass depends on the
        emulation. It uses the field gates only (--ledger is ignored).
        A negative control that read no record cannot fail, so it proves
        nothing. Thus the run also exits 1, before it judges a rule, when
        --audit-log is not given (this mode has no default log, and an empty
        value counts as not given), when the log does not exist, and when the
        log holds no audit event. The count is the number that the `Loaded N
        audit event(s)` line prints: the records of the log (see "A record of
        the log" below).

    ... --report
        Report rule misses in the summary instead of failing on them. A rule
        that fails to compile still fails the run, and so does a failed
        Procedure E gap assertion (with --ledger): that is a control, not a miss.

    ... --json PATH
        Also write a machine-readable report (status, detail and the
        explanation lines of every rule) to PATH. A PATH that the run cannot
        write (a directory) is an ERROR, and the run exits 1.

A record of the log is an audit event: a JSON object with "kind": "Event" and an
apiVersion of the group audit.k8s.io (RECORDS). A blank line, and a line that is
not JSON (a line that was cut at the end of a capture), are not records. Each
other line that is not a record fails every run that reads the log (a strict run,
--report and --expect-miss), and no rule is judged: JSON that is not an object
(`[]`), a JSON object that is not an audit event (`{}`, a core Event of
`kubectl get events`, an audit EventList), bytes that are not UTF-8, the byte
order mark of UTF-8 at the start of line 1, and JSON that the validator cannot
read (too deep, or a number that is too long). One ERROR line names the log, the
line and the problem (at most 10 lines for each log, then the number of the
others), and a FAILED line ends the run with exit 1. With --expect-miss the --json
control of the pre-emulation log says FAILED, and --json gets `log_problems` (with
the same limit) when a log holds such a line. A log that is a directory, or that
the run cannot open, is an ERROR too (exit 1): it is not a log that was not found.

The key finding (exec recorded as verb=get over WebSocket and verb=create over
SPDY) is gated by 'A websocket' and 'A spdy'. CI pins kubectl and the server at
v1.36, where the KUBECTL_REMOTE_COMMAND_WEBSOCKETS toggle selects the protocol.
A cluster older than v1.31, or a kubectl that ignores the toggle, fails one of
the two gates; the chokepoint rule itself matches on the subresource for any
verb. The verb counts are still printed below the gates.

The module-level PROCEDURES map gives, per (TRR, procedure letter), the rule
files whose MANIFEST entry gates that procedure with a gate of its own
(research/tools/coverage_report.py reads it).

A MISS is explained beneath its line (sigma_explain.py): what the gate requires,
how many events name the target pod, and the one that came closest to the rule,
item by item; or, when none does, that the emulation may not have run. A failed
--expect-miss shows the event(s) the rule matched and why.
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402
try:  # explanations are optional: a broken sigma_explain must never break a verdict
    import sigma_explain  # noqa: E402
except Exception as _e:  # noqa: BLE001
    sigma_explain = None
    print(f"[diag] no explanations: sigma_explain failed to import "
          f"({type(_e).__name__}: {_e})")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO, "detections", "sigma", "T1609")

# The pod every emulated procedure targets (atomics/T1609/src/emulate.sh), its
# namespace and container, and the service account Procedure F reads as.
TARGET_POD = os.environ.get("TRR9002_POD", "trr9002-target")
NAMESPACE = os.environ.get("TRR9002_NAMESPACE", "default")
CONTAINER = os.environ.get("TRR9002_CONTAINER", "app")
NODE_READER = "trr9002-node-reader"
TRR = "TRR9002"


def field_is(field, value):
    def gate(e):
        return e.get(field) == value
    gate.describe = f"{field} == {value!r}"  # for the MISS explanation
    return gate


def field_contains(field, sub):
    def gate(e):
        return sub in (e.get(field) or "")
    gate.describe = f"{field} contains {sub!r}"
    return gate


def _code(e):
    try:
        return int(e.get("responseStatus.code"))
    except (TypeError, ValueError):
        return None


def rec(resource, sub, verb=None, name=None, uri=None, user=None, code=(200,), window=None):
    """One procedure's own audit record: resource/subresource, and optionally the
    verb, the object name, a requestURI substring and a user.username substring;
    responseStatus.code must be one of `code`. `window` is the (TRR, procedure)
    key of the procedure's ledger row (see windowed()); it also names the
    procedure the gate proves, for PROCEDURES."""
    parts = [field_is("objectRef.resource", resource), field_is("objectRef.subresource", sub)]
    if verb:
        parts.append(field_is("verb", verb))
    if name:
        parts.append(field_is("objectRef.name", name))
    if uri:
        parts.append(field_contains("requestURI", uri))
    if user:
        parts.append(field_contains("user.username", user))
    codes = tuple(code)

    def gate(e):
        return _code(e) in codes and all(p(e) for p in parts)
    gate.describe = (" and ".join(p.describe for p in parts)
                     + f" and responseStatus.code in {list(codes)}")
    gate.window = window
    return gate


# Each rule paired with the procedures it serves, a one-line note, and one gate
# per procedure (label, gate): EVERY gate needs a record of its own. Order is the
# report order. A streaming request (exec, attach) is recorded with code 101.
MANIFEST = [
    ("k8s_pod_exec_attach.yml", "A/B/C",
     "exec or attach through the API server (chokepoint)", [
         ("A websocket", rec("pods", "exec", verb="get", name=TARGET_POD, code=(101,),
                             window=(TRR, "A"))),
         ("A spdy", rec("pods", "exec", verb="create", name=TARGET_POD, code=(101,),
                        window=(TRR, "A"))),
         ("B attach", rec("pods", "attach", name=TARGET_POD, uri=f"container={CONTAINER}",
                          code=(101,), window=(TRR, "B"))),
         ("C attach", rec("pods", "attach", name=TARGET_POD,
                          uri="container=trr9002-debug-attach", code=(101,),
                          window=(TRR, "C")))]),
    ("k8s_pod_ephemeral_container.yml", "C",
     "ephemeral debug container", [
         ("C", rec("pods", "ephemeralcontainers", name=TARGET_POD, code=(200,),
                   window=(TRR, "C")))]),
    ("k8s_node_proxy_exec.yml", "D",
     "exec through the API server node proxy (POST to the kubelet /run)", [
         ("D", rec("nodes", "proxy", verb="create",
                   uri=f"/proxy/run/{NAMESPACE}/{TARGET_POD}/", code=(200,),
                   window=(TRR, "D")))]),
    ("k8s_node_proxy_kubelet_api.yml", "F",
     "kubelet pod read through the API server node proxy", [
         ("F runningpods", rec("nodes", "proxy", verb="get", uri="/proxy/runningpods/",
                               user=NODE_READER, code=(200,), window=(TRR, "F"))),
         ("F pods", rec("nodes", "proxy", verb="get", uri="/proxy/pods", user=NODE_READER,
                        code=(200,), window=(TRR, "F")))]),
]

# Procedure E (direct kubelet access) is the documented gap: no API server audit
# event is expected. With --ledger the validator asserts it (see check_gap_e()).
GAP_E = (TRR, "E")


def _procedures(manifest, folder):
    """{(TRR, letter): sorted rule paths}: the rules whose MANIFEST entry gates that
    procedure with a gate of its own (the gate's ledger window names it)."""
    out = {}
    for fname, _proc, _note, gates in manifest:
        for _label, gate in gates:
            key = getattr(gate, "window", None)
            if key:
                out.setdefault(key, set()).add(f"{folder}/{fname}")
    return {key: sorted(paths) for key, paths in sorted(out.items())}


PROCEDURES = _procedures(MANIFEST, os.path.basename(RULES_DIR))

# Anything the emulation touches mentions this; used when no event passes a gate.
TAG = "trr9002"


# ---- what a record of each log is ---------------------------------------------
# The table of the log reader below. For each source of MANIFEST: the name of its
# log, the name of one record, the test of one JSON object, and what the test needs.
# Each test is the smallest identity that the code that reads the log needs (see
# detections/README.md, "A record of each log").


RECORDS = {
    "audit": {
        "log": "audit log", "record": "audit event", "a": "an audit event",
        "test": lambda doc: (doc.get("kind") == "Event"
                             and isinstance(doc.get("apiVersion"), str)
                             and doc["apiVersion"].startswith("audit.k8s.io/")),
        "needs": 'an audit event has "kind": "Event" and an apiVersion of the group '
                 "audit.k8s.io",
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


def read_log(path, source):
    """(records, problems): the records of the log of `source` at `path`, flattened to
    the dotted field names of the rules (sigma_eval.flatten), and the problems.

    The records are what each rule of that source is run on. The `Loaded N ...` line
    prints their number. A line of a CRI log is a `crictl pods -o json` snapshot
    ({"items": [...]}) or one sandbox; a sandbox counts once, at the first line that
    holds its id.

    A problem is a line, or an item of a snapshot, that is not a record of the log:
    bytes that are not UTF-8, the byte order mark of UTF-8 at the start of line 1,
    JSON that the validator cannot read (too deep, or a number that is too long),
    JSON that is not an object, a JSON object that is not a record of the log, a
    record that one event table cannot hold (table_problem()), and a snapshot whose
    "items" is not a list. Each problem is (line, item, text): lines
    and items count from 1, and item is None for a line. A blank line, and a line
    that is not JSON (a line that was cut at the end of a capture), are no record and
    no problem. Raises LogError for a log that is a directory or cannot be read.
    """
    spec = RECORDS[source]
    if os.path.isdir(path):
        raise LogError(f"the {spec['log']} {path} is a directory, not a file")
    records, problems, seen = [], [], set()
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            for n, text in enumerate(fh, 1):
                line = text.strip()
                if not line:
                    continue
                bad = next((i for i, ch in enumerate(text) if 0xDC80 <= ord(ch) <= 0xDCFF), None)
                if bad is not None:
                    problems.append((n, None, f"bytes that are not UTF-8 (the byte "
                                              f"0x{ord(text[bad]) - 0xdc00:02x} at character "
                                              f"{bad + 1} of the line)"))
                    continue
                if n == 1 and text.startswith(BYTE_ORDER_MARK):
                    problems.append((n, None, "the line starts with the byte order mark of "
                                              "UTF-8 (EF BB BF)"))
                    continue
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                except (ValueError, RecursionError) as e:
                    problems.append((n, None, _cannot_read(e)))
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
    except OSError as e:
        raise LogError(f"the {spec['log']} {path} cannot be read ({e.strerror or e})") from None
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

# --expect-miss: why a pre-emulation log that gave the rules no record fails the run.
VACUOUS = "A negative control that read no record cannot fail, so it proves nothing."


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


def exec_verbs(events):
    """Verbs seen on pods/exec events — the key-finding report.

    Deduplicated by auditID so a long-running exec that emits both
    ResponseStarted and ResponseComplete counts once.
    """
    verbs = {}
    for e in dedup_by_audit_id(events):
        if e.get("objectRef.resource") == "pods" and e.get("objectRef.subresource") == "exec":
            verb = e.get("verb", "?")
            verbs[verb] = verbs.get(verb, 0) + 1
    return verbs


# ---- failure explanations (sigma_explain) --------------------------------
# The same helpers as validate_apiserver_detections.py; each validator stays standalone.


def summary(e):
    """One line naming an audit event: verb, resource, name, namespace, user."""
    resource = str(e.get("objectRef.resource"))
    if e.get("objectRef.subresource"):
        resource += f"/{e['objectRef.subresource']}"
    return (f"verb={e.get('verb')} resource={resource} name={e.get('objectRef.name')} "
            f"ns={e.get('objectRef.namespace')} user={e.get('user.username')}"
            + (f" code={e['responseStatus.code']}" if e.get("responseStatus.code") else "")
            + (f" stage={e['stage']}" if e.get("stage") else ""))


def labeller(events):
    index = {id(e): i for i, e in enumerate(events)}
    return lambda e: f"event #{index.get(id(e), '?')} [{summary(e)}]"


def absent_hint(rule, events, scope, where):
    """A line naming rule fields no event carries, and whether the audit level explains it."""
    fields = dict.fromkeys(f for a in rule.positive_atoms() for f in rule.fields(a))
    absent = [f for f in fields if all(e.get(f) is None for e in events)]
    if not absent:
        return []
    hint = f"rule field(s) no event in the log carries: {', '.join(absent)}"
    if any(f.startswith("requestObject") for f in absent):
        if not any(k.startswith("requestObject") for e in scope for k in e):
            return [hint + f"; {where} carry no requestObject at all: the audit policy "
                    "records this resource below level Request, which the rule needs"]
        return [hint + "; requestObject is recorded but never sets these"]
    return [hint + "; no event of that shape reached the log, the audit policy does not "
            "record it, or the field is named differently (casing, flattening)"]


def explain_gated_miss(rule_path, events, gate, matched):
    """Why no event the emulation made matched: the gate, then the closest marked event."""
    rule = sigma_explain.load(rule_path).stripped()  # no null guards or copies
    label = labeller(events)
    marked = [i for i, e in enumerate(events) if gate(e)]
    lines = [f"gate: {getattr(gate, 'describe', 'see its MANIFEST entry')}"]
    candidates, where = marked, "the marked event(s)"
    if marked:
        lines.append(f"{len(marked)} event(s) carry the emulation's marker and the rule "
                     "matches none of them")
    else:
        lines.append(f"NO event carries the emulation's marker: the emulation may not have run, "
                     f"or its events do not pass the gate above (TRR9002_POD sets the target "
                     f"pod, now {TARGET_POD!r})")
        candidates = [i for i, e in enumerate(events) if any(TAG in str(v) for v in e.values())]
        where = f"the event(s) mentioning {TAG!r}"
        hit = {id(e) for e in matched}
        if candidates:
            lines.append(f"{len(candidates)} event(s) mention {TAG!r} but fail the gate, e.g.:")
            lines.extend(f"  {label(events[i])}" for i in candidates[:3])
            fired = sum(1 for i in candidates if id(events[i]) in hit)
            if fired:
                lines.append(f"the rule DOES match {fired} of them: the rule works, the gate "
                             "does not recognise the event as the emulation's")
        else:
            where = "the events of the whole log"
            if matched:
                lines.append(f"no event mentions {TAG!r} at all, while the rule matches "
                             f"{len(matched)} other event(s): the emulation's own records are "
                             "missing (check the emulate step's output)")
            else:
                lines.append(f"no event mentions {TAG!r} at all")
                candidates = None  # nothing to narrow to: grade the whole log
    lines += absent_hint(rule, events,
                         [events[i] for i in candidates] if candidates else events, where)
    if candidates or candidates is None:
        lines.append(f"per block over {where}, then the closest event, item by item:")
        lines += sigma_explain.explain_miss(rule, events, k=1, candidates=candidates,
                                            label=label)
    return lines


def explain_unexpected(rule_path, events, ours, gate=None):
    """--expect-miss failed: the event(s) the rule matched, and why it fired."""
    rule = sigma_explain.load(rule_path)
    label = labeller(events)
    marker = getattr(gate, "describe", f"the target pod {TARGET_POD!r}")
    lines = [f"the pre-emulation log already holds {len(ours)} match(es) that pass the gate "
             f"({marker}); a log captured before the emulation should hold none (captured "
             "late, or a pod or service account left over from an earlier run?):"]
    for e in ours[:3]:
        lines.append(f"  {label(e)}"
                     + (f" at {e['requestReceivedTimestamp']}"
                        if e.get("requestReceivedTimestamp") else ""))
        lines.extend("  " + ln for ln in sigma_explain.explain_hit(rule, e))
    if len(ours) > 3:
        lines.append(f"  ... and {len(ours) - 3} more")
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
# The same contract as validate_apiserver_detections.py; each validator stays
# standalone. Each emulation run appends one JSON line per procedure:
#   {"trr": "TRR9002", "procedure": "A", "start": "...Z", "end": "...Z",
#    "exit": 0, "expect": 0}
# start and end are UTC ISO 8601 with microseconds (YYYY-MM-DDTHH:MM:SS.ffffffZ, from
# now() of the emulation script, which reads EPOCHREALTIME of bash).
# The kind node is a container on the runner, so the audit timestamps and the
# ledger read the same kernel clock.


def _ts(value):
    """A UTC datetime from an ISO 8601 timestamp (any number of fraction digits,
    'Z' or an offset), or None when it does not parse."""
    if value is None or value == "":
        return None
    text = str(value).strip()
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
    """('TRR9002', 'A') from 'TRR9002'/'9002' and 'A'/'a'."""
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
                "exit": row.get("exit"), "expect": row.get("expect", 0)}
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
    return True, f"requestReceivedTimestamp in [{_iso(row['start'])}, {_iso(row['end'])}]"


def in_window(e, row):
    t = _ts(e.get("requestReceivedTimestamp"))
    return t is not None and row["start"] <= t <= row["end"]


def windowed(gate, ledger):
    """The gate, also bound to its procedure's ledger row when a ledger is given."""
    key = getattr(gate, "window", None)
    if ledger is None or key is None:
        return gate
    ok, state = ledger_state(ledger, key)
    row = ledger.get(key)

    def bound(e):
        return ok and in_window(e, row) and gate(e)
    bound.describe = f"{gate.describe}; ledger {key[0]}.{key[1]}: {state}"
    bound.window = key
    bound.ledger = state
    return bound


def check_gap_e(events, queries, ledger):
    """Procedure E leaves no audit event a TRR9002 rule matches. Returns failures."""
    ok, state = ledger_state(ledger, GAP_E)
    if not ok:
        failures = [f"Procedure E: {state}; E must reach the kubelet and get a 200 "
                    "(curl -f), or the gap claim is untested"]
        print(f"\nProcedure E (direct kubelet access): {state}.")
    else:
        row = ledger[GAP_E]
        inside = [e for e in events if in_window(e, row)]
        failures = []
        for fname, query in queries.items():
            hits = dedup_by_audit_id([h[0] for h in sigma_eval.evaluate(query, inside)])
            if hits:
                failures.append(f"{fname} matched {len(hits)} audit event(s) inside "
                                f"Procedure E's window, e.g. [{summary(hits[0])}]: the "
                                "direct kubelet call is not invisible to the audit log")
        print(f"\nProcedure E (direct kubelet access): ran (ledger exit {row['exit']}); "
              f"{len(inside)} audit event(s) in its window ({state}); "
              + ("no TRR9002 rule matches any of them: gap confirmed." if not failures
                 else "GAP CLAIM BROKEN."))
    for f in failures:
        print(f"  GAP FAILED: {f}")
    return failures


def main():
    ap = argparse.ArgumentParser(description="Validate TRR9002 K8s detections.")
    ap.add_argument("--audit-log",
                    help="Path to the API server audit log (JSON lines). A strict run "
                         f"without it reads {DEFAULT_AUDIT_LOG}; --expect-miss needs it.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compile rules only; no cluster or log needed.")
    ap.add_argument("--expect-miss", action="store_true",
                    help="Negative control: fail if any rule passes, or if the "
                         "pre-emulation log is not given, is missing or holds no "
                         "audit event.")
    ap.add_argument("--report", action="store_true",
                    help="Report rule misses instead of failing on them (a compile "
                         "error or a failed Procedure E gap assertion still fails).")
    ap.add_argument("--json", metavar="PATH",
                    help="Also write a machine-readable report (results + explanations).")
    ap.add_argument("--ledger", metavar="PATH",
                    help="Emulation ledger (JSON lines, one per procedure): bind each gate "
                         "to its procedure's window and exit status.")
    args = ap.parse_args()
    report = {"validator": "k8s",
              "mode": "dry-run" if args.dry_run else
              "expect-miss" if args.expect_miss else "validate", "results": [],
              "procedures": {}, "controls": []}
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
    for fname, proc, note, _ in MANIFEST:
        try:
            queries[fname] = sigma_eval.compile_rule(os.path.join(RULES_DIR, fname))
            print(f"OK (compile)  {fname}  [{proc}] {note}")
        except Exception as e:  # noqa: BLE001
            parse_errors += 1
            print(f"ERROR compile {fname}: {e}")
            results.append({"rule": fname, "procedure": proc, "status": "ERROR",
                            "detail": f"compile: {e}", "explanation": []})
    # Compile any other rule in the folder too.
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
        if os.path.basename(path) not in queries:
            try:
                sigma_eval.compile_rule(path)
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
        print(f"Dry run OK: {len(queries)} rule(s) compile with pySigma.")
        return 0

    # A strict run takes the default only when the option is absent. An empty value
    # (--audit-log '') is then a log that does not exist, as it was before the
    # negative control got its checks.
    audit_log = DEFAULT_AUDIT_LOG if args.audit_log is None else args.audit_log
    if args.expect_miss:
        # A negative control must read the log that was captured before the
        # emulation. Without that log it read no record: an error, not a SKIP. An
        # empty value counts as a log that is not given.
        why = ("no pre-emulation audit log was given (--audit-log)" if not args.audit_log
               else f"the pre-emulation audit log {audit_log} was not found"
               if not os.path.exists(audit_log) else None)
        if why:
            print(f"\nERROR: {why}. {VACUOUS}")
            report["controls"].append({"control": "the pre-emulation audit log holds a "
                                                  "record", "status": "FAILED", "detail": why})
            return 1
    elif not os.path.exists(audit_log):
        print(f"\nAudit log not found: {audit_log}")
        print("SKIP: no audit log to validate against (exit 0).")
        return 0 if not parse_errors else 1

    try:
        events, problems = read_log(audit_log, "audit")
    except LogError as e:
        # A directory, or a file that the run cannot open: not a log that was not
        # found (that is a SKIP of a strict run), and not a log to judge a rule on.
        print(f"\nERROR: {e}.")
        if args.expect_miss:
            report["controls"].append({"control": "the pre-emulation audit log holds a "
                                                  "record", "status": "FAILED", "detail": str(e)})
        return 1
    print(f"\nLoaded {len(events)} audit event(s) from {audit_log}")
    bad = show_log_problems("audit", audit_log, problems, report)
    if args.expect_miss:
        # The count is what read_log() returned: the records that each rule is run on
        # (this mode has no time filter). No rule can match a log without a record,
        # so no rule is judged.
        why = [] if events else [
            f"the pre-emulation audit log {audit_log} holds no audit event (0 records "
            f"read from {nonblank_lines(audit_log)} non-blank line(s))"]
        report["controls"].append({
            "control": "the pre-emulation audit log holds a record",
            "status": "FAILED" if why or bad else "held",
            "detail": "; ".join(why + ([f"{bad} line(s) of the pre-emulation audit log "
                                        f"{audit_log} are not audit events"] if bad else []))
            or f"{len(events)} audit event(s)"})
        for line in why:
            print(f"\nNEGATIVE CONTROL FAILED: {line}. {VACUOUS}")
        if why and not bad:
            return 1
    if bad:
        # A line that is not a record: the log is not what the validator reads, so
        # no rule is judged on it (a strict run, --report and --expect-miss alike).
        print(f"\n{log_problems_failed(bad)}")
        return 1

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

    passes = misses = 0
    proc_status = report["procedures"]
    for fname, proc, note, gates in MANIFEST:
        if fname not in queries:
            continue
        matched = dedup_by_audit_id(
            [hit[0] for hit in sigma_eval.evaluate(queries[fname], events)])
        found = []
        for label, gate in gates:
            g = windowed(gate, ledger)
            found.append((label, g, [e for e in matched if g(e)]))
        ours = {id(e) for _, _, hits in found for e in hits}
        other = len(matched) - len(ours)
        every, some = all(h for _, _, h in found), any(h for _, _, h in found)
        passed = some if args.expect_miss else every
        rule_path = os.path.join(RULES_DIR, fname)
        explanation = []
        if passed:
            passes += 1
            detail = f"{len(ours)} emulation event(s) match" + (f" (+{other} other)"
                                                                if other else "")
            print(f"PASS  [{proc}] {fname}: {detail}")
        else:
            misses += 1
            detail = ("no emulation event matched" if not some else
                      "a procedure has no record of its own") + (
                f" ({other} unrelated match(es) ignored)" if other else "")
            print(f"MISS  [{proc}] {fname}: {detail}")
        for label, g, hits in found:
            if hits:
                sample = hits[0]
                print(f"        ok   {label}: {len(hits)} match(es), e.g. "
                      f"verb={sample.get('verb')} "
                      f"resource={sample.get('objectRef.resource')} "
                      f"subresource={sample.get('objectRef.subresource')} "
                      f"code={sample.get('responseStatus.code')} "
                      f"user={sample.get('user.username')}")
            else:
                print(f"        MISS {label}: 0 match(es)"
                      + (f" [ledger: {g.ledger}]" if getattr(g, "ledger", None) else ""))
                if not args.expect_miss:
                    lines = [f"{label}:"] + ["  " + ln for ln in explained(
                        explain_gated_miss, rule_path, events, g, matched)]
                    explanation += lines
                    for line in lines[1:]:
                        print("          " + line)
            key = getattr(g, "window", None)
            if key:
                entry = proc_status.setdefault(f"{key[0]}.{key[1]}", {"status": "ok",
                                                                      "gates": {}})
                entry["gates"][label] = len(hits)
                if not hits:
                    entry["status"] = "MISS"
        if passed and args.expect_miss:
            first = next(g for _, g, h in found if h)
            explanation = explained(explain_unexpected, rule_path, events,
                                    [e for _, _, h in found for e in h], first)
            for line in explanation:
                print("        " + line)
        results.append({"rule": fname, "procedure": proc, "status": "PASS" if passed else "MISS",
                        "detail": detail, "emulation_matches": len(ours),
                        "other_matches": other,
                        "procedures": {label: len(h) for label, _, h in found},
                        "explanation": explanation})

    # Key finding: both exec verbs. Gated above by 'A websocket' and 'A spdy'.
    verbs = exec_verbs(events)
    print()
    if verbs:
        shown = ", ".join(f"{v} x{n}" for v, n in sorted(verbs.items()))
        print(f"Key finding (gated by 'A websocket' and 'A spdy') — pods/exec verbs "
              f"observed: {shown}")
        if "get" in verbs and "create" in verbs:
            print("  Both verbs seen: WebSocket (get) and SPDY (create). "
                  "A create-only rule would miss the WebSocket exec.")
        elif "get" in verbs:
            print("  WebSocket exec (verb=get) seen. A create-only rule would "
                  "miss it.")
        elif "create" in verbs:
            print("  Only verb=create seen (SPDY). This cluster/kubectl did not "
                  "produce a WebSocket exec, so 'A websocket' fails; the chokepoint "
                  "rule matches either way.")
    else:
        print("Key finding — no pods/exec events found to report verbs.")

    # Procedure E gap: asserted with a ledger, informational without one.
    gap_failures = []
    if ledger is not None:
        gap_failures = check_gap_e(events, queries, ledger)
        report["controls"].append({"control": "Procedure E leaves no audit event a TRR9002 "
                                              "rule matches",
                                   "status": "FAILED" if gap_failures else "held",
                                   "detail": "; ".join(gap_failures)})
    else:
        print("\nProcedure E (direct kubelet access): no API server audit event is "
              "expected.\n  The audit-log layer cannot see it; Strategy 4 needs a "
              "node runtime sensor. (Asserted only with --ledger.)")

    print()
    if parse_errors:
        print(f"FAILED: {parse_errors} compile error(s).")
        return 1
    if args.expect_miss:
        if passes:
            print(f"NEGATIVE CONTROL FAILED: {passes} rule(s) passed on a log "
                  "captured before the emulation ran (a procedure gate matched).")
            return 1
        print("Negative control held: no procedure gate matches without the emulation.")
        return 0
    if gap_failures:
        print(f"FAILED: the Procedure E gap assertion failed ({len(gap_failures)}).")
        return 1
    if misses and not args.report:
        print(f"FAILED: {misses} rule(s) did not fire on every procedure. "
              f"(Use --report to treat misses as non-fatal.)")
        return 1
    if misses:
        print(f"Reported {misses} miss(es); not gated (--report).")
        return 0
    print("All TRR9002 detections fired on the emulated telemetry, every procedure "
          "with a record of its own" + (" inside its ledger window." if ledger is not None
                                        else " (field gates only, no ledger)."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
