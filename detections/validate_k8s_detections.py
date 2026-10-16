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
PASSES only if it matches an event from the emulation itself (one naming the
target pod), not merely some event in the log.

Modes:
    python3 detections/validate_k8s_detections.py --dry-run
        Compile the rules only. No cluster or log needed. Exits 0 unless a
        rule fails to compile.

    python3 detections/validate_k8s_detections.py --audit-log PATH
        Full validation against the given audit log. Default strict: a rule
        with no matching emulation event fails the run (exit 1). The emulation
        in kind is deterministic, so a miss is a real regression.

    ... --expect-miss
        Negative control, for a log captured BEFORE the emulation ran: exit 1
        if any rule passes. Proves a pass depends on the emulation.

    ... --report
        Report misses in the summary instead of failing on them. Only a rule
        that fails to compile fails the run.

    ... --json PATH
        Also write a machine-readable report (status, detail and the
        explanation lines of every rule) to PATH.

The key-finding check (exec recorded as verb=get over WebSocket and verb=create
over SPDY) is reported, never gated: a cluster older than v1.31, or a kubectl
that ignores the protocol toggle, changes which verbs appear, but the chokepoint
rule matches on the subresource regardless of verb.

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

# The pod every emulated procedure targets (atomics/T1609/src/emulate.sh).
TARGET_POD = os.environ.get("TRR9002_POD", "trr9002-target")


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


# Each rule paired with the procedure it serves, a one-line note, and how to
# recognise the emulation's own event. Order is the report order.
MANIFEST = [
    ("k8s_pod_exec_attach.yml", "A/B",
     "exec or attach through the API server (chokepoint)",
     field_is("objectRef.name", TARGET_POD)),
    ("k8s_pod_ephemeral_container.yml", "C",
     "ephemeral debug container",
     field_is("objectRef.name", TARGET_POD)),
    ("k8s_node_proxy_exec.yml", "D",
     "exec through the API server node proxy",
     field_contains("requestURI", f"/{TARGET_POD}/")),
]

# Anything the emulation touches mentions this; used when no event passes a gate.
TAG = "trr9002"


def load_events(audit_log):
    """Read the audit log (one JSON object per line), flattened. Skip garbage."""
    events = []
    with open(audit_log, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(sigma_eval.flatten(json.loads(line)))
            except json.JSONDecodeError:
                continue
    return events


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
    rule = sigma_explain.load(rule_path)
    label = labeller(events)
    marked = [i for i, e in enumerate(events) if gate(e)]
    lines = [f"gate: {getattr(gate, 'describe', 'see its MANIFEST entry')}"]
    candidates, where = marked, "the marked event(s)"
    if marked:
        lines.append(f"{len(marked)} event(s) carry the emulation's marker and the rule "
                     "matches none of them")
    else:
        lines.append(f"NO event carries the emulation's marker: the emulation may not have run, "
                     f"or the target pod is not named {TARGET_POD!r} (TRR9002_POD)")
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


def explain_unexpected(rule_path, events, ours):
    """--expect-miss failed: the event(s) the rule matched, and why it fired."""
    rule = sigma_explain.load(rule_path)
    label = labeller(events)
    lines = [f"the pre-emulation log already holds {len(ours)} match(es) on {TARGET_POD!r}; "
             "a log captured before the emulation should hold none (captured late, or a "
             "pod left over from an earlier run?):"]
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


def main():
    ap = argparse.ArgumentParser(description="Validate TRR9002 K8s detections.")
    ap.add_argument("--audit-log", default="/tmp/kube-apiserver-audit.log",
                    help="Path to the API server audit log (JSON lines).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compile rules only; no cluster or log needed.")
    ap.add_argument("--expect-miss", action="store_true",
                    help="Negative control: fail if any rule passes.")
    ap.add_argument("--report", action="store_true",
                    help="Report misses instead of failing on them.")
    ap.add_argument("--json", metavar="PATH",
                    help="Also write a machine-readable report (results + explanations).")
    args = ap.parse_args()
    report = {"validator": "k8s",
              "mode": "dry-run" if args.dry_run else
              "expect-miss" if args.expect_miss else "validate", "results": []}
    code = validate(args, report)
    if args.json:
        report["exit"] = code
        write_json(args.json, report)
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

    if not os.path.exists(args.audit_log):
        print(f"\nAudit log not found: {args.audit_log}")
        print("SKIP: no audit log to validate against (exit 0).")
        return 0 if not parse_errors else 1

    events = load_events(args.audit_log)
    print(f"\nLoaded {len(events)} audit event(s) from {args.audit_log}\n")

    passes = misses = 0
    for fname, proc, note, from_emulation in MANIFEST:
        if fname not in queries:
            continue
        matched = dedup_by_audit_id(
            [hit[0] for hit in sigma_eval.evaluate(queries[fname], events)])
        ours = [e for e in matched if from_emulation(e)]
        other = len(matched) - len(ours)
        rule_path = os.path.join(RULES_DIR, fname)
        explanation = []
        if ours:
            passes += 1
            detail = f"{len(ours)} emulation event(s) match" + (f" (+{other} other)"
                                                                if other else "")
            print(f"PASS  [{proc}] {fname}: {detail}")
            sample = ours[0]
            print(f"        e.g. verb={sample.get('verb')} "
                  f"resource={sample.get('objectRef.resource')} "
                  f"subresource={sample.get('objectRef.subresource')} "
                  f"user={sample.get('user.username')}")
            if args.expect_miss:
                explanation = explained(explain_unexpected, rule_path, events, ours)
        else:
            misses += 1
            detail = "no emulation event matched" + (f" ({other} unrelated match(es) ignored)"
                                                     if other else "")
            print(f"MISS  [{proc}] {fname}: {detail}")
            if not args.expect_miss:
                explanation = explained(explain_gated_miss, rule_path, events, from_emulation,
                                        matched)
        for line in explanation:
            print("        " + line)
        results.append({"rule": fname, "procedure": proc, "status": "PASS" if ours else "MISS",
                        "detail": detail, "emulation_matches": len(ours),
                        "other_matches": other, "explanation": explanation})

    # Key-finding report (never gated).
    verbs = exec_verbs(events)
    print()
    if verbs:
        shown = ", ".join(f"{v} x{n}" for v, n in sorted(verbs.items()))
        print(f"Key finding — pods/exec verbs observed: {shown}")
        if "get" in verbs and "create" in verbs:
            print("  Both verbs seen: WebSocket (get) and SPDY (create). "
                  "A create-only rule would miss the WebSocket exec.")
        elif "get" in verbs:
            print("  WebSocket exec (verb=get) seen. A create-only rule would "
                  "miss it.")
        elif "create" in verbs:
            print("  Only verb=create seen (SPDY). This cluster/kubectl did not "
                  "produce a WebSocket exec; the chokepoint rule matches "
                  "either way.")
    else:
        print("Key finding — no pods/exec events found to report verbs.")

    # Procedure E gap (informational).
    print("\nProcedure E (direct kubelet access): no API server audit event is "
          "expected.\n  The audit-log layer cannot see it; Strategy 4 needs a "
          "node runtime sensor.")

    print()
    if parse_errors:
        print(f"FAILED: {parse_errors} compile error(s).")
        return 1
    if args.expect_miss:
        if passes:
            print(f"NEGATIVE CONTROL FAILED: {passes} rule(s) passed on a log "
                  "captured before the emulation ran.")
            return 1
        print("Negative control held: no rule passes without the emulation.")
        return 0
    if misses and not args.report:
        print(f"FAILED: {misses} rule(s) did not fire. "
              f"(Use --report to treat misses as non-fatal.)")
        return 1
    if misses:
        print(f"Reported {misses} miss(es); not gated (--report).")
        return 0
    print("All TRR9002 detections fired on the emulated telemetry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
