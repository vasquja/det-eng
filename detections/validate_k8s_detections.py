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

The key-finding check (exec recorded as verb=get over WebSocket and verb=create
over SPDY) is reported, never gated: a cluster older than v1.31, or a kubectl
that ignores the protocol toggle, changes which verbs appear, but the chokepoint
rule matches on the subresource regardless of verb.
"""

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO, "detections", "sigma", "T1609")

# The pod every emulated procedure targets (atomics/T1609/src/emulate.sh).
TARGET_POD = os.environ.get("TRR9002_POD", "trr9002-target")

# Each rule paired with the procedure it serves, a one-line note, and how to
# recognise the emulation's own event. Order is the report order.
MANIFEST = [
    ("k8s_pod_exec_attach.yml", "A/B",
     "exec or attach through the API server (chokepoint)",
     lambda e: e.get("objectRef.name") == TARGET_POD),
    ("k8s_pod_ephemeral_container.yml", "C",
     "ephemeral debug container",
     lambda e: e.get("objectRef.name") == TARGET_POD),
    ("k8s_node_proxy_exec.yml", "D",
     "exec through the API server node proxy",
     lambda e: f"/{TARGET_POD}/" in (e.get("requestURI") or "")),
]


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
    args = ap.parse_args()

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
    # Compile any other rule in the folder too.
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
        if os.path.basename(path) not in queries:
            try:
                sigma_eval.compile_rule(path)
            except Exception as e:  # noqa: BLE001
                parse_errors += 1
                print(f"ERROR compile {os.path.basename(path)}: {e}")

    if args.dry_run:
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
        if ours:
            passes += 1
            print(f"PASS  [{proc}] {fname}: {len(ours)} emulation event(s) match"
                  + (f" (+{other} other)" if other else ""))
            sample = ours[0]
            print(f"        e.g. verb={sample.get('verb')} "
                  f"resource={sample.get('objectRef.resource')} "
                  f"subresource={sample.get('objectRef.subresource')} "
                  f"user={sample.get('user.username')}")
        else:
            misses += 1
            print(f"MISS  [{proc}] {fname}: no emulation event matched"
                  + (f" ({other} unrelated match(es) ignored)" if other else ""))

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
