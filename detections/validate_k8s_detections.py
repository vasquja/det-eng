#!/usr/bin/env python3
"""
Validate that each TRR9002 Sigma rule fires on the API server audit log that the
emulation produced. The Kubernetes counterpart of validate_detections.py.

The loop this proves:

    emulate a procedure -> API server writes an audit event ->
    assert the paired Sigma rule's selection matches that event

It parses the API server audit log (JSON lines), then for each rule checks that
at least one event matches the rule's `detection:` selection. It understands the
small slice of Sigma these rules use: plain equality, a list of values (OR), the
`|contains` modifier, and an `A and B` condition over named selections.

Modes:
    python3 detections/validate_k8s_detections.py --dry-run
        Parse and sanity-check the rules only. No cluster or log needed. Safe
        anywhere; exits 0 unless a rule fails to parse.

    python3 detections/validate_k8s_detections.py --audit-log PATH
        Full validation against the given audit log. Default strict: a rule with
        zero matching events fails the run (exit 1). The emulation in kind is
        deterministic, so a miss is a real regression, not a disabled feature.

    ... --report
        Report misses in the summary instead of failing on them. Only a rule
        that fails to parse fails the run. Mirrors validate_detections.py.

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

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO, "detections", "sigma", "T1609")

# Each rule paired with the procedure it serves and a one-line note. Order is
# the report order.
MANIFEST = [
    ("k8s_pod_exec_attach.yml", "A/B",
     "exec or attach through the API server (chokepoint)"),
    ("k8s_pod_ephemeral_container.yml", "C",
     "ephemeral debug container"),
    ("k8s_node_proxy_exec.yml", "D",
     "exec through the API server node proxy"),
]


def get_field(event, dotted):
    """Resolve a possibly dotted field name against the event dict."""
    cur = event
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def match_field(event, field_spec, value_spec):
    """Match one `field: value(s)` pair, honoring a `|contains` modifier."""
    name, _, mod = field_spec.partition("|")
    actual = get_field(event, name)
    if actual is None:
        return False
    actual_s = str(actual)
    candidates = value_spec if isinstance(value_spec, list) else [value_spec]
    for v in candidates:
        v = str(v)
        if mod == "":
            if actual_s == v:
                return True
        elif mod == "contains":
            if v in actual_s:
                return True
        else:
            raise ValueError(f"unsupported Sigma modifier: |{mod}")
    return False


def match_selection(event, selection):
    return all(match_field(event, f, v) for f, v in selection.items())


def rule_matches(event, detection):
    """Evaluate the rule condition (supports `A` and `A and B`)."""
    cond = str(detection["condition"]).strip()
    names = [t.strip() for t in cond.split(" and ")]
    for n in names:
        if n not in detection:
            raise ValueError(f"condition names unknown selection: {n}")
        if not match_selection(event, detection[n]):
            return False
    return True


def load_rule(path):
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if "detection" not in doc or "condition" not in doc["detection"]:
        raise ValueError("rule has no detection/condition")
    # Touch every selection so a structural error surfaces in --dry-run.
    det = doc["detection"]
    for key, val in det.items():
        if key == "condition":
            continue
        if not isinstance(val, dict):
            raise ValueError(f"selection '{key}' is not a mapping")
    return doc


def load_events(audit_log):
    """Read the audit log (one JSON object per line). Skip blanks/garbage."""
    events = []
    with open(audit_log, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
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
    verbs, seen = {}, set()
    for e in events:
        ref = e.get("objectRef") or {}
        if ref.get("resource") == "pods" and ref.get("subresource") == "exec":
            aid = e.get("auditID")
            if aid and aid in seen:
                continue
            if aid:
                seen.add(aid)
            verb = e.get("verb", "?")
            verbs[verb] = verbs.get(verb, 0) + 1
    return verbs


def main():
    ap = argparse.ArgumentParser(description="Validate TRR9002 K8s detections.")
    ap.add_argument("--audit-log", default="/tmp/kube-apiserver-audit.log",
                    help="Path to the API server audit log (JSON lines).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Parse rules only; no cluster or log needed.")
    ap.add_argument("--report", action="store_true",
                    help="Report misses instead of failing on them.")
    args = ap.parse_args()

    # Load and parse the rules first; a parse error always fails.
    rules = {}
    parse_errors = 0
    for fname, proc, note in MANIFEST:
        path = os.path.join(RULES_DIR, fname)
        try:
            rules[fname] = load_rule(path)
            print(f"OK (parse)  {fname}  [{proc}] {note}")
        except Exception as e:  # noqa: BLE001
            parse_errors += 1
            print(f"ERROR parse {fname}: {e}")
    # Lint any other rule in the folder too.
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
        if os.path.basename(path) not in rules:
            try:
                load_rule(path)
            except Exception as e:  # noqa: BLE001
                parse_errors += 1
                print(f"ERROR parse {os.path.basename(path)}: {e}")

    if args.dry_run:
        print()
        if parse_errors:
            print(f"Dry run FAILED: {parse_errors} parse error(s).")
            return 1
        print(f"Dry run OK: {len(rules)} rule(s) parse and are well-formed.")
        return 0

    if not os.path.exists(args.audit_log):
        print(f"\nAudit log not found: {args.audit_log}")
        print("SKIP: no audit log to validate against (exit 0).")
        return 0 if not parse_errors else 1

    events = load_events(args.audit_log)
    print(f"\nLoaded {len(events)} audit event(s) from {args.audit_log}\n")

    misses = 0
    for fname, proc, note in MANIFEST:
        doc = rules.get(fname)
        if doc is None:
            continue
        det = doc["detection"]
        matched = dedup_by_audit_id([e for e in events if rule_matches(e, det)])
        if matched:
            print(f"PASS  [{proc}] {fname}: {len(matched)} event(s) match")
            sample = matched[0]
            ref = sample.get("objectRef") or {}
            print(f"        e.g. verb={sample.get('verb')} "
                  f"resource={ref.get('resource')} "
                  f"subresource={ref.get('subresource')} "
                  f"user={(sample.get('user') or {}).get('username')}")
        else:
            misses += 1
            print(f"MISS  [{proc}] {fname}: no event matched")

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
        print(f"FAILED: {parse_errors} parse error(s).")
        return 1
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
