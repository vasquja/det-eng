#!/usr/bin/env python3
"""
Validate the TRR9003 (static pod, T1543.005) detection loop on the API server
audit log that the emulation produced. Sibling of validate_k8s_detections.py.

The loop this proves:

    drop a static pod manifest on a node -> the kubelet runs it and registers a
    mirror pod -> the API server writes a `create pods` event by a node identity
    -> assert the Strategy 2 Sigma rule matches that event

It also reports the detection GAP that defines this technique: the chokepoint
(the kubelet starting a pod the API server never scheduled) leaves NO audit
event, so the evasion test (an invalid-namespace static pod) is invisible to the
audit log and must be caught by a node runtime sensor. The validator cannot
assert a node-sensor rule, so it reports the gap rather than gating on it — the
same design as validate_k8s_detections.py Procedure E.

It parses the audit log (JSON lines), then for each rule in MANIFEST checks that
at least one event matches the rule's `detection:` selection. It understands the
small slice of Sigma these rules use: plain equality, a list of values (OR), the
`|contains` modifier, and an `A and B` condition over named selections.

Modes:
    python3 detections/validate_staticpod_detections.py --dry-run
        Parse and sanity-check the rules only. No cluster or log needed.

    python3 detections/validate_staticpod_detections.py --audit-log PATH
        Full validation against the given audit log. Default strict: the Strategy
        2 rule with zero matching events fails the run (exit 1).

    ... --report
        Report misses in the summary instead of failing on them.
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
RULES_DIR = os.path.join(REPO, "detections", "sigma", "T1543.005")

# Only the audit-log rule is match-gated. The Strategy 3 file-event rule in the
# same folder is a NODE sensor rule; it is parse-linted but not exercised here,
# because it needs host file telemetry, not the API server audit log.
MANIFEST = [
    ("k8s_static_pod_mirror_create.yml", "A/B",
     "mirror pod create by a node identity (Strategy 2 fallback)"),
]

# The emulation's own static pod (Procedure A) and its evasion variant (the gap).
INJECTED_PREFIX = "trr9003-static"
GHOST_NAME = "trr9003-ghost"

# Control-plane static pods a kubeadm/kind node registers at start — the baseline
# that the Strategy 2 rule also matches, by design.
CONTROL_PLANE_PREFIXES = ("kube-apiserver-", "etcd-", "kube-controller-manager-",
                          "kube-scheduler-")


def get_field(event, dotted):
    cur = event
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def match_field(event, field_spec, value_spec):
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
    det = doc["detection"]
    for key, val in det.items():
        if key == "condition":
            continue
        if not isinstance(val, dict):
            raise ValueError(f"selection '{key}' is not a mapping")
    return doc


def load_events(audit_log):
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


def node_created_pods(events):
    """(name, namespace, user, code) for each create-pods by a system:node identity.

    `code` is responseStatus.code: 2xx for a mirror pod that was stored, non-2xx
    for a mirror-create the API server rejected (e.g. an invalid-namespace
    evasion static pod). The create attempt is audited either way.
    """
    out = []
    for e in events:
        ref = e.get("objectRef") or {}
        user = (e.get("user") or {}).get("username", "")
        if (e.get("verb") == "create" and ref.get("resource") == "pods"
                and "system:node:" in str(user)):
            code = (e.get("responseStatus") or {}).get("code")
            out.append((ref.get("name"), ref.get("namespace"), user, code))
    return out


def main():
    ap = argparse.ArgumentParser(description="Validate TRR9003 static-pod detections.")
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
    # Lint any other rule in the folder too (e.g. the Strategy 3 node rule).
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
        if os.path.basename(path) not in rules:
            try:
                load_rule(path)
                print(f"OK (parse)  {os.path.basename(path)}  [node sensor] "
                      f"not match-gated here")
            except Exception as e:  # noqa: BLE001
                parse_errors += 1
                print(f"ERROR parse {os.path.basename(path)}: {e}")

    if args.dry_run:
        print()
        if parse_errors:
            print(f"Dry run FAILED: {parse_errors} parse error(s).")
            return 1
        print(f"Dry run OK: {len(rules)} match-gated rule(s) parse and are well-formed.")
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
                  f"name={ref.get('name')} ns={ref.get('namespace')} "
                  f"user={(sample.get('user') or {}).get('username')}")
        else:
            misses += 1
            print(f"MISS  [{proc}] {fname}: no event matched")

    # Separate the emulation's own static pods from the control-plane baseline.
    created = node_created_pods(events)
    injected = [p for p in created if (p[0] or "").startswith(INJECTED_PREFIX)]
    baseline = [p for p in created
                if (p[0] or "").startswith(CONTROL_PLANE_PREFIXES)]
    evasion = [p for p in created if (p[0] or "").startswith(GHOST_NAME)]
    classified = set(injected) | set(baseline) | set(evasion)
    other = [p for p in created if p not in classified]
    print()
    print(f"Node-created pods (mirror-pod creates) seen: {len(created)}")
    if baseline:
        print(f"  baseline (control-plane static pods): "
              f"{', '.join(sorted({n for n, _, _, _ in baseline}))}")
    if injected:
        for name, ns, user, code in injected:
            print(f"  INJECTED (Procedure A): {name} in ns={ns} by {user} (code={code})")
        print("  -> the emulated static pod produced the Strategy 2 audit event.")
    else:
        print("  note: no 'trr9003-static-*' mirror pod seen. If Procedure A ran, "
              "the kubelet may not have flushed it yet, or the audit policy did "
              "not record pods create.")
    if other:
        print(f"  other node-created pods (triage): "
              f"{', '.join(sorted(n for n, _, _, _ in other))}")

    # Evasion variant and the chokepoint (informational, never gated). The
    # invalid-namespace static pod does NOT evade the audit log: the kubelet still
    # ATTEMPTS the mirror-pod create, which is audited as a FAILED (non-2xx)
    # create. What it evades is the pod OBJECT store (kubectl get pods is blind)
    # and, crucially, any record that the pod is actually RUNNING — only a node
    # runtime sensor sees that.
    print("\nEvasion variant (invalid namespace) and the Strategy 1 chokepoint:")
    if evasion:
        codes = sorted({str(c) for _, _, _, c in evasion})
        failed = [p for p in evasion
                  if not (isinstance(p[3], int) and 200 <= p[3] < 300)]
        print(f"  the invalid-namespace static pod ('{GHOST_NAME}') appears as a "
              f"mirror-create by the node, responseStatus code(s): {', '.join(codes)}.")
        if failed:
            print("  that create FAILED (non-2xx): the API server rejected the mirror "
                  "pod because the namespace does not exist, so NO pod object was "
                  "stored and 'kubectl get pods -A' is blind to it. But the attempt "
                  "is still audited, and the Strategy 2 rule matches it — a node "
                  "creating a pod into a non-existent namespace is high signal.")
        print("  What NO audit event records is the pod actually RUNNING on the node "
              "(the audit log sees the mirror attempt, not the workload). That is the "
              "gap Strategy 1 fills, and only a node runtime sensor is evasion-proof.")
    else:
        print(f"  note: no '{GHOST_NAME}' events seen (the evasion test may not have "
              "run, or the audit policy did not record failed pods create).")

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
    print("All TRR9003 match-gated detections fired on the emulated telemetry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
