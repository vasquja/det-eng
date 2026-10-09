#!/usr/bin/env python3
"""
Validate the TRR9003 (static pod, T1543.005) detection loop on the telemetry the
emulation produced. Sibling of validate_k8s_detections.py.

Two rules are match-gated, one per sensor:

  * Strategy 1, the chokepoint — node runtime sensor (CRI pod sandboxes):
        drop a static pod manifest on a node -> the kubelet starts the pod with
        `kubernetes.io/config.source: file` -> the CRI rule matches the sandbox.
    It must match the emulation's injected static pod AND the invalid-namespace
    variant (`trr9003-ghost`), the pod that runs on the node while the API
    server stores no object for it. That second match is the gap this rule
    closes.

  * Strategy 2, the fallback — API server audit log:
        the kubelet registers a mirror pod -> the API server writes a
        `create pods` event by a node identity -> the audit rule matches it.

Both rules also match the control-plane static pods every kubeadm node starts,
by design (a documented false positive). So a match alone proves nothing about
the emulation: a rule PASSES only if it matches the emulation's own pods. The
validator reports the baseline separately. For the CRI rule it also runs a
false-positive control: the rule must not match any sandbox the API server
scheduled (`config.source: api`), and there must be some in the log, so the
control is not vacuous.

Each log is flattened to dotted field names and each rule runs through its
pySigma-compiled query (see sigma_eval.py).

Logs:
    --audit-log PATH   API server audit log (JSON lines).
    --cri-log PATH     node runtime sensor log: one `crictl pods -o json`
                       snapshot per line, as detections/k8s/cri-pod-sensor.sh
                       writes it. Each sandbox counts once, at first sighting.

Modes:
    python3 detections/validate_staticpod_detections.py --dry-run
        Compile the rules only. No cluster or log needed.

    python3 detections/validate_staticpod_detections.py --audit-log A --cri-log C
        Full validation. Default strict: a rule that misses a required
        emulation pod, or a failed control, fails the run (exit 1). A rule whose
        log is not given is skipped.

    ... --expect-miss
        Negative control, for logs captured BEFORE the emulation ran: exit 1 if
        any rule passes. Proves the baseline alone cannot pass.

    ... --report
        Report misses in the summary instead of failing on them.
"""

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO, "detections", "sigma", "T1543.005")

# The emulation's own static pod (Procedure A) and its evasion variant (the gap).
INJECTED_PREFIX = "trr9003-static"
GHOST_NAME = "trr9003-ghost"

CONFIG_SOURCE = "annotations.kubernetes.io/config.source"


def _starts(field, prefix):
    return lambda e: (e.get(field) or "").startswith(prefix)


# Each match-gated rule: the log it reads, the procedures it covers, a note, and
# the emulation events it must match (all of them). The Strategy 3 file-event
# rule in the same folder needs node file telemetry; it is compiled, not gated.
MANIFEST = [
    ("k8s_cri_static_pod_start.yml", "cri", "A/B",
     "kubelet starts a pod from a non-API source (Strategy 1 chokepoint)",
     [("injected static pod", _starts("metadata.name", INJECTED_PREFIX)),
      ("invalid-namespace static pod (the audit-log gap)",
       _starts("metadata.name", GHOST_NAME))]),
    ("k8s_static_pod_mirror_create.yml", "audit", "A/B",
     "mirror pod create by a node identity (Strategy 2 fallback)",
     [("injected static pod", _starts("objectRef.name", INJECTED_PREFIX))]),
]

# Control-plane static pods a kubeadm/kind node starts — the baseline both rules
# also match, by design.
CONTROL_PLANE_PREFIXES = ("kube-apiserver-", "etcd-", "kube-controller-manager-",
                          "kube-scheduler-")


def load_events(audit_log):
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


def load_cri(cri_log):
    """CRI pod sandboxes, flattened, one per sandbox id (its first sighting).

    Each line is a `crictl pods -o json` snapshot ({"items": [...]}) or a single
    sandbox object. A sandbox shows up in every snapshot while it exists; a
    runtime sensor reports it once, when it starts.
    """
    seen, sandboxes = set(), []
    with open(cri_log, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue  # e.g. a snapshot cut off mid-write
            for sandbox in (doc.get("items") or []) if "items" in doc else [doc]:
                sid = sandbox.get("id")
                if sid in seen:
                    continue
                seen.add(sid)
                sandboxes.append(sigma_eval.flatten(sandbox))
    return sandboxes


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
    if name.startswith(CONTROL_PLANE_PREFIXES):
        return "baseline"
    return "other"


def report_audit(events):
    """Separate the emulation's mirror-pod creates from the control-plane baseline."""
    created = node_created_pods(events)
    kinds = {k: [p for p in created if classify(p[0]) == k]
             for k in ("baseline", "injected", "ghost", "other")}
    print(f"\nAudit log — node-created pods (mirror-pod creates) seen: {len(created)}")
    if kinds["baseline"]:
        print(f"  baseline (control-plane static pods): "
              f"{', '.join(sorted({p[0] for p in kinds['baseline']}))}")
    for name, ns, user, code in kinds["injected"]:
        print(f"  INJECTED (Procedure A): {name} in ns={ns} by {user} (code={code})")
    if not kinds["injected"]:
        print("  note: no 'trr9003-static-*' mirror pod seen.")
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


def report_cri(sandboxes, cri_hits):
    """The static sandboxes the sensor saw, and the API-pod false-positive control.

    Returns a list of control failures (empty when the control holds).
    """
    static = [s for s in sandboxes if s.get(CONFIG_SOURCE) in ("file", "http")]
    api = [s for s in sandboxes if s.get(CONFIG_SOURCE) == "api"]
    print(f"\nNode runtime sensor — pod sandboxes seen: {len(sandboxes)} "
          f"({len(static)} from file/http, {len(api)} from the API server)")
    for kind, label in (("baseline", "baseline (control-plane static pods)"),
                        ("injected", "INJECTED (Procedure A)"),
                        ("ghost", "EVASION (invalid namespace, no API object)"),
                        ("other", "other static pods (triage)")):
        names = sorted({f"{s.get('metadata.name')} in ns={s.get('metadata.namespace')}"
                        for s in static if classify(s.get("metadata.name")) == kind})
        if names:
            print(f"  {label}: {', '.join(names)}")

    failures = []
    api_hits = [s for s in cri_hits if s.get(CONFIG_SOURCE) == "api"]
    if not api:
        failures.append("no API-scheduled sandbox (config.source=api) in the CRI "
                        "log, so the false-positive control proves nothing; does "
                        "the sensor record carry the pod annotations?")
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


def main():
    ap = argparse.ArgumentParser(description="Validate TRR9003 static-pod detections.")
    ap.add_argument("--audit-log", default="/tmp/kube-apiserver-audit.log",
                    help="Path to the API server audit log (JSON lines).")
    ap.add_argument("--cri-log",
                    help="Path to the node runtime sensor log (crictl pods snapshots).")
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
    for fname, source, proc, note, _ in MANIFEST:
        try:
            queries[fname] = sigma_eval.compile_rule(os.path.join(RULES_DIR, fname))
            print(f"OK (compile)  {fname}  [{proc}, {source}] {note}")
        except Exception as e:  # noqa: BLE001
            parse_errors += 1
            print(f"ERROR compile {fname}: {e}")
    # Compile any other rule in the folder too (e.g. the Strategy 3 node rule).
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
        if os.path.basename(path) not in queries:
            try:
                sigma_eval.compile_rule(path)
                print(f"OK (compile)  {os.path.basename(path)}  [node file sensor] "
                      f"not match-gated here")
            except Exception as e:  # noqa: BLE001
                parse_errors += 1
                print(f"ERROR compile {os.path.basename(path)}: {e}")

    if args.dry_run:
        print()
        if parse_errors:
            print(f"Dry run FAILED: {parse_errors} compile error(s).")
            return 1
        print(f"Dry run OK: {len(queries)} match-gated rule(s) compile with pySigma.")
        return 0

    logs = {}
    if os.path.exists(args.audit_log):
        logs["audit"] = load_events(args.audit_log)
        print(f"\nLoaded {len(logs['audit'])} audit event(s) from {args.audit_log}")
    else:
        print(f"\nAudit log not found: {args.audit_log}")
    if args.cri_log:
        if not os.path.exists(args.cri_log):
            print(f"ERROR: CRI sensor log not found: {args.cri_log}")
            return 1
        logs["cri"] = load_cri(args.cri_log)
        print(f"Loaded {len(logs['cri'])} pod sandbox(es) from {args.cri_log}")
    if not logs:
        print("SKIP: no log to validate against (exit 0).")
        return 0 if not parse_errors else 1
    print()

    passes = misses = skipped = 0
    hits_by_source = {}
    for fname, source, proc, note, required in MANIFEST:
        if fname not in queries:
            continue
        if source not in logs:
            skipped += 1
            print(f"SKIP  [{proc}] {fname}: no {source} log given")
            continue
        matched = [hit[0] for hit in sigma_eval.evaluate(queries[fname], logs[source])]
        if source == "audit":
            matched = dedup_by_audit_id(matched)
        hits_by_source[source] = matched
        found = [(label, [e for e in matched if pred(e)]) for label, pred in required]
        ours = sum(len(events) for _, events in found)
        other = len(matched) - ours
        if all(events for _, events in found):
            passes += 1
            print(f"PASS  [{proc}] {fname}: matched every emulation pod "
                  f"(+{other} other, e.g. control-plane baseline)")
        else:
            misses += 1
            print(f"MISS  [{proc}] {fname}: missed an emulation pod"
                  + (f" ({other} baseline/unrelated match(es) ignored)" if other else ""))
        for label, events in found:
            mark = "ok  " if events else "MISS"
            print(f"        {mark} {label}: {len(events)} match(es)")

    controls = []
    if "audit" in logs:
        report_audit(logs["audit"])
    if "cri" in logs:
        controls = report_cri(logs["cri"], hits_by_source.get("cri", []))

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
                  "captured before the emulation ran.")
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
          "including the invalid-namespace pod the audit log cannot see running.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
