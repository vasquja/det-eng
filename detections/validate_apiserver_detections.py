#!/usr/bin/env python3
"""
Validate the API-server-mediated Kubernetes detection loops on the telemetry the
emulations produced. Sibling of validate_k8s_detections.py (TRR9002) and
validate_staticpod_detections.py (TRR9003), extended to the techniques that all
key on the same API server audit log (plus one node runtime sensor rule):

  * TRR9004 (T1098.006, RBAC)            - rbac writes
  * TRR9005 (T1053.007, Jobs/CronJobs)   - batch writes + a node CRI job-pod rule
  * TRR9006 (T1552.007, Secrets)         - secret reads + TokenRequest
  * TRR9007 (T1611, dangerous pod spec)  - pod + controller requestObject
  * TRR9008 (T1685, disable or modify tools) - admissionregistration disable + grade
  * TRR9009 (T1134, impersonation)       - impersonatedUser presence
  * TRR9010 (T1070, indicator removal)   - events delete/deletecollection
  * TRR9025 (T1546, malicious admission webhook) - admissionregistration create + grade
  * TRR9026 (T1572, pod port-forward)    - pods/portforward subresource (verb-agnostic)
  * TRR9027 (T1565.001, cluster DNS poison) - kube-system DNS ConfigMap write + Corefile grade

The loop this proves, for each match-gated rule:

    emulate a procedure -> API server (or node) writes a record ->
    the paired Sigma rule, run by pySigma, matches a record the emulation made

Every emulation names its objects with a unique per-technique marker, so a rule
PASSES only when it matches an event that marker identifies as the emulation's
own -- never merely some event in the log. This matters because the shipped rules
are intentionally generic and a fresh kind cluster is full of baseline matches
(bootstrap RBAC, controller-created Jobs, controller Secret reads, kube-proxy and
kindnet privileged pods). The gate is:

  * TRR9004 / TRR9005 (audit) / TRR9007 : objectRef.name begins with 'trr9004-' /
    'trr9005-' / 'trr9007-'.
  * TRR9005 (cri)  : the pod sandbox's batch.kubernetes.io/job-name begins with
    'trr9005-'.
  * TRR9006        : objectRef.namespace is the fixed emulation namespace AND the
    caller is not a system identity (a controller reads Secrets in that namespace
    too; a 'list' has no objectRef.name, so the namespace + non-system-caller pair
    is the only gate that spans A/B/C/D).
  * TRR9025 / TRR9026 : objectRef.name begins with 'trr9025-' / 'trr9026-'.
  * TRR9027        : objectRef.name is a cluster-DNS ConfigMap (coredns / kube-dns /
    coredns-custom) in kube-system AND the write carries the 'trr9027' sentinel in its
    requestObject (the coredns ConfigMap exists at bootstrap, so the name alone is not
    enough; the sentinel identifies the emulation's own write and excludes the restore).

Rules in each technique folder that are NOT match-gated here (the Linux file-event
token-read rule, for example) are still COMPILED, so a broken rule fails the run.

Modes:
    --dry-run           Compile every rule; no cluster or log needed.
    --audit-log PATH    API server audit log (JSON lines). Default strict.
    --cri-log PATH      node runtime sensor log (crictl pods snapshots), optional.
    --expect-miss       Negative control: fail if any gated rule passes.
    --report            Report misses instead of failing on them.
"""

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA = os.path.join(REPO, "detections", "sigma")

# The fixed emulation namespace for TRR9006 (atomics/T1552.007/src/emulate.sh).
SECRET_NS = os.environ.get("TRR9006_NAMESPACE", "trr9006")


def name_prefix(prefix):
    return lambda e: (e.get("objectRef.name") or "").startswith(prefix)


def job_label_prefix(prefix):
    return lambda e: (e.get("labels.batch.kubernetes.io/job-name") or "").startswith(prefix)


def secret_gate(e):
    """TRR9006: the emulation's own read, told apart from a controller's.

    A controller reads Secrets in the new namespace too, so the namespace alone is
    not enough; require a non-system caller. Works for list (no objectRef.name),
    get, watch, and the token create -- all carry objectRef.namespace.
    """
    if e.get("objectRef.namespace") != SECRET_NS:
        return False
    return not str(e.get("user.username") or "").startswith("system:")


def impersonation_gate(e):
    """TRR9009: the emulation's own impersonation, by the unique 'trr9009' marker.

    List verbs carry no objectRef.name, so the identity marker is the anchor, not an
    object name. Procedure C borrows system:serviceaccount:trr9009:trr9009-sa, so
    'contains', not 'startswith'. The group variant marks the group instead.
    """
    u = str(e.get("impersonatedUser.username") or "")
    g = str(e.get("impersonatedUser.groups") or "")
    return "trr9009" in u or "trr9009-group" in g


def trr9010_gate(e):
    """TRR9010: a trr9010- named delete, or the bulk wipe (deletecollection) in ns.

    A deletecollection audit event carries no objectRef.name, so the name prefix
    cannot gate the bulk wipe -- the namespace plus the verb anchors it.
    """
    if (e.get("objectRef.name") or "").startswith("trr9010-"):
        return True
    return e.get("objectRef.namespace") == "trr9010" and e.get("verb") == "deletecollection"


def coredns_gate(e):
    """TRR9027: the emulation's own cluster-DNS write, told apart by the trr9027 sentinel.

    The coredns ConfigMap exists at bootstrap and kube-dns/coredns-custom may be created by
    other tooling, so name + namespace alone is not enough. The emulation injects its unique
    'trr9027' sentinel into every write's requestObject (the poisoned Corefile, the kube-dns
    stubDomains redirect, the coredns-custom snippet), recorded because the audit policy keeps
    kube-system ConfigMap writes at Request. The restore write carries the original Corefile
    and no sentinel, so it is correctly excluded.
    """
    if e.get("objectRef.namespace") != "kube-system":
        return False
    if (e.get("objectRef.name") or "") not in ("coredns", "kube-dns", "coredns-custom"):
        return False
    return any("trr9027" in str(v) for v in e.values())


# (technique folder, rule file, source, label, note, gate). Order is report order.
MANIFEST = [
    ("T1098.006", "k8s_rbac_write.yml", "audit", "9004 A-E",
     "RBAC write chokepoint", name_prefix("trr9004-")),
    ("T1098.006", "k8s_rbac_privileged_grant.yml", "audit", "9004 sev",
     "RBAC dangerous-grant severity (Request)", name_prefix("trr9004-")),
    ("T1053.007", "k8s_job_create.yml", "audit", "9005 A-D",
     "batch write chokepoint", name_prefix("trr9005-")),
    ("T1053.007", "k8s_cri_job_pod.yml", "cri", "9005 pod",
     "job pod on the node (runtime sensor)", job_label_prefix("trr9005-")),
    ("T1552.007", "k8s_secret_access.yml", "audit", "9006 A-C",
     "secret read chokepoint", secret_gate),
    ("T1552.007", "k8s_secret_token_request.yml", "audit", "9006 D",
     "TokenRequest fallback", secret_gate),
    ("T1611", "k8s_podspec_host_access.yml", "audit", "9007 A-D",
     "pod-spec host-access chokepoint (Request)", name_prefix("trr9007-")),
    ("T1611", "k8s_podspec_controller_host_access.yml", "audit", "9007 ctrl",
     "controller-template host-access (Request)", name_prefix("trr9007-")),
    ("T1685", "k8s_admission_webhook_disabled.yml", "audit", "9008 A-C",
     "admission-control disable chokepoint", name_prefix("trr9008-")),
    ("T1685", "k8s_admission_webhook_neutered.yml", "audit", "9008 sev",
     "webhook neuter severity (Request)", name_prefix("trr9008-")),
    ("T1685", "k8s_security_tool_workload_removed.yml", "audit", "9008 D",
     "enforcer workload removal fallback", name_prefix("trr9008-")),
    ("T1134", "k8s_impersonation.yml", "audit", "9009 A-D",
     "impersonation presence chokepoint", impersonation_gate),
    ("T1134", "k8s_impersonation_privileged.yml", "audit", "9009 sev",
     "privileged-identity impersonation severity", impersonation_gate),
    ("T1070", "k8s_events_deleted.yml", "audit", "9010 A-C",
     "events-deletion chokepoint (delete + deletecollection)", trr9010_gate),
    ("T1070", "k8s_workload_deleted_evidence.yml", "audit", "9010 D",
     "workload-record deletion fallback", trr9010_gate),
    ("T1546", "k8s_admission_webhook_created.yml", "audit", "9025 A-C",
     "malicious admission-webhook create chokepoint", name_prefix("trr9025-")),
    ("T1546", "k8s_malicious_admission_webhook_created.yml", "audit", "9025 sev",
     "malicious webhook grader: off-cluster url / wildcard+secrets (Request)", name_prefix("trr9025-")),
    ("T1572", "k8s_pod_portforward.yml", "audit", "9026 A-B",
     "pod port-forward chokepoint (verb-agnostic subresource)", name_prefix("trr9026-")),
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 A-C",
     "cluster DNS ConfigMap write chokepoint", coredns_gate),
    ("T1565.001", "k8s_coredns_corefile_poisoned.yml", "audit", "9027 sev",
     "CoreDNS Corefile poison grader (Request)", coredns_gate),
]

# Folders whose other rules are compiled (not match-gated) so a break still fails.
FOLDERS = sorted({folder for folder, *_ in MANIFEST})


def load_events(path):
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(sigma_eval.flatten(json.loads(line)))
            except json.JSONDecodeError:
                continue
    return events


def load_cri(path):
    """CRI pod sandboxes, flattened, one per sandbox id (first sighting).

    Each line is a `crictl pods -o json` snapshot ({"items": [...]}) or a single
    sandbox object, as detections/k8s/cri-pod-sensor.sh writes it.
    """
    seen, sandboxes = set(), []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
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


def main():
    ap = argparse.ArgumentParser(description="Validate TRR9004-9010 K8s detections.")
    ap.add_argument("--audit-log", default="/tmp/kube-apiserver-audit.log",
                    help="Path to the API server audit log (JSON lines).")
    ap.add_argument("--cri-log",
                    help="Path to the node runtime sensor log (crictl pods snapshots).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compile rules only; no cluster or log needed.")
    ap.add_argument("--expect-miss", action="store_true",
                    help="Negative control: fail if any gated rule passes.")
    ap.add_argument("--report", action="store_true",
                    help="Report misses instead of failing on them.")
    args = ap.parse_args()

    # Compile the match-gated rules.
    queries = {}
    parse_errors = 0
    gated = set()
    for folder, fname, source, label, note, _ in MANIFEST:
        key = (folder, fname)
        gated.add(key)
        try:
            queries[key] = sigma_eval.compile_rule(os.path.join(SIGMA, folder, fname))
            print(f"OK (compile)  {folder}/{fname}  [{label}, {source}] {note}")
        except Exception as e:  # noqa: BLE001
            parse_errors += 1
            print(f"ERROR compile {folder}/{fname}: {e}")
    # Compile every other rule in the four folders (not match-gated here).
    for folder in FOLDERS:
        for path in sorted(glob.glob(os.path.join(SIGMA, folder, "*.yml"))):
            key = (folder, os.path.basename(path))
            if key in gated:
                continue
            try:
                sigma_eval.compile_rule(path)
                print(f"OK (compile)  {folder}/{os.path.basename(path)}  "
                      f"[not match-gated here]")
            except Exception as e:  # noqa: BLE001
                parse_errors += 1
                print(f"ERROR compile {folder}/{os.path.basename(path)}: {e}")

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
    for folder, fname, source, label, note, gate in MANIFEST:
        key = (folder, fname)
        if key not in queries:
            continue
        if source not in logs:
            skipped += 1
            print(f"SKIP  [{label}] {fname}: no {source} log given")
            continue
        matched = [hit[0] for hit in sigma_eval.evaluate(queries[key], logs[source])]
        if source == "audit":
            matched = dedup_by_audit_id(matched)
        ours = [e for e in matched if gate(e)]
        other = len(matched) - len(ours)
        if ours:
            passes += 1
            sample = ours[0]
            print(f"PASS  [{label}] {fname}: {len(ours)} emulation record(s) match"
                  + (f" (+{other} baseline/other)" if other else ""))
            if source == "audit":
                print(f"        e.g. verb={sample.get('verb')} "
                      f"apiGroup={sample.get('objectRef.apiGroup')} "
                      f"resource={sample.get('objectRef.resource')}"
                      + (f"/{sample.get('objectRef.subresource')}"
                         if sample.get('objectRef.subresource') else "")
                      + f" name={sample.get('objectRef.name')} "
                      f"ns={sample.get('objectRef.namespace')} "
                      f"user={sample.get('user.username')}")
            else:
                print(f"        e.g. pod={sample.get('metadata.name')} "
                      f"job={sample.get('labels.batch.kubernetes.io/job-name')}")
        else:
            misses += 1
            print(f"MISS  [{label}] {fname}: no emulation record matched"
                  + (f" ({other} baseline/unrelated match(es) ignored)" if other else ""))

    print()
    if parse_errors:
        print(f"FAILED: {parse_errors} compile error(s).")
        return 1
    if args.expect_miss:
        if passes:
            print(f"NEGATIVE CONTROL FAILED: {passes} rule(s) passed on logs "
                  "captured before the emulation ran.")
            return 1
        print("Negative control held: the baseline alone does not pass any rule.")
        return 0
    if misses and not args.report:
        print(f"FAILED: {misses} rule(s) did not fire. "
              f"(Use --report to treat misses as non-fatal.)")
        return 1
    if misses:
        print(f"Reported {misses} miss(es); not gated (--report).")
        return 0
    if skipped:
        print(f"The rule(s) with a log fired on the emulated telemetry; {skipped} "
              "rule(s) skipped for lack of a log.")
        return 0
    print("All TRR9004-9010 match-gated detections fired on the emulated telemetry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
