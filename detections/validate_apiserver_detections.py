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
  * TRR9010 (T1070, indicator removal)   - events delete/deletecollection + namespace delete
  * TRR9025 (T1546, malicious admission webhook) - admissionregistration create + grade
  * TRR9026 (T1572, pod port-forward)    - pods/portforward subresource (verb-agnostic)
                                           + nodes/proxy /portForward/ path
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
  * TRR9026 C (nodes/proxy): requestURI contains '/trr9026-' (objectRef.name is the node).
  * TRR9008 D (scale): objectRef.name begins with 'trr9008-' AND objectRef.subresource
    is 'scale' (the kubectl scale write, which the audit policy must log at Request).
  * TRR9027: objectRef.name is a cluster-DNS ConfigMap (coredns / kube-dns /
    coredns-custom) in kube-system AND the write carries the 'trr9027' sentinel in its
    requestObject (the coredns ConfigMap exists at bootstrap, so the name alone is not
    enough; the sentinel identifies the emulation's own write and excludes the
    restore). The chokepoint is gated once per procedure, on its ConfigMap's name:
    A coredns, B kube-dns, C coredns-custom, and D the create (POST) of a recreated
    coredns. A, B and C write by name (B and C by server-side apply), which the policy
    logs at RequestResponse by resourceNames; D's create names no object, and the policy
    logs it by its kube-system ConfigMap create rule at Request. Each carries its body
    and sentinel.

Rules in each technique folder that are NOT match-gated here (the Linux file-event
token-read rule, for example) are still COMPILED, so a broken rule fails the run.

Modes:
    --dry-run           Compile every rule; no cluster or log needed.
    --audit-log PATH    API server audit log (JSON lines). Default strict.
    --cri-log PATH      node runtime sensor log (crictl pods snapshots), optional.
    --expect-miss       Negative control: fail if any gated rule passes.
    --report            Report misses instead of failing on them.
    --json PATH         Also write a machine-readable report (status, detail and the
                        explanation lines of every rule) to PATH.

A MISS is explained beneath its line (sigma_explain.py): what the gate requires,
how many events carry the emulation's marker, and the marked event that came
closest to the rule, item by item. When no event carries the marker it says so
plainly, and lists events that mention the technique's tag but fail the gate. It
also names rule fields that no event in the log carries (an audit policy level
too low for requestObject, or a renamed field). A failed --expect-miss shows the
marked event(s) the rule matched in the pre-emulation log, and why it matched.
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
SIGMA = os.path.join(REPO, "detections", "sigma")

# The fixed emulation namespace for TRR9006 (atomics/T1552.007/src/emulate.sh).
SECRET_NS = os.environ.get("TRR9006_NAMESPACE", "trr9006")


def name_prefix(prefix):
    def gate(e):
        return (e.get("objectRef.name") or "").startswith(prefix)
    gate.describe = f"objectRef.name begins with {prefix!r}"  # for the MISS explanation
    return gate


def scale_subresource(prefix):
    """TRR9008 D: the kubectl scale write (the deployments/scale subresource) of an object
    whose name begins with `prefix`. Proves the audit policy logs */scale at Request: a
    Metadata record has no requestObject, so the rule cannot match it."""
    def gate(e):
        return ((e.get("objectRef.name") or "").startswith(prefix)
                and e.get("objectRef.subresource") == "scale")
    gate.describe = f"objectRef.name begins with {prefix!r} and objectRef.subresource == 'scale'"
    return gate


def job_label_prefix(prefix):
    def gate(e):
        return (e.get("labels.batch.kubernetes.io/job-name") or "").startswith(prefix)
    gate.describe = f"labels.batch.kubernetes.io/job-name begins with {prefix!r}"
    return gate


def uri_contains(sub):
    """A record whose requestURI contains `sub`. For a nodes/proxy request objectRef.name
    is the NODE name, not the emulation's target, so the emulation's marker rides in the
    requestURI (the kubelet path), which is the only field that names the target pod."""
    def gate(e):
        return sub in (e.get("requestURI") or "")
    gate.describe = f"requestURI contains {sub!r}"
    return gate


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
    other tooling, so name + namespace alone is not enough. The emulation puts its unique
    'trr9027' sentinel into every write's body. The audit policy's RequestResponse rule for
    these ConfigMaps is scoped by resourceNames, which only a request to the named object
    meets: A patches coredns, and B and C create kube-dns and coredns-custom by server-side
    apply, a PATCH to the named object. D's plain create names no object when the policy is
    evaluated, so the policy's kube-system ConfigMap create rule (Request) logs it. Each is
    logged with its body and sentinel. The restore write carries the original Corefile and
    no sentinel, so it is correctly excluded.
    """
    if e.get("objectRef.namespace") != "kube-system":
        return False
    if (e.get("objectRef.name") or "") not in ("coredns", "kube-dns", "coredns-custom"):
        return False
    return any("trr9027" in str(v) for v in e.values())


def coredns_gate_named(name):
    """TRR9027, one procedure: the sentinel-marked write to the DNS ConfigMap `name`."""
    def gate(e):
        return e.get("objectRef.name") == name and coredns_gate(e)
    gate.describe = (f"objectRef.namespace == 'kube-system', objectRef.name == {name!r}, and "
                     "some field contains 'trr9027'")
    return gate


def coredns_gate_created(name):
    """TRR9027 D: the sentinel-marked CREATE (a POST to the collection) of DNS ConfigMap
    `name`. A create names no object when the audit policy is evaluated, so only the
    policy's kube-system ConfigMap create rule (Request) puts its body, and so the
    sentinel, into the log; at Metadata no create would pass this gate."""
    def gate(e):
        return e.get("verb") == "create" and coredns_gate_named(name)(e)
    gate.describe = (f"verb == 'create', objectRef.namespace == 'kube-system', objectRef.name == "
                     f"{name!r}, and some field contains 'trr9027'")
    return gate


def coredns_gate_modified(name):
    """TRR9027 A: the sentinel-marked in-place write (patch or update, not D's create) of
    DNS ConfigMap `name`, so Procedure A is proven apart from Procedure D's re-create."""
    def gate(e):
        return e.get("verb") in ("patch", "update") and coredns_gate_named(name)(e)
    gate.describe = (f"verb in ('patch', 'update'), objectRef.namespace == 'kube-system', "
                     f"objectRef.name == {name!r}, and some field contains 'trr9027'")
    return gate


# What each named gate requires, for the MISS explanation (the factories above set theirs).
secret_gate.describe = (f"objectRef.namespace == {SECRET_NS!r} and user.username not "
                        "'system:*'")
impersonation_gate.describe = ("impersonatedUser.username contains 'trr9009' or "
                               "impersonatedUser.groups contains 'trr9009-group'")
trr9010_gate.describe = ("objectRef.name begins with 'trr9010-', or verb == deletecollection "
                         "in objectRef.namespace 'trr9010'")
coredns_gate.describe = ("objectRef.namespace == 'kube-system', objectRef.name in coredns / "
                         "kube-dns / coredns-custom, and some field contains 'trr9027'")


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
     "webhook neuter severity (Request; RequestResponse for update/patch)", name_prefix("trr9008-")),
    # Procedure C's other request shapes, each on its own object. merge and json leave no
    # neuter marker in the request body: only the stored object (responseObject, which
    # the policy records at RequestResponse for an update or patch) shows the lost rules.
    ("T1685", "k8s_admission_webhook_neutered.yml", "audit", "9008 C merge",
     "neuter: merge patch replaces the webhooks list without rules (responseObject)",
     name_prefix("trr9008-neuter-merge")),
    ("T1685", "k8s_admission_webhook_neutered.yml", "audit", "9008 C json",
     "neuter: JSON patch replaces the list, one webhook loses its rules (responseObject)",
     name_prefix("trr9008-neuter-json")),
    ("T1685", "k8s_admission_webhook_neutered.yml", "audit", "9008 C const",
     "neuter: constant-false matchCondition (1 == 2)", name_prefix("trr9008-neuter-const")),
    ("T1685", "k8s_admission_webhook_neutered.yml", "audit", "9008 C nssel",
     "neuter: namespaceSelector that matches no namespace", name_prefix("trr9008-neuter-nssel")),
    ("T1685", "k8s_security_tool_workload_removed.yml", "audit", "9008 D",
     "enforcer workload removal fallback", name_prefix("trr9008-")),
    ("T1685", "k8s_security_tool_workload_removed.yml", "audit", "9008 D scale",
     "enforcer scale-to-zero via kubectl scale (deployments/scale at Request)",
     scale_subresource("trr9008-")),
    ("T1134", "k8s_impersonation.yml", "audit", "9009 A-D",
     "impersonation presence chokepoint", impersonation_gate),
    ("T1134", "k8s_impersonation_privileged.yml", "audit", "9009 sev",
     "privileged-identity impersonation severity", impersonation_gate),
    ("T1070", "k8s_events_deleted.yml", "audit", "9010 A-C",
     "events-deletion chokepoint (delete + deletecollection)", trr9010_gate),
    ("T1070", "k8s_workload_deleted_evidence.yml", "audit", "9010 D",
     "workload-record deletion fallback", trr9010_gate),
    ("T1070", "k8s_namespace_deleted.yml", "audit", "9010 F",
     "namespace-delete hunting rule: the actor's own accepted delete of trr9010-ns-f",
     trr9010_gate),
    ("T1546", "k8s_admission_webhook_created.yml", "audit", "9025 A-C",
     "malicious admission-webhook create chokepoint", name_prefix("trr9025-")),
    ("T1546", "k8s_malicious_admission_webhook_created.yml", "audit", "9025 sev",
     "malicious webhook grader: clientConfig.url (Request)", name_prefix("trr9025-")),
    ("T1572", "k8s_pod_portforward.yml", "audit", "9026 A-B",
     "pod port-forward chokepoint (verb-agnostic subresource)", name_prefix("trr9026-")),
    ("T1572", "k8s_node_proxy_portforward.yml", "audit", "9026 C proxy",
     "port-forward through nodes/proxy (requestURI /proxy/portForward/; objectRef.name is "
     "the node, so gate on the marker in requestURI)", uri_contains("/trr9026-")),
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 A",
     "cluster DNS ConfigMap write chokepoint: coredns patch", coredns_gate_modified("coredns")),
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 B",
     "cluster DNS ConfigMap write chokepoint: kube-dns server-side apply",
     coredns_gate_named("kube-dns")),
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 C",
     "cluster DNS ConfigMap write chokepoint: coredns-custom server-side apply",
     coredns_gate_named("coredns-custom")),
    ("T1565.001", "k8s_coredns_corefile_poisoned.yml", "audit", "9027 sev",
     "CoreDNS Corefile poison grader on Procedure A's patch (Request)",
     coredns_gate_modified("coredns")),
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 D",
     "cluster DNS ConfigMap write chokepoint: coredns deleted and created again (POST)",
     coredns_gate_created("coredns")),
    ("T1565.001", "k8s_coredns_corefile_poisoned.yml", "audit", "9027 D create",
     "Corefile grader on a recreated coredns (create body at Request; stub-zone forward to a "
     "public IP)", coredns_gate_created("coredns")),
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


# ---- failure explanations (sigma_explain) --------------------------------


def summary(e):
    """One line naming an audit event (verb, resource, name, namespace, user) or a sandbox."""
    if "verb" not in e and "metadata.name" in e:
        return (f"pod={e.get('metadata.name')} ns={e.get('metadata.namespace')} "
                f"config.source={e.get('annotations.kubernetes.io/config.source')} "
                f"job={e.get('labels.batch.kubernetes.io/job-name')}")
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


def describe_gate(gate):
    doc = (gate.__doc__ or "").strip().splitlines()
    return getattr(gate, "describe", None) or (doc[0] if doc else "see its MANIFEST entry")


def absent_fields(rule, events):
    """Fields the rule's selections read that no event in the log carries."""
    fields = dict.fromkeys(f for a in rule.positive_atoms() for f in rule.fields(a))
    return [f for f in fields if all(e.get(f) is None for e in events)]


def absent_hint(fields, scope, where):
    """Name the absent fields; say whether the audit level explains them (over `scope`)."""
    hint = f"rule field(s) no event in the log carries: {', '.join(fields)}"
    for body, levels in (("requestObject", "Request or RequestResponse"),
                         ("responseObject", "RequestResponse")):
        if not any(f.startswith(body) for f in fields):
            continue
        if not any(k.startswith(body) for e in scope for k in e):
            return hint + (f"; {where} carry no {body} at all: "
                           f"the audit policy records this resource below level {levels}, "
                           "which the rule needs")
        return hint + (f"; {body} is recorded but never sets these (a field read by one OR "
                       "alternative only may be absent legitimately)")
    return hint + ("; no event of that shape reached the log, the audit policy or sensor "
                   "does not record it, or the field is named differently (casing, flattening)")


def explain_gated_miss(rule_path, events, gate, tag, matched):
    """Why no event the emulation made matched: the gate, then the closest marked event."""
    rule = sigma_explain.load(rule_path)
    label = labeller(events)
    marked = [i for i, e in enumerate(events) if gate(e)]
    lines = [f"gate: {describe_gate(gate)}"]
    if marked:
        candidates, where = marked, "the marked event(s)"
        lines.append(f"{len(marked)} event(s) carry the emulation's marker and the rule "
                     "matches none of them")
    else:
        lines.append("NO event carries the emulation's marker: the emulation may not have run, "
                     "or it named its objects differently (object name / namespace) from "
                     "what the gate expects")
        candidates = [i for i, e in enumerate(events)
                      if any(tag in str(v) for v in e.values())]
        where = f"the event(s) mentioning {tag!r}"
        hit = {id(e) for e in matched}
        fired = [i for i in candidates if id(events[i]) in hit]
        if candidates:
            lines.append(f"{len(candidates)} event(s) mention {tag!r} but fail the gate, e.g.:")
            lines.extend(f"  {label(events[i])}" for i in candidates[:3])
        if fired:
            lines.append(f"the rule DOES match {len(fired)} of them: the rule works, the gate "
                         "does not recognise the object as the emulation's (did its naming "
                         "change?)")
        elif not candidates:
            where = "the events of the whole log"
            if matched:
                lines.append(f"no event mentions {tag!r} at all, while the rule matches "
                             f"{len(matched)} other event(s): the rule and the log work, the "
                             "emulation's own records are missing (check the emulate step's "
                             "output)")
            else:
                lines.append(f"no event mentions {tag!r} at all")
                candidates = None  # nothing to narrow to: grade the whole log
    absent = absent_fields(rule, events)
    if absent:
        scope = [events[i] for i in candidates] if candidates else events
        lines.append(absent_hint(absent, scope, where))
    if candidates or candidates is None:
        lines.append(f"per block over {where}, then the closest event, item by item:")
        lines += sigma_explain.explain_miss(rule, events, k=1, candidates=candidates,
                                            label=label)
    return lines


def explain_unexpected(rule_path, events, ours, tag):
    """--expect-miss failed: the marked event(s) the rule matched, and why it fired."""
    rule = sigma_explain.load(rule_path)
    label = labeller(events)
    lines = [f"the pre-emulation log already holds {len(ours)} marked match(es); a log "
             f"captured before the emulation should hold no {tag!r} object (captured late, "
             "or left over from an earlier run?):"]
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
    ap = argparse.ArgumentParser(description="Validate TRR9004-9010, 9025-9027 K8s detections.")
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
    ap.add_argument("--json", metavar="PATH",
                    help="Also write a machine-readable report (results + explanations).")
    args = ap.parse_args()
    report = {"validator": "apiserver",
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
            results.append({"rule": f"{folder}/{fname}", "label": label, "status": "ERROR",
                            "detail": f"compile: {e}", "explanation": []})
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
                results.append({"rule": f"{folder}/{os.path.basename(path)}",
                                "status": "ERROR", "detail": f"compile: {e}",
                                "explanation": []})

    if args.dry_run:
        results.extend({"rule": f"{folder}/{fname}", "status": "OK", "detail": "compiles",
                        "explanation": []} for folder, fname in queries)
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
            results.append({"rule": f"{folder}/{fname}", "label": label, "source": source,
                            "status": "SKIP", "detail": f"no {source} log given",
                            "explanation": []})
            continue
        matched = [hit[0] for hit in sigma_eval.evaluate(queries[key], logs[source])]
        if source == "audit":
            matched = dedup_by_audit_id(matched)
        ours = [e for e in matched if gate(e)]
        other = len(matched) - len(ours)
        rule_path = os.path.join(SIGMA, folder, fname)
        tag = "trr" + label.split()[0]  # e.g. '9004 A-E' -> 'trr9004'
        explanation = []
        if ours:
            passes += 1
            sample = ours[0]
            detail = (f"{len(ours)} emulation record(s) match"
                      + (f" (+{other} baseline/other)" if other else ""))
            print(f"PASS  [{label}] {fname}: {detail}")
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
            if args.expect_miss:
                explanation = explained(explain_unexpected, rule_path, logs[source], ours, tag)
        else:
            misses += 1
            detail = ("no emulation record matched"
                      + (f" ({other} baseline/unrelated match(es) ignored)" if other else ""))
            print(f"MISS  [{label}] {fname}: {detail}")
            if not args.expect_miss:
                explanation = explained(explain_gated_miss, rule_path, logs[source], gate,
                                        tag, matched)
        for line in explanation:
            print("        " + line)
        results.append({"rule": f"{folder}/{fname}", "label": label, "source": source,
                        "status": "PASS" if ours else "MISS", "detail": detail,
                        "emulation_matches": len(ours), "other_matches": other,
                        "explanation": explanation})

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
    print("All TRR9004-9010, 9025-9027 match-gated detections fired on the emulated telemetry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
