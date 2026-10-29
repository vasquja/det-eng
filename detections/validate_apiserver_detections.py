#!/usr/bin/env python3
"""
Validate the API-server-mediated Kubernetes detection loops on the telemetry the
emulations produced. Sibling of validate_k8s_detections.py (TRR9002) and
validate_staticpod_detections.py (TRR9003), extended to the techniques that all
key on the same API server audit log (plus one node runtime sensor rule):

  * TRR9004 (T1098.006, RBAC)            - rbac writes + kube-system/aws-auth ConfigMap
                                           write
  * TRR9005 (T1053.007, Jobs/CronJobs)   - batch writes + a node CRI job-pod rule
  * TRR9006 (T1552.007, Secrets)         - secret reads + TokenRequest
  * TRR9007 (T1611, dangerous pod spec)  - pod + controller requestObject
  * TRR9008 (T1685, disable or modify tools) - admissionregistration disable + grade,
                                           and apps-group enforcer workload removal
  * TRR9009 (T1134, impersonation)       - impersonatedUser presence
  * TRR9010 (T1070, indicator removal)   - events delete/deletecollection + namespace delete
  * TRR9025 (T1546, malicious admission webhook) - admissionregistration create/SSA install
                                           + grade, and repoint grade
  * TRR9026 (T1572, pod port-forward)    - pods/portforward subresource (verb-agnostic)
                                           + nodes/proxy /portForward/ path
  * TRR9027 (T1565.001, cluster DNS poison) - kube-system and OpenShift DNS config writes
                                           + Corefile grade

The loop this proves, for each match-gated rule:

    emulate a procedure -> API server (or node) writes a record ->
    the paired Sigma rule, run by pySigma, matches a record the emulation made

Every emulation names its objects with a unique per-technique marker, so a rule
PASSES only when it matches an event that marker identifies as the emulation's
own -- never merely some event in the log. This matters because the shipped rules
are intentionally generic and a fresh kind cluster is full of baseline matches
(bootstrap RBAC, controller-created Jobs, controller Secret reads, kube-proxy and
kindnet privileged pods).

The gates are PER PROCEDURE (C1-1). A MANIFEST entry's gate is one callable (any
marked record passes) or a list of (procedure, gate) pairs; with a list, the entry
passes only when EVERY procedure has a matching record of its own, and in
--expect-miss mode it fails when ANY one procedure matches. Each pair names one
procedure's own request:

  * rec(verb, resource, sub, name | prefix, ns, user, also, code, window) builds most
    gates: the exact verb, resource and subresource, the exact object name (or a name
    prefix), the namespace, the caller (`user`) and any extra field test (`also`). For
    example TRR9004 A is `create clusterrolebindings trr9004-crb-view`, TRR9006 A-D are
    the list / get / watch / token create in the fixed namespace by a non-system caller,
    and TRR9010 B and G are the `deletecollection` of events in trr9010 by a non-system
    caller (they name no object), B in the core group and G in events.k8s.io.
  * win(gate, window) binds a helper that already encodes its own precision to the
    procedure's window: the trr9004 sentinel in kube-system/aws-auth (9004 F; the object
    name is fixed), the JSON-patch operation list (9007 K18 and E jp), the stand-in
    Deployment in a policy engine's default namespace and the kyverno namespace delete
    (9008 D2 rows; that record carries no marker, and kind has no kyverno namespace
    before d2 runs), the accepted repoint and the SSA install (9025 D), the trr9026
    marker in a nodes/proxy requestURI (9026 C; objectRef.name is the node), the
    trr9027 sentinel in each DNS ConfigMap write (9027 A-D), and the sentinel zone in
    the request body of the openshift-dns/dns-default patch (9027 E) and of the
    dnses.operator.openshift.io/default patch (9027 F); the objects that E and F create
    carry the trr9027 label, so these two gates read only the request body.
  * The response code is part of the procedure. By default (rec and win alike) a gate
    needs an accepted response, a 2xx or 101 for a streaming upgrade, so a cleanup
    DELETE that hit a 404, or a write the API server refused, cannot stand in for a
    procedure. Two procedures are refused by design and say so: TRR9009's denied
    impersonation probes (A, the trr9009-group probe, C, D and the gap) pass only on a
    403, and a 200 there fails the gate (a throwaway identity would have gained rights;
    only the system:masters list in B is a 200); and TRR9026 C's un-upgraded nodes/proxy
    GET, which the kubelet refuses, takes any code (code=None) until a live record pins
    the kubelet's refusal code.
  * '9007 static' gates the kubelet's mirror create of the TRR9007 static pod: create
    pods, a 'trr9007-escape-static-' name, a 'system:node:' caller.
  * TRR9005 (cri): the pod sandbox's batch.kubernetes.io/job-name begins with
    'trr9005-' (one gate; the node sensor has no per-procedure record).

With --ledger (C1-3), every gate that carries a window=(TRR, procedure) also needs
the record's time (requestReceivedTimestamp for an audit event, Timestamp for a node
file event) inside that procedure's [start, end] in the
emulation ledger, and the procedure's exit to equal its expected exit; a missing row
reports 'did not run'. Without --ledger the gates fall back to fields only.

The ABSENCE list asserts a documented gap with the ledger (C2-4): TRR9006 Procedure E
reads a token off the node's disk and makes no API call, so k8s_secret_access and
k8s_secret_token_request must match no event by a non-system caller in E's window.
The check fails when E did not run or failed, when its row has no window, and when a
matching event cannot be placed in time (no requestReceivedTimestamp).

The MISS_MANIFEST list asserts, with the ledger, that a rule matches none of the
emulation's own server-side dry runs (R2-d): the `dryrun` control of TRR9008, TRR9010
and TRR9025 sends each write as a server-side dry run (kubectl --dry-run=server, or a
deletecollection with a DeleteOptions body that holds dryRun All) on trr90NN-dryrun-
objects (and on the gatekeeper-system namespace that the TRR9008 control creates).
Each shape needs at least one record in the control's window (so a control that did
not run fails), the rule must match none of them, and the rule must match at least
one of them once the dry-run marker is removed (so a rule that is quiet for another
reason fails). No positive gate selects a dry-run object (DRY_RUN_PREFIXES, by name or
namespace). Without --ledger, and with --expect-miss, the checks do not run.

PROCEDURES ({(trr_id, LETTER): sorted rule paths}) is derived from the MANIFEST
labels; it is the interface for the procedure coverage report.

A node file-event source (C2-7) gates one rule that the API server cannot see:
T1552.007/linux_k8s_sa_token_read.yml. TRR9006 Procedure E reads an already-mounted
service-account token off the node and makes no API call, so no audit rule matches
it (the "9006 E gap" ABSENCE check proves that on the audit log). In CI the runner's
auditd watches one projected token file for reads: the workflow resolves the file in
the node and adds a per-file watch through /proc/<node pid>/root, because the token
is on a tmpfs that the kubelet mounts inside the node's own mount namespace, which a
host-side directory-tree watch cannot see. E reads that same file through a marked
copy of cat (/usr/local/bin/trr9006-reader), so the file-event rule has a live gate.
The records are linux/file_event JSON lines from detections/k8s/auditd_file_events.py;
a file gate places a record in its ledger window by its Timestamp field. A
false-positive control runs on the file log in strict and --expect-miss runs: the
token rule must match none of the kubelet's own reads of the watched token (an Image
whose file name is kubelet, in any directory). A log with no kubelet read gets a
notice, not a failure. Live CI has recorded no kubelet read of the watched token in
any run so far (3 of 3 runs to 2026-10-23, each watched for about 2 minutes), so this
control has had no live input; the kubelet filter is proven by the sidecar filtered
case kubelet-writes-projected-token.

Rules in each technique folder that are NOT match-gated here are still COMPILED, so a
broken rule fails the run.

Modes:
    --dry-run           Compile every rule; no cluster or log needed.
    --audit-log PATH    API server audit log (JSON lines). Default strict.
    --cri-log PATH      node runtime sensor log (crictl pods snapshots), optional.
    --file-log PATH     node file-event sensor log (linux/file_event JSON lines:
                        TargetFilename, Image, ProcessId, EventType, Timestamp), optional.
    --expect-miss       Negative control: fail if any gated rule passes.
    --report            Report misses instead of failing on them.
    --json PATH         Also write a machine-readable report (status, detail and the
                        explanation lines of every rule) to PATH.
    --ledger PATH       Emulation ledger (JSON lines, one per procedure). Binds each
                        procedure gate to its window and exit status, and runs the
                        ABSENCE and MISS_MANIFEST checks. A missing file, or a line that
                        does not parse, fails the run.
    --policy NAME       The audit policy the cluster ran: lab (default; the API server
                        lab policy, detections/k8s/audit-policy-apiserver.yaml) or
                        recommended (detections/k8s/audit-policy-recommended.yaml).
                        It selects the POLICY_GATES and EXPECTED_MISS entries below;
                        nothing else. A strict run (also with --report) under a policy
                        with such entries needs --ledger (else exit 2).

POLICY_GATES ({policy: {(rule path, MANIFEST label): {"reason", "case", "gate"}}}) names
the MANIFEST entries whose gate a policy REPLACES in a strict run, because the policy
logs the procedure's record in another shape. Under the recommended policy: 9027 D (its
opt-in kube-system ConfigMap-create line is off, so D's POST create of kube-system/
coredns reaches the log at Metadata, with no body and so no trr9027 sentinel; the
chokepoint still fires on it, and its gate takes D's accepted create by a non-system
user in D's ledger window, logged with no requestObject), and 9027 B and C (their gate
also needs the record at level RequestResponse with the sentinel in the request body,
so the run proves the policy's RequestResponse row for kube-dns and coredns-custom, not
only the requestURI). A policy gate must PASS, as every MANIFEST gate must.

EXPECTED_MISS ({policy: {(rule path, MANIFEST label): {"reason", "evidence", "fires",
"case"}}}) names the MANIFEST entries that must MISS under a policy because the policy
does not log, by design, the body that the rule needs (the recommended policy: 9027 D
create, the Corefile grader on D's Metadata create). In a strict run such an entry is
reported XMISS and does not fail the run. It FAILS the run when it passes (XPASS: the
policy now logs the record; update the map, and RECOMMENDED_OPT_IN_LOSSES in
k8s_policy_coverage.py), and (XMISS?) when its evidence gate selects no record in the
procedure's ledger window, when a selected record holds a requestObject (so the miss is
proven to come from the missing body, not from a procedure that did not run), or when
the rule's match of those records is not what "fires" says. An expected miss never makes
another entry pass. --expect-miss runs the MANIFEST gate of every entry (POLICY_GATES and
EXPECTED_MISS do not apply to the negative control: no entry may pass on the
pre-emulation log). A key of the selected policy's maps that names no MANIFEST entry, a
key in both maps, or an entry with no sidecar "case" fails the run; --dry-run checks the
maps of every policy, and the self-test of k8s_policy_coverage.py (the platform-coverage
job) also checks each "case" against the simulator.

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


def ssa_create_prefix(prefix):
    """TRR9025 K21: a server-side-apply install of a missing object, which the API
    server performs as a PATCH answered 201. Gated on the object name AND verb patch
    AND responseStatus.code 201, so it proves the create-via-apply path (the create
    rules' `verb patch and responseStatus.code 201` branch), apart from a repoint
    (a patch answered 200) and from a plain create (verb create)."""
    def gate(e):
        return ((e.get("objectRef.name") or "").startswith(prefix)
                and e.get("verb") == "patch"
                and e.get("responseStatus.code") == 201)
    gate.describe = (f"objectRef.name begins with {prefix!r}, verb == 'patch' and "
                     "responseStatus.code == 201")
    return gate


def accepted_modify(prefix, verbs=("update", "patch")):
    """TRR9025 D: an accepted modify (responseStatus.code 200) of an object whose name
    begins with `prefix`, by one of `verbs`. A refused write (403, 409, 422) still carries
    its body, so a name-only gate would pass it; this gate proves the write took effect."""
    def gate(e):
        return ((e.get("objectRef.name") or "").startswith(prefix)
                and e.get("verb") in verbs
                and e.get("responseStatus.code") == 200)
    gate.describe = (f"objectRef.name begins with {prefix!r}, verb in {list(verbs)} and "
                     "responseStatus.code == 200")
    return gate


def jsonpatch_gate(prefix, resource, subresource=None):
    """TRR9007 K18: a kubectl patch --type=json of `resource` named `prefix`* whose audit
    requestObject is the operation list (a JSON text that flattens to one `requestObject`
    field beginning with '['). This gates the JSON-patch delivery specifically: a
    strategic-merge or full-object write flattens to requestObject.spec.* instead and
    never meets it, so a pass proves the rule's requestObject|re JSON-patch branches
    fired on a real JSON patch, not a merge look-alike."""
    def gate(e):
        ro = e.get("requestObject")
        return ((e.get("objectRef.name") or "").startswith(prefix)
                and e.get("objectRef.resource") == resource
                and (subresource is None or e.get("objectRef.subresource") == subresource)
                and e.get("verb") == "patch"
                and isinstance(ro, str) and ro.lstrip().startswith("["))
    sub = f"/{subresource}" if subresource else ""
    gate.describe = (f"objectRef.name begins with {prefix!r}, resource {resource}{sub}, verb "
                     "patch, and requestObject is a JSON-patch operation list (starts with '[')")
    return gate


ENFORCER_NAMESPACES = ("gatekeeper-system", "kyverno", "falco")


def enforcer_ns(prefix, namespaces=ENFORCER_NAMESPACES):
    """TRR9008 D2: a record of an object whose name begins with `prefix` in a policy
    engine's default namespace (the stand-in Deployment in kyverno)."""
    def gate(e):
        return ((e.get("objectRef.name") or "").startswith(prefix)
                and e.get("objectRef.namespace") in namespaces)
    gate.describe = (f"objectRef.name begins with {prefix!r} and objectRef.namespace in "
                     f"{', '.join(namespaces)}")
    return gate


def enforcer_write(prefix, verb, subresource=None, resource="deployments",
                   namespaces=ENFORCER_NAMESPACES):
    """TRR9008 D2 put / patch / delete: one write of the stand-in Deployment, so that
    each branch of the alert rule that the atomic exercises is proven on its own
    record. `subresource` None is the deployments resource itself. The update (PUT) of
    deployments/scale (kubectl scale --current-replicas) holds the Scale encoded again,
    so a scale to 0 has no spec.replicas key (omitempty)."""
    in_ns = enforcer_ns(prefix, namespaces)

    def gate(e):
        return (in_ns(e) and e.get("verb") == verb
                and e.get("objectRef.resource") == resource
                and e.get("objectRef.subresource") == subresource)
    gate.describe = (f"{in_ns.describe}, verb == {verb!r}, objectRef.resource == "
                     f"{resource!r} and objectRef.subresource == {subresource!r}")
    return gate


def enforcer_namespace_delete(name):
    """TRR9008 D2 ns: the atomic's delete of the enforcer namespace `name` (kyverno).

    The record names the real namespace and carries no trr9008 marker, so the gate is
    the exact write: objectRef.resource 'namespaces', objectRef.name `name`, verb
    'delete', by a caller that is not a system identity (the namespace controller's own
    writes during the teardown are excluded; the TRR9006 pattern). The gate rests on kind
    having no such namespace before d2 runs: the atomic creates the namespace only when
    it is absent and deletes it only when it created it, and kind never has it, so the
    delete happens on every CI run and the pre-emulation log holds no such record (the
    --expect-miss negative control proves it)."""
    def gate(e):
        return (e.get("objectRef.resource") == "namespaces"
                and e.get("objectRef.name") == name
                and e.get("verb") == "delete"
                and not str(e.get("user.username") or "").startswith("system:"))
    gate.describe = (f"objectRef.resource == 'namespaces', objectRef.name == {name!r}, "
                     "verb == 'delete' and user.username not 'system:*'")
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


def aws_auth_gate(e):
    """TRR9004 F: the emulation's own aws-auth write, told apart by the trr9004 sentinel.

    aws-auth is a fixed object name (the IAM authenticator reads only kube-system/aws-auth),
    so a name-prefix gate cannot work. Name + namespace alone is not enough either: a real
    aws-auth exists on an EKS cluster. The emulation puts its unique 'trr9004' sentinel into
    the body (a create at Request and a patch at RequestResponse both carry it). Modeled on
    coredns_gate. On kind there is no aws-auth before the emulation runs, so the
    pre-emulation log cannot pass this gate.
    """
    if e.get("objectRef.namespace") != "kube-system":
        return False
    if (e.get("objectRef.name") or "") != "aws-auth":
        return False
    return any("trr9004" in str(v) for v in e.values())


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


# The sentinel ZONE of the TRR9027 E and F poisoning writes (trr9027poison.example.invalid).
# The E and F gates look for it in the request body only: every object that E and F create
# carries the label value 'trr9027' (app.kubernetes.io/part-of), so 'trr9027' alone is in
# the setup creates and in the stored object (responseObject) of every later write too.
OCP_SENTINEL_ZONE = "trr9027poison"


def _sentinel_in_request(e, token=OCP_SENTINEL_ZONE):
    """True when a requestObject field (the body the client sent) holds `token`."""
    return any(token in str(v) for k, v in e.items() if k.startswith("requestObject"))


def openshift_dns_configmap_gate(e):
    """TRR9027 E: the emulation's own poisoning write of the OpenShift DNS ConfigMap
    openshift-dns/dns-default. On kind there is no DNS Operator, so the emulation creates
    an inert dns-default of the operator's shape (labelled trr9027, no sentinel zone) and
    then patches it with the sentinel server block. The gate needs a patch or update whose
    request body holds the sentinel zone: the verb test keeps out the setup create, and the
    request-body test keeps out a patch that does not poison (the stored object of every
    patch carries the trr9027 label). The audit policy's RequestResponse rule for
    dns-default is scoped by resourceNames."""
    if e.get("objectRef.namespace") != "openshift-dns":
        return False
    if (e.get("objectRef.name") or "") != "dns-default":
        return False
    if e.get("verb") not in ("patch", "update"):
        return False
    return _sentinel_in_request(e)


openshift_dns_configmap_gate.describe = (
    "verb in ('patch', 'update'), objectRef.namespace == 'openshift-dns', objectRef.name == "
    f"'dns-default', and a requestObject field contains {OCP_SENTINEL_ZONE!r}")


def openshift_dnses_gate(e):
    """TRR9027 F: the emulation's own poisoning write of the DNS Operator object
    dnses.operator.openshift.io/default. The emulation creates the object (labelled
    trr9027, empty spec) and then patches spec.servers with the sentinel zone. The gate
    needs a patch or update of dnses/default (no subresource) whose request body holds the
    sentinel zone: the verb test keeps out the setup create and the cleanup delete, and the
    request-body test keeps out a write whose only trr9027 text is the label."""
    if e.get("objectRef.apiGroup") != "operator.openshift.io":
        return False
    if e.get("objectRef.resource") != "dnses":
        return False
    if e.get("objectRef.subresource"):
        return False
    if (e.get("objectRef.name") or "") != "default":
        return False
    if e.get("verb") not in ("patch", "update"):
        return False
    return _sentinel_in_request(e)


openshift_dnses_gate.describe = (
    "verb in ('patch', 'update'), objectRef.apiGroup == 'operator.openshift.io', "
    "objectRef.resource == 'dnses', objectRef.name == 'default', no subresource, and a "
    f"requestObject field contains {OCP_SENTINEL_ZONE!r}")


# ---- per-procedure gates (C1-1) ---------------------------------------------
# A MANIFEST entry's gate element is either ONE gate (any marked record passes the
# entry, as before) or a list of (procedure label, gate) pairs. With a list, the entry
# passes in validate mode only when EVERY procedure has a matching record of its own,
# so one procedure that fails silently (or sends a request the API server refused)
# fails the entry; in --expect-miss mode it fails if ANY one procedure matches. The
# rec() builder names one procedure's request shape, and win() binds a precise helper
# gate to its procedure's window. Both, by default, require that the API server
# accepted the request (a 2xx, or 101 for a streaming upgrade), so a cleanup DELETE
# that hit a 404, or a create the server refused, cannot stand in for the procedure.
# A procedure that is refused by design states its code: 403 for the TRR9009 probes,
# None (any code) for the TRR9026 C kubelet refusal.

ANY = object()          # rec(sub=ANY): any subresource; rec(sub=None): none
OK = "ok"               # 2xx, or 101 Switching Protocols (exec/attach/portforward)

# The dry-run step of TRR9008, TRR9010 and TRR9025 names every object it creates and
# dry-runs with one of these prefixes (R2-d, MISS_MANIFEST). No positive gate (rec()
# or win()) selects such an object, so neither a dry-run request nor the real create
# and cleanup delete of a dry-run object can stand in for a procedure.
DRY_RUN_PREFIXES = ("trr9008-dryrun-", "trr9010-dryrun-", "trr9025-dryrun-")
NOT_DRY_RUN = ("not a dry-run control object (name and namespace do not begin with "
               + ", ".join(repr(p) for p in DRY_RUN_PREFIXES) + ")")


def dry_run_object(e):
    """True for a record of a dry-run control's object: its name, or its namespace (a
    deletecollection in the control's own namespace names no object), begins with one
    of DRY_RUN_PREFIXES."""
    return any(str(e.get(f) or "").startswith(DRY_RUN_PREFIXES)
               for f in ("objectRef.name", "objectRef.namespace"))


def _code_ok(e, code):
    c = e.get("responseStatus.code")
    if code is None:
        return True
    if code == OK:
        return isinstance(c, int) and (200 <= c < 300 or c == 101)
    return c in (code if isinstance(code, (tuple, list, set)) else (code,))


def rec(*, verb=None, resource=None, sub=None, name=None, prefix=None, ns=None,
        user=None, code=OK, also=None, window=None, desc=None, dry_run=False):
    """One procedure's own audit record. `verb` is a string or a tuple; `sub` None means
    no subresource and ANY means any; `name` is exact, `prefix` a startswith; `user` and
    `also` are extra predicates (callables); `code` defaults to 2xx/101 (None skips the
    check); `window` is the (TRR, procedure) key of the emulation ledger (C1-3). A gate
    never selects a dry-run object (DRY_RUN_PREFIXES, by name or namespace) unless
    `dry_run` is True, as only the MISS_MANIFEST gates set it; `describe` says so."""
    verbs = (verb,) if isinstance(verb, str) else verb

    def gate(e):
        if not dry_run and dry_run_object(e):
            return False
        if verbs and e.get("verb") not in verbs:
            return False
        if resource is not None and e.get("objectRef.resource") != resource:
            return False
        if sub is not ANY and e.get("objectRef.subresource") != sub:
            return False
        if name is not None and e.get("objectRef.name") != name:
            return False
        if prefix is not None and not str(e.get("objectRef.name") or "").startswith(prefix):
            return False
        if ns is not None and e.get("objectRef.namespace") != ns:
            return False
        if user is not None and not user(e):
            return False
        if also is not None and not also(e):
            return False
        return _code_ok(e, code)
    parts = [f"verb in {list(verbs)}" if verbs else None,
             f"resource == {resource!r}" if resource is not None else None,
             (None if sub is ANY else (f"subresource == {sub!r}" if sub is not None
                                       else "no subresource")),
             f"name == {name!r}" if name is not None else None,
             f"name begins with {prefix!r}" if prefix is not None else None,
             f"namespace == {ns!r}" if ns is not None else None,
             getattr(user, "describe", None) if user is not None else None,
             getattr(also, "describe", None) if also is not None else None,
             ("code 2xx/101" if code == OK else f"code in {code!r}") if code is not None else None]
    text = desc or ", ".join(p for p in parts if p)
    gate.describe = text if dry_run else f"{text}, {NOT_DRY_RUN}"
    gate.window = window
    return gate


# The marked reader TRR9006 Procedure E reads the token through: a copy of cat in an
# exec-capable node directory (a kind node's /tmp is a noexec tmpfs).
READER_IMAGE = "/usr/local/bin/trr9006-reader"


def file_read(image, endswith="/token", window=None, time="Timestamp"):
    """TRR9006 Procedure E, node file sensor (C2-7): the marked reader
    (READER_IMAGE, a copy of cat the atomic uses) opens the projected
    service-account token off the node. The event is a linux/file_event record from
    auditd_file_events.py (Image, TargetFilename, Timestamp), not an audit event, so
    the gate reads Image and TargetFilename and the window reads `Timestamp`. Among
    the token rule's matches (which include the node's own workloads re-reading their
    tokens), Image tells the emulation's read apart; the kubelet is excluded by the
    rule's own filter."""
    def gate(e):
        return (e.get("Image") == image
                and str(e.get("TargetFilename") or "").endswith(endswith))
    gate.describe = f"Image == {image!r} and TargetFilename ends with {endswith!r}"
    gate.window = window
    gate.time_field = time
    return gate


# The file control (C2-7) tests the token rule's kubelet filter on live data when the
# file log holds a kubelet read. The kubelet reads each projected file before it
# decides to write a new version (kubernetes v1.36.4 pkg/volume/util/atomic_writer.go,
# shouldWriteFile: os.ReadFile of ..<timestamp>/token), so such a read can occur; live
# CI has recorded none so far (see report_file).
# kind installs the kubelet at /usr/bin/kubelet (kind v0.33.0
# pkg/build/nodeimage/buildcontext.go). A kubelet read is selected by the file name of
# its Image, in any directory, so a read with another exe spelling is still tested.
TOKEN_RULE = ("T1552.007", "linux_k8s_sa_token_read.yml")
KUBELET_NAME = "kubelet"


def _kubelet_token_reads(events):
    """The kubelet's reads of a token in a file log (Image file name, TargetFilename)."""
    return [e for e in events
            if os.path.basename(str(e.get("Image") or "")) == KUBELET_NAME
            and str(e.get("TargetFilename") or "").endswith("/token")]


def report_file(events, file_hits):
    """The token rule's false-positive control on the kubelet's own token reads.

    The rule must match none of them (filter_expected names the kubelet by its full
    path). A log can hold no such read: live CI has recorded none in any run so far (3
    of 3 runs to 2026-10-23, each watched for about 2 minutes). Then the control prints
    a notice and does not fail; the sidecar filtered case kubelet-writes-projected-token
    proves the filter offline. Returns a list of control failures (empty when the
    control holds or has nothing to test).
    """
    reads = _kubelet_token_reads(events)
    images = sorted({str(e.get("Image")) for e in reads})
    print(f"\nNode file-event sensor — file events seen: {len(events)} "
          f"({len(reads)} kubelet token read(s)"
          + (f", Image {', '.join(images)}" if images else "") + ")")
    if not reads:
        print("  notice: no kubelet token read in this log, so the kubelet filter is not "
              "tested on live data in this run (the sidecar filtered case "
              "kubelet-writes-projected-token proves it offline)")
        return []
    read_ids = {id(e) for e in reads}
    hits = [e for e in file_hits if id(e) in read_ids]
    if hits:
        failure = (f"the token rule matched {len(hits)} of the {len(reads)} kubelet token "
                   f"read(s) (Image {', '.join(sorted({str(e.get('Image')) for e in hits}))}): "
                   "its filter_expected does not hold on this sensor's exe spelling")
        print(f"  CONTROL FAILED: {failure}")
        return [failure]
    print(f"  control held: the token rule matched none of the {len(reads)} kubelet token "
          "read(s).")
    return []


def explain_file_control(rule_path, events, file_hits):
    """Why the file control failed: the kubelet read(s) the token rule matched."""
    rule = sigma_explain.load(rule_path)
    label = labeller(events)
    read_ids = {id(e) for e in _kubelet_token_reads(events)}
    hits = [e for e in file_hits if id(e) in read_ids]
    lines = ["the kubelet's own token read must never look like a credential read; the "
             "rule matched:"]
    for e in hits[:3]:
        lines.append(f"  {label(e)}")
        lines.extend("  " + ln for ln in sigma_explain.explain_hit(rule, e))
    if len(hits) > 3:
        lines.append(f"  ... and {len(hits) - 3} more")
    return lines


def non_system(e):
    return not str(e.get("user.username") or "").startswith("system:")


non_system.describe = "user.username not 'system:*'"


def node_user(e):
    return str(e.get("user.username") or "").startswith("system:node:")


node_user.describe = "user.username begins with 'system:node:'"


def field_eq(field, value):
    def gate(e):
        return e.get(field) == value
    gate.describe = f"{field} == {value!r}"
    return gate


def field_has(field, sub):
    def gate(e):
        return sub in str(e.get(field) or "")
    gate.describe = f"{field} contains {sub!r}"
    return gate


def field_in(field, values):
    def gate(e):
        return e.get(field) in values
    gate.describe = f"{field} in {', '.join(values)}"
    return gate


def core_group(e):
    return e.get("objectRef.apiGroup") in (None, "")


core_group.describe = "core API group"


def apigroup(group):
    return field_eq("objectRef.apiGroup", group)


def all_of(*gates):
    def gate(e):
        return all(g(e) for g in gates)
    gate.describe = " and ".join(getattr(g, "describe", "?") for g in gates)
    return gate


def no_field(field):
    def gate(e):
        return e.get(field) in (None, "", [], "[]")
    gate.describe = f"{field} absent"
    return gate


def procedures(entry_gate):
    """[(procedure label, gate), ...] for a MANIFEST entry's gate (one gate = one item,
    labelled None so the single-gate reporting stays as before)."""
    if isinstance(entry_gate, (list, tuple)):
        return list(entry_gate)
    return [(None, entry_gate)]


# TRR9009 impersonation identities (C1-1). The borrowed identities hold no RBAC, so A,
# B-group, C, D and the gap are DENIED (403) by design; only the system:masters list in
# B is allowed (200). The expected code is part of the procedure: a 200 on A would mean
# a throwaway identity gained rights, so the gate fails on it.
IMP_USER = "trr9009-impersonated"
NO_GROUP = all_of(no_field("impersonatedUser.uid"),
                  lambda e: "trr9009-group" not in str(e.get("impersonatedUser.groups") or "")
                  and "system:masters" not in str(e.get("impersonatedUser.groups") or ""))
NO_GROUP.describe = "no impersonated uid, no trr9009-group / system:masters group"


def imp(username, *extra):
    return all_of(field_eq("impersonatedUser.username", username), *extra)


# What each named gate requires, for the MISS explanation (the factories above set theirs).
coredns_gate.describe = ("objectRef.namespace == 'kube-system', objectRef.name in coredns / "
                         "kube-dns / coredns-custom, and some field contains 'trr9027'")
aws_auth_gate.describe = ("objectRef.namespace == 'kube-system', objectRef.name == 'aws-auth', "
                          "and some field contains 'trr9004'")


def win(gate, window, code=OK):
    """`gate` (a helper that already encodes its own precision) bound to its procedure's
    ledger window (C1-3), for a (procedure, gate) MANIFEST list. `code` is checked as in
    rec(): by default an accepted response (2xx, or 101); None skips the check, for a
    procedure whose refusal is the expected outcome and whose code is not pinned. As in
    rec(), a dry-run object (DRY_RUN_PREFIXES) is never selected."""
    def g(e):
        return not dry_run_object(e) and gate(e) and _code_ok(e, code)
    base = getattr(gate, "describe", "its MANIFEST entry")
    g.describe = (base if code is None else
                  f"{base}, code 2xx/101" if code == OK else f"{base}, code in {code!r}")
    g.describe += f", {NOT_DRY_RUN}"
    g.window = window
    return g


# (technique folder, rule file, source, label, note, gate). Order is report order.
# The gate is one callable (any marked record passes), or a list of (procedure label,
# gate) pairs: then EVERY procedure must have its own record (C1-1). A rec(window=...)
# or win(..., window) gate also binds the record to that procedure's ledger window when
# a ledger is loaded (C1-3).
MANIFEST = [
    ("T1098.006", "k8s_rbac_write.yml", "audit", "9004 A-E,G",
     "RBAC write chokepoint", [
        ("A", rec(verb="create", resource="clusterrolebindings", name="trr9004-crb-view",
                  window=("9004", "a"))),
        ("B", rec(verb="create", resource="rolebindings", name="trr9004-rb-view",
                  window=("9004", "b"))),
        ("C benign", rec(verb="create", resource="clusterroles", name="trr9004-cr-benign",
                         window=("9004", "c"))),
        ("C wild", rec(verb="create", resource="clusterroles", name="trr9004-cr-wild",
                       window=("9004", "c"))),
        ("D", rec(verb="create", resource="clusterrolebindings", name="trr9004-crb-grp",
                  window=("9004", "d"))),
        ("E", rec(verb="patch", resource="clusterroles", name="trr9004-cr-benign",
                  window=("9004", "e"))),
        ("G", rec(verb="create", resource="clusterroles", name="trr9004-cr-secrets",
                  window=("9004", "g")))]),
    # Five of the grader's branches are proven live, each by an inert graded object
    # (C2-6) in its procedure's window: C-wild (a wildcard rule), A-sev (roleRef edit,
    # cluster-wide), B-sev (roleRef edit, namespaced), D-sev (a mass-grant group
    # subject) and E-sev (a JSON patch of /rules that adds impersonate). The other
    # branches (nodes/proxy rules, a JSON patch of /subjects, a built-in admin
    # binding) and the aggregation-controller filter are proven by sidecar cases only.
    ("T1098.006", "k8s_rbac_privileged_grant.yml", "audit", "9004 sev",
     "RBAC dangerous-grant severity (Request)", [
        ("C wild", rec(verb="create", resource="clusterroles", name="trr9004-cr-wild",
                       window=("9004", "c"))),
        ("A sev", rec(verb="create", resource="clusterrolebindings", name="trr9004-crb-admin",
                      window=("9004", "a"))),
        ("B sev", rec(verb="create", resource="rolebindings", name="trr9004-rb-edit",
                      ns="trr9004-sev", window=("9004", "b"))),
        ("D sev", rec(verb="create", resource="clusterrolebindings", name="trr9004-crb-sev-grp",
                      window=("9004", "d"))),
        ("E sev", win(jsonpatch_gate("trr9004-cr-esc", "clusterroles"), ("9004", "e")))]),
    ("T1098.006", "k8s_rbac_sensitive_permission_grant.yml", "audit", "9004 sens",
     "RBAC sensitive-grant severity: exec / token / cluster-wide secrets (Request)", [
        ("G secrets", rec(verb="create", resource="clusterroles", name="trr9004-cr-secrets",
                          window=("9004", "g"))),
        ("G exec", rec(verb="create", resource="roles", name="trr9004-role-exec",
                       window=("9004", "g"))),
        ("G token", rec(verb="create", resource="roles", name="trr9004-role-token",
                        window=("9004", "g")))]),
    ("T1098.006", "k8s_eks_aws_auth_configmap_modified.yml", "audit", "9004 F",
     "EKS aws-auth ConfigMap write chokepoint",
     [("F", win(aws_auth_gate, ("9004", "f")))]),
    ("T1053.007", "k8s_job_create.yml", "audit", "9005 A-D", "batch write chokepoint", [
        ("A", rec(verb="create", resource="cronjobs", name="trr9005-cron", window=("9005", "a"))),
        ("B", rec(verb="create", resource="jobs", name="trr9005-job", window=("9005", "b"))),
        ("C", rec(verb="create", resource="jobs", name="trr9005-hostjob", window=("9005", "c"))),
        ("D", rec(verb="patch", resource="cronjobs", name="trr9005-cron", window=("9005", "d")))]),
    ("T1053.007", "k8s_cri_job_pod.yml", "cri", "9005 pod",
     "job pod on the node (runtime sensor)", job_label_prefix("trr9005-")),
    ("T1552.007", "k8s_secret_access.yml", "audit", "9006 A-C", "secret read chokepoint", [
        ("A", rec(verb="list", resource="secrets", ns=SECRET_NS, user=non_system,
                  window=("9006", "a"))),
        ("B", rec(verb="get", resource="secrets", name="trr9006-cred", ns=SECRET_NS,
                  user=non_system, window=("9006", "b"))),
        ("C", rec(verb="watch", resource="secrets", ns=SECRET_NS, user=non_system,
                  window=("9006", "c")))]),
    ("T1552.007", "k8s_secret_token_request.yml", "audit", "9006 D", "TokenRequest fallback", [
        ("D", rec(verb="create", resource="serviceaccounts", sub="token", name="trr9006-sa",
                  ns=SECRET_NS, user=non_system, window=("9006", "d")))]),
    # Strategy 3, the node file sensor (C2-7): Procedure E reads an already-mounted
    # token off the node and makes no API call, so no audit rule can see it (the
    # "9006 E gap" ABSENCE check below proves that gap on the audit log). An auditd
    # per-file read watch on the token file E reads does see the read; E reads
    # through a marked copy of cat (READER_IMAGE), so the file-event rule has a live
    # gate for the detection gap it was written to close.
    ("T1552.007", "linux_k8s_sa_token_read.yml", "file", "9006 E",
     "projected SA token read off the node (Strategy 3 file-event rule; the audit-log "
     "gap E demonstrates is proven by the 9006 E absence check)",
     [("E", file_read(READER_IMAGE, window=("9006", "e")))]),
    ("T1611", "k8s_podspec_host_access.yml", "audit", "9007 A-D",
     "pod-spec host-access chokepoint (Request)", [
        ("A", rec(verb="create", resource="pods", name="trr9007-priv", window=("9007", "a"))),
        ("B", rec(verb="create", resource="pods", name="trr9007-hostpath", window=("9007", "b"))),
        ("C", rec(verb="create", resource="pods", name="trr9007-hostns", window=("9007", "c"))),
        ("D", rec(verb="create", resource="pods", name="trr9007-caps", window=("9007", "d")))]),
    ("T1611", "k8s_podspec_host_access.yml", "audit", "9007 static",
     "static-pod delivery: the kubelet's system:node mirror create carries the spec (Request)", [
        ("static", rec(verb="create", resource="pods", prefix="trr9007-escape-static-",
                       user=node_user, window=("9007", "gap")))]),
    ("T1611", "k8s_podspec_controller_host_access.yml", "audit", "9007 ctrl",
     "controller-template host-access (Request)", [
        ("ctrl", rec(verb="create", resource="deployments", name="trr9007-depl",
                     window=("9007", "ctrl")))]),
    ("T1611", "k8s_podspec_confinement_disabled.yml", "audit", "9007 E",
     "pod-level seccomp Unconfined on a pod (Request)",
     [("E", rec(verb="create", resource="pods", name="trr9007-unconfined", sub=None,
                window=("9007", "e")))]),
    ("T1611", "k8s_podspec_confinement_disabled.yml", "audit", "9007 E aa",
     "container AppArmor Unconfined on a pod (Request)",
     [("E aa", rec(verb="create", resource="pods", name="trr9007-unconfined-aa", sub=None,
                   window=("9007", "e")))]),
    ("T1611", "k8s_podspec_confinement_disabled.yml", "audit", "9007 E ctrl",
     "seccomp Unconfined on a Deployment template (Request)",
     [("E ctrl", rec(verb="create", resource="deployments", name="trr9007-unconfined-depl",
                     sub=None, window=("9007", "e")))]),
    ("T1611", "k8s_podspec_confinement_disabled.yml", "audit", "9007 E jp",
     "seccomp Unconfined on an ephemeral container via a JSON patch (Request)",
     [("E jp", win(jsonpatch_gate("trr9007-jp-pod", "pods", "ephemeralcontainers"),
                   ("9007", "jp")))]),
    # K18: the JSON-patch delivery, proven live. A kubectl patch --type=json makes a
    # Deployment template privileged, and adds a privileged ephemeral container to a pod
    # (pods/ephemeralcontainers). The gate requires the JSON-patch operation list, so a
    # pass proves the rules' requestObject|re branches fired on a real JSON patch.
    ("T1611", "k8s_podspec_controller_host_access.yml", "audit", "9007 K18 ctrl",
     "controller host-access via a JSON patch (Request)",
     [("K18 ctrl", win(jsonpatch_gate("trr9007-jp-depl", "deployments"), ("9007", "jp")))]),
    ("T1611", "k8s_podspec_host_access.yml", "audit", "9007 K18 eph",
     "privileged ephemeral container via a JSON patch (Request)",
     [("K18 eph", win(jsonpatch_gate("trr9007-jp-pod", "pods", "ephemeralcontainers"),
                      ("9007", "jp")))]),
    ("T1685", "k8s_admission_webhook_disabled.yml", "audit", "9008 A-C",
     "admission-control disable chokepoint", [
        ("A", rec(verb="delete", resource="validatingwebhookconfigurations", name="trr9008-vwc",
                  window=("9008", "a"))),
        ("B", rec(verb="delete", resource="mutatingwebhookconfigurations", name="trr9008-mwc",
                  window=("9008", "b"))),
        ("C", rec(verb="patch", resource="validatingwebhookconfigurations", name="trr9008-neuter",
                  window=("9008", "c")))]),
    ("T1685", "k8s_admission_webhook_neutered.yml", "audit", "9008 sev",
     "webhook neuter severity (Request; RequestResponse for update/patch)", [
        ("C", rec(verb="patch", resource="validatingwebhookconfigurations", name="trr9008-neuter",
                  window=("9008", "c")))]),
    # Procedure C's other request shapes, each on its own object. merge and json leave no
    # neuter marker in the request body: only the stored object (responseObject, which
    # the policy records at RequestResponse for an update or patch) shows the lost rules.
    ("T1685", "k8s_admission_webhook_neutered.yml", "audit", "9008 C merge",
     "neuter: merge patch replaces the webhooks list without rules (responseObject)",
     [("C merge", rec(verb="patch", resource="validatingwebhookconfigurations",
                      name="trr9008-neuter-merge", window=("9008", "c")))]),
    ("T1685", "k8s_admission_webhook_neutered.yml", "audit", "9008 C json",
     "neuter: JSON patch replaces the list, one webhook loses its rules (responseObject)",
     [("C json", rec(verb="patch", resource="validatingwebhookconfigurations",
                     name="trr9008-neuter-json", window=("9008", "c")))]),
    ("T1685", "k8s_admission_webhook_neutered.yml", "audit", "9008 C const",
     "neuter: constant-false matchCondition (1 == 2)",
     [("C const", rec(verb="patch", resource="validatingwebhookconfigurations",
                      name="trr9008-neuter-const", window=("9008", "c")))]),
    ("T1685", "k8s_admission_webhook_neutered.yml", "audit", "9008 C nssel",
     "neuter: namespaceSelector that matches no namespace",
     [("C nssel", rec(verb="patch", resource="validatingwebhookconfigurations",
                      name="trr9008-neuter-nssel", window=("9008", "c")))]),
    ("T1685", "k8s_security_tool_workload_removed.yml", "audit", "9008 D",
     "enforcer workload removal anchor (any namespace)", [
        ("D patch", rec(verb="patch", resource="deployments", name="trr9008-deploy",
                        window=("9008", "d"))),
        ("D delete", rec(verb="delete", resource="deployments", name="trr9008-deploy",
                         window=("9008", "d")))]),
    ("T1685", "k8s_security_tool_workload_removed.yml", "audit", "9008 D scale",
     "enforcer scale-to-zero via kubectl scale (deployments/scale at Request)",
     [("D scale", rec(verb="patch", resource="deployments", sub="scale", name="trr9008-deploy",
                      window=("9008", "d")))]),
    ("T1685", "k8s_security_tool_workload_removed.yml", "audit", "9008 D put",
     "anchor: scale-to-zero by a PUT of deployments/scale (kubectl scale --current-replicas)",
     [("D put", win(enforcer_write("trr9008-", "update", "scale"), ("9008", "d2")))]),
    ("T1685", "k8s_enforcer_workload_removed.yml", "audit", "9008 D2",
     "enforcer workload removal in an enforcer namespace (the stand-in in kyverno)",
     [("D2", win(enforcer_ns("trr9008-"), ("9008", "d2")))]),
    ("T1685", "k8s_enforcer_workload_removed.yml", "audit", "9008 D2 put",
     "enforcer scale-to-zero by a PUT of deployments/scale (the Scale body omits replicas 0)",
     [("D2 put", win(enforcer_write("trr9008-", "update", "scale"), ("9008", "d2")))]),
    ("T1685", "k8s_enforcer_workload_removed.yml", "audit", "9008 D2 patch",
     "enforcer scale-to-zero by a patch of deployments/scale (plain kubectl scale)",
     [("D2 patch", win(enforcer_write("trr9008-", "patch", "scale"), ("9008", "d2")))]),
    ("T1685", "k8s_enforcer_workload_removed.yml", "audit", "9008 D2 delete",
     "enforcer Deployment delete in an enforcer namespace",
     [("D2 delete", win(enforcer_write("trr9008-", "delete"), ("9008", "d2")))]),
    # The enforcer-namespace delete branch of both T1685 workload rules, on d2's delete
    # of the kyverno namespace it created. No marker: the gate rests on kind having no
    # kyverno namespace before d2 (the pre-emulation negative control has no such record).
    ("T1685", "k8s_enforcer_workload_removed.yml", "audit", "9008 D2 ns",
     "enforcer namespace delete (d2 deletes the kyverno namespace it created)",
     [("D2 ns", win(enforcer_namespace_delete("kyverno"), ("9008", "d2")))]),
    ("T1685", "k8s_security_tool_workload_removed.yml", "audit", "9008 D ns",
     "anchor: enforcer namespace delete (d2 deletes the kyverno namespace it created)",
     [("D ns", win(enforcer_namespace_delete("kyverno"), ("9008", "d2")))]),
    ("T1134", "k8s_impersonation.yml", "audit", "9009 A-D",
     "impersonation presence chokepoint", [
        ("A user", rec(verb="list", resource="namespaces", code=403,
                       also=imp(IMP_USER, NO_GROUP), window=("9009", "a"))),
        ("B group", rec(verb="list", resource="namespaces", code=403,
                        also=imp(IMP_USER, field_has("impersonatedUser.groups", "trr9009-group")),
                        window=("9009", "b"))),
        ("B masters", rec(verb="list", resource="namespaces", code=200,
                          also=imp(IMP_USER, field_has("impersonatedUser.groups", "system:masters")),
                          window=("9009", "b"))),
        ("C sa", rec(verb="list", resource="namespaces", code=403,
                     also=imp("system:serviceaccount:trr9009:trr9009-sa"), window=("9009", "c"))),
        ("D uid", rec(verb="list", resource="namespaces", code=403,
                      also=imp(IMP_USER, field_eq("impersonatedUser.uid", "trr9009-uid-0001")),
                      window=("9009", "d"))),
        ("gap forbid", rec(verb="list", resource="secrets", code=403, also=imp(IMP_USER),
                           window=("9009", "gap")))]),
    ("T1134", "k8s_impersonation_privileged.yml", "audit", "9009 sev",
     "privileged-identity impersonation severity", [
        ("B masters", rec(verb="list", resource="namespaces", code=200,
                          also=imp(IMP_USER, field_has("impersonatedUser.groups", "system:masters")),
                          window=("9009", "b")))]),
    # A and C delete an Event the procedure created first, so each delete must be
    # accepted (200, the rec() default): a 404 delete of an Event whose create failed
    # does not prove the procedure. B and G are the two collection DELETEs, one per API
    # group, so each gate names its group. Each also needs a caller that is not a
    # system: identity, so without a ledger a sweep of trr9010 by a system identity
    # that the rule does not filter (kube-controller-manager without per-controller
    # credentials) cannot stand in for it. The rule's filter_namespace_teardown already
    # removes the namespace controller's own sweep, and a gate sees only rule matches.
    ("T1070", "k8s_events_deleted.yml", "audit", "9010 A-C,G",
     "events-deletion chokepoint (delete + deletecollection)", [
        ("A", rec(verb="delete", resource="events", name="trr9010-evt-a", ns="trr9010",
                  also=core_group, window=("9010", "a"))),
        ("B", rec(verb="deletecollection", resource="events", ns="trr9010",
                  user=non_system, also=core_group, window=("9010", "b"))),
        ("C", rec(verb="delete", resource="events", name="trr9010-evt-c", ns="trr9010",
                  also=apigroup("events.k8s.io"), window=("9010", "c"))),
        ("G", rec(verb="deletecollection", resource="events", ns="trr9010",
                  user=non_system, also=apigroup("events.k8s.io"),
                  window=("9010", "g")))]),
    ("T1070", "k8s_workload_deleted_evidence.yml", "audit", "9010 D",
     "workload-record deletion fallback", [
        ("D", rec(verb="delete", resource="pods", name="trr9010-workload", ns="trr9010",
                  window=("9010", "d")))]),
    ("T1070", "k8s_namespace_deleted.yml", "audit", "9010 F",
     "namespace-delete hunting rule: the actor's own accepted delete of trr9010-ns-f",
     [("F", rec(verb="delete", resource="namespaces", name="trr9010-ns-f",
                window=("9010", "f")))]),
    ("T1546", "k8s_admission_webhook_created.yml", "audit", "9025 A-C",
     "malicious admission-webhook create chokepoint", [
        ("A", rec(verb="create", resource="mutatingwebhookconfigurations", name="trr9025-mwc",
                  window=("9025", "a"))),
        ("B", rec(verb="create", resource="validatingwebhookconfigurations", name="trr9025-vwc",
                  window=("9025", "b"))),
        ("C", rec(verb="create", resource="validatingadmissionpolicies", name="trr9025-vap",
                  window=("9025", "c")))]),
    ("T1546", "k8s_malicious_admission_webhook_created.yml", "audit", "9025 sev",
     "malicious webhook grader: clientConfig.url (Request)", [
        ("A", rec(verb="create", resource="mutatingwebhookconfigurations", name="trr9025-mwc",
                  window=("9025", "a"))),
        ("B", rec(verb="create", resource="validatingwebhookconfigurations", name="trr9025-vwc",
                  window=("9025", "b")))]),
    # K21: the server-side-apply install is a PATCH answered 201. Both create rules
    # match it through their SSA-create branch; gated on trr9025-ssa-create, the new
    # URL-mode webhook the emulation installs with `kubectl apply --server-side`.
    ("T1546", "k8s_admission_webhook_created.yml", "audit", "9025 ssa-create",
     "create chokepoint on a server-side-apply install (verb patch, code 201)",
     [("D ssa-create", win(ssa_create_prefix("trr9025-ssa-create"), ("9025", "d")))]),
    ("T1546", "k8s_malicious_admission_webhook_created.yml", "audit", "9025 sev ssa-create",
     "grader on a server-side-apply URL-mode install (verb patch, code 201)",
     [("D ssa-create", win(ssa_create_prefix("trr9025-ssa-create"), ("9025", "d")))]),
    # TRR9025 Procedure D: an update or patch that repoints an installed webhook to a
    # url. Each request shape runs on its own object; each gate needs the shape's verb
    # and an accepted modify (200), so a refused write fails CI instead of passing.
    ("T1685", "k8s_admission_webhook_disabled.yml", "audit", "9025 D chk",
     "TRR9008 chokepoint on the Procedure D repoints (accepted update/patch)", [
        ("D smp", win(accepted_modify("trr9025-hijack-smp", ("patch",)), ("9025", "d"))),
        ("D json", win(accepted_modify("trr9025-hijack-json", ("patch",)), ("9025", "d"))),
        ("D put", win(accepted_modify("trr9025-hijack-put", ("update",)), ("9025", "d"))),
        ("D ssa", win(accepted_modify("trr9025-hijack-ssa", ("patch",)), ("9025", "d")))]),
    ("T1546", "k8s_admission_webhook_repointed_to_url.yml", "audit", "9025 D smp",
     "repoint grader: strategic merge patch service -> url",
     [("D smp", win(accepted_modify("trr9025-hijack-smp", ("patch",)), ("9025", "d")))]),
    ("T1546", "k8s_admission_webhook_repointed_to_url.yml", "audit", "9025 D json",
     "repoint grader: JSON patch remove service, add url",
     [("D json", win(accepted_modify("trr9025-hijack-json", ("patch",)), ("9025", "d")))]),
    ("T1546", "k8s_admission_webhook_repointed_to_url.yml", "audit", "9025 D put",
     "repoint grader: kubectl replace (PUT) with url",
     [("D put", win(accepted_modify("trr9025-hijack-put", ("update",)), ("9025", "d")))]),
    ("T1546", "k8s_admission_webhook_repointed_to_url.yml", "audit", "9025 D ssa",
     "repoint grader: server-side apply with url (patch answered 200)",
     [("D ssa", win(accepted_modify("trr9025-hijack-ssa", ("patch",)), ("9025", "d")))]),
    ("T1572", "k8s_pod_portforward.yml", "audit", "9026 A-B",
     "pod port-forward chokepoint (verb-agnostic subresource)", [
        ("A spdy", rec(verb="create", resource="pods", sub="portforward", name="trr9026-target",
                       window=("9026", "a"))),
        ("B websocket", rec(verb="get", resource="pods", sub="portforward", name="trr9026-target",
                            window=("9026", "b")))]),
    ("T1572", "k8s_node_proxy_portforward.yml", "audit", "9026 C proxy",
     "port-forward through nodes/proxy (requestURI /proxy/portForward/; objectRef.name is "
     "the node, so gate on the marker in requestURI)",
     # The kubelet REFUSES this un-upgraded GET by design (the atomic checks for the
     # refusal), so the gate takes any code: the audit record is the proof, whatever the
     # kubelet's refusal code (500 from its proxy responder in v1.36.4; not yet pinned
     # by a live record).
     [("C proxy", win(uri_contains("/trr9026-"), ("9026", "c"), code=None))]),
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 A",
     "cluster DNS ConfigMap write chokepoint: coredns patch",
     [("A", win(coredns_gate_modified("coredns"), ("9027", "a")))]),
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 B",
     "cluster DNS ConfigMap write chokepoint: kube-dns server-side apply",
     [("B", win(coredns_gate_named("kube-dns"), ("9027", "b")))]),
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 C",
     "cluster DNS ConfigMap write chokepoint: coredns-custom server-side apply",
     [("C", win(coredns_gate_named("coredns-custom"), ("9027", "c")))]),
    ("T1565.001", "k8s_coredns_corefile_poisoned.yml", "audit", "9027 sev",
     "CoreDNS Corefile poison grader on Procedure A's patch (Request)",
     [("A", win(all_of(field_eq("verb", "patch"), coredns_gate_named("coredns")),
                ("9027", "a")))]),
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 D",
     "cluster DNS ConfigMap write chokepoint: coredns deleted and created again (POST)",
     [("D", win(coredns_gate_created("coredns"), ("9027", "d")))]),
    ("T1565.001", "k8s_coredns_corefile_poisoned.yml", "audit", "9027 D create",
     "Corefile grader on a recreated coredns (create body at Request; stub-zone forward to a "
     "public IP)", [("D create", win(coredns_gate_created("coredns"), ("9027", "d")))]),
    # OpenShift (E, F): kind has no DNS Operator, so the emulation creates inert objects of
    # the operator's shape and patches them. E proves the chokepoint and the grader on
    # openshift-dns/dns-default; F proves the chokepoint on the dnses.operator.openshift.io
    # object. Each gate needs a patch or update whose request body holds the sentinel zone,
    # so the setup creates (labelled trr9027, no sentinel zone) cannot pass it. The grader
    # is not gated for F: a dnses write is not a Corefile (a real cluster's operator
    # renders it, which kind cannot do; the grader's operator-rendered positives are in
    # the sidecar).
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 E",
     "OpenShift DNS ConfigMap write chokepoint: openshift-dns/dns-default patch",
     [("E", win(openshift_dns_configmap_gate, ("9027", "e")))]),
    ("T1565.001", "k8s_coredns_corefile_poisoned.yml", "audit", "9027 E sev",
     "CoreDNS Corefile poison grader on Procedure E's dns-default patch (RequestResponse)",
     [("E", win(openshift_dns_configmap_gate, ("9027", "e")))]),
    ("T1565.001", "k8s_coredns_configmap_modified.yml", "audit", "9027 F",
     "OpenShift DNS Operator object write chokepoint: dnses.operator.openshift.io/default "
     "spec.servers patch",
     [("F", win(openshift_dnses_gate, ("9027", "f")))]),
]


# Absence checks (C2-4): with a ledger, these rules must match NOTHING in a procedure's
# window. They prove a documented gap -- a node/on-disk action that leaves no API audit
# event. Each is (label, folder, [rule file, ...], window, gate): a FAIL if any event the
# gate selects, in that window, matches one of the rules. The gate is any non-system
# caller (the operator identity the emulation runs as, in any namespace), so a
# controller's or the kubelet's own background Secret read in the window cannot flake
# the check. The check also fails when the procedure did not run, failed, has no window,
# or when a matching event has no requestReceivedTimestamp to place it in time. Without
# --ledger there is no window to bound them, so they are skipped.
ABSENCE = [
    ("9006 E gap", "T1552.007",
     ["k8s_secret_access.yml", "k8s_secret_token_request.yml"],
     ("9006", "e"), non_system),
]


# Must-not-match checks (R2-d): with a ledger, each rule here must match NONE of the
# emulation's own server-side dry runs. A dry run is authorized, admitted and answered
# 200 like the real write, but persists nothing, and each rule here has a filter for
# it. Each entry is (folder, rule file, label, gate); the gate is one callable or a list
# of (shape, gate) pairs, as in MANIFEST. Each gate selects one request of the dry-run
# step, inside the step's ledger window, by verb, resource and subresource and by a
# trr90NN-dryrun- object (DRY_RUN_PREFIXES), the control's own namespace, or the exact
# object (gatekeeper-system, which the TRR9008 control creates), and needs an accepted
# response. The gate does not test the dry-run marker (the ?dryRun=All query or the
# DeleteOptions dryRun field). Each shape passes only when all three hold:
#   * at least one record passes the gate (so a dry-run step that did not run, failed,
#     or was refused fails the check);
#   * the rule matches none of them;
#   * the rule matches at least one of them once the dry-run marker is removed (the
#     dryRun parameter of the query, and requestObject.dryRun). So the rule is quiet
#     because of its dry-run filter, not because the record lacks a field the rule
#     reads (a policy that logs the request at Metadata, or another request shape).
# The real creates of the step have another verb, and the requests that delete its
# objects are sent from the atomic's cleanup, after the step's window. The controller
# teardown that follows (the namespace controller's sweep, the kubelet's final pod
# delete) can fall in a later procedure's window; no positive gate selects a dry-run
# object, and each gate here is bound to the step's own window. Without --ledger, and
# in --expect-miss mode, the checks do not run: no window bounds them, and the
# pre-emulation log holds no dry run.
def dry(verb, resource, window, *, prefix=None, name=None, ns=None, sub=None, also=None):
    gate = rec(verb=verb, resource=resource, sub=sub, name=name, prefix=prefix, ns=ns,
               also=also, window=window, dry_run=True)

    def near(e):
        """A record of the same object (for the explanation of an empty shape)."""
        if e.get("objectRef.resource") != resource:
            return False
        return (dry_run_object(e) if prefix is not None else True) and \
            (name is None or e.get("objectRef.name") == name) and \
            (ns is None or e.get("objectRef.namespace") == ns)
    gate.near = near
    return gate


def without_dry_run(e):
    """A copy of the flattened record `e` without its dry-run marker: the dryRun
    parameter of the requestURI query and requestObject.dryRun (the DeleteOptions body)
    are removed, and every other field stays."""
    c = dict(e)
    c.pop("requestObject.dryRun", None)
    uri = c.get("requestURI")
    if isinstance(uri, str) and "?" in uri:
        path, _, query = uri.partition("?")
        params = [p for p in query.split("&") if p.split("=", 1)[0] != "dryRun"]
        c["requestURI"] = path + ("?" + "&".join(params) if params else "")
    return c


DRY_9008 = ("9008", "dryrun")
DRY_9010 = ("9010", "dryrun")
DRY_9025 = ("9025", "dryrun")
DRY_NS_9008 = "gatekeeper-system"     # the TRR9008 control's namespace (it creates it)
DRY_NS_9010 = "trr9010-dryrun-ns"     # the TRR9010 control's own namespace
IN_ENFORCER_NS = field_in("objectRef.namespace", ENFORCER_NAMESPACES)
# kubectl delete --raw of a collection URL with a DeleteOptions body: the step's dry-run
# deletecollection names its own objects in the query (a label selector).
STANDIN_SELECTOR = field_has("requestURI", "trr9008-dryrun-standin")
MISS_MANIFEST = [
    # TRR9010: kubectl delete --dry-run=server of an Event (core, and the same Event
    # through events.k8s.io), a pod, a Job and a namespace, and a deletecollection of
    # the Events (core, then events.k8s.io) and of the pods of the control's namespace
    # (kubectl delete --raw with a DeleteOptions body): the dry run is in the
    # DeleteOptions body.
    ("T1070", "k8s_events_deleted.yml", "9010 dryrun", [
        ("core", dry("delete", "events", DRY_9010, prefix="trr9010-dryrun-",
                     also=core_group)),
        ("events.k8s.io", dry("delete", "events", DRY_9010, prefix="trr9010-dryrun-",
                              also=apigroup("events.k8s.io"))),
        ("deletecollection", dry("deletecollection", "events", DRY_9010, ns=DRY_NS_9010,
                                 also=core_group)),
        ("events.k8s.io deletecollection", dry("deletecollection", "events", DRY_9010,
                                               ns=DRY_NS_9010,
                                               also=apigroup("events.k8s.io")))]),
    ("T1070", "k8s_workload_deleted_evidence.yml", "9010 dryrun", [
        ("pod", dry("delete", "pods", DRY_9010, prefix="trr9010-dryrun-")),
        ("job", dry("delete", "jobs", DRY_9010, prefix="trr9010-dryrun-")),
        ("pod deletecollection", dry("deletecollection", "pods", DRY_9010, ns=DRY_NS_9010))]),
    ("T1070", "k8s_namespace_deleted.yml", "9010 dryrun", [
        ("namespace", dry("delete", "namespaces", DRY_9010, prefix="trr9010-dryrun-"))]),
    # TRR9008: a webhook configuration (a neuter merge patch, then a delete), a
    # Deployment in an enforcer namespace (a patch of replicas 0, kubectl scale as a
    # patch and as a PUT of deployments/scale, a delete, and a deletecollection that
    # selects it by label), and that namespace itself, each --dry-run=server.
    ("T1685", "k8s_admission_webhook_disabled.yml", "9008 dryrun", [
        ("patch", dry("patch", "validatingwebhookconfigurations", DRY_9008,
                      prefix="trr9008-dryrun-")),
        ("delete", dry("delete", "validatingwebhookconfigurations", DRY_9008,
                       prefix="trr9008-dryrun-"))]),
    ("T1685", "k8s_admission_webhook_neutered.yml", "9008 dryrun", [
        ("neuter patch", dry("patch", "validatingwebhookconfigurations", DRY_9008,
                             prefix="trr9008-dryrun-"))]),
    ("T1685", "k8s_security_tool_workload_removed.yml", "9008 dryrun", [
        ("patch", dry("patch", "deployments", DRY_9008, prefix="trr9008-dryrun-")),
        ("scale patch", dry("patch", "deployments", DRY_9008, prefix="trr9008-dryrun-",
                            sub="scale")),
        ("scale put", dry("update", "deployments", DRY_9008, prefix="trr9008-dryrun-",
                          sub="scale")),
        ("delete", dry("delete", "deployments", DRY_9008, prefix="trr9008-dryrun-")),
        ("deletecollection", dry("deletecollection", "deployments", DRY_9008, ns=DRY_NS_9008,
                                 also=STANDIN_SELECTOR)),
        ("namespace delete", dry("delete", "namespaces", DRY_9008, name=DRY_NS_9008))]),
    ("T1685", "k8s_enforcer_workload_removed.yml", "9008 dryrun", [
        ("patch", dry("patch", "deployments", DRY_9008, prefix="trr9008-dryrun-",
                      also=IN_ENFORCER_NS)),
        ("scale patch", dry("patch", "deployments", DRY_9008, prefix="trr9008-dryrun-",
                            sub="scale", also=IN_ENFORCER_NS)),
        ("scale put", dry("update", "deployments", DRY_9008, prefix="trr9008-dryrun-",
                          sub="scale", also=IN_ENFORCER_NS)),
        ("delete", dry("delete", "deployments", DRY_9008, prefix="trr9008-dryrun-",
                       also=IN_ENFORCER_NS)),
        ("deletecollection", dry("deletecollection", "deployments", DRY_9008, ns=DRY_NS_9008,
                                 also=STANDIN_SELECTOR)),
        ("namespace delete", dry("delete", "namespaces", DRY_9008, name=DRY_NS_9008))]),
    # TRR9025: a strategic merge patch --dry-run=server that moves a Service-backed
    # webhook to a URL (the TRR9008 chokepoint must stay quiet on it too).
    ("T1546", "k8s_admission_webhook_repointed_to_url.yml", "9025 dryrun", [
        ("repoint patch", dry("patch", "validatingwebhookconfigurations", DRY_9025,
                              prefix="trr9025-dryrun-"))]),
    ("T1685", "k8s_admission_webhook_disabled.yml", "9025 dryrun", [
        ("repoint patch", dry("patch", "validatingwebhookconfigurations", DRY_9025,
                              prefix="trr9025-dryrun-"))]),
]


# The audit policies a run can name (--policy), and the MANIFEST entries that must MISS
# under each (see the module docstring). "evidence" is a gate that, with --ledger, must
# select at least one record in the procedure's window, and none of those records may
# hold a requestObject: the request was logged, but without the body the gate needs.
# "fires" says whether the rule itself matches an evidence record (False: the grader has
# nothing to grade); the run checks it. "case" names the rule's sidecar positive for the
# same request: k8s_policy_coverage.py's self-test checks that the simulator agrees (a
# "fires": False case is an expected opt-in loss, RECOMMENDED_OPT_IN_LOSSES), not that the
# case is the positive of this request.
POLICY_CHOICES = ("lab", "recommended")
_D_CREATE_EVIDENCE = rec(verb="create", resource="configmaps", name="coredns",
                         ns="kube-system", user=non_system, window=("9027", "d"))
EXPECTED_MISS = {
    "lab": {},
    "recommended": {
        ("T1565.001/k8s_coredns_corefile_poisoned.yml", "9027 D create"): {
            "reason": "the grader reads the Corefile in the body of D's POST create of "
                      "kube-system/coredns; the recommended policy logs that create at "
                      "Metadata (its opt-in line is off), so there is no Corefile to grade",
            "evidence": _D_CREATE_EVIDENCE, "fires": False,
            "case": "recreate-coredns-create-procD"},
    },
}


def no_request_body(e):
    """A record with no requestObject field (Metadata level, or a body the policy drops)."""
    return not any(k.startswith("requestObject") for k in e)


no_request_body.describe = "no requestObject"


def request_body_has(token):
    """A record whose requestObject (the body the client sent) holds `token`."""
    def gate(e):
        return _sentinel_in_request(e, token)
    gate.describe = f"a requestObject field contains {token!r}"
    return gate


# The MANIFEST entries whose gate a policy REPLACES in a strict run (see the module
# docstring), with the reason and the rule's sidecar positive for the same request
# ("case"; the self-test of k8s_policy_coverage.py checks that it is a positive of the
# rule and fires under that policy, not that it is the positive of this request). A
# policy gate never makes the run weaker than the policy allows: 9027 D's
# gate takes D's create with NO body (the policy is proven to drop it) in D's window,
# and the 9027 B and C gates need a RequestResponse record with the sentinel in the
# request body, where the MANIFEST gate also takes the fieldManager=trr9027-emulation of
# the requestURI. A run under a policy with a policy gate or an expected miss needs
# --ledger: without D's window the D gate would take kubeadm's bootstrap create of
# coredns, and an expected miss would have no evidence. --expect-miss runs the MANIFEST
# gates. For 9027 B and C they are wider than the policy gates. For 9027 D the MANIFEST
# gate (the sentinel) and the policy gate (no body) select different records: only D's
# ledger window tells the policy gate's record from the bootstrap create, and the
# negative control runs without a ledger, so it cannot test that gate.
POLICY_GATES = {
    "lab": {},
    "recommended": {
        ("T1565.001/k8s_coredns_configmap_modified.yml", "9027 D"): {
            "reason": "the MANIFEST gate tells D's POST create of kube-system/coredns from "
                      "the kubeadm bootstrap create by the trr9027 sentinel in its body; "
                      "the recommended policy logs that create at Metadata (its opt-in "
                      "line is off), so the gate takes D's accepted create by a non-system "
                      "user in D's ledger window, logged with no requestObject",
            "case": "coredns-recreate-create-procD",
            "gate": [("D", rec(verb="create", resource="configmaps", name="coredns",
                               ns="kube-system", user=non_system, also=no_request_body,
                               window=("9027", "d")))]},
        ("T1565.001/k8s_coredns_configmap_modified.yml", "9027 B"): {
            "reason": "the policy logs kube-dns writes at RequestResponse; the gate needs "
                      "that level and the trr9027 sentinel in the request body, so a "
                      "record logged lower (a policy that lost the row, or logs it at "
                      "Request) does not pass on the requestURI",
            "case": "kube-dns-stubdomains-ssa-procB",
            "gate": [("B", win(all_of(coredns_gate_named("kube-dns"),
                                      field_eq("level", "RequestResponse"),
                                      request_body_has("trr9027")), ("9027", "b")))]},
        ("T1565.001/k8s_coredns_configmap_modified.yml", "9027 C"): {
            "reason": "the policy logs coredns-custom writes at RequestResponse; the gate "
                      "needs that level and the trr9027 sentinel in the request body, so a "
                      "record logged lower does not pass on the requestURI",
            "case": "coredns-custom-ssa-procC",
            "gate": [("C", win(all_of(coredns_gate_named("coredns-custom"),
                                      field_eq("level", "RequestResponse"),
                                      request_body_has("trr9027")), ("9027", "c")))]},
    },
}


def expected_miss_errors(policy=None):
    """Errors in the EXPECTED_MISS and POLICY_GATES maps of the one `policy`, or of every
    policy when it is None: a policy with no map, a key that names no MANIFEST entry, a
    key in both maps, and an entry with no sidecar "case"."""
    entries = {(f"{folder}/{fname}", label) for folder, fname, _s, label, _n, _g in MANIFEST}
    pols = POLICY_CHOICES if policy is None else (policy,)
    errs = []
    for name, maps in (("EXPECTED_MISS", EXPECTED_MISS), ("POLICY_GATES", POLICY_GATES)):
        errs += [f"{name} has no map for --policy {pol!r}" for pol in pols if pol not in maps]
        errs += [f"{name}[{pol!r}] names no MANIFEST entry {key!r}"
                 for pol in pols for key in maps.get(pol, {}) if key not in entries]
        errs += [f"{name}[{pol!r}][{key!r}] has no sidecar 'case'"
                 for pol in pols for key, entry in maps.get(pol, {}).items()
                 if not isinstance(entry.get("case"), str)]
    errs += [f"EXPECTED_MISS[{pol!r}] and POLICY_GATES[{pol!r}] both name {key!r}"
             for pol in pols for key in EXPECTED_MISS.get(pol, {})
             if key in POLICY_GATES.get(pol, {})]
    return errs


def expected_miss_evidence(entry, events, ledger, matched=()):
    """Problems with an expected miss's evidence (an empty list when it holds), given the
    rule's matches `matched`. Without a ledger the evidence cannot be placed in the
    procedure's window, and that is a problem too (a strict run under such a policy
    refuses to start without --ledger)."""
    if ledger is None:
        return ["no --ledger, so the evidence cannot be placed in the procedure's window"]
    gate = windowed(entry["evidence"], ledger)
    selected = [e for e in events if gate(e)]
    if not selected:
        return [f"no record passes the evidence gate ({describe_gate(gate)}): the "
                "procedure did not run, failed, or sent another request"]
    bodied = [e for e in selected if any(k.startswith("requestObject") for k in e)]
    if bodied:
        return [f"{len(bodied)} of the {len(selected)} evidence record(s) hold a "
                "requestObject, so the policy logs the body this miss expects to be absent"]
    hit = {id(e) for e in matched}
    fired = any(id(e) in hit for e in selected)
    if "fires" in entry and fired != entry["fires"]:
        return [("the rule matches no evidence record, but EXPECTED_MISS says that it "
                 "fires on it" if entry["fires"] else
                 "the rule matches an evidence record, but EXPECTED_MISS says that it has "
                 "nothing to match there")]
    return []


# Folders whose other rules are compiled (not match-gated) so a break still fails.
FOLDERS = sorted({folder for folder, *_ in MANIFEST})


def _build_procedures():
    """PROCEDURES: {(trr_id, LETTER): sorted [rule path, ...]} for the coverage report
    and item B. A rule path like 'T1098.006/k8s_rbac_write.yml' is listed under
    (trr_id, LETTER) when that rule's MANIFEST entry gates the lettered procedure with a
    gate of its own (a (procedure, gate) pair). LETTER is the procedure letter the entry
    names (A-G): the first character of the procedure label when it is one of 'ABCDEFG',
    so 'C wild', 'D scale', 'B masters', 'D2 ns' all fold onto their letter, while a
    delivery or gap label ('ctrl', 'static', 'jp', 'K18 ...', 'gap ...', lower case or
    beyond G) names no lettered procedure and is left out. A shared single-gate entry
    (no (procedure, gate) list) selects no one procedure, so it adds nothing."""
    out = {}
    letters = "ABCDEFG"
    for folder, fname, source, label, _note, entry_gate in MANIFEST:
        if not isinstance(entry_gate, (list, tuple)):
            continue
        trr = "TRR" + label.split()[0]
        path = f"{folder}/{fname}"
        for proc, _gate in entry_gate:
            if not proc or proc[0] not in letters:
                continue
            out.setdefault((trr, proc[0]), set()).add(path)
    return {key: sorted(paths) for key, paths in out.items()}


# Interface for the coverage report (C1-7) and item B: which rule proves which
# procedure, keyed (trr_id, LETTER). Derived from the MANIFEST, so it stays in step.
PROCEDURES = _build_procedures()


# ---- the emulation ledger (procedure windows, C1-3) ------------------------
# Each emulation step appends one JSON line per procedure it ran, to $DETENG_LEDGER:
#   {"trr": "TRR9004", "procedure": "a", "start": ISO, "end": ISO, "exit": 0, "expect": 0}
# with start and end in UTC to the microsecond. With --ledger, a gate that carries a
# window=(trr, procedure) also requires the record's time (requestReceivedTimestamp for an
# audit event, Timestamp for a node file event) to fall inside that procedure's window AND the procedure to have exited as expected. That
# attributes each record to the procedure that made it, even when two procedures send
# the same request shape (a setup GET and Procedure B's GET of the same Secret), and it
# fails a procedure that did not run or that failed. Without --ledger the gates fall
# back to fields only, so a local run and an old log still work. The kind node is a
# container on the runner, so the audit timestamps and the ledger share one kernel
# clock; the procedures wait for their asynchronous writes (C1-4), so a record stays
# inside its window.


def _ts(value):
    """Parse an audit requestReceivedTimestamp or a ledger start/end to an aware
    datetime, or None. Both are RFC3339 UTC to the microsecond (metav1.MicroTime,
    `date -u +%Y-%m-%dT%H:%M:%S.%6NZ`); be liberal about the fraction and the zone, and
    read a value with no zone as UTC (both sides are UTC)."""
    from datetime import datetime, timezone
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00").replace("z", "+00:00")
    if "." in text:  # normalise the fraction to exactly 6 digits for fromisoformat
        head, _, tail = text.partition(".")
        digits = ""
        i = 0
        while i < len(tail) and tail[i].isdigit():
            digits += tail[i]
            i += 1
        text = f"{head}.{digits[:6].ljust(6, '0')}{tail[i:]}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ledger_trr(value):
    """Normalise a ledger `trr` to the bare number the gate windows use: both the
    documented 'TRR9004' and a bare '9004' key the same ('9004')."""
    text = str(value or "").strip()
    low = text.lower()
    return text[3:] if low.startswith("trr") else text


def _ledger_int(value):
    """An exit / expect value as an int ('0' and 0 alike), or None when it is not one."""
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def load_ledger(path):
    """({(trr, procedure): (start, end, exit, expect)}, [problem, ...], [note, ...])
    from a JSONL emulation ledger. `trr` is normalised to the bare number ('TRR9004' and '9004' both
    key '9004') and `procedure` to lower case. A line that does not parse, a row with no
    trr or procedure, or an exit / expect that is not an integer is a PROBLEM, named by
    its line number; the caller fails the run on any problem, so a truncated or corrupt
    ledger can never pass (and a lost row is not misreported as 'did not run' alone). A
    row whose start or end does not parse is kept with None, and its gates report
    'no start/end timestamp'. A second row for the same procedure (an atomic run twice)
    replaces the first and is only noted: the earlier run's records then fall outside
    the window, so a duplicate can make a gate miss but never pass."""
    windows, problems, notes = {}, [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
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
            key = (_ledger_trr(row.get("trr")), str(row.get("procedure")).lower())
            rc, expect = _ledger_int(row.get("exit")), _ledger_int(row.get("expect", 0))
            if rc is None or expect is None:
                problems.append(f"line {n} ({key[0]}.{key[1]}): exit {row.get('exit')!r} / "
                                f"expect {row.get('expect', 0)!r} is not an integer")
                continue
            if key in windows:
                notes.append(f"line {n} ({key[0]}.{key[1]}): a second row for this "
                             "procedure; the later row's window is used")
            windows[key] = (_ts(row.get("start")), _ts(row.get("end")), rc, expect)
    return windows, problems, notes


def ledger_state(win):
    """Why a ledger row cannot bound a gate, or None when it can."""
    if win is None:
        return "no ledger entry: the procedure did not run"
    if win[2] != win[3]:
        return f"ledger exit {win[2]} != expected {win[3]}: the procedure failed"
    if win[0] is None or win[1] is None:
        return "the ledger row has no start/end timestamp"
    return None


def in_window(e, win, field="requestReceivedTimestamp"):
    """True when the event's time field is inside [start, end] of `win`. The field is
    requestReceivedTimestamp for an audit event; a node file-event source (C2-7) names
    its own time field (Timestamp) through the gate's time_field attribute."""
    t = _ts(e.get(field))
    return t is not None and win[0] <= t <= win[1]


def windowed(gate, ledger):
    """The gate, also bound to its procedure's ledger window when a ledger is given.
    A missing row, a wrong exit, or a timestamp outside the window makes it never match,
    and `describe` says which, so the MISS explanation names the ledger reason."""
    key = getattr(gate, "window", None)
    if ledger is None or key is None:
        return gate
    win = ledger.get((key[0], str(key[1]).lower()))
    usable = ledger_state(win) is None
    field = getattr(gate, "time_field", "requestReceivedTimestamp")

    def bound(e):
        return usable and in_window(e, win, field) and gate(e)
    text = (f"{field} in [{win[0].isoformat()}, {win[1].isoformat()}]"
            if usable else ledger_state(win))
    bound.describe = f"{describe_gate(gate)}; ledger {key[0]}.{key[1]}: {text}"
    bound.window = key
    return bound


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
    """One line naming an audit event (verb, resource, name, namespace, user), a sandbox,
    or a node file event (Image, TargetFilename, EventType, pid)."""
    if "verb" not in e and "TargetFilename" in e:
        return (f"Image={e.get('Image')} TargetFilename={e.get('TargetFilename')} "
                f"EventType={e.get('EventType')} pid={e.get('ProcessId')}")
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
    rule = sigma_explain.load(rule_path).stripped()  # no null guards or copies
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


def must_not_match(args, logs, ledger, queries, results):
    """Run the MISS_MANIFEST checks (R2-d); return how many failed. Each shape of an
    entry needs at least one record its windowed gate selects, the rule must match none
    of them, and the rule must match at least one of them once the dry-run marker is
    removed (without_dry_run), so a rule that is quiet for another reason fails. The
    checks need a ledger (the window keeps the dry-run objects' real creates and
    cleanup deletes out) and do not run in --expect-miss mode."""
    if not MISS_MANIFEST or "audit" not in logs or args.expect_miss:
        if MISS_MANIFEST and args.expect_miss:
            print(f"SKIP  must-not-match: {len(MISS_MANIFEST)} dry-run check(s) do not run "
                  "in --expect-miss mode (the pre-emulation log holds no dry run)")
        return 0
    if ledger is None:
        print(f"SKIP  must-not-match: {len(MISS_MANIFEST)} dry-run check(s) need --ledger "
              "(no window bounds the dry-run step without it)")
        return 0
    events = logs["audit"]
    label_of = labeller(events)
    failed = 0
    for folder, fname, label, entry_gate in MISS_MANIFEST:
        q = queries.get((folder, fname))
        if q is None:
            continue  # a compile error, already counted
        rule_path = os.path.join(SIGMA, folder, fname)
        hit = {id(h[0]) for h in sigma_eval.evaluate(q, events)}
        shapes = []
        for shape, gate in procedures(entry_gate):
            near = getattr(gate, "near", None)
            gate = windowed(gate, ledger)
            selected = dedup_by_audit_id([e for e in events if gate(e)])
            copies = [without_dry_run(e) for e in selected]
            fires = ({id(h[0]) for h in sigma_eval.evaluate(q, copies)} if copies else set())
            shapes.append({"shape": shape, "gate": gate, "near": near, "selected": selected,
                           "matched": [e for e in selected if id(e) in hit],
                           "copies": copies,
                           "flipped": [c for c in copies if id(c) in fires]})
        for s in shapes:
            s["vacuous"] = bool(s["selected"]) and not s["matched"] and not s["flipped"]
        empty = [s for s in shapes if not s["selected"]]
        fired = [s for s in shapes if s["matched"]]
        vacuous = [s for s in shapes if s["vacuous"]]
        total = sum(len(s["selected"]) for s in shapes)
        ok = not empty and not fired and not vacuous
        explanation, why = [], []
        if ok:
            print(f"PASS  [{label}] {fname}: quiet on {total} dry-run record(s); each shape "
                  "fires once its dry-run marker is removed")
        else:
            failed += 1
            if fired:
                why.append(f"matched {sum(len(s['matched']) for s in fired)} dry-run record(s)")
            if empty:
                why.append(f"{len(empty)} shape(s) have no dry-run record")
            if vacuous:
                why.append(f"{len(vacuous)} shape(s) do not fire without the dry run either "
                           "(the quiet proves nothing about the dry-run filter)")
            print(f"MISS  [{label}] {fname}: must not match: {'; '.join(why)}")
        for s in shapes:
            shape, selected, matched = s["shape"], s["selected"], s["matched"]
            state = "MISS" if matched or not selected or s["vacuous"] else "ok  "
            print(f"        {state} {shape}: {len(selected)} dry-run record(s), "
                  f"{len(matched)} matched, {len(s['flipped'])} fire(s) without the dry run"
                  + ("" if selected else f"   [gate: {describe_gate(s['gate'])}]"))
            if matched:
                lines = [f"{shape}: the rule matched a dry run the emulation sent:"]
                for e in matched[:2]:
                    lines.append(f"  {label_of(e)} uri={e.get('requestURI')} "
                                 f"level={e.get('level')}")
                    lines += ["  " + ln for ln in explained(
                        lambda p, ev: sigma_explain.explain_hit(sigma_explain.load(p), ev),
                        rule_path, e)]
                explanation += lines
            elif not selected:
                near = [e for e in events if s["near"] is not None and s["near"](e)]
                lines = [f"{shape}: no record passes the gate; the dry-run step did not run, "
                         "failed, was refused, or sent another request shape"]
                if near:
                    lines.append(f"{len(near)} record(s) name that dry-run object or "
                                 "namespace but fail the gate (verb, code or window), e.g.:")
                    lines += [f"  {label_of(e)} at {e.get('requestReceivedTimestamp')}"
                              for e in near[:3]]
                explanation += lines
            elif s["vacuous"]:
                e = selected[0]
                lines = [f"{shape}: the rule matches none of these records with the dry-run "
                         "marker removed either, so its quiet does not show that its dry-run "
                         "filter works (the record lacks a field the rule reads: an audit "
                         "level too low, or another request shape). First record:",
                         f"  {label_of(e)} uri={e.get('requestURI')} level={e.get('level')}"]
                lines += ["  " + ln for ln in explained(
                    lambda p, evs: sigma_explain.explain_miss(
                        sigma_explain.load(p).stripped(), evs, k=1),
                    rule_path, s["copies"][:1])]
                explanation += lines
        for line in explanation:
            print("        " + line)
        results.append({"rule": f"{folder}/{fname}", "label": label, "source": "audit",
                        "check": "must-not-match",
                        "status": "PASS" if ok else "MISS",
                        "detail": "; ".join(why) or f"quiet on {total} dry-run record(s)",
                        "shapes": {s["shape"]: {"records": len(s["selected"]),
                                                "matched": len(s["matched"]),
                                                "fires_without_dry_run": len(s["flipped"])}
                                   for s in shapes},
                        "explanation": explanation})
    return failed


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
    ap.add_argument("--file-log",
                    help="Path to the node file-event sensor log (linux/file_event JSON "
                         "lines, as detections/k8s/auditd_file_events.py writes them).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compile rules only; no cluster or log needed.")
    ap.add_argument("--expect-miss", action="store_true",
                    help="Negative control: fail if any gated rule passes.")
    ap.add_argument("--report", action="store_true",
                    help="Report misses instead of failing on them.")
    ap.add_argument("--json", metavar="PATH",
                    help="Also write a machine-readable report (results + explanations).")
    ap.add_argument("--ledger", metavar="PATH",
                    help="Emulation ledger (JSONL procedure windows). Binds each procedure "
                         "gate to its procedure's time window and exit status (C1-3); without "
                         "it the gates fall back to fields only.")
    ap.add_argument("--policy", choices=POLICY_CHOICES, default="lab",
                    help="The audit policy the cluster ran (default lab). It selects the "
                         "EXPECTED_MISS entries: the rows that must miss under that policy.")
    args = ap.parse_args()
    report = {"validator": "apiserver", "policy": args.policy,
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
    # --dry-run checks every policy's map; a run on a log checks the map it uses.
    map_errors = expected_miss_errors(None if args.dry_run
                                      else getattr(args, "policy", "lab"))
    for line in map_errors:
        print(f"ERROR {line}")
    policy = getattr(args, "policy", "lab")
    expected = EXPECTED_MISS.get(policy, {})
    pgates = POLICY_GATES.get(policy, {})
    if (expected or pgates) and args.expect_miss:
        print(f"Audit policy: {policy}. EXPECTED_MISS and POLICY_GATES do not apply to the "
              "negative control: every entry runs its MANIFEST gate and must stay quiet.\n")
    elif (expected or pgates) and not args.dry_run:
        if not getattr(args, "ledger", None):
            print(f"ERROR: --policy {policy} needs --ledger: its policy gates and expected "
                  "misses are proven only in their procedure's ledger window.")
            return 2
        print(f"Audit policy: {policy}.")
        if pgates:
            print(f"  {len(pgates)} MANIFEST entr{'y' if len(pgates) == 1 else 'ies'} "
                  "run a policy gate in place of the MANIFEST gate (POLICY_GATES), and must "
                  "pass:")
            for (rule, label), entry in pgates.items():
                print(f"  [{label}] {rule}: {entry['reason']}")
        if expected:
            print(f"  {len(expected)} MANIFEST entr{'y' if len(expected) == 1 else 'ies'} "
                  "must miss, with evidence (EXPECTED_MISS):")
            for (rule, label), entry in expected.items():
                print(f"  [{label}] {rule}: {entry['reason']}")
        print()
    # Compile the match-gated rules.
    queries = {}
    parse_errors = len(map_errors)
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
    # Compile a must-not-match rule that no MANIFEST entry gates (none today).
    for folder, fname, label, _ in MISS_MANIFEST:
        key = (folder, fname)
        if key in gated:
            continue
        gated.add(key)
        try:
            queries[key] = sigma_eval.compile_rule(os.path.join(SIGMA, folder, fname))
            print(f"OK (compile)  {folder}/{fname}  [{label}, must-not-match]")
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
            print(f"Dry run FAILED: {parse_errors} compile, EXPECTED_MISS or POLICY_GATES error(s).")
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
    if args.file_log:
        if not os.path.exists(args.file_log):
            print(f"ERROR: node file-event log not found: {args.file_log}")
            return 1
        logs["file"] = load_events(args.file_log)
        print(f"Loaded {len(logs['file'])} file event(s) from {args.file_log}")
    if not logs:
        print("SKIP: no log to validate against (exit 0).")
        return 0 if not parse_errors else 1
    print()

    ledger, ledger_problems = None, []
    if args.ledger and args.expect_miss:
        # A ledger narrows every gate to a window, which would weaken the negative
        # control: it runs on the field gates only.
        print("ERROR: --ledger cannot be combined with --expect-miss (the negative control "
              "runs on the field gates only).")
        return 2
    if args.ledger:
        if not os.path.isfile(args.ledger):
            print(f"ERROR: emulation ledger not found: {args.ledger}")
            report["ledger"] = {"path": args.ledger, "problems": ["file not found"]}
            return 1
        ledger, ledger_problems, ledger_notes = load_ledger(args.ledger)
        print(f"Loaded {len(ledger)} procedure window(s) from the emulation ledger "
              f"{args.ledger}")
        for line in ledger_notes:
            print(f"  [ledger] note: {line}")
        for line in ledger_problems:
            print(f"  [ledger] PROBLEM: {line}")
        report["ledger"] = {"path": args.ledger, "windows": len(ledger),
                            "problems": ledger_problems, "notes": ledger_notes}
        print()

    passes = misses = skipped = 0
    xmisses, xfails = 0, []
    for folder, fname, source, label, note, entry_gate in MANIFEST:
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
        rule_path = os.path.join(SIGMA, folder, fname)
        tag = "trr" + label.split()[0]  # e.g. '9004 A-E' -> 'trr9004'
        # A policy gate (POLICY_GATES) replaces the MANIFEST gate in a strict run.
        pentry = None if args.expect_miss else pgates.get((f"{folder}/{fname}", label))
        if pentry is not None:
            entry_gate = pentry["gate"]
        # Each procedure of the entry needs a record of its own (C1-1); with a ledger,
        # the gate is also bound to that procedure's window and exit status (C1-3).
        procs = []
        for proc, gate in procedures(entry_gate):
            gate = windowed(gate, ledger)
            procs.append((proc, gate, [e for e in matched if gate(e)]))
        ours_ids = {id(e) for _, _, hits in procs for e in hits}
        other = len(matched) - len(ours_ids)
        every = all(hits for _, _, hits in procs)
        some = any(hits for _, _, hits in procs)
        # Validate: every procedure needs its own record. Negative control: a pass is
        # any one procedure matching in the pre-emulation log.
        passed = some if args.expect_miss else every
        # An expected miss under --policy (EXPECTED_MISS): in a strict run it must miss,
        # with its evidence; a pass, or missing evidence, fails the run.
        xentry = None if args.expect_miss else expected.get((f"{folder}/{fname}", label))
        explanation = []
        status = "PASS" if passed else "MISS"
        if xentry is not None:
            problems = expected_miss_evidence(xentry, logs[source], ledger, matched)
            if passed:
                status = "XPASS"
                detail = (f"an expected miss under --policy {args.policy} passed "
                          f"({len(ours_ids)} emulation record(s) match): the policy now "
                          "logs what EXPECTED_MISS says it does not; update EXPECTED_MISS "
                          "and RECOMMENDED_OPT_IN_LOSSES (k8s_policy_coverage.py)")
                xfails.append(f"[{label}] {fname}: {detail}")
            elif problems:
                status = "XMISS?"
                detail = (f"an expected miss under --policy {args.policy}, but its "
                          f"evidence does not hold: {'; '.join(problems)}")
                xfails.append(f"[{label}] {fname}: {detail}")
            else:
                status = "XMISS"
                xmisses += 1
                detail = (f"expected miss under --policy {args.policy}: {xentry['reason']}"
                          " (evidence: the request is logged without a body"
                          + ("; the rule fires on it)" if xentry.get("fires") else
                             "; the rule does not fire on it)"))
            print(f"{status:5} [{label}] {fname}: {detail}")
        elif passed:
            passes += 1
            detail = (f"{len(ours_ids)} emulation record(s) match"
                      + (f" (+{other} baseline/other)" if other else ""))
            print(f"PASS  [{label}] {fname}: {detail}")
        else:
            misses += 1
            detail = ("no emulation record matched" if not some else
                      "a procedure has no record of its own") + (
                f" ({other} baseline/unrelated match(es) ignored)" if other else "")
            print(f"MISS  [{label}] {fname}: {detail}")
        if pentry is not None:
            print(f"        policy gate (--policy {policy}): {pentry['reason']}")
        for proc, gate, hits in procs:
            if proc is not None:
                print(f"        {'ok  ' if hits else 'MISS'} {proc}: {len(hits)} match(es)"
                      + ("" if hits else f"   [gate: {describe_gate(gate)}]"))
        if passed and not args.expect_miss and xentry is None:
            sample = next(e for _, _, hits in procs for e in hits)
            if source == "audit":
                print(f"        e.g. verb={sample.get('verb')} "
                      f"apiGroup={sample.get('objectRef.apiGroup')} "
                      f"resource={sample.get('objectRef.resource')}"
                      + (f"/{sample.get('objectRef.subresource')}"
                         if sample.get('objectRef.subresource') else "")
                      + f" name={sample.get('objectRef.name')} "
                      f"ns={sample.get('objectRef.namespace')} "
                      f"user={sample.get('user.username')}")
            elif source == "file":
                print(f"        e.g. Image={sample.get('Image')} "
                      f"TargetFilename={sample.get('TargetFilename')} "
                      f"EventType={sample.get('EventType')}")
            else:
                print(f"        e.g. pod={sample.get('metadata.name')} "
                      f"job={sample.get('labels.batch.kubernetes.io/job-name')}")
        if passed and args.expect_miss:
            ours = [e for _, _, hits in procs for e in hits]
            explanation = explained(explain_unexpected, rule_path, logs[source], ours, tag)
        elif not passed and not args.expect_miss and xentry is None:
            for proc, gate, hits in procs:
                if hits:
                    continue
                lines = explained(explain_gated_miss, rule_path, logs[source], gate, tag, matched)
                explanation += ([f"{proc}:"] + ["  " + ln for ln in lines]) if proc else lines
        for line in explanation:
            print("        " + line)
        if source == "file" and args.expect_miss:
            # Say what the file log holds, so that an empty log is not read as
            # selectivity evidence: the gate selects the marked reader only (the file
            # control below tests the rule on the kubelet's reads).
            n = len(logs[source])
            print(f"        file log: {n} file event(s), the rule matches {len(matched)}"
                  + ("; the log is empty, so this negative control can only fail on a "
                     "stray marked-reader event" if n == 0 else ""))
        results.append({"rule": f"{folder}/{fname}", "label": label, "source": source,
                        "status": status, "detail": detail,
                        "policy_gate": pentry is not None,
                        "emulation_matches": len(ours_ids), "other_matches": other,
                        "procedures": {p: len(h) for p, _, h in procs if p is not None},
                        "explanation": explanation})

    # Absence checks (C2-4): a documented gap must leave no API event in its window. The
    # proof fails closed: the procedure must have run and exited as expected, its row
    # must carry a window, and every gate-selected match must be placeable in time.
    absent_fail = 0
    if ledger is not None and not args.expect_miss and "audit" in logs:
        for label, folder, rules, window, gate in ABSENCE:
            win = ledger.get((window[0], str(window[1]).lower()))
            state = ledger_state(win)
            hits, untimed = [], []
            if state is None:
                for fname in rules:
                    q = queries.get((folder, fname))
                    if q is None:
                        continue
                    for e in dedup_by_audit_id([h[0] for h in
                                                sigma_eval.evaluate(q, logs["audit"])]):
                        if not gate(e):
                            continue
                        if _ts(e.get("requestReceivedTimestamp")) is None:
                            untimed.append((fname, e))
                        elif in_window(e, win):
                            hits.append((fname, e))
            scope = f"from a caller the absence gate selects ({describe_gate(gate)})"
            if state is not None:
                why = f"{window[0]}.{window[1]}: {state}; the gap was not exercised"
                detail = why
                expl = []
            elif hits:
                why = (f"{hits[0][0]} matched an API event {scope} in the window; the gap is "
                       "not a gap")
                detail = f"{hits[0][0]} matched in window"
                expl = [summary(e) for _, e in hits[:3]]
            elif untimed:
                why = (f"cannot place {len(untimed)} {untimed[0][0]} match(es) {scope} in the "
                       "window (no requestReceivedTimestamp), so the absence is not proven")
                detail = "untimed match"
                expl = [f"auditID {e.get('auditID')}: {summary(e)}" for _, e in untimed[:3]]
            else:
                print(f"ok    [{label}] absence: no {' / '.join(rules)} event {scope} in "
                      f"{window[0]}.{window[1]}'s window (the documented gap holds)")
                results.append({"rule": f"{folder} absence", "label": label, "source": "audit",
                                "status": "PASS", "detail": "no API event in window",
                                "explanation": []})
                continue
            absent_fail += 1
            print(f"MISS  [{label}] absence: {why}")
            for line in expl:
                print("        " + line)
            results.append({"rule": f"{folder} absence", "label": label, "source": "audit",
                            "status": "MISS", "detail": detail, "explanation": expl})

    # Node file-event control (C2-7), in strict and --expect-miss runs: the token rule
    # must match none of the kubelet's own token reads in the file log.
    file_controls = []
    if "file" in logs and TOKEN_RULE in queries:
        file_hits = [hit[0] for hit in sigma_eval.evaluate(queries[TOKEN_RULE], logs["file"])]
        file_controls = report_file(logs["file"], file_hits)
        lines = (explained(explain_file_control, os.path.join(SIGMA, *TOKEN_RULE),
                           logs["file"], file_hits) if file_controls else [])
        for line in lines:
            print("    " + line)
        report.setdefault("controls", []).append({
            "control": "the token rule matches no kubelet token read",
            "status": "FAILED" if file_controls else "held",
            "kubelet_reads": len(_kubelet_token_reads(logs["file"])),
            "detail": "; ".join(file_controls), "explanation": lines})

    quiet_fail = must_not_match(args, logs, ledger, queries, results)

    print()
    if parse_errors:
        print(f"FAILED: {parse_errors} compile, EXPECTED_MISS or POLICY_GATES error(s).")
        return 1
    if file_controls:
        print(f"FAILED: {len(file_controls)} file control(s) failed (see CONTROL FAILED "
              "above).")
        return 1
    if args.expect_miss:
        if passes:
            print(f"NEGATIVE CONTROL FAILED: {passes} rule(s) passed on logs "
                  "captured before the emulation ran.")
            return 1
        print("Negative control held: the baseline alone does not pass any rule.")
        return 0
    if ledger_problems:
        print(f"FAILED: the emulation ledger has {len(ledger_problems)} line(s) that do not "
              "parse as a ledger row (see [ledger] PROBLEM above); a corrupt ledger proves "
              "nothing.")
        return 1
    if absent_fail:
        print(f"FAILED: {absent_fail} absence check(s) did not prove the documented gap "
              "(an API event in the window, an untimed match, or a procedure that did not "
              "run or failed).")
        return 1
    if quiet_fail:
        print(f"FAILED: {quiet_fail} must-not-match check(s) failed: a rule matched the "
              "emulation's own server-side dry run, a dry-run shape has no record (the "
              "dry-run step did not run, failed, or was refused), or a rule does not fire "
              "on a shape without its dry-run marker either.")
        return 1
    if xfails:
        print(f"FAILED: {len(xfails)} expected miss(es) under --policy {args.policy} did "
              "not hold (EXPECTED_MISS):")
        for line in xfails:
            print(f"  {line}")
        return 1
    if misses and not args.report:
        print(f"FAILED: {misses} rule(s) did not fire. "
              f"(Use --report to treat misses as non-fatal.)")
        return 1
    if misses:
        print(f"Reported {misses} miss(es); not gated (--report).")
        return 0
    xnote = (f" ({xmisses} expected miss(es) under --policy {args.policy}, each with its "
             "reason above)" if xmisses else "")
    if skipped:
        print(f"The rule(s) with a log fired on the emulated telemetry; {skipped} "
              f"rule(s) skipped for lack of a log.{xnote}")
        return 0
    print("All TRR9004-9010, 9025-9027 match-gated detections fired on the emulated "
          f"telemetry.{xnote}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
