# Disabling Admission Control (Kubernetes)

> Prose uses Simplified Technical English (ASD-STE100) where practical.
> API group names, resource names, verbs, field names, and ATT&CK IDs are
> technical names.

## Metadata

| Key          | Value |
|--------------|-------|
| ID           | TRR9008 |
| External IDs | T1685 |
| Tactics      | Defense Impairment |
| Platforms    | Kubernetes |
| Contributors | det-eng |
| Status       | draft |

### Scope Statement

This TRR covers Defense Impairment through **disabling dynamic admission control**:
removing or disarming the admission webhooks and CEL policies that enforce
Kubernetes security policy, and removing the workload that serves them.

This TRR does not cover these related actions:

- Creating a *malicious* admission webhook (a mutating webhook that injects a
  sidecar, or a webhook that exfiltrates every admitted object), or repointing an
  installed one to an attacker URL. That is persistence (Event Triggered Execution,
  T1546), a different technique. [TRR9025](../../trr9025/k8s/README.md) covers it. A
  repoint is an `update` or `patch`, so this report's chokepoint
  (`k8s_admission_webhook_disabled`) fires on it at medium; TRR9025's Procedure D
  grader reads the new `clientConfig.url` and grades it high. This report covers only
  the disabling verbs on existing admission objects, not the intent of the new
  endpoint.
- The RBAC grant that lets an adversary write admission objects. TRR9004
  (T1098.006) detects the grant; this report detects the use. An attacker
  usually needs the grant first, so the two are correlated but distinct.

> ATT&CK has no Kubernetes-specific defense-impairment sub-technique, and T1685
> (Disable or Modify Tools) lists Containers among its platforms, so it is the
> correct and defensible mapping for neutering the policy engine. This report
> covers Kubernetes only. The repository's Linux io_uring rule
> ([`detections/sigma/T1685/io_uring_setup.yml`](../../../detections/sigma/T1685/io_uring_setup.yml))
> also carries T1685 and has no TRR.

## Technique Overview

Kubernetes enforces most of its runtime security policy through dynamic admission
control. Before any create, update, or delete is stored, the API server sends it
to the admission webhooks registered in two cluster-scoped objects, a
ValidatingWebhookConfiguration and a MutatingWebhookConfiguration. These webhooks
are how OPA/Gatekeeper, Kyverno, image-signature verifiers, and Falco admission
paths say "no" to a dangerous pod, an unsigned image, or a privilege grab. The
same API group now also holds the CEL ValidatingAdmissionPolicy and its binding.

An adversary who has gained write access to these objects does not need an
exploit to get past the policy engine. They turn it off. They delete the webhook
configuration so nothing validates admission; they leave it in place but neuter
it, setting failurePolicy to Ignore so an outage is silently allowed, or emptying
the rules so it never fires; or they leave admission alone and remove the enforcer
itself, deleting the Gatekeeper, Kyverno, or Falco workload (or scaling a
Deployment to zero) so the webhook endpoint is gone. After any of these, the next malicious pod, the next
unsigned image, the next privileged workload sails through. It is a one-request
defense-impairment step that clears the way for everything else.

## Technical Background

### The objects and the knobs

A ValidatingWebhookConfiguration or MutatingWebhookConfiguration is a
cluster-scoped object in admissionregistration.k8s.io/v1. Each carries a webhooks
list; each webhook has a clientConfig (the service or URL to call), rules (which
apiGroups, apiVersions, resources, and operations trigger it), namespaceSelector
and objectSelector (label selectors that further gate it), and failurePolicy (Fail
or Ignore, default Fail). When the API server cannot reach the webhook, Fail
rejects the request (fail-closed) and Ignore allows it (fail-open). Every neuter
is a knob on this object: failurePolicy to Ignore plus a dead endpoint allows
everything; an empty rules list or an impossible selector means the webhook never
fires. The CEL ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding live
in the same API group, so one group-scoped rule is the invariant across webhook
and policy objects.

### The audit shape, and the two levels

Every disabling path is a write to the admissionregistration.k8s.io group. The
HTTP method maps to the audit verb: DELETE (single) to delete, DELETE (collection)
to deletecollection, PUT to update, PATCH to patch. There is no replace audit verb.
Webhook configurations are cluster-scoped, so the audit event carries
objectRef.name with an empty objectRef.namespace; the gate for an emulation is the
name, not the namespace. A delete is described at Metadata level well enough to fire
the chokepoint; only Request level records the DeleteOptions body that shows a
server-side dry run, so the shared lab policy logs these deletes at Request. A neuter
via update or patch is not: at Metadata you see that a webhook config changed but
not that failurePolicy became Ignore or rules became empty. Grading the neuter needs
the requestObject, which exists only at Request level, and for some patches the stored
object after the write (responseObject), which exists only at RequestResponse level.

### Removing the enforcer is a different edge

Deleting or scaling the policy engine's own workload is an apps-group write, not an
admissionregistration one. A `kubectl patch` of spec.replicas to 0 is on the
deployments resource. A `kubectl scale` uses the deployments/scale subresource,
which an audit policy must list explicitly (as deployments/scale) to capture with a
body, because Kubernetes audit resource matching is exact. The shipped policy
(`detections/k8s/audit-policy-apiserver.yaml`) lists deployments/scale,
statefulsets/scale and replicasets/scale at Request. A plain `kubectl scale` sends a
merge patch of the subresource. With `--current-replicas` or `--resource-version`,
kubectl reads the Scale object and writes it back with an update (PUT). The API
server logs the decoded autoscaling/v1 Scale of an update, encoded again, and its
`spec.replicas` field is `omitempty`: a scale to 0 leaves no `replicas` key in the
record. A patch of the scale subresource is applied to the current Scale, and the
result is decoded: a `replicas` key that the patch removes (a merge patch with
`"replicas": null`, a JSON-patch `remove`, a replace of `/spec`) decodes as 0, so it
is a scale to zero too. On the deployments resource the same patch resets the count
to its default of 1. A strategic merge patch (the `kubectl patch` default) has two
more ways to reach 0, on the resource and on the subresource. The API server merges
it as a map of int64 values and then converts the count to the int32 field with no
range check, so a count of 4294967296 (2^32) becomes 0. Its directives can also drop
or set the count: `"$patch": "delete"` in the Scale's spec empties the spec, and a
`$deleteFromPrimitiveList/replicas` key (or `$deleteFromPrimitiveList/spec` at the
root) acts as the plain key when the current object holds a number or a map there.
A JSON patch (`kubectl patch --type=json`) carries an ops array,
not a spec, so a scale to zero is an op on /spec/replicas, or a replace of `/spec`
whose value holds `replicas: 0`. A write of the status subresource cannot change the
spec. A DaemonSet has no replica count at all: it runs one pod on each node that its
pod template allows. Deleting the engine's whole namespace
removes its workloads too: the API server records the actor's namespace delete, and
then the namespace controller deletes the workloads with one deletecollection per
resource type.

### Why the technique works

Admission control is the gate that stops dangerous configuration from being stored.
It is itself ordinary Kubernetes configuration, protected only by RBAC. An
identity that can write admission objects can remove the gate. A detection must see
the write and, for a neuter, read the request body; and a node sensor must cover
the control-plane bypass the API server never sees.

## Procedures

| Procedure | ID | Name | Entry point |
|-----------|----|------|-------------|
| A | TRR9008.K8S.A | Delete a ValidatingWebhookConfiguration | `delete validatingwebhookconfigurations` |
| B | TRR9008.K8S.B | Delete a MutatingWebhookConfiguration | `delete mutatingwebhookconfigurations` |
| C | TRR9008.K8S.C | Neuter a webhook configuration in place | `update`/`patch` a webhook config |
| D | TRR9008.K8S.D | Remove the enforcer's workload | `delete` a Deployment or DaemonSet, scale a Deployment to zero, or `delete` the namespace |

> A tool is not a procedure. `kubectl`, a client library, Helm, and a raw HTTP
> client all send the same admission write. They are the same procedure.

**Reading the DDMs.** Green borders are operations the client performs. Blue
borders are operations the API server performs. Purple borders are operations on
the node. Black borders are the abstract effect. The pill names the telemetry; the
`Key: value` lines are what a rule matches; a shaded node is the primary detection
opportunity.

### Procedure A: Delete a ValidatingWebhookConfiguration  (`TRR9008.K8S.A`)

The adversary deletes the object that registers the validating webhooks, so nothing
validates admission for the resources it covered.

- **Prerequisites:** `delete` on `validatingwebhookconfigurations` (cluster-scoped).
- **Mechanics:** a single DELETE removes the enforcement surface.
- **Impact:** policy validation stops for the covered resources.
- **Tools on this path:** `kubectl delete`, any client.

#### Detection Data Model — `TRR9008.K8S.A`

![DDM - Delete a ValidatingWebhookConfiguration](ddms/trr9008_k8s_a.png)

Source: [`ddms/trr9008_k8s_a.json`](ddms/trr9008_k8s_a.json) (Arrows app format).

**DDM summary.** The shaded node is the API server's authorize-and-audit of the
admission write (`objectRef.apiGroup: admissionregistration.k8s.io`, a disabling
verb), the chokepoint for A, B, and C. A delete is described at Metadata well enough to
fire the chokepoint; its dry-run filter needs the DeleteOptions body (Request level).

### Procedure B: Delete a MutatingWebhookConfiguration  (`TRR9008.K8S.B`)

The adversary deletes the mutating webhook configuration, so sidecar injection and
defaulting stop.

- **Prerequisites:** `delete` on `mutatingwebhookconfigurations`.
- **Mechanics:** a single DELETE.
- **Impact:** mutation policy stops.
- **Tools on this path:** `kubectl delete`, any client.

#### Detection Data Model — `TRR9008.K8S.B`

![DDM - Delete a MutatingWebhookConfiguration](ddms/trr9008_k8s_b.png)

Source: [`ddms/trr9008_k8s_b.json`](ddms/trr9008_k8s_b.json) (Arrows app format).

**DDM summary.** Same chokepoint audit event; only the resource is
`mutatingwebhookconfigurations`.

### Procedure C: Neuter a webhook configuration in place  (`TRR9008.K8S.C`)

The adversary leaves the webhook config in place but disarms it, setting
failurePolicy to Ignore (fail-open) or emptying the rules so it never fires.

- **Prerequisites:** `update` or `patch` on the webhook config.
- **Mechanics:** an in-place edit; the object still exists, so a delete-watcher
  misses it.
- **Impact:** the webhook is installed but blocks nothing.
- **Tools on this path:** `kubectl replace`/`apply`/`patch`, any client.

#### Detection Data Model — `TRR9008.K8S.C`

![DDM - Neuter a webhook configuration](ddms/trr9008_k8s_c.png)

Source: [`ddms/trr9008_k8s_c.json`](ddms/trr9008_k8s_c.json) (Arrows app format).

**DDM summary.** Same chokepoint, verb `update` or `patch`. The disarming field
(failurePolicy Ignore, rules []) is in `requestObject` and needs Request level. A
patch body is logged raw and keeps `"rules": []`, or `"rules": null` for a
strategic merge patch (the `kubectl patch` default). A PUT is logged as the
decoded, defaulted object re-encoded; `rules` is `omitempty`, so an emptied list
leaves no `rules` key. The grader reads that gap from the keys around it, in the
API server's Go field order (`name`, `clientConfig`, then directly `failurePolicy`)
and in the order a key-sorting pipeline delivers (a validating webhook's `name`,
`namespaceSelector`, `objectSelector`, then directly `sideEffects`; a mutating
webhook's `reinvocationPolicy`, then directly `sideEffects`); each test needs the
context of its own order, so a webhook that keeps its rules matches neither. A
JSON patch carries only the ops array, and the grader reads it for an operation
that sets `/webhooks/N/failurePolicy` to Ignore or removes or empties
`/webhooks/N/rules`; for an operation on the whole list, a whole webhook or its
`matchConditions` whose value fails open or adds a constant condition; and for an
operation on the whole list or a whole webhook that leaves no non-empty `rules`
list. A `matchConditions` expression that names no variable (`object`, `oldObject`,
`request`, `authorizer`) is a constant, the same for every request. The grader
matches such an expression when it is built only from literals, operators, brackets,
`in` and a fixed list of standard functions (`size`, `int`, `uint`, `double`,
`string`, `bytes`, `bool`, `dyn`, `type`, `matches`, `startsWith`, `endsWith`,
`contains`), with blanks between them, also the JSON escapes `\n`, `\t` and `\r` (a
YAML block scalar ends `false` with a line break): `false`, `1 == 2`, `!true`,
`size([]) > 0`. A constant written in another way (a macro with its own bound
variable, such as `[1].all(x, x > 1)`, or a function outside the list) is not
matched. A `namespaceSelector` that requires the `kubernetes.io/metadata.name` label
to be absent or empty (`DoesNotExist`, a `matchLabels` value `""`, or `In` with only
the empty string as values) is graded too: the API server sets that label to the
namespace's name on every namespace, so it matches none.

A JSON merge patch (`--type=merge`) that replaces the webhooks list with a webhook
without `rules` looks like a strategic merge patch that leaves rules unchanged (the
patch type is not logged), and a JSON patch that replaces the whole list can drop
`rules` from one webhook only. For an update or patch the policy records the stored
object after the write (`responseObject`, RequestResponse level), and the grader reads
it for a webhook without rules, a constant condition or a never-matching
`namespaceSelector`, whatever the patch type. It grades the stored state, not the
change: the earlier state is only in the record of the object's previous write, at
any time before, and a Sigma correlation can neither reach back an unbounded time nor
compare a webhook across two records. A selector on any other label that matches
nothing (or `kubernetes.io/metadata.name In` names that no namespace has), and a
condition that reads a variable but never matches in practice
(`request.name == 'no-such-object'`), cannot be told from a legitimate narrowing:
whether they match depends on the labels and requests of the cluster, which the
record does not carry. A selector or condition that contradicts itself (the same key
with `Exists` and `DoesNotExist`, or `In` and `NotIn` of the same value) matches
nothing on any cluster, but the grader does not detect it either: comparing two keys
or values for equality needs a back-reference, which the portable regex subset does
not have. They fire the chokepoint only.

### Procedure D: Remove the enforcer's workload  (`TRR9008.K8S.D`)

The adversary deletes the Deployment or DaemonSet that serves the webhook (or runs
the sensor), scales the Deployment to zero, or deletes the engine's namespace, so the
endpoint is gone.

- **Prerequisites:** `delete` or `patch`/`update` on the policy engine's
  Deployment/DaemonSet (or the Deployment's scale subresource), or `delete` on its
  namespace.
- **Mechanics:** with failurePolicy already Ignore, admission then fails open.
- **Impact:** enforcement stops without touching the webhook config.
- **Tools on this path:** `kubectl delete`/`scale`/`patch`, any client.

Each project's install instructions name a default namespace: `gatekeeper-system`
for Gatekeeper (`deploy/gatekeeper.yaml` and its Helm chart), `kyverno` for Kyverno
(its `install.yaml` and Helm chart) and `falco` for Falco (its Helm chart). An
operator can install an engine in another namespace, so the namespace is a strong
hint, not proof.

The rules do not see every way to stop the enforcer:

- A DaemonSet (Falco) has no replica count. A patch that gives its pod template a
  nodeSelector, a node affinity or a nodeName that no node matches makes the
  DaemonSet controller delete every Falco pod. Neither rule matches that write
  ([`RULE_DEFECTS.md` K29](../../../detections/RULE_DEFECTS.md#k29-t1685-enforcer-removal-rules-a-daemonset-unscheduled-by-its-pod-template)).
- A strategic merge patch of the scale subresource can hold a count above 0 and
  also a null `$deleteFromPrimitiveList/replicas`. In most runs the merge deletes the
  count after it sets it, so the Scale goes to 0. A null value is not a field in the
  record, so the record looks like a scale up, and neither rule matches it
  ([`RULE_DEFECTS.md` K32](../../../detections/RULE_DEFECTS.md#k32-t1685-enforcer-removal-rules-a-null-strategic-merge-directive-next-to-a-count)).
- A raw client can add an extra key to a JSON-patch operation, which the API server
  ignores. The rules read past a key whose value nests objects two levels deep, but
  not three levels deep or a nested object that holds a string with a brace
  ([`RULE_DEFECTS.md` K33](../../../detections/RULE_DEFECTS.md#k33-json-text-skip-grammars-a-key-nested-three-levels-deep-splits-an-operation)).
- The webhook can stop without an apps write. Gatekeeper's webhooks call the Service
  `gatekeeper-webhook-service` in `gatekeeper-system`, and its validating webhook has
  failurePolicy Ignore, so a delete of that Service (or of its EndpointSlices) turns
  the validation off. A NetworkPolicy that blocks the webhook port does the same, and
  so does a ResourceQuota of 0 pods in the engine's namespace followed by pod
  deletes. These are core or networking writes; no TRR9008 rule matches them.

#### Detection Data Model — `TRR9008.K8S.D`

![DDM - Remove the enforcer's workload](ddms/trr9008_k8s_d.png)

Source: [`ddms/trr9008_k8s_d.json`](ddms/trr9008_k8s_d.json) (Arrows app format).

**DDM summary.** This is a different edge, an apps-group write, so it has its own
rules (Strategy 3). The two shaded nodes are the primary detections. The first is
the apps write: a delete of a Deployment or DaemonSet, or a scale to zero of a
Deployment (a patch or update with `spec.replicas` 0, a Scale update without
`spec.replicas`, a patch of the scale subresource that sets no count above 0, a
strategic merge patch that truncates or drops the count, or a JSON-patch op on
/spec/replicas). The alert rule limits it to the engines' default
namespaces; the anchor rule matches it in every namespace. The second is the delete
of an engine's default namespace, which both rules match. The node also sees the
enforcer pods disappear.

## Detection Strategy

Compare the four DDMs. Procedures A, B, and C all write the admission API group, so
each leaves the same kind of audit event — one chokepoint rule covers all three.
Procedure D is a different edge (an apps-group write) and needs its own rule. A
node sensor covers the control-plane bypass the API server never sees.

**Telemetry requirement.** The audit policy must record the
admissionregistration.k8s.io group for the write verbs at **Request** level, so the
neuter's requestObject is visible, and its updates and patches at
**RequestResponse**, so the stored object (responseObject) shows a webhook that lost
its rules whatever the patch type; and the apps group at Request (already recorded)
for Procedure D. Webhook configurations hold no secret: a caBundle is a public CA
certificate, and the API rejects credentials in a webhook URL. Put the admission rule above the catch-all. Baseline the actor,
not the object.

**Strategy 1 — chokepoint (covers A, B, C).**
Match audit events where `objectRef.apiGroup` is `admissionregistration.k8s.io` and
`verb` is `delete`, `deletecollection`, `update`, or `patch`. The `create` verb is
excluded (that is persistence, TRR9025). But a server-side-apply install of a missing
object is a `patch` answered 201, not a create, so it fires this rule (K21). The TRR9025
create rules fire on the same record, so such an install alerts twice, which is
expected. A refused server-side-apply install (a `patch` answered 4xx) fires this rule
only. A server-side dry run is filtered: the `?dryRun=All` query of an
update or patch, or the DeleteOptions body of a delete (which the shipped policy logs at
Request level). The query counts only when `dryRun=All` is a whole parameter of it
(the first `?` starts the query, and Go `net/url` splits it at `&`), so a value of
another parameter, such as `?fieldManager=?dryRun=All`, is not a dry run. It also
counts only when the URI holds at most 100 `&`: Go `net/url` reads no parameter of a
query that has more than 10,000, and the API server then stores the write. A delete or
deletecollection with no body whose query holds `?dryRun=All` is a dry run too, but it
still fires ([RULE_DEFECTS K36](../../../detections/RULE_DEFECTS.md#k36-delete-dry-run-filters-read-only-the-body-a-query-only-dry-run-fires)). Baseline the policy engine's own controller, GitOps/Helm,
and cluster-upgrade tooling by `user.username`.

- Sensor: API server audit log.
- Rule: `detections/sigma/T1685/k8s_admission_webhook_disabled.yml` (built).

**Strategy 2 — severity (grades C; needs Request level, RequestResponse for the
stored object).**
On top of the chokepoint, match a webhook write whose `requestObject.webhooks` sets
failurePolicy to Ignore, an empty rules list, a constant matchCondition or a
never-matching namespaceSelector, or whose stored object (`responseObject.webhooks`)
has a webhook without rules, a constant condition or such a selector. In a JSON patch
the webhook index is any JSON-pointer token, because the API server's JSON patch
library (`json-patch.v4` v4.13.0) reads `+0`, `-0` and `-1` as indexes. The grader
filters what cannot neuter an installed webhook: a server-side dry run of an update or
patch (the `?dryRun=All` query, for example `kubectl diff` or an Argo CD server-side
diff), and a server-side-apply install (a `patch` answered 201, which the TRR9025 create
rules own). Between the keys of one JSON-patch operation, the fail-open and
rules-cleared matches skip whole strings and nested objects two levels deep, so an
ignored extra key (`"q": {}`) does not hide the operation; a key nested three levels
deep, or a brace string in a nested object, does ([K33](../../../detections/RULE_DEFECTS.md#k33-json-text-skip-grammars-a-key-nested-three-levels-deep-splits-an-operation)).

- Sensor: API server audit log at Request and RequestResponse level.
- Rule: `detections/sigma/T1685/k8s_admission_webhook_neutered.yml` (built).

**Strategy 3 — enforcer removal (covers D).**
Match an apps-group write that deletes a Deployment/DaemonSet (verb delete or
deletecollection), or scales a Deployment to zero: requestObject.spec.replicas 0 on
the resource or on its scale subresource, an update of the scale subresource whose
Scale body has no spec.replicas (the 0 is omitted), a patch of the scale subresource
that does not set a count above 0 (a null, a JSON-patch remove, a replace of
`/spec`), a strategic merge patch with a count outside the int32 range or with a
directive that drops or sets the count (`"$patch": "delete"` in spec, a
`$deleteFromPrimitiveList/replicas` or `$deleteFromPrimitiveList/spec` key), or a
JSON patch that sets /spec/replicas to 0 (or -0), copies or moves a value into it,
or replaces `/spec` with a value that holds replicas 0. Between the keys of one
JSON-patch operation, the match skips whole strings and nested objects two levels
deep, so an ignored extra key does not hide the operation; a key nested three levels
deep, or a brace string in a nested object, does ([RULE_DEFECTS K33](../../../detections/RULE_DEFECTS.md#k33-json-text-skip-grammars-a-key-nested-three-levels-deep-splits-an-operation)). A write of the
status subresource is filtered. The namespace controller's teardown deletecollection
is filtered; the rules match the delete of the engine's default namespace
(gatekeeper-system, kyverno, falco) instead. Only accepted writes (200, 201, 202)
match, and server-side dry runs are filtered as in Strategy 1. Neither rule matches a
DaemonSet whose pod template is changed so that no node runs it (K29), a Scale
patch with a null directive next to a count above 0 (K32), a JSON-patch operation
with an ignored key nested three levels deep (K33), or a
webhook stopped by a write outside the apps group (see Procedure D).

Two rules share this logic. The alert rule (level high) matches the workload writes
only in the three default namespaces, plus the namespace delete. The anchor rule
(level low) matches the workload writes in every namespace, plus the same namespace
delete: it does not check that the target is a security tool. Use it to correlate an enforcer that is installed in
another namespace, or an identity that also changed an admission configuration.

- Sensor: API server audit log.
- Rule (alert): `detections/sigma/T1685/k8s_enforcer_workload_removed.yml` (built).
- Rule (anchor): `detections/sigma/T1685/k8s_security_tool_workload_removed.yml` (built).

**Demonstrated gap — the control-plane bypass.**
An adversary with control-plane node access can disable admission without any
admissionregistration write: edit the kube-apiserver static manifest to drop the
ValidatingAdmissionWebhook/MutatingAdmissionWebhook plugins, or tamper with the
webhook TLS material on disk so calls fail (fail-open if any webhook is Ignore).
None of that is an API write, so the chokepoint and the grading rule are blind. A
node file-integrity sensor on `/etc/kubernetes/manifests/kube-apiserver.yaml` and
the webhook cert paths covers it, and the CRI sensor sees the enforcer pods vanish.
This repository already ships the manifest half:
[`detections/sigma/T1543.005/linux_static_pod_manifest_write.yml`](../../../detections/sigma/T1543.005/linux_static_pod_manifest_write.yml)
(TRR9003, level high) matches a write under `/etc/kubernetes/manifests/`, which holds
`kube-apiserver.yaml`. CI gates it on TRR9003 Procedure A with the node file-event
sensor (an auditd write watch on the static-pod directory). No CI emulation edits
`kube-apiserver.yaml` (the sensor records kubeadm's bootstrap write of it, and the
staticpod file control checks that the rule stays quiet on that write), so this TRR's
control-plane edit is not exercised live. It
filters writes by kubeadm, the kubelet and the package managers, each by its full
install path. On a sensor that also reports reads, it also fires when a process
outside its install filter reads a manifest
([`RULE_DEFECTS.md`](../../../detections/RULE_DEFECTS.md) L15). No rule covers the
webhook cert paths.
The lab demonstrates the gap read-only, by showing the apiserver manifest path on
the node and noting no admissionregistration audit event follows an edit there.

**Audit-pipeline gap — a YAML apply body.**
A server-side apply patch whose body is YAML (not the JSON that kubectl and client-go
send) leaves no audit record at Request level or higher: the API server logs the raw
patch body as JSON, the JSON log backend cannot encode it, and it drops the whole
event. So a neuter in place (C) or a scale patch (D) sent that way fires no rule, the
chokepoint included. The deletes (A and B) send no patch and are not affected. The
operator signal is the kube-apiserver line `Error in audit plugin` and the metric
`apiserver_audit_error_total`. The gap holds for every resource that the shipped
policy logs at Request or higher. Tracked as
[RULE_DEFECTS K23](../../../detections/RULE_DEFECTS.md#k23-apply-patches-with-a-yaml-body-no-audit-record-at-request-level-or-higher).

**Coverage summary.**

| Procedure | Covered by | How |
|-----------|-----------|-----|
| A | Strategy 1 (chokepoint) | delete `validatingwebhookconfigurations` |
| B | Strategy 1 (chokepoint) | delete `mutatingwebhookconfigurations` |
| C | Strategy 1; graded by Strategy 2 | `update`/`patch` webhook config; failurePolicy Ignore / rules [] |
| D | Strategy 3 (alert and anchor) | delete the enforcer Deployment/DaemonSet, scale the Deployment to zero, or delete its namespace (not a DaemonSet that no node runs: K29; not a null-directive Scale patch: K32; not an op with an ignored key nested three levels deep: K33) |

One chokepoint rule covers the three admission-config paths. A severity rule grades
the neuter. An alert rule covers the enforcer-workload removal in the engines'
default namespaces, and an anchor rule covers it in every namespace.

## Available Emulation Tests

The tests run in a lab cluster with the shared audit policy (now recording the
admission group at Request level, and its updates and patches at RequestResponse). The lab is a `kind` cluster; its config and audit
policy are in [`detections/k8s/`](../../../detections/k8s/). Every object the tests
create is named `trr9008-*` (the namespace of test d is `trr9008`), except the
`kyverno` namespace: test d2 creates it only when it is absent, labels it
`trr9008-created=true`, and deletes it only when the test created it. Its records carry
no marker, so the validator gates the namespace delete by the exact write (see
[Detections](#detections)). Every webhook is a no-op (failurePolicy Ignore, rules
scoped to a bogus apiGroup) that cannot affect a real admission request. One script drives them:
[`atomics/T1685/src/emulate_k8s.sh`](../../../atomics/T1685/src/emulate_k8s.sh),
with Atomic Red Team wrappers in
[`atomics/T1685/T1685.yaml`](../../../atomics/T1685/T1685.yaml)
(alongside the Linux io_uring test for the same technique).

| Procedure | Test | Status |
|-----------|------|--------|
| TRR9008.K8S.A | `emulate_k8s.sh a` — apply then delete a no-op ValidatingWebhookConfiguration. | **built** |
| TRR9008.K8S.B | `emulate_k8s.sh b` — apply then delete a no-op MutatingWebhookConfiguration. | **built** |
| TRR9008.K8S.C | `emulate_k8s.sh c` — neuter a webhook config (failurePolicy Ignore, rules []), then four more shapes on their own configs: a merge patch and a JSON patch that replace the webhooks list and drop rules, a constant-false matchCondition, and a namespaceSelector that matches no namespace. | **built** |
| TRR9008.K8S.D | `emulate_k8s.sh d` — create a pause Deployment, scale it to zero with `kubectl scale` and with a patch, delete it. | **built** |
| TRR9008.K8S.D | `emulate_k8s.sh d2` — the same in the `kyverno` namespace (created only when absent, labelled `trr9008-created=true`, and deleted only when the test created it): a pause Deployment `trr9008-enforcer-standin`, scaled to zero with `kubectl scale --current-replicas=1` (an update of the scale subresource) and with a plain `kubectl scale`, then deleted. | **built** |

`emulate_k8s.sh dryrun` is a control, not a procedure. It installs `trr9008-dryrun-vwc`
(the Procedure C copy) and a pause Deployment `trr9008-dryrun-standin` in the
`gatekeeper-system` namespace (created only when absent and labelled as d2 labels
`kyverno`), then sends each write with `--dry-run=server`: a neuter merge patch and a
delete of the webhook configuration; a patch of `spec.replicas` 0, both `kubectl
scale` shapes, a delete of the Deployment and a deletecollection of the Deployments
that carry its label (`kubectl delete --raw` with a DeleteOptions body that holds
`dryRun: ["All"]`); and a delete of the `gatekeeper-system` namespace. When that
namespace existed before the test (it has no `trr9008-created` label), the step fails
before its first write and sends nothing to it. Then it checks that the webhook still
fails closed, the Deployment still asks for one replica and the namespace is still
Active. A server-side dry run persists nothing, so with the emulation ledger the
validator's must-not-match checks (`MISS_MANIFEST`) assert that the chokepoint, the
neuter grader and both workload rules match none of these records, and that each rule
fires on each shape once its dry-run marker is removed.

## Detections

| Strategy | Covers | Sigma rule | Sensor |
|----------|--------|------------|--------|
| 1 (chokepoint) | A, B, C | [`detections/sigma/T1685/k8s_admission_webhook_disabled.yml`](../../../detections/sigma/T1685/k8s_admission_webhook_disabled.yml) | API server audit log |
| 2 (severity) | grades C | [`detections/sigma/T1685/k8s_admission_webhook_neutered.yml`](../../../detections/sigma/T1685/k8s_admission_webhook_neutered.yml) | API server audit log (Request, RequestResponse) |
| 3 (alert) | D | [`detections/sigma/T1685/k8s_enforcer_workload_removed.yml`](../../../detections/sigma/T1685/k8s_enforcer_workload_removed.yml) | API server audit log |
| 3 (anchor) | D | [`detections/sigma/T1685/k8s_security_tool_workload_removed.yml`](../../../detections/sigma/T1685/k8s_security_tool_workload_removed.yml) | API server audit log |

The validator
[`detections/validate_apiserver_detections.py`](../../../detections/validate_apiserver_detections.py)
reads the API server audit log the emulation produced and asserts each rule matches
an event naming a `trr9008-` object; for the alert rule, a `trr9008-` object in the
`kyverno` namespace (`9008 D2`), and each write of it on its own: the update of its
scale subresource (`9008 D2 put`), the patch of it (`9008 D2 patch`) and the
Deployment delete (`9008 D2 delete`). The anchor rule is also proven on that update
(`9008 D put`). The atomic's delete of the `kyverno` namespace names the real
namespace, which carries no emulation marker, so it is gated by the exact write
(resource `namespaces`, name `kyverno`, verb `delete`, a caller that is not
`system:*`): `9008 D2 ns` proves the alert rule and `9008 D ns` the anchor rule. That
gate rests on the kind cluster having no `kyverno` namespace before d2 runs, so the
pre-emulation negative control holds no such record. The workflow
[`validate-apiserver-detections.yml`](../../../.github/workflows/validate-apiserver-detections.yml)
runs the loop on a `kind` cluster, with a negative control on the pre-emulation log.

Upstream: the SigmaHQ rule `kubernetes_audit_change_admission_controller.yml`
covers webhook configs but lists a phantom `replace` verb, cannot grade a neuter
(no requestObject), and has no enforcer-workload edge. Elastic's "Kubernetes Admission
Webhook Created or Modified" also matches `update`, `patch` and `delete` of webhook
configurations (tagged T1546 and T1562) but reads no body, so it cannot grade a neuter
either; Falco's k8saudit "K8s Deployment Deleted" (priority INFO) and the SigmaHQ rule
`kubernetes_audit_deployment_deleted.yml` (level low) match any Deployment delete, with
no scale-to-zero and no namespace scope. Stratus Red Team and Atomic Red Team have no
Kubernetes test that removes an enforcer. Propose the corrected chokepoint plus the
neuter grader and the workload-removal rules.

## References

- MITRE ATT&CK, T1685 Disable or Modify Tools:
  <https://attack.mitre.org/techniques/T1685/>
- Kubernetes documentation, Dynamic Admission Control (webhook configs,
  failurePolicy, rules, selectors, clientConfig):
  <https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/>
- Kubernetes documentation, Validating Admission Policy (CEL, GA in 1.30):
  <https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/>
- Kubernetes documentation, Auditing (levels, stages, verb mapping):
  <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>
- SigmaHQ rule, Kubernetes Admission Controller Modification:
  <https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_change_admission_controller.yml>
- Microsoft Threat Matrix for Kubernetes:
  <https://microsoft.github.io/Threat-Matrix-for-Kubernetes/>
- Default install namespaces: Gatekeeper `deploy/gatekeeper.yaml`
  (<https://github.com/open-policy-agent/gatekeeper/blob/master/deploy/gatekeeper.yaml>;
  it also defines the Service `gatekeeper-webhook-service` and the validating webhook's
  failurePolicy Ignore) and the Gatekeeper Helm chart
  (<https://github.com/open-policy-agent/gatekeeper/blob/master/charts/gatekeeper/README.md>),
  the Kyverno release `install.yaml`
  (<https://github.com/kyverno/kyverno/releases/download/v1.15.0/install.yaml>) and
  Helm chart (<https://github.com/kyverno/kyverno/blob/main/charts/kyverno/README.md>),
  and the Falco Helm chart
  (<https://github.com/falcosecurity/charts/blob/master/charts/falco/README.md>).
- Kubernetes v1.36.4 source, the audit record of an update (the decoded object,
  encoded again) and the Scale type (`spec.replicas` is `omitempty`):
  <https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/update.go>,
  <https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/api/autoscaling/v1/types.go>
- Kubernetes v1.36.4 source, how a patch is applied (to the current object encoded as
  JSON, then decoded) and the DaemonSet controller's node check:
  <https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go>,
  <https://github.com/kubernetes/kubernetes/blob/v1.36.4/pkg/controller/daemon/daemon_controller.go>
- Kubernetes v1.36.4 source, the strategic merge of a patch (its directives, and the
  `$deleteFromPrimitiveList/` key on a field that is not a list) and the conversion
  of the merged map to the typed object (no int32 range check):
  <https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/apimachinery/pkg/util/strategicpatch/patch.go>,
  <https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/apimachinery/pkg/runtime/converter.go>
- TRR method:
  <https://github.com/tired-labs/techniques/blob/main/docs/TECHNIQUE-RESEARCH-REPORT.md>
