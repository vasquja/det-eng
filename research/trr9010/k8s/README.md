# Indicator Removal (Kubernetes)

> Prose uses Simplified Technical English (ASD-STE100) where practical.
> Resource names, verbs, field names, and ATT&CK IDs are technical names.

## Metadata

| Key          | Value |
|--------------|-------|
| ID           | TRR9010 |
| External IDs | T1070, T1070.004 |
| Tactics      | Stealth |
| Platforms    | Kubernetes |
| Contributors | det-eng |
| Status       | draft |

### Scope Statement

This TRR covers Stealth through **indicator removal**: destroying the
records of what happened in a cluster. It covers deleting Kubernetes Events (the
cluster's own activity record), deleting the Pods and Jobs that ran, and clearing
the API server audit log on the node.

This TRR does not cover these related actions:

- Creating a Job or CronJob to run code. TRR9005 (T1053.007) covers that; deleting
  a Job here is the inverse — removing the record, not creating one.
- Command execution in a container (T1609) or a dangerous pod spec (T1611). Deleting
  a pod to remove evidence is distinct from running one.

> ATT&CK maps this to T1070 (Indicator Removal, Stealth); Containers is a
> platform of the parent with no container sub-technique. Clearing the audit log
> file on the node maps to T1070.004 (File Deletion), as Elastic's own "Kubernetes
> Events Deleted" rule tags it.

## Technique Overview

Kubernetes keeps its own running record of what happens. Events note that a pod was
scheduled, an image was pulled, a probe failed, or a policy denied a request. When
responders investigate an intrusion, these records are part of the story. So is the
existence of the pod that ran the adversary's code, and the API server audit log
itself.

An adversary who has done their work deletes the evidence. They delete the Events
that mention their activity, or wipe a whole namespace's Events at once. They delete
the Pod and the Job that ran their container, so the workload record is gone. And if
they reach the control-plane node, they truncate the audit log file, which erases
the record of everything — a step the API server itself cannot see, because it is a
local file operation, not an API call. The defensive goal is to notice the API-level
deletions, and to lean on a node sensor for the one path the audit log cannot
record.

## Technical Background

### Events, and the two API groups

Kubernetes Events are namespaced objects. They exist in two API groups that hold the
same objects: the core group (resource `events`, apiGroup empty) and events.k8s.io
(resource `events`). A single delete is a DELETE on one Event; a bulk wipe is a
collection DELETE, recorded as the `deletecollection` verb. In both groups the audit
event records `objectRef.resource` as `events`, so a rule that does not pin the
apiGroup covers both.

### Routine turnover is not a delete

Events do not pile up forever. The API server expires them at the etcd storage
layer, governed by the event-ttl (default one hour). That expiry is not an API
DELETE and writes no audit event. So on a quiet cluster the baseline of
delete/deletecollection on Events is near zero — a genuine delete stands out. The
kube-system controllers create Events but do not delete them.

### What the audit log records, and what it cannot

A delete or deletecollection on Events is fully described at Metadata level: the verb,
the resource, the namespace, the name (a deletecollection has no single name), the
identity, and the result. A delete is audited even when the object does not exist —
the request is recorded with its objectRef and a 404 — so the telemetry exists
whether or not the Event was still there. The one thing the audit log cannot record
is a node-local operation: truncating the audit log file or disabling the audit sink
is a filesystem action, not an API call, so it leaves no audit event at all.

### Why the technique works

The records are ordinary Kubernetes objects and a local log file. An identity that
can delete Events, or reach the node's filesystem, can destroy them. A detection
must see the API-level deletions and, for the node-local path, rely on a file
sensor and a continuity check on the audit pipeline.

## Procedures

| Procedure | ID | Name | Entry point |
|-----------|----|------|-------------|
| A | TRR9010.K8S.A | Delete a single Event (core group) | `delete events` |
| B | TRR9010.K8S.B | Bulk-wipe Events (deletecollection) | `deletecollection events` |
| C | TRR9010.K8S.C | Delete an Event (events.k8s.io group) | `delete events` (events.k8s.io) |
| D | TRR9010.K8S.D | Delete a Pod or Job (workload record) | `delete pods`/`jobs` |
| E | TRR9010.K8S.E | Clear the audit log on the node | node filesystem (no API call) |

> A tool is not a procedure. `kubectl delete`, a client library, and a raw HTTP
> client all produce the same audit shape.

**Reading the DDMs.** Green borders are operations the client performs. Blue borders
are operations the API server performs. Purple borders are operations on the node.
Black borders are the abstract effect. The pill names the telemetry; the
`Key: value` lines are what a rule matches; a shaded node is the primary detection
opportunity.

### Procedure A: Delete a single Event — core group  (`TRR9010.K8S.A`)

The adversary deletes one Event that mentions their activity.

- **Prerequisites:** `delete` on `events` in the namespace.
- **Mechanics:** a single DELETE.
- **Impact:** one record of activity is gone.
- **Tools on this path:** `kubectl delete event`, any client.

#### Detection Data Model — `TRR9010.K8S.A`

![DDM - Delete a single Event](ddms/trr9010_k8s_a.png)

Source: [`ddms/trr9010_k8s_a.json`](ddms/trr9010_k8s_a.json) (Arrows app format).

**DDM summary.** The shaded node is the API server's authorize-and-audit of the
delete (`objectRef.resource: events`, verb `delete`), the chokepoint for A, B, and C.

### Procedure B: Bulk-wipe Events — deletecollection  (`TRR9010.K8S.B`)

The adversary wipes a whole namespace's Events in one request.

- **Prerequisites:** `deletecollection` on `events`.
- **Mechanics:** a collection DELETE; no single objectRef.name.
- **Impact:** the mass cover-up — every Event in the namespace is gone.
- **Tools on this path:** a collection DELETE, `kubectl delete events --all`.

#### Detection Data Model — `TRR9010.K8S.B`

![DDM - Bulk-wipe Events](ddms/trr9010_k8s_b.png)

Source: [`ddms/trr9010_k8s_b.json`](ddms/trr9010_k8s_b.json) (Arrows app format).

**DDM summary.** Same chokepoint, verb `deletecollection`. The event has no
`objectRef.name`, so the detection must match the verb, not a single object. The
upstream SigmaHQ rule matches `delete` only and misses this bulk wipe.

### Procedure C: Delete an Event — events.k8s.io group  (`TRR9010.K8S.C`)

The adversary deletes an Event in the second API group.

- **Prerequisites:** `delete` on `events` in events.k8s.io.
- **Mechanics:** the same object, a different group.
- **Impact:** one record gone; a rule that pins the core group would miss it.
- **Tools on this path:** `kubectl delete events.events.k8s.io`, any client.

#### Detection Data Model — `TRR9010.K8S.C`

![DDM - Delete an Event (events.k8s.io)](ddms/trr9010_k8s_c.png)

Source: [`ddms/trr9010_k8s_c.json`](ddms/trr9010_k8s_c.json) (Arrows app format).

**DDM summary.** Same chokepoint; `objectRef.apiGroup` is `events.k8s.io`. The rule
does not pin the apiGroup, so it covers both groups.

### Procedure D: Delete a Pod or Job — workload record  (`TRR9010.K8S.D`)

The adversary deletes the Pod (and the Job) that ran their code.

- **Prerequisites:** `delete` on `pods` (or `jobs`).
- **Mechanics:** a routine-looking teardown.
- **Impact:** the record of what ran is gone.
- **Tools on this path:** `kubectl delete pod`/`job`, any client.

#### Detection Data Model — `TRR9010.K8S.D`

![DDM - Delete a Pod or Job](ddms/trr9010_k8s_d.png)

Source: [`ddms/trr9010_k8s_d.json`](ddms/trr9010_k8s_d.json) (Arrows app format).

**DDM summary.** A different resource, a separate rule (Strategy 2). Pod and Job
deletion is routine, so this is low fidelity — a correlation anchor, the inverse of
TRR9005 (Job creation for execution), not a standalone alert.

### Procedure E: Clear the audit log on the node — the gap  (`TRR9010.K8S.E`)

The adversary truncates the audit log file on the control-plane node, or disables
the audit sink.

- **Prerequisites:** control-plane node filesystem access.
- **Mechanics:** a local file operation; no API call.
- **Impact:** the record of everything is erased, with no audit event.
- **Tools on this path:** a shell on the node.

#### Detection Data Model — `TRR9010.K8S.E`

![DDM - Clear the audit log on the node](ddms/trr9010_k8s_e.png)

Source: [`ddms/trr9010_k8s_e.json`](ddms/trr9010_k8s_e.json) (Arrows app format).

**DDM summary.** There is no audit event. The read-and-truncate is visible only to a
node file sensor watching the audit log path, and to a continuity check on the audit
pipeline — an unexplained gap or a truncation of the log is itself the signal.

## Detection Strategy

Compare the five DDMs. Procedures A, B, and C all delete Events, so each leaves the
same kind of audit event — one chokepoint rule covers all three. Procedure D is a
different resource and a low-fidelity fallback. Procedure E never reaches the API
server, so no audit rule can see it; a node sensor covers it.

**Telemetry requirement.** The audit policy must record delete and deletecollection
on `events` at Metadata level. The shared policy's catch-all Metadata rule already
does, and the `events` None rule is scoped to reads only, so deletes are not
dropped. No policy change is needed.

**Strategy 1 — chokepoint (covers A, B, C).**
Match audit events where `objectRef.resource` is `events` and `verb` is `delete` or
`deletecollection`. Do not pin the apiGroup (so events.k8s.io is covered) and do not
match `delete` only (so the bulk `deletecollection` wipe is covered). Filter one
request: the namespace controller's `deletecollection` of the Events of a namespace
being deleted (`system:serviceaccount:kube-system:namespace-controller`), which every
namespace teardown makes. Baseline the other system identities and any event-exporter
service accounts by `user.username`.

- Sensor: API server audit log.
- Rule: `detections/sigma/T1070/k8s_events_deleted.yml` (built).

**Strategy 2 — workload-record fallback (covers D).**
Match a delete or deletecollection of Pods or Jobs (the namespace controller's
teardown sweep is filtered). This is low fidelity; use it for correlation only
— the same identity that also deleted Events, a deletion in a sensitive namespace,
or a Job whose creation the identity made.

- Sensor: API server audit log.
- Rule: `detections/sigma/T1070/k8s_workload_deleted_evidence.yml` (built).

**Strategy 3 — node sensor (covers E; the gap).**
Watch the audit log path on the node for write, truncate, or unlink, and the
kube-apiserver static-pod manifest for changes to the audit flags; and run a
continuity check on the audit pipeline. No API event exists for this path.

- Sensor: a node file-integrity or runtime agent, plus an audit-pipeline heartbeat.

**Demonstrated gap.**
Clearing or truncating the audit log file on the node (Procedure E) destroys
evidence with no API call, so the API server writes no audit event — the audit layer
is structurally blind to it. This is the inverse of the TRR9002 and TRR9006 Procedure
E gaps: same lesson, a different layer. The lab demonstrates it read-only, by showing
the audit log path on the node and noting that a truncation there emits no API event.

A second, smaller gap is at the API: deleting a whole namespace destroys its Events,
but the Events are then deleted by the namespace controller, not by the actor, and
the chokepoint filters that sweep. The actor's own record is a `delete` of
`namespaces`, which no shipped rule matches in general (only the three policy-engine
namespaces of TRR9008 are matched). A namespace delete is routine (CI preview
environments, tenant teardown) and its record does not show why, so it is left to
hunting and correlation by actor and namespace. Case `namespace-delete-known-miss` in
the chokepoint's sidecar records this miss.

**Coverage summary.**

| Procedure | Covered by | How |
|-----------|-----------|-----|
| A | Strategy 1 (chokepoint) | `delete events` (core) |
| B | Strategy 1 (chokepoint) | `deletecollection events` (bulk wipe) |
| C | Strategy 1 (chokepoint) | `delete events` (events.k8s.io) |
| D | Strategy 2 (fallback) | `delete pods`/`jobs` |
| E | Strategy 3 (node sensor); the gap | audit-log file cleared; no audit event |

One chokepoint rule covers every API-level event deletion that the actor makes; an
Events wipe through a namespace delete is not covered. A low-fidelity fallback
covers workload-record deletion. A node sensor covers the audit-log clearing the API
server never sees.

## Available Emulation Tests

The tests run in a lab cluster with the shared audit policy. The lab is a `kind`
cluster; its config and audit policy are in
[`detections/k8s/`](../../../detections/k8s/). Everything happens in a throwaway
namespace `trr9010` with uniquely named objects, so a validator matches the
emulation's own events. One script drives them:
[`atomics/T1070/src/emulate.sh`](../../../atomics/T1070/src/emulate.sh), with Atomic
Red Team wrappers in [`atomics/T1070/T1070.yaml`](../../../atomics/T1070/T1070.yaml).

| Procedure | Test | Status |
|-----------|------|--------|
| TRR9010.K8S.A | `emulate.sh a` — create and delete a core v1 Event. | **built** |
| TRR9010.K8S.B | `emulate.sh b` — bulk-wipe Events with a collection DELETE. | **built** |
| TRR9010.K8S.C | `emulate.sh c` — create and delete an events.k8s.io Event. | **built** |
| TRR9010.K8S.D | `emulate.sh d` — create and delete a busybox pod. | **built** |
| TRR9010.K8S.E | `emulate.sh gap` — show the audit log path on the node (read-only). | **built** |

## Detections

| Strategy | Covers | Sigma rule | Sensor |
|----------|--------|------------|--------|
| 1 (chokepoint) | A, B, C | [`detections/sigma/T1070/k8s_events_deleted.yml`](../../../detections/sigma/T1070/k8s_events_deleted.yml) | API server audit log |
| 2 (fallback) | D | [`detections/sigma/T1070/k8s_workload_deleted_evidence.yml`](../../../detections/sigma/T1070/k8s_workload_deleted_evidence.yml) | API server audit log |
| 3 (node sensor) | E; the gap | none at the audit-log layer, by design | node file-integrity sensor |

The validator
[`detections/validate_apiserver_detections.py`](../../../detections/validate_apiserver_detections.py)
reads the API server audit log the emulation produced and asserts Strategies 1 and 2
match an event the emulation produced (a `trr9010-` named delete, or the bulk
deletecollection in the `trr9010` namespace). The workflow
[`validate-apiserver-detections.yml`](../../../.github/workflows/validate-apiserver-detections.yml)
runs the loop on a `kind` cluster, with a negative control on the pre-emulation log.

Upstream: the SigmaHQ rule `kubernetes_audit_events_deleted.yml` matches `delete`
only and misses the bulk `deletecollection` wipe. Propose widening the verb list to
`delete` and `deletecollection`.

## References

- MITRE ATT&CK, T1070 Indicator Removal:
  <https://attack.mitre.org/techniques/T1070/>
- MITRE ATT&CK, T1070.004 Indicator Removal: File Deletion:
  <https://attack.mitre.org/techniques/T1070/004/>
- Kubernetes documentation, Auditing (levels, stages, verb mapping, `deletecollection`):
  <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>
- Kubernetes documentation, API Concepts (delete vs deletecollection):
  <https://kubernetes.io/docs/reference/using-api/api-concepts/>
- SigmaHQ rule, Kubernetes Events Deleted:
  <https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_events_deleted.yml>
- Elastic rule, Kubernetes Events Deleted (maps T1070 + T1070.004):
  <https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/kubernetes/defense_evasion_events_deleted>
- Microsoft Threat Matrix for Kubernetes, Delete K8S events:
  <https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Delete%20K8S%20events/>
- TRR method:
  <https://github.com/tired-labs/techniques/blob/main/docs/TECHNIQUE-RESEARCH-REPORT.md>
