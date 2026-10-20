# Additional Container Cluster Roles (Kubernetes)

> Prose uses Simplified Technical English (ASD-STE100) where practical.
> API group names, resource names, verbs, field names, and ATT&CK IDs are
> technical names.

## Metadata

| Key          | Value |
|--------------|-------|
| ID           | TRR9004 |
| External IDs | T1098.006 |
| Tactics      | Persistence, Privilege Escalation |
| Platforms    | Kubernetes |
| Contributors | det-eng |
| Status       | draft |

### Scope Statement

This TRR covers privilege escalation and persistence through **Kubernetes
RBAC**: writing or changing the objects in the `rbac.authorization.k8s.io` API
group (`roles`, `clusterroles`, `rolebindings`, `clusterrolebindings`) so that
an identity the adversary controls gains more permission than it had.

This TRR does not cover these related actions:

- Authenticating with a credential the adversary already stole and using the
  access it already has, with no permission change. ATT&CK T1078 (Valid
  Accounts) covers that. The chokepoint here is the *write* that changes a
  permission, not a login.
- Granting a cloud IAM role on a managed cluster (GKE, EKS, AKS). That write
  happens in the cloud provider's API, not the Kubernetes API server, so the
  Kubernetes audit log does not see it. ATT&CK T1098.003 (Additional Cloud
  Roles) covers it. A managed-cluster attack can chain both.
- Creating a Kubernetes identity (a ServiceAccount). This report changes what an
  identity *can do*, not whether it exists.

> One third-party catalog files this technique under T1548 (Abuse Elevation
> Control Mechanism) with a Defense Evasion tactic. ATT&CK is authoritative:
> T1098.006, tactics Persistence and Privilege Escalation.

## Technique Overview

Kubernetes decides what every identity — a user, a group, or a service account —
is allowed to do with Role-Based Access Control (RBAC). Four object types hold
those decisions. A Role or a ClusterRole lists permissions. A RoleBinding or a
ClusterRoleBinding grants a listed set of permissions to a subject.

An adversary who can already write these objects can quietly give an identity
they control a great deal of power, up to full cluster-admin. The grant stays
after a password reset or a pod restart, because it lives in the cluster's own
configuration, not in a stolen credential. This is the Kubernetes form of
"adding yourself to the admins group."

The technique is attractive for three reasons. It looks like ordinary
administration, because operators and GitOps pipelines create bindings all the
time. It survives reboots and credential rotation. And in its loudest form it
can grant power to *every* authenticated user at once, by binding a built-in
group such as `system:authenticated`. The defensive goal is to see when an RBAC
object is written, and to tell an everyday, harmless grant apart from one that
hands out dangerous power.

## Technical Background

### The four objects and the one group

All four RBAC object types live in the API group `rbac.authorization.k8s.io`,
with the resource names `roles`, `clusterroles`, `rolebindings`, and
`clusterrolebindings`. A Role or ClusterRole carries a `rules` list; each rule is
a set of `apiGroups`, `resources`, and `verbs`. A binding carries a `subjects`
list and a single, required, **immutable** `roleRef` (an `apiGroup`, a `kind`,
and a `name`) that names the role it grants. Because `roleRef` is immutable,
re-pointing a binding at a different role means delete and re-create.

A RoleBinding's `roleRef` may name a Role in its own namespace **or** a
ClusterRole. In the second case the ClusterRole's rules apply inside that one
namespace. A ClusterRoleBinding may reference only a ClusterRole, and it grants
cluster-wide.

### The escalation guard, and the verbs that defeat it

Kubernetes has a built-in guard against privilege escalation. When you write a
Role or ClusterRole, you may normally include only permissions you already hold.
When you create a binding, you may normally bind only a role whose permissions
you already hold. Two special RBAC verbs defeat this guard: `escalate` lets a
subject write a role that grants more than it holds, and `bind` lets a subject
create a binding to a role it does not hold. A wildcard verb (`*`) on
`roles`/`clusterroles` includes `escalate` and `bind` by implication.

**An audit nuance that matters for detection.** `escalate` and `bind` are
authorization checks on a write request. They are *not* the audit `verb`. When
the adversary actually creates a binding or writes a role, the audit event's
`verb` is the ordinary `create`, `update`, or `patch`. The escalation shows up
two other ways: if the adversary is *granting* `escalate`/`bind` to someone, it
appears in the written role's `rules[].verbs` (in `requestObject`, so Request
level); and the authorization decision that let the write through is recorded in
the event annotations (`authorization.k8s.io/decision` and
`authorization.k8s.io/reason`).

There is also no `replace` audit verb. An HTTP `PUT` — `kubectl replace`, or an
apply sent as `PUT` — is recorded as `verb: update`. So the write-verb set is
`create`, `update`, `patch`, `delete`, and `deletecollection` (a bulk delete of the
roles or bindings in a namespace).

### The audit log, and what Metadata level hides

The API server writes audit events as its policy specifies, at level `None`,
`Metadata`, `Request`, or `RequestResponse`. For this technique the chokepoint
*fires* at `Metadata`: `verb`, `objectRef.apiGroup`, `objectRef.resource`,
`objectRef.name`, and `responseStatus.code` are all present, and
`objectRef.name` is what a name-gated test matches.

But `Metadata` hides the part that says whether the grant is dangerous. The
binding's `roleRef` (which role), the binding's `subjects` (who, or which group),
and the role's `rules` (wildcard, or `escalate`/`bind`) all live only in
`requestObject`, which `Metadata` does not record. At `Metadata` a binding to
`view` and a binding to `cluster-admin` are byte-for-byte identical. So the RBAC
audit rule must run at `Request` (or `RequestResponse`) level. RBAC writes are
rare and security-critical, so the extra volume is cheap.

### Why the technique works

Writing RBAC is a normal administration action. The cluster cannot tell a good
grant from a bad one by the write alone. The only controls are authorization
(who may write RBAC) and admission. A detection must therefore use the *content*
of the write: which role is bound, to whom, and with what rules — and the actor,
to separate an operator or a controller from an adversary.

## Procedures

| Procedure | ID | Name | Entry point |
|-----------|----|------|-------------|
| A | TRR9004.K8S.A | ClusterRoleBinding to a powerful ClusterRole | `create clusterrolebindings` |
| B | TRR9004.K8S.B | Namespaced RoleBinding to a ClusterRole | `create rolebindings` |
| C | TRR9004.K8S.C | Write a wildcard or escalate/bind role | `create`/`update`/`patch` `clusterroles` or `roles` |
| D | TRR9004.K8S.D | Bind a built-in group (mass grant) | `create` binding with a Group subject |
| E | TRR9004.K8S.E | Patch an existing binding or role | `patch`/`update` any RBAC object |

> A tool is not a procedure. `kubectl`, `client-go`, Helm, Argo CD, and a raw
> HTTP client all send the same RBAC write. They are the same procedure. The
> protocol and the client do not change the audit path.

**Reading the DDMs.** Each DDM is a PNG in the style of the
`tired-labs/techniques` reports, rendered from the Arrows app JSON beside it.
Green borders are operations the client performs. Blue borders are operations
the API server performs. Black borders are the abstract effect. The pill on a
node names the telemetry that records it, and the `Key: value` lines are the
details a rule can match. A shaded node is the primary detection opportunity. In
every procedure here the shaded node is the same one: the API server's audit of
the RBAC write.

### Procedure A: ClusterRoleBinding to a powerful ClusterRole  (`TRR9004.K8S.A`)

The adversary creates a ClusterRoleBinding whose `roleRef` names a powerful
ClusterRole (`cluster-admin`, the built-in `admin` or `edit`, or a custom
wildcard role) and whose subject is an identity they control. The grant is
cluster-wide and persists.

- **Prerequisites:** `create` on `clusterrolebindings`. To bind a role more
  powerful than the writer holds, the `bind` verb (or a wildcard that includes
  it) as well.
- **Mechanics:** the API server stores the binding. From then on, the subject has
  the ClusterRole's permissions across the whole cluster.
- **Impact:** cluster-wide privilege escalation and persistence. A binding to
  `cluster-admin` gives full control.
- **Tools on this path:** `kubectl create clusterrolebinding`, `kubectl apply`,
  and any client that POSTs to the `clusterrolebindings` endpoint.

#### Detection Data Model — `TRR9004.K8S.A`

![DDM - ClusterRoleBinding to a powerful ClusterRole](ddms/trr9004_k8s_a.png)

Source: [`ddms/trr9004_k8s_a.json`](ddms/trr9004_k8s_a.json) (Arrows app format).

**DDM summary.** The shaded node is the API server's authorize-and-audit of the
RBAC write (*Authorize + Audit RBAC Write*). It fires at `Metadata` on
`objectRef.apiGroup: rbac.authorization.k8s.io` with a write verb, which is the
invariant for every procedure. `roleRef` (the fact that this binds a ClusterRole,
and which one) is on the next node, visible only at `Request` level — that is
what grades the severity.

### Procedure B: Namespaced RoleBinding to a ClusterRole  (`TRR9004.K8S.B`)

The adversary creates a namespaced RoleBinding whose `roleRef.kind` is
`ClusterRole`. The binding lives in one namespace, but the role it grants is
defined cluster-wide, so a powerful ClusterRole (`admin`, `edit`, or a custom
wildcard role) grants strong power scoped to that namespace.

- **Prerequisites:** `create` on `rolebindings` in the target namespace; `bind`
  if the referenced role exceeds the writer's permissions.
- **Mechanics:** lower prerequisite than Procedure A (a namespaced create), and
  it blends with normal per-namespace operator activity.
- **Impact:** namespace-scoped escalation and persistence; strong if the
  referenced ClusterRole is powerful.
- **Tools on this path:** `kubectl create rolebinding --clusterrole=...`,
  `kubectl apply`.

#### Detection Data Model — `TRR9004.K8S.B`

![DDM - Namespaced RoleBinding to a ClusterRole](ddms/trr9004_k8s_b.png)

Source: [`ddms/trr9004_k8s_b.json`](ddms/trr9004_k8s_b.json) (Arrows app format).

**DDM summary.** The anchor is the same RBAC-write audit event as Procedure A;
only the resource is `rolebindings` and `objectRef.namespace` is set. The tell
that a namespaced binding reaches a cluster-wide role is
`requestObject.roleRef.kind: ClusterRole`, which is on the store node and needs
`Request` level.

### Procedure C: Write a wildcard or escalate/bind role  (`TRR9004.K8S.C`)

Instead of binding an existing powerful role, the adversary writes a *new* role
(or widens one they can already be bound to) that contains a wildcard rule
(`apiGroups: ['*']`, `resources: ['*']`, `verbs: ['*']`) or the escalation verbs
`escalate`/`bind`/`impersonate`. A stealth variant adds only a label so the role
is merged into a built-in aggregated ClusterRole; the written object looks tiny
while the aggregation controller inflates its effect.

- **Prerequisites:** `create`/`update`/`patch` on `roles` or `clusterroles`;
  `escalate` (or a pre-existing wildcard) to add permissions beyond what the
  writer holds.
- **Mechanics:** this builds the powerful role that a later or existing binding
  points at. A role grants nothing until it is bound.
- **Impact:** the role is the raw material for escalation; the aggregation
  variant hides the power.
- **Tools on this path:** `kubectl create clusterrole`/`role`, `kubectl apply`,
  `kubectl edit`, `kubectl patch`.

#### Detection Data Model — `TRR9004.K8S.C`

![DDM - Write a wildcard or escalate/bind role](ddms/trr9004_k8s_c.png)

Source: [`ddms/trr9004_k8s_c.json`](ddms/trr9004_k8s_c.json) (Arrows app format).

**DDM summary.** Same chokepoint audit event, resource `clusterroles` (or
`roles`). The dangerous content is the `rules` list — a wildcard `*`, or
`escalate`/`bind`/`impersonate` — which is on the store node and recorded only at
`Request` level. At `Metadata` a wildcard role and a read-only role are
indistinguishable.

### Procedure D: Bind a built-in group — mass grant  (`TRR9004.K8S.D`)

The adversary sets the binding's subject to a built-in group rather than a single
identity. Binding `system:authenticated` grants the role to *every*
authenticated user; `system:unauthenticated` or `system:anonymous` grants it to
unauthenticated callers. One small object grants power broadly, which is both
high-impact and easy to miss, because the object count is tiny.

- **Prerequisites:** `create` on `clusterrolebindings` or `rolebindings`; `bind`
  if the referenced role exceeds the writer's permissions.
- **Mechanics:** the subject is a `Group`, not a user or a service account.
- **Impact:** a mass privilege grant to all authenticated (or all anonymous)
  principals.
- **Tools on this path:** `kubectl create clusterrolebinding --group=...`,
  `kubectl apply`.

#### Detection Data Model — `TRR9004.K8S.D`

![DDM - Bind a built-in group](ddms/trr9004_k8s_d.png)

Source: [`ddms/trr9004_k8s_d.json`](ddms/trr9004_k8s_d.json) (Arrows app format).

**DDM summary.** The chokepoint audit event is identical to Procedure A. The
signal is the subject: `requestObject.subjects[].kind: Group` with a built-in
group name, on the store node, at `Request` level. The group name is the whole
point and is invisible at `Metadata`.

### Procedure E: Patch an existing binding or role  (`TRR9004.K8S.E`)

Rather than create a new object, the adversary amends a legitimate existing one:
patch a well-known binding to append an adversary subject, or patch an existing
role to add rules. This hides inside an object operators expect to exist, and it
evades detections that watch only `create`. (`roleRef` is immutable, so
re-pointing a binding needs delete-and-create, which also passes the chokepoint.)

- **Prerequisites:** `update`/`patch` on the target object; `bind`/`escalate` as
  applicable.
- **Mechanics:** the write verb is `patch` or `update`, not `create`.
- **Impact:** stealthy persistence and escalation by amending trusted RBAC
  objects.
- **Tools on this path:** `kubectl patch`/`edit`/`apply`, a client `PATCH`/`PUT`.

#### Detection Data Model — `TRR9004.K8S.E`

![DDM - Patch an existing binding or role](ddms/trr9004_k8s_e.png)

Source: [`ddms/trr9004_k8s_e.json`](ddms/trr9004_k8s_e.json) (Arrows app format).

**DDM summary.** Same chokepoint, verb `patch` or `update`. Because the chokepoint
keys on the API group and the write verb, not on `create`, it sees this path
where a create-only rule does not. The added subject or rule is in
`requestObject` at `Request` level.

## Detection Strategy

Compare the five DDMs. Every procedure is a mutating call against the
`rbac.authorization.k8s.io` API group, and every one leaves the same kind of
audit event. There is no path that escalates through RBAC without this write. So
the plan is one chokepoint rule, plus one severity rule that reads the request
body to grade the grant.

**Telemetry requirement.** The audit policy must record the
`rbac.authorization.k8s.io` group for the write verbs at **Request** (or
`RequestResponse`) level, so `requestObject` is present. Put the RBAC rule above
any `level: None` rule, and keep it user-agnostic: do not drop
`system:kube-controller-manager` or the bootstrap identities' RBAC *writes*,
because an adversary who impersonates a controller would then be invisible, and
the negative control needs to see the baseline writes and exclude them by name.

**Strategy 1 — chokepoint (covers A–E).**
Match audit events where `objectRef.apiGroup` is `rbac.authorization.k8s.io` and
`verb` is `create`, `update`, `patch`, `delete`, or `deletecollection`. Filter one
request: the namespace controller's `deletecollection` when it empties a namespace
that is being deleted (the namespace delete names the actor). This is noisy on its own: a
kubeadm cluster writes dozens of RBAC objects at bootstrap and reconciles the
default roles continuously. Baseline the **actor**, not the object: suppress
`system:kube-controller-manager`, `system:apiserver`, the kubeadm and
`system:bootstrappers` identities, and known GitOps or CI service accounts by
`user.username` and `user.groups`.

- Sensor: API server audit log.
- Rule: `detections/sigma/T1098.006/k8s_rbac_write.yml` (built).

**Strategy 2 — severity (grades A–E; needs Request level).**
On top of the chokepoint, match the writes that grant dangerous power: a
`roleRef.name` of `cluster-admin`, `admin`, or `edit`; a subject that is a
built-in group (`system:authenticated`, `system:unauthenticated`,
`system:anonymous`, `system:serviceaccounts`, or
`system:serviceaccounts:<namespace>`); a `rules` list with a wildcard or an
`escalate`/`bind`/`impersonate` verb; or a `rules` list that grants `nodes/proxy`
or `*/proxy` with any verb (a `get` is enough to run a command in every pod on the
node through the kubelet). A JSON patch (`kubectl patch --type=json`,
Procedure E's form) logs `requestObject` as the operation list, so the rule also
reads that list: an operation on `/rules` that carries a wildcard, one of the
verbs, `nodes/proxy` or `*/proxy`, or an operation on `/subjects` that names one of the groups. A patch or
update of a built-in binding whose `roleRef` is `cluster-admin` (`cluster-admin`,
`kubeadm:cluster-admins`) matches by name, because a patch carries no `roleRef`;
this grades Procedure E's headline form, a subject appended to that binding. A
subject appended to any other existing binding is graded only when it is one of
the groups above; otherwise only Strategy 1 sees it.

The kube-system `clusterrole-aggregation-controller` re-applying the built-in
`admin` and `edit` roles (both carry `impersonate` on `serviceaccounts`) is
filtered, but only while the written rules carry nothing more: no wildcard, no
`escalate` or `bind`, no `nodes/proxy`, and no `impersonate` on `users`, `groups`,
`uids` or `userextras`. `view` is never filtered. This keeps Procedure C's stealth variant
visible: a label patch that aggregates an existing powerful role
(`kubectl label clusterrole cluster-admin rbac.authorization.k8s.io/aggregate-to-view=true`)
carries no rules and does not fire, but the controller's next write of `view`,
`edit` or `admin` carries the wildcard and fires. The aggregated `impersonate`
test reads the rule in the Go field order the controller writes (`verbs`,
`apiGroups`, `resources`); a log pipeline that re-orders keys leaves that one
case filtered. This rule reads `requestObject`, so it needs `Request` level —
which is exactly the gap below.

- Sensor: API server audit log at `Request` level.
- Rule: `detections/sigma/T1098.006/k8s_rbac_privileged_grant.yml` (built).

**Demonstrated gap — the Metadata blindness.**
Emulate Procedure A (bind the read-only `view` role) and read the audit event at
`Metadata`: it shows `objectRef.resource: clusterrolebindings`,
`objectRef.name: trr9004-crb-view`, `verb: create` — and is indistinguishable
from a binding to `cluster-admin`, because `roleRef` lives only in
`requestObject`. The chokepoint still *fires* (good: high coverage), but it
cannot grade severity. Raising the RBAC audit rule to `Request` captures
`requestObject.roleRef` and closes the gap. The lab demonstrates this
harmlessly, by binding `view` and never granting real power.

**Deeper bypass — off the audit path (node/etcd sensor).**
RBAC written directly to etcd (with `etcdctl` or control-plane file and key
access), or injected by a malicious static-pod controller, never reaches the API
server, so no audit event exists. Only a node runtime or etcd sensor, or a
reconciliation that compares the RBAC in etcd and the API with an expected set,
catches it. This connects to TRR9003: node access, then a static pod, then a
mutation of RBAC off the audit path.

**Enrichment (raises fidelity; not a primary anchor).**

- **Actor.** An RBAC write from an identity that has never written RBAC, or from
  a pod service account, is unusual.
- **Authorization annotations.** `authorization.k8s.io/reason` names the binding
  that allowed the write; a write allowed by a binding the adversary just made is
  a chain.
- **Target.** A grant to a subject in a system namespace, or a self-grant (the
  writer binds a role to itself), is higher signal.

**Coverage summary.**

| Procedure | Covered by | How |
|-----------|-----------|-----|
| A | Strategy 1; graded by Strategy 2 | `create clusterrolebindings` |
| B | Strategy 1; graded by Strategy 2 | `create rolebindings` with `roleRef.kind: ClusterRole` |
| C | Strategy 1; graded by Strategy 2 | `create`/`update`/`patch` role with wildcard or escalate/bind |
| D | Strategy 1; graded by Strategy 2 | binding with a built-in Group subject |
| E | Strategy 1; graded by Strategy 2 | `patch`/`update` an existing RBAC object |

One chokepoint rule covers every procedure. One severity rule, which needs
`Request` level, tells a dangerous grant from an everyday one.

## Available Emulation Tests

The tests run in a lab cluster with an audit policy that records the RBAC group
at `Request` level. The lab is a `kind` cluster; its config and audit policy are
in [`detections/k8s/`](../../../detections/k8s/). Every object the tests write is
named with the unique prefix `trr9004-`, so a validator matches the emulation's
own events and the many bootstrap RBAC writes cannot be confused for it. One
script drives them all:
[`atomics/T1098.006/src/emulate.sh`](../../../atomics/T1098.006/src/emulate.sh),
with an Atomic Red Team wrapper in
[`atomics/T1098.006/T1098.006.yaml`](../../../atomics/T1098.006/T1098.006.yaml).

| Procedure | Test | Status |
|-----------|------|--------|
| TRR9004.K8S.A | `emulate.sh a` — bind a throwaway service account to the read-only `view` ClusterRole. | **built** |
| TRR9004.K8S.B | `emulate.sh b` — a namespaced RoleBinding whose `roleRef` is the `view` ClusterRole. | **built** |
| TRR9004.K8S.C | `emulate.sh c` — create a read-only role and a wildcard role that is never bound. | **built** |
| TRR9004.K8S.D | `emulate.sh d` — bind the `view` role to a throwaway group (the mass-grant shape). | **built** |
| TRR9004.K8S.E | `emulate.sh e` — patch the benign role to add a rule (`verb: patch`). | **built** |

Every binding points at the read-only `view` role, the wildcard role is never
bound, and the group binding uses a throwaway group `trr9004-nogroup` that no
principal belongs to. Nothing gains real power.

## Detections

| Strategy | Covers | Sigma rule | Sensor |
|----------|--------|------------|--------|
| 1 (chokepoint) | A, B, C, D, E | [`detections/sigma/T1098.006/k8s_rbac_write.yml`](../../../detections/sigma/T1098.006/k8s_rbac_write.yml) | API server audit log |
| 2 (severity) | grades A–E | [`detections/sigma/T1098.006/k8s_rbac_privileged_grant.yml`](../../../detections/sigma/T1098.006/k8s_rbac_privileged_grant.yml) | API server audit log (Request) |

The auditd validator (`detections/validate_detections.py`) replays syscall
atomics and cannot test these rules. The Kubernetes API server loop has its own
validator,
[`detections/validate_apiserver_detections.py`](../../../detections/validate_apiserver_detections.py):
it reads the API server audit log the emulation produced and asserts each Sigma
rule above matches an event from the emulation itself (one naming a `trr9004-`
object). The workflow
[`validate-apiserver-detections.yml`](../../../.github/workflows/validate-apiserver-detections.yml)
runs the whole loop on a `kind` cluster for every change to these files, and runs
the validator as a negative control on the audit log captured *before* the
emulation (where the many bootstrap RBAC writes must not make any rule pass).

Upstream: the SigmaHQ rule `kubernetes_audit_rolebinding_modification.yml`
matches bindings only (not role writes, procedure C), does not inspect
`requestObject`, and has no group-subject or escalate/bind detection. Elastic already
grades role bodies: "Kubernetes Creation or Modification of Sensitive Role" reads
`requestObject`/`responseObject` rules for a wildcard, `escalate`, `bind` or
`impersonate` (RequestResponse level only), and "Kubernetes RBAC Wildcard Elevation on
Existing Role" reads the stored role after a patch. Falco's k8saudit ruleset has
"ClusterRole With Wildcard Created" and "Attach to cluster-admin Role". None grades a
built-in group subject (Procedure D) or reads a JSON-patch operation list. Stratus Red
Team `k8s.persistence.create-admin-clusterrole` emulates Procedures A and C together.
Propose the chokepoint rule (whole RBAC group, all write verbs) plus the
`requestObject` severity rule as an improvement.

## References

- MITRE ATT&CK, T1098.006 Additional Container Cluster Roles:
  <https://attack.mitre.org/techniques/T1098/006/>
- Kubernetes documentation, Using RBAC Authorization (objects, `roleRef`,
  `escalate`/`bind`, privilege escalation prevention):
  <https://kubernetes.io/docs/reference/access-authn-authz/rbac/>
- Kubernetes documentation, RBAC Good Practices (escalation verbs):
  <https://kubernetes.io/docs/concepts/security/rbac-good-practices/>
- Kubernetes documentation, RoleBinding v1 API (`roleRef` immutable):
  <https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/role-binding-v1/>
- Kubernetes documentation, Auditing (levels, stages, event fields):
  <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>
- SigmaHQ rule, Kubernetes Rolebinding Modification:
  <https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_rolebinding_modification.yml>
- Elastic rule, Kubernetes Cluster-Admin Role Binding Created:
  <https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/kubernetes/persistence_cluster_admin_rolebinding_created>
- Microsoft Threat Matrix for Kubernetes:
  <https://microsoft.github.io/Threat-Matrix-for-Kubernetes/>
- TRR method:
  <https://github.com/tired-labs/techniques/blob/main/docs/TECHNIQUE-RESEARCH-REPORT.md>
