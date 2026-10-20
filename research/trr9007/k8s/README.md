# Escape to Host via a Dangerous Pod Spec (Kubernetes)

> Prose uses Simplified Technical English (ASD-STE100) where practical.
> Field names, resource names, capability names, and ATT&CK IDs are technical
> names.

## Metadata

| Key          | Value |
|--------------|-------|
| ID           | TRR9007 |
| External IDs | T1611 |
| Tactics      | Privilege Escalation |
| Platforms    | Kubernetes |
| Contributors | det-eng |
| Status       | draft |

### Scope Statement

This TRR covers escape to the host through a **dangerous pod specification**: the
host-access fields a pod creator requests at admission time — a privileged
container, a `hostPath` volume, a host namespace (`hostPID`/`hostNetwork`/
`hostIPC`), or an added Linux capability.

This TRR does not cover these related actions:

- The in-container kernel or runtime escape once a pod is running (a `setns`,
  cgroups `release_agent`, or runc breakout). The Linux syscall atomic for T1611
  in this repository (`atomics/T1611/src/setns_namespace_join_behavioral.c`)
  covers that; it keys on syscalls, not the audit log. The two share the ATT&CK
  ID but are different platforms and different telemetry: this report is the
  Kubernetes pod-spec request, that one is the Linux syscall.
- Command execution into an existing privileged pod. ATT&CK T1609 (TRR9002)
  covers exec; a command does not grant host access, a dangerous spec does.
- Persistence through a static pod. ATT&CK T1543.005 (TRR9003) covers that. Here
  a static pod is only the clearest API-server-bypass *delivery* of a dangerous
  spec, and the overlap is deliberate — the same node sensor is the fallback for
  both.

`hostPort`, `runAsUser: 0`, and `allowPrivilegeEscalation` are weaker Pod
Security violations that enrich a finding but are not themselves host escape, so
they are enrichment, not chokepoint fields.

## Technique Overview

Kubernetes runs each workload in a container that is meant to be walled off from
the machine — the node — it runs on. This technique is an adversary who can
create workloads asking, at creation time, for a pod that tears that wall down.
The dangerous settings all live in the pod's own specification: mark the
container "privileged"; let it share the node's process, network, or IPC
namespace; mount a sensitive node directory into the container with a `hostPath`
volume (the root `/`, the Docker socket, `/etc/kubernetes`, or the kubelet
directory); or grant it powerful Linux capabilities (`SYS_ADMIN`, `SYS_PTRACE`,
`SYS_MODULE`).

A pod with any of these can reach the node itself and, from there, every other
pod on it. The adversary never needs a kernel exploit — Kubernetes hands over the
host because the pod spec politely asked. Because the request to create such a
pod goes through the API server, the audit log records the full pod specification,
so the dangerous request can be caught at the moment it is made. The audit log has
to record the spec for this to work, though: a cluster that logs only metadata
cannot see the dangerous fields, and there a sensor on the node is the only thing
that sees the privileged container.

## Technical Background

### The dangerous fields are in the request body

The dangerous fields are part of the Kubernetes PodSpec and are carried in the
API request body. They map to the Pod Security Standards "privileged" and
"baseline" violations: `securityContext.privileged`, `hostPID`/`hostNetwork`/
`hostIPC`, `hostPath` volumes, and added capabilities are exactly the fields the
Baseline profile forbids. PodSecurityPolicy was removed in v1.25 and replaced by
the Pod Security Admission controller, which is label-driven per namespace and
off by default on an unlabeled namespace — so on a default cluster these pods are
admitted.

### Why the audit level matters

The detection telemetry is the API server audit log. The submitted pod
specification appears in the audit event as the `requestObject` field **only at
audit level `Request` or `RequestResponse`**. At `Metadata` level — the common
default, and the cap on several managed providers — `requestObject` is absent, so
a rule that keys on spec fields has nothing to match. `Request` level is
sufficient: `requestObject` is the client-submitted body, which already contains
every adversary-set field. Because it is the request body, it is logged **even
when admission rejects the pod** (a 403), so the chokepoint also catches blocked
attempts.

### How the fields appear to a rule

The det-eng validator flattens an audit event the way any log store does: nested
objects become dotted field names, and arrays become JSON text. So the fields
split into two kinds, matched two ways:

- **Top-level booleans.** `requestObject.spec.hostPID`, `hostNetwork`, and
  `hostIPC` stay real booleans. A rule matches them with `: true`, which a Sigma
  backend compiles to an equality that a stored boolean satisfies.
- **JSON-string arrays.** `requestObject.spec.containers`, `initContainers`,
  `ephemeralContainers`, and `volumes` become JSON text. A rule matches
  `"privileged": true` with `|contains` and lists both the spaced (request-body)
  and compact (Go) forms so the rule is portable. Matching `"privileged": true`,
  not the bare key, is deliberate: it does not match a benign
  `"privileged": false`. A capability is matched with `|re` only inside a
  capabilities `"add"` list (`"add":\s*\[[^\]]*"SYS_ADMIN"`), and a hostPath only
  as a volume source key (`"hostPath":\s*\{`). A bare substring would also match a
  container named `syslog`, an env value, a `drop` list or a volume named
  `hostpath`. `ALL` grants every capability and is on the list. The API server
  does not validate capability names, and the runtimes normalise them: containerd
  upper-cases each added name (`"CAP_"+ToUpper`) and tests `ALL` with
  `EqualFold`; CRI-O does the same and also keeps a `CAP_` prefix in any case. So
  `sys_admin`, `all` and `Cap_Sys_Admin` grant the capability, and the rule
  matches the names case-insensitively (`|re|i`) with an optional `CAP_` prefix.

A pod created through a workload controller puts the same fields one level
deeper, under `requestObject.spec.template.spec.*` (and, for a CronJob,
`requestObject.spec.jobTemplate.spec.template.spec.*`).

### Why the technique works

The control a dangerous pod defeats is container isolation itself. The control
the detection relies on is that the API server sees and records the request
before the workload runs. The gap is the one delivery that skips the API server.

## Procedures

| Procedure | ID | Name | Dangerous field |
|-----------|----|------|-----------------|
| A | TRR9007.K8S.A | Privileged container | `securityContext.privileged: true` |
| B | TRR9007.K8S.B | hostPath mount of a sensitive node directory | `volumes[].hostPath` |
| C | TRR9007.K8S.C | Host namespace | `hostPID`/`hostNetwork`/`hostIPC: true` |
| D | TRR9007.K8S.D | Added dangerous capabilities | `securityContext.capabilities.add` |

> A delivery mechanism is not a procedure. The same dangerous field can arrive as
> a direct pod, through a workload controller, or as a static pod. These are
> delivery variants, covered by the chokepoint plus the two fallbacks, not new
> procedures — consistent with this repository's "a tool is not a procedure" rule.

**Reading the DDMs.** Green borders are operations the client performs. Blue
borders are operations the API server performs. Purple borders are operations on
the node (the container runtime). Black borders are the abstract effect. The pill
on a node names the telemetry that records it. A shaded node is the primary
detection opportunity; here it is the API server's admission audit of the pod
spec, shared by all four procedures.

### Procedure A: Privileged container  (`TRR9007.K8S.A`)

The adversary creates a pod whose container is `privileged`. A privileged
container runs with almost all host access.

- **Prerequisites:** `create` on `pods` in a namespace that admits the pod.
- **Mechanics:** the container gets the node's devices and can reach its
  filesystem.
- **Impact:** full reach to the node and every pod on it.
- **Tools on this path:** `kubectl apply`, `kubectl run --privileged`, any client.

#### Detection Data Model — `TRR9007.K8S.A`

![DDM - Privileged container](ddms/trr9007_k8s_a.png)

Source: [`ddms/trr9007_k8s_a.json`](ddms/trr9007_k8s_a.json) (Arrows app format).

**DDM summary.** The shaded node is the API server's admit-and-audit of the pod
spec, at `Request` level, where `requestObject.spec.containers` carries
`"privileged": true`. This is the chokepoint for all four procedures. The node
runtime (purple) is the fallback sensor for the delivery that skips the API
server.

### Procedure B: hostPath mount of a sensitive node directory  (`TRR9007.K8S.B`)

The adversary mounts a sensitive node directory into the container — the root
`/`, the Docker socket, `/etc/kubernetes`, or the kubelet directory.

- **Prerequisites:** `create` on `pods`.
- **Mechanics:** the container reads and writes host files through the mount.
- **Impact:** host file access; the Docker socket or the kubelet directory is a
  direct path to control the node.
- **Tools on this path:** `kubectl apply`, any client.

#### Detection Data Model — `TRR9007.K8S.B`

![DDM - hostPath mount](ddms/trr9007_k8s_b.png)

Source: [`ddms/trr9007_k8s_b.json`](ddms/trr9007_k8s_b.json) (Arrows app format).

**DDM summary.** Same chokepoint audit event; the tell is
`requestObject.spec.volumes` containing `"hostPath"`. The sensitive-path literals
(`"path": "/"`, `"/var/run/docker.sock"`, `"/etc/kubernetes"`,
`"/var/lib/kubelet"`) grade the severity.

### Procedure C: Host namespace  (`TRR9007.K8S.C`)

The adversary sets `hostPID`, `hostNetwork`, or `hostIPC`, so the container shares
the node's process, network, or IPC namespace.

- **Prerequisites:** `create` on `pods`.
- **Mechanics:** the container sees host processes, host network, or host IPC.
- **Impact:** host-level visibility and a path to other processes and sockets.
- **Tools on this path:** `kubectl apply`, any client.

#### Detection Data Model — `TRR9007.K8S.C`

![DDM - Host namespace](ddms/trr9007_k8s_c.png)

Source: [`ddms/trr9007_k8s_c.json`](ddms/trr9007_k8s_c.json) (Arrows app format).

**DDM summary.** Same chokepoint; the tell is a top-level boolean,
`requestObject.spec.hostPID: true` (or `hostNetwork`/`hostIPC`), matched by
equality, not inside the containers blob.

### Procedure D: Added dangerous capabilities  (`TRR9007.K8S.D`)

The adversary adds powerful Linux capabilities to the container — `SYS_ADMIN`,
`SYS_PTRACE`, `SYS_MODULE`, and others.

- **Prerequisites:** `create` on `pods`.
- **Mechanics:** the capability grants a specific host-level power without the
  full `privileged` flag.
- **Impact:** kernel-level actions; `SYS_ADMIN` is close to privileged,
  `SYS_MODULE` loads kernel modules, `SYS_PTRACE` traces host processes.
- **Tools on this path:** `kubectl apply`, any client.

#### Detection Data Model — `TRR9007.K8S.D`

![DDM - Added dangerous capabilities](ddms/trr9007_k8s_d.png)

Source: [`ddms/trr9007_k8s_d.json`](ddms/trr9007_k8s_d.json) (Arrows app format).

**DDM summary.** Same chokepoint; the tell is a capability name inside
`requestObject.spec.containers`, for example `"SYS_ADMIN"`.

## Detection Strategy

Compare the four DDMs. Every procedure puts its dangerous field in the pod spec,
and the pod spec is the request body the API server records at `Request` level.
So the chokepoint is one admission-time rule that fires on a pod write whose
`requestObject.spec` carries any dangerous field. Two fallbacks cover the two
deliveries that the pod-level chokepoint does not catch cleanly: a workload
controller (where the real create is the controller object), and a static pod
(where there is no API event at all).

**Telemetry requirement.** The audit policy must log `pods` (and
`pods/ephemeralcontainers`) and the workload controller resources for the write
verbs at **`Request`** level, so `requestObject` is present. `Metadata` level
makes every rule here blind. Put the `Request` rules first, and never let a broad
`None` rule for `pods/status` or a `pods` group shadow them.

**Strategy 1 — chokepoint (covers A–D, direct pods).**
Match a pod write (`objectRef.resource: pods`, verb `create`/`update`/`patch`)
whose `requestObject.spec` has a privileged container, a `hostPath` volume, a host
namespace, or a dangerous capability. This also catches a privileged ephemeral
container and a rejected (403) attempt.

- Sensor: API server audit log (`Request` level).
- Rule: `detections/sigma/T1611/k8s_podspec_host_access.yml` (built).

**Strategy 2 — controller fallback.**
Match a workload controller write (Deployment, DaemonSet, StatefulSet, ReplicaSet,
ReplicationController, Job, CronJob) whose embedded Pod template requests host
access. A pod created through a controller has the fields one (or, for a CronJob,
two) levels deeper, and the eventual pod create is by the controller service
account after admission. This rule catches the adversary's own create, with the
real identity and name. A privileged Job or CronJob also matches the TRR9005
chokepoint — the same write, two lenses; dedup by `auditID`.

- Sensor: API server audit log (`Request` level).
- Rule: `detections/sigma/T1611/k8s_podspec_controller_host_access.yml` (built).

**Strategy 3 — node sensor.**
A node runtime sensor sees the running container regardless of how it was
delivered, and it covers the one case the audit rules cannot: a `Metadata`-only
audit policy, where `requestObject` is absent and every spec-based rule is blind.
Reuse the TRR9003 chokepoint (`k8s_cri_static_pod_start.yml`), which catches any
pod the kubelet runs from a non-API source (`config.source: file`/`http`); a real
runtime agent (Falco "Launch Privileged Container", Tetragon, an EDR) additionally
sees the privileged, host-namespace, or host-mount container.

- Sensor: a node runtime sensor (CRI pod sandboxes; a runtime agent for the
  security context).

**The static-pod delivery is covered, with a caveat.**
A static pod runs on the node directly, but the kubelet then registers a mirror
pod so the API shows it, and that mirror create is audited — attributed to the
node identity (`system:node:<node>`) and, at `Request` level, carrying the full
spec. The chokepoint has no identity filter, so it matches that mirror create: the
sidecar case `mirror-create-privileged-static-pod` proves it on a `system:node`
pods-create that carries the spec. That is a weaker signal than a direct user create:
it looks like a kubelet action, so triage on the node identity together with the
dangerous spec, and confirm with the node sensor that the privileged container is
really running. The `emulate_k8s.sh gap` test writes the static pod and shows that the
node runtime sees it (`crictl`). It does not assert the mirror create (it can log
`static: no mirror pod object yet`), and no validator gate isolates a `system:node`
create.

**Demonstrated gap — the Request-level dependency.**
The real blind spot is the audit level, not the delivery. Under a `Metadata`-only
policy — the default cap on several managed providers — the `pods` create event is
present but `requestObject` is absent, so the chokepoint and the controller
fallback cannot see the dangerous fields at all, even for an ordinary
API-created privileged pod. The node sensor is then the only thing that sees the
privileged container. This is why the lab policy records `pods` and the workload
controllers at `Request` level; a cluster that caps audit at `Metadata` must lean
on the node sensor for this technique.

**Enrichment (raises fidelity; not a primary anchor).**

- **Sensitive hostPath.** A mount of `/`, `/var/run/docker.sock`,
  `/etc/kubernetes`, or `/var/lib/kubelet` is a direct node-control path.
- **Identity and source.** A dangerous pod from a pod service account, or an
  identity that has not created such a pod before, is unusual.
- **Combination.** Privileged plus `hostPID` plus a root `hostPath` together is a
  near-certain escape setup.

**Coverage summary.**

| Procedure / delivery | Covered by | How |
|----------------------|-----------|-----|
| A, B, C, D (direct pod) | Strategy 1 (chokepoint) | pod write with a dangerous `requestObject.spec` field |
| Any, through a controller | Strategy 2 (fallback) | controller write with a dangerous template |
| Any, as a static pod | Strategy 1 (via the mirror create) + Strategy 3 | `system:node` pods-create with the spec; node sensor confirms the running pod |
| Any, under a `Metadata`-only policy | gap (no repository rule) | `requestObject` absent; only a runtime agent's privileged-container rule sees the running container. `k8s_cri_static_pod_start` sees only a pod with `config.source` `file`/`http` |

One chokepoint rule covers the four dangerous-field paths for a direct pod and the
static-pod delivery (through the kubelet's mirror create). One fallback covers the
controller delivery. Under a `Metadata`-only policy no rule in this repository sees an
API-created dangerous pod; a runtime agent is the only view.

## Available Emulation Tests

The tests run in a lab cluster with an audit policy that records `pods` and the
workload controllers at `Request` level, and a node runtime sensor for the gap.
The lab is a `kind` cluster; its config and audit policy are in
[`detections/k8s/`](../../../detections/k8s/). Every object is named with the
unique prefix `trr9007-`, so a validator matches the emulation's own events and
the baseline privileged pods a kind cluster starts (kube-proxy, kindnet, the
control plane) cannot be confused for it. Every container only runs `sleep 3600`:
the host access is requested but never used. One script drives them all:
[`atomics/T1611/src/emulate_k8s.sh`](../../../atomics/T1611/src/emulate_k8s.sh),
with the pod manifests beside it and the Atomic Red Team wrappers in
[`atomics/T1611/T1611.yaml`](../../../atomics/T1611/T1611.yaml) (alongside the
Linux setns test for the same technique).

| Procedure / delivery | Test | Status |
|----------------------|------|--------|
| TRR9007.K8S.A | `emulate_k8s.sh a` — a privileged container. | **built** |
| TRR9007.K8S.B | `emulate_k8s.sh b` — a `hostPath` mount of the node root. | **built** |
| TRR9007.K8S.C | `emulate_k8s.sh c` — host namespaces (`hostPID` + `hostIPC`). | **built** |
| TRR9007.K8S.D | `emulate_k8s.sh d` — added `SYS_ADMIN` and `SYS_PTRACE`. | **built** |
| controller delivery | `emulate_k8s.sh ctrl` — a Deployment with a privileged template. | **built** |
| static-pod delivery | `emulate_k8s.sh gap` — a dangerous static pod on the node; the node sensor sees the running pod. The script does not assert the `system:node` mirror create. | **built** |

## Detections

| Strategy | Covers | Sigma rule | Sensor |
|----------|--------|------------|--------|
| 1 (chokepoint) | A, B, C, D (direct pod) | [`detections/sigma/T1611/k8s_podspec_host_access.yml`](../../../detections/sigma/T1611/k8s_podspec_host_access.yml) | API server audit log (Request) |
| 2 (fallback) | controller delivery | [`detections/sigma/T1611/k8s_podspec_controller_host_access.yml`](../../../detections/sigma/T1611/k8s_podspec_controller_host_access.yml) | API server audit log (Request) |
| 3 (node sensor) | static-pod delivery only (`config.source` `file`/`http`); not an API-created pod under a `Metadata`-only policy | [`detections/sigma/T1543.005/k8s_cri_static_pod_start.yml`](../../../detections/sigma/T1543.005/k8s_cri_static_pod_start.yml) (TRR9003) | node runtime sensor |

The Kubernetes API server loop has its own validator,
[`detections/validate_apiserver_detections.py`](../../../detections/validate_apiserver_detections.py):
it reads the API server audit log the emulation produced and asserts Strategies 1
and 2 match an event from the emulation itself (one naming a `trr9007-` object).
A `system:node` mirror create that carries the spec matches Strategy 1 (sidecar case
`mirror-create-privileged-static-pod`); the validator gate does not isolate it.
Strategy 3 is the TRR9003 CRI rule, validated by its own loop. The workflow
[`validate-apiserver-detections.yml`](../../../.github/workflows/validate-apiserver-detections.yml)
runs the loop on a `kind` cluster and runs the validator as a negative control on
the audit log captured *before* the emulation (which contains the baseline
privileged pods but no `trr9007-` object, so no rule may pass).

Upstream: Elastic ships one pods-only rule per field (privileged pod, `hostPID`,
`hostIPC`, `hostNetwork`, sensitive `hostPath`, excessive capabilities), Falco's
k8saudit ruleset has pod-only rules for privileged, sensitive mounts and the three host
namespaces, Splunk has privileged pod and host network, and SigmaHQ has privileged and
`hostPath` rules. None combines all four dangerous-field paths with the
controller-template fallback in one Sigma pair. Prior emulation: Stratus Red Team
`k8s.privilege-escalation.privileged-pod` and `k8s.privilege-escalation.hostpath-volume`
(Procedures A and B), and Atomic Red Team T1611 test 1 ("Deploy container using nsenter
container escape", a `hostPID` privileged pod: A and C).
Propose the chokepoint plus the controller rule as an improvement.

## References

- MITRE ATT&CK, T1611 Escape to Host:
  <https://attack.mitre.org/techniques/T1611/>
- Kubernetes documentation, Pod Security Standards (privileged/baseline fields):
  <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- Kubernetes documentation, Pod Security Admission:
  <https://kubernetes.io/docs/concepts/security/pod-security-admission/>
- Kubernetes documentation, Auditing (levels, stages, `requestObject`):
  <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>
- Kubernetes documentation, Security Context for a Pod or Container:
  <https://kubernetes.io/docs/tasks/configure-pod-container/security-context/>
- Elastic rule, Kubernetes Pod Created With HostNetwork:
  <https://www.elastic.co/guide/en/security/current/kubernetes-pod-created-with-hostnetwork.html>
- Microsoft Threat Matrix for Kubernetes, Privileged container:
  <https://microsoft.github.io/Threat-Matrix-for-Kubernetes/>
- TRR method:
  <https://github.com/tired-labs/techniques/blob/main/docs/TECHNIQUE-RESEARCH-REPORT.md>
