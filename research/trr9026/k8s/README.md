# Pod Port-Forward Tunnel (Kubernetes)

> Prose uses Simplified Technical English (ASD-STE100) where practical.
> API paths, resource names, subresource names, field names, and ATT&CK IDs are
> technical names.

## Metadata

| Key          | Value |
|--------------|-------|
| ID           | TRR9026 |
| External IDs | T1572 |
| Tactics      | Command and Control |
| Platforms    | Kubernetes |
| Contributors | det-eng |
| Status       | draft |

### Scope Statement

This TRR covers **port-forward tunneling** through the Kubernetes API server: using
the `pods/portforward` subresource, or the `nodes/proxy` subresource to the kubelet
`/portForward` endpoint (Procedure C), to open a TCP tunnel from the client, through
the kube-apiserver, to a port on a pod — reaching an in-cluster service, database, or
dashboard the client could not reach directly.

This TRR does not cover these related actions:

- Command execution in a container (`pods/exec`, `pods/attach`, ephemeral
  containers). ATT&CK T1609 (TRR9002) covers that. TRR9002 **explicitly scoped
  port-forward out** ("It opens a network tunnel. It does not run a command."); this
  report owns that tunnel. Port-forward and exec are siblings on the same
  chokepoint family (a pod subresource), different subresources.
- Port-forward that goes **directly to the kubelet** (`:10250`), bypassing the API
  server. That leaves no API audit event at all; it is the direct-kubelet gap TRR9002
  already documents, and it is Procedure D here (a demonstrated gap). Port-forward
  through **`nodes/proxy`** does leave an audit record (`objectRef.resource: nodes`,
  `subresource: proxy`), and Procedure C now covers it with a dedicated rule.
- The application-layer attack carried **over** the tunnel (a database login, a
  dashboard exploit). The tunnel is the C2/lateral-movement primitive; what rides it
  is a separate technique.

> **ATT&CK mapping caveat.** The best available ID is **T1572 (Protocol Tunneling)**,
> tactic Command and Control — a `kubectl port-forward` tunnels arbitrary TCP through
> the API server, which is the mapping Elastic's kubectl-networking rules also use.
> The ATT&CK Containers matrix has **no dedicated port-forward technique**, and
> T1572's v20 platforms are ESXi, Linux, macOS and Windows (no Containers), so T1572
> is a stated cross-domain best-fit. The lateral-movement framing (reach an internal
> service) is real, but the T1021 (Remote Services) sub-techniques are
> protocol-specific (SSH/RDP/SMB/VNC) and do not fit an API-server tunnel, so T1021 is
> a weaker secondary and is not the primary ID.

## Technique Overview

Kubernetes lets a client forward a local port to a port on a pod. `kubectl
port-forward` does this: it opens a tunnel from the client, through the API server, to
the pod, so the client can speak to the pod's own network as if it were local.
Operators use it to reach a service that is not exposed outside the cluster — a
database, an admin UI, a metrics endpoint — for debugging.

An adversary with a credential that can port-forward uses the same feature to reach
those same internal targets. The tunnel is a general TCP conduit: it lets the attacker
talk to an in-cluster database, an unauthenticated dashboard, or another pod's service
from outside the cluster, turning a single API credential into network reach inside
the cluster. It is a control channel and a lateral-movement primitive at once. The
request looks like ordinary debugging; the difference is who opens it, from where,
and into which pod.

## Technical Background

### The subresource and the two transports

A port-forward is a request to the `portforward` subresource of a pod:
`/api/v1/namespaces/<ns>/pods/<pod>/portforward`. The API server authenticates the
client, authorizes the `pods/portforward` resource, writes an audit event, and then
proxies the tunnel to the kubelet. In the audit event, `objectRef.resource` is
`pods`, `objectRef.subresource` is `portforward` (lowercase — the kubelet URL path
uses camelCase `portForward`, but the pods subresource in `objectRef` is lowercase),
and `objectRef.name` is the pod. These are set by the API server from the request
path; the attacker cannot forge them.

The tunnel runs over one of two transports, and the transport decides the audit
**verb**:

- **SPDY** (the legacy transport): an HTTP `POST` connection upgrade, recorded as
  `verb: create`.
- **WebSocket** (the `portforward.k8s.io` subprotocol that recent kubectl uses): an
  HTTP `GET` connection upgrade, recorded as `verb: get`.

A rule that matched only `verb: create` would be dead against a current kubectl — the
same WebSocket verb trap TRR9002 documents for exec. The invariant is the
subresource, independent of the verb.

### What the audit event carries, and what it does not

A port-forward is fully described at `Metadata` level: the verb, `objectRef`
(resource/subresource/namespace/name), the identity, `sourceIPs`, the user agent, the
`requestURI`, and the response code. Unlike exec, there is no command in the request —
`requestObject` is empty — so there is nothing in the body to key on; the subresource
is the whole signal. The forwarded ports and the bytes on the tunnel are not in the
audit log.

### Why the technique works, and the fidelity limit

Port-forward is a designed debugging feature, gated only by RBAC on the
`pods/portforward` resource. A developer's port-forward and an attacker's tunnel are
byte-identical in the audit record. So the detection is a low-fidelity hunting and
correlation anchor, not a standalone alert: the usable signal comes from context — a
port-forward by a service-account principal, cross-namespace, into kube-system or a
Secrets-bearing or database pod, off-hours, or from an unexpected source IP.

## Procedures

| Procedure | ID | Name | Entry point |
|-----------|----|------|-------------|
| A | TRR9026.K8S.A | Port-forward over SPDY | `create pods/portforward` |
| B | TRR9026.K8S.B | Port-forward over WebSocket | `get pods/portforward` |
| C | TRR9026.K8S.C | Port-forward through the node proxy | `nodes/proxy` to kubelet `/portForward` |
| D | TRR9026.K8S.D | Direct-kubelet tunnel | kubelet `:10250` (no API audit event) |

> A tool is not a procedure. `kubectl port-forward`, a client library, and a raw HTTP
> client all send the same `pods/portforward` request. They are the same procedure;
> the transport (SPDY vs WebSocket) is the distinction between A and B.

**Reading the DDMs.** Green borders are operations the client performs. Blue borders
are operations the API server performs. Purple borders are operations on the node. The
pill names the telemetry; the `Key: value` lines are what a rule matches; a shaded
node is the primary detection opportunity.

### Procedure A: Port-forward over SPDY  (`TRR9026.K8S.A`)

The adversary opens a port-forward over the legacy SPDY transport — an HTTP POST
upgrade — recorded as `verb: create` on `pods/portforward`.

- **Prerequisites:** `create`/`get` on `pods/portforward`.
- **Mechanics:** a POST connection upgrade; the API server proxies the tunnel.
- **Impact:** a TCP tunnel to the pod's network.
- **Tools on this path:** `kubectl port-forward` (older clients, many libraries).

#### Detection Data Model — `TRR9026.K8S.A`

![DDM - Port-forward over SPDY](ddms/trr9026_k8s_a.png)

Source: [`ddms/trr9026_k8s_a.json`](ddms/trr9026_k8s_a.json) (Arrows app format).

**DDM summary.** The shaded node is the API server's authorize-and-audit of the
port-forward (`objectRef.resource: pods`, `objectRef.subresource: portforward`), the
chokepoint for A and B. The verb is `create` on this transport.

### Procedure B: Port-forward over WebSocket  (`TRR9026.K8S.B`)

The adversary opens a port-forward over the WebSocket transport (the
`portforward.k8s.io` subprotocol) — an HTTP GET upgrade — recorded as `verb: get` on
`pods/portforward`. Modern kubectl defaults here.

- **Prerequisites:** `create`/`get` on `pods/portforward`.
- **Mechanics:** a GET connection upgrade; otherwise identical to A.
- **Impact:** the same TCP tunnel.
- **Tools on this path:** current `kubectl port-forward`, WebSocket-aware clients.

#### Detection Data Model — `TRR9026.K8S.B`

![DDM - Port-forward over WebSocket](ddms/trr9026_k8s_b.png)

Source: [`ddms/trr9026_k8s_b.json`](ddms/trr9026_k8s_b.json) (Arrows app format).

**DDM summary.** Same chokepoint, `verb: get`. A create-only rule would miss this; the
rule is verb-agnostic and matches both.

### Procedure C: Port-forward through the node proxy  (`TRR9026.K8S.C`)

The adversary reaches the kubelet `/portForward` endpoint through the API server node
proxy (`nodes/proxy`), not the pods subresource. There is then no `pods/portforward`
event, but the API server does authorize and audit the `nodes/proxy` request: the
record shows `objectRef.resource: nodes`, `objectRef.subresource: proxy`, and the
`/proxy/portForward/` path in `requestURI`. `objectRef.name` is the node, so the target
pod is carried only in `requestURI`.

- **Prerequisites:** RBAC `get`/`create` on `nodes/proxy`, and a raw client — `kubectl
  port-forward` never uses this path.
- **Mechanics:** a request to `/api/v1/nodes/<node>/proxy/portForward/<ns>/<pod>`,
  proxied to the kubelet. WebSocket is a `get`, SPDY is a `create`, so the record's
  verb is `get` or `create`.
- **Impact:** the same TCP tunnel, recorded as a `nodes/proxy` event, not a
  `pods/portforward` one.
- **Tools on this path:** `kubeletctl`, a raw client, `kubectl get --raw`.

#### Detection Data Model — `TRR9026.K8S.C`

![DDM - Port-forward through the node proxy](ddms/trr9026_k8s_c.png)

Source: [`ddms/trr9026_k8s_c.json`](ddms/trr9026_k8s_c.json) (Arrows app format).

**DDM summary.** The shaded node is the API server's authorize-and-audit of the
`nodes/proxy` request (`objectRef.resource: nodes`, `objectRef.subresource: proxy`,
`requestURI` holds `/proxy/portForward/`), the chokepoint for Procedure C. The rule
is verb-agnostic (`get` for WebSocket, `create` for SPDY). `k8s_node_proxy_exec`
(TRR9002) does not fire on this path: its filter excludes the `portForward` endpoint,
and the path names no `/exec/`, `/run/` or `/attach/`. Nearest prior art: Elastic ships
a native rule on any non-system `nodes/proxy` request
(`privilege_escalation_api_proxy_to_node.toml`) and an AKS rule that names
`/proxy/portForward` (`execution_azure_aks_kubelet_proxy_command_endpoint.toml`); this
report references them and ships a provider-agnostic Sigma rule scoped to the
port-forward endpoint.

### Procedure D: Direct-kubelet tunnel  (`TRR9026.K8S.D`)

The adversary port-forwards straight to the kubelet on `:10250`, bypassing the API
server. There is then no API audit event at all — the record exists only on the node.

- **Prerequisites:** a kubelet client credential and network reach to `:10250`.
- **Mechanics:** a direct kubelet `/portForward` call, no API server in the path.
- **Impact:** the same tunnel, with no API audit trace.
- **Tools on this path:** `kubeletctl`, a raw client to `:10250`.

#### Detection Data Model — `TRR9026.K8S.D`

![DDM - Direct-kubelet tunnel](ddms/trr9026_k8s_d.png)

Source: [`ddms/trr9026_k8s_d.json`](ddms/trr9026_k8s_d.json) (Arrows app format).

**DDM summary.** The shaded node is a node sensor, not the audit log: a direct kubelet
port-forward writes no API audit event. This is the TRR9002 direct-kubelet gap,
restated for the tunnel. A node/kubelet-access sensor is the only cover; the lab states
the gap and makes no kubelet call.

## Detection Strategy

Compare the four DDMs. Procedures A and B both produce a `pods/portforward` audit
event and differ only on the verb, so one verb-agnostic chokepoint rule covers both.
Procedure C never produces a `pods/portforward` event, but it does produce a
`nodes/proxy` event with the `/proxy/portForward/` path, which a second verb-agnostic
rule covers. Procedure D, the direct-kubelet form, writes no API audit event at all, so
the audit-log chokepoints are structurally blind to it.

**Telemetry requirement.** The audit policy must record `pods/portforward` at
`Metadata` or higher. The shared policy
(`detections/k8s/audit-policy-apiserver.yaml`) records it: this report adds an
explicit `pods/portforward` Metadata rule so the capture is self-documenting and does
not rely on the catch-all. No request body is needed. Strategy 2 needs the
`nodes/proxy` subresource at `Metadata` or higher, with `requestURI`. This report
pins `nodes/proxy` at `Metadata` in the same TRR9026 rule, so the capture is
self-documenting and does not rely on the final catch-all; a policy that drops
`nodes/proxy` (or all `nodes` subresources) at `None` would make Strategy 2 blind.

**Strategy 1 — chokepoint (covers A, B).**
Match an audit event where `objectRef.resource` is `pods` and `objectRef.subresource`
is `portforward`, with no verb filter. SigmaHQ ships no `pods/portforward` rule
(only the exec sibling); Falco's default k8saudit ruleset ships an equivalent
`port-forward` rule, so this is its provider-agnostic Sigma/pySigma counterpart,
stated as a backstop, not a discovery. It is a low-fidelity
hunting anchor: baseline the identities that legitimately port-forward.

- Sensor: API server audit log.
- Rule: `detections/sigma/T1572/k8s_pod_portforward.yml` (built).

**Strategy 2 — node-proxy chokepoint (covers C).**
Match an audit event where `objectRef.resource` is `nodes` and `objectRef.subresource`
is `proxy`, the `requestURI` path (the text before `?`) names the kubelet
`/portForward` endpoint, with no verb filter. This is the port-forward tunnel reached
through `nodes/proxy`. The kubelet routes `/portForward` case-sensitively (the
camelCase route), so the rule matches the camelCase `portForward` segment — the same
casing `k8s_node_proxy_exec` (TRR9002) uses for this endpoint in its filter. The API
server joins the proxied path with `path.Join` before it routes it to the kubelet, so
it drops empty (`//`) and single-dot (`/./`) segments and resolves `/../`, and it
decodes percent encoding. The two rules split these shapes: `k8s_node_proxy_exec`
fires on any `nodes/proxy` `requestURI` path that holds a percent-encoded byte or a
`/../` segment, whatever endpoint it seems to name, so a port-forward behind an
encoded endpoint is detected there. This rule allows empty and single-dot segments
between `/proxy/` and `portForward/` (for example `/proxy//portForward/` or
`/proxy/./portForward/`), which `k8s_node_proxy_exec` does not match. A request that
names `/portForward/` and also holds a percent-encoded byte or a `/../` segment (for
example `/proxy/portForward/../run/...`) fires both rules — an acceptable, documented
double alert, because such a request is itself anomalous.

- Sensor: API server audit log.
- Rule: `detections/sigma/T1572/k8s_node_proxy_portforward.yml` (built).

**Correlation and severity lift (built on Strategy 1).**
A port-forward is high-signal when the context is wrong: the principal is a service
account (`system:serviceaccount:*`), the target pod is cross-namespace from the
caller, the target is in kube-system or is a Secrets-bearing or database pod, the time
is off-hours, or the `sourceIPs` are unexpected. These are triage lifts on the
chokepoint, not separate rules.

**Demonstrated gap — the direct-kubelet tunnel (Procedure D).**
A port-forward straight to the kubelet on `:10250` leaves no API audit event at all.
The audit-log chokepoints are structurally blind to it, the same gap TRR9002
demonstrates for exec. A node/kubelet-access sensor is the only cover. The lab states
the gap and makes no kubelet call.

**Coverage summary.**

| Procedure | Covered by | How |
|-----------|-----------|-----|
| A | Strategy 1 (chokepoint) | `create pods/portforward` (SPDY) |
| B | Strategy 1 (chokepoint) | `get pods/portforward` (WebSocket) |
| C | Strategy 2 (node-proxy chokepoint) | `nodes/proxy` with `/proxy/portForward/`, any verb |
| D | gap (node sensor) | direct kubelet `:10250`; no API audit event |

Two verb-agnostic chokepoint rules cover the API-server transports and the node-proxy
path. The direct-kubelet tunnel is a stated gap, shared with TRR9002.

## Available Emulation Tests

The tests run in a lab cluster with the shared audit policy. The lab is a `kind`
cluster; its config and audit policy are in
[`detections/k8s/`](../../../detections/k8s/). The emulation port-forwards to a
throwaway pod named `trr9026-target` so a validator matches the emulation's own events,
and the forwarded connection is harmless (it opens and closes a local listener; no
traffic is sent to the pod). One script drives them:
[`atomics/T1572/src/emulate.sh`](../../../atomics/T1572/src/emulate.sh), with Atomic
Red Team wrappers in [`atomics/T1572/T1572.yaml`](../../../atomics/T1572/T1572.yaml).

| Procedure | Test | Status |
|-----------|------|--------|
| TRR9026.K8S.A | `emulate.sh a` — port-forward to `trr9026-target` over SPDY (`verb=create`). | **built** |
| TRR9026.K8S.B | `emulate.sh b` — port-forward to `trr9026-target` over WebSocket (`verb=get`). | **built** |
| TRR9026.K8S.C | `emulate.sh c` — reach the kubelet `/portForward` for `trr9026-target` through `nodes/proxy` (`kubectl get --raw`). The un-upgraded GET is refused, but the API server writes the `nodes/proxy` record; a real tunnel writes the same `requestURI`. | **built** |
| TRR9026.K8S.D | `emulate.sh d` — print the gap: a direct-kubelet port-forward writes no API audit event. Read-only; it makes no kubelet call. | **built (statement only)** |

## Detections

| Strategy | Covers | Sigma rule | Sensor |
|----------|--------|------------|--------|
| 1 (chokepoint) | A, B | [`detections/sigma/T1572/k8s_pod_portforward.yml`](../../../detections/sigma/T1572/k8s_pod_portforward.yml) | API server audit log |
| 2 (node-proxy chokepoint) | C | [`detections/sigma/T1572/k8s_node_proxy_portforward.yml`](../../../detections/sigma/T1572/k8s_node_proxy_portforward.yml) | API server audit log |

The validator
[`detections/validate_apiserver_detections.py`](../../../detections/validate_apiserver_detections.py)
reads the API server audit log the emulation produced and asserts the Strategy 1 rule
matches an event whose `objectRef.name` is the `trr9026-target` pod, and the Strategy 2
rule matches a `nodes/proxy` event whose `requestURI` carries the `trr9026-` marker
(for a `nodes/proxy` request `objectRef.name` is the node, so the pod rides in
`requestURI`). The workflow
[`validate-apiserver-detections.yml`](../../../.github/workflows/validate-apiserver-detections.yml)
runs the loop on a `kind` cluster, with a negative control on the pre-emulation log.

Upstream: SigmaHQ has an exec rule but no `pods/portforward` rule; Falco's k8saudit
plugin ruleset has a `port-forward` rule. Elastic's audit rules cover the `nodes/proxy`
form (see Procedure C): "Kubernetes API Server Proxying Request to Kubelet"
(`privilege_escalation_api_proxy_to_node.toml`) on any non-system `nodes/proxy` request,
and an AKS rule that names `/proxy/portForward`
(`execution_azure_aks_kubelet_proxy_command_endpoint.toml`); its "Kubectl Network
Configuration Modification" rule sees `kubectl port-forward` as a process on the client
host. Propose the two Sigma rules: the `pods/portforward` chokepoint matching both
transports (the verb-agnostic form that catches the WebSocket `get`), and the
`nodes/proxy` `/proxy/portForward/` rule as a provider-agnostic counterpart to Elastic's.

## References

- MITRE ATT&CK, T1572 Protocol Tunneling:
  <https://attack.mitre.org/techniques/T1572/>
- Kubernetes documentation, Use Port Forwarding to Access Applications in a Cluster:
  <https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/>
- Kubernetes blog, Enabling WebSocket for port-forward (portforward.k8s.io):
  <https://kubernetes.io/blog/2024/08/20/websockets-transition/>
- Kubernetes documentation, Auditing:
  <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>
- Kubernetes documentation, Kubelet authentication/authorization:
  <https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/>
- Falco k8saudit plugin ruleset (the `port-forward` rule):
  <https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml>
- Elastic rule, Kubernetes API Server Proxying Request to Kubelet (`nodes/proxy`):
  <https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_api_proxy_to_node.toml>
- Elastic rule, Kubelet proxy command endpoint on AKS (`/proxy/portForward`):
  <https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/execution_azure_aks_kubelet_proxy_command_endpoint.toml>
- TRR method:
  <https://github.com/tired-labs/techniques/blob/main/docs/TECHNIQUE-RESEARCH-REPORT.md>
