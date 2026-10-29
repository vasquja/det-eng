# Managed-cluster field mappings (AKS, GKE, EKS)

The Kubernetes audit rules (`product: kubernetes`, `service: audit`) are written for the
`audit.k8s.io/v1` Event: the record that the API server writes, and that the CI kind
clusters prove every rule on. Managed clusters store the same event in other shapes.
This directory holds a pySigma processing pipeline for each shape that renames the
fields, a converter, and real-shape anchors. The mappings are `experimental`, like the
rules, and are proved offline by
[`check_provider_mappings.py`](../check_provider_mappings.py) (see [The proof](#the-proof)).
No query here has run on a live AKS or GKE log yet: that is a human step (backlog issue
#55).

## Which pipeline for which log shape

| Platform and store | Record shape | Pipeline | Field names in the query |
|--------------------|--------------|----------|--------------------------|
| Self-managed (kubeadm, kind, the CI lab) | the native Event (JSON lines) | none | native |
| EKS: CloudWatch Logs, log group `/aws/eks/<cluster>/cluster`, streams `kube-apiserver-audit-*` | each log event is one native Event as JSON text | none | native, after JSON parsing (see [EKS](#eks-no-field-mapping)) |
| AKS, resource-specific mode: table `AKSAudit` (and `AKSAuditAdmin`, the same rows without `get` and `list`) | PascalCase columns; `dynamic` columns keep camelCase keys | [`kubernetes_aks_auditlogs.yml`](kubernetes_aks_auditlogs.yml) | `ObjectRef.resource`, `User.username`, `Verb`, ... |
| AKS, Azure diagnostics mode: table `AzureDiagnostics`, `Category == "kube-audit"` | the native Event as JSON text in `log_s` | none | native, after `parse_json(log_s)` |
| AKS export to Event Hubs or storage | the native Event as JSON text in `properties.log` | none | native, after JSON parsing |
| GKE: Cloud Logging, Cloud Audit Logs (`protoPayload.serviceName = "k8s.io"`) | a LogEntry with a `google.cloud.audit.AuditLog` payload | [`k8s_gke.py`](k8s_gke.py) (Python) | `protoPayload.methodName`, `protoPayload.resourceName`, ... |

Sources: [AKSAudit](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aksaudit)
and [AKSAuditAdmin](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aksauditadmin)
columns; the [AKS monitoring page](https://learn.microsoft.com/azure/aks/monitor-aks#azure-monitor-resource-logs)
(`extend event = parse_json(log_s)` for `kube-audit` in AzureDiagnostics); Falco's
`k8saudit-aks` plugin (the Event Hub record's `properties.log` is the audit event); the
[EKS user guide](https://github.com/awsdocs/amazon-eks-user-guide/blob/8d43223e0e0dbb6afec4a6c9d6ba5b837b52ebb8/latest/ug/observability/control-plane-logs.adoc)
(log group and stream names); GKE: see [SOURCES.md](SOURCES.md). Every source, its
commit and its SHA-256 is in [SOURCES.md](SOURCES.md).

## Convert

```
pip install -r detections/requirements.txt -r detections/requirements-convert.txt

# AKS: KQL for AKSAudit (default) or AKSAuditAdmin
python3 detections/pipelines/convert_k8s.py aks detections/sigma/T1609/k8s_pod_exec_attach.yml
python3 detections/pipelines/convert_k8s.py aks --table AKSAuditAdmin detections/sigma/T1611/k8s_podspec_host_access.yml

# GKE: the Python pipeline with any installed pySigma backend except kusto (sqlite ships
# with detections/requirements.txt; install the backend of your log store for its query language)
python3 detections/pipelines/convert_k8s.py gke --target sqlite detections/sigma/T1609/k8s_pod_exec_attach.yml
```

Output of the first command:

```
// detections/sigma/T1609/k8s_pod_exec_attach.yml
AKSAudit
| where ObjectRef.resource =~ "pods" and (ObjectRef.subresource in~ ("exec", "attach"))
```

A query that reads a whole request or response body starts with an `extend` line (see
[AKS](#aks)):

```
AKSAudit
| extend RequestObjectNotBag = iff(gettype(RequestObject) == "dictionary", dynamic(null), RequestObject)
| where ...
```

The converter converts each rule alone and prints a query for each rule that converts.
For a rule that does not, it writes one line on stderr and goes on with the next rule:

- `NOT PORTABLE: <rule>: <reason>`: the pipeline refuses a field that the provider does
  not record, or the rule's logsource is not `kubernetes` / `audit` (a CRI rule, a cloud
  rule). A rule is never converted into a query that silently drops a condition.
- `CANNOT CONVERT: <rule>: <reason>`: the converter cannot render a field (for example a
  map key with a `/` under a map it does not know, see below).

The exit code is 1 when a rule failed, 2 on a usage error or when the Kusto backend is not
installed (`aks` needs `detections/requirements-convert.txt`), else 0. `aks` with a
`--target` other than `kusto` is refused: `AKSAudit` is a Log Analytics table, queried
with KQL only, and only the `kusto` target writes the `extend` lines of the whole-body
columns. `gke --target kusto` is refused: GKE logs in Microsoft Sentinel are in the
`GCPAuditLogs` table, a different shape. With `--table AKSAuditAdmin`, the converter
warns on stderr when the rule loses positive cases there (`loses_positive_without_reads` in
[`mapping_results.json`](mapping_results.json)).

The AKS pipeline is YAML, so `sigma convert -p
detections/pipelines/kubernetes_aks_auditlogs.yml` loads it too, but with the stock Kusto
backend the query is wrong (next sections), and a query that reads a whole body names
`RequestObjectNotBag` without its `extend` line (KQL then fails on the unknown column).
`sigma convert -p` cannot load the Python GKE pipeline: use the converter.

## AKS

The pipeline renames each top-level field to its column (`verb` -> `Verb`, `requestURI`
-> `RequestUri`, `sourceIPs` -> `SourceIps`, `objectRef.` -> `ObjectRef.`, `user.` ->
`User.`, `requestObject.` -> `RequestObject.`, `responseStatus.` -> `ResponseStatus.`,
`annotations.` -> `Annotations.`, ...). Microsoft's sample queries read the keys inside a
`dynamic` column in camelCase (`ObjectRef.resource == "deployments"`, `User.username`,
`ResponseStatus.code != 401`), so only the first segment changes.

- **A whole body maps to a query-time column.** On the native Event (and in
  `sigma_eval.flatten()`, the validators' model) an object has no value of its own, so a
  whole-body item (`requestObject|re: ...`, `requestObject: null`) reads only a JSON-patch
  list or raw text. In KQL a `dynamic` column that holds a property bag is not null, and a
  string operator reads its JSON text. So the pipeline maps `requestObject` and
  `responseObject` (the whole field, not the paths under it) to `RequestObjectNotBag` and
  `ResponseObjectNotBag`, which the converter defines with an `extend` line: the body, or
  null when it is a property bag
  ([gettype()](https://learn.microsoft.com/kusto/query/gettype-function) returns
  `dictionary` for one). The harness models KQL the same way (below), and proves on
  every case that the whole-body items of the 9 rules that have them keep their truth.
- **Not portable:** the tables have no `ImpersonatedUser` column, so
  `T1134/k8s_impersonation.yml` and `k8s_impersonation_privileged.yml` fail conversion.
  Convert them for AzureDiagnostics (`parse_json(log_s)`) or the Event Hub export, which
  keep the raw Event.
- **AKSAuditAdmin has no `get` and `list` events** (the table page names only those two;
  whether it keeps `watch` is unverified: issue #55). The rules whose
  positive cases need such a read (computed on every case: `loses_positive_without_reads`
  in `mapping_results.json`) are `T1552.007/k8s_secret_access.yml` (its `watch` positive
  still fires), `T1609/k8s_pod_exec_attach.yml` and `T1572/k8s_pod_portforward.yml` (the
  WebSocket forms, verb `get`), the three `nodes/proxy` rules
  (`T1572/k8s_node_proxy_portforward.yml`, `T1609/k8s_node_proxy_exec.yml`,
  `T1609/k8s_node_proxy_kubelet_api.yml`), and the two impersonation rules (not portable
  to these tables anyway). Use `AKSAudit` for them; the converter warns.
- `RequestObject` and `ResponseObject` can be the string `"skipped-too-big-size-object"`
  (Microsoft Learn, column descriptions). A rule that reads the body then sees nothing.
- Microsoft sets the AKS audit policy; the lab policy is not in force there.
- **Key order:** Kusto does not keep the key order of a property bag
  ([the dynamic data type](https://learn.microsoft.com/kusto/query/scalar-data-types/dynamic)),
  and `dynamic_to_json()` sorts the keys. The harness checks each case with the keys in
  the original order and sorted. One block needs the API server's key order:
  [RULE_DEFECTS.md K43](../RULE_DEFECTS.md#k43-k8s_rbac_privileged_grant-the-aggregation-clause-needs-the-api-servers-key-order).
- **The AKS anchor is a column reference, not a recorded row.** No public AKSAudit row
  was found. [`anchors/aks/`](anchors/aks/) lists the columns (with each type and what
  the Learn description says it holds) and the paths of Microsoft's sample queries; the
  harness requires a `field_map` entry for every mapping that the pipeline writes, so a
  wrong column that the pipeline and the transform share is caught there.
- **Unverified (needs a Log Analytics workspace with AKS data):** that `contains`, `=~`,
  `in~`, `startswith` and `matches regex` on a `dynamic` value (a list, or an object at a
  path below a whole body) test its JSON text with no blanks (the harness assumes the
  compact text that `tostring()` writes); that `tolong()`, `todouble()` and `tobool()` of
  a `dynamic` number or boolean give the native comparison (the converter casts them, as
  the Learn page on `dynamic` says to); the order of keys that a query really sees.
  The casts also convert values of other types, so the KQL query can match a value that
  the native model does not:
  [tobool()](https://learn.microsoft.com/kusto/query/tobool-function) gives true for
  any non-zero number (`tobool(123) == true`; natively `hostPID: true` matches `true`,
  the string `"true"` and `1`, not `123`), and
  [tolong()](https://learn.microsoft.com/kusto/query/tolong-function) converts a string
  (`tolong("0") == 0`; natively `replicas: 0` does not match the string `"0"`). The API
  server rejects such a typed field, so only the body of a rejected request (a JSON
  patch or merge patch) can hold one; no sidecar case does. A guard such as
  `gettype(p) == "bool"` would make the query stricter than the native model (which
  matches the string `"true"`), and its type names on `dynamic` values are unverified,
  so the converter does not add one.

### The Kusto backend's defects (workaround in convert_k8s.py)

`pySigma-backend-kusto` 1.0.1 (the newest release on PyPI, 2025-11-28;
[AttackIQ/pySigma-backend-kusto](https://github.com/AttackIQ/pySigma-backend-kusto) at
`v1.0.1`, commit `c83f737`) puts every field name that is not one word in single quotes
(`field_quote = "'"`, `field_quote_pattern = "^\w+$"`, negated;
`sigma/backends/kusto/kusto.py` lines 49-57). In KQL a single-quoted token is a string
literal, so the query compares two constants and never reads the column:

```
$ sigma convert -t kusto -p detections/pipelines/kubernetes_aks_auditlogs.yml detections/sigma/T1609/k8s_pod_exec_attach.yml
'ObjectRef.resource' =~ "pods" and ('ObjectRef.subresource' in~ ("exec", "attach"))
```

`convert_k8s.py` subclasses the backend (`KqlPathBackend`) and fixes six defects:

1. A field becomes a KQL path: `ObjectRef.resource`; `Annotations['audit.k8s.io/truncated']`;
   `RequestObject.metadata.annotations['kubectl.kubernetes.io/last-applied-configuration']`;
   `RequestObject.data['config.yaml']`; `RequestObject['$deleteFromPrimitiveList/spec']['$patch']`.
   After a map name in `MAP_PARENTS` (`annotations`, `labels`, `matchLabels`,
   `nodeSelector`, the ConfigMap / Secret maps `data`, `stringData`, `binaryData`, and the
   user's `extra` map, for example `User.extra['authentication.kubernetes.io/pod-name']`)
   the rest of the field is one key. Under any other key the field splits at each dot; a part
   that holds a `/` (and does not start with `$`, a strategic-merge directive) fails
   conversion (`CANNOT CONVERT`), because its map is unknown. A dotted key without a `/`
   under an unknown map is split at each dot: add its map to `MAP_PARENTS`. A field that
   walks into an object under a `MAP_PARENTS` name (a ControllerRevision's `data` is an
   object) is rendered as one key; no rule here reads one.
2. A value list with a wildcard value renders each value from the Sigma field (the stock
   backend renders the field twice, `''ObjectRef.name'' startswith ...`, and splits an
   inner wildcard into unordered `contains` terms).
3. A value with an inner wildcard is `matches regex "(?is)^a.*b$"` (the stock backend's
   regex is unanchored and case-sensitive). The `s` flag lets a wildcard match a line
   break, as SQLite `LIKE` does in the native model: without it, `.` does not match `\n`
   in a KQL regex ([regex syntax](https://learn.microsoft.com/kusto/query/re2)), and
   `requestObject.data.Corefile: '*forward*8.8.8.8*'` would miss a multi-line Corefile.
4. Numbers on a `dynamic` path are cast: `tolong(ResponseStatus.code) in (200, 202)`,
   `tolong(ResponseStatus.code) == 201`, `tolong(RequestObject.spec.replicas) > 0`
   (`todouble()` for a non-integer). The stock backend tests a number list as strings
   (`in~ ("200", "202")`) and compares without a cast.
5. A boolean is `tobool(RequestObject.spec.hostPID) == true` (the stock backend writes
   `=~ true`, and KQL documents `=~` for strings only:
   [=~ operator](https://learn.microsoft.com/kusto/query/equals-operator)).
6. A plain value list under `|all` is `ObjectRef.name =~ "a" and ObjectRef.name =~ "b"`
   (Sigma: the field equals each value). The stock backend writes `has_all ("a", "b")`,
   a search for terms in the field
   ([has_all](https://learn.microsoft.com/kusto/query/has-all-operator)), not equality.
   No rule here has such a list.

`python3 detections/pipelines/convert_k8s.py --self-test` reproduces each defect with the
stock backend, proves each fix, and converts every rule the pipeline converts (each field
a valid KQL path, rendered once) (CI: `provider-mappings`). When upstream fixes a defect and
the pin moves, the self-test fails on purpose at that defect: remove that part of the
workaround then.

The upstream issue text (prepared, not filed; filing it is a human step) is in
[`upstream/pySigma-backend-kusto/ISSUE.md`](../../upstream/pySigma-backend-kusto/ISSUE.md),
listed in [UPSTREAM.md](../../UPSTREAM.md#tool-issues).

## GKE

GKE does not keep the Event. It encodes it in a Cloud Logging LogEntry (the grammar is
in [`k8s_gke.py`](k8s_gke.py); each line has a source in [SOURCES.md](SOURCES.md)):

| Event field | GKE LogEntry field |
|-------------|--------------------|
| `verb`, `objectRef.resource`, `objectRef.subresource` | `protoPayload.methodName`: `io.k8s.<group>.<version>.<resource>[.<subresource>].<verb>`; `<group>` is `core`, or the API group without `.k8s.io` and with its labels reversed (`rbac.authorization.k8s.io` -> `authorization.rbac`) |
| `objectRef.apiGroup`, `objectRef.namespace`, `objectRef.name` | `protoPayload.resourceName`: `<group>/<version>[/namespaces/<ns>]/<resource>[/<name>[/<subresource>]]`; `<group>` is `core` or the full group; a namespace object is `core/v1/namespaces/<name>`. A create without a subresource has no `<name>` when it failed, and the created object's name when it succeeded |
| `objectRef.apiGroup: null` (the core group) | `protoPayload.methodName` `io.k8s.core.<version>.*` |
| `user.username` | `protoPayload.authenticationInfo.principalEmail` |
| `impersonatedUser.username` | `protoPayload.authenticationInfo.authoritySelector` (Elastic's GKE rules say so; no public record shows it: unverified) |
| `sourceIPs` | `protoPayload.requestMetadata.callerIp` (one address) |
| `userAgent` | `protoPayload.requestMetadata.callerSuppliedUserAgent` |
| `requestObject`, `responseObject` | `protoPayload.request`, `protoPayload.response` (a `google.protobuf.Struct`, with an `@type` key) |
| `annotations.<key>` | `labels.<key>` |

The pipeline rewrites each `verb` and `objectRef.*` item into regular expressions on
`methodName` and `resourceName`, adds `protoPayload.serviceName: k8s.io`, and renames
the other fields. A wildcard stays inside one name segment. Each generated regular
expression is in the portable `|re` subset ([detections/README.md, Portable regular
expressions](../README.md#portable-regular-expressions)), and the harness lints each one
(RE2 too). `objectRef.name` is exact also where the path alone is ambiguous: a configmap
in namespace `kube-system` does not match `objectRef.name: kube-system`, and a namespace
object and its `status` and `finalize` subresources do. The anchor
[`anchors/gke/method-and-resource-names.json`](anchors/gke/method-and-resource-names.json)
holds these properties as `must_hold` / `must_not_hold` probes (also: no prefix match of
a namespace or a group, `delete` is not `deletecollection`, a subresource is not a group
label), and the self-test plants each regex error and requires a probe to catch it.

- **Create names.** The API server fills `objectRef.name` from the request body before
  it generates a name, so a `generateName` create has no `objectRef.name` (kube-apiserver
  v1.36.4, `handlers/create.go` line 161 and `audit/request.go` lines 129-135). GKE's
  `resourceName` for that create holds the generated name (a recorded KHI entry), and a
  failed create has no name even when the request names the object (KHI's extractor
  tests). The transform follows both: on a create without a subresource, the name is the
  response object's name, else `objectRef.name`, and no name when the create failed. So
  an `objectRef.name` item on a failed create, or on a generateName create, can differ on
  GKE; no current case shows such a difference (reason `GKE_CREATE_NAME` approves one,
  with the same counterfactual proof as below).
- **Namespace creates.** `objectRef.namespace: X` also holds on GKE on the create of
  namespace X: `core/v1/namespaces/<name>` is both the namespace object and the
  namespace prefix of a path, and a successful create names the created object. The
  native Event has no namespace there (kube-apiserver v1.36.4 `requestinfo.go` lines
  194-196 take the namespace from a path part after `namespaces`, and `POST
  /api/v1/namespaces` has none; `audit/request.go` lines 130-131 take it from the
  object's `metadata.namespace`, which a Namespace does not have). On a get, update or
  delete of namespace X the native `objectRef.namespace` is X too, so only the create
  differs. No current rule or case shows the difference; the anchor
  [`anchors/gke/method-and-resource-names.json`](anchors/gke/method-and-resource-names.json)
  holds it as two `known_differences` probes (true on GKE, false natively), so a change
  of the encoding shows there.
- **Not portable (conversion fails, with the reason):** `requestURI` (resourceName has
  no query string, so the `?dryRun=All` filters of the delete and write rules and the
  kubelet path items of the three `nodes/proxy` rules cannot be written);
  `responseStatus.*` (the sources conflict: gke-mcp lists
  `protoPayload.responseStatus.code`, "the HTTP status code for the request (if
  present)", but `audit_log.proto` and the recorded KHI entries have only
  `protoPayload.status`, a `google.rpc.Status` with code 0 = OK, and Falco's converter
  infers the HTTP status; the safe default is to refuse, a human decision); `level` and
  `stage`; `user.groups`, `uid` and `extra`; `impersonatedUser.groups`, `uid` and
  `extra`; `objectRef.apiGroup: ''` (it never matches the native Event, which omits an
  empty group: write `null`). That is 13 of the 31 rules (the list is `NOT_PORTABLE` in
  the harness and in [`mapping_results.json`](mapping_results.json)); 3 of them
  (`k8s_impersonation`, `k8s_admission_webhook_created`,
  `k8s_malicious_admission_webhook_created`) only because of `responseStatus`.
- **JSON-patch bodies:** `protoPayload.request` is a Struct (an object). A JSON patch is
  an array, and no public GKE record shows how GKE stores it. The transform drops it, so
  the blocks that read the operation list do not work on the GKE shape: 173 cases over 9
  rules, each an `EXPECTED_LOSS` entry with the reason `GKE_JSON_PATCH`. The harness
  proves the reason for each entry: the difference vanishes when the transform keeps the
  body.
- **Reads need Data Access logs.** GKE writes reads (`get`, `list`, `watch`) to the Data
  Access log, "if enabled" (gke-mcp). Without it, the same 8 rules as on AKSAuditAdmin
  lose positive cases, and `k8s_secret_access` also loses its `watch` positive
  (`loses_positive_without_reads.gke_admin_activity`).
- **The store model.** The harness evaluates GKE records as `sigma_eval.flatten()` does:
  an object (the `request` Struct) has no value of its own. That is right for a store
  that flattens the LogEntry JSON to leaf fields. A store whose string operators read an
  object's JSON text (like KQL, or a JSON column in BigQuery) needs the AKS treatment of
  whole-body items: that is not modelled for GKE.
- **Unverified (no public GKE record shows it):** the impersonation encoding above; the
  HTTP status (above); the methodName of a non-resource request (the transform writes
  `io.k8s.<verb>`); the resourceName of a successful create logged without a response
  object (the transform uses `objectRef.name`, as KHI's trimmed test inputs show); whether
  the `nodes/<name>/proxy` resourceName carries the kubelet path (Elastic's rule
  `privilege_escalation_gcp_gke_api_proxy_to_node.toml` filters `resource_name` on
  `*stats/summary*`, which suggests it does; the `objectRef.name` regex accepts a longer
  path); the `@type` of an object of a group other than `core`; the GKE audit policy. KHI
  reads a dry-run marker from the label `command.gke.io/dryRun` (`extractor.go`); no
  Google document describes it.
- `docs.cloud.google.com` (where `cloud.google.com/kubernetes-engine/docs/how-to/audit-logging`
  redirects) did not resolve from the environment that wrote this, so no statement here
  rests on it.

## EKS (no field mapping)

EKS sends the native Event: each CloudWatch Logs event in the `kube-apiserver-audit-*`
streams is one `audit.k8s.io/v1` Event as JSON text. Evidence: the EKS user guide calls
the audit log type "Kubernetes audit logs"; Falco's `k8saudit-eks` plugin parses each
CloudWatch message with the generic `k8saudit` parser (`k8sauditeks.go` line 170); and
Elastic's EKS rules read native names (`aws.eks.audit.objectRef.resource`,
`aws.eks.audit.verb`). So the rules apply after JSON parsing with no field pipeline. Two
limits:

- A message over the CloudWatch Logs event size limit ends with `[Truncated...]` and is
  not valid JSON (Falco skips it: `k8sauditeks.go` lines 160-168). A large
  RequestResponse body (a ConfigMap, a big pod spec) can be lost this way.
- A query in CloudWatch Logs Insights reads the fields that it discovers in the JSON, and
  a JSON list there is not one text field. See the next section.

## Rules that read a list as its JSON text

`sigma_eval.flatten()` (the validators' event model) stores a JSON list as its JSON
text, so a rule can match inside it with `|contains` or `|re`. A store that keeps the
event as JSON text (the raw message) or as a `dynamic` value (KQL) supports that. A
backend that explodes a JSON array into multi-valued leaf fields (Elastic, whose own
Kubernetes rules read `kubernetes.audit.requestObject.spec.containers.securityContext.privileged`),
or into indexed keys (`field.0`, `field.1`), has no field that holds the list's text,
and such an item never matches there. Conversion does not fail, so the loss is silent.

A recount on this commit (`list_text_items` in `mapping_results.json`, computed from the
fields that hold a list in some sidecar event; the plan said 9 rules): **16 of the 31
rules** have such items.

| Kind of list | Rules |
|--------------|-------|
| a list of objects (containers, volumes, webhooks, RBAC rules or subjects) or the JSON-patch operation list | `T1098.006/k8s_rbac_privileged_grant`, `k8s_rbac_sensitive_permission_grant`, `T1546/k8s_admission_webhook_repointed_to_url`, `k8s_malicious_admission_webhook_created`, `T1565.001/k8s_coredns_corefile_poisoned`, `T1611/k8s_podspec_confinement_disabled`, `k8s_podspec_controller_host_access`, `k8s_podspec_host_access`, `T1685/k8s_admission_webhook_neutered`, `k8s_enforcer_workload_removed`, `k8s_security_tool_workload_removed` |
| a list of strings only (`requestObject.dryRun`, `impersonatedUser.groups`) | `T1070/k8s_events_deleted`, `k8s_namespace_deleted`, `k8s_workload_deleted_evidence`, `T1134/k8s_impersonation_privileged`, `T1685/k8s_admission_webhook_disabled` |

The harness mode `exploded` (indexed keys, no pipeline) shows the loss case by case and
never fails: all 16 rules show differences there, and the other 15 keep every verdict
and block. A multi-valued backend should keep more of the string lists
(`requestObject.dryRun|contains: All` can match one element), but not a pattern with JSON
quotes (`impersonatedUser.groups|contains: '"system:masters"'`) nor a list of objects;
this is reasoned from the item patterns, not run on such a backend.

**What a backend pipeline must do:** map each such item to the field that holds the raw
event JSON where the ingest keeps it (Splunk `_raw`, Elastic `event.original`, the
CloudWatch Logs Insights `@message`), and accept the scope loss: the text can then
match anywhere in the event, not only inside that list. No rule change is proposed, and
there is no RULE_DEFECTS entry: on the AKS shape (KQL model) and the GKE shape (a
flattening store), the harness proves that the items keep their truth on every case,
except the JSON-patch operation list on GKE (the transform drops those bodies: the
approved `GKE_JSON_PATCH` losses above), and the native Event (EKS, self-managed) is
the rules' own shape; the dependency is a property of the backend's ingest. A human
decides whether to track it in
[RULE_DEFECTS.md](../RULE_DEFECTS.md) instead (that would mark the 16 rules' procedures
"Proven, open defect" in [research/COVERAGE.md](../../research/COVERAGE.md)).

## The proof

[`check_provider_mappings.py`](../check_provider_mappings.py) runs in CI (job
`provider-mappings` in `.github/workflows/detection-quality.yml`, not a required check):

```
python3 detections/check_provider_mappings.py --check    # the check; also fails on a stale mapping_results.json
python3 detections/check_provider_mappings.py --self-test
python3 detections/pipelines/convert_k8s.py --self-test   # needs detections/requirements-convert.txt
```

For every Kubernetes audit rule with a sidecar, and for AKS and GKE, it transforms every
event of every case into the provider's record (the transforms are documented in the
script's docstring), compiles the rule, each block and each item plainly and through the
pipeline, and requires the same case verdict and the same events per block in both
shapes, for each variant of a list's text (`compact`, and `sorted` keys). The AKS records
follow the KQL model of a `dynamic` value: a list and an object read as their JSON text,
an object is not null, and the query-time columns hold the body unless it is an object
(the harness checks that it models the same columns that `convert_k8s.py` defines). It
also checks the mapped field names case-sensitively (SQLite column names are not), checks
that a mapped field is present wherever the native field is, lints every generated
regular expression, checks that the AKS converter can write every mapped field
(`convert_k8s.kql_path`: a field it cannot write is NOT PORTABLE with the reason
`CANNOT CONVERT: ...`, and an error that no approval excuses, as in the converter's own
self-test), and checks the anchors in `anchors/<provider>/`: the transform must
rebuild each real-shape record from its native Event, the named rules must give the
stated verdicts on both shapes, each methodName / resourceName pair from a source must
hold (and its `lost` items must not), each probe must hold or not hold as stated (a
`known_differences` probe: its stated, different truth on each shape), and each AKS
mapping must have a `field_map` entry. The converter self-test in turn requires that
the rules it refuses are exactly the rules that `mapping_results.json` marks not
portable to AKS. For the stores that keep no reads
(AKSAuditAdmin; GKE without Data Access logs) it reports, as a warning, the positive
cases that stop firing.

`--self-test` plants 24 errors and requires each one to be caught: a subresource read
from the verb position, a column the table does not have, a column in the wrong letter
case, a dropped subresource, a swapped column, a non-portable generated regex, a stale
approval, a changed approval, a reason that does not hold, an unapproved NOT PORTABLE
rule, a broken group encoding, a misspelled field, whole-body items that read the AKS
object column (caught only with the KQL model), a column swap that the pipeline and the
transform share, five GKE regex errors (a namespace prefix match, a cluster-scoped name
branch that accepts `namespaces`, an unanchored verb, a resource regex that accepts the
subresource label, a subresource regex that matches any label), an approval keyed on an
unknown provider, a create name taken from `objectRef.name`, an AKS converter that does
not know the `annotations` map (a `CANNOT CONVERT` field), a change of the GKE namespace
create encoding (a `known_differences` probe), and a stale results file.

**Approvals.** An accepted difference is an `EXPECTED_LOSS` entry keyed (provider, rule,
case) with its reason and its exact difference; a rule that cannot convert is a
`NOT_PORTABLE` entry keyed (provider, rule) with its items. Both are human approvals,
like the waivers in `check_sufficiency.py`. The check fails on a difference that is not
listed, on a listed difference that changed, on a reason that does not hold (each reason
but `KEY_ORDER` has a counterfactual transform without that one loss, and the difference
must vanish under it; a `KEY_ORDER` difference must show in the `sorted` variant only),
on a stale entry, and on an entry keyed on a provider that does not gate.
`python3 detections/check_provider_mappings.py --approvals-table` prints every approval
as a Markdown table (with the case kind, and "drops a positive" where a positive case
fires natively and not on the provider) for the pull request that a human approves.

**After a Kubernetes rule or case change.** Run `python3
detections/check_provider_mappings.py --check`. When it reports a new difference, run
`--propose`: it prints the tables for this run with the reason it can prove for each case
(`<WHY?>` where it proves none). A human reviews them; then `--write` updates
`mapping_results.json`. A new case that changes no provider result (no new difference, no
new list field, no new status) keeps `mapping_results.json` current: the file records no
case counts and no per-case text for the warning modes.

Each approval is keyed per case, and the approvals are Python tables in
`check_provider_mappings.py`. So a change that adds a provider difference (for example
each new GKE JSON-patch case in one of the 9 JSON-patch rules, a content-only sidecar
change), that makes an entry stale, or that adds a NOT PORTABLE item needs an edit of
that `.py` file. The `automerge` workflow treats a `.py` file as not content, so such a
pull request is a hand merge by the maintainer, by design: an approval is a human
decision. A result change that edits no approval (a new `list_text_items` entry, a
`loses_positive_without_reads` or `exploded` status change) changes only
`mapping_results.json`, which is not on the content allowlist either; adding
`^detections/pipelines/mapping_results\.json$` to that allowlist (as for
`detections/benign/scores.json`) would let only that kind of pull request merge without
the maintainer. A rule-level approval would remove most of the `.py` edits: approve, for
a (provider, rule), every difference that the `GKE_JSON_PATCH` counterfactual proves,
with no per-case list; but a new case is then approved without a review of that case.
Both are human decisions proposed in the Wave 4 pull request. The defaults: approvals
stay per case, and the allowlist does not change.

## mapping_results.json

Generated by `--write`; sorted keys, no timestamps, no case counts, so it changes only
when a result changes. Schema 2:

```
{
  "schema": 2,
  "generated_by": "python3 detections/check_provider_mappings.py --write",
  "providers": {"aks"|"gke"|"exploded": {"title": str, "gate": bool, "variants": [str],
                                          "pipeline": str|null}},
  "reads":     {"aksauditadmin"|"gke_admin_activity": str},     # what each store drops
  "summary":   {"aks"|"gke"|"exploded": {"same": int, "expected_loss": int,
                                          "not_portable": int, "diverges": int},
                "aksauditadmin"|"gke_admin_activity": {"rules_losing_a_positive": int}},
  "anchors":   {"anchors/<provider>/<file>.json": "ok"|"failed"},
  "rules": {
    "<T-id>/<stem>.yml": {
      "list_text_items": [atom],             # items that read a list as its JSON text
      "loses_positive_without_reads": {"aksauditadmin": bool, "gke_admin_activity": bool},
      "providers": {
        "aks"|"gke": {"status": "same"|"expected_loss"|"not_portable"|"diverges",
                      "not_portable": {atom: reason},
                      "expected_loss": {case: {"diff": str,
                                               "why": "GKE_JSON_PATCH"|"KEY_ORDER"|"GKE_CREATE_NAME"}},
                      "unexpected": {case: diff},   # empty when the check passes
                      "errors": [str]},             # empty when the check passes
        "exploded": {"status": "same"|"diverges", "loses_positive": bool}
      }
    }
  }
}
```

The `aks` row is the `AKSAudit` table; for `AKSAuditAdmin` and for GKE without Data
Access logs, read `loses_positive_without_reads` too. An atom is a detection item, named
as `rule_cases.py` names it (`block.field`, `block[i].field`). A diff is `<variant>:
<verdict difference>; blocks <names>`, or `all: ...` when every variant shows the same
difference. Status precedence: `not_portable` > `diverges` > `expected_loss` > `same`.
