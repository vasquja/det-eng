# Kubernetes rules on each platform

This page tells you which Kubernetes audit rule of this repository works on which
platform, with which audit policy and in which log shape, and why. CI proves every
rule live on a kind cluster with the lab policies in this directory. A managed cluster
(EKS, AKS, GKE, OpenShift) runs its own audit policy and stores the audit record in its
own shape. k3s writes no audit log until the admin sets one up.

Two offline checks make the generated tables on this page. Nothing on this page comes
from a live managed cluster: that is backlog issue #55. The hand-written parts cite a
file and line or a URL for each fact, and mark each fact that is not checked against a
primary source as **unverified**, with what would verify it.

## How to read this page

### Audit levels

The API server gives each request one level from the first policy rule that matches
it (kubernetes v1.36.4 `staging/src/k8s.io/apiserver/pkg/audit/policy/checker.go`):

| Level | What the record holds |
|---|---|
| `None` | no record |
| `Metadata` | who, what, where and the result: `user`, `verb`, `objectRef`, `requestURI`, `sourceIPs`, `userAgent`, `responseStatus`, `annotations`; no body |
| `Request` | Metadata and the request body (`requestObject`) |
| `RequestResponse` | Request and the response body (`responseObject`) |

A rule that reads `requestObject` or `responseObject` (a "grader") needs `Request` or
`RequestResponse` for the requests it grades. A rule that reads only Metadata fields
(a "chokepoint") works at `Metadata`. A policy can also omit a stage. When a policy
keeps the `RequestReceived` stage, one request writes a `RequestReceived` record and a
`ResponseComplete` record; a long-running request (watch, exec, attach, port-forward)
also writes a `ResponseStarted` record. The API server writes the `RequestReceived`
record before it handles the request, so that record has no `responseStatus`, no
`impersonatedUser` and no body (kubernetes v1.36.4
[`endpoints/filters/audit.go` L61-78](https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/apiserver/pkg/endpoints/filters/audit.go#L61-L78)).
A rule that tests none of these fields (and not `stage`) can alert twice for one
request; a rule that tests one of them fires only on a later record. Deduplicate by
`auditID`.

### What the two checks compute, and what they do not

- **The policy simulator**, [`k8s_policy_coverage.py`](../k8s_policy_coverage.py),
  replays every sidecar case of every rule as each policy would record it, and runs
  the real rule on the result. Its output is
  [`policy_coverage.json`](policy_coverage.json). It reads **published policy texts**
  ([`provider-policies/SOURCES.md`](provider-policies/SOURCES.md)), not captures:
  whether a provider runs its published text unchanged is unverified for every
  provider. It models the **policy only**: no transport, no size limit, no field
  names. A record can only lose data. When a policy logs a body that the case record
  does not hold, the simulator cannot add it: the code `not-modeled` counts those
  events where the rule reads that body, and those cases are not proven on that
  platform.
- **The mapping harness**,
  [`check_provider_mappings.py`](../check_provider_mappings.py), transforms every case
  into the AKS (`AKSAudit`) and GKE (Cloud Audit Logs) record shapes and checks that
  each rule keeps its verdict through the provider pipeline. Its output is
  [`mapping_results.json`](../pipelines/mapping_results.json). A rule that the
  pipeline cannot express is `NOT_PORTABLE`; a difference that a human accepted is an
  `EXPECTED_LOSS` entry. The harness reads the case records as recorded, not as a
  policy keeps them. See [`pipelines/README.md`](../pipelines/README.md).
- **This page** joins the two results per rule and platform log shape:
  [`k8s_platforms_md.py`](../k8s_platforms_md.py) rewrites the generated blocks from
  the two JSON files and the sidecars. A positive case that either check loses is lost
  in the cell. The two checks run apart, so a cell is the union of two losses, not one
  replay. For GKE with Data Access logs off, the script replays every case under the
  `gce-kube-up` policy with a filter that drops `get`, `list` and `watch`, as the
  simulator models the AKS `kube-audit-admin` category, so every count of that column
  is the store's. The script's docstring gives the exact rules.

### Support words and reason codes

Each cell has one support word, the positive cases that fire out of all positive
cases, and reason codes.

| Word | Meaning |
|---|---|
| **full** | every positive case fires on that shape |
| **partial** | some positive cases fire |
| **chokepoint only** | the rule is a grader that fires no positive case; its chokepoint rule fires every one of its own positive cases on that shape, and the replay ([Chokepoint pairs](#chokepoint-pairs)) shows the chokepoint firing on every positive case of the grader under that policy and store |
| **chokepoint partial** | as **chokepoint only**, but the chokepoint fires on some of the grader's positive cases, not all |
| **blind** | no positive case fires, and no chokepoint covers them |
| **not portable** | the shape's pipeline cannot express the rule (a field is not in the schema), and the policy and the store keep at least one positive case; the bracket gives the positive cases that they keep |

A cell that fails only on the schema is **not portable**, not **blind**: the policy and
the store keep the record, and only the provider's record shape lacks a field. When the
policy or the store keeps no positive case (for example `AKSAuditAdmin` and a rule whose
positives are all `get` or `list`), the cell is **blind**, and the missing field is a
code. On AKS a store that keeps the raw Event runs a rule that the `AKSAudit` columns
cannot express (the `AKS raw Event` columns); the `kube-audit-admin` category still
drops `get` and `list` there.

| Code | Meaning |
|---|---|
| `no-record n #i` | n positive cases leave no record: policy rule `#i` (0-based index over the policy's rules, in file order) sets level None or omits the stage; `#-` means that no rule matched |
| `body-removed n` | the record is kept at a lower level, so the body that the rule reads is gone |
| `opt-in n` | n positive cases that the policy names as opt-in losses: each needs a line of the policy that is commented out |
| `reads-dropped n` | the store keeps no reads: `AKSAuditAdmin` (and the `kube-audit-admin` category) drops `get` and `list`; GKE without Data Access logs drops `get`, `list` and `watch` |
| `not-in-schema: f` | the field `f` is not in the provider's schema (`NOT_PORTABLE`) |
| `approved-loss n` | an approved `EXPECTED_LOSS` entry drops n positive cases on that shape, in every variant of the JSON text |
| `approved-loss-if-sorted n` | the same, but only when the store sorts the keys of a JSON object (`KEY_ORDER`, [K43](../RULE_DEFECTS.md#k43-k8s_rbac_privileged_grant-the-aggregation-clause-needs-the-api-servers-key-order)); whether AKS or GKE does is open question 4. The cell counts these cases as lost |
| `approved-diff n` | n approved `EXPECTED_LOSS` entries change a block of the rule but no case verdict |
| `not-modeled n` | n events that the policy and the store log with a body the case record lacks, where the rule reads that body: those cases are not proven there |
| `fp n` | n negative cases fire on that shape: under the policy and the store, or by an approved mapping difference (see [False-positive exposure](#false-positive-exposure)) |
| `partial-record n`, `other n` | n positive cases lost for these reasons, as the policy simulator reports them |
| `chokepoint k/n` | (a grader) its chokepoint fires on k of the grader's n positive cases on that shape |
| `chokepoint not full (w)` | (a grader) the chokepoint's own cell on that shape has the word w, so it does not cover the grader there |

**Chokepoint pairs.** The grader and chokepoint pairs come from each TRR's Detection
Strategy (`GRADERS` in the script). `--write` and `--check` replay each grader's
positive cases through its chokepoint under every policy, with the simulator's record
model and the validators' backend; [Chokepoint pairs](#chokepoint-pairs) gives the
result. A chokepoint can filter some grader positives on purpose: the CoreDNS
chokepoint filters writes of `openshift-dns/dns-default` with the DNS Operator's
identity ([RULE_DEFECTS.md K45](../RULE_DEFECTS.md#k45-k8s_coredns_configmap_modified-the-dns-operator-filter-trusts-the-operators-name)),
so on OpenShift with the Default profile, where the Corefile grader is blind, no rule
sees those writes. The replay covers the policy, its log filter and a store without
reads (no mapping); the mapping verdict of a chokepoint comes from its own cases only.

### Unverified claims

A claim marked **unverified** was not checked against a primary source (the provider's
own documentation, source code or a live record). Each such claim says what would
verify it. Most of them need a live capture on the platform (backlog issue #55).

## Platform summary

Hand-written. Retrieved and checked on 2026-10-29, except where a cell says otherwise.

| Platform | Audit log on by default | Policy customizable | Record shape and field names | Pipeline needed | Transport limits |
|---|---|---|---|---|---|
| kind lab (CI) | Yes: each kind config passes `audit-policy-file` and `audit-log-path` to the API server (for example [kind-apiserver-cluster.yaml](kind-apiserver-cluster.yaml) lines 38-39). Without a policy file the API server records nothing ([kubernetes v1.36.4 `options/audit.go` L297](https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/apiserver/pkg/server/options/audit.go#L297)). | Yes: [audit-policy-apiserver.yaml](audit-policy-apiserver.yaml), [audit-policy.yaml](audit-policy.yaml), [audit-policy-staticpod.yaml](audit-policy-staticpod.yaml) | the native `audit.k8s.io/v1` Event, one JSON object per line, camelCase (`objectRef.resource`, `user.username`, `requestObject`) | none | none modeled: the validators read the log file on the node |
| Amazon EKS | No: "By default, cluster control plane logs aren't sent to CloudWatch Logs" ([EKS user guide `control-plane-logs.adoc` L51](https://github.com/awsdocs/amazon-eks-user-guide/blob/8d43223e0e0dbb6afec4a6c9d6ba5b837b52ebb8/latest/ug/observability/control-plane-logs.adoc#L51)). Turn on the `audit` log type. | No setting found. The Best Practices Guide says the audit logs "are part of the EKS managed Kubernetes control plane logs that are managed by EKS" ([`detective.adoc` L185-186](https://github.com/aws/aws-eks-best-practices/blob/71a660c69498ac1173a0658e3090b23cbe8b2f66/latest/bpg/security/detective.adoc#L185-L186)), and no AWS page found offers a policy setting. The policy EKS runs is **unverified**: the guide's text (column `eks`) is `audit.k8s.io/v1beta1`, which a v1.36 API server does not load ([`policy/reader.go` L35, L87](https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/apiserver/pkg/audit/policy/reader.go#L35)), and the user guide links the kube-up policy (column `gce-kube-up`, [L29](https://github.com/awsdocs/amazon-eks-user-guide/blob/8d43223e0e0dbb6afec4a6c9d6ba5b837b52ebb8/latest/ug/observability/control-plane-logs.adoc#L29)). Verify: a capture of known requests on a live cluster. | CloudWatch Logs group `/aws/eks/<cluster>/cluster` ([L147](https://github.com/awsdocs/amazon-eks-user-guide/blob/8d43223e0e0dbb6afec4a6c9d6ba5b837b52ebb8/latest/ug/observability/control-plane-logs.adoc#L147)), streams `kube-apiserver-audit-<id>` ([L153](https://github.com/awsdocs/amazon-eks-user-guide/blob/8d43223e0e0dbb6afec4a6c9d6ba5b837b52ebb8/latest/ug/observability/control-plane-logs.adoc#L153)). Each message is one native Event as JSON text: Falco's `k8saudit-eks` plugin parses it with the generic audit parser ([`k8sauditeks.go` L170](https://github.com/falcosecurity/plugins/blob/7481621f5de13c79c72aba72b285acd8268ab094/plugins/k8saudit-eks/pkg/k8sauditeks/k8sauditeks.go#L170)). | none: parse the JSON ([pipelines/README.md, EKS](../pipelines/README.md#eks-no-field-mapping)) | "The maximum size for a CloudWatch Logs entry is 1MB whereas the maximum Kubernetes API request size is 1.5MiB. Log entries greater than 1MB will either be truncated or only include the request metadata." ([`detective.adoc` L199](https://github.com/aws/aws-eks-best-practices/blob/71a660c69498ac1173a0658e3090b23cbe8b2f66/latest/bpg/security/detective.adoc#L199)). A truncated message ends with `[Truncated...]` and is not valid JSON (Falco skips it: [`k8sauditeks.go` L160-168](https://github.com/falcosecurity/plugins/blob/7481621f5de13c79c72aba72b285acd8268ab094/plugins/k8saudit-eks/pkg/k8sauditeks/k8sauditeks.go#L160-L168)). A subscription filter sends the logs Base64 encoded and gzip compressed ([L13](https://github.com/awsdocs/amazon-eks-user-guide/blob/8d43223e0e0dbb6afec4a6c9d6ba5b837b52ebb8/latest/ug/observability/control-plane-logs.adoc#L13)). A store that explodes JSON arrays loses the `L` items. |
| Azure AKS | No: "Resource logs aren't collected and stored until you create a diagnostic setting" ([`monitor-aks.md` L111](https://github.com/MicrosoftDocs/azure-aks-docs/blob/e2c989a0116ab5416d32be4e49ab532f148a29a6/articles/aks/monitor-aks.md#L111)). Choose the category `kube-audit` (every event) or `kube-audit-admin`, "which excludes the `get` and `list` audit events" ([L119](https://github.com/MicrosoftDocs/azure-aks-docs/blob/e2c989a0116ab5416d32be4e49ab532f148a29a6/articles/aks/monitor-aks.md#L119)). | No: "The audit policy is managed by AKS and can't be customized." ([L420](https://github.com/MicrosoftDocs/azure-aks-docs/blob/e2c989a0116ab5416d32be4e49ab532f148a29a6/articles/aks/monitor-aks.md#L420)) | Three shapes. (1) Resource-specific mode: tables `AKSAudit` and `AKSAuditAdmin` ([L151-152](https://github.com/MicrosoftDocs/azure-aks-docs/blob/e2c989a0116ab5416d32be4e49ab532f148a29a6/articles/aks/monitor-aks.md#L151-L152)) with PascalCase columns (`ObjectRef`, `User`, `Verb`, `RequestObject`, `ResponseStatus`) and **no `ImpersonatedUser` column** ([AKSAudit table reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aksaudit)); the keys inside a `dynamic` column stay camelCase (`ResponseStatus.code` in [Microsoft's AKSAudit sample query](https://learn.microsoft.com/azure/azure-monitor/reference/queries/aksaudit); [pipelines/SOURCES.md](../pipelines/SOURCES.md#cited)). (2) Azure diagnostics mode: table `AzureDiagnostics`, `Category == "kube-audit"`, the Event as JSON text in `log_s` ([L150](https://github.com/MicrosoftDocs/azure-aks-docs/blob/e2c989a0116ab5416d32be4e49ab532f148a29a6/articles/aks/monitor-aks.md#L150)). (3) Export to Event Hubs or storage: the Event as JSON text in `properties.log` ([Falco `k8sauditaks.go` L201-210](https://github.com/falcosecurity/plugins/blob/7481621f5de13c79c72aba72b285acd8268ab094/plugins/k8saudit-aks/pkg/k8sauditaks/k8sauditaks.go#L201-L210); Elastic reads `azure.platformlogs.properties.log.*`: [rule L105-113](https://github.com/elastic/detection-rules/blob/a67542227a004777bb308bd7900c9ad69846eca4/rules/integrations/azure/credential_access_azure_aks_coredns_configmap_modified.toml#L105-L113)). | (1): [`kubernetes_aks_auditlogs.yml`](../pipelines/kubernetes_aks_auditlogs.yml) with `convert_k8s.py aks` (KQL); (2) and (3): none, parse the JSON | `RequestObject` and `ResponseObject` can be the string `"skipped-too-big-size-object"` ([AKSAudit table reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aksaudit)). `kube-audit-admin` keeps no `get` and `list` ([K42](../RULE_DEFECTS.md#k42-aks-kube-audit-admin-the-category-drops-get-and-list-so-read-shaped-procedures-leave-no-record)); whether it keeps `watch` is **unverified** (verify: one `watch` of Secrets on a cluster that collects only that category). |
| Google GKE | Admin Activity logs: on, and cannot be turned off. Data Access logs (the reads): off by default. Both **unverified**: Google's GKE audit-logging page (`docs.cloud.google.com`) did not resolve from the build host; web-search results quote it. gke-mcp says the Data Access log holds reads "if enabled" ([`k8s_audit_logs.md` L16-17](https://github.com/GoogleCloudPlatform/gke-mcp/blob/e34795c03284ff31ec871c6ff53a4e0882cdd02d/pkg/tools/logging/schemas/k8s_audit_logs.md#L16-L17)). Verify: read that page, or a project's audit-log configuration. | No (**unverified**). The GKE audit-policy page, quoted in a search result, says that GKE supplies the policy file and that `configure-helper.sh` generates it ([SOURCES.md, GCE kube-up](provider-policies/SOURCES.md#gce-kube-up-the-policy-the-eks-user-guide-links-and-the-gke-audit-policy-page-names)). The GKE columns below use that script's policy (`gce-kube-up`) as a stand-in. Verify: a capture of known requests on a live cluster. | Cloud Logging `LogEntry`; `protoPayload` is a `google.cloud.audit.AuditLog` with `serviceName` `k8s.io`, `methodName` `io.k8s.<group>.<version>.<resource>.<verb>`, `resourceName` `<group>/<version>/namespaces/<ns>/<resource>/<name>`, `authenticationInfo.principalEmail`, `requestMetadata.callerIp` ([`k8s_audit_logs.md` L10-34](https://github.com/GoogleCloudPlatform/gke-mcp/blob/e34795c03284ff31ec871c6ff53a4e0882cdd02d/pkg/tools/logging/schemas/k8s_audit_logs.md#L10-L34)) | [`k8s_gke.py`](../pipelines/k8s_gke.py) with `convert_k8s.py gke` | No request URI (no query string), no audit level or stage, no `user.groups`, a conflict on the HTTP status field, and no public record of a JSON-patch body ([pipelines/README.md, GKE](../pipelines/README.md#gke)). Reads only with Data Access logs on. |
| Red Hat OpenShift | Yes: the `audit` field defaults to `{profile: Default}` ([openshift/api `types_apiserver.go` L102, L147-149](https://github.com/openshift/api/blob/7ecc11c5c1b6594f9a79c665c6596392d88dd25a/config/v1/types_apiserver.go#L99-L149)). The kube-apiserver writes `/var/log/kube-apiserver/audit.log` in JSON ([operator `defaultconfig.yaml` L42-52](https://github.com/openshift/cluster-kube-apiserver-operator/blob/c7f615ba375151e412bb5d4ac79f3fe5bf6747a8/bindata/assets/config/defaultconfig.yaml#L42-L52), `release-4.18`). | Profiles only: `Default`, `WriteRequestBodies`, `AllRequestBodies`, `None`, and `customRules` per user group ([`types_apiserver.go` L106-157](https://github.com/openshift/api/blob/7ecc11c5c1b6594f9a79c665c6596392d88dd25a/config/v1/types_apiserver.go#L106-L157)); no raw policy. | the native Event, one JSON object per line | none | The Default profile logs every write at Metadata ([`default-rules-release-4.18.yaml`](provider-policies/openshift/default-rules-release-4.18.yaml) lines 10-15), so the graders are blind ([K40](../RULE_DEFECTS.md#k40-body-graders-are-blind-under-the-openshift-default-profile-and-the-k3s-starter-policy)). 4.17 and earlier log core Events at None ([`base-policy-release-4.17.yaml`](provider-policies/openshift/base-policy-release-4.17.yaml) lines 9-13; [K38](../RULE_DEFECTS.md#k38-kubernetes-events-deletes-leave-no-record-on-eks-gce-kube-up-and-openshift-417-and-no-collection-delete-record-on-aks)). The API text of `Default` still says that events are "not logged at all" ([L133-135](https://github.com/openshift/api/blob/7ecc11c5c1b6594f9a79c665c6596392d88dd25a/config/v1/types_apiserver.go#L133-L135)); the 4.18 base policy has no such rule. Cluster DNS is `openshift-dns/dns-default` and `dnses.operator.openshift.io/default` (TRR9027 Procedures E and F). How the log leaves the node (the log forwarder; hosted control planes) is **unverified**: `docs.redhat.com` did not answer from the build host. Verify: Red Hat's audit-log documentation. |
| k3s | No: "K3s doesn't enable auditing by default, so audit log configuration and audit policy must be created manually." ([`hardening-guide.md` L113](https://github.com/k3s-io/docs/blob/911393ceaf029778b356593cc8b6fab977293e96/docs/security/hardening-guide.md#L113)) | Yes: the admin writes the policy and passes `audit-policy-file` and `audit-log-path` (`/var/lib/rancher/k3s/server/logs/audit.log`) as API server arguments ([L47-54](https://github.com/k3s-io/docs/blob/911393ceaf029778b356593cc8b6fab977293e96/docs/security/hardening-guide.md#L47-L54)) | the native Event, one JSON object per line | none | The guide's starter policy is one `level: Metadata` rule with no `omitStages` ([L542-549](https://github.com/k3s-io/docs/blob/911393ceaf029778b356593cc8b6fab977293e96/docs/security/hardening-guide.md#L542-L549)): the graders are blind ([K40](../RULE_DEFECTS.md#k40-body-graders-are-blind-under-the-openshift-default-profile-and-the-k3s-starter-policy)), and every request also writes a `RequestReceived` record: a rule that tests no `responseStatus`, `impersonatedUser` or body field can alert twice for one request ([Audit levels](#audit-levels)). |

## Rules on each platform

One row per rule, one column per platform log shape. Read
[Support words and reason codes](#support-words-and-reason-codes) first.

<!-- platform-coverage:begin -->
<!-- Generated by detections/k8s_platforms_md.py --write from detections/k8s/policy_coverage.json and detections/pipelines/mapping_results.json. Do not edit by hand. -->

Columns (each is one policy and one record shape):

- **kind lab (home policy)**: policy: the rule's home lab policy, native Event. The lab policy of the validator whose MANIFEST registers the rule (proven live in CI).
- **EKS (CloudWatch)**: policy `eks`, native Event. The EKS Best Practices Guide policy; each CloudWatch message is the native Event, so no mapping.
- **GKE, Data Access on**: policy `gce-kube-up`, mapping `gke`. The GCE kube-up policy (the GKE audit-policy page names its script; whether GKE runs it is unverified) and the GKE mapping.
- **GKE, Admin Activity only**: policy `gce-kube-up`, mapping `gke`, store without reads `gke_admin_activity`. As the GKE column, without get, list and watch events (Data Access logs off): the store replay runs every case under the gce-kube-up policy with a filter that drops those verbs, so every count is the store's.
- **AKS AKSAudit**: policy `aks-kube-audit`, mapping `aks`. The AKS policy, kube-audit category, and the AKSAudit mapping.
- **AKS AKSAuditAdmin**: policy `aks-kube-audit-admin`, mapping `aks`, store without reads `aksauditadmin`. The AKS policy, kube-audit-admin category (no get and list), and the AKSAudit mapping (AKSAuditAdmin has the same columns).
- **AKS raw Event, kube-audit**: policy `aks-kube-audit`, native Event. The AKS policy, kube-audit category, stored as the native Event (AzureDiagnostics log_s, or the Event Hub or storage export's properties.log), so no mapping.
- **AKS raw Event, kube-audit-admin**: policy `aks-kube-audit-admin`, native Event, store without reads `aksauditadmin`. As the raw kube-audit column, kube-audit-admin category (no get and list).
- **OpenShift 4.18+ Default**: policy `openshift-default`, native Event. OpenShift 4.18 and later, Default audit profile.
- **OpenShift 4.18+ WriteRequestBodies**: policy `openshift-wrb`, native Event. OpenShift 4.18 and later, WriteRequestBodies audit profile.
- **OpenShift 4.17 Default**: policy `openshift-default-4.17`, native Event. OpenShift 4.17 and earlier, Default audit profile (core Events at None).
- **OpenShift 4.17 WriteRequestBodies**: policy `openshift-wrb-4.17`, native Event. OpenShift 4.17 and earlier, WriteRequestBodies audit profile.
- **k3s starter policy**: policy `k3s-starter`, native Event. K3s hardening-guide starter policy (k3s writes no audit log by default).

`L` after a rule: some item reads a JSON list as its text (`list_text_items`); a store that explodes JSON arrays cannot match it ([pipelines/README.md](../pipelines/README.md#rules-that-read-a-list-as-its-json-text)).

| Rule | kind lab (home policy) | EKS (CloudWatch) | GKE, Data Access on | GKE, Admin Activity only | AKS AKSAudit | AKS AKSAuditAdmin | AKS raw Event, kube-audit | AKS raw Event, kube-audit-admin | OpenShift 4.18+ Default | OpenShift 4.18+ WriteRequestBodies | OpenShift 4.17 Default | OpenShift 4.17 WriteRequestBodies | k3s starter policy |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [`T1053.007/k8s_job_create`](../sigma/T1053.007/k8s_job_create.yml) | **full** 6/6 `lab-apiserver` | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 |
| [`T1070/k8s_events_deleted`](../sigma/T1070/k8s_events_deleted.yml) L | **full** 8/8 `lab-apiserver`; not-modeled 8 | **partial** 2/8; no-record 6 #8; not-modeled 3; fp 1 | **partial** 2/8; no-record 6 #9; not-modeled 3; fp 1 | **partial** 2/8; no-record 6 #9; not-modeled 3; fp 1 | **partial** 5/8; no-record 3 #10; not-modeled 2; fp 1 | **partial** 5/8; no-record 3 #10; not-modeled 2; fp 1 | **partial** 5/8; no-record 3 #10; not-modeled 2; fp 1 | **partial** 5/8; no-record 3 #10; not-modeled 2; fp 1 | **full** 8/8; fp 3 | **full** 8/8; not-modeled 9 | **partial** 2/8; no-record 6 #0; fp 1 | **partial** 2/8; no-record 6 #0; not-modeled 4 | **full** 8/8; fp 3 |
| [`T1070/k8s_namespace_deleted`](../sigma/T1070/k8s_namespace_deleted.yml) L | **full** 8/8 `lab-apiserver`; not-modeled 10 | **full** 8/8; not-modeled 12 | **not portable** (8/8 by policy and store); not-in-schema: `requestURI`, `responseStatus.code`; not-modeled 12 | **not portable** (8/8 by policy and store); not-in-schema: `requestURI`, `responseStatus.code`; not-modeled 11 | **full** 8/8; not-modeled 12 | **full** 8/8; not-modeled 11 | **full** 8/8; not-modeled 12 | **full** 8/8; not-modeled 11 | **partial** 7/8; body-removed 1; fp 1 | **full** 8/8; not-modeled 12 | **partial** 7/8; body-removed 1; fp 1 | **full** 8/8; not-modeled 12 | **partial** 7/8; body-removed 1; fp 1 |
| [`T1070/k8s_workload_deleted_evidence`](../sigma/T1070/k8s_workload_deleted_evidence.yml) L | **full** 6/6 `lab-apiserver`; not-modeled 3 | **full** 6/6; not-modeled 4 | **full** 6/6; not-modeled 4 | **full** 6/6; not-modeled 3 | **full** 6/6; not-modeled 4 | **full** 6/6; not-modeled 3 | **full** 6/6; not-modeled 4 | **full** 6/6; not-modeled 3 | **full** 6/6; fp 2 | **full** 6/6; not-modeled 3 | **full** 6/6; fp 2 | **full** 6/6; not-modeled 3 | **full** 6/6; fp 2 |
| [`T1098.006/k8s_eks_aws_auth_configmap_modified`](../sigma/T1098.006/k8s_eks_aws_auth_configmap_modified.yml) | **full** 6/6 `lab-apiserver` | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 |
| [`T1098.006/k8s_rbac_privileged_grant`](../sigma/T1098.006/k8s_rbac_privileged_grant.yml) L | **full** 20/20 `lab-apiserver` | **full** 20/20 | **partial** 15/20; approved-loss 4; approved-loss-if-sorted 1; approved-diff 5 | **partial** 15/20; approved-loss 4; approved-loss-if-sorted 1; approved-diff 5 | **partial** 19/20; approved-loss-if-sorted 1 | **partial** 19/20; approved-loss-if-sorted 1 | **full** 20/20 | **full** 20/20 | **partial** 2/20; body-removed 18 | **full** 20/20 | **partial** 2/20; body-removed 18 | **full** 20/20 | **partial** 2/20; body-removed 18 |
| [`T1098.006/k8s_rbac_sensitive_permission_grant`](../sigma/T1098.006/k8s_rbac_sensitive_permission_grant.yml) L | **full** 10/10 `lab-apiserver` | **full** 10/10 | **full** 10/10 | **full** 10/10 | **full** 10/10 | **full** 10/10 | **full** 10/10 | **full** 10/10 | **chokepoint only** 0/10; body-removed 10; chokepoint 10/10 | **full** 10/10 | **chokepoint only** 0/10; body-removed 10; chokepoint 10/10 | **full** 10/10 | **chokepoint only** 0/10; body-removed 10; chokepoint 10/10 |
| [`T1098.006/k8s_rbac_write`](../sigma/T1098.006/k8s_rbac_write.yml) | **full** 6/6 `lab-apiserver` | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 |
| [`T1134/k8s_impersonation`](../sigma/T1134/k8s_impersonation.yml) | **full** 11/11 `lab-apiserver` | **full** 11/11 | **not portable** (11/11 by policy and store); not-in-schema: `responseStatus.code`, `responseStatus.message` | **blind** 0/11; not-in-schema: `responseStatus.code`, `responseStatus.message`; reads-dropped 11 | **not portable** (11/11 by policy and store); not-in-schema: `impersonatedUser.username` | **blind** 0/11; not-in-schema: `impersonatedUser.username`; reads-dropped 11 | **full** 11/11 | **blind** 0/11; reads-dropped 11 | **full** 11/11 | **full** 11/11 | **full** 11/11 | **full** 11/11 | **full** 11/11 |
| [`T1134/k8s_impersonation_privileged`](../sigma/T1134/k8s_impersonation_privileged.yml) L | **full** 3/3 `lab-apiserver` | **full** 3/3 | **not portable** (3/3 by policy and store); not-in-schema: `impersonatedUser.groups` | **blind** 0/3; not-in-schema: `impersonatedUser.groups`; reads-dropped 3 | **not portable** (3/3 by policy and store); not-in-schema: `impersonatedUser.groups`, `impersonatedUser.username` | **blind** 0/3; not-in-schema: `impersonatedUser.groups`, `impersonatedUser.username`; reads-dropped 3 | **full** 3/3 | **blind** 0/3; reads-dropped 3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 |
| [`T1543.005/k8s_static_pod_mirror_create`](../sigma/T1543.005/k8s_static_pod_mirror_create.yml) | **full** 3/3 `lab-staticpod` | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 |
| [`T1546/k8s_admission_webhook_created`](../sigma/T1546/k8s_admission_webhook_created.yml) | **full** 4/4 `lab-apiserver` | **full** 4/4 | **not portable** (4/4 by policy and store); not-in-schema: `responseStatus.code` | **not portable** (4/4 by policy and store); not-in-schema: `responseStatus.code` | **full** 4/4 | **full** 4/4 | **full** 4/4 | **full** 4/4 | **full** 4/4 | **full** 4/4 | **full** 4/4 | **full** 4/4 | **full** 4/4 |
| [`T1546/k8s_admission_webhook_repointed_to_url`](../sigma/T1546/k8s_admission_webhook_repointed_to_url.yml) L | **full** 20/20 `lab-apiserver` | **full** 20/20 | **not portable** (20/20 by policy and store); not-in-schema: `requestURI`, `responseStatus.code` | **not portable** (20/20 by policy and store); not-in-schema: `requestURI`, `responseStatus.code` | **full** 20/20 | **full** 20/20 | **full** 20/20 | **full** 20/20 | **chokepoint only** 0/20; body-removed 20; chokepoint 20/20 | **full** 20/20 | **chokepoint only** 0/20; body-removed 20; chokepoint 20/20 | **full** 20/20 | **chokepoint only** 0/20; body-removed 20; chokepoint 20/20 |
| [`T1546/k8s_malicious_admission_webhook_created`](../sigma/T1546/k8s_malicious_admission_webhook_created.yml) L | **full** 3/3 `lab-apiserver` | **full** 3/3 | **not portable** (3/3 by policy and store); not-in-schema: `responseStatus.code` | **not portable** (3/3 by policy and store); not-in-schema: `responseStatus.code` | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **chokepoint only** 0/3; body-removed 3; chokepoint 3/3 | **full** 3/3 | **chokepoint only** 0/3; body-removed 3; chokepoint 3/3 | **full** 3/3 | **chokepoint only** 0/3; body-removed 3; chokepoint 3/3 |
| [`T1552.007/k8s_secret_access`](../sigma/T1552.007/k8s_secret_access.yml) | **full** 4/4 `lab-apiserver` | **full** 4/4 | **full** 4/4 | **blind** 0/4; reads-dropped 4 | **full** 4/4 | **partial** 1/4; reads-dropped 3 | **full** 4/4 | **partial** 1/4; reads-dropped 3 | **full** 4/4 | **full** 4/4 | **full** 4/4 | **full** 4/4 | **full** 4/4 |
| [`T1552.007/k8s_secret_token_request`](../sigma/T1552.007/k8s_secret_token_request.yml) | **full** 3/3 `lab-apiserver` | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 | **full** 3/3 |
| [`T1565.001/k8s_coredns_configmap_modified`](../sigma/T1565.001/k8s_coredns_configmap_modified.yml) | **full** 18/18 `lab-apiserver` | **full** 18/18 | **full** 18/18 | **full** 18/18 | **full** 18/18 | **full** 18/18 | **full** 18/18 | **full** 18/18 | **full** 18/18 | **full** 18/18 | **full** 18/18 | **full** 18/18 | **full** 18/18 |
| [`T1565.001/k8s_coredns_corefile_poisoned`](../sigma/T1565.001/k8s_coredns_corefile_poisoned.yml) L | **full** 47/47 `lab-apiserver`; not-modeled 59 | **chokepoint partial** 0/47; body-removed 47; chokepoint 43/47 | **chokepoint partial** 0/47; body-removed 47; approved-diff 1; chokepoint 43/47 | **chokepoint partial** 0/47; body-removed 47; approved-diff 1; chokepoint 43/47 | **chokepoint partial** 0/47; body-removed 47; chokepoint 43/47 | **chokepoint partial** 0/47; body-removed 47; chokepoint 43/47 | **chokepoint partial** 0/47; body-removed 47; chokepoint 43/47 | **chokepoint partial** 0/47; body-removed 47; chokepoint 43/47 | **chokepoint partial** 0/47; body-removed 47; chokepoint 43/47 | **full** 47/47; not-modeled 63 | **chokepoint partial** 0/47; body-removed 47; chokepoint 43/47 | **full** 47/47; not-modeled 63 | **chokepoint partial** 0/47; body-removed 47; chokepoint 43/47 |
| [`T1572/k8s_node_proxy_portforward`](../sigma/T1572/k8s_node_proxy_portforward.yml) | **full** 4/4 `lab-apiserver` | **full** 4/4 | **not portable** (4/4 by policy and store); not-in-schema: `requestURI` | **not portable** (1/4 by policy and store); not-in-schema: `requestURI`; reads-dropped 3 | **full** 4/4 | **partial** 1/4; reads-dropped 3 | **full** 4/4 | **partial** 1/4; reads-dropped 3 | **full** 4/4 | **full** 4/4 | **full** 4/4 | **full** 4/4 | **full** 4/4 |
| [`T1572/k8s_pod_portforward`](../sigma/T1572/k8s_pod_portforward.yml) | **full** 2/2 `lab-apiserver` | **full** 2/2 | **full** 2/2 | **partial** 1/2; reads-dropped 1 | **full** 2/2 | **partial** 1/2; reads-dropped 1 | **full** 2/2 | **partial** 1/2; reads-dropped 1 | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 |
| [`T1609/k8s_node_proxy_exec`](../sigma/T1609/k8s_node_proxy_exec.yml) | **full** 7/7 `lab-k8s` | **full** 7/7 | **not portable** (7/7 by policy and store); not-in-schema: `requestURI` | **not portable** (1/7 by policy and store); not-in-schema: `requestURI`; reads-dropped 6 | **full** 7/7 | **partial** 1/7; reads-dropped 6 | **full** 7/7 | **partial** 1/7; reads-dropped 6 | **full** 7/7 | **full** 7/7 | **full** 7/7 | **full** 7/7 | **full** 7/7 |
| [`T1609/k8s_node_proxy_kubelet_api`](../sigma/T1609/k8s_node_proxy_kubelet_api.yml) | **full** 6/6 `lab-k8s` | **full** 6/6 | **not portable** (6/6 by policy and store); not-in-schema: `requestURI` | **not portable** (2/6 by policy and store); not-in-schema: `requestURI`; reads-dropped 4 | **full** 6/6 | **partial** 2/6; reads-dropped 4 | **full** 6/6 | **partial** 2/6; reads-dropped 4 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 |
| [`T1609/k8s_pod_ephemeral_container`](../sigma/T1609/k8s_pod_ephemeral_container.yml) | **full** 2/2 `lab-k8s` | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 | **full** 2/2 |
| [`T1609/k8s_pod_exec_attach`](../sigma/T1609/k8s_pod_exec_attach.yml) | **full** 6/6 `lab-k8s` | **full** 6/6 | **full** 6/6 | **partial** 2/6; reads-dropped 4 | **full** 6/6 | **partial** 2/6; reads-dropped 4 | **full** 6/6 | **partial** 2/6; reads-dropped 4 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 | **full** 6/6 |
| [`T1611/k8s_podspec_confinement_disabled`](../sigma/T1611/k8s_podspec_confinement_disabled.yml) L | **full** 51/51 `lab-apiserver` | **full** 51/51 | **partial** 26/51; approved-loss 25; approved-diff 3 | **partial** 26/51; approved-loss 25; approved-diff 3 | **full** 51/51 | **full** 51/51 | **full** 51/51 | **full** 51/51 | **blind** 0/51; body-removed 51 | **full** 51/51 | **blind** 0/51; body-removed 51 | **full** 51/51 | **blind** 0/51; body-removed 51 |
| [`T1611/k8s_podspec_controller_host_access`](../sigma/T1611/k8s_podspec_controller_host_access.yml) L | **full** 41/41 `lab-apiserver` | **full** 41/41 | **partial** 13/41; approved-loss 28; approved-diff 12 | **partial** 13/41; approved-loss 28; approved-diff 12 | **full** 41/41 | **full** 41/41 | **full** 41/41 | **full** 41/41 | **blind** 0/41; body-removed 41 | **full** 41/41 | **blind** 0/41; body-removed 41 | **full** 41/41 | **blind** 0/41; body-removed 41 |
| [`T1611/k8s_podspec_host_access`](../sigma/T1611/k8s_podspec_host_access.yml) L | **full** 36/36 `lab-apiserver` | **full** 36/36 | **partial** 18/36; approved-loss 18; approved-diff 8 | **partial** 18/36; approved-loss 18; approved-diff 8 | **full** 36/36 | **full** 36/36 | **full** 36/36 | **full** 36/36 | **blind** 0/36; body-removed 36 | **full** 36/36 | **blind** 0/36; body-removed 36 | **full** 36/36 | **blind** 0/36; body-removed 36 |
| [`T1685/k8s_admission_webhook_disabled`](../sigma/T1685/k8s_admission_webhook_disabled.yml) L | **full** 8/8 `lab-apiserver` | **full** 8/8; not-modeled 2 | **not portable** (8/8 by policy and store); not-in-schema: `requestURI`; not-modeled 2 | **not portable** (8/8 by policy and store); not-in-schema: `requestURI`; not-modeled 1 | **full** 8/8; not-modeled 2 | **full** 8/8; not-modeled 1 | **full** 8/8; not-modeled 2 | **full** 8/8; not-modeled 1 | **full** 8/8; fp 1 | **full** 8/8; not-modeled 1 | **full** 8/8; fp 1 | **full** 8/8; not-modeled 1 | **full** 8/8; fp 1 |
| [`T1685/k8s_admission_webhook_neutered`](../sigma/T1685/k8s_admission_webhook_neutered.yml) L | **full** 36/36 `lab-apiserver`; not-modeled 50 | **full** 36/36; not-modeled 51 | **not portable** (36/36 by policy and store); not-in-schema: `requestURI`, `responseStatus.code`; not-modeled 51 | **not portable** (36/36 by policy and store); not-in-schema: `requestURI`, `responseStatus.code`; not-modeled 51 | **full** 36/36; not-modeled 51 | **full** 36/36; not-modeled 51 | **full** 36/36; not-modeled 51 | **full** 36/36; not-modeled 51 | **chokepoint only** 0/36; body-removed 36; chokepoint 36/36 | **full** 36/36; not-modeled 51 | **chokepoint only** 0/36; body-removed 36; chokepoint 36/36 | **full** 36/36; not-modeled 51 | **chokepoint only** 0/36; body-removed 36; chokepoint 36/36 |
| [`T1685/k8s_enforcer_workload_removed`](../sigma/T1685/k8s_enforcer_workload_removed.yml) L | **full** 26/26 `lab-apiserver`; not-modeled 6 | **full** 26/26; not-modeled 9 | **not portable** (26/26 by policy and store); not-in-schema: `level`, `requestURI`, `responseStatus.code`; not-modeled 9 | **not portable** (26/26 by policy and store); not-in-schema: `level`, `requestURI`, `responseStatus.code`; not-modeled 8 | **full** 26/26; not-modeled 8 | **full** 26/26; not-modeled 7 | **full** 26/26; not-modeled 8 | **full** 26/26; not-modeled 7 | **partial** 5/26; body-removed 21; fp 3 | **full** 26/26; not-modeled 8 | **partial** 5/26; body-removed 21; fp 3 | **full** 26/26; not-modeled 8 | **partial** 5/26; body-removed 21; fp 3 |
| [`T1685/k8s_security_tool_workload_removed`](../sigma/T1685/k8s_security_tool_workload_removed.yml) L | **full** 31/31 `lab-apiserver`; not-modeled 6 | **full** 31/31; not-modeled 7 | **not portable** (31/31 by policy and store); not-in-schema: `level`, `requestURI`, `responseStatus.code`; not-modeled 7 | **not portable** (31/31 by policy and store); not-in-schema: `level`, `requestURI`, `responseStatus.code`; not-modeled 6 | **full** 31/31; not-modeled 7 | **full** 31/31; not-modeled 6 | **full** 31/31; not-modeled 7 | **full** 31/31; not-modeled 6 | **partial** 6/31; body-removed 25; fp 3 | **full** 31/31; not-modeled 6 | **partial** 6/31; body-removed 25; fp 3 | **full** 31/31; not-modeled 6 | **partial** 6/31; body-removed 25; fp 3 |

Rules per support word (full, partial, chokepoint only, chokepoint partial, blind, not portable):

| Shape | full | partial | chokepoint only | chokepoint partial | blind | not portable |
|---|---|---|---|---|---|---|
| kind lab (home policy) | 31 | 0 | 0 | 0 | 0 | 0 |
| EKS (CloudWatch) | 29 | 1 | 0 | 1 | 0 | 0 |
| GKE, Data Access on | 12 | 5 | 0 | 1 | 0 | 13 |
| GKE, Admin Activity only | 9 | 7 | 0 | 1 | 3 | 11 |
| AKS AKSAudit | 26 | 2 | 0 | 1 | 0 | 2 |
| AKS AKSAuditAdmin | 20 | 8 | 0 | 1 | 2 | 0 |
| AKS raw Event, kube-audit | 29 | 1 | 0 | 1 | 0 | 0 |
| AKS raw Event, kube-audit-admin | 21 | 7 | 0 | 1 | 2 | 0 |
| OpenShift 4.18+ Default | 19 | 4 | 4 | 1 | 3 | 0 |
| OpenShift 4.18+ WriteRequestBodies | 31 | 0 | 0 | 0 | 0 | 0 |
| OpenShift 4.17 Default | 18 | 5 | 4 | 1 | 3 | 0 |
| OpenShift 4.17 WriteRequestBodies | 30 | 1 | 0 | 0 | 0 | 0 |
| k3s starter policy | 19 | 4 | 4 | 1 | 3 | 0 |

Every policy, as the simulator reports it (no mapping): rules with every / some / no positive case firing, positive cases firing, negative cases that fire, and events whose missing body the rule reads (not proven):

| Policy | Platform | What the column is | Rules every / some / none | Positives firing | Negatives firing | Not proven | What is verified |
|---|---|---|---|---|---|---|---|
| `lab-apiserver` | kind lab (CI) | API server lab policy (TRR9004-9010, TRR9025-9027) ([`audit-policy-apiserver.yaml`](audit-policy-apiserver.yaml)) | 31 / 0 / 0 | 442 of 442 | 0 | 142 | proven live in CI |
| `lab-k8s` | kind lab (CI) | TRR9002 lab policy (exec, attach, node proxy) ([`audit-policy.yaml`](audit-policy.yaml)) | 19 / 4 / 8 | 133 of 442 | 13 | 0 | proven live in CI |
| `lab-staticpod` | kind lab (CI) | TRR9003 lab policy (static pods) ([`audit-policy-staticpod.yaml`](audit-policy-staticpod.yaml)) | 8 / 11 / 12 | 74 of 442 | 11 | 0 | proven live in CI |
| `eks` | Amazon EKS | EKS audit policy as the EKS Best Practices Guide publishes it ([`eks-bpg-audit-policy.yaml`](provider-policies/eks/eks-bpg-audit-policy.yaml)) | 29 / 1 / 1 | 389 of 442 | 1 | 88 | published text, a variant of the kube-up configure-helper.sh policy (it adds aws-auth writes at RequestResponse and serviceaccounts/token at Request, and drops a few kube-up identities); the EKS user guide (control-plane-logs) links that configure-helper.sh policy as its audit policy (the gce-kube-up column); neither text is verified on a live EKS cluster |
| `gce-kube-up` | GCE kube-up (the policy the EKS user guide links; GKE unverified) | the policy kube-up's configure-helper.sh writes on GCE ([`gce-kube-up-audit-policy.yaml`](provider-policies/gce/gce-kube-up-audit-policy.yaml)) | 29 / 1 / 1 | 389 of 442 | 1 | 88 | the EKS user guide (control-plane-logs) links this configure-helper.sh policy as 'the audit policy', and the GKE audit-policy page names configure-helper.sh as the script that generates the policy; whether EKS or GKE runs this text unchanged, and GKE's Admin Activity / Data Access split of reads, are unverified (not modeled) |
| `aks-kube-audit` | Azure AKS | AKS audit policy, kube-audit log category ([`aks-audit-policy.yaml`](provider-policies/aks/aks-audit-policy.yaml)) | 29 / 1 / 1 | 392 of 442 | 1 | 86 | published text; the page says the policy is managed by AKS and cannot be customized |
| `aks-kube-audit-admin` | Azure AKS | AKS audit policy, kube-audit-admin log category (no get and list) ([`aks-audit-policy.yaml`](provider-policies/aks/aks-audit-policy.yaml)) | 21 / 7 / 3 | 357 of 442 | 1 | 81 | published text; whether kube-audit-admin also drops watch is unverified (the page names get and list only) |
| `openshift-default` | Red Hat OpenShift | OpenShift 4.18 and later, Default audit profile ([`base-policy-release-4.18.yaml`](provider-policies/openshift/base-policy-release-4.18.yaml), [`default-rules-release-4.18.yaml`](provider-policies/openshift/default-rules-release-4.18.yaml)) | 19 / 4 / 8 | 133 of 442 | 13 | 0 | source text; the kube-apiserver operator release-4.18 vendors the same files |
| `openshift-default-4.17` | Red Hat OpenShift | OpenShift 4.17 and earlier, Default audit profile (core Events at None) ([`base-policy-release-4.17.yaml`](provider-policies/openshift/base-policy-release-4.17.yaml), [`default-rules-release-4.17.yaml`](provider-policies/openshift/default-rules-release-4.17.yaml)) | 18 / 5 / 8 | 127 of 442 | 11 | 0 | source text; the kube-apiserver operator release-4.17 vendors the same files |
| `openshift-wrb` | Red Hat OpenShift | OpenShift 4.18 and later, WriteRequestBodies audit profile ([`base-policy-release-4.18.yaml`](provider-policies/openshift/base-policy-release-4.18.yaml), [`writerequestbodies-rules-release-4.18.yaml`](provider-policies/openshift/writerequestbodies-rules-release-4.18.yaml)) | 31 / 0 / 0 | 442 of 442 | 0 | 153 | source text; an admin chooses this profile (the default is Default) |
| `openshift-wrb-4.17` | Red Hat OpenShift | OpenShift 4.17 and earlier, WriteRequestBodies audit profile ([`base-policy-release-4.17.yaml`](provider-policies/openshift/base-policy-release-4.17.yaml), [`writerequestbodies-rules-release-4.17.yaml`](provider-policies/openshift/writerequestbodies-rules-release-4.17.yaml)) | 30 / 1 / 0 | 436 of 442 | 0 | 148 | source text; an admin chooses this profile (the default is Default) |
| `k3s-starter` | k3s | k3s hardening-guide starter policy (k3s writes no audit log by default) ([`k3s-hardening-starter-audit-policy.yaml`](provider-policies/k3s/k3s-hardening-starter-audit-policy.yaml)) | 19 / 4 / 8 | 133 of 442 | 13 | 0 | published text; the guide calls it a starter policy, and a k3s cluster has no audit policy until the admin writes one |

Simulator warnings:

- `eks`: detections/k8s/provider-policies/eks/eks-bpg-audit-policy.yaml: apiVersion 'audit.k8s.io/v1beta1'; the v1.36 API server loads only audit.k8s.io/v1, so the rules are evaluated as v1
- `openshift-wrb`: writerequestbodies-rules-release-4.18.yaml rule 0 (policy rule #2).resources[4]: unknown key 'resource' ignored (lenient decoding)
<!-- platform-coverage:end -->

### Chokepoint pairs

The replay of each grader's positive cases through its chokepoint, per policy and
store without reads. A cell above says **chokepoint only** only where this table shows
no miss for that policy and store.

<!-- platform-pairs:begin -->
<!-- Generated by detections/k8s_platforms_md.py --write. Do not edit by hand. -->

The replay runs each grader's positive cases through its chokepoint rule under each policy with its log filter, and under each replayed store (its policy, without the store's read verbs). It applies no mapping. A miss is a positive case of the grader on which the chokepoint does not fire.

| Grader | Chokepoint | Positive cases | The chokepoint fires on every one of them under | Misses (policies and stores: fired / total, cases) |
|---|---|---|---|---|
| `T1098.006/k8s_rbac_privileged_grant` | `T1098.006/k8s_rbac_write` | 20 | every policy and store | none |
| `T1098.006/k8s_rbac_sensitive_permission_grant` | `T1098.006/k8s_rbac_write` | 10 | every policy and store | none |
| `T1546/k8s_admission_webhook_repointed_to_url` | `T1685/k8s_admission_webhook_disabled` | 20 | every policy and store | none |
| `T1546/k8s_malicious_admission_webhook_created` | `T1546/k8s_admission_webhook_created` | 3 | every policy and store | none |
| `T1565.001/k8s_coredns_corefile_poisoned` | `T1565.001/k8s_coredns_configmap_modified` | 47 | no policy | `lab-apiserver`, `lab-k8s`, `eks`, `gce-kube-up`, `aks-kube-audit`, `aks-kube-audit-admin`, `openshift-default`, `openshift-default-4.17`, `openshift-wrb`, `openshift-wrb-4.17`, `k3s-starter`, `gce-kube-up` + store `gke_admin_activity`: 43/47, `openshift-dns-operator-token-put-poisoned-dns-default`, `openshift-operator-renders-public-stub-zone`, `openshift-operator-renders-root-upstream-after-stub`, `openshift-operator-renders-root-upstream-first`; `lab-staticpod`: 0/47, 47 cases |
| `T1685/k8s_admission_webhook_neutered` | `T1685/k8s_admission_webhook_disabled` | 36 | every policy and store | none |
<!-- platform-pairs:end -->

## What each rule needs

The audit level and the requests that each rule needs, from the policy simulator.

<!-- platform-needs:begin -->
<!-- Generated by detections/k8s_platforms_md.py --write. Do not edit by hand. -->

The needs data is not computed yet: no rule in `detections/k8s/policy_coverage.json` has a `needs` key. When the policy simulator writes it, this block lists, for each rule, the lowest audit level at which every positive case fires and the requests of those cases.
<!-- platform-needs:end -->

## False-positive exposure

A negative case that starts to fire on a platform is a false positive there. The usual
cause is a dry run: the platform logs the delete at Metadata, so the dry-run filter
that reads the DeleteOptions body has no input
([K39](../RULE_DEFECTS.md#k39-delete-dry-run-body-filters-have-no-input-where-a-platform-logs-deletes-at-metadata)).

<!-- platform-fp:begin -->
<!-- Generated by detections/k8s_platforms_md.py --write. Do not edit by hand. -->

Negative cases that fire, per platform policy and replayed store: `eks` 1, `gce-kube-up` 1, `aks-kube-audit` 1, `aks-kube-audit-admin` 1, `openshift-default` 13, `openshift-default-4.17` 11, `k3s-starter` 13, `gce-kube-up` + store `gke_admin_activity` 1. Lab policies are left out: they are not platforms, and under its own home policy no negative case of a rule fires (the simulator's home check).

| Policy | Rule | Case | Kind | Why it fires |
|---|---|---|---|---|
| `eks` | `T1070/k8s_events_deleted` | `deletecollection-eventsk8s-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `gce-kube-up` | `T1070/k8s_events_deleted` | `deletecollection-eventsk8s-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `aks-kube-audit` | `T1070/k8s_events_deleted` | `delete-core-event-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `aks-kube-audit-admin` | `T1070/k8s_events_deleted` | `delete-core-event-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1070/k8s_events_deleted` | `delete-core-event-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1070/k8s_events_deleted` | `deletecollection-events-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1070/k8s_events_deleted` | `deletecollection-eventsk8s-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1070/k8s_namespace_deleted` | `namespace-delete-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1070/k8s_workload_deleted_evidence` | `delete-job-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1070/k8s_workload_deleted_evidence` | `deletecollection-pods-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1685/k8s_admission_webhook_disabled` | `delete-validating-webhook-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1685/k8s_enforcer_workload_removed` | `delete-falco-daemonset-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1685/k8s_enforcer_workload_removed` | `enforcer-namespace-delete-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1685/k8s_enforcer_workload_removed` | `deletecollection-deployments-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1685/k8s_security_tool_workload_removed` | `delete-deployment-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1685/k8s_security_tool_workload_removed` | `enforcer-namespace-delete-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default` | `T1685/k8s_security_tool_workload_removed` | `deletecollection-deployments-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1070/k8s_events_deleted` | `deletecollection-eventsk8s-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1070/k8s_namespace_deleted` | `namespace-delete-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1070/k8s_workload_deleted_evidence` | `delete-job-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1070/k8s_workload_deleted_evidence` | `deletecollection-pods-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1685/k8s_admission_webhook_disabled` | `delete-validating-webhook-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1685/k8s_enforcer_workload_removed` | `delete-falco-daemonset-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1685/k8s_enforcer_workload_removed` | `enforcer-namespace-delete-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1685/k8s_enforcer_workload_removed` | `deletecollection-deployments-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1685/k8s_security_tool_workload_removed` | `delete-deployment-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1685/k8s_security_tool_workload_removed` | `enforcer-namespace-delete-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `openshift-default-4.17` | `T1685/k8s_security_tool_workload_removed` | `deletecollection-deployments-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1070/k8s_events_deleted` | `delete-core-event-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1070/k8s_events_deleted` | `deletecollection-events-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1070/k8s_events_deleted` | `deletecollection-eventsk8s-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1070/k8s_namespace_deleted` | `namespace-delete-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1070/k8s_workload_deleted_evidence` | `delete-job-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1070/k8s_workload_deleted_evidence` | `deletecollection-pods-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1685/k8s_admission_webhook_disabled` | `delete-validating-webhook-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1685/k8s_enforcer_workload_removed` | `delete-falco-daemonset-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1685/k8s_enforcer_workload_removed` | `enforcer-namespace-delete-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1685/k8s_enforcer_workload_removed` | `deletecollection-deployments-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1685/k8s_security_tool_workload_removed` | `delete-deployment-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1685/k8s_security_tool_workload_removed` | `enforcer-namespace-delete-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `k3s-starter` | `T1685/k8s_security_tool_workload_removed` | `deletecollection-deployments-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
| `gce-kube-up` + store `gke_admin_activity` | `T1070/k8s_events_deleted` | `deletecollection-eventsk8s-dry-run-body` | filtered | the record has no body, so a filter that reads the body has no input |
<!-- platform-fp:end -->

## Managed control-plane principals that no rule filters

A managed control plane sends its own requests to the API server with identities that
a self-managed cluster does not have. No rule here filters the identities below, and
no slice of the benign corpus ([`../benign/slices/kubernetes/`](../benign/slices/kubernetes/))
holds them. So the false-positive rate of each rule on a managed cluster is
**unmeasured**. Baseline these identities by `user.username` before a rule alerts.

| Identity | Platform | Source | Status |
|---|---|---|---|
| `eks:cluster-bootstrap` ("Used for `kubectl` operations during cluster bootstrap"), `eks:support-engineer` ("Used for cluster management operations") | Amazon EKS | EKS user guide, [`default-roles-users.adoc` L38-41](https://github.com/awsdocs/amazon-eks-user-guide/blob/8d43223e0e0dbb6afec4a6c9d6ba5b837b52ebb8/latest/ug/security/default-roles-users.adoc#L38-L41): "special user identities ... not visible in the cluster's configuration" | the names are sourced; what they send is **unverified** (verify: a capture) |
| other `eks:*` users, for example `eks:k8s-metrics` | Amazon EKS | the same page, [L130](https://github.com/awsdocs/amazon-eks-user-guide/blob/8d43223e0e0dbb6afec4a6c9d6ba5b837b52ebb8/latest/ug/security/default-roles-users.adoc#L130) (a RoleBinding subject); `eks:kms-storage-migrator` is named in the falsepositives of [`k8s_eks_aws_auth_configmap_modified`](../sigma/T1098.006/k8s_eks_aws_auth_configmap_modified.yml) | **unverified** list: no AWS page lists every `eks:` user |
| `aksService` | Azure AKS | Monitor AKS names it "the default user/cert used by aks in master node" ([`monitor-aks.md` L170, L186, L212, L229](https://github.com/MicrosoftDocs/azure-aks-docs/blob/e2c989a0116ab5416d32be4e49ab532f148a29a6/articles/aks/monitor-aks.md#L170)). The AKS policy logs its `get` and `list` at None, and its `get` and `update` of kube-system Endpoints ([`aks-audit-policy.yaml`](provider-policies/aks/aks-audit-policy.yaml) lines 5-7, 30-38, 47-52), so its other writes reach a rule. Elastic's rule `credential_access_azure_aks_coredns_configmap_modified.toml` filters it on writes of the CoreDNS ConfigMaps ([L113-116](https://github.com/elastic/detection-rules/blob/a67542227a004777bb308bd7900c9ad69846eca4/rules/integrations/azure/credential_access_azure_aks_coredns_configmap_modified.toml#L113-L116)), which [`k8s_coredns_configmap_modified`](../sigma/T1565.001/k8s_coredns_configmap_modified.yml) matches. | the name is sourced; what it writes is **unverified** (verify: a capture) |
| `hcpService`, `readinessChecker` | Azure AKS | Elastic's rule filters them with `aksService` on writes of the CoreDNS ConfigMaps ([L113-116](https://github.com/elastic/detection-rules/blob/a67542227a004777bb308bd7900c9ad69846eca4/rules/integrations/azure/credential_access_azure_aks_coredns_configmap_modified.toml#L113-L116)). That suggests they write those ConfigMaps. | **unverified**: no Microsoft page fetched names them (verify: a capture, or Microsoft documentation) |
| GKE system identities | Google GKE | none found. The GKE anchors of the mapping harness show `system:node:gke-<cluster>-...` and `system:serviceaccount:kube-system:replicaset-controller` ([`anchors/gke/`](../pipelines/anchors/gke/)), which are ordinary Kubernetes identities | **unverified**: Google's pages did not resolve from the build host (verify: a capture) |

## Recommended policy

For a cluster where you write the audit policy yourself (kubeadm, k3s, kind and
similar). AKS does not let the user change its policy
([`monitor-aks.md` L420](https://github.com/MicrosoftDocs/azure-aks-docs/blob/e2c989a0116ab5416d32be4e49ab532f148a29a6/articles/aks/monitor-aks.md#L420)).
No setting to change the EKS or GKE policy was found (**unverified**; see the
[Platform summary](#platform-summary)). OpenShift takes a profile.

<!-- platform-recommended:begin -->
<!-- Generated by detections/k8s_platforms_md.py --write. Do not edit by hand. -->

A recommended policy is not available yet: `detections/k8s/policy_coverage.json` has no policy with id `recommended`. When it has one, this block names it, links its file and gives its simulator result.
<!-- platform-recommended:end -->

## Open questions

Each question needs a live capture or an account on the platform. All are tracked in
backlog issue #55.

1. Which policy does each provider really run on each version? The EKS text is
   `audit.k8s.io/v1beta1`, which a v1.36 API server does not load. GKE's policy is not
   published as text (the GKE columns use the kube-up script's policy). (#55)
2. GKE: which verbs go to the Data Access log? The mapping harness drops `get`, `list`
   and `watch`. A web-search result quotes the GKE audit-policy page as "get, list, and
   updateStatus". An `updateStatus` write that goes to Data Access would also be lost
   with Data Access logs off. (#55)
3. GKE: how does GKE store a JSON-patch body, the HTTP status, an impersonated user
   and the methodName of a non-resource request? ([pipelines/README.md, GKE](../pipelines/README.md#gke)) (#55)
4. AKS: does `kube-audit-admin` keep `watch`? Do KQL string operators on a `dynamic`
   column see the JSON text with no blanks? AKS and GKE: in which key order does the
   store give a JSON object (an AKS `dynamic` column, GKE's `protoPayload.request`) to
   a query
   ([K43](../RULE_DEFECTS.md#k43-k8s_rbac_privileged_grant-the-aggregation-clause-needs-the-api-servers-key-order))?
   (#55)
5. EKS: which RequestResponse records of this repository's rules pass the 1 MB entry
   limit, and does a truncated entry keep the request metadata or end with
   `[Truncated...]`? (#55)
6. What do the managed control-plane identities above send, and how many alerts do
   they cause per day? No benign slice holds them. (#55)
7. OpenShift with hosted control planes: where is the audit log, and which profile
   applies? (#55)

## Regenerate

```bash
python3 detections/k8s_policy_coverage.py --update       # the policy result
python3 detections/check_provider_mappings.py --write     # the mapping result (after --propose and review)
python3 detections/k8s_platforms_md.py --write            # this page (needs pySigma)
python3 detections/k8s_platforms_md.py --check            # what CI runs (job platform-coverage)
python3 detections/k8s_platforms_md.py --anchors          # what CI runs (job markdown-links)
```
