# Rule defects and gaps

This is the one tracker of every known rule defect, false negative, dead filter and
audit-policy gap: what the near-miss cases, the benign corpus and the live captures
showed and a rule fix has not closed yet. Each problem below stays in the rule until
a pull request fixes it, with a case that proves the fix.

A sidecar case, a budget `why` or a doc that says a defect is "tracked" points here,
by entry ID (for example `L14`). IDs are not reused: a closed entry's ID stays retired.

## How to read an entry

- **Kind**: *false positive* (fires on benign activity), *false negative* (misses
  the technique), *evasion* (a filter or match that an attacker controls), *dead
  filter* (an allowlist entry that matches nothing real), *policy gap* (the audit
  policy does not record what the rule needs), *description* (the rule text claims
  what the rule does not do).
- **Severity**: *high*: the rule misses a common variant of its technique, or a
  high-level rule fires on routine activity of most hosts or clusters. *medium*: a
  narrower miss, or routine noise in a common setup. *low*: a portability caveat, a
  description mismatch or a rare path.
- **Evidence** names where to look:
  - *case*: a case in the rule's sidecar `<rule>.cases.jsonl`;
  - *corpus*: a slice of the [benign corpus](benign/README.md), with the hits and
    actors that [`benign/scores.json`](benign/scores.json) records at commit `00216e3`
    and the rule's `why` in [`benign/budgets.json`](benign/budgets.json). The slices
    are synthetic, so a count is a presence indicator, not a production rate;
  - *CI capture*: the `benign-linux-live` job (detection-quality run 38692762582,
    commit `a95a35c`) recorded a real Ubuntu runner workload
    ([`benign/linux/workload.sh`](benign/linux/workload.sh)) and annotated each Linux
    rule's hits. The per-process detail is in that run's `linux-benign-capture`
    artifact. No rule changed between that commit and this one;
  - *probe*: an event (set) that was run through the rule with the real pySigma
    backend (`sigma_eval.py`) on the current rule, with the result shown. Reproduce
    one with the snippet in [Reproducing a probe](#reproducing-a-probe);
  - *source*: the upstream source that shows the real behaviour, as the reviewer read
    it. Where nothing in this repository recorded the real telemetry, the entry says
    **unverified**.
- **Fix** is the proposed change. **Then** says which case or budget changes once the
  fix lands, so the fix is proven, not just claimed.

## Summary

| ID | Rule | Problem | Kind | Severity |
|----|------|---------|------|----------|
| [L14](#l14-exe-and-comm-allowlists-trust-the-binary-not-the-code-in-it) | three Linux rules | allowlisted tools that ordinary users run (kcapi, debuggers) hide injected code | evasion | medium |
| [K4](#k4-k8s_admission_webhook_neutered-neuters-the-audit-record-cannot-show) | `T1685/k8s_admission_webhook_neutered` | selectors on other labels, self-contradicting selectors or conditions, variable-bound constants | false negative | low |
| [K9](#k9-k8s_coredns_corefile_poisoned-what-the-corefile-grader-does-not-grade) | `T1565.001/k8s_coredns_corefile_poisoned` | private non-cluster stub zones, `import`, mid-token CR, `#<TAB>` comments | false negative, false positive | low |
| [K14](#k14-k8s_namespace_deleted-a-query-dry-run-at-metadata-level) | `T1070/k8s_namespace_deleted` | at Metadata level a real delete that carries `?dryRun=All` next to a body is filtered | evasion | medium |
| [K16](#k16-k8s_impersonation-an-impersonation-request-without-a-user-header) | `T1134/k8s_impersonation` | on v1.34 and earlier, `Impersonate-Group`/`-Uid`/`-Extra` without `Impersonate-User` is a 500 with no trace (unverified live) | false negative | low |
| [K17](#k17-k8s_rbac_privileged_grant-the-wildcard-clause-fires-on-bootstrap-and-read-only-roles) | `T1098.006/k8s_rbac_privileged_grant` | the `"*"` clause fires on the bootstrap controller roles and on read-only wildcard roles | false positive | low |
| [K18](#k18-t1611-pod-spec-rules-a-json-patched-controller-template) | `T1611/k8s_podspec_controller_host_access`, `k8s_podspec_host_access` | a JSON patch of a controller pod template, or of a pod's ephemeral containers, is not graded | false negative | low |
| [KTBD-C1](#ktbd-c1-k8s_admission_webhook_repointed_to_url-a-service-to-service-repoint-or-a-json-patch-copymove) | `T1546/k8s_admission_webhook_repointed_to_url` | a repoint to another in-cluster Service, or a JSON-patch copy/move, carries no URL | false negative | low |
| [KTBD-C2](#ktbd-c2-admission-object-apply-patches-with-a-yaml-body-no-audit-record) | `T1546/k8s_admission_webhook_repointed_to_url`, `k8s_admission_webhook_created`, `k8s_malicious_admission_webhook_created`, `T1685/k8s_admission_webhook_disabled` | an apply patch with a YAML body is dropped from the audit log at Request level or higher | policy gap | medium |
| [C6](#c6-gcp_workforce_principalset_privileged_binding-where-the-privileged-role-tier-ends) | `T1199/gcp_workforce_principalset_privileged_binding` | service-level admin roles granted to a group fire only pool-wide | false negative, false positive (trade-off) | low |
| [C12](#c12-aws_cognito_unauthenticated_identity_use-keyed-on-the-consoles-role-name) | `T1078.004/aws_cognito_unauthenticated_identity_use` | a renamed guest role is a miss; needs a live capture | false negative (documented) | low |
| [C15](#c15-public-policy-rules-a-public-statement-after-the-fifth-and-scope-key-presence) | `T1537/aws_resource_policy_made_public`, `aws_efs_file_system_policy_made_public` | a public statement after the fifth fires unscoped; scope keys checked for presence | false positive | low |

## Linux (auditd and node file events)

### L14. Exe and comm allowlists trust the binary, not the code in it

- **Rules**: [`copyfail_af_alg_authencesn`](sigma/T1068/copyfail_af_alg_authencesn.yml) (level high),
  [`ptrace_traceme`](sigma/T1622/ptrace_traceme.yml),
  [`setns_namespace_join`](sigma/T1611/setns_namespace_join.yml).
- **Kind**: evasion. **Severity**: medium (the copyfail gap is an unprivileged path to
  a high rule); low for the others.
- **Already fixed**: the auditd events and the Linux corpus carry `uid`, `euid` and
  `auid`, and the entries for tools that always run as root require `euid` 0
  (`keyring_add_key_burst`, `memfd_create_execveat`, `bpf_prog_load`'s runc entry,
  `perf_event_open_non_profiler`'s system-probe). Code an ordinary user injects into
  those tools now fires (cases `ldpreload-into-cryptsetup-known-miss` and
  `ldpreload-into-runc-as-exe-known-miss`, now positives).
- **Problem** (what remains):
  1. `copyfail_af_alg_authencesn` `kcapi_hash_tools`: any user runs the libkcapi
     hash tools, and auditd does not decode the AF_ALG cipher name, so an
     unprivileged `LD_PRELOAD` into `kcapi-hasher` or `kcapi-dgst` still hides the
     CopyFail sequence.
  2. `ptrace_traceme` `debugger_images`: gdb, gdbserver and lldb-server run as any
     user, so no id separates a debugger's inferior from injected code.
  3. `setns_namespace_join` `runtime_images` has no `euid` condition by design: an
     unprivileged setns cannot join a namespace it does not own, and rootless runc
     runs as the user.
  4. Every entry: a process that already has `euid` 0 (including root in a container
     without user-namespace remapping) can still inject into an allowlisted binary or
     place a binary at the logged path.
  5. The snap-confine entries (`bpf_prog_load`, `setns_namespace_join`) have no `euid`
     condition, because snap-confine runs as the caller on snapd 2.70 and later.
     Secure-execution mode blocks injection into the real binary, but any user who
     can create a user namespace can run their own binary at a snap-confine path, so
     an unprivileged BPF socket-filter load (with `unprivileged_bpf_disabled=0`) is
     hidden. Remove the snap-confine entries on hosts without snapd.
- **Evidence**: cases `ldpreload-into-kcapi-hasher-known-miss`,
  `ldpreload-into-gdb-known-miss` and `snap-confine-path-in-user-namespace-known-miss`
  (filtered, KNOWN MISS).
- **Fix**: remove the kcapi filter on hosts without the libkcapi tools; baseline
  debugger use per host. No Sigma-level fix is known for 1 and 2.
- **New false positives, documented in the rules**: rootless runc < 1.2 fires
  `memfd_create_execveat` on every container start and exec; a user running
  `cryptsetup open --test-passphrase --link-vk-to-keyring` (cryptsetup 2.7.1 and
  later) fires `keyring_add_key_burst` once per key.

### Live-capture hits not yet attributed

The CI capture also annotated two rules that this tracker does not call defective:
`T1040/afpacket_raw_socket` (2 hits; enforce at 0 on the corpus, so a real fire would
fail if the capture were a committed slice) and `T1040/afinet_raw_socket` (5 hits). The
workload's AF_PACKET users are `tcpdump` (allowlisted) and `arping` (not in
`sniffer_processes`); its raw-socket user is `mtr` (the documented `mtr-packet` noise
in budgets.json). Read the run's `linux-benign-capture` artifact before you decide
whether `arping` belongs in the allowlist.

## Kubernetes (API server audit and CRI)

### K4. k8s_admission_webhook_neutered: neuters the audit record cannot show

- **Rule**: [`sigma/T1685/k8s_admission_webhook_neutered.yml`](sigma/T1685/k8s_admission_webhook_neutered.yml) (level high).
- **Kind**: false negative. **Severity**: low.
- **Problem**: the shipped policy now logs webhook-configuration update and patch at
  RequestResponse, so merge-patch and JSON-patch list replacements, rule-less webhooks
  in sorted key order, escaped-blank constants (`"false\n"`) and `kubernetes.io/metadata.name
  In [""]` selectors are graded. What is left cannot be told from a legitimate edit in
  one record:
  1. a `namespaceSelector`/`objectSelector` on a label other than
     `kubernetes.io/metadata.name` that matches nothing, or a
     `kubernetes.io/metadata.name In` list that names no real namespace;
  2. a selector or condition that contradicts itself (the same key with `Exists` and
     `DoesNotExist`, `In` and `NotIn` of one value): equality of two keys needs a
     back-reference, which the portable subset lacks;
  3. a `matchConditions` expression that reads a variable but never matches in
     practice, or a constant built with a macro that binds a variable
     (`[1].all(x, x > 1)`); constants are matched only when written from literals,
     operators, `in` and a fixed list of functions (`size`, `int`, `string`, `matches`, ...);
  4. at Request level (a policy without the RequestResponse rule), list replacements and
     JSON-patch selectors are seen by the chokepoint only.
- **Evidence**: cases `matchconditions-size-of-object-labels`,
  `namespace-selector-name-notin-empty-string`,
  `stored-namespace-selector-name-in-real-namespace`; the rule's description ("Blind
  spots").
- **Fix**: needs the cluster's labels or the old object (enrichment); none planned in
  Sigma.

### K9. k8s_coredns_corefile_poisoned: what the Corefile grader does not grade

- **Rule**: [`sigma/T1565.001/k8s_coredns_corefile_poisoned.yml`](sigma/T1565.001/k8s_coredns_corefile_poisoned.yml) (level high).
- **Kind**: false negative, false positive. **Severity**: low.
- **Problem**: the shipped policy now logs the three DNS ConfigMaps at RequestResponse
  and kube-system ConfigMap creates at Request, so a delete-and-recreate, a JSON patch
  (through the stored Corefile), quoted directives, directives on the brace line,
  `{$VAR}` placeholders, NBSP/NEL blanks, IPv4-mapped public targets and forwards of the
  cluster zone are graded. What is left:
  1. a forward of a zone other than the cluster zone to a **private** address, outside
     the root block: its record differs from a corporate stub zone only in the zone name
     and the address, so it is seen by the chokepoint only;
  2. the root-block grammar does not follow `import`; in the JSON-patch text (no
     responseObject) it reads one nested brace level, `#` comments as plain text and no
     quoted `import` path, because the full grammar exceeds Lucene's budget there;
  3. CoreDNS drops a carriage return even inside a token (`ho<CR>sts`) and splits on
     `unicode.IsSpace`; no portable construct names CR, VT or FF alone, and the forward
     grammars rely on `\s`, which holds NBSP and NEL only in Python;
  4. a commented-out directive written `#<TAB>rewrite` fires the plugin clause (false
     positive): the portable subset cannot say "line break only";
  5. the cluster-zone clause knows only `cluster.local`, and entries in k3s's
     `NodeHosts` data key are not graded.
- **Evidence**: near-misses `private-stub-zone-forward`,
  `jsonpatch-private-stub-zone-forward`, `stub-before-root-forwards-ip`,
  `lookalike-zone-mycluster-local`, `stub-zone-forward-ipv4-mapped-private`; positives
  `root-after-stub-block`, `jsonpatch-root-after-stub-block`,
  `stub-zone-forward-ipv4-mapped-public`; filtered `k3s-node-controller-nodehosts-update`,
  `minikube-default-annotation-patch`.
- **Fix**: none planned for 1 to 5.

### K14. k8s_namespace_deleted: a query dry run at Metadata level

- **Rule**: [`sigma/T1070/k8s_namespace_deleted.yml`](sigma/T1070/k8s_namespace_deleted.yml) (level low).
- **Kind**: evasion. **Severity**: medium.
- **Problem**: when a DELETE has a body, the API server reads DeleteOptions from the
  body and ignores the query, so `?dryRun=All` in `requestURI` does not prove a dry run.
  The rule now trusts the query form only when the record holds no request body, which
  fixes a Request-level record. A Metadata-level record never holds the body, so there
  a real namespace delete that also carries `?dryRun=All` is still filtered. The shipped
  lab policy logs namespace deletes at Metadata.
- **Evidence**: *source* — apiserver `endpoints/handlers/delete.go` (DeleteOptions from
  the body when present). *case* — positive `namespace-delete-query-dry-run-ignored-body`
  (Request level, fires); filtered `namespace-delete-dry-run-query` (Metadata level, the
  residual).
- **Fix**: trust the query form only on a record that would show a body: add
  `level: ['Request', 'RequestResponse']` to the query branch of `filter_dry_run`, next
  to `requestObject.kind: null`. A Metadata-level `?dryRun=All` delete then fires; a real
  query-only dry run logged at Metadata becomes a false positive, listed under
  falsepositives (as kubectl's body dry run at Metadata already is). Separately, logging
  namespace deletes at Request level in `detections/k8s/audit-policy-apiserver.yaml` lets
  the lab filter its own dry runs.
- **Then**: a new positive (a Metadata-level real delete with `?dryRun=All`) fires and a
  new filtered case (Request level, no body, `?dryRun=All`) holds. The existing filtered
  case `namespace-delete-dry-run-query` (Metadata) then fires, so relabelling it is a
  human decision (sufficiency-ratchet). The entry closes.

### K16. k8s_impersonation: an impersonation request without a user header

- **Rule**: [`sigma/T1134/k8s_impersonation.yml`](sigma/T1134/k8s_impersonation.yml) (level medium).
- **Kind**: false negative. **Severity**: low (the request fails and grants nothing).
- **Problem**: `Impersonate-Group`, `Impersonate-Uid` or `Impersonate-Extra-*` without
  `Impersonate-User` is refused before the identity is swapped. From v1.35 both filters
  refuse it with a 400 BadRequest Status: the legacy filter says "requested [...] without
  impersonating a user", and the constrained filter (beta and on by default from v1.36,
  the CI pin) says "... without impersonating a user name". The rule matches both
  (`select_headers_without_user`, positive
  `impersonate-group-header-without-user-constrained`). Up to v1.34 the legacy filter
  answers with HTTP 500 from `responsewriters.InternalError` (plain text, no Status), so
  the event has no `impersonatedUser` and no message; only `responseStatus.code: 500`
  remains.
- **Evidence**: *source* — kubernetes v1.32.0
  `staging/src/k8s.io/apiserver/pkg/endpoints/filters/impersonation.go:44-47,269-270`,
  `handlers/responsewriters/errors.go:80-84`, `filters/audit.go:231-237`; v1.34.0
  `filters/impersonation.go:269` (a plain error); v1.35.0
  `filters/impersonation/impersonation.go:270` (`NewBadRequest`); v1.36.4
  `filters/impersonation/constrained_impersonation.go:161-162`. **unverified** on a live
  cluster.
- **Fix**: none in Sigma for the 500 shape (v1.34 and earlier): no field of the record
  names the headers.

### K17. k8s_rbac_privileged_grant: the wildcard clause fires on bootstrap and read-only roles

- **Rule**: [`sigma/T1098.006/k8s_rbac_privileged_grant.yml`](sigma/T1098.006/k8s_rbac_privileged_grant.yml) (level high).
- **Kind**: false positive. **Severity**: low.
- **Problem**: `sel_dangerous_rules` matches `"*"` anywhere in `requestObject.rules`. The
  bootstrap policy that `system:apiserver` writes at start-up carries wildcard roles with
  write verbs (the garbage collector: get, list, watch, patch, update, delete on `*/*`;
  the namespace controller: get, list, watch, delete, deletecollection on `*/*`; the
  HPA: get, update on `*/scale`) and with read verbs only (the resource-quota
  controller: list, watch on `*/*`; the disruption controller: get on `*/scale`). All
  fire this high-level rule, as do read-only operators installed by GitOps. They account
  for much of what the live kind bootstrap capture records for this rule (17 hits, budget
  9, shadow mode).
- **Evidence**: *probe* — a ClusterRole create by `system:apiserver` with `list`/`watch`
  on `*/*` fires; a read-only role on `pods` does not. *source* — kubernetes v1.36.4
  `plugin/pkg/auth/authorizer/rbac/bootstrappolicy/controller_policy.go:139,278,287,317,386`.
  *CI capture* — the validate-apiserver live shadow slice on v1.32.2 (runs 38976160238
  and 39262859317): 17 hits.
- **Fix**: two parts. Requiring `*` in `verbs`, or a write or escalation verb next to the
  wildcard, removes only the read-only roles (near-miss: read-only `list`/`watch` on
  `*/*`). Filtering `user.username: system:apiserver` (only the API server's loopback
  client presents it; impersonation does not change `user.username`) removes the
  bootstrap writes (filtered case).
- **Then**: the near-miss and filtered cases hold; the live shadow count drops by the
  read-only roles with the first part, and to the non-bootstrap writes with both.

### K18. T1611 pod-spec rules: a JSON-patched controller template

- **Rules**: [`sigma/T1611/k8s_podspec_controller_host_access.yml`](sigma/T1611/k8s_podspec_controller_host_access.yml),
  [`sigma/T1611/k8s_podspec_host_access.yml`](sigma/T1611/k8s_podspec_host_access.yml) (level high).
- **Kind**: false negative. **Severity**: low (the pods a controller then creates still
  fire `k8s_podspec_host_access` under the controller's identity; an ephemeral-container
  write still fires the medium `T1609/k8s_pod_ephemeral_container`).
- **Problem**: a JSON patch (`kubectl patch --type=json`) logs `requestObject` as the list
  of operations, so `requestObject.spec.template.spec.*` and `requestObject.spec.*` do not
  exist. A JSON patch that makes a Deployment's pod template privileged is not graded; a
  strategic-merge patch of the same change is. A JSON patch of `pods/ephemeralcontainers`
  that adds a privileged ephemeral container is not graded by the pod rule either.
- **Evidence**: *probe* — the controller rule on a Deployment patch: strategic merge
  `{"spec":{"template":{"spec":{"containers":[{"securityContext":{"privileged":true}}]}}}}`
  fires; JSON patch `[{"op":"add","path":"/spec/template/spec/containers/0/securityContext","value":{"privileged":true}}]`
  does not. The pod rule on a `pods/ephemeralcontainers` patch: the strategic-merge
  positive `privileged-ephemeral-debug` fires; JSON patch
  `[{"op":"add","path":"/spec/ephemeralContainers/-","value":{"name":"dbg","securityContext":{"privileged":true}}}]`
  does not (`k8s_pod_ephemeral_container` fires).
- **Fix**: `requestObject|re` branches for an operation whose path is `/spec`,
  `/spec/template`, `/spec/template/spec`, the `/spec/jobTemplate/...` equivalents, or any
  path below them (pod rule: `/spec/ephemeralContainers` or below), and that sets a
  dangerous field, either in the value text (`"privileged":true`, `"hostPID"`,
  `"hostNetwork"` or `"hostIPC"` true, `"hostPath":{`, a dangerous capability in `add`) or
  as the last path segment (`/securityContext/privileged`, `/hostPID`, `/hostNetwork`,
  `/hostIPC` with value true; `/capabilities/add` with a dangerous value; `/volumes/-` with
  a hostPath value). Modelled on the TRR9008 JSON-patch selectors, with positives and
  near-misses.

### KTBD-C1. k8s_admission_webhook_repointed_to_url: a service-to-service repoint, or a JSON-patch copy/move

- **Rule**: [`sigma/T1546/k8s_admission_webhook_repointed_to_url.yml`](sigma/T1546/k8s_admission_webhook_repointed_to_url.yml) (level high).
- **Kind**: false negative. **Severity**: low.
- **Problem**: the Procedure D grader reads a `clientConfig.url` in the request body.
  Two repoints carry no URL in the request:
  1. a repoint from one `clientConfig.service` to another (an attacker-run in-cluster
     Service): the body sets a `service`, not a `url`, so the grader does not fire. The
     webhook now calls the attacker's pod through a Service, with no off-cluster URL;
  2. a JSON patch `copy` or `move` that takes an existing `clientConfig.url` from
     another webhook in the same configuration: the operation names source and target
     paths, not a URL value, so the request carries no URL text.
  Both fire only the TRR9008 chokepoint `k8s_admission_webhook_disabled` (any admission
  update or patch, medium).
- **Evidence**: *case* — near-misses
  `smp-patch-service-to-other-service-known-miss` (blind spot 1) and
  `jsonpatch-copy-clientconfig-known-miss` (blind spot 2) in
  [`sigma/T1546/k8s_admission_webhook_repointed_to_url.cases.jsonl`](sigma/T1546/k8s_admission_webhook_repointed_to_url.cases.jsonl)
  (KNOWN MISS). *probe* — gopkg.in/evanphx/json-patch.v4 v4.13.0 (the API server's
  JSON patch library) applies
  `[{"op":"copy","from":"/webhooks/1/clientConfig","path":"/webhooks/0/clientConfig"}]`
  and copies webhook 1's url to webhook 0. The rule's description names both blind
  spots.
- **Fix**: none in Sigma for the service-to-service repoint (the discriminator is the
  attacker's pod behind the Service, which the record does not show). For the JSON-patch
  copy/move, a `responseObject`-based branch gated on the `copy`/`move` op could read the
  stored `clientConfig.url` after the write (the policy records `responseObject` at
  RequestResponse). Not built yet: it reads the stored object, not the request, so it
  needs RequestResponse level and a case that proves it.

### KTBD-C2. Admission-object apply patches with a YAML body: no audit record

- **Rules**: [`sigma/T1546/k8s_admission_webhook_repointed_to_url.yml`](sigma/T1546/k8s_admission_webhook_repointed_to_url.yml) (level high),
  [`sigma/T1546/k8s_admission_webhook_created.yml`](sigma/T1546/k8s_admission_webhook_created.yml) (medium),
  [`sigma/T1546/k8s_malicious_admission_webhook_created.yml`](sigma/T1546/k8s_malicious_admission_webhook_created.yml) (high),
  [`sigma/T1685/k8s_admission_webhook_disabled.yml`](sigma/T1685/k8s_admission_webhook_disabled.yml) (medium).
- **Kind**: policy gap. **Severity**: medium.
- **Problem**: the API server stores the raw body of a patch as `requestObject` and
  marks it as JSON before it applies the patch. A server-side apply patch
  (`application/apply-patch+yaml`) may carry a YAML body, which the API server accepts.
  The audit backend cannot encode that body as JSON, so it drops the whole event. The
  shipped policy logs `admissionregistration.k8s.io` patches at RequestResponse, so no
  record of such a write (a server-side-apply install or repoint of a webhook
  configuration) reaches the log, and none of the rules above fires. kubectl and
  client-go send apply bodies as JSON, which is logged; a raw client can send YAML. The
  webhook audit backend fails the whole batch that holds such an event.
- **Evidence**: *source* — kubernetes v1.36.4
  `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go` (`audit.LogRequestPatch`
  before the patch is decoded; `ApplyYAMLPatchType` decodes with `yaml.Unmarshal`),
  `staging/src/k8s.io/apiserver/pkg/audit/context.go` (`LogRequestPatch` stores a
  `runtime.Unknown` with `ContentType` JSON), `plugin/pkg/audit/log/backend.go` (an encode
  error goes to `HandlePluginError`). *probe* — the v0.36.4 log backend, given an event
  whose `requestObject` is a YAML apply body, writes 0 bytes and logs
  `Error in audit plugin 'log' affecting 1 audit events`; with a JSON body it writes the
  event.
- **Fix**: none in Sigma. Watch the fallback evidence: the kube-apiserver log line
  `Error in audit plugin '<name>' affecting N audit events` (it prints each impacted
  event's method, user and URI) and the metric `apiserver_audit_error_total{plugin="log"}`
  (or `webhook`). A change in the API server (log a YAML apply body converted to JSON) is
  an upstream step for a human.
- **Then**: a recorded YAML-bodied apply patch of a webhook configuration fires the
  repoint grader (patch answered 200) or both create rules (patch answered 201).

## Cloud (AWS, Azure, GCP)

### C6. gcp_workforce_principalset_privileged_binding: where the privileged-role tier ends

- **Rule**: [`sigma/T1199/gcp_workforce_principalset_privileged_binding.yml`](sigma/T1199/gcp_workforce_principalset_privileged_binding.yml) (level medium).
- **Kind**: false negative, false positive (trade-off). **Severity**: low.
- **Problem**: the rule now has two tiers. A role that controls IAM fires at every member
  scope: `roles/owner`, `roles/editor`, `roles/iam.*Admin|Creator|User`,
  `roles/resourcemanager.{project,folder,organization}IamAdmin`,
  `roles/resourcemanager.{folder,organization}Admin`, `roles/orgpolicy.policyAdmin`, and a
  custom role whose ID contains `Owner`, `Editor` or `Admin`. Any other role whose name
  contains owner, editor or admin (`roles/secretmanager.admin`, `roles/cloudkms.admin`,
  `roles/logging.admin`, `roles/bigquery.dataOwner`, ...) fires only when granted to the
  whole pool. So a backdoor that uses such a service-level role at `/group/` or
  `/attribute.` scope is missed, and a narrow custom role named `*Admin` fires at every
  scope. The corpus hits went from 3 to 0 (`gcp-iam-federation-admin`).
- **Evidence**: cases `group-scoped-container-admin`, `group-scoped-bigquery-data-editor`,
  `group-scoped-compute-security-admin`, `subject-scoped-bigquery-data-owner` (near-miss);
  `group-scoped-orgpolicy-policy-admin`, `group-scoped-custom-admin-role`,
  `whole-pool-bigquery-data-editor` (positive).
- **Fix**: a human approves where the tier boundary sits, or a pipeline baselines the
  approved groups so every admin role can fire at every scope.

### C12. aws_cognito_unauthenticated_identity_use: keyed on the console's role name

- **Rule**: [`sigma/T1078.004/aws_cognito_unauthenticated_identity_use.yml`](sigma/T1078.004/aws_cognito_unauthenticated_identity_use.yml) (level medium).
- **Kind**: false negative (documented). **Severity**: low.
- **Problem**: the rule finds the guest role by the console's naming
  (`Cognito_<pool>Unauth_Role`, Amplify's `...-unauthRole`), so a pool whose guest role
  has a site-specific name is missed. The rule's description says so.
- **Evidence**: the `PLATFORM_NAMING` waiver in
  [`check_sufficiency.py`](check_sufficiency.py) keeps only `Unauth` through the
  rename test for this reason. [TRR9016](../research/trr9016/aws/README.md) (Blind spots)
  sets out what the documents confirm: the guest fact is the token's `amr` claim, which
  no documented default-trail field carries. Two points are **unverified**: what
  `webIdFederationData.attributes` holds for a guest (the fixtures' `attributes: {}` is
  synthetic), and whether the enhanced flow's background `AssumeRoleWithWebIdentity`
  reaches the customer trail with `policyArns` naming
  `AmazonCognitoUnauthenticatedIdentities`, which would be a guest marker independent of
  the role name.
- **Fix**: capture one guest and one signed-in issuance live, in both flows. If either
  unverified field separates them, key the rule on it and drop the waiver; if not, the
  entry stays as a proven telemetry limit.

### C15. Public-policy rules: a public statement after the fifth, and scope-key presence

- **Rules**: [`sigma/T1537/aws_resource_policy_made_public.yml`](sigma/T1537/aws_resource_policy_made_public.yml),
  [`sigma/T1537/aws_efs_file_system_policy_made_public.yml`](sigma/T1537/aws_efs_file_system_policy_made_public.yml).
- **Kind**: false positive. **Severity**: low.
- **Problem**: statements 1 to 5 are now tested one by one against their own
  Condition, so two to five scoped public Allow statements no longer fire. A public
  Allow at statement 6 or later fires without a scope test, on purpose (a fixed-length
  portable pattern). A scoping key is checked for presence in the statement's
  Condition, not for its value.
- **Evidence**: cases `sqs-two-scoped-public-statements-fire` and
  `efs-two-org-scoped-public-statements-fire` (now filtered),
  `sqs-6-scoped-public-statements-beyond-limit-fire`,
  `sqs-public-allow-scoping-key-as-condition-value`,
  `efs-public-allow-scoping-key-as-condition-value`.
- **Fix**: decode the policy JSON in the log pipeline and test each statement.

## Checks to add

- `T1543.005/linux_static_pod_manifest_write`: check-sufficiency R5 warns that no
  negative breaks `selection_dir.TargetFilename`. That selection has one item, so a
  record that breaks it shares no item with the rule and grades trivial (a write to
  `/etc/kubernetes/manifests-disabled/kube-scheduler.yaml` by `/usr/bin/mv` does). No
  near-miss can close the warning; its proof is the filtered cases. The R5 message
  should not offer an item that is the only item of its selection.

(The thin-negative warnings on `T1053.007/k8s_cri_job_pod` and `T1134/k8s_impersonation`
are gone: near-misses `operator-pod-labelled-controller-uid` and
`policy-webhook-denial-quotes-impersonate` pass `check_sufficiency.py`.)

## Closed entries

An ID stays retired after its entry closes. A sidecar `why` that names a closed ID
points here.

| ID | Closed by | Proof |
|----|-----------|-------|
| K13 | new hunting rule `T1070/k8s_namespace_deleted` (level low) | positive `namespace-delete-payments`; filtered dry-run and garbage-collector cases; budget 4 (`k8s-audit-gitops-ci`) |
| K15 | `T1609/k8s_node_proxy_exec` fires on a `nodes/proxy` request whose requestURI path (anything before `?`) holds a percent-encoded byte or a dot segment, whatever endpoint it seems to name, also when the encoding is in the `/api/v1/nodes/<n>/proxy/` prefix | positives `node-proxy-exec-dot-segment-after-containerlogs`, `node-proxy-exec-percent-encoded-endpoint`, `node-proxy-exec-percent-encoded-prefix-and-endpoint`; near-miss `node-proxy-containerlogs-encoded-query-only` (not verified live) |
| K19 | `T1685/k8s_security_tool_workload_removed` retitled as a generic Deployment or DaemonSet anchor (its title claimed security tools only); matches only accepted (200/201/202) writes and filters the dry runs the record shows (the `?dryRun=All` query of an update or patch; the DeleteOptions body of a delete at Request level) | near-misses `delete-deployment-forbidden`, `delete-deployment-not-found`; filtered `delete-deployment-dry-run-body`, `scale-to-zero-patch-dry-run-query`, `kubectl-scale-zero-dry-run` |
| K20 | `T1134/k8s_impersonation` matches the v1.36 constrained-impersonation refusals (`cannot impersonate:<mode>`, `cannot impersonate-on:<mode>:<verb>`), not only the legacy `cannot impersonate resource` | positives `denied-serviceaccount-impersonation-probe-constrained`, `denied-user-impersonation-probe-constrained`, `constrained-impersonation-username-check-denied` |
| K21 | both TRR9025 create rules (`k8s_admission_webhook_created`, `k8s_malicious_admission_webhook_created`) match `verb: create` OR (`verb: patch` AND `responseStatus.code: 201`), so a server-side-apply install (a patch answered 201) fires both; the chokepoint's CHOKEPOINT waiver digest was re-approved | positives `ssa-create-webhook-patch-201` (chokepoint) and `ssa-create-offcluster-url-patch-201` (grader); near-misses `ssa-create-patch-answered-200-not-create` and `repoint-offcluster-url-patch-answered-200` (a patch answered 200 is a modify, not a create) |
| C13 | `entra_app_federated_credential_backdoor` reads only `newValue`, in any key order | near-misses `fic-with-unapproved-issuer-removed`, `fic-repointed-away-new-value-first` and the other reordered cases |
| C14 | `aws_resource_policy_made_public` reads a `Statement` that is one object | positives `s3-single-statement-object-public-read`, `sqs-single-statement-object-public-send`, `efs-single-statement-object-public-mount` |
| C16 | `aws_github_oidc_role_trust_abuse` grades each `sub` value | near-miss `two-subs-pinned-ref-wildcards-grade-high`; positive `two-subs-pinned-ref-wildcards-go-to-high-rule` of the low rule |
| S1 | every `\|re` value fits Lucene's default `max_determinized_states` (10000) | a Lucene 10.1 `RegExp` build over all 236 values wrapped in `.*`: largest 7,986 states (the CoreDNS JSON-patch root grammar) |

## Closing an entry

1. Fix the rule. If check-sufficiency waives the rule (`CHOKEPOINT`, `PRESENCE`,
   `COMPILE_ONLY`, `PLATFORM_NAMING`), the edit changes its digest, and a human
   re-approves the waiver.
2. Turn the evidence into a case: the probe or the KNOWN MISS confounder becomes a
   positive (false negative), or a filtered, near-miss or benign case (false
   positive). Relabelling or editing an existing case (its kind, `breaks` or events)
   fails `sufficiency-ratchet` on the pull request, which is a human's decision (the
   `automerge` bot turns its auto-merge off when it sees the failure); a new case,
   or a reworded `why`, does not.
3. Run `rule_cases.py`, `check_sufficiency.py`, the rule's validator and
   `score_benign.py --check --enforce`; regenerate `scores.json` with `--update`.
4. Propose the lower budget (`score_benign.py --reseeds 10`) in `budgets.json`,
   which a human approves, and update its `why`.
5. Delete the entry here and add a row to [Closed entries](#closed-entries); a sidecar
   `why` may keep the retired ID as a pointer.

## Reproducing a probe

```python
import sys; sys.path.insert(0, "detections")
import sigma_eval, sigma_explain
rule = "detections/sigma/T1068/dirtyfrag_xfrm_unshare_netlink.yml"
base = {"type": "SYSCALL", "success": "yes", "pid": 500, "comm": "x", "exe": "/x"}
events = [dict(base, syscall="unshare", a0="50020000", timestamp="2026-10-12 14:00:00.000"),
          dict(base, syscall="socket", a0="10", a1="3", a2="6", timestamp="2026-10-12 14:00:00.100")]
flat = [sigma_eval.flatten(e) for e in events]
print(bool(sigma_eval.evaluate(sigma_eval.compile_rule(rule), flat)))            # False: L3
print(sigma_explain.judge_events(sigma_explain.load(rule), flat)[0].kind)        # near-miss
```
