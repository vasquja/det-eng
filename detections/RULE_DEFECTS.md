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
    it. A *Go reproduction against `<module>@<version>`* is a small program, not kept in
    this repository, that ran that module's code; it is source evidence, not a probe.
    Where nothing in this repository recorded the real telemetry, the entry says
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
| [K17](#k17-k8s_rbac_privileged_grant-the-wildcard-clause-fires-on-bootstrap-and-read-only-roles) | `T1098.006/k8s_rbac_privileged_grant` | the `"*"` clause fires on the bootstrap controller roles and on read-only wildcard roles; other bootstrap roles that `system:apiserver` writes fire through `impersonate` or `"*"` | false positive | low |
| [K22](#k22-k8s_admission_webhook_repointed_to_url-a-service-to-service-repoint-or-a-json-patch-copymove) | `T1546/k8s_admission_webhook_repointed_to_url` | a repoint to another in-cluster Service, or a JSON-patch copy/move, carries no URL | false negative | low |
| [K23](#k23-apply-patches-with-a-yaml-body-no-audit-record-at-request-level-or-higher) | every Kubernetes rule whose records the shipped audit policy logs at Request or higher (RBAC objects, pods, apps and batch workloads and their scale subresources, admission configuration objects, the kube-system DNS and aws-auth ConfigMaps) | an apply patch with a YAML body is dropped from the audit log at Request level or higher, so no rule sees that write | policy gap | medium |
| [K24](#k24-k8s_podspec_confinement_disabled-per-container-annotations-keyed-by-container-name) | `T1611/k8s_podspec_confinement_disabled` | a per-container seccomp/AppArmor annotation in a pod or controller body written outside `kubectl apply` is keyed by container name and not graded (a JSON patch is graded) | false negative | low |
| [K25](#k25-k8s_podspec_confinement_disabled-selinux-type-outside-the-baseline-list) | `T1611/k8s_podspec_confinement_disabled` | SELinux `seLinuxOptions.type` set to `spc_t` (or another type off the Baseline list) also removes confinement and is not graded | false negative | low |
| [K26](#k26-k8s_rbac_sensitive_permission_grant-the-bootstrap-roles-fire) | `T1098.006/k8s_rbac_sensitive_permission_grant` | the built-in roles the API server writes at bootstrap (system:aggregate-to-edit, system:node, system:kube-controller-manager) fire | false positive | low |
| [K27](#k27-k8s_rbac_sensitive_permission_grant-residual-blind-spots) | `T1098.006/k8s_rbac_sensitive_permission_grant` | a JSON-patch operation list is not read; pods/ephemeralcontainers and resourceNames are not graded; a bind to an existing sensitive role is not graded here | false negative | low |
| [K28](#k28-k8s_eks_aws_auth_configmap_modified-a-denied-create-names-no-object) | `T1098.006/k8s_eks_aws_auth_configmap_modified` | a denied create logs no objectRef.name (a YAML-bodied server-side apply: see K23) | false negative | low |
| [K29](#k29-t1685-enforcer-removal-rules-a-daemonset-unscheduled-by-its-pod-template) | `T1685/k8s_enforcer_workload_removed`, `k8s_security_tool_workload_removed` | a DaemonSet (Falco) whose pod template gets a nodeSelector, affinity or nodeName that no node matches loses every pod, and neither rule fires | false negative | medium |
| [K32](#k32-t1685-enforcer-removal-rules-a-null-strategic-merge-directive-next-to-a-count) | `T1685/k8s_enforcer_workload_removed`, `k8s_security_tool_workload_removed` | a strategic merge patch of deployments/scale with a count above 0 and a null `$deleteFromPrimitiveList/replicas` (or `/spec`) scales to 0, and neither rule fires | false negative | low |
| [K33](#k33-json-text-skip-grammars-a-key-nested-three-levels-deep-splits-an-operation) | `T1685/k8s_enforcer_workload_removed`, `k8s_security_tool_workload_removed`, `k8s_admission_webhook_neutered`, `T1611/k8s_podspec_controller_host_access`, `k8s_podspec_host_access`, `k8s_podspec_confinement_disabled` | an ignored key nested three levels deep, or a brace string inside a nested object, splits a JSON-patch operation or a profile object, so it is not graded (Lucene's budget) | false negative | low |
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
  fixes a Request-level record. A record that the audit truncate backend cut (annotation
  `audit.k8s.io/truncated`) has lost its body too, so the rule does not trust the query
  form there (positive `namespace-delete-query-dry-run-truncated-record`). A Metadata-level record never holds the body, so there
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
  fire this high-level rule, as do read-only operators installed by GitOps. The
  bootstrap roles in `policy.go` that `system:apiserver` writes fire it through other
  clauses too: `system:aggregate-to-edit` through `impersonate` (on serviceaccounts), and
  `system:kube-controller-manager` (list, watch on `*/*`) and `cluster-admin` through
  `"*"`. Only part 2 of the fix (the `system:apiserver` filter) removes those, so K17
  and K26 describe the same writer. They account for much of what the live kind
  bootstrap capture records for this rule (17 hits, budget 9, shadow mode).
- **Evidence**: *probe* — a ClusterRole create by `system:apiserver` with `list`/`watch`
  on `*/*` fires; a read-only role on `pods` does not; `system:aggregate-to-edit`
  (`impersonate` on serviceaccounts), `system:kube-controller-manager` and
  `cluster-admin`, each written by `system:apiserver`, fire. *source* — kubernetes v1.36.4
  `plugin/pkg/auth/authorizer/rbac/bootstrappolicy/controller_policy.go:139,278,287,317,386`
  and `policy.go:159` (`impersonate` in `editRules`), `:322` (`cluster-admin` on `*/*/*`),
  `:488` (`system:kube-controller-manager` list, watch on `*/*`).
  *CI capture* — the validate-apiserver live shadow slice on v1.32.2 (runs 38976160238
  and 39262859317): 17 hits.
- **Fix**: two parts. Requiring `*` in `verbs`, or a write or escalation verb next to the
  wildcard, removes only the read-only roles (near-miss: read-only `list`/`watch` on
  `*/*`); it does not remove `system:aggregate-to-edit`, which fires through
  `impersonate`. Filtering `user.username: system:apiserver` (only the API server's
  loopback client presents it; impersonation does not change `user.username`) removes the
  bootstrap writes (filtered case).
- **Then**: the near-miss and filtered cases hold; the live shadow count drops by the
  read-only roles with the first part, and to the non-bootstrap writes with both.

### K22. k8s_admission_webhook_repointed_to_url: a service-to-service repoint, or a JSON-patch copy/move

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
- **Evidence**: *case* — KNOWN MISS confounders
  `smp-patch-service-to-other-service-known-miss` (blind spot 1) and
  `jsonpatch-copy-clientconfig-known-miss` (blind spot 2) in
  [`sigma/T1546/k8s_admission_webhook_repointed_to_url.cases.jsonl`](sigma/T1546/k8s_admission_webhook_repointed_to_url.cases.jsonl).
  *source* — Go reproduction against `gopkg.in/evanphx/json-patch.v4@v4.13.0` (the API
  server's JSON patch library): it applies
  `[{"op":"copy","from":"/webhooks/1/clientConfig","path":"/webhooks/0/clientConfig"}]`
  and copies webhook 1's url to webhook 0. The rule's description names both blind
  spots.
- **Fix**: none in Sigma for the service-to-service repoint (the discriminator is the
  attacker's pod behind the Service, which the record does not show). For the JSON-patch
  copy/move, a `responseObject`-based branch gated on the `copy`/`move` op could read the
  stored `clientConfig.url` after the write (the policy records `responseObject` at
  RequestResponse). Not built yet: it reads the stored object, not the request, so it
  needs RequestResponse level and a case that proves it.
- **Then**: with that `responseObject` branch, the confounder
  `jsonpatch-copy-clientconfig-known-miss` fires; relabelling it as a positive is a
  human decision under the sufficiency ratchet. The confounder
  `smp-patch-service-to-other-service-known-miss` stays a KNOWN MISS.

### K23. Apply patches with a YAML body: no audit record at Request level or higher

- **Scope**: every Kubernetes rule that reads a record which the shipped policy
  ([`k8s/audit-policy-apiserver.yaml`](k8s/audit-policy-apiserver.yaml)) logs at
  Request or RequestResponse. The policy rules at that level cover patches of these
  resources:
  - RBAC objects (roles, clusterroles, rolebindings and clusterrolebindings);
  - pods and `pods/ephemeralcontainers`;
  - apps and batch workloads (deployments, daemonsets, statefulsets, replicasets, jobs
    and cronjobs), replicationcontrollers, and the scale subresources of deployments,
    statefulsets and replicasets;
  - admission configuration objects (webhook configurations, validating admission
    policies and their bindings);
  - the kube-system ConfigMaps `coredns`, `kube-dns`, `coredns-custom` and `aws-auth`.

  This entry names no rule file in the Summary row or in a Rules bullet, because
  `research/tools/coverage_report.py` maps a listed rule to its procedures, and a gap of
  the audit pipeline is not a defect of one rule. So it marks no procedure in
  [`research/COVERAGE.md`](../research/COVERAGE.md), which states this exception
  under "Limits of this report".
- **Kind**: policy gap. **Severity**: medium (the client chooses the body format, and
  the record is lost for every rule on the resource, the chokepoints included; kubectl
  and client-go send JSON, so only a raw client can use it).
- **Problem**: the API server logs the raw body of every patch as `requestObject` and
  marks it as JSON before it decodes the patch. A server-side apply patch
  (`Content-Type: application/apply-patch+yaml`) can carry a YAML body, which the API
  server accepts. The JSON log backend cannot encode that body, so it drops the whole
  event: no line is written, and no rule can fire on that write. This is true for every
  resource and patch target at Request level or higher; a delete, a create (POST) and an
  update (PUT) are not affected. At Metadata level the body is not logged, so the record
  survives (a Metadata-level rule still fires). The webhook audit backend fails the
  whole batch that holds such an event. Examples: a server-side-apply install or repoint
  of a webhook configuration (TRR9025), a neuter in place (TRR9008 C), a scale patch
  (TRR9008 D), a role or binding apply (TRR9004), a pod or controller apply (TRR9007), a
  CoreDNS ConfigMap apply (TRR9027 B and C are server-side applies). The TRR9008 deletes
  (A and B) send no patch and are not affected. Do not lower the audit level to avoid
  the gap: the graders and the validators' sentinel gates need the body.
- **Evidence**: *source* — kubernetes v1.36.4 (module `k8s.io/apiserver@v0.36.4`):
  `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go:133`
  (`audit.LogRequestPatch(req.Context(), patchBytes)` for every patch type, before the
  `case types.ApplyYAMLPatchType` branch at line 138); `pkg/audit/request.go:162-167`
  (`LogRequestPatch` returns early only below Request level);
  `pkg/audit/context.go:178-183` (`RequestObject = &runtime.Unknown{Raw: patch,
  ContentType: runtime.ContentTypeJSON}`); `k8s.io/apimachinery@v0.36.4`
  `pkg/runtime/embedded.go:86-94` (`Unknown.MarshalJSON` returns `Raw` as it is);
  `plugin/pkg/audit/log/backend.go:76-79` (an encode error goes to `HandlePluginError`,
  and the function returns false with no line written). Go reproduction against
  `k8s.io/apiserver@v0.36.4`: the log backend, given an event whose `requestObject` is a
  YAML apply body, writes 0 bytes and logs `Error in audit plugin 'log' affecting 1 audit
  events`; with a JSON body it writes the event.
- **Fix**: none in Sigma, and no rule change closes it. Watch the operator signal: the
  kube-apiserver log line `Error in audit plugin '<name>' affecting N audit events`
  (`pkg/audit/metrics.go`, `HandlePluginError`; it prints each impacted event's method,
  user and URI) and the metric `apiserver_audit_error_total{plugin="log"}` (or
  `webhook`). A change in the API server (log a YAML apply body converted to JSON) is an
  upstream step for a human.
- **Then**: a YAML-bodied apply patch is recorded and fires the same rules as the same
  patch with a JSON body. For example, a webhook-configuration apply fires the repoint
  grader (patch answered 200) or both create rules (patch answered 201).

### K24. k8s_podspec_confinement_disabled: per-container annotations keyed by container name

- **Rule**: [`sigma/T1611/k8s_podspec_confinement_disabled.yml`](sigma/T1611/k8s_podspec_confinement_disabled.yml) (level medium).
- **Kind**: false negative. **Severity**: low.
- **Problem**: the deprecated per-container AppArmor annotation
  `container.apparmor.security.beta.kubernetes.io/<container>: unconfined` is still
  honoured: the API server copies it to the container's `appArmorProfile` field in
  `PrepareForCreate` (`applyAppArmorVersionSkew`, `pkg/registry/core/pod/strategy.go`),
  which runs AFTER `audit.LogRequestObject` writes the request body
  (`staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go`), so the body holds
  only the annotation. The annotation key carries the container name, and a Sigma field
  name cannot be a pattern, so in a pod or controller body (a create, an update, or a
  strategic-merge or merge patch) the rule reads these annotations only through kubectl's
  fixed-key `last-applied-configuration` (`sel_last_applied`). A pod or template written
  another way with that annotation is not seen: a raw client, server-side apply, and the
  pod create that a ReplicaSet, DaemonSet or Job controller makes from such a template.
  A JSON patch is graded, because its operation list is one text field
  (`sel_jp_conf_annotation`). The non-functional per-container seccomp annotation
  (`container.seccomp.security.alpha.kubernetes.io/<container>`) has the same shape.
- **Evidence**: *source* — `applyAppArmorVersionSkew` in `pkg/registry/core/pod/strategy.go`
  at tag v1.36.4; *case* — KNOWN MISS confounder
  `replicaset-pod-create-apparmor-annotation-only` (a controller pod create that carries
  only the annotation); positives `apparmor-container-annotation-via-kubectl-apply` and
  `deployment-apparmor-annotation-via-kubectl-apply` (the `kubectl apply` path), and
  `deployment-apparmor-annotation-map-jsonpatch` and
  `deployment-apparmor-annotation-leaf-jsonpatch` (the JSON-patch path).
- **Fix**: none in Sigma for a non-JSON-patch body with the current log shape: it needs a
  pipeline that keeps `metadata.annotations` as one JSON text (so a `|re` can read the
  per-container key), or `RequestResponse` for pods so the copied `appArmorProfile` field
  appears in `responseObject` (a human decision: log volume).
- **Then**: the confounder `replicaset-pod-create-apparmor-annotation-only` fires;
  relabelling it as a positive is a human decision under the sufficiency ratchet.

### K25. k8s_podspec_confinement_disabled: SELinux type outside the Baseline list

- **Rule**: [`sigma/T1611/k8s_podspec_confinement_disabled.yml`](sigma/T1611/k8s_podspec_confinement_disabled.yml) (level medium).
- **Kind**: false negative. **Severity**: low.
- **Problem**: setting `securityContext.seLinuxOptions.type` to `spc_t` (the SELinux
  "super-privileged container" type) or another type outside the Pod Security Baseline
  allow-list also removes a confinement layer, and the rule grades only seccomp and
  AppArmor. The Baseline allows only an empty type, `container_t`, `container_init_t`,
  `container_kvm_t` and, since policy version v1.31, `container_engine_t`; an off-list
  type is a Baseline violation like Unconfined.
- **Evidence**: *source* — kubernetes v1.36.4
  `staging/src/k8s.io/pod-security-admission/policy/check_seLinuxOptions.go`
  (`selinuxAllowedTypes1_0` and `selinuxAllowedTypes1_31`); *case* — KNOWN MISS
  confounder `selinux-spc-t-not-graded` (a pod with `seLinuxOptions.type: spc_t` that the
  rule does not fire on).
- **Fix**: a possible branch on `requestObject.spec*.securityContext.seLinuxOptions.type`
  (and the container lists) against the types outside the Baseline allow-list, with its
  own positives and near-misses. Deferred: SELinux is enforced only on SELinux nodes, so
  the value differs from the seccomp/AppArmor layer this rule anchors on.
- **Then**: the confounder `selinux-spc-t-not-graded` fires; relabelling it as a positive
  is a human decision under the sufficiency ratchet.

### K26. k8s_rbac_sensitive_permission_grant: the bootstrap roles fire

- **Rule**: [`sigma/T1098.006/k8s_rbac_sensitive_permission_grant.yml`](sigma/T1098.006/k8s_rbac_sensitive_permission_grant.yml) (level medium).
- **Kind**: false positive. **Severity**: low.
- **Problem**: the sensitive-grant clauses match the built-in ClusterRoles the API
  server writes as `system:apiserver` at start-up and at an upgrade. `editRules`
  is written into `system:aggregate-to-edit` (which carries `pods/exec`,
  `pods/attach`, `secrets` reads and `serviceaccounts/token create`); `edit`
  itself is written with only an `aggregationRule` and no `rules`, so the bootstrap
  write of `edit` does not fire, and `edit` gets those rules from the aggregation
  controller, which the filter excludes. `system:node` carries
  `secrets get/list/watch` and `serviceaccounts/token create`;
  `system:kube-controller-manager` carries `secrets` reads and
  `serviceaccounts/token create`. All of `system:aggregate-to-edit`, `system:node`
  and `system:kube-controller-manager` fire. The filter excludes only the
  `clusterrole-aggregation-controller` on `admin`/`edit`, not the API server's
  bootstrap writes.
- **Precedent and choice**: K17 records the same false positive for the high
  privileged-grant rule and is still open. K17's planned fix filters
  `user.username: system:apiserver`, which is safe: only the API server's loopback
  client presents that username, and impersonation does not change `user.username`
  (an impersonated identity goes to `impersonatedUser`, not `user`), so the filter
  does not hide an adversary who impersonates the loopback client. This rule keeps
  K17's current state — documented in `falsepositives`, not filtered — so the two
  rules move together. When K17's filter lands, add the same filter here with a
  filtered case (`system:aggregate-to-edit` written by `system:apiserver`). Elastic's
  sensitive-role rule instead excludes the bootstrap writer by loopback source IP
  (`not kubernetes.audit.sourceIPs in ("::1", "127.0.0.1")`); either is available.
  The negative control is unaffected either way: it gates on `trr9004-` names, so a
  Sigma filter on this rule changes nothing there (the point about not dropping the
  baseline writes belongs to the audit policy, not the rule).
- **Evidence**: *probe* — `sigma_eval.py` on the current rule:
  `system:aggregate-to-edit`, `system:node` and `system:kube-controller-manager`
  written by `system:apiserver` all fire; `edit` (an `aggregationRule` and no
  `rules`) and `system:aggregate-to-view` (read-only) do not. *source* — kubernetes
  v1.36.4 `plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go` (`editRules`
  at `system:aggregate-to-edit`, `edit` with `AggregationRule` only, `NodeRules`,
  `system:kube-controller-manager`); `staging/src/k8s.io/apiserver/pkg/audit/context.go`
  `LogImpersonatedUser` (sets only `ImpersonatedUser`).
- **Fix**: none applied in Sigma while K17 is open (baseline the actor, as K17 does).
  When K17's `user.username: system:apiserver` filter lands, add it here too, with a
  filtered case; Elastic's loopback source-IP exclusion is the alternative.
- **Then**: a new filtered case (`system:aggregate-to-edit` written by
  `system:apiserver`) holds, and a positive for the same role written by another user
  still fires. The rule's live shadow count drops by the bootstrap writes.

### K27. k8s_rbac_sensitive_permission_grant: residual blind spots

- **Rule**: [`sigma/T1098.006/k8s_rbac_sensitive_permission_grant.yml`](sigma/T1098.006/k8s_rbac_sensitive_permission_grant.yml) (level medium).
- **Kind**: false negative. **Severity**: low.
- **Problem**: four residuals.
  1. A JSON patch (`kubectl patch --type=json`) logs `requestObject` as the list of
     operations, so `requestObject.rules` does not exist and the rule does not read
     the operation list. A JSON patch that appends an exec, token or secret-read
     rule is seen by the chokepoint (`k8s_rbac_write`) only. (The high
     privileged-grant rule reads the operation list; this medium rule does not, to
     keep it simple.) This also means the rule does not grade Procedure E's emulated
     form, which is a JSON patch; it grades a create, update, or merge/strategic/apply
     patch.
  2. `pods/ephemeralcontainers` (update/patch — the `kubectl debug` path, another
     way to run code in a pod) is not graded by this rule or by the high
     `k8s_rbac_privileged_grant`. A grant of it is seen by the chokepoint only. It
     could be added to the exec clause with a positive and a near-miss if the
     coverage is judged worth the extra surface at this severity.
  3. `resourceNames` is not graded: a rule that grants `pods/exec` or
     `serviceaccounts/token` but is limited by `resourceNames` to named objects is
     narrower than the match suggests, and still fires (documented in
     `falsepositives`).
  4. A RoleBinding or ClusterRoleBinding to an *existing* sensitive role is not
     graded here. The binding rules do not grade it either, except for the three
     built-in names: `k8s_rbac_privileged_grant`'s roleRef clause grades only
     `cluster-admin`, `admin` and `edit`. A bind to a custom secrets reader,
     `system:node` or `system:kube-controller-manager` is seen only by the
     `k8s_rbac_write` chokepoint. This rule grades the role *write*, not the bind.
- **Evidence**: *probe* — `sigma_eval.py`: a JSON patch
  `[{"op":"add","path":"/rules/-","value":{...pods/exec...}}]` does not fire; a Role
  that grants `pods/ephemeralcontainers` update/patch does not fire on either rule; a
  ClusterRole with `pods/exec` and a `resourceNames` list does fire; a
  ClusterRoleBinding (no `requestObject.rules`) does not fire.
- **Fix**: for (1) and (2), add `requestObject|re` branches (a JSON-patch branch
  modelled on `k8s_rbac_privileged_grant`; an `ephemeralcontainers` branch) with
  positives and near-misses, if the coverage proves worth the complexity at this
  severity. (3) and (4) are by design.
- **Then**: for (1), a JSON-patch positive that appends a `pods/exec` rule fires, and its
  near-miss (the same operation on a resource that is not sensitive) holds. For (2), a
  positive that grants `pods/ephemeralcontainers` update fires, and its near-miss (a
  read verb only) holds.

### K28. k8s_eks_aws_auth_configmap_modified: a denied create names no object

- **Rule**: [`sigma/T1098.006/k8s_eks_aws_auth_configmap_modified.yml`](sigma/T1098.006/k8s_eks_aws_auth_configmap_modified.yml) (level medium).
- **Kind**: false negative. **Severity**: low.
- **Problem**: a create (a POST to the collection) that authorization *denies* (403)
  never reaches the create handler, so `audit.LogRequestObject` never runs and the
  record has no `objectRef.name`. The rule keys on `objectRef.name: aws-auth`, so a
  denied create cannot be tied to aws-auth and does not fire. A denied *update*,
  *patch* or *delete* carries the name from the URL, so those fire on any outcome. (A
  second residual, a server-side apply with a YAML body, which leaves no record, is
  not specific to this rule: see [K23](#k23-apply-patches-with-a-yaml-body-no-audit-record-at-request-level-or-higher).)
- **Evidence**: *probe* — `sigma_eval.py`: a create record with
  `objectRef {resource: configmaps, namespace: kube-system}`, no name, code 403 gives
  0 hits; the same record with `objectRef.name: aws-auth` and code 201 gives 1 hit.
  *source* — kubernetes v1.36.4
  `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go` (`LogRequestObject`
  inside the handler, after the authorization filter).
- **Fix**: none: the denied-create case is by design (the record lacks the identity to
  key on). It is documented, not fixed in Sigma. For the YAML-bodied apply, K23 names
  the operator signal (the audit-error metric and log line).

### K29. T1685 enforcer-removal rules: a DaemonSet unscheduled by its pod template

- **Rules**: [`sigma/T1685/k8s_enforcer_workload_removed.yml`](sigma/T1685/k8s_enforcer_workload_removed.yml) (level high),
  [`sigma/T1685/k8s_security_tool_workload_removed.yml`](sigma/T1685/k8s_security_tool_workload_removed.yml) (level low).
- **Kind**: false negative. **Severity**: medium (Falco, the runtime sensor that the
  high rule names, runs as a DaemonSet, and one patch removes every Falco pod; a
  delete of the DaemonSet or of its namespace still fires).
- **Problem**: a DaemonSet has no replica count, so neither rule has a scale-to-zero
  shape for it. A patch or update that gives the DaemonSet's pod template a
  nodeSelector, a required node affinity or a nodeName that no node matches makes the
  DaemonSet controller delete the daemon pod on every node. No branch of either rule
  reads the pod template's scheduling fields.
- **Evidence**: *probe* — a patch of `daemonsets/falco` in namespace `falco` (Request
  level, code 200) with requestObject
  `{"spec":{"template":{"spec":{"nodeSelector":{"example.com/none":"true"}}}}}` fires
  neither rule; the sidecar confounders `daemonset-nodeselector-matches-no-node-known-miss`
  (high rule) and `anchor-daemonset-nodeselector-matches-no-node-known-miss` (anchor)
  hold that record. *source* — Kubernetes v1.36.4
  `pkg/controller/daemon/daemon_controller.go`: `NodeShouldRunDaemonPod` returns false
  when the template's node affinity or nodeSelector does not fit the node, and
  `podsShouldBeOnNode` then deletes the daemon pods on that node.
- **Fix**: in the high rule, a branch for an accepted update or patch of daemonsets in
  the enforcer namespaces whose requestObject sets `spec.template.spec.nodeSelector`,
  `spec.template.spec.affinity` or `spec.template.spec.nodeName` (a merge-patch or
  update body, or JSON-patch text on those paths). A Helm or GitOps upgrade that
  writes the chart's own nodeSelector writes the same fields, so the branch needs a
  benign budget, which a human approves.
- **Then**: the two KNOWN MISS confounders become positives (a relabel, which
  `sufficiency-ratchet` sends to a human), with near-misses in another namespace.

### K32. T1685 enforcer-removal rules: a null strategic merge directive next to a count

- **Rules**: [`sigma/T1685/k8s_enforcer_workload_removed.yml`](sigma/T1685/k8s_enforcer_workload_removed.yml) (level high),
  [`sigma/T1685/k8s_security_tool_workload_removed.yml`](sigma/T1685/k8s_security_tool_workload_removed.yml) (level low).
- **Kind**: false negative. **Severity**: low (a hand-written strategic merge patch
  of the scale subresource that no client sends; the result depends on Go map order,
  so it can need a second try; `kubectl scale --replicas=0` and the other
  scale-to-zero shapes fire).
- **Problem**: a strategic merge patch of deployments/scale holds `spec.replicas`
  above 0 and also the key `$deleteFromPrimitiveList/replicas` in spec (or
  `$deleteFromPrimitiveList/spec` at the root) with the value null. The merge uses
  that key as the plain key, and a null deletes the count. The merge reads the keys
  in Go map order, so in most runs the delete comes after the count, and the Scale
  decodes to 0. The rules match the same keys with a non-null value
  (`sel_smp_directive`). A null value is not a field in the flattened record, and a
  log store reads a null field as absent, so the record looks like a scale to 3, and
  `filter_scale_patch_positive` removes it. A null child of a root
  `$deleteFromPrimitiveList/spec` (`{"replicas": null}`) is the same gap. On the
  deployments resource the same null resets the count to its default of 1, so only
  the scale subresource is affected.
- **Evidence**: *probe* — a patch of `deployments/scale` in namespace `kyverno`
  (Request level, code 200) with requestObject
  `{"spec":{"replicas":3,"$deleteFromPrimitiveList/replicas":null}}` fires neither
  rule; the sidecar confounders `scale-smp-null-alias-with-count-known-miss` (high
  rule) and `anchor-scale-smp-null-alias-with-count-known-miss` (anchor) hold that
  record. *source* — Kubernetes v1.36.4
  `staging/src/k8s.io/apimachinery/pkg/util/strategicpatch/patch.go`: `mergeMap`
  maps a `$deleteFromPrimitiveList/` key to the plain key
  (`preprocessDeletionListForMerging`) and deletes the key on a null value. Go
  reproduction against `k8s.io/apimachinery@v0.36.4` and `k8s.io/api@v0.36.4` (the code
  of `strategicPatchObject`): replicas 0 in 39 of 40 runs, with no error.
- **Fix**: log deployments/scale (and statefulsets/scale, replicasets/scale) at
  RequestResponse in `detections/k8s/audit-policy-apiserver.yaml`, and add a branch
  for an accepted patch or update of the scale subresource whose responseObject is
  a Scale without `spec.replicas` (the result, which the request body cannot show).
  The policy change adds log volume, which a human approves.
- **Then**: the two KNOWN MISS confounders become positives (a relabel, which
  `sufficiency-ratchet` sends to a human).

### K33. JSON-text skip grammars: a key nested three levels deep splits an operation

- **Rules**: [`sigma/T1685/k8s_enforcer_workload_removed.yml`](sigma/T1685/k8s_enforcer_workload_removed.yml) (level high),
  [`sigma/T1685/k8s_security_tool_workload_removed.yml`](sigma/T1685/k8s_security_tool_workload_removed.yml) (level low),
  [`sigma/T1685/k8s_admission_webhook_neutered.yml`](sigma/T1685/k8s_admission_webhook_neutered.yml) (level high; its fail-open and rules-cleared JSON-patch branches),
  [`sigma/T1611/k8s_podspec_controller_host_access.yml`](sigma/T1611/k8s_podspec_controller_host_access.yml) (level high),
  [`sigma/T1611/k8s_podspec_host_access.yml`](sigma/T1611/k8s_podspec_host_access.yml) (level high),
  [`sigma/T1611/k8s_podspec_confinement_disabled.yml`](sigma/T1611/k8s_podspec_confinement_disabled.yml) (level medium).
- **Kind**: false negative. **Severity**: low (only a raw client or a hand-written patch
  adds an ignored key; the operations that kubectl and controllers send are graded).
- **Problem**: these rules read a JSON-patch operation, or a seccomp or AppArmor profile
  object in a request body, as JSON text with `|re`. Between two keys of one operation
  (or of one profile object), the match skips whole JSON strings and nested objects up
  to two levels deep. The API server ignores an unknown operation key, and drops an
  unknown profile key at the default `fieldValidation=Warn`, so an extra key does not
  change what the write does. Two shapes split the operation (or the profile), and the
  rule does not read its path and value together:
  1. an extra key whose value nests objects three levels deep;
  2. an extra key whose value is an object that holds a string with a brace (inside a
     nested object the grammar skips any text but a brace).
  The grammar stops at two levels to keep each value inside Lucene's default
  determinization budget (10,000 states): reading strings inside nested objects took
  the T1685 value from about 3,800 to about 15,000 states. The neuter grader used a
  weaker grammar until this entry was extended: its op match skipped no nested object,
  so an extra key with any object value, even `{}`, split the op. It now uses the same
  grammar, one value per key order (the largest is about 4,100 states).
- **Evidence**: *case* — KNOWN MISS confounders
  `jsonpatch-scale-zero-gatekeeper-deep-nested-key-known-miss` and
  `jsonpatch-scale-zero-gatekeeper-brace-string-in-nested-key-known-miss` (enforcer
  rule), `anchor-jsonpatch-scale-zero-deep-nested-key-known-miss` and
  `anchor-jsonpatch-scale-zero-brace-string-in-nested-key-known-miss` (anchor),
  `patch-deployment-hostpid-leaf-deep-nested-key-not-graded` (controller host-access
  rule), `ephemeral-privileged-leaf-deep-nested-key-known-miss` (pod host-access rule),
  `deployment-container-seccomp-deep-nested-key-before-type-not-graded` (confinement
  rule), `jsonpatch-fail-open-deep-nested-key-known-miss` and
  `jsonpatch-fail-open-brace-string-in-nested-key-known-miss` (neuter grader). The
  two-level form fires (positives `jsonpatch-scale-zero-extra-object-key`,
  `patch-deployment-hostpid-leaf-extra-object-key-jsonpatch`,
  `ephemeral-privileged-leaf-extra-key-jsonpatch`,
  `deployment-container-seccomp-extra-object-key-before-type-smp`,
  `jsonpatch-fail-open-extra-object-key` and
  `jsonpatch-remove-rules-extra-empty-object-key`). The neuter grader's extra-key
  positives miss on the grader at commit `23693e5` (*probe*). *source* —
  `github.com/evanphx/json-patch` v4.13.0 (an `Operation` is a map of raw values; keys
  other than `op`, `path`, `from` and `value` are not read). The anchor rule's
  description gives the limit, and the enforcer rule points to it; the T1611 rules'
  and the neuter grader's comments give it too.
- **Fix**: none planned in Sigma: a deeper skip leaves Lucene's budget. A log pipeline
  that decodes the operation list (or the profile object) into fields would remove the
  gap, with a rule on those fields.
- **Then**: the KNOWN MISS confounders fire; relabelling them as positives is a human
  decision under the sufficiency ratchet.

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
| K15 | `T1609/k8s_node_proxy_exec` fires on a `nodes/proxy` request whose requestURI path (anything before `?`) holds a percent-encoded byte or a `..` segment, whatever endpoint it seems to name, also when the encoding is in the `/api/v1/nodes/<n>/proxy/` prefix | positives `node-proxy-exec-dot-segment-after-containerlogs`, `node-proxy-exec-percent-encoded-endpoint`, `node-proxy-exec-percent-encoded-prefix-and-endpoint`; near-miss `node-proxy-containerlogs-encoded-query-only` (not verified live) |
| K18 | both `T1611` host-access rules grade a JSON patch (`kubectl patch --type=json`, whose `requestObject` is the operation list) through `requestObject\|re` branches: an op at the pod template, an ephemeral-container path or the document root (`""`) with a dangerous field in its value; a leaf op whose path's last segment is the dangerous field, in either key order and with ignored extra keys between the keys (the T1685 skip grammar); and a copy or move into such a path. A list index in a path (`capabilities/add/<index>`) is any JSON-pointer token, because the API server's JSON patch library reads `+0`, `-0` and `-1` as indexes. The new `T1611/k8s_podspec_confinement_disabled` grades JSON patches the same way | controller: positives `patch-deployment-privileged-jsonpatch-leaf`, `patch-deployment-add-securitycontext-privileged-jsonpatch-value`, `patch-daemonset-hostnetwork-value-jsonpatch`, `patch-deployment-hostpath-leaf-jsonpatch`, `patch-deployment-sys-admin-leaf-jsonpatch`, `patch-deployment-hostpid-leaf-extra-object-key-jsonpatch`, `patch-deployment-root-replace-privileged-jsonpatch`, `patch-deployment-copy-into-hostpid-jsonpatch` and one for each other `\|re` value; pod: positives `ephemeral-privileged-jsonpatch-value`, `ephemeral-sys-ptrace-jsonpatch-leaf`, `ephemeral-sys-admin-caps-value-jsonpatch`, `ephemeral-privileged-leaf-extra-key-jsonpatch`, `ephemeral-root-replace-privileged-jsonpatch`, `ephemeral-copy-into-privileged-jsonpatch` and one for each other `\|re` value; the index tokens: `patch-deployment-sys-admin-leaf-index-plus-zero-jsonpatch`, `patch-deployment-sys-admin-leaf-negative-index-value-first-jsonpatch`, `patch-deployment-copy-into-caps-index-minus-zero-jsonpatch` (controller), `ephemeral-sys-admin-leaf-index-plus-zero-jsonpatch`, `ephemeral-sys-admin-leaf-negative-index-value-first-jsonpatch`, `ephemeral-move-into-caps-index-plus-zero-jsonpatch` (pod); a near-miss for every `sel_jp_*` item of both rules; proven live by validate-apiserver run 39448010277 at commit `c9d2074` (MANIFEST rows `9007 K18 ctrl`, `9007 K18 eph` and `9007 E jp`) |
| K19 | `T1685/k8s_security_tool_workload_removed` retitled as a generic Deployment or DaemonSet anchor (its title claimed security tools only); matches only accepted (200/201/202) writes and filters the dry runs the record shows (the `?dryRun=All` query of an update or patch; the DeleteOptions body of a delete at Request level) | near-misses `delete-deployment-forbidden`, `delete-deployment-not-found`; filtered `delete-deployment-dry-run-body`, `scale-to-zero-patch-dry-run-query`, `kubectl-scale-zero-dry-run` |
| K20 | `T1134/k8s_impersonation` matches the v1.36 constrained-impersonation refusals (`cannot impersonate:<mode>`, `cannot impersonate-on:<mode>:<verb>`), not only the legacy `cannot impersonate resource` | positives `denied-serviceaccount-impersonation-probe-constrained`, `denied-user-impersonation-probe-constrained`, `constrained-impersonation-username-check-denied` |
| K21 | both TRR9025 create rules (`k8s_admission_webhook_created`, `k8s_malicious_admission_webhook_created`) match `verb: create` OR (`verb: patch` AND `responseStatus.code: 201`), so a server-side-apply install (a patch answered 201) fires both. A 201 patch is a patch, so it also fires the TRR9008 chokepoint (an expected double alert), and the TRR9008 neuter grader filters it (`filter_ssa_install`); a refused server-side-apply install (a patch answered 4xx) fires only the TRR9008 chokepoint. The chokepoint's CHOKEPOINT waiver digest was re-approved. `check_sufficiency.py` now reports that waiver as stale (an R2 warning), because the SSA branch has a discriminating item (`select_adm_ssa_create.responseStatus.code`); removing the waiver is a maintainer decision | positives `ssa-create-webhook-patch-201` (chokepoint) and `ssa-create-offcluster-url-patch-201` (grader); near-misses `ssa-create-patch-answered-200-not-create` and `repoint-offcluster-url-patch-answered-200` (a patch answered 200 is a modify, not a create); filtered `ssa-install-fail-open-webhook-201` (neuter grader); proven live by validate-apiserver run 39448010277 at commit `c9d2074` (MANIFEST rows `9025 ssa-create` and `9025 sev ssa-create`) |
| K30 | `T1685/k8s_security_tool_workload_removed` (and the new `T1685/k8s_enforcer_workload_removed`) match the scale-to-zero shapes that the anchor missed: an update (PUT) of deployments/scale whose re-encoded autoscaling/v1 Scale omits `spec.replicas` 0 (`kubectl scale --current-replicas`/`--resource-version`); a patch of the scale subresource that sets no count above 0 (a merge or strategic `null`, a JSON-patch `remove`, a replace of `/spec`); a JSON-patch value `-0`; a JSON patch that replaces `/spec` with a spec that holds replicas 0; a strategic merge patch whose count is outside the int32 range (the merge truncates 2^32 to 0); a strategic merge directive that drops or sets the count (`"$patch": "delete"` in spec, a non-null `$deleteFromPrimitiveList/replicas` in spec or `$deleteFromPrimitiveList/spec` at the root; the null form is K32) | positives `deployment-smp-replicas-two-to-the-32`, `scale-smp-replicas-two-to-the-32`, `deployment-smp-replicas-minus-two-to-the-32`, `scale-smp-spec-patch-delete-with-count`, `deployment-smp-delete-from-primitive-list-replicas`, `deployment-smp-delete-from-primitive-list-spec`, `deployment-smp-nested-delete-from-primitive-list-alias`, `scale-smp-delete-from-primitive-list-replicas-with-count`, `scale-smp-root-alias-patch-delete-with-count`, `scale-smp-root-alias-retain-keys-with-count` (high rule) and their `anchor-` twins; near-misses `deployment-smp-replicas-three`, `deployment-smp-replicas-two-to-the-32-forbidden`, `deployment-smp-replicas-two-to-the-32-monitoring`, `scale-smp-spec-patch-replace-with-count`, `deployment-smp-delete-from-primitive-list-finalizers`; filtered `deployment-smp-delete-from-primitive-list-replicas-dry-run`; positives `kubectl-scale-zero-update-omitted-replicas`, `anchor-scale-merge-patch-replicas-null`, `anchor-scale-jsonpatch-remove-replicas`, `anchor-scale-jsonpatch-set-count-then-remove`, `anchor-deployment-jsonpatch-replace-spec-replicas-zero`, `anchor-deployment-jsonpatch-value-minus-zero-raw-text`; near-misses `hpa-scale-update-to-three`, `scale-update-metadata-level-no-body`, `anchor-scale-patch-metadata-level-no-body`, `anchor-deployment-merge-patch-replicas-null-defaults-to-one`, `anchor-deployment-jsonpatch-replace-spec-replicas-two`; filtered `kubectl-scale-zero-update-dry-run`, `anchor-kubectl-scale-to-two`, `anchor-scale-jsonpatch-replace-to-three`; proven live by validate-apiserver run 39448010277 at commit `c9d2074` (MANIFEST rows `9008 D2 put` and `9008 D put`) |
| K31 | `T1685/k8s_security_tool_workload_removed` (and `T1685/k8s_enforcer_workload_removed`) filter a write of a status subresource: the deployment controller's update of deployments/status carries the whole Deployment, with `spec.replicas` 0 after a scale to zero, and fired the rule under a policy that logs every apps subresource at Request | filtered `anchor-deployment-controller-status-update-zero-replicas` (anchor), `deployment-controller-status-update-zero-replicas` (high rule) |
| C13 | `entra_app_federated_credential_backdoor` reads only `newValue`, in any key order | near-misses `fic-with-unapproved-issuer-removed`, `fic-repointed-away-new-value-first` and the other reordered cases |
| C14 | `aws_resource_policy_made_public` reads a `Statement` that is one object | positives `s3-single-statement-object-public-read`, `sqs-single-statement-object-public-send`, `efs-single-statement-object-public-mount` |
| C16 | `aws_github_oidc_role_trust_abuse` grades each `sub` value | near-miss `two-subs-pinned-ref-wildcards-grade-high`; positive `two-subs-pinned-ref-wildcards-go-to-high-rule` of the low rule |
| S1 | every `\|re` value fits Lucene's default `max_determinized_states` (10000) | a Lucene 10.1 `RegExp` build over all 236 values wrapped in `.*`: largest 7,986 states (the CoreDNS JSON-patch root grammar). Recount on 2026-10-20 (Kubernetes coverage wave 2): 321 values, all fit; with case folding (`ASCII_CASE_INSENSITIVE`) the largest is 8,094 states (the JSON-patch capability grammar of `T1611/k8s_podspec_controller_host_access`), and without it 7,986 (the CoreDNS root grammar) |

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
