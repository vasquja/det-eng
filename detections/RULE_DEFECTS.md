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
| [KTBD-C1](#ktbd-c1-k8s_admission_webhook_repointed_to_url-a-service-to-service-repoint-or-a-json-patch-copymove) | `T1546/k8s_admission_webhook_repointed_to_url` | a repoint to another in-cluster Service, or a JSON-patch copy/move, carries no URL | false negative | low |
| [KTBD-C2](#ktbd-c2-admission-object-apply-patches-with-a-yaml-body-no-audit-record) | `T1546/k8s_admission_webhook_repointed_to_url`, `k8s_admission_webhook_created`, `k8s_malicious_admission_webhook_created`, `T1685/k8s_admission_webhook_disabled` | an apply patch with a YAML body is dropped from the audit log at Request level or higher | policy gap | medium |
| [KTBD-D1](#ktbd-d1-k8s_podspec_confinement_disabled-per-container-annotations-keyed-by-container-name) | `T1611/k8s_podspec_confinement_disabled` | a per-container seccomp/AppArmor annotation in a pod or controller body written outside `kubectl apply` is keyed by container name and not graded (a JSON patch is graded) | false negative | low |
| [KTBD-D2](#ktbd-d2-k8s_podspec_confinement_disabled-selinux-type-outside-the-baseline-list) | `T1611/k8s_podspec_confinement_disabled` | SELinux `seLinuxOptions.type` set to `spc_t` (or another type off the Baseline list) also removes confinement and is not graded | false negative | low |
| [KTBD-E1](#ktbd-e1-k8s_rbac_sensitive_permission_grant-the-bootstrap-roles-fire) | `T1098.006/k8s_rbac_sensitive_permission_grant` | the built-in roles the API server writes at bootstrap (system:aggregate-to-edit, system:node, system:kube-controller-manager) fire | false positive | low |
| [KTBD-E2](#ktbd-e2-k8s_rbac_sensitive_permission_grant-residual-blind-spots) | `T1098.006/k8s_rbac_sensitive_permission_grant` | a JSON-patch operation list is not read; pods/ephemeralcontainers and resourceNames are not graded; a bind to an existing sensitive role is not graded here | false negative | low |
| [KTBD-E3](#ktbd-e3-k8s_eks_aws_auth_configmap_modified-chokepoint-residuals) | `T1098.006/k8s_eks_aws_auth_configmap_modified` | a denied create logs no objectRef.name; a server-side apply with a YAML body is dropped by the JSON audit backend | false negative | low |
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

### KTBD-D1. k8s_podspec_confinement_disabled: per-container annotations keyed by container name

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

### KTBD-D2. k8s_podspec_confinement_disabled: SELinux type outside the Baseline list

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

### KTBD-E1. k8s_rbac_sensitive_permission_grant: the bootstrap roles fire

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

### KTBD-E2. k8s_rbac_sensitive_permission_grant: residual blind spots

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

### KTBD-E3. k8s_eks_aws_auth_configmap_modified: chokepoint residuals

- **Rule**: [`sigma/T1098.006/k8s_eks_aws_auth_configmap_modified.yml`](sigma/T1098.006/k8s_eks_aws_auth_configmap_modified.yml) (level medium).
- **Kind**: false negative. **Severity**: low.
- **Problem**: two residuals.
  1. A create (a POST to the collection) that authorization *denies* (403) never
     reaches the create handler, so `audit.LogRequestObject` never runs and the
     record has no `objectRef.name`. The rule keys on `objectRef.name: aws-auth`, so
     a denied create cannot be tied to aws-auth and does not fire. A denied *update*,
     *patch* or *delete* carries the name from the URL, so those fire on any outcome.
  2. A server-side apply sent with a YAML body (`Content-Type:
     application/apply-patch+yaml`) is stored by `audit.LogRequestPatch` as the raw
     bytes labelled `ContentType: application/json`; at `Request`/`RequestResponse`
     level the JSON log backend then fails to encode the event (the raw YAML is not
     valid JSON) and drops the whole audit line, so that write leaves no record. This
     is an upstream audit-pipeline limitation, not specific to this rule or to
     aws-auth (it affects every `Request`+ level policy rule, and EKS's own policy
     logs aws-auth the same way). `kubectl apply --server-side` sends a JSON body and
     is not affected; only a client that sends raw YAML is. Do not lower the audit
     level to avoid it: the validator's sentinel gate needs the body.
- **Evidence**: *probe* — `sigma_eval.py`: a create record with
  `objectRef {resource: configmaps, namespace: kube-system}`, no name, code 403 gives
  0 hits; the same record with `objectRef.name: aws-auth` and code 201 gives 1 hit.
  *source* — kubernetes v1.36.4
  `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go` (`LogRequestObject`
  inside the handler, after the authorization filter) and `.../handlers/patch.go`
  (`LogRequestPatch` before the apply-YAML branch),
  `.../pkg/audit/context.go` (`RequestObject = Unknown{Raw, ContentType: json}`),
  `.../plugin/pkg/audit/log/backend.go` (`runtime.Encode` error ->
  `HandlePluginError`, no line written). A Go reproduction of the encode path shows a
  YAML body labelled JSON fails `json.Marshal` ("invalid character ... looking for
  beginning of value").
- **Fix**: pair the rule with an API server audit-error metric or log monitor as the
  backstop for the dropped-event case; the denied-create case is by design (the
  record simply lacks the identity to key on). Both are documented, not fixed in Sigma.

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
| K18 | both `T1611` host-access rules grade a JSON patch (`kubectl patch --type=json`, whose `requestObject` is the operation list) through `requestObject\|re` branches: an op at the pod template, an ephemeral-container path or the document root (`""`) with a dangerous field in its value; a leaf op whose path's last segment is the dangerous field, in either key order and with ignored extra keys between the keys (the T1685 skip grammar); and a copy or move into such a path. The new `T1611/k8s_podspec_confinement_disabled` grades JSON patches the same way | controller: positives `patch-deployment-privileged-jsonpatch-leaf`, `patch-deployment-add-securitycontext-privileged-jsonpatch-value`, `patch-daemonset-hostnetwork-value-jsonpatch`, `patch-deployment-hostpath-leaf-jsonpatch`, `patch-deployment-sys-admin-leaf-jsonpatch`, `patch-deployment-hostpid-leaf-extra-object-key-jsonpatch`, `patch-deployment-root-replace-privileged-jsonpatch`, `patch-deployment-copy-into-hostpid-jsonpatch` and one for each other `\|re` value; pod: positives `ephemeral-privileged-jsonpatch-value`, `ephemeral-sys-ptrace-jsonpatch-leaf`, `ephemeral-sys-admin-caps-value-jsonpatch`, `ephemeral-privileged-leaf-extra-key-jsonpatch`, `ephemeral-root-replace-privileged-jsonpatch`, `ephemeral-copy-into-privileged-jsonpatch` and one for each other `\|re` value; a near-miss for every `sel_jp_*` item of both rules; gated live by the MANIFEST rows `9007 K18 ctrl`, `9007 K18 eph` and `9007 E jp` (validate-apiserver CI on the pull request; not yet run on kind) |
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
