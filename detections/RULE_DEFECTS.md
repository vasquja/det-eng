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
  what the rule does not do), *portability* (the rule is proven under the lab
  policy, but a platform's own audit policy or log category does not record what it
  needs; the platform's published policy decides, and the user often cannot change
  it).
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
  - *simulator*: [`k8s_policy_coverage.py`](k8s_policy_coverage.py) replayed the
    rule's sidecar cases as an audit policy records them (the lab policies and the
    published provider policies in [`k8s/provider-policies/`](k8s/provider-policies/SOURCES.md)),
    through the same backend. Its result is
    [`k8s/policy_coverage.json`](k8s/policy_coverage.json); `python3
    detections/k8s_policy_coverage.py --detail` prints it. A published policy is not a
    capture, so a simulator result is **unverified** on a live cluster;
  - *source*: the upstream source that shows the real behaviour, as the reviewer read
    it. A *Go reproduction against `<module>@<version>`* is a small program, not kept in
    this repository, that ran that module's code; it is source evidence, not a probe.
    Where nothing in this repository recorded the real telemetry, the entry says
    **unverified**.
- **Procedures** (optional) lists the TRR procedures that the defect affects, when it
  is in one branch of a rule. [`coverage_report.py`](../research/tools/coverage_report.py)
  then marks only those procedures of the named rule as "Proven, open defect"; an entry
  without it marks every procedure that the rule proves.
- **Fix** is the proposed change. **Then** says which case or budget changes once the
  fix lands, so the fix is proven, not just claimed.

## Summary

| ID | Rule | Problem | Kind | Severity |
|----|------|---------|------|----------|
| [L14](#l14-exe-and-comm-allowlists-trust-the-binary-not-the-code-in-it) | three Linux rules | allowlisted tools that ordinary users run (kcapi, debuggers) hide injected code | evasion | medium |
| [L15](#l15-linux_static_pod_manifest_write-fires-on-reads-of-the-manifests) | `T1543.005/linux_static_pod_manifest_write` | on an open-capable sensor every read of a manifest by a process outside `filter_install` fires (a tar backup; Ansible's `stat` module, its `file` and `lsattr` children, the `copy` module's checksum read): `selection_dir` has no event-type item | false positive, description | medium |
| [L16](#l16-linux_k8s_sa_token_read-fires-on-every-workload-that-reads-its-own-token) | `T1552.007/linux_k8s_sa_token_read` | every workload's client library re-reads its own token (at most about once a minute, on its next API request after its cached copy expires), and the in-container selection has no reader constraint | false positive, description | high |
| [K4](#k4-k8s_admission_webhook_neutered-neuters-the-audit-record-cannot-show) | `T1685/k8s_admission_webhook_neutered` | selectors on other labels, self-contradicting selectors or conditions, variable-bound constants | false negative | low |
| [K9](#k9-k8s_coredns_corefile_poisoned-what-the-corefile-grader-does-not-grade) | `T1565.001/k8s_coredns_corefile_poisoned` | private non-cluster stub zones, `import`, mid-token CR, `#<TAB>` comments | false negative, false positive | low |
| [K14](#k14-k8s_namespace_deleted-a-query-dry-run-at-metadata-level) | `T1070/k8s_namespace_deleted` | at Metadata level a real delete that carries `?dryRun=All` next to a body is filtered | evasion | medium |
| [K16](#k16-k8s_impersonation-an-impersonation-request-without-a-user-header) | `T1134/k8s_impersonation` | on v1.34 and earlier, `Impersonate-Group`/`-Uid`/`-Extra` without `Impersonate-User` is a 500 with no trace (unverified live) | false negative | low |
| [K17](#k17-k8s_rbac_privileged_grant-the-wildcard-clause-fires-on-bootstrap-and-read-only-roles) | `T1098.006/k8s_rbac_privileged_grant` | the `"*"` clause fires on the bootstrap controller roles and on read-only wildcard roles; other bootstrap roles that `system:apiserver` writes fire through `impersonate` or `"*"` | false positive | low |
| [K22](#k22-k8s_admission_webhook_repointed_to_url-a-service-to-service-repoint-or-a-json-patch-copymove) | `T1546/k8s_admission_webhook_repointed_to_url` | a repoint to another in-cluster Service, or a JSON-patch copy/move, carries no URL | false negative | low |
| [K23](#k23-apply-patches-with-a-yaml-body-no-audit-record-at-request-level-or-higher) | every Kubernetes rule whose records the shipped audit policy logs at Request or higher (RBAC objects, pods, apps and batch workloads and their scale subresources, admission configuration objects, the kube-system DNS and aws-auth ConfigMaps, the OpenShift DNS ConfigMap and DNS Operator objects) | an apply patch with a YAML body is dropped from the audit log at Request level or higher, so no rule sees that write | policy gap | medium |
| [K24](#k24-k8s_podspec_confinement_disabled-per-container-annotations-keyed-by-container-name) | `T1611/k8s_podspec_confinement_disabled` | a per-container seccomp/AppArmor annotation in a pod or controller body written outside `kubectl apply` is keyed by container name and not graded (a JSON patch is graded) | false negative | low |
| [K25](#k25-k8s_podspec_confinement_disabled-selinux-type-outside-the-baseline-list) | `T1611/k8s_podspec_confinement_disabled` | SELinux `seLinuxOptions.type` set to `spc_t` (or another type off the Baseline list) also removes confinement and is not graded | false negative | low |
| [K26](#k26-k8s_rbac_sensitive_permission_grant-the-bootstrap-roles-fire) | `T1098.006/k8s_rbac_sensitive_permission_grant` | the built-in roles the API server writes at bootstrap (system:aggregate-to-edit, system:node, system:kube-controller-manager) fire | false positive | low |
| [K27](#k27-k8s_rbac_sensitive_permission_grant-residual-blind-spots) | `T1098.006/k8s_rbac_sensitive_permission_grant` | a JSON-patch operation list is not read; pods/ephemeralcontainers and resourceNames are not graded; a bind to an existing sensitive role is not graded here | false negative | low |
| [K28](#k28-k8s_eks_aws_auth_configmap_modified-a-denied-create-names-no-object) | `T1098.006/k8s_eks_aws_auth_configmap_modified` | a denied create logs no objectRef.name (a YAML-bodied server-side apply: see K23) | false negative | low |
| [K29](#k29-t1685-enforcer-removal-rules-a-daemonset-unscheduled-by-its-pod-template) | `T1685/k8s_enforcer_workload_removed`, `k8s_security_tool_workload_removed` | a DaemonSet (Falco) whose pod template gets a nodeSelector, affinity or nodeName that no node matches loses every pod, and neither rule fires | false negative | medium |
| [K32](#k32-t1685-enforcer-removal-rules-a-null-strategic-merge-directive-next-to-a-count) | `T1685/k8s_enforcer_workload_removed`, `k8s_security_tool_workload_removed` | a strategic merge patch of deployments/scale with a count above 0 and a null `$deleteFromPrimitiveList/replicas` (or `/spec`) scales to 0, and neither rule fires | false negative | low |
| [K33](#k33-json-text-skip-grammars-a-key-nested-three-levels-deep-splits-an-operation) | `T1685/k8s_enforcer_workload_removed`, `k8s_security_tool_workload_removed`, `k8s_admission_webhook_neutered`, `T1611/k8s_podspec_controller_host_access`, `k8s_podspec_host_access`, `k8s_podspec_confinement_disabled` | an ignored key nested three levels deep, or a brace string inside a nested object, splits a JSON-patch operation or a profile object, so it is not graded (Lucene's budget) | false negative | low |
| [K34](#k34-k8s_podspec_host_access-a-default-kubectl-debug-from-kubectl-v136-adds-sys_ptrace) | `T1611/k8s_podspec_host_access` | from kubectl v1.36 (the CI pin), a default `kubectl debug` adds SYS_PTRACE to its debug container, in an ephemeral container (a `pods/ephemeralcontainers` patch) and in a `--copy-to` pod copy (a `pods` create), and fires this level-high rule where that write is logged at Request | false positive, description | medium |
| [K35](#k35-api-server-lab-policy-mutatingadmissionpolicy-deletes-at-metadata-hide-a-dry-run) | the API server lab policy (`k8s/audit-policy-apiserver.yaml`), for the delete dry-run filter of the T1685 webhook-disabled rule | the lab logs MutatingAdmissionPolicy and binding deletes at Metadata, so a server-side dry-run delete of one fires that rule (its delete dry-run filter needs the body) | policy gap | low |
| [K36](#k36-delete-dry-run-filters-read-only-the-body-a-query-only-dry-run-fires) | `T1070/k8s_events_deleted`, `k8s_workload_deleted_evidence`, `T1685/k8s_admission_webhook_disabled`, `k8s_enforcer_workload_removed`, `k8s_security_tool_workload_removed` | a delete or deletecollection with no body whose query holds `?dryRun=All` is a server-side dry run, and these rules fire on it: their delete dry-run filter reads only the DeleteOptions body | false positive | low |
| [K37](#k37-namespace-teardown-filters-trust-the-namespace-controllers-name) | `T1070/k8s_events_deleted`, `k8s_workload_deleted_evidence`, `T1685/k8s_enforcer_workload_removed`, `k8s_security_tool_workload_removed` (the same filter is in two more rules; see the entry) | `filter_namespace_teardown` reads only the identity and the verb, so a deletecollection sent with a token of the namespace controller's service account (for example an Events bulk wipe, TRR9010 B or G) is filtered as teardown in a namespace that nobody deletes | evasion | low |
| [K38](#k38-kubernetes-events-deletes-leave-no-record-on-eks-gce-kube-up-and-openshift-417-and-no-collection-delete-record-on-aks) | the T1070 Events-deleted chokepoint, on EKS, the GCE kube-up policy, OpenShift 4.17 and earlier, and AKS | the platform policy logs core-group Events at None (and AKS drops every Events collection DELETE), so a core Events delete or collection DELETE leaves no record | portability, policy gap | medium |
| [K39](#k39-delete-dry-run-body-filters-have-no-input-where-a-platform-logs-deletes-at-metadata) | the six delete rules with a DeleteOptions dry-run filter (T1070, T1685), on AKS, OpenShift with the Default profile, the k3s starter policy, and the events.k8s.io group on EKS and GCE kube-up | the platform logs the delete at Metadata, so a `kubectl delete --dry-run=server` fires | false positive, portability | low |
| [K40](#k40-body-graders-are-blind-under-the-openshift-default-profile-and-the-k3s-starter-policy) | the request-body graders of TRR9004, TRR9007, TRR9008 and TRR9025, under the OpenShift Default profile and the k3s starter policy | writes are logged at Metadata, so no `requestObject` or `responseObject` exists to grade | portability, policy gap | medium |
| [K41](#k41-k8s_coredns_corefile_poisoned-blind-under-every-published-managed-policy) | the TRR9027 Corefile grader, on EKS, GCE kube-up, AKS, OpenShift with the Default profile and the k3s starter policy | the kube-system/coredns write is logged at Metadata, so the Corefile is not in the record | portability, policy gap | low |
| [K42](#k42-aks-kube-audit-admin-the-category-drops-get-and-list-so-read-shaped-procedures-leave-no-record) | the read-shaped Kubernetes rules (TRR9002, TRR9006, TRR9009, TRR9026), on AKS with the kube-audit-admin category | the category drops every get and list record | portability | medium |
| [K43](#k43-k8s_rbac_privileged_grant-the-aggregation-clause-needs-the-api-servers-key-order) | `T1098.006/k8s_rbac_privileged_grant` | on a store that does not keep the key order of an object (AKS `dynamic` columns, GKE's `Struct` body), the clusterrole-aggregation-controller's write of impersonate on users into admin or edit is filtered: `sel_agg_beyond_builtin` needs the keys of each RBAC rule in Go field order | false negative | low |
| [K45](#k45-k8s_coredns_configmap_modified-the-dns-operator-filter-trusts-the-operators-name) | `T1565.001/k8s_coredns_configmap_modified` | `filter_openshift_dns_operator` reads only the identity and the verb, so a create or a PUT of `openshift-dns/dns-default` or of the DNS Operator object sent with a stolen token of the DNS Operator's service account is filtered (TRR9027 E and F) | evasion | low |
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

### L15. linux_static_pod_manifest_write: fires on reads of the manifests

- **Rule**: [`sigma/T1543.005/linux_static_pod_manifest_write.yml`](sigma/T1543.005/linux_static_pod_manifest_write.yml) (level high).
- **Live gate (C2-7)**: the validate-staticpod job runs an auditd node file-event
  sensor (a `-p wa` watch on the static-pod directory, added before the cluster is
  created), so this rule is match-gated live. `validate_staticpod_detections.py` gates
  it on TRR9003 Procedure A (`/usr/local/bin/trr9003-tee` writing the injected
  manifest) with a `file` log source, and a control requires that it matches none of
  `kubeadm`'s control-plane manifest writes. Its `COMPILE_ONLY` waiver is removed. A
  `-p wa` watch records no reads, so the live log cannot show this defect; it records
  the emulation's cleanup deletes (`rm`, `EventType: delete`), and the rule matches
  them too, from the same missing event-type item (the validator counts them as other
  matches). This defect still stands; the event-type fix below is a human decision.
- **Kind**: false positive, description. **Severity**: medium (routine noise where a
  backup job or configuration management reads the control-plane manifests).
- **Problem**: the description says "a file create or write", and the logsource is
  Sigma's `file_event` category, but `selection_dir` has only the path item
  (`TargetFilename|contains: '/etc/kubernetes/manifests/'`). No item restricts the
  event type. On a sensor that also reports opens for read (Falco, Tetragon, auditd
  `open`/`openat` with PATH records), every process outside `filter_install` that
  reads a manifest fires: an operator's `tar` backup of `/etc/kubernetes`; each
  Ansible `copy` or `template` task on a manifest, also when nothing changes (its
  `stat` module reads the file for a checksum, then runs
  `file --mime-type --mime-encoding` and `lsattr -vd` on it); a scanner; a `cat`. The
  kubelet re-lists the directory every 20 s (`fileCheckFrequency`) and opens each
  manifest; only the `filter_install` Image entry keeps those reads quiet. Ansible's
  `atomic_move` writes (it creates a `.ansible_tmp<random><name>` file in the
  directory, copies the new content into it and renames it over the manifest) are real
  writes: they are the configuration-management noise that the rule's falsepositives
  names, not this defect.

  The root cause is shared with
  [L16](#l16-linux_k8s_sa_token_read-fires-on-every-workload-that-reads-its-own-token):
  the two node rules declare the same logsource (`linux` / `file_event`), but they need
  opposite inputs. This rule must see only writes. `linux_k8s_sa_token_read` must see
  reads (an open of the token), and its description says that a creation-only producer
  makes it blind.
- **Evidence**: *corpus* — slice `linux-k8s-node-file-events` v3 (1501 events). The
  pull request that adds this entry also adds the slice, so these figures are in the
  `benign/scores.json` of that pull request, not in the snapshot at `00216e3`. 103
  hits, 91 of them reads: `/usr/bin/lsattr` x36 (two opens in each of 18 Ansible
  `stat` runs), `/usr/bin/python3.12` x34 (the 18 `stat` checksum reads, and for each
  of 4 changes the `copy` module's checksum read, the temp-file create, the write of
  the new content into the temp file and the rename), `/usr/bin/file` x18 and
  `/usr/bin/tar` x15 (3 backups, each reads the 5 manifests). Of the 430 events under
  `/etc/kubernetes/manifests/`, the kubelet's 307 opens and kubeadm's 20 upgrade reads
  and renames (2 runs) are quiet only through `filter_install`.
  `score_benign.py --examples 1` explains the first hit: `selection_dir` holds on
  `TargetFilename='/etc/kubernetes/manifests/kube-apiserver.yaml'`, and
  `filter_install` does not match `Image='/usr/bin/python3.12'`. Budget 118
  (`--reseeds 10`).
  *probe* — a scratch copy of the rule with a second selection `selection_write:
  EventType: [create, write, rename]` and the condition
  `selection_dir and selection_write and not filter_install` raises 12 hits on the
  slice (the Ansible writes only; 15 over the reseeds), and each of the rule's 8
  sidecar cases keeps its outcome. *source* — Kubernetes v1.36.4
  `pkg/kubelet/config/file.go` (`extractFromDir`: a `Glob` of `[^.]*`, then an
  `os.Open` of each manifest) and the default `fileCheckFrequency` of 20 s
  (`pkg/kubelet/apis/config/v1beta1/defaults.go`); Ansible 2.17.5
  `lib/ansible/plugins/action/__init__.py` `_execute_remote_stat` (the `copy` and
  `template` actions run `stat` on the destination with `get_checksum`, and leave
  `get_mime` and `get_attributes` at their default `true`), `lib/ansible/modules/stat.py`
  (`digest_from_file`, then `file --mime-type --mime-encoding <path>`, then
  `get_file_attributes`: `lsattr -vd <path>`), `lib/ansible/modules/copy.py`
  (`module.sha1(dest)` before `atomic_move`) and `lib/ansible/module_utils/basic.py`
  `atomic_move` (`tempfile.mkstemp(prefix=b'.ansible_tmp', dir=b_dest_dir,
  suffix=b_suffix)` after `os.rename` fails with EXDEV, EPERM, EACCES, ETXTBSY or
  EBUSY, then `shutil.move(b_src, b_tmp_dest_name, copy_function=shutil.copy ...)`
  and `os.rename(b_tmp_dest_name, b_dest)`); CPython 3.12 `Lib/shutil.py` (`move`
  calls the copy function when its own `os.rename` raises `OSError`, as it does across
  file systems, and `copyfile` opens the destination with `open(dst, 'wb')`);
  e2fsprogs 1.47.0 `lib/e2p/fgetflags.c` and `lib/e2p/fgetversion.c` (`lsattr -v`
  opens the file once in each).
- **Fix** (a human decision), one of:
  - *A, an event-type item.* Require a write or create event type where the pipeline
    maps one (Falco `evt.is_open_write`, an auditd watch with `-p wa`, or an
    `EventType` field as in the sidecar cases). An event-type field is not part of
    Sigma's `file_event` taxonomy, and a creation-only producer that has no such field
    never matches an item on it. So put the item in a processing-pipeline step that
    applies to this rule only, or in one rule variant for each sensor. Option A works
    for both node rules on one event stream: this rule keeps only the writes, and the
    token rule still gets the reads.
  - *B, creation-only input.* State in the rule that it must get creation-only events
    (Sysmon for Linux FileCreate). A pipeline that feeds `linux` / `file_event` from
    such a producer gives `linux_k8s_sa_token_read` no reads, so that rule is blind
    ([L16](#l16-linux_k8s_sa_token_read-fires-on-every-workload-that-reads-its-own-token)).
    Option B therefore also needs the token rule on its own logsource (for example
    Sigma's `file_access` category, with its own benign slice), or a pipeline that
    sends the reads only to the token rule.
- **Then**: with the item in the rule (the probe's variant), a new near-miss case,
  `tar` opening `/etc/kubernetes/manifests/kube-apiserver.yaml` with `EventType: open`
  and `breaks: [selection_write.EventType]`, stays quiet; the positives keep firing;
  the budget drops to the Ansible writes (15 over the reseeds of slice v3). A scratch
  run of that variant with that case passes `rule_cases.py` and the sufficiency
  ratchet, and clears this rule's R5 "thin" warning. This also closes the
  `linux_static_pod_manifest_write` item under [Checks to add](#checks-to-add); remove
  it in the same pull request. The rule edit is checked by the sufficiency ratchet and
  by the TRR9003 A file gate and its `kubeadm` control (no waiver digest covers this
  rule). With the item in the pipeline, a case cannot name it in `breaks` (R3 fails a
  `breaks` that names no condition atom), so prove that fix with a pipeline test
  instead.

### L16. linux_k8s_sa_token_read: fires on every workload that reads its own token

- **Rule**: [`sigma/T1552.007/linux_k8s_sa_token_read.yml`](sigma/T1552.007/linux_k8s_sa_token_read.yml) (level high).
- **Live gate (C2-7)**: the validate-apiserver job runs an auditd node file-event
  sensor (a per-file read watch on one projected token file of the node's kube-proxy
  pod, added through `/proc/<node pid>/root`), so this rule is match-gated live.
  `validate_apiserver_detections.py` gates it on TRR9006 Procedure E
  (`/usr/local/bin/trr9006-reader` reading that token file off the node) with a `file`
  log source, so its `COMPILE_ONLY` waiver is removed and the coverage report marks E
  "Proven, open defect" (this defect). This defect (the in-container selection has no
  reader constraint) still stands; the split-rule fix below is a human decision.
- **Kind**: false positive, description. **Severity**: high (a high-level rule fires on
  routine activity of most clusters).
- **Problem**: `selection_container` matches an open of any
  `.../secrets/kubernetes.io/serviceaccount/.../token` path by any process except the
  kubelet: it has no reader constraint. Each workload that calls the API server reads
  that file again and again, not only at start as the description and falsepositives
  say. client-go's cached file token source keeps the token for one minute less a
  10 s leeway (`period: time.Minute`, `leeway: 10 * time.Second`), and reads the file
  again on the next request after that. The Python client (`token_refresh_period`,
  one minute) and the Java client (60 s) do the same, and kube-proxy reads the token
  through the `tokenFile` of its kubeconfig. So the rule fires up to about once a
  minute for each such container, CoreDNS and kube-proxy included; a client that
  mostly holds watches open makes fewer requests, and reads the token less often. The
  falsepositives text tells the operator to baseline the expected reader per image; at
  level high and without that baseline, the rule behaves as a hunting rule.
  `selection_node` (the node-side `kubernetes.io~projected/` path) does not show this
  problem on the slice: there only the kubelet opens those files. The logsource has
  the root cause that
  [L15](#l15-linux_static_pod_manifest_write-fires-on-reads-of-the-manifests)
  records: this rule needs reads, and a pipeline that gives `linux` / `file_event`
  only creation events makes it blind.
- **Evidence**: *corpus* — slice `linux-k8s-node-file-events` v3 (1501 events). The
  pull request that adds this entry also adds the slice, so these figures are in the
  `benign/scores.json` of that pull request, not in the snapshot at `00216e3`. 251
  hits, each an open of the in-container token by its own workload, from 9 images
  (`/coredns` x51, `/usr/local/bin/kube-proxy` x30, `/opt/java/openjdk/bin/java` x29,
  `/opt/bin/flanneld` x26, `/usr/bin/local-path-provisioner` x25, `/app/server` x24,
  `/usr/local/bin/python3.12` x23, `/metrics-server` x22,
  `/nginx-ingress-controller` x21). The kubelet has 344 events under
  `kubernetes.io~projected/`. Its 127 creates and compare reads of a projected `token`
  file are quiet through `filter_expected`. Its other 217 events there (the `ca.crt`
  and `namespace` creates and reads, and the `..data` renames) do not end in `/token`
  and match no selection. `score_benign.py --examples 1` explains the first hit
  (actor `/coredns`): `selection_container` holds on
  `/var/run/secrets/kubernetes.io/serviceaccount/token`. Budget 266 (`--reseeds 10`).
  *probe* — scratch copies of the rule (results on the slice, and the most over the
  reseeds):
  - `selection_node and not filter_expected` alone: 0 hits (0). It fires on the 3
    node-side positives (`node-path-projected-token`,
    `node-path-resolved-timestamp-token`, `binary-named-kubelet-reads-token`).
  - `selection_container and selection_reader and not filter_expected`, where
    `selection_reader` is `Image|endswith` this list: the shells `/sh`, `/bash`,
    `/dash`, `/ash`, `/zsh`, `/busybox`; the file readers `/cat`, `/head`, `/tail`,
    `/base64`, `/dd`, `/cp`, `/tar`, `/strings`, `/xxd`, `/od`; the interpreters
    `/python`, `/python3`, `/python3.12`, `/perl`, `/ruby`, `/node`, `/php`; the
    network tools `/curl`, `/wget`, `/nc`, `/ncat`, `/socat`. 23 hits (39): the Python
    workload, whose own client runs in the interpreter `/usr/local/bin/python3.12`. It
    fires on the 3 in-container positives (`shell-reads-incontainer-token` with
    `/usr/bin/head`, `run-secrets-spelling-known-miss` and
    `incontainer-resolved-timestamp-token-known-miss` with `/usr/bin/cat`), but not on
    positive `binary-named-mount-reads-token` (`/tmp/mount`, a name that is in no
    list). `/java` is not in the list; with it, the Java workload adds 29 hits (52 on
    the slice, 67 over the reseeds).
  - The same list without the interpreters: 0 hits (0), and it misses a Python
    one-liner (`/usr/bin/python3`) that reads the token.
  - The same list without the file readers (only shells, interpreters and network
    tools): it fires on none of the 3 in-container positives.

  *source* — Kubernetes v1.36.4 `staging/src/k8s.io/client-go/transport/token_source.go`
  (`NewCachedFileTokenSource`; `cachingTokenSource.Token` reads the file again only
  when it is called after the cached token's expiry less the leeway),
  `staging/src/k8s.io/client-go/rest/config.go` (`InClusterConfig`),
  `cmd/kubeadm/app/phases/addons/proxy/manifests.go` (`tokenFile`);
  kubernetes-client/python `kubernetes/base/config/incluster_config.py`;
  kubernetes-client/java `util/.../credentials/TokenFileAuthentication.java`.
- **Fix** (a human decision): give the node-path branch its own high rule, and keep
  this rule as the low hunting rule. That keeps every sidecar case, so the gates
  accept it:
  - Keep `linux_k8s_sa_token_read.yml` with both branches and all its cases, and
    lower its level to low, with the per-image baseline as its documented noise.
    Correct its description and falsepositives: a workload's client re-reads the
    token while it runs, not only at start.
  - Add a new high rule with only the node-path branch
    (`selection_node and not filter_expected`), with its own sidecar, and gate it by
    adding it to the `9006 E` file entry of `validate_apiserver_detections.py`
    (Procedure E's marked read is a node-path read), not by a waiver. Add an entry in
    TRR9006 Strategy 3 and its Detections table.
  - An in-container rule with a reader list (level medium) is optional. Its list must
    hold shells, file readers, interpreters and network tools (the probe's list):
    without the file readers it misses `head` and `cat`. Any binary outside the list
    evades it (`binary-named-mount-reads-token`), and a workload that runs in an
    interpreter still fires it, so it does not replace the hunting rule.

  Do not split the rule by moving cases out of `linux_k8s_sa_token_read.yml`. A
  scratch run of that split fails the required gates: the near-miss of the branch that
  leaves (`reads-namespace-file-not-token` or `projected-configmap-file-read`) has no
  condition atom left to break (R3), and the sufficiency ratchet reports the moved
  cases as gone. Only a human can accept that red ratchet.
- **Then**: the new high rule raises 0 hits on the slice (0 over the reseeds of slice
  v3). Its sidecar holds copies of the 3 node-side positives, of
  `kubelet-writes-projected-token` (filtered) and of `projected-configmap-file-read`
  (near-miss, `breaks: [selection_node.TargetFilename|endswith]`), and a new
  near-miss: `/coredns` opening `/var/run/secrets/kubernetes.io/serviceaccount/token`,
  `breaks: [selection_node.TargetFilename|contains]`. A scratch run of this plan
  passes `rule_cases.py`, the sufficiency ratchet and the benign budgets; that run
  predates the node file-event sensor, and its new rule failed only R1 and R4. Now
  register it in the `9006 E` file entry (R1) and give it a positive with the
  emulation identity, the marked reader's node-path read (R4). The low rule keeps its
  cases and its budget (266), and its
  budget's `why` becomes `documented noise:` once this entry closes. An in-container
  reader rule, if added, keeps copies of `shell-reads-incontainer-token`,
  `run-secrets-spelling-known-miss` and `incontainer-resolved-timestamp-token-known-miss`
  as positives that must fire, adds the `/coredns` read as a near-miss that breaks
  `selection_reader.Image|endswith`, gets its own `COMPILE_ONLY` waiver, and gets its
  budget from `--reseeds 10` (39 for the probe's list on slice v3).

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
- **Problem**: the shipped policy now logs the three DNS ConfigMaps and
  `openshift-dns/dns-default` at RequestResponse and kube-system and openshift-dns
  ConfigMap creates at Request, so a delete-and-recreate, a JSON patch
  (through the stored Corefile), quoted directives, directives on the brace line,
  `{$VAR}` placeholders, NBSP/NEL blanks, IPv4-mapped public targets and forwards of the
  cluster zone are graded. What is left:
  1. a forward of a zone other than the cluster zone to a **private** address, outside
     the root block: its record differs from a corporate stub zone only in the zone name
     and the address, so it is seen by the chokepoint only. On OpenShift this includes a
     private stub zone that the DNS Operator renders from `spec.servers` (plain or
     DNS-over-TLS);
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
  `minikube-default-annotation-patch`; for limit 1 on OpenShift, confounders
  `openshift-private-stub-zone` and `openshift-tls-private-stub-zone`.
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
  lab policy now logs namespace deletes at Request, so in the lab such a delete carries
  its body and fires, and kubectl's own body dry run is filtered. The Metadata-level
  residual stays for a deployment whose policy logs namespace deletes at Metadata.
- **Evidence**: *source* — apiserver `endpoints/handlers/delete.go` (DeleteOptions from
  the body when present). *case* — positive `namespace-delete-query-dry-run-ignored-body`
  (Request level, fires); filtered `namespace-delete-dry-run-query` (Metadata level, the
  residual). *simulator* — the residual is live under the published OpenShift Default
  profile (4.17 and 4.18) and the k3s starter policy, which log namespace deletes at
  Metadata: there `namespace-delete-query-dry-run-ignored-body` is lost (`body-removed`).
  It fires under the API server lab policy and the EKS, GCE kube-up, AKS and OpenShift
  WriteRequestBodies policies
  ([K39](#k39-delete-dry-run-body-filters-have-no-input-where-a-platform-logs-deletes-at-metadata)).
- **Fix**: trust the query form only on a record that would show a body: add
  `level: ['Request', 'RequestResponse']` to the query branch of `filter_dry_run`, next
  to `requestObject.kind: null`. A Metadata-level `?dryRun=All` delete then fires; a real
  query-only dry run logged at Metadata becomes a false positive, listed under
  falsepositives (as kubectl's body dry run at Metadata already is). The lab half is
  done: `detections/k8s/audit-policy-apiserver.yaml` logs namespace deletes at Request,
  and the validator's must-not-match check (`9010 dryrun`) asserts in each CI run that the rule
  stays quiet on a `kubectl delete namespace --dry-run=server`.
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
  - the ConfigMap `openshift-dns/dns-default` and the DNS Operator objects
    (`dnses.operator.openshift.io`), for TRR9027 E and F.

  On OpenShift the gap follows the cluster's audit profile, not this policy: the
  WriteRequestBodies and AllRequestBodies profiles log every write at RequestResponse
  (openshift/library-go `pkg/operator/apiserver/audit/manifests`), so there a
  YAML-bodied apply patch of any resource, `dns-default` and the DNS Operator object
  included, leaves no record, and the TRR9027 chokepoint misses it too. The Default
  profile logs writes at Metadata and keeps the record.

  On managed platforms the gap is wider (*simulator*, on the published policies in
  [`k8s/provider-policies/`](k8s/provider-policies/SOURCES.md); **unverified** on a live
  cluster). The EKS, GCE kube-up and AKS policies log every write of a known API group
  at RequestResponse, except the resources they keep at Metadata (Secrets and most
  ConfigMaps). The OpenShift WriteRequestBodies profile logs every write at
  RequestResponse, except the resources it keeps at Metadata (Secrets, tokens, routes,
  OAuth clients, the machineconfiguration group). So on those platforms a YAML-bodied
  apply patch of nearly any resource leaves no record, and the chokepoints that read
  only Metadata fields miss it too. Under the OpenShift Default profile (apart from
  OpenShift identity and OAuth-token writes) and the k3s starter policy, writes are
  logged at Metadata, so the record survives
  ([K40](#k40-body-graders-are-blind-under-the-openshift-default-profile-and-the-k3s-starter-policy)
  applies there instead).

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

### K34. k8s_podspec_host_access: a default kubectl debug from kubectl v1.36 adds SYS_PTRACE

- **Rule**: [`sigma/T1611/k8s_podspec_host_access.yml`](sigma/T1611/k8s_podspec_host_access.yml) (level high).
- **Kind**: false positive, description. **Severity**: medium (routine operator noise
  wherever `pods/ephemeralcontainers` patches or `pods` creates are logged at Request, as
  the shipped API server lab policy logs both).
- **Problem**: from kubectl v1.36 (the CI pin), `kubectl debug` uses the `general`
  profile when `--profile` is not given. That profile adds the `SYS_PTRACE` capability to
  the debug container in both pod forms of `kubectl debug`:
  - the ephemeral form (`kubectl debug <pod>`), a strategic merge patch of
    `pods/ephemeralcontainers`, which the `sel_caps_ephem` selection reads;
  - the copy form (`kubectl debug <pod> --copy-to=<new>`), a plain `pods` create of the
    copy, which the `sel_caps` selection reads. The capability goes on the new debug
    container, or on the existing container that `--container` names, and the copy also
    shares the process namespace.

  The rule grades `SYS_PTRACE` as an escape capability, so every default `kubectl debug`
  of a pod from a kubectl v1.36 or later client fires this level-high T1611 rule where
  that write is logged at Request. The copy form does not depend on how
  `pods/ephemeralcontainers` is logged: it fires wherever `pods` creates are logged at
  Request, as the API server lab policy logs them
  ([`k8s/audit-policy-apiserver.yaml`](k8s/audit-policy-apiserver.yaml), the rule headed `TRR9007: pods and ephemeral containers at Request`).
  kubectl v1.35 and earlier (default profile `legacy`) add no capability in either
  form, and their debug bodies do not fire. (The node form,
  `kubectl debug node/<name>`, mounts the host root and uses the host namespaces with
  both profiles, so it fires on every kubectl version and is not part of this change.)
  The rule's falsepositives text names only `kubectl debug --profile=general or
  sysadmin` and an ephemeral container, so it does not say that the default fires, or
  that a copy fires. The benign corpus cannot measure this noise: the `kubectl debug`
  template of `k8s-audit-human-operators` models only the ephemeral form, with kubectl
  v1.30 and v1.31 bodies (no `securityContext`), so `scores.json` records 0 hits for
  this rule on that slice, and no template models a `--copy-to` create. CI does not see
  it either: the TRR9002 lab logs `pods/ephemeralcontainers` and `pods` at Metadata, and
  no step of the API server lab runs `kubectl debug`.
- **Evidence**: *probe* (`sigma_eval.py`, all 31 Kubernetes audit rules) — a
  Request-level `pods/ephemeralcontainers` patch whose ephemeral container has
  `securityContext.capabilities.add: ["SYS_PTRACE"]` (the kubectl v1.36 default body)
  fires; the same body with no `securityContext` (the v1.35 `legacy` body) does not; the
  v1.36 patch at Metadata level does not. `T1609/k8s_pod_ephemeral_container` fires on
  all three, as it keys on the subresource. A Request-level `pods` create of a copy with
  `shareProcessNamespace: true` and `SYS_PTRACE` on a new debug container (the kubectl
  v1.36 `--copy-to` body) fires, and so does the same copy with `SYS_PTRACE` on the
  existing container (`--copy-to --container=<existing>`); the copy with no
  `securityContext` (the v1.35 `legacy` copy body) does not, and the v1.36 copy at
  Metadata level does not. This rule is the only rule that fires on a copy. A node debug
  pod (host-root `hostPath`, `hostPID`, `hostNetwork`, `hostIPC`) fires for both
  profiles. *source* — kubectl `staging/src/k8s.io/kubectl/pkg/cmd/debug/debug.go`
  v1.36.4 L216 (default `ProfileGeneral`) and v1.35.8 L217 (default `ProfileLegacy`);
  `debug.go` v1.36.4 L628 (`debugByCopy` creates the copy with `Pods(...).Create`) and
  L776-850 (`generatePodCopyWithDebugContainer` appends the debug container, or takes the
  one `--container` names, and calls `o.Applier.Apply(copied, c.Name, pod)` at L850);
  `profiles.go` v1.36.4 L157-170 (`getDebugStyle`: `podCopy` when the pod is not the
  target), L206-212 (copy style: `allowProcessTracing` at L211, `shareProcessNamespace`
  at L212), L214-215 (ephemeral style: `allowProcessTracing`), L201-204 (node style) and
  L419-427 (`addCapability(c, "SYS_PTRACE")`); `profiles.go` v1.35.8 L181-184 (`legacy`
  copy style: it only removes labels) and L185-186 (`legacy` ephemeral style: no change).
  *corpus* — `k8s-audit-human-operators`, template "kubectl debug: ephemeral debug
  container in a distroless pod" (user agents kubectl v1.30.5 and v1.31.1), 0 hits; no
  `--copy-to` template.
- **Fix**: a human decision (plan item C3-3c); no rule changes in the pull request that
  records this entry. Each choice must cover both forms. The choices include: keep the
  level-high alert and baseline the known operator identities (for the patch and for the
  create); or grade, at a lower level in a separate rule, a write whose only escape
  signal is `SYS_PTRACE` on one container: an ephemeral container, or a pod create
  (the `--copy-to` shape; an attacker's pod can have the same shape, so this choice
  lowers that alert too). In each case, correct the falsepositives text to say that a
  default `kubectl debug` from kubectl v1.36 fires, in the ephemeral and in the copy
  form.
- **Then**: the benign corpus gains a kubectl v1.36 or later ephemeral `kubectl debug`
  body and a kubectl v1.36 or later `--copy-to` pod-create body (a corpus change that a
  human approves), and the rule's budget, level or a new near-miss case follows the
  decision. The entry closes.

### K35. API server lab policy: MutatingAdmissionPolicy deletes at Metadata hide a dry run

- **Scope**: the API server lab policy
  ([`k8s/audit-policy-apiserver.yaml`](k8s/audit-policy-apiserver.yaml)) and the one rule
  whose filter needs the record it does not keep,
  [`sigma/T1685/k8s_admission_webhook_disabled.yml`](sigma/T1685/k8s_admission_webhook_disabled.yml)
  (level medium). As K23, this entry names no rule file in the Summary row or in a Rules
  bullet: `research/tools/coverage_report.py` maps a listed rule to all its procedures,
  and this gap of the lab policy does not touch what those procedures send (they write
  webhook configurations, which the policy logs at Request). Whether it must name the
  rule is a human decision.
- **Kind**: policy gap. **Severity**: low (a dry run changes nothing, and
  MutatingAdmissionPolicy is served by default only from v1.36).
- **Problem**: the rule filters a server-side dry-run delete by its DeleteOptions body
  (`filter_dry_run_delete_body`: `requestObject.dryRun` contains `All`), and its
  falsepositives text says that the shipped lab policy records that body (Request
  level). That is true for the four resources that the admission-control rows of
  [`k8s/audit-policy-apiserver.yaml`](k8s/audit-policy-apiserver.yaml) list (the two
  webhook configurations, ValidatingAdmissionPolicy and its binding). It is not true for
  `mutatingadmissionpolicies` and `mutatingadmissionpolicybindings`: their writes fall to
  the Metadata catch-all, which logs no `requestObject`. So a `kubectl delete
  --dry-run=server` of a MutatingAdmissionPolicy or its binding fires the rule, and the
  same dry run of a webhook configuration is filtered. MutatingAdmissionPolicy is GA and
  on by default from v1.36 (the CI pin), so the pin and the v1.37 leg of the version
  matrix serve it. The rule's description does not list the MutatingAdmissionPolicy
  resources, though `select_adm_write` matches them (it keys on the API group).
- **Evidence**: *probe* — a Metadata-level `delete` of `mutatingadmissionpolicies` (no
  `requestObject`, as the lab logs a `--dry-run=server` delete) fires; a Metadata-level
  `deletecollection` of `mutatingadmissionpolicybindings` fires; a Request-level `delete`
  of a `validatingwebhookconfigurations` object whose DeleteOptions body has `dryRun:
  ["All"]` does not fire, and the same delete without `dryRun` fires. *source* —
  `detections/k8s/audit-policy-apiserver.yaml`, the two rules headed `TRR9008: admission-control updates and patches at RequestResponse` and `TRR9008 / TRR9025: admission-control creates and deletes at Request` (the update/patch and
  create/delete rows list only the four resources) and its Metadata catch-all; apiserver
  `staging/src/k8s.io/apiserver/pkg/features/kube_features.go` v1.36.4 L443-447
  (MutatingAdmissionPolicy GA and on from 1.36). No emulation creates a
  MutatingAdmissionPolicy, so no CI record shows it.
- **Fix**: a human decision: add `mutatingadmissionpolicies` and
  `mutatingadmissionpolicybindings` to the two admission-control rows of
  `detections/k8s/audit-policy-apiserver.yaml` (RequestResponse for update and patch,
  Request for create, delete and deletecollection), so the lab logs the DeleteOptions
  body and the rule's dry-run filter can read it. Name both resources in the rule's
  description.
- **Then**: no case changes (the delete dry-run filter already reads the body of any
  `admissionregistration.k8s.io` delete). The entry closes when the policy rows list both
  resources.

### K36. Delete dry-run filters read only the body: a query-only dry run fires

- **Rules**: [`sigma/T1070/k8s_events_deleted.yml`](sigma/T1070/k8s_events_deleted.yml) (level medium),
  [`sigma/T1070/k8s_workload_deleted_evidence.yml`](sigma/T1070/k8s_workload_deleted_evidence.yml) (level low),
  [`sigma/T1685/k8s_admission_webhook_disabled.yml`](sigma/T1685/k8s_admission_webhook_disabled.yml) (level medium, its delete form),
  [`sigma/T1685/k8s_enforcer_workload_removed.yml`](sigma/T1685/k8s_enforcer_workload_removed.yml) (level high),
  [`sigma/T1685/k8s_security_tool_workload_removed.yml`](sigma/T1685/k8s_security_tool_workload_removed.yml) (level low).
- **Kind**: false positive. **Severity**: low (a dry run changes nothing, and the noise
  needs a client that sends the dry run in the query with no body; kubectl delete
  --dry-run=server does not).
- **Problem**: each rule filters a server-side dry-run delete by its DeleteOptions body
  only (`filter_dry_run_delete_body`: `requestObject.dryRun` contains `All`). A DELETE of
  one object, or of a collection, that has no body and carries `?dryRun=All` in the query
  is a real dry run too: with no body the API server decodes DeleteOptions from the
  query. The audit record of such a request holds no `requestObject` at any level (the
  API server records the request object of a delete only when it decodes a body), so
  the filter cannot hold and each rule fires on a request that deleted nothing.
  `kubectl delete --dry-run=server` and the client-go typed and dynamic clients send
  the dry run in the body, so the lab's own dry runs are filtered (the validator's
  must-not-match checks assert that in CI). Two clients send the query form: the
  official Python client (kubernetes-client/python), whose `delete_*` calls put
  `dry_run="All"` in the query and send no body unless the caller passes one, and
  `kubectl delete --raw '<object URL>?dryRun=All'` with no `-f`. The same record at
  Metadata level also fires, and there it cannot show whether a body was sent.
  [`k8s_namespace_deleted`](sigma/T1070/k8s_namespace_deleted.yml) has a query branch
  for this shape (K14) and stays quiet on it. The falsepositives text of the five rules
  names the query form.
- **Evidence**: *probe* (`sigma_eval.py`) — Request-level records with no
  `requestObject`, `?dryRun=All` as the whole query and the user agent
  `OpenAPI-Generator/34.1.0/python`: a core Event delete, an events.k8s.io Event delete
  and an Event deletecollection fire `k8s_events_deleted`; a pod delete and a Job delete
  fire `k8s_workload_deleted_evidence`; a `validatingwebhookconfigurations` delete fires
  `k8s_admission_webhook_disabled`; a Deployment delete in `gatekeeper-system`, a
  Deployment deletecollection in `kyverno` and a delete of the `gatekeeper-system`
  namespace fire `k8s_enforcer_workload_removed` and
  `k8s_security_tool_workload_removed`. The same records with a DeleteOptions body that
  holds `dryRun: ["All"]` (kubectl's shape) fire no rule, and `k8s_namespace_deleted`
  is quiet on the query-only namespace delete. *source* — apiserver
  `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/delete.go` v1.36.4 L95-121
  (`DeleteResource`: the body is decoded and recorded with `audit.LogRequestObject`
  when it is not empty, else DeleteOptions come from the query) and L272-296
  (`DeleteCollection`, the same); kubernetes-client/python v34.1.0
  `kubernetes/client/api/core_v1_api.py` L12263 (`dryRun` goes to the query) and L12278
  (`body_params = None` unless a body is passed), and `kubernetes/client/rest.py`
  L169-170 (no request body when `body` is None); kubectl
  `staging/src/k8s.io/kubectl/pkg/rawhttp/raw.go` v1.36.4 L54-55 (`--raw` with no file
  sends an empty body).
- **Fix**: a human decision. Give each `filter_dry_run_delete_body` a query branch for a
  record that would show a body if one was sent: `level` in `Request` or
  `RequestResponse`, `requestObject.kind: null`, `annotations.audit.k8s.io/truncated:
  null`, and the whole-parameter `requestURI|re` test of `dryRun=All` with the 100-`&`
  limit that `k8s_namespace_deleted` uses. The branch must not apply at Metadata level,
  where a real delete with a body and a `?dryRun=All` query would be filtered (K14).
- **Then**: new filtered cases (Request level, no body, `?dryRun=All`) hold for each of
  the five rules, and new near-miss cases (the same record at Metadata level; the same
  record with a DeleteOptions body that holds no `dryRun`) fire. No existing case
  changes. The entry closes.

### K37. Namespace-teardown filters trust the namespace controller's name

- **Rules**: [`sigma/T1070/k8s_events_deleted.yml`](sigma/T1070/k8s_events_deleted.yml) (level medium),
  and the same `filter_namespace_teardown` in
  [`sigma/T1070/k8s_workload_deleted_evidence.yml`](sigma/T1070/k8s_workload_deleted_evidence.yml) (level low),
  [`sigma/T1685/k8s_enforcer_workload_removed.yml`](sigma/T1685/k8s_enforcer_workload_removed.yml) (level high) and
  [`sigma/T1685/k8s_security_tool_workload_removed.yml`](sigma/T1685/k8s_security_tool_workload_removed.yml) (level low).
  These are the rules where a procedure's own path is a deletecollection (TRR9010 B, D
  and G, TRR9008 D).
- **Kind**: evasion. **Severity**: low (the attacker needs a credential that
  authenticates as `system:serviceaccount:kube-system:namespace-controller`: `create` on
  `serviceaccounts/token` for that service account in `kube-system`; `create` on pods (or
  on any workload) in `kube-system` with `serviceAccountName: namespace-controller`, because
  the ServiceAccount admission plugin mounts that account's token into the pod; `create`
  and `get` on Secrets in `kube-system`, for a `kubernetes.io/service-account-token` Secret
  of that account, which the token controller fills; or the credentials of
  kube-controller-manager. Each path already needs `kube-system`-level access, which
  allows much more than a cover-up).
- **Problem**: each `filter_namespace_teardown` drops every `deletecollection` whose
  `user.username` is `system:serviceaccount:kube-system:namespace-controller`. It reads
  only the identity and the verb. The real namespace controller sends a deletecollection
  only for a namespace that has a deletion timestamp, so its sweep always follows an
  accepted delete of that namespace: by the actor, which `k8s_namespace_deleted` matches,
  or by the garbage collector, which that rule filters (`filter_lifecycle_garbage_collector`).
  The controller sends its sweep again on each sync until the namespace is empty, so a
  namespace that stays Terminating (a finalizer, a slow pod shutdown) gets legitimate
  sweeps long after the delete. A request sent with a token of that service account is
  filtered too, from any client and any address, in a namespace that nobody deletes: for
  example the Events bulk wipe of TRR9010 Procedure B or G, sent with `kubectl --token`,
  or a deletecollection of the
  pods or of the enforcer's DaemonSets in its namespace. A single delete by that
  identity still fires (case `namespace-controller-identity-single-event-delete`).
  Impersonation does not evade the filter: with `--as`, `user.username` holds the real
  caller, and `impersonatedUser` holds the service account. Two more rules,
  `T1053.007/k8s_job_create` and `T1098.006/k8s_rbac_write`, have the same filter and the
  same gap for a deletecollection of Jobs or of RBAC objects. No procedure of TRR9005 or
  TRR9004 deletes a collection, so the entry does not name them under Rules (the
  coverage report would then mark every procedure of those two TRRs).
- **Evidence**: *probe* (`sigma_eval.py`) — the sidecar positives
  `deletecollection-bulk-procB` and `deletecollection-eventsk8s-procG` with
  `user.username` set to the namespace controller, the user agent `kubectl/v1.36.4
  (linux/amd64) kubernetes/0000000` and `sourceIPs` `["10.244.1.17"]` (a pod address)
  are quiet. With `impersonatedUser` set to that account instead (the real user stays
  `kubernetes-admin`), they fire. The same change of `user`, user agent and address on the
  deletecollection positive of each other rule (`user-deletecollection-pods`,
  `user-deletecollection-jobs`, `user-deletecollection-rolebindings`,
  `user-deletecollection-falco-daemonsets`, `user-deletecollection-deployments`) is quiet
  too. *case* — `namespace-controller-token-deletecollection-eventsk8s-known-miss` in the
  `k8s_events_deleted` sidecar (confounder). *source* — kubernetes v1.36.4
  `pkg/controller/namespace/deletion/namespaced_resources_deleter.go` L109-111 (`Delete`
  returns when the namespace has no deletion timestamp), L136 (each sync calls
  `deleteAllContent`) and L326 (a `DeleteCollection` for each resource);
  `pkg/controller/namespace/namespace_controller.go` L157-160 (while content remains, the
  namespace goes back on the queue with `AddAfter`);
  `plugin/pkg/admission/serviceaccount/admission.go` L160-165 (`Admit` looks up the pod's
  `serviceAccountName` and mounts that account's token);
  `pkg/controller/serviceaccount/tokens_controller.go` L381-384 (`generateTokenIfNeeded`
  fills a service-account-token Secret);
  `staging/src/k8s.io/controller-manager/pkg/clientbuilder/client_builder_dynamic.go`
  L235-245 (with service-account credentials, each controller's client adds
  `/system:serviceaccount:kube-system:<name>` to the kube-controller-manager user agent;
  `cmd/kube-controller-manager/app/controllermanager.go` L826-828 selects that builder);
  `staging/src/k8s.io/apimachinery/pkg/util/net/http.go` L309-355 (`SourceIPs`: the
  `X-Forwarded-For` and `X-Real-Ip` values first, which the client sets, and the peer
  address last).
- **Fix**: a human decision. (1) Hunting, with no rule change: a namespace-controller
  deletecollection in a namespace that has no accepted delete of that namespace, by any
  identity, since the namespace was created (so the namespace is not Terminating). Search
  the raw audit records for that delete, not the hits of `k8s_namespace_deleted`, which
  filters the garbage collector's delete. The controller sends its sweep again until the
  namespace is empty, so do not limit the look-back to a short window. Also hunt for one
  whose last `sourceIPs` entry is not a control-plane node, or one whose `userAgent` does
  not begin with `kube-controller-manager/`. (2) A rule change: add
  `userAgent|startswith: 'kube-controller-manager/'` to each `filter_namespace_teardown`,
  so that a request from another client fires. This only raises the bar, because the
  client sets its user agent. Before that change, check each platform's controller user
  agent and the benign corpus.
- **Then**: with fix (2), the confounder
  `namespace-controller-token-deletecollection-eventsk8s-known-miss` fires; a new positive
  with the same record proves the fix (relabelling the confounder is a human decision
  under the sufficiency ratchet), and a new filtered case with the kube-controller-manager
  user agent keeps the teardown quiet. Each other rule gets the same pair of cases.

### Platform entries (K38 to K42): how they are scoped

The five entries that follow (K38 to K42) are platform gaps: each rule is proven under
the lab policy, and the gap is in what a managed platform's own published audit policy
(or log category) records. The evidence is the policy simulator (*simulator* above) on
the policy texts in [`k8s/provider-policies/`](k8s/provider-policies/SOURCES.md), not
a capture from a live cluster (backlog issue #55). As K23 and K35, these entries name
their rules in a **Scope** bullet, not in the Summary row or a Rules bullet, so
`research/tools/coverage_report.py` does not mark the lab-proven procedures as open
defects; whether a platform gap must mark them is a human decision. The numbers are
the simulator output on the branch that added these entries (Kubernetes coverage wave
4, before its other items merged); `python3 detections/k8s_policy_coverage.py` prints
the current ones.

### K38. Kubernetes Events deletes leave no record on EKS, GCE kube-up and OpenShift 4.17, and no collection-DELETE record on AKS

- **Scope**: [`sigma/T1070/k8s_events_deleted.yml`](sigma/T1070/k8s_events_deleted.yml)
  (level medium), TRR9010 Procedures A and B (and on AKS Procedure G).
  Platforms:
  Amazon EKS (the Best Practices Guide policy), a cluster that runs the GCE kube-up
  policy (the GKE audit-policy page names that script; GKE itself is **unverified**),
  OpenShift 4.17 and earlier (Default and WriteRequestBodies), and Azure AKS (both log
  categories).
- **Kind**: portability, policy gap. **Severity**: medium (the indicator removal that
  the rule exists for leaves no trace on these platforms, and no rule change can
  help).
- **Problem**: the EKS, GCE kube-up and OpenShift 4.17 policies log every request on
  core-group Events at level None. Plain `kubectl delete event` and `kubectl delete
  events --all` use the core group (client-go's REST mapper puts core `v1` first): the
  first sends one DELETE (Procedure A), and the second sends a list and then one DELETE
  per Event, not a collection DELETE. A collection DELETE in the core group (Procedure
  B: a raw API call, or client-go `DeleteCollection`) is at None too. So on these
  platforms none of them writes an audit record; only a request in the events.k8s.io
  group is recorded (Procedures C and G), at
  Metadata (EKS, GCE kube-up, OpenShift 4.17 Default) or RequestResponse (OpenShift
  4.17 WriteRequestBodies). The
  AKS policy logs an Events delete and list at Metadata and drops every other Events
  request (create, update and patch are kept in `default` and `kube-system`). So on
  AKS a collection DELETE writes no record in either group (Procedures B and G), but `kubectl
  delete events --all` sends one DELETE per Event, which AKS logs at Metadata, and the
  rule fires on each of them. The AKS Events rules do not omit the RequestReceived
  stage, so there each delete writes two records and the rule alerts twice. OpenShift
  4.18 and later and the k3s starter policy log Events deletes. The namespace delete of
  Procedure F is recorded on every one of these platforms (`k8s_namespace_deleted`'s
  positive `namespace-delete-payments` fires under every policy). But where a platform
  logs namespace deletes at Metadata (OpenShift Default, 4.17 and 4.18, and the k3s
  starter policy), a real namespace delete that also carries `?dryRun=All` next to its
  DeleteOptions body is filtered there: the K14 residual.
- **Evidence**: *simulator* — positives of `k8s_events_deleted` that fire: lab 8 of 8;
  `eks` 2 of 8, `gce-kube-up` 2 of 8, `openshift-default-4.17` and
  `openshift-wrb-4.17` 2 of 8 (the lost six are `no-record`; only the events.k8s.io
  positives fire: `delete-eventsk8s-procC` and `deletecollection-eventsk8s-procG`);
  `aks-kube-audit` and `aks-kube-audit-admin` 5 of 8
  (`deletecollection-bulk-procB`, `deletecollection-eventsk8s-procG` and
  `deletecollection-events-failed-authentication` are `no-record`; AKS policy rule
  index 10, 0-based: the "Don't log other events requests" None rule);
  `openshift-default`, `openshift-wrb` and `k3s-starter` 8 of 8. *source* — EKS
  Best Practices Guide `latest/bpg/security/detective.adoc` L85-89 ("Do not log events
  resources", group `""` only); kubernetes v1.36.4
  `cluster/gce/gci/configure-helper.sh` L1234-1238 ("Don't log events requests
  because of performance impact."); Microsoft Learn `monitor-aks.md` L239-262 (the
  three Events rules: Metadata for create/update/patch in `default` and
  `kube-system`, Metadata for delete and list, None for the rest, both groups);
  openshift/library-go `release-4.17` `base-policy.yaml` L9-13 (None for core
  Events; `release-4.18` and later have no such rule); kubernetes v1.36.4
  `staging/src/k8s.io/client-go/restmapper/discovery.go` L47-49 (core `v1` first in
  the REST mapper priority); kubernetes v1.36.4
  `staging/src/k8s.io/kubectl/pkg/cmd/delete/delete.go` L367-411 and L480-484
  (`DeleteResult` visits each object and calls `DeleteWithOptions` for it; the file has
  no `DeleteCollection` call). The policy texts are in
  [`k8s/provider-policies/`](k8s/provider-policies/SOURCES.md). **unverified** on a
  live cluster.
- **Fix**: none in the rule: no rule can match a record that is not written, and EKS
  and AKS do not let the user change the policy. Compensating control: copy Events out
  of the cluster as they happen (an event exporter to the log store), so that a delete
  does not remove the only copy. OpenShift: 4.18 and later log core Events (a
  `customRules` entry cannot help on 4.17, because the base policy's None rule comes
  first). The events.k8s.io bulk wipe, which EKS and GCE kube-up still record, gets its
  own emulation step and positive in a parallel Wave 4 item (the plan's MP15).
- **Then**: no case changes. The entry closes when a live capture (backlog issue #55)
  shows that a platform logs core Events deletes, or the platform's published policy
  changes; the simulator column then moves with the vendored policy.

### K39. Delete dry-run body filters have no input where a platform logs deletes at Metadata

- **Scope**: the six rules that filter a server-side dry run by its DeleteOptions body
  (`requestObject.dryRun` contains `All`):
  [`sigma/T1070/k8s_events_deleted.yml`](sigma/T1070/k8s_events_deleted.yml),
  [`sigma/T1070/k8s_namespace_deleted.yml`](sigma/T1070/k8s_namespace_deleted.yml),
  [`sigma/T1070/k8s_workload_deleted_evidence.yml`](sigma/T1070/k8s_workload_deleted_evidence.yml),
  [`sigma/T1685/k8s_admission_webhook_disabled.yml`](sigma/T1685/k8s_admission_webhook_disabled.yml),
  [`sigma/T1685/k8s_enforcer_workload_removed.yml`](sigma/T1685/k8s_enforcer_workload_removed.yml)
  and [`sigma/T1685/k8s_security_tool_workload_removed.yml`](sigma/T1685/k8s_security_tool_workload_removed.yml).
  Platforms: OpenShift with the Default profile (4.17 and 4.18), the k3s starter
  policy, AKS (Events deletes), and the events.k8s.io group on EKS and under the GCE
  kube-up policy (Events deletes).
- **Kind**: false positive, portability. **Severity**: low (a dry run changes nothing;
  the rules' falsepositives text already says that a dry run logged at Metadata fires).
- **Problem**: `kubectl delete --dry-run=server` sends `dryRun: ["All"]` in the
  DeleteOptions body, which only a Request-level (or higher) record holds. The lab
  policy logs these deletes at Request, so there the dry runs are filtered (the
  validator's must-not-match checks assert it). The OpenShift Default profile and the
  k3s starter policy log every delete at Metadata, AKS logs an Events delete at
  Metadata, and the EKS and GCE kube-up policies log an events.k8s.io delete at
  Metadata (their catch-all), so on those platforms each dry run fires its rule. The
  EKS, GCE kube-up and AKS policies log the other deletes (core, apps, batch,
  admissionregistration) at RequestResponse, so there the body filters work. This is
  not K14 (a query `?dryRun=All` next to a body, at Metadata) and not K36 (a dry run
  sent only in the query, with no body, at any level): here the client sends the
  body, and the platform does not record it. The same platforms make the K14 residual
  live for namespace deletes: OpenShift Default and the k3s starter policy log them at
  Metadata, so a real namespace delete that carries `?dryRun=All` next to its body is
  filtered there (K14 has the entry; the evidence below gives the simulator result).
- **Evidence**: *simulator* — filtered cases that fire: `k8s_events_deleted`
  `delete-core-event-dry-run-body` under `aks-kube-audit`, `aks-kube-audit-admin`,
  `openshift-default` and `k3s-starter`, `deletecollection-events-dry-run-body`
  under `openshift-default` and `k3s-starter`, and
  `deletecollection-eventsk8s-dry-run-body` under `eks`, `gce-kube-up`,
  `openshift-default`, `openshift-default-4.17` and `k3s-starter`; `k8s_namespace_deleted`
  `namespace-delete-dry-run-body`, `k8s_workload_deleted_evidence`
  `delete-job-dry-run-body` and `deletecollection-pods-dry-run-body`,
  `k8s_admission_webhook_disabled` `delete-validating-webhook-dry-run-body`,
  `k8s_enforcer_workload_removed` `delete-falco-daemonset-dry-run-body`,
  `enforcer-namespace-delete-dry-run-body` and
  `deletecollection-deployments-dry-run-body`, `k8s_security_tool_workload_removed`
  `delete-deployment-dry-run-body`, `enforcer-namespace-delete-dry-run-body` and
  `deletecollection-deployments-dry-run-body`, each under `openshift-default`,
  `openshift-default-4.17` and `k3s-starter`. No negative fires under `lab-apiserver`,
  `openshift-wrb` or `openshift-wrb-4.17`. Under `eks` and `gce-kube-up` a dry run
  fires only when it is an Events delete or deletecollection in the events.k8s.io
  group, which those policies log at Metadata (`deletecollection-eventsk8s-dry-run-body`
  and the probe below); they log the other
  deletes at RequestResponse, so there every other filtered dry run stays quiet.
  These six rules read
  only `requestObject`. A sidecar case recorded at Metadata that a platform logs at
  Request or higher lacks the DeleteOptions body that the platform records, and the
  simulator cannot add it (`not_modeled_reads`, the `~` cells): for those cases the
  dry-run filter is not exercised on that platform. The K14 residual: the positive
  `namespace-delete-query-dry-run-ignored-body` of `k8s_namespace_deleted` is lost
  (`body-removed`) under `openshift-default`, `openshift-default-4.17` and
  `k3s-starter`, and fires under every other policy. *probe* — the record of
  `delete-core-event-dry-run-body` with `objectRef.apiGroup: events.k8s.io`, put
  through each policy by the simulator's `records_under()`, fires under `eks`,
  `gce-kube-up` and `openshift-default-4.17` (Metadata) and stays quiet under
  `openshift-wrb-4.17` (RequestResponse); the record of
  `deletecollection-events-dry-run-body` in the same group fires under `eks` and
  `gce-kube-up` too (Metadata), and leaves no record on AKS. **unverified** on a live
  cluster.
- **Fix**: where the user writes the policy, log delete and deletecollection of these
  resources at Request: on OpenShift, the WriteRequestBodies profile (no negative fires
  under `openshift-wrb`); on k3s and other self-written policies, the delete rows of
  the lab policy (phase-2 item G's recommended production policy,
  `detections/k8s/audit-policy-recommended.yaml`, is the place to name them). Where the
  policy is fixed (AKS, EKS), none: baseline the dry runs by `userAgent` and actor, or
  accept the noise. A higher level has a cost (K23): at Request or higher, a
  server-side apply patch with a YAML body leaves no record at all, so a profile or
  policy change that moves patches to Request trades this gap for K23's on those
  patches (deletes are not affected).
- **Then**: no case changes. Each platform column of the simulator stops listing these
  filtered cases once its policy logs the deletes at Request; the entry closes when no
  published policy in `k8s/provider-policies/` leaves them at Metadata, or when a human
  accepts the residual for the fixed policies.

### K40. Body graders are blind under the OpenShift Default profile and the k3s starter policy

- **Scope**: the rules that read `requestObject` or `responseObject` of a write:
  [`sigma/T1611/k8s_podspec_host_access.yml`](sigma/T1611/k8s_podspec_host_access.yml),
  [`sigma/T1611/k8s_podspec_controller_host_access.yml`](sigma/T1611/k8s_podspec_controller_host_access.yml),
  [`sigma/T1611/k8s_podspec_confinement_disabled.yml`](sigma/T1611/k8s_podspec_confinement_disabled.yml),
  [`sigma/T1098.006/k8s_rbac_privileged_grant.yml`](sigma/T1098.006/k8s_rbac_privileged_grant.yml),
  [`sigma/T1098.006/k8s_rbac_sensitive_permission_grant.yml`](sigma/T1098.006/k8s_rbac_sensitive_permission_grant.yml),
  [`sigma/T1685/k8s_admission_webhook_neutered.yml`](sigma/T1685/k8s_admission_webhook_neutered.yml),
  [`sigma/T1546/k8s_admission_webhook_repointed_to_url.yml`](sigma/T1546/k8s_admission_webhook_repointed_to_url.yml),
  [`sigma/T1546/k8s_malicious_admission_webhook_created.yml`](sigma/T1546/k8s_malicious_admission_webhook_created.yml),
  and the scale-to-zero shapes of
  [`sigma/T1685/k8s_enforcer_workload_removed.yml`](sigma/T1685/k8s_enforcer_workload_removed.yml)
  and [`sigma/T1685/k8s_security_tool_workload_removed.yml`](sigma/T1685/k8s_security_tool_workload_removed.yml).
  (The Corefile grader is K41.) Platforms: OpenShift 4.17 and 4.18 with the Default
  profile (the default), and the k3s hardening-guide starter policy.
- **Kind**: portability, policy gap. **Severity**: medium (the Default profile is what
  an OpenShift cluster runs unless an admin changes it; TRR9007 then has no audit-log
  detection at all, only the node sensor).
- **Problem**: both policies log every write at Metadata (OpenShift Default: one
  catch-all Metadata rule after the identity and OAuth-token rules; k3s: a single
  `level: Metadata` rule), so no pod spec, role rule, binding subject, webhook
  configuration or scale body is in the record. The chokepoints that read only
  Metadata fields still fire (`k8s_rbac_write`, `k8s_job_create`,
  `k8s_admission_webhook_created`, `k8s_admission_webhook_disabled`). The published
  EKS, GCE kube-up and AKS policies log these writes at RequestResponse ("known APIs"),
  so there every positive of these graders fires.
- **Evidence**: *simulator* — positives that fire under `openshift-default`,
  `openshift-default-4.17` and `k3s-starter` (the same in all three):
  `k8s_podspec_host_access` 0 of 36, `k8s_podspec_controller_host_access` 0 of 41,
  `k8s_podspec_confinement_disabled` 0 of 51, `k8s_rbac_privileged_grant` 2 of 20,
  `k8s_rbac_sensitive_permission_grant` 0 of 10, `k8s_admission_webhook_neutered` 0 of
  36, `k8s_admission_webhook_repointed_to_url` 0 of 20,
  `k8s_malicious_admission_webhook_created` 0 of 3, `k8s_enforcer_workload_removed` 5
  of 26 and `k8s_security_tool_workload_removed` 6 of 31 (every lost positive is
  `body-removed`). Under `eks`, `gce-kube-up`, `aks-kube-audit`,
  `aks-kube-audit-admin`, `openshift-wrb` and `openshift-wrb-4.17` all of them fire.
  `k8s_admission_webhook_neutered` also reads `responseObject`, and its sidecar records
  are at Request: on the RequestResponse platforms the simulator cannot add the stored
  object, so there its negatives are not proven (the `~` cells; `not_modeled_reads` 51
  under each of these policies). `k8s_enforcer_workload_removed` and
  `k8s_security_tool_workload_removed` read only `requestObject`, but some of their
  cases are recorded at Metadata, and these policies log the same requests with a
  `requestObject`: deletes, deletecollections, scale updates and patches, a get, and
  a namespace label patch (`not_modeled_reads` 6 to 9 per policy; the `~` cells). So
  on these platforms their dry-run and scale filters are not exercised on those
  cases, and the cases are not proven there either. The other graders lack no body
  they read on these platforms (`not_modeled_reads` 0). Under the k3s starter policy (one
  `level: Metadata` rule, no `omitStages`) every request also writes a RequestReceived
  record, so each chokepoint that still fires there alerts twice for one request.
  *source* — openshift/library-go `default-rules.yaml` (both branches) L10-15 (the
  Metadata catch-all) and `writerequestbodies-rules.yaml` (RequestResponse for every
  write, after a Metadata rule for the sensitive resources it lists: Secrets, tokens,
  routes, OAuth clients); k3s-io/docs
  `docs/security/hardening-guide.md` L544-549. **unverified** on a live cluster.
- **Fix**: OpenShift: set the WriteRequestBodies (or AllRequestBodies) audit profile
  (an admin decision; it logs write bodies, so Secrets stay at Metadata and ConfigMap
  bodies are logged). k3s and other self-written policies: log these writes at Request
  (RequestResponse for webhook-configuration updates and patches), as the lab policy
  does, and add `omitStages: [RequestReceived]`; phase-2 item G's recommended
  production policy (`detections/k8s/audit-policy-recommended.yaml`) is the place to
  state those lines. TRR9007 on a Metadata-only cluster: the node sensor. Either change
  has a cost (K23): at Request or higher, a server-side apply patch with a YAML body
  leaves no record at all, so the body graders and the chokepoints both miss it. Under
  WriteRequestBodies that is every patch except the resources the profile keeps at
  Metadata (Secrets, tokens, routes, OAuth clients, the machineconfiguration group);
  under the EKS, GCE kube-up and AKS policies, every patch of a known API group except
  the resources they keep at Metadata (Secrets and most ConfigMaps). The profile change
  trades this blind spot for K23's.
- **Then**: no case changes. The entry closes for a platform when its default policy
  records the bodies; the OpenShift Default and k3s starter columns are expected to stay
  as they are, so a human decides whether the entry stays open as documentation.

### K41. k8s_coredns_corefile_poisoned: blind under every published managed policy

- **Scope**: [`sigma/T1565.001/k8s_coredns_corefile_poisoned.yml`](sigma/T1565.001/k8s_coredns_corefile_poisoned.yml)
  (level high), the TRR9027 grader. Platforms: EKS, the GCE kube-up policy, AKS (both
  categories), OpenShift with the Default profile, the k3s starter policy.
- **Kind**: portability, policy gap. **Severity**: low (the chokepoint
  [`k8s_coredns_configmap_modified`](sigma/T1565.001/k8s_coredns_configmap_modified.yml)
  needs only Metadata and fires under every published policy: 16 of 16; the grader only
  ranks).
- **Problem**: the grader reads the Corefile in the request or stored ConfigMap, which
  only a Request or RequestResponse record of the kube-system/coredns write holds. The
  EKS, GCE kube-up and AKS policies log every ConfigMap request at Metadata by design
  (ConfigMaps can hold credentials); EKS keeps RequestResponse only for `aws-auth`, and
  AKS only for `coredns-custom` updates and patches, whose snippets this grader does not
  read (its description says so). The OpenShift Default profile and the k3s starter
  policy log every write at Metadata. Under the OpenShift WriteRequestBodies profile the
  kube-system/coredns write keeps its body, but OpenShift's own DNS ConfigMap is
  `openshift-dns/dns-default`, which both CoreDNS rules also cover (TRR9027 Procedure
  E; see K45).
- **Evidence**: *simulator* — positives that fire: lab 47 of 47; `eks`, `gce-kube-up`,
  `aks-kube-audit`, `aks-kube-audit-admin`, `openshift-default`,
  `openshift-default-4.17` and `k3s-starter` 0 of 47 (all `body-removed`);
  `openshift-wrb` and `openshift-wrb-4.17` 47 of 47. The grader also reads
  `responseObject`; its sidecar records hold none where the lab and WriteRequestBodies
  log RequestResponse, so its negatives under those policies are not proven with the
  stored ConfigMap (the `~` cells). *source* — EKS
  `detective.adoc` L114-122 (Secrets and ConfigMaps at Metadata); kubernetes v1.36.4
  `configure-helper.sh` L1265-1274 (the same); Microsoft Learn `monitor-aks.md`
  L304-322 (`coredns-custom` update and patch at RequestResponse, then Secrets,
  ConfigMaps and service accounts at Metadata). **unverified** on a live cluster.
- **Fix**: none where the policy is fixed (EKS, AKS): rely on the chokepoint and
  triage the write by actor and time; read the stored Corefile out of band. Where the
  user writes the policy: the lab policy's two TRR9027 rows (read their Helm warning
  first), which phase-2 item G's recommended policy
  (`detections/k8s/audit-policy-recommended.yaml`) is to state. OpenShift: the
  WriteRequestBodies profile. At that level a server-side apply of the ConfigMap with a
  YAML body leaves no record (K23; TRR9027 B and C are server-side applies), so the
  chokepoint misses it too.
- **Then**: no case changes.

### K42. AKS kube-audit-admin: the category drops get and list, so read-shaped procedures leave no record

- **Scope**: on AKS with only the `kube-audit-admin` diagnostic category (the AKSAuditAdmin
  table):
  [`sigma/T1609/k8s_pod_exec_attach.yml`](sigma/T1609/k8s_pod_exec_attach.yml),
  [`sigma/T1609/k8s_node_proxy_exec.yml`](sigma/T1609/k8s_node_proxy_exec.yml),
  [`sigma/T1609/k8s_node_proxy_kubelet_api.yml`](sigma/T1609/k8s_node_proxy_kubelet_api.yml),
  [`sigma/T1572/k8s_pod_portforward.yml`](sigma/T1572/k8s_pod_portforward.yml),
  [`sigma/T1572/k8s_node_proxy_portforward.yml`](sigma/T1572/k8s_node_proxy_portforward.yml),
  [`sigma/T1552.007/k8s_secret_access.yml`](sigma/T1552.007/k8s_secret_access.yml),
  [`sigma/T1134/k8s_impersonation.yml`](sigma/T1134/k8s_impersonation.yml) and
  [`sigma/T1134/k8s_impersonation_privileged.yml`](sigma/T1134/k8s_impersonation_privileged.yml).
- **Kind**: portability (log category). **Severity**: medium (Microsoft recommends
  `kube-audit-admin` over `kube-audit` to cut cost, and the WebSocket exec, the Secret
  read and the node-proxy read are the common shapes).
- **Problem**: Microsoft Learn says that `kube-audit-admin` "excludes the `get` and
  `list` audit events". An exec, attach or port-forward over WebSocket is a `get` on
  the subresource, a node-proxy request sent as an HTTP GET is a `get` on
  `nodes/proxy`, and a Secret read is a `get` or `list`, so none of them is in that
  category. The SPDY forms and a node-proxy POST (`create`) and `watch` stay. The impersonation positives are impersonated reads (`get` or
  `list`); an impersonated write is still recorded. Whether the category also drops
  `watch` is **unverified** (the page names get and list). The AKSAudit and
  AKSAuditAdmin tables also lack an impersonated-user column; that schema gap is the
  provider-mapping harness's (a parallel Wave 4 item), not this entry.
- **Evidence**: *simulator* (`aks-kube-audit-admin`, which drops `get` and `list` after
  the AKS policy) — positives that fire: `k8s_pod_exec_attach` 2 of 6,
  `k8s_node_proxy_exec` 1 of 7, `k8s_node_proxy_kubelet_api` 2 of 6,
  `k8s_pod_portforward` 1 of 2, `k8s_node_proxy_portforward` 1 of 4,
  `k8s_secret_access` 1 of 4, `k8s_impersonation` 0 of 11,
  `k8s_impersonation_privileged` 0 of 3 (each lost positive is `no-record`); under
  `aks-kube-audit` all of them fire. *source* — Microsoft Learn `monitor-aks.md` L119
  and L152 (kube-audit-admin and AKSAuditAdmin exclude get and list). **unverified** on
  a live cluster.
- **Fix**: collect the `kube-audit` category (the AKSAudit table) for these rules, or
  at least for the reads they need, and accept its cost; with `kube-audit-admin` only,
  these procedures are seen by no audit rule.
- **Then**: no case changes. The entry closes if Microsoft changes what the category
  keeps.

### K43. k8s_rbac_privileged_grant: the aggregation clause needs the API server's key order

- **Rule**: [`sigma/T1098.006/k8s_rbac_privileged_grant.yml`](sigma/T1098.006/k8s_rbac_privileged_grant.yml) (level high).
- **Kind**: false negative. **Severity**: low (a portability caveat: the lab and every
  store that keeps the audit record's JSON text are not affected, and the aggregated
  ClusterRole that adds the permission fires the rule on its own write).
- **Problem**: the rule filters the clusterrole-aggregation-controller's writes of the
  built-in `admin` and `edit` (`filter_aggregation_controller`) unless the written rules
  carry more than the built-in roles (`sel_agg_beyond_builtin`). The impersonate clause
  of `sel_agg_beyond_builtin` is a `|re` on the JSON text of `requestObject.rules`:
  `"impersonate"[^\]]*\],\s*"apiGroups":\s*\[[^\]]*\],\s*"resources":\s*\[[^\]]*"(users|groups|uids|userextras)`.
  It matches only when the keys of each RBAC rule come in Go field order (`verbs`,
  `apiGroups`, `resources`), as the API server writes them. A store that does not keep
  the key order of an object can give the text in another order: Kusto, for the AKS
  `RequestObject` column ("Kusto doesn't attempt to preserve the order of name-to-value
  mappings in a property bag",
  [the dynamic data type](https://learn.microsoft.com/kusto/query/scalar-data-types/dynamic);
  `dynamic_to_json()` sorts them), and GKE, whose `protoPayload.request` is a
  `google.protobuf.Struct` (a map). There the clause does not hold, the filter holds,
  and the controller's write of impersonate on users, groups, uids or userextras into
  `admin` or `edit` does not fire. The other clauses (`"*"`, `escalate`, `bind`,
  `nodes/proxy`) do not depend on key order.
- **Evidence**: *probe* (`sigma_eval.py`) — the positive case
  `aggregation-controller-writes-impersonate-users-into-admin` fires (1 hit) as
  recorded; the same event with the keys of each object in `requestObject.rules` sorted
  (`apiGroups`, `resources`, `verbs`) gives 0 hits. A create of a ClusterRole labelled
  `rbac.authorization.k8s.io/aggregate-to-admin` with impersonate on users, by a user
  other than the controller, fires in both key orders (1 hit each). *check* —
  `python3 detections/check_provider_mappings.py -v --provider aks detections/sigma/T1098.006/k8s_rbac_privileged_grant.yml`
  reports `sorted: native fires, aks quiet; blocks sel_agg_beyond_builtin` (and the same
  for GKE); the AKS and GKE `EXPECTED_LOSS` entries for that case (reason `KEY_ORDER`)
  point here. Which key order a KQL query or a GKE log store really gives: **unverified**
  (backlog issue #55).
- **Fix**: make the impersonate clause independent of the key order: add an alternative
  for each other order of `verbs`, `apiGroups` and `resources` (the `[^\]]*` skips stay
  inside one list, so each order is one more alternative of the same form). A rule change,
  so a later pull request.
- **Then**: a new positive case with the rule objects' keys sorted fires; the two
  `KEY_ORDER` entries in `check_provider_mappings.py` become stale and are removed; the
  entry closes.

### K45. k8s_coredns_configmap_modified: the DNS Operator filter trusts the operator's name

- **Rule**: [`sigma/T1565.001/k8s_coredns_configmap_modified.yml`](sigma/T1565.001/k8s_coredns_configmap_modified.yml) (level medium).
  The filter applies to its two OpenShift selections only (TRR9027 E and F); the
  kube-system branch (A to D) has no identity filter.
- **Procedures**: `TRR9027.K8S.E`, `TRR9027.K8S.F` (A to D are not affected).
- **Kind**: evasion. **Severity**: low (the attacker needs a credential that
  authenticates as `system:serviceaccount:openshift-dns-operator:dns-operator`: `create` on
  `serviceaccounts/token` for that account in `openshift-dns-operator`; `create` on pods in
  `openshift-dns-operator` with `serviceAccountName: dns-operator`, because the
  ServiceAccount admission plugin mounts that account's token into the pod; `create` on
  `pods/exec` of the operator pod; or access to its node. Each path already needs rights in
  the operator's namespace or on a control-plane node). On HyperShift-based platforms (for
  example ROSA and ARO with hosted control planes) the operator runs in the hosted
  control-plane namespace on the management cluster, and its credential is a client
  certificate with the same username (CN), in the Secret
  `dns-operator-service-account-kubeconfig` of that namespace. So in the guest cluster no
  operator pod or node path applies; only a credential minted for a guest ServiceAccount of
  that name does (`serviceaccounts/token`, or a pod with `serviceAccountName:
  dns-operator`), and only where the guest has that ServiceAccount (**unverified**).
- **Problem**: `filter_openshift_dns_operator` drops every `create` and `update` (PUT) of
  `openshift-dns/dns-default` and of the DNS Operator object whose `user.username` is the
  operator's service account. It reads only the identity and the verb. The real operator
  sends only those two verbs to these objects, so a `patch`, `delete` or `deletecollection`
  with that identity fires (positives `openshift-dns-operator-identity-patch-dns-default`,
  `openshift-dns-operator-identity-patch-dnses-unmanaged`,
  `openshift-dns-operator-identity-delete-dnses`). A PUT (`kubectl replace`) or a create
  sent with a token of that account is filtered, from any client and any address. With
  such a token an adversary can first set the DNS object to `managementState: Unmanaged`
  with a PUT, so that the operator no longer reverts a direct edit, and then PUT a
  poisoned `dns-default`. Under OpenShift's Default audit profile (Metadata) no rule sees
  either write. Under the WriteRequestBodies or AllRequestBodies profile the grader
  (`k8s_coredns_corefile_poisoned`, no identity filter) fires on the poisoned
  `dns-default`; no rule grades the DNS object. Impersonation does not evade the filter:
  with `--as`, `user.username` holds the real caller.
- **Evidence**: *probe* (`sigma_eval.py`, the rules of this change) — with the operator's
  identity, a Metadata-level `update` of `dnses/default` and of `dns-default` from
  `192.0.2.10` are quiet in both rules; a `patch` or `delete` of either fires the
  chokepoint; a RequestResponse-level `update` of a poisoned `dns-default` fires the
  grader. *case* — confounders `openshift-dns-operator-token-put-unmanaged-known-miss` and
  `openshift-dns-operator-token-put-dns-default-known-miss` (chokepoint sidecar); positive
  `openshift-dns-operator-token-put-poisoned-dns-default` (grader sidecar). *source* —
  openshift/cluster-dns-operator `82578923164636746e0d74d594ab32d83a660c0b` (release-4.20):
  `pkg/operator/controller/controller_dns_configmap.go` L135 (`client.Create` of
  `dns-default`) and L326-334 (`updateDNSConfigMap`: `client.Update`, only when
  `corefileChanged`); `pkg/operator/controller/controller.go` L256 and L336
  (`client.Update` of the DNS object, the finalizer); `pkg/operator/controller/dns_status.go`
  L33-34 (`Status().Update`, only when the status differs); `pkg/operator/operator.go` L206
  (`client.Create` of the default DNS object). No `Patch` or `Delete` of either object (the
  `client.Delete` calls, `controller.go` L325 and `controller_dns_daemonset.go` L73, are of
  a Service and of the DaemonSet). `manifests/0000_70_dns-operator_00-cluster-role.yaml`
  grants `*` on `dnses` and on `configmaps`.
- **Fix**: a human decision. (1) Hunting, with no rule change: a write of these two
  objects by the operator's identity whose last `sourceIPs` entry is not in the network
  that the real operator connects from, or whose `userAgent` does not begin with
  `dns-operator/` (client-go's default user agent names the binary, which is
  `dns-operator` in the operator's Deployment; check the value on a live cluster first).
  On a self-managed cluster that network is the cluster's pod network. On HyperShift the
  operator connects from the hosted control-plane namespace on the management cluster, so
  every legitimate write comes from outside the guest pod network: baseline the real
  source range there (the management cluster's pod network) before you use the
  `sourceIPs` clause, or use only the `userAgent` clause. Under a body profile, also a PUT
  of the DNS object by that identity whose `requestObject.spec` differs from the stored
  object (the operator's own update of the DNS object changes only its finalizers).
  (2) A rule change: add `userAgent|startswith: 'dns-operator/'` to
  `filter_openshift_dns_operator`, so that a request from another client fires. This only
  raises the bar, because the client sets its user agent. Before that change, read the
  operator's user agent from a live OpenShift record (backlog #55).
- **Then**: with fix (2), the two KNOWN MISS confounders fire; new positives with the same
  records prove the fix (relabelling a confounder is a human decision under the
  sufficiency ratchet), and a new filtered case with the operator's user agent keeps its
  own writes quiet.

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
  `/etc/kubernetes/manifests-disabled/kube-scheduler.yaml` by `/usr/bin/mv` does).
  While the rule has no selection item other than `selection_dir.TargetFilename` (its
  condition is `selection_dir and not filter_install`), no near-miss can close the
  warning; its proof is the filtered cases. The R5 hint no longer asks for that
  near-miss: `check_sufficiency.py` does not offer an item that its shape test shows to
  be the only selection item of its branch (with the item true, the condition reads no
  other selection item) and that the grader confirms (in no truth assignment of the
  rule's items does a verdict count a flip of it), and says that no near-miss can break
  it. The shape test does not clear every item that no case can break: the hint still
  offers `a` in `(a and not f) or b`, an item that is also negated (`m` in
  `(a and m) or not m`) and an item whose flip alone never fires the rule (`a` in
  `(a and b) or b`). The grader search reads every truth assignment, so no item of a
  rule of more than 12 items is cleared. On 2026-10-21 (main at `df43bcd`), no rule of
  16 or fewer items in the repository (correlations aside) had an offered item or filter
  that no case can break (an exhaustive search over the grader's verdicts found none).
  No gate repeats that search, so a rule added later can change this. The warning stays,
  because what it reports is true (no verified negative breaks a discriminating
  selection item) and a warning never fails the gate. A second required item added to
  the rule only to satisfy the gate is not a fix. An item added for a real reason is a
  fix (for example, an event-type item that keeps reads of the manifests quiet): a
  near-miss that breaks only that item then closes the warning.

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
| K44 | both TRR9027 rules missed OpenShift, whose DNS Operator owns cluster DNS: they pinned `kube-system` and the names `coredns`, `kube-dns` and `coredns-custom`, so a write of `openshift-dns/dns-default` or of the DNS Operator object (`dnses.operator.openshift.io`) fired neither (probe: the rules at `861f97b` match none of the fifteen OpenShift positives below, nine of the chokepoint and six of the grader, and the rules of this change match all fifteen). `T1565.001/k8s_coredns_configmap_modified` now matches writes of both objects (the DNS Operator's own creates and updates filtered; what that hides is open entry K45), and `k8s_coredns_corefile_poisoned` grades writes of `dns-default` (no identity filter) | chokepoint: positives `openshift-dns-default-patch-procE` and `openshift-dns-operator-config-patch-procF` (recorded on a kube-apiserver v1.36.4 lab), `openshift-dns-default-edit-default-profile`, `openshift-dns-operator-unmanaged-default-profile`, `openshift-dns-operator-config-delete`, `openshift-dns-operator-config-deletecollection`, and the operator-identity patch and delete positives; a near-miss for every item of the two OpenShift selections; filtered `openshift-dns-operator-renders-dns-default`, `openshift-dns-operator-status-update`, `openshift-dns-operator-adds-finalizer`, `openshift-dns-operator-creates-default-dns`, `openshift-dns-operator-creates-dns-default-configmap`. Grader: positives `openshift-dns-default-patch-procE` (recorded), `openshift-dns-default-direct-edit-port-5353`, `openshift-operator-renders-public-stub-zone`, `openshift-operator-renders-root-upstream-after-stub`, `openshift-operator-renders-root-upstream-first`, `openshift-dns-operator-token-put-poisoned-dns-default`; near-misses `openshift-rewrite-in-wrong-namespace`, `openshift-dns-staging-copy-poisoned`, `openshift-dns-default-get-allrequestbodies`; confounders on the operator's rendered default, private, DNS-over-TLS and DNSNameResolver Corefiles. Live: an emulated `openshift-dns` namespace and the vendored DNS Operator CRD; MANIFEST rows `9027 E`, `9027 E sev` and `9027 F` pass on a local kube-apiserver v1.36.4 lab with this policy, and are to be proven by the pull request's validate-apiserver run on kind |
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
