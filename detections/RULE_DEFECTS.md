# Rule defects and gaps

This is the one tracker of every rule defect, false negative, dead filter and
audit-policy gap that the near-miss cases, the benign corpus and the live captures
showed. It is the plan for the follow-up rule-fix pull request. This change set did
not edit any rule (`detections/sigma/**/*.yml`): each problem below stays in the rule
until that pull request fixes it.

A sidecar case, a budget `why` or a doc that says a defect is "tracked" points here,
by entry ID (for example `L3`).

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
| [L1](#l1-setns_namespace_join-runcs-own-children-fire) | `T1611/setns_namespace_join` | runc's nsexec children, snap-confine and `ip netns exec` fire | false positive | high |
| [L2](#l2-memfd_create_execveat-runc--12-re-exec-fires) | `T1620/memfd_create_execveat` | runc < 1.2 re-execs itself from a memfd on every container start | false positive | high |
| [L3](#l3-dirtyfrag_xfrm_unshare_netlink-clone_newnet-tested-as-a-hex-substring) | `T1068/dirtyfrag_xfrm_unshare_netlink` | `CLONE_NEWNET` is tested as a hex substring, so extra flag bits evade | false negative | high |
| [L4](#l4-io_uring_setup-no-allowlist-and-every-io_uring_enter) | `T1685/io_uring_setup` | no allowlist, and it matches every per-I/O `io_uring_enter` | false positive, description | high |
| [L5](#l5-bpf_prog_load-runc-and-snap-confine-fire) | `T1014/bpf_prog_load` | runc's and snap-confine's device-cgroup programs fire | false positive | medium |
| [L6](#l6-ptrace_traceme-debugger-inferiors-fire) | `T1622/ptrace_traceme` | a debugger's inferior (gdb, dlv) fires | false positive | medium |
| [L7](#l7-keyring_add_key_burst-no-burst-threshold) | `T1068/keyring_add_key_burst` | no burst threshold: one `add_key` fires (LUKS unlock) | false positive, description | medium |
| [L8](#l8-copyfail_af_alg_authencesn-libkcapi-splices) | `T1068/copyfail_af_alg_authencesn` | libkcapi's `kcapi-hasher` splices inputs of 32 KiB or more | false positive | medium |
| [L9](#l9-dirtyfrag_rxrpc_socket-the-openafs-allowlist-covers-no-af_rxrpc-user) | `T1068/dirtyfrag_rxrpc_socket` | the OpenAFS allowlist covers no AF_RXRPC user | evasion, description | medium |
| [L10](#l10-perf_event_open_non_profiler-dead-datadog-agent-entry) | `T1068/perf_event_open_non_profiler` | `datadog-agent` is never a comm; JVM profilers show thread names | dead filter | low |
| [L11](#l11-userfaultfd_syscall-no-allowlist) | `T1068/userfaultfd_syscall` | its falsepositives promise an allowlist the rule does not have | false positive, description | low |
| [L12](#l12-linux_k8s_sa_token_read-path-spellings-non-token-files-and-name-keyed-filters) | `T1552.007/linux_k8s_sa_token_read` | misses `/run/secrets` and resolved paths; fires on any projected file; name-keyed filter | false negative, false positive, evasion | medium |
| [L13](#l13-linux_static_pod_manifest_write-name-keyed-installer-filter) | `T1543.005/linux_static_pod_manifest_write` | any binary named like an installer is filtered | evasion | low |
| [K1](#k1-k8s_podspec_host_access-capabilities-outside-containers-all-and-substring-matches) | `T1611/k8s_podspec_host_access` | init/ephemeral capabilities and `ALL` miss; substring matches fire on names | false negative, false positive | high |
| [K2](#k2-k8s_podspec_controller_host_access-template-initcontainers-and-all) | `T1611/k8s_podspec_controller_host_access` | template `initContainers` and `ALL` miss | false negative | medium |
| [K3](#k3-k8s_rbac_privileged_grant-json-patches-system-groups-and-the-aggregation-controller) | `T1098.006/k8s_rbac_privileged_grant` | JSON patches and `system:serviceaccounts` miss; the aggregation controller fires | false negative, false positive | medium |
| [K4](#k4-k8s_admission_webhook_neutered-state-not-transition-and-unseen-neuters) | `T1685/k8s_admission_webhook_neutered` | grades state, not transition; several neuters are unseen | false positive, false negative | medium |
| [K5](#k5-k8s_security_tool_workload_removed-scale-json-patch-and-namespace-delete) | `T1685/k8s_security_tool_workload_removed` | `kubectl scale`, JSON-patch scale-down and namespace delete miss | false negative | medium |
| [K6](#k6-deletecollection-evades-four-delete-rules) | four Kubernetes delete rules | `deletecollection` is not matched | evasion | medium |
| [K7](#k7-k8s_job_create-two-kube-system-controllers-fire) | `T1053.007/k8s_job_create` | ttl-after-finished and garbage-collector deletes fire | false positive | medium |
| [K8](#k8-k8s_events_deleted-the-namespace-controller-fires) | `T1070/k8s_events_deleted` | the namespace controller deletes Events; falsepositives say it never does | false positive, description | medium |
| [K9](#k9-k8s_coredns_corefile_poisoned-any-forward-to-an-ip-fires) | `T1565.001/k8s_coredns_corefile_poisoned` | a private stub zone fires at high; `create` is unreachable | false positive, policy gap | medium |
| [K10](#k10-k8s_impersonation-a-denied-probe-leaves-no-impersonateduser) | `T1134/k8s_impersonation` | a denied impersonation probe has no `impersonatedUser` | false negative (unverified) | low |
| [K11](#k11-k8s_pod_exec_attach-procedure-c-makes-no-attach-request) | `T1609/k8s_pod_exec_attach` | claims the attach step of Procedure C, which makes none | description | low |
| [K12](#k12-k8s_cri_job_pod-only-the-v127-job-label) | `T1053.007/k8s_cri_job_pod` | keys only on the label Kubernetes stamps from v1.27 | false negative (portability) | low |
| [C1](#c1-azure_managed_identity_federated_credential_backdoor-case-sensitive-operationname) | `T1098.001/azure_managed_identity_federated_credential_backdoor` | case-sensitive `operationName` misses the export form | false negative | high |
| [C2](#c2-aws_leaked_access_key_recon-the-aida-branch-matches-temporary-credentials) | `T1078.004/aws_leaked_access_key_recon` | the AIDA branch matches IAM-user temporary credentials | false positive | medium |
| [C3](#c3-aws_resource_policy_made_public-whole-document-match-and-missing-scope-keys) | `T1537/aws_resource_policy_made_public` | whole-document match; scoping keys missing | false positive | medium |
| [C4](#c4-entra_illicit_oauth_consent_grant-allprincipals-alone-fires) | `T1528/entra_illicit_oauth_consent_grant` | `AllPrincipals` alone fires for sign-in-only scopes | false positive | medium |
| [C5](#c5-aws_github_oidc_role_trust_abuse-a-wildcard-in-the-ref-fires-at-high) | `T1098.001/aws_github_oidc_role_trust_abuse` | a wildcard inside a pinned repo's ref fires at high | false positive | medium |
| [C6](#c6-gcp_workforce_principalset_privileged_binding-breadth-is-never-checked) | `T1199/gcp_workforce_principalset_privileged_binding` | whole-pool breadth is never checked | false positive, description | medium |
| [C7](#c7-aws_s3_bucket_acl_made_public-a-single-grant-object) | `T1537/aws_s3_bucket_acl_made_public` | a single public grant (an object, not a list) misses | false negative (unverified) | medium |
| [C8](#c8-aws_s3_block_public_access_disabled-the-delete-event-name) | `T1537/aws_s3_block_public_access_disabled` | the delete branch's event name is probably wrong | false negative (unverified) | medium |
| [C9](#c9-aws_efs_file_system_policy_made_public-the-console-wizard-policy) | `T1537/aws_efs_file_system_policy_made_public` | the EFS console's mount-target-scoped policy fires | false positive | low |
| [C10](#c10-gcp_workload_identity_pool_provider_created-a-condition-cleared-by-update) | `T1098.001/gcp_workload_identity_pool_provider_created` | an update that only clears the condition misses | false negative | low |
| [C11](#c11-gcp_workforce_pool_provider_no_attribute_condition-rare-but-valid) | `T1199/gcp_workforce_pool_provider_no_attribute_condition` | "rare but valid" understates a common setup | description | low |
| [C12](#c12-aws_cognito_unauthenticated_identity_use-keyed-on-the-consoles-role-name) | `T1078.004/aws_cognito_unauthenticated_identity_use` | a renamed guest role is a miss | false negative (documented) | low |
| [P1](#p1-the-scale-subresources-are-logged-at-metadata) | `k8s/audit-policy-apiserver.yaml` | `*/scale` writes are logged with no body | policy gap | medium |
| [P2](#p2-a-dns-configmap-create-is-logged-at-metadata) | `k8s/audit-policy-apiserver.yaml` | a DNS ConfigMap create is logged with no body | policy gap | low |

## Linux (auditd and node file events)

### L1. setns_namespace_join: runc's own children fire

- **Rule**: [`sigma/T1611/setns_namespace_join.yml`](sigma/T1611/setns_namespace_join.yml) (level high).
- **Kind**: false positive. **Severity**: high.
- **Problem**: `runtime_processes` matches comm `runc` exactly. runc's nsexec sets
  comm to `runc:[1:CHILD]` before it calls `setns()`, once per namespace, so every
  `docker exec`/`kubectl exec` and every pod container that joins its sandbox fires.
  `snap-confine` joins the snap mount namespace on every snap launch, and `ip netns
  exec` (comm `ip`) is not allowlisted.
- **Evidence**:
  - case `runc-rootfs-setns-allowlisted` (filtered): its `why` records that the one
    setns path that runs as comm `runc` is the rootfs setup, and that the exec path
    runs as `runc:[1:CHILD]`/`runc:[2:INIT]` (recorded with strace of runc 1.5.1);
  - corpus `linux-auditd-dev-workstation`: 37 hits (exe
    `/memfd:runc_cloned:/proc/self/exe (deleted)` x30, `/usr/bin/ip` x5,
    snap-confine x2); budgets.json `why` starts "rule defect";
  - CI capture: 14 hits; the workload runs `docker exec`, `nsenter -n` and `ip netns exec`;
  - probe: `setns` with comm `runc:[1:CHILD]`, and with comm `snap-confine`: both match;
  - source: runc v1.2.0 `libcontainer/nsenter/nsexec.c` (`prctl(PR_SET_NAME,
    "runc:[1:CHILD]")`, then `join_namespaces()` and `setns()`).
- **Fix**: allowlist the runtime by `exe` (the runc binary path and runc's
  `/memfd:runc_cloned:` re-exec image) rather than by comm, which any process can set
  with `prctl`; add `snap-confine` by exe. Decide whether `ip netns exec` is noise to
  allowlist or a signal to keep.
- **Then**: add a filtered case for the `runc:[1:CHILD]` record; lower its budget.

### L2. memfd_create_execveat: runc < 1.2 re-exec fires

- **Rule**: [`sigma/T1620/memfd_create_execveat.yml`](sigma/T1620/memfd_create_execveat.yml) (level high).
- **Kind**: false positive. **Severity**: high.
- **Problem**: runc before 1.2 copies itself into a memfd and re-executes it on every
  container start and exec: `runc init` (comm `exe`, exe `/usr/bin/runc`) calls
  `memfd_create`, then `execveat(fd, "", AT_EMPTY_PATH)` in the same pid about 40 ms
  later. Every container start on such a host fires this high-level rule.
- **Evidence**:
  - corpus `linux-auditd-dev-workstation`: 5 hits (`/usr/bin/runc`), from the slice's
    docker-run/exec sequence templates; budgets.json `why` starts "rule defect";
  - probe: `memfd_create` (comm `exe`, exe `/usr/bin/runc`), then `execveat` (comm
    `6`, exe `/memfd:runc_cloned:/proc/self/exe (deleted)`) 38 ms later, same pid: match;
  - CI capture: 0 hits, so the runner's runc did not take this path.
- **Fix**: exclude the runc re-exec (the `memfd_create` base by exe `/usr/bin/runc`,
  or the `execveat` base by its `/memfd:runc_cloned:` image), or require a parent that
  is not a container runtime.
- **Then**: add a filtered case for the runc sequence; lower its budget.

### L3. dirtyfrag_xfrm_unshare_netlink: CLONE_NEWNET tested as a hex substring

- **Rule**: [`sigma/T1068/dirtyfrag_xfrm_unshare_netlink.yml`](sigma/T1068/dirtyfrag_xfrm_unshare_netlink.yml) (level high).
- **Kind**: false negative. **Severity**: high.
- **Problem**: the base `dirtyfrag_xfrm_unshare_user_net` matches `a0|contains`
  `50000000` or `40000000`. That is a substring of the hex string, not a test of the
  `CLONE_NEWNET` bit, so any extra flag hides the bit: `unshare -Urnm`
  (`0x50020000`), `CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWIPC` (`0x58000000`) and runc's
  combined set (`0x6c020000`) all miss. The exploit chooses the flags, so this is a
  one-bit evasion.
- **Evidence**:
  - case `unshare-combined-exact-then-netlink-xfrm` (positive): its `why` says only the
    exact value `0x50000000` fires;
  - probe: `unshare` a0 `50020000`, `58000000` or `6c020000`, then `socket(AF_NETLINK,
    SOCK_RAW, NETLINK_XFRM)` in the same pid: no match (graded near-miss).
- **Fix**: test the bit. auditd logs `a0` in lowercase hex without leading zeros, so
  bit 30 is set exactly when the value has 8 digits and the first is one of `4-7` or
  `c-f`: `a0|re: '^[4-7c-f][0-9a-f]{7}$'`. On a scratch copy of the rule with that
  item, `50000000`, `40000000`, `50020000`, `58000000`, `6c020000` and `c0000000` fire
  and `20000`, `10000000` and `8000000` do not. Or decode the flags in the log pipeline.
- **Then**: add positives for `50020000` and `58000000`.

### L4. io_uring_setup: no allowlist, and every io_uring_enter

- **Rule**: [`sigma/T1685/io_uring_setup.yml`](sigma/T1685/io_uring_setup.yml) (level medium).
- **Kind**: false positive, description. **Severity**: high.
- **Problem**: the title says "By Non-Allowlisted Process" and the description says
  the rule flags ring creation, but the rule has no allowlist and also matches
  `io_uring_enter`, which a ring user calls for every submit or reap batch.
- **Evidence**:
  - CI capture: **57,887 hits** from one runner workload; the workload runs
    `fio --ioengine=io_uring`;
  - corpus `linux-auditd-dev-workstation`: 12 hits (`/usr/bin/fio`); budgets.json
    `why` starts "rule defect";
  - case `io-uring-enter-only` (positive): `io_uring_enter` alone fires;
  - probe: `io_uring_enter` by `fio`: match.
- **Fix**: match ring creation only (drop `io_uring_enter`, or move it to a separate
  low-level hunting rule), and add the allowlist the rule describes (by exe).
- **Then**: change `io-uring-enter-only` from positive to a near-miss on the syscall;
  add a filtered case; lower the budget.

### L5. bpf_prog_load: runc and snap-confine fire

- **Rule**: [`sigma/T1014/bpf_prog_load.yml`](sigma/T1014/bpf_prog_load.yml) (level medium).
- **Kind**: false positive. **Severity**: medium.
- **Problem**: stock OS and runtime behaviour is missing from `bpf_processes`: runc
  loads the cgroup-v2 device-filter program on every container create, and
  snap-confine loads a device-cgroup program on snap launches.
- **Evidence**:
  - corpus `linux-auditd-dev-workstation`: 9 hits (snap-confine x6, and bcc's
    python3 x3, which is documented noise; the runc device-filter template was drawn 0
    times at the committed seed); budgets.json `why` starts "rule defect";
  - CI capture: 4 hits; the workload runs `docker run`;
  - probe: `bpf(BPF_PROG_LOAD)` by `runc`: match.
- **Fix**: allowlist runc and snap-confine by exe.
- **Then**: filtered cases for both; lower its budget.

### L6. ptrace_traceme: debugger inferiors fire

- **Rule**: [`sigma/T1622/ptrace_traceme.yml`](sigma/T1622/ptrace_traceme.yml) (level medium).
- **Kind**: false positive. **Severity**: medium.
- **Problem**: `gdb ./prog` and `dlv debug` fork the inferior, which calls
  `PTRACE_TRACEME` before `exec`, still with the debugger's comm and exe. On a
  developer host this is the main source of `TRACEME`. The falsepositives do not name
  debuggers.
- **Evidence**:
  - corpus `linux-auditd-dev-workstation`: 15 hits (gdb x10, dlv x5); budgets.json
    `why` starts "rule defect";
  - CI capture: 6 hits; the workload runs `gdb -batch -ex run` and `strace`;
  - probe: `ptrace` a0 `0` by `gdb`: match.
- **Fix**: exclude known debugger launchers by exe (`gdb`, `gdbserver`,
  `lldb-server`, `dlv`) and name them in the falsepositives.
- **Then**: a filtered case for the gdb inferior; lower its budget.

### L7. keyring_add_key_burst: no burst threshold

- **Rule**: [`sigma/T1068/keyring_add_key_burst.yml`](sigma/T1068/keyring_add_key_burst.yml) (level medium).
- **Kind**: false positive, description. **Severity**: medium.
- **Problem**: the title and description describe a burst ("a single add_key ... is
  benign"), but the rule has no count or correlation: one `add_key` fires.
  `cryptsetup open` and `systemd-cryptsetup` hand every LUKS2 volume key to dm-crypt
  with `add_key("logon", ...)`. The eCryptfs/fscrypt setup that the falsepositives
  name is not in the allowlist.
- **Evidence**:
  - case `add-key-nonallowlisted` (positive): one `add_key` event fires;
  - corpus `linux-auditd-dev-workstation`: 2 hits (`/usr/sbin/cryptsetup`);
    budgets.json `why` starts "rule defect";
  - CI capture: 7 hits; the workload runs `keyctl add` and `keyctl unlink`;
  - probe: one `add_key` by `cryptsetup`: match.
- **Fix**: make it a per-pid `event_count` correlation with a threshold, or retitle
  it as a single-event rule; allowlist cryptsetup and systemd-cryptsetup by exe.
- **Then**: a near-miss under the threshold (correlation `threshold` atom); lower the budget.

### L8. copyfail_af_alg_authencesn: libkcapi splices

- **Rule**: [`sigma/T1068/copyfail_af_alg_authencesn.yml`](sigma/T1068/copyfail_af_alg_authencesn.yml) (level high).
- **Kind**: false positive. **Severity**: medium.
- **Problem**: libkcapi opens `socket(AF_ALG, SOCK_SEQPACKET, 0)`, takes a `pipe()` at
  handle init, and for any update of 32 KiB or more uses `vmsplice` then `splice(pipe
  -> op fd)`. `kcapi-hasher` hashes a whole file in one update, so hashing a large
  file is AF_ALG socket + pipe + splice in one pid within milliseconds: the rule's
  exact correlation. The rule's falsepositives name kcapi-tools as a class.
- **Evidence**:
  - case `cryptsetup-afalg-no-splice` (near-miss): its `why` records this false
    positive;
  - probe: `socket` a0 `26` + `pipe2` + `splice`, same pid, comm `kcapi-hasher`: match;
  - source: libkcapi `lib/kcapi-kernel-if.c` (socket, pipe, `splice`) and
    `lib/kcapi-md.c` (the 32 KiB vmsplice/splice path);
  - corpus: **not modelled**. The Linux slice has no kcapi event, and the rule has no
    budget entry (default enforce at 0), so the corpus cannot show it today.
- **Fix**: allowlist the libkcapi tools by exe on the AF_ALG base, and add a
  kcapi-hasher sequence (socket, pipe2, splice) to the Linux slice so the corpus
  measures it.
- **Then**: a filtered case for kcapi-hasher.

### L9. dirtyfrag_rxrpc_socket: the OpenAFS allowlist covers no AF_RXRPC user

- **Rule**: [`sigma/T1068/dirtyfrag_rxrpc_socket.yml`](sigma/T1068/dirtyfrag_rxrpc_socket.yml) (level high).
- **Kind**: evasion, description. **Severity**: medium.
- **Problem**: `afs_processes` allowlists OpenAFS daemons (`afsd`, `fileserver`,
  `vlserver`, `bosserver`, `dafsserver`, `openafs`) and `kafs-preload`. OpenAFS runs
  its own Rx protocol over UDP (`socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)` in user
  space, `sock_create_kern` in its kernel module), and the in-kernel kafs client makes
  no `socket()` syscall. So no allowlisted name is a known AF_RXRPC user: the filter
  suppresses nothing real, and any binary named `afsd` evades the rule. The
  description's "AF_RXRPC is used almost exclusively by AFS implementations (kafs,
  OpenAFS)" is wrong for OpenAFS.
- **Evidence**:
  - the rule's sidecar has no filtered case: the two that claimed OpenAFS opens
    AF_RXRPC (`afsd-allowlisted`, `fileserver-allowlisted`) modelled events that do
    not exist and were removed;
  - probe: `socket` a0 `21` by a binary named `afsd`: suppressed (graded filtered);
  - source: OpenAFS `src/rx/rx_user.c` and `src/rx/LINUX/rx_knet.c`.
- **Fix**: remove the OpenAFS entries, or replace them with a recorded userspace
  AF_RXRPC user (for example a kafs-utils tool) by exe; correct the description.
- **Then**: a filtered case only for a recorded user.

### L10. perf_event_open_non_profiler: dead datadog-agent entry

- **Rule**: [`sigma/T1068/perf_event_open_non_profiler.yml`](sigma/T1068/perf_event_open_non_profiler.yml) (level medium).
- **Kind**: dead filter. **Severity**: low.
- **Problem**: the Datadog agent execs `/opt/datadog-agent/bin/agent` (comm `agent`),
  and the component that calls `perf_event_open` runs as `system-probe`; neither is
  `datadog-agent`, so that entry matches nothing. A comm allowlist also cannot cover
  JVM-hosted profilers: auditd's comm is the thread name (`Attach Listener` for
  async-profiler).
- **Evidence**:
  - case `bpftrace-allowlisted` (filtered): its `why` records the dead entry;
  - corpus `linux-auditd-dev-workstation`: 8 hits, 5 of them the JVM (exe
    `/usr/lib/jvm/java-21-openjdk-amd64/bin/java`); budgets.json `why` notes the
    thread-name comm;
  - probe: `perf_event_open` with comm `agent`, and with comm `system-probe`: both match.
- **Fix**: replace the `datadog-agent` comm with `exe|startswith:
  '/opt/datadog-agent/'`; allowlist profilers by exe, not comm.
- **Then**: a filtered case for the Datadog system-probe.

### L11. userfaultfd_syscall: no allowlist

- **Rule**: [`sigma/T1068/userfaultfd_syscall.yml`](sigma/T1068/userfaultfd_syscall.yml) (level high).
- **Kind**: false positive, description. **Severity**: low.
- **Problem**: the falsepositives tell the operator to "baseline and allowlist" CRIU,
  QEMU and some databases/JITs, but the rule has no filter block (its three sibling
  T1068 syscall rules do). Any `userfaultfd()` fires.
- **Evidence**: probe: `userfaultfd` by `criu`: match. The corpus has no userfaultfd
  user, so it shows 0 hits.
- **Fix**: add a `uffd_processes` exe allowlist, or say in the rule that it is
  allowlist-free by design.

### L12. linux_k8s_sa_token_read: path spellings, non-token files and name-keyed filters

- **Rule**: [`sigma/T1552.007/linux_k8s_sa_token_read.yml`](sigma/T1552.007/linux_k8s_sa_token_read.yml) (level high).
- **Kind**: false negative, false positive, evasion. **Severity**: medium.
- **Problem**:
  1. *Missed spellings*: the in-container branch is the literal
     `/var/run/secrets/kubernetes.io/serviceaccount/token`. A read through
     `/run/secrets/...` (`/var/run` is a symlink to `/run` in most images) and the
     resolved `..<timestamp>/token` path (the projected `token` is a symlink into the
     AtomicWriter timestamp directory) do not match.
  2. *Non-token files*: the node branch is `kubernetes.io~projected/`, so a read of any
     file in any projected volume (a configMap or downwardAPI projection) fires.
  3. *Name-keyed filter*: `filter_expected` suppresses any image whose path ends in
     `/kubelet`, `/mount` or `/umount`. The mount helper only mounts tmpfs on the
     volume directory and never opens the token, so `/mount` and `/umount` are dead
     entries that only let a binary named `mount` read the token unseen.
  4. *Event type*: the rule needs file read/open telemetry but declares Sigma's
     `linux` `file_event` category, which is modelled on file creation (Sysmon for
     Linux event 11); no standard `file_event` producer emits a read.
- **Evidence**:
  - probe: `TargetFilename` `/run/secrets/kubernetes.io/serviceaccount/token`, and
    `/var/run/secrets/kubernetes.io/serviceaccount/..2026_10_12_13_00_00.123456789/token`:
    no match (graded trivial); Image `/tmp/mount` reading the token: suppressed;
    python3 reading `.../volumes/kubernetes.io~projected/app-config/settings.json`:
    match;
  - case `node-path-resolved-timestamp-token` (positive) covers only the node-side
    resolved path; case `kubelet-writes-projected-token` (filtered) is the only real
    filter path;
  - check-sufficiency warns R5 (thin): one selection item, so no near-miss exists;
  - **unverified**: which spelling a given sensor reports (Falco `fd.name`, Tetragon
    `d_path`, auditd `PATH`) was not recorded. To check on kind: `kubectl exec <pod> --
    head -c 20 /run/secrets/kubernetes.io/serviceaccount/token` under the chosen sensor.
- **Fix**: match `TargetFilename|contains: '/secrets/kubernetes.io/serviceaccount/'`
  together with `TargetFilename|endswith: '/token'`, and the node path
  `kubernetes.io~projected/` together with `endswith: '/token'`; drop `/mount` and
  `/umount`; pin the kubelet by its full path; name the sensor and event type the rule
  needs.
- **Then**: positives for the `/run` spelling and the resolved in-container path; a
  confounder for the non-token projected read.

### L13. linux_static_pod_manifest_write: name-keyed installer filter

- **Rule**: [`sigma/T1543.005/linux_static_pod_manifest_write.yml`](sigma/T1543.005/linux_static_pod_manifest_write.yml) (level high).
- **Kind**: evasion. **Severity**: low.
- **Problem**: `filter_install` suppresses any image whose path ends in `/kubeadm`,
  `/kubelet`, `/dpkg`, `/apt`, `/apt-get`, `/yum`, `/dnf` or `/rpm`, so a dropper named
  `/tmp/kubeadm` writes a manifest unseen. The rule has one selection item, so it can
  have no near-miss (check-sufficiency warns R5 permanently).
- **Evidence**: cases `kubeadm-bootstrap-manifest` and `dpkg-installs-kubelet-keep`
  (filtered) exercise the basename match; the R5 warning.
- **Fix**: pin the installers by full path, or pair the write with package-manager
  context.

### Live-capture hits not yet attributed

The CI capture also annotated two rules that this tracker does not call defective:
`T1040/afpacket_raw_socket` (2 hits; enforce at 0 on the corpus, so a real fire would
fail if the capture were a committed slice) and `T1040/afinet_raw_socket` (5 hits). The
workload's AF_PACKET users are `tcpdump` (allowlisted) and `arping` (not in
`sniffer_processes`); its raw-socket user is `mtr` (the documented `mtr-packet` noise
in budgets.json). Read the run's `linux-benign-capture` artifact before you decide
whether `arping` belongs in the allowlist.

## Kubernetes (API server audit and CRI)

### K1. k8s_podspec_host_access: capabilities outside containers, ALL, and substring matches

- **Rule**: [`sigma/T1611/k8s_podspec_host_access.yml`](sigma/T1611/k8s_podspec_host_access.yml) (level high).
- **Kind**: false negative, false positive. **Severity**: high.
- **Problem**:
  1. `sel_caps` reads only `requestObject.spec.containers`. Procedure D's
     capabilities moved to an `initContainer` (which runs on the node with them), and
     an ephemeral container's capabilities (`kubectl debug --profile=general` adds
     `SYS_PTRACE`), do not fire.
  2. `capabilities.add: ["ALL"]` grants every capability and is not in the list.
  3. Every capability and `hostPath` item is a substring match over the whole
     serialized containers or volumes JSON (and SQLite `LIKE` ignores case). A
     container named `syslog`, an env value `syslog`, a `capabilities.drop` list that
     names `SYS_ADMIN`, or an `emptyDir` volume named `hostpath` fires the rule.
- **Evidence**: probe: a pod with an initContainer adding `SYS_ADMIN`, a
  `pods/ephemeralcontainers` patch adding `SYS_PTRACE`, and a container adding `ALL`:
  no match (graded near-miss); a pod with a container named `syslog`, a
  `capabilities.drop: [NET_ADMIN, SYS_ADMIN]`, and an `emptyDir` named `hostpath`:
  match.
- **Fix**: add `sel_caps_init` and `sel_caps_ephem`; add `"ALL"`; anchor the
  capability items to the `add` array with `|re` (for example
  `'"add": \[[^\]]*"SYS_ADMIN"'`) and `hostPath` to `'"hostPath": \{'`.
- **Then**: positives for the init, ephemeral and `ALL` cases; confounders for the
  name, env, drop-list and volume-name cases.

### K2. k8s_podspec_controller_host_access: template initContainers and ALL

- **Rule**: [`sigma/T1611/k8s_podspec_controller_host_access.yml`](sigma/T1611/k8s_podspec_controller_host_access.yml) (level high).
- **Kind**: false negative. **Severity**: medium.
- **Problem**: the rule never reads `spec.template.spec.initContainers` or the
  CronJob `jobTemplate` initContainers, so a Deployment, DaemonSet, Job or CronJob
  whose template has a privileged initContainer is missed at the adversary's own
  create (only the derived pod create, under a controller identity, is caught by K1's
  rule, which has `sel_privileged_init`). `ALL` is missing here too, and the same
  substring matching as K1 applies.
- **Evidence**: probe: a Deployment create whose template initContainer is
  `privileged: true`, and one whose container adds `ALL`: no match (graded near-miss).
- **Fix**: add the template and jobTemplate initContainer items; add `"ALL"`; anchor
  as in K1.

### K3. k8s_rbac_privileged_grant: JSON patches, system groups and the aggregation controller

- **Rule**: [`sigma/T1098.006/k8s_rbac_privileged_grant.yml`](sigma/T1098.006/k8s_rbac_privileged_grant.yml) (level high).
- **Kind**: false negative, false positive. **Severity**: medium.
- **Problem**:
  1. A JSON patch (`kubectl patch --type=json`) logs `requestObject` as the list of
     operations, so `requestObject.rules`, `.subjects` and `.roleRef` never exist. The
     repository's own Procedure E is delivered this way, though the description says
     the rule grades A-E. (The chokepoint rule `k8s_rbac_write` still fires.)
  2. The mass-grant clause lists `system:authenticated`, `system:unauthenticated` and
     `system:anonymous`, not `system:serviceaccounts` (every service account) or
     `system:serviceaccounts:<namespace>`.
  3. The kube-system `clusterrole-aggregation-controller` re-applies the built-in
     `edit`/`admin` ClusterRoles, which carry `impersonate`, and fires.
- **Evidence**:
  - corpus `k8s-audit-gitops-ci`: 7 hits (clusterrole-aggregation-controller x2,
    argocd tenant bindings x5); budgets.json `why` starts "rule defect";
  - probe: a JSON patch adding a `*`/`*`/`*` rule to a ClusterRole, and a
    ClusterRoleBinding to group `system:serviceaccounts`: no match (graded near-miss).
- **Fix**: add a selection on the flattened `requestObject` text of a patch
  (`"path": "/rules` or `"/subjects` with `"*"`, `escalate`, `bind`, `impersonate` or a
  system group); add the service-account groups; exclude the aggregation controller
  (by username and the built-in role names).

### K4. k8s_admission_webhook_neutered: state, not transition, and unseen neuters

- **Rule**: [`sigma/T1685/k8s_admission_webhook_neutered.yml`](sigma/T1685/k8s_admission_webhook_neutered.yml) (level high).
- **Kind**: false positive, false negative. **Severity**: medium.
- **Problem**:
  1. It grades the submitted state. A full-object rewrite of a webhook that already
     fails open by design (Gatekeeper's CA rotation, a Helm upgrade, Kyverno's
     `validate.kyverno.svc-ignore` on every reconcile) is graded as a neuter.
  2. The `"rules": []` half cannot match a create or update: the API server logs the
     decoded object re-encoded, and the webhook `rules` field is `omitempty`, so an
     emptied list leaves no `rules` key. Only a patch body keeps `"rules":[]`.
  3. A never-matching `namespaceSelector`/`objectSelector`, a `matchConditions`
     expression `false`, and a JSON patch of `failurePolicy` disarm the webhook unseen.
- **Evidence**:
  - case `replace-rules-emptied-known-miss` (confounder, KNOWN MISS);
  - corpus `k8s-audit-gitops-ci`: 1 hit (gatekeeper-admin); budgets.json `why` starts
    "rule defect";
  - probe: a Kyverno reconcile carrying its Ignore webhook: match; a never-matching
    `namespaceSelector`, `matchConditions` `false`, and a JSON patch of `failurePolicy`:
    no match;
  - source: Kubernetes v1.32 `update.go` (the re-encoded object) and the
    admissionregistration types (`rules,omitempty`); **unverified** on a live cluster.
- **Fix**: allowlist known fail-open webhooks or their reconcilers (no old value is
  logged, so a true transition test needs enrichment); detect a webhook entry with no
  `rules` key on create/update; add the selector, `matchConditions` and JSON-patch
  forms.
- **Then**: relabel `replace-rules-emptied-known-miss` as a positive.

### K5. k8s_security_tool_workload_removed: scale, JSON patch and namespace delete

- **Rule**: [`sigma/T1685/k8s_security_tool_workload_removed.yml`](sigma/T1685/k8s_security_tool_workload_removed.yml) (level medium).
- **Kind**: false negative. **Severity**: medium.
- **Problem**: `kubectl scale --replicas=0` patches the `deployments/scale`
  subresource, which the shipped policy logs with no body ([P1](#p1-the-scale-subresources-are-logged-at-metadata)).
  A scale-down by JSON patch has no `requestObject.spec.replicas`. Deleting the
  enforcer's namespace is a core `delete namespaces` (plus a namespace-controller
  `deletecollection`, see [K6](#k6-deletecollection-evades-four-delete-rules)).
- **Evidence**: case `kubectl-scale-zero-known-miss` (confounder, KNOWN MISS); probe:
  a JSON patch `replace /spec/replicas 0` (graded near-miss) and a `delete namespaces
  gatekeeper-system` (graded distant): no match.
- **Fix**: fix P1; add the JSON-patch form (`"path": "/spec/replicas"` with value 0);
  add namespace deletion of known enforcer namespaces (or a separate rule).
- **Then**: relabel `kubectl-scale-zero-known-miss` as a positive at Request.

### K6. deletecollection evades four delete rules

- **Rules**: [`sigma/T1070/k8s_workload_deleted_evidence.yml`](sigma/T1070/k8s_workload_deleted_evidence.yml),
  [`sigma/T1053.007/k8s_job_create.yml`](sigma/T1053.007/k8s_job_create.yml),
  [`sigma/T1098.006/k8s_rbac_write.yml`](sigma/T1098.006/k8s_rbac_write.yml),
  [`sigma/T1685/k8s_security_tool_workload_removed.yml`](sigma/T1685/k8s_security_tool_workload_removed.yml).
- **Kind**: evasion. **Severity**: medium.
- **Problem**: they match verb `delete`, not `deletecollection`, so a `DELETE` on the
  collection (`kubectl delete pods --all`, a label-selected delete) removes the same
  objects unseen. `k8s_rbac_write`'s description says "any write". The corpus now
  holds this verb (the namespace controller's sweep), so a fix shows in scoring.
- **Evidence**: probe: `deletecollection` of pods, of jobs, of rolebindings and of
  deployments: no match (graded near-miss on `verb`). Cases
  `rolebindings-deletecollection-ns-teardown` (k8s_rbac_write) and
  `namespace-teardown-deletecollection` (k8s_job_create) are near-misses on `verb`
  today: their `why` keeps the namespace controller's teardown sweep out by leaving
  the verb out, which also lets every other caller's `deletecollection` through.
- **Fix**: add `deletecollection`, and filter the namespace controller
  (`system:serviceaccount:kube-system:namespace-controller`) where its teardown sweep
  is noise.
- **Then**: those two cases become filtered cases on the namespace-controller
  filter; add a positive for a user's `deletecollection`.

### K7. k8s_job_create: two kube-system controllers fire

- **Rule**: [`sigma/T1053.007/k8s_job_create.yml`](sigma/T1053.007/k8s_job_create.yml) (level medium).
- **Kind**: false positive. **Severity**: medium.
- **Problem**: `filter_controllers` excludes only the cronjob and job controllers. The
  ttl-after-finished controller and the garbage collector delete Jobs routinely
  (every Job with `ttlSecondsAfterFinished`, and every Job cascaded away with its
  CronJob). The emulation's own `hostjob.yaml` sets `ttlSecondsAfterFinished: 60`, so a
  controller delete of `trr9005-hostjob` also passes the validator's `trr9005-` gate.
- **Evidence**:
  - corpus `k8s-audit-control-plane`: ttl-after-finished-controller x12 of the rule's
    33 hits; budgets.json `why` starts "rule defect";
  - probe: a Job delete by each of the two controllers: match.
  - **unverified**: the filter assumes per-controller credentials
    (`--use-service-account-credentials=true`, the kubeadm and kind default). Where the
    controllers act as `system:kube-controller-manager`, every scheduled CronJob run
    would fire.
- **Fix**: add `system:serviceaccount:kube-system:ttl-after-finished-controller` and
  `system:serviceaccount:kube-system:generic-garbage-collector` to
  `filter_controllers`; document the credentials assumption.

### K8. k8s_events_deleted: the namespace controller fires

- **Rule**: [`sigma/T1070/k8s_events_deleted.yml`](sigma/T1070/k8s_events_deleted.yml) (level medium).
- **Kind**: false positive, description. **Severity**: medium.
- **Problem**: the namespace controller `deletecollection`s core and
  `events.k8s.io` Events in every namespace being deleted, as
  `system:serviceaccount:kube-system:namespace-controller`. The falsepositives say
  kube-system controllers create Events but never delete them.
- **Evidence**: corpus `k8s-audit-gitops-ci`: 2 hits (namespace-controller, from the
  slice's preview-namespace teardown sequence); budgets.json `why` starts "rule
  defect"; probe: that `deletecollection`: match.
- **Fix**: filter or baseline that identity's `deletecollection`; correct the
  falsepositives.

### K9. k8s_coredns_corefile_poisoned: any forward to an IP fires

- **Rule**: [`sigma/T1565.001/k8s_coredns_corefile_poisoned.yml`](sigma/T1565.001/k8s_coredns_corefile_poisoned.yml) (level high).
- **Kind**: false positive, policy gap. **Severity**: medium.
- **Problem**: the forward-to-IP clause matches a `forward` to an IP in any server
  block, so a private stub zone (`corp.example.com:53 { forward . 10.10.0.53 }`) fires
  at high. Separately, the `create` verb in `select_dns_configmap_write` cannot be
  reached under the shipped policy ([P2](#p2-a-dns-configmap-create-is-logged-at-metadata)),
  and no producible near-miss exists on its name, namespace or verb items.
- **Evidence**: corpus `k8s-audit-gitops-ci`: 4 hits (argocd applying a stub zone);
  budgets.json `why` starts "rule defect"; probe: a patch of `kube-system/coredns`
  with that stub zone: match; cases `poisoned-but-wrong-name`,
  `poisoned-but-wrong-namespace` and `poisoned-but-verb-delete` are confounders, not
  near-misses, for that reason.
- **Fix**: scope the forward clause to the root (`.`) server block, or to targets
  outside RFC 1918, with a baseline diff; fix P2 or drop `create`.

### K10. k8s_impersonation: a denied probe leaves no impersonatedUser

- **Rule**: [`sigma/T1134/k8s_impersonation.yml`](sigma/T1134/k8s_impersonation.yml) (level medium).
- **Kind**: false negative. **Severity**: low. **Unverified**.
- **Problem**: when the caller lacks the `impersonate` verb, the API server's
  impersonation filter returns 403 before it stamps `impersonatedUser`, so a failed
  probe is invisible to a presence rule. This is a reading of the impersonation
  filter, not a lab recording.
- **Evidence**: probe: a 403 `list namespaces` with message `cannot impersonate` and
  no `impersonatedUser`: no match (trivially).
- **Fix**: a companion rule on `responseStatus.message|contains: 'cannot impersonate'`.
  Record the real event on kind first.

### K11. k8s_pod_exec_attach: Procedure C makes no attach request

- **Rule**: [`sigma/T1609/k8s_pod_exec_attach.yml`](sigma/T1609/k8s_pod_exec_attach.yml).
- **Kind**: description. **Severity**: low.
- **Problem**: the description claims "the attach step of Procedure C", but
  `atomics/T1609/src/emulate.sh` procedure C runs `kubectl debug` without `-i` or
  `--attach`, so it makes no `pods/attach` request.
- **Evidence**: case `debug-attach-step` (confounder in
  `sigma/T1609/k8s_pod_ephemeral_container.cases.jsonl`) is sourced as `kubectl debug
  -it`, not as the emulation.
- **Fix**: add `--attach` (or `-i`) to procedure C, or drop the claim.

### K12. k8s_cri_job_pod: only the v1.27 Job label

- **Rule**: [`sigma/T1053.007/k8s_cri_job_pod.yml`](sigma/T1053.007/k8s_cri_job_pod.yml) (level low).
- **Kind**: false negative (portability). **Severity**: low.
- **Problem**: the rule keys only on `labels.batch.kubernetes.io/job-name`, which the
  Job controller stamps from Kubernetes v1.27. Job pods on older clusters carry only
  the legacy `job-name`/`controller-uid` labels.
- **Evidence**: case `bare-pod-legacy-job-label` (benign) pins today's behaviour.
- **Fix**: also match the legacy label, or state the version floor in the rule.

## Cloud (AWS, Azure, GCP)

### C1. azure_managed_identity_federated_credential_backdoor: case-sensitive operationName

- **Rule**: [`sigma/T1098.001/azure_managed_identity_federated_credential_backdoor.yml`](sigma/T1098.001/azure_managed_identity_federated_credential_backdoor.yml) (level medium).
- **Kind**: false negative. **Severity**: high.
- **Problem**: `operationName` compiles to a case-sensitive equality on the ARM REST
  form `Microsoft.ManagedIdentity/.../federatedIdentityCredentials/write`. Storage and
  Event Hub exports carry it UPPERCASE, so the rule misses the attack there. Every ARM
  write also logs a Start and a Success record, so each operation counts twice.
- **Evidence**:
  - corpus `azure-activity-mi-admin` (v2 carries each operation in the ARM form and
    in two export forms): 29 hits, none from the UPPERCASE-`operationName` form;
    budgets.json `why` starts "rule defect";
  - probe: the UPPERCASE `operationName` with category `Administrative`: no match.
  - **Open question**: the rule requires top-level `category: Administrative`. The MS
    Learn mapping table says so; MS Learn's own Event Hub example and Elastic's
    captured record carry the operation type (`Write`/`Action`) there instead.
- **Fix**: `operationName|re: '(?i)^microsoft\.managedidentity/userassignedidentities/federatedidentitycredentials/write$'`;
  count one record per operation (the Success); settle the category question.
- **Then**: positives in the export form.

### C2. aws_leaked_access_key_recon: the AIDA branch matches temporary credentials

- **Rule**: [`sigma/T1078.004/aws_leaked_access_key_recon.yml`](sigma/T1078.004/aws_leaked_access_key_recon.yml) (level medium).
- **Kind**: false positive. **Severity**: medium.
- **Problem**: the description excludes temporary (`ASIA`) credentials and calls the
  `principalId` `AIDA` branch a fallback for a missing `accessKeyId`. But `id_aida`
  matches every IAM-user event, whatever the key type, so MFA sessions
  (`GetSessionToken`) and console sessions fire.
- **Evidence**: corpus `aws-developer-iam-user-keys`: 266 hits (the corpus build
  attributed 77 of the first version's 263 to temporary credentials); budgets.json
  `why` starts "rule defect"; probe: an IAM user's `ListBuckets` with `accessKeyId`
  `ASIA...` and `principalId` `AIDA...` from an off-egress IP: match.
- **Fix**: require `accessKeyId` absent or empty in the `id_aida` branch, or add `not
  userIdentity.accessKeyId|startswith: 'ASIA'`.
- **Then**: add the IAM user's `ASIA` session as the near-miss on
  `id_akia`/`id_aida`; that also clears the rule's R5 (thin) warning.

### C3. aws_resource_policy_made_public: whole-document match and missing scope keys

- **Rule**: [`sigma/T1537/aws_resource_policy_made_public.yml`](sigma/T1537/aws_resource_policy_made_public.yml) (level high).
- **Kind**: false positive. **Severity**: medium.
- **Problem**: `allow_present` and `public_principal` each match the whole policy text,
  so an Allow for a named role plus the standard `DenyInsecureTransport` statement
  (Deny, `Principal: "*"`, which Security Hub S3.5 recommends on every bucket) reads
  as public. `filter_scoped` lacks `aws:SourceOwner` (the SNS default policy) and
  `kms:CallerAccount`/`kms:ViaService` (the documented EBS default-key pattern).
- **Evidence**: corpus `aws-iac-admin-policy-changes`: 32 hits (terraform-apply);
  budgets.json `why` starts "rule defect"; probe: each of the three shapes: match.
- **Fix**: require `Allow` and `Principal: "*"` in the same statement object (a
  bounded `\{[^{}]*...\}` regex, as the GCP rules use); add `aws:SourceOwner`,
  `kms:CallerAccount` (and `aws:PrincipalAccount`) to `filter_scoped`.
- **Then**: filtered cases for the SNS and KMS shapes; a near-miss for the named
  Allow plus Deny.

### C4. entra_illicit_oauth_consent_grant: AllPrincipals alone fires

- **Rule**: [`sigma/T1528/entra_illicit_oauth_consent_grant.yml`](sigma/T1528/entra_illicit_oauth_consent_grant.yml) (level high).
- **Kind**: false positive. **Severity**: medium.
- **Problem**: `AllPrincipals` is one of the "high-privilege scope" tokens, so
  tenant-wide consent to sign-in-only scopes (`User.Read openid profile email`) fires,
  against the title and the falsepositives. Where user consent is disabled
  (Microsoft's recommended setting) every SSO onboarding is an `AllPrincipals` consent.
- **Evidence**: corpus `azure-entra-audit-appmgmt`: 37 hits (admins); budgets.json
  `why` starts "rule defect"; probe: admin consent `AllPrincipals` with
  `User.Read openid profile email`: match.
- **Fix**: require `AllPrincipals` and a high-privilege scope together, or make
  `AllPrincipals` alone a separate low-severity rule.
- **Then**: that consent as a near-miss; it also clears the rule's R5 warning.

### C5. aws_github_oidc_role_trust_abuse: a wildcard in the ref fires at high

- **Rule**: [`sigma/T1098.001/aws_github_oidc_role_trust_abuse.yml`](sigma/T1098.001/aws_github_oidc_role_trust_abuse.yml) (level high).
- **Kind**: false positive. **Severity**: medium.
- **Problem**: `sub_wildcard_*` fires on any `%2A` in the `sub` value, including a
  wildcard inside the ref of a pinned owner/repo (`repo:example-org/cli-tool:ref:refs/tags/v*`),
  where no fork or other repository can match.
- **Evidence**: corpus `aws-iac-admin-policy-changes`: 13 hits; budgets.json `why`
  starts "rule defect"; probe: that trust policy: match.
- **Fix**: keep high for a wildcard in the owner or repo segment; grade a ref-segment
  wildcard lower.

### C6. gcp_workforce_principalset_privileged_binding: breadth is never checked

- **Rule**: [`sigma/T1199/gcp_workforce_principalset_privileged_binding.yml`](sigma/T1199/gcp_workforce_principalset_privileged_binding.yml) (level medium).
- **Kind**: false positive, description. **Severity**: medium.
- **Problem**: the description says privileged role plus whole-pool breadth, but the
  regex never checks breadth, so group-scoped workforce RBAC on any role containing
  `admin` fires.
- **Evidence**: corpus `gcp-iam-federation-admin`: 3 hits (terraform granting
  `roles/container.admin` to one IdP group); budgets.json `why` starts "rule
  defect"; probe: that grant: match.
- **Fix**: require a whole-pool member (`/*`) or a single subject, or align the
  description with the regex.

### C7. aws_s3_bucket_acl_made_public: a single Grant object

- **Rule**: [`sigma/T1537/aws_s3_bucket_acl_made_public.yml`](sigma/T1537/aws_s3_bucket_acl_made_public.yml) (level high).
- **Kind**: false negative. **Severity**: medium. **Unverified** telemetry shape.
- **Problem**: CloudTrail logs a single-grant `AccessControlPolicy` with `Grant` as an
  object (the AWS documentation example), which flattens to
  `...AccessControlList.Grant.Grantee.URI`, so `...AccessControlList.Grant|contains`
  never sees a single public grant.
- **Evidence**: probe: `PutBucketAcl` with one `Grant` object granting `READ` to
  `AllUsers`: no match (graded near-miss). The rule has no sidecar; no recorded event
  of this shape is in the repository.
- **Fix**: also match `...AccessControlList.Grant.Grantee.URI`.
- **Then**: a sidecar with that positive.

### C8. aws_s3_block_public_access_disabled: the delete event name

- **Rule**: [`sigma/T1537/aws_s3_block_public_access_disabled.yml`](sigma/T1537/aws_s3_block_public_access_disabled.yml) (level high).
- **Kind**: false negative. **Severity**: medium. **Unverified**.
- **Problem**: `selection_delete` matches `eventName: DeletePublicAccessBlock`. The
  rule, fixture and corpus log the put as `PutBucketPublicAccessBlock` and the get as
  `GetBucketPublicAccessBlock`, so by the same convention the delete is probably
  `DeleteBucketPublicAccessBlock` (and `DeleteAccountPublicAccessBlock` at account
  level). If so, the delete branch never matches real CloudTrail.
- **Evidence**: none recorded; the S3 CloudTrail documentation could not be reached
  offline.
- **Fix**: confirm the names; match both forms; correct
  `research/trr9019/aws/README.md`, which uses the same name.

### C9. aws_efs_file_system_policy_made_public: the console wizard policy

- **Rule**: [`sigma/T1537/aws_efs_file_system_policy_made_public.yml`](sigma/T1537/aws_efs_file_system_policy_made_public.yml) (level high).
- **Kind**: false positive. **Severity**: low.
- **Problem**: the EFS console's policy wizard writes an Allow with `Principal:
  {"AWS": "*"}` conditioned on `elasticfilesystem:AccessedViaMountTarget`, which limits
  access to clients that reach a mount target in the VPC. `filter_scoped` lacks that
  key.
- **Evidence**: corpus `aws-iac-admin-policy-changes`: 6 hits (console SSO admins);
  budgets.json `why` starts "rule defect"; probe: that policy: match. **Unverified**:
  whether EFS Block Public Access treats that condition as non-public.
- **Fix**: confirm in the EFS documentation, then add the key to `filter_scoped`.

### C10. gcp_workload_identity_pool_provider_created: a condition cleared by update

- **Rule**: [`sigma/T1098.001/gcp_workload_identity_pool_provider_created.yml`](sigma/T1098.001/gcp_workload_identity_pool_provider_created.yml) (level medium).
- **Kind**: false negative. **Severity**: low.
- **Problem**: a field-masked `UpdateWorkloadIdentityPoolProvider` that clears the
  condition (`updateMask: attributeCondition`, no trust body) does not fire, because
  `selection_request_trust` needs the trust body in the request. The workforce
  sibling covers this with `selection_update_touches_condition`. **Unverified**: GCP
  may now support X.509 providers, which have no `oidc`/`aws`/`saml` block.
- **Evidence**: probe: that update: no match (graded near-miss).
- **Fix**: mirror the workforce rule's update branch; check the X.509 provider shape.

### C11. gcp_workforce_pool_provider_no_attribute_condition: "rare but valid"

- **Rule**: [`sigma/T1199/gcp_workforce_pool_provider_no_attribute_condition.yml`](sigma/T1199/gcp_workforce_pool_provider_no_attribute_condition.yml) (level medium).
- **Kind**: description. **Severity**: low.
- **Problem**: the falsepositives call a provider without a condition "rare but
  valid". For a tenant-specific corporate IdP the condition is optional (gcloud's
  `--attribute-condition` help: "If unspecified, all valid authentication credential
  will be accepted") and commonly omitted, because the tenant issuer already scopes
  trust. The workload sibling has the same wording.
- **Evidence**: corpus `gcp-iam-federation-admin`: 2 hits (an Entra ID workforce
  provider with no condition); budgets.json `why` is "documented noise".
- **Fix**: correct the wording; consider excluding the organization's approved
  `issuerUri` values.

### C12. aws_cognito_unauthenticated_identity_use: keyed on the console's role name

- **Rule**: [`sigma/T1078.004/aws_cognito_unauthenticated_identity_use.yml`](sigma/T1078.004/aws_cognito_unauthenticated_identity_use.yml) (level medium).
- **Kind**: false negative (documented). **Severity**: low.
- **Problem**: the rule finds the guest role by the console's naming
  (`Cognito_<pool>Unauth_Role`, Amplify's `...-unauthRole`), so a pool whose guest role
  has a site-specific name is missed. The rule's description says so.
- **Evidence**: the `PLATFORM_NAMING` waiver in
  [`check_sufficiency.py`](check_sufficiency.py) keeps only `Unauth` through the
  rename test for this reason.
- **Fix**: find a signal of a guest identity that does not depend on the role name;
  until then the waiver and the description stay.

## Audit-policy gaps

### P1. The scale subresources are logged at Metadata

- **File**: [`k8s/audit-policy-apiserver.yaml`](k8s/audit-policy-apiserver.yaml).
- **Kind**: policy gap. **Severity**: medium.
- **Problem**: audit resource matching is exact, and no rule lists
  `deployments/scale`, `statefulsets/scale` or `replicasets/scale`, so `kubectl scale
  --replicas=0` falls to the catch-all Metadata rule with no `requestObject`: a live
  false negative for [K5](#k5-k8s_security_tool_workload_removed-scale-json-patch-and-namespace-delete),
  whose description says the policy must list `*/scale`.
- **Evidence**: case `kubectl-scale-zero-known-miss`.
- **Fix**: add the three scale subresources (verbs update and patch) to the
  workload-controller Request rule.

### P2. A DNS ConfigMap create is logged at Metadata

- **File**: [`k8s/audit-policy-apiserver.yaml`](k8s/audit-policy-apiserver.yaml).
- **Kind**: policy gap. **Severity**: low.
- **Problem**: the TRR9027 Request rule is scoped by `resourceNames`, and a create
  (a POST to the collection) has no name when the policy is evaluated, so the creates
  of procedures B and C (`kube-dns`, `coredns-custom`) are logged at Metadata with no
  body and no `trr9027` sentinel. Only the chokepoint rule sees them, the validator
  proves TRR9027 on procedure A only (its MANIFEST label is `9027 A`), and the
  poisoning grader's `create` verb is unreachable
  ([K9](#k9-k8s_coredns_corefile_poisoned-any-forward-to-an-ip-fires)).
- **Evidence**: cases `kube-dns-stubdomains-create-procB` and
  `coredns-custom-create-procC` (Metadata, no `requestObject`).
- **Fix**: emulate B and C with `kubectl apply --server-side` (a PATCH by name, which
  the rule matches), or log DNS ConfigMap creates at Request (which logs the body of
  every kube-system ConfigMap create), or gate B and C on name, namespace and verb.

## Checks to add once the rules are fixed

Each "Then" above is part of the fix. Two R5 (thin) warnings are not defects but ride
along: `T1098.001/entra_app_federated_credential_backdoor` and
`T1528/entra_illicit_oauth_consent_grant` need a near-miss on a discriminating item
(for C4, the sign-in-only consent).

## Closing an entry

1. Fix the rule. If check-sufficiency waives the rule (`CHOKEPOINT`, `PRESENCE`,
   `COMPILE_ONLY`, `PLATFORM_NAMING`), the edit changes its digest, and a human
   re-approves the waiver.
2. Turn the evidence into a case: the probe or the KNOWN MISS confounder becomes a
   positive (false negative), or a filtered, near-miss or benign case (false
   positive).
3. Run `rule_cases.py`, `check_sufficiency.py`, the rule's validator and
   `score_benign.py --check --enforce`; regenerate `scores.json` with `--update`.
4. Propose the lower budget (`score_benign.py --reseeds 10`) or the move to
   `enforce` in `budgets.json`, which a human approves, and update its `why`.
5. Delete the entry here, and the pointer to it in the sidecar `why`.

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
