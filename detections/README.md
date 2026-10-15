# Detections

Sigma rules for the behavioral atomics, plus the pieces that prove each rule
fires on its paired atomic.

> **Source of truth:** each rule here should trace back to a detection
> strategy in a Technique Research Report under [`../research/`](../research/README.md).
> A rule keys on an invariant chokepoint when one exists (one rule, many
> procedures); it falls back to a per-procedure rule only where no chokepoint
> covers the procedure. See the worked example:
> [`research/trr9001/lin`](../research/trr9001/lin/README.md).

## The three layers

1. **Atomic** (`atomics/<TECH>/`) — the stimulus. It emits the syscall
   pattern of an exploit or abuse primitive, then stops before any harm.
2. **Audit rules** (`audit/atomic.rules`) — make the telemetry exist. On a
   default auditd install the relevant syscalls are not logged, so a Sigma
   rule has nothing to match. Load this file first.
3. **Sigma rule** (`sigma/<TECH>/`) — what to look for in the audit events.

The atomic does not, by itself, prove the Sigma rule works. Layer 2 makes the
behavior visible; the validator below checks that layer 3 matches it.

## Validate (atomic -> telemetry -> rule fires)

The validator runs each atomic, turns the resulting audit records into events,
and runs the paired Sigma rule over them **with a real Sigma backend**: pySigma
compiles the rule (plain or correlation) to SQL with its SQLite backend, and
the validator executes that query (see `sigma_eval.py`). It does not
re-implement Sigma matching by hand.

```
pip install -r detections/requirements.txt   # pySigma + SQLite backend, PyYAML

# Real validation + controls — needs root and a running auditd:
sudo python3 detections/validate_detections.py

# Compile the rules (pySigma) and the atomics only — no auditd needed:
python3 detections/validate_detections.py --dry-run
```

Without root or auditd the script SKIPS (exit 0), unless `--require-audit` is
given (CI passes it, so a broken audit setup fails instead of passing). It
needs `gcc` always, and `auditctl` and `ausyscall` for a real run.

### What a PASS means

A case passes only if all three hold:

1. **The rule matches, as Sigma defines it.** The backend evaluates the full
   condition, including the `not <allowlist>` filters and correlation windows.
2. **The match came from the atomic.** Every event behind the hit belongs to
   the atomic's process tree, so nothing else running in the window (the
   validator itself included) can satisfy the rule.
3. **The syscalls succeeded** (`success=yes`). A syscall the kernel rejected is
   an attempt, not an execution of the technique.

A miss is a **SKIP** only when an independent kernel-feature probe, run before
the test, shows the kernel lacks what the technique needs (no AF_ALG or
AF_RXRPC, io_uring disabled, Yama ptrace_scope 3, ...). Every other miss is a
**FAIL** and fails the run.

### Controls: testing the test

After the detections, the validator runs stimuli that must **not** pass. If one
does, the check above is unsound and the run fails:

- **No-op** (`controls/noop.c`), evaluated against every rule.
- **Mutants** (`controls/*.c`) that keep the surface of a technique but break
  it: a `splice()` with no `pipe()` of its own, `memfd_create` and `fexecve`
  in different processes, a `bpf(BPF_PROG_LOAD)` the kernel rejects, and a
  `SOCK_STREAM` socket against the raw-socket rule.
- **Allowlisted names**: each atomic whose rule has a `not <allowlist>` filter
  is re-run under a process name from that allowlist (e.g. `tcpdump`), and the
  filter must suppress it.

Each mutant also declares the condition item it is built to break, for example
`afinet_raw_socket.a1`. The validator grades the mutant's closest event against
the rule (see [Explained failures](#explained-failures)). It warns when the mutant
holds for a different reason than the one it claims, because a control that is
`distant` from the rule does not test the rule.

## Rule test cases and the sufficiency gate

The controls above run live, and only for the Linux rules. Every rule, on every
platform, also ships **offline test cases next to it**:
`sigma/<T>/<stem>.cases.jsonl`, one JSON object per line. Each case is a small event
set in the rule's own log shape, with a declared kind:

| kind | expectation |
|------|-------------|
| `positive` | the rule fires (the telemetry its emulation produces) |
| `near-miss` | no match; keeps the technique's surface and breaks exactly one required item, named in `breaks` |
| `filtered` | no match; every selection holds and one `not <filter>` item alone suppresses it |
| `confounder` | no match; a realistic legitimate look-alike (must share the rule's surface) |
| `benign` | no match; anything |

`rule_cases.py` runs the cases through the same pySigma backend as the
validators. It also uses [`sigma_explain.py`](sigma_explain.py) to verify that each
`near-miss` / `filtered` case really is one item away from firing, on the exact item
it declares. An unrelated event cannot pass as a near-miss.

`check_sufficiency.py` is the gate on top. It fails a rule that:

- has no registered positive in a validator `MANIFEST` (documented telemetry gaps are
  listed in its `COMPILE_ONLY`, and still need a sidecar positive);
- has no **verified** near-miss or filtered negative, from its cases or (cloud) its
  hard benign fixture. A no-op, an unrelated event or a pre-emulation baseline does
  not count;
- has a failing case;
- (cloud) has near-misses that flip only the emulation's marker fields, so its
  negatives differ from the attack only in naming.

It also warns about *thin* checks: rules that exercise far fewer of their condition
items than the median rule of their platform.

```
python3 detections/rule_cases.py --atoms sigma/T1040/afinet_raw_socket.yml  # the items `breaks` can name
python3 detections/rule_cases.py                     # every rule's cases
python3 detections/check_sufficiency.py              # the gate (CI: detection-quality / check-sufficiency)
```

## The benign corpus (false-positive scores)

The hard gate answers "does the rule key on the technique?". The **benign corpus**
([`benign/`](benign/README.md)) answers the production question: "how often does it
fire on ordinary activity?". [`score_benign.py`](score_benign.py) runs every rule
over versioned slices of benign operational activity (admin, developer, CI/CD,
controller and service traffic, including legitimate near-miss tools). It reports
hits, the rate per 10,000 events, and the distinct processes or principals behind
them. Per-rule budgets decide whether an overrun is a warning (`shadow`) or a
failure (`enforce`). A committed snapshot (`benign/scores.json`) makes every change
in a rule's false-positive count visible in review. The kind cluster's
pre-emulation audit log and a live Ubuntu-runner workload are scored in CI too, in
shadow mode.

```
python3 detections/score_benign.py                  # report
python3 detections/score_benign.py --check --enforce  # what CI runs
```

## Explained failures

A red run says *why* it failed. Every validator prints, under each failing line:

- the match count of every detection block and item, over all events or the
  emulation's own events;
- the nearest event, item by item, with the values it carried;
- a hint when the rule reads a field that no event carries (an audit level or
  field-name problem rather than rule logic).

A broken control prints the events behind its hit. A Linux case prints its
kernel-probe result. `--json PATH` writes the same results machine-readably for an
agent to parse.

### Event schema the rules assume

One event per auditd `SYSCALL` record: `type`, `syscall` (the **name**),
`success`, `exit`, `a0`..`a3` (raw hex, exactly as auditd logs them), `pid`,
`ppid`, `comm`, `exe`, `timestamp`. auditd's `ENRICHED` log format carries the
syscall name (`SYSCALL=`); with `RAW` format the validator resolves it with
`ausyscall`. Neither raw `audit.log` (`syscall=41`) nor `ausearch -i` output
(`a0=packet`) has this shape as-is, so the log pipeline that feeds these rules
to a SIEM must normalize to it, or add a pySigma field-mapping pipeline.

### Correlation rules

A Sigma condition such as `A and B` is evaluated against **one** event, and an
auditd event records one syscall. So a two-syscall pattern (CopyFail,
DirtyFrag xfrm, DirtyPipe, memfd -> execveat) is written as a Sigma
correlation rule: each file holds a `type: temporal` correlation grouped by
`pid` plus the base rules it references. A backend without correlation support
cannot run these four rules.

## Continuous validation (CI)

`.github/workflows/validate-detections.yml` runs this loop on every push and
pull request. A standard `ubuntu-latest` runner is a full VM, so the audit
subsystem is available to root. The job installs auditd and the Python
requirements, then runs the validator with `--require-audit`. It is strict: a
detection FAIL or a broken control fails the job; only a probe-confirmed SKIP
does not. On a public repository the run is free.

## Manual run

```
sudo auditctl -R detections/audit/atomic.rules   # load (root)
# ... run an atomic from atomics/<TECH>/ ...
sudo grep 'key="det-eng"' /var/log/audit/audit.log   # read the telemetry
# or, where ausearch resolves its log path:
sudo ausearch -if /var/log/audit/audit.log -k det-eng -i
```

Note: the validator reads `/var/log/audit/audit.log` directly instead of
calling `ausearch`. On some hosts (GitHub-hosted runners among them)
`ausearch` resolves its default log path to nothing and reports no matches
even though the records are present in the file.

## Kubernetes detections (TRR9002)

The Kubernetes rules (`sigma/T1609/`) key on the API server **audit log**, not
on syscalls, so they have their own layer stack and validator:

1. **Emulation** (`atomics/T1609/`) — `emulate.sh` runs the benign command `id`
   through each control path (exec, attach, ephemeral container, node proxy,
   direct kubelet).
2. **Audit policy** (`k8s/audit-policy.yaml`) — makes the telemetry exist. A
   default cluster writes no audit log, so a rule has nothing to match. The
   `k8s/kind-audit-cluster.yaml` config mounts it into a `kind` cluster.
3. **Sigma rule** (`sigma/T1609/`) — what to look for in the audit events.

Validate the loop (emulate -> audit -> rule fires):

```
# Compile the rules only — no cluster needed:
python3 detections/validate_k8s_detections.py --dry-run

# Full run against an audit log you collected from the cluster:
python3 detections/validate_k8s_detections.py \
  --audit-log /tmp/kube-apiserver-audit.log

# Negative control, on a log collected BEFORE the emulation ran:
python3 detections/validate_k8s_detections.py \
  --audit-log /tmp/pre-emulation-audit.log --expect-miss
```

The audit log is flattened to the dotted field names the rules use
(`objectRef.resource`, `user.username`, ...) and each rule runs through the
same pySigma backend as the auditd rules. A rule passes only on an event from
the emulation itself (one naming the target pod), not on any event in the log.

`.github/workflows/validate-k8s-detections.yml` runs the whole loop on a `kind`
cluster for every change to the TRR9002 files, strict: a rule that does not
fire fails the job, because the `kind` emulation is deterministic. It also
captures the audit log before the emulation and runs the validator on it with
`--expect-miss`, so a pass that does not depend on the emulation fails the job.
`validate_staticpod_detections.py` and
`.github/workflows/validate-staticpod-detections.yml` do the same for TRR9003
(T1543.005), where the gate matters most: both of its rules also match the
control-plane static pods every node starts, so only the emulation's own pods
count.

### Node runtime sensor (TRR9003 Strategy 1)

A static pod never passes through the API server, and the invalid-namespace
variant leaves no pod object at all, so the chokepoint rule
(`sigma/T1543.005/k8s_cri_static_pod_start.yml`) reads the node's container
runtime instead: a pod sandbox whose `kubernetes.io/config.source` annotation is
`file` or `http`, which the kubelet sets itself on every pod it runs (`api` for
a scheduled pod).

- **Log source.** Sigma has none for this, so the rule declares
  `product: kubernetes`, `service: cri`: one record per pod sandbox with the CRI
  `PodSandbox` fields, flattened to dotted names (`metadata.name`,
  `metadata.namespace`, `state`, `labels.*`,
  `annotations.kubernetes.io/config.source`, ...). A runtime security or EDR
  agent with container context reports these when a sandbox starts; map its
  field names to these.
- **Lab sensor.** `k8s/cri-pod-sensor.sh` polls `crictl pods -o json` on the
  node and appends one snapshot per line; the validator keeps each sandbox's
  first sighting. It is a stand-in for a real agent, good enough to prove the
  rule on real runtime data.
- **Validation.** The CRI rule must match both the injected static pod and the
  invalid-namespace pod, and must match none of the API-scheduled sandboxes in
  the same log:

```
python3 detections/validate_staticpod_detections.py \
  --audit-log /tmp/kube-apiserver-audit.log --cri-log /tmp/cri-pods.jsonl
```

## Kubernetes API server detections (TRR9004–9010, 9025–9027)

Several more Kubernetes techniques key on the same API server **audit log**, so one
shared `kind` cluster, one audit policy (`k8s/audit-policy-apiserver.yaml`), one
validator (`validate_apiserver_detections.py`), and one workflow
(`.github/workflows/validate-apiserver-detections.yml`) cover them all:

| TRR | Technique | Chokepoint rule(s) | Audit level |
|-----|-----------|--------------------|-------------|
| TRR9004 | RBAC (T1098.006) | `sigma/T1098.006/k8s_rbac_write.yml` + a Request-level severity rule | Request |
| TRR9005 | Jobs/CronJobs (T1053.007) | `sigma/T1053.007/k8s_job_create.yml` + a node-runtime job-pod rule | Request |
| TRR9006 | Secrets (T1552.007) | `sigma/T1552.007/k8s_secret_access.yml` + a TokenRequest rule | Metadata |
| TRR9007 | Dangerous pod spec (T1611) | `sigma/T1611/k8s_podspec_host_access.yml` + a controller rule | Request |
| TRR9008 | Disable admission control (T1685) | `sigma/T1685/k8s_admission_webhook_disabled.yml` + a neuter grader + a workload-removal rule | Request |
| TRR9009 | Impersonation (T1134) | `sigma/T1134/k8s_impersonation.yml` + a privileged-target rule | Metadata |
| TRR9010 | Indicator removal (T1070) | `sigma/T1070/k8s_events_deleted.yml` + a workload-deletion rule | Metadata |
| TRR9025 | Malicious admission webhook (T1546) | `sigma/T1546/k8s_admission_webhook_created.yml` + a Request-level body grader | Request |
| TRR9026 | Pod port-forward (T1572) | `sigma/T1572/k8s_pod_portforward.yml` (verb-agnostic subresource) | Metadata |
| TRR9027 | Cluster DNS poisoning (T1565.001) | `sigma/T1565.001/k8s_coredns_configmap_modified.yml` + a Request-level Corefile grader | Metadata + Request |

The audit **level** is per technique: pods, workload controllers, RBAC, and
admission-webhook creates are logged at `Request` so `requestObject` carries the
privileged/hostPath fields, the bound role, the group subject, and the webhook
`clientConfig`; `kube-system` ConfigMap writes are at `Request` so the CoreDNS
Corefile is present; Secrets and `serviceaccounts/token` stay at `Metadata`, never
higher, because `RequestResponse` would copy the Secret data and the signed token
into the log.

These rules are intentionally generic, and a fresh `kind` cluster is full of
baseline matches: bootstrap RBAC writes, controller-created Jobs and Pods,
controller Secret reads, the kube-proxy and kindnet privileged pods, and the
bootstrap coredns ConfigMap. So the validator gates each rule on the emulation's
own marker — a `trr9004-`/`trr9005-`/`trr9007-`/`trr9025-`/`trr9026-` object name,
the `trr9006` namespace with a non-system caller, a `trr9005-` Job label on the node
sensor, or the `trr9027` sentinel in a DNS-ConfigMap write — and the negative
control proves a pass depends on the emulation, not the baseline.

```
python3 detections/validate_apiserver_detections.py --dry-run     # compile only
python3 detections/validate_apiserver_detections.py \
  --audit-log /tmp/kube-apiserver-audit.log --cri-log /tmp/cri-pods.jsonl
```

TRR9006 Procedure E (reading an already-mounted token off disk) and the TRR9007
static-pod delivery bypass the API server, so they leave no audit event. Their
rules (`sigma/T1552.007/linux_k8s_sa_token_read.yml`, and TRR9003's CRI rule for
the static pod) are compiled but not match-gated here; the emulations document the
gaps the way TRR9002 Procedure E does.

## External cloud detections (TRR9011–9015)

Five techniques key on a cloud provider's audit log instead of Linux syscalls or the
Kubernetes API server, so they have their own validator
(`validate_cloud_detections.py`) and workflow (`validate-cloud-detections.yml`):

| TRR | Technique | Log | Chokepoint rule |
|-----|-----------|-----|-----------------|
| TRR9011 | IMDS creds used off-instance (T1552.005, AWS) | CloudTrail | `sigma/T1552.005/aws_imds_creds_used_off_instance.yml` |
| TRR9012 | Leaked long-term access key (T1078.004, AWS) | CloudTrail | `sigma/T1078.004/aws_leaked_access_key_recon.yml` |
| TRR9013 | Entra federated-identity backdoor (T1098.001, Azure) | Entra audit + Azure Activity | `sigma/T1098.001/entra_app_federated_credential_backdoor.yml` + `azure_managed_identity_federated_credential_backdoor.yml` |
| TRR9014 | Public IAM exposure (T1098.003, GCP) | Cloud Audit Logs | `sigma/T1098.003/gcp_public_iam_member_grant.yml` |
| TRR9015 | GitHub-OIDC role-trust abuse (T1098.001, AWS) | CloudTrail | `sigma/T1098.001/aws_github_oidc_role_trust_abuse.yml` |

Cloud has no free live target to run the attacks against, so the loop is proven on
**recorded logs** rather than a live run. Each technique ships two committed,
schema-faithful fixtures under `cloud/fixtures/<trr>/` — an **attack** set and a hard
**benign** baseline. Every field path is a real field of the provider's audit log,
grounded on the provider's schema docs and real samples (see each TRR's References);
only safe markers are used (RFC 5737 TEST-NET IPs, RFC 2606 `example.com`, the AWS doc
account `123456789012`, and `trr90NN-` resource names). The validator runs each rule
through the **same pySigma SQLite backend** the Kubernetes validators use (`sigma_eval.py`),
and a technique passes only if the rule fires on its attack fixture (carrying the
emulation's marker) **and** matches nothing in the benign baseline.

The benign baseline is deliberately hard: it hits the same log source, method, and
structural fields as the attack and differs only on the discriminating field (the
off-instance source IP, the identity type, the FIC issuer, the public-vs-specific
principal, the pinned-vs-wildcard OIDC subject). So a pass proves the rule keys on the
technique's chokepoint, not on the fixture's shape or marker.

```
pip install -r detections/requirements.txt
python3 detections/validate_cloud_detections.py --dry-run   # compile every cloud rule
python3 detections/validate_cloud_detections.py             # attack fires + control holds
```

The runnable emulations (`atomics/<TECH>/src/`) perform the real attack in **your own**
cloud account, guarded by a `TRR90NN_LIVE=1` opt-in, and are **not run in CI** — they
need credentials and, for the data-plane / off-instance cases, cloud resources. The
committed fixtures are what CI validates, and each emulation can print its recorded
fixture with `--show-fixture`.

Because the nested list fields in these logs (CloudTrail `sessionContext` aside —
Azure `targetResources[]`, GCP `bindingDeltas[]`/`members[]`, and the URL-encoded AWS
trust policy) flatten to searchable text, the rules match those with `|contains` over
the flattened field, which is how a SIEM indexes nested JSON. The rule descriptions note
where a production pipeline should decode/parse a field (e.g. the URL-encoded IAM trust
policy) for a more precise match.

## Status

All Sigma rules are `status: experimental`. Levels are set by how rare the
syscall is: `high` where it is genuinely unusual (userfaultfd, memfd->execveat,
setns), `medium` where benign software also uses it (splice, raw sockets,
add_key, perf_event_open, io_uring, bpf). The `medium` rules ship with a
process allowlist and documented false positives; baseline them before you
alert.
