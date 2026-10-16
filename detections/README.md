# Detections

Sigma rules for the behavioral atomics, plus the pieces that prove each rule
fires on its paired atomic.

> **Source of truth:** each rule here should trace back to a detection
> strategy in a Technique Research Report under [`../research/`](../research/README.md).
> A rule keys on an invariant chokepoint when one exists (one rule, many
> procedures); it falls back to a per-procedure rule only where no chokepoint
> covers the procedure. See the worked example:
> [`research/trr9001/lin`](../research/trr9001/lin/README.md).

## How a rule earns its place

Firing on its own attack emulation is not enough. A rule can do that and still
be noisy on normal activity, or have tests so easy that they prove nothing.
So every rule must pass four kinds of check:

1. **It fires on the attack.** The validators run the technique's emulation
   (on a real auditd VM, a live `kind` cluster, or recorded cloud audit logs)
   and check that the rule matches the telemetry it produced.
2. **Its tests are hard to fake.** Next to each rule is a test file
   (`<rule>.cases.jsonl`) with **near-miss** examples: events that look almost
   exactly like the attack but are wrong in one key detail. A checker proves
   each near-miss really is one detail away from firing the rule, and fails a
   rule whose tests are trivial, or that only works because it matches the
   emulation's own file or process names. See
   [Rule test cases and the sufficiency gate](#rule-test-cases-and-the-sufficiency-gate).
3. **It stays quiet on ordinary activity.** Every rule is run over a library of
   realistic normal activity (admin work, CI jobs, Kubernetes controllers,
   cloud console use) and gets a hit **budget**. Going over the budget fails CI,
   and the scores are saved, so any change in a rule's noise shows up in review.
   See [The benign corpus](#the-benign-corpus-false-positive-scores).
4. **Its failures explain themselves.** When a check fails, it names the
   event, the field, the value it saw and what the rule wanted, so the fix
   starts from evidence. See [Explained failures](#explained-failures).

CI also compares each pull request with `main`, so tests cannot be quietly
deleted or weakened, and a rule cannot quietly get noisier.

When these checks were first run against the existing rules, they found
problems the old tests had missed: attack variants a rule misses, and routine
activity a rule fires on. Each one is recorded, with its evidence and the
proposed fix, in [`RULE_DEFECTS.md`](RULE_DEFECTS.md) until the rule is fixed.

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
  it: a pipe created in one process and spliced into by a forked child (two
  pids), `memfd_create` and `fexecve` in different processes, a
  `bpf(BPF_PROG_LOAD)` the kernel rejects, and a `SOCK_STREAM` socket against the
  raw-socket rule.
- **Allowlisted names**: each atomic whose rule has a `not <allowlist>` filter
  is re-run under a process name from that allowlist (e.g. `tcpdump`), and the
  filter must suppress it.

Each mutant also declares the condition item it is built to break: for example
`afinet_raw_socket.a1`, `group-by` (both halves of a correlation in different
pids), or `success` (the validator's own success=yes gate, for a syscall the
kernel rejects). The validator grades the mutant's own succeeded syscalls against
the rule (see [Explained failures](#explained-failures)). It warns when the mutant
holds for a different reason than the one it claims, because a control that is
`distant` from the rule does not test the rule. A mutant whose process tree made
no audited syscall at all is **vacuous**: it proves nothing about the rule, so it
counts as a broken control and fails the run.

### Event schema the rules assume

One event per auditd `SYSCALL` record: `type`, `syscall` (the **name**),
`success`, `exit`, `a0`..`a3` (raw hex, exactly as auditd logs them), `pid`,
`ppid`, `comm`, `exe`, `timestamp`. auditd's `ENRICHED` log format carries the
syscall name (`SYSCALL=`); with `RAW` format the validator resolves it with
`ausyscall`. `comm` and `exe` are text: the kernel logs a value that holds a
space, a double quote or a non-printable byte as unquoted uppercase hex
(`comm=417474616368204C697374656E6572`), and the validator decodes it
(`Attach Listener`). Neither raw `audit.log` (`syscall=41`) nor `ausearch -i`
output (`a0=packet`) has this shape as-is, so the log pipeline that feeds these
rules to a SIEM must normalize to it, or add a pySigma field-mapping pipeline.

### Correlation rules

A Sigma condition such as `A and B` is evaluated against **one** event, and an
auditd event records one syscall. So a two-syscall pattern (CopyFail,
DirtyFrag xfrm, DirtyPipe, memfd -> execveat) is written as a Sigma
correlation rule: each file holds a `type: temporal` correlation grouped by
`pid` plus the base rules it references. A backend without correlation support
cannot run these four rules.

### Two deliberate pass/fail changes

This validator's verdicts changed in two places against the base of this work
(`ed8c3b6`), both on purpose:

1. **A vacuous control fails the run.** At the base, a control whose process tree
   made no audited syscall counted as held, which is a pass. Now it counts as
   broken, because a control that never reached the audit log tests nothing (for
   example, a mutant that crashes before its first syscall).
2. **Hex-encoded `comm` and `exe` are decoded.** At the base, a rule or an
   allowlist saw the hex string for any process name with a space (a JVM thread
   such as `Attach Listener`, a Firefox content process) or for runc's
   `/memfd:runc_cloned:/proc/self/exe (deleted)` image. Now it sees the decoded
   name. A quoted value, and an unquoted value that is not uppercase hex (such as
   `(null)`), are left as they are.

## Rule test cases and the sufficiency gate

The controls above run live, and only for the Linux rules. Rules on every
platform also ship **offline test cases next to them**:
`sigma/<T>/<stem>.cases.jsonl`, one JSON object per line. A cloud rule without a
sidecar takes its verified negatives from the records of its hard benign fixture,
and its rename-test positives from its attack fixture. Each case is a small event
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

- **R0** cannot be split into items, or sits in a `detections/sigma/` that holds
  anything but `*.md` notes and `T<id>/` directories of `*.yml`, `*.cases.jsonl`
  and `*.md`. The rules directory shares the `sigma` package namespace with
  pySigma, so a stray `.py` there would replace pySigma modules. R0 also fails on
  anything in `detections/` or `detections/__pycache__/` named `sigma.*` (a
  `sigma.py` or `sigma.pyc` beside the directory would replace pySigma whole), and
  on any compiled module directly in `detections/`: a name ending in a bytecode or
  extension-module suffix of the running interpreter (on Linux `.pyc`, `.so`,
  `.abi3.so` and `.cpython-3XX-<platform>.so`). A gate run as a script has `detections/`
  first on `sys.path`, so a sourceless `yaml.pyc` there would replace PyYAML, or a
  standard-library module of its name, in every gate, and a binary cannot be
  reviewed. The usual `__pycache__/<module>.cpython-*.pyc` files are allowed.
  `check_sufficiency.py` imports the standard library before `detections/` is on
  `sys.path`, so R0 runs before such a file can be imported. `sigma_eval.py`
  refuses to load in each of these cases too, but its guard runs only when it is
  first imported. It cannot stop a module that a script imports before it
  (`validate_detections.py` and `sigma_explain.py` import PyYAML first, and the
  other gates import some of the standard library first), a plain-source
  `detections/<name>.py`, or a package directory. None of those paths is content,
  so `automerge` turns on auto-merge for them only after a human approves.
- **R1** has no registered positive in a validator `MANIFEST`, or declares a log
  source other than the one that validator proves it on (auditd: `linux/auditd`;
  API server and TRR9003: `kubernetes/audit` or `kubernetes/cri`, as the entry
  says; TRR9002: `kubernetes/audit`; cloud: the entry's provider). The benign
  corpus scores a rule only on the slices of its log source, so a rule moved to
  another log would escape its budget. A documented telemetry gap is listed in
  `COMPILE_ONLY` and still needs a sidecar positive.
- **R2** has no **verified** negative that breaks a *discriminating* item or a
  filter. A verified negative is a near-miss or filtered case, from the rule's
  cases or (cloud) its hard benign fixture. A no-op, an unrelated event or a
  pre-emulation baseline does not count, and neither does a negative that breaks
  only the surface (`syscall`, `verb`, `eventName`). A correlation is checked base
  by base: each base that has a discriminating item needs its own verified
  negative, a set declared `breaks: [base:<name>]` in which one event misses that
  base by one such item and, marked as the base's match, makes the compiled
  correlation fire (so it is in the right group and window).
- **R3** has a failing or unparsable case, or a sidecar exists without its rule.
- **R4** keys on the emulation's naming: its detection names an emulation
  literally (`trr9NNN`, `deteng_`); or the rename test stops it firing; or it has
  no positive to rename; or none of its positives carries an emulation identity,
  so the test renamed nothing (a `COMPILE_ONLY` rule is excused); or every
  verified negative breaks only items that the rename flips. The test renames
  every emulation identity in each positive unit:
  - every passing sidecar positive;
  - for a rule the auditd validator runs, a copy of each such positive in which
    every event carries the `exe` and `comm` that the validator's run of each of
    the rule's atomics writes (`/tmp/deteng_val_<8 random>/deteng_<atomic stem>`
    and its first 15 characters), used only if that copy fires;
  - for cloud, each attack record that fires and carries the gate's marker.

  An identity is an emulation name or a gate marker plus the rest of its token,
  so `deteng_afxdp_socket_behavioral` and `trr9026-target` are renamed whole. Each
  unit is renamed twice, with replacements drawn at random for each run, and must
  fire after both. *Same-shape* swaps every letter and digit for another of its
  class, one random substitution for the run. *Neutral* turns each identity into
  random lowercase letters 3 to 8 characters longer. The failure names the original
  identities and which rename stopped the rule, never the replacement. A cloud
  rule's validator gate must also be a `marker(...)`. Not renamed: what precedes
  the name in its token (the AWS key type in `AKIATRR9012...`), source IPs,
  account or instance ids and timestamps. Outside the auditd rules the units are
  the sidecar and the attack fixtures as written, so a positive that carries an
  identity only in a field the rule does not read passes too. A human reviewer
  must catch a rule keyed on any of those.

Four waiver tables exist in `check_sufficiency.py` (a protected path, so a human
approves every entry). Each entry is the reason plus the digest of the rule content
the human approved: the rule's `name`, `id`, `logsource`, `detection` and
`correlation` blocks. When any of those changes, the waiver stops excusing the rule,
and the gate prints the new digest for a human to re-approve. Its `level`,
`status`, `description`, tags and comments are not part of the digest.

- `COMPILE_ONLY` (R1): CI collects no telemetry for the rule; a sidecar positive
  is still required.
- `CHOKEPOINT` (R2): every positive item is a surface field because the record
  kind itself is the technique (any `add_key`, any Events delete). Any verified
  negative then counts. One base of a correlation is waived as `<rule> base:<name>`.
- `PRESENCE` (R2): one positive item and no filter (any impersonated request, any
  static-pod sandbox). No negative can be one item from firing, so the proof is the
  positive case and the rule's benign-corpus budget.
- `PLATFORM_NAMING` (R4): the rule keys on a platform's naming template that
  follows the emulation's name (Cognito's `Cognito_<pool>Unauth_Role`); the rename
  keeps the named substrings (`Unauth`).

It warns (never fails) about *thin* checks (**R5**): rules that exercise fewer than
half as many of their condition items as the median rule of their platform (over
the rules that have any verified negative), or whose negatives break only filters
(or only surface items and filters) and no discriminating selection item.

With `--baseline FILE` (the base branch's `--json` report) it also runs the
**ratchet**. The report records every sidecar case by name, with its kind and a
digest (sha256 of its kind, `breaks` and events, not its `why`), and a digest of
every verified negative (its case's, or a cloud fixture record's canonical JSON).
The ratchet fails when:

- a rule of the base is not on the head (deleted or renamed);
- a sidecar case of the base, of any kind, is gone or its kind, `breaks` or
  events changed;
- a verified negative of the base is gone or changed. A fixture negative is named
  by its record's index, so a moved record counts as gone;
- a rule has fewer verified negatives, has lost an item those negatives
  exercised, has fewer passing positive cases, has lost its sidecar, or has
  changed its logsource (or a correlation base's: a moved rule is scored on other
  slices and budgets).

New cases and new rules pass, and so does rewording a case's `why`. A base report
from an older copy of the script carries no digests: the ratchet then compares
those rules' cases and negatives by count and name only, and prints a note saying
so. Not compared: the rule's own detection (a broadened rule that keeps every case
passes here; its near-miss cases and the benign comparison below guard it), and
fixture records that are not verified negatives.

CI's `sufficiency-ratchet` job runs it on every pull request, with the base
branch's own copy of the script. The same job then runs the head's
`score_benign.py --baseline-scores` against the base branch's committed
`benign/scores.json`, and fails when a rule raises more benign hits than there,
even inside its budget. Sidecars, rules and `scores.json` are content, for which
`automerge` turns on auto-merge without a human, so the ratchet is what sends a pull
request that deletes or edits a case, deletes or renames a rule, or makes a rule
noisier to a human instead. It is not a required check of the `main` ruleset, so it
stops the bot's merge only if it has failed when an `automerge` evaluation runs,
before the required checks finish; if they finish first, GitHub merges (see
[Branch protection](benign/README.md#branch-protection-what-binds-a-manual-merge)).

A case that shows a rule defect stays as it is. Record the defect in
[`RULE_DEFECTS.md`](RULE_DEFECTS.md), the tracker for the next rule-fix pull
request, and never weaken the case.

```
python3 detections/rule_cases.py --atoms detections/sigma/T1040/afinet_raw_socket.yml  # the items `breaks` can name
python3 detections/rule_cases.py                     # every rule's cases
python3 detections/check_sufficiency.py              # the gate (CI: detection-quality / check-sufficiency)
```

## The benign corpus (false-positive scores)

The hard gate answers "does the rule key on the technique?". The **benign corpus**
([`benign/`](benign/README.md)) answers the production question: "how often does it
fire on ordinary activity?". [`score_benign.py`](score_benign.py) runs every rule
over versioned slices of benign activity (admin, developer, CI/CD, controller and
service traffic, including legitimate near-miss tools). Every committed slice is
synthetic today, generated from templates modelled on documented real activity, so
a rule's hits there are presence indicators, not production rates. It reports
hits, the rate per 10,000 events, and the distinct processes or principals behind
them. Per-rule budgets decide whether an overrun is a warning (`shadow`) or a
failure (`enforce`). A committed snapshot (`benign/scores.json`) makes every change
in a rule's false-positive count visible in review. A budget leaves headroom above
a rule's hits at the committed seed, so on a pull request `sufficiency-ratchet`
also fails any rule with more hits than in the base branch's snapshot (fewer hits
pass). The kind cluster's
pre-emulation audit log and a live Ubuntu-runner workload are scored in CI too, in
shadow mode. A hit that a rule defect explains is tracked in
[`RULE_DEFECTS.md`](RULE_DEFECTS.md).

```
python3 detections/score_benign.py                  # report
python3 detections/score_benign.py --check --enforce  # what CI runs
python3 detections/score_benign.py --baseline-scores base-scores.json  # any rule noisier than that snapshot? (CI: sufficiency-ratchet)
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

## Continuous validation (CI)

`.github/workflows/validate-detections.yml` runs this loop on every pull request,
on push to `main`, and weekly. A standard `ubuntu-latest` runner is a full VM, so
the audit subsystem is available to root. The job installs auditd and the Python
requirements, then runs the validator with `--require-audit`. It is strict: a
detection FAIL, a broken control or a vacuous control fails the job; only a
probe-confirmed SKIP does not. On a public repository the run is free.

`.github/workflows/detection-quality.yml` runs the offline layers on every pull
request, on push to `main`, and weekly: `rule-cases`, `check-sufficiency`,
`sufficiency-ratchet` (pull requests only), `benign-corpus`
(`score_benign.py --check --enforce`) and the shadow `benign-linux-live` capture.

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
`clientConfig`; an update, patch or delete of the three `kube-system` DNS
ConfigMaps (`coredns`, `kube-dns`, `coredns-custom`) is at `Request` so the Corefile
is present (a create names no object when the policy is evaluated, so it is logged
at `Metadata` with no body: [`RULE_DEFECTS.md`](RULE_DEFECTS.md) P2); Secrets and
`serviceaccounts/token` stay at `Metadata`, never higher, because `RequestResponse`
would copy the Secret data and the signed token into the log.

These rules are intentionally generic, and a fresh `kind` cluster is full of
baseline matches: bootstrap RBAC writes, controller-created Jobs and Pods,
controller Secret reads, the kube-proxy and kindnet privileged pods, and the
bootstrap coredns ConfigMap. So the validator gates each rule on the emulation's
own marker — a `trr9004-`/`trr9005-`/`trr9007-`/`trr9025-`/`trr9026-` object name,
the `trr9006` namespace with a non-system caller, a `trr9005-` Job label on the node
sensor, or the `trr9027` sentinel in procedure A's DNS-ConfigMap patch (procedures
B and C create their ConfigMaps, which are logged with no body, so this validator
proves TRR9027 on procedure A only) — and the negative control proves a pass depends
on the emulation, not the baseline.

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
