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
(T1543.005), where the gate matters most: the mirror-pod rule also matches the
control-plane static pods every node registers at start, so only the injected
static pod's event counts.

## Status

All Sigma rules are `status: experimental`. Levels are set by how rare the
syscall is: `high` where it is genuinely unusual (userfaultfd, memfd->execveat,
setns), `medium` where benign software also uses it (splice, raw sockets,
add_key, perf_event_open, io_uring, bpf). The `medium` rules ship with a
process allowlist and documented false positives; baseline them before you
alert.
