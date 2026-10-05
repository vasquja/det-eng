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

The validator runs each atomic and asserts that its paired Sigma rule's
SYSCALL selections match the resulting audit events.

```
# Real validation — needs root and a running auditd:
sudo python3 detections/validate_detections.py

# Parse rules and compile atomics only — no auditd needed:
python3 detections/validate_detections.py --dry-run
```

Without root or auditd the script SKIPS (exit 0), so it is safe in CI on
hosts that have no auditd. It needs `gcc` always, and `auditctl`, `ausearch`,
`ausyscall` for a real run.

### What the validator checks

- It confirms the **positive** match: the required syscall(s) and their
  `a0`/`a1`/`a2` argument values appear in the audit log for the process that
  ran the atomic.
- It does **not** re-apply a rule's process allowlist (`... and not comm`).
  The validator's binaries use a `deteng_` process name that is in no
  allowlist, so the allowlist never changes the "does it fire" answer. Tuning
  the allowlist against your own fleet is a separate, operational step.

## Continuous validation (CI)

`.github/workflows/validate-detections.yml` runs this loop on every push and
pull request. A standard `ubuntu-latest` runner is a full VM, so the audit
subsystem is available to root. The job installs auditd, loads the rules, and
runs the validator with `--report`. In `--report` mode only a compile or parse
ERROR fails the job; a detection that does not fire (for example because the
runner kernel has io_uring or AF_ALG turned off) is reported in the job
summary, not treated as a defect. On a public repository the run is free.

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

## Status

All Sigma rules are `status: experimental`. Levels are set by how rare the
syscall is: `high` where it is genuinely unusual (userfaultfd, memfd->execveat,
setns), `medium` where benign software also uses it (splice, raw sockets,
add_key, perf_event_open, io_uring, bpf). The `medium` rules ship with a
process allowlist and documented false positives; baseline them before you
alert.
