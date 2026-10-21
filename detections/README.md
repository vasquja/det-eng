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
   and check that the rule matches the telemetry it produced. A rule whose
   telemetry CI cannot collect is compiled and proven on its offline positive
   case instead, under a human-approved waiver.
2. **Its tests are hard to fake.** Next to most rules is a test file
   (`<rule>.cases.jsonl`) with **near-miss** examples: events that look almost
   exactly like the attack but are wrong in one key detail. A cloud rule without
   one takes its negatives from its hard benign fixture. A checker proves
   each near-miss really is one detail away from firing the rule, and fails a
   rule whose tests are trivial, or that only works because it matches the
   emulation's own file or process names. See
   [Rule test cases and the sufficiency gate](#rule-test-cases-and-the-sufficiency-gate).
3. **It stays quiet on ordinary activity.** Every rule that a benign slice can
   read is run over a library of realistic normal activity (admin work, CI jobs,
   Kubernetes controllers, cloud console use) and gets a hit **budget**; a rule
   that no slice reads is listed, with its reason, under `unscored` in
   `benign/budgets.json`. Going over the budget fails CI,
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
`ppid`, `uid`, `euid`, `auid`, `comm`, `exe`, `timestamp`. The ids are decimal text,
as the kernel sees them from the host (root in a user-namespace-remapped container
shows as its host uid), and an unset `auid` is `4294967295`. Allowlist entries for
tools that always run as root also require `euid` `0`, so code injected into those
tools by an ordinary user still fires; a pipeline that drops `euid` makes those
entries fire on the real tools instead of hiding them. auditd's `ENRICHED` log format carries the
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
- `PRESENCE` (R2): one positive item and no filter (any static-pod sandbox). No negative can be one item from firing, so the proof is the
  positive case and the rule's benign-corpus budget.
- `PLATFORM_NAMING` (R4): the rule keys on a platform's naming template that
  follows the emulation's name (Cognito's `Cognito_<pool>Unauth_Role`); the rename
  keeps the named substrings (`Unauth`).

It warns (never fails) about *thin* checks (**R5**): rules that exercise fewer than
half as many of their condition items as the median rule of their platform (over
the rules that have any verified negative), or whose negatives break only filters
(or only surface items and filters) and no discriminating selection item. When the
hint starts "No near-miss can break", no case can break the items it names (each is
the only selection item of its branch): add the filtered cases it names, if any, and
keep the warning. If the rule lacks an item that the technique really has (an event
type, a provenance field), record that as a rule defect in
[`RULE_DEFECTS.md`](RULE_DEFECTS.md).

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

## Portable regular expressions

The validators prove every rule with pySigma's SQLite backend, whose `REGEXP` is
Python's `re`. Python accepts constructs that other Sigma backends reject or read
differently, so every `|re` value must stay inside a subset that each main backend
runs with the same meaning. [`check_sigma_regex.py`](../.github/scripts/check_sigma_regex.py)
enforces it (CI: `validate-detections` / `sigma-lint`):

```
python3 .github/scripts/check_sigma_regex.py                # every |re value in detections/sigma
python3 .github/scripts/check_sigma_regex.py --require-re2  # also compile each one with RE2 (pip install google-re2)
```

**The subset** is the intersection of these sources:

| Source | What it allows |
|--------|----------------|
| [Sigma specification, modifiers appendix](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md) (`re`, sub-modifiers `i` `m` `s`) | "PCRE with the following metacharacters": `.`, `^ $`, `* + ? {n,m}`, `[a-z] [^a-z]`, `\|`, `()`; "other metacharacters are unsupported" |
| [RE2 syntax](https://github.com/google/re2/wiki/Syntax) (Go-based backends) and the [KQL regex dialect](https://learn.microsoft.com/kusto/query/regex) (Microsoft Sentinel) | RE2: no lookaround, no backreferences, no possessive quantifiers, no atomic groups, no `\Z`, repetition counts up to 1000. KQL documents its own dialect (lazy quantifiers, inline flags, `\<` `\>` word boundaries, class set operators), so the subset avoids the constructs whose meaning differs |
| [Lucene RegExp](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/util/automaton/RegExp.java) (Elasticsearch [`regexp` / `query_string`](https://github.com/elastic/elasticsearch/blob/main/docs/reference/query-languages/query-dsl/regexp-syntax.md) and ES\|QL `RLIKE`) | no anchors (a pattern matches the whole value), no `(?` groups or inline flags; `"` `#` `@` `&` `~` `<` `>` are operators; a backslash before a letter other than `d D s S w W` is an error (Lucene 9+) |
| Splunk (PCRE) | everything above |

So a `|re` value may use: literal characters; a backslash before a punctuation
character (a literal); `.`; `^` only as the first character and `$` only as the last;
greedy `* + ?` and `{n}` `{n,}` `{n,m}` (n, m at most 1000); `[...]` and `[^...]` with
ranges; `|`; plain `( )` groups; `\s` and `\S`; the sub-modifiers `|i` and `|s`. Written
differently:

| Construct | Write instead |
|-----------|---------------|
| `(?=` `(?!` `(?<=` `(?<!` lookaround | split the test into Sigma items, values or selections and combine them in the condition |
| `(?:...)` | `(...)` (no rule uses a backreference, so the groups match the same) |
| `(?i)` and other inline flags | the `\|re\|i` (or `\|re\|s`) sub-modifier |
| `\d` `\w` `\D` `\W` | `[0-9]` `[A-Za-z0-9_]` `[^0-9]` `[^A-Za-z0-9_]` (Python and KQL read the shorthand as Unicode classes) |
| `\n` `\t` `\x..` `\u....` | `\s`, `\S`, or a class such as `[^\S ]` (whitespace other than a space); Lucene rejects the escape, and a raw line break ends a KQL or SPL string literal |
| `\A` `\Z` `\z` `\b` | `^` first or `$` last; a class for a word edge |
| lazy `*?` or possessive `*+`, atomic `(?>` | the greedy form (a lazy quantifier does not change whether a regex matches) |
| bare `"` `#` `@` `&` `~` | `\"` `\#` `\@` `\&` `\~` (inside `[...]` they are plain) |
| bare `<` `>` | `[<]` `[>]` (`\<` is a word boundary in KQL) |
| a bare `{` `}` `]` outside a quantifier or class | `\{` `\}` `\]` |
| `[` and `&&` `--` `~~` `\|\|` inside a class | an escaped `\[`; KQL reads the pairs as set operators |
| a value over 1000 characters | Elasticsearch's `index.max_regex_length` default; split it |

**Differences no lint removes.** A backend must still translate the edges. A check with
pySigma 1.5.1 (`pySigma-backend-elasticsearch` 2.1.1) and Lucene 10.1 found these:

- **Anchors.** Lucene has no anchors and matches the whole value, so a search-style
  `|re` needs `.*` around it (drop it where the pattern starts with `^` or ends with
  `$`). pySigma's Lucene backend does not add it today.
- **Case folding.** pySigma renders `|re|i` as an inline `(?i)` for Lucene, ES|QL
  `RLIKE` and EQL `regex~`. Lucene reads `(?i)` as the literal characters `?i`, with no
  error, so a converted `|re|i` value never matches. Use the regexp query's
  `case_insensitive` flag, or fold the case with classes (`[hH][tT][tT][pP]`), as
  `T1546/k8s_admission_webhook_repointed_to_url.yml` does for its URL scheme. These
  rules still use `|re|i`: `T1611/k8s_podspec_host_access.yml` and
  `T1611/k8s_podspec_controller_host_access.yml` (the capability names),
  `T1098.001/azure_managed_identity_federated_credential_backdoor.yml` and
  `T1537/aws_efs_file_system_policy_made_public.yml`.
- **A `/` in a field name.** pySigma's Lucene backend does not escape `/` in a field
  name, and `query_string` reads it as the start of a `/regex/` term, so the query does
  not parse. Escape it as `\/`. The keys are annotation and label keys
  (`kubectl.kubernetes.io/last-applied-configuration`,
  `seccomp.security.alpha.kubernetes.io/pod`, `batch.kubernetes.io/job-name`,
  `kubernetes.io/config.source`) and strategic-merge directive keys
  (`$deleteFromPrimitiveList/<name>`). The rules: `T1611/k8s_podspec_confinement_disabled.yml`,
  `T1685/k8s_enforcer_workload_removed.yml`, `T1685/k8s_security_tool_workload_removed.yml`,
  `T1053.007/k8s_cri_job_pod.yml` and `T1543.005/k8s_cri_static_pod_start.yml`. KQL
  needs bracket access (`requestObject.spec['$deleteFromPrimitiveList/replicas']`) for a
  key with `.`, `/` or `$`.
- **`|exists` on EQL.** pySigma's EQL backend cannot convert `|exists` ("Field exists
  expressions are not supported"). Write `<field> != null` there. It affects
  `sel_smp_directive` in both T1685 workload rules, and `T1053.007/k8s_cri_job_pod.yml`.
  Lucene (`_exists_:`), ES|QL (`is not null`) and Splunk (`=*`) convert it.
- **`not` and a missing field.** Sigma's `not` is null-safe: a record without the
  filter's field does not match the filter, so the rule still fires. The SQLite backend
  that the validators use wraps each negation as `NOT COALESCE(<test>, 0)`, which keeps
  that meaning. ES|QL and other SQL-semantics backends use three-valued logic: a test on
  a missing field is NULL, `NOT NULL` is NULL, and `WHERE` keeps only true. So
  `and not <filter>` drops every record that lacks the filter's field, and CI cannot
  see it. A deployment there must make each negation null-safe:
  `(<field> is null or not <filter>)`, or a Sigma `field: null` selection ORed with the
  `not`. The three T1611 pod-spec rules and both T1685 workload rules
  (`k8s_enforcer_workload_removed.yml` and the anchor
  `k8s_security_tool_workload_removed.yml`) use the second form for each filter on a
  field that a record can lack (`objectRef.subresource`, `requestObject.dryRun`,
  `requestObject.spec.replicas`, and the `requestObject` text of a JSON patch), and
  lose no positive. A probe that removed the `COALESCE` wrappers, and made a regular
  expression on a missing field NULL, found 16 rules that still lose positives, all of
  them on `main` too: the three T1070 delete rules, the seven T1537 public-policy rules,
  `T1550.001/aws_eks_irsa_web_identity_assumed_off_cluster.yml`,
  `T1098.001/aws_github_oidc_role_trust_abuse.yml` (4 of 8),
  `T1098.001/aws_github_oidc_role_trust_ref_wildcard.yml` (5 of 5),
  `T1098.001/gcp_workload_identity_pool_provider_created.yml` (4 of 5),
  `T1199/gcp_workforce_pool_provider_no_attribute_condition.yml` (1 of 3) and
  `T1685/k8s_admission_webhook_disabled.yml` (5 of 8: its delete-body dry-run filter
  drops every delete without a body, Procedures A and B included). Wave 4 of the
  Kubernetes coverage plan (item 4.2, the backend mapping proof harness) measures and
  fixes these.
- **`.` and a line break.** In Python, RE2 and PCRE `.` does not match a line break
  unless `|re|s` is set; in Lucene it always does.
- **`\s`.** `\s` is `[\t\n\r ]` in Lucene (no vertical tab or form feed), ASCII
  whitespace without the vertical tab in RE2, and Unicode whitespace in Python and KQL.
  A rule that must split on the blanks of a Unicode-aware parser (the CoreDNS Corefile
  lexer) lists U+00A0 and U+0085 as literal characters in its class; write such a value
  as a YAML double-quoted string with `\u00A0`/`\u0085` escapes, because PyYAML folds a
  raw U+0085 into a line break. No portable construct names a carriage return, vertical
  tab or form feed alone.
- **Determinization budget.** A long pattern can exceed Lucene's default determinization
  budget (`max_determinized_states`, 10,000). A check with Lucene 10.1's `RegExp`
  found that every `|re` value (321 at this writing) parses and fits the budget. With
  case folding (`ASCII_CASE_INSENSITIVE`, as the `case_insensitive` flag uses), the
  largest is the JSON-patch capability grammar of
  `T1611/k8s_podspec_controller_host_access.yml` (8,094 states); without it, the
  JSON-patch root grammar of `T1565.001/k8s_coredns_corefile_poisoned.yml` (7,986
  states). Each value, wrapped in `.*` (no `.*` before a leading `^` or after a
  trailing `$`), gives the same verdict as Python and RE2 on every case, fixture and
  benign-corpus value of its field.

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
It also runs `schedule-freshness` (not on push), which reads the Actions API; see
below.

**Weekly scheduled runs.** Each workflow file with a `schedule:` trigger (the
cron line is in the file) runs once a week, so CI proves a rule again when only
pySigma, the runner image or the kernel changed. GitHub can start a scheduled run
late (about 7 hours on 2026-10-19), drop it under high load, or not start it when
the workflow is disabled, and nothing fails when that happens. The
`schedule-freshness` job in `detection-quality.yml` checks for this. It finds the
workflow files with a `schedule:` trigger at run time (so a new scheduled
workflow is checked with no edit), and `.github/scripts/check_schedule_freshness.py`
reads the newest scheduled runs of each from the Actions API (the job has
`actions: read`):

- The scheduled and manual (`workflow_dispatch`) runs warn when the newest
  successful scheduled run is more than 8 days old, or when one red scheduled run
  (failure, cancelled, timed out) follows it. They fail at more than 15 days, at
  two red scheduled runs in a row, or when GitHub reports the workflow as
  disabled.
- A pull request only warns, with an annotation, for the same conditions.
- `detection-quality.yml` holds the check, and its other jobs run again in the
  same run. So its own red scheduled runs are not counted (two of them can come
  from this check), only the age of its newest scheduled run, and its scheduled
  run counts as fresh for itself. A manual run after a fix is not held by the red
  runs that the old cause made.
- Phase: all the weekly crons are on Monday morning. The crons of `lint-trr.yml`
  and the `validate-*.yml` workflows (06:11 to 06:43 UTC) come before the cron of
  `detection-quality.yml` (06:53 UTC). Their scheduled runs usually end in
  minutes, before it starts (on 2026-10-19 they ended 6 to 55 minutes before it).
  So the scheduled run sees ages of about 0, 7, 14 or 21 days. A red run counts as
  soon as it has ended: one red week warns, and two red weeks in a row fail. A run
  that GitHub drops (no run at all) shows only by age: one dropped week is not
  seen (7 days is ok), two in a row warn (a warning on a green run sends no
  notice), and three in a row fail. For a workflow whose cron is after 06:53 UTC,
  add 7 days. A pull request or a manual run at another time of the week sees
  other ages, and warns from day 8.
- A workflow with no successful scheduled run yet (a new one) only warns, also
  when its runs are red. It is new while its oldest scheduled run is 15 days old
  or less. With no scheduled run at all, or when GitHub does not list it as a
  workflow, it is new while `main` has no such file, or the version on `main` has
  no schedule trigger, or has had it, unchanged, for 15 days or less. After that,
  it fails: the schedule never started, or never passed.
- A schedule must run at least once a week (the day-of-month and month fields of
  one cron entry are `*`). Another schedule stops the job (exit 2), so that a human
  picks thresholds for it first.
- An API error that a re-run can clear (a rate limit, or a 5xx, a 429, a network
  error or a truncated answer on all its attempts, up to 4; or a request that the
  time budget below stops) fails the scheduled and manual runs (exit 2), and only
  warns on a pull request. Any other API error (for example a 403 or a 404, which
  is a fault in the token or its permissions) or an answer of the wrong shape
  fails every run, also on a pull request. An error on one workflow does not stop
  the check of the others. `--self-test` proves the grading on constructed API
  answers in the same job.
- A slow API outage ends as API errors, not at the job's `timeout-minutes` (which
  would end the step with no report). An attempt waits at most 15 seconds. After
  one request fails on all its attempts, each later request gets one attempt. The
  reads stop 240 seconds after the first one (`--api-budget`), and a request that
  this budget stops is an API error that a re-run can clear. Each workflow still
  gets its own row, written as soon as it is graded. With 8 scheduled workflows
  and no answer at all, the reads end after about 215 seconds.

In a public repository, GitHub disables the scheduled workflows after 60 days
without repository activity. That also disables `detection-quality.yml`, so this
job cannot report it: a pull request then gets no check from these workflows.
When a human enables the workflows again, the next run names each workflow that
is still disabled. A failed scheduled run opens no issue; GitHub sends its notice
to the user who last changed the cron line.

The three Kubernetes workflows (`validate-k8s-detections.yml`,
`validate-staticpod-detections.yml` and `validate-apiserver-detections.yml`) run their
loops on a kind cluster. They pin kind, the kindest/node image (by digest) and kubectl,
check the sha256 of both binaries, and fail when the cluster's server version differs
from the pin. The pin moves every quarter, and before the pinned minor reaches end of
life; the `env` block of each workflow says how.

`.github/workflows/k8s-version-matrix.yml` runs the three Kubernetes workflows every
week on the minors beside the pin: v1.35.8 and v1.37.0, the newest kindest/node images
of those minors that kind v0.33.0 publishes. (v1.34 is not in the matrix: it reaches end
of life on 2026-10-27.) Each leg dispatches one workflow with the `workflow_dispatch`
inputs `node_image`, `kubectl_version`, `kubectl_sha256` and `label`, finds its run by
the label in the run name, and waits for it. The steps stay in one file, and the job and
check names do not change. A red leg only alerts: the matrix is not a required check,
and it blocks nothing. It runs on `main` only, because a child run reports its checks on
the head commit of its ref. Empty inputs, and every push, pull request and schedule run,
use the pins. On `main`, a red leg shows a red `validate-*` check on main's head commit,
which gates no pull request. The `validate-apiserver-detections` badge in the top-level
README shows only the schedule runs (`?event=schedule`: the weekly run on the pin), so
a leg does not change it. A cancelled leg also cancels its run, when it has found that run.

### Kubernetes version notes

These upstream changes can move the rules' inputs or the emulations when the cluster
moves from the old pin (v1.32.2, kind v0.27.0) to v1.35, v1.36 (the pin) or v1.37. Each
item names its source at the tag. Each rule claim was checked with `sigma_eval.py` on
constructed events.

- **Impersonation (TRR9009).** The audit Event has
  `authenticationMetadata.impersonationConstraint` from v1.35
  ([audit/v1/types.go v1.35.8 L93-95, L148-153](https://github.com/kubernetes/kubernetes/blob/v1.35.8/staging/src/k8s.io/apiserver/pkg/apis/audit/v1/types.go#L93-L95)).
  ConstrainedImpersonation is alpha (off) in v1.35 and beta (on) from v1.36
  ([apiserver kube_features.go v1.37.0 L367-370](https://github.com/kubernetes/kubernetes/blob/v1.37.0/staging/src/k8s.io/apiserver/pkg/features/kube_features.go#L367-L370)),
  so a refusal on the v1.35 leg has the legacy message. `k8s_impersonation.yml` matches
  the legacy and the constrained refusal messages. No rule or validator gate reads
  `authenticationMetadata`, and the TRR9009 gate keys on `impersonatedUser`. The
  constrained refusal cases are built from source, not recorded live (the emulation
  runs no probe by a caller without the impersonate verb).
- **Watch-list reads (TRR9006).** client-go WatchListClient is on from v1.35
  ([known_features.go v1.37.0 L141-144](https://github.com/kubernetes/kubernetes/blob/v1.37.0/staging/src/k8s.io/client-go/features/known_features.go#L141-L144);
  off at v1.32.2 L76). An informer then opens one watch with `sendInitialEvents=true`
  instead of a list and a watch
  ([reflector.go v1.37.0 L361, L475-483](https://github.com/kubernetes/kubernetes/blob/v1.37.0/staging/src/k8s.io/client-go/tools/cache/reflector.go#L361)),
  so controller Secret reads move from `list` to `watch`. `k8s_secret_access.yml`
  matches get, list and watch.
- **kubectl debug profile (TRR9002, TRR9007).** From kubectl v1.36, `kubectl debug`
  uses the `general` profile when `--profile` is not given
  ([debug.go v1.36.4 L216](https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/kubectl/pkg/cmd/debug/debug.go#L216);
  `legacy` at v1.35.8 L217). The general profile adds SYS_PTRACE to the debug container
  in both pod forms: the ephemeral container of `kubectl debug <pod>`, a
  `pods/ephemeralcontainers` patch
  ([profiles.go v1.36.4 L214-215, L419-427](https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/kubectl/pkg/cmd/debug/profiles.go#L214-L215)),
  and the copy of `kubectl debug <pod> --copy-to=<new>`, a `pods` create (same file,
  L206-212; the copy also shares the process namespace). The legacy profile adds no
  capability in either form (profiles.go v1.35.8 L181-186). So the pinned kubectl
  (v1.36.4) already adds SYS_PTRACE. Every default `kubectl debug` of a pod from kubectl
  v1.36 or later matches `k8s_podspec_host_access.yml` (T1611, level high) where its
  write is logged at Request: the patch where a policy logs `pods/ephemeralcontainers`
  at Request, and the copy wherever `pods` creates are logged at Request (the API
  server lab policy logs both). The TRR9002 lab logs both at Metadata, and no step in
  the API server lab runs `kubectl debug`, so CI does not see this. Whether a default
  `kubectl debug` must be a high T1611 alert is an open human decision
  ([RULE_DEFECTS K34](RULE_DEFECTS.md#k34-k8s_podspec_host_access-a-default-kubectl-debug-from-kubectl-v136-adds-sys_ptrace));
  the rules do not change here.
- **Cgroup v1 (all labs).** The kubelet defaults `failCgroupV1` to true from v1.35
  ([v1beta1/defaults.go v1.35.8 L292-294](https://github.com/kubernetes/kubernetes/blob/v1.35.8/pkg/kubelet/apis/config/v1beta1/defaults.go#L292-L294);
  false at v1.32.2 L289-291), and kind does not set it. A local lab on a cgroup v1 host
  does not start. The CI runners start the v1.36.4 cluster, so they are not on cgroup v1.
- **kubeadm config (all labs).** kind v0.33.0 renders kubeadm v1beta4 for v1.36 and
  later, and v1beta3 below
  ([kubeadm/config.go L673-679](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/cluster/internal/kubeadm/config.go#L673-L679)).
  The `extraArgs` map in `k8s/kind-*.yaml` is native to v1beta3, and kind converts it to
  the v1beta4 list because the patch sets no `apiVersion`
  ([patch/kubeadm_merge.go L96-104](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/pkg/internal/patch/kubeadm_merge.go#L96-L104)).
  So the audit flags render on every leg (the v1.36.4 run shows all four `--audit-`
  flags).
- **Node image (all labs).** The kind v0.33.0 base image is Debian 13 (trixie) with
  containerd v2.3.4, runc v1.4.3 and crictl v1.36.0; kind v0.27.0 had Debian 12,
  containerd v2.0.2 and crictl v1.32.0
  ([images/base/Dockerfile v0.33.0 L23, L127, L145, L160](https://github.com/kubernetes-sigs/kind/blob/v0.33.0/images/base/Dockerfile#L23);
  v0.27.0 L23, L125, L158).
  All three legs use images of kind v0.33.0, so the node runtime is not what differs
  between them.
- **Exec, attach and port-forward (TRR9002, TRR9026).** kubectl v1.37.0 keeps both
  transport switches, `KUBECTL_REMOTE_COMMAND_WEBSOCKETS` and
  `KUBECTL_PORT_FORWARD_WEBSOCKETS`
  ([cmd/util/helpers.go v1.37.0 L445-446](https://github.com/kubernetes/kubernetes/blob/v1.37.0/staging/src/k8s.io/kubectl/pkg/cmd/util/helpers.go#L445-L446)).
  The server's PortForwardWebsockets is beta and on
  ([kube_features.go v1.37.0 L2010-2013](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/features/kube_features.go#L2010-L2013)),
  and AuthorizePodWebsocketUpgradeCreatePermission is on from v1.35 (same file,
  L1370-1372). `kubectl apply` stays client-side by default (`--server-side` false,
  helpers.go v1.37.0 L512), so an apply of a new object is still a `create`.
- **MutatingAdmissionPolicy (TRR9008, TRR9025).** It is GA and on from v1.36, and beta
  and off in v1.35
  ([apiserver kube_features.go v1.36.4 L443-447](https://github.com/kubernetes/kubernetes/blob/v1.36.4/staging/src/k8s.io/apiserver/pkg/features/kube_features.go#L443-L447)).
  The API server lab policy (`k8s/audit-policy-apiserver.yaml`) has no row for
  `mutatingadmissionpolicies` or `mutatingadmissionpolicybindings`, so their writes fall
  to its Metadata catch-all. `k8s_admission_webhook_created.yml` (create) and
  `k8s_admission_webhook_disabled.yml` (delete, deletecollection, update, patch) key on
  the `admissionregistration.k8s.io` group and the verb, so they match these writes. At
  Metadata a delete has no DeleteOptions body, so the delete dry-run filter of
  `k8s_admission_webhook_disabled.yml` cannot see one, and a server-side dry-run delete
  of a MutatingAdmissionPolicy or its binding also fires
  ([RULE_DEFECTS K35](RULE_DEFECTS.md#k35-api-server-lab-policy-mutatingadmissionpolicy-deletes-at-metadata-hide-a-dry-run)).
  No grader reads a policy body, and no emulation creates one.
- **userAgent.** client-go builds it as `<command>/<version> (<os>/<arch>)
  kubernetes/<commit>`
  ([rest/config.go v1.37.0 L527-530](https://github.com/kubernetes/kubernetes/blob/v1.37.0/staging/src/k8s.io/client-go/rest/config.go#L527-L530)),
  so it carries the kubectl and component versions of each leg. No Kubernetes rule and
  no validator gate keys on `userAgent`.
- **Bootstrap objects (shadow slice).** Some bootstrap controller roles exist only when a
  feature gate of that minor is on. For example, the
  `system:controller:device-taint-eviction-controller` role needs DRADeviceTaints
  ([bootstrappolicy/controller_policy.go v1.36.4 L227, L251](https://github.com/kubernetes/kubernetes/blob/v1.36.4/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/controller_policy.go#L227)),
  which is off in v1.35 and on from v1.36
  ([kube_features.go v1.36.4 L1369-1372](https://github.com/kubernetes/kubernetes/blob/v1.36.4/pkg/features/kube_features.go#L1369-L1372);
  v1.35.8 L1244-1246). So the role exists on the pin and on the v1.37 leg, but not on
  the v1.35 leg, and the shadow benign counts of the live slice can differ per leg. Compare a
  leg only with earlier runs of the same leg.

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
   through each control path (exec, attach, ephemeral container, and a POST to
   the kubelet `/run` through the node proxy), makes one read-only direct kubelet
   call, and reads the kubelet pod lists through the node proxy as a temporary
   service account (Procedure F). Each procedure's action must succeed or the
   step fails, naming the procedure; the run appends one ledger line per
   procedure (`$DETENG_LEDGER`: its time window and exit status).
2. **Audit policy** (`k8s/audit-policy.yaml`) — makes the telemetry exist. A
   default cluster writes no audit log, so a rule has nothing to match. The
   `k8s/kind-audit-cluster.yaml` config mounts it into a `kind` cluster.
3. **Sigma rule** (`sigma/T1609/`) — what to look for in the audit events.

Validate the loop (emulate -> audit -> rule fires):

```
# Compile the rules only — no cluster needed:
python3 detections/validate_k8s_detections.py --dry-run

# Full run against an audit log you collected from the cluster, with the
# emulation ledger (bind each procedure gate to its window and exit status):
python3 detections/validate_k8s_detections.py \
  --audit-log /tmp/kube-apiserver-audit.log --ledger /tmp/emulation-ledger.jsonl

# Negative control, on a log collected BEFORE the emulation ran:
python3 detections/validate_k8s_detections.py \
  --audit-log /tmp/pre-emulation-audit.log --expect-miss
```

The audit log is flattened to the dotted field names the rules use
(`objectRef.resource`, `user.username`, ...) and each rule runs through the
same pySigma backend as the auditd rules. Each MANIFEST entry carries one gate
per procedure (and per variant), and the entry passes only when every gate
matches a record of its own: A over WebSocket (`pods/exec`, verb `get`, code
101) and A over SPDY (`pods/exec`, verb `create`, code 101), B (`pods/attach`,
`container=app`, code 101), C (`pods/ephemeralcontainers`, code 200), D
(`nodes/proxy`, verb `create`, the `/proxy/run/` path, code 200) and the two
Procedure F reads (`nodes/proxy` get of `/runningpods/` and `/pods` by the
`trr9002-node-reader` service account, code 200). With `--ledger`, a gate also
needs its record inside the procedure's time window and the procedure to have
exited as expected, which tells apart procedures of the same shape and fails a
procedure that did not run. Procedure E (the direct kubelet call) is the
documented gap: with `--ledger` the validator asserts it ran and that no TRR9002
rule matches any audit event inside E's window. `validate_k8s_detections.py`
exposes a module-level `PROCEDURES` map — `(TRR id, letter)` to the rule files
that gate that procedure — which `research/tools/coverage_report.py` reads to
mark a procedure Proven only with a per-procedure gate.

**The list-as-JSON-text contract.** The API server audit log holds lists as JSON
arrays (`requestObject.rules`, `requestObject.webhooks`, `requestObject.spec.containers`),
and it holds the `requestObject` of a JSON patch as the raw operation array. The
validators flatten every list to its JSON text (`sigma_eval.flatten`), and many
Kubernetes rules match that text with `|contains` or `|re`: for example
`requestObject.spec.*containers|re` (T1611), `requestObject.rules|re` (T1098.006),
`requestObject.webhooks|contains` (T1546) and `requestObject|re` in the JSON-patch
branches of the T1546, T1611 and T1685 rules. A SIEM pipeline must index each such
field, and the `requestObject` of a JSON patch, as that JSON text, as the cloud rules
require for their nested lists (see [External cloud detections](#external-cloud-detections-aws-azure-gcp)).
Elastic's Kubernetes audit integration does not meet this contract: it maps
`requestObject.rules` as `nested`, and its ingest pipeline removes
`requestObject.metadata`, so the T1611 confinement rule's pod-annotation branches
(`sel_pod_annotation`, and `sel_last_applied` on kubectl's
`last-applied-configuration`) cannot match there (elastic/integrations `packages/kubernetes/data_stream/audit_logs`,
`fields/fields.yml` and `elasticsearch/ingest_pipeline/default.yml`).

`.github/workflows/validate-k8s-detections.yml` runs the whole loop on a `kind`
cluster for every change to the TRR9002 files, strict: a rule that does not
fire fails the job, because the `kind` emulation is deterministic. It also
captures the audit log before the emulation and runs the validator on it with
`--expect-miss`, so a pass that does not depend on the emulation fails the job.
`validate_staticpod_detections.py` and
`.github/workflows/validate-staticpod-detections.yml` do the same for TRR9003
(T1543.005), where the gate matters most: both rules the validator match-gates
(the CRI rule and the mirror-pod rule) also match the control-plane static pods
every node starts, so only the emulation's own pods count. Each rule gates the
injected static pod *and* the invalid-namespace evasion variant — the CRI rule
on both running sandboxes, the mirror-pod rule on the stored mirror (code 2xx)
and on the refused mirror-create attempt (code 404). Its emulation writes the
same per-procedure ledger (`A`, `GAP`, `B`); with `--ledger` a CRI sandbox is
bound to its window by `createdAt` and an audit event by
`requestReceivedTimestamp`. It also exposes a `PROCEDURES` map for the coverage
report. Procedure B stays a read-only demonstration with no telemetry, so it has
no gate.

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
  --audit-log /tmp/kube-apiserver-audit.log --cri-log /tmp/cri-pods.jsonl \
  --ledger /tmp/emulation-ledger.jsonl
```

### Container runtime layer (out of scope)

Shells in containers, container drift, miners, metadata-service calls from pods and
escape primitives beyond `setns` run below the API server, so the audit log never sees
them. auditd records carry no container identity, and CI collects no container-runtime
telemetry, so this repository records the layer as out of scope (vetted NO-GO,
2026-10-20, in the technique-selection ledger). Falco's stable, incubating and sandbox
rules are the reference there.

## Kubernetes API server detections (TRR9004–9010, 9025–9027)

Several more Kubernetes techniques key on the same API server **audit log**, so one
shared `kind` cluster, one audit policy (`k8s/audit-policy-apiserver.yaml`), one
validator (`validate_apiserver_detections.py`), and one workflow
(`.github/workflows/validate-apiserver-detections.yml`) cover them all:

| TRR | Technique | Chokepoint rule(s) | Audit level |
|-----|-----------|--------------------|-------------|
| TRR9004 | RBAC (T1098.006) | `sigma/T1098.006/k8s_rbac_write.yml` + two Request-level severity rules (`k8s_rbac_privileged_grant.yml` high; `k8s_rbac_sensitive_permission_grant.yml` medium) + `k8s_eks_aws_auth_configmap_modified.yml` (EKS aws-auth, Procedure F) | Request (RBAC); RequestResponse for `kube-system/aws-auth` update/patch/delete, Request for the kube-system ConfigMap create |
| TRR9005 | Jobs/CronJobs (T1053.007) | `sigma/T1053.007/k8s_job_create.yml` + a node-runtime job-pod rule | Request |
| TRR9006 | Secrets (T1552.007) | `sigma/T1552.007/k8s_secret_access.yml` + a TokenRequest rule | Metadata |
| TRR9007 | Dangerous pod spec (T1611) | `sigma/T1611/k8s_podspec_host_access.yml` + a controller rule + a confinement (Unconfined) rule | Request |
| TRR9008 | Disable admission control (T1685) | `sigma/T1685/k8s_admission_webhook_disabled.yml` + a neuter grader + an enforcer-removal rule (the engines' default namespaces) and its any-namespace anchor | Request (RequestResponse for webhook-configuration update and patch) |
| TRR9009 | Impersonation (T1134) | `sigma/T1134/k8s_impersonation.yml` + a privileged-target rule | Metadata |
| TRR9010 | Indicator removal (T1070) | `sigma/T1070/k8s_events_deleted.yml` + a workload-deletion rule + a namespace-delete hunting rule | Metadata |
| TRR9025 | Malicious admission webhook (T1546) | `sigma/T1546/k8s_admission_webhook_created.yml` + a create grader and a repoint grader | Request (RequestResponse for update/patch) |
| TRR9026 | Pod port-forward (T1572) | `sigma/T1572/k8s_pod_portforward.yml` (verb-agnostic subresource) + a nodes/proxy `/portForward/` rule | Metadata |
| TRR9027 | Cluster DNS poisoning (T1565.001) | `sigma/T1565.001/k8s_coredns_configmap_modified.yml` + a Corefile grader | Metadata + RequestResponse (the three DNS ConfigMaps) + Request (kube-system ConfigMap creates; drop that rule where Helm stores releases in kube-system ConfigMaps) |

The audit **level** is per technique: pods, workload controllers, RBAC, and
admission-webhook creates are logged at `Request` so `requestObject` carries the
privileged/hostPath fields, the bound role, the group subject, and the webhook
`clientConfig`. An update or patch of a webhook configuration is at `RequestResponse`,
so the stored webhooks are graded whatever the patch type. An update, patch or delete
of the three `kube-system` DNS ConfigMaps (`coredns`, `kube-dns`, `coredns-custom`) is
at `RequestResponse`, so the stored Corefile is graded whatever the patch type; every
ConfigMap create in `kube-system` is at `Request` (a create names no object when the
policy is evaluated, so the rule cannot name the three), so a delete-and-recreate
(TRR9027 Procedure D) is graded. An update, patch or delete of the EKS
`kube-system/aws-auth` ConfigMap (TRR9004 Procedure F) is likewise at `RequestResponse`,
as EKS logs it, so the stored `mapRoles` after an update or patch are kept for triage
(its create falls to the kube-system ConfigMap create rule at `Request`); the
validator's `trr9004` sentinel gate needs only `Request` (the create body and the patch
body). aws-auth holds IAM role ARNs, Kubernetes usernames and group names, and no
credentials. Two costs come with these levels:
- A Corefile can hold plugin credentials (route53 `aws_access_key`, azure `secret`,
  tsig `secret`); every write to it then copies them into the log.
- Helm 2 (Tiller), and Helm 3 with `HELM_DRIVER=configmap`, store each release in
  `kube-system` as a ConfigMap whose body holds the rendered manifests, Secret data
  included. Such a cluster must drop the create rule.

Secrets and `serviceaccounts/token` stay at `Metadata`, never higher, because
`RequestResponse` would copy the Secret data and the signed token into the log.

These rules are intentionally generic, and a fresh `kind` cluster is full of
baseline matches: bootstrap RBAC writes, controller-created Jobs and Pods,
controller Secret reads, the kube-proxy and kindnet privileged pods, and the
bootstrap coredns ConfigMap. So the validator gates each rule on the emulation's
own marker (each `MANIFEST` entry in `validate_apiserver_detections.py` names its gate):
for example a `trr90NN-` object name, the `trr9009` impersonated user or group, the
`trr9006` namespace with a non-system caller, a `trr9005-` Job label on the node
sensor, the `trr9004` sentinel in the fixed-name `kube-system/aws-auth` write (whose
object name cannot be prefixed), or the `trr9027` sentinel in each procedure's DNS-ConfigMap write (procedure A patches
`coredns`; B and C create `kube-dns` and `coredns-custom` by server-side apply, a
patch by name that the policy logs with its body; D deletes `coredns` and recreates it
with the sentinel, then restores the saved object and fails the step unless the restored
Corefile matches byte for byte; each is proven separately). The negative control
proves a pass depends on the emulation, not the baseline.

**Per-procedure gates and the emulation ledger.** A `MANIFEST` entry's gate is either
one callable (any marked record passes, as before) or a list of `(procedure, gate)`
pairs. With a list, the entry passes only when **every** procedure has a matching record
of its own, so one procedure that fails silently — or whose write the API server refused
— fails the entry; in `--expect-miss` mode the entry fails if **any** one procedure
matches. Most gates are built with `rec(verb, resource, sub, name|prefix, ns, user,
also, code, window)`; a gate that needs a precise helper (a body sentinel, a JSON-patch
operation list, a marker in the `requestURI`) is bound to its procedure with
`win(gate, window, code)`. Both, by default, require an accepted response (a 2xx, or 101
for a streaming upgrade), so a cleanup `DELETE` that hit a 404, or a refused create, can
no longer stand in for a procedure. Two procedures are refused by design, and their
gates say so. TRR9009's denied impersonation probes (A, the group probe, C, D and the
gap) pass only on a `403`, and a `200` there fails the gate, because it would mean a
throwaway identity had gained rights; only the `system:masters` list is expected to be
`200`. TRR9026 Procedure C sends an un-upgraded `nodes/proxy` GET that the kubelet
refuses: its gate takes any response code (`code=None`), because the audit record is
the proof and no live record has pinned the kubelet's refusal code yet. The atomic
passes on the kubelet's upgrade refusal (or on an unexpected success, which the API
server audits too) and fails on any other error.

The `--ledger` flag binds each procedure gate to its own time window and exit status.
Each emulation appends one JSON line per procedure to `$DETENG_LEDGER`
(`{"trr","procedure","start","end","exit","expect"}`, UTC to the microsecond); with a
ledger, a gate also requires the record's `requestReceivedTimestamp` to fall inside that
procedure's `[start, end]` and the procedure to have exited as expected, and a missing
row is reported as "did not run". This tells apart two procedures that send the same
request shape, and fails a procedure that did not run or failed. Without `--ledger` the
gates fall back to fields only, so a local run and an old log still work (the CI negative
control runs without a ledger, on field gates only). The CI job sets `DETENG_LEDGER`,
passes `--ledger`, and uploads the ledger with the logs so a reviewer can re-run the
validator offline (`--ledger` is refused with `--expect-miss`, so the negative control
can never be narrowed to a window). A documented gap is asserted with an **absence
check**: with a ledger, TRR9006 Procedure E (an on-disk token read) must leave no
`k8s_secret_access` or `k8s_secret_token_request` event by a non-system caller (in any
namespace) in E's window. Controller and kubelet reads (`system:*`) are left out so that
background traffic cannot flake the check. The check also fails when E did not run or
failed, and when a matching event has no `requestReceivedTimestamp` to place it in time.
A ledger line that does not parse, or is not a row with `trr` and `procedure`, fails
the run, because a corrupt ledger proves nothing. The TRR9002 and TRR9003 validators
do the same.

Module-level `PROCEDURES` maps `(trr_id, LETTER)` (e.g. `('TRR9004', 'A')`) to the sorted
rule paths that gate that procedure with a gate of its own. It is the interface for the
procedure coverage report (`research/tools/coverage_report.py`), so that a procedure
counts as proven by a gate of its own, not by a file-name substring test.

```
python3 detections/validate_apiserver_detections.py --dry-run     # compile only
python3 detections/validate_apiserver_detections.py \
  --audit-log /tmp/kube-apiserver-audit.log --cri-log /tmp/cri-pods.jsonl \
  --ledger /tmp/emulation-ledger.jsonl
```

TRR9006 Procedure E (reading an already-mounted token off disk) bypasses the API
server, so it leaves no audit event. Its rule
(`sigma/T1552.007/linux_k8s_sa_token_read.yml`) is compiled but not match-gated here;
the emulation documents the gap the way TRR9002 Procedure E does, and (with a ledger)
the absence check asserts it: no secret-read or token-request event by a non-system
caller in E's window.
The TRR9007 static-pod delivery also skips the API server's admission, but the kubelet's
mirror create is audited as `system:node:<node>` and carries the spec at `Request` level,
so the `9007 static` entry match-gates the pod-spec chokepoint on it (`create pods`, a
`trr9007-escape-static-` name, a `system:node:` caller, in the gap procedure's window);
the emulation polls up to 60 s for that mirror pod and fails if it never registers.
TRR9003's CRI rule for the static pod is not compiled by this validator;
`validate_staticpod_detections.py` compiles and match-gates it on the TRR9003 emulation.

## External cloud detections (AWS, Azure, GCP)

The cloud techniques (the AWS, Azure and GCP rows of the
[research index](../research/README.md#index)) key on a cloud provider's audit log instead
of Linux syscalls or the Kubernetes API server, so they have their own validator
(`validate_cloud_detections.py`) and workflow (`validate-cloud-detections.yml`). The
validator's `MANIFEST` lists every cloud rule it proves, and each TRR's `## Detections`
table names its own rules. The first five, as examples:

| TRR | Technique | Log | Chokepoint rule |
|-----|-----------|-----|-----------------|
| TRR9011 | IMDS creds used off-instance (T1552.005, AWS) | CloudTrail | `sigma/T1552.005/aws_imds_creds_used_off_instance.yml` |
| TRR9012 | Leaked long-term access key (T1078.004, AWS) | CloudTrail | `sigma/T1078.004/aws_leaked_access_key_recon.yml` |
| TRR9013 | Entra federated-identity backdoor (T1098.001, Azure) | Entra audit + Azure Activity | `sigma/T1098.001/entra_app_federated_credential_backdoor.yml` + `azure_managed_identity_federated_credential_backdoor.yml` |
| TRR9014 | Public IAM exposure (T1098.003, GCP) | Cloud Audit Logs | `sigma/T1098.003/gcp_public_iam_member_grant.yml` |
| TRR9015 | GitHub-OIDC role-trust abuse (T1098.001, AWS) | CloudTrail | `sigma/T1098.001/aws_github_oidc_role_trust_abuse.yml` |

Cloud has no free live target to run the attacks against, so the loop is proven on
**recorded logs** rather than a live run. Each technique ships committed,
schema-faithful fixtures under `cloud/fixtures/<trr>/`: an **attack** set and a hard
**benign** baseline for each log it reads. Every field path is a real field of the
provider's audit log, grounded on the provider's schema docs and real samples (see
each TRR's References); only safe markers are used, for example RFC 5737 TEST-NET and
RFC 1918 private IPs, RFC 2606 `example.com`, the AWS doc account `123456789012`,
placeholder IDs, and `trr90NN-` resource names. The validator runs each rule
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
add_key, perf_event_open, io_uring, bpf). Most `medium` rules ship with a
process allowlist (by `comm`, and where it can be forged also by `exe`) and
documented false positives; `io_uring_setup` has none by design. Baseline them
before you alert. An allowlist trusts the binary, not code injected into it
([`RULE_DEFECTS.md`](RULE_DEFECTS.md) L14).
