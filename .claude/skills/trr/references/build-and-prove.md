# Build & prove mechanics

Read this once you have a GO and the pinned telemetry. It is the how-to for turning a
vetted technique into green, reviewed detection artifacts. Everything here is enforced by
the repo's CI, so following it is what makes a PR mergeable.

## Contents
- [The proof contract](#the-proof-contract)
- [What a sufficient check looks like](#what-a-sufficient-check-looks-like)
- [Reading a red run](#reading-a-red-run)
- [The benign corpus (scored false positives)](#the-benign-corpus-scored-false-positives)
- [The pySigma backend and its gotchas](#the-pysigma-backend-and-its-gotchas)
- [Reusable rule patterns](#reusable-rule-patterns)
- [Fixtures and the validator MANIFEST](#fixtures-and-the-validator-manifest)
- [TRR README + DDMs (trr_lint)](#trr-readme--ddms-trr_lint)
- [Atomics](#atomics)
- [CI wiring](#ci-wiring)
- [Adversarial review](#adversarial-review)
- [Environment](#environment)

## The proof contract

For each rule, `detections/validate_cloud_detections.py` asserts, over committed fixtures:

> the recorded **attack** fixture makes the rule fire **and** the firing record carries the
> emulation **marker**; AND the **benign** baseline makes the rule fire on **nothing**.

The benign baseline must be **hard**: same log source / method / structural fields as the
attack, differing only on the discriminating field (the off-instance source IP, the
identity type, the public-vs-scoped principal, the `oidc.eks` provenance, etc.). A pass
then proves the rule keys on the technique's chokepoint and not on the fixture's shape or
marker. Add **provenance confounders** — look-alikes that must NOT fire (e.g. an EKS Pod
Identity call with empty `webIdFederationData`, a GitHub-OIDC exchange with a non-`oidc.eks`
provider) — to prove the discriminator, not just the IP.

Kubernetes/auditd TRRs use sibling validators (`validate_apiserver_detections.py`,
`validate_detections.py`) that run the real emulation on a live kind cluster / auditd VM in
CI rather than recorded fixtures.

## What a sufficient check looks like

You write the checks as well as the rule, so "a check that currently passes" is not the
bar. A check is sufficient only if it would **fail for a plausible wrong rule**. The
`check-sufficiency` gate (`detections/check_sufficiency.py`) enforces the minimum, and
`detections/sigma_explain.py` grades every negative against the rule's condition:

| Grade | Meaning | Counts toward sufficiency |
|-------|---------|---------------------------|
| `near-miss` | some positive **item** holds, and flipping one item (`selection.a1`, `sel_pod.verb`) alone fires the rule through a branch the event already shares | yes |
| `filtered` | every selection holds; one `not <filter>` item alone suppresses it | yes |
| `distant` | some positive item holds, but no single flip fires the rule (two or more flips away) | no |
| `trivial` | no positive item holds (a no-op, an unrelated event), however few flips away | no |

An atom is one detection item (`<block>.<field>`, or `<block>.<field>|<modifiers>`
when a block has several items on one field), not a whole block. A near-miss
therefore means "one field condition away from firing, through a branch the event
shares"; under an OR condition, several positive items of other branches may be
false. List a rule's atoms with `python3 detections/rule_cases.py --atoms <rule>`.

**A new rule ships with, next to it, in `detections/sigma/<T>/<stem>.cases.jsonl`:**

1. **≥1 `positive`.** The telemetry the repo's own emulation produces, in the real log
   shape: same field names, casing, nesting and encoding (auditd hex args, nested
   `audit.k8s.io/v1` Events, CloudTrail lowerCamelCase). Add a second positive for each
   procedure variant the rule claims to cover, such as a second verb or transport, a
   flag combination, or IPv6.
2. **≥1 verified `near-miss`**: same chokepoint, one required item broken, with
   `breaks: ["<block>.<field>"]`. The runner fails the case unless that item really is
   the single flip, so a no-op cannot be passed off as a near-miss. Aim to cover **every
   discriminating item**, not one.
3. **A `filtered` case for every `not <filter>` block**: an allowlisted look-alike that
   the filter alone suppresses. This proves each filter does work and is not dead code.
   Model a real allowlisted process doing the real call; a filtered case for a process
   that never makes the call proves nothing (and the filter entry is then an evasion).
4. **`confounder` cases** for realistic legitimate look-alikes, which must share the
   rule's surface (the runner rejects a trivial confounder).

Cloud rules may instead get their near-misses from their hard benign fixture, and
some older cloud rules have no sidecar yet. The gate grades fixture records the same
way. A rule with one positive item and no filter cannot have a near-miss at all
(`PRESENCE`, below), and a rule with one selection item can have only filtered and
benign negatives.

Model every event on the telemetry the pipeline really produces: a syscall that
`detections/audit/atomic.rules` audits, an audit level and `requestObject` that the
audit policy really logs, the comm and exe the real process has. An event that cannot
occur proves nothing.

**Templates for the negative that matters most**, per platform:

- **auditd syscall rule**: same `syscall`, one argument wrong (`SOCK_STREAM` for
  `SOCK_RAW`, a `bpf` command other than `BPF_PROG_LOAD`). Also the allowlisted `comm`
  doing the exact positive call.
- **auditd correlation**: *half a correlation* (`breaks: ["base:<name>"]`): only one of
  the base events. Also *different group* (`breaks: ["group-by"]`): both halves, in
  different pids (the `memfd_fexecve_in_child` mutant offline). The gate also checks
  each base on its own: a base with an argument needs a set in which the other base
  holds and this base's event keeps its surface but breaks that argument, in the
  right group and window (`ip netns add` then a `NETLINK_ROUTE` socket breaks the
  `NETLINK_XFRM` base's `a2`). Add a live mutant in `detections/controls/` with its
  expected atom in the `CONTROLS` entry. The validator grades it on every CI run and
  warns if it misses the declared atom; a mutant that makes no audited syscall at all
  is vacuous and fails the run.
- **Kubernetes audit**: same `verb` + `objectRef.resource`, with the dangerous
  `requestObject` field absent or safe (`hostPID: false`, `privileged: false`). Also a
  system controller identity the filter excludes, and a Request-level grader's input
  with an in-cluster `service` instead of an off-cluster `url`.
- **Cloud audit log**: same `eventSource`/`eventName`, one discriminator flipped: a
  specific principal instead of `*`, a pinned OIDC `sub`, an allowlisted egress IP, a
  failed call (`errorCode`). Also a provenance confounder (e.g. Pod Identity's empty
  `webIdFederationData`).

**What the gate rejects** (each fails `check-sufficiency`):

- A rule with no registered positive in any validator `MANIFEST`. A documented
  telemetry gap goes in `COMPILE_ONLY` with a reason (human-approved) and still needs
  a sidecar positive. A registered rule must also declare the log source its
  validator proves it on (`linux/auditd`, `kubernetes/audit` or `kubernetes/cri`, the
  cloud provider): the benign corpus scores a rule only on its log source.
- A rule with no verified negative that breaks a **discriminating** item or a
  filter. Trivial and distant negatives don't count: no-op runs, unrelated events, a
  pre-emulation baseline, or a record where *no* positive item holds (an `{"x": 1}`
  grades trivial for every rule). Neither does a near-miss that breaks only the
  surface (`syscall`, `verb`, `eventName`), because it would pass just as well for the
  rule with its argument deleted. A near-miss must share the branch it nearly fires.
- A rule that keys on the emulation's naming. The rename test renames every
  emulation identity (`trr9NNN` or `deteng_` or the gate marker, plus the rest of its
  token, so `deteng_afxdp_socket_behavioral` and `trr9026-target` go whole) in every
  positive unit: each passing sidecar positive; for an auditd rule, a copy of each
  with the `exe` and `comm` that the validator's run of each of the rule's atomics
  writes (`/tmp/deteng_val_<random>/deteng_<atomic stem>`), if that copy fires; and
  for a cloud rule, each attack record that fires and carries the marker. Each unit
  is renamed twice, with replacements drawn at random for each run: same-shape (every
  letter and digit becomes another of its class) and neutral (random lowercase
  letters, 3 to 8 longer). The rule must still fire after both, so it may key on
  neither the name nor its shape. A rule that names an emulation literally, has no
  positive unit, or has no unit that carries an identity (the test renamed nothing;
  a `COMPILE_ONLY` rule is excused) fails too. A
  cloud rule's validator gate must be a `marker(...)` on a name only the emulation
  uses (`trr90NN-...`), never on a string the rule itself matches. A gate of
  `Unauth` on a rule that keys on Cognito's `...Unauth_Role` naming proved
  nothing. Source IPs, account ids and the part of a token before the name are not
  renamed: do not key a rule on them. Outside the auditd rules the units are your
  sidecar and fixtures as written, so give each positive the emulation's real names
  in the fields the rule reads; a positive whose name sits only in a field the rule
  does not read proves nothing, and the gate does not notice.
- Any failing sidecar case; any file under `detections/sigma/` other than `T<id>/`
  rule files, `.cases.jsonl` sidecars and `.md`; and anything in `detections/` named
  `sigma.*` or a compiled module (`.pyc`, `.so`) directly in `detections/`, which
  would replace pySigma, PyYAML or a standard-library module in every gate.

Four human-approved waiver tables exist in `check_sufficiency.py`. Never add an
entry yourself; propose it in the PR with the reason. Each entry carries the digest of
the rule content a human approved (its `name`, `id`, `logsource`, `detection` and
`correlation`), so editing any of those in a waived rule fails the gate until a human
re-approves the new digest, which the gate prints (`level`, `status`, `description`
and tags are not covered):

- `COMPILE_ONLY` (R1): CI collects no telemetry for the rule; it still needs a
  sidecar positive.
- `CHOKEPOINT` (R2): the record kind itself is the technique, so every positive item
  is a surface field (key `<rule> base:<name>` for one base of a correlation).
- `PRESENCE` (R2): one positive item, no filter. No negative can be one flip away, so
  the positive and the benign-corpus budget are the proof.
- `PLATFORM_NAMING` (R4): the rule keys on a platform naming template that follows
  the emulation's name; the rename keeps the named substrings.

Correlation atoms (`base:<name>`, `group-by`, `timespan`, `order`, `threshold`) are
verified by construction: the grader repairs the named atom (unifies the pid,
re-stamps into the window) and requires the repaired set to fire the compiled rule.
Every event needs a parseable timestamp and a value for every group-by field, or the
correlation never sees it. A set with such an event is never a near-miss: it grades
distant, or trivial if no base is visible.

It **warns** (never fails) on *thin* checks: a rule whose exercised-atom ratio is
below half its platform's median, or whose negatives exercise only filters (or only
surface items and filters) and no discriminating selection item. Treat that warning
as a request to add near-misses.

On a pull request, the `sufficiency-ratchet` job compares every rule with the base
branch. It fails on:

- a base rule that is gone from the head (deleted or renamed);
- a sidecar case of the base, of any kind, that is gone or whose kind, `breaks` or
  events changed (each case is compared by a digest of those three);
- a verified negative whose cloud fixture record is gone or changed;
- fewer verified negatives, a lost exercised item, fewer passing positives, a lost
  sidecar or a changed logsource;
- a rule with more benign-corpus hits than in the base branch's `scores.json`, even
  inside its budget.

Adding cases and rewording a case's `why` pass. So an edited or deleted case, a
moved or renamed rule, or a noisier rule goes to a human. The job does not compare
the rule's own detection: a broadened rule that keeps every case is left to its
near-miss cases and the benign comparison.

Never weaken a case, relabel its kind, or edit a rule's condition to make a check
pass. If a negative you believe is correct fires, the rule has a defect: fix the rule
and keep the case, or record it in `detections/RULE_DEFECTS.md` (rule, kind,
severity, evidence, proposed fix) and point the case's `why` at that entry.

## Reading a red run

The validators explain their failures item by item, so you should not have to guess
what broke. Fix the cause the output names:

- **Rule did not fire.** The output prints each block's and each item's match count
  over the events (or over the emulation's own events, for the cluster validators)
  and the nearest event, item by item, with the field values it carried. For
  example, `- afinet_raw_socket [FAILS]` over
  `no   a1  a1='2'  (rule wants: '3' or '803' or ...)` says the stimulus opened
  `SOCK_DGRAM`. "no event carries `requestObject.spec.hostPID`" means the telemetry
  never records that field: an audit-policy level, an audit rule, or a field
  name/casing problem, not a rule-logic problem.
- **No emulation event at all** (cluster validators): the emulation did not run,
  or its marker (name prefix, namespace) differs from the gate.
- **A control passed.** The output prints the events behind the unexpected hit
  (syscall, pid, comm, args) and which items held. A mutant that is graded
  `distant` instead of `near-miss` on its declared atom does not test what it
  claims, even while it holds.
- **Kernel probe.** Every Linux case prints its probe result. A miss is a SKIP only
  when the probe says the kernel lacks the feature.
- **Benign fixture hit** (cloud): the benign record index and the items that held
  on it.
- **Machine-readable.** Every validator takes `--json PATH`
  (`{rule, status, detail, explanation}`), so you can parse results rather than
  scrape logs.

## The benign corpus (scored false positives)

The hard gate proves the rule keys on the technique. The benign corpus
(`detections/benign/`, see its README) measures how often the rule fires on ordinary
operational activity: hits, rate per 10k events, and the distinct
processes/principals behind them. `detection-quality / benign-corpus` runs
`score_benign.py --check --enforce`:

- `--check` fails if `detections/benign/scores.json` is stale. After an intended
  change, run `python3 detections/score_benign.py --update` and commit the snapshot.
  The false-positive change is then visible in review.
- `--enforce` fails for an `enforce`-mode rule over its budget in
  `detections/benign/budgets.json`; shadow-mode overruns are warnings. With either
  flag, a rule that no slice reads fails unless `budgets.json` lists it under
  `unscored`, and so does a stale `unscored` entry. Every run fails on a
  `budgets.json` key that names no rule, on an `unscored` entry without a `why`, and
  on a per-rule entry whose `why` does not start `documented noise:` or `rule defect,
  tracked in detections/RULE_DEFECTS.md <ID>:` (an ID the tracker lists). Every
  per-rule entry is `enforce` today. A budget is the most hits over eleven seeds, so
  it leaves headroom above the committed seed's hits: a rule that gets noisier fails
  `benign-corpus` only once it passes `max_hits`. On a pull request,
  `sufficiency-ratchet` fails any rise over the base branch's `scores.json`, even
  inside that headroom (`score_benign.py --baseline-scores`). Fewer hits pass.

When a new rule fires on the corpus, read the explained example hit first. A precise
rule firing on benign activity is a rule defect. A deliberately generic hunting rule
may need a budget: **propose** one (`enforce`) with a `why`, and say so in the PR. Base `max_hits` on
`score_benign.py --reseeds 10` (the most hits over ten reseeds of every synthetic
slice), not on one seed's count. A rule whose log source no slice reads is proposed
under `unscored` with a `why`. A precise rule that fires on benign activity goes in
`detections/RULE_DEFECTS.md`. Budget and corpus changes are not
content, so they need a human's approval before merge. Never
edit the corpus to silence a rule. You may propose new slices for realistic activity,
but a human decides what counts as benign enough.

## The pySigma backend and its gotchas

`detections/sigma_eval.py` compiles each rule with pySigma's SQLite backend and runs it
over events loaded into an in-memory table — so a rule passes only if its real Sigma
semantics match. Reproduce any behavior question with it directly:

```python
import sys, json; sys.path.insert(0, "detections"); import sigma_eval
q = sigma_eval.compile_rule("detections/sigma/<T...>/<rule>.yml")
ev = sigma_eval.flatten(json.loads(open("detections/cloud/fixtures/<trr>/attack.json").read())[0])
print(bool(sigma_eval.evaluate(q, [ev])))
```

- **`flatten()`**: nested dicts → dotted keys (`userIdentity.sessionContext.x`); lists →
  `json.dumps` text (so list contents are matchable with `|contains`); scalars kept
  (bools/ints preserved). An empty `{}` yields no key at all — so a rule keying on a field
  inside it simply does not match (this is how IRSA's non-empty `federatedProvider`
  excludes Pod Identity's empty `webIdFederationData`).
- **`|cidr`** compiles to a textual `LIKE '<prefix>%'`. IPv4 CIDRs on octet boundaries are
  exact; IPv6 only matches the canonical compressed lowercase form on a nibble boundary —
  document that in any IPv6 allowlist.
- **`|re`** works (a `REGEXP` function is registered, full Python `re`, look-around OK).

**The Sigma-wildcard trap (has bitten this repo twice).** In a plain value or `|contains`,
`*` is a Sigma WILDCARD. `|contains: '"AWS":"*"'` compiles to `LIKE '%"AWS":"%"%'` and
matches ANY named principal — a false positive. To match a LITERAL asterisk (a public
principal), use `|re` with an escaped star, and cover the array form:
`|re: '"(?:Principal|AWS)"\s*:\s*\[?\s*"\*"'`. Pair a public-principal match with an
`Effect":"Allow"` guard so a deny-only policy doesn't fire.

**Presence vs. value.** `field: '*'` is a PRESENCE test and matches an empty string too;
for non-empty use `|re: '.+'`. A field the provider serializes as a string when you expect
an int is a silent dead rule against real logs — e.g. Azure `resultType` is `"0"` (string)
in the diagnostic stream; match `|re: '^0$'` to catch int or string. CloudTrail normalizes
`requestParameters`/`responseElements` to **lowerCamelCase** even though the API model is
PascalCase — match `subjectFromWebIdentityToken`, not `SubjectFromWebIdentityToken`.

## Reusable rule patterns

- **Off-egress "used from a source we don't own"** (TRR9011, TRR9022): match the trusted
  provenance marker, then `not filter_<owned>_source` where the filter is a
  `sourceIPAddress|cidr` allowlist (RFC1918 + CGNAT + the account's NAT/EIP + IPv6 egress,
  as documented placeholders the operator baselines).
- **AWS service-source guard (REQUIRED on any off-egress allowlist rule).** An AWS service
  acting on behalf of a session logs `sourceIPAddress` as a service DNS name
  (`athena.amazonaws.com`) or the literal `AWS Internal`, which is neither RFC1918 nor an
  egress CIDR and would bypass the allowlist. Add, and AND into the condition:
  ```yaml
  filter_service_source:
    sourceIPAddress|endswith: '.amazonaws.com'
  filter_internal_source:
    sourceIPAddress: 'AWS Internal'
  ```
  It can never suppress a true positive — a real attacker always presents a client IP.
- **`not filter_failed` (`errorCode: '*'`)** to drop failed attempts where a successful
  action is the signal.
- **Provenance is not a detection.** Fields true of ~100% of benign activity (an
  `AssumedRole` type, a provider ARN) scope the rule; the discriminator is what fires it.
  Say which is which in the description.

## Fixtures and the validator MANIFEST

- Fixtures are schema-faithful recorded logs under `detections/cloud/fixtures/<trr>/`.
  Safe markers only: RFC 5737 TEST-NET IPs (`198.51.100.x` off-net, `203.0.113.0/24` as
  the allowlisted egress placeholder), RFC 2606 `example.com`, the AWS doc account
  `123456789012`, and `trr90NN-` resource names. The marker substring must appear in a
  field the rule's firing record carries.
- Register each rule in the `MANIFEST` in `detections/validate_cloud_detections.py`:
  `(TRR, folder, rulefile, attack.json, benign.json, provider, note, marker(substr, *fields))`.
  The `marker()` gate checks that at least one named flattened field of a firing attack
  record contains the substring.

## TRR README + DDMs (trr_lint)

`.github/scripts/trr_lint.py` (offline) enforces the tired-labs report shape. A README at
`research/trr<NNNN>/<platform>/README.md` must have, in order: `## Metadata` (table rows
ID, External IDs, Tactics, Platforms, Contributors; ID matches the folder),
`## Technique Overview`, `## Technical Background`, `## Procedures`,
`## Available Emulation Tests`, `## References`. (`Scope Statement`, `Detection Strategy`,
`Detections` are allowed extras.) Each procedure needs a `### ...` heading carrying a
`TRR<NNNN>.<PLATFORM>.<LETTER>` ID and a `#### Detection Data Model` subsection embedding a
`ddms/*.png`. `research/index.json` must have a matching entry (id + procedure keys).

**DDMs** are Arrows-app JSON (`ddms/<trr>_<plat>_<letter>.json`: `style`, `nodes` with
`position`/`caption`/`labels`/`properties`/`style`, `relationships`). Render with
`python3 research/tools/render_ddm.py <json...>` — it draws the PNG and stamps the JSON's
sha256 into it; `--check` verifies freshness without a browser (trr_lint runs `--check`).
Convention: green border = unlogged theft, blue border + yellow fill = the CloudTrail
chokepoint, black = outcome, grey = out-of-scope/gap.

## Atomics

The repo's `atomics/<T...>/` copy is det-eng staging shape: dry-by-default with a
`TRR90NN_LIVE=1` guard for the real (operator-account) run and a `--show-fixture` that
prints the committed fixture. ART format (`attack_technique`, `display_name`,
`atomic_tests[]` with `supported_platforms` `iaas:aws`/`iaas:azure`/`iaas:gcp`/`containers`,
`executor`). Keep GUIDs unique; `bash -n` clean. (The upstream-shaped copy differs — see
`references/upstream.md`.)

## CI wiring

These workflows run on every PR. The `main` ruleset requires only the validator,
`sigma-lint`, `markdown-links` and `trr-lint` checks; `automerge` waits for every check
(see `detections/benign/README.md`, "Branch protection: what binds a manual merge"):

- `validate-detections.yml`: auditd loop + `sigma check` + `markdown-links`, runs on
  every PR.
- `validate-cloud-detections.yml`: the fixture loop, **path-filtered**. Add
  `detections/sigma/<T...>/**` and `atomics/<T...>/**` to the `push` `paths:` list,
  and add the directory prefixes `'detections/sigma/<T...>/'` and `'atomics/<T...>/'`
  (trailing slash, no `**`) to the `changes`-job pattern list. That job treats an
  entry ending in `/` as a prefix and any other entry as an exact path, so a glob
  there never matches, and the validator is skipped (which counts as success). The
  kind validators have the same two lists.
- The kind validators.
- `lint-trr.yml`.
- `detection-quality.yml`, on every PR:
  - `rule-cases` runs every sidecar.
  - `check-sufficiency` is the gate above.
  - `sufficiency-ratchet` (pull requests only) compares every rule with the base
    branch: its sufficiency report (cases, negatives, positives, logsource) and its
    benign-corpus hits.
  - `benign-corpus` checks the FP snapshot and budgets.
  - `benign-linux-live` is a shadow capture of a real runner workload.

Every validator also runs weekly on a schedule, so a rule re-proves itself after
unrelated changes (pySigma, runner image, kernel).

Run locally before pushing:
```bash
python3 detections/rule_cases.py detections/sigma/<T...>/<rule>.yml   # sidecar cases hold
python3 detections/check_sufficiency.py --rule detections/sigma/<T...>/<rule>.yml
python3 detections/validate_cloud_detections.py            # attack fires + benign clean
python3 detections/score_benign.py --check --enforce       # FP snapshot current, budgets held
sigma check -x attacktag -x d3_fendtag -x cartag -x detection_tag detections/sigma/<T...>/
python3 .github/scripts/trr_lint.py
python3 .github/scripts/check_md_links.py
```
The `sigma check` exclusions matter: the egress proxy blocks the ATT&CK/D3FEND/CAR tag
downloads those validators need, so exclude them locally; they re-run server-side.

## Adversarial review

Before a PR is "done", run a skeptic pass — per rule, per fixture, per README — and
**reproduce every finding against `sigma_eval.py`** (a crafted variant event that should or
shouldn't fire). Fan out one dimension per subagent. This has repeatedly found real
defects in rules that already passed CI: a dead int-vs-string match, a Sigma-wildcard
false positive, a service-source bypass, an over-claimed novelty line. Fix the root cause,
re-validate, then push.

## Environment

A fresh container may lack pySigma. Install with:
```bash
pip install --quiet --ignore-installed PyYAML==6.0.3 pySigma==1.5.1 pySigma-backend-sqlite==2.0.0
pip install --quiet --ignore-installed sigma-cli    # for `sigma check`
```
Chromium for `render_ddm.py` is preinstalled (`PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers`);
do not run `playwright install`.
