# Benign corpus: the false-positive layer

The validators are the **hard gate**. A rule must fire on its own emulation and stay
silent on its broken variants: no-op runs, mutants, allowlisted names, near-miss
cases and hard benign fixtures. That gate is binary and strict, and it answers one
question: *does the rule key on the technique?*

It does not answer the question production asks: *how often does the rule fire on
ordinary operational activity?* A rule can catch its atomic, reject every mutant,
and still alert on every CI runner in the fleet. This corpus is the second, softer
layer that measures that.

| Layer | Question | Shape | Fails CI |
|-------|----------|-------|----------|
| Hard gate (validators, `rule_cases.py`, `check_sufficiency.py`) | Does the rule catch the technique and reject its near-misses? | binary, per rule | always |
| Benign corpus (`score_benign.py`) | How much does it fire on normal activity? | scored: hits, rate, actors | when `scores.json` is stale, a rule is unscored without an exemption, or an `enforce`-mode rule is over budget; on a pull request, also when a rule has more hits than in the base branch's `scores.json` |

## What is in it

Each slice is one JSON spec under [`slices/<family>/`](slices/). Its `logsource`
must match a rule's `logsource`, and the rule is then scored against every event in
the slice. The full spec format is documented in
[`../benign_corpus.py`](../benign_corpus.py).

Slices come in two fidelities:

- **`recorded`**: real telemetry, captured and sanitized, stored as JSONL next to
  the spec. This is the highest fidelity: real processes, real field values, real
  noise.
- **`synthetic`**: generated deterministically from weighted event templates that
  model documented real activity (admin, developer, CI/CD, service and controller
  traffic). Synthetic slices deliberately include **near-miss operational
  activity**: legitimate traffic that shares surface characteristics with the
  chokepoints the rules key on. Examples are a profiler calling `perf_event_open`,
  `tcpdump` opening an `AF_PACKET` socket, a GitOps controller writing RBAC, and
  Terraform sharing an AMI with a named DR account.

Every committed slice is synthetic today; the live captures below are the path to
the first recorded slice. Template weights deliberately over-sample the activity
next to each rule's chokepoint, so a rule's hits and rate on a slice are corpus
figures (presence indicators), not a production rate.

The same specs always expand to the same events, so the corpus is versioned data.
A slice's `version` changes when its content changes, and the snapshot records a
digest of every slice.

Two live captures are also scored in CI, in shadow mode only. Neither is committed:

- **kind bootstrap + operator workload.** In `validate-apiserver-detections`, the
  API server audit log captured before the emulation runs. It includes a fresh
  cluster's own traffic plus [`k8s/workload.sh`](k8s/workload.sh).
- **Ubuntu runner workload.** The `benign-linux-live` job in `detection-quality`
  records [`linux/workload.sh`](linux/workload.sh) under the det-eng audit rules
  with [`linux/capture.py`](linux/capture.py) and uploads the capture as an
  artifact.

A human can sanitize a live capture and promote it into a `recorded` slice.

## What is measured

For every rule, [`../score_benign.py`](../score_benign.py) reports:

- **hits**: alerts raised on benign activity (one per matching event, or one per
  correlation alert);
- **rate per 10k**: hits per 10,000 events of the rule's logsource, so slices of
  different sizes compare;
- **actors**: who is behind the hits: the distinct processes (auditd `exe`, else
  `comm`) or principals (Kubernetes audit `user.username`; CloudTrail the session
  issuer's role ARN, else `userIdentity.arn`, so one role counts once across its
  sessions; the Azure and GCP caller or principal fields). For the Kubernetes CRI
  log it is the pod's namespace, not a principal. One noisy actor is an allowlist
  candidate; fifty distinct actors means the rule is too broad;
- **slices**: which slices the hits came from;
- an **explained example hit** per rule: which items of the rule held on the
  benign event, so the cause is visible without reproducing it.

A plain "zero hits" bar gets brittle once the corpus grows. Counts, rates and
actors show *how* a rule is noisy, and the committed snapshot tracks that over time.

## Budgets, shadow mode and enforcement

[`budgets.json`](budgets.json) sets, per rule, how many benign hits are acceptable
(`max_hits`, optionally `max_rate_per_10k`) and what happens when a rule goes over:

- **`enforce`**: the overrun fails the `benign-corpus` check.
- **`shadow`**: the overrun is a CI warning (an annotation on the run), never a
  failure. It is for a rule a human accepts while its corpus is not yet trusted. No
  entry uses it today.

A rule with no entry gets `default`, which is **enforce at 0 hits**: a new rule must
stay silent on the corpus, or a human approves a budget for it. Every per-rule entry
must carry a `why` that starts `documented noise:` (a deliberately generic or hunting
rule, or a falsepositives class the rule names) or `rule defect, tracked in
detections/RULE_DEFECTS.md <ID>:`, naming an entry of
[`../RULE_DEFECTS.md`](../RULE_DEFECTS.md). `score_benign.py` fails on any other
`why`, on a cited ID that the tracker's summary table does not list, on a mode other
than `enforce` or `shadow`, on an `unscored` entry without a `why`, and on a
`budgets.json` key that names no rule.

Today every per-rule entry is `enforce`. Its `max_hits` is the most hits the rule
raised over the committed seed and ten reseeds of every synthetic slice
(`score_benign.py --reseeds 10` prints that figure), not one seed's exact count, so a
routine version bump of a slice does not trip it. That leaves headroom: most budgets
sit above the rule's hits at the committed seed. Two checks cover a rule that gets
noisier on the committed corpus:

- a rise past `max_hits` fails `benign-corpus` (`--check --enforce`) on every run,
  until a human raises the budget or the rule is fixed;
- on a pull request, any rise over the base branch's committed `scores.json`, even
  inside the headroom, fails `sufficiency-ratchet` (see
  [Tracking it over time](#tracking-it-over-time)), so that a human decides. That
  check is not required, so it stops `automerge` only if it has failed when an
  evaluation runs, before the required checks finish; if they finish first, GitHub
  merges (see
  [Branch protection](#branch-protection-what-binds-a-manual-merge)).

Fewer hits pass both, so a rule fix that makes the rule quieter passes; lower the
budget in the same pull request.

A rule that no slice reads is not scored. A slice reads a rule when it has the
rule's product and service; category counts only when neither names a service.
`--check`/`--enforce` fail for an unscored rule unless `budgets.json` lists it under
`unscored` with the reason, and a stale entry fails too. That stops a rule from
leaving scoring by moving to a log source no slice reads. A rule that moves to a log
source another slice reads stays scored, but its hits can drop to zero, while the
compiled query, which ignores the log source, still passes the validators. `check_sufficiency.py`
(R1) fails such a move for every rule a validator registers, because the rule's log
source must name the log its validator proves it on. R1 cannot see two moves: a cloud
validator entry names only the provider, so a cloud rule could move between the
services of one provider (Azure `activitylogs`, `auditlogs`, `signinlogs`); and a
`COMPILE_ONLY` rule has no validator log to compare. The `sufficiency-ratchet` check
covers both on a pull request: it fails when a rule that exists on the base branch
changes its logsource (or a correlation base's), so the move goes to a human.

A slice can hold real multi-event behaviour as a **sequence** template, sharing one
draw of the variables with per-step delays: runc's memfd re-exec, or a namespace
deletion and its controller's cleanup. Events drawn independently almost never line
up inside a correlation window. Keys that differ only by case (`requestId` and
`RequestID`) cannot share one slice, because SQLite folds column case; split such
records across slices.

## Tracking it over time

[`scores.json`](scores.json) is the committed snapshot of every rule's score
(hits, rate, distinct actors, per-slice hits) and of the corpus digest. The
`benign-corpus` check runs `score_benign.py --check --enforce`; `--check` fails when
a rule's score or the corpus digest differs from the snapshot. So any change that
moves a rule's false-positive count (a rule edit, a new rule, a corpus change) must
commit the new snapshot. The change then appears in the pull-request diff, and the
file's git history is the trend. The per-slice summary (each slice's version,
fidelity and event count) is informational: it is compared only when the corpus
digest changes, and `_doc` never is, so a hand edit there alone passes `--check`.

`--check` asks only whether the snapshot is current, so a pull request can make a
rule noisier and commit the new snapshot. On a pull request, `sufficiency-ratchet`
therefore also runs the head's `score_benign.py --baseline-scores` against the base
branch's committed `scores.json`. It scores the head's rules on the head's corpus
and compares each rule scored in both with the base snapshot:

- more hits fails, with `RISE <rule>: hits B -> H (budget M)` and the new or grown
  actors, so that a human decides (the failure stops `automerge` only if it has
  failed before the required checks finish; see
  [Branch protection](#branch-protection-what-binds-a-manual-merge));
- fewer or equal hits pass;
- a rule absent from the base snapshot is new, and its budget alone governs it;
- a rule in the base snapshot that is no longer scored is not compared.

When the corpus digest differs from the base's, it prints a note, and a rise that a
corpus or slice change causes fails too. This step reads the base snapshot as data
and runs no code from the base. It is skipped, with a notice, when the base has no
`scores.json`, and it fails on one it cannot read or that is not a scores snapshot.

```bash
python3 detections/score_benign.py              # report (with an explained example hit per rule)
python3 detections/score_benign.py --check      # is scores.json current?
python3 detections/score_benign.py --update     # rewrite scores.json after an intended change
python3 detections/score_benign.py --check --enforce   # what CI runs
python3 detections/score_benign.py --reseeds 10 # most hits over 10 reseeds: the basis for max_hits
python3 detections/score_benign.py --baseline-scores base-scores.json  # fail on any rule noisier than that snapshot
python3 detections/score_benign.py --extra-slice capture.jsonl \
    --extra-logsource linux/auditd --extra-label my-host   # score a live capture (shadow)
```

## Maintaining the corpus

Treat the corpus like test data:

- **Version it.** Bump a slice's `version` when you change it, and say in the pull
  request what activity it now represents.
- **Document it.** `represents`, `provenance` and `adjacent_to` must stay true.
  A synthetic slice states what its shapes are based on.
- **Grow it from reality.** When a rule false-positives in staging or production,
  add a sanitized slice (or templates) for that activity, so the regression stays
  fixed.
- **Keep it benign.** A slice holds only activity that is genuinely benign. If an
  event's benignity is in doubt, leave it out.
- **Never tune the corpus to silence a rule.** If a rule fires on realistic benign
  activity, fix the rule (record the defect in
  [`../RULE_DEFECTS.md`](../RULE_DEFECTS.md) until the fix lands), document the
  noise, or set a budget. Do not edit the corpus to hide the hit.

**A human signs off on what counts as benign enough, and on everything the gates
run.** An agent may propose new slices, templates and budget changes. The
`automerge` workflow, though, turns on GitHub's native auto-merge for a pull request
without a human only when *every* changed path is content:

- rules and their `.cases.jsonl` under `detections/sigma/T<id>/`;
- cloud fixtures;
- this directory's `scores.json` (derived: the benign-corpus check proves every
  rule's score and the corpus digest current, and `sufficiency-ratchet` fails a
  rule with more hits than on the base branch);
- `research/` (no `*.py`, nothing under `research/tools/`), `docs/` (except
  `docs/CODEOWNERS`), `upstream/`;
- Markdown outside `.github/`, any `.claude` entry (at the root or nested, such as
  `research/<trr>/.claude/skills/`) and `research/tools/`, except agent instruction
  files: `CLAUDE.md`, `CLAUDE.local.md` and `AGENTS.md` in any directory, matched in
  any letter case (as are `.github/`, `.claude` and `docs/CODEOWNERS`).

Anything else needs an approving review on the exact head commit. That includes
`budgets.json`, `slices/`, the live workloads, every `*.py` (the gate scripts,
`sigma_eval.py`, the validators), the workflows, `atomics/` other than Markdown
(the validator jobs compile, run or `kubectl apply` the atomics in the same job and
workspace as the validator, the Linux one as root, so an atomic could rewrite its
own gate), `docs/CODEOWNERS` (GitHub reads it when neither `.github/` nor the root
has one), a `.claude` entry at any depth, whether a directory or a symlink (an agent
loads a nested `.claude/skills/` for work under that directory), and every
new-technique pull request (it edits a validator `MANIFEST`, the workflow path
filters and its atomics). The approver must be a human (not a bot) with write,
maintain or admin permission who is neither the pull request's author nor an author
or committer of any of its commits, and the approval must be that reviewer's latest
decision and must have been submitted after the pull request's last base change: a
review records the head commit but not the base, so an approval given while the
pull request targeted another branch does not survive a retarget to `main`. A push
after the approval moves the head, so `automerge` disables the auto-merge it
enabled until a human approves the new head.

A commit's author and committer are e-mail addresses written by whoever made it, and
GitHub links them to an account without checking unless the commit carries a
verified signature. So a commit without a verified signature, or whose author or
committer is linked to no GitHub account, is unattributed. A pull request that needs
an approval and contains one is held for a human to merge by hand: no approval can be
shown to be independent of that commit.

Sidecar cases are content, so deleting or editing one does not need an approval by
path. The `sufficiency-ratchet` check catches it instead. The base branch's report
holds a digest of every sidecar case (its kind, `breaks` and events) and of every
verified negative, so the check fails when a case of any kind (positive, near-miss,
filtered, confounder or benign) is gone or changed, when a verified negative's cloud
fixture record is gone or changed, when a rule of the base is deleted or renamed,
and when a rule has fewer verified negatives, exercised items or passing positives
than on the base branch. Adding a case, or rewording a case's `why`, passes. The
check does not compare the rule's own detection: a broadened rule that keeps every
case passes it, and is left to its near-miss cases and the benign-hits comparison
above. `automerge` disables auto-merge on a pull request with a failed check on its
head commit, but `sufficiency-ratchet` is not a required check, so its failure stops
the bot's merge only if it has failed when an evaluation runs, before the required
checks finish. If the required checks finish first, GitHub merges (see
[Branch protection](#branch-protection-what-binds-a-manual-merge)).

An approval re-runs `automerge`: every review submitted, dismissed or edited starts
[`automerge-review-relay`](../../.github/workflows/automerge-review-relay.yml), and
its completion re-runs `automerge` from `main`'s copy. If the required checks have
already passed by then, GitHub will not enable auto-merge (there is nothing left to
wait for), the run logs a warning, and a human merges the pull request; the bot
never merges directly. Approvals usually come after the checks are green, so expect
to merge an approved pull request by hand. GitHub may also refuse to merge a pull
request that changes `.github/workflows/` under the bot's token, which has no
`workflows` permission; a human merges that one.

### Branch protection: what binds a manual merge

This rail binds only the `automerge` bot. A human with write access can still merge
a pull request by hand, or enable auto-merge on it themselves (`automerge` disables
only an auto-merge that it enabled), and only the repository's branch rules bind
that merge. The same rules decide what holds the bot's own merge: `automerge` only
turns GitHub's native auto-merge on and off, and GitHub merges as soon as the
required checks pass. `automerge` disables auto-merge when it sees a failed check
on the head commit, but it looks only when an evaluation runs (a label change, a
push, a review, or the completion of a CI workflow; a failed `detection-quality` job
is seen once that whole workflow, or another CI workflow, completes). So a check
that is not required holds the merge only if it has failed when an evaluation runs,
before the required checks finish. If the required checks finish first, GitHub
merges, and the failure comes too late.

#### With a single maintainer

This repository has one maintainer, and the agent opens its pull requests under that
maintainer's account. GitHub does not let anyone approve their own pull request, so
the bot's approval rail can never be met on these pull requests. That is the intended
outcome:

- A content-only pull request (rules, cases, fixtures, docs) auto-merges once its
  required checks pass, if it carries the `automerge` label.
- Any other pull request (Python, workflows, budgets, waivers, the corpus, atomics)
  never auto-merges. It waits for the maintainer to merge it by hand, and that merge
  is the sign-off.

Configure the `Main` ruleset for this:

1. **Require no approving review**, and no Code Owner review or most-recent-push
   approval. A maintainer cannot approve their own pull request, so a required
   approval would block every pull request. A `CODEOWNERS` file adds nothing with one
   owner.
2. **Require `rule-cases`, `check-sufficiency` and `benign-corpus`** as status checks,
   with the validator checks already required. GitHub's native auto-merge waits only
   for required checks, so without these a content-only pull request could auto-merge
   before a failing case, gate or budget check finished.
3. **Leave `sufficiency-ratchet` not required.** It fails by design on a change the
   maintainer may accept (an edited or relabelled case, a deliberate rise in benign
   hits with a raised budget). Made required, with no bypass actors, it would block
   such a pull request for everyone. Left out, it still holds the bot's merge when it
   fails before the required checks finish, and a maintainer merging by hand sees it
   red and decides.
4. Keep the ruleset free of bypass actors.

#### With a second approver

To put a second signature on record, open the agent's pull requests from a separate
account (a GitHub App or a machine user) so that the maintainer can approve them.
Then the bot's rail applies as written above: a non-content pull request auto-merges
only after the maintainer approves its head commit. To make the same rule bind a
manual merge, add `.github/CODEOWNERS` naming the approvers for every non-content
path, and turn on "Require review from Code Owners" and "Require approval of the most
recent reviewable push" in the ruleset. Keep the approval count at 0: 1 or more makes
every pull request wait for a human, content included, which ends content-only
auto-merge.
