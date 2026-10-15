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
| Benign corpus (`score_benign.py`) | How much does it fire on normal activity? | scored: hits, rate, actors | when `scores.json` is stale, a rule is unscored without an exemption, or an `enforce`-mode rule is over budget |

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
routine version bump of a slice does not trip it. So a rule that gets noisier on the
committed corpus fails CI until a human raises its budget, and a rule fix that makes
it quieter passes; lower the budget in the same pull request.

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

```bash
python3 detections/score_benign.py              # report (with an explained example hit per rule)
python3 detections/score_benign.py --check      # is scores.json current?
python3 detections/score_benign.py --update     # rewrite scores.json after an intended change
python3 detections/score_benign.py --check --enforce   # what CI runs
python3 detections/score_benign.py --reseeds 10 # most hits over 10 reseeds: the basis for max_hits
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
`automerge` workflow, though, merges a pull request without a human only when
*every* changed path is content:

- rules and their `.cases.jsonl` under `detections/sigma/T<id>/`;
- cloud fixtures;
- this directory's `scores.json` (derived: the benign-corpus check proves every
  rule's score and the corpus digest current);
- `research/` (no `*.py`, nothing under `research/tools/`), `docs/`, `upstream/`;
- `atomics/`, including the C and shell emulation sources that CI compiles and runs
  (the Linux validator runs its atomics as root);
- Markdown outside `.github/`, `.claude/` and `research/tools/`, except agent
  instruction files: `CLAUDE.md`, `CLAUDE.local.md` and `AGENTS.md` in any directory,
  matched in any letter case (as are `.github/` and `.claude/`).

Anything else needs an approving review on the exact head commit. That includes
`budgets.json`, `slices/`, the live workloads, every `*.py` (the gate scripts,
`sigma_eval.py`, the validators), the workflows, and every new-technique pull
request (it edits a validator `MANIFEST` and the workflow path filters). The
approver must be a human (not a bot) with write, maintain or admin permission who
is neither the pull request's author nor an author or committer of any of its
commits. A pull request that needs an approval and has a commit whose author or
committer is linked to no GitHub account is held for a human to merge by hand: no
approval can be shown to be independent of that commit.

Sidecar cases are content, so deleting or weakening one does not need an approval
by path. The `sufficiency-ratchet` check catches it instead: it fails when a rule
has fewer verified negatives, exercised items or passing positives than on the base
branch, and `automerge` holds a pull request with a failed check.

After approving, remove and re-add the `automerge` label, or merge by hand; an
approval alone does not re-run `automerge`.

### Branch protection: what binds a manual merge

This rail binds only the `automerge` bot. A human with write access can still merge
a pull request by hand, and only the repository's branch rules bind that merge.
They are configured in the repository settings, outside the code, and as of
2026-10-15 (read with the GitHub API) they do **not** enforce the sign-off:

- `main` is governed by the repository ruleset `Main` (active, with no bypass
  actors), not by classic branch protection. It requires a pull request, squash
  merges and a linear history, and blocks deletion and force pushes.
- It requires these status checks: `trr-lint`, `validate`, `sigma-lint`,
  `markdown-links`, `validate-k8s`, `validate-staticpod`, `validate-cloud`,
  `validate-apiserver`. It does not require the `detection-quality` checks
  (`rule-cases`, `check-sufficiency`, `sufficiency-ratchet`, `benign-corpus`).
- It requires **no** approving review, **no** Code Owner review and **no** approval
  of the most recent push. The repository has no `CODEOWNERS` file.

So today anyone with write access can merge a budget, corpus, gate or workflow
change by hand, with no second human, once the required validator checks pass.

To make the sign-off bind a manual merge, a repository admin must:

1. Add `.github/CODEOWNERS` that names the human approvers for every path that is
   not content (the list above).
2. In the `Main` ruleset, turn on "Require review from Code Owners" and "Require
   approval of the most recent reviewable push". Choose the approval count with
   care: 1 or more makes every pull request wait for a human, content included,
   which ends content-only auto-merge. With 0, Code Owner review applies to the
   code-owned paths only. Check the result on a test pull request; it was not
   verified here.
3. Add `rule-cases`, `check-sufficiency`, `sufficiency-ratchet` and `benign-corpus`
   as required status checks (not `benign-linux-live`, which is shadow only).
4. Keep the ruleset free of bypass actors.

Until then, the sign-off is a convention for manual merges, and a rule of the bot
only.
