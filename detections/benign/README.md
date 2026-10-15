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
| Benign corpus (`score_benign.py`) | How much does it fire on normal activity? | scored: hits, rate, actors | only for rules in `enforce` mode |

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
- **actors**: the distinct processes (auditd `exe`) or principals (Kubernetes
  `user.username`, CloudTrail `userIdentity.arn`, ...) behind the hits. One noisy
  actor is an allowlist candidate; fifty distinct actors means the rule is too broad;
- **slices**: which slices the hits came from;
- an **explained example hit** per rule: which items of the rule held on the
  benign event, so the cause is visible without reproducing it.

A plain "zero hits" bar gets brittle once the corpus grows. Counts, rates and
actors show *how* a rule is noisy, and the committed snapshot tracks that over time.

## Budgets, shadow mode and enforcement

[`budgets.json`](budgets.json) sets, per rule, how many benign hits are acceptable
(`max_hits`, optionally `max_rate_per_10k`) and what happens when a rule goes over:

- **`shadow`**: the overrun is a CI warning (an annotation on the run), never a
  failure. Use this for a rule whose corpus is not yet trusted, or for a
  deliberately generic hunting rule whose noise is the documented cost.
- **`enforce`**: the overrun fails the `benign-corpus` check.

A rule with no entry gets `default`. Every entry must carry a `why`.

## Tracking it over time

[`scores.json`](scores.json) is the committed snapshot of every rule's score
(hits, rate, distinct actors, per-slice hits) and of the corpus digest. The
`benign-corpus` check runs `score_benign.py --check`, which fails when the snapshot
is stale. So any change that moves a rule's false-positive count (a rule edit, a
new rule, a corpus change) must commit the new snapshot. The change then appears
in the pull-request diff, and the file's git history is the trend.

```bash
python3 detections/score_benign.py              # report (with an explained example hit per rule)
python3 detections/score_benign.py --check      # is scores.json current?
python3 detections/score_benign.py --update     # rewrite scores.json after an intended change
python3 detections/score_benign.py --enforce    # what CI runs: fail on enforce-mode overruns
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
  activity, fix the rule, document the noise, or set a budget. Do not edit the
  corpus to hide the hit.

**A human signs off on what counts as benign enough.** An agent may propose new
slices, templates and budget changes. But a number of paths are protected:

- `budgets.json` and anything under `slices/`;
- the gate scripts: `check_sufficiency.py`, `rule_cases.py`, `sigma_explain.py`,
  `score_benign.py` and `benign_corpus.py`;
- the `detection-quality` and `automerge` workflows.

The `automerge` workflow will not merge a pull request that changes any of them
without an approving review on its exact head commit. That review must come from
a human collaborator who is not the pull request's author. Otherwise a human
merges it.
