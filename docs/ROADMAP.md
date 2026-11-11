# Roadmap

The ordered work for this repository. An AI agent owns and maintains the codebase
(see [`AGENTS.md`](../AGENTS.md)). This file is how one session tells the next
what the direction is.

Last update: 2026-11-11.

## The goal

One owner, little direction. The agent researches, emulates and writes detections.
Coverage grows quickly, and CI, not a person who reads each pull request, shows
that a detection works.

The reasons for each item are in two design records:

- [`design/2026-11-09-design-review.md`](design/2026-11-09-design-review.md): what
  is wrong today, with evidence.
- [`design/2026-11-09-operating-design.md`](design/2026-11-09-operating-design.md):
  the target design. Its sections are cited below as "design 4.2".

## How to use this file

- When you have no other task from a person, take the first item below that is
  `not started` and whose "needs" are `done`. Work top to bottom.
- One item for each pull request. Keep the pull request small enough to review.
- Change the status of the item in the same pull request. Add what you learned
  under the item if it changes a later item.
- An item is `done` only when its acceptance check is true on `main`.
- If you find that an item is wrong, change the item and say why in the pull
  request. The direction is yours to correct.
- Do not start an item marked `owner`. Tell the owner what it waits for.

Status words: `done`, `in progress`, `not started`, `owner` (only the owner can do
it), `blocked` (with the reason).

## 1. Trust: make a green run mean something

The order matters. Tests for the gates come before each change to the gates.

| ID | Item | Status | Needs | Acceptance check |
|----|------|--------|-------|------------------|
| R2 | **The gates test themselves** (design 4.2). A set of planted bad artifacts that each gate must reject, and a CI job that runs it with the self-tests that no workflow runs today. | in progress | | A job on each pull request fails when a gate stops rejecting a planted artifact. Each planted artifact is rejected for its intended reason, not for a side effect. The suite is `detections/tests/` and the job is `gate-tests`. The item is `done` when that job is green on `main`. |
| R2b | **Linux controls are not vacuous** (design 4.2). Grade vacuity for each control. Replace the no-op control with a wrong-argument control for the rules that have no other live negative. | not started | R2 | For each Linux rule, one live negative control would fire the rule if one required argument changed. |
| R2c | **Negative controls and baselines cannot be empty** (design 4.2). A negative control that read no record cannot fail. Each Kubernetes validator fails `--expect-miss` when a pre-emulation log holds no record. The cloud validator fails a benign baseline that holds no record, and a rule of its `MANIFEST` whose fixture is missing. | not started | R2 | Its known-gap tests are rejection tests. Each validator exits with an error that names the empty log, the empty baseline or the missing fixture. |
| R2d | **Hygiene and report truth** (design 4.2). No rule file is hidden from the gates: a rule in a dotfile under `detections/sigma/` fails. The coverage report counts an entry of `detections/RULE_DEFECTS.md` that has a section and no Summary row. `rule_cases.py` names the rule and the case when two keys of an event differ only in letter case, and does not stop with a traceback. | not started | R2 | Its known-gap tests are rejection tests. Each gate exits with an error that names the hidden file, the defect entry or the case. |
| R7 | **Representation variants in the oracle** (design 4.7). Run each case as compact JSON, sorted JSON, a multi-valued list model, case-sensitive `LIKE` and RE2. Correct the two GCP rules that lose their hit under compact JSON. Write `detections/SEMANTICS.md`. | not started | R2 | A check fails on a new divergence between variants. The known losses are listed as expected, each with a reason. |
| R3 | **External records** (design 4.3). Records that the agent did not write, from `splunk/attack_data` (Apache-2.0), pinned by hash. A same-technique record must fire the rule unless a protected file says why not. | not started | R2 | The check runs in CI in shadow mode and reports each rule's result on each same-technique dataset. The first real-record miss has a defect entry. |
| R4 | **Harvest the captures of CI** (design 4.4). The lab validators write the records that the kernel or the API server produced. A scheduled job commits them as evidence. | not started | R2, T8 | A Linux or Kubernetes rule has a committed captured positive that the agent did not write by hand. |
| R5 | **Provenance tiers** (design 4.5). Each case and fixture says where it came from. The coverage report shows `proven-live`, `proven-recorded`, `proven-synthetic` and `claimed`. Stop calling a hand-written fixture "recorded". | not started | R3 | The coverage report does not call a cloud procedure Proven when its only evidence is a fixture that the agent wrote. |
| R6 | **Mutation ratchet** (design 4.6). Build mutants of each rule. The count of surviving mutants for a rule must not rise. | not started | R2 | A pull request that adds a dead or over-broad item to a rule fails. |
| R1 | **Gate code from `main`** (design 4.1). Each checking job runs the gate code of `main`, not of the pull request. | not started | T2, T5 | A pull request that changes a gate and a rule together cannot make its own rule pass. Until T2 and T5 are done, each technique pull request must edit the validators, so this item waits for them. |
| R8 | **Approvals as checked properties** (design 4.8). A waiver or a budget is accepted only when a machine can check its conditions. | not started | R5 | A waiver that does not meet its conditions fails a check. |
| R9 | **Live cloud capture** (design 4.9). | in progress | owner | The setup guides and the smoke test are merged (`docs/setup/`). Open: the owner creates the accounts; `atomics/lib/live.sh` with an undo stack; the capture workflow; one supervised run. No gate reads the live emulation scripts today. Thus a live script without an undo trap has no gate test until `atomics/lib/live.sh` and its lint exist. |

The gate tests (R2) record known gaps. A known gap is an artifact that a gate
should reject and does not reject today. `python3 -B detections/tests/gatelib.py --gaps`
lists them, each with the item of this table that closes it. To close an item,
correct the gate and, in the same pull request, change each of its known-gap tests
into a rejection test (see [`detections/tests/README.md`](../detections/tests/README.md),
"Known gaps").

## 2. Throughput: many builders, no hand integration

| ID | Item | Status | Needs | Acceptance check |
|----|------|--------|-------|------------------|
| T2 | **A sidecar for each rule** in place of each shared registry (design 5): the `MANIFEST` lists, waivers, budgets, defects. | not started | R2 | A new technique changes no file outside its own directories. |
| T5 | **Workflow wiring derived at run time** (design 5). No hand-copied path list. | not started | T2 | A new technique changes no workflow file. |
| T1 | **One technique for each pull request**, enforced by a check, with the TRR ID from the backlog issue number (design 5). | not started | T2, T5 | A pull request with two new TRR directories fails. |
| T3 | **Fragments for each TRR** for `research/index.json`, the README table and the Atomic Red Team YAML (design 5). | not started | T2 | Two technique pull requests that are open together do not conflict. |
| T4 | **Derived files leave the diff** (design 5): `scores.json`, `policy_coverage.json`, `COVERAGE.md`, the charts. | not started | T2 | A technique pull request holds no generated file. |
| T6 | **Emulate and validate in separate jobs** for the kind workflows (design 5). | not started | R1 | The job that grades a Kubernetes rule runs no code from the pull request. |
| T7 | **The backlog as issues** (design 5), ranked by a script, with the GO or NO-GO result in each issue. | not started | L3 | Each candidate is an issue with its vet result. |
| T8 | **The builder workflow**: the agent opens its pull requests from GitHub Actions. | blocked | owner | Waits for the identity gate (`docs/setup/agent-identity.md`, step A5). Then: a workflow that takes one backlog issue and opens one pull request as the agent's identity, with the off switch and a turn limit. |

## 3. The life of a detection after it merges

| ID | Item | Status | Needs | Acceptance check |
|----|------|--------|-------|------------------|
| L6 | **Supply chain** (design 8): pin each action in each workflow to a commit, add `dependabot.yml`, pin `sigma-cli` to the pySigma version of the validators. | not started | | No workflow uses an action by tag. The lint job and the validators resolve the same pySigma. |
| L7 | **Correct the live scripts** that the sandbox guide lists as defective (`docs/setup/cloud-sandbox.md`, "Problems in the live scripts"). | not started | | Each listed script runs to its end in dry-run mode and its live commands agree with the provider reference. The table in the guide is shorter. |
| L2 | **A machine condition to close a defect** (design 6): a `known-miss` case that must not fire today and becomes a positive when the rule is corrected. | not started | R2 | Each open false-negative defect has a case that fails when the defect is fixed without closing it. |
| L1 | **A path to retire or rewrite a rule** (design 6). | not started | T2 | A rule can be retired with a defect citation and no override label. |
| L3 | **What 100 % coverage means** (design 6). | owner | | The owner confirms or changes the recommendation in `docs/setup/README.md`. Then write it into `research/README.md` and report against it. |
| L4 | **The review job** (design 6): make it run the skeptic checks for each changed rule, or remove it. Restore `AGENTS.md` from `main` in it. Name the agent in `allowed_bots`. | not started | | The review job cannot be instructed by the pull request that it reviews. |
| L5 | **Vendor documents drift** (design 6): a hash for each source of a TRR, read again each month. | not started | T8 | A changed vendor page gives a row in a report. |

## 4. What waits for the owner

These need a repository setting, a payment card or a decision. An agent session
must not do them. The steps are in [`setup/`](setup/README.md).

| Item | Where | Date |
|------|-------|------|
| The Actions policy that keeps `automerge.yml` in operation | `setup/repository-settings.md`, first section | Before 2026-12-02 |
| The identity probe and the gate | `setup/agent-identity.md`, A1 to A5 | Blocks T8 |
| Labels, the off switch, `null-safety` as a required check | `setup/repository-settings.md`, steps 1 to 5 | |
| What 100 % coverage means | `setup/README.md`, "Decisions" | Blocks T7 |
| Cloud sandbox accounts (optional) | `setup/cloud-sandbox.md` | Blocks the rest of R9 |

## 5. New detections

New techniques continue to be valid work: load the `trr` skill and follow
[`AGENTS.md`](../AGENTS.md). Until R3 and R5 are done, a cloud rule has no evidence
that the agent did not write. Thus, between a trust item and a new cloud technique,
do the trust item first. A Linux or Kubernetes technique has a live oracle in CI
and does not have that limit.
