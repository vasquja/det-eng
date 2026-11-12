# Roadmap

The ordered work for this repository. An AI agent owns and maintains the codebase
(see [`AGENTS.md`](../AGENTS.md)). This file is how one session tells the next
what the direction is.

Last update: 2026-11-12.

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

- First read each item that is `in progress`. If its acceptance check is true on
  `main`, set it to `done` in your pull request.
- When you have no other task from a person, take the first item below that is
  `not started` and whose "needs" are `done`. Work top to bottom.
- One item for each pull request. Keep the pull request small enough to review.
- Change the status of the item in the same pull request. Add what you learned
  under the item if it changes a later item.
- An item is `done` only when its acceptance check is true on `main`.
- Do not set an item to `done` while
  `python3 -B detections/tests/gatelib.py --gaps` lists a gap that it closes.
- The gate tests read section 1 of this file (`detections/tests/test_suite.py`,
  class `KnownGapList`). When you add, remove or rename an item of section 1,
  change the table `ROADMAP` in `detections/tests/gatelib.py` in the same pull
  request. Write only a status word in the Status cell, and put a reason in the
  Needs cell.
- If you find that an item is wrong, change the item and say why in the pull
  request. The direction is yours to correct.
- Do not start an item marked `owner`. Tell the owner what it waits for.

Status words: `done`, `in progress`, `not started`, `owner` (only the owner can do
it), `blocked` (with the reason in the Needs cell).

## 1. Trust: make a green run mean something

The order matters. Tests for the gates come before each change to the gates.

| ID | Item | Status | Needs | Acceptance check |
|----|------|--------|-------|------------------|
| R2 | **The gates test themselves** (design 4.2). A set of planted bad artifacts that each gate must reject, and a CI job that runs it with the self-tests that no workflow runs today. | done | | A job on each pull request fails when a gate stops rejecting a planted artifact. Each planted artifact is rejected for its intended reason, not for a side effect. The suite is `detections/tests/` and the job is `gate-tests`. The item is `done` when that job is green on `main`. |
| R2b | **Linux controls are not vacuous** (design 4.2). Grade vacuity for each control. Replace the no-op control with a wrong-argument control for the rules that have no other live negative. | not started | R2 | For each Linux rule, one live negative control would fire the rule if one required argument changed. |
| R2c | **Negative controls and baselines cannot be empty** (design 4.2). A negative control that read no record cannot fail. Each Kubernetes validator fails `--expect-miss` when a pre-emulation log holds no record. The cloud validator fails a benign baseline that holds no record, and a rule of its `MANIFEST` whose fixture is missing. | not started | R2 | Its known-gap tests are rejection tests. Each validator exits with an error that names the empty log, the empty baseline or the missing fixture. |
| R2d | **Hygiene and report truth** (design 4.2). No rule file is hidden from the gates: a rule in a dotfile under `detections/sigma/` fails. The coverage report counts an entry of `detections/RULE_DEFECTS.md` that has a section and no Summary row. `rule_cases.py` names the rule and the case when two keys of an event differ only in letter case, and does not stop with a traceback. | not started | R2 | Its known-gap tests are rejection tests. Each gate exits with an error that names the hidden file, the defect entry or the case. |
| R7 | **Representation variants in the oracle** (design 4.7). Run each case as compact JSON, sorted JSON, a multi-valued list model, case-sensitive `LIKE` and RE2. Correct the two GCP rules that lose their hit under compact JSON. Write `detections/SEMANTICS.md`. | not started | R2 | A check fails on a new divergence between variants. The known losses are listed as expected, each with a reason. Two rules lose their hit under compact JSON today: `T1199/gcp_workforce_principalset_privileged_binding.yml` and `T1098.001/gcp_workload_identity_federation_sa_binding.yml`. This item records both in `detections/RULE_DEFECTS.md` and corrects them. |
| R3 | **External records** (design 4.3). Records that the agent did not write, from `splunk/attack_data` (Apache-2.0), pinned by hash. A same-technique record must fire the rule unless a protected file says why not. | not started | R2 | The check runs in CI in shadow mode and reports each rule's result on each same-technique dataset. The first real-record miss has a defect entry. |
| R4 | **Harvest the captures of CI** (design 4.4). The lab validators write the records that the kernel or the API server produced. A scheduled job commits them as evidence. | not started | R2, T8 | A Linux or Kubernetes rule has a committed captured positive that the agent did not write by hand. |
| R5 | **Provenance tiers** (design 4.5). Each case and fixture says where it came from. The coverage report shows `proven-live`, `proven-recorded`, `proven-synthetic` and `claimed`. Stop calling a hand-written fixture "recorded". | not started | R3 | The coverage report does not call a cloud procedure Proven when its only evidence is a fixture that the agent wrote. |
| R6 | **Mutation ratchet** (design 4.6). Build mutants of each rule. The count of surviving mutants for a rule must not rise. | not started | R2 | A pull request that adds a dead or over-broad item to a rule fails. |
| R1 | **Gate code from `main`** (design 4.1). Each checking job runs the gate code of `main`, not of the pull request. | not started | T2, T5 | A pull request that changes a gate and a rule together cannot make its own rule pass. Until T2 and T5 are done, each technique pull request must edit the validators, so this item waits for them. |
| R8 | **Approvals as checked properties** (design 4.8). A waiver or a budget is accepted only when a machine can check its conditions. | not started | R5 | A waiver that does not meet its conditions fails a check. |
| R9 | **Live cloud capture** (design 4.9). | in progress | owner | The setup guides and the smoke test are merged (`docs/setup/`). Open: the owner creates the accounts; `atomics/lib/live.sh` with an undo stack; the capture workflow; one supervised run. The job `emulation-scripts` (L7) tests six live scripts with stub CLIs; the other live scripts have no test. Thus a live script without an undo block has no test until `atomics/lib/live.sh` and its lint exist. |

The gate tests (R2) record known gaps. A known gap is an artifact that a gate
should reject and does not reject today. `python3 -B detections/tests/gatelib.py --gaps`
lists them, each with the item of this table that closes it. To close an item,
correct the gate and, in the same pull request, change each of its known-gap tests
into a rejection test (see [`detections/tests/README.md`](../detections/tests/README.md),
"Known gaps"). The gate tests also read this table: see "How to use this file".

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
| L6 | **Supply chain** (design 8): pin each action in each workflow to a commit, add `dependabot.yml`, pin `sigma-cli` to the pySigma version of the validators. | not started | R2 (the check that no action is used by tag is a gate test, and the `gate-tests` job is one of the jobs to pin) | No workflow uses an action by tag. The lint job and the validators resolve the same pySigma. |
| L7 | **Correct the live scripts** that the sandbox guide lists as defective (`docs/setup/cloud-sandbox.md`, "Problems in the live scripts"). | done | | Each listed script runs to its end in dry-run mode and its live commands agree with the provider reference. The table in the guide is shorter. |
| L2 | **A machine condition to close a defect** (design 6): a `known-miss` case that must not fire today and becomes a positive when the rule is corrected. | not started | R2 | Each open false-negative defect has a case that fails when the defect is fixed without closing it. |
| L1 | **A path to retire or rewrite a rule** (design 6). | not started | T2 | A rule can be retired with a defect citation and no override label. |
| L3 | **What 100 % coverage means** (design 6). | owner | | The owner confirms or changes the recommendation in `docs/setup/README.md`. Then write it into `research/README.md` and report against it. |
| L4 | **The review job** (design 6): make it run the skeptic checks for each changed rule, or remove it. Restore `AGENTS.md` from `main` in it. Name the agent in `allowed_bots`. | not started | | The review job cannot be instructed by the pull request that it reviews. |
| L5 | **Vendor documents drift** (design 6): a hash for each source of a TRR, read again each month. | not started | T8 | A changed vendor page gives a row in a report. |

What L7 did, and what it found for later items:

- Six scripts under `atomics/` were corrected, and the copy of the TRR9020 script
  for upstream filing. The tests in [`atomics/tests/`](../atomics/tests/README.md)
  run each one with a stub in the place of each cloud CLI, and the CI job
  `emulation-scripts` runs the tests. No command ran against a cloud account. The
  provider reference was the Google Cloud SDK (its help and its argument parser) and
  Microsoft Learn. Only a live run shows that a provider accepts a command and
  writes the record: that stays for R9.
- Each of the five scripts that makes a change holds the same undo block
  (`atomics/tests/undo_block.sh`). R9 moves the block to `atomics/lib/live.sh` and
  gives it to the other live scripts. The tests send the signals `HUP`, `INT` and
  `TERM` to a script. No test shows what each CLI does when a browser shell
  disconnects and the undo commands have no terminal to write to.
- R9 must keep these properties of the undo block. A script registers the undo
  after the command that makes the change, so a stop signal during that command
  must wait for the registration (`change_next`). An undo command that a signal
  stops must start again, two times at most, and one that
  ran to its end must not run again. A stop signal that comes when the run already
  ends must not skip the undo: bash does not start the EXIT trap a second time, so
  the signal trap must not call a plain `exit`. A reader of the output that goes
  away (`| head`) must not stop the undo. A create command whose answer is not one
  ID has no undo: the run must stop and name the change. The block holds no command
  substitution: with bash 5.2.21, a stop signal at the start of a `$( )` ends the
  run with a syntax error of bash (exit 2; the exit path runs all the same). The
  lines of a script that read the answer of a create command with `$( )` still
  have that fault: R9 can read such an answer from a file (a process substitution has the same fault). The
  table "What is open" in
  [`setup/cloud-sandbox.md`](setup/cloud-sandbox.md#problems-in-the-live-scripts)
  lists the scripts that do not have the block.
- For R5 and R9, three fixtures hold a record that the provider possibly does not
  write. This is not confirmed, because no live record exists. `trr9018/attack.json`:
  a provider with the GitHub issuer and no attribute condition (Google requires a
  condition for that issuer), and with the provider ID `gh` (the SDK says that an ID
  has 4 to 32 characters). `trr9020/attack.json`: a workforce provider with no
  `oidc.webSsoConfig` (the SDK makes that field necessary). `trr9038/attack.json`: a
  successful delete of the `_Default` sink and of the `_Default` bucket (the
  documents of Google, as far as they were read, say that these cannot be deleted),
  and a `CreateExclusion` record whose user agent names `gcloud logging exclusions
  create`, a command that the Google Cloud SDK 570.0.0 does not have.
  A fourth fixture differs from the live command, not from the provider:
  `trr9013/attack.json` holds the subject `repo:trr9013-attacker/*` and a
  description, and the script now sends an exact subject and no description (the
  paired rule reads the issuer only).
  CI is green because the paired rules match these records, or do not read the
  field that differs (the value of the issuer, `webSsoConfig`, the user agent), and
  no gate compares a fixture with what the provider writes. The first live capture
  of each technique must replace the fixture. For `trr9038`, the two `_Default`
  delete records are the only fixture records for the `DeleteSink` and
  `DeleteBucket` branch of the rule: R5 must decide what holds that branch.
- TRR9038 procedure B has no safe live run that fires its rule. The rule reads a
  bucket operation only on `_Default`, and the script deletes only a spare bucket.
  The live record of B is thus the benign baseline of the rule.

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
