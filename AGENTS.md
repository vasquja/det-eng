# AGENTS.md

Operating guide for AI agents in this repository. Humans: see [`README.md`](README.md).

## Purpose

Detection engineering at scale. Turn one ATT&CK technique on one platform into
Sigma detections that CI **proves** work. Validation, not your judgment of the
rule, decides what is done.

## Definition of done

A detection change is done only when CI shows all of these:

1. **Fires.** The rule matches telemetry produced by its own emulation (the
   atomic's process tree, or a record carrying the emulation's marker), not
   just any matching event in the log.
2. **Stays quiet.** The rule matches nothing in its controls:
   - Linux (auditd): no-op, broken mutants, allowlisted process names.
   - Kubernetes: the audit log captured before the emulation (`--expect-miss`).
   - Cloud: a hard benign baseline that differs from the attack only in the
     discriminating field.
3. **Has sufficient checks.** The rule's sidecar
   `detections/sigma/<ATT&CK-ID>/<stem>.cases.jsonl` holds a positive and at least
   one near-miss: a variant that shares the chokepoint but breaks one required
   field (declared in `breaks`), which `rule_cases.py` proves is the single flip
   that would fire the rule. `check_sufficiency.py` fails a rule with no verified
   near-miss or filtered negative, or one that keys on the emulation's names.
4. **Stays within its benign budget.** `score_benign.py --check --enforce` passes:
   the rule's hits on the benign corpus (`detections/benign/`) are within its
   budget (0 for a new rule), and `scores.json` is current.
5. **Lints clean.** `trr_lint.py`, `check_md_links.py`, `check_sigma_regex.py` (every
   `|re` value stays in the portable regex subset) and `sigma check` pass.

Never skip, disable, or loosen a control, a test, a case, or a benign baseline to
get green, and never edit the corpus to silence a rule. Fix the rule, or record the
defect in [`detections/RULE_DEFECTS.md`](detections/RULE_DEFECTS.md). A failure
message names the event, the item and the value that failed; read it before you
change anything.

## Workflow

For any TRR or new detection, load the `trr` skill first:
[`.claude/skills/trr/SKILL.md`](.claude/skills/trr/SKILL.md). Order:

1. **Select and novelty-vet** (GO/NO-GO gate) before building anything.
2. **Research.** Pin exact telemetry field names and types from primary sources.
3. **Build** the artifacts below.
4. **Prove** with the validators.
5. **Review adversarially.** Reproduce every finding with `detections/sigma_eval.py`.
6. Open the PR and drive it to green.

## Artifacts per technique

| Artifact | Path |
|----------|------|
| TRR | `research/trrNNNN/<platform>/README.md`, copied from `research/templates/TRR-TEMPLATE.md` |
| DDMs | `research/trrNNNN/<platform>/ddms/*.json`, rendered to PNG with `python3 research/tools/render_ddm.py <json...>` |
| Index | Entry in `research/index.json` and a row in the table in `research/README.md` |
| Coverage report | Regenerate with `python3 research/tools/coverage_report.py` (updates `research/COVERAGE.md` and the README chart) |
| Emulation | `atomics/<ATT&CK-ID>/` |
| Sigma rule | `detections/sigma/<ATT&CK-ID>/*.yml`, `status: experimental` |
| Rule cases | `detections/sigma/<ATT&CK-ID>/<stem>.cases.jsonl`: positive, near-miss, filtered, confounder and benign cases |
| Cloud fixtures | `detections/cloud/fixtures/<trr>/`: attack + benign |
| Validator entry | The `MANIFEST` list in the matching `detections/validate_*.py` |
| CI wiring | In the matching `.github/workflows/validate-*.yml`, add the new `detections/sigma/<ATT&CK-ID>/` and `atomics/<ATT&CK-ID>/` paths to both the `push: paths:` list and the `changes`-job pattern list. Keep the two in sync, or the PR skips behavioral validation. |

## Conventions

- **IDs.** Local TRR IDs use the `TRR9000+` band. Procedure IDs are
  `TRRID.PLATFORM.LETTER` (e.g. `TRR9001.LIN.A`). A procedure is a distinct
  execution path, not a tool.
- **Platform codes.** `lin`, `k8s`, `aws`, `azr`, `gcp` (tired-labs `platforms.json`).
- **Chokepoint first.** One rule at the invariant chokepoint that covers the most
  procedures; per-procedure rules only for what it misses.
- **ATT&CK version.** Enterprise v20 IDs and tactic names (see `research/README.md`).
- **Prose.** Simplified Technical English (ASD-STE100) where practical.
- **Safe fixture markers only.** RFC 5737 IPs, `example.com`, AWS account
  `123456789012`, `trr90NN-` resource names.
- **Emulations stop before harm.** Live cloud emulations are gated by
  `TRR90NN_LIVE=1` and never run in CI.

## Commands

```bash
pip install -r detections/requirements.txt

# Cloud (AWS / Azure / GCP): recorded attack + benign fixtures, pure Python
python3 detections/validate_cloud_detections.py

# Linux (auditd): compile only; a real run needs root + auditd
python3 detections/validate_detections.py --dry-run
sudo python3 detections/validate_detections.py

# Kubernetes: compile only; a real run needs an audit log from a kind cluster
python3 detections/validate_k8s_detections.py --dry-run
python3 detections/validate_staticpod_detections.py --dry-run
python3 detections/validate_apiserver_detections.py --dry-run

# Rule cases, the sufficiency gate and the benign corpus (offline)
python3 detections/rule_cases.py
python3 detections/check_sufficiency.py
python3 detections/score_benign.py --check --enforce

# Null safety: every rule gives the same hits in two- and three-valued logic
python3 detections/check_null_safety.py

# Kubernetes platforms (offline): audit-policy simulator and provider field mappings.
# After a Kubernetes rule, case, lab policy or MANIFEST change: --update / --write.
python3 detections/k8s_policy_coverage.py --check
python3 detections/check_provider_mappings.py --check

# Procedure coverage report (README chart + research/COVERAGE.md); --check in CI
python3 research/tools/coverage_report.py

# Lint
python3 .github/scripts/trr_lint.py
python3 .github/scripts/check_md_links.py
python3 .github/scripts/check_sigma_regex.py   # portable |re subset; --require-re2 with google-re2
sigma check -x attacktag -x d3_fendtag -x cartag detections/sigma/
```

Each validator's details are in [`detections/README.md`](detections/README.md).

## Boundaries

- **Not production.** Rules ship `status: experimental`.
- **Novelty claims need evidence.** Never write "first" or "only" without vetting
  prior art (Stratus Red Team, Atomic Red Team, SigmaHQ, Elastic, Splunk, Panther).
  Name the nearest existing rule.
- **Upstream filing is a human step.** Prepare artifacts per
  [`UPSTREAM.md`](UPSTREAM.md); do not open PRs against tired-labs, Atomic Red
  Team, or SigmaHQ.
- **Merging is a human decision.** A human merges, or adds the `automerge` label.
  With the label, the `automerge` workflow turns on GitHub's native auto-merge only
  while its rails hold: a pull request that changes anything but content (rules,
  cases, fixtures, docs) also needs an approval on its head commit from an
  independent human. With one maintainer, who authors your pull requests, that
  approval cannot exist, so such a pull request waits for the maintainer to merge it
  by hand. Do not add that label yourself. Budgets, corpus slices and
  check waivers are human decisions too: propose them in the pull request.
