# Detection at Scale

[![lint-trr](https://github.com/vasquja/det-eng/actions/workflows/lint-trr.yml/badge.svg)](https://github.com/vasquja/det-eng/actions/workflows/lint-trr.yml) [![validate-detections](https://github.com/vasquja/det-eng/actions/workflows/validate-detections.yml/badge.svg)](https://github.com/vasquja/det-eng/actions/workflows/validate-detections.yml) [![validate-apiserver-detections](https://github.com/vasquja/det-eng/actions/workflows/validate-apiserver-detections.yml/badge.svg?event=schedule)](https://github.com/vasquja/det-eng/actions/workflows/validate-apiserver-detections.yml) [![validate-cloud-detections](https://github.com/vasquja/det-eng/actions/workflows/validate-cloud-detections.yml/badge.svg)](https://github.com/vasquja/det-eng/actions/workflows/validate-cloud-detections.yml)

**AI-written detections that have to prove they work.**

Attackers use AI to find and exploit weaknesses faster than people can review
them. Defenders cannot answer that one hand-written rule at a time; they need
**detection at scale**. This repository is an experiment in how to get there:
an AI agent does the detection engineering (research, attack emulation, Sigma
rules) across Linux, Kubernetes, AWS, Azure, and GCP, and an automated
validation loop decides what counts as done.

## Validation is the point

Writing a rule is cheap. A rule that looks right but never fires is worse than
no rule, because it gives false confidence. So nothing here is accepted on the
agent's word. Before a detection merges, CI must show that:

- **It fires on the attack.** Each rule is paired with an emulation of the
  technique. CI runs it (on a real auditd VM, a live `kind` cluster, or recorded
  cloud audit logs), compiles the rule with a real Sigma backend, and checks
  that the rule matches the telemetry that emulation produced. Where CI cannot
  collect a rule's telemetry, a human-approved waiver lets CI compile the rule
  and prove it on its offline positive case instead.
- **It stays quiet on everything else.** The same rule must not fire on no-op
  runs, broken "mutant" attacks, allowlisted tools, or a benign baseline that
  differs from the attack only in the one field the rule keys on.
- **Its checks are hard to game.** Each rule needs verified near-miss or
  filtered negatives that share the attack's chokepoint: sidecar cases or, for
  a cloud rule, records of its hard benign fixture. A gate fails a rule that
  has none (unless a human approves a waiver), whose negatives are trivial, or
  that keys on the emulation's own names. A versioned benign corpus scores how
  often each rule fires on ordinary activity, against a budget a human approves;
  a rule that no benign slice can read is listed as unscored, with its reason.
- **Its reasoning can be checked.** A written Technique Research Report (TRR)
  maps each way to perform the technique and picks the chokepoint they all
  pass through. Each rule traces back to a TRR, except 11 early Linux syscall
  rules that are older than the TRR method.

A rule that cannot pass this loop does not land, however plausible it reads.

![Workflow: a human picks a technique; the AI agent researches it, writes an emulation, and writes a Sigma rule; CI proves the rule fires on the emulation and stays quiet on controls, sending failures back to the agent; passing work goes back to the human to merge.](docs/diagrams/workflow-light.png#gh-light-mode-only)
![Workflow: a human picks a technique; the AI agent researches it, writes an emulation, and writes a Sigma rule; CI proves the rule fires on the emulation and stays quiet on controls, sending failures back to the agent; passing work goes back to the human to merge.](docs/diagrams/workflow-dark.png#gh-dark-mode-only)

<sub>Drawn with <a href="https://github.com/cathrynlavery/diagram-design">diagram-design</a>; source in <a href="docs/diagrams/"><code>docs/diagrams/</code></a>.</sub>

## Coverage, counted by procedure

A technique on an ATT&CK heatmap turns green when one rule maps to it, even if
that rule sees only one of the ways to perform the technique. So this repository
counts coverage by **procedure**: each distinct execution path that a TRR
researched. A procedure counts as covered only when its own emulation runs in CI
and a validated rule fires on it.

![Coverage chart: ATT&CK techniques with a rule compared with procedures proven in CI, then procedures per platform split into proven, proven with an open defect, claimed, sensor only, and gap.](docs/coverage/coverage-light.svg#gh-light-mode-only)
![Coverage chart: ATT&CK techniques with a rule compared with procedures proven in CI, then procedures per platform split into proven, proven with an open defect, claimed, sensor only, and gap.](docs/coverage/coverage-dark.svg#gh-dark-mode-only)

Every procedure, its status and the gaps are in
[`research/COVERAGE.md`](research/COVERAGE.md). CI regenerates the report and
fails when the committed copy is stale, so the chart always matches the rules.

## What's inside

| Folder | Contents |
|--------|----------|
| [`research/`](research/README.md) | The TRRs and their index. **Start here.** |
| [`atomics/`](atomics/) | Safe emulations of each technique, by ATT&CK ID. |
| [`detections/`](detections/README.md) | Sigma rules and the validators that prove them. |

Which Kubernetes rule works on EKS, AKS, GKE, OpenShift or k3s: [`detections/k8s/PLATFORMS.md`](detections/k8s/PLATFORMS.md).

Try the cloud loop locally (pure Python, no cloud account needed):

```bash
pip install -r detections/requirements.txt
python3 detections/validate_cloud_detections.py
```

> **Not for production.** Rules are `status: experimental` and need baselining
> in your environment before they alert. Finished work is prepared for
> contribution upstream; see [`UPSTREAM.md`](UPSTREAM.md).

AI agents working in this repository: read [`AGENTS.md`](AGENTS.md).
