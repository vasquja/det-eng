# Detection at Scale

[![lint-trr](https://github.com/vasquja/det-eng/actions/workflows/lint-trr.yml/badge.svg)](https://github.com/vasquja/det-eng/actions/workflows/lint-trr.yml) [![validate-detections](https://github.com/vasquja/det-eng/actions/workflows/validate-detections.yml/badge.svg)](https://github.com/vasquja/det-eng/actions/workflows/validate-detections.yml) [![validate-apiserver-detections](https://github.com/vasquja/det-eng/actions/workflows/validate-apiserver-detections.yml/badge.svg)](https://github.com/vasquja/det-eng/actions/workflows/validate-apiserver-detections.yml) [![validate-cloud-detections](https://github.com/vasquja/det-eng/actions/workflows/validate-cloud-detections.yml/badge.svg)](https://github.com/vasquja/det-eng/actions/workflows/validate-cloud-detections.yml)

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
  that the rule matches the telemetry that emulation produced.
- **It stays quiet on everything else.** The same rule must not fire on no-op
  runs, broken "mutant" attacks, allowlisted tools, or a benign baseline that
  differs from the attack only in the one field the rule keys on.
- **Its reasoning can be checked.** Every rule traces back to a written
  Technique Research Report (TRR) that maps each way to perform the technique
  and picks the chokepoint they all pass through.

A rule that cannot pass this loop does not land, however plausible it reads.

![Workflow: a human picks a technique; the AI agent researches it, writes an emulation, and writes a Sigma rule; CI proves the rule fires on the emulation and stays quiet on controls, sending failures back to the agent; passing work goes back to the human to merge.](docs/diagrams/workflow-light.png#gh-light-mode-only)
![Workflow: a human picks a technique; the AI agent researches it, writes an emulation, and writes a Sigma rule; CI proves the rule fires on the emulation and stays quiet on controls, sending failures back to the agent; passing work goes back to the human to merge.](docs/diagrams/workflow-dark.png#gh-dark-mode-only)

<sub>Drawn with <a href="https://github.com/cathrynlavery/diagram-design">diagram-design</a>; source in <a href="docs/diagrams/"><code>docs/diagrams/</code></a>.</sub>

## What's inside

| Folder | Contents |
|--------|----------|
| [`research/`](research/README.md) | The TRRs and their index. **Start here.** |
| [`atomics/`](atomics/) | Safe emulations of each technique, by ATT&CK ID. |
| [`detections/`](detections/README.md) | Sigma rules and the validators that prove them. |

Try the cloud loop locally (pure Python, no cloud account needed):

```bash
pip install -r detections/requirements.txt
python3 detections/validate_cloud_detections.py
```

> **Not for production.** Rules are `status: experimental` and need baselining
> in your environment before they alert. Finished work is prepared for
> contribution upstream; see [`UPSTREAM.md`](UPSTREAM.md).

AI agents working in this repository: read [`AGENTS.md`](AGENTS.md).
