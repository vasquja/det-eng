# det-eng (Detection Engineering Research)

Detection research I'm working on. Nothing here should be considered useful
for production use. Production-ready work will be contributed to relevant
projects/repos.

## Method: research-first

Work starts with a **Technique Research Report (TRR)**, then flows to an
emulation test and a detection rule. This follows Andrew VanVleet's TRR method
and the [tired-labs/techniques](https://github.com/tired-labs/techniques)
project.

```
0. Pick one MITRE technique (one platform).
1. research/   — write the TRR: overview, background, procedures,
                 detection data models, detection strategy (chokepoint first).
2. atomics/    — one behavioral emulation test per procedure (ART style).
3. detections/ — one Sigma rule per detection strategy (chokepoint first,
                 per-procedure fallback), plus the auditd ruleset and the
                 validator that proves atomic -> telemetry -> rule.
4. contribute  — TRR to tired-labs/techniques, tests to Atomic Red Team,
                 rules to SigmaHQ/sigma.
```

The procedure ID (for example `TRR9001.LIN.A`) is the spine: the research, the
test, and the rule all name it.

| Folder | Role |
|--------|------|
| [`research/`](research/README.md) | TRRs — the source of truth. Start here. |
| [`atomics/`](atomics/) | Behavioral emulation tests, by technique. |
| [`detections/`](detections/README.md) | Sigma rules, auditd ruleset, validator. |

### Worked example

[`research/trr9001/lin`](research/trr9001/lin/README.md) — Network Sniffing
(T1040, Linux). It shows the full loop: four procedures, a detection data
model for each, and a chokepoint rule (`AF_PACKET` socket) that covers the two
common procedures, with fallbacks for the rest.
