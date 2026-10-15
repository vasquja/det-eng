---
name: trr
description: >-
  Detection-engineering methodology for this repository's Technique Research Reports
  (TRRs): the research -> emulate -> detect -> prove loop, from picking a technique
  through a CI-proven Sigma detection. Use this whenever the work is choosing, vetting,
  researching, or building a TRR or a new cloud/Kubernetes detection here -- e.g. "what
  should we research next", "is this technique novel / worth a TRR", "build a TRR for X",
  "add a detection for <ATT&CK technique>", vetting a candidate against Stratus Red Team /
  Atomic Red Team / SigmaHQ, writing a Sigma rule with recorded log fixtures + DDMs + an
  atomic, or driving it green through the validators and the adversarial review. Always
  lead with the technique-selection + novelty-vet GO/NO-GO gate BEFORE building anything;
  a weak or redundant candidate is cheaper to drop here than after a rule is written.
---

# Technique Research Reports (TRRs)

This repository turns an attacker technique into a **CI-proven detection** through one
loop: **research → emulate → detect → prove**. A finished TRR ships a grounded report,
one or more Sigma rules, recorded log fixtures that the rules are proven against, Detection
Data Models (DDMs), and a runnable atomic — all green through the repo's validators and
linters.

The scarce resource is not build effort; it is **judgment about what to build**. Most of
the value (and most of the mistakes avoided) is in the front gate: picking a technique
with a real, provable chokepoint that isn't already covered. So this skill is
**selection-first** — vet before you build.

## The loop at a glance

1. **Select + novelty-vet (the gate).** Find a candidate, then decide GO/NO-GO against
   hard criteria. Most of your leverage is here. → `references/technique-selection.md`
2. **Research + ground.** Pin the EXACT telemetry (field names, casing, nesting, which
   events are default-logged) from primary sources before writing a rule. Guessed field
   shapes produce rules that are dead against real logs.
3. **Build.** Write the Sigma rule(s), the recorded attack + hard-benign fixtures, the
   DDMs, and the atomic. → `references/build-and-prove.md`
4. **Prove.** The rule fires on the recorded attack (carrying the emulation marker) and
   matches NOTHING in a benign baseline that differs only on the discriminating field.
   It ships a `<rule>.cases.jsonl` beside it with a positive and **verified near-miss**
   negatives (one required item broken each), which `check-sufficiency` grades. Its
   false-positive rate on the benign corpus is scored and committed. Run the repo's
   validators + linters green. → `references/build-and-prove.md`
5. **Review.** An adversarial pass (per-rule / per-fixture / per-README skeptics, each
   finding reproduced against the real pySigma backend) before the PR is "done".
6. **Document + wire CI**, then open the PR and drive it to green.
7. **Upstream (optional, human step).** Prepare contribution-ready artifacts; the person
   files the PRs. → `references/upstream.md`

Steps 2–6 are mechanics and live in the references. Read them when you reach that step;
don't preload everything.

## Lead with the selection + novelty-vet gate

Before any rule is written, a candidate must clear four questions. If it fails one, it is
a **NO-GO** — drop it or redesign, and record why (the ledger in
`references/technique-selection.md` is where that institutional memory accrues, and it is
the part of this skill you will keep editing):

1. **Is there a trusted, non-spoofable, in-record marker** that scopes the detection to
   the right thing? (e.g. IMDS `ec2RoleDelivery`, or EKS IRSA's
   `webIdFederationData.federatedProvider`.) If the only tell is attacker-controllable
   (a session name, a user-agent), the rule can't stand on it. *This is the question that
   dropped the ECS task-role candidate and cleared the EKS IRSA one.*
2. **Is it already covered** by a provider-native control the user would already have
   (GuardDuty, a built-in posture check)? Redundancy isn't automatically fatal — a
   provider-agnostic backstop can still be worth it — but you must say so honestly and
   position the contribution as a backstop, not a discovery.
3. **Is there a crisp invariant chokepoint provable with committed fixtures** (no live
   cloud account)? If you can't construct an attack fixture that fires and a hard benign
   baseline that differs only on the discriminator, it isn't ready.
4. **Is it genuinely new emulation/detection ground**, and if not, how is it honestly
   differentiated? Vet against Stratus Red Team, Atomic Red Team, SigmaHQ, Panther,
   Elastic, Splunk ESCU. Finding a near-identical prior rule is not disqualifying, but it
   must be disclosed and the difference stated plainly — never claim "first" or "only"
   without checking.

Run the vet as real research (web + primary docs), not from memory — vendor coverage and
upstream rule sets change. When the vet is substantial, fan it out (one angle per
subagent: marker / existing-coverage / novelty / chokepoint) and converge on a GO/NO-GO.

## Principles that keep a TRR honest

- **Ground before you build.** Pin real telemetry first. The repo has been bitten by a
  field matched as an int when the provider emits a string, and by a Sigma wildcard
  hiding in a plain value — both pass a hand-made fixture and fail against real logs.
- **The benign baseline is the proof.** A rule that fires on an attack fixture proves
  little; a rule that fires on the attack AND stays silent on a baseline differing only
  on the chokepoint field proves it keys on the technique, not the fixture's shape. Make
  the baseline hard, and add provenance confounders (a look-alike that must NOT fire).
- **Write checks that would fail for a wrong rule.** A negative that any reasonable
  rule rejects (a no-op, an unrelated event) proves nothing. Each negative should keep
  the chokepoint and break one required item, and each `not <filter>` should have a
  look-alike that only the filter suppresses. Optimize for the intent, not for the
  checks you already have: never relabel or weaken a case, edit the corpus, or raise
  a budget to turn a run green. A budget or corpus change is a human's call.
- **Review adversarially, and reproduce every finding.** Claims about a rule's behavior
  are cheap; a crafted event run through `detections/sigma_eval.py` is proof. The review
  has repeatedly caught defects in already-"done" rules.
- **Novelty claims are load-bearing** in this repo's value proposition — be exact and
  honest about prior art, down to naming the nearest existing rule.
- **Upstream filing is a human step** — prepare, don't submit. See `references/upstream.md`.

## Reference files

- `references/technique-selection.md` — the selection + novelty-vet playbook and the
  **built / vetted-and-dropped ledger**. Read first, every round. This is the living
  document; append to the ledger as candidates are vetted.
- `references/build-and-prove.md` — the build + prove mechanics: the pySigma backend and
  its gotchas, the fixture format, the `marker()`-gated validator, `trr_lint`, DDM
  rendering, the atomic shape, CI wiring, and the reusable rule patterns.
- `references/upstream.md` — the upstream contribution boundary and what "prepare, don't
  file" means in practice. The authoritative filing requirements live in the repo-root
  `UPSTREAM.md`.
