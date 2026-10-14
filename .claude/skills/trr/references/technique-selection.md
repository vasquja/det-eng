# Technique selection & novelty-vet playbook

This is the front of the loop and the part worth iterating on. The goal is to spend
judgment *before* build effort: find candidate techniques, vet each against the GO/NO-GO
gate, and record the decision so the reasoning compounds instead of being re-derived.

## Contents
- [Finding candidates (gap analysis)](#finding-candidates-gap-analysis)
- [The novelty-vet sources](#the-novelty-vet-sources)
- [The GO/NO-GO gate](#the-gono-go-gate)
- [How to run a vet round](#how-to-run-a-vet-round)
- [The ledger](#the-ledger)

## Finding candidates (gap analysis)

Start from what exists and look for whitespace:

- **The current set** is `research/index.json` (source of truth for built TRRs) and the
  readiness table in `UPSTREAM.md`. Read it first so you don't re-propose something built.
- **Adjacency to a built TRR.** The strongest candidates are often siblings of existing
  ones on a different service/identity/mechanism — e.g. workload-identity federation on
  GCP (TRR9018) has a workforce-identity sibling (TRR9020); EC2 IMDS off-instance
  (TRR9011) has an EKS IRSA off-cluster sibling (TRR9022). A sibling reuses hard-won
  telemetry knowledge and a proven validator shape.
- **ATT&CK coverage gaps.** Walk the tactics/techniques relevant to the platforms in
  scope (AWS, Azure/Entra, GCP, Kubernetes) and find chokepoints with no detection yet.
- **"Long-tail" of a covered behavior.** A technique covered for one service often has
  under-covered cousins (TRR9019 resource-policy public exposure → TRR9021 ACL +
  EventBridge/EFS/Glue/SSM long tail).
- **Use-side vs. write-side.** A backdoor that is detected when *written* often has an
  undetected *use* (TRR9013 writes a FIC → TRR9023 detects the FIC being used to sign in).

## The novelty-vet sources

Check each; cite what you find. Coverage changes, so vet by real lookup, not memory:

- **Stratus Red Team** (DataDog) — the de-facto cloud emulation catalog. If Stratus ships
  the emulation, the *emulation* half is not novel (the detection may still be).
- **Atomic Red Team** (redcanaryco) — existence-check the ATT&CK ID; note existing tests.
- **SigmaHQ/sigma** — is there already a rule? (code-search the repo for the API/eventName.)
- **Panther, Elastic (detection-rules), Splunk ESCU** — the main open detection rule sets.
  Elastic in particular ships a lot of cloud rules; find the nearest and differentiate.
- **Provider-native detections** — GuardDuty finding types (AWS), Defender/Entra, GCP
  SCC. These decide question 2 of the gate.

## The GO/NO-GO gate

A candidate must clear all four. Failing one is a NO-GO (drop or redesign); record why.

1. **Trusted non-spoofable in-record marker.** Is there a field, set by the provider and
   not attacker-controllable, that scopes the rule to the right credential class / object
   / identity? Session names, user-agents, and free-form tags are spoofable and cannot
   carry a detection alone. This is the single most common NO-GO.
2. **Not merely redundant with a provider-native control.** If GuardDuty (or equivalent)
   already fires on exactly this with enrichment you can't match, a bare re-implementation
   adds little. A provider-agnostic backstop is still worth shipping — but say so, and
   don't oversell it as a gap. Conversely, a documented GAP in provider coverage is a
   strong GO signal.
3. **Fixture-provable chokepoint.** You must be able to build (a) an attack fixture that
   fires, and (b) a hard benign baseline that differs only on the discriminating field.
   If the discriminator needs enrichment or state a single record can't carry, the rule
   can only *approximate* it — that's acceptable (TRR9011 does), but it must be stated as
   a demonstrated gap, and the fixture must still prove the approximation.
4. **Novel or honestly differentiated.** New emulation ground, new detection ground, or a
   clear, stated difference from the nearest prior art. Never claim "first"/"only" without
   having actually searched the sources above.

## How to run a vet round

- Treat it as research, not recall. Use web + primary provider docs. For a substantial
  candidate, fan out one angle per subagent — **marker**, **existing-coverage/GuardDuty**,
  **novelty vs. Stratus/ART/Sigma/Elastic/Splunk**, **fixture-provable chokepoint** — and
  converge. (This is how the ECS vs. EKS IRSA decision was made.)
- Produce an explicit GO / NO-GO / LEAN-GO with the reasoning tied to the four questions.
- For a GO, capture the pinned telemetry the build will need (exact field paths + casing)
  while you have the sources open — step 2 of the loop depends on it.
- Record the outcome in the ledger below, whether GO or NO-GO. A NO-GO with a clear reason
  is as valuable as a build — it stops the next round re-litigating it.

## The ledger

Source of truth for *built* TRRs is `research/index.json`. This ledger adds the part that
isn't in the repo: candidates **vetted and dropped**, and notable GO rationales, so the
reasoning survives. Append an entry per vet; keep it short.

### Built (see research/index.json for the full list)
- Kubernetes: TRR9001–9010 (sniffing, exec, static pods, RBAC, jobs, secrets, host escape,
  admission control, impersonation, indicator removal).
- Cloud rounds: TRR9011 (AWS IMDS off-instance), TRR9012 (AWS leaked key), TRR9013 (Entra
  FIC backdoor), TRR9014 (GCP public IAM), TRR9015 (AWS GitHub-OIDC trust), TRR9016 (AWS
  Cognito unauth), TRR9017 (Entra illicit consent / device-code), TRR9018 (GCP workload
  identity federation), TRR9019 (AWS public/cross-account resource exposure), TRR9020 (GCP
  workforce identity federation), TRR9021 (AWS ACL + service long-tail exposure), TRR9022
  (EKS IRSA creds used off-cluster), TRR9023 (Entra federated SP sign-in).

### Vetted and dropped / notable rationale
- **ECS task-role off-task use — NO-GO (question 1).** An ECS task-role session carries no
  trusted, non-spoofable in-record CloudTrail marker (no `ec2RoleDelivery` analog), the
  session name is spoofable, and GuardDuty's ResourceCredentialExfiltration already covers
  ECS. Dropped; this is why the TRR9022 slot went to EKS IRSA instead.
- **EKS IRSA off-cluster — GO (built as TRR9022).** Strictly stronger than ECS: the
  subsequent-call `userIdentity.sessionContext.webIdFederationData.federatedProvider`
  (the cluster `oidc.eks...` provider ARN) is STS-populated and non-forgeable, and there
  is NO GuardDuty finding for classic IRSA (Instance/ResourceCredentialExfiltration cover
  EC2/ECS/Lambda, not AssumeRoleWithWebIdentity), so the CloudTrail rule is primary.
  Elastic ships two adjacent rules — disclose and differentiate (off-egress + oidc.eks
  provenance vs. their external-ASN / ES|QL correlation).
- **Redshift `AuthorizeSnapshotAccess` — dropped from TRR9021.** No public / `all` form;
  it is account-to-account only, so there is no "public exposure" chokepoint to detect.

<!-- Append new vet outcomes here. Template:
- **<technique / candidate> — GO|NO-GO|LEAN-GO (question N).** <one-line reason + the
  marker/field or the prior-art it overlaps>. <built as TRRxxxx | dropped | deferred>.
-->
