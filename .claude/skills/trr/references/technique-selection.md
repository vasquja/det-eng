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
  admission control, impersonation, indicator removal); TRR9025 (malicious admission webhook),
  TRR9026 (pod port-forward tunnel), TRR9027 (cluster DNS / CoreDNS poisoning).
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

- **Deploy Container / create a pod-bearing workload (T1610) — NO-GO (question 3, reinforced by 2 and 4).**
  After TRR9005 (batch), TRR9003 (static pods), and TRR9007 (dangerous specs) carve out their
  slices, the residual is "create a plain, non-privileged Deployment/DaemonSet/StatefulSet/
  ReplicaSet/RC or bare Pod running an ordinary image" — the single highest-volume write in any
  cluster. The server-set markers (objectRef.resource=pods + apiGroup=""/"apps", verb=create) are
  non-spoofable but match *every* workload, so there is no discriminating field on which a hard
  benign baseline differs: a benign and a malicious Deployment create are byte-identical in audit
  shape except for attacker-chosen values (image, registry, name) that benign deployers also use
  and that are themselves spoofable. The only non-spoofable discriminators that raise fidelity are
  already shipped: Elastic `execution_anonymous_create_update_patch_pod_request.toml` ("Kubernetes
  Anonymous User Create/Update/Patch Pods Request", mapped to the SAME T1610/Execution) covers the
  anonymous-identity signal, and SigmaHQ `kubernetes_audit_pod_in_system_namespace.yml` ("Creation
  Of Pod In System Namespace") covers the kube-system signal; the privileged/host-access slice is
  TRR9007 + Falco's Create Privileged Pod / Sensitive Mount / HostNetwork + Elastic's privileged/
  hostPID/hostIPC/hostPath/caps rules. MITRE's own DET0249 phrases the detectable form as "images
  not on an allow-list, non-admin principals, or risky attributes" — i.e. enrichment on top of
  those existing gates, not a standalone chokepoint. Weaker than TRR9005/9010 (which narrow to a
  genuine resource/verb slice) and redundant exactly where it is useful. Stratus ships no generic
  deploy technique (only "Run a Privileged Pod" = TRR9007) and ART T1610 ships only a Docker test,
  so the *emulation* ground is open — but an open emulation does not rescue a detection with no
  chokepoint. Dropped.

<!-- Append new vet outcomes here. Template:
- **<technique / candidate> — GO|NO-GO|LEAN-GO (question N).** <one-line reason + the
  marker/field or the prior-art it overlaps>. <built as TRRxxxx | dropped | deferred>.
-->

- **Port-forward tunneling into a pod (pods/portforward) — LEAN-GO (sibling of TRR9002; honesty caveats on Q2+Q3).**
  Best ATT&CK map T1572 Protocol Tunneling / Command and Control (tunnel through the API server; Elastic's
  kubectl-networking rules map here too); Containers matrix has no dedicated port-forward technique and T1021
  sub-techniques are protocol-specific, so T1572 is a stated cross-domain best-fit. Q1 PASS: objectRef.resource=pods
  + objectRef.subresource=portforward (lowercase) are server-set, non-spoofable — same class as TRR9002 exec/attach.
  Q2 REDUNDANT-but-backstop: Falco's DEFAULT k8s_audit ruleset already ships a dedicated `port-forward` rule
  (`ka.target.subresource in (portforward)`); SigmaHQ has the exec rule (kubernetes_audit_exec_into_container.yml)
  but NO portforward rule, and Elastic covers only nodes/proxy kubelet portforward + host-level kubectl/kubeletctl,
  not pods/portforward at the API-audit layer. So this is the Sigma/pySigma-pipeline counterpart to Falco's rule,
  NOT a discovery. Q3 PASS-but-LOW-FIDELITY: attack (create/get on pods/portforward) fires and a hard benign baseline
  (pods/exec, pods/attach, plain pods get) differs only on subresource and stays silent — fixture-provable — but a
  benign developer port-forward is byte-identical to a malicious tunnel in the audit record, so it's a low-fidelity
  hunting/correlation anchor like TRR9005/9010, not a standalone alert. Q4 differentiated: closes the WebSocket verb
  trap (SPDY POST->verb:create vs WebSocket portforward.k8s.io GET->verb:get; a create-only rule misses modern kubectl,
  the same trap TRR9002 documents for exec). Build it as a stated backstop + anchor, reusing TRR9002 telemetry.
  **Built as TRR9026.**

- **Malicious admission webhook creation (T1546) — LEAN-GO (built as TRR9025).** The persistence+cred-access
  sibling TRR9008 explicitly scoped out (TRR9008 keys on delete/neuter and excludes `create`). Q1 PASS:
  `objectRef.apiGroup=admissionregistration.k8s.io` + `objectRef.resource` (mutating/validating webhook configs)
  + `verb=create` are server-set, cluster-scoped `objectRef.name`. Q2: no provider-native "malicious webhook"
  finding (GuardDuty-EKS / Falco default have none), but the bare create chokepoint duplicates SigmaHQ
  `kubernetes_audit_change_admission_controller.yml` and Elastic "Kubernetes Admission Webhook Created or
  Modified" — disclosed, shipped as the anchor. Q3/Q4 novel: neither reads the webhook body; the Request-level
  grader keys on `requestObject.webhooks[].clientConfig.url` (off-cluster, matched with dual-form `|contains`)
  and on cluster-wide `rules` over `secrets` (literal `*` matched with `|re`, avoiding the Sigma-wildcard trap),
  and the emulation is new ground (absent from Stratus + ART). ATT&CK caveat: T1546 lists no Containers platform
  (unlike TRR9008's T1685); mapping follows Elastic + the MS Threat Matrix "Malicious admission controller".

- **CoreDNS / cluster-DNS ConfigMap poisoning (T1565.001) — LEAN-GO (built as TRR9027).** Q1 PASS and
  load-bearing: `objectRef.name` ∈ {coredns, kube-dns, coredns-custom} in `objectRef.namespace=kube-system` is
  non-spoofable AND forced (the CoreDNS Deployment mounts the ConfigMap named `coredns`; the attacker cannot
  rename it). Q2: provider-agnostic backstop — no GuardDuty-EKS / Falco-default coverage. Q3 PASS-but-trodden:
  Elastic ships three near-identical rules incl. one at the same K8s-audit layer — disclosed. Q4 differentiated:
  the Request-level content grader on `requestObject.data.Corefile` (a `rewrite`/`template` plugin, or a
  `forward` to a literal IP) separates a poisoning edit from a benign one. Mapping caveat: T1565.001 lists no
  Containers platform; the Corefile is stored config data being manipulated (same move as TRR9008/T1685). The
  emulation captures and restores the real Corefile so cluster DNS is unchanged.

- **Resource / permission discovery via self-subject review (T1613) — NO-GO (question 3/4).** The proposed
  chokepoint — `create` on `selfsubjectrulesreviews`/`selfsubjectaccessreviews` in `authorization.k8s.io` (what
  `kubectl auth can-i --list` does) — is already shipped near byte-for-byte by BOTH SigmaHQ ("Kubernetes Audit
  RBAC permissions listing", Leo Tsaousis) and Elastic ("Kubernetes Suspicious Self-Subject Review", two rules
  tuned on actor + decision + user-agent), so a bare re-implementation adds no detection ground. Q1 passes
  (server-set `objectRef.resource`/`apiGroup`/`verb`), but benign automation floods the same chokepoint (the
  Dashboard, controllers, CI), so it is a low-fidelity anchor with no novel angle. Dropped.

- **Direct kubelet API access on :10250 (T1609/discovery) — NO-GO (question 3, reinforced by 1 and 4).** The
  technique is defined by the ABSENCE of an API-server audit event (a direct kubelet `/exec`, `/run`,
  `/portForward` call bypasses the API server), so the one Kubernetes loop this repo has proven — the API-server
  audit log — is structurally blind to it, and TRR9002 (9002.K8S.E) already demonstrates exactly this as a
  negative-control gap. At the node/process/network layer where it IS observable there is no trusted,
  non-spoofable in-record marker (Q1), and the open detections (Elastic's process-arg / kubeletctl host rules)
  have no honest differentiation beyond logsource (Q4). Left as the TRR9002 gap; the TRR9026 port-forward report
  restates it as its own Procedure C gap.
