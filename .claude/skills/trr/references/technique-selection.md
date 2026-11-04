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

- **Port-forward tunneling into a pod (pods/portforward) — LEAN-GO (sibling of TRR9002; honesty caveats on
  Q2+Q3).**
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
  grader keys only on `requestObject.webhooks[].clientConfig.url` (any URL-mode webhook, matched with dual-form
  `|contains`). It deliberately does not key on cluster-wide `rules` or a `secrets` scope, because Kyverno and
  Gatekeeper validate cluster-wide and over Secrets. The emulation is new ground (absent from Stratus + ART). ATT&CK caveat: T1546 lists no Containers platform
  (unlike TRR9008's T1685); mapping follows Elastic + the MS Threat Matrix "Malicious admission controller".

- **CoreDNS / cluster-DNS ConfigMap poisoning (T1565.001) — LEAN-GO (built as TRR9027).** Q1 PASS and
  load-bearing: `objectRef.name` ∈ {coredns, kube-dns, coredns-custom} in `objectRef.namespace=kube-system` is
  non-spoofable AND forced (the CoreDNS Deployment mounts the ConfigMap named `coredns`; the attacker cannot
  rename it). Q2: provider-agnostic backstop — no GuardDuty-EKS / Falco-default coverage. Q3 PASS-but-trodden:
  Elastic ships three near-identical rules incl. one at the same K8s-audit layer — disclosed. Q4 differentiated:
  the Request-level content grader on `requestObject.data.Corefile` (a `rewrite`/`template` plugin, or a
  `forward` to a literal IP) separates a poisoning edit from a benign one. Mapping caveat: T1565.001 lists no
  Containers platform; the Corefile is stored config data being manipulated (a cross-domain mapping, as
  TRR9025/T1546 makes; not like TRR9008, whose T1685 lists Containers). The
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
  restates it as its own Procedure D gap (Procedure C, the port-forward through the node proxy, is detected by
  `k8s_node_proxy_portforward`).

- **Pod-bound SA token used from an unexpected source (T1528/T1550.001/T1078) — LEAN-GO (strongest Q1; Q3
  fidelity caveat on managed clusters).** Server-set, signed-claim, non-spoofable markers in user.extra:
  authentication.kubernetes.io/pod-name+pod-uid (v1.12; pod default v1.22), node-name+node-uid (v1.29
  alpha/v1.32 GA), credential-id 'JTI='/x509 'X509SHA256=' (v1.29 alpha/v1.32 GA) — verified in kubernetes
  claims.go/util.go/strategy.go; impersonated extras go to impersonatedUser.extra, so a client cannot inject
  them. Compare against the LAST sourceIPs entry (audit types.go: all but last are client-settable via
  XFF/X-Real-Ip). Q2 GAP: no GuardDuty EKS / GKE ETD audit rule for token-off-pod; Defender's token signal is a
  runtime sensor, not an audit compare. Q3: a single-record off-cluster CIDR-allowlist rule is fixture-provable
  on kind/kubeadm (kindnetd LOCAL carve-out keeps the pod IP; repo fixtures already show 10.244.0.31 vs admin
  172.18.0.1) but DEGRADES to an approximation on EKS/GKE/AKS where the apiserver's peer is a konnectivity agent
  / NAT (state as a demonstrated gap, like TRR9011/9022); a credential-id value_count correlation (one token
  from >=2 sourceIPs) is a portable fallback (both prototyped in sigma_eval). sourceIPs|cidr compiles to a
  first/whole-element LIKE prefix (wrong for XFF chains); an anchored |re on the last array element isolates the
  trustworthy entry and survives XFF prepending. Q4: nearest prior art Elastic 'Service Account Token or
  Certificate Access Followed by Kubernetes API Request' + 3 D4C sequences join on pod-name but need a runtime
  sensor and never compare markers to sourceIPs or key on credential-id/node-name; SigmaHQ/Splunk/Falco ship
  none. Use-side sibling of TRR9006 (Procedure E gap) and k8s sibling of TRR9022. **Built as TRR9030**
  (k8s, detections/sigma/T1528/k8s_pod_token_used_off_source.yml): the single-record off-source rule
  (pod-name marker vs the anchored last sourceIPs entry) is shipped and proven live on kind (Procedure A fires
  from the off-pod runner 172.18.0.1; the in-pod baseline from 10.244.x stays quiet, the 9030 B absence check);
  0 benign-corpus hits (every corpus pod-bound record is pod-IP sourced). AKS converts SAME; GKE is NOT_PORTABLE
  (AuditLog records principalEmail only, no user.extra, and one callerIp, not the sourceIPs array). DROPPED from
  the ship: detection (2), the credential-id value_count correlation, is prototyped and proven in sigma_eval but
  NOT shipped as a live rule -- the repo's correlation backend keys on a `timestamp` column that a k8s audit
  record (requestReceivedTimestamp) does not carry (a shared-tooling change, a human decision). The
  managed-cluster single-record degradation is RULE_DEFECTS K53; the hostNetwork node-IP false positive is
  in the rule's falsepositives.

- **CSR client-certificate persistence (T1098.006/T1136) — LEAN-GO as a disclosed backstop (Q4 trodden; two
  proven build limits).** Q1 PASS: server-set objectRef.resource=certificatesigningrequests, verb=create,
  subresource=approval, verb=update; spec.username injected server-side (strategy.go:78-97, not spoofable);
  signerName kubernetes.io/kube-apiserver-client in requestObject.spec (needs Request level). Q2: no GuardDuty
  EKS CSR finding, but GKE ETD ships CSR detectors and Stratus notes the technique does not succeed on EKS
  (self-managed/kind emulation only). Q3 fixture-provable (benign baseline = kubelet-client/kubelet-serving node
  CSRs differing only on signerName+requester) but the repo's apiserver audit policy logs NO
  certificatesigningrequests today (new Request-level entry needed) and the benign corpus has ZERO CSR events
  (new slice or an unscored entry = human decision). Two proven limits: the requested subject (system:masters)
  is NOT Sigma-gradable (single-base64 forms absent from spec.request; only in the line-wrapped inner PEM, which
  GKE decodes in ES|QL and pySigma cannot); self-approval via user.username|fieldref is non-portable (Elastic
  Lucene+EQL raise SigmaFeatureNotSupportedByBackendError; Splunk defers). Q4: duplicates Elastic 'Kubernetes
  Client Certificate Signing Request Created or Approved' + GKE/AKS rules; Stratus ships the emulation. Weaker
  than TRR9025/9027 (no content grader possible). Deferred to build as TRR9035 (k8s),
  detections/sigma/T1098.006/, as a disclosed backstop; the subject grader and the fieldref self-approval check
  are dropped unless a human accepts a non-portable rule.
  **Built as TRR9035** (detections/sigma/T1098.006/k8s_csr_client_cert_minted.yml, status experimental).
  Shipped: the bare create/approve chokepoint — the create leg scoped by signerName
  kubernetes.io/kube-apiserver-client (proven on a v1.36.4 lab; the kube-apiserver-client-kubelet and
  kubelet-serving node CSRs, which differ only on signerName, are the hard near-misses), the approve leg on
  objectRef.subresource=approval + verb=update with a `not system:*` approver filter (the csrapprover
  auto-approval is the filtered case). Null-safe. Both legs proven live on the local kube-apiserver lab and
  wired into validate-apiserver (MANIFEST 9035 A-B, atomics/T1098.006/src/emulate_csr.sh). Dropped as proven,
  per the two limits: the subject grader (not Sigma-expressible — and v1.36.4's CertificateSubjectRestriction
  admission plugin refuses a kube-apiserver-client CSR requesting system:masters, confirmed 403 on the lab) and
  the fieldref self-approval check (non-portable). Both limits recorded in RULE_DEFECTS.md K60. No
  CHOKEPOINT waiver was needed: the signerName discriminator makes check_sufficiency pass without one.

- **ServiceAccount create, incl. kube-system / lookalike names (T1136.001/T1036.010) — NO-GO (Q3, reinforced by
  Q2+Q4).** Server-set markers (verb=create, objectRef.resource=serviceaccounts, apiGroup='') are non-spoofable
  but match every benign SA create: every namespace makes a default SA (the corpus already has the
  service-account-controller create), every onboarding creates SAs — no discriminating field on which a hard
  benign baseline differs. The only high-fidelity slices (kube-system/kube-public create, lookalike name) are
  already shipped by Falco-default ('K8s Serviceaccount Created' + 'Service Account Created in Kube Namespace'
  with its trusted_sa allowlist), SigmaHQ 'New Kubernetes Service Account Created', and GKE ETD 'Service Account
  Created in sensitive namespace'. Same shape as the T1610 Deploy-Container NO-GO. TRR9004 correctly scoped SA
  creation out. Dropped (maintainer accepted the NO-GO, 2026-10-20).

- **Anonymous/unauthenticated and default-account access (T1078.001) — NO-GO (Q2+Q4), default-SA-use sliver at
  most a TRR9004 note.** Q1 PASS (server-set system:anonymous / system:unauthenticated / decision=allow /
  default SA). The anonymous-allowed chokepoint is saturated: Falco-default 'Anonymous Request Allowed',
  GuardDuty EKS SuccessfulAnonymousAccess + Policy:Kubernetes/AnonymousAccessGranted, GKE ETD
  anonymous-from-internet + anonymous-cluster-admin, Elastic anonymous-UA/pod-create/endpoint-enum, SigmaHQ
  401/403, Splunk scanning — no honest differentiation. On default kubeadm/kind anonymous gets only
  public-info-viewer discovery endpoints (bootstrappolicy policy.go:714; KEP-4633 restricts anonymous to
  configured endpoints, beta v1.32/GA v1.34), so a real-resource anonymous allow IS the misconfig finding. The
  default-SA-use sliver is a low-fidelity overlay on TRR9004 (an allow implies a binding) needing a benign
  confounder the corpus lacks. Dropped (maintainer accepted the NO-GO, 2026-10-20); optionally note in TRR9004
  that k8s_rbac_privileged_grant catches bindings TO system:anonymous, system:unauthenticated and the
  system:serviceaccounts groups (not to a namespace's default service account), but not their REQUESTS, left
  to Falco-default by design.

- **EKS aws-auth ConfigMap backdoor, the in-cluster write (T1098.006) — LEAN-GO (fold into TRR9004 as Procedure
  F; questions 2 and 4 are backstop and Sigma-counterpart).** Q1 PASS and load-bearing:
  `objectRef.name=aws-auth` in `objectRef.namespace=kube-system` is non-spoofable AND forced, because the EKS
  authenticator reads only that object. Q2: no GuardDuty-EKS, Defender or Falco-default control found (the
  GuardDuty finding page was unreachable during the vet; re-check). Defender itself writes its MDC role into
  aws-auth, a benign confounder. Q3: the bare write fires at Metadata. A content grade only approximates,
  because one record carries the new mapping, not the old: a 'mapRoles contains system:masters' grader fired on
  a benign node-group update (sigma_eval probe). Q4: Elastic 'EKS Authentication Configuration Modified' is the
  same chokepoint (update/patch/delete, decision allow, minus eks:kms-storage-migrator). SigmaHQ, Splunk, Falco,
  Panther and ART have none, and Stratus ships the emulation. This is the Sigma counterpart, plus `create`.
  Needs an aws-auth RequestResponse policy rule (as EKS logs it) so the validator's sentinel gate can see the
  body. aws-auth is deprecated (EKS user guide). **Built as TRR9004.K8S.F** (rule
  `k8s_eks_aws_auth_configmap_modified.yml`, a bare chokepoint; the aws-auth RequestResponse policy rule and the
  sentinel gate were added; no response-code or `eks:kms-storage-migrator` filter, both baselined by actor).

- **EKS access-entry backdoor in CloudTrail, CreateAccessEntry / AssociateAccessPolicy (T1098.006, secondary
  T1098.003) — LEAN-GO (questions 2 and 4: backstop and differentiated).** A cloud TRR proven by
  `validate_cloud_detections.py` fixtures, not a Kubernetes one: the grant never reaches the Kubernetes audit
  log. Q1 PASS on `requestParameters.policyArn` (a closed set of AWS-managed cluster-access-policy ARNs) plus
  `accessScope.type`. The cross-account form fails Q1 as Sigma can express it: `principalArn|fieldref|contains:
  recipientAccountId` goes quiet when the attacker names its role with the victim account ID (probe), so only an
  anchored `|re` with an org-account list would hold. Q2: no GuardDuty or Defender finding found (re-check the
  GuardDuty list); Datadog Cloud SIEM def-000-cm5/-dzx/-b69 are closed. Q3 PASS: recorded attack (ClusterAdmin
  at cluster scope) and hard benign (same call with only View, or only namespace scope, or denied). The bare
  'any access-entry write' is pure-surface and needs a human CHOKEPOINT entry. Q4: Elastic ships three rules
  (cluster-admin policy at any scope, any access-entry write, create-then-delete EQL); SigmaHQ has none. The
  difference is scope grading, every policy that reads Secrets, and Sigma. Note: `principalArn` is URL-encoded
  in AssociateAccessPolicy. **Built as TRR9032 (aws).** Two rules:
  `aws_eks_access_entry_cluster_admin_policy.yml` (graded, high — `AssociateAccessPolicy` of a reads-Secrets/admin
  policy at `accessScope.type: cluster`, null-safe `errorCode`) and `aws_eks_access_entry_write.yml` (surface
  chokepoint, medium — any access-entry write; human-approved `CHOKEPOINT` waiver). The reads-Secrets set was pinned
  from the awsdocs access-policy-reference at commit `8d43223` (2026-09-16): the **nine** AWS-managed cluster-access
  policies that read Secrets and are associable to a customer principal — ClusterAdmin, Admin, AdminView, Edit,
  SecretAdmin, SecretReader, ArgoCDPolicy (core `secrets` or `*`), **and** AWSBackupFullAccessPolicyForBackup /
  AWSBackupFullAccessPolicyForRestore (`*`/`*` read; the two AWSBackup policies were added in round-1 review after the
  pinned source showed they read every Secret and carry no service-linked restriction). ArgoCDClusterPolicy, ViewPolicy,
  ACKPolicy and KROPolicy read no core Secrets; ClusterInsights is service-linked-only. Proven by
  `validate_cloud_detections.py` over committed CloudTrail fixtures. **Dropped**: the namespace-scoped-secrets tier
  (one record cannot weigh namespaces; K56) and the cross-account provenance predicate (the real
  `principalArn|fieldref|contains: recipientAccountId` form runs on `sigma_eval` and its embedded-victim-ID evasion was
  reproduced; the sound fix is a portable `sel_external and not filter_org_accounts` `|re` pair needing a
  per-deployment org-account allowlist; K57) — both documented, not shipped.

- **Service exposure through NodePort / LoadBalancer (T1133, MS-TA9005) — LEAN-GO (question 2 backstop; question
  4 differentiated).** Q1 PASS: `requestObject.spec.type` is an API enum the attacker must set to expose
  anything. `objectRef.namespace` is forced by the target, because a Service selects pods only in its own
  namespace. Name, source ranges and internal/internet-facing annotations are attacker-chosen and must never be
  filters. Q2: GuardDuty ExposedDashboard/KubeflowDashboardExposed (EKS) and Defender 'Exposed Kubernetes
  service detected' already cover the sensitive-interface LoadBalancer slice. Falco's default 'Create NodePort
  Service' covers create plus NodePort only. Q3 PASS-with-approximation: create is unambiguous; a patch or
  update cannot tell a type change from a re-assertion in one record. The repo logs services at the Metadata
  catch-all, so it needs a services RequestResponse policy rule (EKS and AKS already log core writes at
  RequestResponse). Probes: Elastic's request-only shape misses a JSON patch of `/spec/type`, and a
  stored-object branch fires on services/status unless `objectRef.subresource` is excluded (the service
  controller patches only `status`, cloud-provider helper.go:142). Q4: the bare NodePort create is trodden
  (Elastic, Splunk, Panther, Falco), but no open rule set covers LoadBalancer, and SigmaHQ has no Service rule.
  Built as TRR9033 (k8s): one chokepoint rule
  `detections/sigma/T1133/k8s_service_exposed_nodeport_loadbalancer.yml` on `spec.type`
  NodePort/LoadBalancer in `requestObject` (A: NodePort create, B: LoadBalancer create)
  or `responseObject` (C: JSON patch of `/spec/type`, which Elastic's request-only shape
  misses), with `objectRef.subresource == status` excluded (the service/cloud controller
  confounder) and null-safe. Dropped: the sensitive-interface grader (kept as a severity
  note, not a brittle namespace/port allowlist that ages; GuardDuty / Defender cover that
  closed slice). Stated limits: update/patch cannot tell a type change from a re-assertion
  (RULE_DEFECTS.md K59), and the rule is blind where core writes stay at Metadata
  (OpenShift Default, k3s starter; K58). A services RequestResponse row was added to
  the lab and recommended audit policies.

- **Credentials in ConfigMaps / pod configuration read through the API (T1552, MS-TA9027) — NO-GO (questions 1
  and 3, reinforced by log-exposure risk).** No field scopes a ConfigMap read to one that holds a credential:
  names are not forced, and a read record carries no content below RequestResponse. The repo's three policies
  drop ConfigMap reads to None, and EKS, GKE and AKS kube-audit keep them at Metadata only. Falco's recommended
  policy logs every non-kube-system ConfigMap at RequestResponse, which copies every stored credential into the
  audit log, against the repo's never-Request rule for Secrets. Even with content, a read by the owning workload
  looks the same as the attacker's except in identity, so no hard benign baseline can differ on one field. The
  write-side grader (Falco 'Create/Modify Configmap With Private Credentials', Kubescape C-0012) is posture, not
  adversary behavior. Dropped (maintainer accepted the NO-GO, 2026-10-20). Record it as an out-of-scope gap in
  TRR9006, and warn in the apiserver policy header that Request-level pod logging copies literal env values.

- **Storage and backup destruction: PVC/PV deletes (T1485), VolumeSnapshot and Velero deletes (T1490) — GO (all
  four questions; Q3 with a stated approximation).** Server-set `verb` + `objectRef.resource`/`apiGroup` (core
  persistentvolumeclaims/persistentvolumes; snapshot.storage.k8s.io volumesnapshots/volumesnapshotcontents;
  velero.io deletebackuprequests create, schedules/backupstoragelocations delete) plus the authenticated
  `user.username` separate an actor's delete from controller churn: namespace-controller deletecollection,
  generic-garbage-collector, persistent-volume-binder or a CSI provisioner PV delete, snapshot-controller
  content deletes, and Velero's own GC delete requests. No rule exists in SigmaHQ, Elastic, Splunk or Falco
  k8saudit, and no test in Stratus or ART. The nearest are SigmaHQ `kubernetes_audit_deployment_deleted.yml` and
  Elastic's AWS Backup/RDS snapshot-deletion rules, which are cloud-side. No provider-native finding was found,
  but the AWS and GCP docs could not be read from this sandbox, so this is unverified. Gap: the PVC delete
  record does not carry the bound PV's `persistentVolumeReclaimPolicy`, so a destructive delete (Delete) looks
  like a non-destructive one (Retain). A Request-level grader on a `patch` that sets the reclaim or deletion
  policy to Delete covers the 'make it destructive' step. `kubectl delete backup` is not destructive, because
  Velero's backup sync re-creates the CR. Deferred to build as two TRRs, TRR9028 (T1485) and TRR9029 (T1490);
  the chokepoints need human CHOKEPOINT waivers.
  Built as TRR9028 (the T1485 half: PVC and PV deletes). Shipped: the chokepoint
  `detections/sigma/T1485/k8s_storage_volume_deleted.yml` (delete/deletecollection of
  core persistentvolumeclaims/persistentvolumes by a non-controller, filtering the
  namespace-controller deletecollection, generic-garbage-collector, persistent-volume-binder
  and the kind local-path provisioner by `user.username`; a CHOKEPOINT waiver, proposed)
  and the Request-level grader `k8s_volume_reclaim_set_to_delete.yml` (a PV patch that sets
  `persistentVolumeReclaimPolicy` to `Delete`). Dropped/deferred: the one-record reclaim
  gap is unchanged and recorded as K49 (a delete record carries no reclaim policy, so
  the grader covers the policy-flip step only); the identity filters' stolen-token evasion
  and the managed-platform CSI-provisioner baseline are K50; no `deletionPolicy` on
  volumesnapshotcontents here (that is the T1490/TRR9029 half, built in parallel). Prior
  art re-checked at build time: still no PVC/PV deletion rule in SigmaHQ, Elastic, Splunk
  or Falco k8saudit, and no Stratus/ART test; provider-native findings remain unverified
  (AWS/GCP docs unreachable).
  Built as TRR9029 (T1490 half): one chokepoint rule
  `detections/sigma/T1490/k8s_snapshot_or_backup_destroyed.yml` over five procedures -- delete a
  VolumeSnapshot (A), delete a cluster-scoped VolumeSnapshotContent (B), delete a Velero Schedule (C), delete a
  Velero BackupStorageLocation (D), create a Velero DeleteBackupRequest (E, the real backup-deletion path; a
  `backups` delete is explicitly NOT covered because backup sync re-creates it). Filters verified from
  external-snapshotter v8.7.0 and velero v1.18.4 source: the snapshot-controller on volumesnapshotcontents
  deletes, and the velero server (GC + backup-deletion controller). Positives are real v1.36.4 lab records; the
  rule is Metadata-only, so no audit-policy body row was added, and it is portable across every modeled managed
  policy (on GKE only the dry-run query filter is dropped, requestURI not in schema). CHOKEPOINT waiver added as
  a proposed human decision (pure-surface). The velero-server filter is scoped to the resources it churns
  (deletebackuprequests, volumesnapshots, volumesnapshotcontents), so a velero-SA Schedule/BSL delete still
  fires. Dropped nothing from the T1490 scope; the reclaimPolicy/deletionPolicy enrichment gap and the
  body-form dry-run FP (kubectl's default `--dry-run=server` delete puts dryRun in the unlogged DeleteOptions
  body, so at Metadata its record is indistinguishable from a real delete and the rule fires -- an accepted FP,
  K52) are documented. The T1485 half is TRR9028.

- **Lookalike workload names (T1036.005) — LEAN-GO (Q1 and Q3 pass on a narrowed chokepoint; Q2 is GKE-native;
  respects the T1610 NO-GO).** Controllers create pods only with `generateName`
  (pkg/controller/controller_utils.go), so their audit records carry no `objectRef.name`. A bare pod (no
  `objectRef.subresource`) with an EXPLICIT name in controller-generated shape (`-<6-10>-<5>` from
  `bcdfghjklmnpqrstvwxz2456789`, or `-<5>` in a system namespace), or with a `generateName` carrying a fake
  pod-template hash, is a client's choice and not a node's (not `system:node:*`). The rule does not key on the
  namespace alone: SigmaHQ 'Creation Of Pod In System Namespace' scores 12 of 2666 benign-corpus hits, all
  controllers, mirror pods and scheduler bindings, and it fires on pods/exec. It does not key on the image
  either (Falco 'Pod Created in Kube Namespace'). GKE Event Threat Detection ships 'Defense Evasion: Potential
  Kubernetes Pod Masquerading'. Not covered: a lookalike Deployment or DaemonSet (its pods are real controller
  creates) and typosquats. **Built as TRR9031 (k8s).** Shipped `k8s_pod_controller_name_mimicry.yml` with two
  branches, both keyed on an EXPLICIT `objectRef.name` (which no controller create carries): A, the ReplicaSet
  shape `-<hash 6-10>-<5>` in any namespace; C, the DaemonSet/Job shape `-<5>` in a control-plane namespace
  (`node-debugger-*` and `system:node:*` filtered). Scores 0/2666 on the benign corpus. Dropped: the vet's
  generateName branch (B). A real ReplicaSet controller's `generateName` (`<owner>-`, e.g.
  `coredns-6f6b679f8f-`) is byte-identical to an adversary's fake-hash generateName, both with no
  `objectRef.name`, confirmed on a kube-apiserver v1.36.4 lab; the only server-trusted discriminator is a
  per-site controller-SA allowlist, so it is a documented gap (RULE_DEFECTS.md K54), not a shippable
  chokepoint. A lookalike controller and typosquats remain stated gaps.

- **Malicious image via an admission-policy verdict (T1204.003) — LEAN-GO (narrow; survives the T1610 NO-GO only
  as a forwarder of policy verdicts).** For a ValidatingAdmissionPolicy binding with `validationActions` Audit,
  the API server writes the event annotation `validation.policy.admission.k8s.io/validation_failure` (apiserver
  dispatcher.go:312 at v1.32.2). For Deny it writes the response message "ValidatingAdmissionPolicy '<p>' with
  binding '<b>' denied request". Both are logged at Metadata, and a client cannot set either. The marker is a
  server-computed verdict, not the attacker-chosen image string that the T1610 entry rejects. But its meaning is
  the site's policy, and the rule is inert without one. Engine-native reporting already exists: Kyverno
  PolicyReports, Gatekeeper audit, Defender gated deployment, and GKE Binary Authorization. Falco exposes
  `ka.validations.admission.policy.failure` but ships no rule; SigmaHQ, Elastic and Splunk have none.
  Kyverno-generated VAPs map Audit to [Audit, Warn]; webhook-based image verifiers leave no such annotation.
  **Built as TRR9034 (k8s).** Re-pinned at v1.36.4: the annotation key and the denied-request message are
  unchanged (apiserver dispatcher.go:312, :294), both at Metadata, and Deny is code 422 (reason Invalid). Built a
  single policy-agnostic rule
  (`detections/sigma/T1204.003/k8s_admission_policy_image_violation.yml`), scoped to workload resources, with two
  branches: the Audit event annotation (value contains `"validationActions":[`) and the Deny responseStatus
  message. Procedures A (Audit annotation), B (Deny 422 message) and C (a Deployment whose replicaset-controller
  pod carries the annotation) with a reference VAP + two bindings the atomic installs; the allowed digest image is
  the hard benign control. Dropped by decision: a pure Warn-only binding leaves no audit marker (documented gap),
  and the Deny branch is NOT portable to GKE (responseStatus.message absent from Cloud Audit Logs; a NOT_PORTABLE
  human-approval entry). Not keyed on the image string (survives the T1610 NO-GO). Mapping and shipping a real
  image policy remain human decisions.

- **Container-runtime lane (shells, drift, miners, IMDS from pods, escape primitives beyond setns) — NO-GO for
  now (question 1 for auditd, plus questions 2 and 3); recorded as out of scope, with Falco as the reference
  (maintainer accepted, 2026-10-20).** auditd records carry no container identity: mainline
  `include/uapi/linux/audit.h` has no container-ID record. The trusted markers (a cgroup-derived container id;
  Falco's `proc.is_exe_upper_layer` for drift) belong to eBPF sensors that det-eng does not run in CI. Falco's
  stable, incubating and sandbox rules cover the lane rule for rule ('Terminal shell in container', 'Drop and
  execute new binary in container', 'Contact cloud metadata service from container', 'Detect release_agent File
  Container Escapes', miner rules), as do Tetragon/Isovalent, Elastic D4C, the Defender sensor, GuardDuty
  Runtime Monitoring and GKE Container Threat Detection. The bounded first step is a container-context proof of
  the EXISTING auditd syscall rules: run their atomics inside a container, attribute events by the in-container
  exe path, and add no new rules. Revisit only if a runtime sensor (Tetragon) and a new validator are approved.

- **OpenShift DNS Operator object grader — a rule that grades dnses.operator.openshift.io itself
  (managementState Unmanaged, upstreams to public IPs) — NO-GO (Q2 and Q4; Q3 caveat).** Q1 passes: the
  TRR9027 chokepoint already matches every write of the object (Procedure F; apiGroup and resource are
  server-set) at Metadata, so under OpenShift's Default profile. Q3: the object's fields are in the body, so a
  grader needs the WriteRequestBodies or AllRequestBodies profile. Q4: the redirect fields act only through
  what the operator renders into openshift-dns/dns-default, and the built Corefile grader reads dns-default with
  no identity filter. sigma_eval on the operator's own rendering (cluster-dns-operator release-4.20 template):
  spec.upstreamResolvers to 203.0.113.53 fires the root-block clause, and a spec.servers zone cluster.local to
  10.9.9.9 fires the cluster-zone clause. Q2: Unmanaged is not a redirect by itself, and OpenShift already
  signals it. The DNS object's Upgradeable condition becomes False (reason OperatorUnmanaged, dns_status.go
  computeDNSUpgradeableCondition), the DNS ClusterOperator then reports Upgradeable=False (reason
  DNSNotUpgradeable, status/controller.go), and the CVO raises the alert ClusterNotUpgradeable (for 60m,
  severity info). Known limits that stay at the chokepoint: under Unmanaged a DaemonSet repoint to another
  ConfigMap is not graded, and the operator-identity filter has an evasion (RULE_DEFECTS K45). Prior art
  (GitHub code search, 2026-10-24: openshift-dns, dns-default, dnses, operator.openshift.io): 0 hits in SigmaHQ,
  elastic/detection-rules, splunk/security_content, panther-labs/panther-analysis, falcosecurity/rules,
  DataDog/stratus-red-team and redcanaryco/atomic-red-team; a search for dnses.operator.openshift.io over all of
  GitHub found no detection repository. Nearest rule: Elastic "Kubernetes CoreDNS or Kube-DNS Configuration
  Modified" (a643e6b8-ba2a-45f1-8d71-d265bfe2ae43), which pins kube-system and does not match openshift-dns.
  The chokepoint still records every write of the object. (MP13 of the Wave 4 managed-cluster plan.)

### Wave 6 vet, round 1 (2026-11-04) — 1 LEAN-GO, 8 NO-GO

Seeded by adjacency to the built set (TRR9001–9035). The round confirmed the easy adjacency is
largely mined out: four seeds duplicate a built TRR, three are saturated by shipped open rules, and
one (Azure ARM RBAC) is a genuine resource-plane gap worth a disclosed backstop. Reserved ID for the
LEAN-GO: **TRR9036** (azure).

- **Azure RBAC privileged role assignment at subscription/management-group scope (T1098.003; Activity Log Microsoft.Authorization/roleAssignments/write) — LEAN-GO as a disclosed backstop (Q1 and Q3 carry it; Q2 backstop + documented MG-scope/no-PIM gap; Q4 trodden).** Q1 PASS with a stated caveat: the assigned role and scope are server-recorded at properties.requestbody (a JSON string) as Properties.RoleDefinitionId and Properties.Scope, read on the Start record (resultType|re '^start') — confirmed from Microsoft's own documented Azure Monitor query (role-assignments-alert) which extractjsons both out of requestbody; it is NOT identity.authorization.evidence.roleDefinitionId (the caller's own authorization, a trap), and requestbody can be absent on some exporters/policies so the body-grade is a fixture-provable approximation like TRR9011/9030. Built-in privileged GUIDs pinned from MS Learn built-in-roles: Owner 8e3af657-a8ff-443c-a75c-2fe8c4bcb635, Contributor b24988ac-6180-42a0-ab88-20f7382dd24c, User Access Administrator 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9, RBAC Administrator f58310d9-a9f6-439a-9e8d-f62e7b41a168 (Reservations Administrator a8889054-... optional). Q2 backstop: Microsoft documents the identical detection only as a customer-built Azure Monitor Kusto alert (not an automatic finding); PIM's 'Roles assigned outside PIM' alert needs Entra ID P2 + PIM and fires at subscription scope only (documented not to trigger on MG/RG/resource) — a real gap for MG-scope grants and non-PIM tenants; Defender for Resource Manager is anomaly-based with no confirmed deterministic equivalent. Q3 PASS: fixture-provable offline and the hard benign already exists in-repo — azure-activity-mi-admin.json carries Terraform roleAssignments/write Start records granting Key Vault Secrets User (4633458b-...) at a KeyVault resource scope, differing from the attack only on RoleDefinitionId + Scope. Q4 trodden: nearest prior art Elastic 'Azure RBAC Built-In Administrator Roles Assigned' (azure.activitylogs, same privileged-GUID discriminator, T1098) is a near-1:1 graded match; SigmaHQ already ships 'Granting Of Permissions To An Account' (azure_granting_permission_detection, a622fcd2-4b5a-436a-b8a2-a4171161833c, T1098.003) as a bare keyword with no role/scope filter; ART T1098 #6/#7 already emulate New-AzRoleAssignment at subscription scope (Stratus ships the adjacent root-user-access-administrator elevateAccess toggle, not the role write). Differentiation is honest and bounded: the graded Sigma counterpart to Elastic/Microsoft, raising fidelity over SigmaHQ's keyword rule, covering management-group scope and the no-PIM gap, fixture-proving the requestbody RoleDefinitionId+Scope discriminator. No built TRR covers this ARM-RBAC chokepoint (TRR9013/9017/9023 are Entra). Build as a new azure TRR, detections/sigma/T1098.003/azure_privileged_role_assignment.yml (status experimental), keyed on the Start record; disclose the custom-role evasion and requestbody-absence limits in RULE_DEFECTS. **Built as TRR9036** (research/trr9036/azr). Shipped: one chokepoint rule `detections/sigma/T1098.003/azure_privileged_role_assignment.yml` (status experimental, level medium) firing on the Activity Log `roleAssignments/write` Start record when `properties.requestbody` carries a privileged built-in role GUID (Owner / Contributor / User Access Administrator / RBAC Administrator) AND a subscription or management-group Scope that is not a resource-group scope; null-safe guard on the requestbody filter; portable `|re` (RE2-clean). Proven offline by `validate_cloud_detections.py` over `detections/cloud/fixtures/trr9036/` (attack = Owner at `/subscriptions/<test-guid>`; hard benign = the existing azure-activity-mi-admin Key Vault Secrets User grant at a Key Vault scope, differing only on RoleDefinitionId + Scope); scores 0 on the benign corpus (enforce-0). Procedures A (subscription) and B (management-group) are built; C (custom-role / exporter evasion) is a documented gap. Dropped/deferred: the two disclosed limits are tracked as RULE_DEFECTS placeholders **KTBD-AZ1** (custom role with Owner-equivalent permissions evades the built-in-GUID allowlist; fix = per-tenant privileged-role-GUID list) and **KTBD-AZ2** (requestbody can be absent/truncated on some Activity Log exporters, and the role+scope are only on the Start record, so the body grade is a fixture-provable approximation that degrades to the surface chokepoint). The integrator renumbers KTBD-AZ1/AZ2 to the next free K-numbers (last used K60).

- **CloudTrail logging tamper — StopLogging / DeleteTrail / UpdateTrail / PutEventSelectors / DeleteEventDataStore (T1562.008, AWS) — NO-GO (question 2, reinforced by 4).** Q1 PASS and not load-bearing: eventSource=cloudtrail.amazonaws.com + eventName (and requestParameters.eventSelectors[].includeManagementEvents) are CloudTrail-set and non-spoofable; Q3 is fixture-provable on recorded CloudTrail (attack = StopLogging / PutEventSelectors includeManagementEvents=false; hard benign = the same call with includeManagementEvents=true or a non-narrowing UpdateTrail) using the existing TRR9011/9032 cloud-fixture infra — but neither rescues a maximally-redundant candidate. The disable case is provider-native GuardDuty Stealth:IAMUser/CloudTrailLoggingDisabled (official finding-types page unreachable from this sandbox, exact trigger list UNVERIFIED), and the open field is saturated: SigmaHQ aws_cloudtrail_disable_logging.yml ("AWS CloudTrail Important Change") already keys StopLogging+UpdateTrail+DeleteTrail; Elastic ships Log Suspended (StopLogging), Log Deleted (DeleteTrail), Log Updated (UpdateTrail) and a dedicated "AWS CloudTrail Management Events Disabled via PutEventSelectors" (includeManagementEvents=false); Panther ships AWS.CloudTrail.Stopped + AWS.CloudTrail.EventSelectorsDisabled; Splunk ESCU ships the DeleteTrail analytic; Chronicle community aws_cloudtrail_logging_tampered.yaral covers all four in one rule. The emulation is fully in Stratus Red Team (cloudtrail-stop/-delete/-event-selectors/-lifecycle-rule) and wrapped by Atomic Red Team. The one proposed differentiator — selector-narrowing grading on requestParameters — is already Elastic's and Panther's, and is itself only a single-record approximation (a CloudTrail record carries the new selectors but not the prior state; the K59/TRR9033 "cannot tell a change from a re-assertion" limit). Nearest Sigma prior art: SigmaHQ aws_cloudtrail_disable_logging.yml. Lone open sliver found: CloudTrail Lake DeleteEventDataStore/UpdateEventDataStore (no open Sigma/Elastic/Stratus rule), a separate narrow candidate, not this headline. Dropped.

- **AWS IAM privilege-escalation primitives in CloudTrail (CreatePolicyVersion/setAsDefault, AttachUser|RolePolicy of AdministratorAccess, PutUserPolicy inline admin, CreateAccessKey for another user, UpdateAssumeRolePolicy, PassRole->compute) (T1548/T1098) — NO-GO (question 4, reinforced by 2 and the Q1 content-grade weakness).** `eventName` is CloudTrail-server-set and non-spoofable and the literal `requestParameters.policyArn == arn:aws:iam::aws:policy/AdministratorAccess` reliably scopes the attach-admin slice, but the generic privesc discriminator for the inline/version legs is admin-equivalence in attacker-authored `policyDocument` JSON (evadable), and a single CloudTrail record cannot carry the one high-fidelity shape — a PassRole->RunInstances/CreateFunction cross-call — which the repo's cloud validator cannot prove anyway (no correlation backend). GuardDuty's deterministic `PrivilegeEscalation:IAMUser/AdministrativePermissions` is retired (only the ML `AnomalousBehavior` remains), a real gap, but it is saturated by the open ecosystem: Elastic "AWS IAM Customer Managed Policy Version Created or Default Version Set" (T1098/T1548.005) and "AWS IAM AdministratorAccess Policy Attached to User/Role/Group", Datadog def-000-sd5, SigmaHQ `aws_iam_backdoor_users_keys.yml`, Turbot/ManageEngine, with the emulation shipped by Stratus `iam-create-backdoor-role`/`iam-backdoor-user`. Nearest prior art: Elastic d4e8f0a1-2b3c-4d5e-a6f7-8b9c0d1e2f3a. A Sigma re-implementation duplicates existing rules (AGENTS.md boundary = NO-GO/backstop, not a win); the only carve-out worth a future separate candidate is a PassRole->compute correlation, which needs correlation infra this cloud validator does not have. Dropped.

- **Entra SP/application secret-or-certificate credential add (addPassword / addKeyCredentials, T1098.001/Azure) — NO-GO (question 4, reinforced by 2 and 3).** The password/cert sibling of TRR9013's FIC backdoor, on the same Entra-audit app/SP credential-write chokepoint; TRR9013 explicitly carved it out as "a separate, well-covered activity." Q1 PASSES: the markers (`loggedByService` Core Directory, `category` ApplicationManagement, activity "Update Application – Certificates and secrets management" / "Add service principal credentials", modifiedProperties displayName KeyCredentials/PasswordCredentials) are Core-Directory-set and non-spoofable — same class as TRR9013, pinned from the MS Learn applications security-ops guide. Q3 FAILS: unlike the FIC issuer-allowlist (unapproved external issuer in newValue — fixture-provable), a credential add carries NO single-record field on which a hard benign baseline differs; a routine secret rotation / CI cert renewal is byte-identical to a malicious add, and the only fidelity signals are enrichment one record can't carry (rare/first-seen user, first-party/Microsoft appId allowlist, off-hours) — the same no-discriminator shape as the dropped T1610 Deploy-Container and ServiceAccount-create NO-GOs. Q4 saturated: Microsoft publishes the Sentinel template "New access credential added to Application or Service Principal" (Azure-Sentinel Detections/AuditLogs/NewAppOrServicePrincipalCredential.yaml, app+SP) and the Defender for Cloud Apps anomaly "Unusual addition of credentials to an OAuth app" (policy 5fe14f5b65a6e4ef21f569e8, feeding Entra ID Protection), its own guide rates it High and links the SigmaHQ cloud/azure rules (tuned PR #4570), Elastic ships three ("Azure Service Principal Credentials Added", New-Terms "…Service Principal Credentials Added by Rare User", ES|QL "…Credentials Added to Rare Service Principal"), and ART T1098.001 ships two Azure emulations ("Azure AD Application Hijacking - Service Principal / App Registration"). Q2 redundant for the same reason. Stratus azure/persistence has no secret/cert add technique (only backdoor-managed-identity-fic), so the Stratus emulation slot is open — but an open emulation does not rescue a detection with no chokepoint and total prior-art saturation. Nearest open prior art: Elastic "Microsoft Entra ID Service Principal Credentials Added by Rare User". Dropped.

- GCP service-account KEY creation (T1098.001, google.iam.admin.v1.CreateServiceAccountKey) and SA impersonation USE (T1134, iamcredentials GenerateAccessToken/GenerateIdToken/SignJwt) -- NO-GO (question 3, reinforced by 2 and 4; the stronger of the two is the key-create sub-option, still NO-GO). Q1 passes for both: protoPayload.methodName, authenticationInfo.principalEmail and the target serviceAccount in the request are server-set and non-spoofable (field casing grounded in the repo's own gcp benign slices, which already carry a bare GenerateAccessToken and google.iam.admin.v1.DeleteServiceAccountKey; GCP primary docs were unreachable this run -- docs.cloud.google.com and stratus-red-team.cloud do not resolve -- so the paths are unverified against Google docs). Q3 is the killer, the same shape as the T1610 Deploy / ServiceAccount-create / anonymous NO-GOs: both methods are among the highest-volume IAM writes in any real project -- a user-managed key create is byte-identical whether it is a benign Terraform/rotation create or an attacker's (and a key-disabled org has zero creates to detect), and GenerateAccessToken fires on every GKE Workload Identity pod, Cloud Build, gcloud --impersonate and IaC run (gcp-platform-ops already has one) -- so no discriminating field lets a hard-benign baseline differ by one flip, and there is no content to grade; the fidelity angles (first-seen caller->target, cross-project, privileged target, long serviceAccountDelegationInfo chain, token-used-off-source) all need state/enrichment one record cannot carry, which is exactly what ETD baselines. Q2: provider-native ships the high-fidelity forms -- GCP ETD "Persistence: Service Account Key Created" for the key path and "Anomalous Impersonation of Service Account for Admin Activity" + "Anomalous SA Delegation Multistep Data Access" for the use path. Q4: saturated -- Elastic "GCP Service Account Key Creation" (persistence_gcp_key_created_for_service_account, event.action google.iam.admin.v*.CreateServiceAccountKey, high) and Panther "GCP Service Account or Keys Created" cover the key path, both emulations are shipped by Stratus (gcp.persistence.create-service-account-key, gcp.privilege-escalation.impersonate-service-accounts), and SigmaHQ ships neither rule -- but open Sigma ground does not rescue a pure-surface chokepoint with no content grader, unlike the accepted backstops TRR9025/9026/9027/9033. Internally the grant side is already covered (TRR9018 gcp_workload_identity_federation_sa_binding grades roles/iam.serviceAccountTokenCreator to a WIF principalSet; T1098.003 covers public grants) and the impersonation USE is the deliberate declared gap of TRR9018 Procedure E and TRR9020 Procedure D. Dropped. Possible future refinement, not this candidate and unverified here: a federated principal (authenticationInfo.principalSubject / principal://) minting a long-lived exportable key as post-federation persistence is a genuinely narrower sibling of TRR9018/9020, but needs the GCP audit field behavior verified against primary docs before a re-vet.

- **EphemeralContainers injection / kubectl debug (T1610, secondary T1609) — NO-GO (redundant-internal; the chokepoint is already shipped).** The proposed marker (objectRef.resource=pods + objectRef.subresource=ephemeralcontainers, server-set lowercase, + verb in {patch,update}) is byte-for-byte the shipped TRR9002 Strategy 2 rule detections/sigma/T1609/k8s_pod_ephemeral_container.yml ("Ephemeral Container Added To a Kubernetes Pod", id d1fbe60b-382e-40be-8519-14617c7cd5f2), which covers Procedure C, is emulated in atomics/T1609/src/emulate.sh (two kubectl debug calls: the no-attach ephemeralcontainers write the exec/attach rule does NOT see, plus an --attach=true container that opens pods/attach), and is CI-proven in validate_apiserver_detections.py (MANIFEST "C", pods/ephemeralcontainers, code 200) with a positive (kubectl-debug-patch-procC) plus a verb near-miss and two subresource near-misses. Q1 actually PASSES (non-spoofable server-set subresource, same class as TRR9002 exec/attach), so this is a finished rule, not a weak one. Externally it also duplicates Elastic "Kubernetes Ephemeral Container Added to Pod" (+ the "Azure AKS Ephemeral Container Added to Pod" variant; update/patch on pods/ephemeralcontainers, decision allowed, excludes system:node:*/kube-system, T1609+T1611) and Falco's default k8saudit "EphemeralContainers Created" (Suspicious K8s Activity policy; GHSA-jhjp-4c2q-xmx4 confirms it is shipped but does not grade privileged settings). The T1610 reframing adds nothing over the T1609 sibling, and generic T1610 Deploy-Container is already a dropped NO-GO. Do not rebuild; the slot is TRR9002's.

- **RBAC escalate/bind verb abuse (T1548/T1078; coverage lives at T1098.006) — NO-GO (question 1, reinforced by redundant-internal and question 4).** The candidate's premise is false: `escalate` and `bind` are RBAC privilege-escalation-prevention authorization checks run inside the role/rolebinding REST storage strategy, NOT audit verbs. The audited write carries `verb` create/update/patch and `objectRef.apiGroup=rbac.authorization.k8s.io`, and the escalate/bind grant surfaces only as the literal strings `"escalate"`/`"bind"`/`"impersonate"` inside `requestObject.rules[].verbs` at Request level (corroborated this run by the Elastic/craftedsignal rule summaries matching exactly those strings in requestObject.rules, and by the SigmaHQ rolebinding rule's verb list being create/delete/patch/replace/update only; kubernetes.io, elastic.co, detection.fyi, the AKS gitbook and the GCP SCC docs host were unreachable and gh was repo-restricted, so pinned against the repo's v1.36.4-sourced TRR9004). The SubjectAccessReview path (`kubectl auth can-i escalate`) is verb=create of a (self)subjectaccessreviews object with the verb nested in `requestObject.spec.resourceAttributes.verb` — a spoofable can-i recon, the same shape already dropped as the T1613 self-subject-review NO-GO. Both real markers are already built: TRR9004 Strategy 1 `k8s_rbac_write.yml` is the write chokepoint for the whole rbac.authorization.k8s.io group (its description already states this escalate/bind audit-verb nuance), and Strategy 2 `k8s_rbac_privileged_grant.yml` already matches `"escalate"`/`"bind"`/`"impersonate"` and `*` in requestObject.rules, proven live in CI (TRR9004 Procedure C/E-sev). Nearest external prior art: Elastic "Kubernetes Creation or Modification of Sensitive Role" (reads requestObject/responseObject.rules for wildcard + escalate/bind/impersonate, RequestResponse); provider-native GCP SCC "Privilege Escalation: Creation of sensitive Kubernetes bindings" and Falco "ClusterRole With Wildcard Created" / "Attach to cluster-admin Role". Dropped: redundant with TRR9004; no new non-spoofable marker exists.

- **TokenRequest minting a token for another ServiceAccount (serviceaccounts/token create, T1528/T1550.001) — NO-GO (redundant-internal; Q4, reinforced by Q1/Q3).** The proposed chokepoint — server-set objectRef.resource=serviceaccounts + objectRef.subresource=token + verb=create, non-spoofable — is already shipped as TRR9006 Procedure D (detections/sigma/T1552.007/k8s_secret_token_request.yml, id 6c4f601d-e642-4dca-b9f4-cf98ef9c18f4, medium, proven live as validate-apiserver 9006 D), which filters the routine minters (system:kube-controller-manager, system:kube-scheduler, system:node:*, system:serviceaccount:kube-system:*) and whose sidecar positive workload-sa-mints-other-sa is exactly this "a non-system workload SA mints a token for a more-powerful SA in another namespace" case. The one differentiator — scope by caller!=target (objectRef.name/namespace vs user.username) instead of the system-minter exclusion — is not portably Sigma-expressible: a workload's user.username is system:serviceaccount:<ns>:<name>, so detecting "caller is not the target SA" needs a objectRef.namespace+objectRef.name concatenation that portable Sigma cannot build, and a bare |fieldref self-compare is the non-portable construct already recorded as K60 (CSR self-approval) and K57/TRR9032 (principalArn|fieldref); it would also drop the self-mint abuse the shipped non-system filter still catches. Nearest external prior art: Elastic "Kubernetes Service Account Token Created via TokenRequest API" (4df91789-7859-4bc4-9c5a-6b56bfa81a8b) plus its GKE and Azure AKS siblings, all keyed on the same subresource with a non-system exclusion list, not a caller!=target compare; Falco's default k8saudit ruleset has no serviceaccounts/token rule, but that provider-agnostic gap is already filled by TRR9006 D. Dropped.

- **Linux systemd service / kernel-module host persistence (T1543.002 / T1547.006) — NO-GO (the stronger lane is redundant-internal; the net-new lane fails Q3, reinforced by Q4/Q2).** Q1 PASS for both on auditd: the kernel-set PATH `name`+`nametype=CREATE` under the systemd unit load path (/etc/systemd/system/, /usr/lib/systemd/system/, ~/.config/systemd/user/) and the SYSCALL init_module/finit_module are host-observable and non-spoofable (unlike the dropped container-runtime lane). But the stronger *detection* — the kmod syscall anchor (rare syscall, small modprobe/kmod benign allowlist, unsigned-module refusal as near-miss) — is already owned by TRR9024: Procedure B "Loadable kernel module" / Strategy 2 "kernel-module anchor (covers B)" names the finit_module/init_module anchor as a backlog build, so a new TRR is redundant-internal; the right move is to fill TRR9024.B, not vet it fresh. The net-new lane, systemd .service writes (no T1543.002 in the repo), fails Q3: the auditd PATH/SYSCALL record carries path + writer identity + syscall but NOT the unit content, so there is no ExecStart grade, and the directory chokepoint matches every benign unit install byte-for-byte (dpkg/rpm to /usr/lib/systemd/system, Ansible/admin to /etc/systemd/system, systemctl edit); the only discriminator is the writer exe, which is spoofable (L14) and floods on admin shells — the exact shape of the dropped T1610 Deploy-Container NO-GO and the L15 linux_static_pod_manifest_write path-only false-positive defect, so no hard-benign baseline differs on one non-spoofable field. Q4/Q2 reinforce: SigmaHQ ships the byte-for-byte auditd anchor rules/linux/auditd/path/lnx_auditd_systemd_service_creation.yml (id 1bac86ba-41aa-4f62-9d6b-405eac99b485, T1543.002, medium) whose own falsepositives say "Admin work like legit service installs", plus the reload rule lnx_auditd_pers_systemd_reload and Elastic "Systemd Service Created"; the kmod nearest is Elastic "Kernel Driver Load" (BBR, T1547.006). Stratus ships no Linux host platform (AWS/Azure/GCP/K8s/EKS/Entra only), so the *emulation* half is open, but an open emulation rescues neither a redundant anchor nor a benign-saturated chokepoint. Dropped; if the kmod anchor is wanted, build it as TRR9024 Strategy 2.
