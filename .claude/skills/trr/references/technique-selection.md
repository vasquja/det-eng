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
  restates it as its own Procedure C gap.

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
  none. Use-side sibling of TRR9006 (Procedure E gap) and k8s sibling of TRR9022. Deferred to build as TRR9030
  (k8s), detections/sigma/T1528/.

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
  in AssociateAccessPolicy. Deferred to build as TRR9032 (aws).

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
  Deferred to build as TRR9033 (k8s), a chokepoint plus a sensitive-interface grader.

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
  creates) and typosquats. Deferred to build as TRR9031 (k8s).

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
  Deferred to build as TRR9034 (k8s), after TRR9031, as a policy-agnostic anchor with a reference VAP. Mapping
  and shipping the policy are human decisions.

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
