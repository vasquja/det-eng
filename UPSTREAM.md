# Contributing upstream

This repository is a staging ground. Each finished Technique Research Report (TRR)
produces three artifacts that belong in three different upstream projects. This
document maps what goes where, records the conformance checks each upstream gate
runs, and lists the exact submission steps.

> **Status.** These are prepared and conformance-checked locally; opening the pull
> requests against the external projects is a human step (fork + PR under your own
> account). This file is the checklist for that step.

## The three destinations

| Artifact | Lives here | Upstream project | Upstream path |
|----------|-----------|------------------|---------------|
| The TRR (research) | `research/trrNNNN/<platform>/` | [tired-labs/techniques](https://github.com/tired-labs/techniques) | `trr0000/<platform>/` (maintainer assigns the final ID) |
| The Sigma rule(s) | `detections/sigma/<ATT&CK>/` | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | `rules/...` by log source (below) |
| The emulation test | `atomics/<ATT&CK>/` | [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) | `atomics/<ATT&CK>/` |

### SigmaHQ rule paths by log source

| Log source (rule `logsource`) | SigmaHQ path |
|-------------------------------|--------------|
| `product: linux` (auditd) | `rules/linux/auditd/` |
| `product: kubernetes` | `rules/application/kubernetes/` |
| `product: aws, service: cloudtrail` | `rules/cloud/aws/cloudtrail/` |
| `product: azure, service: auditlogs` / `activitylogs` / `signinlogs` | `rules/cloud/azure/` |
| `product: gcp, service: gcp.audit` | `rules/cloud/gcp/gcp_audit/` |

## Readiness table

Regenerate with `python3 research/tools/upstream_report.py` (reads
`research/index.json`, so it always reflects the current set):

```
TRR      Platform    ATT&CK           Sigma rule files                         atomics
-----------------------------------------------------------------------------------------------
TRR9001  Linux       T1040            afinet_raw_socket.yml (+2)               T1040
TRR9002  Kubernetes  T1609            k8s_node_proxy_exec.yml (+2)             T1609
TRR9003  Kubernetes  T1543.005        k8s_cri_static_pod_start.yml (+2)        T1543.005
TRR9004  Kubernetes  T1098.006        k8s_rbac_privileged_grant.yml (+1)       T1098.006
TRR9005  Kubernetes  T1053.007        k8s_cri_job_pod.yml (+1)                 T1053.007
TRR9006  Kubernetes  T1552.007        k8s_secret_access.yml (+2)               T1552.007
TRR9007  Kubernetes  T1611            k8s_podspec_controller_host_access.yml (+2) T1611
TRR9008  Kubernetes  T1562.001        io_uring_setup.yml (+3)                  T1562.001
TRR9009  Kubernetes  T1134            k8s_impersonation.yml (+1)               T1134
TRR9010  Kubernetes  T1070,T1070.004  k8s_events_deleted.yml (+1)              T1070
TRR9011  AWS         T1552.005        aws_imds_creds_used_off_instance.yml     T1552.005
TRR9012  AWS         T1078.004        aws_cognito_identity_pool_unauth_enabled.yml (+2) T1078.004
TRR9013  Azure       T1098.001        aws_github_oidc_role_trust_abuse.yml (+4) T1098.001
TRR9014  GCP         T1098.003        gcp_public_iam_member_grant.yml          T1098.003
TRR9015  AWS         T1098.001        aws_github_oidc_role_trust_abuse.yml (+4) T1098.001
TRR9016  AWS         T1078.004        aws_cognito_identity_pool_unauth_enabled.yml (+2) T1078.004
TRR9017  Azure       T1528,T1566.002  entra_device_code_authentication.yml (+1) T1528
TRR9018  GCP         T1098.001,T1199  aws_github_oidc_role_trust_abuse.yml (+4) T1098.001
TRR9019  AWS         T1537            aws_resource_policy_made_public.yml (+2) T1537
-----------------------------------------------------------------------------------------------
19 TRRs | 52 Sigma rule files | 20 atomic technique dirs
```

The "first rule" column is just the alphabetically-first file in each folder; a TRR
owns the rules named in its own `## Detections` table. T1098.001 is shared by TRR9013
(Entra/Azure), TRR9015 (AWS), and TRR9018 (GCP); T1078.004 by TRR9012 and TRR9016 (AWS);
T1562.001 by the Linux io_uring rule and TRR9008.

> Note: `detections/sigma/T1098.001/` holds five rules (TRR9013's two Entra/Azure
> rules, TRR9015's AWS rule, and TRR9018's two GCP rules); `detections/sigma/T1078.004/`
> holds TRR9012's leaked-key rule and TRR9016's two Cognito rules;
> `detections/sigma/T1562.001/` holds the Linux
> io_uring rule alongside TRR9008's Kubernetes rules. Submit each rule to the
> SigmaHQ path for *its own* log source, not the folder's.

## Conformance gates

### Sigma rules — `sigma check` (SigmaHQ's own validator)

```
pip install sigma-cli
# This environment's egress proxy blocks the ATT&CK/D3FEND tag-list download the
# online tag validators need, so exclude them; they re-run server-side on the PR:
sigma check -x attacktag -x d3_fendtag -x detection_tag detections/sigma/
```

Current result: **0 errors, 0 condition errors.** The only findings are 14
LOW-severity style notes, each defensible:

- **NumberAsStringIssue (×12)** — auditd syscall-argument fields (`a0`..`a3`, `exit`,
  arg counts) are hex/decimal **strings** in the auditd event, so matching them as
  quoted strings is correct for `product: linux`. Leave as-is, or convert to bare
  numbers only if a target backend coerces types.
- **EscapedWildcardIssue (×2)** — both match a **literal** `*` with `\*`, intentionally:
  `k8s_rbac_privileged_grant.yml` (an RBAC wildcard grant `verbs: ["*"]`), and
  `aws_resource_policy_made_public.yml` (TRR9019; the Lambda public principal `"*"`).

The cloud rules (TRR9011–9019) produce **0 errors**; the only cloud note is that one
intentional EscapedWildcardIssue in the TRR9019 resource-policy rule.

### Atomics — Atomic Red Team schema

Each `atomics/<ATT&CK>/<ATT&CK>.yaml` follows the ART test format (`attack_technique`,
`display_name`, `atomic_tests[]` with `name`, `auto_generated_guid`,
`supported_platforms`, `executor`). Cloud tests use the IaaS platforms
(`iaas:aws` / `iaas:azure` / `iaas:gcp`); they require the operator's own cloud
account and are opt-in (`TRR90NN_LIVE=1`), so they are documentation + a reproducible
telemetry fixture, not a CI-run test. Validate against ART's published schema at
submission time (`atomic_red_team.schema.json` in the ART repo).

### TRRs — the repo's own linter

`python3 .github/scripts/trr_lint.py` (offline) enforces the tired-labs structure:
required sections and order, the Metadata table, `TRRID.PLATFORM.LETTER` procedure
IDs, a rendered DDM PNG per procedure, and `index.json` consistency. All reports pass.

## Submission steps

### 1. TRR → tired-labs/techniques

1. Copy `research/trrNNNN/<platform>/` to `trr0000/<platform>/` in a fork of
   tired-labs/techniques.
2. Rewrite the local ID to the placeholder: `TRRNNNN` → `TRR0000` and
   `trrNNNN` → `trr0000` in the README prose, the Metadata table, every
   `TRRNNNN.PLATFORM.LETTER` procedure ID, and the DDM filenames/embeds. Re-render
   the DDM PNGs so their stamped source hash matches
   (`python3 research/tools/render_ddm.py trr0000/<platform>/ddms/*.json`).
3. Drop the local `path` field and the `{_comment, trrs:[]}` wrapper when emitting
   the `index.json` entry into upstream's top-level array (see the note in
   `research/index.json`).
4. The maintainer assigns the final upstream ID on merge.

### 2. Sigma rule → SigmaHQ/sigma

1. Place each rule at the path for its log source (table above).
2. Keep `status: experimental` and the `author`, `date`, `references`,
   `falsepositives`, and `level` fields (already present).
3. Re-run `sigma check` without the `-x` exclusions in a network-enabled environment
   so the ATT&CK-tag validator passes, then open the PR.

### 3. Atomic → redcanaryco/atomic-red-team

1. Copy `atomics/<ATT&CK>/` (the `<ATT&CK>.yaml` and `src/`).
2. Keep each test's `auto_generated_guid` (already assigned).
3. For the cloud tests, keep the opt-in guard and the `--show-fixture` path, and state
   in the PR that they act against the operator's own account and are not destructive
   (they create throwaway resources and clean up, or are read-only).

## What stays here

The validators, CI workflows, the recorded cloud fixtures, the DDM renderer, and this
staging layout are repository infrastructure, not upstream artifacts — they prove the
loop locally and do not ship upstream.
