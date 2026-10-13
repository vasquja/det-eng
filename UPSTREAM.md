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
| The TRR (research) | `research/trrNNNN/<platform>/` | [tired-labs/techniques](https://github.com/tired-labs/techniques) | `reports/trr0000/<platform>/` (maintainer assigns the final ID) |
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
TRR9012  AWS         T1078.004        aws_cognito_identity_pool_unauth_enabled.yml (+3) T1078.004
TRR9013  Azure       T1098.001        aws_github_oidc_role_trust_abuse.yml (+4) T1098.001
TRR9014  GCP         T1098.003        gcp_public_iam_member_grant.yml          T1098.003
TRR9015  AWS         T1098.001        aws_github_oidc_role_trust_abuse.yml (+4) T1098.001
TRR9016  AWS         T1078.004        aws_cognito_identity_pool_unauth_enabled.yml (+3) T1078.004
TRR9017  Azure       T1528,T1566.002  entra_device_code_authentication.yml (+1) T1528
TRR9018  GCP         T1098.001,T1199  aws_github_oidc_role_trust_abuse.yml (+6) T1098.001,T1199
TRR9019  AWS         T1537            aws_efs_file_system_policy_made_public.yml (+7) T1537
TRR9020  GCP         T1199,T1098.001  aws_github_oidc_role_trust_abuse.yml (+6) T1098.001,T1199
TRR9021  AWS         T1537            aws_efs_file_system_policy_made_public.yml (+7) T1537
TRR9023  Azure       T1078.004,T1550.001 aws_cognito_identity_pool_unauth_enabled.yml (+5) T1078.004,T1550.001
TRR9022  AWS         T1550.001,T1078.004 aws_cognito_identity_pool_unauth_enabled.yml (+5) T1078.004,T1550.001
-----------------------------------------------------------------------------------------------
23 TRRs | 62 Sigma rule files | 22 atomic technique dirs
```

The "first rule" column is just the alphabetically-first file in each folder; a TRR
owns the rules named in its own `## Detections` table. T1098.001 is shared by TRR9013
(Entra/Azure), TRR9015 (AWS), and TRR9018 (GCP); T1078.004 by TRR9012, TRR9016 (AWS) and
TRR9023 (Entra SP sign-in); T1537 by TRR9019 (policies/snapshots/BPA) and TRR9021 (ACL +
long-tail); T1199 by TRR9020 (GCP workforce); T1562.001 by the Linux io_uring rule and TRR9008;
T1550.001 by TRR9022 (EKS IRSA off-cluster) and TRR9023 (Entra SP sign-in).

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

Current result: **0 errors, 0 condition errors.** The only findings are 13
LOW-severity style notes, each defensible:

- **NumberAsStringIssue (×12)** — auditd syscall-argument fields (`a0`..`a3`, `exit`,
  arg counts) are hex/decimal **strings** in the auditd event, so matching them as
  quoted strings is correct for `product: linux`. Leave as-is, or convert to bare
  numbers only if a target backend coerces types.
- **EscapedWildcardIssue (×1)** — `k8s_rbac_privileged_grant.yml` matches a **literal** `*`
  (an RBAC wildcard grant `verbs: ["*"]`) with `\*`; intentional. (The cloud rules now match a
  literal `*` with `|re` instead, so they carry no escaped-wildcard note.)

The cloud rules (TRR9011–9023) produce **0 errors and 0 issues** (they match a literal `*`
with `|re`, avoiding the escaped-wildcard note entirely).

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

> These steps were reconciled against each project's CURRENT `CONTRIBUTING`, format spec,
> and CI workflows (read 2026-10-13). They correct earlier assumptions; re-pull each project's
> linter/spec before a filing wave, since those gates are what bounce a PR. None of the three
> projects requires a DCO sign-off or CLA as of that read (confirm from your own experience).
> Opening each PR is a human step: fork + PR under your own account.

### 1. TRR → tired-labs/techniques

Upstream TRRs are **research-only** and the layout is rooted at `reports/`. Each report needs a
structural transform (our local house style keeps extras the upstream linter rejects):

1. Copy `research/trrNNNN/<platform>/` → `reports/trr0000/<platform>/` in a fork. `trr0000` is the
   mandatory placeholder; a merge-bot assigns the real number and rewrites it.
2. Remap the ID to the placeholder everywhere: `TRRNNNN`→`TRR0000`, `trrNNNN`→`trr0000` in prose,
   the Metadata `ID` row, every `TRRNNNN.PLATFORM.LETTER` procedure ID, and DDM filenames/embeds.
   Re-render the PNGs so their stamped hash matches
   (`python3 research/tools/render_ddm.py reports/trr0000/<platform>/ddms/*.json`).
3. **Delete** the `| Status |` metadata row, and the entire `## Detection Strategy` and
   `## Detections` sections — upstream TRRs carry no detection content (the Sigma mapping moves to
   the SigmaHQ PR).
4. Rewrite the Procedures table header to exactly `| ID | Title | Tactic |`, and the Available
   Emulation Tests table header to exactly `| ID | Link |` (link reference-style, or `None`).
5. Re-wrap every prose/list line to ≤80 chars, and convert every inline Markdown link and every
   bare `<url>` autolink to reference-style (`[text][ref]` with a matching `[ref]: url` footnote
   block).
6. Set `Contributors` to real human name(s), not `det-eng`. **(Confirm the names before filing.)**
7. Do NOT add/edit upstream `index.json` (the bot generates it); do not include `research/index.json`.
8. Gate locally: `go run tools/trrlint/main.go <README.md>` → 0 errors, and
   `python3 tools/index/index.py merge_test -f <README.md>` → success. One technique per PR.

### 2. Sigma rule → SigmaHQ/sigma

1. Place each rule by **log source** (table above); novel research detections go under
   `rules-emerging-threats/...` — which then **requires** a `detection.emerging-threats` tag (and
   plain `rules/...` must NOT carry it). Filenames are lowercase, `_`-separated, product-prefixed
   (`aws_*`/`azure_*`/`gcp_*`; no `entra_*` prefix — remap Entra to `azure_*`).
2. Normalise tags: one canonical ATT&CK tactic form (we have a hyphen/underscore mix to fix), every
   technique tag paired with its mapped tactic tag, and CVE tags as `cve.YYYY.NNNN` (dots).
3. Keep `status: experimental`; titles ≤120 chars, Title Case, not starting "Detect"/ending with a
   period; `references` with no MITRE-site links and git permalinks only.
4. Rework any literal `\*` escaped-wildcard match (the `escaped_wildcard` validator flags it, and our
   UUIDs are not on the exclusion list). `cri` / Kubernetes logsource fields may need a maintainer
   discussion first (`test_logsource.py`).
5. Run the REAL gate locally (not a plain `sigma check`):
   `sigma check --fail-on-error --fail-on-issues --validation-config <sigma>/tests/sigma_cli_conf.yml`
   with `pySigma-validators-sigmahq==0.21.*` installed, plus `yamllint -s` and `tests/test_logsource.py`.
   Submit per-logsource-family PRs, not one big batch; fill the PR template's tagged Changelog block.

### 3. Atomic → redcanaryco/atomic-red-team

1. **Merge, do not copy.** Most technique IDs already exist upstream with community tests — open the
   upstream `<T####>.yaml` and **append** our `atomic_tests[]`, keeping their `display_name`. Only a
   genuinely-absent ID (e.g. T1098.006, T1199) is a new file. Existence-check every ID first.
2. **Remove** hand-assigned `auto_generated_guid` from new tests (a GitHub Action assigns them); for
   merges, ensure no GUID collides with the existing file.
3. Strip the `TRRxxxx.PLAT.X —` name prefix and scrub `Rule: detections/sigma/...` / `Chokepoint:`
   from descriptions (internal references).
4. Reshape the cloud tests: drop the `*_LIVE=1` guard / dry-by-default / `--show-fixture` shape so
   `command` runs the behaviour, gate on a `prereq_command` auth check, and add `cleanup_command` for
   resource-creating tests (mark read-only ones as needing none).
5. Gate locally: `cd atomic_red_team && poetry install && poetry run python runner.py validate`
   (validates the whole repo). One PR per technique; `.yaml` extension, only `src`/`bin` subdirs.

## What stays here

The validators, CI workflows, the recorded cloud fixtures, the DDM renderer, and this
staging layout are repository infrastructure, not upstream artifacts — they prove the
loop locally and do not ship upstream.
