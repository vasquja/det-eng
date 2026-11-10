# Cloud sandbox accounts

This guide is step 4 of [`docs/setup/`](README.md). It is optional. Nothing in CI
needs a cloud account today.

Independent reviewers checked this page and the workflow
[`sandbox-smoke.yml`](../../.github/workflows/sandbox-smoke.yml) against primary
sources on 2026-11-10: the GitHub documentation source, the GitHub REST API
description, the source of the GitHub CLI and the source of the sign-in actions
at the pinned commits. No command on this page was run against a real repository
setting or a real cloud account. The provider pages say the same, and each one
has a "Not verified" list.

| Provider | Guide | Techniques that have a live script |
|----------|-------|-------------------------------------|
| AWS | [`cloud-aws.md`](cloud-aws.md) | TRR9011, TRR9012, TRR9015, TRR9016, TRR9019, TRR9021, TRR9022, TRR9032, TRR9037 |
| Azure and Microsoft Entra | [`cloud-azure.md`](cloud-azure.md) | TRR9013, TRR9017, TRR9036. TRR9023 has a script, but no run by hand: see [step 7.5](cloud-azure.md#75-trr9023-read-the-sign-in-of-the-smoke-test) of the Azure page. |
| Google Cloud | [`cloud-gcp.md`](cloud-gcp.md) | TRR9014, TRR9018, TRR9038. TRR9020 has a script that cannot complete at this time: see [section 7](cloud-gcp.md#7-optional-an-organization-for-trr9020) of the Google Cloud page. |

You do not need all three. Start with one. Some of these scripts have defects:
see [Problems in the live scripts](#problems-in-the-live-scripts).

## What the sandbox is for

CI proves each cloud rule against recorded fixtures: an `attack.json` and a
`benign.json` under `detections/cloud/fixtures/`. A person or an AI agent wrote
those records from the provider documentation. CI thus proves that the rule agrees
with the fixture. It does not prove that the fixture agrees with what the cloud
writes.

A sandbox closes that gap. Each technique has an emulation script under
`atomics/`. With `TRR90NN_LIVE=1` the script makes the real change in your account
and reverts it. The cloud then writes a real audit record, and you can run the rule
on that record.

## What is in the repository, and what is not

| Item | State |
|------|-------|
| Emulation scripts with a live mode | In the repository. They run only when a person starts them. See [Problems in the live scripts](#problems-in-the-live-scripts). |
| This guide and the three provider pages | In the repository. |
| [`sandbox-smoke.yml`](../../.github/workflows/sandbox-smoke.yml) | In the repository. It signs in and makes one read-only call. It runs only when a person starts it, and each run waits for an approval. |
| The cloud identity that CI signs in as | Not in the repository. You make it in the federation step of a provider page. It is read-only: it gets only what the one call of the smoke test needs. See rule 2 of [The security rules](#the-security-rules). |
| A workflow that runs the emulations in the sandbox and collects the records | **Not built.** [`AGENTS.md`](../../AGENTS.md) says that live emulations never run in CI. That rule stays until such a workflow is designed and reviewed. Until then, the CI identity gets no more than the smoke test needs. |

So today the sandbox is for runs by hand. The GitHub federation in this guide is
the base for a later workflow. You can stop before it: each provider page, up to
and including its step "Run one emulation by hand and read the record", is
sufficient for runs by hand.

## The security rules

The emulations do what an attacker does: they make a bucket public, add a
backdoor credential, give an administrator role. The rules below keep that safe.

1. **One empty account for each provider, used for nothing else.** The empty
   account is the security boundary. You are an administrator in it for the runs
   by hand, and that is acceptable only because there is nothing in it to take or
   to break. Never use an account of your employer. Never connect the sandbox to a
   different account (no peering, no shared organization, no trust).
2. **The CI identity is read-only.** No workflow in the repository runs an
   emulation in the sandbox. The only job that uses the cloud identity is the
   smoke test. It signs in and makes one read-only call. Thus the federation step
   of each provider page gives the identity only what that call needs. AWS: the
   role `det-eng-sandbox-github-oidc` gets no permissions policy. Azure: the CI
   application gets the role `Reader` on the sandbox subscription. Google Cloud:
   the service account `ci-sandbox` gets `roles/browser` on the sandbox project.
   Give the identity more only when a reviewed workflow needs more. Each provider
   page keeps those commands under the title "Later: when a reviewed workflow runs
   the emulations":
   [AWS](cloud-aws.md#6-later-when-a-reviewed-workflow-runs-the-emulations),
   [Azure](cloud-azure.md#later-when-a-reviewed-workflow-runs-the-emulations),
   [Google Cloud](cloud-gcp.md#65-later-when-a-reviewed-workflow-runs-the-emulations).
   Do not do that part now.
3. **No stored key.** GitHub Actions signs in with a short-lived token (OIDC
   federation). There is no access key, client secret or JSON key to leak. If a
   guide tells you to store one, it shows an older method.
4. **The cloud trusts one exact identity.** The trust names the subject of a job
   in the environment `sandbox` of your repository. It has no wildcard. A fork, a
   different repository and a job that does not name the environment get a
   different subject, and the cloud refuses them. Before you rename, move, delete
   or make private the repository, or rename or delete your GitHub account,
   delete the trust in the cloud: see the "Teardown" section of the provider page.
5. **The environment permits the branch `main` only, and you are its required
   reviewer.** The subject of an environment job does not include the branch.
   GitHub applies the branch rule and the reviewer rule. Thus a person who can
   change the environment settings, or who can put code on `main` and approve a
   run, can act as the CI identity. Keep these under your control. GitHub applies
   the two rules to a public repository. On GitHub Free, GitHub ignores the
   protection rules and the secrets of an environment when the repository becomes
   private. On GitHub Pro and Team, required reviewers are for public
   repositories only. The trust in the cloud stays in each case.
6. **A workflow that names the environment `sandbox` has `workflow_dispatch` as
   its only trigger.** "The branch `main`" does not mean "started by the owner". A
   run from the event `issue_comment` or `workflow_run` has the default branch as
   its ref. A run from `pull_request_target` has the base branch of the pull
   request. These runs pass the branch rule, and a person with no write access can
   cause some of them. Refuse each change that adds a different trigger to a
   workflow that names the environment.
7. **Multifactor authentication on each administrator account of a cloud, and on
   your GitHub account.** Use the root or first account of a cloud for setup only.
8. **A budget alert on each account**, and the hard limit of the free trial where
   the provider has one.
9. **Do not commit a live record as it is.** It holds your account ID, your IP
   address and your email address. Replace each of them with the value that the
   committed fixture of the same technique has in the same field
   (`detections/cloud/fixtures/trr90NN/attack.json`). For an IP address, a
   domain, an AWS account and a resource name, the fixtures have the safe markers
   that [`AGENTS.md`](../../AGENTS.md) names: an RFC 5737 IP address,
   `example.com`, the AWS account `123456789012` and `trr90NN-` names. `AGENTS.md`
   names no marker for an Azure tenant, subscription or object ID, and none for a
   Google Cloud project number or organization ID. For these, the fixture is the
   only source. Examples: the subscription `11111111-2222-3333-4444-555555555555`
   in the TRR9036 fixture, and the project number `123456789012` in the TRR9018
   fixture.

**What the reviewer rule cannot do.** An approval can also be sent through the
GitHub API, with a token of your account. While an AI agent session works through
your GitHub account (see [`agent-identity.md`](agent-identity.md)), GitHub cannot
tell that session from you. The approval is thus a check by a person only when no
automation holds your credentials. While an agent session can act with your
account, rules 1 and 2 are the boundaries that hold: the account is empty, and the
CI identity can only read.

How the sign-in works, in one paragraph: a person starts a workflow on `main` that
has a job in the environment `sandbox`. The job waits until you approve it. Then
it asks GitHub for a token. GitHub signs a token that says which repository and
which environment the job is in. The job sends the token to the cloud. The cloud
checks the signature and compares the subject with the one string that you
stored. If they agree, the cloud gives the job a credential that is valid for
about one hour.

## Sequence

1. Follow one provider page up to and including its step "Run one emulation by
   hand and read the record". The steps before it give you the account, the
   guardrails and the throwaway resources.
2. Do [The GitHub side](#the-github-side) on this page one time. All providers
   use it.
3. Follow the federation step of the provider page. Its title starts with "Let
   GitHub Actions".
4. Run [Test the federation](#test-the-federation).

## The GitHub side

### Before you start

You need the GitHub CLI (`gh`) on your own computer, signed in as the owner of the
repository. [Before you start](README.md#before-you-start) in the index tells you
how to install it and how to sign in. Do not run these commands in the browser
shell of a cloud provider. Each step also names the web page that does the same.
In each command, replace `OWNER/REPO` with your repository: `OWNER` is your GitHub
user name or organization, and `REPO` is the name of the repository.

In a fork, enable GitHub Actions first. Open the **Actions** tab of the fork and
select **I understand my workflows, go ahead and enable them**. Until you do, no
workflow runs in the fork, and the smoke test cannot start.

```bash
gh auth status
gh api repos/OWNER/REPO --jq '"admin: \(.permissions.admin)  visibility: \(.visibility)"'
```

Check: the first command shows your account. The second command prints
`admin: true` and the visibility of the repository (`public` or `private`).

Turn on two-factor authentication for your GitHub account, if it is not on. Your
account is the administrator of the repository and the reviewer of each run. Web:
your profile picture > Settings > Password and authentication > "Two-factor
authentication".

Check: that section of the page shows a method that is configured.

### 1. Create the environment and permit the branch `main` only

Do this before you run the smoke test or store a value.

Web: repository > Settings > Environments > New environment > name `sandbox` (in
lowercase letters) > Configure environment > "Deployment branches and tags" >
"Selected branches and tags" > "Add deployment branch or tag rule" > Branch >
`main` > Add rule.

Or with the CLI:

```bash
gh api -X PUT repos/OWNER/REPO/environments/sandbox --silent \
  -F 'deployment_branch_policy[protected_branches]=false' \
  -F 'deployment_branch_policy[custom_branch_policies]=true'
gh api -X POST repos/OWNER/REPO/environments/sandbox/deployment-branch-policies --silent -f name=main -f type=branch
gh api repos/OWNER/REPO/environments/sandbox/deployment-branch-policies --jq '.branch_policies[] | "\(.type):\(.name)"'
```

Check: the last command prints one line, `branch:main`.

Notes:

- The name is part of the subject that the cloud trusts. If you change the name
  of the environment, the sign-in stops.
- Environments with branch rules are available on a public repository with each
  GitHub plan. A private repository needs GitHub Pro, Team or Enterprise.
- If a job names an environment that does not exist, GitHub creates it with no
  rule. The smoke test has a `preflight` job that stops the run in that
  condition. That job reads the environment with the permission `actions: read`.
  GitHub documents that permission for the two calls that the job makes, and no
  permission for a public repository.
- Do not delete the environment while a cloud trusts it. The first job that names
  it then makes a new environment with no rule. See
  [Off switch and teardown](#off-switch-and-teardown).
- If you send the `PUT` command again after step 2, do the check of step 2 again.
  GitHub does not document what the call does to a reviewer that it does not
  name.

### 2. Make yourself a required reviewer

Do this before the federation step of a provider page. The smoke test stops if
the environment has no required reviewer.

Web: repository > Settings > Environments > `sandbox` > select "Required
reviewers" > add your user name > keep "Prevent self-review" cleared > Save
protection rules.

Or with the CLI:

```bash
MY_ID="$(gh api user --jq .id)"
gh api -X PUT repos/OWNER/REPO/environments/sandbox --silent --input - <<EOF
{
  "prevent_self_review": false,
  "reviewers": [{"type": "User", "id": ${MY_ID:?gh is not signed in}}],
  "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}
}
EOF
gh api repos/OWNER/REPO/environments/sandbox --jq '.protection_rules[] | select(.type == "required_reviewers") | "reviewers: \([.reviewers[].reviewer.login] | join(","))  prevent_self_review: \(.prevent_self_review)"'
gh api repos/OWNER/REPO/environments/sandbox/deployment-branch-policies --jq '.branch_policies[] | "\(.type):\(.name)"'
```

Check: the last two commands print two lines. The first line shows your user name
and `prevent_self_review: false`. The second line is `branch:main`. If the second
line is missing, do the `POST` command of step 1 again.

Each job that names the environment then waits until you approve it. To approve:
repository > Actions > the run > Review deployments > select `sandbox` > Approve
and deploy. No run is unattended. Keep this rule. Only the reviewed design of a
later workflow can be a reason to change it.

Approve only a run that you started. Each account or token with write access can
start a run, and a different workflow on `main` that names the environment shows
the same button. Before you approve, read what waits. Replace `RUN_ID` with the
number at the end of the address of the run:

```bash
gh api repos/OWNER/REPO/actions/runs/RUN_ID --jq '"\(.path)  \(.event)  \(.head_branch)  \(.triggering_actor.login)"'
```

Check: the line is `.github/workflows/sandbox-smoke.yml  workflow_dispatch  main`
and your user name. For each other run: Review deployments > Reject.

Notes:

- Keep "Prevent self-review" cleared. With it, the person who starts a run cannot
  approve that run, and you are the only reviewer.
- On a private repository, required reviewers need GitHub Enterprise. With GitHub
  Free, Pro or Team, the option is available on a public repository only. Without
  a reviewer the smoke test stops, so the federation of this guide then needs a
  public repository.
- If more than one person is an administrator of the repository, also clear
  "Allow administrators to bypass configured protection rules" on the same page.
  With it, each administrator can start a job that waits.
- The rule has a limit. Read "What the reviewer rule cannot do" in
  [The security rules](#the-security-rules).

### 3. Find your exact subject string

The cloud compares the subject character by character. GitHub has two formats:

| Format | Subject of a job in the environment `sandbox` | When GitHub uses it |
|--------|-----------------------------------------------|---------------------|
| Names only | `repo:OWNER/REPO:environment:sandbox` | The repository was created before 2026-07-15, was not renamed or moved after that date, and did not opt in. |
| Names and IDs | `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:sandbox` | The repository was created, renamed or moved after 2026-07-15, or it opted in. A new fork is expected to be in this group. |

`OWNER_ID` and `REPO_ID` are numbers that GitHub gives to the account and to the
repository. Do not build the string from this table. The value from a run is the
only source.

**Read the setting.**

```bash
gh api repos/OWNER/REPO/actions/oidc/customization/sub
gh api repos/OWNER/REPO --jq '"created \(.created_at)  owner id \(.owner.id)  repository id \(.id)"'
```

The first command prints `use_default`, `sub_claim_prefix` and, if it is set,
`use_immutable_subject`. `sub_claim_prefix` is the part of the subject before
`:environment:`. If it has an `@`, the repository has the format with IDs. If
`use_default` is `false`, a person changed the subject template. This guide
assumes the default: find out why before you continue. The second command prints
the two numbers that the format with IDs holds.

**Recommended: opt in to the format with IDs.** Do this only if the repository
has the format with names only, and only before a cloud trust exists. That format
holds names only. If you rename, move or delete the repository or the account
later, a different person can take the name, and a cloud trust for the old string
then accepts a token of that person's repository. The format with IDs prevents
that.

```bash
gh api -X PUT repos/OWNER/REPO/actions/oidc/customization/sub --silent -F use_default=true -F use_immutable_subject=true
gh api repos/OWNER/REPO/actions/oidc/customization/sub
```

Check: `use_immutable_subject` is `true`.

The opt-in changes the `sub` of each workflow of the repository that asks for an
OIDC token. A trust for the old `sub` then refuses the token. In this repository,
`claude-code-review.yml` and `agent-identity-probe.yml` ask for a token, through
`anthropics/claude-code-action`. After the opt-in, run the identity probe again:
see the step [Run the identity probe](agent-identity.md#a4-run-the-identity-probe)
in `agent-identity.md`. If that sign-in fails, set the field back with the command
below, and use the format with names only.

```bash
gh api -X PUT repos/OWNER/REPO/actions/oidc/customization/sub --silent -F use_default=true -F use_immutable_subject=false
```

**Read the subject from a run.** Run the smoke test with `claims` (see
[Test the federation](#test-the-federation)). It prints the claims of a real
token. These are five of them (`REPOSITORY_ID` stands for a number):

```json
{
  "sub": "repo:OWNER/REPO:environment:sandbox",
  "repository_id": "REPOSITORY_ID",
  "environment": "sandbox",
  "ref": "refs/heads/main",
  "event_name": "workflow_dispatch"
}
```

Copy the `sub` value exactly. With the format with IDs it has two `@` characters.
Each provider page puts the value into a shell variable (`SUBJECT`, or
`GH_SUBJECT` on the Google Cloud page). The Google Cloud page also uses
`repository_id`, `ref` and `event_name`. If the value from the run and the value
that you expect from the first command are different, use the value from the run.

GitHub documents the format with IDs with a branch example only. The form with
`:environment:` is by analogy. That is one more reason to copy the value from a
run.

### 4. The names of the stored values

Each provider page tells you when to store its values. All of them go into the
**environment** `sandbox`, not into the repository, so that a job outside the
environment cannot read them.

| Provider | Name | Type | Value |
|----------|------|------|-------|
| AWS | `AWS_ROLE_ARN` | secret | The ARN of the CI role |
| AWS | `AWS_REGION` | variable | `us-east-1` |
| Azure | `AZURE_CLIENT_ID` | secret | The application (client) ID of the CI application |
| Azure | `AZURE_TENANT_ID` | secret | The tenant ID |
| Azure | `AZURE_SUBSCRIPTION_ID` | secret | The subscription ID |
| Google Cloud | `GCP_WORKLOAD_IDENTITY_PROVIDER` | secret | The full name of the provider |
| Google Cloud | `GCP_SERVICE_ACCOUNT` | secret | The email address of the CI service account |
| Google Cloud | `GCP_PROJECT_ID` | secret | The project ID |

None of these values is a credential. With one of them and no token from the
environment, a person can do nothing. They are secrets for one reason: GitHub
then masks them in the log, and the log of a public repository is public.

After you stored the values of a provider, check where they are:

```bash
gh secret list --env sandbox --repo OWNER/REPO
gh variable list --env sandbox --repo OWNER/REPO
gh secret list --repo OWNER/REPO
gh variable list --repo OWNER/REPO
```

Check: the first two commands show the names of your provider. The last two
commands show no name from the table. A job in an environment also reads the
secrets and variables of the repository. The smoke test thus cannot find a value
that is in the wrong place, and each job of the repository can read that value.
If a name from the table is in the repository list, delete it there with
`gh secret delete NAME --repo OWNER/REPO` or
`gh variable delete NAME --repo OWNER/REPO`, where `NAME` is that name. Then
store it again with `--env sandbox`.

### 5. Optional: an Actions policy for the smoke test

This step was built from the GitHub documentation source and the REST API
description. It was not run.

An Actions policy is a rule of the repository that says which events can start a
workflow. The policy below permits `workflow_dispatch` only for the file
`sandbox-smoke.yml`. GitHub then refuses a run of that file from a different
event, also if a later change adds a trigger to the file. Actions policies are
available on each public repository, and on a private repository with GitHub Team
or Enterprise.

Web: repository > Settings > Actions > Policies > create a policy > enforcement
"Active" > target the workflow `.github/workflows/sandbox-smoke.yml` > "Restrict
events" > permit `workflow_dispatch` only.

Or with the CLI:

```bash
gh api -X POST repos/OWNER/REPO/actions/policies --silent --input - <<'EOF'
{
  "name": "sandbox-smoke: manual start only",
  "enforcement": "active",
  "conditions": {
    "workflow_path": {"include": [".github/workflows/sandbox-smoke.yml"], "exclude": []}
  },
  "rules": [
    {"type": "restrict_action_events", "parameters": {"allowed_events": ["workflow_dispatch"]}}
  ]
}
EOF
gh api repos/OWNER/REPO/actions/policies --jq '.policies[] | "\(.id)  \(.name)  \(.enforcement)"'
```

Check: the last command prints a line with the name of the policy and `active`.
Then run the smoke test: it must start as before.

Notes:

- To permit only yourself to start the smoke test, open the policy on the web page
  and add yourself under "Restrict actors".
- The policy is for this one file. It does not stop a different workflow file
  that names the environment. Rule 6 of
  [The security rules](#the-security-rules) is for that.
- This policy does not replace the
  [Actions policy for `automerge.yml`](repository-settings.md#first-the-actions-policy-for-automergeyml-before-2026-12-02)
  that `repository-settings.md` describes. The two have different targets. This
  policy names only `sandbox-smoke.yml`. Do not rely on it to keep `automerge.yml`
  in operation. The policy for `automerge.yml` has a date: 2026-12-02.
- To remove the policy: `gh api -X DELETE repos/OWNER/REPO/actions/policies/POLICY_ID`.
  `POLICY_ID` is the first value of the check line.

## Test the federation

The workflow [`sandbox-smoke.yml`](../../.github/workflows/sandbox-smoke.yml) must
be on the branch `main` of your repository. Each run waits for your approval (step
2 of [The GitHub side](#the-github-side)).

Web: repository > Actions > `sandbox-smoke` > Run workflow > branch `main` >
select `claims`, `aws`, `azure` or `gcp` > Run workflow. Then open the new run >
Review deployments > select `sandbox` > Approve and deploy.

Or with the CLI. Start the run and find it:

```bash
gh workflow run sandbox-smoke.yml --repo OWNER/REPO --ref main -f cloud=claims
sleep 10
gh run list --repo OWNER/REPO --workflow sandbox-smoke.yml --limit 1 --json databaseId,status,url --jq '.[] | "\(.databaseId)  \(.status)  \(.url)"'
```

For a provider test, put `aws`, `azure` or `gcp` in the place of `claims` in the
first line.

Check: the last command prints one line: the ID of the run (a number), its status
and its address. The status is `queued` or `in_progress` while the `preflight`
job runs. If the command prints nothing, or if the status is `completed`, the
list does not show the new run yet. Wait some seconds and run the last command
again.

Approve the run: open the address in a browser > Review deployments > select
`sandbox` > Approve and deploy. The button shows when a job waits for the
approval. That is after the `preflight` job.

Then wait for the end of the run and read the log. Replace `RUN_ID` with the ID
of the run:

```bash
gh run watch RUN_ID --repo OWNER/REPO
gh run view RUN_ID --repo OWNER/REPO --log
```

`gh run watch` returns when the run is complete. Before that, `gh run view --log`
stops with "run ... is still in progress". `gh run watch` does not work with a
fine-grained personal access token: look at the run in the browser then.

For a `claims` run, this command prints only the four values that the provider
pages use:

```bash
gh run view RUN_ID --repo OWNER/REPO --log | grep -E '"(sub|repository_id|ref|event_name)":'
```

Check: the command prints four lines, one for each of `sub`, `repository_id`,
`ref` and `event_name`.

What a good run prints in its last step:

| Input | Output |
|-------|--------|
| `claims` | A JSON object. `sub` ends with `:environment:sandbox`, `ref` is `refs/heads/main`, and `event_name` is `workflow_dispatch`. |
| `aws` | `assumed role: det-eng-sandbox-github-oidc  session: GitHubActions`. The step does not print the ARN: the sign-in action masks the account ID and the full ARN, and the log shows `***` for them. |
| `azure` | `"signedInAs": "servicePrincipal"` and `"subscriptionState": "Enabled"` |
| `gcp` | `ACTIVE` |

The test changes nothing in the account. It does not run an emulation.

If a run fails or does not continue:

| Where | Message | Cause |
|-------|---------|-------|
| The run | No message. The run stays in the state `pending` and starts no job. | An earlier run of the smoke test is not complete. Approve that run, or stop it with `gh run cancel RUN_ID --repo OWNER/REPO`. |
| A job that names the environment | No message. The job stays in the state `waiting`. | The job waits for your approval: Review deployments > select `sandbox` > Approve and deploy. |
| `preflight` | "does not exist", "is not set to 'Selected branches and tags'" or "must permit the branch main only" | Do step 1 of [The GitHub side](#the-github-side). |
| `preflight` | "has no required reviewer" | Do step 2 of [The GitHub side](#the-github-side). |
| `preflight` | "Start this workflow from the branch main." | You started the run from a different branch. Start it again with the branch `main`. |
| The first step of a cloud job | "Set the secret ..." | The values are not stored, or a name is different. Do the check of step 4 of [The GitHub side](#the-github-side). |
| AWS sign-in | "Could not assume role with OIDC: Not authorized to perform sts:AssumeRoleWithWebIdentity" | The `sub` or `aud` in the trust policy of the role does not agree with the token. Compare the stored subject with the `sub` value of a `claims` run, and correct the trust in place: [step 5.2](cloud-aws.md#52-create-the-role-and-trust-one-subject) of the AWS page (`aws iam update-assume-role-policy`). |
| Azure sign-in | `AADSTS700213`, or `AADSTS7002138` if only the letter case is different (no matching federated identity record for the subject) | The subject in the federated credential does not agree with the token. The sign-in step prints "Federated token details" with the `subject claim` of the token. Compare it with the stored subject, character by character, and correct the credential in place: [step 7.2](cloud-azure.md#72-trust-the-environment-sandbox-and-nothing-else) of the Azure page. |
| Azure sign-in | `AADSTS70021` (no matching federated identity record) | The credential was created or changed some minutes ago. Wait and try again. |
| Azure sign-in | "No subscriptions found" | The `Reader` role of [step 7.3](cloud-azure.md#73-give-the-application-the-reader-role) of the Azure page is missing, or it is less than 10 minutes old. |
| Google Cloud, the sign-in step | "Failed to generate Google Cloud federated token" | The attribute condition of the provider does not agree with the token, or the pool or the provider is less than five minutes old. That step gets a token from the Security Token Service. It does not use the service account. Correct the provider in place: [step 6.2](cloud-gcp.md#62-create-the-pool-and-the-provider) of the Google Cloud page. |
| Google Cloud, the last step | An error from `gcloud` | The last step is the first that acts as the service account. The binding that lets the subject act as the service account is wrong ([step 6.3](cloud-gcp.md#63-let-that-one-subject-act-as-the-service-account) of the Google Cloud page), or the role of the service account is missing ([step 6.1](cloud-gcp.md#61-create-the-service-account-for-ci)), or one of them is less than five minutes old. |

## Off switch and teardown

**The off switch.** This command stops each start of the smoke test:

```bash
gh workflow disable sandbox-smoke.yml --repo OWNER/REPO
gh workflow list --all --repo OWNER/REPO
```

Check: the line of `sandbox-smoke` shows `disabled_manually`. The command
`gh workflow enable sandbox-smoke.yml --repo OWNER/REPO` turns it on again.

The off switch does not remove the trust in the cloud. It does not stop a
different workflow on `main` that names the environment. To remove the trust, do
the teardown.

**The teardown.** Do the three parts in this sequence.

1. Delete the trust in the cloud. The "Teardown" section of the provider page
   deletes the CI identity. After this, the cloud refuses each token of the
   repository.
2. Delete the stored values of that provider. Use the names from the table in
   step 4 of [The GitHub side](#the-github-side). Replace `NAME` with each secret
   name. The `gh variable` line is for AWS only.

   ```bash
   gh secret delete NAME --env sandbox --repo OWNER/REPO
   gh variable delete AWS_REGION --env sandbox --repo OWNER/REPO
   gh secret list --env sandbox --repo OWNER/REPO
   gh variable list --env sandbox --repo OWNER/REPO
   ```

   Check: the last two commands do not show the names of that provider.
3. Delete the environment last, and only if no workflow on `main` can name it. If
   a workflow names an environment that does not exist, GitHub creates it again
   with no branch rule and no reviewer. So first use the off switch, or remove
   `sandbox-smoke.yml` from `main`. If the workflow stays, keep the environment:
   an environment with its two rules and no values gives no access.

   ```bash
   gh api -X DELETE repos/OWNER/REPO/environments/sandbox
   gh api repos/OWNER/REPO/environments --jq '[.environments[].name] | join(" ")'
   ```

   Check: the last command does not print `sandbox`. GitHub deletes the secrets
   and the rules of the environment with it.

## Problems in the live scripts

These problems were found when the scripts were read against the references of
the providers. They were not found by a run. Until they are corrected, use the
committed fixtures for the procedures that they stop.

| Script | Problem | Effect |
|--------|---------|--------|
| `atomics/T1199/src/emulate_gcp_workforce.sh` (TRR9020) | The script gives `--organization` to `gcloud iam workforce-pools providers create-oidc`, `providers delete` and `workforce-pools delete`. The Google Cloud SDK 570.0.0 does not have that option on these three commands. `providers create-oidc` also requires `--client-id`, and a client secret for the response type `code`. The script does not give them. | The live run cannot complete. It leaves the pool. |
| `atomics/T1098.001/src/emulate_gcp_wif.sh` (TRR9018) | The default issuer is the GitHub issuer, with no attribute condition. Google requires a condition for that issuer. | The live run stops unless `TRR9018_ISSUER` is set. |
| The same script | The default name of the provider is `gh`. It has 2 characters, and Google requires 4 to 32. | The live run stops unless `TRR9018_PROVIDER` is set. It leaves the pool. |
| The same script | It adds the binding `roles/iam.workloadIdentityUser` for `principalSet://.../workloadIdentityPools/POOL/*` to the service account, and it does not remove it. `POOL` stands for the name of the pool. | Each run leaves one binding. [Step 5.4](cloud-gcp.md#54-the-other-emulations) of the Google Cloud page removes it, and step 5.5 checks it. |
| The same script, and the TRR9020 script | The pool name is fixed. Google blocks the name of a deleted pool for 30 days. The name of a workforce pool (TRR9020) must also be unique in all of Google Cloud, so a different customer can have the default name `trr9020-ext-pool`. | The second run in 30 days fails unless `TRR9018_POOL` or `TRR9020_POOL` is set. The first TRR9020 run can fail for the same reason. |
| `atomics/T1562.008/src/emulate_gcp_log_sink.sh` c (TRR9038) | `gcloud logging exclusions create` is not a command of the Google Cloud SDK 570.0.0. | Procedure c cannot run. |
| `atomics/T1528/src/emulate_entra_consent.sh` a, b, c, e (TRR9017) | The script registers the application and deletes it. It does not grant consent. | No "Consent to application" record, which is the record that the rule reads. |
| The same script, d | A tenant that was created on 2026-07-01 or later blocks the device code flow. | No sign-in that succeeds, so no record that the rule reads. |
| `atomics/T1098.001/src/emulate_entra.sh` (TRR9013) | The subject has a `*`. Microsoft documents that a wildcard is not supported. | Not confirmed. The run can stop before its cleanup line. |
| `atomics/T1078.004/src/emulate_entra_sp_fic_signin.sh` (TRR9023) | The script needs an OIDC token of a different issuer, so a person cannot run it by hand. It discards the answer of the token request and does not look at the HTTP status. If `TRR9023_TENANT` or `TRR9023_APPID` is not set, it uses a placeholder ID. | The script prints "done" also when Entra refuses the token. [Step 7.5](cloud-azure.md#75-trr9023-read-the-sign-in-of-the-smoke-test) of the Azure page tells you how to get a real record without the script. |
| Most live scripts | The script stops at the first error, and has no cleanup step for that condition. | A run that fails can leave the change in place. Each provider page has a check that nothing stays behind, with the commands that put things back: [step 4.5](cloud-aws.md#45-after-each-live-run-make-sure-that-nothing-stays-behind) of the AWS page, [Make sure that nothing stays behind](cloud-azure.md#make-sure-that-nothing-stays-behind) on the Azure page, and [step 5.5](cloud-gcp.md#55-after-each-live-run-make-sure-that-nothing-stays-behind) of the Google Cloud page. |

## Costs

| Provider | During the free offer | After it | Optional items |
|----------|-----------------------|----------|----------------|
| AWS | 0 USD. The Free plan cannot be charged. It ends after 6 months or when the credits are used. | You must upgrade to keep the account. The resources on the AWS page cost about 0 USD each month. | An EKS cluster: 0.10 USD each hour while it exists. |
| Azure | 0 USD for 30 days, with a hard spending limit. | The subscription is disabled until you upgrade to pay-as-you-go, which has no spending limit. The storage account for the logs costs less than 0.01 USD each month. | Microsoft Entra ID P1 for the sign-in logs: 7 USD for each user each month, paid for one year at a time (84 USD for one licence). |
| Google Cloud | 0 USD for 90 days. The trial cannot charge you. | You must upgrade to keep the project. The resources on the Google Cloud page cost about 0 USD each month. | A domain name, only for TRR9020. |
| GitHub | Standard runners are free for a public repository. | | |

After the free offer, no provider has a hard limit for the full account. The
budget alert is then your protection. The lowest-cost plan is to delete the
sandbox when you do not use it, and to make it again with these pages.

## Not verified

- No step was run against a real repository setting or a real account. The first
  run of the smoke test is the test of the workflow. That includes the `preflight`
  job on a private repository.
- The subject of an environment job in the format with IDs. GitHub shows that
  format with a branch only. See step 3.
- That a new fork has the format with IDs. GitHub names new repositories, renames
  and moves only. It also does not say if a rename of the owner account changes
  the format of an older repository.
- The opt-in of step 3. The call is in the REST API description. This guide does
  not know if the token exchange of `anthropics/claude-code-action` accepts the
  format with IDs, what `use_immutable_subject` shows for a repository that was
  created after 2026-07-15, and if such a repository can set it to `false`.
- What the `PUT` call of an environment does to a reviewer or a branch rule that
  the call does not name. The checks of steps 1 and 2 show the result.
- If GitHub creates an environment that does not exist when the run starts, or
  only when the job that names it starts. In the first condition, the `preflight`
  job stops the use of the new environment, but not its creation.
- If the administrator bypass of an environment also applies to its branch rule.
- The Actions policy of step 5: how GitHub combines it with a second policy, and
  if GitHub counts it as a policy for the event `pull_request_target`, which
  `automerge.yml` uses.
- The label of the button that enables GitHub Actions in a fork ("Before you
  start"). GitHub Docs say that workflows do not run in a fork until you enable
  GitHub Actions in its Actions tab. The label is from a GitHub Docs page about
  code scanning.
- The exact text of the error messages in the table of
  [Test the federation](#test-the-federation). They can change with a new release
  of an action or of a cloud service.
- The exact label of the two-factor section on the GitHub settings page.

## Sources

- GitHub OIDC reference, the sections "Immutable subject claims" and "Configuring
  the subject in your cloud provider":
  `github.com/github/docs/blob/main/content/actions/reference/security/oidc.md`
- GitHub environments: "Required reviewers", "Deployment branches and tags" and
  "Allow administrators to bypass configured protection rules" in
  `content/actions/reference/workflows-and-actions/deployments-and-environments.md`,
  and `manage-environments.md` and `review-deployments.md` in
  `content/actions/how-tos/deploy/configure-and-manage-deployments/` of the same
  repository.
- The ref of each event:
  `content/actions/reference/workflows-and-actions/events-that-trigger-workflows.md`
- Secrets and variables of an environment and of a repository:
  `content/actions/reference/security/secrets.md` and
  `content/actions/reference/workflows-and-actions/variables.md`
- Actions policies: `content/actions/concepts/about-actions-policies.md` and
  `content/actions/how-tos/administer/control-workflow-execution.md`
- GitHub Actions in a fork ("Workflows don't run in forked repositories by
  default"): `data/reusables/developer-site/pull_request_forked_repos_link.md`
- Two-factor authentication:
  `content/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication.md`
- GitHub REST API description, the paths `/repos/{owner}/{repo}/environments/...`,
  `/repos/{owner}/{repo}/actions/oidc/customization/sub`,
  `/repos/{owner}/{repo}/actions/policies` and
  `/repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments`:
  `github.com/github/rest-api-description`. The permission of each call:
  `src/rest/data/` in `github.com/github/docs`.
- The source and the built-in help of the GitHub CLI 2.89.0 (`gh run list`,
  `gh run watch`, `gh run view`, `gh workflow disable`, `gh secret`,
  `gh variable`, `gh api`): `github.com/cli/cli`
- The source and the README files of the sign-in actions at the pinned commits.
  The commit IDs in the workflow were compared with the tags on 2026-11-10:
  `aws-actions/configure-aws-credentials` v6.3.0, `azure/login` v3.1.0,
  `google-github-actions/auth` v3.0.0, `google-github-actions/setup-gcloud` v3.0.1
  and `actions/checkout` v7.0.1.
- The Entra error codes: the troubleshooting section of the `azure/login` README,
  and Microsoft Learn, "Important considerations and restrictions for federated
  identity credentials" and "What's new for authentication?" (August 2024).
- The runner image list (`ubuntu-latest` is Ubuntu 24.04, with the AWS CLI, the
  Azure CLI, the Google Cloud CLI, the GitHub CLI and `jq`):
  `github.com/actions/runner-images`
