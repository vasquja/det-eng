# Give the agent its own GitHub identity

This guide is step 1 of [`docs/setup/`](README.md). Read it before
[`repository-settings.md`](repository-settings.md). The code-owner steps there
(steps 7 to 9: the `CODEOWNERS` check, code-owner review, last-push approval) are
safe only when two things are true:

1. You passed **the gate**: step A5 of this guide.
2. The agent opens its daily pull requests from GitHub Actions. This guide calls
   that day **the switch to GitHub Actions**. See
   [What the gate does not show](#what-the-gate-does-not-show).

Independent reviewers checked this page against primary sources on 2026-11-10: the
GitHub documentation source, the GitHub REST description, the Claude Code
documentation, the `gh` CLI source, and the `anthropics/claude-code-action` source
at the commit that the probe workflow uses. No command on this page was run against
a real account or repository, and no setting was changed. The probe workflow has
not run. Its first run is the test. Read the [Not verified](#not-verified) list.

## The problem

An AI agent writes most pull requests in this repository. The design wants GitHub,
and not a sentence in a file, to stop the agent from approving or merging changes
to the checking code. GitHub can do that only if it can tell the agent from the
owner.

Today it cannot. A Claude Code cloud session (one that you start at
`claude.ai/code`, and also a scheduled task) reaches GitHub through **your**
connected GitHub account. The Claude Code documentation says: "Anything a
scheduled task does through your connected GitHub identity or connectors appears
as you. Commits and pull requests carry your GitHub user." No setting changes this.

The results:

- Each pull request from a cloud session has **you** as its author. GitHub does
  not let an author approve their own pull request. So a rule that needs your
  approval can never be satisfied for those pull requests.
- An approval, a label or a merge that the agent makes in a cloud session is,
  for GitHub, yours.

The agent needs an identity that is not you, and it must run in a place that does
not hold your GitHub credentials.

## What GitHub can and cannot enforce here

This repository belongs to a personal account. These facts decide the design:

| Fact | Result |
|------|--------|
| A personal repository has two levels only: owner and collaborator. A collaborator always has write access. | A second user account can push, label, merge when the rules allow, change repository variables, and approve a pull request that it did not open. Only rulesets and other admin settings are owner-only. |
| A GitHub App holds only the permissions that its owner selected. Its account type is `Bot`. It cannot be named in `CODEOWNERS`. Its tokens live one hour. | An App with write access to Contents and Pull requests can push branches, open pull requests, add and remove labels, submit reviews, and merge each pull request that the ruleset permits. Only the ruleset (required checks, code-owner review) limits the merge. |
| An event that the built-in `GITHUB_TOKEN` makes starts no workflow run. There are two exceptions. `workflow_dispatch` and `repository_dispatch` always start runs. A pull request that a workflow opens or updates with `GITHUB_TOKEN` gets workflow runs that wait until a person with write access selects "Approve workflows to run". An event that an App token or a personal access token makes starts runs normally. | The agent must not use `GITHUB_TOKEN` to push. The author would be `github-actions[bot]`, not the agent, and CI would wait for your click on each pull request. |
| A fine-grained personal access token cannot write to a repository where its user is only a collaborator. | A second user account needs a classic token, which is long-lived and broad. |
| "Require approval of the most recent reviewable push" looks at who **pushed** last, not at who opened the pull request. | The agent's pushes must also come from the agent's identity. |

## The options

| Option | What you set up | What you get | Limits |
|--------|-----------------|--------------|--------|
| **A. The Claude GitHub App, through `anthropics/claude-code-action` in GitHub Actions.** Recommended first step. | In the first repository: nothing new. It has the App and the secret `CLAUDE_CODE_OAUTH_TOKEN` already (`claude-code-review.yml` uses them). In a fork: install the App (A1) and set the secret (A2). | Pull requests and pushes come from `claude[bot]`. The job holds none of your GitHub credentials. | Anthropic fixes the permission set of the App, and it is broader than a builder needs. A job runs for 6 hours at most. Runs use your Claude subscription. |
| **B. Your own GitHub App**, with its token passed to the same action. | Register an App (about 15 minutes), store its key as a secret. | The same as A, and the App holds only the permissions that you select. | One more secret to keep. |
| **C. A machine user**: a second GitHub user account. | Create the account by hand, invite it, make a classic token. | An identity that also works outside GitHub Actions. | Always has write access: it can label, change variables and approve pull requests that it did not open. The token is long-lived. The action's own security notes say not to use a personal access token where the agent reads untrusted content. |
| **D. Move the repository to a free organization.** | Create an organization, transfer the repository. | Fine-grained tokens, roles below write, teams as code owners, merge queue. | New address. Not necessary for this design. Do it later if a second maintainer joins or you want the merge queue. |

Options A and B have three more limits. Know them before you build on them:

- **What the job holds.** The job holds the secret `CLAUDE_CODE_OAUTH_TOKEN` and a
  token of the App. The Claude token can only make model requests, on your
  subscription, and it is valid for one year. The action's documents say that the
  App token can write Contents, Pull requests and Issues. The commands that the
  agent runs have the two tokens in their environment. An agent that reads text
  from outside the repository can be made to send them out. So permit exact
  commands only, as the probe workflow does.
- **Workflow files.** The agent cannot push a change under `.github/workflows/`
  unless its token has the Workflows permission. In option A, the action's
  documents say that the workflow must ask for it with the input
  `additional_permissions` (`workflows: write`). In option B you select it for
  your App.
- **Commit signing.** Commits that the action pushes with `git` are not signed.
  Rail 8 of `automerge.yml` then holds each pull request that is not content only
  for a merge by hand, also after your approval. The input
  `use_commit_signing: true` makes the action commit through the GitHub API, with
  a verified signature of the App.

Not possible: a different GitHub identity for a Claude Code cloud session. If you
want unattended agents with an identity of their own, they must run in GitHub
Actions (options A or B), or in cloud sessions of a second Claude account that is
connected to a machine user (a second paid seat).

**Recommendation.** Use option A now. It needs no new account and proves the
design. Move to option B when the builder workflow is in daily use, if you want
the narrower permissions. Use option C only if the agent must run outside GitHub
Actions.

## Option A, step by step

### Before you start

Run the commands in your own terminal, on your own computer. Do not run them in an
agent session.

You need the GitHub CLI (`gh`). If you do not have it, install it from
`https://cli.github.com`. Then run `gh auth login` and sign in through the browser
as the owner of the repository.

Set the repository. Replace `OWNER/REPO` with your repository (for the first
repository: `vasquja/det-eng`).

```bash
REPO=OWNER/REPO
```

Keep the terminal open. The later blocks use `$REPO`, `$RUN_ID` and `$PR_NUMBER`.
If you open a new terminal, set `REPO` again.

```bash
gh auth status
gh api "repos/$REPO" --jq '"\(.full_name) admin=\(.permissions.admin) default_branch=\(.default_branch)"'
gh api "repos/$REPO/contents/.github/workflows/agent-identity-probe.yml" --jq .path
```

Check:

- The first command shows the account of the repository owner.
- The second command prints your repository, `admin=true` and
  `default_branch=main`.
- The third command prints `.github/workflows/agent-identity-probe.yml`. The probe
  workflow is then on the default branch. GitHub can start it only from there. If
  the command fails with `Not Found`, merge the pull request that adds the
  workflow. Then do this check again.

**In a fork**, three more things are necessary before the probe can run:

1. Enable GitHub Actions now. Open the **Actions** tab of your fork and select
   **I understand my workflows, go ahead and enable them**. Until you do, no
   workflow runs in the fork.
2. Install the Claude GitHub App on the fork. Step A1 shows how.
3. Set the secret `CLAUDE_CODE_OAUTH_TOKEN`. Step A2 shows how. The runs then use
   your Claude subscription.

### A1. Check that the Claude GitHub App is installed on this repository

In the browser, open the repository > Settings > GitHub Apps (under
"Integrations").

Check: the list contains `Claude`.

If `Claude` is not in the list, add this repository:

- **Your account does not have the App.** Open `https://github.com/apps/claude` >
  Install > your account > "Only select repositories" > this repository > Install.
- **Your account has the App for other repositories.** Your profile picture >
  Settings > Applications > Installed GitHub Apps > Claude > Configure. Under
  "Repository access", add this repository to the selected repositories > Save.

Then do the check again.

The design needs the App on this repository. It does not need the App removed from
your other repositories. Remove a different repository only if you do not use
Claude with it: Claude Code features such as projects, Code Review and Auto-fix
need the App on each repository that they work on.

### A2. Check the Claude token secret

```bash
gh secret list --repo "$REPO"
```

Check: the list contains `CLAUDE_CODE_OAUTH_TOKEN`.

If it is missing, run `claude setup-token` in a terminal where Claude Code is
installed, and approve the request in the browser. The token prints in the
terminal. It needs a paid Claude plan. Then run this line alone, and paste the
token when the command asks for it:

```bash
gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo "${REPO:?set REPO first}"
```

Do not put the token in a file, in a chat or on a command line. Do the check
again.

### A3. Check that workflows cannot approve pull requests

```bash
gh api "repos/$REPO/actions/permissions/workflow"
```

Check: the answer has `"can_approve_pull_request_reviews": false`. If it is `true`:
repository > Settings > Actions > General > "Workflow permissions" > clear "Allow
GitHub Actions to create and approve pull requests" > Save.

### A4. Run the identity probe

The workflow [`agent-identity-probe.yml`](../../.github/workflows/agent-identity-probe.yml)
lets Claude open one throwaway pull request from inside GitHub Actions. It then
reports who authored the pull request and who pushed its branch.

Start the probe from the default branch. Do not add `--ref`: the action checks the
workflow file against the default branch, and skips its work if the check fails.

```bash
gh workflow run agent-identity-probe.yml --repo "${REPO:?set REPO first}" -f path_kind=content
sleep 15
RUN_ID="$(gh run list --repo "$REPO" --workflow agent-identity-probe.yml --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
echo "Run ID: ${RUN_ID:?no run is listed yet}"
```

Check: the last line prints `Run ID:` and one number. If it prints
`no run is listed yet`, wait 30 seconds, then run the last two lines again.

```bash
gh run watch "${RUN_ID:?set RUN_ID first}" --repo "$REPO"
gh run view "${RUN_ID:?set RUN_ID first}" --repo "$REPO" --web
```

The first command shows the jobs `probe` and `report` until they end. If it says at
once that the run "has already completed", the list gave you an older run: run the
`RUN_ID=` line and this block again. The second command opens the run page in the
browser. Read the summary `Identity probe` on that page.

Check, all four:

- The summary says `Identity probe: PASS`.
- The pull request author is `claude[bot]`, of account type `Bot`.
- The account that pushed the branch is `claude[bot]`.
- `Commit signature verified` is `false`. That is expected: the probe commits with
  `git` (see "Commit signing" above).

PASS means that GitHub named the author and the pusher, and that neither is the
repository owner or the account that started the run.

If the summary does not say PASS, do not go on:

- **FAIL, or the `probe` job is red.** Read the log of the `probe` job. The usual
  causes: the App is not installed on the repository (A1); the token is missing or
  expired (A2); Claude wrote a command in a form that the permission rules of the
  workflow refuse. Correct the cause and run the probe again.
- **UNKNOWN.** GitHub did not name the author or the pusher. This is not a pass.
  Open the repository page > Activity, and read who pushed the branch of this run.
  Its name is `agent-identity-probe/` and then the run ID. Run the probe again. If
  the second run also says UNKNOWN, stop, and open an issue with what the Activity
  page shows.

If a run that did not pass made a pull request, close it: run the first block and
the last block of A5. Do not run the block that approves.

Run the probe again after each change to the App installation, to the secret, or
to the subject format of the repository's OIDC token (see
[`cloud-sandbox.md`](cloud-sandbox.md#3-find-your-exact-subject-string)).

### A5. The gate: approve the probe pull request

Find the pull request of the run:

```bash
PR_NUMBER="$(gh pr list --repo "$REPO" --state open --head "agent-identity-probe/${RUN_ID:?set RUN_ID first}" --json number --jq '.[0].number // empty')"
echo "Pull request: ${PR_NUMBER:?no open pull request for this run}"
```

Check: the last line prints `Pull request:` and one number.

If you opened a new terminal after A4, `$RUN_ID` is empty. Then find the number
with `gh pr list --repo "$REPO" --state open --search "Identity probe in:title"`.
The number is in the first column. Set it with `PR_NUMBER=` and that number.

Approve it:

```bash
gh pr review "${PR_NUMBER:?set PR_NUMBER first}" --repo "${REPO:?set REPO first}" --approve --body "Identity test: the owner can approve the agent's pull request."
gh api "repos/$REPO/pulls/${PR_NUMBER:?set PR_NUMBER first}/reviews" --jq '.[] | "\(.user.login) \(.state)"'
```

Check: the last command prints your login and `APPROVED`. If GitHub refuses the
review, you are the author of that pull request: the agent still acts through your
account.

The pull request starts the normal CI. Expect one red check: the `review` job of
`claude-code-review`. The action refuses a run that a bot started, and its log says
`Workflow initiated by non-human actor: claude (type: Bot)`. The red check does not
stop your approval.

You can close the pull request as soon as you have the result. Do not merge it.

```bash
gh pr close "${PR_NUMBER:?set PR_NUMBER first}" --repo "${REPO:?set REPO first}" --delete-branch
gh pr view "${PR_NUMBER:?set PR_NUMBER first}" --repo "$REPO" --json state --jq .state
```

Check: the last command prints `CLOSED`.

**The gate is passed when A4 says PASS and A5 prints your approval.** It shows
that an agent that runs in GitHub Actions has its own identity.

### What the gate does not show

The gate is about the probe: one pull request that GitHub Actions opened. The
code-owner steps of [`repository-settings.md`](repository-settings.md) (steps 7 to
9) also need **the switch to GitHub Actions**: the pull requests that the agent
opens in its daily work come from GitHub Actions, not from a cloud session. The
builder workflow that does this is not in the repository yet. Until the switch, the
agent's pull requests have you as their author, and code-owner review would block
each one that touches an owned path.

So, today, you can do steps 1 to 5 of `repository-settings.md` (labels, the off
switch, the `null-safety` check) and you can run this probe. Also do the first
section of that guide today,
[the Actions policy for `automerge.yml`](repository-settings.md#first-the-actions-policy-for-automergeyml-before-2026-12-02).
It has a date: 2026-12-02.

Do the code-owner steps on the day of the switch:

- Not before. They block your own pull requests.
- Not later. From the switch until those steps are done, GitHub does not stop the
  agent's identity from merging a change to the checking code. Its token can add a
  label, submit a review and merge a pull request, and the ruleset of the first
  repository asks for 0 approvals (read on 2026-11-09).

The probe also does not test these three things. Decide each one before the switch:

- **The automated review.** The `review` job is red on each pull request that the
  agent opens (see A5). While it is red, rail 6 of `automerge.yml` does not turn on
  auto-merge for that pull request. To let the review run, add
  `allowed_bots: "claude"` to the `with:` block of the action in
  `claude-code-review.yml`, in a pull request of its own. That input lets
  `claude[bot]` start the review, and no other bot.
- **Workflow files.** `AGENTS.md` needs a change under `.github/workflows/` for
  each new technique. The probe file for `path_kind=owned` is under `.github/`, not
  under `.github/workflows/`, so the probe does not show that the agent can push
  such a change. Think before you give the agent the Workflows permission: a
  workflow file on a branch runs with the secrets of the repository. Without the
  permission, you make each workflow change yourself. After the code-owner steps,
  your own pull request then needs a way out from
  [`repository-settings.md`](repository-settings.md#10-if-a-pull-request-is-stuck).
- **Commit signing.** See "Commit signing" in [The options](#the-options).

## Option B: your own GitHub App

Do this later, if you want the agent to hold only the permissions it needs.

1. **Register the App.** Profile picture > Settings > Developer settings > GitHub
   Apps > New GitHub App. Give it a name (34 characters at most, unique on GitHub)
   and a homepage URL (the repository address is acceptable). Under "Webhook",
   clear "Active". Under "Repository permissions" select Contents: Read and write,
   and Pull requests: Read and write. Select nothing else. Under "Where can this
   GitHub App be installed?" select "Only on this account". Create the App.
2. **Install it on this repository only.** On the App's page: Install App > your
   account > Only select repositories > this repository > Install.
3. **Make a private key.** On the App's page: Private keys > Generate a private
   key. A `.pem` file downloads. GitHub keeps only the public half.
4. **Store the two values.** Replace `CLIENT_ID` with the Client ID from the App's
   page. Replace `PATH_TO_KEY.pem` with the path of the downloaded file.

   ```bash
   gh variable set AGENT_APP_CLIENT_ID --repo "${REPO:?set REPO first}" --body "CLIENT_ID"
   gh secret set AGENT_APP_PRIVATE_KEY --repo "${REPO:?set REPO first}" < PATH_TO_KEY.pem
   gh variable get AGENT_APP_CLIENT_ID --repo "$REPO"
   gh secret list --repo "$REPO"
   ```

   Check: the third command prints the Client ID. The last command lists
   `AGENT_APP_PRIVATE_KEY`. Then delete the `.pem` file, or keep it in a password
   manager.
5. **Use it in the builder workflow.** The workflow makes a one-hour token and
   gives it to the action. The inputs `bot_name` and `bot_id` set the commit
   author. `APP_SLUG` is the name of the App in its address
   (`https://github.com/apps/APP_SLUG`). `APP_BOT_USER_ID` is the number that
   `gh api "users/APP_SLUG[bot]" --jq .id` prints.

   ```yaml
   - uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0
     id: agent-token
     with:
       client-id: ${{ vars.AGENT_APP_CLIENT_ID }}
       private-key: ${{ secrets.AGENT_APP_PRIVATE_KEY }}
       permission-contents: write
       permission-pull-requests: write
   - uses: anthropics/claude-code-action@4fa93a88de49bbef68b10eb15aabedf28ca0e1ed # v1.0.271
     with:
       claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
       github_token: ${{ steps.agent-token.outputs.token }}
       bot_name: "APP_SLUG[bot]"
       bot_id: "APP_BOT_USER_ID"
   ```

The two permissions are sufficient to push, to open pull requests, to label, to
review and to merge. The action's setup document names a third permission, Issues,
for an App of your own. If a run fails for a missing permission, select Issues:
Read and write for the App, and add `permission-issues: write` to the first step.

The probe workflow in this repository tests option A only. To test option B, add
the first step above to a copy of the probe and pass `github_token` to the action.
An App without the "Workflows" permission cannot push a change to a file under
`.github/workflows/`. That is a useful hard limit, and it also means that such an
agent cannot wire a new technique into the validator workflows by itself.

## Option C: a machine user

Use this only when the agent must run outside GitHub Actions.

1. **Create the account by hand.** The GitHub Terms of Service allow one free
   machine account for each person, and say that a human must create it. Sign out,
   open `https://github.com/signup`, and use an email address that is not on your
   own account.
2. **Turn on two-factor authentication** for that account: Settings > Password and
   authentication > Enable two-factor authentication. Keep the recovery codes in a
   password manager.
3. **Invite it.** Repository > Settings > Collaborators > Add people. Accept the
   invitation in the browser, signed in as the machine user.
4. **Make a classic token**, signed in as the machine user: Settings > Developer
   settings > Personal access tokens > Tokens (classic) > Generate new token
   (classic). Select the scope `public_repo` only, and an expiry date. A
   fine-grained token does not work for a collaborator on another person's
   repository.
5. **Check it.** Do not type the token on a command line: the shell saves each
   command line in its history file. Run this line alone. Then paste the token and
   press Enter. The token does not show.

   ```bash
   read -rs MACHINE_TOKEN
   ```

   Then run the check:

   ```bash
   GH_TOKEN="${MACHINE_TOKEN:?run the read line first}" gh api user --jq .login
   GH_TOKEN="${MACHINE_TOKEN:?run the read line first}" gh api "repos/$REPO" --jq '.permissions | "push=\(.push) admin=\(.admin)"'
   unset MACHINE_TOKEN
   ```

   Check: the first command prints the login of the machine user. The second
   command prints `push=true admin=false`.

Know the limits before you choose this. The machine user is a normal user with
write access. It can add any label, change the off-switch variable, and approve a
pull request that it did not open. Never name it in `CODEOWNERS`.

## Rules of use after the gate

1. **Unattended agents run in GitHub Actions.** They must never hold your GitHub
   credentials.
2. **A session that you start is you.** It is correct for work that you watch. Do
   not let a scheduled task work on this repository under your account when
   code-owner review is on: it can approve as you.
3. **Do not push to a branch of the agent** when "Require approval of the most
   recent reviewable push" is on. You become the last pusher, and your approval
   stops counting. Ask the agent to push again, then approve.
4. **To change the checking code yourself**, use the temporary rollback in
   [`repository-settings.md`](repository-settings.md#10-if-a-pull-request-is-stuck).
   A pull request that the agent's identity opens from your branch helps only if
   the agent also makes the last push to that branch. No workflow in the repository
   does that today.

## Not verified

- No command on this page was run against GitHub. The command blocks were run only
  against a local stub of `gh`. The probe workflow has not run. Only the shell
  logic of its `report` job and the parsing of its tool list were run, on sample
  data.
- That Claude writes the five commands of the probe exactly as the prompt gives
  them. The permission rules of the workflow are from the Claude Code
  documentation and the action source. If Claude writes a command in a different
  form, the probe fails and no pull request appears.
- That `gh pr create` works with the App token inside the action. The action's
  documents show only `gh pr comment`, `gh pr view` and `gh pr diff` with it.
- Which permissions the App token of a run has. The action's documents say
  Contents, Pull requests and Issues. The action sends no permission list unless
  the workflow sets `additional_permissions`, so Anthropic's service decides. It
  was not tested that the service gives `workflows: write` when a workflow asks.
- That the activity list of the repository names the pusher of a new branch within
  about 30 seconds. The `report` job reads it five times, then says UNKNOWN.
- That the `review` job fails on the probe pull request with exactly the text in
  A5. The text is from the action source.
- That GitHub applies the "Approve workflows to run" rule for `GITHUB_TOKEN` to
  each repository today. GitHub Docs describe it. The documentation source says
  that GitHub was still rolling it out on 2026-11-09.
- That option B works without the Issues permission.
- That an approving review from an App counts for a required approval. An App with
  the Pull requests permission can submit one. It does not matter for the
  code-owner rule (an App cannot be a code owner, and rail 8 of `automerge.yml`
  accepts only a `User`), but do not raise the required approval count in place of
  code owners.
- The exact account type string that the API returns for an App's account. The
  probe prints it.
- That the classic scope `public_repo` is enough to open pull requests and add
  labels. If a call is refused for its scope, make the token again with `repo`.

## Sources

- Claude Code documentation, read on 2026-11-10: scheduled tasks
  (`https://code.claude.com/docs/en/routines`), cloud sessions
  (`https://code.claude.com/docs/en/claude-code-on-the-web`), GitHub Actions
  (`https://code.claude.com/docs/en/github-actions`), permission rules
  (`https://code.claude.com/docs/en/permissions`) and authentication
  (`https://code.claude.com/docs/en/authentication`).
- `anthropics/claude-code-action` at commit `4fa93a88` (release v1.0.271):
  `action.yml`, `src/entrypoints/run.ts`, `src/github/token.ts`,
  `src/github/validation/actor.ts`, `src/github/validation/permissions.ts`,
  `src/modes/agent/index.ts`, `base-action/src/parse-sdk-options.ts`,
  `docs/setup.md`, `docs/security.md`, `docs/configuration.md` and `docs/faq.md`.
- GitHub Docs, read from the `github/docs` source at commit `d59e392`
  (2026-11-09): permission levels for a personal account repository; managing your
  personal access tokens; registering a GitHub App; reviewing and modifying
  installed GitHub Apps; installing a GitHub App from a third party; triggering a
  workflow from a workflow; managing GitHub Actions settings for a repository;
  manually running a workflow; using the activity view; about protected branches;
  about code owners. The permission data for GitHub Apps and the REST description
  from the same source.
- The `gh` CLI: built-in help of version 2.89.0, and the source of `gh api`,
  `gh workflow run`, `gh run watch` and `gh pr create`.
- GitHub Terms of Service, section B.3, "Account Requirements".
