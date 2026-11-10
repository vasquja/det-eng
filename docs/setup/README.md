# Setup guides

These guides are for the owner of this repository, or of a fork, who wants an AI
agent to research, test and write detections with little direction. You do not need
them to read the research or to run the validators: for that, see the
[`README.md`](../../README.md) of the repository.

Each guide is written for a person who has not done the task before. Each step has
a check. The guides were written from the documentation of GitHub and of the cloud
providers on 2026-11-09. Independent reviewers checked them against primary
sources on 2026-11-10. No command that changes a repository setting was run, and
no command was run against a real cloud account. The two workflows of these guides
have not run. Each guide has a "Not verified" list: read it.

How to read the commands:

- A word in capitals, such as `OWNER/REPO`, is a placeholder. Replace it with your
  value. `OWNER` is your GitHub user name or organization, and `REPO` is the name
  of the repository. For the first repository, `OWNER/REPO` is `vasquja/det-eng`.
- A word that starts with `$`, such as `$REPO`, is a shell variable. A block of
  the guide sets it. Do not replace it. `agent-identity.md` and
  `repository-settings.md` set `REPO` one time, and their later commands use
  `$REPO`.
- The blocks are for the shell `bash`.

## Before you start

The commands that start with `gh` use the GitHub CLI. Run them in a terminal on
your own computer. Do not run them in an agent session: the settings that they
change are the guard, and the agent must not hold the key.

Install the GitHub CLI. The page `https://cli.github.com` has it for each
operating system.

Then sign in. Run this command alone:

```bash
gh auth login
```

The command asks some questions. Select `GitHub.com`, and then
`Login with a web browser`. The command shows a one-time code and opens the
browser. Sign in there as the owner of the repository, and type the code.

Then check the account and your access. Replace `OWNER/REPO` with your
repository:

```bash
gh auth status
gh api repos/OWNER/REPO --jq .permissions.admin
```

Check: the first command shows the account of the repository owner. The second
command prints `true`. If it prints `false`, you are not signed in as the owner,
and the commands of these guides cannot work. If the output has the words
`Not Found`, the value that you put in the place of `OWNER/REPO` is wrong.

`repository-settings.md` also needs the tool `jq`.

The cloud pages are different. Their `aws`, `az` and `gcloud` commands run in the
browser shell of the provider. Each cloud page tells you which lines go to your
own terminal.

## The steps

| Step | Guide | What you get | Time |
|------|-------|--------------|------|
| 1 | [`agent-identity.md`](agent-identity.md) | Proof that the agent can open a pull request under an identity that is not yours. GitHub can then tell the agent from you. | 15 minutes |
| 2 | [`repository-settings.md`](repository-settings.md) | An Actions policy that keeps `automerge.yml` in operation after 2026-12-02. Labels, an off switch and one more required check. Then, on the day of the switch to GitHub Actions, a rule that only you can approve a change to the checking code. | 30 minutes, in two visits |
| 3 | [Decisions](#3-decisions) on this page | A licence, and a definition of 100 % coverage. | 10 minutes |
| 4 | [`cloud-sandbox.md`](cloud-sandbox.md), then [`cloud-aws.md`](cloud-aws.md), [`cloud-azure.md`](cloud-azure.md) or [`cloud-gcp.md`](cloud-gcp.md) | An empty cloud account in which you run the emulations by hand. Then, if you want it, a sign-in from GitHub Actions to that account with an identity that can only read. Optional. | 45 to 60 minutes for each provider |

## What you can do today, and what must wait

```text
Today                                 After the gate                  On the day of the switch
                                      (step A5 of agent-identity.md)  to GitHub Actions
-----                                 ------------------------------  ------------------------
1  agent-identity.md, A1 to A5        (step A5 is the gate)
2  repository-settings.md:            repository-settings.md:         repository-settings.md:
   the Actions policy (before         step 6, wait for the switch     steps 7 to 9
   2026-12-02), then steps 1 to 5
3  the two decisions
4  cloud-sandbox.md (optional; its
   federation needs the required
   reviewer of its step 2)
```

**One item has a date.** On 2026-12-02 GitHub enforces a default Actions policy.
It blocks the event `pull_request_target` in each public repository that has no
applicable event policy of its own. `automerge.yml` starts on that event. Do the
first section of `repository-settings.md` before that date:
[the Actions policy for `automerge.yml`](repository-settings.md#first-the-actions-policy-for-automergeyml-before-2026-12-02).
It is safe to do today.

**Two conditions have names.** The guides use these names with one meaning only:

- **The gate** is step A5 of [`agent-identity.md`](agent-identity.md). The
  identity probe says PASS, and you approved its pull request. The gate shows
  that an agent that runs in GitHub Actions has an identity that is not yours.
- **The switch to GitHub Actions** is the day from which the agent's daily pull
  requests come from GitHub Actions. The workflow that does this (the "builder
  workflow") is not in the repository at this time.

Steps 7 to 9 of `repository-settings.md` need the two conditions. The gate alone
is not sufficient. Those steps make your approval necessary for each change to
the checking code. GitHub does not let an author approve their own pull request.
While the agent opens its pull requests through your account, you are the author,
and such a pull request could never merge. Thus:

- Do not do steps 7 to 9 before the switch.
- Do them on the day of the switch, not later. From the switch until step 8 is
  on, GitHub does not stop the agent's identity from merging a change to the
  checking code.

**Step 4 has two parts.** The first part gives you an empty cloud account, in
which you run the emulations by hand. The second part (the federation) lets a
job of GitHub Actions sign in to that account. Know these facts before you do
the second part:

- The identity of that job can only read. It gets only what the one call of the
  smoke test needs. No workflow in the repository runs an emulation in the
  sandbox, and [`AGENTS.md`](../../AGENTS.md) keeps live emulations out of CI.
- The federation needs a required reviewer on the environment `sandbox`:
  [step 2 of "The GitHub side"](cloud-sandbox.md#2-make-yourself-a-required-reviewer)
  in `cloud-sandbox.md`. Each run of the smoke test then waits for your approval,
  and the smoke test stops if the environment has no reviewer.
- The reviewer rule has a limit while an agent session works through your GitHub
  account. Read "What the reviewer rule cannot do" in
  [The security rules](cloud-sandbox.md#the-security-rules).

## What is in the repository, and what only you can do

In the repository, ready to use:

| File | Purpose |
|------|---------|
| [`.github/CODEOWNERS`](../../.github/CODEOWNERS) | Names the owner of each path that is not content. It also names the owner of `docs/setup/`. It blocks nothing until step 8 of `repository-settings.md`. In a fork, replace the user name in it with yours (step 7 of `repository-settings.md`). |
| [`.github/workflows/agent-identity-probe.yml`](../../.github/workflows/agent-identity-probe.yml) | The test for step 1, and for steps 8 and 9 of `repository-settings.md`. It runs only when you start it. |
| [`.github/workflows/sandbox-smoke.yml`](../../.github/workflows/sandbox-smoke.yml) | The test for step 4. It runs only when you start it, and each run waits for your approval. It signs in to the cloud and makes one read-only call. |
| [`docs/setup/ruleset-main.json`](ruleset-main.json) | The ruleset `Main` of the first repository, as read on 2026-11-09. A fork creates its ruleset from it (step 1 of `repository-settings.md`). |

Not in the repository at this time:

- The builder workflow, which opens the agent's daily pull requests from GitHub
  Actions. The switch to GitHub Actions needs it.
- A workflow that runs the emulations in a cloud sandbox. Until such a workflow
  is designed and reviewed, the cloud identity of CI stays read-only.

These are for the owner to do, because they are the guard, or because they need a
payment card and a phone:

- Change a repository setting: the ruleset, the Actions policy, the environment
  and, while the repository has no collaborator, the variables. Labels are
  different: the agent's identity can also create, add and remove a label (step 3
  of `repository-settings.md`).
- Create a cloud account.
- Approve a run of the smoke test.
- Approve and merge a pull request that changes anything but content.
- Make the two decisions below.

## 3. Decisions

### The licence

A public repository without a licence file gives no person the right to use what
is in it. If the root of the repository has a `LICENSE` file, this decision is
made.

The recommendation, if it is not:

| Part | Licence | Why |
|------|---------|-----|
| Code, documents, research | Apache License 2.0, in `LICENSE` | Permissive, with a patent grant. The copies of the GCE kube-up and OpenShift audit policies under `detections/k8s/provider-policies/` have that licence already. The EKS, AKS and k3s copies in that folder have other licences: see [`SOURCES.md`](../../detections/k8s/provider-policies/SOURCES.md) there. |
| Sigma rules under `detections/sigma/` | Detection Rule License 1.1, in `detections/sigma/LICENSE.md` | The licence that SigmaHQ uses. A rule can then go upstream with no change of licence. It asks a user to keep the `author` field of the rule. |

Things to know before you decide:

- A licence that you give cannot be taken back for the copies that people already
  have.
- The other usual choice is the MIT License for all files. It is shorter and has
  no patent grant.
- This is not legal advice. If your employer has a claim on the work, ask before
  you publish.

### What 100 % coverage means

The coverage report ([`research/COVERAGE.md`](../../research/COVERAGE.md)) counts
the procedures that were researched. It does not say how much is not researched
yet. An agent that works alone needs that number, or "scale the coverage" has no
end and no sequence.

The recommendation: the set is each technique and sub-technique that the pinned
ATT&CK version (Enterprise v20) tags for the platforms that this repository
covers: Linux, Containers, IaaS and Identity Provider. A technique is covered when
each of its researched procedures is `Proven` in the coverage report. A technique
that the selection gate drops (NO-GO) is counted as decided, with its reason.

When you agree, or choose a different set, write the decision into
[`research/README.md`](../../research/README.md), so that the agent reads it.

## For a fork

A fork has the files of the first repository. GitHub Docs say that a fork has its
own settings and permissions. These guides thus expect that a new fork has no
ruleset, no `automerge` label, no variable, no environment, no secret and no
Claude GitHub App. That was not confirmed on a real fork. The steps for a fork
are safe in the two conditions: each one first shows what is there, and adds a
thing only if it is missing.

These are the places where a fork has more work, in the sequence of the guides:

1. **Enable GitHub Actions.** GitHub Actions is off in a new fork. Open the
   **Actions** tab of your fork and select **I understand my workflows, go ahead
   and enable them**. Until you do, no workflow runs in the fork, and no
   `gh workflow run` command of these guides works.
2. **Install the Claude GitHub App, and add the secret.** The App and the secret
   `CLAUDE_CODE_OAUTH_TOKEN` are not in a fork. Steps
   [A1](agent-identity.md#a1-check-that-the-claude-github-app-is-installed-on-this-repository)
   and [A2](agent-identity.md#a2-check-the-claude-token-secret) of
   `agent-identity.md` show how to add them.
3. **Create the Actions policy for `automerge.yml`.** Do
   [the first section](repository-settings.md#first-the-actions-policy-for-automergeyml-before-2026-12-02)
   of `repository-settings.md` in a fork also, before you use `automerge.yml`
   there.
4. **Create the ruleset and the label `automerge`.** The later steps of the
   guides create the other labels, the variable and the environment. Create the
   ruleset first, from the template [`ruleset-main.json`](ruleset-main.json): see
   [Fork only](repository-settings.md#fork-only-create-the-ruleset-and-the-automerge-label)
   in step 1 of `repository-settings.md`. That part also creates the label
   `automerge`. Steps 2, 5, 8 and 9 of that guide need the ruleset.
5. **Put your name into `CODEOWNERS`.** The file names the owner of the first
   repository, who has no write access to your fork. Step 7 of
   `repository-settings.md` tells you how to replace the name.

Two more things to know:

- The check values in the guides (IDs, names of required checks) are those of the
  first repository, and are marked as such.
- GitHub has two formats for the subject of an OIDC token. A repository that was
  created after 2026-07-15 has the format with IDs. Do not assume the format of
  your fork: [`cloud-sandbox.md`](cloud-sandbox.md#3-find-your-exact-subject-string)
  shows how to read the subject from a run.

## If a guide is wrong

The providers change their pages and their defaults often. If a step does not
agree with what you see, stop: do not continue with a guess. Open an issue with
the step number and what you saw, and correct the guide in a pull request.
