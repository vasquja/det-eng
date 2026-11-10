# Repository settings: labels, off switch, required checks, code owners

This guide is step 2 of [`docs/setup/`](README.md). It changes settings that only
the repository owner can change. Run every command in **your own terminal**, signed
in to the `gh` CLI as the owner. Do not run it in an agent session: these settings
are the guard, so the guarded party must not hold the key.

Independent reviewers checked this page against primary sources on 2026-11-10: the
GitHub documentation source, the GitHub REST description, the `gh` CLI (built-in
help and source) and the files of this repository. Only commands that read were run
against `vasquja/det-eng`. No command that changes a repository setting was run.
Each such command has a check and a rollback. Read the [Not verified](#not-verified)
list.

## What you can do today, and what must wait

| Steps | What | When |
|-------|------|------|
| [First](#first-the-actions-policy-for-automergeyml-before-2026-12-02) | An Actions policy that keeps `automerge.yml` in operation | Before 2026-12-02. |
| 1 to 5 | Pre-flight (in a fork: also the ruleset and the `automerge` label), rollback file, labels, off switch, `null-safety` as a required check | Today. They cannot block a pull request that is correct. |
| 6 | Stop | Until you passed the gate and made the switch to GitHub Actions. |
| 7 to 9 | `CODEOWNERS` check, code-owner review, last-push approval | On the day of the switch to GitHub Actions. Not before, and not later. |
| 10 | Ways out if a pull request is stuck | When you need it. |

Two terms come from [`agent-identity.md`](agent-identity.md):

- **The gate** is step A5 of that guide. The identity probe says PASS, and you
  approved its pull request.
- **The switch to GitHub Actions** is the day from which the agent's daily pull
  requests come from GitHub Actions, under the agent's own identity. The workflow
  that does this (the "builder workflow") is not in the repository at this time.

**Not before: the trap.** With "Require review from Code Owners" on, a pull request
that touches an owned path needs an approval from the code owner. GitHub does not
let an author approve their own pull request, and this ruleset has no bypass list.
If your account is the only code owner and is also the author, such a pull request
can never merge. While the agent opens its pull requests through your account, you
are the author.

**Not later.** From the switch, the agent works with a token of a GitHub App that
can write Contents and Pull requests. With that token it can push a branch, open a
pull request, add and remove labels, submit a review, and merge each pull request
that the ruleset permits. The ruleset asks for 0 approvals. Until step 8 is on,
GitHub does not stop the agent's identity from merging a change to the checking
code.

## Before you start

You need `gh` (the GitHub CLI), `jq`, and `bash` or `zsh`. If you do not have `gh`,
install it from `https://cli.github.com`. If `gh auth status` shows no account, run
`gh auth login` and sign in through the browser as the owner.

In the second line, replace `OWNER/REPO` with your repository. For the first
repository it is `vasquja/det-eng`.

```bash
gh auth status
REPO=OWNER/REPO
BODY='{name, target, enforcement, bypass_actors, conditions, rules} | with_entries(select(.value != null))'
RULESET_ID=$(gh api "repos/$REPO/rulesets?includes_parents=false" --jq '.[] | select(.name == "Main") | .id') || RULESET_ID=
echo "REPO=$REPO RULESET_ID=$RULESET_ID"
```

Check: the last line prints your repository, then `RULESET_ID=` and one number. For
the first repository the number is `24626383`. In a new fork the number is missing.
That is normal until the fork part of step 1.

This is the **session block**. It changes nothing. Run it again at the start of
each visit and in each new terminal. The later steps use `$REPO`, `$BODY` and
`$RULESET_ID`. Where an empty value could change the wrong thing, they write
`${REPO:?}`, `${BODY:?}` and `${RULESET_ID:?}`. If the variable is empty, the
command stops with a message such as `RULESET_ID: parameter null or not set`, and
changes nothing. Then run the session block again.

A word in capitals in a command, such as `PR_NUMBER`, is a placeholder. The text
near the command says what to put in its place.

## First: the Actions policy for `automerge.yml`, before 2026-12-02

This section was built from the GitHub documentation source and the REST API
description. It was not run.

GitHub has a default Actions policy for public repositories. It blocks the event
`pull_request_target` in each public repository that has no applicable event policy
of its own. At this time the default policy is in "evaluate" mode: the runs
continue, and the page Policy insights shows the runs that the policy would block.
On 2026-12-02 GitHub enforces it.

[`automerge.yml`](../../.github/workflows/automerge.yml) starts on two events,
`pull_request_target` and `workflow_run`. After that date, without a policy of your
own, each run that a label or a push starts fails with an error of the form
`Event 'pull_request_target' is not allowed to trigger Actions workflows`. The
workflow then acts only when a CI workflow ends. It can miss a removed `automerge`
label or a new push.

An Actions policy is a rule of the repository that says which events can start a
workflow. The policy below permits the two events for the file `automerge.yml`
only. That file reads data from the API. It does not check out or run code from a
pull request.

Web: repository > Settings > Actions > Policies > create a policy > enforcement
"Active" > target the workflow `.github/workflows/automerge.yml` > "Restrict
events" > permit `pull_request_target` and `workflow_run` only.

Or with the CLI:

```bash
if gh api "repos/$REPO/actions/policies" --jq '.policies[].name' | grep -qxF 'automerge: pull_request_target and workflow_run'; then
  echo "The policy exists already. Nothing was created."
else
  gh api --method POST "repos/$REPO/actions/policies" --silent --input - <<'EOF'
{
  "name": "automerge: pull_request_target and workflow_run",
  "enforcement": "active",
  "conditions": {
    "workflow_path": {"include": [".github/workflows/automerge.yml"], "exclude": []}
  },
  "rules": [
    {"type": "restrict_action_events", "parameters": {"allowed_events": ["pull_request_target", "workflow_run"]}}
  ]
}
EOF
fi
gh api "repos/$REPO/actions/policies" --jq '.policies[] | "\(.id)\t\(.name)\t\(.enforcement)\t\(.source_type)"'
POLICY_ID=$(gh api "repos/$REPO/actions/policies" --jq '.policies[] | select(.name == "automerge: pull_request_target and workflow_run") | .id') || POLICY_ID=
gh api "repos/$REPO/actions/policies/${POLICY_ID:?}" --jq '{enforcement, conditions, rules}'
```

Check:

- The list has a line with the name of the policy, `active` and `Repository`.
- The last command shows the path of `automerge.yml` and the two events.
- In the browser, open Settings > Actions > Policy insights. Wait for the next
  event of a pull request (a push, or a label that you add and remove). After it,
  the page must show no run of `automerge.yml` that the event `pull_request_target`
  would block. Do this check before 2026-12-02.

If Policy insights still shows such a run, GitHub does not count this policy. Then
open the policy on the web page. Remove the workflow target, so that the policy is
for all workflows. Permit each event that the workflows of this repository use:
`push`, `pull_request`, `pull_request_review`, `pull_request_target`, `schedule`,
`workflow_dispatch` and `workflow_run`. Do the check again.

This second form permits `pull_request_target` for each workflow file. That is
wider than the default of GitHub. Use it only if the check fails. `automerge.yml`
must stay the only file with that trigger. In a clone of the repository:

```bash
grep -lE '^[[:space:]]+pull_request_target:' .github/workflows/*.yml
```

Check: the command prints `.github/workflows/automerge.yml` and nothing else.
Refuse each change that adds that trigger to a different workflow file.

Rollback: `gh api --method DELETE "repos/$REPO/actions/policies/${POLICY_ID:?}"`.
In a new terminal, first run the line of the block that starts with `POLICY_ID=`.

Notes:

- Actions policies are available on each public repository, and on a private
  repository with GitHub Team or Enterprise. The default policy is for public
  repositories only.
- **In a fork**, do this section also. GitHub gives the date only for a repository
  that had the default policy before the feature became generally available. This
  guide does not know what GitHub does in a newer repository. Create the policy
  before you use `automerge.yml` there.
- The optional policy of
  [step 5 in `cloud-sandbox.md`](cloud-sandbox.md#5-optional-an-actions-policy-for-the-smoke-test)
  is a separate policy, for `.github/workflows/sandbox-smoke.yml` only. Do not
  rely on it to permit `pull_request_target` for `automerge.yml`. This policy
  does not replace it. The two have different targets.

## 1. Pre-flight

```bash
gh api "repos/$REPO" --jq '{owner: .owner.login, owner_type: .owner.type, admin: .permissions.admin, visibility: .visibility, allow_auto_merge: .allow_auto_merge}'
gh api "repos/$REPO/rulesets?includes_parents=false" --jq '.[] | "\(.id)\t\(.name)\t\(.enforcement)"'
gh api "repos/$REPO/branches/main/protection"
gh api "repos/$REPO/actions/permissions/workflow"
```

Check:

- The first command prints `"admin": true`. If not, you are not signed in as the
  owner.
- The second command prints one row: an id, `Main`, `active`. The id is the value
  of `$RULESET_ID`. In a fork it prints nothing: do the fork part below.
- The third command fails with `Branch not protected (HTTP 404)`. That is correct:
  no classic branch protection rule lies on top of the ruleset.
- The last command prints `"can_approve_pull_request_reviews": false`. If it is
  `true`, clear the box at Settings > Actions > General > Workflow permissions >
  "Allow GitHub Actions to create and approve pull requests".

Rulesets and code owners are available on a public repository with GitHub Free. A
private repository on a Free plan has neither.

### Fork only: create the ruleset and the `automerge` label

A fork has the files of the first repository. It does not have its settings. This
block was not run.

The file [`ruleset-main.json`](ruleset-main.json) is the ruleset `Main` of the
first repository, as read on 2026-11-09 and not changed on 2026-11-10: no deletion
and no force push of `main`, squash merge through a pull request, 11 required
checks, 0 approvals, code-owner review off, no bypass. The block creates a ruleset
only if the repository has none.

```bash
mkdir -p ~/ruleset-backup && cd ~/ruleset-backup
if [ "$(gh api "repos/$REPO/rulesets?includes_parents=false" --jq length)" = 0 ]; then
  gh api "repos/$REPO/contents/docs/setup/ruleset-main.json" -H "Accept: application/vnd.github.raw+json" > ruleset-main.json
  jq -e '.name == "Main" and .enforcement == "active" and .bypass_actors == [] and (.rules | length) == 5' ruleset-main.json > /dev/null && gh api --method POST "repos/$REPO/rulesets" --input ruleset-main.json --jq '"\(.id)\t\(.name)\t\(.enforcement)"'
else
  echo "The repository has a ruleset already, or the list could not be read. Nothing was created."
fi
gh label create automerge --color 0E8A16 --description "Opt in to auto-merge once CI is green and branch protection is satisfied" --repo "${REPO:?}"
```

Check: the block prints an id, `Main` and `active`. Run the session block again:
it now prints that id as `RULESET_ID`. If the label exists already, the last
command says so and changes nothing.

Rollback: delete the ruleset in the browser (Settings > Rules > Rulesets > Main),
and run `gh label delete automerge --repo "${REPO:?}" --yes`.

Notes for a fork:

- The 11 required checks are jobs of the workflows in `.github/workflows/`. Each
  pull request waits until they report. They report only when GitHub Actions is on
  in the fork: see "In a fork" in [`agent-identity.md`](agent-identity.md).
- The number `15368` in the file is the id of the GitHub Actions app. Step 5 prints
  that id for your repository.
- `automerge.yml` needs more settings, for example "Allow auto-merge"
  (`allow_auto_merge` in the first command of this step). The comment
  "Requirements" at the top of that file lists them.

## 2. Save the rollback file

A Free personal repository has no "Evaluate" mode and no ruleset history. The file
that you save here is the only rollback.

```bash
mkdir -p ~/ruleset-backup && cd ~/ruleset-backup
gh api "repos/$REPO/rulesets/${RULESET_ID:?}" > ruleset.raw.json
[ -s ruleset.rollback.json ] && echo "ruleset.rollback.json exists already. It was not changed." || { jq -e "${BODY:?} | select((.rules | length) > 0)" ruleset.raw.json > ruleset.rollback.tmp && mv ruleset.rollback.tmp ruleset.rollback.json; }
[ -s ruleset.rollback.json ] && cp ruleset.rollback.json "ruleset.rollback.$(date +%Y%m%d-%H%M%S).json"
jq -e '(.rules | length) > 0 and .bypass_actors == [] and .enforcement == "active"' ruleset.rollback.json
jq -c '[.rules[].type]' ruleset.rollback.json
```

Check: the last two lines print `true` and then, for the first repository,
`["deletion","non_fast_forward","required_status_checks","pull_request","required_linear_history"]`.

If the check does not print `true`, run `cat ruleset.raw.json`:

- A `Not Found` message means that `$REPO` or `$RULESET_ID` is wrong. Run the
  session block again. Then delete `ruleset.rollback.json` and do this step again.
- If the ruleset is there and has no field `bypass_actors`, you are not signed in
  as the owner. GitHub returns that field only to a person with write access to
  the ruleset.
- If `jq .bypass_actors ruleset.rollback.json` prints an entry, the ruleset has a
  bypass list. An actor on that list can merge without the rules. Remove the entry
  (Settings > Rules > Rulesets > Main > Bypass list). Then delete
  `ruleset.rollback.json` and do this step again.

Keep `~/ruleset-backup` outside the repository. Never edit `ruleset.rollback.json`.
`$BODY` keeps the six fields that the update call accepts. Every change below sends
the complete ruleset, because the API reference does not say if a partial rule list
replaces or merges.

Each later step saves the ruleset to a `before-*.json` file, then makes and sends
an `after-*.json` file. Run the block of a step one time. A second run writes the
changed ruleset into the `before` file of that step. This step does not write
`ruleset.rollback.json` a second time.

**Before each rollback in this guide, stop auto-merge.** A rollback switches a rule
off. GitHub then merges each open pull request that has auto-merge on, as soon as
its other requirements are met.

```bash
for n in $(gh pr list --repo "${REPO:?}" --state open --limit 200 --json number,autoMergeRequest --jq '.[] | select(.autoMergeRequest != null) | .number'); do gh pr merge "$n" --repo "${REPO:?}" --disable-auto; done
gh pr list --repo "${REPO:?}" --state open --limit 200 --json number,title,autoMergeRequest --jq '.[] | select(.autoMergeRequest != null) | "\(.number)\t\(.title)"'
```

Check: the last command prints nothing.

To go back to the ruleset of this step at any time:

```bash
cd ~/ruleset-backup
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input ruleset.rollback.json > /dev/null
[ -s ruleset.rollback.json ] && diff <(jq -S . ruleset.rollback.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

Check: the last line prints `MATCH`. Each rollback below has the same lines with
its own file. If a rollback does not print `MATCH`, read the difference that `diff`
shows. A different sequence of the same entries is not a fault.

## 3. Create the labels

No workflow reads these labels yet. They are for planned changes (a human veto, an
override of the ratchet, the vet backlog). The label `automerge` exists already in
the first repository. In a fork, step 1 creates it. You can do this step now or
with the change that first uses the labels.

```bash
gh label create hold --color B60205 --description "Do not merge. Only the owner removes this label." --repo "${REPO:?}"
gh label create ratchet-override --color D93F0B --description "The owner accepts the sufficiency-ratchet failure on this pull request." --repo "${REPO:?}"
gh label create infra --color 5319E7 --description "Changes checking code, workflows or agent policy. Needs the owner's approval." --repo "${REPO:?}"
gh label create go --color 2DA44E --description "Novelty vet result: GO. The technique may be built." --repo "${REPO:?}"
gh label create no-go --color 6E7781 --description "Novelty vet result: NO-GO. Do not build this technique." --repo "${REPO:?}"
```

Check: `gh api "repos/$REPO/labels?per_page=100" --jq '.[].name'` lists the five
names. Rollback: `gh label delete NAME --repo "${REPO:?}" --yes`, where `NAME` is the
name of the label.

**A label does not prove that you acted.** Each collaborator on a personal
repository can add and remove labels. So can an App with the "Pull requests"
permission, and the agent's identity has that permission. The GitHub documentation
shows no setting that keeps a label for the owner. Thus:

- `hold` is a request, not a lock. The agent's identity can remove it.
- `ratchet-override` and `go` stay on a pull request when a commit is pushed after
  you added them. The label then covers a commit that you did not see.

A workflow that treats a label as your decision must do two checks itself: who
made the last `labeled` or `unlabeled` event, and whether that event is newer than
the last push. No workflow in the repository does this at this time. You can read
the two facts by hand before you merge:

```bash
gh api "repos/$REPO/issues/PR_NUMBER/timeline" --paginate --jq '.[] | select((.event == "labeled" or .event == "unlabeled") and .label.name == "LABEL_NAME") | "\(.event)\t\(.actor.login)\t\(.actor.type)\t\(.created_at)"' | tail -n 1
gh api "repos/$REPO/activity?ref=refs/heads/BRANCH&per_page=1" --jq '.[0] | "\(.activity_type)\t\(.actor.login)\t\(.timestamp)"'
```

`PR_NUMBER` is the number of the pull request, `LABEL_NAME` is the label, and
`BRANCH` is the branch of the pull request. The first command prints the last
label event and the account that made it. The second prints the last push to the
branch.

## 4. Create the off switch

One repository variable that stops the automation. No workflow reads it yet; the
planned workflows will do their work only when its value is exactly `on`.

```bash
gh variable set AGENT_AUTOMATION --body on --repo "${REPO:?}"
gh variable get AGENT_AUTOMATION --repo "${REPO:?}"
```

Check: the last command prints `on`.

To stop the automation: `gh variable set AGENT_AUTOMATION --body off --repo "${REPO:?}"`.
You can also change it in the browser, also on a phone: Settings > Secrets and
variables > Actions > Variables.

Rollback: `gh variable delete AGENT_AUTOMATION --repo "${REPO:?}"`. After it,
`gh variable get AGENT_AUTOMATION --repo "${REPO:?}"` fails, because the variable is
gone.

Know the limits:

- A variable that is not set reads as an empty string. The workflows must test for
  the exact value `on`, so that a deleted or misspelt variable means "off".
- The switch must not be an `if:` on a job that is a required status check. A job
  that is skipped counts as passed.
- A collaborator can change repository variables. An App without the "Variables"
  permission cannot, and neither can the built-in `GITHUB_TOKEN`.
- A change of the variable starts no workflow run. It does not stop an auto-merge
  that is already enabled on a pull request. For that:
  `gh pr merge PR_NUMBER --repo "${REPO:?}" --disable-auto`, where `PR_NUMBER` is the
  number of the pull request.

## 5. Make `null-safety` a required check

GitHub's auto-merge waits only for required checks. Until `null-safety` is
required, a pull request can merge while that check is red. The check runs on each
pull request (its workflow has no path filter), so it is safe to require.

First look at the check on `main`:

```bash
gh api "repos/$REPO/commits/main/check-runs?per_page=100" --jq '.check_runs[] | select(.name == "null-safety") | "\(.name) \(.conclusion) app=\(.app.id) \(.app.slug)"' | sort -u
```

Check: it prints one line, `null-safety success app=15368 github-actions`. If it
prints nothing, stop: the check did not run on `main`. If it prints a different
app id, put that id in place of `15368` in the third line of the next block.

```bash
cd ~/ruleset-backup
gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq "${BODY:?}" > before-null-safety.json
jq '(.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks) |= (if any(.[]; .context == "null-safety") then . else . + [{"context": "null-safety", "integration_id": 15368}] end)' before-null-safety.json > after-null-safety.json
diff <(jq -S . before-null-safety.json) <(jq -S . after-null-safety.json)
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input after-null-safety.json > /dev/null
[ -s after-null-safety.json ] && diff <(jq -S . after-null-safety.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

Check:

- The first `diff` shows one added entry (`null-safety`) and nothing else.
- The last line prints `MATCH`.

Rollback, only before step 8 (first stop auto-merge, see step 2). The file is the
ruleset as it was before this step. After step 8 it would also switch code-owner
review and last-push approval off.

```bash
cd ~/ruleset-backup
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input before-null-safety.json > /dev/null
[ -s before-null-safety.json ] && diff <(jq -S . before-null-safety.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

After step 8, remove only the entry:

```bash
cd ~/ruleset-backup
gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq "${BODY:?}" > before-drop-null-safety.json
jq '(.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks) |= map(select(.context != "null-safety"))' before-drop-null-safety.json > after-drop-null-safety.json
diff <(jq -S . before-drop-null-safety.json) <(jq -S . after-drop-null-safety.json)
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input after-drop-null-safety.json > /dev/null
[ -s after-drop-null-safety.json ] && diff <(jq -S . after-drop-null-safety.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

Check: the first `diff` shows one removed entry (`null-safety`) and nothing else.
The last line prints `MATCH`.

Notes. The name of a required check is the **job** name, not the workflow name.
Keep `integration_id`: without it, any account with write access can post a status
with that name. Never require a check from a workflow that a path filter can skip:
the check stays "Pending" and the pull request waits without end.

Optional. The four heavy validators (`validate-k8s`, `validate-cloud`,
`validate-staticpod`, `validate-apiserver`) each depend on a `changes-*` job. If
that job fails, the validator is skipped, and a skipped job counts as passed. The
`changes-*` jobs are not required checks today. The automerge workflow holds such a
pull request, but a merge by hand is not blocked. To close this, add
`changes-k8s`, `changes-cloud`, `changes-staticpod` and `changes-apiserver` with
the same `jq` line.

## 6. Stop: wait for the gate and for the switch to GitHub Actions

**Do not go on until both statements are true.**

1. You passed the gate: the probe in [`agent-identity.md`](agent-identity.md) says
   PASS, and you approved its pull request.
2. You made the switch to GitHub Actions: the agent's pull requests in its daily
   work come from GitHub Actions under the agent's identity, not from a cloud
   session under your account.

Do steps 7 to 9 on the day of the switch. Between the switch and step 8, GitHub
does not stop the agent's identity from merging a change to an owned path. Keep
that time short.

The guides under `docs/setup/` hold the commands that you paste as administrator.
Until step 8 is on, GitHub does not ask for your approval of a change to them. So
look at their history before you paste a command on a later visit:

```bash
gh api "repos/$REPO/commits?path=docs/setup&per_page=10" --jq '.[] | "\(.commit.committer.date)\t\(.sha[0:7])\t\(.author.login // "no account")\t\(.commit.message | split("\n")[0])"'
gh api "repos/$REPO/commits?path=.github/CODEOWNERS&per_page=10" --jq '.[] | "\(.commit.committer.date)\t\(.sha[0:7])\t\(.author.login // "no account")\t\(.commit.message | split("\n")[0])"'
gh pr list --repo "${REPO:?}" --author "@me" --state open
```

Check:

- You know each commit that the first two commands list after the date of your
  last visit. If not, read that commit on GitHub before you go on.
- The last command lists your own open pull requests. Merge or close each one
  before step 8. After step 8, one that touches an owned path cannot merge.

## 7. Check the `CODEOWNERS` file

The file [`.github/CODEOWNERS`](../../.github/CODEOWNERS) is in the repository. It
names the owner for each path that is not content: workflows, Python, emulations,
budgets, the benign corpus, audit policies, agent instructions, and the guides
under `docs/setup/`. It leaves rules, cases, fixtures, TRRs and other documents
without an owner. It follows rail 8 in
[`automerge.yml`](../../.github/workflows/automerge.yml). The comment at its top
says where the two differ. While the ruleset setting is off, the file blocks
nothing.

**In a fork:** replace each `@vasquja` in the file with your own login, through a
pull request. The upstream owner has no write access to your fork, and a name
without write access gives no owner at all.

```bash
gh api "repos/$REPO/codeowners/errors" --jq .errors
gh api "repos/$REPO/contents/.github/CODEOWNERS" -H "Accept: application/vnd.github.raw+json" | grep -v '^#' | grep -o '@[A-Za-z0-9_/-]*' | sort | uniq -c
```

Check:

- The first command prints `[]`. If it prints `Not Found`, the file is not on the
  default branch: merge the pull request that adds it.
- The second command prints one line: a count, then `@` and your login.
- On GitHub, open a workflow file and hold the pointer on the shield icon: it
  names you. `README.md` has no shield.

A wrong name fails open. A name that GitHub does not know, or a line with a syntax
error, gives no owner and no error at merge time. Run the check after each change
to the file.

## 8. Turn on "Require review from Code Owners", and test it

From this point GitHub refuses to merge a change to an owned path without your
approval, on each merge path. The required approval count stays 0, so a pull
request that touches content only needs no review.

```bash
cd ~/ruleset-backup
gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq "${BODY:?}" > before-codeowner.json
jq -e '.bypass_actors == []' before-codeowner.json || echo "STOP: the ruleset has a bypass list. Remove it first (step 2)."
jq '(.rules[] | select(.type == "pull_request") | .parameters) |= (.required_approving_review_count = 0 | .require_code_owner_review = true)' before-codeowner.json > after-codeowner.json
diff <(jq -S . before-codeowner.json) <(jq -S . after-codeowner.json)
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input after-codeowner.json > /dev/null
[ -s after-codeowner.json ] && diff <(jq -S . after-codeowner.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

Check: the second line prints `true` and no `STOP`. If it prints `STOP`, do not
continue: an actor on the bypass list could merge a change to an owned path
without your approval. The first `diff` shows one changed line
(`require_code_owner_review` from `false` to `true`). The last line prints `MATCH`.

Now test both directions with the probe workflow. It opens the pull requests as the
agent. Start the two runs:

```bash
gh workflow run agent-identity-probe.yml --repo "${REPO:?}" -f path_kind=owned
gh workflow run agent-identity-probe.yml --repo "${REPO:?}" -f path_kind=content
sleep 15
gh run list --repo "${REPO:?}" --workflow agent-identity-probe.yml --limit 2 --json databaseId,status,conclusion --jq '.[] | "\(.databaseId)\t\(.status)\t\(.conclusion)"'
```

The first run makes the pull request T1 (a file under `.github/`). The second makes
T2 (a file under `docs/probe/`). The second run waits for the first by itself. The
last command prints one line for each of the two newest runs: the ID of the run,
its status and its result. Repeat the last command until the two lines show
`completed`. The result must be `success`. With `failure`, the summary of that run
does not say PASS, and UNKNOWN is not a pass. Read the summary as
[step A4](agent-identity.md#a4-run-the-identity-probe) of `agent-identity.md`
shows. Close the pull request of that run, and start that run again.

Then wait some minutes for the checks of the two pull requests, and read their
state:

```bash
gh pr list --repo "${REPO:?}" --state open --search "Identity probe in:title" --json number,title,reviewDecision,mergeStateStatus --jq '.[] | "\(.number)\t\(.title)\treview=\(.reviewDecision)\tmerge=\(.mergeStateStatus)"'
```

The title of T1 has `(owned)`. The title of T2 has `(content)`. The first column
is the number of the pull request. If the command does not list the two pull
requests, the two runs are not complete. Wait, then run the `gh run list` line
and this command again. If a line shows `merge=UNKNOWN`, run the command again.
Expected results:

- **T1:** `review=REVIEW_REQUIRED` and `merge=BLOCKED`. Then approve it with
  `gh pr review PR_NUMBER --repo "${REPO:?}" --approve`, where `PR_NUMBER` is the
  number of T1. After that: `review=APPROVED`, and `merge=CLEAN` or
  `merge=UNSTABLE` when the required checks are green.
- **T2:** `review=` with no value, and `merge=CLEAN` or `merge=UNSTABLE` when the
  required checks are green, with no approval.

`UNSTABLE` means that the pull request can merge and that a check that is not
required is red. Expect it: the `review` job of `claude-code-review` fails on a
pull request that a bot opened, until that workflow names the bot in
`allowed_bots` (see [`agent-identity.md`](agent-identity.md)). The test fails only
if a pull request stays `BLOCKED` after the required checks are green.

Close both pull requests after the test. Do not merge them. Run this line for
each number: `gh pr close PR_NUMBER --repo "${REPO:?}" --delete-branch`.

The expected results follow from the documented wording. The documentation gives no
example with a count of 0. If T2 asks for a review, roll back and keep the result.

Rollback (first stop auto-merge, see step 2). This rollback also undoes step 9,
if you did it:

```bash
cd ~/ruleset-backup
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input before-codeowner.json > /dev/null
[ -s before-codeowner.json ] && diff <(jq -S . before-codeowner.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

From now on, a pull request that **you** open and that touches an owned path cannot
merge. Let the agent's identity open it, or use step 10. `gh pr merge --admin` does
not help: the ruleset has no bypass.

A change under `.github/workflows/` is a special case. The agent's identity can
push it only if its token has the Workflows permission. See "Workflow files" in
[`agent-identity.md`](agent-identity.md). Without that permission, you make each
workflow change yourself, and each one needs way 1 of step 10.

## 9. Turn on "Require approval of the most recent reviewable push", and test it

This setting is meant to stop a commit that is pushed after your approval. The
documentation does not say what it does when the required approval count is 0. Read
literally, it could ask for an approval on each pull request, which would end
content-only auto-merge. So it is a separate change with its own test.

```bash
cd ~/ruleset-backup
gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq "${BODY:?}" > before-lastpush.json
jq '(.rules[] | select(.type == "pull_request") | .parameters) |= (.require_last_push_approval = true)' before-lastpush.json > after-lastpush.json
diff <(jq -S . before-lastpush.json) <(jq -S . after-lastpush.json)
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input after-lastpush.json > /dev/null
[ -s after-lastpush.json ] && diff <(jq -S . after-lastpush.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

Check: the first `diff` shows one changed line (`require_last_push_approval` from
`false` to `true`). The last line prints `MATCH`.

Repeat T1 and T2 from step 8 with two new probe runs.

- **T2 PASS:** `review=` with no value, and `merge=CLEAN` or `merge=UNSTABLE` with
  no approval when the required checks are green.
- **T1 PASS:** after your approval, `review=APPROVED`, and `merge=CLEAN` or
  `merge=UNSTABLE` when the required checks are green. Your approval then counts
  for a push of the agent.
- **FAIL:** T1 or T2 stays `BLOCKED`, or T2 asks for a review. Then undo this
  setting and use the documented alternative. It removes an approval when new
  commits arrive, and it cannot make a new approval necessary:

```bash
cd ~/ruleset-backup
jq '(.rules[] | select(.type == "pull_request") | .parameters) |= (.require_last_push_approval = false | .dismiss_stale_reviews_on_push = true)' before-lastpush.json > after-dismiss-stale.json
diff <(jq -S . before-lastpush.json) <(jq -S . after-dismiss-stale.json)
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input after-dismiss-stale.json > /dev/null
[ -s after-dismiss-stale.json ] && diff <(jq -S . after-dismiss-stale.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

Check: the first `diff` shows one changed line (`dismiss_stale_reviews_on_push`).
The last line prints `MATCH`.

Close the probe pull requests as in step 8.

Rollback of this step only (first stop auto-merge, see step 2):

```bash
cd ~/ruleset-backup
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input before-lastpush.json > /dev/null
[ -s before-lastpush.json ] && diff <(jq -S . before-lastpush.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

With this setting on, do not push to a branch of the agent. You become the last
pusher, your approval stops counting, and the agent, as the author, cannot approve.
Ask the agent to push again, then approve. The button "Update branch" makes a
commit in your name: do not use it on a pull request of the agent.

## 10. If a pull request is stuck

This step is for the time after step 8. The usual cause: a pull request that
**you** opened touches an owned path. Each way out needs only your admin access. A
ruleset cannot take that away.

Use **one** way. Do not paste more than one. The way with the least damage is
first. While a rule is off, GitHub does not stop a merge that the rule would stop.
That includes a merge by the agent's identity. Keep that time short. To merge your
pull request, use the browser, or `gh pr merge PR_NUMBER --repo "${REPO:?}" --squash`.

**Before each way:** save the ruleset as it is, and stop auto-merge.

```bash
cd ~/ruleset-backup
gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq "${BODY:?}" > now.json
jq -e '.enforcement == "active" and any(.rules[]; .type == "pull_request" and .parameters.require_code_owner_review == true)' now.json && cp now.json before-stuck.json
for n in $(gh pr list --repo "${REPO:?}" --state open --limit 200 --json number,autoMergeRequest --jq '.[] | select(.autoMergeRequest != null) | .number'); do gh pr merge "$n" --repo "${REPO:?}" --disable-auto; done
gh pr list --repo "${REPO:?}" --state open --limit 200 --json number,title,autoMergeRequest --jq '.[] | select(.autoMergeRequest != null) | "\(.number)\t\(.title)"'
```

Check:

- The third line prints `true`. The file `before-stuck.json` then holds the
  ruleset that you put back after the merge. If it prints `false`, code-owner
  review is off already, and the file was not written. If a way out is open from
  an earlier visit, run only the block of that way that puts the rules back. If
  you did not do step 8, use the rollback of the step that you did last.
- The last command prints nothing: no open pull request has auto-merge on.

### Way 1. Switch off code-owner review only

```bash
cd ~/ruleset-backup
jq '(.rules[] | select(.type == "pull_request") | .parameters.require_code_owner_review) = false' before-stuck.json > way1.json
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input way1.json > /dev/null
[ -s way1.json ] && diff <(jq -S . way1.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

Check: the last line prints `MATCH`. Merge your pull request. Then put the rules
back at once:

```bash
cd ~/ruleset-backup
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input before-stuck.json > /dev/null
[ -s before-stuck.json ] && diff <(jq -S . before-stuck.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

Check: the last line prints `MATCH`.

### Way 2. Go back to the ruleset as it was before this guide

This also removes `null-safety` from the required checks.

```bash
cd ~/ruleset-backup
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input ruleset.rollback.json > /dev/null
[ -s ruleset.rollback.json ] && diff <(jq -S . ruleset.rollback.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

Check: the last line prints `MATCH`. Merge your pull request. Then put the rules
back at once:

```bash
cd ~/ruleset-backup
gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input before-stuck.json > /dev/null
[ -s before-stuck.json ] && diff <(jq -S . before-stuck.json) <(gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq -S "${BODY:?}") && echo MATCH
```

Check: the last line prints `MATCH`.

### Way 3. Last resort: switch the complete ruleset off

This way needs no saved file. While the ruleset is disabled, nothing protects
`main`: no required checks, no pull request rule, and a force push is possible.

```bash
gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq "${BODY:?}" | jq '.enforcement = "disabled"' | gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input - > /dev/null
gh api "repos/$REPO/rulesets/${RULESET_ID:?}" --jq .enforcement
```

Check: the last line prints `disabled`. Merge your pull request. Then switch the
ruleset on again at once:

```bash
gh api "repos/$REPO/rulesets/${RULESET_ID:?}" | jq "${BODY:?}" | jq '.enforcement = "active"' | gh api --method PUT "repos/$REPO/rulesets/${RULESET_ID:?}" --input - > /dev/null
gh api "repos/$REPO/rulesets/${RULESET_ID:?}" --jq .enforcement
```

Check: the last line prints `active`.

### After each way

Look at what merged while the rule was off:

```bash
gh pr list --repo "${REPO:?}" --state merged --limit 10 --json number,title,mergedAt,mergedBy --jq '.[] | "\(.mergedAt)\t\(.number)\t\(.mergedBy.login)\t\(.title)"'
```

Check: in that time, only your pull request merged.

After way 3, also look at each change of `main`. A direct push and a force push
do not show in the list of pull requests:

```bash
gh api "repos/${REPO:?}/activity?ref=refs/heads/main&per_page=10" --jq '.[] | "\(.timestamp)\t\(.activity_type)\t\(.actor.login)"'
```

Check: in that time, the list has one line, `pr_merge` with your user name. It has
no `push` and no `force_push`.

Auto-merge stays off on the pull requests where you stopped it. `automerge.yml`
turns it on again at the next event of such a pull request, if its rails hold.

### Other ways out, and what does not work

Without the files, in the browser: Settings > Rules > Rulesets > Main > clear
"Require review from Code Owners" > Save changes. Merge your pull request. Then
select the box again and save.

One way keeps the rule: close your pull request, and let the agent's identity open
a pull request from the same branch. Then you can approve it. If step 9 is on, the
agent must also make the most recent push to that branch. While your push is the
most recent one, your approval does not count. No workflow in the repository can
do this at this time. Until the builder workflow can, use way 1.

These do not work: `gh pr merge --admin`; a change to `CODEOWNERS` in the blocked
pull request (GitHub uses the copy on the base branch); "Evaluate" mode and ruleset
history (GitHub Enterprise only).

You can also add a bypass for the repository admin role, "For pull requests only".
Think before you do. A bypass covers each rule in the ruleset, the required checks
too, and each session that acts with your account gets it. Never add the write
role: each collaborator has it.

## Not verified

- No command that changes a setting was run. The blocks were run in `bash`, in the
  sequence of this page, against a local stand-in for `gh` that held a copy of the
  ruleset: step 5 adds one entry, steps 8 and 9 change one boolean each, each
  rollback puts the saved file back, and all five rules stay. The blocks were not
  run in `zsh`.
- That a `PUT` replaces the complete rule list, and that a read after a `PUT`
  returns the rules and the required checks in the same sequence. The `MATCH`
  checks show it.
- The Actions policy section, all of it. The open points: that GitHub counts a
  policy for one workflow file as an applicable event policy, so that its default
  policy does not block `pull_request_target` for `automerge.yml`; the form of the
  path in `workflow_path`; how GitHub combines two policies; what the default
  policy does in a repository that was created after general availability. The
  Policy insights check is the test.
- The fork part of step 1. The file `ruleset-main.json` agrees with the schema of
  the create call in the REST description. GitHub Docs say only that a fork "has
  its own settings": that a new fork has no ruleset and no `automerge` label was
  not confirmed. The block is safe in the two conditions.
- With a count of 0 and code-owner review on, that a pull request without an owned
  file merges with no review. It follows from the documented wording. Step 8 tests
  it.
- What last-push approval does at a count of 0, and that your approval counts for
  a push of the agent. Step 9 tests the two.
- Which values `reviewDecision` and `mergeStateStatus` show in each test. The
  values are real, the mapping is an expectation. That the `review` job is red on
  a pull request of the agent comes from the source of the action.
- That the button "Update branch" counts as a push by you for step 9. The
  documentation does not say. This guide treats it as one.
- If the agent's token can get the Workflows permission. The documents of
  `anthropics/claude-code-action` name `workflows: write` as a permission that a
  workflow can ask for. Its FAQ says that the Claude App has no workflow write
  access.
- That the `vars` context is empty in a workflow run that a fork starts. Treat an
  empty value as "off".
- The `CODEOWNERS` file was checked with an offline matcher that follows the
  documented rules. On the tracked files, each path that rail 8 of `automerge.yml`
  holds has an owner. GitHub's own check is the errors call in step 7.
  `CODEOWNERS` cannot match a name in any letter case. An agent-instruction file
  or a `.claude` directory in a spelling that the file does not list has no owner.
- Rail 8 of `automerge.yml` still treats `docs/setup/` as content, until that
  workflow is changed in a pull request of its own. The workflow can thus turn on
  auto-merge for a labeled pull request that changes only these guides. Until
  step 8 is on, GitHub then merges it with no approval. After step 8, it waits for
  your approval.

## Sources

GitHub Docs, read from the `github/docs` source at commit `d59e392` (2026-11-09):
about rulesets; available rules for rulesets; managing rulesets for a repository;
troubleshooting rules; about code owners; automatically merging a pull request;
issue event types; store information in variables; troubleshooting required status
checks; about Actions policies; governing execution of GitHub Actions workflows;
securely using `pull_request_target` (section "Default policy for
`pull_request_target`"). From the same source: the permission data for GitHub
Apps, and the GraphQL schema (`MergeStateStatus`, `PullRequestReviewDecision`).

The GitHub REST description (`github/rest-api-description`): the paths for
repository rulesets, Actions policies, labels, Actions variables, `CODEOWNERS`
errors, the issue timeline, repository activity, commits and contents.

The `gh` CLI: built-in help of version 2.89.0, and the source of `gh api`,
`gh label` and `gh variable`.

`anthropics/claude-code-action` at commit `4fa93a88` (release v1.0.271):
`src/github/validation/actor.ts`, `src/github/token.ts`, `docs/configuration.md`
and `docs/faq.md`.

This repository: `.github/workflows/automerge.yml`,
`.github/workflows/agent-identity-probe.yml`,
`.github/workflows/claude-code-review.yml` and `.github/CODEOWNERS`.
