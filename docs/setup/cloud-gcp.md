# Google Cloud sandbox project

Part of [`cloud-sandbox.md`](cloud-sandbox.md). Read that page first: it explains
what the sandbox is for, the security rules, and the GitHub side.

Independent reviewers checked this page against primary sources on 2026-11-10: the
built-in reference (`gcloud help`) and the source of the Google Cloud SDK 570.0.0,
the API descriptions of Google, the Google Cloud pricing and free-trial pages, the
source of the sign-in action, and the scripts in this repository. The Google
documentation host (`docs.cloud.google.com`) could not be opened, so console labels
come from search results. **No command on this page was run against a real
project.** The SDK parsed each `gcloud` command of this page in a sandbox with no
network connection and no credentials. That confirms the spelling of a command,
not the answer of Google. Each step has a check. If a check fails, stop and read
the notes. Read the [Not verified](#not-verified) list.

The text about the scripts for TRR9018, TRR9020 and TRR9038 (steps 5.4 to 5.6
and section 7) was changed on 2026-11-11. It was compared with the scripts and
with the same SDK.

Time: about 45 minutes. Cost: 0 USD during the free trial. See [Costs](#costs).

A word in capitals, such as `OWNER/REPO`, is a placeholder. Replace it before you
run the command. The step tells you where the value comes from. A name that starts
with `$`, such as `$PROJECT_ID`, is a shell variable. Do not replace it.

Words that this page uses:

- **Project.** The container for Google Cloud resources. The empty sandbox project
  is the security boundary.
- **Billing account.** The object that pays for one or more projects.
- **Organization.** An optional parent of projects. Only TRR9020 needs one.
- **Session block.** The block of step 2.2. It sets the shell variables.

## 1. Create the account

### 1.1 Create a Google Account for the sandbox only

Open a private browser window. Create a new Google Account at
`https://accounts.google.com/signup`. The account must have an email address. Stay
signed in as this account for each later step.

A new account can use the free trial. An account that paid for Google Cloud, Google
Maps Platform or Firebase before cannot.

### 1.2 Turn on 2-Step Verification

`https://security.google.com` > "How you sign in to Google" > 2-Step Verification >
turn it on. Keep the backup codes: this account is the only administrator.

Check: the next sign-in asks for the second step.

### 1.3 Start the free trial

Open `https://console.cloud.google.com/freetrial`. Select your country, accept the
terms, and give a name, an address and a payment method.

Check: Billing > Overview shows a Free Trial billing account with a credit of 300
USD for 90 days.

A Free Trial billing account cannot charge you. It closes when the credit is used
or when 90 days pass. Google charges you only after you select "Upgrade". Do not
select it until you have read step 3.

## 2. Open a terminal and create the project

### 2.1 Cloud Shell

`https://console.cloud.google.com` > the "Activate Cloud Shell" icon at the top
right > Authorize. Cloud Shell is a terminal in the browser. It has `gcloud` and
`git`, and it is signed in as you. It is free. The blocks on this page are for the
Bash shell.

```bash
gcloud auth list
```

Check: the sandbox account is `ACTIVE`.

On your own computer, install the gcloud CLI from
`https://docs.cloud.google.com/sdk/docs/install` and run `gcloud auth login`. Use a
Bash shell. Never make or download a service account key.

### 2.2 At the start of each session

Cloud Shell loses the shell variables when a session ends. Thus run this block at
the start of each session, and each time that you are not sure. You can run it any
number of times. It creates nothing in Google Cloud.

The first time, the block makes a copy (a clone) of the repository in the
directory `~/det-eng`. Replace `OWNER/REPO` with your repository on GitHub, for
example your fork. After that, the clone exists and the block does not use
`OWNER/REPO`.

```bash
cd ~
[ -d det-eng ] || GIT_TERMINAL_PROMPT=0 git clone https://github.com/OWNER/REPO.git det-eng
cd ~/det-eng && { grep -qxF '/live-*.json' .git/info/exclude || printf '%s\n' '/live-*.json' '/drs-allow-all.yaml' >> .git/info/exclude; }
export SANDBOX_ACCOUNT_EMAIL=$(gcloud auth list --filter=status:ACTIVE --format='value(account)')
export BILLING_ACCOUNT_ID=$(gcloud billing accounts list --filter=open=true --format='value(name.basename())')
export PROJECT_ID=$(gcloud projects list --format='value(projectId,name)' | awk -F'\t' '$2 == "trr-sandbox" { print $1 }')
if [ "$PWD" != "$HOME/det-eng" ]; then
  echo "STOP: no clone. Correct OWNER/REPO in the second line, then run this block again."
elif [ -z "$SANDBOX_ACCOUNT_EMAIL" ]; then
  echo "STOP: gcloud is not signed in. Do step 2.1, then run this block again."
elif [ -z "$PROJECT_ID" ]; then
  echo "NO PROJECT YET: account ${SANDBOX_ACCOUNT_EMAIL}, billing account ${BILLING_ACCOUNT_ID}"
elif [ "$(echo "$PROJECT_ID" | wc -l)" -ne 1 ]; then
  echo "STOP: more than one project has the name trr-sandbox:" $PROJECT_ID
  unset PROJECT_ID
else
  gcloud config set project "$PROJECT_ID" --quiet
  export PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
  export ORG_ID=$(gcloud projects describe "$PROJECT_ID" --format='value(parent.type,parent.id)' | awk '$1 == "organization" { print $2 }')
  export CI_SA="ci-sandbox@${PROJECT_ID}.iam.gserviceaccount.com"
  export TRR9014_BUCKET="trr9014-${PROJECT_ID}" TRR9014_SERVICE=trr9014-svc TRR9014_REGION=us-central1
  export TRR9018_PROJECT="$PROJECT_ID"
  export TRR9038_PROJECT="$PROJECT_ID" TRR9038_CUSTOM_BUCKET=trr9038-custom
  echo "OK: project ${PROJECT_ID} (number ${PROJECT_NUMBER}), organization ${ORG_ID:-none}, billing account ${BILLING_ACCOUNT_ID}, account ${SANDBOX_ACCOUNT_EMAIL}, directory ${PWD}"
fi
```

Check: before step 2.3, the last line starts with `NO PROJECT YET:`. That is
normal. It shows the address of the sandbox Google Account and one billing account
ID in the form `0X0X0X-0X0X0X-0X0X0X`. After step 2.3, the last line starts with
`OK:`. A line that starts with `STOP:` tells you what to do.

Notes:

- The block finds the project by its name, `trr-sandbox`. Step 2.3 gives the
  project that name. The block reads the account and the billing account from
  `gcloud`. It only computes the other names. It is normal that the resources with
  these names do not exist before step 4 and section 6.
- `$SANDBOX_ACCOUNT_EMAIL` is the address of the sandbox Google Account. Some
  commands give a role to that address. If the line shows your usual address, sign
  in as the sandbox account and run the block again.
- If the line shows no billing account, do step 1.3. If it shows more than one,
  stop: this page has no procedure for an account with more than one open billing
  account.
- If the block says that more than one project has the name, delete the project
  that you do not use (`gcloud projects delete ITS_PROJECT_ID`). Then run the
  block again.
- The line with `.git/info/exclude` keeps the working files of this page (the
  `live-*.json` records and `drs-allow-all.yaml`) out of `git status`, in this
  clone only. Those files hold your project ID, your email address and live
  records. Do not commit from this clone.
- Some commands have the form `"${NAME:?run the session block first}"`. If the
  variable is empty, the shell does not run that command, and prints the message.
  Then run this block, and run the command again.
- Some commands have the option `--condition=None`. It stops a question that
  `gcloud` asks when a policy has a binding with a condition. A question in a
  block that you paste takes the next line of the block as its answer.

### 2.3 Create the project and link billing

Choose a project ID: 6 to 30 characters, lowercase letters, digits and hyphens
only. It must start with a letter. It must not end with a hyphen. It must be unique
in all of Google Cloud. You cannot change it later. Replace `YOUR_PROJECT_ID`:

```bash
gcloud projects create YOUR_PROJECT_ID --name="trr-sandbox"
```

Check: the output has no line that starts with `ERROR:`. If `gcloud` says that
the ID is in use, choose a different ID.

Run the session block of step 2.2 again.

Check: the last line starts with `OK:` and shows your project ID and a project
number. If it starts with `NO PROJECT YET:`, wait one minute and run the block
again. The list of projects can be late.

```bash
gcloud billing projects link "${PROJECT_ID:?run the session block first}" \
  --billing-account="${BILLING_ACCOUNT_ID:?run the session block first}"
```

Check: the command prints `billingEnabled: true`.

Do not use a project that holds anything else.

### 2.4 Find out if the project is in an organization

```bash
gcloud projects describe "$PROJECT_ID" --format='value(parent.type,parent.id)'
gcloud organizations list
```

Check: the first command prints nothing (no organization), or `organization` and a
number. The session block puts that number into `$ORG_ID`, and its `OK:` line shows
it. If the first command prints `folder`, the project is in a folder of an
organization. This page has no procedure for that condition.

Older guides say that a personal account has no organization. Google now can make
one automatically for a new customer. Do not assume: use what the command prints.
You need the answer in step 4.1.

### 2.5 Enable the services

```bash
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com \
  cloudresourcemanager.googleapis.com logging.googleapis.com run.googleapis.com \
  storage.googleapis.com --project="$PROJECT_ID"
```

Check: the command ends with `finished successfully`.

## 3. Guardrails

### 3.1 Stay on the free trial

While the billing account is a Free Trial account, Google cannot charge you. That
is the only hard limit for the full account. After 90 days the project stops. You
then have 30 days to upgrade, and after that Google deletes the resources.

After an upgrade, real charges are possible, and steps 3.2 and 3.3 are your
protection. Do step 3.2 now.

### 3.2 Create a budget with an email alert

Run this block one time. A second run makes a second budget with the same name.

```bash
gcloud services enable billingbudgets.googleapis.com --project="$PROJECT_ID"
gcloud billing budgets create --billing-account="${BILLING_ACCOUNT_ID:?run the session block first}" \
  --display-name="trr-sandbox-budget" --budget-amount=5 --calendar-period=month \
  --filter-projects="projects/${PROJECT_ID:?run the session block first}" \
  --credit-types-treatment=exclude-all-credits \
  --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0
gcloud billing budgets list --billing-account="$BILLING_ACCOUNT_ID"
```

Check: the list shows `trr-sandbox-budget`.

The command names no recipient. Google sends the alert to each account that has
the role Billing Account Administrator or Billing Account User. In the sandbox,
that is the sandbox Google Account, not your usual address. Read that mailbox, or
forward its mail to an address that you read. If you do not, no person sees the
alert.

A budget is an alert. It does not stop spending, and the cost data is some hours
old. `--credit-types-treatment=exclude-all-credits` is necessary: without it the
trial credit hides the spending and no alert is sent. The amount is in the currency
of the billing account.

### 3.3 Know the off switch

Do not run this command now. Keep it for the day when the project costs money and
you do not know why.

```bash
gcloud billing projects unlink "${PROJECT_ID:?run the session block first}"
```

This command removes the billing account from the project. The billable resources
and services in the project stop. To use the sandbox again, run the `link` command
of step 2.3.

### 3.4 Optional: a spend cap for Cloud Run

Since 2026-10-30 a budget can have a "spend cap" that pauses one service of one
project when the amount is reached. The announcement of the preview (2026-04-22)
named Cloud Run as a service that it covers. Cloud Run is the only service on this
page in that list. `gcloud` 570.0.0 has no option for a spend cap: use the console
(Billing > Budgets & alerts). It is not necessary during the free trial.

## 4. Throwaway resources

Each emulation script changes one small resource and puts it back. Some scripts
make the resource themselves. For the other scripts, create these resources one
time. Keep them empty.

### 4.1 Only if the project is in an organization: permit a public grant

Skip this step if the `OK:` line of the session block shows `organization none`.

A new organization has a default policy that refuses a grant to `allUsers`. The
policy is named domain-restricted sharing (`iam.allowedPolicyMemberDomains`).
TRR9014 is such a grant. First read the policy:

```bash
gcloud services enable orgpolicy.googleapis.com --project="$PROJECT_ID"
gcloud org-policies describe iam.allowedPolicyMemberDomains --project="$PROJECT_ID" --effective
```

Check: if the output shows `allowAll: true`, the policy does not stop the grant.
Skip the remainder of this step.

If it shows a different rule, permit the grant for the sandbox project only:

```bash
gcloud organizations add-iam-policy-binding "${ORG_ID:?the project is not in an organization}" --condition=None \
  --member="user:${SANDBOX_ACCOUNT_EMAIL:?run the session block first}" --role="roles/orgpolicy.policyAdmin"
cat <<EOF > drs-allow-all.yaml
name: projects/${PROJECT_ID:?run the session block first}/policies/iam.allowedPolicyMemberDomains
spec:
  rules:
  - allowAll: true
EOF
gcloud org-policies set-policy drs-allow-all.yaml
gcloud org-policies describe iam.allowedPolicyMemberDomains --project="$PROJECT_ID" --effective
```

Check: the last command shows `allowAll: true`. The change can take some minutes.

Notes:

- The first command gives the sandbox account the role that can change an
  organization policy. Step 8 removes it.
- If `set-policy` says that you do not have the permission, wait one minute. Then
  run the last two commands again. A new role needs some time.
- If a grant to `allUsers` is still refused, look at these two policies with the
  same `describe` command: `iam.managed.allowedPolicyMembers` and
  `storage.publicAccessPrevention`.

### 4.2 The resources

```bash
# TRR9014 a: an empty bucket. The script grants allUsers read access and removes it.
gcloud storage buckets create "gs://trr9014-${PROJECT_ID:?run the session block first}" --project="$PROJECT_ID" \
  --location=us-central1 --uniform-bucket-level-access --no-public-access-prevention

# TRR9014 b: a private Cloud Run service with a service account that has no roles.
gcloud iam service-accounts create trr9014-run --project="${PROJECT_ID:?run the session block first}" \
  --display-name="trr9014 runtime, no roles"
gcloud run deploy trr9014-svc --project="${PROJECT_ID:?run the session block first}" --region=us-central1 \
  --image=us-docker.pkg.dev/cloudrun/container/hello --no-allow-unauthenticated --max-instances=1 \
  --service-account="trr9014-run@$PROJECT_ID.iam.gserviceaccount.com"

# TRR9018 (optional): a service account that has no roles. The script makes its own
# throwaway service account when TRR9018_SA is not set, so this is needed only if you
# set TRR9018_SA to this address in step 5.4 to bind an existing service account.
gcloud iam service-accounts create trr9018-deployer --project="${PROJECT_ID:?run the session block first}" \
  --display-name="trr9018 target, no roles"

# TRR9038 b: a spare log bucket. Never use _Default or _Required.
gcloud logging buckets create trr9038-custom --location=global --project="${PROJECT_ID:?run the session block first}" \
  --description="trr9038 throwaway"
```

Check: each `create` command and the `deploy` command end without an error. The
deploy prints a Service URL. That URL gives `403 Forbidden` in a browser, because
the service is private.

Notes:

- The names agree with the variables that the session block sets
  (`$TRR9014_BUCKET`, `$TRR9014_SERVICE`, `$TRR9038_CUSTOM_BUCKET`). The emulation
  scripts read those variables. `trr9018-deployer` matches the address that you
  would put in `TRR9018_SA` to bind an existing service account instead of a
  throwaway one.
- Bucket names are global. That is why the project ID is in the name.
- The bucket must not have public access prevention set to `enforced`, or Google
  refuses the grant. The option `--no-public-access-prevention` sets the bucket to
  `inherited`, which is not `enforced`.
- If the deploy says that the service account does not exist, wait one minute and
  run it again.
- If you run the block a second time, each `create` command says that the resource
  exists. That is not a problem.
- The Cloud Run service scales to zero. It has no cost while no request arrives.
- Give no role to `trr9014-run` and `trr9018-deployer`.

## 5. Run one emulation by hand and read the record

Run the session block of step 2.2 first. It sets the variables that the scripts
read, and it goes to the clone.

### 5.1 Run TRR9014 a

```bash
bash atomics/T1098.003/src/emulate.sh a
TRR9014_LIVE=1 bash atomics/T1098.003/src/emulate.sh a
```

The first line is a dry run: it changes nothing. The second line is the live run:
it gives `allUsers` read access to the bucket, then removes that access.

Check: the output of the live run ends with a line that starts with `[live] done.`

The TRR9014 script does not hold the undo block that
[Problems in the live scripts](cloud-sandbox.md#problems-in-the-live-scripts)
describes. If the run stops before that line, the grant to `allUsers` can stay.
Then do step 5.5 immediately.

### 5.2 Read the record

Google writes each change to the Admin Activity audit log of the project, with no
setup and no charge. Wait one or two minutes, then:

```bash
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity" AND protoPayload.serviceName="storage.googleapis.com" AND protoPayload.methodName="storage.setIamPermissions"' \
  --project="${PROJECT_ID:?run the session block first}" --freshness=1h --limit=2 --format=json > live-trr9014.json
```

Check: `live-trr9014.json` is a JSON array of two records with `protoPayload`,
`resource` and `logName`: the same shape as
[`detections/cloud/fixtures/trr9014/attack.json`](../../detections/cloud/fixtures/trr9014/attack.json).
The newest record is first. It is the revoke (`action: REMOVE`). The second record
is the grant (`action: ADD`, `member: allUsers`), which is the one that the rule
reads. If the file holds `[]`, wait one minute and run the command again.

### 5.3 Run the rule on the record

`detections/sigma_eval.py` is a library, not a command. The block below uses it.
It needs Python 3.10 or later, and the packages of the repository.

```bash
python3 --version
```

If the command prints a version lower than 3.10, do this step on your own
computer. Keep the file outside the clone of the repository there: that clone has
no exclude line, and the file holds your project ID, email address and IP address.

Run this block from the root directory of the clone. On your own computer, give
the path of the file in the place of `live-trr9014.json` in the second line:

```bash
python3 -m pip install -r detections/requirements.txt
python3 - live-trr9014.json <<'EOF'
import json, sys
sys.path.insert(0, "detections")
import sigma_eval
rule = "detections/sigma/T1098.003/gcp_public_iam_member_grant.yml"
events = [sigma_eval.flatten(e) for e in json.load(open(sys.argv[1]))]
hits = sigma_eval.evaluate(sigma_eval.compile_rule(rule), events)
print(len(hits), "hit(s) in", len(events), "record(s):", [h[0].get("protoPayload.methodName") for h in hits])
EOF
```

Check: the output is `1 hit(s) in 2 record(s): ['storage.setIamPermissions']`. The
grant is a hit, and the revoke is not. If the output is `0 hit(s)`, the rule or the
fixture does not agree with the real record. That is the finding that the sandbox
is for. Keep the file, and make a record of the finding.

If `pip` refuses to install into the system Python (`externally-managed-environment`),
make a virtual environment and run the block again:
`python3 -m venv ~/trr-venv && . ~/trr-venv/bin/activate`.

A live record holds your real project ID, email address and IP address. Do not
commit it as it is. Make a copy, and replace each real value with the value that
the committed fixture
[`attack.json`](../../detections/cloud/fixtures/trr9014/attack.json) has in the
same field: the project ID `trr9014-demo-project` (your project ID is also in
`logName` and in the bucket name), the bucket name `trr9014-public-exposure-demo`,
the address `trr9014-attacker@example.com` and the IP address `198.51.100.23`.
[`AGENTS.md`](../../AGENTS.md) lists the safe markers. Replace `COPY_FILE` with the
name of the copy:

```bash
grep -c -e "${PROJECT_ID:?run the session block first}" -e "${SANDBOX_ACCOUNT_EMAIL:?run the session block first}" COPY_FILE
```

Check: the command prints `0`. Look at `callerIp` too: the shell does not know
your IP address.

### 5.4 The other emulations

Run one line at a time. Read the last lines of the output before you run the
next line.

**TRR9014 b** (the Cloud Run service):

```bash
TRR9014_LIVE=1 bash atomics/T1098.003/src/emulate.sh b
```

Check: the output ends with a line that starts with `[live] done.` If the run
stops before that line, do step 5.5 immediately.

**TRR9018** (a workload identity pool, a provider and a binding):

```bash
TRR9018_LIVE=1 bash atomics/T1098.001/src/emulate_gcp_wif.sh a
```

Check: the last line is `[live] done.`

What the live run does:

- It makes a throwaway service account, a pool and a provider. Then it gives the
  role `roles/iam.workloadIdentityUser` on the service account to each identity
  of the pool.
- Then it removes the binding, the provider, the pool and the service account,
  in that sequence.
- The pool gets a different name for each run: `trr9018-`, the date and time,
  and a random number. Google blocks the name of a deleted pool for 30 days.
- The provider has the name `trr9018-oidc`, the issuer
  `https://attacker.example.com` and no attribute condition. The SDK parsed the
  command. That Google accepts it is in [Not verified](#not-verified).
- The script needs `TRR9018_PROJECT`. The session block sets it. Without it,
  the script stops before the first change with exit 2, and names the variable.
- Do not set `TRR9018_POOL` or `TRR9018_PROVIDER`. A name that you set must
  start with `trr9018-`. If it does not, the script stops with exit 2.
- Procedures `a` and `c` make the same live run. Procedures `b`, `d` and `e`
  have no live run. For them, the script prints `no record was caused` and
  ends with exit 1.

Optional: to bind the service account of step 4.2 in the place of a throwaway
one, set `TRR9018_SA` before the run:

```bash
export TRR9018_SA="trr9018-deployer@${PROJECT_ID:?run the session block first}.iam.gserviceaccount.com"
```

The script then makes no service account. At the end it removes the binding, and
it does not delete the account. The command `unset TRR9018_SA` goes back to the
throwaway account.

**TRR9038** a (the `_Default` sink), b (the spare log bucket) and c (a project
exclusion):

```bash
TRR9038_LIVE=1 bash atomics/T1562.008/src/emulate_gcp_log_sink.sh a
TRR9038_LIVE=1 bash atomics/T1562.008/src/emulate_gcp_log_sink.sh b
TRR9038_LIVE=1 bash atomics/T1562.008/src/emulate_gcp_log_sink.sh c
```

Check: each live run ends with a line that starts with `[live] done.`

What each live run does:

- **a** reads the state of the `_Default` sink first. If the sink is disabled
  before the run, the script stops with exit 2 and changes nothing: see step
  5.6. If not, it disables the sink and enables it again.
- **b** deletes the spare log bucket `trr9038-custom` and gets it back with
  `undelete`. The name in `TRR9038_CUSTOM_BUCKET` must start with `trr9038-`. If
  it does not, the script stops with exit 2. Thus the script cannot delete
  `_Default` or `_Required`.
- **c** creates the exclusion `trr9038-drop-audit` and removes it. The script
  creates the exclusion with `"disabled": true`. A disabled exclusion drops no
  log. The attack leaves `"disabled"` out. The script also sends the delete
  request when the create request gets no answer, an error of the server (a
  status that is not 2xx and not 4xx), or the status 409. The delete request
  accepts the answer "not found".
- The Google Cloud SDK has no `gcloud logging exclusions` command. Thus
  procedure c calls the Cloud Logging REST API with `curl`. It needs `curl` on
  `PATH` and a `gcloud` that is signed in.
- Procedure c reads the access token one time from
  `gcloud auth print-access-token`. The token goes to `curl` on its standard
  input. The script does not print the token, and does not put it on a command
  line or in a file.
- The script gives `--quiet` to `gcloud logging buckets delete`. Without that
  option, the command asks a question. No `CLOUDSDK_CORE_DISABLE_PROMPTS=1`
  prefix is necessary.

Wait one or two minutes, then read the records. The function `read_record` is the
command of step 5.2 with two parameters: the output file and the filter. Each
technique gets its own file, so that no file is written over:

```bash
read_record() {
  gcloud logging read "logName:\"cloudaudit.googleapis.com%2Factivity\" AND $2" \
    --project="${PROJECT_ID:?run the session block first}" --freshness=1h --limit=2 --format=json > "${1:?give a file name}"
}
read_record live-trr9014-b.json        'protoPayload.serviceName="run.googleapis.com" AND protoPayload.methodName:"SetIamPolicy"'
read_record live-trr9018-provider.json 'protoPayload.methodName:"CreateWorkloadIdentityPoolProvider" AND operation.first=true'
read_record live-trr9018-binding.json  'protoPayload.serviceName="iam.googleapis.com" AND protoPayload.methodName:"SetIAMPolicy"'
read_record live-trr9038-a.json        'protoPayload.methodName:"UpdateSink"'
read_record live-trr9038-b.json        'protoPayload.methodName:"DeleteBucket"'
read_record live-trr9038-c.json        'protoPayload.methodName:"CreateExclusion"'
```

Check: each file of a technique that you ran holds one or two records. A file of a
technique that you did not run holds `[]`.

The TRR9038 b record (`DeleteBucket` of the bucket `trr9038-custom`) does not
fire the rule. That is by design. For a bucket, the rule reads only a resource
name that ends with `/buckets/_Default`, and the script does not touch the
`_Default` bucket. The script prints a note about this. Thus the b record is a
benign baseline for the rule.

The rule fires on the fixture records of procedure a (`UpdateSink` on
`_Default`) and of procedure c (`CreateExclusion`). The rule does not read the
field `disabled` of an exclusion. A live record of a or c must show the same
result: see [Not verified](#not-verified).

### 5.5 After each live run: make sure that nothing stays behind

Do this after each live run, and always after a run whose last line does not
start with `[live] done.` The block changes nothing.

```bash
P=$(gcloud storage buckets get-iam-policy "gs://$TRR9014_BUCKET" --format=json) && echo "TRR9014 bucket: $(grep -c allUsers <<<"$P") public grant(s)"
P=$(gcloud run services get-iam-policy trr9014-svc --region=us-central1 --project="$PROJECT_ID" --format=json) && echo "TRR9014 service: $(grep -c allUsers <<<"$P") public grant(s)"
P=$(gcloud iam service-accounts list --project="$PROJECT_ID" --filter='email~^trr9018-sa-' --format='value(email)') && echo "TRR9018 throwaway SAs:" $P
P=$(gcloud iam workload-identity-pools list --location=global --project="$PROJECT_ID" --format='value(name.basename())') && echo "pools:" $P
P=$(gcloud logging sinks describe _Default --project="$PROJECT_ID" --format='value(disabled)') && echo "TRR9038 _Default sink: disabled=${P:-False}"
P=$(gcloud logging buckets describe trr9038-custom --location=global --project="$PROJECT_ID" --format='value(lifecycleState)') && echo "TRR9038 log bucket: $P"
P=$(printf 'header = "Authorization: Bearer %s"\n' "$(gcloud auth print-access-token)" | curl -q -sS -f --config - "https://logging.googleapis.com/v2/projects/$PROJECT_ID/exclusions") && echo "TRR9038 exclusion: $(grep -c trr9038-drop-audit <<<"$P") found"
```

Check: the block prints these seven lines, and no line that starts with `ERROR:`
or with `curl:`. After section 6, the `pools:` line shows `ci-github`, and no
other pool.

```text
TRR9014 bucket: 0 public grant(s)
TRR9014 service: 0 public grant(s)
TRR9018 throwaway SAs:
pools:
TRR9038 _Default sink: disabled=False
TRR9038 log bucket: ACTIVE
TRR9038 exclusion: 0 found
```

The last line of the block uses the REST API, because `gcloud` has no command
for exclusions. `printf` is a part of the shell, so the access token is not on
the command line of a program. `curl` reads the token on its standard input
(`--config -`). Keep `-q` as the first option: `curl` then does not read your
own `.curlrc` file, which can hold an option that prints the token.

If a line is different, run only the command for that line. Then run the check
block again.

```bash
# TRR9014 bucket: the number is not 0
gcloud storage buckets remove-iam-policy-binding "gs://${TRR9014_BUCKET:?run the session block first}" --member=allUsers --role=roles/storage.objectViewer
# TRR9014 service: the number is not 0
gcloud run services remove-iam-policy-binding trr9014-svc --region=us-central1 --project="${PROJECT_ID:?run the session block first}" --member=allUsers --role=roles/run.invoker
# TRR9038 _Default sink: disabled=True
gcloud logging sinks update _Default --no-disabled --project="${PROJECT_ID:?run the session block first}"
# TRR9038 log bucket: DELETE_REQUESTED (Google keeps a deleted log bucket for 7 days)
gcloud logging buckets undelete trr9038-custom --location=global --project="${PROJECT_ID:?run the session block first}"
# TRR9038 exclusion: the number is not 0 (the exclusion is disabled, so it drops no log)
printf 'header = "Authorization: Bearer %s"\n' "$(gcloud auth print-access-token)" \
  | curl -q -sS -f --config - -X DELETE "https://logging.googleapis.com/v2/projects/${PROJECT_ID:?run the session block first}/exclusions/trr9038-drop-audit"
```

TRR9018: the script removes its binding, its provider, its pool and its
throwaway service account. The commands below are for a run that did not
complete its undo commands.

If the `TRR9018 throwaway SAs:` line shows an email address, delete that service
account. Replace `EMAIL` with the address:

```bash
gcloud iam service-accounts delete EMAIL --project="${PROJECT_ID:?run the session block first}" --quiet
```

If the `pools:` line shows a name that starts with `trr9018-`, delete that pool.
Replace `POOL_ID` with the name. Never delete the pool `ci-github`:

```bash
gcloud iam workload-identity-pools delete POOL_ID --location=global --project="${PROJECT_ID:?run the session block first}" --quiet
```

Only if you set `TRR9018_SA`: read the policy of that service account.

```bash
gcloud iam service-accounts get-iam-policy "${TRR9018_SA:?is not set}" --project="$PROJECT_ID" \
  --flatten='bindings[].members' --format='value(bindings.members)'
```

Check: the command prints no line that starts with `principalSet://`. If it
prints such a line, remove that binding. Replace `MEMBER` with the full line:

```bash
gcloud iam service-accounts remove-iam-policy-binding "${TRR9018_SA:?is not set}" --project="${PROJECT_ID:?run the session block first}" \
  --role=roles/iam.workloadIdentityUser --member='MEMBER' --condition=None
```

If the output of a run has a line that starts with
`[live] LEFT BEHIND, this command failed:`, that line shows the undo command
that failed. You can also run that command again. For the exclusion of TRR9038
c, the line shows the name of a function of the script: use the `curl` command
above.

### 5.6 Things that can make a live run fail

- **A necessary variable is not set.** Run the session block before each run.
  Without `TRR9018_PROJECT` or `TRR9038_PROJECT`, the script stops before the
  first change with exit 2, and names the variable. TRR9038 b does the same
  without `TRR9038_CUSTOM_BUCKET`, and TRR9020 without `TRR9020_ORG` (section
  7). These three scripts use no placeholder project and no placeholder
  organization.
- **A name without the prefix of the technique.** A value that you give to
  `TRR9018_POOL`, `TRR9018_PROVIDER`, `TRR9020_POOL`, `TRR9020_PROVIDER` or
  `TRR9038_CUSTOM_BUCKET` must start with `trr9018-`, `trr9020-` or `trr9038-`.
  If it does not, the script stops with exit 2.
- **TRR9014 in an organization.** See step 4.1.
- **TRR9014 stops between the grant and the revoke.** The TRR9014 script stops
  at the first error and does not clean up after it. The grant to `allUsers`
  then stays. Do step 5.5 immediately.
- **TRR9018 and TRR9020, the pool name.** Google blocks the name of a deleted
  pool for 30 days. A workforce pool ID (TRR9020) must also be unique in all of
  Google Cloud. If `TRR9018_POOL` or `TRR9020_POOL` is not set, the script makes
  a different name for each run. Thus do not set these variables.
- **TRR9038 a, the sink is disabled before the run.** The script stops with
  exit 2 and changes nothing. Its undo command enables the sink, so it cannot
  put a disabled sink back. Step 5.5 shows the state of the sink, and it has the
  command that enables the sink.
- **TRR9038 c, the exclusion is there before the run.** If Google answers with
  the HTTP status 409, the script says that an earlier run left the exclusion.
  The script removes the exclusion and ends with exit 1. That run caused no
  record. Run procedure c again.
- **TRR9038 c, Google refuses the create request.** For a 4xx status that is
  not 409 (for example 403), the script prints the answer of the API and ends
  with exit 1. It registers no undo command for the exclusion, and it names the
  exclusion as a change that can stay. No exclusion is expected after a
  refusal. Do step 5.5 to make sure.
- **TRR9038 c, the create request gets an error of the server.** For a status
  that is not 2xx and not 4xx (for example 500), the exclusion possibly exists.
  The script prints the answer of the API and sends the delete request. The
  delete request accepts the answer "not found". The script ends with exit 1.
  Do step 5.5.
- **TRR9038 c, no `curl` or no token.** The script needs `curl` on `PATH`, and a
  `gcloud` that is signed in. If one is missing, it stops before the first
  change.
- **A run that stops.** The scripts for TRR9018, TRR9020 and TRR9038 run the
  undo commands of the changes that they made, and print `[live] FAILED`. An
  object can stay in two conditions. In the first, an undo command fails: the
  script prints `[live] LEFT BEHIND`. In the second, the run stops during a
  command that makes a change: the script prints
  `[live] The run stopped before the undo of this change was registered:`. In
  each condition, do step 5.5 (for TRR9020, step 7.1).

[Problems in the live scripts](cloud-sandbox.md#problems-in-the-live-scripts)
describes the undo block and the exit codes, and lists what is open for all
providers.

## 6. Let GitHub Actions act in the project

No workflow in the repository runs an emulation in the sandbox. The only job that
uses this identity is the smoke test, which signs in and makes one read-only call.
Thus this section gives the CI identity one role that can read the state of the
project, and no more.

First do the GitHub steps in [`cloud-sandbox.md`](cloud-sandbox.md#the-github-side):
create the environment `sandbox`, limit it to the branch `main`, make yourself a
required reviewer, and
[find your exact subject string](cloud-sandbox.md#3-find-your-exact-subject-string).
The `claims` run of the smoke test prints the values that you need here: `sub`,
`repository_id`, `ref` and `event_name`.

Run the session block of step 2.2. Then put the `sub` value and the
`repository_id` value of the `claims` run between the single quotes. Do not build
the subject from the name of the repository: the value from the run is the only
source.

```bash
export GH_SUBJECT='PASTE_THE_SUB_VALUE_HERE'               # for example repo:OWNER/REPO:environment:sandbox
export GH_REPO_ID='PASTE_THE_REPOSITORY_ID_VALUE_HERE'     # a number
```

Then run this block. It changes nothing in Google Cloud. It builds the two strings
that steps 6.2 and 6.3 store.

```bash
unset CI_CONDITION CI_MEMBER
if [ -z "$PROJECT_NUMBER" ]; then
  echo "STOP: run the session block of step 2.2 first."
elif [ "${GH_SUBJECT%:environment:sandbox}" = "$GH_SUBJECT" ]; then
  echo "STOP: GH_SUBJECT does not end with :environment:sandbox. Set it again."
elif [ -z "$GH_REPO_ID" ] || [ -n "$(printf '%s' "$GH_REPO_ID" | tr -d '0-9')" ]; then
  echo "STOP: GH_REPO_ID is not a number. Set it again."
elif [ "$(printf '%s' "$GH_SUBJECT" | wc -c)" -gt 127 ]; then
  echo "STOP: the subject is longer than 127 bytes. Google refuses it."
else
  export CI_CONDITION="assertion.sub == '${GH_SUBJECT}' && assertion.repository_id == '${GH_REPO_ID}' && assertion.ref == 'refs/heads/main' && assertion.event_name == 'workflow_dispatch'"
  export CI_MEMBER="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/ci-github/subject/${GH_SUBJECT}"
  echo "OK"; echo "$CI_CONDITION"; echo "$CI_MEMBER"
fi
```

Check: the output is `OK` and two lines. Compare the subject and the repository ID
in them with the `sub` and `repository_id` lines of the `claims` run, character by
character. The `ref` line of that run must be `refs/heads/main`, and the
`event_name` line must be `workflow_dispatch`.

If a new session starts before you complete this section, run the session block
and these two blocks again. Google maps the subject to an attribute that cannot
exceed 127 bytes. This page has no procedure for a longer subject.

### 6.1 Create the service account for CI

```bash
gcloud iam service-accounts create ci-sandbox --project="${PROJECT_ID:?run the session block first}" \
  --display-name="GitHub Actions sandbox CI"
gcloud projects add-iam-policy-binding "${PROJECT_ID:?run the session block first}" --condition=None \
  --member="serviceAccount:${CI_SA:?run the session block first}" --role="roles/browser"
gcloud projects get-iam-policy "$PROJECT_ID" --flatten='bindings[].members' \
  --filter="bindings.members=serviceAccount:$CI_SA" --format='value(bindings.role)'
```

Check: the last command prints one line, `roles/browser`. If the second command
says that the service account does not exist, wait one minute and run the last two
commands again.

`roles/browser` is a role to read the project itself, not the resources in it. It
holds the permission `resourcemanager.projects.get`, which the one call of the
smoke test needs (see [Not verified](#not-verified)). Give this account no other
role, and no role on a different project, on the billing account or on an
organization. Never make a key for it.

### 6.2 Create the pool and the provider

```bash
gcloud iam workload-identity-pools create ci-github --project="${PROJECT_ID:?run the session block first}" \
  --location=global --display-name="CI GitHub Actions"
gcloud iam workload-identity-pools providers create-oidc github-oidc --project="${PROJECT_ID:?run the session block first}" \
  --location=global --workload-identity-pool=ci-github --display-name="GitHub OIDC sandbox" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository_id=assertion.repository_id,attribute.ref=assertion.ref" \
  --attribute-condition="${CI_CONDITION:?run the two blocks at the start of section 6 first}"
```

Check: the two commands print `Created workload identity pool [ci-github].` and
`Created workload identity pool provider [github-oidc].`

Then read the condition that Google stored:

```bash
gcloud iam workload-identity-pools providers describe github-oidc --project="$PROJECT_ID" \
  --location=global --workload-identity-pool=ci-github --format='value(attributeCondition)'
```

Check: the command prints the condition with your subject and your repository ID.

To correct a wrong subject or repository ID, change the provider in place. Set the
two `GH_` variables again, run the block that prints `OK` again, and then:

```bash
gcloud iam workload-identity-pools providers update-oidc github-oidc --project="${PROJECT_ID:?run the session block first}" \
  --location=global --workload-identity-pool=ci-github \
  --attribute-condition="${CI_CONDITION:?run the two blocks at the start of section 6 first}"
```

Check: the `describe` command above prints the new condition. If you changed the
subject, correct the binding of step 6.3 too.

**Do not delete the pool or the provider to start again.** Google blocks the name
of a deleted pool or provider for 30 days, so you cannot create `ci-github` or
`github-oidc` a second time. If you deleted one, get it back:

```bash
gcloud iam workload-identity-pools undelete ci-github --location=global --project="${PROJECT_ID:?run the session block first}"
gcloud iam workload-identity-pools providers undelete github-oidc --location=global \
  --workload-identity-pool=ci-github --project="${PROJECT_ID:?run the session block first}"
```

Rules:

- The attribute condition is the lock. It names one subject, one repository ID, one
  branch and one event, with `==`. No wildcard and no `startsWith`.
- The repository ID does not change when the repository gets a new name. A
  different repository that gets the old name later has a different ID, so it does
  not pass the condition.
- The event `workflow_dispatch` is a run that a person or a token with write
  access starts.
  The events `pull_request_target`, `issue_comment` and `workflow_run` also run on
  `main`, and a person with no write access can cause some of them. The condition
  refuses them.
- Do not set `--allowed-audiences`. The default audience is the full name of the
  provider, and that is what the GitHub action sends.
- Keep the names `ci-github` and `github-oidc`, so that this pool is never
  confused with the `trr9018-...` pools of the emulation.
- This setup writes the same type of record that the TRR9018 rules read. One alert
  from your own setup is correct.

### 6.3 Let that one subject act as the service account

```bash
gcloud iam service-accounts add-iam-policy-binding "${CI_SA:?run the session block first}" \
  --project="${PROJECT_ID:?run the session block first}" --role="roles/iam.workloadIdentityUser" \
  --member="${CI_MEMBER:?run the two blocks at the start of section 6 first}"
gcloud iam service-accounts get-iam-policy "$CI_SA" --project="$PROJECT_ID" \
  --flatten='bindings[].members' --format='value(bindings.members)'
```

Check: the last command prints one line. It starts with `principal://`, it has the
project **number** (not the project ID), and it ends with your subject.

Use `principal://.../subject/...` (one identity). Never `principalSet://.../*`
(the full pool).

To correct a wrong line, remove it and add the correct one. Replace `WRONG_MEMBER`
with the full line that the check printed. Then run the block of this step again.

```bash
gcloud iam service-accounts remove-iam-policy-binding "${CI_SA:?run the session block first}" \
  --project="${PROJECT_ID:?run the session block first}" --role="roles/iam.workloadIdentityUser" \
  --member="WRONG_MEMBER"
```

Before you rename, move or delete the repository or your GitHub account, remove
the binding with the same command: use the line that the check prints. The
sign-in then stops, and the names `ci-github` and `github-oidc` stay for a later
use.

### 6.4 Store the values in the GitHub environment

In Cloud Shell, print the three commands with your values in them:

```bash
PROVIDER_NAME=$(gcloud iam workload-identity-pools providers describe github-oidc --project="$PROJECT_ID" \
  --location=global --workload-identity-pool=ci-github --format='value(name)')
echo "gh secret set GCP_WORKLOAD_IDENTITY_PROVIDER --env sandbox --repo OWNER/REPO --body \"$PROVIDER_NAME\""
echo "gh secret set GCP_SERVICE_ACCOUNT --env sandbox --repo OWNER/REPO --body \"$CI_SA\""
echo "gh secret set GCP_PROJECT_ID --env sandbox --repo OWNER/REPO --body \"$PROJECT_ID\""
```

Check: the block prints three lines. The first line has a provider name in the
form `projects/NUMBER/locations/global/workloadIdentityPools/ci-github/providers/github-oidc`.
`NUMBER` stands for the number of your project: the `OK:` line of the session
block shows it. The second line has `ci-sandbox@`, your project ID and
`.iam.gserviceaccount.com`.

Copy the three printed lines to your own terminal, where `gh` is signed in as the
owner of the repository. Replace `OWNER/REPO` in each line, and run them.

Check: `gh secret list --env sandbox --repo OWNER/REPO` shows the three names.

There is no key, password or token to store. If a guide tells you to add a JSON
key, it shows the old method.

Then run the smoke test in [`cloud-sandbox.md`](cloud-sandbox.md#test-the-federation)
with `gcp`. A change to a pool, a provider or a role can take five minutes to
apply. If the run fails:

| Step that fails | Message | Cause |
|-----------------|---------|-------|
| `Sign in to Google Cloud with OIDC` | "Failed to generate Google Cloud federated token" | The attribute condition does not agree with the token, or the pool or the provider is less than five minutes old. Compare `sub`, `repository_id`, `ref` and `event_name` of a `claims` run with the condition that step 6.2 prints. Correct the provider in place. |
| `Make one read-only call` | `gcloud` cannot get a token for the service account ("Unable to acquire impersonated credentials") | The binding of step 6.3 is wrong, or it is less than five minutes old. |
| `Make one read-only call` | A permission error for the project | The role of step 6.1 is missing, or it is less than five minutes old. |

The sign-in step exchanges the GitHub token for a Google token. That tests the
attribute condition. It does not act as the service account. The call in the last
step does, so that step tests the binding and the role.

### 6.5 Later: when a reviewed workflow runs the emulations

**Do not do this subsection now.** A workflow that runs the emulations in the
sandbox does not exist. [`AGENTS.md`](../../AGENTS.md) keeps live emulations out of
CI until such a workflow is designed and reviewed. This subsection keeps what the
identity of that workflow will need.

The emulations change IAM policies, pools and log settings, so `roles/browser` is
not sufficient for them. The simplest role is `roles/owner` on the sandbox project.
A narrower set of roles is better. It is not worked out yet.

```bash
gcloud projects add-iam-policy-binding "${PROJECT_ID:?run the session block first}" --condition=None \
  --member="serviceAccount:${CI_SA:?run the session block first}" --role="roles/owner"
```

Check: the printed policy has `roles/owner` for `ci-sandbox@...`.

- `roles/owner` is acceptable only because the project is empty. Give this account
  no role on a different project, on the billing account or on an organization.
  Never make a key for it.
- To take the role away again, run the same command with
  `remove-iam-policy-binding` in the place of `add-iam-policy-binding`.
- The condition of step 6.2 permits the event `workflow_dispatch` only. A workflow
  that runs on a schedule also needs `|| assertion.event_name == 'schedule'` in
  the condition, with parentheses around the two event tests.
- TRR9020 stays a run by hand. See section 7.

## 7. Optional: an organization for TRR9020

Skip this section unless you want live records for TRR9020 (workforce identity
pools). The committed fixtures cover it.

TRR9020 needs an organization, because a workforce pool is a resource of an
organization and its records are in the log of the organization:

- If step 2.4 showed an organization, use it. It was not confirmed that an
  organization that Google made automatically permits workforce pools.
- If not, you need a domain name that you control, and Cloud Identity Free (0 USD)
  with a DNS record to prove the domain.

What a live run of procedure `a` does:

1. It makes a workforce pool. The pool gets a different name for each run:
   `trr9020-`, the date and time, and a random number.
2. It makes the OIDC provider `trr9020-idp` in the pool, with the issuer
   `https://attacker.example.com` and no attribute condition.
3. It gives a role on the organization to each identity of the pool. The
   default role is `roles/viewer`.
4. It removes the binding, the provider and the pool, in that sequence.

The command lines of the script agree with the built-in help of the Google
Cloud SDK 570.0.0:

- Only `gcloud iam workforce-pools create` gets `--organization`. The commands
  `providers create-oidc`, `providers delete` and `workforce-pools delete` do
  not have that option.
- `providers create-oidc` gets `--client-id` and the response type `id-token`.
  The help says that a client secret is necessary only for the response type
  `code`. Thus no secret is on a command line.
- The script adds and removes the binding with `--condition=None`.

The SDK parsed these command lines. Only a live run shows that Google accepts
them: see [Not verified](#not-verified).

The variables:

- `TRR9020_ORG` is necessary. Without it, the script stops before the first
  change with exit 2, and names the variable.
- Do not set `TRR9020_POOL` or `TRR9020_PROVIDER`. A name that you set must
  start with `trr9020-`, or the script stops with exit 2. A fixed pool name
  fails on the second run: see step 5.6.
- `TRR9020_ROLE` is the role of the binding. See "The record that fires the
  binding rule" below.
- Procedures `a` and `c` make the same live run. Procedures `b` and `d` have no
  live run. For them, the script prints `no record was caused` and ends with
  exit 1.

Run it by hand as the administrator of the organization. Do not give the CI
service account a role on an organization.

First set the variable and give yourself the role for workforce pools:

```bash
export TRR9020_ORG="${ORG_ID:?the project is not in an organization}"
gcloud organizations add-iam-policy-binding "$TRR9020_ORG" --condition=None \
  --member="user:${SANDBOX_ACCOUNT_EMAIL:?run the session block first}" --role="roles/iam.workforcePoolAdmin"
```

Check: the printed policy has `roles/iam.workforcePoolAdmin` for your address.

Then run the script with the default role:

```bash
TRR9020_LIVE=1 bash atomics/T1199/src/emulate_gcp_workforce.sh a
```

Check: the last line starts with `[live] done.` Before the undo lines, the
script prints that the `SetIamPolicy` record is written for `roles/viewer`, but
that the binding rule does not fire.

Wait one or two minutes, then read the record of the provider:

```bash
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity" AND protoPayload.methodName:"CreateWorkforcePoolProvider"' \
  --organization="${TRR9020_ORG:?set it first}" --freshness=1h --limit=2 --format=json > live-trr9020.json
```

Check: `live-trr9020.json` holds the `CreateWorkforcePoolProvider` record. If the
file holds `[]`, wait one minute and run the command again.

**The record that fires the binding rule.** The binding rule does not fire on
the `SetIamPolicy` record of a binding to `roles/viewer`. That is by design. The
rule fires for a binding to the full pool if the name of the role contains
`owner`, `editor` or `admin`. It also fires for a `roles/iam.` role whose name
ends with `Creator` or `User`, for example
`roles/iam.serviceAccountTokenCreator`. The rule reads the name of the role, not
its power, and the script prints what the rule does with the role that you set.
`roles/owner` is the role of the attack. A role with less power is sufficient
for the record, for example `roles/pubsub.editor`:

```bash
TRR9020_ROLE=roles/pubsub.editor TRR9020_LIVE=1 bash atomics/T1199/src/emulate_gcp_workforce.sh a
```

Check: the last line of the run starts with `[live] done.` Before the undo
lines, the script prints
`The role roles/pubsub.editor holds owner, editor or admin: the binding rule reads this record.`

Wait one or two minutes, then read the records of the bindings:

```bash
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity" AND protoPayload.serviceName="cloudresourcemanager.googleapis.com" AND protoPayload.methodName:"SetIamPolicy"' \
  --organization="${TRR9020_ORG:?set it first}" --freshness=1h --limit=10 --format=json > live-trr9020-binding.json
```

Check: `live-trr9020-binding.json` holds the record that adds
`roles/pubsub.editor` for a `principalSet://` member with `workforcePools/trr9020-`
in it. The file also holds the other `SetIamPolicy` records of the last hour.
They are the record that removes the binding, the records of the first run, and
the record of the role that you gave yourself.

For some seconds, each identity that the provider accepts has that role on the
organization. The issuer is a name under `example.com`, which no person can
register. Do not use a role with more power than is necessary for the record.

### 7.1 After each live run of TRR9020: make sure that nothing stays behind

Do this after each live run of TRR9020, and always after a run whose last line
does not start with `[live] done.` The script removes its binding, its provider
and its pool. The commands below find what a run that did not complete its undo
commands left behind:

```bash
gcloud iam workforce-pools list --organization="${TRR9020_ORG:?set it first}" \
  --location=global --format='value(name.basename())'
gcloud organizations get-iam-policy "${TRR9020_ORG:?set it first}" \
  --flatten='bindings[].members' --filter='bindings.members:workforcePools/trr9020-' \
  --format='value(bindings.role,bindings.members)'
```

Check: the two commands print nothing.

If the second command prints a role and a member, remove that binding. Replace
`ROLE` and `MEMBER` with the two values that it printed:

```bash
gcloud organizations remove-iam-policy-binding "${TRR9020_ORG:?set it first}" --condition=None \
  --role=ROLE --member='MEMBER'
```

If the first command prints a name that starts with `trr9020-`, delete that pool.
Replace `POOL_ID` with the name:

```bash
gcloud iam workforce-pools delete POOL_ID --location=global --quiet
```

Then run the two check commands again.

## 8. Teardown

[`cloud-sandbox.md`](cloud-sandbox.md) has the sequence for all providers in its
section "Off switch and teardown": the cloud side first, then the stored values,
then the environment. This section is the cloud side for Google Cloud, and the
stored values.

In Cloud Shell, run the session block of step 2.2. Remove the roles on the
organization before you delete the project: after the deletion, the session block
cannot find the organization.

If you did step 4.1, remove the role that it gave:

```bash
gcloud organizations remove-iam-policy-binding "${ORG_ID:?the project is not in an organization}" --condition=None \
  --member="user:${SANDBOX_ACCOUNT_EMAIL:?run the session block first}" --role="roles/orgpolicy.policyAdmin"
```

Check: the printed policy has no `roles/orgpolicy.policyAdmin` for your address.

If you used section 7, remove what stays in the organization. Replace `POOL_ID`
with each name that the first command prints:

```bash
gcloud iam workforce-pools list --organization="${ORG_ID:?is empty: run the session block first}" \
  --location=global --format='value(name.basename())'
gcloud iam workforce-pools delete POOL_ID --location=global --quiet
gcloud organizations remove-iam-policy-binding "${ORG_ID:?is empty: run the session block first}" --condition=None \
  --member="user:${SANDBOX_ACCOUNT_EMAIL:?run the session block first}" --role="roles/iam.workforcePoolAdmin"
```

Check: the `list` command prints nothing when you run it again.

Then delete the project. `gcloud` asks you to confirm: type `Y`.

```bash
gcloud projects delete "${PROJECT_ID:?run the session block first}"
```

```bash
gcloud projects describe "$PROJECT_ID" --format='value(lifecycleState)'
```

Check: the second command prints `DELETE_REQUESTED`.

One command removes the bucket, the Cloud Run service, the service accounts, the
pools and the log bucket. The CI identity `ci-sandbox` goes with them. To stop the
sign-in before the deletion, remove the binding as step 6.3 shows. `gcloud` says
that you can get the project back with `gcloud projects undelete` for a limited
period. Expect about 30 days. Do not plan to use the project ID again.

Then, from your own terminal, delete the three stored values. Replace
`OWNER/REPO`:

```bash
gh secret delete GCP_WORKLOAD_IDENTITY_PROVIDER --env sandbox --repo OWNER/REPO
gh secret delete GCP_SERVICE_ACCOUNT --env sandbox --repo OWNER/REPO
gh secret delete GCP_PROJECT_ID --env sandbox --repo OWNER/REPO
gh secret list --env sandbox --repo OWNER/REPO
```

Check: the last command shows no name that starts with `GCP_`.

The budget stays on the billing account. It has no cost. To close the billing
account: Console > Billing > Account management > Close billing account. A Free
Trial billing account closes by itself when the trial ends.

## Costs

| Item | Cost | Source |
|------|------|--------|
| Free trial | 0 USD. 300 USD of credit for 90 days. No charge unless you select Upgrade. | `cloud.google.com/signup-faqs` |
| Admin Activity audit logs | No charge. Kept for 400 days. | `cloud.google.com/products/observability/pricing` |
| The empty spare log bucket | 0 USD while no sink sends logs to it. | The same page |
| Cloud Run service | 0 USD while no request arrives. A free amount each month. | `cloud.google.com/run/pricing` |
| Empty Cloud Storage bucket in `us-central1` | 0 USD. | `cloud.google.com/storage/pricing` |
| Service accounts, workload identity pools, workforce pools | Free. | `cloud.google.com/iam/pricing` |
| Cloud Shell | Free. | `cloud.google.com/shell/pricing` |
| Cloud Identity Free (optional) | 0 USD. The domain name is paid to your registrar. | `cloud.google.com/identity/pricing` |

Budgets and budget alerts are believed to have no charge. No page that gives a
price for them could be opened.

## Not verified

- No command was run against a real project. Command and option names were checked
  against the built-in reference (`gcloud help`) of the Google Cloud SDK 570.0.0,
  which is not the newest release. The output formats (`--format`, `--flatten`,
  `--filter`) were tested with that SDK on sample data, not on answers of Google.
- The two `curl` lines of step 5.5. The paths and the methods (`GET` and `DELETE`
  on `v2/projects/PROJECT/exclusions`) are in the API description of the SDK
  570.0.0. The lines were run against a test server on the local computer, with
  a stub in the place of `gcloud`. Not verified: that the Cloud Logging API
  accepts the token of `gcloud auth print-access-token` with no
  `X-Goog-User-Project` header, and the exact text of its answers.
- That a live run of TRR9018, TRR9020 or TRR9038 causes the record that the
  paired rule reads, and that each undo command reverts its change. The tests in
  [`atomics/tests/`](../../atomics/tests/README.md) show the sequence of the
  commands with stub programs. A stub accepts each command.
- What stays in the project when Ctrl-C stops a `gcloud` command or a `curl`
  request that makes a change. The script names that change. Steps 5.5 and 7.1
  find it.
- Console labels, the sign-up pages and the address of the account security page
  (step 1.2). The Google documentation host could not be opened.
- What Cloud Shell keeps between sessions, which shell it starts, and which Python
  version it has. The session block makes the clone again if it is not there.
- Whether a new account gets an organization automatically, whether
  `gcloud projects create` puts the project in it, which policies that organization
  has, and whether it permits workforce pools. Google announced the default
  policies for new organizations on 2024-03-20. The date from which they apply
  (2024-05-03 in the notes for this page) was not confirmed.
- The role name `roles/iam.workforcePoolAdmin`, and the constraint name
  `iam.managed.allowedPolicyMembers`.
- That `roles/browser` holds the permission `resourcemanager.projects.get`, which
  the call of the smoke test needs. The help of `gcloud projects list` and the
  Resource Manager API description say it together. The page that lists the
  permissions of a role could not be opened. The smoke test shows it.
- A narrower set of roles than `roles/owner` for step 6.5.
- Whether a bucket that `gcloud` makes has public access prevention off by
  default. The command sets it.
- That Google accepts an issuer that does not answer (`https://attacker.example.com`)
  for a workload identity pool provider (TRR9018) or a workforce pool provider
  (TRR9020). Also not verified: that Google requires an attribute condition only
  for an issuer that many customers share, such as the GitHub issuer. The
  TRR9018 and TRR9020 runs need the two.
- That Google accepts a workforce OIDC provider with the response type `id-token`
  and no client secret. The help of the SDK says that the secret is necessary
  for the response type `code`. TRR9020 uses `id-token`.
- That the policy of the organization permits a binding for a workforce
  `principalSet://` member (TRR9020).
- That Google accepts the roles `roles/viewer` and `roles/pubsub.editor` in a
  binding on an organization. The SDK names `roles/pubsub.editor` in the source
  of a different command.
- For TRR9038 c: that `CreateExclusion` with `"disabled": true` writes an Admin
  Activity record, and that a second request with the same name gets the HTTP
  status 409.
- That the committed fixtures agree with the records of a live run. Four
  differences are known. CI is not affected: the paired rules match these
  records, or do not read the field that differs (the value of the issuer,
  `webSsoConfig`, the user agent), and no check compares a fixture with what
  Google writes. The roadmap lists them for the items R5 and R9.
  - The TRR9018 fixture has the GitHub issuer and no attribute condition. A live
    run writes the issuer `https://attacker.example.com`.
  - The TRR9020 fixture has no `webSsoConfig`. The SDK sends one in the request
    of a live run.
  - The TRR9038 fixture has a successful delete of the `_Default` sink and of the
    `_Default` bucket. The script does not delete them. It is not known if
    Google permits these two deletes.
  - The `CreateExclusion` record of the TRR9038 fixture names a
    `gcloud logging exclusions` command. The SDK 570.0.0 does not have that
    command. The record has `"disabled": false`. A live run of procedure c is a
    `curl` request with `"disabled": true`.
- That Google accepts the character `@` in the subject of a `principal://` member.
  A subject in the GitHub format with IDs has it. Google shows only `:` and `/` in
  its examples.
- That the subject of an environment job in the GitHub format with IDs ends with
  `:environment:sandbox`. The check block of section 6 requires that ending. See
  step 3 of [`cloud-sandbox.md`](cloud-sandbox.md#3-find-your-exact-subject-string).
- That Google lets you remove a `principalSet://` binding after its pool is
  deleted. The TRR9018 script removes the binding before it deletes the pool.
  The last command of step 5.5 is for a binding that stays.
- The text that `gcloud` prints on the runner when the binding of step 6.3 is
  wrong. "Unable to acquire impersonated credentials" is the text in the SDK
  570.0.0. The runner has a newer SDK.
- The exact method names in the log filters `storage.setIamPermissions` and
  `SetIAMPolicy`. They agree with the committed fixtures.
- Whether the administrator of an organization can read its audit log (section 7)
  with no additional role.
- Whether `gcloud billing projects unlink` only stops the resources, or whether
  Google can delete them after some time.
- The list of services that a spend cap covers since general availability.
- How long an audit record takes to arrive. Expect seconds to some minutes.
- The time in which a deleted project can be restored, that its project ID cannot
  be used again, and how fast the sign-in stops after `gcloud projects delete`.
