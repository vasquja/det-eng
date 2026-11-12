# AWS sandbox account

Part of [`cloud-sandbox.md`](cloud-sandbox.md). Read that page first: it explains
what the sandbox is for, the security rules, and the GitHub side.

Independent reviewers checked this page against primary sources on 2026-11-10: the
AWS documentation, the service descriptions of the AWS CLI, and the scripts in this
repository. **No command on this page was run against a real AWS account.** The
AWS CLI parsed each `aws` command against a local recorder that contacts no AWS
service. That confirms the spelling of a command, not the answer of AWS. Each step
has a check. If a check fails, stop and read the notes. Read the
[Not verified](#not-verified) list.

Time: about 45 minutes of work. AWS can need up to 24 hours to activate a new
account. Cost: 0 USD on the Free plan. See [Costs](#costs).

Use the Region `us-east-1` for each step. CloudTrail Event history is per Region,
and the events of global services such as IAM are recorded there.

A word in capitals, such as `OWNER/REPO`, is a placeholder. Replace it before you
run the command. The step tells you where the value comes from. A name that
starts with `$`, such as `$ACCOUNT_ID`, is a shell variable. Do not replace it.

## 1. Create the account

### 1.1 Use the "advanced" sign-up path

AWS has two sign-up paths since October 2026. Open
`https://docs.aws.amazon.com/accounts/latest/reference/sign-up-for-aws.html` and
follow the link "Sign up for AWS (advanced)".

Check: the form asks for a "Root user email address" and an "AWS account name". If
you see a Google, Apple or GitHub login button, "AWS Builder ID" or "project", you
are on the other path. Stop. That path gives an account in which AWS denies the
creation of an identity provider, so step 5 cannot work.

### 1.2 Create the account

Use an email address that you use for nothing else, and the account name
`det-eng-sandbox`. AWS asks for a password, contact data, a payment card and a
phone number that can receive an SMS. Select the free basic support plan.

When AWS asks for the account plan, select the **Free plan** if it is offered.
The Free plan cannot be charged. It ends after 6 months or when its credits are
used, and the account then closes (you have 90 days to upgrade). If you have or
had another AWS account, AWS gives you the Paid plan. Then the budget in step 2.4
is your protection.

Do not use an account that holds anything else. The empty account is the security
boundary.

AWS then activates the account. This usually takes some minutes. It can take up
to 24 hours. Wait for the email message that says that the account is active.

Check: you have the activation message, and you can sign in to the AWS Management
Console as the root user.

### 1.3 Add MFA to the root user

Sign in to the AWS Management Console as the root user. Account name (top right) >
Security credentials > Multi-Factor Authentication (MFA) > Assign MFA device >
Authenticator app.

Make sure that you have a second method to sign in. Before you scan the QR code,
select "Show secret key" and store the key in your password manager. As an
alternative, assign a second MFA device after the first one: AWS permits eight.
Keep access to the root email address and to the phone number of the account.
AWS uses the two to confirm who you are when the MFA device is lost.

Then scan the QR code and type two codes that follow each other.

Check: the device is in the list, and the next root sign-in asks for a code.

Never make an access key for the root user. Use the root user for setup and for
closing the account only.

### 1.4 Create an admin user for your work

As root: IAM console > Users > Create user. User name `sandbox-admin`. Select
"Provide user access to the AWS Management Console" and "I want to create an IAM
user". Add the user to a new group `sandbox-admins` with the policy
`AdministratorAccess`. Create the user and download the `.csv` file.

Sign out. Sign in as `sandbox-admin` at the address in the `.csv` file, set a new
password, then: IAM console > Users > sandbox-admin > Security credentials > Assign
MFA device.

Check: you can sign in as `sandbox-admin` with an MFA code. The user has no access
key. Do not make one.

## 2. Guardrails

### 2.1 Open a terminal: AWS CloudShell

Signed in as `sandbox-admin`, with the Region selector on US East (N. Virginia):
select the CloudShell icon in the navigation bar. CloudShell is a terminal in the
browser. It has the AWS CLI, `git` and `jq`, and it is signed in as you. It has no
additional charge. It starts with the Bash shell. The blocks on this page are for
Bash: do not change the shell.

```bash
aws sts get-caller-identity
```

Check: the command prints an ARN that ends in `user/sandbox-admin`.

On your own computer, you can use `aws login` (AWS CLI 2.32.0 or later). It signs
in through the browser and saves no access key. Use a Bash shell there too.

### 2.2 At the start of each session

A CloudShell session ends after 20 to 30 minutes without input. The files in your
home directory stay. The shell variables and the working directory are lost. Thus
run this block at the start of each session, and each time that you are not sure.
You can run it any number of times. It makes nothing in the account.

The first time, the block makes a copy (a clone) of the repository in the
directory `~/det-eng`. Replace `OWNER/REPO` with your repository on GitHub, for
example your fork. After that, the clone exists and the block does not use
`OWNER/REPO`.

```bash
cd ~
[ -d det-eng ] || GIT_TERMINAL_PROMPT=0 git clone https://github.com/OWNER/REPO.git det-eng
cd ~/det-eng && { grep -qxF '/*.json' .git/info/exclude || printf '%s\n' '/*.json' '/trr9037-ca.*' >> .git/info/exclude; }
export AWS_PAGER="" AWS_DEFAULT_OUTPUT=json
export AWS_REGION=us-east-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
if [ -z "$ACCOUNT_ID" ]; then
  echo "STOP: no account ID. Sign in again, then run this block again."
elif [ "$PWD" != "$HOME/det-eng" ]; then
  echo "STOP: no clone. Correct OWNER/REPO in the second line, then run this block again."
else
  export TRR9019_BUCKET="trr9019-${ACCOUNT_ID}"
  export TRR9021_BUCKET="trr9021-${ACCOUNT_ID}"
  export TRR9021_BUS=trr9021-bus
  export TRR9021_DOC=trr9021-doc
  export TRR9037_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/trr9037-disposable-role"
  export TRR9037_CERT_PEM="$HOME/det-eng/trr9037-ca.pem"
  export TRR9032_CLUSTER=trr9032-cluster
  export TRR9032_PRINCIPAL_ARN="arn:aws:iam::${ACCOUNT_ID}:role/trr9032-disposable-principal"
  echo "OK: account ${ACCOUNT_ID}, directory ${PWD}"
fi
```

Check: the last line of the output starts with `OK:`. It shows 12 digits, and a
directory that ends in `/det-eng`. A line that starts with `STOP:` tells you what
to do.

Notes:

- The block only computes names. It is normal that the resources with these
  names do not exist before step 3.
- The line with `.git/info/exclude` keeps the working files of this page (each
  `.json` file and the certificate) out of `git status`, in this clone only.
  Those files hold your account ID, your email address and live records. Do not
  commit from this clone.
- `AWS_PAGER=""` stops the AWS CLI from showing long output in a pager. A pager
  would take the next lines that you paste as key presses. `AWS_DEFAULT_OUTPUT`
  makes the output JSON, which the checks on this page show.
- Some commands have the form `"${NAME:?run the session block first}"`. If the
  variable is empty, the shell does not run that command, and prints the message.
  Then run this block, and run the command again.

### 2.3 Check the plan

```bash
aws freetier get-account-plan-state
```

Check: `accountPlanType` is `FREE` or `PAID`, with the credits and the end date.

### 2.4 Create a budget with an email alert

Set the address that gets the alerts. Replace the text between the quotation
marks with your email address.

```bash
ALERT_EMAIL='PASTE_YOUR_EMAIL_ADDRESS_HERE'
```

Then run this block.

```bash
cat > budget.json <<'EOF'
{
  "BudgetName": "sandbox-monthly",
  "BudgetType": "COST",
  "TimeUnit": "MONTHLY",
  "BudgetLimit": { "Amount": "10", "Unit": "USD" },
  "CostTypes": {
    "IncludeCredit": false,
    "IncludeDiscount": true,
    "IncludeOtherSubscription": true,
    "IncludeRecurring": true,
    "IncludeRefund": false,
    "IncludeSubscription": true,
    "IncludeSupport": true,
    "IncludeTax": true,
    "IncludeUpfront": true,
    "UseBlended": false
  }
}
EOF
cat > notifications.json <<EOF
[
  { "Notification": { "ComparisonOperator": "GREATER_THAN", "NotificationType": "ACTUAL", "Threshold": 50, "ThresholdType": "PERCENTAGE" },
    "Subscribers": [ { "Address": "${ALERT_EMAIL:?set ALERT_EMAIL first}", "SubscriptionType": "EMAIL" } ] },
  { "Notification": { "ComparisonOperator": "GREATER_THAN", "NotificationType": "ACTUAL", "Threshold": 100, "ThresholdType": "PERCENTAGE" },
    "Subscribers": [ { "Address": "${ALERT_EMAIL:?set ALERT_EMAIL first}", "SubscriptionType": "EMAIL" } ] }
]
EOF
aws budgets create-budget --account-id "$ACCOUNT_ID" --budget file://budget.json --notifications-with-subscribers file://notifications.json
aws budgets describe-budget --account-id "$ACCOUNT_ID" --budget-name sandbox-monthly
aws budgets describe-subscribers-for-notification --account-id "$ACCOUNT_ID" --budget-name sandbox-monthly \
  --notification NotificationType=ACTUAL,ComparisonOperator=GREATER_THAN,Threshold=100,ThresholdType=PERCENTAGE \
  --query 'Subscribers[].Address'
```

Check: the second-last command prints the budget with a limit of 10 USD. The last
command prints your email address. If the address is wrong, delete the budget
with the command below, set `ALERT_EMAIL` again, and run the block again.

```bash
aws budgets delete-budget --account-id "${ACCOUNT_ID:?run the session block first}" --budget-name sandbox-monthly
```

A budget is an alert. It does not stop spending, and AWS updates its data only a
few times each day. `IncludeCredit` is `false` so that the free credits do not hide
real usage. A standalone account has no hard spend limit other than the Free plan.

## 3. Throwaway resources

Each emulation script changes one small resource and puts it back. Create these
resources once. Keep them empty. In a new session, run the block of step 2.2
first.

```bash
# TRR9019: a bucket. The script turns Block Public Access off, puts a public policy, and reverts.
aws s3api create-bucket --bucket "$TRR9019_BUCKET" --region us-east-1

# TRR9021 a: a bucket on which an ACL can be set.
aws s3api create-bucket --bucket "$TRR9021_BUCKET" --region us-east-1 --object-ownership BucketOwnerPreferred

# TRR9021 b: an event bus.
aws events create-event-bus --name "$TRR9021_BUS" --region us-east-1

# TRR9021 e: a Systems Manager document that does nothing.
cat > trr9021-doc.json <<'EOF'
{
  "schemaVersion": "2.2",
  "description": "trr9021 throwaway document. It does nothing.",
  "mainSteps": [
    { "action": "aws:runShellScript", "name": "noop", "inputs": { "runCommand": [ "echo trr9021" ] } }
  ]
}
EOF
aws ssm create-document --name "$TRR9021_DOC" --document-type Command --document-format JSON --content file://trr9021-doc.json --region us-east-1

# TRR9037: a role with no permissions, and a CA certificate whose key is deleted at once.
cat > trr9037-trust.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Principal": { "Service": "rolesanywhere.amazonaws.com" },
      "Action": [ "sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity" ] }
  ]
}
EOF
aws iam create-role --role-name trr9037-disposable-role --assume-role-policy-document file://trr9037-trust.json
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 7 \
  -keyout trr9037-ca.key -out "${TRR9037_CERT_PEM:?run the session block first}" \
  -subj "/CN=trr9037-throwaway-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
rm -f trr9037-ca.key
head -1 "$TRR9037_CERT_PEM"
```

Check: each `create` command prints the new resource. The last line prints
`-----BEGIN CERTIFICATE-----`.

Notes:

- Bucket names are global. That is why the account ID is in the name. The
  scripts have default names that are not yours. If a script shows a bucket name
  without your account ID, the variables are lost: run the block of step 2.2.
- The certificate is valid for 7 days. If you run TRR9037 later than that, run
  the `openssl` line and the `rm` line again.
- IAM needs some seconds to make a new role or a new access key known to each AWS
  service. If a command fails immediately after you made the role or the key that
  it uses, wait 15 seconds and run the same command again.
- TRR9016 (Cognito) and TRR9015 (GitHub OIDC role trust) make and delete their
  own resource. TRR9012 (a leaked key) has its own block in step 4.4. TRR9015
  needs the identity provider from step 5.1.
- TRR9032 and TRR9022 need an EKS cluster, and TRR9011 needs an EC2 instance. Those
  cost money by the hour. See [Optional](#7-optional-resources-that-cost-money).

## 4. Run one emulation by hand and read the record

### 4.1 Run TRR9019

First a dry run. It changes nothing.

```bash
bash atomics/T1537/src/emulate_aws_public_exposure.sh a
```

Check: the output has a line that starts with `(dry)`, and no line that starts
with `[live]`.

Then the live run. It makes the change and reverts it.

```bash
TRR9019_LIVE=1 bash atomics/T1537/src/emulate_aws_public_exposure.sh a
```

Check: the live run ends with `[live] reverted (BPA re-enabled, policy removed). Done.`
If it stops before that line, do step 4.5 now, then read step 4.6.

### 4.2 Read the record

CloudTrail records each management call with no setup and no charge. Wait about
five minutes, then:

```bash
aws cloudtrail lookup-events --region us-east-1 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy \
  --max-items 5 --query 'Events[].CloudTrailEvent' --output json \
  | jq 'map(fromjson)' > live-trr9019.json
jq 'map(.eventName)' live-trr9019.json
```

Check: the last command prints one `"PutBucketPolicy"` for each live run. If it
prints `[]`, wait some minutes more and run the block again. Each record in
`live-trr9019.json` starts with `eventVersion`, `userIdentity`, `eventTime`,
`eventSource`, `eventName`: the same shape as
[`detections/cloud/fixtures/trr9019/attack.json`](../../detections/cloud/fixtures/trr9019/attack.json).

For a different technique, change the event name and the file name. The table in
step 4.4 gives the event names.

### 4.3 Run the rule on the record

`detections/sigma_eval.py` is a library, not a command. The block below uses it.
It needs Python 3.10 or later, and the packages of the repository.

```bash
python3 --version
```

CloudShell is built on Amazon Linux 2023, whose `python3` is Python 3.9. If the
command prints a version lower than 3.10, do this step on your own computer.
Download the file (CloudShell > Actions > Download file >
`det-eng/live-trr9019.json`). On your computer, keep the file outside the clone of
the repository: a clone there has no exclude line, and the file holds your account
ID and IP address.

Run this block from the root directory of the repository. On your own computer,
give the path of the file in the place of `live-trr9019.json` in the second line.

```bash
python3 -m pip install -r detections/requirements.txt
python3 - live-trr9019.json <<'EOF'
import json, sys
sys.path.insert(0, "detections")
import sigma_eval
rule = "detections/sigma/T1537/aws_resource_policy_made_public.yml"
events = [sigma_eval.flatten(e) for e in json.load(open(sys.argv[1]))]
hits = sigma_eval.evaluate(sigma_eval.compile_rule(rule), events)
print(len(hits), "hit(s):", [h[0].get("eventName") for h in hits])
EOF
```

Check: the output is `1 hit(s): ['PutBucketPolicy']` for one live run. If the
output is `0 hit(s): []`, the rule or the fixture does not agree with the real
record. That is the finding that the sandbox is for. Keep the file, and make a
record of the finding.

If `pip` refuses to install into the system Python (`externally-managed-environment`),
make a virtual environment and run the block again:
`python3 -m venv ~/trr-venv && . ~/trr-venv/bin/activate`.

A live record holds your account ID, your IP address, your user name and the ID
of your access key. Do not commit it as it is. Make a copy, and replace each real
value with the value that the committed fixture
[`attack.json`](../../detections/cloud/fixtures/trr9019/attack.json) has in the
same field: the account ID `123456789012` (your account ID is also in the bucket
name and in each ARN), the address `198.51.100.23`, the key ID
`AKIAIOSFODNN7EXAMPLE`, the principal ID `AIDAEXAMPLE9019OPER` and the user name
`trr9019-operator`. [`AGENTS.md`](../../AGENTS.md) lists the safe markers.

Check: a search of the copy for your account ID, your IP address and
`sandbox-admin` finds nothing.

### 4.4 The other emulations

| Technique | Script under `atomics/` | Letter | Variable | Event names in CloudTrail |
|-----------|-------------------------|--------|----------|---------------------------|
| TRR9019 | `T1537/src/emulate_aws_public_exposure.sh` | `a` | `TRR9019_LIVE` | `PutBucketPublicAccessBlock`, `PutBucketPolicy` |
| TRR9021 | `T1537/src/emulate_aws_public_exposure_longtail.sh` | `a`, `b`, `e` | `TRR9021_LIVE` | `PutBucketAcl`, `PutPermission`, `ModifyDocumentPermission` |
| TRR9037 | `T1098.001/src/emulate_rolesanywhere.sh` | `a` | `TRR9037_LIVE` | `CreateTrustAnchor`, `CreateProfile` |
| TRR9016 | `T1078.004/src/emulate_aws_cognito.sh` | `d` | `TRR9016_LIVE` | `CreateIdentityPool` |
| TRR9015 | `T1098.001/src/emulate_aws_oidc.sh` | `c` | `TRR9015_LIVE` | `CreateRole` |
| TRR9012 | `T1078.004/src/emulate.sh` | `a` | `TRR9012_LIVE` | `GetCallerIdentity` |
| TRR9032 | `T1098.006/src/emulate_eks_access_entry.sh` | `a` | `TRR9032_LIVE` | `CreateAccessEntry`, `AssociateAccessPolicy` |
| TRR9022 | `T1550.001/src/emulate_eks_irsa_offpod.sh` | `a` | `TRR9022_LIVE` | `AssumeRoleWithWebIdentity`, `GetCallerIdentity` |
| TRR9011 | `T1552.005/src/emulate.sh` | `a` | `TRR9011_LIVE` | `GetCallerIdentity`, `DescribeInstances` |

The letter is the procedure. Each script prints the description of the procedure.
The scripts for TRR9019, TRR9016, TRR9015 and TRR9012 make the same live change
for each letter. The TRR9021 script has a live change for `a`, `b` and `e` only.
The last three rows need the resources of
[section 7](#7-optional-resources-that-cost-money).

```bash
# TRR9021 a (bucket ACL). Open the ACL block of the bucket, run, close it again.
aws s3api put-public-access-block --bucket "${TRR9021_BUCKET:?run the session block first}" --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
TRR9021_LIVE=1 bash atomics/T1537/src/emulate_aws_public_exposure_longtail.sh a
aws s3api put-public-access-block --bucket "${TRR9021_BUCKET:?run the session block first}" --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# TRR9021 b (event bus) and e (Systems Manager document).
TRR9021_LIVE=1 bash atomics/T1537/src/emulate_aws_public_exposure_longtail.sh b
TRR9021_LIVE=1 bash atomics/T1537/src/emulate_aws_public_exposure_longtail.sh e

# TRR9037 (IAM Roles Anywhere trust anchor).
TRR9037_LIVE=1 bash atomics/T1098.001/src/emulate_rolesanywhere.sh a

# TRR9016 (Cognito identity pool).
TRR9016_LIVE=1 bash atomics/T1078.004/src/emulate_aws_cognito.sh d
```

Check: each run ends with a line that starts with `[live] done`. The TRR9037 run
ends with `[live] revert done.` That line is not a sufficient check for TRR9037:
the script prints it also when a delete command of its revert step fails. Do
step 4.5 after the run.

TRR9015 needs the identity provider from step 5.1. Run it after that step.

```bash
TRR9015_ACCOUNT="${ACCOUNT_ID:?run the session block first}" TRR9015_LIVE=1 bash atomics/T1098.001/src/emulate_aws_oidc.sh c
```

Check: the run ends with `[live] done.`

TRR9012 (a leaked key) needs an access key of a user that can do nothing. The
block makes the key, uses it for one run, and deletes each key of that user. It
is the only long-lived key in the sandbox. AWS gives the secret of a key only
when it makes the key. Thus the block reads the secret into a variable at that
moment, and does not show it. The empty `AWS_SESSION_TOKEN` makes sure that the
run uses the key alone.

```bash
aws iam create-user --user-name trr9012-leaked-key-user
read -r KEY_ID KEY_SECRET < <(aws iam create-access-key --user-name trr9012-leaked-key-user \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
sleep 15
AWS_ACCESS_KEY_ID="${KEY_ID:?no key was made}" AWS_SECRET_ACCESS_KEY="$KEY_SECRET" AWS_SESSION_TOKEN= TRR9012_LIVE=1 bash atomics/T1078.004/src/emulate.sh a
unset KEY_ID KEY_SECRET
for k in $(aws iam list-access-keys --user-name trr9012-leaked-key-user --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name trr9012-leaked-key-user --access-key-id "$k"
done
aws iam list-access-keys --user-name trr9012-leaked-key-user --query 'AccessKeyMetadata[].AccessKeyId'
```

Check: the run prints an ARN that ends in `user/trr9012-leaked-key-user`, and the
last command prints `[]`. If the last command prints a key ID, run the three
`for` lines again. If the run stops at its first call with an error about the key
or the token, the key was not known yet: run the block again. The message that
the user exists is then normal.

### 4.5 After each live run: make sure that nothing stays behind

Most of the scripts stop at the first error and do not clean up after it. Run the
checks for the technique that you ran. The checks change nothing.

```bash
# TRR9019. Good: four times true, then an error that says that the bucket has no policy.
aws s3api get-public-access-block --bucket "$TRR9019_BUCKET" --query PublicAccessBlockConfiguration
aws s3api get-bucket-policy --bucket "$TRR9019_BUCKET"

# TRR9021 a. Good: four times true, then [].
aws s3api get-public-access-block --bucket "$TRR9021_BUCKET" --query PublicAccessBlockConfiguration
aws s3api get-bucket-acl --bucket "$TRR9021_BUCKET" --query 'Grants[].Grantee.URI'

# TRR9021 b. Good: null.
aws events describe-event-bus --name "$TRR9021_BUS" --query Policy

# TRR9021 e. Good: [].
aws ssm describe-document-permission --name "$TRR9021_DOC" --permission-type Share --query AccountIds

# TRR9016. Good: no line with trr9016Pool.
aws cognito-identity list-identity-pools --max-results 60 --query 'IdentityPools[].[IdentityPoolName,IdentityPoolId]' --output text

# TRR9015. Good: an error that says that the role cannot be found.
aws iam get-role --role-name trr9015-github-deploy --query Role.RoleName

# TRR9037. Good: no line that starts with trr9037-.
aws rolesanywhere list-trust-anchors --query 'trustAnchors[].[name,trustAnchorId]' --output text
aws rolesanywhere list-profiles --query 'profiles[].[name,profileId]' --output text

# TRR9012. Good: [], or an error that says that the user cannot be found.
aws iam list-access-keys --user-name trr9012-leaked-key-user --query 'AccessKeyMetadata[].AccessKeyId'
```

If a check is not good, run the block below. Each command puts one thing back. A
command for a thing that is already in order does nothing or prints an error.
Then run the checks again.

```bash
# TRR9019
aws s3api delete-bucket-policy --bucket "${TRR9019_BUCKET:?run the session block first}"
aws s3api put-public-access-block --bucket "${TRR9019_BUCKET:?run the session block first}" --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# TRR9021 a, b, e
aws s3api put-bucket-acl --bucket "${TRR9021_BUCKET:?run the session block first}" --acl private
aws s3api put-public-access-block --bucket "${TRR9021_BUCKET:?run the session block first}" --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
aws events remove-permission --event-bus-name "${TRR9021_BUS:?run the session block first}" --statement-id trr9021-open-bus
aws ssm modify-document-permission --name "${TRR9021_DOC:?run the session block first}" --permission-type Share --account-ids-to-remove All

# TRR9016: each identity pool with the name trr9016Pool
for p in $(aws cognito-identity list-identity-pools --max-results 60 --query 'IdentityPools[?IdentityPoolName==`trr9016Pool`].IdentityPoolId' --output text); do
  aws cognito-identity delete-identity-pool --identity-pool-id "$p"
done

# TRR9015
aws iam delete-role --role-name trr9015-github-deploy

# TRR9037: each profile and each trust anchor with a name that starts with trr9037-
for p in $(aws rolesanywhere list-profiles --query 'profiles[?starts_with(name, `trr9037-`)].profileId' --output text); do
  aws rolesanywhere delete-profile --profile-id "$p"
done
for t in $(aws rolesanywhere list-trust-anchors --query 'trustAnchors[?starts_with(name, `trr9037-`)].trustAnchorId' --output text); do
  aws rolesanywhere delete-trust-anchor --trust-anchor-id "$t"
done

# TRR9012: each access key of the throwaway user
for k in $(aws iam list-access-keys --user-name trr9012-leaked-key-user --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name trr9012-leaked-key-user --access-key-id "$k"
done
```

### 4.6 Things that can make a live run fail

- **The variables are lost.** The script shows a bucket name without your
  account ID, or refuses to run. Run the block of step 2.2.
- **TRR9019 and TRR9021 a: Block Public Access for the account.** A setting for
  the account applies to each bucket. See it:

  ```bash
  aws s3control get-public-access-block --account-id "$ACCOUNT_ID"
  ```

  The error `NoSuchPublicAccessBlockConfiguration` is the good result: the account
  has no setting, and nothing stops the scripts. If the command prints
  `"BlockPublicPolicy": true`, S3 refuses the public policy of TRR9019. If it
  prints `"BlockPublicAcls": true`, S3 refuses the public ACL of TRR9021 a. Then
  open these two settings before the run:

  ```bash
  aws s3control put-public-access-block --account-id "${ACCOUNT_ID:?run the session block first}" \
    --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=true"
  ```

  The other two settings stay `true`. With them, S3 ignores a public ACL, and it
  limits a bucket that has a public policy to the users of the account and to
  AWS services. So nothing is open to the internet during the run. The change is
  not immediate in each Region: if the run fails again, wait one minute. Close
  the settings after the run:

  ```bash
  aws s3control put-public-access-block --account-id "${ACCOUNT_ID:?run the session block first}" \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
  aws s3control get-public-access-block --account-id "$ACCOUNT_ID"
  ```

  Check: the last command prints four times `true`.
- **TRR9021 a.** The bucket must let an ACL be set. The first line of the block
  in step 4.4 does that for the bucket, and the third line reverts it.
- **TRR9021 e.** If `aws ssm get-service-setting --setting-id /ssm/documents/console/public-sharing-permission --region us-east-1`
  shows `Disable`, public sharing is blocked in the Region.
- **TRR9016 a** writes CloudTrail *data* events. Event history does not show them.
  The committed fixtures cover that procedure.
- **A new role or key.** See the IAM note in step 3.

## 5. Let GitHub Actions act in the account

First do all the steps of [The GitHub side](cloud-sandbox.md#the-github-side) in
`cloud-sandbox.md`. They create the environment `sandbox` with its rules, and they
give you your exact subject string.

This step lets a job in that environment sign in to the account as a role. The
role gets no permissions policy. The only job that uses the role is the smoke
test. It reads its own identity (`sts:GetCallerIdentity`), and AWS needs no
permission for that call.

### 5.1 Create the identity provider

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn'
```

Check: the last command prints an ARN that ends in
`:oidc-provider/token.actions.githubusercontent.com`. If the first command says
that the provider exists, that is normal for a second run.

### 5.2 Create the role, and trust one subject

Put the subject string into a shell variable. Use the `sub` value that the
`claims` run of the smoke test printed (see
[Find your exact subject string](cloud-sandbox.md#3-find-your-exact-subject-string)).
Do not build the value yourself. Replace the text between the quotation marks.

```bash
# for example repo:OWNER/REPO:environment:sandbox
SUBJECT='PASTE_THE_SUB_VALUE_HERE'
```

Write the trust policy.

```bash
cat > github-oidc-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "arn:aws:iam::${ACCOUNT_ID:?run the session block first}:oidc-provider/token.actions.githubusercontent.com" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "${SUBJECT:?set SUBJECT first}"
        }
      }
    }
  ]
}
EOF
```

Create the role, and read back what AWS stored.

```bash
aws iam create-role --role-name det-eng-sandbox-github-oidc --assume-role-policy-document file://github-oidc-trust.json
aws iam get-role --role-name det-eng-sandbox-github-oidc \
  --query 'Role.AssumeRolePolicyDocument.Statement[0].[Principal.Federated, Condition.StringEquals]'
aws iam list-attached-role-policies --role-name det-eng-sandbox-github-oidc --query 'AttachedPolicies[].PolicyName'
```

Check:

- The second command prints the ARN of the provider with your 12-digit account
  ID, then `sts.amazonaws.com`, then your subject. Compare the subject with the
  `sub` value of the run, character by character. If you see
  `PASTE_THE_SUB_VALUE_HERE`, you did not set `SUBJECT`.
- The last command prints `[]`: the role has no permissions policy.

If the stored subject is wrong, correct it in place. Do the same if a later
`claims` run prints a different `sub` value, for example after a change of the
subject format. Set `SUBJECT` again. Run the block that writes
`github-oidc-trust.json` again. Then:

```bash
aws iam update-assume-role-policy --role-name det-eng-sandbox-github-oidc --policy-document file://github-oidc-trust.json
aws iam get-role --role-name det-eng-sandbox-github-oidc \
  --query 'Role.AssumeRolePolicyDocument.Statement[0].[Principal.Federated, Condition.StringEquals]'
```

Rules:

- Use `StringEquals` for the two keys. Never `StringLike`, never `*`.
- No thumbprint is necessary. Older guides that calculate one are out of date.
- Do not attach a permissions policy to the role now. See
  [section 6](#6-later-when-a-reviewed-workflow-runs-the-emulations).
- Never make an access key for CI. The role has no long-lived credential.
- Before you rename, move or delete the repository or your GitHub account, delete
  the role (see [Teardown](#8-teardown)). A subject that holds only names can be
  made again by the person who takes a name that is free. After a rename or a
  move, do step 5.2 again with the new subject.

### 5.3 Store the values in the GitHub environment

In CloudShell, print the first command with the ARN of the role in it:

```bash
ROLE_ARN=$(aws iam get-role --role-name det-eng-sandbox-github-oidc --query Role.Arn --output text)
echo "gh secret set AWS_ROLE_ARN --env sandbox --repo OWNER/REPO --body \"${ROLE_ARN:?the role does not exist}\""
```

Copy the printed line to your own terminal, where `gh` is signed in as the owner
of the repository. Replace `OWNER/REPO` with your repository, and run the line.
Then run these lines in the same terminal:

```bash
gh variable set AWS_REGION --env sandbox --repo OWNER/REPO --body "us-east-1"
gh secret list --env sandbox --repo OWNER/REPO
gh variable list --env sandbox --repo OWNER/REPO
```

Check: the last two commands show `AWS_ROLE_ARN` and `AWS_REGION`.

Then run the smoke test with `aws`: see
[Test the federation](cloud-sandbox.md#test-the-federation).

## 6. Later: when a reviewed workflow runs the emulations

**Do not do this section now.** The workflow that runs the emulations in the
sandbox does not exist. [`AGENTS.md`](../../AGENTS.md) keeps live emulations out
of CI until that workflow is designed and reviewed. Until then the CI role needs
no permission. Without a permissions policy, AWS refuses each call of the role
that needs a permission. This section keeps the commands for that later day.

### 6.1 Permissions for the CI role

The role of that workflow needs the permissions of the emulations:
`AdministratorAccess`, or a narrower policy that the design of the workflow
gives.

```bash
aws iam attach-role-policy --role-name det-eng-sandbox-github-oidc --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

`AdministratorAccess` is acceptable only because the account is empty. With it, a
job in the environment `sandbox` can make users, access keys and roles. Do step
6.2 on the same day.

### 6.2 Cut the CI role off when the budget is exceeded

When spending passes the budget, AWS attaches `AWSDenyAll` to the CI role. Set
`ALERT_EMAIL` as in step 2.4, then run the block.

```bash
cat > budgets-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Principal": { "Service": "budgets.amazonaws.com" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "ArnLike": { "aws:SourceArn": "arn:aws:budgets::${ACCOUNT_ID:?run the session block first}:budget/*" },
        "StringEquals": { "aws:SourceAccount": "${ACCOUNT_ID}" }
      } }
  ]
}
EOF
aws iam create-role --role-name det-eng-sandbox-budget-action --assume-role-policy-document file://budgets-trust.json
cat > budgets-permissions.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Action": [ "iam:AttachRolePolicy", "iam:DetachRolePolicy" ],
      "Resource": "arn:aws:iam::${ACCOUNT_ID:?run the session block first}:role/det-eng-sandbox-github-oidc",
      "Condition": { "ArnEquals": { "iam:PolicyARN": "arn:aws:iam::aws:policy/AWSDenyAll" } } }
  ]
}
EOF
aws iam put-role-policy --role-name det-eng-sandbox-budget-action --policy-name budgets-apply-iam-policy --policy-document file://budgets-permissions.json
sleep 15
aws budgets create-budget-action --account-id "$ACCOUNT_ID" --budget-name sandbox-monthly \
  --notification-type ACTUAL --action-type APPLY_IAM_POLICY \
  --action-threshold ActionThresholdValue=100,ActionThresholdType=PERCENTAGE \
  --definition "IamActionDefinition={PolicyArn=arn:aws:iam::aws:policy/AWSDenyAll,Roles=[det-eng-sandbox-github-oidc]}" \
  --execution-role-arn "arn:aws:iam::${ACCOUNT_ID}:role/det-eng-sandbox-budget-action" \
  --approval-model AUTOMATIC \
  --subscribers SubscriptionType=EMAIL,Address="${ALERT_EMAIL:?set ALERT_EMAIL first}"
aws budgets describe-budget-actions-for-budget --account-id "$ACCOUNT_ID" --budget-name sandbox-monthly
```

Check: the last command lists one action of type `APPLY_IAM_POLICY`. If
`create-budget-action` fails, see the IAM note in step 3 and run that command
again.

What the action does, and what it does not do:

- It runs only after the billing data shows the overrun. That can be many hours
  later.
- It stops that one role. It does not stop a resource that already runs.
- It does not stop a user, an access key or a role that the CI role made before
  the action ran.

After the action ran, this command gives the role its permissions back:

```bash
aws iam detach-role-policy --role-name det-eng-sandbox-github-oidc --policy-arn arn:aws:iam::aws:policy/AWSDenyAll
```

If you think that a person misused the CI role, do not repair the account. Close
it (see [Teardown](#8-teardown)) and make a new one. To look first:

```bash
aws iam list-users --query 'Users[].[UserName,CreateDate]' --output table
aws iam list-roles --query 'Roles[].[RoleName,Path,CreateDate]' --output table
```

Check: the users are `sandbox-admin` and, if you made it,
`trr9012-leaked-key-user`. Each role is a role that this page made, or a role of
an AWS service: its path starts with `/aws-service-role/`.

The permissions policy of the budget role is narrower than the one in the AWS
documentation. That one permits the attach and detach actions for each role, user
and group, and the organization actions. The policy above permits the two role
actions, for the CI role and for `AWSDenyAll` only. It was not tried with a real
account. If AWS refuses the action, or if the action does not run, use the
documented policy ("Allow AWS Budgets to apply IAM policies and SCPs").

## 7. Optional: resources that cost money

Skip this section unless you want live records for TRR9032, TRR9022 or TRR9011. The
committed fixtures cover them. Delete each resource on the day that you make it.
These sequences are built from the AWS pages. They were **not confirmed from start
to end**.

**TRR9032 (EKS access entry).** A cluster costs 0.10 USD for each hour that it
exists, with or without nodes.

```bash
cat > eks-trust.json <<'EOF'
{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Principal": { "Service": "eks.amazonaws.com" }, "Action": "sts:AssumeRole" } ] }
EOF
aws iam create-role --role-name trr9032-eks-cluster-role --assume-role-policy-document file://eks-trust.json
aws iam attach-role-policy --role-name trr9032-eks-cluster-role --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy
SUBNETS=$(aws ec2 describe-subnets --region us-east-1 --filters Name=default-for-az,Values=true \
  --query 'Subnets[?AvailabilityZoneId!=`use1-az3`] | [0:2].SubnetId' --output text | tr '\t' ',')
echo "subnets: $SUBNETS"
```

Check: the last line shows two subnet IDs with a comma between them. They are the
default subnets of two Availability Zones. The command leaves out the zone
`use1-az3`: Amazon EKS does not accept a subnet in it.

```bash
aws eks create-cluster --region us-east-1 --name trr9032-cluster \
  --role-arn "arn:aws:iam::${ACCOUNT_ID:?run the session block first}:role/trr9032-eks-cluster-role" \
  --resources-vpc-config subnetIds="${SUBNETS:?no subnets found}" \
  --access-config authenticationMode=API_AND_CONFIG_MAP
aws eks wait cluster-active --region us-east-1 --name trr9032-cluster
aws eks describe-cluster --region us-east-1 --name trr9032-cluster --query "cluster.status"
```

Check: the last command prints `"ACTIVE"`. The `wait` command returns when the
cluster is ready. It waits for 20 minutes at most: if it stops with an error and
the status is `"CREATING"`, run it again. If `create-cluster` fails immediately,
see the IAM note in step 3. The `--access-config` option is necessary: a cluster
that the CLI makes has no access entries without it.

Then make a principal that can do nothing, and run the script:

```bash
cat > trr9032-principal-trust.json <<EOF
{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID:?run the session block first}:root" }, "Action": "sts:AssumeRole" } ] }
EOF
aws iam create-role --role-name trr9032-disposable-principal --assume-role-policy-document file://trr9032-principal-trust.json
sleep 15
TRR9032_LIVE=1 bash atomics/T1098.006/src/emulate_eks_access_entry.sh a
```

Check: the run ends with `[live] revert done.` The script prints that line also
when it cannot delete the access entry. The access entry is a part of the cluster
`trr9032-cluster`, and the next block deletes that cluster. It is not verified
that AWS removes each access entry together with its cluster.

Delete the cluster:

```bash
aws eks delete-cluster --region us-east-1 --name trr9032-cluster
aws eks wait cluster-deleted --region us-east-1 --name trr9032-cluster
aws eks list-clusters --region us-east-1 --query clusters
```

Check: the last command prints `[]`. The cluster costs money until then.

**TRR9022 (IRSA credentials used off the cluster)** needs the same cluster, its
OIDC provider, a role that trusts it, and a service-account token. **TRR9011
(instance credentials used off the instance)** needs one small EC2 instance with an
instance role. Both need steps that this guide could not confirm. Use the committed
fixtures for them until a person has run the sequence once and written it down.

## 8. Teardown

Run the block of step 2.2 first. Then run the checks of step 4.5. Run only the
blocks for the resources that you made.

The small resources:

```bash
aws s3api delete-bucket --bucket "${TRR9019_BUCKET:?run the session block first}" --region us-east-1
aws s3api delete-bucket --bucket "${TRR9021_BUCKET:?run the session block first}" --region us-east-1
aws events delete-event-bus --name trr9021-bus --region us-east-1
aws ssm delete-document --name trr9021-doc --region us-east-1
for k in $(aws iam list-access-keys --user-name trr9012-leaked-key-user --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name trr9012-leaked-key-user --access-key-id "$k"
done
aws iam delete-user --user-name trr9012-leaked-key-user
aws iam delete-role --role-name trr9037-disposable-role
rm -f "${TRR9037_CERT_PEM:?run the session block first}"
```

The optional resources of section 7:

```bash
aws eks delete-cluster --region us-east-1 --name trr9032-cluster
aws eks wait cluster-deleted --region us-east-1 --name trr9032-cluster
aws iam detach-role-policy --role-name trr9032-eks-cluster-role --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy
aws iam delete-role --role-name trr9032-eks-cluster-role
aws iam delete-role --role-name trr9032-disposable-principal
```

The budget action of section 6, if you made it:

```bash
for a in $(aws budgets describe-budget-actions-for-budget --account-id "${ACCOUNT_ID:?run the session block first}" --budget-name sandbox-monthly --query 'Actions[].ActionId' --output text); do
  aws budgets delete-budget-action --account-id "${ACCOUNT_ID:?run the session block first}" --budget-name sandbox-monthly --action-id "$a"
done
aws iam delete-role-policy --role-name det-eng-sandbox-budget-action --policy-name budgets-apply-iam-policy
aws iam delete-role --role-name det-eng-sandbox-budget-action
```

The CI federation of step 5. The loop detaches each policy that the role has
(`AdministratorAccess` from step 6.1, or `AWSDenyAll` if the budget action ran). A
role with an attached policy cannot be deleted.

```bash
for p in $(aws iam list-attached-role-policies --role-name det-eng-sandbox-github-oidc --query 'AttachedPolicies[].PolicyArn' --output text); do
  aws iam detach-role-policy --role-name det-eng-sandbox-github-oidc --policy-arn "$p"
done
aws iam delete-role --role-name det-eng-sandbox-github-oidc
aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "arn:aws:iam::${ACCOUNT_ID:?run the session block first}:oidc-provider/token.actions.githubusercontent.com"
```

Check that the roles, the user, the provider and the buckets of this page are
gone:

```bash
aws iam list-roles --query 'Roles[?starts_with(RoleName, `trr90`) || starts_with(RoleName, `det-eng-sandbox`)].RoleName'
aws iam list-users --query 'Users[?UserName!=`sandbox-admin`].UserName'
aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn'
aws s3api list-buckets --query 'Buckets[].Name'
```

Check: each command prints `[]`.

Then remove the stored values on the GitHub side. They are the secret
`AWS_ROLE_ARN` and the variable `AWS_REGION` in the environment `sandbox`. Run
these lines in your own terminal:

```bash
gh secret delete AWS_ROLE_ARN --env sandbox --repo OWNER/REPO
gh variable delete AWS_REGION --env sandbox --repo OWNER/REPO
gh secret list --env sandbox --repo OWNER/REPO
```

Check: the last command does not show `AWS_ROLE_ARN`.

Do not delete the environment `sandbox` while a cloud trusts it. The Azure trust
and the Google Cloud trust name the same environment. If the environment is
deleted, the first job that names it makes a new environment with no rule. Delete
the trust in each cloud first.

Keep the budget while the account is open. It is your alert. This command
deletes it:

```bash
aws budgets delete-budget --account-id "${ACCOUNT_ID:?run the session block first}" --budget-name sandbox-monthly
```

A user with an access key, a bucket that is not empty, and a role with an
attached policy cannot be deleted. The blocks above remove the keys and the
policies first. The buckets of this page are empty.

To close the account: sign in as the **root** user > account name > Account > Close
account. AWS keeps a closed account for 90 days, in which you can open it again,
and then deletes it. The root email address cannot be used for another AWS account.

## Costs

| Item | Cost | Source |
|------|------|--------|
| Account on the Free plan | 0 USD. 100 USD of credits at sign-up. Ends after 6 months or when the credits are used. | `docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/free-tier-plans.html` |
| CloudTrail Event history and `lookup-events` | No charge. 90 days of management events. | `aws.amazon.com/cloudtrail/pricing/` |
| CloudShell | No additional charge. | `docs.aws.amazon.com/cloudshell/latest/userguide/welcome.html` |
| Budgets and alerts; the first two budgets with an action | Free. | `aws.amazon.com/aws-cost-management/aws-budgets/pricing/` |
| Two empty buckets, an event bus without events, a Cognito identity pool | About 0 USD. | The S3, EventBridge and Cognito pricing pages |
| EKS cluster (optional) | 0.10 USD for each hour, about 2.40 USD for each day that you forget it. | `aws.amazon.com/eks/pricing/` |
| EC2 `t3.micro` with a public address (optional) | About 0.015 USD for each hour. | The AWS price list for `us-east-1` |

IAM, STS, Systems Manager documents and IAM Roles Anywhere are believed to have no
charge. No pricing page for them could be opened.

## Not verified

- No command was run against a real account. The AWS CLI parsed each `aws`
  command against a local recorder. The recorder was used with AWS CLI 1.46.3.
  CloudShell has AWS CLI version 2. The `aws s3control` commands put the account
  ID in the host name, so they cannot go to a local recorder: the CLI accepted
  them, and their request was built without a connection.
- The output that this page calls "good" in the checks (`[]`, `null`, the name of
  an error) is built from the service descriptions. No AWS service gave it.
- Which services the Free plan allows in an account from the advanced sign-up path.
  The documentation says "select AWS services". If a call is refused because of the
  plan, that technique needs the Paid plan.
- If `aws freetier get-account-plan-state` works for an IAM user before the root
  user turns on "Activate IAM Access" (root user > account name > Account).
- Whether account-level S3 Block Public Access is on in a new account, and the
  default of the Systems Manager public-sharing setting. Step 4.6 gives the
  commands that show them.
- That `openssl` is installed in CloudShell. The certificate command was run with
  OpenSSL 3.0.13 on another computer, and its output has the properties that IAM
  Roles Anywhere documents (X.509 version 3, SHA-256, `CA:TRUE`, certificate sign).
- The Python version of CloudShell. Its documentation names Amazon Linux 2023 and
  no Python version. Step 4.3 starts with a check for that reason.
- That 15 seconds are sufficient for a new role or key. AWS documents the delay
  and gives no time.
- If IAM refuses the role of TRR9015 when the identity provider of step 5.1 does
  not exist.
- Section 6: the narrowed permissions policy of the budget role, and if the
  manual detach of `AWSDenyAll` is equal to the documented reversal of an action.
- The optional EKS, IRSA and EC2 sequences of section 7, and the price of the EC2
  instance in the Costs table.
- The sign-up pages were not opened. Their wording and the address are from the
  AWS documentation.
