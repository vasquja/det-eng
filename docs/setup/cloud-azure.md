# Azure and Microsoft Entra sandbox

Part of [`cloud-sandbox.md`](cloud-sandbox.md). Read that page first: it explains
what the sandbox is for, the security rules, and the GitHub side.

Independent reviewers checked this page against primary sources on 2026-11-10: the
Microsoft documentation, the built-in help and the source of the Azure CLI 2.92.0,
and the scripts in this repository. **No command on this page was run against a
real tenant.** Each step has a check. If a check fails, stop and read the notes of
that step. [Not verified](#not-verified) lists what no source confirmed.

The text about the scripts for TRR9013, TRR9017 and TRR9023 was changed on
2026-11-11: steps 5.2 and 5.4, section 6, step 7.5 and the subsection "Later".
It was compared with the scripts and with Microsoft Learn. The Azure CLI was not
available for that comparison. For one item, the Python library that formats
the output of the Azure CLI (`knack` 0.14.0) was run on a local machine with no
account: see [Not verified](#not-verified).

Time: about 60 minutes. Then you wait for the first exported log record: some
minutes for the Activity log, and up to three days for the Entra logs. Cost: 0 USD
for the first 30 days. See [Costs](#costs).

Two words that this page uses:

- **Tenant.** Your directory in Microsoft Entra ID: the users, the applications and
  their sign-in records.
- **Subscription.** The container for Azure resources, and the unit that is billed.
  A subscription belongs to one tenant.

The emulations change both. That is why the sandbox is a new tenant with a new
subscription, and not a corner of a tenant that has real users.

How to read the commands:

- A word in capitals, such as `OWNER/REPO` or `NNNNNN`, is a placeholder. Replace it
  with your value. The text explains each placeholder where it occurs first.
- A word that starts with `$`, such as `$SUBSCRIPTION_ID`, is a shell variable. The
  block in [At the start of each session](#at-the-start-of-each-session) sets it.
  Do not type its value.
- The commands are for `bash`, the shell of Azure Cloud Shell.

## 1. Create the account

### 1.1 Use an identity that has never used Azure

Open a private browser window. Create a new personal Microsoft account (a new
`outlook.com` address) at `https://account.microsoft.com/account`. Do not use a work
or school account, and do not use an account that is a member of the tenant of your
employer.

A new personal account gets a new, empty tenant when it signs up for Azure, and you
become its Global Administrator. If the account already belongs to a tenant, the
subscription goes into that tenant. The test user, the Owner assignment of the
emulation and the tenant-wide log export on this page would then touch real people.

### 1.2 Sign up for the Azure free account

Go to `https://azure.microsoft.com/pricing/purchase-options/azure-account` and
select "Try Azure for free". Sign in with the new account. Azure asks for a profile
(the country must agree with the billing address of your card), a phone number and a
credit or debit card that is not prepaid.

Check: `https://portal.azure.com` opens. "Subscriptions" shows one subscription of
the type Free Trial, with a credit of 200 USD for 30 days. The credit can take up to
one hour to show.

If your card or phone number was used for Azure before, Azure gives you a
pay-as-you-go subscription. That subscription has **no spending limit**. You can
follow this page, but the budget in step 2.2 is then your only protection.

### 1.3 Write down three values

Azure portal > Subscriptions: the "Subscription ID". Azure portal > Microsoft Entra
ID > Overview: the "Tenant ID" and the "Primary domain" (it ends in
`.onmicrosoft.com`).

The block in [At the start of each session](#at-the-start-of-each-session) reads
the same values with the CLI into `$SUBSCRIPTION_ID`, `$TENANT_ID` and
`$TENANT_DOMAIN`. Your notes are the check that the shell works in the correct
tenant.

Check: the Overview page shows the licence "Microsoft Entra ID Free".

### 1.4 Check that multifactor authentication is on

Go to `https://entra.microsoft.com` > Entra ID > Overview > Properties > "Manage
security defaults". The setting must be "Enabled". Sign out, sign in again, and
register an authenticator app when Microsoft asks.

Check: each sign-in to the Azure portal asks for a second factor. Microsoft gives a
new tenant 24 hours before it enforces this. If Microsoft does not ask on the first
day, continue, and do this check again on the next day.

Do not turn security defaults off. Do not make a second administrator: you can
delete a tenant only when one user is left.

## 2. Guardrails

### 2.1 Keep the spending limit

A Free Trial subscription has a spending limit that is on by default. When the
credit is used, Azure stops your services and does not charge the card. It is the
only hard limit that Azure has.

Do not select "Upgrade" or the "remove spending limit" banner until you have read
step 2.3. The limit does not cover Microsoft Entra ID P1 or P2 licences, Marketplace
offers and support plans.

### 2.2 Create a budget with an email alert

Azure portal > Subscriptions > your subscription > Budgets > Add. Name
`trr-sandbox-budget`, reset period Monthly, amount `5`. Add alert conditions of the
type Actual at 50 %, 80 % and 100 %, and type your email address as the recipient.
Select Create.

Check: the Budgets page lists the budget with a spend of 0.

A budget is an alert. It does not stop spending. Azure compares the budget with the
cost data one time each day, and on a Free Trial or pay-as-you-go subscription that
data can be up to 72 hours old. On a new subscription the Budgets page can be empty
or show an error for up to 48 hours: come back later.

### 2.3 Decide what occurs on day 30

The Free Trial ends after 30 days. Azure then disables the subscription until you
upgrade it to pay-as-you-go. A sandbox that stays has no spending limit after that
day, for good. Thus:

- Make the budget in step 2.2 before you upgrade.
- When you upgrade, select the support plan "Basic". A paid support plan is a
  charge each month.
- Or delete the sandbox before day 30 ([Teardown](#8-teardown)) and make a new one
  when you need it.

### 2.4 Create only what this page lists

The only resource on this page that is billed is one storage account that holds a
few kilobytes of logs. Do not add a Log Analytics workspace, Microsoft Sentinel, an
Event Hub or a virtual machine. They are billed for each gigabyte or each hour.

## 3. Open a terminal: Azure Cloud Shell

Azure portal > the Cloud Shell icon in the top bar > Bash > "No storage account
required" > your subscription > Apply.

```bash
az account show --query "{tenantId:tenantId, subscriptionId:id, user:user.name}" -o json
```

Check: `tenantId` and `subscriptionId` are the values from step 1.3.

If Cloud Shell does not start: Azure portal > Subscriptions > your subscription >
Resource providers > search `cloudshell` > select `Microsoft.CloudShell` > Register.

A Cloud Shell session of this type keeps no files and no variables. It ends after 20
minutes without input, and the next session starts empty. That is why the next
section has one block that you run at the start of each session.

If a command fails with "subscription is not registered to use namespace", run
`az provider register --namespace NAMESPACE` and try again. `NAMESPACE` is the name
in the error message, for example `Microsoft.Storage` or `Microsoft.Insights`.

### If a command does not work in Cloud Shell

Cloud Shell signs you in with its own token service. If that service cannot give the
token that a command needs, the command stops with the error
`Audience ... is not a supported MSI token audience`, or with an authorization
error. Microsoft's page for this error tells you to run
`az login --use-device-code`. Do not do that. Security defaults block the device
code flow in each tenant that was created on 2026-07-01 or later. In a terminal
that has no browser, a plain `az login` changes to the same flow.

Use the Azure CLI on your computer:

1. Install the Azure CLI, version 2.72.0 or later. `az version` shows the version.
   An older version does not know the option `--assignee-object-id` of the delete
   commands on this page.
2. Use the shell `bash`. If `echo $0` does not show `bash`, type `bash` and press
   Enter. A different shell, such as `zsh`, does not read each line of this page
   in the same way.
3. Run `az login --tenant TENANT_ID`. Replace `TENANT_ID` with the tenant ID from
   step 1.3. A browser window opens for the sign-in. Always give `--tenant`, so that
   you never work in a different tenant by accident.
4. Run the block of the next section in that terminal. Then do the step that failed
   again.

## At the start of each session

This page calls the block below the session block. Run it at the start of each
session, and each time that a step tells you to. You can run it as many times as
you want: it creates nothing in Azure. It goes into your clone of the repository,
and it makes the clone only if the directory is missing. Then it reads the IDs of
the objects that exist into shell variables.

Replace `OWNER/REPO` in the first line with the owner and the name of your
repository on GitHub, for example your fork. Keep your copy of the block in a text
file on your computer.

```bash
REPO_URL=https://github.com/OWNER/REPO.git
CLONE="$HOME/$(basename "$REPO_URL" .git)"
[ -d "$CLONE" ] || GIT_TERMINAL_PROMPT=0 git clone "$REPO_URL" "$CLONE"
cd "$CLONE"
grep -qsxF 'live-*.json' "$CLONE/.git/info/exclude" \
  || printf '%s\n' 'live-*.json' PT1H.json credential.json >> "$CLONE/.git/info/exclude"

LOCATION=eastus
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)
TENANT_DOMAIN=$(az rest --method get --url "https://management.azure.com/tenants?api-version=2022-12-01" \
  --query "value[?tenantId=='$TENANT_ID'].defaultDomain | [0]" -o tsv)
SA_ID=$(az resource list --resource-type Microsoft.Storage/storageAccounts \
  --query "[?resourceGroup=='trr-sandbox-rg'].id | [0]" -o tsv)
SA=${SA_ID##*/}
APP_ID=$(az ad app list --display-name trr-sandbox-github-ci --query "[0].appId" -o tsv)
SP_OBJECT_ID=$(az ad sp list --display-name trr-sandbox-github-ci --query "[0].id" -o tsv)
export TRR9036_SUBSCRIPTION_ID="$SUBSCRIPTION_ID"
export TRR9036_ASSIGNEE_OBJECT_ID=$(az ad user list --display-name trr9036-test-user --query "[0].id" -o tsv)
export TRR9036_MANAGEMENT_GROUP_ID=trr9036-mg

printf '%-26s [%s]\n' "directory" "$PWD" "subscription" "$SUBSCRIPTION_ID" "tenant" "$TENANT_ID" \
  "tenant domain" "$TENANT_DOMAIN" "storage account (4.1)" "$SA_ID" \
  "test user (5.1)" "$TRR9036_ASSIGNEE_OBJECT_ID" "CI application (7.1)" "$APP_ID" \
  "CI service principal (7.1)" "$SP_OBJECT_ID"
```

Check, in the lines that the block prints last:

- `directory` ends with the name of your repository. If it does not, the address
  in the first line of the block is wrong. Correct it and run the block again.
- `subscription` and `tenant` show the IDs from step 1.3.
- `tenant domain` shows the primary domain from step 1.3. If its brackets are
  empty, set the value by hand: `TENANT_DOMAIN=NAME.onmicrosoft.com`. Replace
  `NAME.onmicrosoft.com` with your primary domain.
- Each of the last four lines names the step that creates its object. Its brackets
  are empty until you do that step. That is normal.

The block also tells Git to ignore the working files of this page in this clone:
`live-*.json`, `PT1H.json` and `credential.json`. They hold real IDs. Do not commit
from this clone.

## 4. Export the logs

Azure has two audit logs, and each rule reads one of them:

| Log | What it records | Techniques |
|-----|-----------------|------------|
| Entra audit log | Changes to applications, consent, users | TRR9013 a, TRR9017 a b c e |
| Entra sign-in logs | Sign-ins of users and of service principals | TRR9017 d, TRR9023 |
| Activity log of the subscription | Changes to Azure resources and role assignments | TRR9013 c, TRR9036 a |
| Activity log of a management group | Role assignments on a management group | TRR9036 b |

The portal and `az monitor activity-log list` show these logs in a different JSON
shape from the fixtures in this repository. The fixtures use the shape of a
**diagnostic setting** export (`time`, `resourceId`, `operationName`, `category`,
`properties`). You get that shape only from a diagnostic setting. That is why you
create a storage account.

### 4.1 Create the storage account

The name of a storage account must be unique in all of Azure: 3 to 24 lowercase
letters and digits. Replace `NNNNNN` in the second line with six digits of your
choice. If the second command says that the name is already taken, use other
digits and run the block again.

```bash
az group create --name trr-sandbox-rg --location "$LOCATION"
az storage account create -n trrsandboxNNNNNN -g trr-sandbox-rg -l "$LOCATION" --sku Standard_LRS --kind StorageV2
SA_ID=$(az resource list --resource-type Microsoft.Storage/storageAccounts \
  --query "[?resourceGroup=='trr-sandbox-rg'].id | [0]" -o tsv)
SA=${SA_ID##*/}
echo "$SA_ID"
```

Check: the last line prints an ID that starts with `/subscriptions/`, contains
`/resourceGroups/trr-sandbox-rg/` and ends with the name that you chose. If the line
is empty, wait one minute and run the session block again. Its line for the
storage account must show the ID.

Let yourself read the blobs. The Owner role does not include this:

```bash
ME=$(az ad signed-in-user show --query id -o tsv)
az role assignment create --assignee-object-id "${ME:?is empty, the lookup failed}" --assignee-principal-type User \
  --role "Storage Blob Data Reader" --scope "${SA_ID:?is empty, run the session block first}"
az role assignment list --assignee "$ME" --scope "${SA_ID:?is empty, run the session block first}" --query "[].roleDefinitionName" -o tsv
```

The guard on `SA_ID` is necessary. With an empty scope, the Azure CLI gives the
role on the full subscription.

Check: the last command prints `Storage Blob Data Reader`. A new role assignment
can take up to 10 minutes to work.

### 4.2 Send the Activity log of the subscription to the storage account

```bash
az monitor diagnostic-settings subscription create --name trr-activity-to-storage \
  --location "$LOCATION" --storage-account "$SA_ID" --logs "[{category:Administrative,enabled:true}]"
az monitor diagnostic-settings subscription list -o table
```

Check: the list shows `trr-activity-to-storage`.

Use the `subscription` sub-command. The plain `az monitor diagnostic-settings create`
is for one resource and does not export the Activity log.

### 4.3 Send the Entra logs to the storage account

`https://entra.microsoft.com` > Entra ID > Monitoring & health > Diagnostic
settings > Add diagnostic setting. Name `trr-entra-to-storage`. Select the category
`AuditLogs`. Select "Archive to a storage account", then your subscription and the
storage account. Save.

Check: the Diagnostic settings table lists `trr-entra-to-storage`.

The sign-in categories need a paid licence. See step 4.4.

Microsoft says that the first records can take up to three days to arrive after a
new setting. The export works when the storage account has a container whose name
starts with `insights-logs-`. The first command of the block in
[Read the exported record](#read-the-exported-record) lists the containers.

### 4.4 Optional: the licence for the sign-in logs

Skip this step unless you want live records for TRR9017 d or TRR9023. The committed
fixtures cover them.

Entra exports sign-in logs only for a tenant that has a Microsoft Entra ID P1 or P2
licence. Before you start, read the item about `admin.microsoft.com` in
[Not verified](#not-verified). To get a licence:

- **Trial.** Open the page "Sign up for Microsoft Entra ID P1 or P2 editions" on
  Microsoft Learn, signed in as the sandbox administrator, and follow the P2 trial
  link. Write down the end date that Microsoft shows.
- **Buy.** `https://admin.microsoft.com` > Billing > Purchase services > "Microsoft
  Entra ID P1" > one licence. The list price is 7 USD for each user each month,
  paid for one year at a time: 84 USD for one licence. The contract renews each
  year until you cancel it. The free credit and the spending limit do not cover it.

Then edit the setting from step 4.3 and select `SignInLogs`,
`NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs` and
`ManagedIdentitySignInLogs`.

A licence stops the deletion of the tenant until you cancel and delete it. See
[Teardown](#8-teardown).

### 4.5 Optional: the Activity log of a management group

Only for TRR9036 b, after you create the management group in step 5.3. There is no
portal page and no `az monitor` command for this setting, only the REST API:

```bash
az rest --method put \
  --url "https://management.azure.com/providers/microsoft.management/managementGroups/trr9036-mg/providers/microsoft.insights/diagnosticSettings/trr-mg-to-storage?api-version=2020-01-01-preview" \
  --body "{\"properties\":{\"storageAccountId\":\"${SA_ID:?is empty, run the session block first}\",\"logs\":[{\"category\":\"Administrative\",\"enabled\":true}]}}"
```

Check: the reply repeats the setting.

## 5. Throwaway resources

### 5.1 TRR9036: a user that no person signs in as

The emulation gives this user the Owner role on the subscription and removes it
again. For about one second the user is Owner. That is the test, and the reason
that the subscription must be empty.

Run this block one time:

```bash
az ad user create --display-name trr9036-test-user \
  --user-principal-name "trr9036-test-user@${TENANT_DOMAIN:?is empty, see the check of the session block}" \
  --password "Aa1-$(python3 -c 'import secrets; print(secrets.token_hex(20))')" --query id -o tsv
export TRR9036_ASSIGNEE_OBJECT_ID=$(az ad user list --display-name trr9036-test-user --query "[0].id" -o tsv)
echo "$TRR9036_ASSIGNEE_OBJECT_ID"
```

Check: the first command and the last line print the same GUID. If the last line is
empty, wait one minute and run the last two lines again. The password is random and
is not kept: no person signs in as this user.

### 5.2 TRR9013 c: a managed identity

There is nothing to create by hand. In a live run, procedure c of the TRR9013
script makes a resource group and a user-assigned managed identity. Their names
are `trr9013-rg-` and `trr9013-mi-`, with the date and time of the run. The
region is the value of `TRR9013_LOCATION`. If that variable is not set, the
region is `eastus`. The script adds the federated credential to the managed
identity. Then it removes the credential, the managed identity and the resource
group.

The script needs the permission to create and to delete a resource group in the
subscription. The Owner role on the subscription has it.

### 5.3 Optional: a management group for TRR9036 b

```bash
az account management-group create --name trr9036-mg
az account management-group show --name trr9036-mg --query name -o tsv
```

Check: the last command prints `trr9036-mg`. The first management group of a tenant
can take up to 15 minutes. If the last command gives an error, wait and run it
again. Do step 4.5 only after this check.

A user can create a management group and becomes its Owner. Leave the subscription
where it is: the new group stays empty. Do not use "elevate access" (the switch
"Access management for Azure resources"). It gives your account control of each
subscription in the tenant, and this page does not need it.

### 5.4 The other techniques

There is nothing to create by hand for TRR9013 a and for TRR9017. In a live
run, each script makes its own throwaway objects in the tenant, and removes them
at the end of the run. [The other emulations](#the-other-emulations) tells you
how to run them. TRR9023 has no run by hand: see step 7.5.

## 6. Run one emulation by hand and read the record

```bash
bash atomics/T1098.003/src/emulate_azure.sh a                  # dry run: changes nothing
TRR9036_LIVE=1 bash atomics/T1098.003/src/emulate_azure.sh a   # live: assign Owner, then revoke
```

Check: the live run prints `[live] assigning role ...` and then `[live] revoked.`

The TRR9036 script stops at the first error and does not clean up after it. If
the run stops before `[live] revoked.`, the Owner role of the test user can
stay. Then do the check below immediately.

### Make sure that nothing stays behind

Do this after each live run. The TRR9036 script has no cleanup step for an
error. The scripts for TRR9013 and TRR9017 run undo commands when a run stops.
An object can stay in two conditions: an undo command fails, or the run stops
during a command that makes a change.
[Problems in the live scripts](cloud-sandbox.md#problems-in-the-live-scripts)
describes the two conditions and the lines that the script prints for them.

```bash
az role assignment list --assignee "${TRR9036_ASSIGNEE_OBJECT_ID:?is empty, run the session block first}" --all -o table
az ad app list --display-name trr9013-victim-app --query "[].appId" -o tsv
az ad app list --filter "startswith(displayName,'trr9017-')" --query "[].appId" -o tsv
az ad sp list --filter "startswith(displayName,'trr9017-')" --query "[].id" -o tsv
az group list --query "[?starts_with(name,'trr9013-rg')].name" -o tsv
```

The two commands with `--filter` ask for each application and each service
principal whose display name starts with `trr9017-`. The TRR9017 script accepts
only such a name, so that includes an object that a run with `TRR9017_APP_NAME`
made.

Check: each command prints nothing. Only if you ran TRR9036 b, do this check
also. `--all` shows the assignments under the subscription, and `trr9036-mg` is not
under it:

```bash
az role assignment list --assignee "${TRR9036_ASSIGNEE_OBJECT_ID:?is empty, run the session block first}" \
  --scope /providers/Microsoft.Management/managementGroups/trr9036-mg -o table
```

If a command prints a row, remove what it shows. A role assignment on the
subscription:

```bash
az role assignment delete --assignee-object-id "${TRR9036_ASSIGNEE_OBJECT_ID:?is empty, run the session block first}" \
  --scope "/subscriptions/${SUBSCRIPTION_ID:?is empty, run the session block first}"
```

A role assignment on the management group:

```bash
az role assignment delete --assignee-object-id "${TRR9036_ASSIGNEE_OBJECT_ID:?is empty, run the session block first}" \
  --scope /providers/Microsoft.Management/managementGroups/trr9036-mg
```

An application. Replace `APP_ID_FOUND` with the ID that the list command printed.
Microsoft says that the delete of an application also deletes its service
principal in the same tenant:

```bash
az ad app delete --id APP_ID_FOUND
```

A service principal that stays after its application is deleted. Replace
`SP_ID_FOUND` with the ID that the `az ad sp list` command printed:

```bash
az ad sp delete --id SP_ID_FOUND
```

A resource group of TRR9013 c. The script makes one resource group for each run
and removes it. This block is for a run that did not complete its undo commands.
The block deletes each resource group whose name starts with `trr9013-rg`, with
its managed identity and its federated credential:

```bash
for rg in $(az group list --query "[?starts_with(name,'trr9013-rg')].name" -o tsv); do
  az group delete --name "$rg" --yes
done
```

A grant or an app role assignment of TRR9017. If the output of the run has a
line that starts with `[live] LEFT BEHIND, this command failed:`, that line
shows the undo command that failed. Run that command again. You can do this for
each undo command of the TRR9013 and TRR9017 scripts.

A line that has the text `LEFT BEHIND: the application` is different. The script
has no ID for that application, only its display name, and `az ad app delete --id`
does not accept a display name. The TRR9017 script prints the two commands for
this condition: an `az ad app list` command that prints the object ID, and the
delete command. For TRR9013, use the list commands and the delete command above.

Notes:

- The delete of an application is a soft delete. Entra keeps the application for
  30 days. You find it in the Entra admin center: Entra ID > App registrations >
  the tab "Deleted applications". The `az ad app list` commands above do not
  show it. That is normal.
- Do this check before the first live run of a session too. The header of the
  TRR9013 script says that `az` uses an application with the same display name
  again. The script then deletes that application at the end of the run.

**Warning.** `az role assignment delete` removes each assignment that agrees with
its arguments. An empty `--assignee-object-id` is not an error: the command then
removes each role assignment at the scope, and your own Owner role is one of them.
That is why these commands have the form `${NAME:?...}`. The shell then stops the
command when the variable is empty. Do not remove that form.

### Read the exported record

Wait 20 minutes (longer on the first day). Cloud Shell can end during the wait: then
run the session block again. The block below downloads the newest blob and writes
the records in the shape of the fixtures. Its first three lines set the container,
a part of `operationName` in lowercase letters, and the file that the block writes:

```bash
C=insights-activity-logs
NEEDLE='roleassignments/write'
OUT=live-trr9036.json
az storage container list --account-name "$SA" --auth-mode login --query "[].name" -o tsv
BLOB=$(az storage blob list --account-name "$SA" --auth-mode login -c "$C" \
  --query "sort_by([], &properties.lastModified)[-1].name" -o tsv)
az storage blob download --account-name "$SA" --auth-mode login -c "$C" -n "$BLOB" -f PT1H.json -o none
python3 - PT1H.json "$NEEDLE" > "$OUT" <<'EOF'
import json, sys
text = open(sys.argv[1]).read()
try:
    data = json.loads(text)
    records = data.get("records", [data]) if isinstance(data, dict) else data
except ValueError:
    records = [json.loads(line) for line in text.splitlines() if line.strip()]
needle = sys.argv[2].lower()
kept = [r for r in records if needle in str(r.get("operationName", "")).lower()]
print(json.dumps(kept, indent=2))
print(len(kept), "of", len(records), "record(s) kept:", [r.get("resultType") for r in kept], file=sys.stderr)
EOF
```

Check: the last line that the block prints is
`2 of N record(s) kept: ['Start', 'Success']`. `N` is the number of records in the
blob. `live-trr9036.json` is then a JSON array of two records. The record with
`resultType` `Start` has `properties.requestbody`: the same shape as
[`detections/cloud/fixtures/trr9036/attack.json`](../../detections/cloud/fixtures/trr9036/attack.json).

For a different technique, change the first three lines of the block:

| Record | `C` | `NEEDLE` | `OUT` |
|--------|-----|----------|-------|
| TRR9036 a | `insights-activity-logs` | `'roleassignments/write'` | `live-trr9036.json` |
| TRR9013 a | `insights-logs-auditlogs` | `'update application'` | `live-trr9013.json` |
| TRR9013 c | `insights-activity-logs` | `'federatedidentitycredentials/write'` | `live-trr9013-mi.json` |
| TRR9017 a | `insights-logs-auditlogs` | `'consent to application'` | `live-trr9017-a.json` |
| TRR9017 b and e | `insights-logs-auditlogs` | `'add delegated permission grant'` | `live-trr9017-grant.json` |
| TRR9017 c | `insights-logs-auditlogs` | `'add app role assignment to service principal'` | `live-trr9017-c.json` |
| TRR9017 d | `insights-logs-noninteractiveusersigninlogs` | `''` | `live-trr9017-d.json` |
| The sign-in of the smoke test (step 7.5) | `insights-logs-serviceprincipalsigninlogs` | `''` | `live-trr9023.json` |

For a record of the Entra logs (the rows TRR9013 a, TRR9017 and the sign-in), the
list in the last line shows `None`, for example `1 of 1 record(s) kept: [None]`.
That is normal: those records have no `resultType` at the top level. The number
of records that were kept is the check. For TRR9017 a, b, c and e, the check is
one record or more.

The row TRR9017 d needs the licence of step 4.4, and a tenant that does not
block the device code flow: see [The other emulations](#the-other-emulations).
The file holds each sign-in of the blob. The record of procedure d has
`"authenticationProtocol": "deviceCode"`. If the file does not have it, read
the container `insights-logs-signinlogs` in the same way.

Notes:

- An exported blob has one JSON record on each line. It is not a JSON array. The
  Python lines above change it into the array that the fixtures use.
- If the container does not exist, no record was exported yet. Wait, and list
  again.
- If a storage command is refused because a permission is missing, the role
  assignment of step 4.1 is missing or is less than 10 minutes old.
- Keep the quotation marks around the value of `NEEDLE`. The value `''` (nothing
  between the quotation marks) keeps each record.
- A live record holds your real tenant ID, subscription ID, object IDs, IP address
  and sign-in name. Do not commit it as it is. Before a record goes into the
  repository, replace each real value with the value that the committed fixture of
  the same technique has in that field. For TRR9036 the fixture is
  `detections/cloud/fixtures/trr9036/attack.json`: subscription
  `11111111-2222-3333-4444-555555555555`, tenant
  `6f1d2c3b-4a5e-4f60-9b8a-7c6d5e4f3a2b`, IP address `198.51.100.91`, name
  `trr9036-attacker@example.com`. For a value that the fixture does not have, use
  the markers that [`AGENTS.md`](../../AGENTS.md) lists.

### Run the rule on the record

[`detections/sigma_eval.py`](../../detections/sigma_eval.py) is a library, not a
command. The lines below use it. They need Python 3.10 or later and the packages of
`detections/requirements.txt`.

The Cloud Shell page of Microsoft lists Python 3.9. If the first line below prints a
version before 3.10, use a clone on your computer. Download the file: Cloud Shell >
Manage files > Download, and type the full path of the file (the `directory` value
of the session block, then `/live-trr9036.json`). Keep the file outside the
repository, and give its path in place of `live-trr9036.json`.

From the root of the repository:

```bash
python3 --version
python3 -m pip install -r detections/requirements.txt
python3 - live-trr9036.json <<'EOF'
import json, sys
sys.path.insert(0, "detections")
import sigma_eval
rule = "detections/sigma/T1098.003/azure_privileged_role_assignment.yml"
events = [sigma_eval.flatten(e) for e in json.load(open(sys.argv[1]))]
hits = sigma_eval.evaluate(sigma_eval.compile_rule(rule), events)
print(len(hits), "hit(s):", [h[0].get("resultType") for h in hits])
EOF
```

Check: the last line is `1 hit(s): ['Start']`. The rule fires on the record that has
the request body. If the line is `0 hit(s): []`, the rule or the fixture does not
agree with the real record. That is the result that the sandbox is for: write it
down.

If `pip` refuses to install into the system Python (`externally-managed-environment`),
make a virtual environment and run the block again:
`python3 -m venv ~/trr-venv && . ~/trr-venv/bin/activate`.

### The other emulations

The scripts for TRR9013 and TRR9017 change the tenant that `az` is signed in to.
The TRR9013 script has no variable for the tenant. The TRR9017 script requires
`TRR9017_TENANT`, but it does not compare the value with the tenant of `az`.
Thus compare them yourself. Run the session block, and then:

```bash
export TRR9017_TENANT="${TENANT_ID:?is empty, run the session block first}"
az account show --query tenantId -o tsv
echo "$TRR9017_TENANT"
```

Check: the two lines that the block prints are the same, and they show the
tenant ID of step 1.3. If they do not, stop: the shell works in a different
tenant.

Run one line at a time. Read the last lines of the output before you run the
next line.

**TRR9013** a (an application) and c (a managed identity):

```bash
TRR9013_LIVE=1 bash atomics/T1098.001/src/emulate_entra.sh a
TRR9013_LIVE=1 bash atomics/T1098.001/src/emulate_entra.sh c
```

Check: the last line of each run is `[live] done.`

- Procedure a registers the application `trr9013-victim-app`. It adds a
  federated credential with the issuer
  `https://oidc.trr9013-attacker.example.com`. Then it removes the credential
  and the application.
- Procedure c makes a resource group and a managed identity: see step 5.2. Its
  last undo command deletes the resource group. `az` waits for that deletion.
- The subject of the credential is an exact value. Microsoft documents that a
  wildcard is not supported in a subject.

**TRR9017** b, c and e. No person is necessary. Wait one minute between two
runs: each run registers an application with the same name.

```bash
TRR9017_LIVE=1 bash atomics/T1528/src/emulate_entra_consent.sh b
TRR9017_LIVE=1 bash atomics/T1528/src/emulate_entra_consent.sh c
TRR9017_LIVE=1 bash atomics/T1528/src/emulate_entra_consent.sh e
```

Check: the last line of each run is `[live] done.`

- Each run registers the application `trr9017-illicit-consent-app` and its
  service principal. The application has no secret and no certificate.
- Procedure b creates a delegated permission grant for all users of the tenant
  (consent type `AllPrincipals`). Procedure e creates the same grant for the
  user that `az` is signed in as (consent type `Principal`). The script calls
  Microsoft Graph with `az rest`. The scopes are
  `offline_access Mail.ReadWrite Mail.Send Files.ReadWrite.All`.
- Procedure c gives the application permission `Mail.Read` of Microsoft Graph to
  the service principal (an app role assignment).
- Then each run removes the grant or the assignment, the service principal and
  the application.

**TRR9017 a.** A person must accept the consent in a browser. Run this line
alone. Do not paste it together with a different line: the script waits for the
Enter key, and a pasted line is an answer to it.

```bash
TRR9017_LIVE=1 bash atomics/T1528/src/emulate_entra_consent.sh a
```

1. The script prints a URL. Open the URL in a private browser window.
2. Sign in as the sandbox administrator. See the note about the user below.
3. The page shows the permissions that the application requests. Do not select
   "Consent on behalf of your organization". Select Accept.
4. The browser goes to `http://localhost` and shows an error. That is normal.
5. Go back to the terminal and press Enter.

Check: the script prints `a delegated grant now exists`, and its last line is
`[live] done.` If the script prints `no delegated grant was found`, it caused no
record. It then removes its application and ends with exit 1.

The note about the user. On a new tenant, a user who is not an administrator
cannot accept the default scopes: the default consent policy of Microsoft
refuses `Mail.ReadWrite` and `Files.ReadWrite.All` for such a user (Microsoft
Learn, "Manage app consent policies"). The script prints this, and the two ways
below. The sandbox of this page has no user who is not an administrator and that
a person can sign in as. Thus use one of these two ways:

- Sign in as the sandbox administrator, as the steps above tell you. An
  administrator can accept the default scopes.
- Or sign in as a user who is not an administrator, and give the script scopes
  that such a user can accept. The rule reads `Mail.Send`. This page has no
  step that makes such a user.

  ```bash
  TRR9017_SCOPES='offline_access Mail.Send' TRR9017_LIVE=1 bash atomics/T1528/src/emulate_entra_consent.sh a
  ```

**TRR9017 d.** Do not run procedure d in the sandbox of this page. Security
defaults block the device code flow in each tenant that was created on
2026-07-01 or later, and step 1.4 tells you to keep security defaults on. The
script then ends with exit 1. Its message says that no sign-in was started, or
that no successful sign-in was recorded. The rule reads only a sign-in that is
successful. Use the committed fixture.

On a tenant that does not block the flow, the line is the same as for the other
procedures, with the letter `d`. The script uses `curl`, not `az`. It prints a
URL and a code. A person opens the URL, types the code and signs in. The script
does not print the token, and it does not change the account of the shell. The
device code (the secret that the token request uses) goes to `curl` on its
standard input, not on a command line, and the script does not print it. A
good run prints `device-code sign-in SUCCEEDED`. It has no `[live] done.` line.
If the person does not sign in during 60 requests (about 5 minutes), or if Entra
refuses the sign-in, the script ends with exit 1. A refused sign-in can leave a
sign-in record with an error code. The rule does not read that record.
With `TRR9017_DEVICECODE_POLL=1`, the script also waits for the sign-in when it
has no terminal. With no terminal and without that variable, the script prints
the code, does not wait, and ends with exit 1.

**TRR9036 b** needs steps 4.5 and 5.3:

```bash
TRR9036_LIVE=1 bash atomics/T1098.003/src/emulate_azure.sh b
```

Check: the live run prints `[live] revoked.`

Then do [Make sure that nothing stays behind](#make-sure-that-nothing-stays-behind)
again.

Things that can make a live run fail, or give no record:

- **`TRR9017_TENANT` is not set.** The TRR9017 script stops before the first
  change with exit 2, and names the variable. It uses no placeholder tenant.
- **`TRR9017_APP_NAME` does not start with `trr9017-`.** For a, b, c and e, the
  script stops before the first change with exit 2. If one application with the
  same display name is in the tenant, `az` uses it again, and the undo then
  deletes it. (With two or more such applications, `az` stops with an error.) Do not set this variable unless you need a second name.
- **A create command does not give one ID.** If `az ad sp create` or one of the
  two `POST` requests ends with exit 0 and its answer is not one ID (it is
  empty, or it holds a character that is not a letter, a digit, `-` or `_`),
  the script stops with exit 1. It
  has no undo command for that change, and it names the change in the line
  `[live] The run stopped before the undo of this change was registered:`. It
  runs the undo commands of the earlier changes: it deletes the application,
  and the service principal if the script has its ID. Do the check that
  nothing stays behind. That check has no command for a grant or an app role
  assignment. It is not known if Entra removes them when the service principal
  is deleted.
- **Entra does not find a new object.** A new application can need some seconds
  before the next `az` command finds it. That command then fails. The script
  runs its undo commands and prints `[live] FAILED`. Do the check that nothing
  stays behind, wait one minute, and run the line again.
- **TRR9017 a, no acceptance.** If no person accepts, or if the script has no
  terminal, the script says that no record was caused. It removes its
  application and ends with exit 1.
- **TRR9017 a, a stop after you accepted.** After you accept the consent, press
  Enter: the script then reads the grant that you made and removes it. If you
  stop the run at the prompt (Ctrl-C) after you accepted, the grant has no undo
  command, and the script cannot name it. If the read of the grant fails or is
  stopped, the script names the grant in the line
  `[live] The run stopped before the undo of this change was registered:`. In
  each of these conditions the script deletes the service principal and the
  application. It is not verified that this also removes the grant.
- **TRR9017 a, a user who is not an administrator.** See the note about the
  user above.
- **TRR9017 d, the device code flow is blocked.** See above.
- **An application with the same name is there before the run.** Do the check
  that nothing stays behind before the first run.
- **A run that stops.** The scripts for TRR9013 and TRR9017 run the undo
  commands of the changes that they made, and print `[live] FAILED`. An object
  can stay in two conditions. In the first, an undo command fails: the script
  prints `[live] LEFT BEHIND`. In the second, the run stops during a command
  that makes a change: the script prints
  `[live] The run stopped before the undo of this change was registered:`. In
  each condition, do the check that nothing stays behind.
- **TRR9036.** The script has no cleanup step for an error. A run that stops
  between the assignment and the revoke leaves the role assignment.

[Problems in the live scripts](cloud-sandbox.md#problems-in-the-live-scripts)
describes the undo commands and the exit codes, and lists what is open for all
providers.

## 7. Let GitHub Actions sign in to the subscription

First do each step of
[The GitHub side](cloud-sandbox.md#the-github-side) in `cloud-sandbox.md`. One of
them gives you the exact subject string: the `sub` value that the `claims` run of
the smoke test prints. See
[Find your exact subject string](cloud-sandbox.md#3-find-your-exact-subject-string).
Use only the value from that run. Do not build the string by hand.

The identity that you make here is for CI. It can sign in and read. It can change
nothing. No workflow in the repository needs more today.

### 7.1 Create the application for CI

Run the session block first. Then:

```bash
az ad app create --display-name trr-sandbox-github-ci --query appId -o tsv
APP_ID=$(az ad app list --display-name trr-sandbox-github-ci --query "[0].appId" -o tsv)
az ad sp create --id "${APP_ID:?is empty, wait one minute and run the block again}" --query id -o tsv
SP_OBJECT_ID=$(az ad sp list --display-name trr-sandbox-github-ci --query "[0].id" -o tsv)
echo "client id: $APP_ID   service principal object id: $SP_OBJECT_ID"
```

Check: the last line prints two GUIDs. If one is missing, wait one minute and run
the block again. In a second run, `az ad sp create` can give an error because the
service principal exists. That error is not a problem.

Do not make a client secret or a certificate for this application. Do not use
`az ad sp create-for-rbac`: it makes a secret.

### 7.2 Trust the environment `sandbox`, and nothing else

Set the subject. Replace `PASTE_THE_SUB_VALUE_HERE` with the `sub` value from the
`claims` run. Keep the quotation marks:

```bash
SUBJECT='PASTE_THE_SUB_VALUE_HERE'      # for example repo:OWNER/REPO:environment:sandbox
```

Then create the credential:

```bash
cat > credential.json <<EOF
{
  "name": "github-environment-sandbox",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "${SUBJECT:?is empty, set it first}",
  "description": "GitHub Actions, environment sandbox",
  "audiences": ["api://AzureADTokenExchange"]
}
EOF
az ad app federated-credential create --id "${APP_ID:?is empty, run the session block first}" --parameters credential.json
az ad app federated-credential list --id "$APP_ID" --query "[].{name:name, subject:subject, issuer:issuer, audiences:audiences}" -o json
echo "you set: $SUBJECT"
```

Check: the list shows one credential. Its `subject` is the `sub` value from the
`claims` run, character by character. Its `issuer` has no `/` at the end.

If the stored subject is wrong, correct it in place. Do not add a second
credential. First set `SUBJECT` again with the first block of this step, with the
correct value. Then run:

```bash
[ "${SUBJECT:?is empty, set it first}" != PASTE_THE_SUB_VALUE_HERE ] && \
az ad app federated-credential update --id "${APP_ID:?is empty, run the session block first}" \
  --federated-credential-id github-environment-sandbox \
  --parameters "{\"subject\": \"${SUBJECT:?is empty, set it first}\"}"
az ad app federated-credential list --id "$APP_ID" --query "[].subject" -o tsv
```

Check: the last command prints one line, the correct subject.

Rules:

- Entra compares the subject character by character. A wrong subject gives no
  error now. The sign-in fails later with `AADSTS700213`, or with `AADSTS7002138`
  if only the letter case is different. The sign-in step of the smoke test prints
  the subject of the token as `subject claim`. Compare it with the stored subject.
- The error `AADSTS70021` can occur in the first minutes after you create or change
  the credential. Wait and try again.
- One credential only. Never add one with a branch or pull-request subject. Do not
  use the "flexible federated identity credential" preview: it is there to permit
  patterns.
- Before you rename, move or delete the repository or your GitHub account, delete
  the CI application: see [Teardown](#8-teardown). A trust for a name that you do
  not hold is a risk.

### 7.3 Give the application the Reader role

```bash
az role assignment create --assignee-object-id "$SP_OBJECT_ID" --assignee-principal-type ServicePrincipal \
  --role Reader --scope "/subscriptions/$SUBSCRIPTION_ID"
az role assignment list --assignee "$SP_OBJECT_ID" --all --query "[].{role:roleDefinitionName, scope:scope}" -o table
```

Check: one row, `Reader` on `/subscriptions/` and your subscription ID.

The smoke test signs in and reads the state of the subscription. The sign-in
action finds the subscription only if the application has a role on it. `Reader` can
read the configuration of resources. It cannot change a resource, read the content
of a blob, or give a role. Give the application no other role, no permission in
Microsoft Graph and no directory role.

### 7.4 Store the values and check that there is no key

In Cloud Shell, print the three `gh` commands with your values:

```bash
printf 'gh secret set %s --env sandbox --repo OWNER/REPO --body "%s"\n' \
  AZURE_CLIENT_ID "$APP_ID" AZURE_TENANT_ID "$TENANT_ID" AZURE_SUBSCRIPTION_ID "$SUBSCRIPTION_ID"
```

Check: the block prints three lines. Each line has a GUID between the quotation
marks.

Copy the three lines to a terminal on your computer in which `gh` is signed in as
the owner of the repository. Replace `OWNER/REPO` in each line with your
repository, and run the lines. Then, in the same terminal:

```bash
gh secret list --env sandbox --repo OWNER/REPO
```

Check: the list shows `AZURE_CLIENT_ID`, `AZURE_SUBSCRIPTION_ID` and
`AZURE_TENANT_ID`.

In Cloud Shell:

```bash
az ad app credential list --id "$APP_ID" -o json
az ad app credential list --id "$APP_ID" --cert -o json
```

Check: each command prints `[]`. The first command lists the secrets, and the
second command lists the certificates. The application has no secret and no
certificate. The only way to sign in as it is a GitHub token from the environment
`sandbox`.

Then run the smoke test with `azure`: see
[Test the federation](cloud-sandbox.md#test-the-federation). A new role assignment
can take up to 10 minutes to work. If the sign-in step fails with "No subscriptions
found", wait and run the test again.

### 7.5 TRR9023: read the sign-in of the smoke test

TRR9023 changes an OIDC token of a different issuer for an Entra token. A person
has no such issuer, so you cannot run
`atomics/T1078.004/src/emulate_entra_sp_fic_signin.sh` live by hand. No workflow in
the repository runs it, and [`AGENTS.md`](../../AGENTS.md) keeps live emulations out
of CI. Do not add a job that runs it.

What a live run of procedure a of the script does:

- It requires `TRR9023_TENANT`, `TRR9023_APPID` and `TRR9023_OIDC_TOKEN`. Without
  one of them, it stops with exit 2 and makes no request. It uses no
  placeholder ID.
- It sends the OIDC token to `curl` on the standard input, not on a command
  line. It does not print the Entra token.
- It reads the HTTP status. If Entra refuses the request, the script prints the
  error of Entra and ends with exit 1. It prints `[live] done.` only after a
  successful sign-in.
- It changes nothing in the tenant. Thus it does not hold the undo block.

Procedures b, c and d have no live run. For them, a live run makes no request,
prints `no record was caused` and ends with exit 1. The dry mode of b, c and d
ends with exit 0, as for each valid letter.

You do not need the script to get a real record. The `azure` run of the smoke test
is a federated sign-in of the CI application. With the licence of step 4.4, Entra
exports that sign-in in the category `ServicePrincipalSignInLogs`. Read it with the
block in [Read the exported record](#read-the-exported-record) and the last row of
its table. Then compare the record with
[`detections/cloud/fixtures/trr9023/attack.json`](../../detections/cloud/fixtures/trr9023/attack.json).

Check: the real record has `properties.federatedCredentialId`, as the fixture has.

### Later: when a reviewed workflow runs the emulations

**Do not do this subsection now.** A workflow that runs the emulations in the
sandbox does not exist. [`AGENTS.md`](../../AGENTS.md) keeps live emulations out of
CI until such a workflow is designed and reviewed. The smoke test needs only the
Reader role of step 7.3.

This subsection is a record of what the identity of that workflow needs. Each item
gives the CI application more power than it has now.

**A role that can write role assignments (TRR9036), and the permission to make
and to delete a resource group and a managed identity (TRR9013 c).** The role
Owner has both:

```bash
az role assignment create --assignee-object-id "$SP_OBJECT_ID" --assignee-principal-type ServicePrincipal \
  --role Owner --scope "/subscriptions/$SUBSCRIPTION_ID"
```

Owner is acceptable only because the subscription is empty. TRR9036 must be able
to write a role assignment, and only a privileged role can do that. Never give a
role on a management group or on `/`, with one exception: for TRR9036 b, give "User
Access Administrator" on `trr9036-mg` only.

A narrower choice than Owner is the role "Role Based Access Control Administrator"
with a condition that permits only the role Owner for the user of step 5.1.
Microsoft shows such conditions in "Examples to delegate Azure role assignment
management with conditions". TRR9013 c then needs a second role. That role must
permit the workflow to make and to delete a resource group in the subscription,
and a managed identity in that group. A role on one resource group is not
sufficient: the script makes a resource group with a different name for each
run. This page has no tested command for that choice.

**Blob read, to collect the exported records:**

```bash
az role assignment create --assignee-object-id "${SP_OBJECT_ID:?is empty, run the session block first}" --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Reader" --scope "${SA_ID:?is empty, run the session block first}"
az role assignment list --assignee "$SP_OBJECT_ID" --all -o table
```

Check: three rows. Reader and Owner on the subscription, and Storage Blob Data
Reader on the storage account.

**The Microsoft Graph permission `Application.ReadWrite.OwnedBy`, with admin
consent (TRR9013 a).** To register and delete an application is a directory
action. Azure roles do not cover it.

```bash
# Microsoft Graph is 00000003-0000-0000-c000-000000000000.
# 18a4783c-866b-4cc7-a460-3d5e5662c884 is Application.ReadWrite.OwnedBy:
# the application can manage only the applications that it made.
az ad app permission add --id "$APP_ID" --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 18a4783c-866b-4cc7-a460-3d5e5662c884=Role
az ad app permission admin-consent --id "$APP_ID"
```

Check: Entra admin center > Entra ID > App registrations >
`trr-sandbox-github-ci` > API permissions shows `Application.ReadWrite.OwnedBy` with
the status "Granted".

- The first command prints a warning that tells you to run
  `az ad app permission grant`. Ignore it. That command is for delegated
  permissions. The `admin-consent` line is the correct one for this permission.
- If `admin-consent` fails in Cloud Shell, give the consent in the browser: on the
  API permissions page of the check, select the button "Grant admin consent for"
  your tenant, and confirm.
- Do not give `Application.ReadWrite.All`. It can change each application in the
  tenant.
- TRR9017 stays a run by hand. Procedures a and d need a person. Procedures b
  and e create a delegated permission grant, and procedure c creates an app role
  assignment. For these calls, Microsoft Graph requires the application
  permissions `DelegatedPermissionGrant.ReadWrite.All` (b, e), and
  `AppRoleAssignment.ReadWrite.All` with `Application.Read.All` (c).
  `Application.ReadWrite.OwnedBy` does not cover them. Do not give these
  permissions to the CI application. Microsoft says that an application with
  `AppRoleAssignment.ReadWrite.All` can give more privileges to itself.
- Procedure e of TRR9017 also reads the user that `az` is signed in as. A
  workflow identity is not a user.

## 8. Teardown

Run the session block first, and read its check. Teardown runs in a new session, and
a new session has no variables.

The CI application (step 7). Only if you did the subsection "Later", run this line
first:

```bash
az role assignment delete --assignee-object-id "${SP_OBJECT_ID:?is empty, run the session block first}" \
  --scope "${SA_ID:?is empty, run the session block first}"
```

Then:

```bash
az role assignment delete --assignee-object-id "${SP_OBJECT_ID:?is empty, run the session block first}" \
  --scope "/subscriptions/${SUBSCRIPTION_ID:?is empty, run the session block first}"
az ad app delete --id "${APP_ID:?is empty, run the session block first}"
```

The test user, the log export and the resource groups:

```bash
az ad user delete --id "${TRR9036_ASSIGNEE_OBJECT_ID:?is empty, run the session block first}"
az monitor diagnostic-settings subscription delete --name trr-activity-to-storage --yes
for rg in $(az group list --query "[?starts_with(name,'trr9013-rg')].name" -o tsv); do
  az group delete --name "$rg" --yes
done
az group delete --name trr-sandbox-rg --yes
```

A line that stops with the message `is empty` did nothing. That is correct if you
did not do the step that makes the object. If you did the step, run the session
block again, and then the line. The warning in
[Make sure that nothing stays behind](#make-sure-that-nothing-stays-behind) applies
here also: never run `az role assignment delete` with an empty value.

`az group delete --name trr-sandbox-rg` deletes each exported log. Download the
records that you want to keep first.

Only if you made the management group:

```bash
az rest --method delete \
  --url "https://management.azure.com/providers/microsoft.management/managementGroups/trr9036-mg/providers/microsoft.insights/diagnosticSettings/trr-mg-to-storage?api-version=2020-01-01-preview"
az account management-group delete --name trr9036-mg
```

Then:

```bash
az resource list -o table
```

Check: the command prints nothing.

Delete the Entra diagnostic setting in the Entra admin center: Entra ID >
Monitoring & health > Diagnostic settings > Edit setting > Delete.

Delete the three secrets, from the terminal on your computer. Replace `OWNER/REPO`
with your repository:

```bash
gh secret delete AZURE_CLIENT_ID --env sandbox --repo OWNER/REPO
gh secret delete AZURE_TENANT_ID --env sandbox --repo OWNER/REPO
gh secret delete AZURE_SUBSCRIPTION_ID --env sandbox --repo OWNER/REPO
gh secret list --env sandbox --repo OWNER/REPO
```

Check: the last command shows no name that starts with `AZURE_`.

To close the sandbox fully, in this sequence:

1. **Licence.** If you started a P1 or P2 trial or bought a licence:
   `https://admin.microsoft.com` > Billing > Your products > the product > Cancel
   subscription, and then Delete. You can delete the tenant 72 hours after this
   Delete, not before.
2. **Subscription.** Azure portal > Subscriptions > your subscription > Cancel.
   Three days later the same page offers Delete.
3. **Tenant.** `https://entra.microsoft.com` > Entra ID > Overview > Manage
   tenants > select the tenant > Delete. The page runs checks and shows what stops
   the deletion: more than one user, an application, a subscription that is
   cancelled but not deleted, or a licence. You cannot undo the deletion. Your
   personal Microsoft account stays.

## Costs

| Item | Cost | Source |
|------|------|--------|
| Azure free account | 0 USD. 200 USD of credit for 30 days. The card is not charged unless you upgrade. | `azure.microsoft.com/pricing/purchase-options/azure-account` |
| After day 30 | The subscription is disabled until you upgrade to pay-as-you-go. Then you pay for use above the free amounts, with no spending limit. | `learn.microsoft.com/azure/cost-management-billing/manage/avoid-charges-free-account` |
| Microsoft Entra ID Free: the tenant, users, applications, the audit log | Free. | `www.microsoft.com/security/business/microsoft-entra-pricing` |
| Microsoft Entra ID P1 (optional, for the sign-in logs) | 7 USD for each user each month, paid for one year at a time: 84 USD for one licence. The contract renews each year. P2 is 10 USD each month (120 USD). Outside the credit and the spending limit. | The same page |
| Storage account for the logs | Billed for each gigabyte. This page stores kilobytes: less than 0.01 USD each month. The exact rate was not read. | `azure.microsoft.com/pricing/details/storage/blobs/` |
| Activity log, budgets, Cloud Shell | No charge. | `learn.microsoft.com/azure/azure-monitor/fundamentals/activity-log` |
| Diagnostic settings | Microsoft says that a diagnostic setting can have a cost that depends on the destination and the volume. The price list of Azure Monitor was not read. This page exports kilobytes. | `learn.microsoft.com/azure/azure-monitor/data-collection/diagnostic-settings` |

Resource groups, role assignments, a managed identity and a management group are
believed to have no charge. No pricing page that says so for each of them was
opened.

## Not verified

- No command was run against a real tenant or in a real Cloud Shell. Command and
  option names were checked against the built-in help and the source of the Azure
  CLI 2.92.0 and against the Microsoft documentation.
- The sequence and the wording of the sign-up pages, and that a card or a phone
  number that was used before gives a pay-as-you-go subscription.
- That a new personal Microsoft account gets a new tenant at the sign-up. No
  documentation page says so directly.
- Whether each `az ad` command works with the Cloud Shell sign-in of a personal
  Microsoft account. Microsoft's page for federated credentials runs
  `az ad app federated-credential` commands in Cloud Shell. Whether Cloud Shell can
  get the token for `az ad app permission admin-consent` is not known. Step 3 gives
  the alternative.
- The lookups of the session block in a real session: that the request `tenants` of
  Azure Resource Manager gives the primary domain, and how fast a new object shows
  in `az resource list` and in the `az ad ... list` commands. The checks tell you to
  wait and to try again.
- That the command name is `python3` in Cloud Shell. The Cloud Shell page lists
  Python 3.9 and not the command name.
- The names of the containers for the Entra categories. The documented pattern is
  `insights-logs-<category>`. That is why the block in step 6 lists the containers.
- How long an Entra record takes to arrive after the first one, and whether a
  tenant on the Free edition refuses a setting that includes the sign-in
  categories or accepts it and exports nothing.
- For a management group: the path of the exported records, and whether the
  record has `properties.requestbody`.
- Whether Microsoft Graph refuses a federated credential subject that has a `*`.
  Microsoft documents that a wildcard is not supported in a property value of a
  federated credential. It also documents that an incorrect subject is created
  without an error and fails only at a token exchange. The TRR9013 script uses
  an exact subject.
- That a live run of TRR9013 or TRR9017 causes the record that the paired rule
  reads, and that each undo command reverts its change. The tests in
  [`atomics/tests/`](../../atomics/tests/README.md) show the sequence of the
  commands with stub programs. A stub accepts each command. For TRR9017, a live
  run must show these three records:
  - "Add delegated permission grant" for the request
    `POST /oauth2PermissionGrants` (b, e);
  - "Add app role assignment to service principal" for the request
    `POST .../appRoleAssignedTo` (c);
  - "Consent to application" for the consent of a person in a browser (a).
- That Microsoft Graph accepts the two `POST` requests of TRR9017 from the
  sign-in of this sandbox. The Graph reference says "Not supported" for a
  personal Microsoft account. The sandbox administrator is a personal Microsoft
  account that signs in to its own tenant. It is not known if Graph treats that
  sign-in differently. It is also not known if the token that `az rest` sends
  has the permissions that the two requests need.
- For TRR9017 a: what the consent page shows to the sandbox administrator, and
  what it shows to a user who is not an administrator.
- For TRR9017 a: that a personal Microsoft account can sign in at the consent
  URL of the application.
- That `az ad app create` uses an application with the same display name again.
  The header of the TRR9013 script says so. The Microsoft Learn page of the
  command does not.
- How `az ad app create --query "[id, appId]" -o tsv` prints the two IDs, in a
  run of `az`. The TRR9017 script reads the object ID and the application ID
  from that one answer. Microsoft Learn ("Set shell variables from Azure CLI
  output") says that the values of such a list are on separate lines, and it
  reads them in Bash with `read -d ''`. The script uses that form. It accepts a
  newline or a tab between the two IDs, and it stops with exit 1 if the answer
  does not have two values. The Python library `knack` formats the output of the
  Azure CLI: the package `azure-cli-core` 2.92.0 requires `knack` 0.14. That
  library was run on a local machine with no account. For a list of two values,
  its `tsv` format prints two lines. `az` itself was not run.
- That the delete of a service principal also removes its delegated permission
  grants and its app role assignments. The TRR9017 script removes them first.
- The two list commands with `--filter "startswith(displayName,'trr9017-')"` in
  [Make sure that nothing stays behind](#make-sure-that-nothing-stays-behind).
  The reference of `az ad app list` and of `az ad sp list` has the option
  `--filter` (an OData filter). No run against a tenant was done.
- How frequently the next `az` command does not find a new application
  (replication delay) in a real tenant. The script then runs its undo commands
  and prints `[live] FAILED`.
- For TRR9017 d: the error that a tenant with security defaults gives, and the
  endpoint that gives it (the device code request or the token request). The
  script prints its hint about security defaults only if the error description
  has the text `blocked`, `security default` or `conditional access`. Also not
  verified: the container that holds a device code sign-in. The research report
  of TRR9017 says that most such sign-ins are in `NonInteractiveUserSignInLogs`.
- What stays in the tenant when Ctrl-C stops an `az` command that makes a
  change. The script names that change. The check that nothing stays behind
  finds an application, a service principal and a resource group. It has no
  command for a grant or an app role assignment of a service principal that
  was deleted.
- The length of the P2 trial and its number of users.
- Whether the personal Microsoft account of step 1.1 can sign in to
  `admin.microsoft.com` for the licence (step 4.4 and Teardown). An answer on
  Microsoft Q&A says that a personal account cannot. That answer is not a
  documentation page. If it is correct, use the committed fixtures for the sign-in
  logs.
- That a budget is available on a Free Trial subscription from the first day.
- Whether the export of a diagnostic setting to a storage account has its own
  charge for each gigabyte.
- Whether an application or a user that you deleted, and that Entra keeps for some
  time in its list of deleted objects, stops the deletion of the tenant.
- The narrower role of the subsection "Later" (Role Based Access Control
  Administrator with a condition). No command for it was written or tested.
