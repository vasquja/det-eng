#!/usr/bin/env python3
"""
Validate the external-cloud detection loops against recorded log fixtures.

Sibling of validate_apiserver_detections.py (Kubernetes), for the cloud TRRs that
key on a provider audit log instead of the Kubernetes API server audit log:

  * TRR9011 (T1552.005, AWS)   - EC2 instance-role creds used off-instance (CloudTrail)
  * TRR9012 (T1078.004, AWS)   - leaked long-term access-key recon (CloudTrail)
  * TRR9013 (T1098.001, Azure) - Entra app FIC backdoor (Entra audit log) + the
                                 managed-identity FIC variant (Azure Activity Log)
  * TRR9014 (T1098.003, GCP)   - public IAM grant allUsers/allAuthenticatedUsers
                                 (Cloud Audit Logs)
  * TRR9015 (T1098.001, AWS)   - GitHub-OIDC role-trust abuse (CloudTrail)

There is no free live cloud to run the attacks against, so (per the project's chosen
cloud-validation approach) each technique ships two committed, schema-faithful log
fixtures -- an ATTACK set and a BENIGN baseline -- and the paired Sigma rule is run
over them with the SAME real pySigma SQLite backend the Kubernetes validators use
(detections/sigma_eval.py). The fixtures are 'representative recorded logs': every
field path is a real field of the provider's audit log, grounded on the provider's
own schema docs and real samples (see each TRR's References), with only safe markers
(RFC 5737 TEST-NET IPs, RFC 2606 example.com, the AWS doc account 123456789012, and
trr90NN- resource names).

The loop this proves, for each rule:

    a recorded attack event -> the paired Sigma rule, run by pySigma, matches it
    (and the match carries the emulation's own marker)
    AND the benign baseline -> the same rule matches nothing (negative control)

Both fixtures that MANIFEST names for a rule must be files, and the benign baseline
must hold a record: a negative control that read no record cannot fail, so it proves
nothing. A fixture that is missing or that the loader cannot read (load_fixture())
gives an ERROR row that names it, and a baseline without a record gives a FAIL row
with `NEGATIVE CONTROL VACUOUS`. Each fails the run (exit 1),
also with --report. The count is the number of records that load_fixture() returns,
which is the set that the rule is run on (no filter stands between the file and the
rule): `[]`, a file of zero bytes or of blank lines, and an envelope with an empty
list (`{"Records": []}`) hold no record.

A baseline that holds records must also be HARD (roadmap item R2e): one record or
more must be a near-miss or a filtered negative of the rule (sigma_explain.NON_TRIVIAL)
through a flip item that
  (a) some marked attack hit (a record of the attack fixture that fires the rule and
      carries the marker) differs from the record on: the item, which reads one
      field, holds on the one and fails on the other;
  (b) is a filter, or reads a field outside check_sufficiency.SURFACE_FIELDS, or
      belongs to a rule in check_sufficiency.CHOKEPOINT; and
  (c) if it is a filter, does not hold on the record only through documentation
      addresses (RFC 5737, RFC 3849): such an allowlist entry is a placeholder for
      the operator's own ranges, so a record that only it filters proves nothing.
For a correlation rule the unit is the event set, and only a near-miss on a base
atom (base:<ref>) counts: a repair of the group-by, the timespan, the order or the
threshold moves the same events. A baseline without such a record gives a FAIL row
with `NEGATIVE CONTROL NOT HARD`, and a baseline that sigma_explain cannot grade a
FAIL row with `NEGATIVE CONTROL NOT GRADED` (fail closed). Each fails the run (exit
1), also with --report. A benign hit on the only hard record leaves no hard record,
so that row is NOT HARD too, also with --report. The check compares with the marked
attack hits: a rule that has none fails for its attack, and its baseline is not
judged.

A MANIFEST entry whose rule file does not exist is PENDING: the run prints it, does
not count it, and does not fail on it. (check_sufficiency.py fails that tree.)

The benign baseline is the control. It is built to hit the same log source / method /
structural fields as the attack and to differ only on the discriminating field (the
off-instance source IP, the identity type, the FIC issuer, the public vs specific
principal, the pinned vs wildcard OIDC subject). The HARD check (above) asks it for
one such record: one flip from firing, through a discriminating item on which a
marked attack hit differs. It does not check each record, or each branch of the
rule. So a PASS shows that the rule keys on that item, not only on the fixture's
shape or marker.

One exception: the TRR9013 managed-identity FIC rule reads the Azure Activity Log,
which carries no issuer/subject, so that rule is a broad signal with no field to
discriminate on. Its benign baseline is therefore a different administrative operation
on the same identity (proving the rule is specific to the FIC-write operationName, not
that it separates a good issuer from a bad one), not an "issuer differs only" control.

Modes:
    --dry-run       Compile every cloud rule; no fixtures needed.
    --report        Report misses instead of failing on them. A miss is a rule that
                    did not fire on a marked record of its attack fixture, or that
                    fired on a benign record. --report does not waive a missing
                    fixture, or a benign baseline that holds no record, holds no
                    hard record (also when the rule fires on the only hard record)
                    or cannot be graded.
    --json PATH     Also write a machine-readable report (status, detail and the
                    explanation lines of every rule) to PATH.

A failing rule is explained beneath its FAIL line (sigma_explain.py): an attack
miss shows each detection block's per-item counts and the attack records that
came closest, item by item; a marker-gate miss shows the gate's fields and their
values on the hits; a benign hit shows the record and why the rule fired on it.
Every rule also gets one line grading its benign records (how many are near-misses,
filtered look-alikes, distant or trivial) and how many of the rule's condition atoms
they exercise; the hard-baseline check reads that grade. A NOT HARD row also names
each near-miss or filtered flip that does not count, and why.
"""

import argparse
import glob
import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402
# sigma_explain explains a failure and grades each benign baseline. The grade decides
# the hard-baseline check, so a sigma_explain that does not import fails each row as
# NOT GRADED (fail closed); the run still judges every rule.
try:
    import sigma_explain  # noqa: E402
    _EXPLAIN_ERROR = None
except Exception as _e:  # noqa: BLE001
    sigma_explain = None
    _EXPLAIN_ERROR = f"sigma_explain failed to import: {type(_e).__name__}: {_e}"
    print(f"[diag] no explanations: {_EXPLAIN_ERROR}")
# The hard-baseline check counts what R2 of check_sufficiency.py counts as
# discriminating: SURFACE_FIELDS and CHOKEPOINT. There is no import cycle:
# check_sufficiency.py imports this module only inside load_manifests().
try:
    import check_sufficiency  # noqa: E402
    _SUFFICIENCY_ERROR = None
except Exception as _e:  # noqa: BLE001
    check_sufficiency = None
    _SUFFICIENCY_ERROR = f"check_sufficiency failed to import: {type(_e).__name__}: {_e}"
    print(f"[diag] no hard-baseline check: {_SUFFICIENCY_ERROR}")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA = os.path.join(REPO, "detections", "sigma")
FIX = os.path.join(REPO, "detections", "cloud", "fixtures")


def marker(substr, *fields):
    """Gate: at least one of the named flattened fields contains substr."""
    def gate(e):
        return any(substr in str(e.get(f) or "") for f in fields)
    gate.substr, gate.fields = substr, fields  # for the failure explanation
    return gate


# (trr, attack-id folder, rule file, attack fixture, benign fixture, provider, note, gate)
MANIFEST = [
    ("TRR9011", "T1552.005", "aws_imds_creds_used_off_instance.yml",
     "trr9011/attack.json", "trr9011/benign.json", "AWS",
     "EC2 instance-role creds used off-instance",
     marker("trr9011-ssrf-demo-role", "userIdentity.sessionContext.sessionIssuer.userName",
            "userIdentity.arn")),
    ("TRR9012", "T1078.004", "aws_leaked_access_key_recon.yml",
     "trr9012/attack.json", "trr9012/benign.json", "AWS",
     "leaked long-term access-key orientation + enumeration",
     marker("trr9012-leaked-key-user", "userIdentity.userName", "userIdentity.arn")),
    ("TRR9013", "T1098.001", "entra_app_federated_credential_backdoor.yml",
     "trr9013/attack.json", "trr9013/benign.json", "Azure",
     "Entra app FIC from an unapproved issuer",
     marker("oidc.trr9013-attacker.example.com", "properties.targetResources")),
    ("TRR9013", "T1098.001", "azure_managed_identity_federated_credential_backdoor.yml",
     "trr9013/attack_mi.json", "trr9013/benign_mi.json", "Azure",
     "managed-identity FIC (Azure Activity Log)",
     marker("TRR9013-MI-BACKDOOR", "resourceId")),
    ("TRR9014", "T1098.003", "gcp_public_iam_member_grant.yml",
     "trr9014/attack.json", "trr9014/benign.json", "GCP",
     "public IAM grant (allUsers / allAuthenticatedUsers)",
     marker("trr9014-public-exposure-demo", "protoPayload.resourceName")),
    ("TRR9015", "T1098.001", "aws_github_oidc_role_trust_abuse.yml",
     "trr9015/attack.json", "trr9015/benign.json", "AWS",
     "GitHub-OIDC role-trust abuse (over-broad sub)",
     marker("trr9015-", "requestParameters.roleName", "requestParameters.policyDocument",
            "userIdentity.arn")),
    # A wildcard after a pinned repository in the sub is graded low by its own rule; the
    # high rule above keeps the wildcard before a repository pin and the absent sub. This
    # rule's only attack record (role trr9015-github-release) is synthetic and
    # documentation-derived (GitHub Docs sub formats); no emulation step writes it.
    ("TRR9015", "T1098.001", "aws_github_oidc_role_trust_ref_wildcard.yml",
     "trr9015/attack.json", "trr9015/benign.json", "AWS",
     "GitHub-OIDC role trust with a ref wildcard on a pinned repo (low)",
     marker("trr9015-", "requestParameters.roleName", "requestParameters.policyDocument",
            "userIdentity.arn")),
    # --- Round 2: TRR9016-9019 (external-cloud identity & exposure chokepoints) ---
    ("TRR9016", "T1078.004", "aws_cognito_unauthenticated_identity_use.yml",
     "trr9016/attack.json", "trr9016/benign.json", "AWS",
     "Cognito unauthenticated (guest) identity-pool credential use",
     # Gate on the emulation's own pool name, not on 'Unauth': the rule itself keys
     # on the Cognito 'Unauth' role naming, so a marker of 'Unauth' would prove nothing.
     marker("trr9016", "userIdentity.sessionContext.sessionIssuer.userName",
            "requestParameters.roleArn")),
    ("TRR9016", "T1078.004", "aws_cognito_identity_pool_unauth_enabled.yml",
     "trr9016/attack.json", "trr9016/benign.json", "AWS",
     "Cognito identity pool configured to allow unauthenticated identities",
     marker("trr9016Pool", "requestParameters.identityPoolName")),
    ("TRR9017", "T1528", "entra_illicit_oauth_consent_grant.yml",
     "trr9017/attack.json", "trr9017/benign.json", "Azure",
     "Entra illicit OAuth consent grant to high-privilege scopes",
     marker("trr9017", "properties.targetResources")),
    ("TRR9017", "T1528", "entra_device_code_authentication.yml",
     "trr9017/attack_signin.json", "trr9017/benign_signin.json", "Azure",
     "Entra device-code authentication (companion phishing signal)",
     marker("TRR9017", "properties.id")),
    ("TRR9018", "T1098.001", "gcp_workload_identity_federation_sa_binding.yml",
     "trr9018/attack.json", "trr9018/benign.json", "GCP",
     "GCP SA bound to a Workload Identity Federation principalSet",
     marker("trr9018", "protoPayload.resourceName")),
    ("TRR9018", "T1098.001", "gcp_workload_identity_pool_provider_created.yml",
     "trr9018/attack.json", "trr9018/benign.json", "GCP",
     "GCP WIF pool provider created without an attribute condition",
     marker("trr9018", "protoPayload.resourceName")),
    ("TRR9019", "T1537", "aws_resource_policy_made_public.yml",
     "trr9019/attack.json", "trr9019/benign.json", "AWS",
     "AWS resource-based policy grants public access (S3/Lambda/etc)",
     marker("trr9019", "requestParameters.bucketName", "requestParameters.functionName")),
    ("TRR9019", "T1537", "aws_snapshot_or_ami_made_public.yml",
     "trr9019/attack.json", "trr9019/benign.json", "AWS",
     "AWS EBS snapshot / AMI / RDS snapshot shared publicly",
     marker("trr9019", "requestParameters.imageId", "requestParameters.snapshotId",
            "requestParameters.dBSnapshotIdentifier")),
    ("TRR9019", "T1537", "aws_s3_block_public_access_disabled.yml",
     "trr9019/attack.json", "trr9019/benign.json", "AWS",
     "AWS S3 Block Public Access disabled or deleted",
     marker("trr9019", "requestParameters.bucketName")),
    # --- Round 3: TRR9020-9023 (workforce federation, ACL/long-tail exposure, FIC use) ---
    ("TRR9020", "T1199", "gcp_workforce_pool_provider_no_attribute_condition.yml",
     "trr9020/attack.json", "trr9020/benign.json", "GCP",
     "GCP workforce pool provider created without an attribute condition",
     marker("trr9020", "protoPayload.resourceName")),
    ("TRR9020", "T1199", "gcp_workforce_principalset_privileged_binding.yml",
     "trr9020/attack.json", "trr9020/benign.json", "GCP",
     "GCP workforce principalSet bound to a privileged resource role",
     marker("trr9020-ext-pool", "protoPayload.serviceData.policyDelta.bindingDeltas")),
    ("TRR9021", "T1537", "aws_s3_bucket_acl_made_public.yml",
     "trr9021/attack.json", "trr9021/benign.json", "AWS",
     "AWS S3 bucket ACL grants public access (AllUsers)",
     marker("trr9021", "requestParameters.bucketName")),
    ("TRR9021", "T1537", "aws_eventbridge_bus_made_public.yml",
     "trr9021/attack.json", "trr9021/benign.json", "AWS",
     "AWS EventBridge event bus permission made public",
     marker("trr9021", "requestParameters.eventBusName")),
    ("TRR9021", "T1537", "aws_efs_file_system_policy_made_public.yml",
     "trr9021/attack.json", "trr9021/benign.json", "AWS",
     "AWS EFS file system policy grants public access",
     marker("trr9021", "requestParameters.fileSystemId")),
    ("TRR9021", "T1537", "aws_glue_resource_policy_made_public.yml",
     "trr9021/attack.json", "trr9021/benign.json", "AWS",
     "AWS Glue Data Catalog resource policy grants public access",
     marker("trr9021", "requestParameters.policyInJson")),
    ("TRR9021", "T1537", "aws_ssm_document_shared_publicly.yml",
     "trr9021/attack.json", "trr9021/benign.json", "AWS",
     "AWS SSM document shared publicly (All)",
     marker("trr9021", "requestParameters.name")),
    ("TRR9023", "T1078.004", "entra_service_principal_federated_credential_signin.yml",
     "trr9023/attack.json", "trr9023/benign.json", "Azure",
     "Entra service principal sign-in using a federated identity credential",
     marker("trr9023", "properties.servicePrincipalName")),
    # --- TRR9022: EKS IRSA credential used off-cluster (the vetted replacement for the
    #     dropped ECS/TRR9022 slot; a trusted-marker sibling of TRR9011) ---
    ("TRR9022", "T1550.001", "aws_eks_irsa_web_identity_assumed_off_cluster.yml",
     "trr9022/attack.json", "trr9022/benign.json", "AWS",
     "EKS IRSA web-identity role assumed off-cluster (exchange leg)",
     marker("trr9022", "requestParameters.roleArn", "responseElements.subjectFromWebIdentityToken",
            "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn")),
    ("TRR9022", "T1550.001", "aws_eks_irsa_role_session_used_off_cluster.yml",
     "trr9022/attack.json", "trr9022/benign.json", "AWS",
     "EKS IRSA role session used off-cluster (use leg)",
     marker("trr9022", "requestParameters.roleArn", "responseElements.subjectFromWebIdentityToken",
            "userIdentity.arn", "userIdentity.sessionContext.sessionIssuer.arn")),
    # --- TRR9032: EKS access-entry backdoor in CloudTrail (T1098.006, secondary T1098.003).
    #     The grant lives in the EKS control plane, so it never reaches the Kubernetes audit
    #     log -- this is a cloud TRR, alongside (not touching) the k8s T1098.006 rules.
    #     The graded rule's benign baseline (benign.json) is the SAME call differing only on
    #     the discriminator (View policy / namespace scope / denied). The chokepoint rule
    #     fires on any access-entry write, so its baseline (benign_chokepoint.json) is EKS
    #     read calls on the same eventSource -- the two rules cannot share one benign file.
    #     principalArn is URL-encoded in AssociateAccessPolicy; the marker 'trr9032' survives
    #     it (letters/digits/'-' are not percent-encoded) and the rule does not match it.
    ("TRR9032", "T1098.006", "aws_eks_access_entry_cluster_admin_policy.yml",
     "trr9032/attack.json", "trr9032/benign.json", "AWS",
     "EKS access entry granted a cluster-wide admin or secrets-reading policy (graded)",
     marker("trr9032", "requestParameters.principalArn")),
    ("TRR9032", "T1098.006", "aws_eks_access_entry_write.yml",
     "trr9032/attack.json", "trr9032/benign_chokepoint.json", "AWS",
     "any EKS access-entry / access-policy write (surface chokepoint)",
     marker("trr9032", "requestParameters.principalArn", "requestParameters.name")),
    # --- Wave 6: TRR9036 -- Azure ARM RBAC privileged role assignment at subscription /
    #     management-group scope (T1098.003, Azure Activity Log). A resource-plane grant:
    #     it lands in the Azure Activity Log (Microsoft.Authorization/roleAssignments/write),
    #     the same log as the TRR9013 managed-identity FIC rule above. The role + scope are
    #     only on the START record, in properties.requestbody (a JSON string), so the rule
    #     fires on resultType '^start' -- the opposite of TRR9013's filter_start. The benign
    #     baseline (benign.json) holds a Terraform grant of the non-privileged Key Vault
    #     Secrets User role at a Key Vault (resource-group) scope (records #0 and #1: they
    #     differ in the role and the scope, so they grade distant), and the hard record #2:
    #     the attack's Start record with the Owner role changed to Reader: of the values
    #     that the rule tests, only the role (requestbody RoleDefinitionId) differs. The marker
    #     'trr9036-attacker' sits in identity.claims.name, which the rule does not read
    #     (the rule keys on requestbody).
    ("TRR9036", "T1098.003", "azure_privileged_role_assignment.yml",
     "trr9036/attack.json", "trr9036/benign.json", "Azure",
     "privileged built-in role assigned at subscription / management-group scope",
     marker("trr9036-attacker", "identity.claims.name")),
    # --- TRR9037: IAM Roles Anywhere trust-anchor abuse in CloudTrail (T1098.001, secondary
    #     T1199). A trust anchor names the CA whose X.509 client certificates exchange for
    #     temporary AWS credentials; registering an EXTERNAL CA (CERTIFICATE_BUNDLE /
    #     SELF_SIGNED_REPOSITORY, not AWS_ACM_PCA) is certificate-based persistence. The
    #     graded rule's hard benign (benign.json) is the SAME CreateTrustAnchor differing only
    #     on the discriminator requestParameters.source.sourceType (AWS_ACM_PCA, an internal
    #     ACM Private CA by a platform admin). The surface chokepoint fires on any trust-anchor
    #     / profile write, so its baseline (benign_chokepoint.json) is Roles Anywhere READ
    #     calls on the same eventSource -- the two rules cannot share one benign file (the
    #     chokepoint would fire on the ACM-PCA create in benign.json, which is expected).
    ("TRR9037", "T1098.001", "aws_rolesanywhere_trust_anchor_external_ca.yml",
     "trr9037/attack.json", "trr9037/benign.json", "AWS",
     "Roles Anywhere trust anchor backed by an external CA (graded)",
     marker("trr9037", "responseElements.trustAnchor.trustAnchorArn",
            "requestParameters.name", "userIdentity.arn")),
    ("TRR9037", "T1098.001", "aws_rolesanywhere_trust_anchor_write.yml",
     "trr9037/attack.json", "trr9037/benign_chokepoint.json", "AWS",
     "any Roles Anywhere trust-anchor / profile write (surface chokepoint)",
     marker("trr9037", "responseElements.trustAnchor.trustAnchorArn",
            "responseElements.profile.profileArn", "requestParameters.name",
            "userIdentity.arn")),
    # --- TRR9038: GCP Cloud Logging sink / bucket / exclusion tamper (T1562.008).
    #     The first GCP defense-evasion TRR. The chokepoint fires on a ConfigServiceV2
    #     write that disrupts logging: delete/disable/re-divert of the _Default sink,
    #     delete of the _Default log bucket, or any exclusion write. The hard benign
    #     is a lifecycle op on a CUSTOM sink/bucket (CreateSink / UpdateSink keeping
    #     destination / DeleteSink of a decommissioned sink), differing only on the
    #     _Default scope (resourceName) and the disable flag. marker() is on the
    #     server-set resourceName; the marker sits in its project segment, which is
    #     disjoint from the /sinks/_Default or /buckets/_Default suffix the rule keys on
    #     (the method and the disable flag are other fields), so the rename test holds.
    ("TRR9038", "T1562.008", "gcp_logging_sink_tampered.yml",
     "trr9038/attack.json", "trr9038/benign.json", "GCP",
     "GCP Cloud Logging _Default sink/bucket delete-or-disable + exclusion tamper",
     marker("trr9038-", "protoPayload.resourceName")),
]

FOLDERS = sorted({folder for _, folder, *_ in MANIFEST})


class FixtureError(Exception):
    """A fixture that the loader cannot read as records. The text names the fixture
    (from the root of the repository) and, where there is one, the line or the
    record (from 1)."""


def _name(path):
    """The path of a fixture as a message names it: from the root of the repository."""
    full = os.path.abspath(path)
    return os.path.relpath(full, REPO) if full.startswith(REPO + os.sep) else path


def _kind(value):
    """The JSON type of a value, for a message: an object, a list, a string, ..."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return {dict: "an object", list: "a list", str: "a string"}.get(type(value), "a number")


def _cannot_read(error):
    """The text of a problem of JSON that json.loads() or flatten() cannot read."""
    text = str(error).split("\n")[0]
    return (f"JSON that the validator cannot read ({type(error).__name__}: "
            + (text if len(text) <= 100 else text[:100] + "...") + ")")


def _text(path):
    """The text of a fixture file; FixtureError for a file that the loader cannot read
    as UTF-8 text."""
    if os.path.isdir(path):
        raise FixtureError(f"{_name(path)}: a directory, not a file")
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        raise FixtureError(f"{_name(path)}: cannot be read ({e.strerror or e})") from None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        line = data.count(b"\n", 0, e.start) + 1
        column = len(data[data.rfind(b"\n", 0, e.start) + 1:e.start].decode("utf-8")) + 1
        raise FixtureError(f"{_name(path)}, line {line}: bytes that are not UTF-8 (the byte "
                           f"0x{data[e.start]:02x} at character {column} of the line)") from None
    if text.startswith(chr(0xFEFF)):
        raise FixtureError(f"{_name(path)}, line 1: the line starts with the byte order mark "
                           "of UTF-8 (EF BB BF)")
    return text


ENVELOPES = ("Records", "value", "items", "entries")  # the keys of a list of records


def _string_or_null(value):
    return value is None or isinstance(value, str)


def _integer(value):
    """True for an integer of 64 bits (with sign), not a bool: a count."""
    return (isinstance(value, int) and not isinstance(value, bool)
            and -2 ** 63 <= value < 2 ** 63)


# The keys that a page of a list API puts beside its list, each with the type of its
# value: Azure REST (nextLink), Microsoft Graph (@odata.context, @odata.nextLink,
# @odata.deltaLink, and @odata.count with $count=true), Cloud Logging entries.list
# (nextPageToken). No value of such a type can hold a record. An envelope holds no
# other key: the loader reads only its list, and would drop each other key without a
# word. Another list page (Google Workspace Reports, a GCP compute list, a kubectl
# List, Azure DevOps, the legacy Azure AD Graph) is written as a JSON array.
PAGE_KEYS = {"nextLink": ("a string or null", _string_or_null),
             "@odata.context": ("a string or null", _string_or_null),
             "@odata.nextLink": ("a string or null", _string_or_null),
             "@odata.deltaLink": ("a string or null", _string_or_null),
             "@odata.count": ("an integer of 64 bits", _integer),
             "nextPageToken": ("a string or null", _string_or_null)}


def _page_keys():
    """The page keys and their types, as a message names them: `nextLink, ... and
    nextPageToken (each a string or null) and @odata.count (an integer of 64 bits)`."""
    types = {}
    for key, (kind, _) in PAGE_KEYS.items():
        types.setdefault(kind, []).append(key)
    return " and ".join(
        (f"{', '.join(keys[:-1])} and {keys[-1]} (each {kind})" if len(keys) > 1
         else f"{keys[0]} ({kind})") for kind, keys in types.items())


class _LongInt:
    """An integer of JSON that int() does not read: it has more digits than
    sys.get_int_max_str_digits() allows (4300 by default). The loader keeps the error
    in the place of the number and names the record that holds it."""

    __slots__ = ("error",)

    def __init__(self, error):
        self.error = error


def _unread(value):
    """The text of the first part of a JSON value that the loader does not read, or
    None: a number with too many digits (_LongInt), or an object that holds a key two
    times (sigma_eval.Twice). The walk uses no recursion: the value can be deep."""
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, _LongInt):
            return _cannot_read(node.error)
        if isinstance(node, dict):
            if type(node) is sigma_eval.Twice:
                return sigma_eval.twice_text(node.key)
            stack.extend(reversed(list(node.values())))
        elif isinstance(node, list):
            stack.extend(reversed(node))
    return None


def _key_names(keys, most=3):
    """The keys of a message, sorted: at most `most` of them, then the count of the
    others ('a', 'b', 'c' and 4 more). A long key is cut at 40 characters."""
    names = [repr(key) if len(key) <= 40 else repr(key[:40]) + "..."
             for key in sorted(keys)]
    if len(names) > most:
        return f"{', '.join(names[:most])} and {len(names) - most} more"
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"


def _envelope_keys(path, doc, env, at):
    """Raise FixtureError when the envelope `doc` (its list is doc[env]) holds a key
    other than its list and the page keys (PAGE_KEYS), or a page key whose value is
    not of its type. A key is another key also when it differs from a page key only
    in letter case. The loader reads only the list of an envelope, so it would drop
    each other key without a word: the attack records of a benign baseline, each with
    a list of benign records under an envelope key, would give a clean baseline. The
    text names the other keys (sorted, at most 3 and the count of the others, each
    cut at 40 characters), and else the first page key of a wrong type (sorted)."""
    other = [key for key in doc if key != env and key not in PAGE_KEYS]
    wrong = [key for key in doc if key in PAGE_KEYS and not PAGE_KEYS[key][1](doc[key])]
    if not other and not wrong:
        return
    place = f"{_name(path)}{', ' + at if at else ''}"
    if other:
        what = (f"that also holds the key{'s' if len(other) > 1 else ''} "
                f"{_key_names(other)}")
    else:
        key = sorted(wrong)[0]
        what = f"whose page key {key!r} is {_kind(doc[key])}, not {PAGE_KEYS[key][0]}"
    raise FixtureError(
        f"{place}: an envelope (the list {env!r}) {what}: the loader reads only the list of "
        f"an envelope, and beside the list an envelope holds only the page keys "
        f"{_page_keys()}. Write the records in a JSON array")


def _document(path, doc, at):
    """(records, where) of one document of a fixture (the one document of the file, or
    a line of JSON lines; `at` names the line, or is None): the list of an envelope,
    the elements of an array, or the object as one record. A line of JSON lines is one
    record or an envelope: a list on a line is a record that is not an object. An
    envelope holds beside its list only page keys (PAGE_KEYS), each with a value of its
    type (_envelope_keys())."""
    if isinstance(doc, list) and at is None:
        return doc, [f"element {n} of the array" for n in range(1, len(doc) + 1)]
    if not isinstance(doc, dict):
        if at is None:
            raise FixtureError(f"{_name(path)}: JSON that is not an array or an object "
                               f"({_kind(doc)})")
        return [doc], [at]
    if type(doc) is sigma_eval.Twice:
        # json kept only the last value of the key: an envelope {"Records": <attack>,
        # "Records": <benign>} would give the benign records only.
        raise FixtureError(f"{_name(path)}{', ' + at if at else ''}: "
                           f"{sigma_eval.twice_text(doc.key)}")
    env = next((env for env in ENVELOPES if isinstance(doc.get(env), list)), None)
    if env is None:
        # An object that holds an envelope key is an envelope; when the key holds no
        # list, the envelope holds no record, and the object is not one record either.
        odd = next((env for env in ENVELOPES if env in doc), None)
        if odd is not None:
            raise FixtureError(
                f"{_name(path)}{', ' + at if at else ''}: an object whose key {odd!r} is "
                f"{_kind(doc[odd])}, not a list of records: the loader reads an object with "
                f"the key {', '.join(ENVELOPES[:-1])} or {ENVELOPES[-1]} as an envelope of "
                "records. Write one record that holds such a key in a JSON array ([{...}])")
        return [doc], [at or "the object of the file"]
    _envelope_keys(path, doc, env, at)
    prefix = f"{at}, " if at else ""
    return doc[env], [f"{prefix}element {n} of the list {env!r}"
                      for n in range(1, len(doc[env]) + 1)]


def _records(path):
    """(records, where): the records of a fixture, as the file holds them, and the
    place of each in the file, as a message names it (`line 3`, `element 2 of the
    array`). Raises FixtureError (load_records())."""
    text = _text(path)

    def parse_int(digits):
        try:
            return int(digits)
        except ValueError as e:
            return _LongInt(e)

    def loads(text):
        return json.loads(text, parse_int=parse_int, object_pairs_hook=sigma_eval.pairs)

    try:
        records, where = _document(path, loads(text), None)
    except json.JSONDecodeError as whole:
        # Not one JSON document: JSON lines. When the first line is not JSON either,
        # the file is one document with an error, and the error of the document names
        # its place.
        records, where, read = [], [], False
        # A line ends at LF only: str.splitlines() also ends one at U+0085, U+2028 and
        # U+2029, which a JSON string may hold as they are.
        for n, line in enumerate(text.split("\n"), 1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = loads(line)
            except json.JSONDecodeError as e:
                e, n = (whole, whole.lineno) if not read else (e, n)
                raise FixtureError(f"{_name(path)}, line {n}: not JSON ({e.msg}, at character "
                                   f"{e.colno}); a fixture is a JSON array, a JSON object or "
                                   "JSON lines") from None
            except (ValueError, RecursionError) as e:
                raise FixtureError(f"{_name(path)}, line {n}: {_cannot_read(e)}") from None
            read = True
            # Each line is read as the one object of a file is: an envelope on a line
            # (CloudTrail writes each log file as one envelope on one line) gives the
            # records of its list.
            line_records, line_where = _document(path, doc, f"line {n}")
            records += line_records
            where += line_where
    except RecursionError as e:
        # json stops in the first JSON value of the text. When that value is the first
        # line that is not blank (JSON lines, or one document on one line), the line
        # is named; else only the fixture.
        n, line = next((n, line) for n, line in enumerate(text.split("\n"), 1)
                       if line.strip())
        try:
            loads(line)
        except RecursionError:
            raise FixtureError(f"{_name(path)}, line {n}: {_cannot_read(e)}") from None
        except ValueError:
            pass
        raise FixtureError(f"{_name(path)}: {_cannot_read(e)}") from None
    except ValueError as e:
        raise FixtureError(f"{_name(path)}: {_cannot_read(e)}") from None
    # Each number with too many digits, and each object that holds a key two times,
    # is in a record here: beside its list an envelope holds only page keys, each with
    # a string, null or an integer of 64 bits (_envelope_keys(): a number with too
    # many digits is none of them), and _document() refuses an object of the file or
    # of a line that holds a key two times (json keeps only one of the two values).
    for at, record in zip(where, records):
        if not isinstance(record, dict):
            raise FixtureError(f"{_name(path)}, {at}: a record that is not a JSON object "
                               f"({_kind(record)})")
        problem = _unread(record)
        if problem is not None:
            raise FixtureError(f"{_name(path)}, {at}: {problem}")
    return records, where


def load_records(path):
    """Load a fixture file to the list of its records, as the file holds them.

    Accepts a JSON array, a single JSON object (one record), a common log envelope
    ({"Records"/"value"/"items"/"entries": [...]}, ENVELOPES), or JSON-lines (a line
    ends at LF). Each line of JSON lines is read as the single object of a file is: one
    record, or an envelope, whose list gives the records. An object that holds an
    envelope key is an envelope: a single record that holds such a key goes in a JSON
    array. Beside its list, an envelope holds only the page keys (PAGE_KEYS): nextLink,
    @odata.context, @odata.nextLink, @odata.deltaLink and nextPageToken, each a string
    or null, and @odata.count, an integer of 64 bits; the loader reads only the list.
    Another list page is written as a JSON array.

    Raises FixtureError, with a text that names the fixture, for a file that is a
    directory or cannot be read; bytes that are not UTF-8; the byte order mark of UTF-8
    at its start; JSON that is not an array or an object (`null`, `1`); an object (the
    file, or a line of JSON lines) whose envelope key is not a list (`{"Records":
    null}`, `{"value": "x"}`); an envelope that holds another key beside its list (an
    attack record with `"items": [...]`, a second envelope key, `"meta": 1`, also a page
    key in another letter case), or a page key whose value is not of its type (a string
    or null; an integer of 64 bits for @odata.count); an object that holds one key two
    times (json keeps only the last value, so `{"Records": <attack records>, "Records":
    <benign records>}` would give the benign records only); a line of JSON lines that is
    not JSON; JSON that the loader cannot read (too deep, a number with too many
    digits); and a record that is not a JSON object (`null`, `[]`, `1`, `"x"`). The text
    names the line or the element where there is one. An object of the file or of a line
    that holds a key two times is named by the fixture or the line, and such an object
    in a record by its record. A number with too many digits is named by its record:
    beside the list of an envelope, such a number is refused before, as the value of
    another key or of a page key of another type, and so is an object that holds a key
    two times. JSON that is too deep for json is named by its line in JSON lines or in a
    document of one line; JSON of one document of more lines that is too deep for json
    is named by the fixture only.
    """
    return _records(path)[0]


def load_fixture(path):
    """Load a fixture file to a list of flattened event dicts (load_records()).

    Also raises FixtureError for a record that is too deep to flatten, and for a
    record that one event table cannot hold (sigma_eval.event_problem(): two keys
    of the record that give one field, as {"a.b": 1, "a": {"b": 2}} does, two keys
    that differ only in the letter case of their ASCII letters, a key that hides a
    row id that the queries read, a value that SQLite does not hold as it is). Keys of
    two records that differ only in letter case are no problem: they share one
    column."""
    events = []
    for record, at in zip(*_records(path)):
        try:
            event = sigma_eval.flatten(record)
        except RecursionError as e:
            raise FixtureError(f"{_name(path)}, {at}: {_cannot_read(e)}") from None
        problem = sigma_eval.event_problem(event)
        if problem:
            raise FixtureError(f"{_name(path)}, {at}: a record that one event table cannot "
                               f"hold: {problem[1]}")
        events.append(event)
    return events


# ---- failure explanations (sigma_explain) --------------------------------

ACTION = ("eventName", "operationName", "protoPayload.methodName")
PRINCIPAL = ("userIdentity.arn", "userIdentity.principalId",
             "properties.initiatedBy.user.userPrincipalName", "properties.userPrincipalName",
             "properties.servicePrincipalName", "protoPayload.authenticationInfo.principalEmail",
             "caller")
SOURCE_IP = ("sourceIPAddress", "callerIpAddress", "properties.ipAddress",
             "properties.initiatedBy.user.ipAddress", "protoPayload.requestMetadata.callerIp")
WHEN = ("eventTime", "time", "timestamp")


def _first(record, fields):
    return next((record[f] for f in fields if record.get(f) not in (None, "")), None)


def _short(value, limit=100):
    text = "<absent>" if value is None else repr(value)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def record_label(records, prefix):
    """label(record) -> '<prefix> record #<i> <eventName/operationName/methodName>'."""
    index = {id(r): i for i, r in enumerate(records)}
    return lambda r: f"{prefix} record #{index.get(id(r), '?')} {_first(r, ACTION) or '?'}"


def summarize(record):
    """One line: what was done, by whom, from where, when (and any error code)."""
    bits = [str(_first(record, ACTION) or "?")]
    for name, fields in (("by", PRINCIPAL), ("from", SOURCE_IP), ("at", WHEN)):
        value = _first(record, fields)
        if value is not None:
            bits.append(f"{name} {value}")
    if record.get("errorCode"):
        bits.append(f"errorCode {record['errorCode']}")
    return " ".join(bits)


def load_rule(path):
    """(sigma_explain's view of the rule, None) or (None, why it could not load)."""
    if sigma_explain is None:
        return None, _EXPLAIN_ERROR
    try:
        return sigma_explain.load(path), None
    except Exception as e:  # noqa: BLE001
        return None, f"sigma_explain could not load the rule: {type(e).__name__}: {e}"


def explained(fn, *args):
    """Run an explanation helper; an explanation must never break the gate."""
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001
        return [f"(no explanation: sigma_explain raised {type(e).__name__}: {e})"]


def explain_attack_miss(rule, attack):
    lines = [f"why it did not fire on the {len(attack)} attack record(s) "
             "(per block: how many records hold it; then the closest records, item by item):"]
    return lines + sigma_explain.explain_miss(rule.stripped(), attack, k=2,
                                              label=record_label(attack, "attack"))


def explain_gate_miss(gate, attack, hit_idx):
    """The marker gate's fields and their values on every record the rule matched."""
    substr, fields = getattr(gate, "substr", None), getattr(gate, "fields", ())
    if substr is None:
        return ["the marker gate is not a marker(); read its MANIFEST entry"]
    lines = [f"marker gate: one of {', '.join(fields)} must contain {substr!r}; "
             f"the rule matched {len(hit_idx)} attack record(s), none carrying it:"]
    for i in hit_idx[:3]:
        lines.append(f"  attack record #{i} {summarize(attack[i])}")
        lines.extend(f"      {f}={_short(attack[i].get(f))}" for f in fields)
    if len(hit_idx) > 3:
        lines.append(f"  ... and {len(hit_idx) - 3} more")
    lines.append("a match without the marker means the rule fired on a record the fixture "
                 "did not mean as the attack, or the marker/gate fields were renamed")
    return lines


def explain_benign_hits(rule, benign, hit_idx):
    """Each benign record the rule fired on (up to 3), and why it fired."""
    lines = [f"the rule fired on {len(hit_idx)} benign record(s); the baseline is built to "
             "share the attack's surface and differ on the discriminating field:"]
    for i in hit_idx[:3]:
        lines.append(f"  benign record #{i}: {summarize(benign[i])}")
        lines.extend("  " + ln for ln in sigma_explain.explain_hit(rule, benign[i]))
    if len(hit_idx) > 3:
        lines.append(f"  ... and {len(hit_idx) - 3} more")
    return lines


# Documentation address ranges: RFC 5737 (IPv4) and RFC 3849 (IPv6). An allowlist
# entry in one of them is a placeholder for the operator's own ranges (the rules mark
# such entries PLACEHOLDERS), so a record that only such an entry filters proves
# nothing about a real environment.
DOCUMENTATION_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def documentation_address(value):
    """Is `value` an address or a network inside a documentation range?"""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return False
    return any(net.version == doc.version and net.subnet_of(doc) for doc in DOCUMENTATION_NETS)


def placeholder_only(rule, atom, record):
    """The documentation addresses of the filter item `atom`, when the item holds on
    `record` only through them; else []. The item is compiled again without those
    values and run on the record."""
    item = rule.item_detection[atom]["_item"]
    key, values = next(iter(item.items())) if isinstance(item, dict) else (None, item)
    values = values if isinstance(values, list) else [values]
    docs = [v for v in values if documentation_address(v)]
    if not docs:
        return []
    real = [v for v in values if not documentation_address(v)]
    if real:
        detection = {"_item": {key: real} if key is not None else real, "condition": "_item"}
        sql = sigma_explain._compile_doc({"title": f"{rule.title} [{atom}, no documentation "
                                                   "address]",
                                          "logsource": rule.logsource, "detection": detection})
        if sigma_eval.EventTable([record]).hit_indices(sql):
            return []
    return [str(v) for v in docs]


def flip_not_counted(rule, atom, record, held, attack_held, chokepoint):
    """Why the flip item `atom` of a near-miss or filtered benign record does not make
    the baseline hard, or None when it does. `held` is the truth of the item on the
    record, and `attack_held` its truth on each marked attack hit. The item counts when
    (a) some marked attack hit differs from the record on the field that the item
    reads: the item holds on the one and not on the other, (b) the item is a filter,
    reads a field outside check_sufficiency.SURFACE_FIELDS, or belongs to a rule in
    check_sufficiency.CHOKEPOINT, and (c) a filter item does not hold on the record
    only through documentation addresses."""
    field = rule.item_field.get(atom)
    is_filter = atom in rule.negated_atoms()
    if not (is_filter or field not in check_sufficiency.SURFACE_FIELDS or chokepoint):
        return (f"it reads {field}, a surface field (check_sufficiency.SURFACE_FIELDS), and "
                "the rule is not in CHOKEPOINT")
    if all(h == held for h in attack_held):
        # A near-miss of a branch that the attack does not use, or a filter item that
        # also holds on the attack: the record tests nothing that the attack depends on.
        shown = f"{field}={_short(record.get(field), 60)}" if field else "a keyword item"
        return (f"the item {'holds' if held else 'fails'} on it and on every marked attack "
                "hit, so no attack hit differs from it on the field that the item reads "
                f"({shown} here)")
    if is_filter:
        docs = placeholder_only(rule, atom, record)
        if docs:
            return (f"the filter holds on it only through documentation addresses "
                    f"({', '.join(docs)}), a placeholder for the operator's own ranges")
    return None


def judge_hard(rule, key, benign, verdicts, ours):
    """(hard, counted, not counted) of a graded baseline. hard is None when the rule
    has no marked attack hit to compare with (the row fails for the attack)."""
    if not ours:
        return None, [], []
    chokepoint = key in check_sufficiency.CHOKEPOINT
    if not rule.is_correlation:
        truth, _ = rule.truth_table(sigma_eval.EventTable(benign))
        attack_truth, _ = rule.truth_table(sigma_eval.EventTable(ours))
    counted, skipped = [], []
    for i, v in enumerate(verdicts):
        if v.kind not in sigma_explain.NON_TRIVIAL:  # a mismatch is graded distant
            continue
        atoms = []
        for atom in v.atoms:
            if rule.is_correlation:
                # A set is a near-miss on one atom repair. Only a base repair shows that
                # a base is load-bearing; a group-by, timespan, order or threshold
                # repair moves the same events, and shows nothing of an item.
                why = (None if atom.startswith("base:") else
                       "a correlation counts a near-miss set only on a base atom (base:<ref>)")
            else:
                why = flip_not_counted(rule, atom, benign[i], truth[i][atom],
                                       [row[atom] for row in attack_truth], chokepoint)
            if why:
                skipped.append({"index": None if rule.is_correlation else i, "kind": v.kind,
                                "atom": atom, "why": why})
            else:
                atoms.append(atom)
        if atoms:
            counted.append({"index": None if rule.is_correlation else i, "kind": v.kind,
                            "atoms": atoms})
    return bool(counted), counted, skipped


def grade_benign(rule, benign, ours=(), key=None):
    """Grade every benign record against the rule, and judge whether the baseline is
    hard (judge_hard()): (one-line summary, details). `ours` are the marked attack
    hits, and `key` is the rule's <folder>/<file> (for CHOKEPOINT). Without marked
    attack hits (the self-test of check_null_safety.py grades a constructed rule) the
    detail says hard None: not judged."""
    rule = rule.stripped()  # without null guards and copies: no items of the rule
    verdicts = sigma_explain.judge_events(rule, benign)
    kinds = {}
    for v in verdicts:
        kinds[v.kind] = kinds.get(v.kind, 0) + 1
    covered, unexercised = sigma_explain.coverage(rule, verdicts)
    exercised = [a for a, hits in covered.items() if hits]
    order = sorted(kinds, key=lambda k: sigma_explain.KIND_RANK[k])
    counts = ", ".join(f"{kinds[k]} {k}" for k in order)
    line = f"benign baseline graded: {counts}; atoms exercised {len(exercised)}/{len(rule.atoms)}"
    mismatched = [i for i, v in enumerate(verdicts) if v.mismatch]
    if mismatched:
        line += (f"; !! sigma_explain disagrees with the compiled rule on benign record(s) "
                 f"{mismatched} (report it)")
    hard, counted, skipped = judge_hard(rule, key, benign, verdicts, ours)
    records = [{"index": i, "kind": v.kind, "atoms": v.atoms} for i, v in enumerate(verdicts)]
    detail = {"summary": line, "kinds": kinds, "exercised": exercised,
              "unexercised": unexercised, "records": records, "counts": counts,
              "mismatched": mismatched, "hard": hard, "hard_records": counted,
              "not_counted": skipped}
    return line, detail


def not_hard_lines(grading):
    """The explanation of a NOT HARD row: each flip that does not count, and why."""
    lines = []
    for s in grading["not_counted"]:
        where = "the benign event set" if s["index"] is None else f"benign record #{s['index']}"
        lines.append(f"{where} is {s['kind']} on `{s['atom']}`, which does not count: "
                     f"{s['why']}")
    lines.append("to make the baseline hard, add a copy of a marked attack hit that breaks "
                 "one discriminating item (a near-miss), or that an allowlist filter of the "
                 "rule holds (filtered)")
    return lines


def write_json(path, report):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")


def main():
    ap = argparse.ArgumentParser(description="Validate the external-cloud detections.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compile every cloud rule; no fixtures needed.")
    ap.add_argument("--report", action="store_true",
                    help="Report misses instead of failing on them (a missing fixture, "
                         "and a benign baseline without a record, without a hard record or "
                         "that cannot be graded, still fail).")
    ap.add_argument("--json", metavar="PATH",
                    help="Also write a machine-readable report (results + explanations).")
    args = ap.parse_args()
    report = {"validator": "cloud", "mode": "dry-run" if args.dry_run else "validate",
              "results": []}
    code = validate(args, report)
    if args.json:
        report["exit"] = code
        write_json(args.json, report)
    return code


def validate(args, report):
    """The validation run behind main(); fills `report` for --json."""
    results = report["results"]
    # Compile the manifest rules.
    queries = {}
    parse_errors = 0
    listed = set()
    for trr, folder, fname, *_ in MANIFEST:
        key = (folder, fname)
        listed.add(key)
        path = os.path.join(SIGMA, folder, fname)
        if not os.path.exists(path):
            print(f"PENDING      {folder}/{fname}  [{trr}] not built yet -- skipped")
            results.append({"rule": f"{folder}/{fname}", "trr": trr, "status": "PENDING",
                            "detail": "not built yet", "explanation": []})
            continue
        try:
            queries[key] = sigma_eval.compile_rule(path)
            print(f"OK (compile)  {folder}/{fname}  [{trr}]")
        except Exception as e:  # noqa: BLE001
            parse_errors += 1
            print(f"ERROR compile {folder}/{fname}: {e}")
            results.append({"rule": f"{folder}/{fname}", "trr": trr, "status": "ERROR",
                            "detail": f"compile: {e}", "explanation": []})
    # Compile any other rule in the touched folders (not manifest-gated).
    for folder in FOLDERS:
        for path in sorted(glob.glob(os.path.join(SIGMA, folder, "*.yml"))):
            key = (folder, os.path.basename(path))
            if key in listed:
                continue
            try:
                sigma_eval.compile_rule(path)
                print(f"OK (compile)  {folder}/{os.path.basename(path)}  [not manifest-gated]")
            except Exception as e:  # noqa: BLE001
                parse_errors += 1
                print(f"ERROR compile {folder}/{os.path.basename(path)}: {e}")
                results.append({"rule": f"{folder}/{os.path.basename(path)}", "status": "ERROR",
                                "detail": f"compile: {e}", "explanation": []})

    if args.dry_run:
        results.extend({"rule": f"{folder}/{fname}", "status": "OK", "detail": "compiles",
                        "explanation": []} for folder, fname in queries)

        print()
        if parse_errors:
            print(f"Dry run FAILED: {parse_errors} compile error(s).")
            return 1
        print(f"Dry run OK: {len(queries)} cloud rule(s) compile with pySigma.")
        return 0

    print()
    # unproven: the rules of MANIFEST that this run cannot prove, because a fixture
    # that MANIFEST names is missing or because the benign baseline holds no record
    # (a negative control that read no record cannot fail). They fail the run, also
    # with --report. fails: the other rules that are not a PASS.
    passes = fails = unproven = 0
    for trr, folder, fname, attack_f, benign_f, provider, note, gate in MANIFEST:
        key = (folder, fname)
        if key not in queries:
            continue
        attack_path = os.path.join(FIX, attack_f)
        benign_path = os.path.join(FIX, benign_f)
        missing = [f"the {kind} fixture {os.path.relpath(path, REPO)}"
                   for kind, path in (("attack", attack_path), ("benign", benign_path))
                   if not os.path.isfile(path)]
        if missing:
            unproven += 1
            why = (f"MANIFEST names {' and '.join(missing)}, and no such file exists: "
                   "nothing proves the rule")
            print(f"ERROR [{trr} {provider}] {fname}: {why} -- {note}")
            results.append({"rule": f"{folder}/{fname}", "trr": trr, "provider": provider,
                            "status": "ERROR", "detail": why, "explanation": []})
            continue
        fixtures, unread = {}, []
        for kind, path in (("attack", attack_path), ("benign", benign_path)):
            try:
                fixtures[kind] = load_fixture(path)
            except FixtureError as e:
                unread.append(f"the {kind} fixture {e}")
        if unread:
            unproven += 1
            why = ("; ".join(unread) + f". The loader cannot read {'them' if unread[1:] else 'it'}"
                   ", so nothing proves the rule")
            print(f"ERROR [{trr} {provider}] {fname}: {why} -- {note}")
            results.append({"rule": f"{folder}/{fname}", "trr": trr, "provider": provider,
                            "status": "ERROR", "detail": why, "explanation": []})
            continue
        attack, benign = fixtures["attack"], fixtures["benign"]
        q = queries[key]
        # sigma_eval.evaluate() == EventTable(...).hits(); the indices name the records.
        attack_idx = [hit[0] for hit in sigma_eval.EventTable(attack).hit_indices(q)]
        benign_idx = [hit[0] for hit in sigma_eval.EventTable(benign).hit_indices(q)]
        attack_hits = [attack[i] for i in attack_idx]
        benign_hits = [benign[i] for i in benign_idx]
        ours = [e for e in attack_hits if gate(e)]
        rule, not_loaded = load_rule(os.path.join(SIGMA, folder, fname))
        why_not = [f"(no explanation: {not_loaded})"] if not_loaded else []

        ok = True
        detail = []
        explanation = []
        if not attack_hits:
            ok = False
            detail.append("rule did NOT fire on the attack fixture")
            explanation += explained(explain_attack_miss, rule, attack) if rule else why_not
        elif not ours:
            ok = False
            detail.append(f"rule fired ({len(attack_hits)}) but no match carried the "
                          f"emulation marker")
            explanation += explained(explain_gate_miss, gate, attack, attack_idx)
        # The count is what load_fixture() returned: the records that the rule is
        # run on. No filter stands between the file and the rule.
        vacuous = not benign
        if vacuous:
            ok = False
            detail.append("NEGATIVE CONTROL VACUOUS: the benign baseline "
                          f"{os.path.relpath(benign_path, REPO)} holds no record (0 records), "
                          "so the negative control cannot fail")
        if benign_hits:
            ok = False
            detail.append(f"NEGATIVE CONTROL FAILED: rule fired on {len(benign_hits)} "
                          f"benign record(s)")
            explanation += (explained(explain_benign_hits, rule, benign, benign_idx)
                            if rule else why_not)
        grade_line, grading = why_not[0] if why_not else "", None
        ungraded = not_loaded or _SUFFICIENCY_ERROR
        if not ungraded:
            try:
                grade_line, grading = grade_benign(rule, benign, ours, f"{folder}/{fname}")
            except Exception as e:  # noqa: BLE001
                ungraded = f"sigma_explain raised {type(e).__name__}: {e}"
                grade_line = f"(no benign grading: {type(e).__name__}: {e})"
        if ungraded and not grade_line:
            grade_line = f"(no benign grading: {ungraded})"
        # The hard-baseline check (roadmap R2e): a baseline that holds records must
        # hold one that differs from the attack in a discriminating field.
        not_hard = False
        if not vacuous and grading is None:
            not_hard = True
            ok = False
            detail.append("NEGATIVE CONTROL NOT GRADED: the benign baseline "
                          f"{os.path.relpath(benign_path, REPO)} could not be graded "
                          f"({ungraded}), so nothing shows that a record of it is a near-miss "
                          "or a filtered negative of the rule")
        elif not vacuous and grading["hard"] is False:
            not_hard = True
            ok = False
            counts = grading["counts"]
            if grading["mismatched"]:
                # sigma_explain grades such a record distant: it cannot count, and the
                # cause is the grader, not the baseline.
                counts += ("; sigma_explain disagrees with the compiled rule on benign "
                           "record(s) " + ", ".join(f"#{i}" for i in grading["mismatched"])
                           + ", so they cannot count (report it)")
            detail.append("NEGATIVE CONTROL NOT HARD: the benign baseline "
                          f"{os.path.relpath(benign_path, REPO)} holds no near-miss or filtered "
                          "record of the rule that differs from the attack in a discriminating "
                          f"field ({counts})")
            explanation += not_hard_lines(grading)

        if ok:
            passes += 1
            print(f"PASS  [{trr} {provider}] {fname}: {len(ours)}/{len(attack)} attack "
                  f"record(s) match; benign baseline clean ({len(benign)} record(s)) "
                  f"-- {note}")
        else:
            if vacuous or not_hard:
                unproven += 1
            else:
                fails += 1
            print(f"FAIL  [{trr} {provider}] {fname}: " + "; ".join(detail) + f" -- {note}")
        for line in explanation + [grade_line]:
            print("        " + line)
        results.append({"rule": f"{folder}/{fname}", "trr": trr, "provider": provider,
                        "status": "PASS" if ok else "FAIL",
                        "detail": "; ".join(detail) if detail else
                        f"{len(ours)}/{len(attack)} attack record(s) match; benign baseline "
                        f"clean ({len(benign)} record(s))",
                        "attack_hits": attack_idx, "benign_hits": benign_idx,
                        "explanation": explanation, "benign_grading": grading})

    print()
    if parse_errors:
        print(f"FAILED: {parse_errors} compile error(s).")
        return 1
    if unproven:
        print(f"FAILED: {unproven} rule(s) of MANIFEST have no proof: a fixture that MANIFEST "
              "names is missing or cannot be read, or a benign baseline holds no record, "
              "holds no hard record or cannot be graded (see the ERROR rows and the NEGATIVE "
              "CONTROL VACUOUS, NOT HARD and NOT GRADED rows). --report does not make this "
              "non-fatal.")
    if fails and not args.report:
        print(f"FAILED: {fails} technique(s) did not satisfy attack-fires + "
              f"control-holds. (Use --report to treat as non-fatal.)")
    elif fails:
        print(f"Reported {fails} failure(s); not gated (--report).")
    if unproven or (fails and not args.report):
        return 1
    if fails:
        return 0
    print(f"All {passes} external-cloud detection(s) fired on their recorded attack "
          f"fixtures, and every negative control held.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
