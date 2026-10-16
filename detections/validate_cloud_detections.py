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

The benign baseline is the control, and it is built to be HARD: it hits the same
log source / method / structural fields as the attack and differs only on the
discriminating field (the off-instance source IP, the identity type, the FIC issuer,
the public vs specific principal, the pinned vs wildcard OIDC subject), so a PASS
proves the rule keys on the technique's chokepoint and not on the fixture's shape or
marker.

One exception: the TRR9013 managed-identity FIC rule reads the Azure Activity Log,
which carries no issuer/subject, so that rule is a broad signal with no field to
discriminate on. Its benign baseline is therefore a different administrative operation
on the same identity (proving the rule is specific to the FIC-write operationName, not
that it separates a good issuer from a bad one), not an "issuer differs only" control.

Modes:
    --dry-run       Compile every cloud rule; no fixtures needed.
    --report        Report misses instead of failing on them.
    --json PATH     Also write a machine-readable report (status, detail and the
                    explanation lines of every rule) to PATH.

A failing rule is explained beneath its FAIL line (sigma_explain.py): an attack
miss shows each detection block's per-item counts and the attack records that
came closest, item by item; a marker-gate miss shows the gate's fields and their
values on the hits; a benign hit shows the record and why the rule fired on it.
Every rule also gets one informational line grading its benign records (how many
are near-misses, filtered look-alikes, distant or trivial) and how many of the
rule's condition atoms they exercise.
"""

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402
try:  # explanations are optional: a broken sigma_explain must never break a verdict
    import sigma_explain  # noqa: E402
except Exception as _e:  # noqa: BLE001
    sigma_explain = None
    print(f"[diag] no explanations: sigma_explain failed to import "
          f"({type(_e).__name__}: {_e})")

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
]

FOLDERS = sorted({folder for _, folder, *_ in MANIFEST})


def load_fixture(path):
    """Load a fixture file to a list of flattened event dicts.

    Accepts a JSON array, a single JSON object, a common log envelope
    ({"Records"/"value"/"items"/"entries": [...]}), or JSON-lines.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    records = None
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            records = doc
        elif isinstance(doc, dict):
            for env in ("Records", "value", "items", "entries"):
                if isinstance(doc.get(env), list):
                    records = doc[env]
                    break
            if records is None:
                records = [doc]
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return [sigma_eval.flatten(r) for r in records]


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
    """(sigma_explain's view of the rule, []) or (None, [why it could not load])."""
    try:
        return sigma_explain.load(path), []
    except Exception as e:  # noqa: BLE001
        return None, [f"(no explanation: sigma_explain could not load the rule: "
                      f"{type(e).__name__}: {e})"]


def explained(fn, *args):
    """Run an explanation helper; an explanation must never break the gate."""
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001
        return [f"(no explanation: sigma_explain raised {type(e).__name__}: {e})"]


def explain_attack_miss(rule, attack):
    lines = [f"why it did not fire on the {len(attack)} attack record(s) "
             "(per block: how many records hold it; then the closest records, item by item):"]
    return lines + sigma_explain.explain_miss(rule, attack, k=2,
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


def grade_benign(rule, benign):
    """Grade every benign record against the rule: (one-line summary, details)."""
    verdicts = sigma_explain.judge_events(rule, benign)
    kinds = {}
    for v in verdicts:
        kinds[v.kind] = kinds.get(v.kind, 0) + 1
    covered, unexercised = sigma_explain.coverage(rule, verdicts)
    exercised = [a for a, hits in covered.items() if hits]
    order = sorted(kinds, key=lambda k: sigma_explain.KIND_RANK[k])
    line = ("benign baseline graded (informational): "
            + ", ".join(f"{kinds[k]} {k}" for k in order)
            + f"; atoms exercised {len(exercised)}/{len(rule.atoms)}")
    mismatched = [i for i, v in enumerate(verdicts) if v.mismatch]
    if mismatched:
        line += (f"; !! sigma_explain disagrees with the compiled rule on benign record(s) "
                 f"{mismatched} (report it)")
    records = [{"index": i, "kind": v.kind, "atoms": v.atoms} for i, v in enumerate(verdicts)]
    detail = {"summary": line, "kinds": kinds, "exercised": exercised,
              "unexercised": unexercised, "records": records}
    return line, detail


def write_json(path, report):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")


def main():
    ap = argparse.ArgumentParser(description="Validate the external-cloud detections.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compile every cloud rule; no fixtures needed.")
    ap.add_argument("--report", action="store_true",
                    help="Report misses instead of failing on them.")
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
    passes = fails = 0
    for trr, folder, fname, attack_f, benign_f, provider, note, gate in MANIFEST:
        key = (folder, fname)
        if key not in queries:
            continue
        attack_path = os.path.join(FIX, attack_f)
        benign_path = os.path.join(FIX, benign_f)
        if not (os.path.exists(attack_path) and os.path.exists(benign_path)):
            print(f"PENDING [{trr}] {fname}: fixtures not present -- skipped")
            results.append({"rule": f"{folder}/{fname}", "trr": trr, "status": "PENDING",
                            "detail": "fixtures not present", "explanation": []})
            continue
        attack = load_fixture(attack_path)
        benign = load_fixture(benign_path)
        q = queries[key]
        # sigma_eval.evaluate() == EventTable(...).hits(); the indices name the records.
        attack_idx = [hit[0] for hit in sigma_eval.EventTable(attack).hit_indices(q)]
        benign_idx = [hit[0] for hit in sigma_eval.EventTable(benign).hit_indices(q)]
        attack_hits = [attack[i] for i in attack_idx]
        benign_hits = [benign[i] for i in benign_idx]
        ours = [e for e in attack_hits if gate(e)]
        rule, why_not = load_rule(os.path.join(SIGMA, folder, fname))

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
        if benign_hits:
            ok = False
            detail.append(f"NEGATIVE CONTROL FAILED: rule fired on {len(benign_hits)} "
                          f"benign record(s)")
            explanation += (explained(explain_benign_hits, rule, benign, benign_idx)
                            if rule else why_not)
        grade_line, grading = why_not[0] if why_not else "", None
        if rule:
            try:
                grade_line, grading = grade_benign(rule, benign)
            except Exception as e:  # noqa: BLE001
                grade_line = f"(no benign grading: {type(e).__name__}: {e})"

        if ok:
            passes += 1
            print(f"PASS  [{trr} {provider}] {fname}: {len(ours)}/{len(attack)} attack "
                  f"record(s) match; benign baseline clean ({len(benign)} record(s)) "
                  f"-- {note}")
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
    if fails and not args.report:
        print(f"FAILED: {fails} technique(s) did not satisfy attack-fires + "
              f"control-holds. (Use --report to treat as non-fatal.)")
        return 1
    if fails:
        print(f"Reported {fails} failure(s); not gated (--report).")
        return 0
    print(f"All {passes} external-cloud detection(s) fired on their recorded attack "
          f"fixtures, and every negative control held.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
