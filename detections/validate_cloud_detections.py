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
"""

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA = os.path.join(REPO, "detections", "sigma")
FIX = os.path.join(REPO, "detections", "cloud", "fixtures")


def marker(substr, *fields):
    """Gate: at least one of the named flattened fields contains substr."""
    def gate(e):
        return any(substr in str(e.get(f) or "") for f in fields)
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


def main():
    ap = argparse.ArgumentParser(description="Validate the external-cloud detections.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compile every cloud rule; no fixtures needed.")
    ap.add_argument("--report", action="store_true",
                    help="Report misses instead of failing on them.")
    args = ap.parse_args()

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
            continue
        try:
            queries[key] = sigma_eval.compile_rule(path)
            print(f"OK (compile)  {folder}/{fname}  [{trr}]")
        except Exception as e:  # noqa: BLE001
            parse_errors += 1
            print(f"ERROR compile {folder}/{fname}: {e}")
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

    if args.dry_run:
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
            continue
        attack = load_fixture(attack_path)
        benign = load_fixture(benign_path)
        q = queries[key]
        attack_hits = [hit[0] for hit in sigma_eval.evaluate(q, attack)]
        benign_hits = [hit[0] for hit in sigma_eval.evaluate(q, benign)]
        ours = [e for e in attack_hits if gate(e)]

        ok = True
        detail = []
        if not attack_hits:
            ok = False
            detail.append("rule did NOT fire on the attack fixture")
        elif not ours:
            ok = False
            detail.append(f"rule fired ({len(attack_hits)}) but no match carried the "
                          f"emulation marker")
        if benign_hits:
            ok = False
            detail.append(f"NEGATIVE CONTROL FAILED: rule fired on {len(benign_hits)} "
                          f"benign record(s)")

        if ok:
            passes += 1
            print(f"PASS  [{trr} {provider}] {fname}: {len(ours)}/{len(attack)} attack "
                  f"record(s) match; benign baseline clean ({len(benign)} record(s)) "
                  f"-- {note}")
        else:
            fails += 1
            print(f"FAIL  [{trr} {provider}] {fname}: " + "; ".join(detail) + f" -- {note}")

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
