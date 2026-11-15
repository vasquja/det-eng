# External records: pins, declarations, licence

This directory holds what the external-records gate
([`../check_external_records.py`](../check_external_records.py)) needs to read the
datasets of [splunk/attack_data](https://github.com/splunk/attack_data). It holds no
record of that repository. The gate downloads each dataset, checks its sha256 and
keeps it in a cache outside the checkout. How the gate reads a dataset and what each
row means: [`../README.md`](../README.md#external-records-splunkattack_data).

| File | What it holds | Who changes it |
|------|---------------|----------------|
| `SOURCES.json` | The pin: one full commit of splunk/attack_data, its licence, and one entry for each dataset that the gate reads, and for each file that it leaves out (`excluded`, with the reason). | The owner (a pin bump) |
| `expectations.json` | The declarations: the expected verdict of a pair of a rule and a dataset, when it is not the default. Empty today. | The owner |
| `syscalls_x86_64.json` | The number and the name of each x86_64 syscall (Linux v6.18, `arch/x86/entry/syscalls/syscall_64.tbl`, rows of the ABIs `common` and `64`), for auditd records that give a syscall as a number. | The owner |
| `LICENSES/Apache-2.0-splunk-attack_data.txt` | The LICENSE file of splunk/attack_data at the pinned commit, byte for byte. | Only with a pin bump |

The three JSON files are not content for the merge policy (rail 8 of
`.github/workflows/automerge.yml`), and `.github/CODEOWNERS` gives them an owner. A
pull request that changes one of them needs a human: `AGENTS.md`, "Boundaries".

## Licence and attribution

splunk/attack_data is licensed under the Apache License 2.0. At the pinned commit
`4b19e4b6824a8ba91b0f5345a3a8de488619e823` (2026-11-12) its `LICENSE` file has the
sha256 `8505946b2464fa90223996d99eecbc7639a86648ca071f0cac21695be2623a0a` and the
notice "Copyright [2023] [Splunk Inc]", and the commit holds no NOTICE file. The copy
in `LICENSES/` is that file; `--lint` compares its sha256 with `SOURCES.json`, and
the report compares the file at the origin with the same sha256.

This repository does not redistribute a dataset: the CI job downloads each one and
keeps no copy, and its job summary and its uploaded report hold dataset ids, sha256
values, counts and the names of rule items, never a value of a record. A record that
someone copies into this repository (a case, an excerpt in a defect entry) is a
redistribution. It then needs, under Apache-2.0 section 4, the licence, a notice of
each change (identifiers must become the safe markers of `AGENTS.md`), and the
attribution above; a change of this kind is the owner's decision.

`syscalls_x86_64.json` holds facts of the source file (a number and a name for each
row), which is GPL-2.0 WITH Linux-syscall-note.

## SOURCES.json

```json
{"schema": 1, "repository": "splunk/attack_data",
 "commit": "<40 hex digits>", "licence": "Apache-2.0", "licence_file": "LICENSE",
 "licence_sha256": "<64 hex>", "licence_copy": "detections/external/LICENSES/...",
 "notice": "none: the commit holds no NOTICE file",
 "datasets": [{"id": "T1098.001/azure_ad_federated_identity_credential/azure-audit",
               "path": "datasets/attack_techniques/T1098.001/.../azure-audit.log",
               "sha256": "<64 hex: the Git LFS oid>", "size": 2998,
               "format": "azure-monitor-json", "records": 2,
               "techniques": ["T1098.001"], "sourcetype": "azure:monitor:aad",
               "yml": "datasets/attack_techniques/T1098.001/.../<name>.yml",
               "yml_sha256": "<64 hex>"}],
 "excluded": [{"id": "...", "path": "...", "sha256": "...", "size": 0,
               "techniques": ["T1537"], "product": "aws", "why": "..."}]}
```

- `id` is `<technique>/<directory>/<file stem>` of the path. The gate refuses an
  entry whose id is not the id of its path, and two entries of the same bytes (list
  one entry; `aliases` holds the other paths).
- `format` is `cloudtrail-json`, `azure-monitor-json`, `k8s-audit-json` or
  `auditd-raw`: native records only. A JSON file is one record for each line, a JSON
  array, one object, or (CloudTrail) `{"Records": [...]}`.
- `records` is the number of records that the loader must read (for auditd, the
  SYSCALL records). Another number is a fault: a loader that drops records cannot
  make a pass.
- `techniques` and `sourcetype` are what the yml gives at the commit (for a yml of the
  old schema, the technique of its directory). The report reads the yml from the
  origin, checks its sha256, and fails when it does not name the path, the techniques
  or the sourcetype of the entry. Without that check, an edit of `techniques` could
  take a dataset away from the rules of its technique.
- `procedure` (optional): `{label, cves, why}` for the raw auditd dataset of a CVE
  exploit (`--lint` refuses it on another format). The label is the CVE or the exploit
  name that the yml names, and `cves` its CVE IDs. A rule whose `cve.*` tags include
  none of them gives `OTHER-PROCEDURE`, not an expected fire. The report fails when the
  `description` of the yml at the commit does not hold the label: a label turns a
  `MISS` into a pair that no mode fails, so it must come from the yml. The `cves` are
  not in every yml (the yml of Copy Fail names only the exploit): the owner reviews
  each label and its CVEs.
- `excluded` holds each file of the log sources of the rules that the gate does not
  read, with a reason that is true: a format that is not native (OCSF, a Splunk search
  export, Activity Log events in the shape of the REST API, Splunk risk events, Office
  365 Management Activity). `product` selects the rules that get an `EXCLUDED` row:
  those of the product whose folder is a technique of the file. No adapter converts
  such a file: a record that an agent converts is not a record that the agent did not
  write.

A dataset is in scope when a yml names it, the yml names the folder technique of a
rule, and the file is a log of the product of that rule. A file that no yml names is
out of scope (roadmap item R3c).

## expectations.json

```json
{"schema": 1,
 "declarations": [{"rule": "T1098.001/entra_app_federated_credential_backdoor.yml",
                   "dataset": "T1098.001/azure_ad_federated_identity_credential/azure-audit",
                   "expect": "known-miss",
                   "why": "rule defect, tracked in detections/RULE_DEFECTS.md <ID>: ...",
                   "rule_digest": "<check_sufficiency.detection_digest of the rule>",
                   "sha256": "<the sha256 of the dataset in SOURCES.json>"}]}
```

| `expect` | The why starts | Meaning | It fails (`--enforce`) when |
|----------|----------------|---------|-----------------------------|
| (none) | | A same-technique pair of the same procedure must fire. | the rule does not fire: `MISS` |
| `quiet` | `quiet:` | The dataset is of the rule's own procedure, and the rule must not fire on it (a consent that a policy blocked). A real record is then a hard negative. | the rule fires: `DECLARED QUIET, FIRED` |
| `n/a` | `another procedure:` or `not in the capture:` | The dataset shows another procedure of the technique, or its capture does not record what the rule reads. | the rule fires: `STALE N/A` |
| `known-miss` | `rule defect, tracked in detections/RULE_DEFECTS.md <ID>:` | A miss with an open defect; the Summary table of `RULE_DEFECTS.md` must list `<ID>`. | the rule fires: `KNOWN-MISS FIRES`, close the defect |
| `fire` | `same procedure:` | A pair that is not expected (related, other procedure, no technique in common) must fire. | the rule does not fire: `MISS` |

A why that starts with `TODO` is refused (`--suggest` prints its drafts so). A
declaration is `STALE`, and excuses nothing, when the digest of the rule or the
sha256 of the dataset changed, when its defect is not in the Summary table, or when
it changes nothing (a `fire` on a pair that must fire already; an `n/a` or a
`known-miss` on a pair that is not expected). A declaration for a rule or a dataset
that does not exist is a fault (exit 2).

## Bump the pin

A bump is a human decision: it changes what the gate checks.

1. Choose the new full commit of splunk/attack_data. Read its `LICENSE` and look for
   a NOTICE file. When either changed, the licence is a decision of the owner first;
   then replace the copy in `LICENSES/` and `licence_sha256`.
2. For each dataset (and each file of `excluded`), print a draft entry at the new
   commit:

   ```bash
   python3 detections/check_external_records.py --commit <sha> \
     --draft datasets/attack_techniques/<T>/<dir>/<file> datasets/attack_techniques/<T>/<dir>/<name>.yml
   ```

   The draft reads the Git LFS pointer (the sha256 and the size) and the yml from the
   raw origin, downloads the file into the cache, finds its native format and counts
   its records. A file of no native format gives a draft of an `excluded` entry with a
   `TODO` reason. Write each reason yourself, from the file.
3. Put the new commit and the entries in `SOURCES.json`, keep the `procedure` labels
   that still hold, and run `--lint` and the report. Each declaration of a dataset
   whose sha256 changed is `STALE`: renew it only after you read the new rows.
4. A pair that fired at the old pin and misses at the new one is a real-record miss:
   find its cause before the bump merges.
