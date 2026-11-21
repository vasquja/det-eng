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
  array, one object, or (CloudTrail) `{"Records": [...]}`, with each key one time (the
  envelope too). A raw auditd line can carry the ENRICHED fields of auditd with no GS
  byte before them (`key="x"ARCH=x86_64 SYSCALL=unshare AUID="ubuntu"`, as in
  `T1068/linux_dirtyfrag/audit`). The loader takes only the lower-case fields of the
  kernel record (`auditd_records.py`, as the Linux validator does), so such a file is
  read: its upper-case fields are not keys of the event, and no key differs from
  another only in letter case.
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
  none of them gives `OTHER-PROCEDURE`, not an expected fire. A label turns a `MISS`
  into a pair that no mode fails, so it must come from the yml:
  - the report fails when the `description` of the yml at the commit does not hold the
    label (white space folded) as a whole token, with no letter, digit or hyphen next
    to it (`CVE-2026-4350` is not in `CVE-2026-43500`);
  - the report fails when a CVE of `cves` is not a whole token of that description and
    not the `cve.*` tag of a rule of the technique folder whose title holds the label
    as whole words, compared without white space, punctuation and letter case ("in"
    is no word of "Keyring Stuffing", and "Dirty" no word of "DirtyPipe"). The yml of Copy Fail names only the
    exploit, so its CVE comes from `T1068/copyfail_af_alg_authencesn.yml` ("... (CopyFail
    CVE-2026-31431)", `cve.2026-31431`), and the two CVEs of Dirty Frag from the two
    dirtyfrag rules of T1068. A change to the title or the `cve.*` tags of such a rule
    makes the report fail for that dataset;
  - `--lint` fails when a label in CVE form is not one of its `cves`.

  These checks do not prove that the label is the procedure: a generic phrase that is
  a whole token of the description, and whole words of the title of a rule with the
  listed CVE, still passes. The owner reviews each label and its CVEs
  (`.github/CODEOWNERS`): that review is the control for it.
- `excluded` holds each file of the log sources of the rules that the gate does not
  read, with a reason that is true: a format that is not native (OCSF, a Splunk search
  export, Activity Log events in the shape of the REST API, Splunk risk events, Office
  365 Management Activity), or records of one log source with more than 1900 distinct
  keys (one table of the gate cannot hold them with the fields of the rules; the
  report fails on such a dataset). `product` selects the rules that get an `EXCLUDED`
  row: those of the product whose folder is a technique of the file. No adapter
  converts such a file: a record that an agent converts is not a record that the agent
  did not write.

A dataset is in scope when a yml names it, the yml names the folder technique of a
rule, and the file is a log of the product of that rule. The report also scores each
rule on each pinned dataset of its log source of another technique (the benign view,
roadmap item R3c; [`../README.md`](../README.md#external-records-splunkattack_data)).
A file that no yml names has no entry: the report reads it only after the owner pins
it (the next section).

## Files that no yml names

Roadmap item R3c scores each rule on the files that no yml names too, but such a file
needs an entry in `SOURCES.json` first, and a new pin is a decision of the owner
(`AGENTS.md`, "Boundaries"). This list is a proposal; it waits for the owner. It comes
from the tree of `splunk/attack_data` at the pinned commit `4b19e4b6` (read on
2026-11-21 with a blobless clone; the sha256 and the size are those of the Git LFS
pointer, and the format and the records are what `--draft` found in the file):

| Path under `datasets/attack_techniques/` | Size | sha256 | What `--draft` found |
|------|-----:|--------|----------------------|
| `T1485/decommissioned_buckets/cloudtrail.json` | 13365 | `ef07feb9a4350482e319a4bda9724fd36c452b0e7a19ef8c8dc7dfbf7e5fc38f` | `cloudtrail-json`, 8 records, each event two times |
| `T1490/aws_bucket_version/cloudtrail.json` | 4394 | `1abe5a2bb8f10e54253ada63d4a6ecee62faf4969bb6df93181e5f1fa19ff8b6` | `cloudtrail-json`, 2 records, one event two times |
| `T1556.006/aws_new_mfa_method_registered_for_user/cloudtrail.json` | 2025 | `3947a363443b869c10b890febe58c27a75bd1208b729a35b02e05eb328d97617` | `cloudtrail-json`, 2 records |
| `T1621/aws_mfa_disabled/cloudtrail.json` | 1905 | `e2c27d7f359285c133610b966062534315ca9dddd9aa383172ace47a5da3f34a` | `cloudtrail-json`, 2 records |
| `T1185/aws_concurrent_sessions_from_different_ips/cloudtrail.json` | 2068 | `cf948583b0a978481ca3033c2d095ff4793b16c697a6de100dec18271067fad3` | `cloudtrail-json`, 2 records |
| `T1548.003/linux_auditd_sudoers_access/linux_path_sudoers.log` | 660 | `66ddf50daa9a4e2fab2548e98f7a82cc9bd3c78d04789f7e5afa1ba54cd66de8` | auditd PATH records in the form of `ausearch -i`: not raw |
| `T1548.003/linux_audited_doas_conf/linux_audited_doas_conf.log` | 1563 | `99a60c16d268a57a2489ec6bba718aaf95694b29cb01beddd3e2ca71277571b9` | raw auditd, PATH records only: no SYSCALL record |
| `T1098.004/linux_auditd_nopasswd/linux_path_ssh_config.log` | 227 | `8bba8bf433dc7a54aa26411092ecc6946e635fd282bffa63f36c2076246bba9c` | auditd PATH record, `ausearch -i` form: not raw |
| `T1574.006/linux_auditd_preload_file/linux_path_preload.log` | 227 | `81fb829014c6a0a08024a304c9f25ae5380054b5060e3768ffeb31b664566d08` | auditd PATH record, `ausearch -i` form: not raw |
| `T1053.003/linux_auditd_cron_file_audited/linux_path_cron.log` | 10247 | `eca54b2aecb6a55dd1b57437c99fe106d631e2fa7515a005893bdb2d66f96f63` | auditd PATH records, `ausearch -i` form: not raw |
| `T1546.004/linux_auditd_unix_shell_mod_config/linux_path_profile_d.log` | 655 | `c232815151609ba6854ae5e90b08ee8bfb83cf2c75ea783ac28986f92b9d1cba` | auditd PATH records, `ausearch -i` form: not raw |
| `T1569.002/linux_service_start/linux_service_start.log` | 4630 | `5c9707fa41038c245ad99e63f99e4b7a37dc07dbd2cd0850186b2e0b06d77533` | raw auditd, PROCTITLE records only: no SYSCALL record |
| `T1053.006/linux_services_restart/linux_services_restart.log` | 3991 | `c7197302320faf7e2574f6683327793c13c652be665ba4487f88a6521a230b54` | raw auditd, PROCTITLE records only: no SYSCALL record |

- The five CloudTrail files are native records. Each can be a dataset entry; its `yml`
  is the yml of its directory, which does not name the file, so the entry needs a form
  that the report accepts for a file that no yml names (today `check_yml()` refuses it).
  That form is a change of the gate and of `SOURCES.json`: the owner decides both.
  A probe at the pin found two rules that fire on `T1485/decommissioned_buckets/cloudtrail`:
  `T1537/aws_resource_policy_made_public.yml` (lines 3 and 4, a public bucket policy) and
  `T1537/aws_s3_block_public_access_disabled.yml` (lines 5 and 6). These are the
  "bucket-decommission capture" of design 4.3. No rule fired on the other four.
- The eight auditd files are the "8 auditd files that no yml names" of the R3 survey.
  None holds a raw SYSCALL record, which is what the auditd rules read, so they go to
  `excluded` with that reason, or stay out.
- Not in the list: the other files that no yml names hold no native record of a log
  source of the rules (Sysmon for Linux, OCSF of Amazon Security Lake, GitHub, Splunk
  audit trails, Windows). The search was by path and file name: it found no unnamed
  Azure, Kubernetes or GCP file.

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
