"""Gate tests of the external-records gate (detections/check_external_records.py).

ExternalLint        `--lint` (offline: SOURCES.json, expectations.json and the syscall
                    table) on the real files, and on one planted defect each.
ExternalRecords     the report on a constructed set of datasets. The suite never
                    downloads (each gate run gets a proxy that refuses every
                    connection), and no record of splunk/attack_data is in the
                    repository: each dataset here is built from the cases of a real
                    sidecar, and the test puts it, with a constructed yml, in the
                    content-addressed cache of the gate (HOME/.cache/det-eng/external).
ExternalRecordsJob  the rules for the job `external-records` of detection-quality.yml.
ExternalLoaders     the auditd loader builds the events that the Linux validator
                    builds from the same lines; the static syscall table agrees with
                    the rules and with detections/k8s/auditd_file_events.py.
"""

import ast
import hashlib
import json
import os
import re
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gatelib  # noqa: E402

GATE = "detections/check_external_records.py"
SOURCES = "detections/external/SOURCES.json"
EXPECTATIONS = "detections/external/expectations.json"
SYSCALLS = "detections/external/syscalls_x86_64.json"
CACHE = os.path.join(".cache", "det-eng", "external", "sha256")     # under HOME

RULES = {
    "snapshot": "detections/sigma/T1537/aws_snapshot_or_ami_made_public.yml",
    "secret": "detections/sigma/T1552.007/k8s_secret_access.yml",
    "consent": "detections/sigma/T1528/entra_illicit_oauth_consent_grant.yml",
    "copyfail": "detections/sigma/T1068/copyfail_af_alg_authencesn.yml",
}
SIDECARS = {k: v[:-len(".yml")] + ".cases.jsonl" for k, v in RULES.items()}
# The constructed datasets: (path, format, sourcetype, technique, the sidecar case).
SET = {
    "snapshot": ("datasets/attack_techniques/T1537/planted_snapshot_public/cloudtrail.json",
                 "cloudtrail-json", "aws:cloudtrail", "T1537", "ebs-snapshot-made-public"),
    "secret": ("datasets/attack_techniques/T1552.007/planted_get_secret/audit.json",
               "k8s-audit-json", "__json", "T1552.007", "get-secret-procB"),
    "consent": ("datasets/attack_techniques/T1528/planted_consent/azure-audit.log",
                "azure-monitor-json", "azure:monitor:aad", "T1528", "user-consent-mail-files"),
    "copyfail": ("datasets/attack_techniques/T1068/planted_copyfail/audit.log",
                 "auditd-raw", "auditd", "T1068", "afalg-then-splice"),
}
SNAPSHOT_NEAR_MISS = "ebs-snapshot-shared-with-dr-account"
COPYFAIL_CVE = {"label": "CVE-2026-31431", "cves": ["CVE-2026-31431"],
                "why": "constructed by detections/tests from the positive case of the rule"}
YML = ("author: detections/tests (constructed; it holds no record of splunk/attack_data)\n"
       "description: {description}\n"
       "mitre_technique:\n- {technique}\n"
       "datasets:\n- name: planted\n  path: /{path}\n  sourcetype: '{sourcetype}'\n"
       "  source: planted\n")


def ds_id(path):
    """The id that the gate gives a data path: <technique>/<directory>/<file stem>."""
    technique, directory, name = path.split("/")[2:5]
    return f"{technique}/{directory}/{name.rsplit('.', 1)[0]}"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def case(tree, key, name):
    """The events of one case of a real sidecar."""
    for row in tree.read_jsonl(SIDECARS[key]):
        if row["name"] == name:
            return row
    raise LookupError(f"{SIDECARS[key]} has no case {name!r} (detections/tests/README.md, "
                      "Limits)")


def raw_audit(tree, events):
    """Raw auditd SYSCALL lines (the kernel's form) for normalized events of a sidecar."""
    names = {v: int(k) for k, v in tree.read_json(SYSCALLS)["syscalls"].items()}
    lines = []
    for n, e in enumerate(events, 7000):
        when = datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S.%f").replace(
            tzinfo=timezone.utc).timestamp()
        fields = ["arch=c000003e", f"syscall={names[e['syscall']]}", f"success={e['success']}",
                  f"exit={e['exit']}"] + [f"a{i}={e[f'a{i}']}" for i in range(4)] \
            + ["items=0", f"ppid={e['ppid']}", f"pid={e['pid']}"] \
            + [f"{k}={e[k]}" for k in ("auid", "uid", "euid") if k in e] \
            + [f'comm="{e["comm"]}"', f'exe="{e["exe"]}"', 'key="det-eng"']
        lines.append(f"type=SYSCALL msg=audit({int(when)}.{round(when % 1 * 1000):03d}:{n}): "
                     + " ".join(fields))
    return "".join(line + "\n" for line in lines).encode()


def jsonl(records):
    return "".join(json.dumps(r) + "\n" for r in records).encode()


def body_of(tree, key, name=None):
    """The bytes of the constructed dataset `key` (from its case, or the case `name`)."""
    events = case(tree, key, name or SET[key][4])["events"]
    return raw_audit(tree, events) if SET[key][1] == "auditd-raw" else jsonl(events)


def plant_set(tree, bodies, records=None, edit=None):
    """Replace the datasets of SOURCES.json in the copy with the constructed ones.

    bodies   {key of SET: bytes of the file}. Each file and its constructed yml go
             into the cache of the gate under HOME.
    records  {key: the pinned record count} (default: the records of the file).
    edit     edit(entries) changes the entries before they are written.
    Returns {key: entry}."""
    cache = os.path.join(tree.home, CACHE)
    os.makedirs(cache, exist_ok=True)
    entries = {}
    for key, body in bodies.items():
        path, fmt, sourcetype, technique, name = SET[key]
        yml = YML.format(description=f"constructed from the case {name}", technique=technique,
                         path=path, sourcetype=sourcetype).encode()
        for blob in (body, yml):
            with open(os.path.join(cache, sha(blob)), "wb") as fh:
                fh.write(blob)
        count = len([line for line in body.split(b"\n") if line.strip()])
        entries[key] = {"id": ds_id(path), "path": path, "sha256": sha(body), "size": len(body),
                        "format": fmt, "records": (records or {}).get(key, count),
                        "techniques": [technique], "sourcetype": sourcetype,
                        "yml": os.path.dirname(path) + "/planted.yml", "yml_sha256": sha(yml)}
        if key == "copyfail":
            entries[key]["procedure"] = COPYFAIL_CVE
    if edit:
        edit(entries)
    tree.edit_json(SOURCES, lambda doc: doc.update(datasets=list(entries.values()), excluded=[]))
    return entries


def declare(tree, *declarations):
    tree.edit_json(EXPECTATIONS, lambda doc: doc.update(declarations=list(declarations)))


DIGESTS = ("import json, sys\nsys.path.insert(0, 'detections')\nimport check_sufficiency\n"
           "print(json.dumps({p: check_sufficiency.detection_digest(p) for p in sys.argv[1:]}))\n")


def digests(tree, *paths):
    """{rule path: check_sufficiency.detection_digest} in the copy."""
    result = tree.run_python(DIGESTS, *paths)
    if result.returncode != 0:
        raise AssertionError("the digest of a rule could not be computed:\n" + result.describe())
    return json.loads(result.stdout)


def rule_key(path):
    return path[len("detections/sigma/"):]


def row(result, pattern):
    """The one output line that matches `pattern` (re.MULTILINE)."""
    found = re.findall(pattern, result.output, re.MULTILINE)
    if len(found) != 1:
        raise AssertionError(f"wanted one line /{pattern}/, got {len(found)}:\n"
                             + result.describe())
    return found[0]


class ExternalLint(gatelib.StartedTogether):
    """`--lint` reads SOURCES.json, expectations.json and the syscall table, and no
    dataset. The control is the CI command (`--lint`) on the unmodified copy. Each
    run plants one defect in a copy of a real file."""

    GATE = GATE
    PARTS = gatelib.DETECTIONS
    RUNS = ("dotdot_path", "short_commit", "duplicate_id", "duplicate_bytes", "bad_sha",
            "over_cap", "licence", "licence_copy", "no_dataset", "unknown_rule",
            "unknown_dataset", "stale_digest", "stale_digest_enforce", "sha_mismatch",
            "unknown_word", "todo_why", "bad_prefix", "untracked_defect", "redundant_fire",
            "duplicate_pair", "bad_procedure")

    @classmethod
    def start_gate(cls, tree, *more):
        return tree.start(cls.GATE, "--lint", *more)

    @classmethod
    def pair(cls):
        """A rule and a dataset of the real SOURCES.json that make a same-technique pair
        (the folder of the rule is a technique of the dataset, and the dataset has no
        procedure label), with the digest of the rule: a valid n/a declaration."""
        if "_pair" not in cls.__dict__:
            good = cls.good()
            doc = good.read_json(SOURCES)
            for ds in doc["datasets"]:
                if ds.get("procedure"):
                    continue
                rules = sorted(p for t in ds["techniques"]
                               for p in good.glob(f"detections/sigma/{t}/*.yml"))
                if rules:
                    break
            cls._pair = {"rule": rule_key(rules[0]), "dataset": ds["id"], "expect": "n/a",
                         "why": "another procedure: planted by detections/tests",
                         "rule_digest": digests(good, rules[0])[rules[0]],
                         "sha256": ds["sha256"]}
        return dict(cls._pair)

    @classmethod
    def edit_first(cls, tree, change):
        tree.edit_json(SOURCES, lambda doc: change(doc["datasets"][0]))

    @classmethod
    def begin_dotdot_path(cls, tree):
        # A `..` in the path: the URL that the gate makes would name another file. The
        # path has the form <technique>/<directory>/<file>, with `..` as the directory.
        cls.edit_first(tree, lambda d: d.update(
            path="datasets/attack_techniques/" + d["path"].split("/")[2] + "/../README.md"))
        return cls.start_gate(tree)

    @classmethod
    def begin_short_commit(cls, tree):
        # A short SHA can name another commit later, or two commits.
        tree.edit_json(SOURCES, lambda doc: doc.update(commit=doc["commit"][:8]))
        return cls.start_gate(tree)

    @classmethod
    def begin_duplicate_id(cls, tree):
        def change(doc):
            twin = dict(doc["datasets"][0], sha256="e" * 64)
            doc["datasets"].append(twin)
        tree.edit_json(SOURCES, change)
        return cls.start_gate(tree)

    @classmethod
    def begin_duplicate_bytes(cls, tree):
        # The same bytes under a second path: one entry, the other path in `aliases`.
        def change(doc):
            first = doc["datasets"][0]
            path = first["path"].rsplit("/", 1)[0] + "/planted_twin.json"
            doc["datasets"].append(dict(first, path=path, id=first["id"].rsplit("/", 1)[0]
                                        + "/planted_twin"))
        tree.edit_json(SOURCES, change)
        return cls.start_gate(tree)

    @classmethod
    def begin_bad_sha(cls, tree):
        cls.edit_first(tree, lambda d: d.update(sha256=d["sha256"].upper()))
        return cls.start_gate(tree)

    @classmethod
    def begin_over_cap(cls, tree):
        cls.edit_first(tree, lambda d: d.update(size=50 * 1024 * 1024 + 1))
        return cls.start_gate(tree)

    @classmethod
    def begin_licence(cls, tree):
        tree.edit_json(SOURCES, lambda doc: doc.update(licence="MIT"))
        return cls.start_gate(tree)

    @classmethod
    def begin_licence_copy(cls, tree):
        copy = tree.read_json(SOURCES)["licence_copy"]
        tree.append(copy, "PLANTED by detections/tests\n")
        return cls.start_gate(tree)

    @classmethod
    def begin_no_dataset(cls, tree):
        tree.edit_json(SOURCES, lambda doc: doc.update(datasets=[]))
        return cls.start_gate(tree)

    @classmethod
    def begin_unknown_rule(cls, tree):
        declare(tree, dict(cls.pair(), rule="T9999/planted_no_such_rule.yml"))
        return cls.start_gate(tree)

    @classmethod
    def begin_unknown_dataset(cls, tree):
        declare(tree, dict(cls.pair(), dataset="T9999/planted/no_such_dataset"))
        return cls.start_gate(tree)

    @classmethod
    def begin_stale_digest(cls, tree):
        # The digest of another rule text: the rule changed after the human approved.
        declare(tree, dict(cls.pair(), rule_digest="0" * 64))
        return cls.start_gate(tree)

    @classmethod
    def begin_stale_digest_enforce(cls, tree):
        declare(tree, dict(cls.pair(), rule_digest="0" * 64))
        return cls.start_gate(tree, "--enforce")

    @classmethod
    def begin_sha_mismatch(cls, tree):
        declare(tree, dict(cls.pair(), sha256="f" * 64))
        return cls.start_gate(tree, "--enforce")

    @classmethod
    def begin_unknown_word(cls, tree):
        declare(tree, dict(cls.pair(), expect="maybe"))
        return cls.start_gate(tree)

    @classmethod
    def begin_todo_why(cls, tree):
        declare(tree, dict(cls.pair(), why="TODO: decide"))
        return cls.start_gate(tree)

    @classmethod
    def begin_bad_prefix(cls, tree):
        declare(tree, dict(cls.pair(), expect="quiet", why="the rule must not fire here"))
        return cls.start_gate(tree)

    @classmethod
    def begin_untracked_defect(cls, tree):
        declare(tree, dict(cls.pair(), expect="known-miss",
                           why="rule defect, tracked in detections/RULE_DEFECTS.md Z99: planted"))
        return cls.start_gate(tree, "--enforce")

    @classmethod
    def begin_redundant_fire(cls, tree):
        declare(tree, dict(cls.pair(), expect="fire", why="same procedure: planted"))
        return cls.start_gate(tree, "--enforce")

    @classmethod
    def begin_duplicate_pair(cls, tree):
        declare(tree, cls.pair(), cls.pair())
        return cls.start_gate(tree)

    @classmethod
    def begin_bad_procedure(cls, tree):
        def change(doc):
            labelled = next(d for d in doc["datasets"] if d.get("procedure"))
            labelled["procedure"] = dict(labelled["procedure"], cves=["2026-31431"])
        tree.edit_json(SOURCES, change)
        return cls.start_gate(tree)

    def test_control_lint_accepts_the_tree(self):
        self.assert_ci_runs(GATE, "--lint")
        good = self.good()
        doc = good.read_json(SOURCES)
        declared = len(good.read_json(EXPECTATIONS)["declarations"])
        syscalls = len(good.read_json(SYSCALLS)["syscalls"])
        self.assertGreater(len(doc["datasets"]), 20, "SOURCES.json was not read")
        _, result = self.started()
        self.assert_accepts(result, rf"^SOURCES\.json: {len(doc['datasets'])} dataset\(s\) and "
                            rf"{len(doc['excluded'])} excluded at {doc['commit'][:12]}; licence "
                            rf"Apache-2\.0 \(copy \S+ sha256 ok\); syscalls_x86_64\.json: "
                            rf"{syscalls} syscall\(s\) of Linux v[\d.]+; expectations\.json: "
                            rf"{declared} declaration\(s\); 0 stale$")

    def test_rejects_a_path_that_leaves_the_datasets(self):
        _, result = self.started("dotdot_path")
        self.assert_rejects(result, r"^ERROR SOURCES\.json dataset '[^']+': path "
                            r"'datasets/attack_techniques/T[\d.]+/\.\./README\.md' is not a path "
                            r"of splunk/attack_data", exit_code=2)
        self.assertEqual(result.output.count("ERROR "), 1, result.describe())

    def test_rejects_a_commit_that_is_not_a_full_sha(self):
        _, result = self.started("short_commit")
        self.assert_rejects(result, r"^ERROR SOURCES\.json: commit '[0-9a-f]{8}' is not a full "
                            r"commit SHA", exit_code=2)

    def test_rejects_an_id_that_is_listed_twice(self):
        _, result = self.started("duplicate_id")
        self.assert_rejects(result, r"^ERROR SOURCES\.json dataset '[^']+': the id '[^']+' is "
                            r"listed twice$", exit_code=2)
        self.assertEqual(result.output.count("ERROR "), 1, result.describe())

    def test_rejects_the_same_bytes_under_two_paths(self):
        _, result = self.started("duplicate_bytes")
        self.assert_rejects(result, r"^ERROR SOURCES\.json dataset '[^']+/planted_twin': the "
                            r"sha256 [0-9a-f]{12}\.\.\. is also the sha256 of [^:]+: list one "
                            r"entry for the bytes, with the other path in its `aliases`$",
                            exit_code=2)
        self.assertEqual(result.output.count("ERROR "), 1, result.describe())

    def test_rejects_a_sha256_that_is_not_lower_case_hex(self):
        _, result = self.started("bad_sha")
        self.assert_rejects(result, r"^ERROR SOURCES\.json dataset '[^']+': sha256 '[0-9A-F]{64}' "
                            r"is not 64 lower-case hex digits$", exit_code=2)

    def test_rejects_a_size_over_the_cap(self):
        _, result = self.started("over_cap")
        self.assert_rejects(result, r"^ERROR SOURCES\.json dataset '[^']+': size 52428801 is over "
                            r"the cap of 52428800 bytes$", exit_code=2)

    def test_rejects_another_licence(self):
        _, result = self.started("licence")
        self.assert_rejects(result, r"^ERROR SOURCES\.json: licence 'MIT' is not 'Apache-2\.0', the "
                            r"licence that the owner accepted", exit_code=2)

    def test_rejects_a_changed_licence_copy(self):
        _, result = self.started("licence_copy")
        self.assert_rejects(result, r"^ERROR SOURCES\.json: the licence copy detections/external/"
                            r"LICENSES/\S+ has sha256 [0-9a-f]{64}, not the licence_sha256 "
                            r"[0-9a-f]{64}$", exit_code=2)

    def test_rejects_a_list_without_a_dataset(self):
        _, result = self.started("no_dataset")
        self.assert_rejects(result, r"^ERROR SOURCES\.json lists no dataset: the gate would check "
                            r"nothing$", exit_code=2)

    def test_rejects_a_declaration_for_a_rule_that_does_not_exist(self):
        _, result = self.started("unknown_rule")
        self.assert_rejects(result, r"^ERROR expectations\.json: the declaration for "
                            r"'T9999/planted_no_such_rule\.yml' on '[^']+': names the rule "
                            r"'T9999/planted_no_such_rule\.yml', which does not exist", exit_code=2)

    def test_rejects_a_declaration_for_a_dataset_that_is_not_listed(self):
        _, result = self.started("unknown_dataset")
        self.assert_rejects(result, r"^ERROR expectations\.json: the declaration for '[^']+' on "
                            r"'T9999/planted/no_such_dataset': names the dataset "
                            r"'T9999/planted/no_such_dataset', which SOURCES\.json does not list$",
                            exit_code=2)

    def test_shadow_reports_a_stale_digest_and_exits_0(self):
        """The CI command (shadow): a stale declaration is a row, not a failure."""
        pair = self.pair()
        _, result = self.started("stale_digest")
        self.assert_accepts(result, r"; 1 stale$")
        self.assertRegex(result.output, re.compile(
            rf"^STALE     {re.escape(pair['rule'])} on {re.escape(pair['dataset'])}: the n/a "
            rf"declaration no longer applies: the rule now digests to {pair['rule_digest']} "
            r"\(declared 0{64}\)", re.MULTILINE))

    def test_enforce_rejects_a_stale_digest(self):
        self.assert_documented(f"python3 {GATE} --lint --enforce")
        pair = self.pair()
        _, result = self.started("stale_digest_enforce")
        self.assert_rejects(result, rf"^STALE     {re.escape(pair['rule'])} on "
                            rf"{re.escape(pair['dataset'])}: the n/a declaration no longer "
                            rf"applies: the rule now digests to {pair['rule_digest']}", exit_code=1)

    def test_enforce_rejects_a_declaration_of_other_bytes(self):
        pair = self.pair()
        _, result = self.started("sha_mismatch")
        self.assert_rejects(result, rf"^STALE     .* no longer applies: SOURCES\.json now pins "
                            rf"{pair['sha256']} \(declared f{{64}}\)$", exit_code=1)

    def test_rejects_an_unknown_verdict_word(self):
        _, result = self.started("unknown_word")
        self.assert_rejects(result, r"^ERROR expectations\.json: the declaration for .*: expect "
                            r"'maybe' is not one of \('quiet', 'n/a', 'known-miss', 'fire'\)$",
                            exit_code=2)

    def test_rejects_a_why_that_is_todo(self):
        _, result = self.started("todo_why")
        self.assert_rejects(result, r"^ERROR expectations\.json: the declaration for .*: the why "
                            r"starts with TODO: a human writes the reason$", exit_code=2)

    def test_rejects_a_why_without_its_prefix(self):
        _, result = self.started("bad_prefix")
        self.assert_rejects(result, r"^ERROR expectations\.json: the declaration for .*: a quiet "
                            r"why starts 'quiet:' and says more$", exit_code=2)

    def test_enforce_rejects_a_known_miss_of_a_defect_that_is_not_listed(self):
        _, result = self.started("untracked_defect")
        self.assert_rejects(result, r"^STALE     .*: the known-miss declaration no longer applies: "
                            r"it cites Z99, which the Summary table of "
                            r"detections/RULE_DEFECTS\.md does not list$", exit_code=1)

    def test_enforce_rejects_a_fire_declaration_that_changes_nothing(self):
        _, result = self.started("redundant_fire")
        self.assert_rejects(result, r"^STALE     .*: the fire declaration no longer applies: the "
                            r"pair is same technique and procedure, so the rule must fire "
                            r"already$", exit_code=1)

    def test_rejects_a_pair_that_is_declared_twice(self):
        _, result = self.started("duplicate_pair")
        self.assert_rejects(result, r"^ERROR expectations\.json: the declaration for .*: the pair "
                            r"is declared twice$", exit_code=2)

    def test_rejects_a_procedure_label_without_cve_ids(self):
        _, result = self.started("bad_procedure")
        self.assert_rejects(result, r"^ERROR SOURCES\.json dataset '[^']+': procedure must be "
                            r"\{label, cves, why\}", exit_code=2)


class ExternalRecords(gatelib.StartedTogether):
    """The report on a constructed set: four datasets, each made from one case of a
    real sidecar (a CloudTrail record, a Kubernetes audit event, an Entra audit
    record, two raw auditd SYSCALL lines), in the cache of the gate.

    The control of the class is the CI step on the unmodified copy: the suite has no
    network, so every pinned dataset is UNAVAILABLE and the run must fail (exit 2): a
    run that read no dataset checked nothing. The runs `constructed` (the CI step)
    and `constructed_enforce` (the documented --enforce) accept the constructed set.
    The first rejection is the CI step on a cached file of other bytes."""

    GATE = GATE
    PARTS = gatelib.DETECTIONS
    RUNS = ("constructed", "constructed_enforce", "hash_mismatch", "miss_enforce", "miss_shadow",
            "declared_quiet_fired", "stale_na", "known_miss_fires", "unavailable_enforce",
            "unavailable_one_shadow", "not_a_record", "count_changed", "line_not_object",
            "not_utf8", "case_clash", "unstorable_value", "yml_technique", "twin",
            "twin_attack_only", "self_declared", "self_declared_plain")
    STEP = ("detection-quality.yml", "external-records", f"{GATE} --markdown")

    @classmethod
    def start_gate(cls, tree):
        """The CI step (shadow), as the job runs it."""
        return tree.start_step(gatelib.ci_step(*cls.STEP))

    @classmethod
    def start_enforce(cls, tree, *keys):
        """The documented --enforce, for the rules of `keys` (default: all four)."""
        return tree.start(cls.GATE, "--enforce",
                          *[a for k in (keys or RULES) for a in ("--rule", RULES[k])])

    @classmethod
    def standard(cls, tree, **bodies):
        """The four constructed datasets; `bodies` replaces the bytes of some."""
        return plant_set(tree, {k: bodies.get(k, body_of(tree, k)) for k in SET})

    @classmethod
    def rule_digests(cls):
        if "_digests" not in cls.__dict__:
            cls._digests = digests(cls.good(), *RULES.values())
        return cls._digests

    @classmethod
    def declaration(cls, entry, expect, why):
        return {"rule": rule_key(RULES["snapshot"]), "dataset": entry["id"], "expect": expect,
                "why": why, "rule_digest": cls.rule_digests()[RULES["snapshot"]],
                "sha256": entry["sha256"]}

    @classmethod
    def begin_constructed(cls, tree):
        cls.standard(tree)
        return cls.start_gate(tree)

    @classmethod
    def begin_constructed_enforce(cls, tree):
        cls.standard(tree)
        return cls.start_enforce(tree)

    @classmethod
    def begin_hash_mismatch(cls, tree):
        entries = cls.standard(tree)
        path = os.path.join(tree.home, CACHE, entries["snapshot"]["sha256"])
        with open(path, "r+b") as fh:          # one byte of the cached file changed
            first = fh.read(1)
            fh.seek(0)
            fh.write(b"[" if first != b"[" else b"{")
        return cls.start_gate(tree)

    @classmethod
    def begin_miss_enforce(cls, tree):
        cls.standard(tree, snapshot=body_of(tree, "snapshot", SNAPSHOT_NEAR_MISS))
        return cls.start_enforce(tree, "snapshot")

    @classmethod
    def begin_miss_shadow(cls, tree):
        cls.standard(tree, snapshot=body_of(tree, "snapshot", SNAPSHOT_NEAR_MISS))
        return cls.start_gate(tree)

    @classmethod
    def begin_declared_quiet_fired(cls, tree):
        entries = cls.standard(tree)
        declare(tree, cls.declaration(entries["snapshot"], "quiet", "quiet: planted"))
        return cls.start_enforce(tree, "snapshot")

    @classmethod
    def begin_stale_na(cls, tree):
        entries = cls.standard(tree)
        declare(tree, cls.declaration(entries["snapshot"], "n/a",
                                      "another procedure: planted"))
        return cls.start_enforce(tree, "snapshot")

    @classmethod
    def begin_known_miss_fires(cls, tree):
        entries = cls.standard(tree)
        defect = cls.tracked_defect(tree)
        declare(tree, cls.declaration(entries["snapshot"], "known-miss",
                                      f"rule defect, tracked in detections/RULE_DEFECTS.md "
                                      f"{defect}: planted"))
        return cls.start_enforce(tree, "snapshot")

    @staticmethod
    def tracked_defect(tree):
        """The first ID of the Summary table of RULE_DEFECTS.md in the copy."""
        return re.search(r"^\| \[([A-Z]\d+)\]\(", tree.read("detections/RULE_DEFECTS.md"),
                         re.MULTILINE).group(1)

    @classmethod
    def remove_cached(cls, tree, entry):
        os.remove(os.path.join(tree.home, CACHE, entry["sha256"]))

    @classmethod
    def begin_unavailable_enforce(cls, tree):
        cls.remove_cached(tree, cls.standard(tree)["snapshot"])
        return cls.start_enforce(tree)

    @classmethod
    def begin_unavailable_one_shadow(cls, tree):
        cls.remove_cached(tree, cls.standard(tree)["snapshot"])
        return cls.start_gate(tree)

    @classmethod
    def begin_not_a_record(cls, tree):
        # A Splunk ES risk event in a file that the yml labels aws:cloudtrail.
        with open(os.path.join(gatelib.KNOWN_BAD, "external/splunk_risk_event.log"), "rb") as fh:
            cls.standard(tree, snapshot=fh.read())
        return cls.start_gate(tree)

    @classmethod
    def begin_count_changed(cls, tree):
        cls.standard(tree)
        tree.edit_json(SOURCES, lambda doc: doc["datasets"][0].update(records=2))
        return cls.start_gate(tree)

    @classmethod
    def begin_line_not_object(cls, tree):
        with open(os.path.join(gatelib.KNOWN_BAD, "external/json_not_object.jsonl"), "rb") as fh:
            cls.standard(tree, snapshot=fh.read())
        return cls.start_gate(tree)

    @classmethod
    def begin_not_utf8(cls, tree):
        with open(os.path.join(gatelib.KNOWN_BAD, "external/not_utf8.jsonl"), "rb") as fh:
            cls.standard(tree, snapshot=fh.read())
        return cls.start_gate(tree)

    @classmethod
    def begin_case_clash(cls, tree):
        record = case(tree, "snapshot", SET["snapshot"][4])["events"][0]
        record["EventName"] = record["eventName"]       # a second spelling of one key
        cls.standard(tree, snapshot=jsonl([record]))
        return cls.start_gate(tree)

    @classmethod
    def begin_unstorable_value(cls, tree):
        # An integer that one SQLite table cannot hold (above 2**63 - 1): the table of
        # sigma_eval.py stops with OverflowError when the gate does not refuse it first.
        record = case(tree, "snapshot", SET["snapshot"][4])["events"][0]
        record["planted"] = 2 ** 70
        cls.standard(tree, snapshot=jsonl([record]))
        return cls.start_gate(tree)

    @classmethod
    def begin_yml_technique(cls, tree):
        # SOURCES.json names another technique than the yml of the dataset at the commit.
        plant_set(tree, {k: body_of(tree, k) for k in SET},
                  edit=lambda e: e["snapshot"].update(techniques=["T1530"]))
        return cls.start_gate(tree)

    @classmethod
    def twin_body(cls, tree):
        """Line 1: the attack record, which the rule misses (the share of a snapshot with
        one account). Line 2: the record that the yml calls benign, on which the rule
        fires (a public share of the test account, kept to test the filter)."""
        near = case(tree, "snapshot", SNAPSHOT_NEAR_MISS)["events"]
        twin = case(tree, "snapshot", SET["snapshot"][4])["events"]
        return jsonl(near + twin)

    @classmethod
    def begin_twin(cls, tree):
        cls.standard(tree, snapshot=cls.twin_body(tree))
        return cls.start_enforce(tree, "snapshot")

    @classmethod
    def begin_twin_attack_only(cls, tree):
        cls.standard(tree, snapshot=jsonl(case(tree, "snapshot", SNAPSHOT_NEAR_MISS)["events"]))
        return cls.start_enforce(tree, "snapshot")

    # The planted change to the rule: it stops reading `get` (the constructed record is
    # a get of a secret), so the rule misses its dataset.
    SECRET_GET = "      - 'get'\n"

    @classmethod
    def begin_self_declared(cls, tree):
        entries = cls.standard(tree)
        tree.replace(RULES["secret"], cls.SECRET_GET, "")
        declare(tree, {"rule": rule_key(RULES["secret"]), "dataset": entries["secret"]["id"],
                       "expect": "n/a", "why": "another procedure: planted with the rule change",
                       "rule_digest": digests(tree, RULES["secret"])[RULES["secret"]],
                       "sha256": entries["secret"]["sha256"]})
        return cls.start_enforce(tree, "secret")

    @classmethod
    def begin_self_declared_plain(cls, tree):
        cls.standard(tree)
        tree.replace(RULES["secret"], cls.SECRET_GET, "")
        return cls.start_enforce(tree, "secret")

    def id_of(self, key):
        return re.escape(ds_id(SET[key][0]))

    def test_control_the_real_pins_without_network_read_nothing(self):
        """The CI step on the unmodified copy: no cache and no network, so each dataset
        is UNAVAILABLE (a row and a ::warning) and the run fails as vacuous."""
        good = self.good()
        n = len(good.read_json(SOURCES)["datasets"])
        _, result = self.started()
        self.assertEqual(len(re.findall(r"^UNAVAILABLE \S+: ", result.output, re.MULTILINE)), n,
                         result.describe())
        self.assertEqual(len(re.findall(r"^::warning title=external-records::UNAVAILABLE ",
                                        result.output, re.MULTILINE)), n + 2, result.describe())
        self.assert_rejects(result, r"^ERROR no dataset was read, so the run checked nothing",
                            exit_code=2)

    def test_constructed_set_ci_step_reports_each_verdict(self):
        """The CI step (shadow) accepts the constructed set and reports each pair."""
        tree, result = self.started("constructed")
        self.assert_accepts(result, r"^Summary: \d+ of \d+ rule\(s\) have a same-technique "
                            r"dataset; .*; 4 dataset\(s\) read, 0 unavailable; shadow: \d+ "
                            r"verdict\(s\) would fail --enforce$")
        for key in ("snapshot", "secret", "consent"):
            self.assertRegex(result.output, re.compile(
                rf"^FIRE      {re.escape(rule_key(RULES[key]))} on {self.id_of(key)}  1/1 "
                rf"record\(s\) \(line 1\)  \[same technique {SET[key][3]}\]$", re.MULTILINE))
        # A correlation counts alerts and the distinct records that are their evidence.
        self.assertRegex(result.output, re.compile(
            rf"^FIRE      {re.escape(rule_key(RULES['copyfail']))} on {self.id_of('copyfail')}  "
            r"1 alert\(s\), 2 distinct evidence record\(s\) of 2 record\(s\)  \[same technique "
            r"T1068\]$", re.MULTILINE))
        # Another rule of the technique and log source must fire too: a MISS row.
        self.assertRegex(result.output, re.compile(
            rf"^MISS      T1537/\S+ on {self.id_of('snapshot')}  0 of 1 record\(s\); nearest "
            r"line 1 \(", re.MULTILINE))
        # A rule of the technique whose log source the dataset does not hold.
        self.assertRegex(result.output, re.compile(
            rf"^NOT READ  T1528/entra_device_code_authentication\.yml on {self.id_of('consent')}: "
            r"no azure/signinlogs record \(the dataset holds: azure/auditlogs\)$", re.MULTILINE))
        # A rule of another CVE than the label of the dataset.
        self.assertRegex(result.output, re.compile(
            rf"^OTHER-PROCEDURE T1068/dirtypipe_splice_readonly\.yml on {self.id_of('copyfail')} "
            r".*\[same technique T1068; the dataset is CVE-2026-31431, the CVE tags of the rule: "
            r"CVE-2022-0847; not expected\]$", re.MULTILINE))
        # A rule whose other attack tag is the technique of the dataset.
        self.assertRegex(result.output, re.compile(
            rf"^RELATED   T1609/k8s_node_proxy_kubelet_api\.yml on {self.id_of('secret')}  0/1 "
            r"record\(s\)  \[tag T1552\.007; not expected\]$", re.MULTILINE))
        with open(tree.out("github/github_step_summary"), encoding="utf-8") as fh:
            self.assertIn("## External records (splunk/attack_data, shadow)", fh.read())
        with open(tree.out("runner-temp/external-records.json"), encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual((report["mode"], report["exit"], len(report["datasets"])),
                         ("shadow", 0, 4))

    def test_constructed_set_enforce_accepts_the_four_fires(self):
        self.assert_documented(f"python3 {GATE} --enforce")
        _, result = self.started("constructed_enforce")
        self.assert_accepts(result, r"^Summary: 4 of 4 rule\(s\) have a same-technique dataset; 4 "
                            r"expected pair\(s\): 4 fire, 0 miss, 0 declared; .*enforce: 0 "
                            r"verdict\(s\) fail$")

    def test_rejects_a_cached_file_of_other_bytes(self):
        """The CI step: a cached file whose sha256 is not the pin fails the run in shadow
        mode too, and the file is gone from the cache."""
        tree, result = self.started("hash_mismatch")
        entry = tree.read_json(SOURCES)["datasets"][0]
        self.assert_rejects(result, rf"^ERROR HASH MISMATCH {self.id_of('snapshot')}: the pin is "
                            rf"{entry['sha256']} \({entry['size']} bytes\); got (?!{entry['sha256']})"
                            r"[0-9a-f]{64} \(\d+ bytes\) from the cache \(.*\); the file was "
                            r"deleted\.", exit_code=2)
        self.assertFalse(os.path.exists(os.path.join(tree.home, CACHE, entry["sha256"])))

    def test_enforce_rejects_a_miss(self):
        tree, result = self.started("miss_enforce")
        broken = case(tree, "snapshot", SNAPSHOT_NEAR_MISS)["breaks"]
        self.assert_rejects(result, rf"^MISS      {re.escape(rule_key(RULES['snapshot']))} on "
                            rf"{self.id_of('snapshot')}  0 of 1 record\(s\); nearest line 1 "
                            rf"\(near-miss; one flip would fire it: {re.escape(', '.join(broken))}\)"
                            r"  \[same technique T1537; no declaration\]$", exit_code=1)

    def test_shadow_reports_a_miss_and_exits_0(self):
        _, result = self.started("miss_shadow")
        self.assert_accepts(result, r"shadow: \d+ verdict\(s\) would fail --enforce$")
        self.assertRegex(result.output, re.compile(
            rf"^MISS      {re.escape(rule_key(RULES['snapshot']))} on {self.id_of('snapshot')}  0 of "
            r"1 record\(s\); nearest line 1 \(near-miss; ", re.MULTILINE))

    def test_enforce_rejects_a_quiet_declaration_that_fired(self):
        _, result = self.started("declared_quiet_fired")
        self.assert_rejects(result, rf"^DECLARED QUIET, FIRED {re.escape(rule_key(RULES['snapshot']))}"
                            rf" on {self.id_of('snapshot')}  1/1 record\(s\) \(line 1\): the "
                            r"declaration says the rule must not fire on it$", exit_code=1)

    def test_enforce_rejects_an_na_declaration_that_fired(self):
        _, result = self.started("stale_na")
        self.assert_rejects(result, rf"^STALE N/A {re.escape(rule_key(RULES['snapshot']))} on "
                            rf"{self.id_of('snapshot')}  1/1 record\(s\) \(line 1\): the rule "
                            r"fires, so the pair applies; remove the n/a declaration$", exit_code=1)

    def test_enforce_rejects_a_known_miss_that_fires(self):
        tree, result = self.started("known_miss_fires")
        defect = self.tracked_defect(tree)
        self.assert_rejects(result, rf"^KNOWN-MISS FIRES {re.escape(rule_key(RULES['snapshot']))} "
                            rf"on {self.id_of('snapshot')}  1/1 record\(s\) \(line 1\): close "
                            rf"{defect} in detections/RULE_DEFECTS\.md and remove the declaration$",
                            exit_code=1)

    def test_enforce_rejects_an_unavailable_dataset(self):
        _, result = self.started("unavailable_enforce")
        self.assertRegex(result.output, re.compile(
            rf"^UNAVAILABLE {self.id_of('snapshot')}: ", re.MULTILINE))
        self.assert_rejects(result, r"^ERROR --enforce: 1 dataset\(s\) UNAVAILABLE$", exit_code=2)

    def test_shadow_reports_one_unavailable_dataset_and_exits_0(self):
        _, result = self.started("unavailable_one_shadow")
        self.assert_accepts(result, r"; 3 dataset\(s\) read, 1 unavailable; shadow: ")
        self.assertRegex(result.output, re.compile(
            rf"^::warning title=external-records::UNAVAILABLE {self.id_of('snapshot')}: ",
            re.MULTILINE))

    def test_rejects_a_line_that_is_not_a_record(self):
        _, result = self.started("not_a_record")
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: line 1 is not JSON ",
                            exit_code=2)

    def test_rejects_a_record_count_that_is_not_the_pin(self):
        _, result = self.started("count_changed")
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: the loader read 1 "
                            r"record\(s\); SOURCES\.json pins 2\.", exit_code=2)

    def test_rejects_a_line_that_is_json_and_not_an_object(self):
        _, result = self.started("line_not_object")
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: line 2 is JSON and not an "
                            r"object \(a list\)$", exit_code=2)

    def test_rejects_a_file_that_is_not_utf8(self):
        _, result = self.started("not_utf8")
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: the file is not UTF-8 "
                            r"\(byte \d+ is not valid UTF-8\)$", exit_code=2)

    def test_rejects_keys_that_differ_only_in_letter_case(self):
        _, result = self.started("case_clash")
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: keys that differ only in "
                            r"letter case: 'EventName' \(line 1\) / 'eventName' \(line 1\)\.",
                            exit_code=2)

    def test_rejects_a_value_that_the_table_cannot_hold(self):
        _, result = self.started("unstorable_value")
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: line 1: the key 'planted' "
                            r"holds an integer outside the signed 64-bit range of the table "
                            r"\(SQLite INTEGER\)$", exit_code=2)
        self.assertEqual(result.output.count("ERROR "), 1, result.describe())

    def test_rejects_techniques_that_are_not_those_of_the_yml(self):
        _, result = self.started("yml_technique")
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: SOURCES\.json pins the "
                            r"techniques \['T1530'\]; the yml at the commit names \['T1537'\]$",
                            exit_code=2)

    @gatelib.known_gap(
        "ext-fire-on-another-record",
        gate="detections/check_external_records.py --enforce",
        reason="A dataset of splunk/attack_data is not labelled record by record, and "
               "SOURCES.json pins no attack record: a rule that fires on any record of a "
               "same-technique dataset gives FIRE. The planted dataset holds the attack "
               "record, which the rule misses, and a record that its yml calls benign, on "
               "which the rule fires; the gate reports FIRE. The real FIC dataset of T1098.001 "
               "holds such a benign twin (its yml says so). In shadow mode no verdict fails, so "
               "only the report is wrong today.",
        closes="R3b")
    def test_gap_fire_on_a_record_that_is_not_the_attack(self):
        """WANTED: a FIRE counts only a hit on a pinned attack record; a dataset whose
        hits are all on other records is a MISS (or a fault: no attack record pinned)."""
        _, result = self.started("twin")
        if result.returncode == 0:
            # The rule misses the attack record alone (a run of the dataset with line 1 only),
            fire = row(result, rf"^FIRE      {re.escape(rule_key(RULES['snapshot']))} on "
                               rf"{self.id_of('snapshot')}  .*$")
            _, alone = self.started("twin_attack_only")
            self.assertEqual(alone.returncode, 1, alone.describe())
            self.assertRegex(alone.output, re.compile(
                rf"^MISS      {re.escape(rule_key(RULES['snapshot']))} on {self.id_of('snapshot')}"
                r"  0 of 1 record\(s\)", re.MULTILINE))
            # and the FIRE comes from line 2 only: the record that the yml calls benign.
            self.assertIn("1/2 record(s) (line 2)", fire)
        self.assert_saw(result, rf"^[A-Z][A-Z -]*\S\s+{re.escape(rule_key(RULES['snapshot']))} on "
                                rf"{self.id_of('snapshot')}\b")
        self.assert_rejects(result, rf"^(MISS|ERROR|UNPINNED)\b.*{self.id_of('snapshot')}\b.*"
                                    r"attack record")

    @gatelib.known_gap(
        "ext-self-added-declaration",
        gate="detections/check_external_records.py --enforce",
        reason="check_external_records.py reads expectations.json from the tree that it "
               "checks, so an n/a declaration with the digest of a changed rule, in the same "
               "change as that rule, excuses the MISS that the change makes. The planted change "
               "does not pass CI on its own: the merge policy needs a human approval for a "
               "change to expectations.json (rail 8 of automerge.yml), and rule_cases.py fails "
               "the positive of the changed rule.",
        closes="R1")
    def test_gap_declaration_added_with_the_rule_it_excuses(self):
        """WANTED: a declaration that arrives in the same change as the rule it excuses
        does not excuse it: --enforce fails the MISS as it does without the declaration."""
        _, result = self.started("self_declared")
        # Without the declaration the changed rule misses its dataset (a second copy).
        _, plain = self.started("self_declared_plain")
        self.assertEqual(plain.returncode, 1, plain.describe())
        self.assertRegex(plain.output, re.compile(
            rf"^MISS      {re.escape(rule_key(RULES['secret']))} on {self.id_of('secret')}  ",
            re.MULTILINE))
        self.assert_saw(result, rf"^(N/A|MISS)\s+{re.escape(rule_key(RULES['secret']))} on "
                                rf"{self.id_of('secret')}  ")
        self.assert_rejects(result, rf"^MISS      {re.escape(rule_key(RULES['secret']))} on "
                                    rf"{self.id_of('secret')}  ", exit_code=1)


class ExternalRecordsJob(unittest.TestCase):
    """The job `external-records` of detection-quality.yml: the lint and the report
    run as gate steps (no continue-on-error), the job has no condition, needs no other
    job and uses no cache action, and it uploads only the JSON report."""

    WORKFLOW = os.path.join(gatelib.REPO, ".github", "workflows", "detection-quality.yml")

    @classmethod
    def setUpClass(cls):
        import yaml
        with open(cls.WORKFLOW, encoding="utf-8") as fh:
            cls.job = yaml.safe_load(fh)["jobs"]["external-records"]

    def test_the_job_runs_the_lint_and_the_report(self):
        gatelib.ci_step("detection-quality.yml", "external-records", f"{GATE} --lint")
        step = gatelib.ci_step("detection-quality.yml", "external-records", f"{GATE} --markdown")
        self.assertIn('--json "$RUNNER_TEMP/external-records.json"', " ".join(step.run.split()))
        self.assertNotIn("|", step.run, "a pipe can lose the exit code of the gate")
        self.assertNotIn("--enforce", step.run, "R3 runs in shadow mode; R3b makes it --enforce")

    def test_the_job_has_no_condition_and_no_cache(self):
        for key in ("if", "needs", "continue-on-error"):
            self.assertNotIn(key, self.job)
        self.assertEqual(self.job["timeout-minutes"], 15)
        uses = [s.get("uses", "") for s in self.job["steps"]]
        self.assertFalse([u for u in uses if "cache" in u],
                         "the job downloads each run: a cache action is the owner's decision")
        for step in self.job["steps"]:
            self.assertNotIn("continue-on-error", step)

    def test_the_artifact_is_the_json_report_only(self):
        uploads = [s for s in self.job["steps"] if s.get("uses", "").startswith(
            "actions/upload-artifact")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["with"]["path"].strip(),
                         "${{ runner.temp }}/external-records.json",
                         "no dataset and no cache may be uploaded: only the report, which holds "
                         "ids, sha256 values, counts and item names")


class ExternalLoaders(gatelib.GateCase):
    """The raw auditd loader of the gate and the Linux validator build the same event
    from the same line: a plain SYSCALL record, a record with its ENRICHED fields
    after a GS byte, a record with them inline (no GS byte, as in the Dirty Frag
    dataset of attack_data), an untrusted string in hex, and a PROCTITLE record."""

    PARTS = gatelib.DETECTIONS
    LINES = [
        'type=SYSCALL msg=audit(1791813600.000:7001): arch=c000003e syscall=41 success=yes '
        'exit=3 a0=26 a1=5 a2=0 a3=0 items=0 ppid=4400 pid=4401 auid=1000 uid=1000 gid=1000 '
        'euid=1000 comm="deteng_copyfail" exe="/tmp/deteng_copyfail" key="det-eng"',
        'type=SYSCALL msg=audit(1791813600.300:7002): arch=c000003e syscall=275 success=yes '
        'exit=16 a0=5 a1=0 a2=4 a3=0 items=0 ppid=4400 pid=4401 auid=1000 uid=1000 gid=1000 '
        'euid=1000 comm="deteng_copyfail" exe="/tmp/deteng_copyfail" key="det-eng"\x1d'
        'ARCH=x86_64 SYSCALL=splice AUID="ubuntu" UID="ubuntu" EUID="ubuntu"',
        'type=SYSCALL msg=audit(1791813601.000:7003): arch=c000003e syscall=272 success=yes '
        'exit=0 a0=50000000 a1=0 a2=0 a3=0 items=0 ppid=4400 pid=4402 auid=1000 uid=1000 '
        'gid=1000 euid=0 comm="exp" exe="/tmp/exp" key="det-eng"ARCH=x86_64 SYSCALL=unshare '
        'AUID="ubuntu" UID="ubuntu" EUID="root"',
        'type=SYSCALL msg=audit(1791813602.000:7004): arch=c000003e syscall=101 success=no '
        'exit=-1 a0=0 a1=0 a2=0 a3=0 items=0 ppid=1 pid=4403 auid=4294967295 uid=0 gid=0 '
        'euid=0 comm=417474616368204C697374656E6572 exe="/usr/bin/java" key="det-eng"',
        'type=PROCTITLE msg=audit(1791813602.000:7004): proctitle=6A617661 key="det-eng"',
    ]
    PARITY = (
        "import json, sys\nsys.path.insert(0, 'detections')\n"
        "import validate_detections as v, external_records as xr\n"
        "lines = json.loads(sys.argv[1])\n"
        "_, table = xr.load_syscalls()\n"
        "v._DUMP = {name: nr for nr, name in table.items()}   # the host table, as ausyscall\n"
        "live = v.normalize([line + '\\n' for line in lines])\n"
        "data = ''.join(line + '\\n' for line in lines).encode()\n"
        "records, other = xr.read_dataset({'id': 'T9999/parity/audit', 'format': 'auditd-raw'},\n"
        "                                 data, table)\n"
        "print(json.dumps({'live': live, 'external': [r.event for r in records],\n"
        "                  'routes': sorted({'/'.join(r.logsource) for r in records}),\n"
        "                  'other': other}))\n")

    def test_auditd_loader_builds_the_events_of_the_linux_validator(self):
        result = self.good().run_python(self.PARITY, json.dumps(self.LINES))
        self.assertEqual(result.returncode, 0, result.describe())
        out = json.loads(result.stdout)
        self.assertEqual(len(out["live"]), 4, "the validator read the four SYSCALL records")
        self.assertEqual(out["external"], out["live"])
        self.assertEqual((out["routes"], out["other"]), (["linux/auditd"], 1))
        by_syscall = {e["syscall"]: e for e in out["live"]}
        self.assertEqual(sorted(by_syscall), ["ptrace", "socket", "splice", "unshare"])
        # The inline ENRICHED fields are not in the event: the lower-case kernel fields are.
        self.assertEqual((by_syscall["unshare"]["uid"], by_syscall["unshare"]["euid"]),
                         ("1000", "0"))
        self.assertNotIn("UID", by_syscall["unshare"])
        self.assertEqual(by_syscall["ptrace"]["comm"], "Attach Listener")

    def test_every_syscall_that_an_auditd_rule_names_is_in_the_table(self):
        import yaml
        good = self.good()
        names = set(good.read_json(SYSCALLS)["syscalls"].values())
        named = set()

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key.split("|")[0] == "syscall":
                        named.update(value if isinstance(value, list) else [value])
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        for rel in good.glob("detections/sigma/*/*.yml"):
            for doc in yaml.safe_load_all(good.read(rel)):
                if isinstance(doc, dict) and (doc.get("logsource") or {}).get("service") == "auditd":
                    walk(doc.get("detection") or {})
        self.assertGreater(len(named), 10, "the rules were not read")
        self.assertEqual(sorted(str(n) for n in named if n not in names), [])

    def test_the_table_agrees_with_the_table_of_auditd_file_events(self):
        good = self.good()
        tree = ast.parse(good.read("detections/k8s/auditd_file_events.py"))
        subset = next(ast.literal_eval(node.value) for node in ast.walk(tree)
                      if isinstance(node, ast.Assign)
                      and any(getattr(t, "id", None) == "_X86_64" for t in node.targets))
        table = good.read_json(SYSCALLS)["syscalls"]
        self.assertGreater(len(subset), 40)
        self.assertEqual({nr: table.get(str(nr)) for nr in subset}, subset)


if __name__ == "__main__":
    unittest.main()
