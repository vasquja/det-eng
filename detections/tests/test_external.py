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
import itertools
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
# The log source that the records of each constructed dataset go to.
SOURCE = {"snapshot": ("aws", "cloudtrail"), "secret": ("kubernetes", "audit"),
          "consent": ("azure", "auditlogs"), "copyfail": ("linux", "auditd")}
# One constructed entry of `excluded`: the gate reads no file of it, and it gives an
# EXCLUDED row for each rule of its technique and product.
EXCLUDED_BYTES = b"constructed by detections/tests: no file of splunk/attack_data\n"
EXCLUDED = {"id": "T1537/planted_ocsf/asl_ocsf",
            "path": "datasets/attack_techniques/T1537/planted_ocsf/asl_ocsf.json",
            "sha256": hashlib.sha256(EXCLUDED_BYTES).hexdigest(), "size": len(EXCLUDED_BYTES),
            "techniques": ["T1537"], "product": "aws",
            "why": "constructed by detections/tests: OCSF records, not CloudTrail records"}
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


def plant_set(tree, bodies, records=None, edit=None, describe=None):
    """Replace the datasets of SOURCES.json in the copy with the constructed ones.

    bodies    {key of SET: bytes of the file}. Each file and its constructed yml go
              into the cache of the gate under HOME.
    records   {key: the pinned record count} (default: the records of the file).
    edit      edit(entries) changes the entries before they are written.
    describe  {key: the description of its yml} (default: the case, and for the
              CopyFail set the procedure label, which the yml must name).
    Returns {key: entry}."""
    cache = os.path.join(tree.home, CACHE)
    os.makedirs(cache, exist_ok=True)
    entries = {}
    for key, body in bodies.items():
        path, fmt, sourcetype, technique, name = SET[key]
        description = (describe or {}).get(key, f"constructed from the case {name}"
                                           + (f" ({COPYFAIL_CVE['label']} privilege escalation)"
                                              if key == "copyfail" else ""))
        yml = YML.format(description=description, technique=technique,
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
    tree.edit_json(SOURCES, lambda doc: doc.update(datasets=list(entries.values()),
                                                   excluded=[dict(EXCLUDED)]))
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


PROBE = ("import json, sys\nsys.path.insert(0, 'detections')\n"
         "import external_records as xr, check_external_records as cer\n"
         "ARGS = []\n"
         "for _path in sys.argv[1:]:\n"
         "    with open(_path, encoding='utf-8') as _fh:\n"
         "        ARGS.append(json.load(_fh))\n")
_PROBES = itertools.count(1)


def probe(tree, code, *args, env=None):
    """Run `code` (after PROBE) in the copy, with each argument as JSON in ARGS (the
    arguments go through files beside the copy: a deep input is longer than a command
    line can be); returns the JSON of the last line that it prints. For the faster
    path of a check: one process for many inputs of the function that the command line
    calls."""
    paths = []
    for arg in args:
        paths.append(tree.out(f"probe/{next(_PROBES)}.json"))
        with open(paths[-1], "w", encoding="utf-8") as fh:
            json.dump(arg, fh)
    result = tree.run_python(PROBE + code, *paths, env=env)
    lines = result.stdout.strip().split("\n")
    if result.returncode != 0 or not lines[-1].startswith("{"):
        raise AssertionError("the probe failed:\n" + result.describe())
    return json.loads(lines[-1])


def rule_facts(tree):
    """{rule key: facts} of each rule file of the copy, read as the gate reads them:
    the folder, the log source, the attack.t* and cve.* tags. The tests take the rules
    of a kind of row from these facts, and name no rule for it."""
    import yaml
    out = {}
    for rel in tree.glob("detections/sigma/*/*.yml"):
        docs = [d for d in yaml.safe_load_all(tree.read(rel)) if isinstance(d, dict)]
        ls = next((d["logsource"] for d in docs if isinstance(d.get("logsource"), dict)), {})
        tags = {str(t) for d in docs for t in (d.get("tags") or [])}
        out[rule_key(rel)] = {
            "path": rel, "folder": rule_key(rel).split("/", 1)[0],
            "source": (ls.get("product"), ls.get("service") or ls.get("category")),
            "techniques": {t[len("attack."):].upper() for t in tags
                           if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)},
            "cves": {"CVE-" + t[len("cve."):] for t in tags if re.fullmatch(r"cve\.\d{4}-\d{4,}", t)}}
    return out


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
            "duplicate_pair", "bad_procedure", "procedure_not_auditd", "unknown_rule_path")

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

    @classmethod
    def begin_unknown_rule_path(cls, tree):
        # A --rule path that is not a rule file: the run would check fewer rules.
        return cls.start_gate(tree, "--rule", "detections/sigma/T9999/planted_no_such_rule.yml")

    @classmethod
    def begin_procedure_not_auditd(cls, tree):
        # A procedure label on a dataset that is not raw auditd (C5: the label is for the
        # raw auditd capture of a CVE exploit).
        def change(doc):
            other = next(d for d in doc["datasets"] if d["format"] != "auditd-raw")
            other["procedure"] = {"label": "Planted label", "cves": ["CVE-2000-0001"],
                                  "why": "planted by detections/tests"}
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

    # One malformed field each: (name, path in SOURCES.json, value, the one problem).
    # A path element "@auditd" is the first raw auditd dataset; the value DELETE
    # removes the key; the path [] replaces the whole document.
    DELETE = "<delete>"
    FIELDS = [
        ("top_key", ["planted"], 1, r"^SOURCES\.json: unknown key\(s\) \['planted'\], missing "
         r"key\(s\) \[\]$"),
        ("schema", ["schema"], 2, r"^SOURCES\.json: schema 2 is not 1$"),
        ("repository", ["repository"], "planted/attack_data",
         r"^SOURCES\.json: repository 'planted/attack_data' is not 'splunk/attack_data'$"),
        ("licence_file", ["licence_file"], "COPYING", r"^SOURCES\.json: licence_file must be "
         r"'LICENSE' \(the licence file of splunk/attack_data at the commit\)$"),
        ("licence_copy_outside", ["licence_copy"], "LICENSE", r"^SOURCES\.json: licence_copy "
         r"'LICENSE' is not a file under detections/external/LICENSES/$"),
        ("licence_copy_missing", ["licence_copy"], "detections/external/LICENSES/planted.txt",
         r"^SOURCES\.json: the licence copy detections/external/LICENSES/planted\.txt cannot be "
         r"read \(No such file or directory\)$"),
        ("notice", ["notice"], 1, r"^SOURCES\.json: notice must say what NOTICE file the commit "
         r"holds$"),
        ("not_lists", ["excluded"], {}, r"^SOURCES\.json: datasets and excluded must be lists$"),
        ("not_object", [], [], r"^SOURCES\.json: the file is not a JSON object$"),
        ("dataset_not_object", ["datasets", 0], 1, r"^SOURCES\.json datasets\[1\]: not an "
         r"object$"),
        ("dataset_key", ["datasets", 0, "planted"], 1, r"^SOURCES\.json datasets\[1\]: missing "
         r"key\(s\) \[\], unknown key\(s\) \['planted'\]$"),
        ("dataset_missing_key", ["datasets", 0, "yml"], DELETE, r"^SOURCES\.json datasets\[1\]: "
         r"missing key\(s\) \['yml'\], unknown key\(s\) \[\]$"),
        ("id_of_path", ["datasets", 0, "id"], "T1053.007/planted/other",
         r": id 'T1053\.007/planted/other' is not '[^']+', the <technique>/<directory>/<file "
         r"stem> of its path$"),
        ("size", ["datasets", 0, "size"], 0, r": size 0 is not a positive integer$"),
        ("size_bool", ["datasets", 0, "size"], True, r": size True is not a positive integer$"),
        ("techniques_form", ["datasets", 0, "techniques"], ["t1053.007"],
         r": techniques \['t1053\.007'\] is not a list of ATT&CK IDs"),
        ("techniques_twice", ["datasets", 0, "techniques"], ["T1053.007", "T1053.007"],
         r": techniques \['T1053\.007', 'T1053\.007'\] is not a list of ATT&CK IDs"),
        ("records_zero", ["datasets", 0, "records"], 0, r": records 0 is not a positive integer"),
        ("records_bool", ["datasets", 0, "records"], True, r": records True is not a positive "
         r"integer"),
        ("format", ["datasets", 0, "format"], "ocsf-json", r": format 'ocsf-json' is not one of "
         r"\('cloudtrail-json', 'azure-monitor-json', 'k8s-audit-json', 'auditd-raw'\)$"),
        ("sourcetype", ["datasets", 0, "sourcetype"], "", r": sourcetype must be the text \(or "
         r"the list\) that the yml gives$"),
        ("yml_path", ["datasets", 0, "yml"],
         "datasets/attack_techniques/T1053.007/planted/readme.txt",
         r": yml '\S+/readme\.txt' is not the path of a \.yml file of splunk/attack_data$"),
        ("yml_sha256", ["datasets", 0, "yml_sha256"], "planted",
         r": yml_sha256 is not 64 lower-case hex digits$"),
        ("aliases", ["datasets", 0, "aliases"], ["datasets/attack_techniques/../planted"],
         r": aliases must be a list of other paths of splunk/attack_data$"),
        ("procedure_todo", ["datasets", "@auditd", "procedure", "label"], "TODO",
         r": procedure must be \{label, cves, why\}"),
        ("procedure_key", ["datasets", "@auditd", "procedure", "planted"], 1,
         r": procedure must be \{label, cves, why\}"),
        # A label in CVE form names its CVE: it must be one of the cves (a CVE cut short).
        ("procedure_cve_label", ["datasets", "@auditd", "procedure", "label"], "CVE-2026-4350",
         r": the procedure label 'CVE-2026-4350' is a CVE ID, and it is not one of the cves "
         r"\[[^]]*\] of the entry$"),
        ("excluded_not_object", ["excluded", 0], 1, r"^SOURCES\.json excluded\[1\]: not an "
         r"object$"),
        ("excluded_key", ["excluded", 0, "planted"], 1, r"^SOURCES\.json excluded\[1\]: missing "
         r"key\(s\) \[\], unknown key\(s\) \['planted'\]$"),
        ("excluded_product", ["excluded", 0, "product"], "windows",
         r": product 'windows' is not one of \('aws', 'azure', 'gcp', 'kubernetes', 'linux'\)$"),
        ("excluded_why_todo", ["excluded", 0, "why"], "TODO: later",
         r": why must say why the dataset is left out \(not TODO\)$"),
        ("excluded_why_empty", ["excluded", 0, "why"], " ",
         r": why must say why the dataset is left out \(not TODO\)$"),
    ]
    LINT = (
        "import copy\n"
        "doc0 = xr.load_json(xr.SOURCES, 'SOURCES.json')\n"
        "auditd = next(n for n, d in enumerate(doc0['datasets']) if d['format'] == 'auditd-raw')\n"
        "out = {'control': xr.lint_sources(doc0, '.')}\n"
        "fields, delete = ARGS\n"
        "for name, path, value in fields:\n"
        "    doc = copy.deepcopy(doc0)\n"
        "    if not path:\n"
        "        doc = value\n"
        "    else:\n"
        "        node = doc\n"
        "        path = [auditd if p == '@auditd' else p for p in path]\n"
        "        for p in path[:-1]:\n"
        "            node = node[p]\n"
        "        if value == delete:\n"
        "            del node[path[-1]]\n"
        "        else:\n"
        "            node[path[-1]] = value\n"
        "    out[name] = xr.lint_sources(doc, '.')\n"
        "print(json.dumps(out))\n")

    def test_lint_names_each_malformed_field(self):
        """The faster path of `--lint` (its function lint_sources(), one process): each
        malformed field of a copy of the real SOURCES.json gives one problem, which
        names the field."""
        out = probe(self.good(), self.LINT, [f[:3] for f in self.FIELDS], self.DELETE)
        self.assertEqual(out["control"], [], "the real SOURCES.json is sound")
        for name, _, _, reason in self.FIELDS:
            with self.subTest(name):
                self.assertEqual(len(out[name]), 1, out[name])
                self.assertRegex(out[name][0], reason)

    # One malformed declaration each: (name, the change to a sound declaration, the one
    # problem). A change {"<key>": DELETE} removes the key.
    DECLARATIONS = [
        ("key", {"planted": 1}, r": wants exactly the keys \['dataset', 'expect', 'rule', "
         r"'rule_digest', 'sha256', 'why'\]$"),
        ("missing_key", {"sha256": DELETE}, r": wants exactly the keys "),
        ("not_text", {"rule": 1}, r": the rule and the dataset must be text$"),
        ("rule_form", {"rule": "T1537/../planted.yml"}, r": names the rule 'T1537/\.\./planted"
         r"\.yml', which does not exist"),
        ("digest_form", {"rule_digest": "PLANTED"}, r": rule_digest is not 64 lower-case hex "
         r"digits$"),
        ("sha256_form", {"sha256": "A" * 64}, r": sha256 is not 64 lower-case hex digits$"),
        ("no_why", {"why": " "}, r": gives no why$"),
        ("known_miss_prefix", {"expect": "known-miss", "why": "the rule misses it"},
         r": a known-miss why starts 'rule defect, tracked in detections/RULE_DEFECTS\.md "
         r"<ID>:'$"),
        ("quiet_prefix_only", {"expect": "quiet", "why": "quiet:"},
         r": a quiet why starts 'quiet:' and says more$"),
        ("na_prefix_only", {"why": "not in the capture: "},
         r": a n/a why starts 'another procedure:' or 'not in the capture:' and says more$"),
        ("fire_prefix", {"expect": "fire", "why": "it fires"},
         r": a fire why starts 'same procedure:' and says more$"),
    ]
    # (expect, the relation of the pair, the reason that the declaration is redundant).
    REDUNDANT = [
        ("n/a", "related", r"^the pair is related, not an expected pair, so a n/a declaration "
         r"changes nothing$"),
        ("known-miss", "other-procedure", r"^the pair is other-procedure, not an expected pair, so "
         r"a known-miss declaration changes nothing$"),
        ("quiet", None, r"^the rule and the dataset have no technique in common, so the gate does "
         r"not run the rule on the dataset and a quiet declaration changes nothing$"),
        ("n/a", None, r"have no technique in common"),
        ("fire", "same", r"^the pair is same technique and procedure, so the rule must fire "
         r"already$"),
        ("quiet", "same", None), ("quiet", "related", None), ("n/a", "same", None),
        ("known-miss", "same", None), ("fire", "related", None), ("fire", None, None),
        ("fire", "other-procedure", None),
    ]
    DECLARE = (
        "sources = xr.load_json(xr.SOURCES, 'SOURCES.json')\n"
        "by_id = {d['id']: d for d in sources['datasets']}\n"
        "rules = {cer.Rule(p).key for p in cer.rule_paths()}\n"
        "base, changes, delete, redundant = ARGS\n"
        "out = {'control': cer.parse_declarations({'schema': 1, 'declarations': [base]}, by_id,\n"
        "                                         rules)[1],\n"
        "       'schema': cer.parse_declarations({'schema': 2, 'declarations': []}, by_id,\n"
        "                                        rules)[1]}\n"
        "for name, change in changes:\n"
        "    d = dict(base, **change)\n"
        "    for k in [k for k, v in change.items() if v == delete]:\n"
        "        del d[k]\n"
        "    out[name] = cer.parse_declarations({'schema': 1, 'declarations': [d]}, by_id,\n"
        "                                       rules)[1]\n"
        "out['redundant'] = [cer.redundant({'expect': e}, rel) for e, rel in redundant]\n"
        "print(json.dumps(out))\n")

    def test_declarations_name_each_malformed_field(self):
        """The faster path of the declaration checks (parse_declarations() and
        redundant(), which `--lint` calls): each malformed field gives one problem."""
        out = probe(self.good(), self.DECLARE, self.pair(), [d[:2] for d in self.DECLARATIONS],
                    self.DELETE, [r[:2] for r in self.REDUNDANT])
        self.assertEqual(out["control"], [], "the declaration of pair() is sound")
        self.assertEqual(out["schema"], ['expectations.json: wants {"schema": 1, "declarations": '
                                         '[...]}'])
        for name, _, reason in self.DECLARATIONS:
            with self.subTest(name):
                self.assertEqual(len(out[name]), 1, out[name])
                self.assertRegex(out[name][0], r"^expectations\.json(:| declarations\[1\]:)")
                self.assertRegex(out[name][0], reason)
        for (expect, rel, reason), got in zip(self.REDUNDANT, out["redundant"]):
            with self.subTest(f"redundant {expect} on {rel}"):
                if reason is None:
                    self.assertIsNone(got)
                else:
                    self.assertRegex(got or "", reason)

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

    def test_rejects_a_rule_path_that_is_not_a_rule(self):
        _, result = self.started("unknown_rule_path")
        self.assert_rejects(result, r"^ERROR --rule 'detections/sigma/T9999/planted_no_such_rule"
                            r"\.yml' is not a rule file under detections/sigma/$", exit_code=2)
        self.assertEqual(result.output.count("ERROR "), 1, result.describe())

    def test_rejects_a_procedure_label_on_a_dataset_that_is_not_raw_auditd(self):
        _, result = self.started("procedure_not_auditd")
        self.assert_rejects(result, r"^ERROR SOURCES\.json dataset '[^']+': a procedure label is for "
                            r"a raw auditd dataset of a CVE exploit; this dataset is "
                            r"'(cloudtrail|azure-monitor|k8s-audit)-json'$", exit_code=2)
        self.assertEqual(result.output.count("ERROR "), 1, result.describe())

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
            "declared_quiet_fired", "stale_na", "known_miss_fires", "declared_fire_miss",
            "declared_no_record", "unavailable_enforce", "origins_enforce",
            "unavailable_one_shadow", "not_a_record", "count_changed", "line_not_object",
            "not_utf8", "case_clash", "unstorable_value", "long_integer", "twice_envelope",
            "label_not_in_yml", "yml_technique", "twin", "twin_attack_only", "self_declared",
            "self_declared_plain")
    STEP = ("detection-quality.yml", "external-records", f"{GATE} --markdown")

    @classmethod
    def start_gate(cls, tree):
        """The CI step (shadow), as the job runs it."""
        return tree.start_step(gatelib.ci_step(*cls.STEP))

    @classmethod
    def start_enforce(cls, tree, *keys):
        """The documented --enforce, for the rules of `keys` (default: all four), with
        --offline: the suite has no network, so an online run cannot compare the
        LICENSE and the syscall table with their origins, and --enforce fails such a
        run (the run `origins_enforce`). --offline reads the datasets and their ymls
        from the cache as an online run does when the cache holds them."""
        return tree.start(cls.GATE, "--enforce", "--offline",
                          *[a for k in (keys or RULES) for a in ("--rule", RULES[k])])

    @classmethod
    def standard(cls, tree, **bodies):
        """The four constructed datasets; `bodies` replaces the bytes of some."""
        return plant_set(tree, {k: bodies.get(k, body_of(tree, k)) for k in SET})

    @classmethod
    def facts(cls):
        if "_facts" not in cls.__dict__:
            cls._facts = rule_facts(cls.good())
        return cls._facts

    @classmethod
    def kind(cls, name):
        """The rules of the tree that give one kind of row on the constructed set.

        not-read   T1528 rules of another Azure log than AuditLogs (the consent set)
        other-cve  T1068 rules whose cve tags do not hold the label of the CopyFail set
        related    rules outside T1552.007 with that tag, on the Kubernetes audit log
        other-product  rules of the folder of a set that read another product
        miss       the other T1537 rules of CloudTrail (the snapshot set)
        excluded   the T1537 rules of AWS (the excluded entry)"""
        facts = cls.facts()
        pick = {
            "not-read": lambda f: f["folder"] == SET["consent"][3]
            and f["source"][0] == "azure" and f["source"] != SOURCE["consent"],
            "other-cve": lambda f: f["folder"] == SET["copyfail"][3]
            and COPYFAIL_CVE["label"] not in f["cves"],
            "related": lambda f: f["folder"] != SET["secret"][3]
            and SET["secret"][3] in f["techniques"] and f["source"] == SOURCE["secret"],
            "other-product": lambda f: any(f["folder"] == SET[k][3]
                                           and f["source"][0] != SOURCE[k][0] for k in SET),
            "miss": lambda f: f["folder"] == SET["snapshot"][3] and f["source"] == SOURCE["snapshot"]
            and f["path"] != RULES["snapshot"],
            "excluded": lambda f: f["folder"] in EXCLUDED["techniques"]
            and f["source"][0] == EXCLUDED["product"],
        }[name]
        return sorted(key for key, f in facts.items() if pick(f))

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
    def begin_declared_fire_miss(cls, tree):
        # A fire declaration on a RELATED pair whose rule does not fire on the record.
        entries = cls.standard(tree)
        rule = cls.facts()[cls.kind("related")[0]]["path"]
        declare(tree, {"rule": rule_key(rule), "dataset": entries["secret"]["id"],
                       "expect": "fire", "why": "same procedure: planted by detections/tests",
                       "rule_digest": digests(tree, rule)[rule],
                       "sha256": entries["secret"]["sha256"]})
        return tree.start(cls.GATE, "--enforce", "--offline", "--rule", rule)

    @classmethod
    def begin_declared_no_record(cls, tree):
        # A quiet declaration on a same-technique pair whose log source the dataset does
        # not hold: it applies to nothing.
        entries = cls.standard(tree)
        rule = cls.facts()[cls.kind("not-read")[0]]["path"]
        declare(tree, {"rule": rule_key(rule), "dataset": entries["consent"]["id"],
                       "expect": "quiet", "why": "quiet: planted by detections/tests",
                       "rule_digest": digests(tree, rule)[rule],
                       "sha256": entries["consent"]["sha256"]})
        return tree.start(cls.GATE, "--enforce", "--offline", "--rule", rule)

    @classmethod
    def begin_unavailable_enforce(cls, tree):
        cls.remove_cached(tree, cls.standard(tree)["snapshot"])
        return cls.start_enforce(tree)

    @classmethod
    def begin_origins_enforce(cls, tree):
        # Online and with no network: the datasets are in the cache, the LICENSE and the
        # syscall table of the kernel are not, so the run cannot compare them.
        cls.standard(tree)
        return tree.start(cls.GATE, "--enforce", "--rule", RULES["snapshot"])

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
    def begin_long_integer(cls, tree):
        # An integer of more than 4300 digits: Python's int() refuses its text with a
        # ValueError that is not a JSONDecodeError.
        record = case(tree, "snapshot", SET["snapshot"][4])["events"][0]
        cls.standard(tree, snapshot=line_of(record)[:-2] + b', "planted": ' + b"7" * 4301 + b"}\n")
        return cls.start_gate(tree)

    @classmethod
    def begin_twice_envelope(cls, tree):
        # A CloudTrail envelope that holds "Records" two times: the first list holds the
        # positive record, the second the near-miss (json keeps the second).
        first = case(tree, "snapshot", SET["snapshot"][4])["events"]
        second = case(tree, "snapshot", SNAPSHOT_NEAR_MISS)["events"]
        body = f'{{"Records": {json.dumps(first)}, "Records": {json.dumps(second)}}}\n'.encode()
        cls.standard(tree, snapshot=body)
        return cls.start_gate(tree)

    @classmethod
    def begin_label_not_in_yml(cls, tree):
        # The procedure label of the CopyFail set is not in the description of its yml.
        plant_set(tree, {k: body_of(tree, k) for k in SET},
                  describe={"copyfail": "constructed from the case afalg-then-splice"})
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
        # A row for each dataset, and one for each of the two origin files.
        self.assertEqual(len(re.findall(r"^UNAVAILABLE \S+: ", result.output, re.MULTILINE)),
                         n + 2, result.describe())
        for name in ("LICENSE", "syscall_64.tbl"):
            self.assertRegex(result.output, re.compile(rf"^UNAVAILABLE {re.escape(name)}: ",
                                                       re.MULTILINE))
        self.assertEqual(len(re.findall(r"^::warning title=external-records::UNAVAILABLE ",
                                        result.output, re.MULTILINE)), n + 2, result.describe())
        self.assert_rejects(result, r"^ERROR no dataset was read, so the run checked nothing",
                            exit_code=2)

    def test_constructed_set_ci_step_reports_each_verdict(self):
        """The CI step (shadow) accepts the constructed set and reports each pair."""
        tree, result = self.started("constructed")
        self.assert_accepts(result, r"^Summary: \d+ of \d+ rule\(s\) have a same-technique "
                            r"dataset of their log source; .*; 4 dataset\(s\) read, 0 unavailable; "
                            r"shadow: \d+ "
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
        facts, limits = self.facts(), "(detections/tests/README.md, Limits)"
        # Every other rule of the technique and log source must fire too: a MISS row.
        for key in self.kind("miss"):
            self.assertRegex(result.output, re.compile(
                rf"^MISS      {re.escape(key)} on {self.id_of('snapshot')}  0 of 1 record\(s\); "
                r"nearest line 1 \(", re.MULTILINE))
        # A rule of the technique whose log source the dataset does not hold.
        self.assertTrue(self.kind("not-read"), "no T1528 rule reads another Azure log " + limits)
        for key in self.kind("not-read"):
            self.assertRegex(result.output, re.compile(
                rf"^NOT READ  {re.escape(key)} on {self.id_of('consent')}: no "
                rf"{re.escape('/'.join(facts[key]['source']))} record \(the dataset holds: "
                r"azure/auditlogs\)$", re.MULTILINE))
        # NOT READ is for a rule of the product of the dataset only.
        self.assertTrue(self.kind("other-product"),
                        "no rule of the folder of a constructed set reads another product " + limits)
        for key in self.kind("other-product"):
            self.assertNotRegex(result.output, re.compile(rf"^NOT READ  {re.escape(key)} on ",
                                                          re.MULTILINE))
        # A rule of another CVE than the label of the dataset.
        self.assertTrue(self.kind("other-cve"), "no T1068 rule of another CVE " + limits)
        for key in self.kind("other-cve"):
            cves = ", ".join(sorted(facts[key]["cves"])) or "none"
            self.assertRegex(result.output, re.compile(
                rf"^OTHER-PROCEDURE {re.escape(key)} on {self.id_of('copyfail')}  .*\[same "
                rf"technique T1068; the dataset is {COPYFAIL_CVE['label']}, the CVE tags of the "
                rf"rule: {re.escape(cves)}; not expected\]$", re.MULTILINE))
        # A rule whose other attack tag is the technique of the dataset.
        self.assertTrue(self.kind("related"), "no rule outside T1552.007 has its tag " + limits)
        for key in self.kind("related"):
            self.assertRegex(result.output, re.compile(
                rf"^RELATED   {re.escape(key)} on {self.id_of('secret')}  0/1 record\(s\)  "
                r"\[tag T1552\.007; not expected\]$", re.MULTILINE))
        # The excluded entry: a row for each rule of its technique and product, with its why.
        self.assertTrue(self.kind("excluded"))
        for key in self.kind("excluded"):
            self.assertRegex(result.output, re.compile(
                rf"^EXCLUDED  {re.escape(key)} on {re.escape(EXCLUDED['id'])}: "
                rf"{re.escape(EXCLUDED['why'])}$", re.MULTILINE))
        # The step summary holds each row of the console, and no other.
        rows = [line for line in result.output.split("\n")
                if re.match(r"(DATASET|FIRE|MISS|NOT READ|RELATED|OTHER-PROCEDURE|EXCLUDED"
                            r"|UNAVAILABLE) ", line)]
        with open(tree.out("github/github_step_summary"), encoding="utf-8") as fh:
            summary = fh.read()
        self.assertIn("## External records (splunk/attack_data, shadow)", summary)
        self.assertIn(f"<details><summary>{len(rows)} row(s)</summary>", summary)
        body = summary.split("```text\n", 1)[1].split("\n```", 1)[0].split("\n")
        self.assertEqual(body, rows)
        with open(tree.out("runner-temp/external-records.json"), encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual((report["mode"], report["exit"], len(report["datasets"])),
                         ("shadow", 0, 4))

    def test_constructed_set_enforce_accepts_the_four_fires(self):
        self.assert_documented(f"python3 {GATE} --enforce")
        _, result = self.started("constructed_enforce")
        self.assert_accepts(result, r"^Summary: 4 of 4 rule\(s\) have a same-technique dataset of "
                            r"their log source; 4 "
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

    def test_enforce_rejects_a_declared_fire_that_misses(self):
        key = self.kind("related")[0]
        _, result = self.started("declared_fire_miss")
        self.assert_rejects(result, rf"^MISS      {re.escape(key)} on {self.id_of('secret')}  0 of 1 "
                            r"record\(s\); nearest line 1 \(.*\)  \[tag T1552\.007; declared "
                            r"fire\]$", exit_code=1)

    def test_enforce_rejects_a_declaration_on_a_pair_without_records(self):
        key = self.kind("not-read")[0]
        source = "/".join(self.facts()[key]["source"])
        _, result = self.started("declared_no_record")
        self.assertRegex(result.output, re.compile(
            rf"^NOT READ  {re.escape(key)} on {self.id_of('consent')}: ", re.MULTILINE))
        self.assert_rejects(result, rf"^STALE     {re.escape(key)} on {self.id_of('consent')}: the "
                            rf"quiet declaration applies to nothing: the dataset holds no "
                            rf"{re.escape(source)} record$", exit_code=1)

    def test_enforce_rejects_an_unavailable_dataset(self):
        _, result = self.started("unavailable_enforce")
        self.assertRegex(result.output, re.compile(
            rf"^UNAVAILABLE {self.id_of('snapshot')}: ", re.MULTILINE))
        self.assert_rejects(result, r"^ERROR --enforce: 1 dataset\(s\) UNAVAILABLE$", exit_code=2)

    def test_enforce_rejects_origins_that_it_could_not_compare(self):
        """An online --enforce run that cannot read the LICENSE and the syscall table at
        their origins fails, as for a dataset: it did not check what it pins."""
        _, result = self.started("origins_enforce")
        for name in ("LICENSE", "syscall_64.tbl"):
            self.assertRegex(result.output, re.compile(rf"^UNAVAILABLE {re.escape(name)}: ",
                                                       re.MULTILINE))
        self.assertRegex(result.output, re.compile(
            rf"^DATASET   {self.id_of('snapshot')}  ", re.MULTILINE))
        self.assert_rejects(result, r"^ERROR --enforce: LICENSE and syscall_64\.tbl UNAVAILABLE: "
                            r"not compared with the origin$", exit_code=2)
        self.assertEqual(result.output.count("ERROR "), 1, result.describe())

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
        """The CI step. Its Summary line, its step summary and its JSON report say that
        the run had a fault, and the step summary shows the ERROR line before the
        collapsed rows."""
        tree, result = self.started("count_changed")
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: the loader read 1 "
                            r"record\(s\); SOURCES\.json pins 2\.", exit_code=2)
        summary = row(result, r"^Summary: .*$")
        self.assertRegex(summary, r"; shadow: \d+ verdict\(s\) would fail --enforce; 1 error\(s\)$")
        error = row(result, r"^ERROR .*$")
        with open(tree.out("github/github_step_summary"), encoding="utf-8") as fh:
            text = fh.read()
        head, details = text.split("<details>", 1)
        self.assertIn(f"\n{summary}\n\n```text\n{error}\n```\n", head)
        self.assertNotIn("ERROR ", details)
        with open(tree.out("runner-temp/external-records.json"), encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual((report["summary"], report["exit"]), (summary, 2))

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
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: line 1 holds an integer "
                            r"outside the signed 64-bit range of the table \(SQLite INTEGER\)$",
                            exit_code=2)
        self.assertEqual(result.output.count("ERROR "), 1, result.describe())

    def test_rejects_an_integer_of_more_than_4300_digits(self):
        """The CI step: one ERROR that names the dataset and the line, not a traceback."""
        _, result = self.started("long_integer")
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: line 1 holds an integer "
                            r"outside the signed 64-bit range of the table \(SQLite INTEGER\)$",
                            exit_code=2)
        self.assertEqual(result.output.count("ERROR "), 1, result.describe())

    def test_rejects_an_envelope_that_holds_its_key_two_times(self):
        """The CI step: a doubled "Records" is a fault, not the MISS of the second list."""
        _, result = self.started("twice_envelope")
        self.assert_rejects(result, rf"^ERROR {self.id_of('snapshot')}: line 1: an object holds the "
                            r"key 'Records' two times \(one reader keeps the first value, another "
                            r"the last\)$", exit_code=2)
        self.assertEqual(result.output.count("ERROR "), 1, result.describe())

    def test_rejects_a_procedure_label_that_the_yml_does_not_name(self):
        """A label makes the pair of a rule of another CVE OTHER-PROCEDURE, which no
        mode fails: a label that the yml does not give would hide a MISS."""
        _, result = self.started("label_not_in_yml")
        self.assert_rejects(result, rf"^ERROR {self.id_of('copyfail')}: SOURCES\.json gives the "
                            rf"procedure label '{COPYFAIL_CVE['label']}'; the description of the "
                            r"yml \S+ at the commit does not name it$", exit_code=2)
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

    def test_the_network_time_of_a_run_ends_inside_the_job(self):
        """TIMEOUT (one step of a request) and DEADLINE (all the network work of a run)
        of external_records.py against the timeout of the job: a run whose origins do
        not answer makes at most 2 + one request for each dataset that waits (the
        LICENSE, the syscall table, the yml of each dataset), and ends before the
        deadline; the deadline leaves 300 s of the job for the other steps."""
        consts = {}
        with open(os.path.join(gatelib.REPO, "detections", "external_records.py"),
                  encoding="utf-8") as fh:
            for node in ast.parse(fh.read()).body:
                if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                        and getattr(node.targets[0], "id", None) in ("TIMEOUT", "DEADLINE"):
                    consts[node.targets[0].id] = ast.literal_eval(node.value)
        with open(os.path.join(gatelib.REPO, SOURCES), encoding="utf-8") as fh:
            datasets = len(json.load(fh)["datasets"])
        self.assertEqual(consts, {"TIMEOUT": 15, "DEADLINE": 600})
        self.assertLessEqual((2 + datasets) * consts["TIMEOUT"], consts["DEADLINE"])
        self.assertLessEqual(consts["DEADLINE"] + 300, self.job["timeout-minutes"] * 60)

    def test_the_artifact_is_the_json_report_only(self):
        uploads = [s for s in self.job["steps"] if s.get("uses", "").startswith(
            "actions/upload-artifact")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["with"]["path"].strip(),
                         "${{ runner.temp }}/external-records.json",
                         "no dataset and no cache may be uploaded: only the report, which holds "
                         "ids, sha256 values, counts and item names")


def ct(**more):
    """One CloudTrail record (constructed: the safe markers of AGENTS.md)."""
    return {"eventSource": "ec2.amazonaws.com", "eventName": "DescribeSnapshots",
            "recipientAccountId": "123456789012", **more}


def line_of(record):
    return (json.dumps(record) + "\n").encode()


def syscall_line(fields, serial=7101):
    return (f"type=SYSCALL msg=audit(1791813600.000:{serial}): {fields}\n").encode()


SYSCALL_FIELDS = ("arch=c000003e syscall=41 success=yes exit=3 a0=26 a1=5 a2=0 a3=0 items=0 "
                  "ppid=4400 pid=4401 auid=1000 uid=1000 euid=1000 comm=\"trr9000-x\" "
                  "exe=\"/tmp/trr9000-x\" key=\"det-eng\"")


def azure(category):
    return {"category": category, "operationName": "Add service principal credentials",
            "properties": {"tenantId": "00000000-0000-0000-0000-000000000000"}}


def k8s(**more):
    return {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "verb": "get",
            "objectRef": {"resource": "secrets", "namespace": "trr9000-ns"}, **more}


def procedure(label, *cves):
    """The procedure of an entry, as a change of the YMLS of ExternalLoaders."""
    return {"procedure": {"label": label, "cves": list(cves), "why": "x"}}


def nested(depth, leaf=b"1"):
    """A JSON text of `depth` nested objects {"a": {"a": ... 1}}."""
    return b'{"a":' * depth + leaf + b"}" * depth


class ExternalLoaders(gatelib.GateCase):
    """The raw auditd loader of the gate and the Linux validator build the same event
    from the same line: a plain SYSCALL record, a record with its ENRICHED fields
    after a GS byte, a record with them inline (no GS byte, as in the Dirty Frag
    dataset of attack_data), an untrusted string in hex, and a PROCTITLE record.

    The other tests are the faster path of the report (the functions that it calls,
    in one process for many inputs): the loader of each format on constructed lines,
    the sniff of --draft, the check of a yml, the table of evaluate(), and the fetch
    and the cache against a server on 127.0.0.1 (no other network)."""

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

    # (name, format, bytes of the file, what the loader gives). The expectation is a
    # regular expression of the Fault, or a list of (where, log source) of the records
    # (log source None: a record that no rule reads), or a dict {key: value} that the
    # event of the first record holds, or ("or read", a regular expression): a Fault
    # that matches, or the records (the json module of Python 3.14 reads an array
    # nested 100000 deep when the stack is large, and 3.13 stops; neither may crash).
    READ = [
        ("bom", "cloudtrail-json", b"\xef\xbb\xbf" + line_of(ct()),
         r": the file starts with a byte order mark \(U\+FEFF\)"),
        ("cloudtrail_line", "cloudtrail-json", line_of(ct()), [("line 1", "aws/cloudtrail")]),
        ("cloudtrail_array", "cloudtrail-json", b"[" + line_of(ct()) + b"," + line_of(ct()) + b"]",
         [("record 1", "aws/cloudtrail"), ("record 2", "aws/cloudtrail")]),
        ("cloudtrail_envelope", "cloudtrail-json", json.dumps({"Records": [ct()]}).encode(),
         [("record 1", "aws/cloudtrail")]),
        ("cloudtrail_object", "cloudtrail-json", json.dumps(ct(), indent=1).encode(),
         [("record 1", "aws/cloudtrail")]),
        ("blank", "cloudtrail-json", b"\n \n", []),
        ("cloudtrail_not_record", "cloudtrail-json", line_of({"eventSource": "s3.amazonaws.com"}),
         r": line 1 is not a CloudTrail record \(no eventSource and eventName text\)$"),
        ("azure_routes", "azure-monitor-json", b"".join(line_of(azure(c)) for c in (
            "AuditLogs", "SignInLogs", "NonInteractiveUserSignInLogs", "ServicePrincipalSignInLogs",
            "ManagedIdentitySignInLogs", "Administrative", "MicrosoftGraphActivityLogs")),
         [("line 1", "azure/auditlogs")] + [(f"line {n}", "azure/signinlogs") for n in (2, 3, 4, 5)]
         + [("line 6", "azure/activitylogs"), ("line 7", None)]),
        ("azure_not_record", "azure-monitor-json", line_of({"category": "AuditLogs"}),
         r": line 1 is not an Azure Monitor record \(no category and operationName text\)$"),
        ("k8s_event", "k8s-audit-json", line_of(k8s()), [("line 1", "kubernetes/audit")]),
        ("k8s_api_version", "k8s-audit-json", line_of(k8s(apiVersion="v1")),
         r": line 1 is not a Kubernetes audit event \(kind Event, apiVersion audit\.k8s\.io/\*\)$"),
        ("k8s_kind", "k8s-audit-json", line_of(k8s(kind="EventList")),
         r": line 1 is not a Kubernetes audit event"),
        ("auditd_x86_64", "auditd-raw", syscall_line(SYSCALL_FIELDS), {"syscall": "socket"}),
        # Another arch: the number stays a number (41 is dup on i386, not socket).
        ("auditd_i386", "auditd-raw",
         syscall_line(SYSCALL_FIELDS.replace("arch=c000003e", "arch=40000003")), {"syscall": "41"}),
        ("auditd_no_pid", "auditd-raw", syscall_line(SYSCALL_FIELDS.replace(" pid=4401", "")),
         r": line 1 is a SYSCALL record without pid \(a decimal number each, and an arch\)$"),
        ("auditd_pid_text", "auditd-raw",
         syscall_line(SYSCALL_FIELDS.replace(" pid=4401", " pid=x4401")),
         r": line 1 is a SYSCALL record without pid "),
        ("auditd_no_arch", "auditd-raw", syscall_line(SYSCALL_FIELDS.replace("arch=c000003e ", "")),
         r": line 1 is a SYSCALL record without arch "),
        ("auditd_not_raw", "auditd-raw", b"SYSCALL arch=c000003e syscall=41\n",
         r": line 1 is not a raw auditd record \(type=<TYPE> msg=audit"),
        ("auditd_other_types", "auditd-raw",
         b'type=PROCTITLE msg=audit(1791813600.000:7101): proctitle=6A617661\n', []),
        # A key or a value that one SQLite table cannot hold. A JSON integer outside 64
        # bits is refused when it is parsed (by its value; one of more than 19 digits
        # by its length, before int() reads it: Python stops at 4300 digits).
        ("big_int", "cloudtrail-json", line_of(ct(planted=2 ** 63)),
         r": line 1 holds an integer outside the signed 64-bit range of the table \(SQLite "
         r"INTEGER\)$"),
        ("small_int", "cloudtrail-json", line_of(ct(planted=-2 ** 63 - 1)),
         r": line 1 holds an integer outside the signed 64-bit range"),
        ("int_edges", "cloudtrail-json", line_of(ct(high=2 ** 63 - 1, low=-2 ** 63)),
         {"high": 2 ** 63 - 1, "low": -2 ** 63}),
        ("long_int", "cloudtrail-json", line_of(ct())[:-2] + b', "planted": ' + b"7" * 4301
         + b"}\n", r": line 1 holds an integer outside the signed 64-bit range of the table "
         r"\(SQLite INTEGER\)$"),
        ("long_int_lines", "cloudtrail-json", line_of(ct()) + line_of(ct())[:-2]
         + b', "planted": [-' + b"7" * 4301 + b"]}\n",
         r": line 2 holds an integer outside the signed 64-bit range"),
        ("long_int_envelope", "cloudtrail-json", b'{"Records": [' + line_of(ct())[:-2]
         + b', "planted": ' + b"7" * 4301 + b"}]}\n",
         r": line 1 holds an integer outside the signed 64-bit range"),
        ("long_int_document", "cloudtrail-json", b"[\n" + json.dumps(ct(), indent=1).encode()[:-2]
         + b',\n "planted": ' + b"7" * 4301 + b"\n}\n]\n",
         r": the JSON document holds an integer outside the signed 64-bit range"),
        ("auditd_big_pid", "auditd-raw",
         syscall_line(SYSCALL_FIELDS.replace(" pid=4401", " pid=99999999999999999999")),
         r": line 1: the key 'pid' holds an integer outside the signed 64-bit range"),
        ("rowid_key", "cloudtrail-json", line_of(ct(_ROWID=1)),
         r": line 1: the key '_ROWID' is the name of the row id of the table"),
        ("nul_key", "cloudtrail-json", line_of(ct(**{"planted\x00": 1})),
         r": line 1: the key 'planted\\x00' holds a NUL character \(SQLite refuses it in a "
         r"column name\)$"),
        ("nul_value", "cloudtrail-json", line_of(ct(planted="a\x00b")),
         r": line 1: the key 'planted' holds text with a NUL character"),
        ("surrogate_key", "cloudtrail-json", line_of(ct(**{"\ud800": 1})),
         r": line 1: the key '\\ud800' holds a lone surrogate \(it is not UTF-8\)$"),
        ("surrogate_value", "cloudtrail-json", line_of(ct(planted="\ud800")),
         r": line 1: the key 'planted' holds text with a lone surrogate \(it is not UTF-8\)$"),
        ("not_finite", "cloudtrail-json", line_of(ct())[:-2] + b', "planted": 1e999}\n',
         r": line 1: the key 'planted' holds a number that is not finite"),
        ("deep_array", "cloudtrail-json", line_of(ct())[:-2] + b', "planted": '
         + b"[" * 100000 + b"]" * 100000 + b"}\n",
         ("or read", r": the file nests JSON values too deep to read$")),
        ("deep_array_lines", "cloudtrail-json", line_of(ct()) + line_of(ct())[:-2]
         + b', "planted": ' + b"[" * 100000 + b"]" * 100000 + b"}\n",
         ("or read", r": line 2 nests JSON values too deep to read$")),
        ("deep_object", "cloudtrail-json", line_of(ct())[:-2] + b', "planted": ' + nested(1500)
         + b"}\n", r": line 1 nests objects too deep to read$"),
        # A JSON record that is not one record of the log.
        ("twice", "cloudtrail-json", line_of(ct())[:-2] + b', "eventName": "ModifySnapshot"}\n',
         r": line 1: an object holds the key 'eventName' two times \(one reader keeps the first "
         r"value, another the last\)$"),
        ("twice_in_list", "cloudtrail-json", line_of(ct()) + line_of(ct())[:-2]
         + b', "planted": [{"k": 1, "k": 2}]}\n', r": line 2: an object holds the key 'k' two times"),
        ("twice_in_array", "cloudtrail-json", b"[" + line_of(ct()) + b"," + line_of(ct())[:-2]
         + b', "planted": {"k": 1, "k": 2}}]', r": record 2: an object holds the key 'k' two times"),
        # The envelope of CloudTrail is an object too: json keeps the last list.
        ("twice_envelope", "cloudtrail-json", b'{"Records": [' + json.dumps(ct(eventName="A")).encode()
         + b'], "Records": [' + json.dumps(ct()).encode() + b"]}\n",
         r": line 1: an object holds the key 'Records' two times \(one reader keeps the first "
         r"value, another the last\)$"),
        ("twice_envelope_document", "cloudtrail-json",
         b'{"Records": [\n' + line_of(ct()) + b'],\n"Records": []}\n',
         r": the JSON document: an object holds the key 'Records' two times"),
        ("one_field", "cloudtrail-json", line_of(ct(**{"a.b": 1, "a": {"b": 2}})),
         r": line 1: two keys give the field 'a\.b' when the record is flattened "
         r"\(sigma_eval\.flatten keeps one of them\)$"),
        ("two_fields", "cloudtrail-json", line_of(ct(**{"a.c": 1, "a": {"b": 2}, "l": [{"a": 1}]})),
         {"a.c": 1, "a.b": 2, "l": '[{"a": 1}]'}),
        ("nan", "cloudtrail-json", line_of(ct())[:-2] + b', "planted": NaN}\n',
         r": line 1 holds NaN, which is not a JSON value \(RFC 8259\)$"),
        ("infinity_in_list", "cloudtrail-json", line_of(ct()) + line_of(ct())[:-2]
         + b', "planted": [-Infinity]}\n',
         r": line 2 holds -Infinity, which is not a JSON value \(RFC 8259\)$"),
        ("nan_in_array", "cloudtrail-json", b"[" + line_of(ct()) + b"," + line_of(ct())[:-2]
         + b', "planted": NaN}]', r": the JSON document holds NaN, which is not a JSON value"),
        # More distinct keys in the records of one log source than one table of the gate
        # holds with the fields of the rules (MAX_KEYS, 1900): the dataset is too wide.
        ("wide", "cloudtrail-json", line_of(ct(**{f"k{i}": i for i in range(1947)})),
         r": the aws/cloudtrail records hold 1950 distinct keys; one SQLite table of the gate "
         r"holds at most 1900 \(2000 columns, less the row id and room for the fields of the "
         r"rules\): exclude the dataset in SOURCES\.json, or split it in a change to the gate$"),
        ("wide_lines", "cloudtrail-json", line_of(ct(**{f"a{i}": i for i in range(1000)}))
         + line_of(ct(**{f"b{i}": i for i in range(1000)})),
         r": the aws/cloudtrail records hold 2003 distinct keys; "),
        ("wide_at_the_bound", "cloudtrail-json", line_of(ct(**{f"k{i}": i for i in range(1897)})),
         [("line 1", "aws/cloudtrail")]),
        ("wide_not_routed", "azure-monitor-json", line_of(dict(
            azure("MicrosoftGraphActivityLogs"), **{f"k{i}": i for i in range(1950)})),
         [("line 1", None)]),
    ]
    READ_PROBE = (
        "import base64, traceback\n"
        "_, table = xr.load_syscalls()\n"
        "out = {}\n"
        "for name, fmt, body in ARGS[0]:\n"
        "    try:\n"
        "        records, other = xr.read_dataset({'id': 'T9999/probe/' + name, 'format': fmt},\n"
        "                                         base64.b64decode(body), table)\n"
        "        out[name] = {'records': [[r.where, '/'.join(r.logsource) if r.logsource else None]\n"
        "                                 for r in records],\n"
        "                     'first': records[0].event if records else None, 'other': other}\n"
        "    except xr.Fault as e:\n"
        "        out[name] = {'fault': str(e)}\n"
        "    except Exception:\n"
        "        out[name] = {'crash': traceback.format_exc()}\n"
        "print(json.dumps(out))\n")

    READ_BODY = {name: body for name, _, body, _ in READ}

    # The backstop of the JSON loader: a ValueError of the json module that is not a
    # JSONDecodeError (the parse_int hook of the loader, put back to int(), lets json
    # raise one on an integer of more than 4300 digits) is a Fault that names the line.
    BACKSTOP_PROBE = (
        "_, table = xr.load_syscalls()\n"
        "xr._integer = int\n"
        "line = '{\"eventSource\": \"s\", \"eventName\": \"n\", \"planted\": ' + '7' * 4301 + '}\\n'\n"
        "first = '{\"eventSource\": \"s\", \"eventName\": \"n\"}\\n'\n"
        "out = {}\n"
        "for name, text in (('document', line), ('lines', first + line)):\n"
        "    try:\n"
        "        xr.read_dataset({'id': 'T9999/probe/' + name, 'format': 'cloudtrail-json'},\n"
        "                        text.encode(), table)\n"
        "        out[name] = 'read'\n"
        "    except xr.Fault as e:\n"
        "        out[name] = str(e)\n"
        "    except Exception as e:\n"
        "        out[name] = 'crash: ' + type(e).__name__\n"
        "print(json.dumps(out))\n")

    def test_a_value_error_of_the_json_module_names_the_line(self):
        out = probe(self.good(), self.BACKSTOP_PROBE)
        self.assertEqual(out, {
            "document": "T9999/probe/document: line 1 is not JSON that the json module reads "
                        "(ValueError)",
            "lines": "T9999/probe/lines: line 2 is not JSON that the json module reads "
                     "(ValueError)"})

    def test_the_loaders_read_each_format_and_refuse_what_is_not_a_record(self):
        import base64
        cases = [(name, fmt, base64.b64encode(body).decode()) for name, fmt, body, _ in self.READ]
        out = probe(self.good(), self.READ_PROBE, cases)
        for name, _, _, want in self.READ:
            with self.subTest(name):
                got = out[name]
                self.assertNotIn("crash", got, got.get("crash"))
                if isinstance(want, tuple):
                    if "fault" in got:
                        self.assertRegex(got["fault"], rf"^T9999/probe/{name}" + want[1])
                    else:
                        self.assertEqual(len(got["records"]), len(self.READ_BODY[name].split(b"\n")) - 1)
                elif isinstance(want, str):
                    self.assertIn("fault", got, got)
                    self.assertRegex(got["fault"], rf"^T9999/probe/{name}" + want)
                elif isinstance(want, list):
                    self.assertEqual(got.get("records"), [list(w) for w in want], got)
                else:
                    self.assertIn("first", got, got)
                    self.assertEqual({k: got["first"].get(k) for k in want}, want)
        self.assertEqual(out["auditd_other_types"]["other"], 1)

    SNIFF = [
        ("k8s", line_of(k8s()), "k8s-audit-json"),
        ("cloudtrail", line_of(ct()), "cloudtrail-json"),
        ("azure", line_of(azure("AuditLogs")), "azure-monitor-json"),
        ("auditd", syscall_line(SYSCALL_FIELDS), "auditd-raw"),
        # Records of no log source of the rules: no format, and a reason for each.
        ("azure_unrouted", line_of(azure("MicrosoftGraphActivityLogs")), None),
        ("ocsf", line_of({"class_uid": 6003, "api": {"operation": "ModifySnapshotAttribute"}}),
         None),
        # A record that no format reads: an integer of more than 4300 digits (--draft
        # prints an excluded entry; it does not stop).
        ("long_int", line_of(ct())[:-2] + b', "planted": ' + b"7" * 4301 + b"}\n", None),
    ]
    SNIFF_PROBE = (
        "import base64\n"
        "_, table = xr.load_syscalls()\n"
        "out = {}\n"
        "for name, body in ARGS[0]:\n"
        "    fmt, records, _ = xr.sniff('T9999/probe/' + name, base64.b64decode(body), table)\n"
        "    out[name] = [fmt, len(records) if fmt else records]\n"
        "print(json.dumps(out))\n")

    def test_the_sniff_of_draft_names_the_native_format(self):
        import base64
        out = probe(self.good(), self.SNIFF_PROBE,
                    [(n, base64.b64encode(b).decode()) for n, b, _ in self.SNIFF])
        for name, _, fmt in self.SNIFF:
            with self.subTest(name):
                self.assertEqual(out[name][0], fmt, out[name])
                if fmt:
                    self.assertEqual(out[name][1], 1)
                else:
                    self.assertEqual(len(out[name][1]), 4, out[name])
        self.assertIn("azure-monitor-json: no record routes to a log source of the repository",
                      out["azure_unrouted"][1])
        for fmt in ("k8s-audit-json", "cloudtrail-json", "azure-monitor-json"):
            self.assertIn(f"{fmt}: T9999/probe/long_int: line 1 holds an integer outside the "
                          "signed 64-bit range of the table (SQLite INTEGER)", out["long_int"][1])

    YML_ENTRY = {"id": "T1068/planted/audit", "path": "datasets/attack_techniques/T1068/planted/audit.log",
                 "techniques": ["T1068"], "sourcetype": "auditd",
                 "yml": "datasets/attack_techniques/T1068/planted/planted.yml",
                 "procedure": {"label": "CVE-2026-31431", "cves": ["CVE-2026-31431"], "why": "x"}}
    YML_TEXT = ("description: Generated datasets for {label} privilege escalation\n"
                "    in attack range.\n"
                "mitre_technique:\n- {technique}\n"
                "datasets:\n- name: audit\n  sourcetype: {sourcetype}\n  path: /{path}\n")
    # The constructed rules of the procedure checks (a folder like detections/sigma/):
    # {path: (title, cve.* tags)}.
    RULE_DIR = {"T1068/planted_copyfail.yml": ("Planted Correlation (CopyFail CVE-2026-31431)",
                                               ["cve.2026-31431"]),
                "T1068/planted_dirtyfrag.yml": ("Planted Socket (DirtyFrag RxRPC CVE-2026-43500)",
                                                ["cve.2026-43500"]),
                "T1040/planted_afpacket.yml": ("Planted AF_PACKET Socket (CVE-2016-8655)",
                                               ["cve.2016-8655"])}
    LABEL = (r"^T1068/planted/audit: SOURCES\.json gives the procedure label '{}'; the "
             r"description of the yml \S+ at the commit does not name it$")
    NO_CVE = (r"^T1068/planted/audit: SOURCES\.json gives the procedure label '{}' the CVE {}; "
              r"the description of the yml \S+ at the commit does not name the CVE, and no rule "
              r"of T1068 with the tag cve\.{} has the label in its title$")

    # (name, the change: the text of the yml, and the procedure of the entry; the
    # problems: one regular expression each). The label of the yml is the text of its
    # description; the label of the entry is CVE-2026-31431 unless the change gives one.
    YMLS = [
        ("sound", {}, []),
        ("label_folded", {"label": "CVE-2026-31431\n   "}, []),
        ("other_path", {"path": "datasets/attack_techniques/T1068/planted/other.log"},
         [r"^T1068/planted/audit: the yml \S+ at the commit does not name the path "
          r"datasets/attack_techniques/T1068/planted/audit\.log$"]),
        ("other_sourcetype", {"sourcetype": "linux_audit"},
         [r"^T1068/planted/audit: SOURCES\.json pins the sourcetype 'auditd'; the yml at the "
          r"commit gives \['linux_audit'\]$"]),
        ("other_technique", {"technique": "T1068.001"},
         [r"^T1068/planted/audit: SOURCES\.json pins the techniques \['T1068'\]; the yml at the "
          r"commit names \['T1068\.001'\]$"]),
        # (Its CVE is the tag of a rule whose title holds the label: no second problem.)
        ("no_label", {"label": "an exploit"}, [LABEL.format("CVE-2026-31431")]),
    ]
    # The label is a whole token of the description: no letter, digit or hyphen next to it.
    YMLS += [
        ("label_in_a_word", {"label": "Copy Failure CVE-2026-31431",
                             **procedure("Copy Fail", "CVE-2026-31431")},
         [LABEL.format("Copy Fail")]),
        ("label_after_a_hyphen", {"label": "Pre-Copy Fail CVE-2026-31431",
                                  **procedure("Copy Fail", "CVE-2026-31431")},
         [LABEL.format("Copy Fail")]),
        ("label_cut_short", {"label": "CVE-2026-43500",
                             **procedure("CVE-2026-4350", "CVE-2026-4350")},
         [LABEL.format("CVE-2026-4350"), NO_CVE.format("CVE-2026-4350", "CVE-2026-4350",
                                                        "2026-4350")]),
    ]
    # Each CVE is a whole token of the description, or the cve.* tag of a rule of the
    # technique folder whose title holds the label (without white space and letter case).
    YMLS += [
        ("cve_by_a_rule", {"label": "Copy Fail", **procedure("Copy Fail", "CVE-2026-31431")},
         []),
        ("cve_by_the_description", {"label": "Planted Exploit CVE-1999-0001",
                                    **procedure("Planted Exploit", "CVE-1999-0001")}, []),
        ("cve_not_named", {"label": "Copy Fail",
                           **procedure("Copy Fail", "CVE-2026-31431", "CVE-1999-0001")},
         [NO_CVE.format("Copy Fail", "CVE-1999-0001", "1999-0001")]),
        ("cve_of_another_title", {"label": "Copy Fail",
                                  **procedure("Copy Fail", "CVE-2026-43500")},
         [NO_CVE.format("Copy Fail", "CVE-2026-43500", "2026-43500")]),
        ("cve_of_another_folder", {"label": "AF_PACKET",
                                   **procedure("AF_PACKET", "CVE-2016-8655")},
         [NO_CVE.format("AF_PACKET", "CVE-2016-8655", "2016-8655")]),
        # A phrase of the description is not the procedure (review of PR-1, X3).
        ("phrase_of_the_description", {"label": "Dirty Frag",
                                       **procedure("privilege escalation", "CVE-2026-31431")},
         [NO_CVE.format("privilege escalation", "CVE-2026-31431", "2026-31431")]),
    ]
    YML_PROBE = (
        "import os\n"
        "entry, text, ymls, rules = ARGS\n"
        "xr.SIGMA = os.path.join(os.environ['TMPDIR'], 'probe-sigma')\n"
        "for rel, (title, tags) in rules.items():\n"
        "    os.makedirs(os.path.dirname(os.path.join(xr.SIGMA, rel)), exist_ok=True)\n"
        "    with open(os.path.join(xr.SIGMA, rel), 'w', encoding='utf-8') as fh:\n"
        "        fh.write(json.dumps({'title': title, 'tags': tags}))\n"
        "out = {}\n"
        "for name, change, base in ymls:\n"
        "    e = dict(entry, procedure=change.pop('procedure', entry['procedure']))\n"
        "    out[name] = xr.check_yml(e, text.format(**dict(base, **change)).encode())\n"
        "out['old_schema'] = xr.check_yml(dict(entry, procedure=None), (\n"
        "    'description: x\\ndataset:\\n- https://media.githubusercontent.com/media/splunk/'\n"
        "    'attack_data/master/' + entry['path'] + '\\nsourcetypes:\\n- auditd\\n').encode())\n"
        "out['not_a_mapping'] = xr.check_yml(entry, b'- a list\\n')\n"
        "out['not_utf8'] = xr.check_yml(entry, b'description: \\xff\\n')\n"
        "print(json.dumps(out))\n")

    def test_the_yml_of_a_dataset_must_agree_with_its_entry(self):
        """check_yml() on constructed ymls, with constructed rules in place of
        detections/sigma/ (xr.SIGMA): the procedure label of the entry against the
        description of its yml and the titles and cve.* tags of the rules."""
        entry = self.YML_ENTRY
        base = {"label": entry["procedure"]["label"], "technique": "T1068",
                "sourcetype": "auditd", "path": entry["path"]}
        out = probe(self.good(), self.YML_PROBE, entry, self.YML_TEXT,
                    [(n, change, base) for n, change, _ in self.YMLS], self.RULE_DIR)
        for name, _, want in self.YMLS + [("old_schema", None, [])]:
            with self.subTest(name):
                self.assertEqual(len(out[name]), len(want), out[name])
                for got, reason in zip(out[name], want):
                    self.assertRegex(got, reason)
        self.assertEqual(out["not_a_mapping"], ["T1068/planted/audit: the yml "
                                                f"{entry['yml']} cannot be read (ValueError)"])
        self.assertEqual(out["not_utf8"], ["T1068/planted/audit: the yml "
                                           f"{entry['yml']} cannot be read (UnicodeDecodeError)"])

    REAL_LABELS = (
        "doc = xr.load_json(xr.SOURCES, 'SOURCES.json')\n"
        "text = ARGS[0]\n"
        "out = {}\n"
        "for e in doc['datasets']:\n"
        "    if e.get('procedure'):\n"
        "        yml = text.format(label=e['procedure']['label'],\n"
        "                          technique='\\n- '.join(e['techniques']),\n"
        "                          sourcetype=e['sourcetype'], path=e['path'])\n"
        "        out[e['id']] = xr.check_yml(e, yml.encode())\n"
        "print(json.dumps(out))\n")

    def test_the_procedure_labels_of_sources_json_hold(self):
        """The control of the procedure checks: each label of the real SOURCES.json, in a
        constructed yml whose description has the form of the ymls of these datasets
        ("Generated datasets for <label> privilege escalation in attack range."), against
        the real rules: a label that is not a CVE ID has its CVEs from the titles and the
        cve.* tags of the rules of its technique (detections/tests/README.md, Limits)."""
        out = probe(self.good(), self.REAL_LABELS, self.YML_TEXT)
        self.assertGreaterEqual(len(out), 5, "the labels of SOURCES.json were not read")
        self.assertEqual({k: v for k, v in out.items() if v}, {})

    TABLE_PROBE = (
        "import argparse\n"
        "rules = [cer.Rule(p) for p in cer.rule_paths() if '/T1537/' in p]\n"
        "args = argparse.Namespace(explain=False, suggest=False, markdown=None, json=None,\n"
        "                          enforce=False)\n"
        "report = cer.Report(args)\n"
        "ds = {'id': 'T1537/probe/cloudtrail', 'format': 'cloudtrail-json',\n"
        "      'techniques': ['T1537']}\n"
        "record = xr.Record('line 1', ('aws', 'cloudtrail'), {'eventSource': 'ec2.amazonaws.com',\n"
        "                   'eventName': 'ModifySnapshotAttribute', 'planted': 2 ** 70})\n"
        "cer.evaluate(report, ds, {('aws', 'cloudtrail'): [record]}, rules, {}, {}, {})\n"
        "print(json.dumps({'rules': len(rules), 'errors': report.errors, 'pairs': report.pairs}))\n")

    def test_the_report_refuses_a_table_that_it_cannot_build(self):
        """The backstop of evaluate(): a record that read_dataset() would refuse (here
        given to evaluate() directly) is one ERROR for the dataset and the log source,
        not a traceback, and no rule is judged on it."""
        out = probe(self.good(), self.TABLE_PROBE)
        self.assertGreater(out["rules"], 1)
        self.assertEqual(out["errors"], [
            "T1537/probe/cloudtrail: the aws/cloudtrail records cannot go into one table "
            "(OverflowError); the loader must refuse such a record by its line (a fault of the "
            "gate)"])
        self.assertEqual(out["pairs"], [])

    # Records at the bound of keys (MAX_KEYS), none of them a field of a rule: every
    # rule of the log source runs on one table of them, as the report shares a table
    # between the rules of a dataset, and each rule adds its fields as columns.
    WIDE_PROBE = (
        "import sigma_eval\n"
        "record = {'k%d' % i: i for i in range(xr.MAX_KEYS)}\n"
        "rules = [cer.Rule(p) for p in cer.rule_paths()]\n"
        "out = {'MAX_KEYS': xr.MAX_KEYS}\n"
        "for name, source in (('cloudtrail', ('aws', 'cloudtrail')),\n"
        "                     ('audit', ('kubernetes', 'audit'))):\n"
        "    table = sigma_eval.EventTable([record])\n"
        "    ran, errors = 0, []\n"
        "    for rule in rules:\n"
        "        if rule.logsource != source:\n"
        "            continue\n"
        "        try:\n"
        "            table.hit_indices(rule.sql())\n"
        "            ran += 1\n"
        "        except Exception as e:\n"
        "            errors.append(f'{rule.key}: {type(e).__name__}: {e}')\n"
        "    columns = len(table.db.execute('PRAGMA table_info(logs)').fetchall())\n"
        "    out[name] = {'ran': ran, 'errors': errors, 'columns': columns}\n"
        "print(json.dumps(out))\n")

    def test_the_bound_of_keys_leaves_room_for_the_fields_of_the_rules(self):
        """A dataset at the bound of the loader runs every rule of its log source on one
        table: the bound (MAX_KEYS) is not the error of a rule (review of PR-1, X5)."""
        out = probe(self.good(), self.WIDE_PROBE)
        self.assertEqual(out["MAX_KEYS"], 1900)
        for name in ("cloudtrail", "audit"):
            with self.subTest(name):
                self.assertGreater(out[name]["ran"], 10, out[name])
                self.assertEqual(out[name]["errors"], [])
                self.assertLess(out[name]["columns"], 2000)

    FETCH_PROBE = (
        "import hashlib, http.server, os, threading\n"
        "GOOD, OTHER = b'constructed by detections/tests\\n', b'other bytes\\n'\n"
        "SHA = hashlib.sha256(GOOD).hexdigest()\n"
        "class Handler(http.server.BaseHTTPRequestHandler):\n"
        "    def log_message(self, *a):\n"
        "        pass\n"
        "    def do_GET(self):\n"
        "        routes = {'/good': GOOD, '/other': OTHER, '/long': GOOD + b'x'}\n"
        "        if self.path in routes:\n"
        "            self.send_response(200)\n"
        "            self.end_headers()\n"
        "            self.wfile.write(routes[self.path])\n"
        "        elif self.path.startswith('/to/'):\n"
        "            self.send_response(302)\n"
        "            self.send_header('Location', self.path[len('/to/'):].replace('PORT2', str(port2))\n"
        "                             .replace('PORT', str(port)))\n"
        "            self.end_headers()\n"
        "        else:\n"
        "            self.send_response(404)\n"
        "            self.end_headers()\n"
        "servers = [http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) for _ in (1, 2)]\n"
        "for server in servers:\n"
        "    threading.Thread(target=server.serve_forever, daemon=True).start()\n"
        "port, port2 = (server.server_address[1] for server in servers)\n"
        "base = f'http://127.0.0.1:{port}'\n"
        "root = os.path.join(os.environ['TMPDIR'], 'probe-cache')\n"
        "def fresh(name):\n"
        "    return xr.Cache(os.path.join(root, name))\n"
        "def put(cache, data):\n"
        "    os.makedirs(os.path.dirname(cache.path(SHA)), exist_ok=True)\n"
        "    with open(cache.path(SHA), 'wb') as fh:\n"
        "        fh.write(data)\n"
        "def held(cache):\n"
        "    if not os.path.isfile(cache.path(SHA)):\n"
        "        return None\n"
        "    with open(cache.path(SHA), 'rb') as fh:\n"
        "        return fh.read().decode()\n"
        "def run(name, cache, url, offline=False, size=len(GOOD)):\n"
        "    try:\n"
        "        data, origin, bad = xr.obtain(cache, SHA, size, url, offline, name)\n"
        "        got = {'data': data.decode(), 'origin': origin, 'bad': bad and str(bad)}\n"
        "    except xr.HashMismatch as e:\n"
        "        got = {'HashMismatch': str(e)}\n"
        "    except xr.Fault as e:\n"
        "        got = {'Fault': str(e)}\n"
        "    except xr.Unavailable as e:\n"
        "        got = {'Unavailable': str(e)}\n"
        "    got['held'] = held(cache)\n"
        "    out[name] = got\n"
        "out = {'port': port, 'port2': port2}\n"
        "run('good', fresh('good'), base + '/good')\n"
        "run('cached', out_cache := fresh('cached'), base + '/good')\n"
        "run('cached_again', out_cache, base + '/missing')\n"
        "run('other_bytes', fresh('other'), base + '/other')\n"
        "run('longer', fresh('longer'), base + '/long')\n"
        "put(c := fresh('bad_then_good'), OTHER)\n"
        "run('bad_then_good', c, base + '/good')\n"
        "put(c := fresh('bad_then_none'), OTHER)\n"
        "run('bad_then_none', c, base + '/missing')\n"
        "put(c := fresh('bad_offline'), OTHER)\n"
        "run('bad_offline', c, base + '/good', offline=True)\n"
        "run('offline', fresh('offline'), base + '/good', offline=True)\n"
        "run('missing', fresh('missing'), base + '/missing')\n"
        "run('redirect_same', fresh('same'), base + '/to//good')\n"
        "run('redirect_port', fresh('port'), base + '/to/http://127.0.0.1:PORT2/good')\n"
        "run('redirect_host', fresh('host'), base + '/to/http://localhost:PORT/good')\n"
        "os.makedirs(fresh('entry_dir').path(SHA))\n"
        "run('entry_dir', fresh('entry_dir'), base + '/good')\n"
        "def bounded(name, cache, url):\n"
        "    # A cache entry that blocks a read must not stop the probe (nor the test).\n"
        "    t = threading.Thread(target=run, args=(name, cache, url), daemon=True)\n"
        "    t.start()\n"
        "    t.join(10)\n"
        "    if t.is_alive():\n"
        "        out[name] = {'hang': 'obtain() did not return in 10 s'}\n"
        "if hasattr(os, 'mkfifo'):\n"
        "    c = fresh('entry_fifo')\n"
        "    os.makedirs(os.path.dirname(c.path(SHA)))\n"
        "    os.mkfifo(c.path(SHA))\n"
        "    bounded('entry_fifo', c, base + '/good')\n"
        "    c = fresh('entry_fifo_link')\n"
        "    os.makedirs(os.path.dirname(c.path(SHA)))\n"
        "    os.mkfifo(os.path.join(c.root, 'fifo'))\n"
        "    os.symlink(os.path.join(c.root, 'fifo'), c.path(SHA))\n"
        "    bounded('entry_fifo_link', c, base + '/good')\n"
        "os.makedirs(root, exist_ok=True)\n"
        "open(os.path.join(root, 'a_file'), 'w').close()\n"
        "run('root_file', fresh('a_file'), base + '/good')\n"
        "run('over_cap', fresh('cap'), base + '/good', size=xr.MAX_BYTES + 1)\n"
        "if os.path.isdir('/proc'):\n"
        "    c = fresh('write_fails')\n"
        "    os.makedirs(c.root)\n"
        "    os.symlink('/proc', os.path.join(c.root, 'sha256'))\n"
        "    run('write_fails', c, base + '/good')\n"
        "    out['write_fails_left'] = sorted(os.listdir(c.root))\n"
        "print(json.dumps(out))\n")

    def test_the_fetch_checks_each_download_and_each_cached_copy(self):
        """xr.obtain() and xr.fetch() against a server of the probe on 127.0.0.1: a
        download of other bytes, a cached copy of other bytes, a redirect off the origin,
        a cache that cannot hold the file. The proxy of the sandbox still refuses every
        other host."""
        out = probe(self.good(), self.FETCH_PROBE,
                    env={"no_proxy": "127.0.0.1", "NO_PROXY": "127.0.0.1"})
        port, port2 = out["port"], out["port2"]
        good = "constructed by detections/tests\n"
        sha = hashlib.sha256(good.encode()).hexdigest()
        want = {
            "good": {"data": good, "origin": "download", "bad": None, "held": good},
            "cached": {"data": good, "origin": "download", "bad": None, "held": good},
            "cached_again": {"data": good, "origin": "cache", "bad": None, "held": good},
            "offline": {"Unavailable": "not in the cache, and the run is --offline", "held": None},
            "missing": {"Unavailable": f"HTTP 404 from http://127.0.0.1:{port}/missing",
                        "held": None},
            "redirect_same": {"data": good, "origin": "download", "bad": None, "held": good},
        }
        for name, expected in want.items():
            with self.subTest(name):
                self.assertEqual(out[name], expected)
        # A download of other bytes, or of more bytes than the pin: nothing is cached.
        for name, url in (("other_bytes", "/other"), ("longer", "/long")):
            with self.subTest(name):
                self.assertRegex(out[name].get("HashMismatch", ""), rf"^HASH MISMATCH {name}: the "
                                 rf"pin is {sha} \({len(good)} bytes\); got (?!{sha})[0-9a-f]{{64}} "
                                 rf"\(\d+ bytes\) from http://127\.0\.0\.1:{port}{url}$")
                self.assertIsNone(out[name]["held"])
        # A cached copy of other bytes is deleted; after a good download the run still
        # reports it, and without one the bad copy is the fault.
        self.assertEqual((out["bad_then_good"]["data"], out["bad_then_good"]["held"]), (good, good))
        self.assertRegex(out["bad_then_good"]["bad"] or "", r"^HASH MISMATCH bad_then_good: .* "
                         r"from the cache \(.*\); the file was deleted$")
        self.assertRegex(out["bad_then_none"].get("HashMismatch", ""), r"^HASH MISMATCH "
                         r"bad_then_none: .*; the file was deleted\. A new download failed: HTTP 404")
        self.assertRegex(out["bad_offline"].get("HashMismatch", ""), r"from the cache \(.*\); the "
                         r"file was deleted$")
        for name in ("bad_then_none", "bad_offline"):
            self.assertIsNone(out[name]["held"])
        # No redirect to another port or host is followed.
        for name, origin in (("redirect_port", f"http://127.0.0.1:{port2}"),
                             ("redirect_host", f"http://localhost:{port}")):
            with self.subTest(name):
                self.assertRegex(out[name].get("Unavailable", ""), rf"redirects to another origin "
                                 rf"\('{re.escape(origin)}'\); no redirect off the origin is followed$")
                self.assertIsNone(out[name]["held"])
        # A cache that cannot hold the file is a fault that names it. An entry that is
        # not a regular file is not read (a FIFO would wait for a writer) and not replaced.
        names = ["entry_dir"] + (["entry_fifo", "entry_fifo_link"] if hasattr(os, "mkfifo") else [])
        for name in names:
            with self.subTest(name):
                self.assertNotIn("hang", out[name], out[name])
                self.assertRegex(out[name].get("Fault", ""), rf"^{name}: the cache entry \S+ is "
                                 r"not a regular file \(a directory, a FIFO or a device, or a link "
                                 r"to one\); delete it or give another --cache$")
        self.assertRegex(out["root_file"].get("Fault", ""), r"^root_file: the cache \S+a_file "
                         r"cannot keep the file \(\w+Error: .*\); give another --cache$")
        self.assertEqual(out["over_cap"].get("Fault"), f"over_cap: size {50 * 1024 * 1024 + 1} is "
                         "over the cap of 52428800 bytes")
        if os.path.isdir("/proc"):       # Linux: the rename into /proc fails
            self.assertRegex(out["write_fails"].get("Fault", ""), r"^write_fails: the cache entry "
                             r"\S+ cannot be written \(\w+Error: .*\); delete it or give another "
                             r"--cache$")
            self.assertEqual(out["write_fails_left"], ["sha256"], "the temporary file was removed")

    DEADLINE_PROBE = (
        "import http.server, os, threading, time\n"
        "seen, stop, mode = [], threading.Event(), {'proxy': 'silent'}\n"
        "class Silent(http.server.BaseHTTPRequestHandler):\n"
        "    # Accepts and never answers (a CONNECT of the proxy too). /trickle, and a\n"
        "    # CONNECT in the mode 'trickle', send a header a byte at a time: no step of\n"
        "    # the request waits longer than the timeout.\n"
        "    def log_message(self, *a):\n"
        "        pass\n"
        "    def do_GET(self):\n"
        "        seen.append(self.path)\n"
        "        if self.path == '/trickle' or (self.command == 'CONNECT'\n"
        "                                       and mode['proxy'] == 'trickle'):\n"
        "            self.wfile.write(b'HTTP/1.0 200 OK\\r\\nX-Planted: ')\n"
        "            while not stop.wait(0.05):\n"
        "                self.wfile.write(b'x')\n"
        "                self.wfile.flush()\n"
        "        stop.wait()\n"
        "    do_CONNECT = do_GET\n"
        "server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Silent)\n"
        "threading.Thread(target=server.serve_forever, daemon=True).start()\n"
        "base = f'http://127.0.0.1:{server.server_address[1]}'\n"
        "def within(seconds, call):\n"
        "    # A regression must fail the test, not hang it.\n"
        "    box = {}\n"
        "    def work():\n"
        "        try:\n"
        "            box['value'] = call()\n"
        "        except Exception as e:\n"
        "            box['value'] = {'crash': f'{type(e).__name__}: {e}'}\n"
        "    t = threading.Thread(target=work, daemon=True)\n"
        "    t.start()\n"
        "    t.join(seconds)\n"
        "    return box.get('value', {'hang': f'no answer in {seconds} s'})\n"
        "def requests(deadline, paths):\n"
        "    got, start = [], time.monotonic()\n"
        "    for path in paths:\n"
        "        t0 = time.monotonic()\n"
        "        try:\n"
        "            xr.fetch(base + path, 100, deadline)\n"
        "            got.append(['read', 0, path])\n"
        "        except xr.Unavailable as e:\n"
        "            got.append([str(e), time.monotonic() - t0, path])\n"
        "    return {'got': got, 'elapsed': time.monotonic() - start}\n"
        "def settled():\n"
        "    # The worker thread of a request that was given up at the deadline can reach\n"
        "    # the server after fetch() returned: wait until the server's list is still.\n"
        "    last, t0 = None, time.monotonic()\n"
        "    while time.monotonic() - t0 < 5:\n"
        "        now = list(seen)\n"
        "        if now == last:\n"
        "            break\n"
        "        last = now\n"
        "        time.sleep(0.3)\n"
        "    return list(seen)\n"
        "out = {'hang': within(30, lambda: requests(xr.Deadline(1.0, 0.3),\n"
        "                                         [f'/hang{n}' for n in range(6)]))}\n"
        "out['hang']['seen'] = settled()\n"
        "out['trickle'] = within(30, lambda: requests(xr.Deadline(0.8, 0.5), ['/trickle']))\n"
        "# The run: one deadline for all its requests (the origins through the proxy).\n"
        "for name in ('https_proxy', 'HTTPS_PROXY'):\n"
        "    os.environ[name] = base\n"
        "xr.DEADLINE, xr.TIMEOUT = 1.0, 0.25\n"
        "def run():\n"
        "    t0 = time.monotonic()\n"
        "    code = cer.main(['--cache', os.path.join(os.environ['TMPDIR'], 'deadline-cache'),\n"
        "                     '--json', report])\n"
        "    return {'code': code, 'elapsed': time.monotonic() - t0}\n"
        "for name in ('silent', 'trickle'):\n"
        "    mode['proxy'] = name\n"
        "    del seen[:]\n"
        "    report = os.path.join(os.environ['TMPDIR'], f'deadline-{name}.json')\n"
        "    out[name + '_run'] = within(60, run)\n"
        "    out[name + '_run']['seen'] = len(settled())\n"
        "    if os.path.exists(report):\n"
        "        with open(report, encoding='utf-8') as fh:\n"
        "            out[name + '_run']['report'] = json.load(fh)\n"
        "stop.set()\n"
        "print(json.dumps(out))\n")

    def test_the_network_work_of_a_run_ends_at_its_deadline(self):
        """xr.fetch() against a server of the probe on 127.0.0.1 that accepts and never
        answers, with a deadline of 1 s and 0.3 s for each step: each request waits one
        step, and after the deadline a request is UNAVAILABLE without a connection. A
        header that comes a byte at a time is given up at the deadline. The report, with
        the origins behind that server (as a proxy that does not answer, or that sends
        a header a byte at a time) and a deadline of 1 s, ends in about 1 s with an
        UNAVAILABLE row for each file (review of PR-1, N2)."""
        out = probe(self.good(), self.DEADLINE_PROBE,
                    env={"no_proxy": "127.0.0.1", "NO_PROXY": "127.0.0.1"})
        slack = 3.0                         # a loaded runner
        hang = out["hang"]
        self.assertFalse({"hang", "crash"} & set(hang), hang)
        late = [m for m, _, _ in hang["got"] if "not requested: the network deadline of the "
                "run (1 s) has passed" in m]
        asked = len(hang["got"]) - len(late)
        self.assertGreaterEqual(len(late), 2, hang)
        self.assertEqual([m for m, _, _ in hang["got"][asked:]], late,
                         "a request after a late one")
        asked_paths = [p for _, _, p in hang["got"][:asked]]
        late_paths = [p for _, _, p in hang["got"][asked:]]
        # No late request reaches the server, and each request that was made does (the
        # server's list is read when it is still, so a request that was given up at the
        # deadline is in it too).
        self.assertFalse(set(hang["seen"]) & set(late_paths), "a late request made a connection")
        self.assertEqual(sorted(hang["seen"]), sorted(asked_paths), hang)
        for message, elapsed, _ in hang["got"][:asked]:
            self.assertRegex(message, r"timed out|given up: the network deadline")
            self.assertLess(elapsed, 0.3 + slack)
        # The first request waits one step (0.3 s), not until the deadline.
        self.assertRegex(hang["got"][0][0], r"/hang0: TimeoutError: timed out$")
        for _, elapsed, _ in hang["got"][asked:]:
            self.assertLess(elapsed, 0.1)
        self.assertLess(hang["elapsed"], 1.0 + slack)
        trickle = out["trickle"]
        self.assertFalse({"hang", "crash"} & set(trickle), trickle)
        (message, elapsed, _), = trickle["got"]
        self.assertRegex(message, r"/trickle: given up: the network deadline of the run "
                                  r"\(0\.8 s\) passed during the request$")
        self.assertGreater(elapsed, 0.7)
        self.assertLess(elapsed, 0.8 + slack)
        datasets = len(self.good().read_json(SOURCES)["datasets"])
        for name in ("silent_run", "trickle_run"):
            with self.subTest(name):
                run = out[name]
                self.assertFalse({"hang", "crash"} & set(run), run)
                self.assertEqual(run["code"], 2)
                self.assertLess(run["elapsed"], 1.0 + slack)
                report = run["report"]
                self.assertEqual(len(report["unavailable"]), datasets + 2)
                late = [u["dataset"] for u in report["unavailable"]
                        if "not requested: the network deadline" in u["why"]]
                self.assertEqual(run["seen"], datasets + 2 - len(late), report["unavailable"])
                self.assertIn("no dataset was read, so the run checked nothing (every dataset "
                              "is UNAVAILABLE)", report["errors"])
                if name == "silent_run":
                    self.assertGreaterEqual(len(late), datasets + 2 - 6, report["unavailable"])
                    self.assertEqual(report["unavailable"][0]["dataset"], "LICENSE")
                    self.assertRegex(report["unavailable"][0]["why"], r": URLError: timed out$")
                else:
                    # One deadline for the run: the first request (the LICENSE) is given
                    # up at the deadline, and no other request is made.
                    first = report["unavailable"][0]
                    self.assertEqual(first["dataset"], "LICENSE")
                    self.assertIn("given up: the network deadline of the run (1 s)", first["why"])
                    self.assertEqual(run["seen"], 1, report["unavailable"])

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
