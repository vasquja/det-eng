#!/usr/bin/env python3
"""
The external-records gate (roadmap item R3): each rule on the records of
splunk/attack_data that are of its technique. The agent did not write these
records.

detections/external/SOURCES.json pins the datasets: one full commit of
splunk/attack_data, and the sha256, the size, the format and the record count of
each file. The gate downloads each file from the fixed origin (or takes it from a
content-addressed cache), checks its sha256 and its record count, reads each record
in its native format and sends it to a log source by its own shape (a CloudTrail
record, an Azure Monitor record by its `category`, a Kubernetes audit event, a raw
auditd SYSCALL record). Then it runs each rule, through the same pySigma backend as
the validators, on the records of the rule's log source.

A rule and a dataset make a pair when one of these is true:

  same technique   the ATT&CK ID of the rule's folder (detections/sigma/<ID>/) is a
                   technique of the dataset (its yml's mitre_technique), and a record
                   of the dataset goes to the rule's log source. The rule must FIRE
                   on the dataset, unless a declaration says otherwise. When the
                   dataset has a `procedure` label (the CVE or the exploit that the
                   description of its yml names; raw auditd only) and no cve.* tag
                   of the rule is one of its CVEs, the pair is OTHER-PROCEDURE:
                   reported, not expected.
  related          another attack.t tag of the rule (not its folder) is a technique
                   of the dataset: RELATED, reported, not expected. A parent or a
                   sub-technique of a technique is not the technique.
  declared fire    a `fire` declaration makes any other pair expected.

Rows (one for each dataset and for each pair; no row holds a value of a record):

  DATASET <id>          the file was read: its format, records, log sources, sha256
  FIRE <rule> on <id>   the rule fired: records that it matched (a correlation:
                        alerts, and the distinct records that are their evidence)
  MISS <rule> on <id>   an expected pair with no hit, and the nearest record with
                        the items of the rule that it fails
  RELATED, OTHER-PROCEDURE    reported pairs, with their hits
  NOT READ <rule> on <id>     same technique and product, but no record of the
                              rule's log source (an Entra sign-in rule on an audit
                              log)
  QUIET, N/A, KNOWN-MISS <ID> a declaration that holds (0 hits)
  DECLARED QUIET, FIRED / STALE N/A / KNOWN-MISS FIRES   a declaration that a hit
                              contradicts
  STALE <rule> on <id>  a declaration that no longer applies (the rule's digest or
                        the dataset's sha256 changed, a defect it cites is not
                        listed, or it is redundant): the default verdict applies
  EXCLUDED <rule> on <id>     a dataset that SOURCES.json leaves out, with its why
  UNAVAILABLE <id>      not in the cache and no download (also a ::warning); also
                        the LICENSE or syscall_64.tbl of an online run
  ERROR ...             a structural fault (exit 2)

Declarations are in detections/external/expectations.json (a human decision; the
file is not content for the merge policy). Each one names a rule, a dataset id,
`expect` (quiet, n/a, known-miss or fire), a why with a fixed prefix, the digest
of the rule (check_sufficiency.detection_digest) and the sha256 of the dataset:

  quiet       why starts `quiet:`: the dataset is of the rule's own procedure and
              the rule must not fire on it (a consent that a policy blocked).
  n/a         why starts `another procedure:` or `not in the capture:`.
  known-miss  why starts `rule defect, tracked in detections/RULE_DEFECTS.md <ID>:`
              and the Summary table of that file lists <ID>.
  fire        why starts `same procedure:`, on a pair that is not expected.

Exit codes:
  0  shadow mode (the default): no verdict fails the run.
  1  --enforce only: a MISS without a declaration, a STALE declaration, a declared
     quiet that fired, an n/a that fired, a known-miss that fires, or a declared
     fire that missed.
  2  in every mode, a structural fault: a malformed SOURCES.json, expectations.json
     or syscall table, a declaration for a rule or a dataset that does not exist, a
     HASH MISMATCH (also of a cached file, which is deleted), a record count that
     is not the pinned count, a line that is not a record of its format (also a JSON
     object that holds a key two times, the envelope {"Records": [...]} too, two keys
     that flatten to one field, NaN or Infinity), a key or a value that one SQLite
     table cannot hold (an integer outside 64 bits, of any length, a NUL, a lone
     surrogate, the key _rowid, a number that is not finite), keys that differ only
     in letter case, a yml at the commit that does not agree with its entry (its
     path, techniques, sourcetype or procedure label), a cache entry that cannot be
     read or written, a rule that does not compile, or a run in which no dataset was
     read. With --enforce, an UNAVAILABLE dataset, LICENSE or syscall_64.tbl too.

Usage:
    python3 detections/check_external_records.py --lint      # offline: the two files
    python3 detections/check_external_records.py             # shadow, as CI runs it
    python3 detections/check_external_records.py --enforce
    python3 detections/check_external_records.py --offline --cache DIR --rule PATH
    python3 detections/check_external_records.py --suggest   # draft declarations
    python3 detections/check_external_records.py --draft DATA_PATH YML_PATH
"""

import argparse
import glob
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import external_records as xr  # noqa: E402
import sigma_eval  # noqa: E402  (checks detections/sigma/ before pySigma loads)
import yaml  # noqa: E402

SIGMA = os.path.join(HERE, "sigma")
DEFECTS = os.path.join(HERE, "RULE_DEFECTS.md")
EXPECT = ("quiet", "n/a", "known-miss", "fire")
PREFIXES = {"quiet": ("quiet:",), "n/a": ("another procedure:", "not in the capture:"),
            "fire": ("same procedure:",)}
DEFECT_WHY = re.compile(r"rule defect, tracked in detections/RULE_DEFECTS\.md ([A-Z]\d+):")
DECLARATION_KEYS = {"rule", "dataset", "expect", "why", "rule_digest", "sha256"}
RULE_KEY = re.compile(r"T\d{4}(?:\.\d{3})?/[^./][^/]*\.yml")
FORMAT_PRODUCT = {"cloudtrail-json": "aws", "azure-monitor-json": "azure",
                  "k8s-audit-json": "kubernetes", "auditd-raw": "linux"}
TITLE = "external-records"


# ---- rules -------------------------------------------------------------------------

class Rule:
    """A rule file: its folder technique, log source and tags. The query and the
    item model are compiled when a pair needs them."""

    def __init__(self, path):
        self.path = path
        self.key = os.path.relpath(path, SIGMA).replace(os.sep, "/")
        self.folder = self.key.split("/", 1)[0]
        with open(path, encoding="utf-8") as fh:
            docs = [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]
        self.correlation = any("correlation" in d for d in docs)
        ls = next((d["logsource"] for d in docs if isinstance(d.get("logsource"), dict)), {})
        self.product = ls.get("product")
        self.logsource = (ls.get("product"), ls.get("service") or ls.get("category"))
        tags = {str(t) for d in docs for t in (d.get("tags") or [])}
        self.techniques = {t[len("attack."):].upper() for t in tags
                           if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)}
        self.cves = {"CVE-" + t[len("cve."):] for t in tags
                     if re.fullmatch(r"cve\.\d{4}-\d{4,}", t)}
        self._sql = self._model = None

    @property
    def source_name(self):
        return "/".join(str(p) for p in self.logsource)

    def sql(self):
        if self._sql is None:
            self._sql = sigma_eval.compile_rule(self.path)
        return self._sql

    def model(self):
        if self._model is None:
            import sigma_explain
            self._model = sigma_explain.load(self.path)
        return self._model


def rule_paths():
    """Every rule file, as the other gates glob them."""
    return sorted(glob.glob(os.path.join(SIGMA, "*", "*.yml")))


def tracked_defects():
    """The IDs of the Summary table of detections/RULE_DEFECTS.md."""
    try:
        with open(DEFECTS, encoding="utf-8") as fh:
            return set(re.findall(r"^\| \[([A-Z]\d+)\]\(", fh.read(), re.M))
    except OSError:
        return set()


def detection_digest(path):
    """What a declaration approves: the digest that the waivers of
    check_sufficiency.py use (one definition)."""
    import check_sufficiency
    return check_sufficiency.detection_digest(path)


# ---- declarations ------------------------------------------------------------------

def parse_declarations(doc, datasets, rule_keys):
    """(declarations by (rule, dataset), structural problems)."""
    if not (isinstance(doc, dict) and set(doc) == {"schema", "declarations"}
            and doc.get("schema") == 1 and isinstance(doc.get("declarations"), list)):
        return {}, ["expectations.json: wants {\"schema\": 1, \"declarations\": [...]}"]
    out, problems, seen = {}, [], set()
    for n, d in enumerate(doc["declarations"], 1):
        where = f"expectations.json declarations[{n}]"
        if not isinstance(d, dict) or set(d) != DECLARATION_KEYS:
            problems.append(f"{where}: wants exactly the keys {sorted(DECLARATION_KEYS)}")
            continue
        rule, dataset, expect, why = d["rule"], d["dataset"], d["expect"], d["why"]
        where = f"expectations.json: the declaration for {rule!r} on {dataset!r}"
        if not (isinstance(rule, str) and isinstance(dataset, str)):
            problems.append(f"{where}: the rule and the dataset must be text")
            continue
        before = len(problems)
        if not (RULE_KEY.fullmatch(rule) and rule in rule_keys):
            problems.append(f"{where}: names the rule {rule!r}, which does not exist "
                            "(a path under detections/sigma/, T<id>/<stem>.yml)")
        if dataset not in datasets:
            problems.append(f"{where}: names the dataset {dataset!r}, which SOURCES.json "
                            "does not list")
        if not (isinstance(expect, str) and expect in EXPECT):
            problems.append(f"{where}: expect {expect!r} is not one of {EXPECT}")
        if not (isinstance(why, str) and why.strip()):
            problems.append(f"{where}: gives no why")
        elif why.strip().upper().startswith("TODO"):
            problems.append(f"{where}: the why starts with TODO: a human writes the reason")
        elif expect == "known-miss":
            if not DEFECT_WHY.match(why):
                problems.append(f"{where}: a known-miss why starts 'rule defect, tracked in "
                                "detections/RULE_DEFECTS.md <ID>:'")
        elif expect in PREFIXES and not (why.startswith(PREFIXES[expect])
                                         and why.strip() not in PREFIXES[expect]):
            problems.append(f"{where}: a {expect} why starts "
                            + " or ".join(repr(p) for p in PREFIXES[expect])
                            + " and says more")
        for key in ("rule_digest", "sha256"):
            if not (isinstance(d[key], str) and xr.SHA256.fullmatch(d[key])):
                problems.append(f"{where}: {key} is not 64 lower-case hex digits")
        if (rule, dataset) in seen:
            problems.append(f"{where}: the pair is declared twice")
        seen.add((rule, dataset))
        if len(problems) == before:         # only a sound declaration takes part
            out[(rule, dataset)] = d
    return out, problems


def stale_reasons(d, rule_path, pinned_sha, tracked):
    """Why a declaration no longer applies (it stops excusing the pair)."""
    reasons = []
    now = detection_digest(rule_path)
    if d["rule_digest"] != now:
        reasons.append(f"the rule now digests to {now} (declared {d['rule_digest']}); a "
                       "human approves the rule again")
    if d["sha256"] != pinned_sha:
        reasons.append(f"SOURCES.json now pins {pinned_sha} (declared {d['sha256']})")
    m = DEFECT_WHY.match(d["why"]) if d["expect"] == "known-miss" else None
    if m and m.group(1) not in tracked:
        reasons.append(f"it cites {m.group(1)}, which the Summary table of "
                       "detections/RULE_DEFECTS.md does not list")
    return reasons


def relation(rule, ds):
    """'same', 'other-procedure', 'related' or None, by technique (not by records)."""
    if rule.folder in ds["techniques"]:
        proc = ds.get("procedure")
        if proc and not rule.cves & set(proc["cves"]):
            return "other-procedure"
        return "same"
    if rule.techniques & set(ds["techniques"]):
        return "related"
    return None


def redundant(d, rel):
    """Why a declaration changes nothing for its pair, or None."""
    if rel is None and d["expect"] != "fire":
        return ("the rule and the dataset have no technique in common, so the gate does not "
                f"run the rule on the dataset and a {d['expect']} declaration changes nothing")
    if d["expect"] == "fire" and rel == "same":
        return "the pair is same technique and procedure, so the rule must fire already"
    if d["expect"] in ("n/a", "known-miss") and rel != "same":
        return (f"the pair is {rel or 'not related'}, not an expected pair, so a "
                f"{d['expect']} declaration changes nothing")
    return None


# ---- the report --------------------------------------------------------------------

class Report:
    def __init__(self, args):
        self.args = args
        self.rows = []          # (kind, text) for the summary and the console
        self.errors = []
        self.warnings = []
        self.datasets, self.pairs, self.excluded, self.unavailable = [], [], [], []
        self.drafts = []
        self.failing = 0        # verdicts that fail --enforce

    def row(self, kind, text, fails=False):
        self.rows.append((kind, text))
        self.failing += bool(fails)
        print(text, flush=True)

    def error(self, text):
        for line in str(text).split("\n"):
            self.errors.append(line)
            print(f"ERROR {line}", flush=True)

    def warn(self, text):
        self.warnings.append(text)
        print(f"::warning title={TITLE}::{text}", flush=True)

    def note(self, text):
        print(text, flush=True)

    def write(self, summary, meta, code):
        args = self.args
        if args.markdown:
            mode = "enforce" if args.enforce else "shadow"
            body = "\n".join(t for _, t in self.rows
                             + [("error", "ERROR " + e) for e in self.errors]).replace("```", "'''")
            with open(args.markdown, "a", encoding="utf-8") as fh:
                fh.write(f"## External records ({xr.REPOSITORY}, {mode})\n\n"
                         f"{summary.replace('|', '/')}\n\n"
                         "Rows hold dataset ids, sha256 values, counts and the names of rule "
                         "items, never a value of a record.\n\n"
                         f"<details><summary>{len(self.rows)} row(s)</summary>\n\n"
                         f"```text\n{body}\n```\n\n</details>\n\n")
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump({"schema": 1, **meta, "mode": "enforce" if args.enforce else "shadow",
                           "datasets": self.datasets, "pairs": self.pairs,
                           "excluded": self.excluded, "unavailable": self.unavailable,
                           "errors": self.errors, "summary": summary, "exit": code},
                          fh, indent=2, sort_keys=True)
                fh.write("\n")


def _records(n):
    return f"{n} record(s)"


def nearest(rule, events, wheres, table):
    """{where, grade, items} of the record (or, for a correlation, the set) that
    came nearest to firing the rule. Item names only, no value."""
    import sigma_explain
    model = rule.model()
    if model.is_correlation:
        v = model.verdict_set(events, table)
        bases = {ref: len({i for hit in table.hit_indices(base.sql) for i in hit})
                 for ref, base in model.bases.items()}
        return {"where": "the record set", "grade": v.kind, "flips": list(v.atoms),
                "bases": bases}
    rows, fired = model.truth_table(table)
    (i, v), = sigma_explain._nearest_plain(model, events, rows, fired, k=1)
    out = {"where": wheres[i], "grade": v.kind, "flips": [] if v.fired else list(v.atoms)}
    if not out["flips"]:
        out["fails"] = [a for a in model.positive_atoms() if not rows[i][a]]
        out["filters"] = [a for a in model.negated_atoms() if rows[i][a]]
    return out


def _first(items, k=4):
    """The first k names of a list, and how many more there are."""
    return ", ".join(items[:k]) + (f" (+{len(items) - k} more)" if len(items) > k else "")


def nearest_text(n):
    if n["where"] == "the record set":
        bases = ", ".join(f"{ref} {k}" for ref, k in n["bases"].items())
        flips = f"; one repair would fire it: {', '.join(n['flips'])}" if n["flips"] else ""
        return f"the record set ({n['grade']}{flips}); records that each base matches: {bases}"
    if n["flips"]:
        return f"nearest {n['where']} ({n['grade']}; one flip would fire it: " \
               f"{', '.join(n['flips'])})"
    bits = [n["grade"]]
    if n.get("fails"):
        bits.append("fails: " + _first(n["fails"]))
    if n.get("filters"):
        bits.append("filter holds: " + _first(n["filters"]))
    return f"nearest {n['where']} ({'; '.join(bits)})"


def hit_text(rule, hits, wheres, total):
    """The count of a hit: records, or for a correlation alerts and evidence."""
    if rule.correlation:
        evidence = sorted({i for hit in hits for i in hit})
        return (f"{len(hits)} alert(s), {len(evidence)} distinct evidence record(s) of "
                f"{_records(total)}"), len(evidence)
    first = ", ".join(wheres[hit[0]] for hit in hits[:5]) + (", ..." if len(hits) > 5 else "")
    return f"{len(hits)}/{_records(total)}" + (f" ({first})" if hits else ""), len(hits)


# ---- the run -----------------------------------------------------------------------

def load_inputs(report):
    """SOURCES.json, the syscall table and expectations.json, or None (errors)."""
    try:
        sources = xr.load_sources()
    except xr.Fault as e:
        report.error(e)
        return None
    try:
        table_doc, syscalls = xr.load_syscalls()
    except xr.Fault as e:
        report.error(e)
        return None
    try:
        expectations = xr.load_json(xr.EXPECTATIONS, "expectations.json")
    except xr.Fault as e:
        report.error(e)
        return None
    return sources, table_doc, syscalls, expectations


def check_declarations(report, sources, expectations, all_rules):
    by_id = {d["id"]: d for d in sources["datasets"]}
    decls, problems = parse_declarations(expectations, by_id, set(all_rules))
    for p in problems:
        report.error(p)
    tracked = tracked_defects()
    stale = {}
    for (rule, dataset), d in sorted(decls.items()):
        reasons = stale_reasons(d, all_rules[rule].path, by_id[dataset]["sha256"], tracked)
        why = redundant(d, relation(all_rules[rule], by_id[dataset]))
        if why:
            reasons.append(why)
        if reasons:
            stale[(rule, dataset)] = reasons
            report.row("stale", f"STALE     {rule} on {dataset}: the {d['expect']} declaration "
                       f"no longer applies: {'; '.join(reasons)}", fails=True)
    return decls, stale


# The two files that an online run compares with their origins (no dataset).
ORIGINS = ("LICENSE", "syscall_64.tbl")


def origin_unavailable(report, name, e, of=""):
    """An origin file that could not be compared: a row and a ::warning; --enforce
    fails the run (exit 2), as for a dataset."""
    report.row("unavailable", f"UNAVAILABLE {name}: {e}")
    report.warn(f"UNAVAILABLE {name}{of}: {e}")
    report.unavailable.append({"dataset": name, "why": str(e)})


def verify_origins(report, sources, table_doc, cache):
    """Online only: the LICENSE and the kernel's syscall table at their origins."""
    url = xr.meta_url(sources["commit"], sources["licence_file"])
    try:
        _, origin, bad = xr.obtain(cache, sources["licence_sha256"], None, url, False,
                                   "LICENSE")
        if bad:
            report.error(bad)
        report.note(f"SOURCE    LICENSE of {xr.REPOSITORY} at the commit: sha256 "
                    f"{sources['licence_sha256'][:12]} ok ({origin})")
    except xr.Unavailable as e:
        origin_unavailable(report, ORIGINS[0], e)
    except xr.Fault as e:
        report.error(e)
    src = table_doc["source"]
    try:
        data, origin, bad = xr.obtain(cache, src["sha256"], src["size"],
                                      xr.syscall_table_url(src), False, "syscall_64.tbl")
        if bad:
            report.error(bad)
        derived = xr.derive_syscalls(data.decode("utf-8"), src["abis"])
        if derived != table_doc["syscalls"]:
            report.error("syscalls_x86_64.json is not the table that syscall_64.tbl of Linux "
                         f"{src['tag']} gives ({len(derived)} rows there, "
                         f"{len(table_doc['syscalls'])} here)")
        else:
            report.note(f"SOURCE    syscall_64.tbl of Linux {src['tag']}: sha256 "
                        f"{src['sha256'][:12]} ok ({origin}); {len(derived)} syscall(s) agree")
    except xr.Unavailable as e:
        origin_unavailable(report, ORIGINS[1], e, f" of Linux {src['tag']}")
    except (xr.Fault, UnicodeDecodeError) as e:
        report.error(e)


def read_one(report, ds, commit, cache, offline, syscalls):
    """The routed records of one dataset, or None (UNAVAILABLE or a fault)."""
    try:
        yml, _, bad = xr.obtain(cache, ds["yml_sha256"], None, xr.meta_url(commit, ds["yml"]),
                                offline, f"{ds['id']} (yml {ds['yml']})")
        if bad:
            report.error(bad)
        problems = xr.check_yml(ds, yml)
        if problems:
            for p in problems:
                report.error(p)
            return None
        data, origin, bad = xr.obtain(cache, ds["sha256"], ds["size"],
                                      xr.data_url(commit, ds["path"]), offline, ds["id"])
        if bad:
            report.error(bad)
    except xr.Unavailable as e:
        report.row("unavailable", f"UNAVAILABLE {ds['id']}: {e}")
        report.warn(f"UNAVAILABLE {ds['id']}: {e}")
        report.unavailable.append({"dataset": ds["id"], "why": str(e)})
        return None
    except xr.Fault as e:
        report.error(e)
        return None
    try:
        records, other = xr.read_dataset(ds, data, syscalls)
    except xr.Fault as e:
        report.error(e)
        return None
    if len(records) != ds["records"]:
        report.error(f"{ds['id']}: the loader read {len(records)} record(s); SOURCES.json pins "
                     f"{ds['records']}. A loader that drops records, or a file that changed "
                     "shape, is a fault, not a miss")
        return None
    routed = {}
    for r in records:
        if r.logsource:
            routed.setdefault(r.logsource, []).append(r)
    parts = ", ".join(f"{'/'.join(ls)} {len(rs)}" for ls, rs in sorted(routed.items()))
    unrouted = sum(1 for r in records if not r.logsource)
    detail = parts + (f", other {unrouted}" if unrouted else "") \
        + (f"; {other} record(s) of other types" if other else "")
    report.row("dataset", f"DATASET   {ds['id']}  {ds['format']}  {_records(len(records))}: "
               f"{detail or 'none of a log source of the rules'}  sha256 {ds['sha256'][:12]} "
               f"ok ({origin})")
    report.datasets.append({"id": ds["id"], "sha256": ds["sha256"], "size": ds["size"],
                            "format": ds["format"], "records": len(records), "other": other,
                            "routed": {"/".join(ls): len(rs) for ls, rs in routed.items()},
                            "origin": origin})
    return routed


def evaluate(report, ds, routed, rules, decls, stale, tables):
    product = FORMAT_PRODUCT[ds["format"]]
    for rule in rules:
        rel = relation(rule, ds)
        d = decls.get((rule.key, ds["id"]))
        if d and (rule.key, ds["id"]) in stale:
            d = None                                    # a stale declaration excuses nothing
        if rel is None and not (d and d["expect"] == "fire"):
            continue
        records = routed.get(rule.logsource, [])
        tag = {"same": f"same technique {rule.folder}",
               "other-procedure": f"same technique {rule.folder}",
               "related": "tag " + ", ".join(sorted(rule.techniques & set(ds["techniques"]))),
               None: "declared fire"}[rel]
        base = {"rule": rule.key, "dataset": ds["id"], "relation": rel or "declared",
                "declared": d["expect"] if d else None,
                "stale": (rule.key, ds["id"]) in stale}
        if not records:
            if rel in ("same", "other-procedure") and rule.product == product:
                present = ", ".join(sorted("/".join(ls) for ls in routed)) or "none"
                report.row("not-read", f"NOT READ  {rule.key} on {ds['id']}: no "
                           f"{rule.source_name} record (the dataset holds: {present})")
                report.pairs.append({**base, "verdict": "not read", "records": 0})
            if d:
                report.row("stale", f"STALE     {rule.key} on {ds['id']}: the {d['expect']} "
                           f"declaration applies to nothing: the dataset holds no "
                           f"{rule.source_name} record", fails=True)
            continue
        key = (ds["id"], rule.logsource)
        if key not in tables:
            try:
                tables[key] = sigma_eval.EventTable([r.event for r in records])
            except Exception as e:      # noqa: BLE001 (a backstop: read_dataset refuses first)
                tables[key] = None
                report.error(f"{ds['id']}: the {rule.source_name} records cannot go into one "
                             f"table ({type(e).__name__}); the loader must refuse such a "
                             "record by its line (a fault of the gate)")
        table = tables[key]
        if table is None:
            continue
        events, wheres = [r.event for r in records], [r.where for r in records]
        try:
            hits = table.hit_indices(rule.sql())
        except Exception as e:      # noqa: BLE001 (a rule that does not compile or run)
            report.error(f"{rule.key}: the rule does not compile or run "
                         f"({type(e).__name__}: {e})")
            continue
        counted, n_hits = hit_text(rule, hits, wheres, len(records))
        entry = {**base, "records": len(records), "hits": n_hits, "alerts": len(hits),
                 "evidence": sorted({wheres[i] for hit in hits for i in hit})}
        expected = rel == "same" or (d is not None and d["expect"] == "fire")
        if d and d["expect"] == "quiet":
            verdict = "declared quiet, fired" if hits else "quiet"
        elif d and d["expect"] == "n/a":
            verdict = "stale n/a" if hits else "n/a"
        elif d and d["expect"] == "known-miss":
            verdict = "known-miss fires" if hits else "known-miss"
        elif expected:
            verdict = "fire" if hits else "miss"
        else:
            verdict = rel
        entry["verdict"] = verdict
        why = f": {d['why']}" if d else ""
        if verdict == "fire":
            note = tag if rel in ("same", None) else f"{tag}; declared fire"
            report.row("fire", f"FIRE      {rule.key} on {ds['id']}  {counted}  [{note}]")
        elif verdict == "miss":
            try:
                near = nearest(rule, events, wheres, table)
            except Exception as e:      # noqa: BLE001 (an explanation never changes a verdict)
                near = {"where": "the records", "grade": f"not graded ({type(e).__name__})",
                        "flips": []}
            entry["nearest"] = near
            declared = "declared fire" if d else "no declaration"
            report.row("miss", f"MISS      {rule.key} on {ds['id']}  0 of {_records(len(records))}; "
                       f"{nearest_text(near)}  [{tag}; {declared}]", fails=True)
            if report.args.explain:
                import sigma_explain
                for line in sigma_explain.explain_miss(rule.model(), events):
                    print("    " + line)
            if report.args.suggest and not d:
                report.drafts.append(draft(rule, ds, near, len(records)))
        elif verdict == "quiet":
            report.row("quiet", f"QUIET     {rule.key} on {ds['id']}  0 of "
                       f"{_records(len(records))}{why}")
        elif verdict == "n/a":
            report.row("n/a", f"N/A       {rule.key} on {ds['id']}  0 of "
                       f"{_records(len(records))}{why}")
        elif verdict == "known-miss":
            report.row("known-miss", f"KNOWN-MISS {DEFECT_WHY.match(d['why']).group(1)} "
                       f"{rule.key} on {ds['id']}  0 of {_records(len(records))}{why}")
        elif verdict == "declared quiet, fired":
            report.row("fails", f"DECLARED QUIET, FIRED {rule.key} on {ds['id']}  {counted}: "
                       "the declaration says the rule must not fire on it", fails=True)
        elif verdict == "stale n/a":
            report.row("fails", f"STALE N/A {rule.key} on {ds['id']}  {counted}: the rule "
                       "fires, so the pair applies; remove the n/a declaration", fails=True)
        elif verdict == "known-miss fires":
            defect = DEFECT_WHY.match(d["why"]).group(1)
            report.row("fails", f"KNOWN-MISS FIRES {rule.key} on {ds['id']}  {counted}: close "
                       f"{defect} in detections/RULE_DEFECTS.md and remove the declaration",
                       fails=True)
        elif verdict == "related":
            report.row("related", f"RELATED   {rule.key} on {ds['id']}  {counted}  [{tag}; not "
                       "expected]")
        elif verdict == "other-procedure":
            proc = ds["procedure"]
            label = proc["label"] if proc["cves"] == [proc["label"]] else \
                f"{proc['label']} ({', '.join(proc['cves'])})"
            cves = ", ".join(sorted(rule.cves)) or "none"
            report.row("other-procedure", f"OTHER-PROCEDURE {rule.key} on {ds['id']}  {counted}  "
                       f"[{tag}; the dataset is {label}, the CVE tags of the rule: {cves}; "
                       "not expected]")
        report.pairs.append(entry)


def draft(rule, ds, near, total):
    facts = f"0 of {total} record(s); {nearest_text(near)}"
    return {"rule": rule.key, "dataset": ds["id"], "expect": "TODO",
            "why": f"TODO: {facts}", "rule_digest": detection_digest(rule.path),
            "sha256": ds["sha256"]}


def excluded_rows(report, sources, rules):
    for e in sorted(sources["excluded"], key=lambda e: e["id"]):
        for rule in rules:
            if rule.folder in e["techniques"] and rule.product == e["product"]:
                report.row("excluded", f"EXCLUDED  {rule.key} on {e['id']}: {e['why']}")
                report.excluded.append({"rule": rule.key, "dataset": e["id"], "why": e["why"]})


def summarise(report, rules, args):
    pairs = report.pairs
    count = lambda *v: sum(1 for p in pairs if p["verdict"] in v)    # noqa: E731
    expected = [p for p in pairs if p["relation"] == "same" or p["declared"] == "fire"]
    expected = [p for p in expected if p["verdict"] != "not read"]
    with_data = sorted({p["rule"] for p in expected})
    declared = count("quiet", "n/a", "known-miss")
    report.without = sorted(r.key for r in rules if r.key not in with_data)
    summary = (f"Summary: {len(with_data)} of {len(rules)} rule(s) have a same-technique "
               f"dataset of their log source; {len(expected)} expected pair(s): "
               f"{count('fire')} fire, "
               f"{count('miss')} miss, {declared} declared; {count('related')} related, "
               f"{count('other-procedure')} other procedure, {count('not read')} not read, "
               f"{len(report.excluded)} excluded; {len(report.datasets)} dataset(s) read, "
               f"{len(dataset_unavailable(report))} unavailable; ")
    summary += (f"enforce: {report.failing} verdict(s) fail" if args.enforce else
                f"shadow: {report.failing} verdict(s) would fail --enforce")
    return summary


def dataset_unavailable(report):
    return [u for u in report.unavailable if u["dataset"] not in ORIGINS]


def run(args):
    report = Report(args)
    inputs = load_inputs(report)
    if inputs is None:
        report.write("Summary: the inputs are not sound (see the errors)", {}, 2)
        print("Summary: the inputs are not sound (see the errors above)")
        return 2
    sources, table_doc, syscalls, expectations = inputs
    meta = {"repository": xr.REPOSITORY, "commit": sources["commit"],
            "licence": sources["licence"]}
    all_rules = {}
    for path in rule_paths():
        r = Rule(path)
        all_rules[r.key] = r
    if args.rule:
        chosen = []
        for path in args.rule:
            key = os.path.relpath(os.path.abspath(path), SIGMA).replace(os.sep, "/")
            if key not in all_rules:
                report.error(f"--rule {path!r} is not a rule file under detections/sigma/")
                continue
            chosen.append(all_rules[key])
    else:
        chosen = list(all_rules.values())
    decls, stale = check_declarations(report, sources, expectations, all_rules)
    n_datasets, n_excluded = len(sources["datasets"]), len(sources["excluded"])
    if args.lint:
        line = (f"SOURCES.json: {n_datasets} dataset(s) and {n_excluded} excluded at "
                f"{sources['commit'][:12]}; licence {sources['licence']} (copy "
                f"{sources['licence_copy']} sha256 ok); syscalls_x86_64.json: "
                f"{len(syscalls)} syscall(s) of Linux {table_doc['source']['tag']}; "
                f"expectations.json: {len(decls)} declaration(s); {len(stale)} stale")
        print(line)
        report.write(line, meta, 2 if report.errors else (1 if args.enforce and stale else 0))
        if report.errors:
            return 2
        return 1 if args.enforce and stale else 0
    cache = xr.Cache(args.cache)
    if args.offline:
        report.note("offline: the LICENSE and the syscall table are not compared with their "
                    "origins; only files in the cache are read")
    else:
        verify_origins(report, sources, table_doc, cache)
    tables, read = {}, 0
    chosen.sort(key=lambda r: r.key)
    for ds in sorted(sources["datasets"], key=lambda d: d["id"]):
        routed = read_one(report, ds, sources["commit"], cache, args.offline, syscalls)
        if routed is None:
            continue
        read += 1
        evaluate(report, ds, routed, chosen, decls, stale, tables)
    excluded_rows(report, sources, chosen)
    if not read and not report.errors:
        report.error("no dataset was read, so the run checked nothing (every dataset is "
                     "UNAVAILABLE)")
    if args.suggest:
        print(f"Draft declarations (--suggest): {len(report.drafts)}. Each why starts with "
              "TODO, so the gate refuses it until a human writes the reason and the verdict:")
        for d in report.drafts:
            print(json.dumps(d, sort_keys=True))
    summary = summarise(report, chosen, args)
    meta["rules_without_dataset"] = report.without
    ds_unavailable = dataset_unavailable(report)
    origins = [u["dataset"] for u in report.unavailable if u["dataset"] in ORIGINS]
    if report.errors:
        code = 2
    elif args.enforce and (ds_unavailable or origins):
        code = 2
        if ds_unavailable:
            report.error(f"--enforce: {len(ds_unavailable)} dataset(s) UNAVAILABLE")
        if origins:
            report.error(f"--enforce: {' and '.join(origins)} UNAVAILABLE: not compared with "
                         "the origin")
    elif args.enforce and report.failing:
        code = 1
    else:
        code = 0
    report.write(summary, meta, code)
    print(summary)
    return code


def run_draft(args):
    """Print a draft entry of SOURCES.json for each DATA_PATH YML_PATH pair."""
    try:
        _, syscalls = xr.load_syscalls()
        commit = args.commit or xr.load_sources()["commit"]
    except xr.Fault as e:
        print(f"ERROR {e}")
        return 2
    if not xr.COMMIT.fullmatch(commit):
        print(f"ERROR --commit {commit!r} is not a full commit SHA")
        return 2
    cache, code = xr.Cache(args.cache), 0
    for path, yml in args.draft:
        try:
            if xr.dataset_id(path) is None or not yml.endswith(".yml"):
                raise xr.Fault(f"{path!r}: not datasets/attack_techniques/<T>/<dir>/<file> "
                               "with a .yml")
            pointer = xr.parse_pointer(xr.fetch(xr.meta_url(commit, path), 1024))
            if pointer is None:
                raise xr.Fault(f"{path}: the raw origin gives no Git LFS pointer, so the "
                               "media origin does not serve the file")
            sha, size = pointer
            data, _, _ = xr.obtain(cache, sha, size, xr.data_url(commit, path), False, path)
            ymlb = xr.fetch(xr.meta_url(commit, yml), xr.MAX_BYTES)
            techniques, sourcetype, named, _ = xr.yml_facts(ymlb.decode("utf-8"), path)
        except (xr.Fault, xr.Unavailable, ValueError, UnicodeDecodeError) as e:
            print(f"ERROR {e}")
            code = 2
            continue
        fmt, records, other = xr.sniff(xr.dataset_id(path), data, syscalls)
        st = sourcetype[0] if len(sourcetype) == 1 else sourcetype
        common = {"id": xr.dataset_id(path), "path": path, "sha256": sha, "size": size,
                  "techniques": [str(t) for t in techniques]}
        if not named:
            print(f"NOTE {path}: the yml {yml} does not name this path")
        if fmt:
            entry = {**common, "records": len(records), "format": fmt, "sourcetype": st,
                     "yml": yml, "yml_sha256": hashlib.sha256(ymlb).hexdigest()}
        else:
            entry = {**common, "product": "TODO",
                     "why": "TODO: " + " | ".join(records)[:400]}
        print(json.dumps(entry, sort_keys=True))
    return code


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Run each rule on the pinned splunk/attack_data datasets of its "
                    "technique (shadow by default).")
    ap.add_argument("--lint", action="store_true",
                    help="offline: check SOURCES.json, expectations.json and the syscall "
                         "table only")
    ap.add_argument("--enforce", action="store_true",
                    help="exit 1 on a miss without a declaration, a stale declaration or a "
                         "declaration that a hit contradicts; exit 2 on an unavailable "
                         "dataset, LICENSE or syscall table")
    ap.add_argument("--offline", action="store_true",
                    help="read only the cache; a dataset that it does not hold is UNAVAILABLE")
    ap.add_argument("--cache", metavar="DIR", default=xr.DEFAULT_CACHE,
                    help="the content-addressed cache (default: %(default)s)")
    ap.add_argument("--rule", action="append", default=[], metavar="PATH",
                    help="run only this rule (repeatable)")
    ap.add_argument("--markdown", metavar="PATH", help="append a summary (e.g. "
                    "$GITHUB_STEP_SUMMARY): ids, sha256 values, counts and item names only")
    ap.add_argument("--json", metavar="PATH", help="write the report as JSON (no record value)")
    ap.add_argument("--suggest", action="store_true",
                    help="print a draft declaration for each MISS (why: TODO, refused until "
                         "a human writes it); writes no file")
    ap.add_argument("--explain", action="store_true",
                    help="print under each MISS the item-by-item explanation of "
                         "sigma_explain.py (console only: it holds values, with repr())")
    ap.add_argument("--draft", nargs=2, action="append", metavar=("DATA_PATH", "YML_PATH"),
                    help="print a draft SOURCES.json entry for a file of splunk/attack_data "
                         "(network; it writes only to the cache, no file of the repository)")
    ap.add_argument("--commit", help="with --draft: the commit (default: the pinned one)")
    args = ap.parse_args(argv)
    if args.draft:
        return run_draft(args)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
