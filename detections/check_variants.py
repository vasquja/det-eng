#!/usr/bin/env python3
"""
The representation gate: every rule must give the same hits when the same records
are stored, or matched, in another way.

Every validator and gate runs a rule in one way: pySigma's SQLite backend on the
table that sigma_eval.flatten() builds. That fixes four things that a real store
or backend decides in its own way (detections/SEMANTICS.md): the JSON text of a
list, a list as one value, the letter case of LIKE, and the regex dialect. A rule
that holds only for the one way of the oracle passes every other gate.

This gate runs each rule again on the same records, once for each VARIANT, and
compares the hits with the default run:

  compact  event transformation. A list is JSON text without blanks
           (`[{"a":1,"b":2}]`), key order kept: sigma_eval.flatten(separators=(",", ":")).
           The default text has a blank after each `,` and `:`.
  sorted   event transformation. As compact, and the keys of each object are sorted
           (a store that does not keep the key order of an object).
  multi    separate matcher. A list is not text: the field has one value for each
           element (a scalar as it is, an object or a list as its default JSON
           text), and an item holds when it holds on one value. So two items on
           one list can hold on two different elements, and `not item` holds when
           no value matches. An empty list has no value. Each item runs alone with
           the real backend on each value, and the rule's own condition composes
           the results (as check_null_safety.py composes them). It does not cover
           a correlation rule on records with a list, or an item that negates
           inside itself (`|neq`) on a list, and it fails such a rule. A
           store that explodes a list into leaf fields or indexed keys is not this
           model: check_provider_mappings.py prints that mode as a warning for the
           Kubernetes audit rules.
  cs_like  oracle option. LIKE does not fold letter case, so |contains,
           |startswith, |endswith and a wildcard value are case-sensitive:
           sigma_eval.EventTable(case_sensitive_like=True).
  re2      separate matcher for `|re`. RE2's search in place of Python's re.search:
           sigma_eval.EventTable(regexp=...). It needs the module re2 (google-re2).
           Without the module the variant does NOT run, and the report says so;
           --require-re2 (as CI passes it) makes that an error.

The records are every case of the rule's sidecar and, for a cloud rule, the attack
and benign fixtures of its rows in validate_cloud_detections.MANIFEST (the event
sets of check_null_safety.py), each from its raw records, not from flattened ones.

A DIFFERENCE is an event set whose hits (the records that fire; for a correlation,
the alerts) are not the hits of the default run. It has one of two faults:

  loss  a record that fires by default does not fire. On a positive case or an
        attack fixture the rule misses the technique on that representation.
  gain  a record that is quiet by default fires. On a near-miss the item that the
        case breaks does not hold it; on a filtered case the filter does not
        apply; on a confounder, a benign case or a benign fixture it is a false
        positive. A positive case or an attack fixture can gain a hit too (a
        record of the set that is quiet by default).

A change of the verdict of the set (fires / quiet) and a change of hits inside a
set that still fires both count. Each difference names the items whose truth
changed on the records in question, and the value they read.

A negative case that stays quiet can still stop being a proof: a near-miss or a
filtered case declares the item that it breaks (`breaks`), and under a variant
another item can keep it quiet. Such a case is reported as WEAKENED (a note, and
in --json); it does not fail the run.

EXPECTED DIFFERENCES. detections/variants/expected.json lists each known
difference: the variant, the rule, the event set, the fault, the hits that are
lost and gained (each hit is the list of its record numbers in the event set), the
items whose truth changes, a reason, one sentence that says why the difference is
accepted (`why`) and, where one exists, the entry of detections/RULE_DEFECTS.md
that tracks it. An entry is a human approval, like a waiver of check_sufficiency.py:
propose it in the pull request (--propose prints the list that this run shows).
The run fails on
  - a difference that is not listed (new);
  - a listed difference whose fault, hits or items changed;
  - a listed entry that shows no difference (stale): delete it;
  - a reason that is not one of REASONS for that variant, or whose proof fails;
  - an entry without a `why`, or a second entry for one event set and variant;
  - a `defect` that is not an open entry of RULE_DEFECTS.md that names the rule;
  - an entry of a variant that did not run, with --require-re2.
--baseline-expected FILE only compares the list with the list of the base branch
(data; no rule runs): an entry that the base does not hold, or that differs from
it, fails. So without a human decision the list can only shrink. A base tree
without the file gives a notice and exit 0; a path with no base tree is an error.
The sufficiency-ratchet job runs it on a pull request. The code that reads the
list is the code of the head, so the comparison binds the list, not the gate
(docs/ROADMAP.md, item R8).

SAME INPUT. A variant that gives a rule the same input as an earlier run of the
same event set is not run again: its answer is the answer of that run. That holds
for `compact` and `sorted` when no record changes (no list), for `sorted` when its
records are those of `compact`, for `multi` when no record holds a list, for
`cs_like` when no query of the rule holds LIKE, and for `re2` when none holds
REGEXP. The self-test proves on the golden probes that this changes no answer.

Usage:
    python3 detections/check_variants.py                    # every rule (the gate)
    python3 detections/check_variants.py detections/sigma/T1537/aws_snapshot_or_ami_made_public.yml
    python3 detections/check_variants.py --require-re2      # as CI runs it
    python3 detections/check_variants.py --json out.json --markdown "$GITHUB_STEP_SUMMARY"
    python3 detections/check_variants.py --propose          # the expected list of this run
    python3 detections/check_variants.py --baseline-expected BASE/detections/variants/expected.json
    python3 detections/check_variants.py --probes           # the golden probes (SEMANTICS.md)
    python3 detections/check_variants.py --self-test        # probes and constructed rules

Exit 0 when no rule has a new difference and the expected list holds, 1 when a
rule fails or the list does not hold, 2 when a variant is not in force (also
--require-re2 without the module) or --baseline-expected names no base tree.
"""

import os
import sys

# Running this script puts detections/ first on sys.path. Import the standard
# library before it is there (as check_null_safety.py does).
_HERE = os.path.dirname(os.path.abspath(__file__))
if sys.path and os.path.abspath(sys.path[0] or os.curdir) == _HERE:
    del sys.path[0]

import argparse  # noqa: E402
import glob  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402

sys.path.insert(0, _HERE)
import sigma_eval  # noqa: E402  (checks detections/ before pySigma loads)
import sigma_explain  # noqa: E402
import rule_cases  # noqa: E402

REPO = os.path.dirname(_HERE)
SIGMA = os.path.join(REPO, "detections", "sigma")
EXPECTED = os.path.join(REPO, "detections", "variants", "expected.json")
DEFECTS = os.path.join(REPO, "detections", "RULE_DEFECTS.md")

VARIANTS = ("compact", "sorted", "multi", "cs_like", "re2")
HOW = {
    "compact": "event transformation: a list as JSON text without blanks",
    "sorted": "event transformation: a list as JSON text without blanks, keys sorted",
    "multi": "separate matcher: a list as one value for each element",
    "cs_like": "oracle option: LIKE does not fold letter case",
    "re2": "separate matcher for |re: RE2",
}


# ---- the RE2 matcher ---------------------------------------------------------


def re2_search():
    """search(pattern, text) with RE2, or (None, reason) when the module is missing."""
    try:
        import re2  # google-re2
    except ImportError:
        return None, "the module re2 (google-re2) is not installed"
    if not hasattr(re2, "Options"):
        return None, "the module re2 is not google-re2 (it has no Options)"
    compiled = {}

    def search(pattern, text):
        rx = compiled.get(pattern)
        if rx is None:
            options = re2.Options()
            options.log_errors = False
            # The backend writes |i, |m and |s as a (?i), (?m), (?s) prefix, which
            # RE2 reads itself.
            rx = compiled[pattern] = re2.compile(pattern, options)
        return rx.search(text) is not None

    return search, None


# ---- the multi-valued list model --------------------------------------------


def _scalar(value):
    return value if value is None or isinstance(value, (str, int, float)) else json.dumps(value)


def split_lists(obj, prefix=""):
    """One raw record -> (scalars, lists): the flat scalar fields, and for each list
    field the values of its elements (a scalar as it is, an object or a list as its
    default JSON text). An object recurses, as in sigma_eval.flatten()."""
    scalars, lists = {}, {}
    for key, val in obj.items():
        name = f"{prefix}{key}"
        if isinstance(val, dict):
            inner_scalars, inner_lists = split_lists(val, f"{name}.")
            scalars.update(inner_scalars)
            lists.update(inner_lists)
        elif isinstance(val, list):
            lists[name] = [_scalar(v) for v in val]
        else:
            scalars[name] = val
    return scalars, lists


def multi_truth(rule, raw_events):
    """Per record: {atom: bool} in the multi-valued model, for a plain rule.

    One table holds, for each record, a base row (its scalar fields; a list field is
    absent) and one row for each element of each list field (the scalar fields and
    that one value). An item on a list field holds when it holds on one of that
    field's rows; any other item is read on the base row."""
    rows, base, element = [], [], []
    for raw in raw_events:
        scalars, lists = split_lists(raw)
        base.append(len(rows))
        rows.append(scalars)
        ids = {}
        for name, values in lists.items():
            ids[name.lower()] = list(range(len(rows), len(rows) + len(values)))
            rows += [dict(scalars, **{name: v}) for v in values]
        element.append(ids)
    table = sigma_eval.EventTable(rows)
    out = [dict() for _ in raw_events]
    list_fields = {name for ids in element for name in ids}
    for atom in rule.items:
        field = (rule.item_field[atom] or "").lower()
        if field in list_fields and rule.item_negates(atom):
            raise ValueError(f"item {atom} negates inside itself (`|neq`) on a list: the "
                             "multi-valued model does not say if one value or every value "
                             "must differ")
        holds = {i for hit in table.hit_indices(rule.item_sql(atom)) for i in hit}
        for i in range(len(raw_events)):
            ids = element[i].get(field)
            out[i][atom] = any(r in holds for r in ids) if ids else base[i] in holds
    return out


def has_list(obj):
    if isinstance(obj, list):
        return True
    return isinstance(obj, dict) and any(has_list(v) for v in obj.values())


# ---- one event set under one variant -----------------------------------------


def _canon(hits):
    return sorted(sorted(h) for h in hits)


def sql_words(rule, sql):
    """Which of the operators that a variant changes (`like`, `regexp`) the queries
    of the rule hold: the compiled rule and each item alone (a correlation: also
    each base). A query without the operator gives the same answer under the
    variant. The search ignores letter case and also finds the word inside a value
    (then the variant runs, which is the safe side)."""
    parts = list(rule.bases.values()) if rule.is_correlation else [rule]
    texts = [sql] + [q for part in parts for q in (part.sql, *part.items.values())]
    return {word for word in ("like", "regexp")
            if any(re.search(rf"(?i)\b{word}\b", text) for text in texts)}


class Context:
    """The matchers of this run: which variants run, and why one does not.

    shortcuts=False runs each variant on its own table, also where its input is
    the input of an earlier run (see SAME INPUT in the module text). Only the
    self-test uses it, to prove that the shortcuts change no answer."""

    WORD = {"cs_like": "like", "re2": "regexp"}

    def __init__(self, variants=VARIANTS, shortcuts=True):
        self.search, self.re2_missing = re2_search()
        self.variants = [v for v in variants if v != "re2" or self.search]
        self.skipped = {"re2": self.re2_missing} if "re2" in variants and not self.search else {}
        self.shortcuts = shortcuts

    @staticmethod
    def records(variant, raw_events):
        """The flattened records of an event transformation (`compact`, `sorted`)."""
        if variant == "compact":
            return [sigma_eval.flatten(e, separators=(",", ":")) for e in raw_events]
        if variant == "sorted":
            return [sigma_eval.flatten(e, separators=(",", ":"), sort_keys=True)
                    for e in raw_events]
        raise ValueError(variant)

    def table(self, variant, flat):
        """The EventTable of a record or table variant (not `multi`). flat: the
        records of the variant for `compact` and `sorted`, else the default ones."""
        if variant in ("compact", "sorted"):
            return sigma_eval.EventTable(flat)
        if variant == "cs_like":
            return sigma_eval.EventTable(flat, case_sensitive_like=True)
        if variant == "re2":
            return sigma_eval.EventTable(flat, regexp=self.search)
        raise ValueError(variant)


class Run:
    """One rule on one event set: the default hits, and the hits of each variant."""

    def __init__(self, rule, sql, raw_events, ctx, words=None):
        self.rule, self.sql, self.raw, self.ctx = rule, sql, raw_events, ctx
        self.flat = [sigma_eval.flatten(e) for e in raw_events]
        self.table = sigma_eval.EventTable(self.flat)
        self.hits = _canon(self.table.hit_indices(sql))
        self.lists = any(has_list(e) for e in raw_events)
        self.words = sql_words(rule, sql) if words is None else words
        self._records = {}  # compact, sorted -> the flattened records
        self._input = {}    # variant -> the run that has the same input (None: default)
        self._tables = {}   # input -> EventTable
        self._hits = {}     # input -> hits
        self._truth = {}    # input -> per record {atom: bool}
        self._flips = {}    # input -> (grade, single flips) of the closest record

    def records(self, variant):
        if variant not in self._records:
            self._records[variant] = self.ctx.records(variant, self.raw)
        return self._records[variant]

    def input_of(self, variant):
        """The run whose input the variant has: None (the default run), an earlier
        variant, or the variant itself (its input is new). See SAME INPUT."""
        if variant is None or not self.ctx.shortcuts:
            return variant
        if variant not in self._input:
            same = variant
            if variant in ("compact", "sorted"):
                if self.records(variant) == self.flat:
                    same = None
                elif variant == "sorted" and self.records("sorted") == self.records("compact"):
                    same = "compact"
            elif variant == "multi":
                same = variant if self.lists else None
            elif self.ctx.WORD[variant] not in self.words:
                same = None
            self._input[variant] = same
        return self._input[variant]

    def variant_table(self, variant):
        key = self.input_of(variant)
        if key is None:
            return self.table
        if key not in self._tables:
            flat = self.records(key) if key in ("compact", "sorted") else self.flat
            self._tables[key] = self.ctx.table(key, flat)
        return self._tables[key]

    def truth(self, variant=None):
        """Per record {atom: bool}; a correlation: {"<base>/<atom>": bool} of its bases."""
        key = self.input_of(variant)
        if key not in self._truth:
            parts = self.rule.bases.items() if self.rule.is_correlation else [(None, self.rule)]
            rows = [dict() for _ in self.raw]
            for ref, part in parts:
                if key == "multi":
                    found = multi_truth(part, self.raw)
                else:
                    found, _ = part.truth_table(self.variant_table(key))
                for i, row in enumerate(found):
                    rows[i].update({(f"{ref}/{a}" if ref else a): v for a, v in row.items()})
            self._truth[key] = rows
        return self._truth[key]

    def variant_hits(self, variant):
        key = self.input_of(variant)
        if key is None:
            return self.hits                # the same input: the same hits
        if key not in self._hits:
            if key == "multi":
                if self.rule.is_correlation:
                    if self.lists:
                        raise ValueError("the multi-valued model does not cover a "
                                         "correlation rule on records with a list")
                    return self.hits        # no list in any record: the same records
                composed = [[i] for i, row in enumerate(self.truth()) if self.rule.evaluate(row)]
                if composed != self.hits:
                    raise ValueError("internal error: the items' default values, composed "
                                     f"through the condition, give hits {composed}; the "
                                     f"compiled rule gives {self.hits} (report it)")
                self._hits[key] = [[i] for i, row in enumerate(self.truth("multi"))
                                   if self.rule.evaluate(row)]
            else:
                self._hits[key] = _canon(self.variant_table(key).hit_indices(self.sql))
        return self._hits[key]

    def changed_items(self, variant, records):
        """[(record, atom, default truth, variant truth)] on the given records."""
        before, after = self.truth(), self.truth(variant)
        return [(i, atom, before[i][atom], after[i][atom])
                for i in records for atom in before[i] if before[i][atom] != after[i][atom]]

    def _item(self, atom):
        if self.rule.is_correlation:
            ref, _, name = atom.partition("/")
            return self.rule.bases[ref], name
        return self.rule, atom

    def item_field(self, atom):
        rule, name = self._item(atom)
        return rule.item_field[name]

    def item_test(self, atom):
        """How the backend tests the item: "like", "regexp" or "other"."""
        rule, name = self._item(atom)
        sql = rule.item_sql(name)
        return "regexp" if " REGEXP " in sql else "like" if " LIKE " in sql else "other"

    def reads_list(self, record, field):
        """Is the field a list in the raw record (not text that looks like one)?"""
        lists = split_lists(self.raw[record])[1]
        return (field or "").lower() in {name.lower() for name in lists}

    def value(self, record, field):
        """What the default run reads in the field (field names: any letter case)."""
        flat = self.flat[record]
        if field in flat:
            return flat[field]
        return next((v for k, v in flat.items() if k.lower() == (field or "").lower()), None)

    def _flips_of(self, key):
        """(grade, single flips) of the closest record, as rule_cases.py grades a
        negative case, on the table of one input (None: the default)."""
        if key not in self._flips:
            table = self.variant_table(key)
            verdicts = sigma_explain.judge_events(self.rule.stripped(), table.events, table)
            best = min(verdicts, key=lambda v: (sigma_explain.KIND_RANK[v.kind], -v.closeness))
            self._flips[key] = (best.kind, set(best.atoms))
        return self._flips[key]

    def weakened(self, variant, case):
        """A near-miss or a filtered case that stays quiet under the variant, while an
        item that it declares (`breaks`) is no longer a single flip that fires the
        rule there. Plain rules, record and table variants only. Returns the text, or
        None."""
        if (self.rule.is_correlation or variant == "multi" or self.hits
                or case.get("kind") not in ("near-miss", "filtered")):
            return None
        key = self.input_of(variant)
        if key is None:
            return None                     # the same input: the same grade
        breaks = case.get("breaks") or []
        declared = breaks if isinstance(breaks, list) else [breaks]
        kind0, atoms0 = self._flips_of(None)
        if kind0 not in sigma_explain.NON_TRIVIAL or not set(declared) <= atoms0:
            return None                     # rule_cases.py fails this case by default
        kind, atoms = self._flips_of(key)
        if kind in sigma_explain.NON_TRIVIAL and set(declared) <= atoms:
            return None
        return (f"quiet in both, but `breaks` {declared} is no longer one flip from a hit "
                f"(graded {kind}; single flips: {', '.join(sorted(atoms)) or 'none'})")


# ---- differences -------------------------------------------------------------


class Difference:
    def __init__(self, variant, rule, platform, source, name, kind, run, hits):
        self.variant, self.rule, self.platform = variant, rule, platform
        self.source, self.name, self.kind = source, name, kind
        self.default_hits, self.variant_hits = len(run.hits), len(hits)
        self.lost = [h for h in run.hits if h not in hits]
        self.gained = [h for h in hits if h not in run.hits]
        self.fault = "loss+gain" if self.lost and self.gained else "loss" if self.lost else "gain"
        records = sorted({i for h in self.lost + self.gained for i in h})
        self.changes = []
        try:
            for i, atom, before, after in run.changed_items(variant, records):
                field = run.item_field(atom)
                self.changes.append({"record": i, "item": atom, "default": before,
                                     "variant": after, "field": field,
                                     "test": run.item_test(atom),
                                     "list": run.reads_list(i, field),
                                     "value": sigma_explain._short(run.value(i, field), 160)})
        except Exception as e:  # noqa: BLE001 - the explanation must not hide the difference
            self.changes.append({"record": -1, "item": f"(cannot explain: {e})", "default": None,
                                 "variant": None, "field": None, "value": ""})
        self.items = sorted({c["item"] for c in self.changes})
        self.status, self.entry, self.note = "new", None, ""

    @property
    def key(self):
        return (self.variant, self.rule, self.source, self.name)

    def text(self):
        if self.default_hits and not self.variant_hits:
            verdict = f"fires by default, quiet as {self.variant}"
        elif self.variant_hits and not self.default_hits:
            verdict = f"quiet by default, fires as {self.variant}"
        else:
            verdict = (f"fires in both, but the hits differ as {self.variant} "
                       f"({self.default_hits} -> {self.variant_hits})")
        if self.fault == "loss":
            meaning = ("the rule misses the technique on that representation"
                       if self.kind in ("positive", "attack") else "a hit is lost")
        elif self.kind == "near-miss":
            meaning = "the item that the case breaks does not hold it there"
        elif self.kind == "filtered":
            meaning = "the filter does not apply there"
        elif self.kind in ("positive", "attack"):
            meaning = "a record that is quiet by default fires there"
        else:
            meaning = "a false positive there"
        return f"[{self.variant}] {self.fault}: {verdict}; {meaning}"

    def lines(self):
        out = []
        for c in self.changes:
            if c["record"] < 0:
                out.append(c["item"])
                continue
            out.append(f"record #{c['record']}: {c['item']}: "
                       f"{'yes' if c['default'] else 'no'} -> {'yes' if c['variant'] else 'no'}"
                       f"; {c['field']} = {c['value']}")
        return out

    def as_dict(self):
        return {"variant": self.variant, "rule": self.rule, "platform": self.platform,
                "source": self.source, "name": self.name, "kind": self.kind,
                "fault": self.fault, "default_hits": self.default_hits,
                "variant_hits": self.variant_hits, "lost": self.lost, "gained": self.gained,
                "items": self.items, "changes": self.changes, "status": self.status,
                "reason": (self.entry or {}).get("reason"),
                "defect": (self.entry or {}).get("defect"), "note": self.note}

    def proposal(self):
        return {"variant": self.variant, "rule": self.rule, "source": self.source,
                "name": self.name, "fault": self.fault, "lost": self.lost,
                "gained": self.gained, "items": self.items,
                "reason": (self.entry or {}).get("reason", "TODO"),
                **({"defect": self.entry["defect"]} if (self.entry or {}).get("defect") else {}),
                "why": (self.entry or {}).get("why", "TODO: one line, what the rule relies on")}


class Problem:
    """A row that fails the run and is not a difference (a rule that cannot be
    checked, a bad entry of the expected list)."""

    def __init__(self, rule, detail):
        self.rule, self.detail = rule, detail


# ---- one rule ----------------------------------------------------------------


def cloud_fixtures():
    """{abs rule path: [(source, name, kind, raw records)]} from the cloud MANIFEST."""
    import validate_cloud_detections as cloud
    out = {}
    for _trr, folder, fname, attack, benign, *_ in cloud.MANIFEST:
        path = os.path.abspath(os.path.join(cloud.SIGMA, folder, fname))
        for kind, rel in (("attack", attack), ("benign", benign)):
            records = cloud.load_records(os.path.join(cloud.FIX, rel))
            out.setdefault(path, []).append(("fixture", rel, kind, records, None))
    return out


def event_sets(rule_path, fixtures):
    """[(source, name, kind, raw events, case or None)]: sidecar cases, then fixtures."""
    sets, errors = [], []
    path = rule_cases.cases_path(rule_path)
    if os.path.exists(path):
        cases, errors = rule_cases.load_cases(path)
        sets += [("case", c["name"], c["kind"], c["events"], c) for c in cases]
    return sets + fixtures.get(os.path.abspath(rule_path), []), errors


def platform_of(rule):
    source = rule.logsource or {}
    return str(source.get("product") or source.get("category") or "unknown")


def check_rule(rule_path, fixtures, ctx, rule=None, sets=None):
    """(rel, sets checked, differences, problems, weakened notes) for one rule."""
    rel = os.path.relpath(rule_path, SIGMA)
    rule = rule or sigma_explain.load(rule_path)
    sql = rule.sql if sets is not None else sigma_eval.compile_rule(rule_path)
    errors = []
    if sets is None:
        sets, errors = event_sets(rule_path, fixtures)
    problems = [Problem(rel, f"sidecar error: {e}") for e in errors]
    if not sets:
        problems.append(Problem(rel, "no sidecar case and no cloud fixture: nothing shows "
                                     "what the rule does under a variant"))
    differences, weakened = [], []
    words = sql_words(rule, sql)
    for source, name, kind, raw, case in sets:
        run = Run(rule, sql, raw, ctx, words)
        for variant in ctx.variants:
            try:
                hits = run.variant_hits(variant)
            except Exception as e:  # noqa: BLE001 - one variant must not hide the others
                problems.append(Problem(rel, f"{source} {kind} {name}: [{variant}] cannot "
                                             f"check: {type(e).__name__}: {e}"))
                continue
            if hits != run.hits:
                differences.append(Difference(variant, rel, platform_of(rule), source, name,
                                              kind, run, hits))
            elif case is not None:
                why = run.weakened(variant, case)
                if why:
                    weakened.append({"variant": variant, "rule": rel, "source": source,
                                     "name": name, "kind": kind, "detail": why})
    return rel, len(sets), differences, problems, weakened


# ---- the expected list -------------------------------------------------------

# Each reason is one cause, for one variant, with a proof that this run makes. A new
# reason is a change to this script, which a human reviews.
REASONS = {
    "KEY_ORDER": ("sorted", "the item matches the JSON text of a list with a pattern that "
                            "needs the key order of the record; the difference shows with "
                            "sorted keys and not in the compact text"),
    "LIKE_CASE": ("cs_like", "the item is a LIKE test (|contains, |startswith, |endswith or a "
                             "wildcard value) that relies on Sigma's default of a match "
                             "without regard to letter case"),
    "LIST_TEXT": ("multi", "the item matches the JSON text of the whole list (its brackets, "
                           "the quotes of an element, or more than one element), or reads an "
                           "empty list, which has no value in a multi-valued field"),
}
ENTRY_KEYS = {"variant", "rule", "source", "name", "fault", "lost", "gained", "items",
              "reason", "why"}
_TEXT_KEYS = ("variant", "rule", "source", "name", "fault", "reason", "why")


def _is_hits(value):
    """A list of hits; each hit is a list of record numbers."""
    return isinstance(value, list) and all(
        isinstance(hit, list) and hit and all(type(i) is int for i in hit) for hit in value)


def _entry_fault(entry):
    """What is wrong with the form of one entry, or None."""
    if not isinstance(entry, dict) or not ENTRY_KEYS <= set(entry) \
            or set(entry) - ENTRY_KEYS - {"defect"}:
        return f"want the keys {sorted(ENTRY_KEYS)} and, optionally, defect"
    for key in _TEXT_KEYS + (("defect",) if "defect" in entry else ()):
        if not isinstance(entry[key], str):
            return f"`{key}` must be text"
    if not isinstance(entry["items"], list) or not all(isinstance(i, str) for i in entry["items"]):
        return "`items` must be a list of item names"
    if not _is_hits(entry["lost"]) or not _is_hits(entry["gained"]):
        return "`lost` and `gained` must be lists of hits (a hit: a list of record numbers)"
    return None


def load_expected(path):
    """(entries, errors). A missing file is an empty list."""
    if not os.path.exists(path):
        return [], []
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        return [], [f"{path}: cannot read: {e}"]
    if not isinstance(doc, dict) or doc.get("schema") != 1 \
            or not isinstance(doc.get("expected"), list):
        return [], [f"{path}: want {{\"schema\": 1, \"expected\": [...]}}"]
    entries, errors, seen = [], [], set()
    for n, entry in enumerate(doc["expected"]):
        where = f"{os.path.relpath(path, REPO)} entry {n}"
        fault = _entry_fault(entry)
        if fault:
            errors.append(f"{where}: {fault}")
            continue
        key = (entry["variant"], entry["rule"], entry["source"], entry["name"])
        if key in seen:
            errors.append(f"{where}: a second entry for {key}")
            continue
        seen.add(key)
        entries.append(entry)
    return entries, errors


_ENTRY_ORDER = ("variant", "rule", "source", "name", "fault", "lost", "gained", "items",
                "reason", "defect", "why")


def format_expected(entries):
    """The text of an expected list: one key on a line, in one order, so that a
    change to one entry is a small diff. --propose prints it."""
    lines = ["{", '  "schema": 1,', '  "expected": [']
    for n, entry in enumerate(entries):
        keys = [k for k in _ENTRY_ORDER if k in entry]
        lines.append("    {")
        lines += [f"      {json.dumps(k)}: {json.dumps(entry[k])}" + ("," if k != keys[-1] else "")
                  for k in keys]
        lines.append("    }" + ("," if n < len(entries) - 1 else ""))
    return "\n".join(lines + ["  ]", "}"]) + "\n"


def open_defects(path=DEFECTS):
    """{ID: text of its section} for each ID of the Summary table of RULE_DEFECTS.md
    (the table that research/tools/coverage_report.py counts)."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return {}
    summary = text.split("\n## Summary", 1)[-1].split("\n## ", 1)[0]
    out = {}
    for ident in re.findall(r"(?m)^\|\s*\[?(\w+)\]?", summary):
        section = re.search(rf"(?ms)^### {re.escape(ident)}\. .*?(?=^### |^## |\Z)", text)
        if section:
            out[ident] = section.group(0)
    return out


def judge_expected(differences, entries, ctx, checked_rules, require_re2=False, defects=None,
                   every_rule=False):
    """Mark each listed difference as expected; return the problems of the list.

    checked_rules: the rules of this run (rel paths). An entry of a rule that this
    run did not check is left alone on a run of some rule files, and is stale on a
    run of every rule (every_rule): the rule is gone or has another name."""
    defects = open_defects() if defects is None else defects
    by_key = {d.key: d for d in differences}
    compact = {d.key[1:] for d in differences if d.variant == "compact"}
    problems = []
    for entry in entries:
        key = (entry["variant"], entry["rule"], entry["source"], entry["name"])
        label = f"expected [{entry['variant']}] {entry['source']} {entry['name']}"
        if entry["rule"] not in checked_rules:
            if every_rule:
                problems.append(Problem(entry["rule"], f"{label}: stale: no rule file "
                                        f"detections/sigma/{entry['rule']}; delete the entry"))
            continue
        if entry["variant"] in ctx.skipped:
            if require_re2:
                problems.append(Problem(entry["rule"], f"{label}: the variant did not run"))
            continue
        bad = None
        reason = REASONS.get(entry["reason"])
        diff = by_key.get(key)
        if diff is None:
            bad = "stale: this run shows no such difference; delete the entry"
        elif reason is None or reason[0] != entry["variant"]:
            bad = (f"reason {entry['reason']!r} is not a reason of the variant "
                   f"{entry['variant']} ({', '.join(k for k, v in REASONS.items() if v[0] == entry['variant']) or 'none'})")
        elif diff.fault != entry["fault"] or diff.items != sorted(entry["items"]):
            bad = (f"the difference changed: listed {entry['fault']} on {sorted(entry['items'])}, "
                   f"this run shows {diff.fault} on {diff.items}")
        elif diff.lost != _canon(entry["lost"]) or diff.gained != _canon(entry["gained"]):
            bad = (f"the hits changed: listed lost {_canon(entry['lost'])}, gained "
                   f"{_canon(entry['gained'])}; this run shows lost {diff.lost}, gained "
                   f"{diff.gained}")
        elif not str(entry["why"]).strip() or str(entry["why"]).startswith("TODO"):
            bad = "`why` is empty"
        else:
            bad = _proof(entry, diff, compact)
        if not bad and entry.get("defect") is not None:
            section = defects.get(entry["defect"])
            stem = os.path.basename(entry["rule"])[:-len(".yml")]
            if section is None:
                bad = (f"defect {entry['defect']!r} is not an open entry of "
                       "detections/RULE_DEFECTS.md (its Summary table)")
            elif stem not in section:
                bad = f"the entry {entry['defect']} of RULE_DEFECTS.md does not name {stem}"
        if bad:
            problems.append(Problem(entry["rule"], f"{label}: {bad}"))
            if diff is not None:
                diff.note = "listed, but the entry does not hold"
        else:
            diff.status, diff.entry = "expected", entry
    return problems


def _proof(entry, diff, compact):
    """None when the reason of an entry holds on this run, else the text."""
    changes = [c for c in diff.changes if c["record"] >= 0]
    if not changes or len(changes) != len(diff.changes):
        return f"{entry['reason']} is not proven: the run cannot name the items that changed"
    if entry["reason"] == "KEY_ORDER":
        if diff.key[1:] in compact:
            return ("KEY_ORDER is not proven: the same event set differs in the compact "
                    "text too, where the key order is the record's")
        if not all(c["list"] for c in changes):
            return "KEY_ORDER is not proven: an item that changed does not read a list"
    elif entry["reason"] == "LIKE_CASE":
        if not all(c["test"] == "like" for c in changes):
            return "LIKE_CASE is not proven: an item that changed is not a LIKE test"
    elif entry["reason"] == "LIST_TEXT":
        if not all(c["list"] for c in changes):
            return "LIST_TEXT is not proven: an item that changed does not read a list"
    return None


def ratchet(entries, base_path):
    """Problems: entries of this tree that the list of the base branch does not hold.
    None when the base has no list (the pull request that adds the gate): nothing to
    compare with, as for the two ratchets of the sufficiency-ratchet job."""
    if not os.path.exists(base_path):
        return None
    base, errors = load_expected(base_path)
    if errors:
        return [Problem("-", f"the expected list of the base cannot be read: {e}") for e in errors]
    held = {json.dumps(e, sort_keys=True) for e in base}
    return [Problem(e["rule"], f"expected [{e['variant']}] {e['source']} {e['name']}: the base "
                               "branch does not list this entry as it is here; a new or changed "
                               "expected difference is a human decision")
            for e in entries if json.dumps(e, sort_keys=True) not in held]


# ---- reports -----------------------------------------------------------------


def run(paths, ctx, fixtures=None):
    fixtures = cloud_fixtures() if fixtures is None else fixtures
    results = []
    for path in paths:
        try:
            results.append(check_rule(path, fixtures, ctx))
        except Exception as e:  # noqa: BLE001 - one broken rule must not hide the others
            rel = os.path.relpath(path, SIGMA)
            results.append((rel, 0, [], [Problem(rel, f"cannot check: {type(e).__name__}: {e}")],
                            []))
    return results


def print_report(results, list_problems, ctx, verbose=False):
    ran = ", ".join(ctx.variants)
    failed = []
    for rel, count, differences, problems, weakened in results:
        new = [d for d in differences if d.status != "expected"]
        known = [d for d in differences if d.status == "expected"]
        listed = [p for p in list_problems if p.rule == rel]
        if not new and not problems and not listed:
            extra = f"; {len(known)} expected difference(s)" if known else ""
            print(f"ok    {rel}: {count} event set(s), same hits as {ran}{extra}")
        else:
            failed.append(rel)
        for d in known:
            tracked = f"; RULE_DEFECTS {d.entry['defect']}" if d.entry.get("defect") else ""
            print(f"known {rel} :: {d.source} {d.kind} {d.name}: [{d.variant}] {d.fault}, "
                  f"expected ({d.entry['reason']}{tracked})")
            if verbose:
                for line in d.lines():
                    print("        " + line)
        for d in new:
            note = f" ({d.note})" if d.note else ""
            print(f"FAIL  {rel} :: {d.source} {d.kind} {d.name}: {d.text()}{note}")
            for line in d.lines():
                print("        " + line)
        for p in problems + listed:
            print(f"FAIL  {rel}: {p.detail}")
        for w in weakened:
            print(f"note  {rel} :: {w['source']} {w['kind']} {w['name']}: [{w['variant']}] "
                  f"weakened: {w['detail']}")
    for p in list_problems:
        if p.rule not in [r[0] for r in results]:
            print(f"FAIL  {p.rule}: {p.detail}")
            failed.append(p.rule)
    print()
    for variant, why in ctx.skipped.items():
        print(f"NOT RUN: variant {variant}: {why}. Nothing is proven for it "
              "(--require-re2 makes this an error).")
    sets = sum(r[1] for r in results)
    known = sum(1 for r in results for d in r[2] if d.status == "expected")
    if failed:
        print(f"FAILED: {len(set(failed))} of {len(results)} rule(s) have a new difference under "
              f"a variant, or an expected entry that does not hold: {', '.join(sorted(set(failed)))}.")
        return 1
    print(f"OK: {len(results)} rule(s), {sets} event set(s), variants {ran}: no new difference; "
          f"{known} expected.")
    return 0


def summary(results):
    """{variant: {platform: {"new": n, "expected": n}}} and the totals."""
    out = {}
    for _, _, differences, _, _ in results:
        for d in differences:
            cell = out.setdefault(d.variant, {}).setdefault(d.platform, {"new": 0, "expected": 0})
            cell["expected" if d.status == "expected" else "new"] += 1
    return out


def write_json(path, results, list_problems, ctx):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({
            "schema": 1,
            "ok": not list_problems and not any(
                r[3] or any(d.status != "expected" for d in r[2]) for r in results),
            "variants": {v: {"ran": v in ctx.variants, "how": HOW[v],
                             **({"not_run": ctx.skipped[v]} if v in ctx.skipped else {})}
                         for v in VARIANTS},
            "rules": len(results), "event_sets": sum(r[1] for r in results),
            "summary": summary(results),
            "differences": [d.as_dict() for r in results for d in r[2]],
            "weakened": [w for r in results for w in r[4]],
            "problems": [{"rule": p.rule, "detail": p.detail}
                         for p in [q for r in results for q in r[3]] + list_problems],
        }, fh, indent=2)
        fh.write("\n")


def write_markdown(path, results, list_problems, ctx):
    lines = ["## Representation variants", ""]
    new = [d for r in results for d in r[2] if d.status != "expected"]
    problems = [q for r in results for q in r[3]] + list_problems
    known = [d for r in results for d in r[2] if d.status == "expected"]
    for variant, why in ctx.skipped.items():
        lines += [f"**NOT RUN**: variant `{variant}`: {why}.", ""]
    if new or problems:
        lines += [f"**FAIL**: {len(new)} new difference(s), {len(problems)} other problem(s).", "",
                  "| rule | case or fixture | variant | fault | items |", "|---|---|---|---|---|"]
        lines += [f"| `{d.rule}` | {d.source} {d.kind} `{d.name}` | {d.variant} | {d.fault} | "
                  + ", ".join(f"`{i}`" for i in d.items).replace("|", "\\|") + " |" for d in new]
        lines += [""] + [f"- `{p.rule}`: {p.detail}" for p in problems]
    else:
        lines.append(f"**OK**: {len(results)} rule(s), {sum(r[1] for r in results)} event set(s), "
                     f"variants {', '.join(ctx.variants)}: no new difference; {len(known)} expected.")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n\n")


# ---- golden probes (detections/SEMANTICS.md) ---------------------------------

# (id, statement, detection, record, {variant: fires}); "default" is the oracle as
# every validator runs it, and a variant that the row does not name gives the
# default answer. The self-test proves each cell; SEMANTICS.md quotes the table.
PROBES = [
    ("eq-case", "equality is case-sensitive (SQL `=`; Sigma's default is not)",
     {"s": {"verb": "Create"}, "condition": "s"}, {"verb": "create"}, {"default": False}),
    ("contains-case", "|contains ignores ASCII case (LIKE)",
     {"s": {"verb|contains": "Create"}, "condition": "s"}, {"verb": "create"},
     {"default": True, "cs_like": False}),
    ("startswith-case", "|startswith ignores ASCII case (LIKE)",
     {"s": {"verb|startswith": "CRE"}, "condition": "s"}, {"verb": "create"},
     {"default": True, "cs_like": False}),
    ("endswith-case", "|endswith ignores ASCII case (LIKE)",
     {"s": {"verb|endswith": "ATE"}, "condition": "s"}, {"verb": "create"},
     {"default": True, "cs_like": False}),
    ("wildcard-case", "a wildcard value is LIKE, so it ignores ASCII case; the same "
                      "value without the wildcard does not",
     {"s": {"verb": "CRE*"}, "condition": "s"}, {"verb": "create"},
     {"default": True, "cs_like": False}),
    ("contains-non-ascii", "LIKE folds ASCII letters only",
     {"s": {"name|contains": "ÉTÉ"}, "condition": "s"}, {"name": "été"},
     {"default": False}),
    ("list-equality", "equality on a list never matches (the field is the JSON text)",
     {"s": {"user.groups": "system:masters"}, "condition": "s"},
     {"user": {"groups": ["system:masters", "dev"]}}, {"default": False, "multi": True}),
    ("list-contains", "|contains matches inside the JSON text of a list",
     {"s": {"user.groups|contains": "system:MASTERS"}, "condition": "s"},
     {"user": {"groups": ["system:masters", "dev"]}},
     {"default": True, "cs_like": False}),
    ("list-quotes", "a value with the JSON quotes of an element matches the text only",
     {"s": {"user.groups|contains": '"system:masters"'}, "condition": "s"},
     {"user": {"groups": ["system:masters", "dev"]}}, {"default": True, "multi": False}),
    ("list-blank", "the JSON text has a blank after each `,` and `:`",
     {"s": {"user.groups|contains": '"system:masters", "dev"'}, "condition": "s"},
     {"user": {"groups": ["system:masters", "dev"]}},
     {"default": True, "compact": False, "sorted": False, "multi": False}),
    ("list-no-blank", "the text without blanks does not match by default",
     {"s": {"user.groups|contains": '"system:masters","dev"'}, "condition": "s"},
     {"user": {"groups": ["system:masters", "dev"]}},
     {"default": False, "compact": True, "sorted": True}),
    ("list-key-order", "the JSON text keeps the key order of the record",
     {"s": {"rules|re": '\\"verbs\\":\\s*\\[[^\\]]*\\],\\s*\\"apiGroups\\"'}, "condition": "s"},
     {"rules": [{"verbs": ["*"], "apiGroups": [""]}]},
     {"default": True, "compact": True, "sorted": False}),
    ("list-empty-exists", "an empty list is the text `[]`, so the field exists",
     {"s": {"items|exists": True}, "condition": "s"}, {"items": []},
     {"default": True, "multi": False}),
    ("object-empty-exists", "an empty object leaves no field",
     {"s": {"spec|exists": True}, "condition": "s"}, {"spec": {}}, {"default": False}),
    ("list-non-ascii", "the JSON text escapes a non-ASCII character",
     {"s": {"names|contains": "é"}, "condition": "s"}, {"names": ["café"]},
     {"default": False, "multi": True}),
    ("re-case", "|re is case-sensitive",
     {"s": {"verb|re": "Create"}, "condition": "s"}, {"verb": "create"}, {"default": False}),
    ("re-i", "|re|i ignores case",
     {"s": {"verb|re|i": "Create"}, "condition": "s"}, {"verb": "create"}, {"default": True}),
    ("re-search", "|re is a search, not a match of the whole value",
     {"s": {"apiVersion|re": "v1"}, "condition": "s"}, {"apiVersion": "apps/v1beta1"},
     {"default": True}),
    ("re-space-class", "`\\s` matches a no-break space in Python re, not in RE2",
     {"s": {"line|re": "rewrite\\sname"}, "condition": "s"}, {"line": "rewrite name"},
     {"default": True, "re2": False}),
    ("re-dollar-newline", "`$` matches before a final line break in Python re, not in RE2",
     {"s": {"line|re": "end$"}, "condition": "s"}, {"line": "the end\n"},
     {"default": True, "re2": False}),
    ("field-name-case", "a field name matches without regard to letter case (SQLite "
                        "columns); check_null_safety.py fails a rule that needs it",
     {"s": {"Verb": "create"}, "condition": "s"}, {"verb": "create"}, {"default": True}),
    ("number-text", "the text of a number does not equal the number",
     {"s": {"code": "200"}, "condition": "s"}, {"code": 200}, {"default": False}),
    ("number-number", "a number equals the number",
     {"s": {"code": 200}, "condition": "s"}, {"code": 200}, {"default": True}),
    ("null-absent", "`field: null` holds on a record without the field",
     {"s": {"verb": "delete", "dryRun": None}, "condition": "s"}, {"verb": "delete"},
     {"default": True}),
    ("null-json-null", "`field: null` holds on a JSON null",
     {"s": {"verb": "delete", "dryRun": None}, "condition": "s"},
     {"verb": "delete", "dryRun": None}, {"default": True}),
    ("not-absent", "`not filter` keeps a record without the filter's field (two-valued; "
                   "check_null_safety.py runs the three-valued logic)",
     {"s": {"verb": "delete"}, "f": {"dryRun": "All"}, "condition": "s and not f"},
     {"verb": "delete"}, {"default": True}),
]


def _probe_rule(detection, ident="probe"):
    return sigma_explain.from_docs([{"title": ident, "logsource": {"product": "probe"},
                                     "detection": detection}])


def probe_results(ctx):
    """[(id, statement, {name: fires}, {name: expected})] for "default" and each variant
    that runs."""
    out = []
    for ident, statement, detection, record, expect in PROBES:
        rule = _probe_rule(detection, ident)
        run = Run(rule, rule.sql, [record], ctx)
        got = {"default": bool(run.hits)}
        want = {"default": expect["default"]}
        for variant in ctx.variants:
            got[variant] = bool(run.variant_hits(variant))
            want[variant] = expect.get(variant, expect["default"])
        out.append((ident, statement, got, want))
    return out


def in_force(ctx):
    """Each variant that runs must change the answer of a probe that names it: a
    variant that changes nothing would pass every rule. Returns the variants that do
    not."""
    changed = set()
    for _, _, got, want in probe_results(ctx):
        changed |= {v for v in ctx.variants if got[v] != got["default"] and got == want}
    return [v for v in ctx.variants if v not in changed]


def print_probes(ctx):
    names = ["default"] + list(ctx.variants)
    print("| probe | statement | " + " | ".join(names) + " |")
    print("|---|---|" + "---|" * len(names))
    bad = 0
    for ident, statement, got, want in probe_results(ctx):
        cells = []
        for name in names:
            cell = "fires" if got[name] else "quiet"
            if got[name] != want[name]:
                cell += " (WANT " + ("fires" if want[name] else "quiet") + ")"
                bad += 1
            cells.append(cell)
        print(f"| `{ident}` | {statement} | " + " | ".join(cells) + " |")
    for variant, why in ctx.skipped.items():
        print(f"\nNOT RUN: variant {variant}: {why}.")
    return 1 if bad else 0


# ---- self-test ---------------------------------------------------------------


def self_test():
    ctx = Context()
    results = []

    def check(name, cond, detail=""):
        results.append(bool(cond))
        if not cond:
            print(f"self-test FAIL: {name}" + (f": {detail}" if detail else ""))

    for ident, _, got, want in probe_results(ctx):
        check(f"probe {ident}", got == want, f"got {got}, want {want}")
    check("each variant that runs is in force", not in_force(ctx), in_force(ctx))

    def judged(detection, sets, entries=(), defects=None):
        rule = _probe_rule(detection, "self-test")
        full = [(s, n, k, e, {"kind": k, "breaks": b} if b else None) for s, n, k, e, b in sets]
        rel, _, differences, problems, weakened = check_rule(
            os.path.join(SIGMA, "T0000", "self_test.yml"), {}, ctx, rule=rule, sets=full)
        listed = judge_expected(differences, list(entries), ctx, {rel}, defects=defects or {},
                                every_rule=True)
        return rel, differences, problems + listed, weakened

    blank = {"s": {"verb": "create", "items|contains": '"group": "all"'}, "condition": "s"}
    record = {"verb": "create", "items": [{"group": "all"}]}
    rel, diffs, problems, _ = judged(blank, [("case", "p", "positive", [record], None)])
    check("a positive that needs the blank is a loss as compact and as sorted",
          sorted((d.variant, d.fault, tuple(d.items)) for d in diffs)
          == [("compact", "loss", ("s.items",)), ("sorted", "loss", ("s.items",))], diffs)
    check("a difference that is not listed is new", all(d.status == "new" for d in diffs))

    filt = {"s": {"verb": "create"}, "f": {"groups|contains": '"system:masters"'},
            "condition": "s and not f"}
    rel, diffs, problems, _ = judged(
        filt, [("case", "f", "filtered", [{"verb": "create", "groups": ["system:masters"]}],
                ["f.groups"])])
    check("a filtered case whose filter reads the quotes of the list text is a gain as multi",
          [(d.variant, d.fault, d.kind) for d in diffs] == [("multi", "gain", "filtered")], diffs)
    entry = {"variant": "multi", "rule": rel, "source": "case", "name": "f", "fault": "gain",
             "lost": [], "gained": [[0]], "items": ["f.groups"], "reason": "LIST_TEXT",
             "why": "the filter reads the quotes"}
    _, diffs, problems, _ = judged(
        filt, [("case", "f", "filtered", [{"verb": "create", "groups": ["system:masters"]}],
                ["f.groups"])], [entry])
    check("a listed difference is expected", [d.status for d in diffs] == ["expected"]
          and not problems, [p.detail for p in problems])
    for name, change, text in (
            ("another fault", {"fault": "loss"}, "the difference changed"),
            ("other items", {"items": ["s.verb"]}, "the difference changed"),
            ("a reason of another variant", {"reason": "LIKE_CASE"}, "is not a reason of the variant"),
            ("an unknown reason", {"reason": "BECAUSE"}, "is not a reason of the variant"),
            ("no why", {"why": " "}, "`why` is empty"),
            ("other hits", {"gained": [[0], [1]]}, "the hits changed"),
            ("a defect that is not open", {"defect": "K999"}, "is not an open entry")):
        _, diffs, problems, _ = judged(
            filt, [("case", "f", "filtered", [{"verb": "create", "groups": ["system:masters"]}],
                    ["f.groups"])], [dict(entry, **change)])
        check(f"an entry with {name} does not excuse the difference",
              [d.status for d in diffs] == ["new"] and any(text in p.detail for p in problems),
              [p.detail for p in problems])
    _, diffs, problems, _ = judged(
        filt, [("case", "f", "filtered", [{"verb": "create", "groups": ["system:masters"]}],
                ["f.groups"])], [dict(entry, name="gone")])
    check("an entry that shows no difference is stale",
          any("stale" in p.detail for p in problems), [p.detail for p in problems])
    _, diffs, problems, _ = judged(
        filt, [("case", "f", "filtered", [{"verb": "create", "groups": ["system:masters"]}],
                ["f.groups"])], [entry, dict(entry, rule="T0000/gone.yml")])
    check("an entry of a rule that is gone is stale on a run of every rule",
          any("no rule file detections/sigma/T0000/gone.yml" in p.detail for p in problems),
          [p.detail for p in problems])
    _, diffs, problems, _ = judged(
        filt, [("case", "f", "filtered", [{"verb": "create", "groups": ["system:masters"]}],
                ["f.groups"])], [dict(entry, defect="K1")],
        defects={"K1": "### K1. self_test: text"})
    check("an entry with an open defect that names the rule is expected",
          [d.status for d in diffs] == ["expected"] and not problems)

    order = {"s": {"rules|re": '\\"verbs\\":\\s*\\[[^\\]]*\\],\\s*\\"apiGroups\\"'},
             "condition": "s"}
    sets = [("case", "o", "positive", [{"rules": [{"verbs": ["*"], "apiGroups": [""]}]}], None)]
    key_order = {"variant": "sorted", "rule": rel, "source": "case", "name": "o",
                 "fault": "loss", "lost": [[0]], "gained": [], "items": ["s.rules"],
                 "reason": "KEY_ORDER", "why": "Go order"}
    _, diffs, problems, _ = judged(order, sets, [key_order])
    check("KEY_ORDER is proven when the compact text keeps the hit",
          [(d.variant, d.status) for d in diffs] == [("sorted", "expected")] and not problems,
          [p.detail for p in problems])
    _, diffs, problems, _ = judged(blank, [("case", "o", "positive", [record], None)],
                                   [dict(key_order, items=["s.items"])])
    check("KEY_ORDER is refused when the compact text loses the hit too",
          any("KEY_ORDER is not proven" in p.detail for p in problems),
          [p.detail for p in problems])

    two = [("fixture", "two.json", "attack",
            [{"rules": [{"verbs": ["*"], "apiGroups": [""]}]},
             {"rules": [{"verbs": ["get"], "apiGroups": ["apps"]}]}], None)]
    one_of_two = dict(key_order, source="fixture", name="two.json", lost=[[0]])
    _, diffs, problems, _ = judged(order, two, [one_of_two])
    check("an entry for one lost record of a fixture does not excuse a second lost record",
          [(d.variant, d.status, d.lost) for d in diffs] == [("sorted", "new", [[0], [1]])]
          and any("the hits changed: listed lost [[0]], gained []; this run shows lost "
                  "[[0], [1]], gained []" in p.detail for p in problems),
          [p.detail for p in problems])
    _, diffs, problems, _ = judged(order, two, [dict(one_of_two, lost=[[0], [1]])])
    check("an entry that lists each lost record of a fixture is expected",
          [d.status for d in diffs] == ["expected"] and not problems,
          [p.detail for p in problems])

    weak = {"s": {"verb": "create", "user": "alice", "items|contains": '"group": "all"'},
            "condition": "s"}
    _, diffs, _, weakened = judged(
        weak, [("case", "n", "near-miss", [dict(record, user="bob")], ["s.user"])])
    check("a near-miss that a second item keeps quiet as compact is weakened, not a difference",
          not diffs and sorted(w["variant"] for w in weakened) == ["compact", "sorted"], weakened)

    corr = sigma_explain.from_docs([
        {"title": "a", "name": "b_a", "logsource": {"product": "probe"},
         "detection": {"s": {"type": "A"}, "condition": "s"}},
        {"title": "c", "correlation": {"type": "event_count", "rules": ["b_a"],
                                       "group-by": ["pid"], "timespan": "5s",
                                       "condition": {"gte": 1}}}])
    events = [{"type": "A", "pid": 1, "timestamp": "2026-01-01T00:00:00Z", "argv": ["x"]}]
    _, _, diffs, problems, _ = check_rule(os.path.join(SIGMA, "T0000", "self_test.yml"), {}, ctx,
                                          rule=corr, sets=[("case", "c", "positive", events, None)])
    check("a correlation rule on a record with a list is refused for multi",
          any("[multi] cannot check" in p.detail for p in problems), [p.detail for p in problems])
    differs = {"s": {"verb": "create", "groups|neq": "dev"}, "condition": "s"}
    _, diffs, problems, _ = judged(
        differs, [("case", "d", "positive", [{"verb": "create", "groups": ["ops"]}], None)])
    check("an item that negates inside itself (`|neq`) on a list is refused for multi",
          not diffs and len(problems) == 1 and "[multi] cannot check" in problems[0].detail
          and "negates inside itself" in problems[0].detail, [p.detail for p in problems])
    _, diffs, problems, _ = judged(
        differs, [("case", "d", "positive", [{"verb": "create", "groups": "ops", "ips": ["a"]}],
                   None)])
    check("the same item on a field that is not a list is checked", not diffs and not problems,
          [p.detail for p in problems])

    base = [dict(entry)]
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "expected.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"schema": 1, "expected": base}, fh)
        check("the ratchet accepts the list of the base", not ratchet(base, path))
        check("a base without the file gives nothing to compare with",
              ratchet(base, os.path.join(tmp, "absent.json")) is None)
        check("the ratchet accepts a list that lost an entry", not ratchet([], path))
        check("the ratchet fails a new entry",
              len(ratchet(base + [dict(entry, name="new")], path)) == 1)
        check("the ratchet fails a changed entry",
              len(ratchet([dict(entry, why="other words")], path)) == 1)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"schema": 1, "expected": [dict(entry), dict(entry)]}, fh)
        check("a second entry for one key is an error", load_expected(path)[1])
        for name, change in (("an entry without its hits", {"lost": None}),
                             ("an entry whose items are not a list", {"items": "f.groups"}),
                             ("an entry with a key that the gate does not read", {"note": "x"}),
                             ("an entry whose why is not text", {"why": 7})):
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"schema": 1, "expected": [dict(entry, **change)]}, fh)
            read, errors = load_expected(path)
            check(f"{name} is an error, and is no entry", errors and not read, errors)

    # SAME INPUT: the shortcuts name the right run, and change no answer of a probe.
    plain = _probe_rule({"s": {"verb": "create"}, "condition": "s"}, "self-test")
    like = _probe_rule({"s": {"verb|contains": "crea"}, "condition": "s"}, "self-test")
    regex = _probe_rule({"s": {"verb|re": "crea"}, "condition": "s"}, "self-test")
    flat = Run(plain, plain.sql, [{"verb": "create", "user": {"name": "a"}}], ctx)
    listed = Run(like, like.sql, [{"verb": "create", "groups": [{"b": 1, "a": 2}]}], ctx)
    in_order = Run(regex, regex.sql, [{"verb": "create", "groups": [{"a": 1, "b": 2}]}], ctx)
    check("a record without a list has the default input as compact, sorted and multi",
          [flat.input_of(v) for v in ("compact", "sorted", "multi")] == [None, None, None])
    check("a record with a list has an input of its own as compact, sorted and multi",
          [listed.input_of(v) for v in ("compact", "sorted", "multi")]
          == ["compact", "sorted", "multi"])
    check("sorted keys that are the record's order give the input of compact",
          in_order.input_of("sorted") == "compact")
    check("a rule without LIKE has the default input as cs_like, a rule with LIKE has not",
          (flat.input_of("cs_like"), listed.input_of("cs_like"), in_order.input_of("cs_like"))
          == (None, "cs_like", None))
    if "re2" in ctx.variants:
        check("a rule without REGEXP has the default input as re2, a rule with REGEXP has not",
              (flat.input_of("re2"), in_order.input_of("re2")) == (None, "re2"))
    full = Context(shortcuts=False)
    check("without the shortcuts each variant has an input of its own",
          [Run(plain, plain.sql, [{"verb": "create"}], full).input_of(v) for v in full.variants]
          == list(full.variants))
    check("the shortcuts change no answer of a golden probe",
          [got for _, _, got, _ in probe_results(ctx)]
          == [got for _, _, got, _ in probe_results(full)])

    if ctx.skipped:
        for variant, why in ctx.skipped.items():
            print(f"self-test: variant {variant} NOT RUN ({why}); its probes are not proven")
    if all(results):
        print(f"self-test: all {len(results)} checks hold")
        return 0
    print(f"self-test: {results.count(False)} of {len(results)} checks FAILED")
    return 1


# ---- main --------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Fail a rule whose hits differ when the same "
                                             "records are stored or matched in another way.")
    ap.add_argument("rules", nargs="*", help="rule files (default: every rule)")
    ap.add_argument("--require-re2", action="store_true",
                    help="fail when the re2 module (google-re2) is missing, as CI does")
    ap.add_argument("--expected", metavar="PATH", default=EXPECTED,
                    help="the list of expected differences (default: %(default)s)")
    ap.add_argument("--baseline-expected", metavar="PATH",
                    help="only compare the expected list with this one, the list of the base "
                         "branch: fail an entry that it does not hold as it is here")
    ap.add_argument("--propose", action="store_true",
                    help="print the expected list that this run shows (for a pull request)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print the items of each expected difference too")
    ap.add_argument("--json", metavar="PATH", help="write every difference as JSON")
    ap.add_argument("--markdown", metavar="PATH",
                    help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    ap.add_argument("--probes", action="store_true", help="print the golden probes, and exit")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the probes and the gate on constructed rules, and exit")
    args = ap.parse_args()
    ctx = Context()
    if args.require_re2 and ctx.skipped:
        print("ERROR: --require-re2 given but " + "; ".join(ctx.skipped.values())
              + " (pip install google-re2)")
        return 2
    if args.self_test:
        return self_test()
    if args.probes:
        return print_probes(ctx)
    if args.baseline_expected:
        entries, errors = load_expected(args.expected)
        compared = ratchet(entries, args.baseline_expected)
        base_detections = os.path.dirname(os.path.dirname(os.path.abspath(args.baseline_expected)))
        if compared is None and not os.path.isdir(base_detections):
            # A wrong path must not pass as "the base has no list".
            print(f"ERROR: --baseline-expected {args.baseline_expected}: the file is not "
                  f"there, and the base tree is not there either (no directory "
                  f"{base_detections}). Give the path of detections/variants/expected.json "
                  "in a checkout of the base branch.")
            return 2
        if compared is None and not errors:
            print("::notice title=variants-ratchet::the base has no "
                  f"{os.path.relpath(args.expected, REPO)}; no expected list to ratchet against "
                  f"({len(entries)} entr(ies) here)")
            return 0
        problems = [Problem("-", e) for e in errors] + (compared or [])
        print(f"Expected-difference ratchet against {args.baseline_expected} (the list of the "
              "base branch):")
        for p in problems:
            print(f"FAIL  {p.rule}: {p.detail}")
        if problems:
            print(f"\nFAILED: {len(problems)} entr(ies) of "
                  f"{os.path.relpath(args.expected, REPO)} are not on the base branch as they "
                  "are here. A new or changed expected difference is a human decision: the "
                  "maintainer merges the pull request by hand, or the entry goes.")
            return 1
        print(f"OK: each of the {len(entries)} expected difference(s) is on the base branch "
              "as it is here (the list did not grow).")
        return 0
    dead = in_force(ctx)
    if dead:
        print(f"ERROR: variant(s) not in force: {', '.join(dead)}: no probe changes its answer "
              "as the table PROBES says. A variant that changes nothing passes every rule.")
        return 2
    paths = args.rules or sorted(glob.glob(os.path.join(SIGMA, "*", "*.yml")))
    results = run(paths, ctx)
    entries, errors = load_expected(args.expected)
    list_problems = [Problem("-", e) for e in errors]
    differences = [d for r in results for d in r[2]]
    list_problems += judge_expected(differences, entries, ctx, {r[0] for r in results},
                                    require_re2=args.require_re2, every_rule=not args.rules)
    if args.propose:
        sys.stdout.write(format_expected([d.proposal() for d in differences]))
        return 0
    rc = print_report(results, list_problems, ctx, verbose=args.verbose)
    if args.json:
        write_json(args.json, results, list_problems, ctx)
    if args.markdown:
        write_markdown(args.markdown, results, list_problems, ctx)
    return rc


if __name__ == "__main__":
    sys.exit(main())
