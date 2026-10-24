#!/usr/bin/env python3
"""
The null-safety gate: every rule must give the same verdict in two-valued and in
three-valued logic.

Sigma's `not` is null-safe: a record without the filter's field does not match the
filter, so `selection and not filter` still fires on it. The validators keep that
meaning: pySigma's SQLite backend writes each negation as NOT COALESCE(<test>, 0).
A backend with SQL semantics (ES|QL and other SQL backends) uses three-valued
logic instead: a test on a missing field is NULL, NOT NULL is NULL, and WHERE
keeps only true. There, `and not filter` drops every record that lacks the
filter's field, and no validator sees it.

This gate runs each rule twice over the same records, offline:

  two-valued    sigma_eval.compile_rule(path) on sigma_eval.EventTable(events),
                as every validator runs it;
  three-valued  sigma_eval.compile_rule(path, three_valued=True) (NOT (<test>)
                with no COALESCE) on EventTable(events, three_valued=True) (a
                regular expression on a missing field is NULL, not false).

The records are every case of the rule's sidecar (<stem>.cases.jsonl, one event
set per case) and, for a cloud rule, the attack and benign fixtures of each of
its rows in validate_cloud_detections.MANIFEST (one event set per fixture). The
gate fails when the hits of any event set differ: the record (for a correlation,
the alert) that fires in one logic must fire in the other. A change of the
case's verdict (fires / does not fire) and a lost hit inside a case that still
fires both fail. For each lost record it names the rule, the case or fixture,
the record, and each negation whose operand is NULL on it (a `not`, or an item
that negates inside itself, `|neq`): the blocks under it, the items that are NULL
and the fields they read (absent on the record). A rule with no sidecar case and
no cloud fixture fails too: nothing shows it is null-safe. Every rule is checked;
there is no exemption list.

Two null-safe forms (sigma_explain's PlainRule.null_helpers() defines them; each
has the two-valued verdict of the plain `not`):

  guard  a filter whose every map reads the field that a record can lack: OR it
         with a block that the field is absent.

             sel_no_dry_run_body:
               requestObject.dryRun: null
             condition: selection and (sel_no_dry_run_body or not filter_dry_run_delete_body)

         `not` may also take an OR of such filters, `not (filter_a or filter_b)`
         or `not 1 of filter_*`. In two-valued logic the verdict is the same (a
         record without the field does not match the filter); in three-valued
         logic `requestObject.dryRun IS NULL` is true for such a record, so the
         OR is true.
  copy   a filter whose maps read different fields: repeat each map as a block of
         its own and read each one only where its field is present.

             condition: selection and not (filter_scoped and
                 ((filter_scoped_key and not sel_no_key) or
                  (filter_scoped_policy and not sel_no_policy)))

         Each term reads its copy only where every field that the copy tests is
         present, one guard per field (`filter_scoped_key and not sel_no_key and
         not sel_no_kind` for a map on two fields). So the OR holds exactly where
         filter_scoped holds, and it is never NULL. Do not use `|exists: true` in
         the copies: pySigma's EQL backend cannot convert it.

A guard covers only the fields it names; any other field the filter reads must be
one that the log source writes on every record the rule matches (--absent probes
this). A guard on several fields holds only where all of them are absent, so it
is accepted only when each map of its filter is one item that holds on any value
of one of its fields (`field: '*'`, `field|exists: true`).

The gate also fails, whatever the records, on a shape that is one of these forms
but not a correct one (PlainRule.null_guard_issues()): a guard on a near spelling
of a field that the filter reads (one that differs only in letter case, or by a
typo, makes the guard true on every record, so the filter never applies on a
backend with case-sensitive fields); a guard on a field that only some maps of its
filter read (it changes the rule); a guard on several fields that its filter can
leave NULL; and a copy that does not repeat its filter's maps exactly, or that
tests a field no guard of its term covers. A `field: null` block ORed with a `not`
on other fields is an ordinary selection, and so are `<block> and not <null block>`
terms when no block ANDed with them has maps with the same keys. If the gate reads
a real selection as a broken guard, write `sel_no_x or not filter` as
`not (filter and not sel_no_x)`: it means the same and is not read as a guard. If
it reads selections as a broken copy, write each `sel_x and not sel_no_x` as
`not (sel_no_x or not sel_x)`.
And the gate fails a rule field that a case's records carry only in another letter
case: SQLite matches column names without regard to case, so every offline gate
reads the record's field, but Lucene, Splunk and ES|QL do not.

Three-valued logic can only lose hits, never add them: Kleene's AND, OR and NOT
are monotone, and the COALESCE at each NOT only replaces a NULL with a definite
value. So a hit that only the three-valued query has is reported as an internal
error. So is a record on which the three-valued values of the rule's items (each
item compiled alone with the three-valued backend), composed through its
condition in Kleene logic, disagree with the compiled three-valued query.

LIMIT: the gate proves null safety on the records the cases and fixtures hold.
A filter on a field that every positive record carries is never tested absent.
--absent lists those: for each firing record of a positive case or an attack
fixture, it drops each field that a filter item or a negating item (`|neq`)
reads, one at a time, and reports the fields whose absence keeps the two-valued
hit but loses the three-valued one. It is information only (exit 0): on a log
source that always writes the field (auditd's comm and exe, the API server's
requestURI and verb, CloudTrail's sourceIPAddress), no record lacks it. For a
field that a record can lack, add a positive case without it and guard the
filter (detections/README.md lists the fields it reports and why each one is
always written on the records the rule matches).

Usage:
    python3 detections/check_null_safety.py               # every rule (the gate)
    python3 detections/check_null_safety.py detections/sigma/T1070/k8s_events_deleted.yml
    python3 detections/check_null_safety.py --absent      # also list untested filter fields
    python3 detections/check_null_safety.py --json out.json --markdown "$GITHUB_STEP_SUMMARY"
    python3 detections/check_null_safety.py --self-test   # constructed good and bad rules

Exit 0 when every rule holds, 1 when any rule fails (or a self-test check fails).
"""

import os
import sys

# Running this script puts detections/ first on sys.path. Import the standard
# library before it is there (as check_sufficiency.py does), so a stray module in
# detections/ cannot replace one; sigma_eval's import guard then checks the rest.
_HERE = os.path.dirname(os.path.abspath(__file__))
if sys.path and os.path.abspath(sys.path[0] or os.curdir) == _HERE:
    del sys.path[0]

import argparse  # noqa: E402
import glob  # noqa: E402
import json  # noqa: E402
import tempfile  # noqa: E402

sys.path.insert(0, _HERE)
import sigma_eval  # noqa: E402  (checks detections/ before pySigma loads)
import sigma_explain  # noqa: E402
import rule_cases  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402

REPO = os.path.dirname(_HERE)
SIGMA = os.path.join(REPO, "detections", "sigma")


# ---- Kleene logic over sigma_explain's condition tree ------------------------


def kleene(node, values):
    """Three-valued value of a condition subtree: True, False or None (NULL)."""
    op = node[0]
    if op == "id":
        return values[node[1]]
    if op == "not":
        inner = kleene(node[1], values)
        return None if inner is None else not inner
    results = [kleene(child, values) for child in node[1]]
    if op == "and":
        if False in results:
            return False
        return None if None in results else True
    if True in results:
        return True
    return None if None in results else False


def item_values(rule, table):
    """Per event: {atom: True / False / None}, each item run alone in three-valued SQL.

    Each item is compiled alone with the three-valued backend (PlainRule.item_sql), so
    an item that negates inside itself (`|neq`) reads NULL on a record without its
    field, as it does in the rule's three-valued query.
    """
    prefix = "SELECT * FROM logs WHERE "
    out = [dict() for _ in table.events]
    for atom in rule.items:
        sql = rule.item_sql(atom, three_valued=True)
        if not sql.startswith(prefix):
            raise ValueError(f"item {atom}: unexpected SQL shape {sql[:60]!r}")
        rows = table._execute(f"SELECT {sigma_eval._ROWID}, ({sql[len(prefix):]}) FROM logs")
        for rowid, value in rows.fetchall():
            out[rowid][atom] = None if value is None else bool(value)
    return out


def _null_leaves(node, values):
    """Atoms under node that are NULL on the path that makes node NULL."""
    if kleene(node, values) is not None:
        return []
    if node[0] == "id":
        return [node[1]]
    if node[0] == "not":
        return _null_leaves(node[1], values)
    return [a for child in node[1] for a in _null_leaves(child, values)]


def null_negations(rule, node, values):
    """The outermost negations whose operand is NULL, on the path that makes the root
    NULL: a `not` node, or an item that negates inside itself (`|neq`). Each is (the
    node, its NULL atoms)."""
    if kleene(node, values) is not None:
        return []
    if node[0] == "not":
        return [(node, _null_leaves(node[1], values))]
    if node[0] == "id":
        # A `|neq` item is NOT <test> inside the item. Any other NULL selection item is
        # false in two-valued logic as well, so it loses nothing.
        return [(node, [node[1]])] if rule.item_negates(node[1]) else []
    return [n for child in node[1] for n in null_negations(rule, child, values)]


render = sigma_explain.render


def explain_lost(rule, event, values):
    """Lines that name each negation whose operand is NULL on a lost record."""
    lines = []
    for node, atoms in null_negations(rule, rule.tree, values):
        blocks = list(dict.fromkeys(rule.block_of[a] for a in atoms))
        what = f"`{render(rule, node)}`" if node[0] == "not" else \
            f"the negating item `{node[1]}` (`|neq`)"
        lines.append(f"{what} is NULL (block {', '.join(blocks)}):")
        for atom in dict.fromkeys(atoms):
            field = rule.item_field[atom]
            shown = f"{field} = {sigma_explain._short(event.get(field))}" if field \
                else "(keyword search)"
            lines.append(f"    {atom} is NULL: {shown}")
    return lines or ["(no negation with a NULL operand was found; report it)"]


# ---- one rule ----------------------------------------------------------------


class Problem:
    def __init__(self, rule, source, name, kind, detail, lines=()):
        self.rule, self.source, self.name, self.kind = rule, source, name, kind
        self.detail, self.lines = detail, list(lines)

    def as_dict(self):
        return {"rule": self.rule, "source": self.source, "name": self.name,
                "kind": self.kind, "detail": self.detail, "lines": self.lines}


def _canon(hits):
    return sorted(sorted(h) for h in hits)


def _base_sql(rule, ref, three_valued):
    docs = [rule.base_docs[ref]]
    return sigma_eval.backend(three_valued).convert(SigmaCollection.from_dicts(docs))[0]


def _event_sets(rule_path, fixtures):
    """[(source, name, kind, flat events)]: sidecar cases, then cloud fixtures."""
    sets, errors = [], []
    path = rule_cases.cases_path(rule_path)
    if os.path.exists(path):
        cases, errors = rule_cases.load_cases(path)
        for case in cases:
            sets.append(("case", case["name"], case["kind"],
                         [sigma_eval.flatten(e) for e in case["events"]]))
    sets += fixtures.get(os.path.abspath(rule_path), [])
    return sets, errors


def check_rule(rule_path, fixtures, absent=False):
    """(rel, sets checked, problems, absent findings) for one rule file."""
    rel = os.path.relpath(rule_path, SIGMA)
    rule = sigma_explain.load(rule_path)
    sql2 = sigma_eval.compile_rule(rule_path)
    sql3 = sigma_eval.compile_rule(rule_path, three_valued=True)
    sets, errors = _event_sets(rule_path, fixtures)
    problems = [Problem(rel, "sidecar", "-", "-", f"sidecar error: {e}") for e in errors]
    if not sets:
        problems.append(Problem(rel, "-", "-", "-", "no sidecar case and no cloud fixture: "
                                "nothing shows that the rule is null-safe"))
    problems += [Problem(rel, "-", "-", "structure", issue) for issue in rule.null_guard_issues()]
    problems += _field_case(rule, rel, sets)
    for source, name, kind, events in sets:
        problems += _compare(rule, rel, source, name, kind, events, sql2, sql3)
    found = _absent_probe(rule, sets, sql2, sql3) if absent and not rule.is_correlation else []
    return rel, len(sets), problems, found


def _rule_fields(rule):
    parts = rule.bases.values() if rule.is_correlation else [rule]
    return sorted({f for part in parts for f in part.item_field.values() if f})


def _field_case(rule, rel, sets):
    """A rule field that a case's records carry only in another letter case. SQLite
    matches column names without regard to case, so every offline gate reads the
    record's field, but Lucene, Splunk and ES|QL do not: there the item never matches
    (a guard on it always holds). One problem per field."""
    problems, seen = [], set()
    fields = _rule_fields(rule)
    for source, name, kind, events in sets:
        keys = {k for e in events for k in e}
        for field in fields:
            if field in keys or field in seen:
                continue
            other = sorted(k for k in keys if k.lower() == field.lower())
            if other:
                seen.add(field)
                problems.append(Problem(
                    rel, source, name, kind, f"the rule reads `{field}`, and the records carry "
                    f"{', '.join(f'`{k}`' for k in other)}: SQLite matches column names without "
                    "regard to case, so the offline gates read that field, but Lucene, Splunk "
                    "and ES|QL do not. Write the field name as the log source writes it"))
    return problems


def _compare(rule, rel, source, name, kind, events, sql2, sql3):
    hits2 = _canon(sigma_eval.EventTable(events).hit_indices(sql2))
    table3 = sigma_eval.EventTable(events, three_valued=True)
    hits3 = _canon(table3.hit_indices(sql3))
    if hits2 == hits3:
        return _composition_errors(rule, rel, source, name, kind, events, table3, hits3)
    verdict = ("fires in two-valued logic, not in three-valued logic" if hits2 and not hits3
               else "fires in three-valued logic, not in two-valued logic" if hits3 and not hits2
               else "fires in both, but loses or adds hits in three-valued logic")
    gained = [h for h in hits3 if h not in hits2]
    lost = [h for h in hits2 if h not in hits3]
    lines = []
    if gained:
        lines.append(f"internal error: three-valued-only hit(s) {gained}; three-valued logic "
                     "cannot add a hit (report it)")
    if rule.is_correlation:
        lines += _explain_correlation(rule, events, lost)
    else:
        values = item_values(rule, table3)
        for (i,) in lost:
            lines.append(f"record #{i} is lost:")
            lines += ["  " + line for line in explain_lost(rule, events[i], values[i])]
    return [Problem(rel, source, name, kind, verdict, lines)]


def _composition_errors(rule, rel, source, name, kind, events, table3, hits3):
    """The items' three-valued values, composed in Kleene logic, must give the
    compiled three-valued query's hits (else the explanation cannot be trusted)."""
    if rule.is_correlation:
        return []
    values = item_values(rule, table3)
    composed = [[i] for i in range(len(events)) if kleene(rule.tree, values[i]) is True]
    if composed == hits3:
        return []
    return [Problem(rel, source, name, kind, "internal error: the items' three-valued values, "
                    f"composed through the condition, give hits {composed}; the compiled "
                    f"three-valued query gives {hits3} (report it)")]


def _explain_correlation(rule, events, lost):
    lines = [f"alert(s) lost: {lost} (event indices of each alert)"]
    t2 = sigma_eval.EventTable(events)
    t3 = sigma_eval.EventTable(events, three_valued=True)
    for ref, base in rule.bases.items():
        h2 = {i for h in t2.hit_indices(_base_sql(rule, ref, False)) for i in h}
        h3 = {i for h in t3.hit_indices(_base_sql(rule, ref, True)) for i in h}
        if h2 == h3:
            continue
        values = item_values(base, t3)
        for i in sorted(h2 - h3):
            lines.append(f"base {ref}: record #{i} is lost:")
            lines += ["  " + line for line in explain_lost(base, events[i], values[i])]
    return lines


def _absent_probe(rule, sets, sql2, sql3):
    """Fields of filter items and of negating items (`|neq`) whose absence from a firing
    positive record loses it in three-valued logic: [(field, source, name)] (first
    instance of each field)."""
    fields = list(dict.fromkeys(rule.item_field[a] for a in rule.atoms if rule.item_field[a]
                                and ("-" in rule.polarity[a] or rule.item_negates(a))))
    found = {}
    for source, name, kind, events in sets:
        if kind not in ("positive", "attack"):
            continue
        for i in sorted({i for h in sigma_eval.EventTable(events).hit_indices(sql2) for i in h}):
            for field in fields:
                if field in found or field not in events[i]:
                    continue
                dropped = {k: v for k, v in events[i].items() if k != field}
                if (sigma_eval.EventTable([dropped]).hit_indices(sql2)
                        and not sigma_eval.EventTable([dropped], three_valued=True)
                        .hit_indices(sql3)):
                    found[field] = (source, name)
    return [(f, *found[f]) for f in fields if f in found]


# ---- cloud fixtures ----------------------------------------------------------


def cloud_fixtures():
    """{abs rule path: [(source, name, kind, flat events)]} from the cloud MANIFEST."""
    import validate_cloud_detections as cloud
    out = {}
    for _trr, folder, fname, attack, benign, *_ in cloud.MANIFEST:
        path = os.path.abspath(os.path.join(cloud.SIGMA, folder, fname))
        for kind, rel in (("attack", attack), ("benign", benign)):
            events = cloud.load_fixture(os.path.join(cloud.FIX, rel))
            out.setdefault(path, []).append(("fixture", rel, kind, events))
    return out


# ---- reports -----------------------------------------------------------------


def run(paths, absent=False, fixtures=None):
    fixtures = cloud_fixtures() if fixtures is None else fixtures
    results = []
    for path in paths:
        try:
            results.append(check_rule(path, fixtures, absent))
        except Exception as e:  # noqa: BLE001 - one broken rule must not hide the others
            rel = os.path.relpath(path, SIGMA)
            results.append((rel, 0, [Problem(rel, "-", "-", "-",
                                             f"cannot check: {type(e).__name__}: {e}")], []))
    return results


def print_report(results, absent=False):
    failed = [r for r in results if r[2]]
    sets = sum(r[1] for r in results)
    for rel, count, problems, found in results:
        if not problems:
            print(f"ok    {rel}: {count} event set(s), same hits in two- and three-valued logic")
        for p in problems:
            where = f" :: {p.source} {p.kind} {p.name}" if p.source != "-" else ""
            print(f"FAIL  {rel}{where}: {p.detail}")
            for line in p.lines:
                print("        " + line)
        if absent:
            for field, source, name in found:
                print(f"note  {rel}: a record without {field} is lost in three-valued logic "
                      f"(dropped from {source} {name}); guard the filter if a record can lack it")
    print()
    if failed:
        print(f"FAILED: {len(failed)} of {len(results)} rule(s) are not null-safe: "
              + ", ".join(r[0] for r in failed) + ".")
        return 1
    print(f"OK: {len(results)} rule(s), {sets} event set(s): every hit is the same in two- "
          "and three-valued logic.")
    return 0


def write_json(path, results):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"ok": not any(r[2] for r in results),
                   "rules": [{"rule": rel, "event_sets": count,
                              "problems": [p.as_dict() for p in problems],
                              "absent": [{"field": f, "source": s, "name": n}
                                         for f, s, n in found]}
                             for rel, count, problems, found in results]}, fh, indent=2)
        fh.write("\n")


def write_markdown(path, results):
    failed = [r for r in results if r[2]]
    lines = ["## Null safety (two- vs three-valued logic)", ""]
    if failed:
        lines.append(f"**FAIL**: {len(failed)} of {len(results)} rule(s) are not null-safe: "
                     "they lose hits in three-valued logic (ES\\|QL and other SQL backends), "
                     "or a null guard, a null-safe copy or a field name is wrong.")
        lines += ["", "| rule | case or fixture | problem |", "|---|---|---|"]
        for rel, _, problems, _ in failed:
            for p in problems:
                detail = p.detail.replace("|", "\\|")
                lines.append(f"| `{rel}` | {p.source} {p.kind} `{p.name}` | {detail} |")
    else:
        lines.append(f"**OK**: {len(results)} rule(s), {sum(r[1] for r in results)} event "
                     "set(s): every hit is the same in two- and three-valued logic.")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n\n")


# ---- self-test ---------------------------------------------------------------


_SELF_TEST = [
    # (name, rule detection, cases, expect: None = holds, else a text the report has)
    ("not on a missing field loses the positive",
     {"sel": {"verb": "delete"}, "filter": {"dryRun|contains": "All"},
      "condition": "sel and not filter"},
     [("positive", [{"verb": "delete"}]),
      ("filtered", [{"verb": "delete", "dryRun": "All"}], ["filter.dryRun"])],
     "`not filter` is NULL (block filter):"),
    ("guarded with field: null holds",
     {"sel": {"verb": "delete"}, "filter": {"dryRun|contains": "All"},
      "sel_no_dry_run": {"dryRun": None},
      "condition": "sel and (sel_no_dry_run or not filter)"},
     [("positive", [{"verb": "delete"}]),
      ("filtered", [{"verb": "delete", "dryRun": "All"}], ["filter.dryRun"])],
     None),
    ("a regular expression on a missing field is NULL",
     {"sel": {"verb": "patch"}, "filter": {"verb": "patch", "uri|re": "dryRun=All"},
      "condition": "sel and not filter"},
     [("positive", [{"verb": "patch"}])],
     "filter.uri is NULL: uri = <absent>"),
    ("a filter on a field every record has holds",
     {"sel": {"verb": "delete"}, "filter": {"user": "system:gc"},
      "condition": "sel and not filter"},
     [("positive", [{"verb": "delete", "user": "alice"}])],
     None),
    ("a lost hit inside a case that still fires fails",
     {"sel": {"verb": "delete"}, "filter": {"dryRun": "All"},
      "condition": "sel and not filter"},
     [("positive", [{"verb": "delete", "dryRun": "None"}, {"verb": "delete"}])],
     "fires in both, but loses or adds hits"),
    ("a NULL nested under a double negation is named once",
     {"sel": {"verb": "delete"}, "agg": {"user": "system:agg"}, "beyond": {"rules": "x"},
      "condition": "sel and not (agg and not beyond)"},
     [("positive", [{"verb": "delete"}])],
     "`not (agg and not beyond)` is NULL"),
    ("a correlation base with an unguarded filter loses the alert",
     None, [("positive", [{"type": "A", "pid": 1, "timestamp": "2026-01-01T00:00:00Z"},
                          {"type": "B", "pid": 1, "timestamp": "2026-01-01T00:00:01Z"}])],
     "base b_a: record #0 is lost:"),
    ("a rule with no case fails", {"sel": {"verb": "delete"}, "condition": "sel"}, [],
     "no sidecar case and no cloud fixture"),
    ("a `|neq` item on a missing field is named",
     {"sel": {"verb": "delete", "dryRun|neq": "All"}, "condition": "sel"},
     [("positive", [{"verb": "delete"}])],
     "the negating item `sel.dryRun` (`|neq`) is NULL (block sel):"),
    ("a guard on a misspelt field fails",
     {"sel": {"verb": "delete"}, "filter": {"errorCode": "*"},
      "sel_no_error_code": {"errorCod": None},
      "condition": "sel and (sel_no_error_code or not filter)"},
     [("positive", [{"verb": "delete"}]),
      ("filtered", [{"verb": "delete", "errorCode": "AccessDenied"}], ["filter.errorCode"])],
     "`sel_no_error_code` (errorCod absent) is ORed with `not filter`, which reads errorCode: "
     "the names differ only in letter case or by a typo"),
    ("a guard on a field that differs only in case fails",
     {"sel": {"verb": "delete"}, "filter": {"dryRun|contains": "All"},
      "sel_no_dry_run": {"dryrun": None},
      "condition": "sel and (sel_no_dry_run or not filter)"},
     [("positive", [{"verb": "delete"}])],
     "`sel_no_dry_run` (dryrun absent) is ORed with `not filter`, which reads dryRun"),
    ("a near-named selection ORed with `not filter` fails",
     {"sel": {"verb": "delete"}, "filter": {"tag": "prod"}, "sel_no_tags": {"tags": None},
      "condition": "sel and (sel_no_tags or not filter)"},
     [("positive", [{"verb": "delete", "tag": "dev"}])],
     "write `not (filter and not sel_no_tags)`, which means the same"),
    ("the same selection written as `not (filter and not sel)` holds",
     {"sel": {"verb": "delete"}, "filter": {"tag": "prod"}, "sel_no_tags": {"tags": None},
      "condition": "sel and not (filter and not sel_no_tags)"},
     [("positive", [{"verb": "delete", "tag": "dev"}]),
      ("positive", [{"verb": "delete", "tag": "prod"}]),
      ("filtered", [{"verb": "delete", "tag": "prod", "tags": "a"}], ["filter.tag"])],
     None),
    ("a guard on a field that only some maps of its filter read fails",
     {"sel": {"verb": "delete"}, "filter": [{"dryRun": "All"}, {"uri|re": "dryRun=All"}],
      "sel_no_dry_run": {"dryRun": None},
      "condition": "sel and (sel_no_dry_run or not filter)"},
     [("positive", [{"verb": "delete", "uri": "/x"}])],
     "but not every map of that filter reads that field"),
    ("a `field: null` selection ORed with a filter on another field holds",
     {"sel": {"eventName": "ConsoleLogin"},
      "sel_no_mfa": {"additionalEventData.MFAUsed": None},
      "filter_sso": {"userIdentity.type": "SAMLUser"},
      "condition": "sel and (sel_no_mfa or not filter_sso)"},
     [("positive", [{"eventName": "ConsoleLogin", "userIdentity.type": "IAMUser",
                     "additionalEventData.MFAUsed": "No"}]),
      ("positive", [{"eventName": "ConsoleLogin", "userIdentity.type": "SAMLUser"}]),
      ("filtered", [{"eventName": "ConsoleLogin", "userIdentity.type": "SAMLUser",
                     "additionalEventData.MFAUsed": "No"}], ["filter_sso.userIdentity.type"])],
     None),
    ("a guard on several fields whose filter tests values fails",
     {"sel": {"eventName": "AddPermission"},
      "filter_scoped": [{"sourceArn|startswith": "arn:aws:s3:::example"},
                        {"principalOrgID": "o-example"}],
      "sel_unscoped": {"sourceArn": None, "principalOrgID": None},
      "condition": "sel and (sel_unscoped or not filter_scoped)"},
     [("positive", [{"eventName": "AddPermission"}]),
      ("filtered", [{"eventName": "AddPermission", "principalOrgID": "o-example"}],
       ["filter_scoped[1].principalOrgID"])],
     "`sel_unscoped` guards several fields at once (principalOrgID, sourceArn)"),
    ("a guard on several fields whose every map matches any value holds",
     {"sel": {"eventName": "AddPermission"},
      "filter_scoped": [{"sourceArn": "*"}, {"principalOrgID": "*"}],
      "sel_unscoped": {"sourceArn": None, "principalOrgID": None},
      "condition": "sel and (sel_unscoped or not filter_scoped)"},
     [("positive", [{"eventName": "AddPermission"}]),
      ("filtered", [{"eventName": "AddPermission", "principalOrgID": "o-example"}],
       ["filter_scoped[1].principalOrgID"])],
     None),
    ("a guard that also names a field the filter does not read fails",
     {"sel": {"verb": "delete"}, "filter": {"errorCode": "*"},
      "sel_no_error_code": {"errorCode": None, "errorCod": None},
      "condition": "sel and (sel_no_error_code or not filter)"},
     [("positive", [{"verb": "delete"}])],
     "but that filter reads no errorCod"),
    ("a rule field that the records carry in another letter case fails",
     {"sel": {"Verb": "delete"}, "condition": "sel"},
     [("positive", [{"verb": "delete"}])],
     "the rule reads `Verb`, and the records carry `verb`"),
    ("a null-safe copy of a filter whose maps read different fields holds",
     {"sel": {"verb": "delete"},
      "filter": [{"uri|re": "dryRun=All"}, {"body|contains": "All"}],
      "filter_uri": {"uri|re": "dryRun=All"}, "filter_body": {"body|contains": "All"},
      "sel_no_uri": {"uri": None}, "sel_no_body": {"body": None},
      "condition": "sel and not (filter and ((filter_uri and not sel_no_uri) or "
                   "(filter_body and not sel_no_body)))"},
     [("positive", [{"verb": "delete", "uri": "/x"}]),
      ("filtered", [{"verb": "delete", "uri": "/x?dryRun=All"}], ["filter[0].uri"])],
     None),
    ("the same filter without its copy loses the positive",
     {"sel": {"verb": "delete"},
      "filter": [{"uri|re": "dryRun=All"}, {"body|contains": "All"}],
      "condition": "sel and not filter"},
     [("positive", [{"verb": "delete", "uri": "/x"}])],
     "`not filter` is NULL (block filter):"),
    ("a copy that does not repeat its filter's maps fails",
     {"sel": {"verb": "delete"},
      "filter": [{"uri|re": "dryRun=All"}, {"body|contains": "All"}],
      "filter_uri": {"uri|re": "dryRun=All"}, "filter_body": {"body|contains": "all"},
      "sel_no_uri": {"uri": None}, "sel_no_body": {"body": None},
      "condition": "sel and not (filter and ((filter_uri and not sel_no_uri) or "
                   "(filter_body and not sel_no_body)))"},
     [("positive", [{"verb": "delete", "uri": "/x"}])],
     "has the shape of a null-safe copy"),
    ("terms that are not a copy, written as `not (<guard> or not <block>)`, hold",
     {"sel": {"verb": "delete"},
      "filter": [{"uri|re": "dryRun=All"}, {"body|contains": "All"}],
      "filter_uri": {"uri|re": "dryRun=All"}, "filter_body": {"body|contains": "all"},
      "sel_no_uri": {"uri": None}, "sel_no_body": {"body": None},
      "condition": "sel and not (filter and (not (sel_no_uri or not filter_uri) or "
                   "not (sel_no_body or not filter_body)))"},
     [("positive", [{"verb": "delete", "uri": "/x"}]),
      ("positive", [{"verb": "delete", "body": "None"}]),
      ("filtered", [{"verb": "delete", "uri": "/x?dryRun=All"}], ["filter[0].uri"])],
     None),
    ("a copy whose guard names a field its block does not read fails",
     {"sel": {"verb": "delete"},
      "filter": [{"uri|re": "dryRun=All"}, {"body|contains": "All"}],
      "filter_uri": {"uri|re": "dryRun=All"}, "filter_body": {"body|contains": "All"},
      "sel_no_uri": {"uri": None}, "sel_no_body": {"Body": None},
      "condition": "sel and not (filter and ((filter_uri and not sel_no_uri) or "
                   "(filter_body and not sel_no_body)))"},
     [("positive", [{"verb": "delete", "uri": "/x"}])],
     "`sel_no_body` guards Body, which `filter_body` does not read"),
    ("a copy that reads a field no guard of its term covers fails",
     {"sel": {"verb": "delete"},
      "filter": [{"uri|re": "dryRun=All", "kind": "DeleteOptions"}, {"body|contains": "All"}],
      "filter_uri": {"uri|re": "dryRun=All", "kind": "DeleteOptions"},
      "filter_body": {"body|contains": "All"},
      "sel_no_uri": {"uri": None}, "sel_no_body": {"body": None},
      "condition": "sel and not (filter and ((filter_uri and not sel_no_uri) or "
                   "(filter_body and not sel_no_body)))"},
     [("positive", [{"verb": "delete", "uri": "/x?dryRun=All", "kind": "Status"}])],
     "`filter_uri` also reads kind, which no guard of its term covers"),
    ("a copy with one guard per field it reads holds",
     {"sel": {"verb": "delete"},
      "filter": [{"uri|re": "dryRun=All", "kind": "DeleteOptions"}, {"body|contains": "All"}],
      "filter_uri": {"uri|re": "dryRun=All", "kind": "DeleteOptions"},
      "filter_body": {"body|contains": "All"},
      "sel_no_uri": {"uri": None}, "sel_no_kind": {"kind": None}, "sel_no_body": {"body": None},
      "condition": "sel and not (filter and ((filter_uri and not sel_no_uri and not sel_no_kind)"
                   " or (filter_body and not sel_no_body)))"},
     [("positive", [{"verb": "delete", "uri": "/x?dryRun=All", "kind": "Status"}]),
      ("positive", [{"verb": "delete", "uri": "/x?dryRun=All"}]),
      ("filtered", [{"verb": "delete", "uri": "/x?dryRun=All", "kind": "DeleteOptions"}],
       ["filter[0].kind"])],
     None),
    ("a copy term whose guard names several fields fails",
     {"sel": {"verb": "delete"},
      "filter": [{"uri|re": "dryRun=All", "kind": "DeleteOptions"}, {"body|contains": "All"}],
      "filter_uri": {"uri|re": "dryRun=All", "kind": "DeleteOptions"},
      "filter_body": {"body|contains": "All"},
      "sel_no_uri_kind": {"uri": None, "kind": None}, "sel_no_body": {"body": None},
      "condition": "sel and not (filter and ((filter_uri and not sel_no_uri_kind) or "
                   "(filter_body and not sel_no_body)))"},
     [("positive", [{"verb": "delete", "uri": "/x?dryRun=All", "kind": "Status"}])],
     "in a copy term, `not sel_no_uri_kind` holds where any one of them is present"),
    ("`<block> and not <null block>` terms that copy no block hold",
     {"sel": {"eventName": "AssumeRole"},
      "sel_role": {"userIdentity.type": "AssumedRole"},
      "sel_user": {"userIdentity.type": "IAMUser"},
      "sel_no_ctx": {"userIdentity.sessionContext.sourceIdentity": None},
      "sel_no_key": {"userIdentity.accessKeyId": None},
      "condition": "sel and ((sel_role and not sel_no_ctx) or (sel_user and not sel_no_key))"},
     [("positive", [{"eventName": "AssumeRole", "userIdentity.type": "AssumedRole",
                     "userIdentity.sessionContext.sourceIdentity": "x"}]),
      ("near-miss", [{"eventName": "AssumeRole", "userIdentity.type": "Root",
                      "userIdentity.sessionContext.sourceIdentity": "x"}],
       ["sel_role.userIdentity.type"])],
     None),
]

_CORRELATION = [
    {"title": "a", "name": "b_a", "logsource": {"product": "test"},
     "detection": {"sel": {"type": "A"}, "filter": {"comm": "ok"},
                   "condition": "sel and not filter"}},
    {"title": "b", "name": "b_b", "logsource": {"product": "test"},
     "detection": {"sel": {"type": "B"}, "condition": "sel"}},
    {"title": "c", "correlation": {"type": "temporal_ordered", "rules": ["b_a", "b_b"],
                                   "group-by": ["pid"], "timespan": "5s"}},
]


def self_test():
    import yaml
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for n, (name, detection, cases, expect) in enumerate(_SELF_TEST):
            path = os.path.join(tmp, f"rule{n}.yml")
            docs = _CORRELATION if detection is None else [
                {"title": name, "logsource": {"product": "test"}, "detection": detection}]
            with open(path, "w", encoding="utf-8") as fh:
                yaml.safe_dump_all(docs, fh, sort_keys=False)
            with open(rule_cases.cases_path(path), "w", encoding="utf-8") as fh:
                for i, case in enumerate(cases):
                    entry = {"name": f"c{i}", "kind": case[0], "why": name, "events": case[1]}
                    if len(case) > 2:
                        entry["breaks"] = case[2]
                    fh.write(json.dumps(entry) + "\n")
            if not cases:
                os.remove(rule_cases.cases_path(path))
            _, _, problems, _ = check_rule(path, {})
            text = "\n".join([p.detail for p in problems]
                             + [line for p in problems for line in p.lines])
            ok = (not problems) if expect is None else (bool(problems) and expect in text)
            failures += not ok
            print(f"{'ok  ' if ok else 'FAIL'}  {name}"
                  + ("" if ok else f"\n        expected {expect!r}, got:\n        "
                     + (text.replace("\n", "\n        ") or "(no problem)")))
        # --absent names a filter field that every positive carries.
        path = os.path.join(tmp, "absent.yml")
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump({"title": "absent", "logsource": {"product": "test"},
                            "detection": {"sel": {"verb": "delete"},
                                          "filter": {"user": "system:gc"},
                                          "condition": "sel and not filter"}}, fh)
        with open(rule_cases.cases_path(path), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"name": "p", "kind": "positive", "why": "-",
                                 "events": [{"verb": "delete", "user": "alice"}]}) + "\n")
        _, _, problems, found = check_rule(path, {}, absent=True)
        ok = not problems and [f for f, _, _ in found] == ["user"]
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  --absent names the filter field every positive "
              f"carries" + ("" if ok else f" (got {problems and problems[0].detail} {found})"))
        helper_checks = _self_test_helpers(tmp)
    failures += sum(1 for ok in helper_checks if not ok)
    total = len(_SELF_TEST) + 1 + len(helper_checks)
    print()
    print("self-test: " + (f"FAILED ({failures} of {total} check(s))" if failures else
                           f"all {total} checks hold"))
    return 1 if failures else 0


# Rules for the null-helper checks: a pure-surface CloudTrail rule (eventSource and
# eventName are surface fields), with one filter on errorCode and one on a scope key.
_SURFACE = {"selection": {"eventSource": "ssm.amazonaws.com",
                          "eventName": "ModifyDocumentPermission"},
            "filter_failed": {"errorCode": "*"},
            "filter_failed_denied": {"errorCode": "AccessDenied"},
            "filter_scoped": [{"scope": "*"}, {"policy|contains": "aws:SourceArn"}],
            "filter_scope_key": {"scope": "*"},
            "filter_scope_policy": {"policy|contains": "aws:SourceArn"},
            "sel_no_error_code": {"errorCode": None},
            "sel_no_scope": {"scope": None},
            "sel_no_policy": {"policy": None},
            "sel_list_guard": [{"errorCode": None}, {"scope": None}],
            "filter_pair": [{"scope": "*", "kind": "Bucket"}, {"policy|contains": "aws:SourceArn"}],
            "filter_pair_scope": {"scope": "*", "kind": "Bucket"},
            "sel_no_kind": {"kind": None},
            "id_null_item": {"principalId|startswith": "AIDA", "accessKeyId": [None, ""]}}
_COPY = ("not (filter_scoped and ((filter_scope_key and not sel_no_scope) or "
         "(filter_scope_policy and not sel_no_policy)))")

_HELPER_CASES = [
    # (name, condition, the helper atoms expected, discriminating atoms expected)
    ("a guard ORed with `not <block>`", "selection and (sel_no_error_code or not filter_failed)",
     ["sel_no_error_code.errorCode"], []),
    ("a guard ORed with `not 1 of filter_*`",
     "selection and (sel_no_error_code or not 1 of filter_failed*)",
     ["sel_no_error_code.errorCode"], []),
    ("a guard ORed with `not (a or b)`",
     "selection and (sel_no_error_code or not (filter_failed or filter_failed_denied))",
     ["sel_no_error_code.errorCode"], []),
    ("a guard ORed with `not (a and not b)` (it falsifies a; b is read twice negated)",
     "selection and (sel_no_error_code or not (filter_failed and not filter_scope_key))",
     ["sel_no_error_code.errorCode"], ["filter_scope_key.scope"]),
    ("a null-safe copy and its guards", "selection and " + _COPY,
     ["filter_scope_key.scope", "sel_no_scope.scope", "filter_scope_policy.policy",
      "sel_no_policy.policy"], []),
    ("a null-safe copy with one guard per field of a map",
     "selection and not (filter_pair and ((filter_pair_scope and not sel_no_scope and not "
     "sel_no_kind) or (filter_scope_policy and not sel_no_policy)))",
     ["filter_pair_scope.kind", "filter_pair_scope.scope", "filter_scope_policy.policy",
      "sel_no_kind.kind", "sel_no_policy.policy", "sel_no_scope.scope"], []),
    ("`<block> and not <guard>` terms that copy no block are no helpers",
     "selection and ((filter_scope_key and not sel_no_scope) or "
     "(filter_scope_policy and not sel_no_policy))", [],
     ["filter_scope_key.scope", "filter_scope_policy.policy"]),
    ("a list of guard maps is no guard (it holds where the filter can hold)",
     "selection and (sel_list_guard or not filter_failed)", [],
     ["sel_list_guard[0].errorCode", "sel_list_guard[1].scope"]),
    ("a `field: null` item inside a selection is no guard",
     "selection and id_null_item and not filter_failed", [],
     ["id_null_item.principalId", "id_null_item.accessKeyId"]),
    ("a guard that the condition also reads elsewhere is no helper",
     "selection and (sel_no_error_code or not filter_failed) and sel_no_error_code", [],
     ["sel_no_error_code.errorCode"]),
]


def _self_test_helpers(tmp):
    """sigma_explain.null_helpers(), check_sufficiency's stripped grading,
    rule_cases' `breaks` check and the validators' miss explanations and benign
    grading on null guards and null-safe copies. Returns one bool per check."""
    import check_sufficiency  # noqa: E402  (the grader the helpers are left out of)
    results = []

    def check(name, ok, detail):
        results.append(ok)
        print(f"{'ok  ' if ok else 'FAIL'}  helpers: {name}" + ("" if ok else f" ({detail})"))

    def rule_of(condition):
        return sigma_explain.from_docs([{"title": "helpers", "logsource": {"product": "aws"},
                                         "detection": dict(_SURFACE, condition=condition)}])

    for name, condition, helpers, disc in _HELPER_CASES:
        rule = rule_of(condition)
        got = sorted(rule.null_helpers())
        got_disc = check_sufficiency.discriminating_atoms(rule)
        check(name, got == sorted(helpers) and got_disc == disc
              and not rule.null_guard_issues(),
              f"helpers {got}, discriminating {got_disc}, issues {rule.null_guard_issues()}")
    rule = rule_of("selection and (sel_no_error_code or not filter_failed) and " + _COPY)
    positive = {"eventSource": "ssm.amazonaws.com", "eventName": "ModifyDocumentPermission"}
    for atom, event in (("sel_no_error_code.errorCode", dict(positive, errorCode="AccessDenied")),
                        ("filter_scope_policy.policy", dict(positive, policy="aws:SourceArn"))):
        res = rule_cases.run_case(rule, {"name": "t", "kind": "filtered", "why": "-",
                                         "events": [event], "breaks": [atom]})
        check(f"rule_cases rejects `breaks: [{atom}]`",
              not res.ok and "null-safety item" in res.detail, res.detail)
    res = rule_cases.run_case(rule, {"name": "t", "kind": "filtered", "why": "-",
                                     "events": [dict(positive, errorCode="AccessDenied")],
                                     "breaks": ["filter_failed.errorCode"]})
    check("rule_cases accepts the guarded filter's own item", res.ok, res.detail)
    # The validators' diagnostics grade the rule without its helpers too: a record that
    # the guarded filter suppresses is `filtered` on the filter's item alone, and no
    # explanation names a guard as an item to flip.
    import validate_cloud_detections as cloud  # noqa: E402
    import validate_apiserver_detections as apiserver  # noqa: E402
    import validate_k8s_detections as k8s  # noqa: E402
    rule = rule_of("selection and (sel_no_error_code or not filter_failed)")
    denied = dict(positive, errorCode="AccessDenied")
    _, detail = cloud.grade_benign(rule, [denied])
    check("validate_cloud grades a benign record on the filter, not the guard",
          detail["kinds"] == {"filtered": 1} and detail["exercised"] == ["filter_failed.errorCode"]
          and all("sel_no_" not in a for a in detail["exercised"] + detail["unexercised"]),
          detail)
    lines = cloud.explain_attack_miss(rule, [denied])
    check("validate_cloud explains a miss without the guard",
          not any("sel_no_error_code" in line for line in lines), lines)
    path = os.path.join(tmp, "helpers_k8s.yml")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"title": "helpers", "logsource": {"product": "kubernetes", "service": "audit"},
                   "detection": {"sel": {"verb": "delete"},
                                 "filter": {"requestObject.dryRun|contains": "All"},
                                 "sel_no_dry_run": {"requestObject.dryRun": None},
                                 "condition": "sel and (sel_no_dry_run or not filter)"}}, fh)
    record = [{"verb": "delete", "requestObject.dryRun": '["All"]', "requestURI": "/x"}]
    for name, lines in (
            ("validate_apiserver", apiserver.explain_gated_miss(path, record, lambda e: True,
                                                                "x", [])),
            ("validate_k8s", k8s.explain_gated_miss(path, record, lambda e: True, []))):
        check(f"{name} explains a miss without the guard",
              not any("sel_no_dry_run" in line for line in lines)
              and any("filtered; one flip would fire it: filter.requestObject.dryRun" in line
                      for line in lines), lines)
    return results


def main():
    ap = argparse.ArgumentParser(description="Fail a rule whose hits differ between two- and "
                                             "three-valued logic.")
    ap.add_argument("rules", nargs="*", help="rule files (default: every rule)")
    ap.add_argument("--absent", action="store_true",
                    help="also list filter fields whose absence from a positive record loses "
                         "it in three-valued logic (information only)")
    ap.add_argument("--json", metavar="PATH", help="write the result as JSON")
    ap.add_argument("--markdown", metavar="PATH",
                    help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    ap.add_argument("--self-test", action="store_true",
                    help="check the gate on constructed good and bad rules, and exit")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    paths = args.rules or sorted(glob.glob(os.path.join(SIGMA, "*", "*.yml")))
    results = run(paths, absent=args.absent)
    rc = print_report(results, absent=args.absent)
    if args.json:
        write_json(args.json, results)
    if args.markdown:
        write_markdown(args.markdown, results)
    return rc


if __name__ == "__main__":
    sys.exit(main())
