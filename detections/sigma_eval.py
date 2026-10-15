"""
Evaluate Sigma rules with a real Sigma backend instead of a hand-written matcher.

Shared by the three validators. Each rule file is compiled by pySigma's SQLite
backend into the query a Sigma-driven engine would run, the events are loaded
into an in-memory SQLite table named `logs`, and the query is executed. So a
rule passes here only if its Sigma semantics actually match the events — the
same answer any conforming backend would give.

Correlation rules (Sigma v2 `correlation:` with their base rules in the same
file) are supported. Their result rows name the evidence events, so a caller
always gets back the concrete events behind every hit and can check where they
came from.
"""

import json
import os
import re
import sqlite3
import sys

# The gates run as `python3 detections/<script>.py`, so detections/ is sys.path[0]
# and the rule directory detections/sigma/ joins pySigma's `sigma` namespace package
# AHEAD of site-packages: a collection.py (or a package, .pyc, .so, ...) dropped
# there would replace pySigma's own module inside every gate and validator. So
# before pySigma is imported, the rule directory must hold only rule material:
# T<id>/ directories of *.yml, *.cases.jsonl and *.md files, nothing else.
_RULE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigma")
_TECHNIQUE_DIR = re.compile(r"T\d{4}(\.\d{3})?")
_RULE_MATERIAL = re.compile(r".+\.(yml|cases\.jsonl|md)")


def _rule_dir_intruders():
    """Entries under detections/sigma/ that are not rule material."""
    bad = []
    try:
        entries = sorted(os.scandir(_RULE_DIR), key=lambda e: e.name)
    except FileNotFoundError:
        return bad
    for entry in entries:
        if not (entry.is_dir(follow_symlinks=False) and _TECHNIQUE_DIR.fullmatch(entry.name)):
            bad.append(entry.name)
            continue
        for item in sorted(os.scandir(entry.path), key=lambda e: e.name):
            if not (item.is_file(follow_symlinks=False) and _RULE_MATERIAL.fullmatch(item.name)):
                bad.append(f"{entry.name}/{item.name}")
    return bad


_intruders = _rule_dir_intruders()
if _intruders:
    sys.exit("refusing to import pySigma: detections/sigma/ may hold only T<id>/ "
             "directories of *.yml, *.cases.jsonl and *.md files, because it shares "
             "the `sigma` package namespace with pySigma and anything importable there "
             "would shadow pySigma's own modules. Move or delete:\n  "
             + "\n  ".join(f"detections/sigma/{p}" for p in _intruders))

try:
    from sigma.backends.sqlite import sqliteBackend
    from sigma.collection import SigmaCollection
except ImportError:
    sys.exit("pySigma is required: pip install -r detections/requirements.txt")

_ROWID = "_rowid"  # INTEGER PRIMARY KEY, so it aliases SQLite's rowid


def compile_rule(path):
    """Compile one rule file to its single SQL query.

    A file holds either one plain rule or one correlation rule plus the base
    rules it references (the base rules generate no query of their own).
    """
    with open(path, encoding="utf-8") as fh:
        collection = SigmaCollection.from_yaml(fh.read())
    queries = sqliteBackend().convert(collection)
    if len(queries) != 1:
        raise ValueError(f"expected one query from {path}, got {len(queries)}")
    return queries[0]


def flatten(obj, prefix=""):
    """Nested dict -> {"a.b.c": value}, the dotted field names Sigma rules use.

    Lists become JSON text so they stay matchable with |contains.
    """
    out = {}
    for key, val in obj.items():
        name = f"{prefix}{key}"
        if isinstance(val, dict):
            out.update(flatten(val, f"{name}."))
        elif isinstance(val, list):
            out[name] = json.dumps(val)
        else:
            out[name] = val
    return out


def _quote(col):
    return '"' + col.replace('"', '""') + '"'


class EventTable:
    """Flat event dicts loaded once into an in-memory `logs` table.

    Load a large event set (a benign corpus slice, a long audit log) once and run
    many compiled rules over it, instead of rebuilding the table per rule.
    """

    def __init__(self, events):
        self.events = events
        self.db = sqlite3.connect(":memory:")
        # pySigma's SQLite backend compiles a `|re` match to the SQL `REGEXP`
        # operator, which SQLite leaves unimplemented by default. Register it with
        # Python's `re` (full syntax, including look-around) so `|re` rules
        # evaluate. `X REGEXP Y` calls regexp(Y, X), i.e. regexp(pattern, value).
        self.db.create_function(
            "regexp", 2,
            lambda pattern, value: 1 if value is not None and re.search(pattern, str(value)) else 0)
        columns = sorted({k for e in events for k in e} - {_ROWID})
        # SQLite column names are case-insensitive: 'level' and 'Level' would be one
        # column (a cryptic "duplicate column name" error), and a rule field would
        # match an event key that differs only by case, which a case-sensitive SIEM
        # would not. Refuse the collision plainly instead.
        folded = {}
        for col in columns:
            folded.setdefault(col.lower(), []).append(col)
        clashes = [names for names in folded.values() if len(names) > 1]
        if clashes:
            raise ValueError("event keys that differ only by case cannot share one table: "
                             + "; ".join(" / ".join(n) for n in clashes)
                             + " (score or evaluate these log shapes separately)")
        self.db.execute(f"CREATE TABLE logs ({_ROWID} INTEGER PRIMARY KEY"
                        + "".join(f", {_quote(c)}" for c in columns) + ")")
        for rowid, event in enumerate(events):
            cols = [c for c in columns if c in event]
            self.db.execute(
                f"INSERT INTO logs ({_ROWID}{''.join(', ' + _quote(c) for c in cols)}) "
                f"VALUES (?{', ?' * len(cols)})",
                [rowid] + [event[c] for c in cols])

    def _execute(self, sql):
        while True:
            try:
                return self.db.execute(sql)
            except sqlite3.OperationalError as e:
                missing = re.match(r"no such column: (.+)$", str(e))
                if not missing:
                    raise
                self.db.execute(f"ALTER TABLE logs ADD COLUMN {_quote(missing.group(1))}")

    def hit_indices(self, sql):
        """One list of event indices per hit (see evaluate())."""
        cur = self._execute(sql)
        names = [d[0] for d in cur.description]
        rows = cur.fetchall()
        if "event_ids" in names:  # correlation alert rows
            idx = names.index("event_ids")
            return [[int(eid.rsplit(":", 1)[1]) for eid in json.loads(row[idx])]
                    for row in rows]
        idx = names.index(_ROWID)
        return [[row[idx]] for row in rows]

    def hits(self, sql):
        return [[self.events[i] for i in hit] for hit in self.hit_indices(sql)]


def evaluate(sql, events):
    """Run a compiled rule over flat event dicts.

    Returns one list of events per hit: a plain rule yields one hit per matching
    event, a correlation rule one hit per alert, holding every event that
    contributed to it. A field no event carries reads as NULL (matches nothing),
    exactly as it would in a log store that never saw the field.
    """
    return EventTable(events).hits(sql)
