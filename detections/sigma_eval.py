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
import re
import sqlite3
import sys

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


def evaluate(sql, events):
    """Run a compiled rule over flat event dicts.

    Returns one list of events per hit: a plain rule yields one hit per matching
    event, a correlation rule one hit per alert, holding every event that
    contributed to it. A field no event carries reads as NULL (matches nothing),
    exactly as it would in a log store that never saw the field.
    """
    db = sqlite3.connect(":memory:")
    columns = sorted({k for e in events for k in e} - {_ROWID})
    db.execute(f"CREATE TABLE logs ({_ROWID} INTEGER PRIMARY KEY"
               + "".join(f", {_quote(c)}" for c in columns) + ")")
    for rowid, event in enumerate(events):
        cols = [c for c in columns if c in event]
        db.execute(
            f"INSERT INTO logs ({_ROWID}{''.join(', ' + _quote(c) for c in cols)}) "
            f"VALUES (?{', ?' * len(cols)})",
            [rowid] + [event[c] for c in cols])

    while True:
        try:
            cur = db.execute(sql)
            break
        except sqlite3.OperationalError as e:
            missing = re.match(r"no such column: (.+)$", str(e))
            if not missing:
                raise
            db.execute(f"ALTER TABLE logs ADD COLUMN {_quote(missing.group(1))}")

    names = [d[0] for d in cur.description]
    rows = cur.fetchall()
    if "event_ids" in names:  # correlation alert rows
        idx = names.index("event_ids")
        return [[events[int(eid.rsplit(":", 1)[1])] for eid in json.loads(row[idx])]
                for row in rows]
    idx = names.index(_ROWID)
    return [[events[row[idx]]] for row in rows]
