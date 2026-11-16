"""
Evaluate Sigma rules with a real Sigma backend instead of a hand-written matcher.

Shared by the validators and the gates. Each rule file is compiled by pySigma's
SQLite backend into one query, the events are loaded into an in-memory SQLite
table named `logs`, and the query is executed. So a rule passes here only if the
query of a real Sigma backend matches the events.

This is ONE backend on ONE representation of the events, not the answer of every
backend: detections/SEMANTICS.md says what this oracle decides (the JSON text of
a list, letter case for each modifier, a missing field, the regex dialect) and
what other stores and backends do. The options of flatten() and EventTable below
change one of those decisions at a time; detections/check_variants.py runs every
case and fixture with each of them. The defaults are what every validator uses.

Correlation rules (Sigma v2 `correlation:` with their base rules in the same
file) are supported. Their result rows name the evidence events, so a caller
always gets back the concrete events behind every hit and can check where they
came from.
"""

import importlib.machinery
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
# No name there may start with a dot: the gates find the rules with the globs
# */*.yml and */*.cases.jsonl, which skip such a name, so a rule in a dotfile
# would pass every gate unchecked. R0 of check_sufficiency.py refuses the same
# names (a gate test plants each kind of name and compares the two lists), and
# rule_files() below lists the rules by the same rule.
# A module named `sigma` NEXT TO the rule directory is worse: in one sys.path entry
# a module (sigma.py, a sourceless sigma.pyc, sigma.so, ...) wins over a namespace
# portion, so it replaces pySigma whole. So detections/ may hold nothing else named
# sigma.* (nor __pycache__/sigma.*), in any letter case.
# The same holds for every other module a gate imports from site-packages or the
# stdlib: a sourceless yaml.pyc (or a yaml.so) in detections/ replaces PyYAML for
# every gate, unreviewable in a diff and hidden locally by .gitignore's *.pyc. So no
# file directly in detections/ may carry a bytecode or extension-module suffix
# (importlib.machinery.BYTECODE_SUFFIXES + EXTENSION_SUFFIXES), in any letter case.
# This runs when sigma_eval is first imported, so it cannot stop a module that a
# script imports before sigma_eval, nor a plain-source detections/<name>.py.
_DETECTIONS = os.path.dirname(os.path.abspath(__file__))
_RULE_DIR = os.path.join(_DETECTIONS, "sigma")
_TECHNIQUE_DIR = re.compile(r"T\d{4}(\.\d{3})?")
_RULE_MATERIAL = re.compile(r"[^.][^/]*\.(yml|cases\.jsonl|md)")
_COMPILED_SUFFIXES = tuple(s.lower() for s in importlib.machinery.BYTECODE_SUFFIXES
                           + importlib.machinery.EXTENSION_SUFFIXES)


def _scan_rule_dir():
    """(material, bad): the rule material under detections/sigma/ as `T<id>/<name>`
    paths, and the entries that are not rule material, in the order of the walk
    (each directory sorted by name)."""
    material, bad = [], []
    try:
        entries = sorted(os.scandir(_RULE_DIR), key=lambda e: e.name)
    except FileNotFoundError:
        return material, bad
    for entry in entries:
        if (entry.is_file(follow_symlinks=False) and entry.name.endswith(".md")
                and not entry.name.startswith(".")):
            continue  # a top-level README cannot shadow a module
        if not (entry.is_dir(follow_symlinks=False) and _TECHNIQUE_DIR.fullmatch(entry.name)):
            bad.append(entry.name)
            continue
        for item in sorted(os.scandir(entry.path), key=lambda e: e.name):
            name = f"{entry.name}/{item.name}"
            if item.is_file(follow_symlinks=False) and _RULE_MATERIAL.fullmatch(item.name):
                material.append(name)
            else:
                bad.append(name)
    return material, bad


def _rule_dir_intruders():
    """Entries under detections/sigma/ that are not rule material."""
    return _scan_rule_dir()[1]


def rule_files():
    """Every rule file, as a `T<id>/<stem>.yml` path relative to detections/sigma/, in
    the order of the walk of the import guard: the rule material that ends in .yml.
    A name that the guard refuses is never in the list (a file that appeared after
    the import, too)."""
    return [p for p in _scan_rule_dir()[0] if p.endswith(".yml")]


def _sibling_intruders():
    """Entries of detections/ (and detections/__pycache__/) named sigma.*, and entries
    of detections/ named as compiled bytecode or an extension module (*.pyc, *.so, ...)."""
    bad = []
    for sub in ("", "__pycache__"):
        try:
            names = sorted(os.listdir(os.path.join(_DETECTIONS, sub)))
        except (FileNotFoundError, NotADirectoryError):
            continue
        bad += [f"{sub}/{n}" if sub else n for n in names
                if n.lower().startswith("sigma.")
                or (not sub and n.lower().endswith(_COMPILED_SUFFIXES))]
    return bad


_intruders = ([f"sigma/{p}" for p in _rule_dir_intruders()]
              + _sibling_intruders())
if _intruders:
    sys.exit("refusing to import pySigma: detections/sigma/ may hold only *.md files "
             "and T<id>/ directories of *.yml, *.cases.jsonl and *.md files, and no name "
             "there may start with a dot (the gates find the rules with the globs */*.yml "
             "and */*.cases.jsonl, which skip such a name, so no gate would check a rule in "
             "it); nothing else in detections/ may be named sigma.* (sigma.py, sigma.pyc, "
             "sigma.so, sigma.pth, __pycache__/sigma.*, ...), because the rule directory "
             "shares the `sigma` package namespace with pySigma: anything importable there would "
             "shadow pySigma's own modules, and a `sigma` module beside it would replace "
             "pySigma whole. Nor may any file in detections/ be compiled bytecode or an "
             "extension module (" + ", ".join("*" + s for s in _COMPILED_SUFFIXES) + "): "
             "a sourceless module there (yaml.pyc, ...) would replace the module of that "
             "name in every gate. Move or delete:\n  "
             + "\n  ".join(f"detections/{p}" for p in _intruders))

try:
    from sigma.backends.sqlite import sqliteBackend
    from sigma.collection import SigmaCollection
except ImportError:
    sys.exit("pySigma is required: pip install -r detections/requirements.txt")

_ROWID = "_rowid"  # INTEGER PRIMARY KEY, so it aliases SQLite's rowid

# SQLite compares two identifiers (two column names) with the 26 ASCII letters folded
# to one letter case, and every other character as it is: `"A"` and `"a"` are one
# column name, `"Ä"` and `"ä"` are two (str.lower() folds both pairs, and also maps
# the Kelvin sign U+212A to `k`). fold() is that comparison.
_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_FOLDED = {}  # key -> fold(key): the keys of a log repeat in each event


def fold(name):
    """A column name as SQLite compares it: the ASCII letters in lower case, each
    other character as it is."""
    folded = _FOLDED.get(name)
    if folded is None:
        folded = _FOLDED[name] = name.translate(_ASCII_FOLD)
    return folded


# The names that SQLite reads as the row id of the table and that the queries on the
# table read. A key with such a name (in any letter case of its ASCII letters) would
# be a column that hides the row id: `_rowid` is the row id column of the table, which
# hit_indices() reads; `rowid` is the name by which the correlation queries of pySigma
# read the row id (its backend option event_id_field). SQLite has two more names of
# the row id, `oid` and `_rowid_`; no query reads them, so a key with such a name is
# an ordinary column.
RESERVED = {
    _ROWID: "is the name of the row id column of the table",
    "rowid": "is the name by which the correlation queries read the row id",
}
_INT64 = (-(1 << 63), (1 << 63) - 1)  # the range of an INTEGER of SQLite
_FINITE = (-float("inf"), float("inf"))


def _surrogate(text):
    """The first lone surrogate of a str (U+D800 to U+DFFF), or None. UTF-8 cannot
    encode it, so SQLite cannot hold such a text: a JSON escape such as \\ud800 gives
    one."""
    if text.isascii():
        return None
    return next((ch for ch in text if "\ud800" <= ch <= "\udfff"), None)


def _key_problem(key):
    """The text of a problem of one key that no column name of SQLite can be, or None:
    a key that holds U+0000 (NUL) or a lone surrogate."""
    if "\x00" in key:
        return f"the key {key!r} holds U+0000 (NUL), which no column name of SQLite can hold"
    ch = _surrogate(key)
    if ch is not None:
        return (f"the key {key!r} holds the lone surrogate U+{ord(ch):04X}, which is not "
                "text of UTF-8, so SQLite cannot hold it")
    return None


class EventError(ValueError):
    """An event that one EventTable cannot hold (event_problem()). `index` is the
    position of the event in the list (from 0), `keys` the keys of the problem, and
    `problem` its text. The message names the event (from 1) and the keys."""

    def __init__(self, index, count, keys, problem):
        self.index, self.keys, self.problem = index, tuple(keys), problem
        super().__init__(f"event {index + 1} of {count}: {problem}")


def key_clashes(event):
    """The groups of keys of one flat event that differ only in the letter case of
    their ASCII letters (fold()): SQLite reads the keys of each group as one column
    name, so one row cannot hold a value for each. Each group is a sorted tuple of two
    keys or more; the groups are sorted. Keys of this kind in DIFFERENT events share
    one column of the table, as a rule field reads them (detections/SEMANTICS.md,
    "Field names")."""
    if len({fold(key) for key in event}) == len(event):
        return []
    groups = {}
    for key in event:
        groups.setdefault(fold(key), []).append(key)
    return sorted(tuple(sorted(keys)) for keys in groups.values() if len(keys) > 1)


def event_problem(event):
    """None when one EventTable can hold the flat event (a dict, as flatten() gives
    it); else (keys, text) of its first problem:

      - a key that SQLite reads as a name of the row id that the queries read
        (RESERVED: _rowid, rowid, in any letter case of the ASCII letters);
      - a key that holds U+0000 (NUL) or a lone surrogate (no column name of SQLite
        can hold it);
      - keys that differ only in the letter case of their ASCII letters
        (key_clashes());
      - a value that SQLite does not hold as it is: an integer outside 64 bits (an
        INTEGER of SQLite), a number that is not finite (NaN, Infinity: JSON has no
        such number, and SQLite stores NaN as NULL), a text with a lone surrogate.

    Each loader of records asks this of each event before an EventTable gets it, and
    EventTable refuses an event with a problem (EventError): the loaders and the
    table refuse the same events."""
    names = {fold(key) for key in event}
    if not names.isdisjoint(RESERVED):
        key = min(key for key in event if fold(key) in RESERVED)
        return (key,), (f"the key {key} {RESERVED[fold(key)]} ({fold(key)}, in any letter "
                        "case of the ASCII letters)")
    for key in event:
        problem = _key_problem(key)
        if problem:
            return (key,), problem
    if len(names) != len(event):
        keys = key_clashes(event)[0]
        return keys, ("keys that differ only by case: " + " / ".join(keys)
                      + ", which SQLite reads as one column name")
    low, high = _INT64
    for key, value in event.items():
        kind = type(value)  # a bool is not of the type int
        if kind is int:
            if not low <= value <= high:
                return (key,), (f"the value of {key} is an integer outside the 64 bits of an "
                                "INTEGER of SQLite")
        elif kind is float:
            if not _FINITE[0] < value < _FINITE[1]:  # NaN compares false
                return (key,), (f"the value of {key} is {_json_number(value)}, a number that "
                                "JSON does not have"
                                + (" (SQLite stores it as NULL)" if value != value else ""))
        elif kind is str:
            ch = _surrogate(value)
            if ch is not None:
                return (key,), (f"the value of {key} holds the lone surrogate "
                                f"U+{ord(ch):04X}, which is not text of UTF-8, so SQLite "
                                "cannot hold it")
    return None


def _json_number(value):
    """NaN, Infinity or -Infinity: a float that is not finite, as json.dumps writes it."""
    return "NaN" if value != value else ("Infinity" if value > 0 else "-Infinity")


class ThreeValuedSqliteBackend(sqliteBackend):
    """pySigma's SQLite backend with SQL's own three-valued NOT (check_null_safety.py).

    sqliteBackend writes the operand of each NOT as COALESCE(<test>, 0). So a test on
    a field that the record does not have is false, and `not <filter>` keeps the
    record: that is Sigma's meaning, and the validators use it. A backend with SQL
    semantics (ES|QL and other SQL backends) has no such wrapper: a test on a
    missing field is NULL, NOT NULL is NULL, and WHERE keeps only true. This backend
    writes NOT (<test>) with no wrapper. Run its query on an
    EventTable(three_valued=True), where a regular expression on a missing field is
    NULL too, to get the verdict of such a backend.
    """

    null_safe_expression = "{expr}"


def backend(three_valued=False):
    """The SQLite backend: two-valued (Sigma's meaning, the default) or three-valued."""
    return ThreeValuedSqliteBackend() if three_valued else sqliteBackend()


def compile_rule(path, three_valued=False):
    """Compile one rule file to its single SQL query.

    A file holds either one plain rule or one correlation rule plus the base
    rules it references (the base rules generate no query of their own).
    three_valued: compile with ThreeValuedSqliteBackend (run the query on an
    EventTable(three_valued=True)).
    """
    with open(path, encoding="utf-8") as fh:
        collection = SigmaCollection.from_yaml(fh.read())
    queries = backend(three_valued).convert(collection)
    if len(queries) != 1:
        raise ValueError(f"expected one query from {path}, got {len(queries)}")
    return queries[0]


# ---- JSON that a loader reads: a key two times ---------------------------------


class Twice(dict):
    """A JSON object that holds one key two times: pairs() gives it in the place of
    the dict. `key` is the first key that the object holds two times. json keeps only
    the last value of such a key, so a loader that reads the object loses the first
    value without a word (an attack record under {"Records": <attack>, "Records":
    <benign>}). Each loader of records or cases refuses it (key_twice())."""

    __slots__ = ("key",)


def pairs(items):
    """The object_pairs_hook of the loaders of records and cases: the dict of
    `items`, or a Twice when two of the items have one key."""
    out = dict(items)
    if len(out) == len(items):
        return out
    seen = set()
    for key, _ in items:
        if key in seen:
            break
        seen.add(key)
    twice = Twice(out)
    twice.key = key
    return twice


def key_twice(value):
    """The key of the first object in the JSON value `value` (read with pairs()) that
    holds a key two times, or None. The walk uses no recursion: the value can be
    deep."""
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if type(node) is Twice:
                return node.key
            stack.extend(reversed(list(node.values())))
        elif isinstance(node, list):
            stack.extend(reversed(node))
    return None


def twice_text(key):
    """The text of the problem of an object that holds `key` two times."""
    return f"an object holds the key {key!r} two times (json keeps only the last value)"


# ---- JSON that a capture cut ---------------------------------------------------
#
# A capture copies a log while its writer adds lines, so the last line of the copy
# can be the start of a record. cut_json() tells such a line from a line that json
# refuses for another reason (a record with more text after it, NUL bytes or
# U+200B in a record): only a cut is no problem.

_BLANKS = " \t\n\r"                         # the blanks of JSON
_WORD_END = _BLANKS + ",]}:"                # the characters after a number or a literal
_HEX = "0123456789abcdefABCDEF"
_TAILS = ("", "0", "rue", "ue", "e", "alse", "lse", "se", "ull", "ll", "l")
_AFTER = {"value": "null", "key": '"":null', "key_or_end": "", "colon": ":null",
          "comma": "", "value_or_end": "", "done": ""}


def cut_json(text):
    """True when `text` is cut JSON: the start of one JSON object without its end.

    _closing() writes the text that closes the open string, number, literal and
    containers of `text`. `text` is cut only when that text is not empty (json does
    not read `text` as it is) and json then reads `text` with it as ONE JSON object.
    So json itself certifies each cut, and the scan of _closing() can only miss a cut,
    never accept JSON that is not a cut: a complete record with more text after it
    ('{...}{', '{...}x', '{...} {'), NUL bytes or U+200B in a record, a comma before
    a "}", an escape that JSON does not have, a control character in a string. A cut
    inside an escape (Go writes `\\u0026` in an audit event), a number, a literal or a
    key is a cut. The time is linear in the length of `text`."""
    rest = _closing(text)
    if not rest:                            # None: no cut; "": complete, or not JSON
        return False
    try:
        return isinstance(json.loads(text + rest), dict)
    except (ValueError, RecursionError):
        return False


def _closing(text):
    """The text that closes `text` to one JSON value, or None when the scan finds a
    character that no JSON value can hold in its place. The scan follows the grammar
    of JSON only as far as cut_json() needs it: json checks the result."""
    stack, expect, i, n = [], "value", 0, len(text)
    while i < n:
        c = text[i]
        if c in _BLANKS:
            i += 1
            continue
        if expect == "done":
            return None
        if expect == "colon":
            if c != ":":
                return None
            expect, i = "value", i + 1
            continue
        if expect == "comma":
            if c == ",":
                expect, i = ("key" if stack[-1] == "}" else "value"), i + 1
            elif c == stack[-1]:
                stack.pop()
                expect, i = ("comma" if stack else "done"), i + 1
            else:
                return None
            continue
        if expect in ("key", "key_or_end"):
            if c == "}" and expect == "key_or_end":
                stack.pop()
                expect, i = ("comma" if stack else "done"), i + 1
                continue
            if c != '"':
                return None
            end, tail = _string(text, i)
            if end is None:
                return tail + ":null" + "".join(reversed(stack))
            expect, i = "colon", end
            continue
        # expect is "value" or "value_or_end"
        if c == "]" and expect == "value_or_end":
            stack.pop()
            expect, i = ("comma" if stack else "done"), i + 1
        elif c in "{[":
            stack.append("}" if c == "{" else "]")
            expect, i = ("key_or_end" if c == "{" else "value_or_end"), i + 1
        elif c == '"':
            end, tail = _string(text, i)
            if end is None:
                return tail + "".join(reversed(stack))
            expect, i = ("comma" if stack else "done"), end
        else:                               # a number or a literal
            j = i
            while j < n and text[j] not in _WORD_END:
                j += 1
            if j == n:                      # at the end of the text: it can be cut
                tail = next((t for t in _TAILS if _scalar(text[i:] + t)), None)
                return None if tail is None else tail + "".join(reversed(stack))
            if not _scalar(text[i:j]):
                return None
            expect, i = ("comma" if stack else "done"), j
    return _AFTER[expect] + "".join(reversed(stack))


def _scalar(word):
    """True when `word` is a JSON number or literal."""
    if word in ("true", "false", "null"):
        return True
    try:
        value = json.loads(word)
    except ValueError:
        return False
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _string(text, i):
    """(end, None) for a string that starts at text[i] and ends in `text` (end is the
    index after its quote), or (None, tail) for a string that `text` cuts: `tail`
    closes it (it ends an escape that the cut opened)."""
    j, n = i + 1, len(text)
    while j < n:
        c = text[j]
        if c == '"':
            return j + 1, None
        if c != "\\":
            j += 1
            continue
        if j + 1 == n:
            return None, 'n"'
        if text[j + 1] == "u":
            digits = text[j + 2:j + 6]
            if j + 2 + len(digits) == n and len(digits) < 4 and all(d in _HEX for d in digits):
                return None, "0" * (4 - len(digits)) + '"'
            j += 6
        else:
            j += 2
    return None, '"'


def utf8_cut(text):
    """`text` without the start of a character of UTF-8 that a cut left at its very
    end; `text` itself when it holds no byte that is not UTF-8; None when it holds
    another byte that is not UTF-8.

    `text` is decoded with errors="surrogateescape", so each byte that is not UTF-8
    is a character U+DC80..U+DCFF. The start of a character is a lead byte (C2..F4)
    with fewer continuation bytes than it needs, at the very end of the text. Each
    other byte that is not UTF-8 is no cut: before the end, or at the end in a
    sequence that UTF-8 does not have (E0 80, ED A0, a lone continuation byte, FF).
    The decoder of UTF-8 stops at the first such byte: the text is a cut when that
    error is "unexpected end of data" at the end of the text."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        pass
    data = text.encode("utf-8", "surrogateescape")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as e:
        if e.reason == "unexpected end of data" and e.end == len(data):
            return data[:e.start].decode("utf-8")
    return None


def flatten(obj, prefix="", *, separators=None, sort_keys=False):
    """Nested dict -> {"a.b.c": value}, the dotted field names Sigma rules use.

    Lists become JSON text so they stay matchable with |contains. The default text
    is the one json.dumps writes: a blank after each `,` and `:`, and the key order
    of the record. separators and sort_keys are those of json.dumps, for a store
    that writes the text in another way (check_variants.py): separators=(",", ":")
    is the text without blanks, sort_keys=True sorts the keys of each object.
    """
    out = {}
    for key, val in obj.items():
        name = f"{prefix}{key}"
        if isinstance(val, dict):
            out.update(flatten(val, f"{name}.", separators=separators, sort_keys=sort_keys))
        elif isinstance(val, list):
            out[name] = json.dumps(val, separators=separators, sort_keys=sort_keys)
        else:
            out[name] = val
    return out


def _quote(col):
    return '"' + col.replace('"', '""') + '"'


class EventTable:
    """Flat event dicts loaded once into an in-memory `logs` table.

    Load a large event set (a benign corpus slice, a long audit log) once and run
    many compiled rules over it, instead of rebuilding the table per rule.

    three_valued: a regular expression on a missing field is NULL (as in SQL),
    not false. Use it with a query from compile_rule(path, three_valued=True).

    case_sensitive_like: LIKE does not fold letter case (PRAGMA case_sensitive_like),
    as on a store whose LIKE is case-sensitive. By default SQLite's LIKE folds the
    ASCII letters, so |contains, |startswith, |endswith and a wildcard value ignore
    their case.

    regexp: search(pattern, text) -> truth, in place of Python's re.search, for a
    `|re` item (for example a search with RE2). The pattern arrives as the backend
    writes it, with its flags as a prefix (`(?i)`); the text is str(value).
    """

    def __init__(self, events, three_valued=False, *, case_sensitive_like=False, regexp=None):
        self.events = events
        self.db = sqlite3.connect(":memory:")
        if case_sensitive_like:
            # One connection for each table, so no other table sees the pragma.
            # SQLite ignores a pragma that it does not know, without an error: prove
            # that this one is in force.
            self.db.execute("PRAGMA case_sensitive_like=ON")
            if self.db.execute("SELECT 'a' LIKE 'A'").fetchone()[0]:
                raise RuntimeError("PRAGMA case_sensitive_like=ON is not in force in this "
                                   f"SQLite ({sqlite3.sqlite_version}): LIKE still folds case")
        search = re.search if regexp is None else regexp
        # pySigma's SQLite backend compiles a `|re` match to the SQL `REGEXP`
        # operator, which SQLite leaves unimplemented by default. Register it with
        # Python's `re` (full syntax, including look-around) so `|re` rules
        # evaluate. `X REGEXP Y` calls regexp(Y, X), i.e. regexp(pattern, value).
        if three_valued:
            self.db.create_function(
                "regexp", 2,
                lambda pattern, value: None if value is None
                else (1 if search(pattern, str(value)) else 0))
        else:
            self.db.create_function(
                "regexp", 2,
                lambda pattern, value: 1 if value is not None and search(pattern, str(value)) else 0)
        # SQLite reads two column names that differ only in the letter case of their
        # ASCII letters as one name (fold()), and so it reads a rule field: the item
        # `Verb: create` reads the key `verb` (detections/SEMANTICS.md, "Field names").
        # So keys of that kind in different events share one column, named as the
        # first key of the group in sorted order. The table refuses an event that it
        # cannot hold (event_problem(), EventError): one event that holds two such keys
        # (two values for one column), a key that hides a row id that the queries read
        # or that no column name can hold, and a value that SQLite does not hold as it
        # is. The keys are tested once for each distinct key, and each event only when a
        # key gives cause; the values at the insert.
        keys = set().union(*events)
        group = {}  # fold(key) -> the keys of the events
        for key in keys:
            group.setdefault(fold(key), []).append(key)
        joined = "".join(keys)
        if (len(group) != len(keys) or not RESERVED.keys().isdisjoint(group)
                or "\x00" in joined or not joined.isascii() and any(map(_surrogate, keys))):
            for index, event in enumerate(events):
                problem = event_problem(event)
                if problem:
                    raise EventError(index, len(events), *problem)
        column = {key: min(names) for names in group.values() for key in names}
        self.db.execute(f"CREATE TABLE logs ({_ROWID} INTEGER PRIMARY KEY"
                        + "".join(f", {_quote(c)}" for c in sorted(set(column.values())))
                        + ")")
        inserts = {}  # the keys of an event, in its order -> the INSERT of such an event
        for rowid, event in enumerate(events):
            shape = tuple(event)
            sql = inserts.get(shape)
            if sql is None:
                names = "".join(", " + _quote(column[k]) for k in shape)
                sql = inserts[shape] = (f"INSERT INTO logs ({_ROWID}{names}) "
                                        f"VALUES (?{', ?' * len(shape)})")
            values = [rowid, *event.values()]
            # SQLite stores NaN as NULL without an error, so the floats are tested here;
            # an integer outside 64 bits and a lone surrogate fail the insert.
            problem = None
            if float in map(type, values) and not all(
                    _FINITE[0] < v < _FINITE[1] for v in values if type(v) is float):
                problem = event_problem(event)
            if problem is None:
                try:
                    self.db.execute(sql, values)
                except (OverflowError, UnicodeEncodeError):
                    problem = event_problem(event)
                    if problem is None:
                        raise
            if problem:
                raise EventError(rowid, len(events), *problem)

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
        if _ROWID in names:  # a plain rule: SELECT * FROM logs, the rows of the table
            idx = names.index(_ROWID)
            return [[row[idx]] for row in rows]
        # A correlation rule: its alert rows name the events in event_ids (and have no
        # column _rowid). An event may hold a key event_ids: it is only a column of a row.
        idx = names.index("event_ids")
        return [[int(eid.rsplit(":", 1)[1]) for eid in json.loads(row[idx])]
                for row in rows]

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
