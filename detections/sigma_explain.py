#!/usr/bin/env python3
"""
Explain a Sigma rule's verdict on events, one detection item at a time.

sigma_eval answers "does the rule fire?". That is enough for a gate, but not for
whoever has to fix a red run: "no hit" leaves them to guess which part of the
rule failed. This module compiles every detection ITEM of a rule on its own
(through the same pySigma SQLite backend), evaluates each item over the events,
and re-evaluates the rule's condition over those per-item results. So a verdict
can be explained field by field, and a non-matching event can be graded by how
close it came to firing the rule. "Holds" below means the item matches the
event on something the event carries: an item that also holds on an empty event
(`field: null`, `|exists: false`) does not count.

  match      the rule fires on it.
  near-miss  some positive (selection) item holds, and flipping one item alone
             fires the rule, through a branch that uses an item the event already
             holds. A variant that keeps part of the technique's surface and
             breaks one required part: the strongest negative test a rule can
             have.
  filtered   every selection holds and flipping one `not <filter>` item alone
             fires the rule: an allowlisted look-alike.
  distant    some positive item holds, but no single flip (of a branch the event
             shares) fires the rule.
  trivial    no positive item holds. Any reasonable rule rejects it, so as a
             negative test it proves nothing about this rule, however few flips
             away it is (for a one-item rule every event is one flip away).

For a correlation rule the unit is an event set. Its atoms are its base rules
(`base:<ref>`, the name or id its `rules:` lists), `group-by`, `timespan`,
`order` (temporal_ordered) and `threshold` (event_count / value_count). A set is
a near-miss on an atom only when repairing THAT atom alone makes the compiled
correlation fire, which is checked by construction, never inferred:

  base:<ref>  no event matches that base: one synthetic event of the base, in a
              matched event's group and time, is added (through a copy of the
              rule whose base matches only the synthetic event).
  group-by    the matched events get one shared group-by value.
  timespan    the matched events are re-stamped into the window, order kept.
  order       the same events, with the order constraint dropped (`temporal`).
  threshold   every matched event is duplicated (with fresh values of the
              counted field for value_count) until the count can be reached.

The correlation only sees an event with a parseable timestamp and a value for
every group-by field (the SQL drops the rest). A set with such a blind event is
never graded near-miss: it is distant (or trivial if the correlation sees no
base at all), with a line naming what is missing. With every base matched and
no repair firing, the set is distant; with no base matched, trivial.

The per-item result always agrees with the full rule: the pySigma SQLite backend
wraps negated blocks in COALESCE, so an absent field reads as "item false" in
both. explain() still cross-checks the composed verdict against the compiled
rule and reports any disagreement instead of hiding it.

    python3 detections/sigma_explain.py --self-test   # crafted rules and events
"""

import argparse
import copy
import fnmatch
import glob
import math
import os
import random
import sys
from datetime import datetime, timedelta, timezone

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402  (checks detections/sigma/ before pySigma loads)

try:
    from sigma.backends.sqlite import sqliteBackend
    from sigma.collection import SigmaCollection
    from sigma.conditions import (ConditionAND, ConditionIdentifier, ConditionNOT,
                                  ConditionOR, ConditionSelector)
    from sigma.rule import SigmaRule
except ImportError:  # pragma: no cover - sigma_eval already exits with a hint
    raise

KIND_RANK = {"match": 0, "near-miss": 1, "filtered": 1, "distant": 2, "trivial": 3}
NON_TRIVIAL = {"near-miss", "filtered"}


def _fields(definition):
    """Field names a detection block reads (modifiers stripped), in order."""
    out = []

    def add(name):
        if name and name not in out:
            out.append(name)

    if isinstance(definition, dict):
        for key in definition:
            add(str(key).split("|")[0])
    elif isinstance(definition, list):
        for item in definition:
            if isinstance(item, dict):
                for key in item:
                    add(str(key).split("|")[0])
    return out


def _short(value, limit=90):
    if value is None:
        return "<absent>"
    text = repr(value)
    return text if len(text) <= limit else text[:limit - 3] + "..."


class Verdict:
    """How a rule judged one event (plain rule) or one event set (correlation)."""

    def __init__(self, fired, kind, atoms, lines, mismatch=False, closeness=0, lone=(),
                 unseen=()):
        self.fired = fired        # the compiled rule's own answer (authoritative)
        self.kind = kind          # match / near-miss / filtered / distant / trivial
        self.atoms = atoms        # match: load-bearing atoms; else atoms one flip/repair fires
        self.lines = lines        # human-readable item-by-item explanation
        self.mismatch = mismatch  # composed verdict disagreed with the compiled rule
        self.closeness = closeness  # positive atoms that hold (tie-break for nearest)
        # Plain rule: atoms whose flip alone fires the rule through a branch the
        # event holds nothing of (so the flip proves no more than an unrelated event).
        self.lone = list(lone)
        # Correlation: events of the set the compiled rule drops (no parseable
        # timestamp, or no group-by value), so they cannot count toward any atom.
        self.unseen = list(unseen)

    def __repr__(self):
        return f"Verdict({self.kind}, atoms={self.atoms})"


# ---- plain rules -------------------------------------------------------------


class PlainRule:
    """One Sigma rule: its items, each compiled alone, and its condition tree."""

    is_correlation = False

    def __init__(self, doc, path=None):
        self.doc = doc
        self.path = path
        self.title = doc.get("title", "")
        self.name = doc.get("name")
        self.level = doc.get("level")
        self.logsource = doc.get("logsource") or {}
        detection = dict(doc.get("detection") or {})
        condition = detection.pop("condition")
        if isinstance(condition, list):
            if len(condition) != 1:
                raise ValueError(f"{path}: one condition expected, got {len(condition)}")
            condition = condition[0]
        self.condition = str(condition)
        self.definitions = detection
        self.sql = _compile_doc(doc)
        # Atoms are detection ITEMS, not whole blocks: `selection.a1` is one atom,
        # so a near-miss means "fails exactly one field condition", not "fails some
        # block". A dict block is the AND of its items; a list of maps is the OR of
        # each map's AND (items named block[i].field); a keyword list is one atom.
        # When one map holds several items on the same field (`exe|startswith`,
        # `exe|endswith`), each is named with its modifiers (`selection.exe|endswith`).
        self.items = {}      # atom -> compiled SQL
        self.item_detection = {}  # atom -> the one-item detection it compiles
        self._items3 = {}    # atom -> three-valued SQL (item_sql(three_valued=True))
        self._nullable = {}  # atom -> item_nullable()
        self.item_expect = {}  # atom -> what the item matches, for explanations
        self.item_field = {}  # atom -> field name (None for keyword atoms)
        self.block_of = {}   # atom -> the detection block it belongs to
        self.block_tree = {}  # block -> subtree over its item atoms
        for name, definition in detection.items():
            self.block_tree[name] = self._block_items(name, name, definition)
        rule = SigmaRule.from_dict({"title": self.title, "logsource": self.logsource,
                                    "detection": doc["detection"]})
        parsed = rule.detection.parsed_condition[0].parse(postprocess=False)
        self.tree = self._convert(parsed)
        self.polarity = {}
        self._walk_polarity(self.tree, True)
        self.atoms = list(self.polarity)
        # Items that hold on an event that carries nothing (`field: null`,
        # `|exists: false`): they hold vacuously, so they never make an event close.
        empty_rows, _ = self.truth_table(sigma_eval.EventTable([{}]))
        self.vacuous = {a for a, held in empty_rows[0].items() if held}
        self._helpers = None  # null_helpers(), computed on first use
        self._stripped = None

    def _compile_item(self, block, atom, field_key, value):
        if atom in self.items:
            raise ValueError(f"{self.path}: two detection items are both named {atom!r}; "
                             "sigma_explain cannot tell them apart")
        detection = {"_item": {field_key: value}, "condition": "_item"} if field_key is not None \
            else {"_item": value, "condition": "_item"}
        self.item_detection[atom] = detection
        self.items[atom] = _compile_doc({"title": f"{self.title} [{atom}]",
                                         "logsource": self.logsource, "detection": detection})
        self.block_of[atom] = block
        self.item_field[atom] = str(field_key).split("|")[0] if field_key is not None else None
        mods = "|".join(str(field_key).split("|")[1:]) if field_key is not None else "keywords"
        values = value if isinstance(value, list) else [value]
        shown = " or ".join(_short(v, 40) for v in values[:6]) + (" ..." if len(values) > 6 else "")
        self.item_expect[atom] = f"{mods + ' ' if mods else ''}{shown}"
        return ("id", atom)

    def _map_items(self, block, prefix, mapping):
        fields = [str(k).split("|")[0] for k in mapping]
        # `<prefix>.<field>`, or `<prefix>.<field>|<mods>` when the field repeats.
        names = [str(k) if fields.count(f) > 1 else f for k, f in zip(mapping, fields)]
        return ("and", [self._compile_item(block, f"{prefix}.{name}", k, v)
                        for name, (k, v) in zip(names, mapping.items())])

    def _block_items(self, block, prefix, definition):
        if isinstance(definition, dict):
            if not definition:
                raise ValueError(f"{self.path}: empty detection block {block}")
            return self._map_items(block, prefix, definition)
        if isinstance(definition, list) and definition and all(isinstance(m, dict)
                                                                 for m in definition):
            if len(definition) == 1:
                return self._block_items(block, prefix, definition[0])
            return ("or", [self._map_items(block, f"{prefix}[{i}]", m)
                           for i, m in enumerate(definition)])
        return self._compile_item(block, prefix, None, definition)  # keyword search

    # condition tree -> ('and'|'or', [..]) / ('not', x) / ('id', name)
    def _convert(self, node):
        if isinstance(node, ConditionIdentifier):
            return self.block_tree[node.identifier]
        if isinstance(node, ConditionSelector):
            if node.pattern == "them":
                names = [n for n in self.definitions if not n.startswith("_")]
            else:
                names = [n for n in self.definitions if fnmatch.fnmatchcase(n, node.pattern)]
            op = "and" if node.cond_class is ConditionAND else "or"
            return (op, [self.block_tree[n] for n in names])
        if isinstance(node, ConditionNOT):
            return ("not", self._convert(node.args[0]))
        if isinstance(node, ConditionAND):
            return ("and", [self._convert(a) for a in node.args])
        if isinstance(node, ConditionOR):
            return ("or", [self._convert(a) for a in node.args])
        raise ValueError(f"{self.path}: unsupported condition node {type(node).__name__}")

    def _walk_polarity(self, node, positive):
        op = node[0]
        if op == "id":
            self.polarity.setdefault(node[1], set()).add("+" if positive else "-")
        elif op == "not":
            self._walk_polarity(node[1], not positive)
        else:
            for child in node[1]:
                self._walk_polarity(child, positive)

    def positive_atoms(self):
        return [a for a in self.atoms if "+" in self.polarity[a]]

    def negated_atoms(self):
        return [a for a in self.atoms if "-" in self.polarity[a]]

    def fields(self, atom):
        """Field names an atom (item) or a whole block reads."""
        if atom in self.item_field:
            return [self.item_field[atom]] if self.item_field[atom] else []
        return _fields(self.definitions.get(atom))

    def blocks_in_condition(self):
        """Block names in the order their atoms appear in the condition."""
        return list(dict.fromkeys(self.block_of[a] for a in self.atoms))

    def block_negated(self, block):
        atoms = [a for a in self.atoms if self.block_of[a] == block]
        return bool(atoms) and all("+" not in self.polarity[a] for a in atoms)

    # ---- null-safety helpers (check_null_safety.py, check_sufficiency.py) -------
    #
    # A backend with three-valued logic (ES|QL and other SQL backends) reads `not` of a
    # test on a missing field as NULL and drops the record. Two forms make a negation
    # null-safe and change no two-valued verdict:
    #
    #   guard  `sel_no_x or not X`: sel_no_x is a block of one map whose every item is
    #          `field: null` (or `field|exists: false`), and X is false on every record
    #          that lacks all of the guard's fields: a block each of whose maps has an
    #          item on one of them that is false when its field is absent, or an OR of
    #          such parts, or an AND with one such part (`not 1 of filter_*`,
    #          `not (filter_a or filter_b)`). The guard holds only where X does not.
    #          A guard covers only the fields it names: any other field that X reads
    #          must be one that the log source writes on every record the rule matches
    #          (check_null_safety.py --absent probes this on the cases). A guard on
    #          several fields holds only where all of them are absent, so it is accepted
    #          only when each map of X is one item that holds on any value of one of its
    #          fields (`field: '*'`, `field|exists: true`): then X is true wherever one
    #          of the fields is present.
    #   copy   `not (F and ((F_1 and not sel_no_1) or (F_2 and not sel_no_2) ...))`:
    #          each F_i is a block of one map that repeats one map of the block F
    #          exactly, every map of F has its F_i, and each term reads its F_i only
    #          where every field that F_i tests is present: one guard per field
    #          (`F_i and not sel_no_a and not sel_no_b`), each on a field that F_i reads.
    #          In two-valued logic the OR holds exactly where F holds; in three-valued
    #          logic it is never NULL, so the AND is false, not NULL, where F has no true
    #          map. A filter whose maps read different fields needs this form.
    #
    # The items of such guards and copies only make a negation null-safe, so a grader
    # must not count them as items of the rule (stripped()), and no case can break one
    # alone (rule_cases.py). A block of `field: null` items that is ORed with a `not` it
    # does not guard is an ordinary selection, unless its field is a near spelling of a
    # field that the `not` reads, or one of the maps under the `not` reads it: then it is
    # reported (null_guard_issues()). An OR of `<block> and not <guard>` terms is read
    # as a copy only when a block ANDed with it has maps with the same keys as the
    # terms' blocks.

    def _names(self):
        return {id(tree): name for name, tree in self.block_tree.items()}

    @staticmethod
    def _maps(node):
        return [node] if node[0] in ("and", "id") else list(node[1])

    def _atoms_under(self, node):
        if node[0] == "id":
            return [node[1]]
        kids = [node[1]] if node[0] == "not" else node[1]
        return [a for c in kids for a in self._atoms_under(c)]

    def _field_items(self, node):
        """{field: [atoms]} of the items under node that are false on an empty record."""
        out = {}
        for a in self._atoms_under(node):
            if a not in self.vacuous and self.item_field.get(a):
                out.setdefault(self.item_field[a], []).append(a)
        return out

    def _guard_fields(self, node, names):
        """The fields of a null guard block, or None if node is not one."""
        name = names.get(id(node))
        if name is None:
            return None
        definition = self.definitions.get(name)
        if isinstance(definition, list) and len(definition) == 1:
            definition = definition[0]
        if not isinstance(definition, dict) or not definition:
            return None
        fields = set()
        for key, value in definition.items():
            field, *mods = str(key).split("|")
            if not ((not mods and value is None) or (mods == ["exists"] and value is False)):
                return None
            fields.add(field)
        return fields

    def _falsified(self, node, fields, names):
        """Is node false (two-valued) on every record that lacks all of `fields`?"""
        if id(node) in names:
            return all(any(a not in self.vacuous and self.item_field.get(a) in fields
                           for a in self._atoms_under(m)) for m in self._maps(node))
        if node[0] == "or":
            return all(self._falsified(c, fields, names) for c in node[1])
        if node[0] == "and":
            return any(self._falsified(c, fields, names) for c in node[1])
        return False

    def _any_value(self, atom):
        """Does the item hold on every value of its field (`field: '*'`,
        `field|exists: true`)?"""
        item = self.item_detection.get(atom, {}).get("_item")
        if not isinstance(item, dict) or len(item) != 1:
            return False
        (key, value), = item.items()
        mods = str(key).split("|")[1:]
        values = value if isinstance(value, list) else [value]
        return (not mods and values == ["*"]) or (mods == ["exists"] and values == [True])

    def _any_value_maps(self, node, fields, names):
        """Is node a block, or an OR of blocks, each of whose maps is one item that holds
        on every value of one of `fields`? Then node is true wherever one is present."""
        if id(node) in names:
            for m in self._maps(node):
                atoms = self._atoms_under(m)
                if (len(atoms) != 1 or self.item_field.get(atoms[0]) not in fields
                        or not self._any_value(atoms[0])):
                    return False
            return True
        if node[0] == "or":
            return all(self._any_value_maps(c, fields, names) for c in node[1])
        return False

    def item_nullable(self, atom):
        """Is the item NULL in three-valued logic on a record that has none of its
        fields? (`field: '*'` and `|re` are; `field: null` and `|exists` are not.)"""
        if atom not in self._nullable:
            prefix = "SELECT * FROM logs WHERE "
            sql = self.item_sql(atom, three_valued=True)
            if not sql.startswith(prefix):
                raise ValueError(f"item {atom}: unexpected SQL shape {sql[:60]!r}")
            table = sigma_eval.EventTable([{}], three_valued=True)
            value = table._execute(f"SELECT ({sql[len(prefix):]}) FROM logs").fetchone()[0]
            self._nullable[atom] = value is None
        return self._nullable[atom]

    @staticmethod
    def _near(a, b):
        """Are two different field names one typo apart: equal in another letter case,
        or at most two edits apart in a name at least four times as long?"""
        if a == b:
            return False
        if a.lower() == b.lower():
            return True
        if abs(len(a) - len(b)) > 2:
            return False
        row = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            prev, row[0] = row[0], i
            for j, cb in enumerate(b, 1):
                prev, row[j] = row[j], min(row[j] + 1, row[j - 1] + 1, prev + (ca != cb))
        return row[-1] <= 2 and 4 * row[-1] <= max(len(a), len(b))

    def _copy_term(self, node, names):
        """(F_i, [(guard node, guard fields)]) when node is `F_i and not sel_no_a ...`:
        one block of one map and one or more negated null guard blocks."""
        if node[0] != "and" or id(node) in names or len(node[1]) < 2:
            return None
        blocks = [k for k in node[1] if k[0] != "not"]
        if len(blocks) != 1 or id(blocks[0]) not in names or len(self._maps(blocks[0])) != 1:
            return None
        guards = []
        for neg in node[1]:
            if neg is blocks[0]:
                continue
            fields = self._guard_fields(neg[1], names)
            if fields is None:
                return None
            guards.append((neg[1], fields))
        return blocks[0], guards

    def _map_defs(self, name):
        definition = self.definitions.get(name)
        return list(definition) if isinstance(definition, list) else [definition]

    def null_helpers(self):
        """{atom: (role, atoms to name instead)} for the items of null guards ("guard")
        and null-safe copies ("copy"), as the comment above defines them. An item that
        the condition also reads in any other place is not a helper."""
        if self._helpers is None:
            self._analyse_null_helpers()
        return self._helpers

    def null_guard_issues(self):
        """Messages for shapes that are a null guard or a null-safe copy but not a
        correct one (a guard on a near spelling of the filter's field, a guard that only
        some maps of its filter read, a guard on several fields whose filter can be NULL
        where one of them is present, a copy that does not repeat its filter's maps or
        that reads a field no guard of its term covers): such a guard holds on records
        where the filter holds, or the negation stays NULL, or a copy changes the rule.
        check_null_safety.py fails each."""
        if self._helpers is None:
            self._analyse_null_helpers()
        return self._issues

    def _analyse_null_helpers(self):
        names = self._names()
        drop, roles, issues = set(), {}, []
        guarded = {}  # guard atom -> the filter atoms it guards

        def text(n):
            return render(self, n)

        def walk(node):
            if id(node) in names or node[0] == "id":
                return
            if node[0] == "not":
                walk(node[1])
                return
            kids = node[1]
            if node[0] == "or":
                nots = [k for k in kids if k[0] == "not"]
                for i, g in enumerate(kids):
                    fields = self._guard_fields(g, names)
                    if fields is None or not nots:
                        continue
                    held = [k for k in nots if self._falsified(k[1], fields, names)]
                    if not held:
                        issues.extend(self._misdirected_guard(names[id(g)], fields, nots, text))
                        continue
                    drop.add((id(node), i))
                    targets = []
                    for k in held:
                        reads = self._field_items(k[1])
                        extra = sorted(f for f in fields if f not in reads)
                        if extra:
                            issues.append(
                                f"`{names[id(g)]}` guards `{text(k)}`, but that filter reads no "
                                f"{', '.join(extra)} (a field name must match exactly, in "
                                "case too): remove the field from the guard or fix its name")
                        if len(fields) > 1 and not self._any_value_maps(k[1], fields, names):
                            issues.append(
                                f"`{names[id(g)]}` guards several fields at once "
                                f"({', '.join(sorted(fields))}): it holds only where all of "
                                f"them are absent, so where one is present and another is "
                                f"absent `{text(k)}` can still be NULL. Use one guard per "
                                "field (De Morgan's laws: `(sel_no_a or not filter_a) and "
                                "(sel_no_b or not filter_b)`, with one filter block per "
                                "field). A guard on several fields is null-safe only when "
                                "each map of its filter is one item that holds on any value "
                                "of one of them (`field: '*'` or `field|exists: true`)")
                        targets += [a for f in sorted(fields) for a in reads.get(f, [])]
                    for a in self._atoms_under(g):
                        guarded.setdefault(a, [])
                        guarded[a] += [t for t in targets if t not in guarded[a]]
            else:
                for i, c in enumerate(kids):
                    if id(c) in names:
                        continue
                    terms = c[1] if c[0] == "or" else [c]
                    parts = [self._copy_term(t, names) for t in terms]
                    if not parts or any(p is None for p in parts):
                        continue
                    found = self._copy_of(parts, [k for j, k in enumerate(kids) if j != i],
                                          names)
                    if found is None:
                        continue  # no block it copies: ordinary selections
                    if isinstance(found, str):
                        issues.append(f"`{text(c)}` has the shape of a null-safe copy "
                                      f"(`<block> and not <guard>` terms), but {found}")
                        continue
                    drop.add((id(node), i))
                    for blk, guards, originals in found:
                        for a in self._atoms_under(blk):
                            role = roles.setdefault(a, ("copy", []))
                            role[1].extend(o for o in [originals[a]] if o not in role[1])
                        for g, fields in guards:
                            targets = [originals[a] for f, atoms in self._field_items(blk).items()
                                       if f in fields for a in atoms]
                            for a in self._atoms_under(g):
                                guarded.setdefault(a, [])
                                guarded[a] += [t for t in targets if t not in guarded[a]]
            for c in kids:
                walk(c)

        walk(self.tree)

        def strip(node):
            if node[0] == "id" or id(node) in names:
                return node
            if node[0] == "not":
                return ("not", strip(node[1]))
            kids = [strip(c) for i, c in enumerate(node[1]) if (id(node), i) not in drop]
            return kids[0] if len(kids) == 1 else (node[0], kids)

        self._stripped_tree = strip(self.tree)
        kept = set(self._atoms_under(self._stripped_tree))
        for a, targets in guarded.items():
            roles.setdefault(a, ("guard", targets))
        self._helpers = {a: roles[a] for a in self.atoms if a not in kept and a in roles}
        self._issues = issues

    def _misdirected_guard(self, name, fields, nots, text):
        """A `field: null` block ORed with `not` operands that it does not guard: an
        ordinary selection, unless it reads like a broken guard (a near spelling of a
        field that an operand reads, or a field that only some maps of an operand read).
        Returns the issue messages."""
        names = self._names()
        out = []
        for k in nots:
            inner = text(k[1])
            if id(k[1]) not in names and k[1][0] in ("and", "or"):
                inner = f"({inner})"
            rewrite = (f"If `{name}` is a selection and not a null guard, write "
                       f"`not ({inner} and not {name})`, which means the same and is not "
                       "read as a guard")
            reads = self._field_items(k[1])
            shared = sorted(f for f in fields if f in reads)
            near = sorted({(f, r) for f in fields for r in reads if self._near(f, r)})
            if near:
                out.append(
                    f"`{name}` ({', '.join(sorted(fields))} absent) is ORed with `{text(k)}`, "
                    f"which reads {', '.join(sorted({r for _, r in near}))}: the names differ "
                    "only in letter case or by a typo. As a null guard it is true on every "
                    "record that lacks the misspelt field, so on Lucene, Splunk and ES|QL "
                    "(which read field names as written) the filter never applies. Write the "
                    "field name exactly as the filter reads it. " + rewrite)
            elif shared:
                out.append(
                    f"`{name}` ({', '.join(shared)} absent) is ORed with `{text(k)}`, but not "
                    "every map of that filter reads "
                    + ("that field" if len(shared) == 1 else "those fields")
                    + ": the block holds on records where a map on another field holds, so "
                    "it changes what the rule matches. Guard a filter whose every map reads "
                    "the field, or use a null-safe copy for a filter whose maps read "
                    "different fields. " + rewrite)
        return out

    def _copy_of(self, parts, siblings, names):
        """[(F_i, [(guard, fields)], {F_i atom: F atom})] when the terms `parts` copy one
        of the sibling blocks; a message that says why they do not, when a sibling has
        maps with the same keys as the terms' blocks; else None (no block to copy: the
        terms are ordinary selections)."""
        maps = [self._map_defs(names[id(blk)])[0] for blk, _ in parts]
        keys = [sorted(map(str, m)) if isinstance(m, dict) else None for m in maps]
        almost = None
        for f in siblings:
            name = names.get(id(f))
            if name is None:
                continue
            fmaps = self._map_defs(name)
            fkeys = [sorted(map(str, m)) if isinstance(m, dict) else None for m in fmaps]
            if not all(k is not None and k in fkeys for k in keys):
                continue
            almost = almost or name
            if not (all(m in maps for m in fmaps) and all(m in fmaps for m in maps)):
                continue
            out = []
            for (blk, guards), m in zip(parts, maps):
                bname = names[id(blk)]
                reads = self._field_items(blk)
                for g, fields in guards:
                    if len(fields) > 1:
                        return (f"`{names[id(g)]}` guards several fields at once "
                                f"({', '.join(sorted(fields))}): in a copy term, `not "
                                f"{names[id(g)]}` holds where any one of them is present, so "
                                f"`{bname}` is read where another can be absent. Use one "
                                f"guard per field (`{bname} and not sel_no_a and not "
                                "sel_no_b`)")
                    extra = sorted(fd for fd in fields if fd not in reads)
                    if extra:
                        return (f"`{names[id(g)]}` guards {', '.join(extra)}, which "
                                f"`{bname}` does not read (a field name must match exactly, "
                                "in case too)")
                covered = {fd for _, fields in guards for fd in fields}
                bare = sorted({self.item_field[a] or "(a keyword item)"
                               for a in self._atoms_under(blk)
                               if self.item_field[a] not in covered and self.item_nullable(a)})
                if bare:
                    return (f"`{bname}` also reads {', '.join(bare)}, which no guard of its "
                            "term covers: where that field is absent the copy is NULL, and "
                            "so is the negation. Read the copy only where every field it "
                            f"tests is present: `{bname} and not "
                            + " and not ".join(names[id(g)] for g, _ in guards)
                            + " and not sel_no_<field>` (a block `<field>: null` per field)")
                i = fmaps.index(m)
                prefix = f"{name}[{i}]" if len(fmaps) > 1 else name
                originals = {a: prefix + a[len(bname):] for a in self._atoms_under(blk)}
                if not all(o in self.items for o in originals.values()):
                    break
                out.append((blk, guards, originals))
            else:
                return out
        if almost is None:
            return None
        return (f"it does not repeat the maps of `{almost}` exactly (its blocks have the "
                f"keys of maps of `{almost}`, so they are read as a copy of it: each map of "
                "that block needs one `<block> and not <guard>` term whose block is that "
                "map, with the same keys and values). If the terms are selections and not "
                "a copy, write each `<block> and not <guard>` as `not (<guard> or not "
                "<block>)`, which means the same and is not read as a copy")

    def stripped(self):
        """This rule with its null guards and null-safe copies left out of the condition
        (null_helpers()). On a real record the verdict is the same: a guard holds only
        where its filter does not, and a copy holds exactly where its filter does. The
        compiled query (sql) stays the full rule's. check_sufficiency.py grades this view,
        so a helper item does not count as an item of the rule."""
        if self._stripped is None:
            helpers = self.null_helpers()
            if not helpers:
                self._stripped = self
            else:
                clone = copy.copy(self)
                clone.tree = self._stripped_tree
                clone.polarity = {}
                clone._walk_polarity(clone.tree, True)
                clone.atoms = list(clone.polarity)
                clone.items = {a: s for a, s in self.items.items() if a in clone.polarity}
                clone.vacuous = {a for a in self.vacuous if a in clone.polarity}
                clone._helpers, clone._issues, clone._stripped = {}, [], clone
                self._stripped = clone
        return self._stripped

    def item_sql(self, atom, three_valued=False):
        """One item's SQL alone: two-valued (pySigma's SQLite backend, as compiled at
        load) or three-valued (sigma_eval.backend(three_valued=True))."""
        if not three_valued:
            return self.items[atom]
        if atom not in self._items3:
            doc = {"title": f"{self.title} [{atom}]", "logsource": self.logsource,
                   "detection": self.item_detection[atom]}
            self._items3[atom] = sigma_eval.backend(True).convert(
                SigmaCollection.from_dicts([doc]))[0]
        return self._items3[atom]

    def item_negates(self, atom):
        """Does the item negate inside itself (`|neq`)? The SQLite backend writes a
        negation, and only a negation, as NOT COALESCE(<test>, 0)."""
        return "COALESCE(" in self.items[atom]

    def evaluate(self, truth):
        return _eval(self.tree, truth)

    def truth_table(self, table):
        """Per event: {atom: bool}, and the compiled rule's own hits."""
        per_item = {atom: {i for hit in table.hit_indices(sql) for i in hit}
                    for atom, sql in self.items.items()}
        fired = {i for hit in table.hit_indices(self.sql) for i in hit}
        rows = [{atom: i in idx for atom, idx in per_item.items()}
                for i in range(len(table.events))]
        return rows, fired

    def closeness(self, truth):
        """Positive items that hold on the event (not vacuously)."""
        return sum(1 for a in self.positive_atoms() if truth.get(a) and a not in self.vacuous)

    def _fires_after(self, truth, flips):
        flipped = dict(truth)
        for atom in flips:
            flipped[atom] = not truth[atom]
        return self.evaluate(flipped)

    def _shares_branch(self, truth, atom):
        """Does flipping `atom` fire the rule only together with an item the event holds?

        Clear every other positive item (keeping vacuous ones, and items that
        also appear negated): if the flip still fires the rule, the branch it
        completes holds nothing of the event, so the event is no closer to it
        than an unrelated event.
        """
        flipped = dict(truth)
        flipped[atom] = not truth[atom]
        for other in self.atoms:
            if other != atom and self.polarity[other] == {"+"} and other not in self.vacuous:
                flipped[other] = False
        return not self.evaluate(flipped)

    def verdict(self, event, truth, fired):
        composed = self.evaluate(truth)
        flips = [a for a in self.atoms if self._fires_after(truth, [a]) != composed]
        closeness = self.closeness(truth)
        mismatch = composed != fired
        lone = []
        if fired:
            # For a match, `flips` are the load-bearing atoms (flip one: no match).
            kind = "match"
        elif mismatch:
            kind, flips = "distant", []
        elif not closeness:
            # No positive item holds: an unrelated event, whatever the flip count.
            kind, lone, flips = "trivial", flips, []
        else:
            lone = [a for a in flips if not self._shares_branch(truth, a)]
            flips = [a for a in flips if a not in lone]
            if any("+" in self.polarity[a] and not truth[a] for a in flips):
                kind = "near-miss"
            elif flips:
                kind = "filtered"
            else:
                kind = "distant"  # some positive item holds, but no single flip fires
        lines = self.describe(event, truth)
        if mismatch:
            lines.append(f"  !! item-composed verdict ({composed}) disagrees with the "
                         f"compiled rule ({fired}); trust the compiled rule")
        return Verdict(fired, kind, flips, lines, mismatch, closeness, lone)

    def describe(self, event, truth):
        lines = []
        composed = self.evaluate(truth)
        for block in self.blocks_in_condition():
            negated = self.block_negated(block)
            atoms = [a for a in self.items if self.block_of[a] == block]
            held = _eval(self.block_tree[block], truth)
            if negated and held:
                # A matched filter suppresses only if the verdict depends on it: with
                # the block forced false, the rule would fire. A `not` that is one
                # OR-alternative of the condition may not decide anything.
                forced = dict(truth, **{a: False for a in atoms})
                if not composed and self.evaluate(forced):
                    mark, role = "!", "filter matched: suppresses"
                else:
                    mark, role = "~", "filter matched, not decisive: same verdict without it"
            elif negated:
                mark, role = ".", "filter not matched"
            else:
                mark, role = ("+", "holds") if held else ("-", "FAILS")
            lines.append(f"  {mark} {block} [{role}]")
            for atom in atoms:
                field = self.item_field[atom]
                shown = f"{field}={_short(event.get(field))}" if field else "(keyword search)"
                # Show what the item wants where it decides the verdict: a failed
                # selection item, or a filter item that matched.
                if truth.get(atom) == negated:
                    shown += f"  (rule wants: {self.item_expect[atom]})"
                lines.append(f"      {'yes' if truth.get(atom) else 'no '}  "
                             f"{atom[len(block):].lstrip('.') or atom}  {shown}")
        return lines


def _eval(node, truth):
    op = node[0]
    if op == "id":
        return bool(truth.get(node[1]))
    if op == "not":
        return not _eval(node[1], truth)
    if op == "and":
        return all(_eval(c, truth) for c in node[1])
    return any(_eval(c, truth) for c in node[1])


def render(rule, node):
    """Condition text of a subtree, with block names where a block is whole."""
    names = {id(tree): name for name, tree in rule.block_tree.items()}

    def text(n, top=False):
        if id(n) in names:
            return names[id(n)]
        if n[0] == "id":
            return n[1]
        if n[0] == "not":
            return "not " + text(n[1])
        inner = f" {n[0]} ".join(text(c) for c in n[1])
        return inner if top else f"({inner})"
    return text(node, top=True)


def _compile_docs(docs):
    queries = sqliteBackend().convert(SigmaCollection.from_dicts(docs))
    if len(queries) != 1:
        raise ValueError(f"expected one query, got {len(queries)}")
    return queries[0]


def _compile_doc(doc):
    return _compile_docs([doc])


# ---- correlation rules -------------------------------------------------------

_BACKEND = sqliteBackend()
TS_FIELD = _BACKEND.timestamp_field
# The correlation reads time exactly this way (julianday() in the compiled SQL).
_TS_SQL = _BACKEND.timestamp_seconds_expression.format(
    field=_BACKEND.escape_and_quote_field(TS_FIELD))
REPAIR_FIELD = "sigma_explain_repair"  # the field a synthetic base event carries

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _seconds(events):
    """Each event's time as the compiled correlation reads it (None: unparseable)."""
    table = sigma_eval.EventTable(events)
    return dict(table._execute(f"SELECT {sigma_eval._ROWID}, {_TS_SQL} FROM logs").fetchall())


def _stamp(secs):
    """Seconds since the epoch -> a timestamp the correlation parses (UTC, ms)."""
    ms = int(round(secs * 1000))
    stamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=ms)
    return stamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _null_key(value):
    """A group-by value the compiled SQL turns into NULL (so it drops the event)."""
    return value is None or (isinstance(value, float) and (math.isinf(value) or math.isnan(value)))


def _group_value(value):
    return value.lower() if isinstance(value, str) else value


class CorrelationRule:
    """A Sigma correlation rule plus the base rules it references (one file)."""

    is_correlation = True

    def __init__(self, docs, path=None):
        self.path = path
        self.docs = docs
        corr = next(d for d in docs if "correlation" in d)
        self.doc = corr
        self.title = corr.get("title", "")
        self.level = corr.get("level")
        spec = corr["correlation"]
        self.type = spec.get("type")
        refs = spec.get("rules") or []
        refs = [refs] if isinstance(refs, str) else list(refs)
        group_by = spec.get("group-by") or []
        self.group_by = [group_by] if isinstance(group_by, str) else list(group_by)
        span = str(spec.get("timespan", "0s"))
        self.span_text = span
        self.timespan = int(span[:-1]) * _UNITS.get(span[-1], 1) if span[:-1].isdigit() else 0
        self.threshold = spec.get("condition") or {}
        # A correlation may reference its base rules by `name` or by `id`.
        named = {key: d for d in docs if "detection" in d
                 for key in (d.get("name"), d.get("id")) if key}
        unknown = [r for r in refs if r not in named]
        if unknown:
            raise ValueError(f"{path}: the correlation references no base rule in this file "
                             f"named or identified {unknown}")
        self.base_docs = {ref: named[ref] for ref in refs}
        self.bases = {ref: PlainRule(named[ref], path) for ref in refs}
        first = next(iter(self.bases.values()), None)
        self.logsource = first.logsource if first else {}
        self.sql = sigma_eval.compile_rule(path) if path else _compile_docs(docs)
        self.ordered = self.type == "temporal_ordered"
        self.counted = self.type in ("event_count", "value_count")
        self.atoms = [f"base:{r}" for r in refs] + (["group-by"] if self.group_by else []) \
            + (["timespan"] if self.timespan else []) + (["order"] if self.ordered else []) \
            + (["threshold"] if self.counted else [])
        self._variants = {}

    def positive_atoms(self):
        return list(self.atoms)

    def negated_atoms(self):
        return []

    def null_helpers(self):
        """A correlation's own atoms are never null-safety helpers (its bases' may be)."""
        return {}

    def null_guard_issues(self):
        return [f"base {ref}: {m}" for ref, b in self.bases.items() for m in b.null_guard_issues()]

    def stripped(self):
        """This correlation with each base stripped (PlainRule.stripped())."""
        if not any(b.null_helpers() for b in self.bases.values()):
            return self
        clone = copy.copy(self)
        clone.bases = {ref: b.stripped() for ref, b in self.bases.items()}
        return clone

    def fields(self, atom):
        if atom.startswith("base:"):
            base = self.bases.get(atom[5:])
            return [f for a in base.atoms for f in base.fields(a)] if base else []
        if atom == "group-by":
            return list(self.group_by)
        return []

    # -- verifying a near-miss by construction --------------------------------

    def _fires(self, events, sql=None):
        return bool(events) and bool(sigma_eval.EventTable(events).hit_indices(sql or self.sql))

    def _variant(self, key):
        """The compiled correlation with one atom relaxed (cached)."""
        if key not in self._variants:
            docs = copy.deepcopy(self.docs)
            if key == "order":
                next(d for d in docs if "correlation" in d)["correlation"]["type"] = "temporal"
            else:  # base:<ref> -> that base matches only a synthetic repair event
                at = next(n for n, d in enumerate(self.docs) if d is self.base_docs[key[5:]])
                docs[at]["detection"] = {"sigma_explain_repair": {REPAIR_FIELD: key},
                                         "condition": "sigma_explain_repair"}
            self._variants[key] = _compile_docs(docs)
        return self._variants[key]

    def _repair_base(self, atom, seen, secs):
        """Add one event of the missing base next to a matched event; does it fire?"""
        anchors = sorted(range(len(seen)), key=lambda n: secs[n])[:16]
        offsets = (0.0, -0.001, 0.001) if self.ordered else (0.0,)
        tries = []
        for n in anchors:
            for off in offsets:
                synthetic = {f: seen[n].get(f) for f in self.group_by}
                synthetic[TS_FIELD] = _stamp(secs[n] + off)
                synthetic[REPAIR_FIELD] = atom
                tries.append(synthetic)
        sql = self._variant(atom)
        if not self.counted:
            # More events of the missing base can only help a temporal correlation,
            # and each alert uses one of them: try every placement in one run.
            return self._fires(seen + tries, sql)
        return any(self._fires(seen + [t], sql) for t in tries)

    @staticmethod
    def _restamped(seen, secs):
        """The matched events squeezed into the window, order (and ties) kept."""
        ranks = {t: n for n, t in enumerate(sorted(set(secs)))}
        start = min(ranks)
        return [dict(e, **{TS_FIELD: _stamp(start + ranks[t] * 0.001)}) for e, t in zip(seen, secs)]

    def _duplicated(self, seen, copies):
        field = self.threshold.get("field") if self.type == "value_count" else None
        out = list(seen)
        for e in seen:
            for j in range(1, copies + 1):
                dup = dict(e)
                if field and e.get(field) is not None:
                    dup[field] = f"{e[field]}~{j}"  # a new distinct value of the counted field
                out.append(dup)
        return out

    def _threshold_copies(self):
        """Copies per matched event that can reach the count (None: adding cannot)."""
        cond = {k: v for k, v in self.threshold.items() if k != "field"}
        if "gte" in cond:
            return [max(int(cond["gte"]) - 1, 1)]
        if "gt" in cond:
            return [max(int(cond["gt"]), 1)]
        if "eq" in cond:
            return list(range(1, max(int(cond["eq"]), 2)))
        return None

    def verdict_set(self, events, table=None):
        """Judge an event set as one unit (the correlation's own unit)."""
        table = table or sigma_eval.EventTable(events)
        fired = bool(table.hit_indices(self.sql)) if self.sql else False
        matched = {}
        lines = []
        for ref, base in self.bases.items():
            idx = sorted({i for hit in table.hit_indices(base.sql) for i in hit})
            matched[ref] = idx
            shown = ", ".join(self._label(events[i]) for i in idx[:4])
            lines.append(f"  {'+' if idx else '-'} base:{ref} matched {len(idx)} event(s)"
                         + (f": {shown}" if idx else ""))
            if not idx:
                rows, _ = base.truth_table(table)
                best = _nearest_plain(base, events, rows, set(), k=1)
                for i, v in best:
                    lines.append(f"      nearest event #{i} for base:{ref} ({v.kind}"
                                 + (f", one flip: {', '.join(v.atoms)}" if v.atoms else "") + "):")
                    lines.extend("    " + ln for ln in v.lines)
        if fired:
            return Verdict(True, "match", [], lines)
        # Only base-matched events reach the correlation; the SQL then drops any
        # without a parseable timestamp or a group-by value.
        hit = sorted({i for idx in matched.values() for i in idx})
        seen = [events[i] for i in hit]
        when = _seconds(seen)
        secs = [when.get(n) for n in range(len(seen))]
        blind = set()
        for i, e, t in zip(hit, seen, secs):
            gaps = []
            if t is None:
                gaps.append(f"no parseable `{TS_FIELD}` ({_short(e.get(TS_FIELD), 40)})")
            absent = [f for f in self.group_by if _null_key(e.get(f))]
            if absent:
                gaps.append(f"no group-by value for {', '.join(absent)}")
            if gaps:
                blind.add(i)
                lines.append(f"  - event #{i} ({self._label(e)}): {'; '.join(gaps)}, so the "
                             "correlation drops it")
        closeness = sum(1 for idx in matched.values() if any(i not in blind for i in idx))
        if not closeness:
            return Verdict(False, "trivial", [], lines, unseen=sorted(blind))
        if blind:
            lines.append("  ~ not a near-miss: an event of the set is invisible to the "
                         "correlation (timestamp or group-by value missing), so no single atom "
                         "is what fails")
            return Verdict(False, "distant", [], lines, closeness=closeness, unseen=sorted(blind))
        missing = [r for r, idx in matched.items() if not idx]
        repaired = []
        for atom in self.atoms:
            ok, note = self._check_atom(atom, seen, secs, missing)
            if note:
                lines.append(note)
            if ok:
                repaired.append(atom)
        return Verdict(False, "near-miss" if repaired else "distant", repaired, lines,
                       closeness=closeness)

    def _check_atom(self, atom, seen, secs, missing):
        """(does repairing only `atom` fire the correlation?, explanation line)."""
        def outcome(ok):
            return "the correlation fires" if ok else "still no alert"

        if atom.startswith("base:"):
            if atom[5:] not in missing:
                return False, None
            if len(missing) > 1:
                return False, (f"  - {atom}: no event matches it, nor {len(missing) - 1} other "
                               "base(s), so one added event cannot fire the correlation")
            ok = self._repair_base(atom, seen, secs)
            return ok, (f"  - {atom}: no event matches it; with one such event added in a matched "
                        f"event's group and time -> {outcome(ok)}")
        if missing:
            return False, None  # a base is absent: no other atom can be the only break
        groups = {}
        for n, e in enumerate(seen):
            key = tuple(_group_value(e.get(f)) for f in self.group_by)
            groups.setdefault(key[0] if len(key) == 1 else key, []).append(n)
        shown = ", ".join(f"{_short(k, 30)}: {len(g)}" for k, g in list(groups.items())[:4]) \
            + (", ..." if len(groups) > 4 else "")
        if atom == "group-by":
            if len(groups) == 1:
                return False, (f"  . group-by {self.group_by}: every matched event shares "
                               f"{_short(next(iter(groups)), 40)}")
            ok = self._fires([dict(e, **{f: seen[0].get(f) for f in self.group_by}) for e in seen])
            return ok, (f"  - group-by {self.group_by}: the matched events fall in {len(groups)} "
                        f"groups (value: events = {shown}); with one shared value -> {outcome(ok)}")
        if atom == "timespan":
            widest = max(max(secs[n] for n in g) - min(secs[n] for n in g) for g in groups.values())
            ok = self._fires(self._restamped(seen, secs))
            return ok, (f"  - timespan {self.span_text}: within one group the matched events "
                        f"span at most {widest:.3f}s; re-stamped into the window, order kept -> "
                        f"{outcome(ok)}")
        if atom == "order":
            ok = self._fires(seen, self._variant("order"))
            return ok, (f"  - order: with the order of the bases ignored -> {outcome(ok)}"
                        + (" (the events come in the wrong order)" if ok else ""))
        if atom == "threshold":
            plan = self._threshold_copies()
            if plan is None:
                return False, f"  - threshold {self.threshold}: adding events cannot satisfy it"
            ok = any(self._fires(self._duplicated(seen, k)) for k in plan)
            return ok, (f"  - threshold {self.threshold}: matched events per group ({shown}); "
                        f"with every matched event duplicated in place -> {outcome(ok)}")
        return False, None

    @staticmethod
    def _label(event):
        bits = [str(event.get(k)) for k in ("syscall", "pid", "eventName", "verb") if event.get(k)]
        return "/".join(bits) or "event"


# ---- loading and the public helpers -----------------------------------------


_CACHE = {}


def from_docs(docs, path=None):
    """A PlainRule or a CorrelationRule from parsed YAML documents."""
    docs = [d for d in docs if d]
    if any("correlation" in d for d in docs):
        return CorrelationRule(docs, path)
    if len(docs) != 1:
        raise ValueError(f"{path}: expected one rule document, got {len(docs)}")
    return PlainRule(docs[0], path)


def load(path):
    """Load a rule file as a PlainRule or a CorrelationRule (cached per path)."""
    path = os.path.abspath(path)
    if path not in _CACHE:
        with open(path, encoding="utf-8") as fh:
            _CACHE[path] = from_docs(list(yaml.safe_load_all(fh)), path)
    return _CACHE[path]


def judge_events(rule, events, table=None):
    """Plain rule: one Verdict per event. Correlation: one Verdict for the whole set."""
    table = table or sigma_eval.EventTable(events)
    if rule.is_correlation:
        return [rule.verdict_set(events, table)]
    rows, fired = rule.truth_table(table)
    return [rule.verdict(events[i], rows[i], i in fired) for i in range(len(events))]


def _nearest_plain(rule, events, rows, fired, k=3, candidates=None, shortlist=50):
    pool = list(candidates) if candidates is not None else list(range(len(events)))
    # Grading every event of a long log is slow; grade the most promising first.
    pool.sort(key=lambda i: (i not in fired, -rule.closeness(rows[i]), i))
    scored = []
    for i in pool[:max(shortlist, k)]:
        v = rule.verdict(events[i], rows[i], i in fired)
        scored.append((KIND_RANK[v.kind], -v.closeness, i, v))
    scored.sort(key=lambda t: t[:3])
    return [(i, v) for _, _, i, v in scored[:k]]


def explain_miss(rule, events, k=2, candidates=None, label=None):
    """Lines explaining why a rule did not fire on `events`.

    For a plain rule: how many events each block and each of its items matched,
    then the `k` events that came closest, item by item. `candidates` limits the
    nearest-event search to some indices (e.g. the emulation's own events), while
    the counts still cover every event. `label(event)` names an event.
    """
    if not events:
        return ["  (no events to explain: the log or the window is empty)"]
    table = sigma_eval.EventTable(events)
    if rule.is_correlation:
        sub = [events[i] for i in candidates] if candidates is not None else events
        return rule.verdict_set(sub).lines
    rows, fired = rule.truth_table(table)
    pool = list(candidates) if candidates is not None else list(range(len(events)))
    scope = pool if candidates is not None else range(len(events))
    noun = "candidate event(s)" if candidates is not None else "event(s)"
    lines = []
    for block in rule.blocks_in_condition():
        negated = rule.block_negated(block)
        held = sum(1 for i in scope if _eval(rule.block_tree[block], rows[i]))
        parts = []
        for atom in (a for a in rule.items if rule.block_of[a] == block):
            n = sum(1 for i in scope if rows[i][atom])
            parts.append(f"{atom[len(block):].lstrip('.') or atom} {n}")
        lines.append(f"  {'filter' if negated else 'block '} {block}: {held}/{len(scope)} {noun}"
                     f" (per item: {', '.join(parts)})")
        if not negated and held == 0:
            absent = [rule.item_field[a] for a in rule.items
                      if rule.block_of[a] == block and rule.item_field[a]
                      and all(e.get(rule.item_field[a]) is None for e in events)]
            if absent:
                lines.append(f"      no event carries {', '.join(absent)}: the telemetry may not "
                             "record it (log level, audit rule, or field name/casing)")
    if not pool:
        lines.append("  (no candidate events: nothing carried the emulation's marker)")
        return lines
    for i, v in _nearest_plain(rule, events, rows, fired, k=k, candidates=pool):
        name = label(events[i]) if label else f"event #{i}"
        hint = f"; one flip would fire it: {', '.join(v.atoms)}" if v.atoms and not v.fired else ""
        lines.append(f"  nearest: {name} ({v.kind}{hint})")
        lines.extend("  " + ln for ln in v.lines)
    return lines


def explain_hit(rule, event):
    """Lines explaining why a rule fired on one event (an unexpected match)."""
    v = judge_events(rule, [event])[0]
    return v.lines


def coverage(rule, verdicts):
    """Which condition atoms the non-trivial negatives exercise.

    Returns ({atom: [indices of verdicts that flip it]}, [atoms nobody flips]).
    Only near-miss and filtered verdicts count: a trivial or distant negative
    does not show that any single part of the rule is load-bearing.
    """
    covered = {a: [] for a in rule.atoms}
    for i, v in enumerate(verdicts):
        if v.kind in NON_TRIVIAL:
            for atom in v.atoms:
                covered.setdefault(atom, []).append(i)
    return covered, [a for a, hits in covered.items() if not hits]


# ---- self-test ---------------------------------------------------------------


def _ts(seconds):
    """A test timestamp `seconds` after 2026-10-12 13:00:00 UTC."""
    return _stamp(datetime(2026, 10, 12, 13, tzinfo=timezone.utc).timestamp() + seconds)


def _base(name, syscall, rule_id=None):
    doc = {"title": f"{syscall} base", "name": name,
           "logsource": {"product": "linux", "service": "auditd"},
           "detection": {"sel": {"type": "SYSCALL", "syscall": syscall}, "condition": "sel"},
           "level": "informational"}
    if rule_id:
        doc["id"] = rule_id
    return doc


def _correlation(kind, rules, bases, timespan="5s", condition=None):
    spec = {"type": kind, "rules": rules, "group-by": ["pid"], "timespan": timespan}
    if condition:
        spec["condition"] = condition
    return from_docs([{"title": f"self-test {kind}", "correlation": spec, "level": "high"}]
                     + bases)


def _plain(detection):
    return from_docs([{"title": "self-test", "level": "high", "detection": detection,
                       "logsource": {"product": "linux", "service": "auditd"}}])


def _ev(syscall, pid, seconds, **extra):
    return dict({"type": "SYSCALL", "syscall": syscall, "pid": pid, "timestamp": _ts(seconds)},
                **extra)


def _drop(event, field):
    return {f: v for f, v in event.items() if f != field}


def _one(rule, event):
    return judge_events(rule, [event])[0]


def _case(rule, kind, events, breaks=None):
    import rule_cases  # the runner these grades feed
    case = {"name": "t", "kind": kind, "why": "self-test", "events": events}
    if breaks:
        case["breaks"] = breaks
    return rule_cases.run_case(rule, case)


PIPE, SPLICE = _ev("pipe", 9401, 0), _ev("splice", 9401, 0.2)


def _test_correlation(check):
    """Finding 0: every correlation near-miss is verified through the compiled SQL."""
    temporal = _correlation("temporal", ["p_pipe", "p_splice"],
                            [_base("p_pipe", "pipe"), _base("p_splice", "splice")])
    no_ts = [_drop(PIPE, "timestamp"), _drop(SPLICE, "timestamp")]
    audit_ts = [dict(PIPE, timestamp="audit(1760274000.000:1)"),
                dict(SPLICE, timestamp="audit(1760274000.200:2)")]
    for name, events, kind, atoms in [
            ("pipe+splice 200ms apart, same pid", [PIPE, SPLICE], "match", []),
            ("splice has no timestamp", [PIPE, _drop(SPLICE, "timestamp")], "distant", []),
            ("neither has a timestamp", no_ts, "trivial", []),
            ("splice has no pid", [PIPE, _drop(SPLICE, "pid")], "distant", []),
            ("auditd-style timestamps", audit_ts, "trivial", []),
            ("other pid AND 30s later", [PIPE, _ev("splice", 9999, 30)], "distant", []),
            ("other pid, same window", [PIPE, _ev("splice", 9999, 0.2)], "near-miss", ["group-by"]),
            ("same pid, 30s later", [PIPE, _ev("splice", 9401, 30)], "near-miss", ["timespan"]),
            ("pipe only", [PIPE], "near-miss", ["base:p_splice"]),
            ("nothing of the rule", [{"x": 1}], "trivial", [])]:
        v = temporal.verdict_set(events)
        check(f"temporal: {name} -> {kind} {atoms}", v.kind == kind and v.atoms == atoms,
              f"got {v.kind} {v.atoms}")
    lines = temporal.verdict_set([PIPE, _drop(SPLICE, "timestamp")]).lines
    check("temporal: a missing timestamp is named",
          any("no parseable `timestamp`" in ln for ln in lines), "\n".join(lines))
    lines = temporal.verdict_set([PIPE, _drop(SPLICE, "pid")]).lines
    check("temporal: a missing group key is named",
          any("no group-by value for pid" in ln for ln in lines), "\n".join(lines))
    check("rule_cases: `breaks: timespan` on a set with no timestamps fails",
          not _case(temporal, "near-miss", no_ts, "timespan").ok)
    check("rule_cases: `breaks: group-by` on a set that also breaks the window fails",
          not _case(temporal, "near-miss", [PIPE, _ev("splice", 9999, 30)], "group-by").ok)

    # Randomised oracle: perturb the positive's pid / timestamp, then repair ONLY the
    # atom the grade names (one shared pid, one shared instant): the rule must fire.
    rng = random.Random(7)
    claimed = wrong = 0
    for _ in range(150):
        events = [dict(PIPE), dict(SPLICE)]
        for e in events:
            if rng.random() < 0.4:
                e["pid"] = rng.choice([1, 2, "1", None])
            if rng.random() < 0.4:
                e["timestamp"] = rng.choice([_ts(0), _ts(300), None, "bad"])
            for k in [k for k, val in e.items() if val is None]:
                del e[k]
        v = temporal.verdict_set(events)
        for atom in (a for a in v.atoms if a in ("group-by", "timespan")):
            field, value = ("pid", events[0].get("pid")) if atom == "group-by" \
                else ("timestamp", _ts(0))
            claimed += 1
            repaired = [dict(e, **{field: value}) for e in events]
            wrong += not sigma_eval.evaluate(temporal.sql, repaired)
    check(f"temporal: each claimed group-by/timespan near-miss fires once repaired "
          f"({claimed} claims)", claimed and not wrong, f"{wrong} did not")

    counting = _correlation("event_count", ["k_add"], [_base("k_add", "add_key")], "10s",
                            {"gte": 3})
    spread = [_ev("add_key", 1, s) for s in (0, 20, 40, 59)]
    v = counting.verdict_set(spread)
    check("event_count: count reached but spread past the window -> near-miss on timespan",
          v.kind == "near-miss" and "timespan" in v.atoms, f"got {v.kind} {v.atoms}")
    check("rule_cases: `breaks: timespan` on that set holds",
          _case(counting, "near-miss", spread, "timespan").ok)
    v = counting.verdict_set([_ev("add_key", 1, 0)])
    check("event_count: one event -> near-miss on threshold only",
          v.kind == "near-miss" and v.atoms == ["threshold"], f"got {v.kind} {v.atoms}")
    v = counting.verdict_set([_ev("add_key", pid, 0) for pid in (1, 2, 3)])
    check("event_count: three events in three pids -> group-by among the repairs",
          v.kind == "near-miss" and "group-by" in v.atoms, f"got {v.kind} {v.atoms}")

    distinct = _correlation("value_count", ["k_add2"], [_base("k_add2", "add_key")], "10s",
                            {"gte": 3, "field": "a0"})
    v = distinct.verdict_set([_ev("add_key", 1, s, a0="x") for s in (0, 1, 2)])
    check("value_count: three events, one value -> near-miss on threshold, not timespan",
          v.kind == "near-miss" and "threshold" in v.atoms and "timespan" not in v.atoms,
          f"got {v.kind} {v.atoms}")
    v = distinct.verdict_set([_ev("add_key", 1, s, a0=f"k{s}") for s in (0, 1, 2)])
    check("value_count: three distinct values fire", v.kind == "match", v.kind)

    ordered = _correlation("temporal_ordered", ["o_pipe", "o_splice"],
                           [_base("o_pipe", "pipe"), _base("o_splice", "splice")])
    check("temporal_ordered: has an `order` atom", "order" in ordered.atoms, str(ordered.atoms))
    for name, events, kind, atoms in [
            ("pipe then splice 1s", [_ev("pipe", 1, 0), _ev("splice", 1, 1)], "match", []),
            ("splice then pipe 1s", [_ev("splice", 1, 0), _ev("pipe", 1, 1)],
             "near-miss", ["order"]),
            ("pipe then splice 30s", [_ev("pipe", 1, 0), _ev("splice", 1, 30)],
             "near-miss", ["timespan"]),
            ("splice then pipe 30s", [_ev("splice", 1, 0), _ev("pipe", 1, 30)], "distant", []),
            ("pipe only", [_ev("pipe", 1, 0)], "near-miss", ["base:o_splice"]),
            ("splice only", [_ev("splice", 1, 0)], "near-miss", ["base:o_pipe"])]:
        v = ordered.verdict_set(events)
        check(f"temporal_ordered: {name} -> {kind} {atoms}",
              v.kind == kind and v.atoms == atoms, f"got {v.kind} {v.atoms}")
    check("temporal_ordered: the `order` grade is real (swap the two times: it fires)",
          bool(sigma_eval.evaluate(ordered.sql, [_ev("splice", 1, 1), _ev("pipe", 1, 0)])))


def _test_correlation_by_id(check):
    """Finding 7: a correlation may name its base rules by id."""
    uid = "4f6c1c1e-0000-4000-8000-000000000001"
    by_id = _correlation("temporal", [uid, "i_splice"],
                         [_base("i_pipe", "pipe", uid), _base("i_splice", "splice")])
    check("correlation by id: loads with a base:<id> atom", f"base:{uid}" in by_id.atoms,
          str(by_id.atoms))
    v = by_id.verdict_set([PIPE, SPLICE])
    check("correlation by id: fires on its positive", v.kind == "match", v.kind)
    v = by_id.verdict_set([SPLICE])
    check("correlation by id: half a correlation is a near-miss on the id base",
          v.atoms == [f"base:{uid}"], f"got {v.kind} {v.atoms}")


def _test_trivial(check):
    """Finding 1: no positive item holds -> trivial, whatever the flip count."""
    one_item = _plain({"sel": {"source": ["file", "http"]}, "condition": "sel"})
    v = _one(one_item, {"source": "api"})
    check("one-item rule: a different value is trivial (no item holds)", v.kind == "trivial",
          f"got {v.kind} {v.atoms}")
    check("rule_cases: that event cannot pass as a near-miss",
          not _case(one_item, "near-miss", [{"source": "api"}], "sel.source").ok)
    branches = _plain({"sel_put": {"eventName": "Put", "flag": False},
                       "sel_delete": {"eventName": "Delete"},
                       "condition": "sel_put or sel_delete"})
    put = {"eventName": "Put", "flag": True}
    v = _one(branches, put)
    check("OR of branches: a flip counts only through a branch the event shares",
          v.kind == "near-miss" and v.atoms == ["sel_put.flag"]
          and v.lone == ["sel_delete.eventName"], f"got {v.kind} {v.atoms} lone {v.lone}")
    res = _case(branches, "near-miss", [put], "sel_delete.eventName")
    check("rule_cases: declaring the lone branch fails, and says why",
          not res.ok and "branch" in res.detail, res.detail)
    check("OR of branches: another rule's record is trivial",
          _one(branches, {"eventName": "PutBucketPolicy"}).kind == "trivial")
    vacuous = _plain({"sel": {"eventName": "X", "errorCode": None}, "condition": "sel"})
    check("an item that holds on an empty event does not make an event close",
          _one(vacuous, {"eventName": "Y"}).kind == "trivial")
    v = _one(vacuous, {"eventName": "X", "errorCode": "AccessDenied"})
    check("... but a real near-miss on that item still grades near-miss",
          v.kind == "near-miss" and v.atoms == ["sel.errorCode"], f"got {v.kind} {v.atoms}")

    # {"x": 1} shares nothing with any rule in the repo, so it is trivial for each.
    sigma_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigma")
    paths = sorted(glob.glob(os.path.join(sigma_dir, "*", "*.yml")))
    not_trivial = []
    for path in paths:
        v = judge_events(load(path), [{"x": 1}])[0]
        if v.kind != "trivial":
            not_trivial.append(f"{os.path.relpath(path, sigma_dir)} ({v.kind} {v.atoms})")
    check(f'{{"x": 1}} is trivial for every rule under detections/sigma/ ({len(paths)} rules)',
          paths and not not_trivial, "; ".join(not_trivial))


def _test_same_field_twice(check):
    """Finding 3: one field with two modifiers in one block is two atoms."""
    dup = _plain({"selection": {"type": "SYSCALL", "exe|startswith": "/tmp/",
                                "exe|endswith": "/payload"}, "condition": "selection"})
    check("same field twice: distinct atoms",
          dup.atoms == ["selection.type", "selection.exe|startswith", "selection.exe|endswith"],
          str(dup.atoms))
    near = {"type": "SYSCALL", "exe": "/usr/bin/payload"}
    v = _one(dup, near)
    check("same field twice: only startswith fails -> near-miss on it, no mismatch",
          v.kind == "near-miss" and v.atoms == ["selection.exe|startswith"] and not v.mismatch,
          f"got {v.kind} {v.atoms} mismatch={v.mismatch}")
    v = _one(dup, {"type": "SYSCALL", "exe": "/usr/bin/other"})
    check("same field twice: both fail (two flips) -> distant, no mismatch",
          v.kind == "distant" and not v.mismatch, f"got {v.kind} {v.atoms}")
    res = _case(dup, "near-miss", [near], "selection.exe")
    check("rule_cases: a bare `selection.exe` is rejected as ambiguous",
          not res.ok and "ambiguous" in res.detail, res.detail)
    dup_list = _plain({"sel": [{"exe|startswith": "/tmp/", "exe|endswith": "/p"},
                               {"comm": "x"}], "condition": "sel"})
    check("same field twice in a list of maps: distinct atoms",
          dup_list.atoms == ["sel[0].exe|startswith", "sel[0].exe|endswith", "sel[1].comm"],
          str(dup_list.atoms))
    try:
        dup._compile_item("selection", "selection.type", "type", "x")
        check("an atom name collision raises", False, "no error")
    except ValueError:
        check("an atom name collision raises", True)


def _test_definitions(check):
    """Finding 6: distant and trivial follow the documented definitions."""
    four = _plain({"sel": {"a": 1, "b": 2, "c": 3, "d": 4}, "f": {"u": 0},
                   "condition": "sel and not f"})
    for name, event, kind in [("three flips away", {"a": 1}, "distant"),
                              ("two flips away", {"a": 1, "b": 2}, "distant"),
                              ("one flip away", {"a": 1, "b": 2, "c": 3}, "near-miss"),
                              ("nothing holds", {"x": 1}, "trivial"),
                              ("allowlisted", {"a": 1, "b": 2, "c": 3, "d": 4, "u": 0},
                               "filtered")]:
        v = _one(four, event)
        check(f"definitions: {name} -> {kind}", v.kind == kind, f"got {v.kind} {v.atoms}")
    check("rule_cases: a confounder three flips away holds (distant, not trivial)",
          _case(four, "confounder", [{"a": 1}]).ok)
    res = _case(four, "confounder", [{"x": 1}])
    check("rule_cases: a confounder where nothing holds fails as trivial",
          not res.ok and "no positive item holds" in res.detail, res.detail)


def _test_filter_labels(check):
    """corpus-cloud 7: a matched `not` that decides nothing is not 'suppresses'."""
    or_not = _plain({"sel": {"s": 1}, "alt": {"a": 1}, "f": {"fv": 1},
                     "condition": "sel and (alt or not f)"})
    v = _one(or_not, {"s": 1, "a": 1, "fv": 1})
    label = next((ln for ln in v.lines if " f [" in ln), "")
    check("describe: a matched filter on a firing event is not 'suppresses'",
          v.fired and "suppresses" not in label and "not decisive" in label, label)
    v = _one(or_not, {"s": 1, "fv": 1})
    label = next((ln for ln in v.lines if " f [" in ln), "")
    check("describe: a matched filter that blocks the alert is 'suppresses'",
          not v.fired and "suppresses" in label, label)


def _self_test():
    failures = []

    def check(name, cond, detail=""):
        print(f"{'ok  ' if cond else 'FAIL'}  {name}" + (f": {detail}" if detail and not cond
                                                         else ""))
        if not cond:
            failures.append(name)

    for test in (_test_correlation, _test_correlation_by_id, _test_trivial,
                 _test_same_field_twice, _test_definitions, _test_filter_labels):
        try:
            test(check)
        except Exception as e:  # a crash is a failed check, not the end of the run
            check(f"{test.__name__} runs", False, f"{type(e).__name__}: {e}")
    print()
    if failures:
        print(f"FAILED: {len(failures)} self-test check(s).")
        return 1
    print("All self-test checks hold.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Explain Sigma verdicts item by item (a library; "
                                             "run --self-test to check the grading).")
    ap.add_argument("--self-test", action="store_true",
                    help="grade crafted rules and events and check every grade")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
