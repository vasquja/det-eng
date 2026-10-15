"""
Explain a Sigma rule's verdict on events, one detection block at a time.

sigma_eval answers "does the rule fire?". That is enough for a gate, but not for
whoever has to fix a red run: "no hit" leaves them to guess which part of the
rule failed. This module compiles every named detection block of a rule on its
own (through the same pySigma SQLite backend), evaluates each block over the
events, and re-evaluates the rule's condition over those per-block results. So a
verdict can be explained field by field, and a non-matching event can be graded
by how close it came to firing the rule:

  match      the rule fires on it.
  near-miss  the event is one condition atom away from firing: flipping one
             positive block (a selection) alone would fire the rule. This is a
             variant that keeps the technique's surface but breaks one required
             part, the strongest negative test a rule can have.
  filtered   every selection holds and one `not <filter>` block alone suppresses
             it: an allowlisted look-alike.
  distant    some positive block holds, but no single flip fires the rule.
  trivial    no positive block holds. Any reasonable rule rejects it, so as a
             negative test it proves nothing about this rule.

For a correlation rule the unit is an event set. Its atoms are its base rules
(`base:<name>`), its `group-by`, its `timespan`, and (for count rules) its
threshold. A set that matches every base rule but one is a near-miss on that
base ("half a correlation"); a set that matches all bases in different groups is
a near-miss on `group-by`.

The per-block result always agrees with the full rule: the pySigma SQLite
backend wraps negated blocks in COALESCE, so an absent field reads as "block
false" in both. explain() still cross-checks the composed verdict against the
compiled rule and reports any disagreement instead of hiding it.
"""

import fnmatch
import os
from datetime import datetime

import yaml

import sigma_eval

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

    def __init__(self, fired, kind, atoms, lines, mismatch=False, closeness=0):
        self.fired = fired        # the compiled rule's own answer (authoritative)
        self.kind = kind          # match / near-miss / filtered / distant / trivial
        self.atoms = atoms        # atoms whose single flip changes the verdict
        self.lines = lines        # human-readable block-by-block explanation
        self.mismatch = mismatch  # composed verdict disagreed with the compiled rule
        self.closeness = closeness  # positive atoms that hold (tie-break for nearest)

    def __repr__(self):
        return f"Verdict({self.kind}, atoms={self.atoms})"


# ---- plain rules -------------------------------------------------------------


class PlainRule:
    """One Sigma rule: its blocks, each compiled alone, and its condition tree."""

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
        self.items = {}      # atom -> compiled SQL
        self.item_field = {}  # atom -> field name (None for keyword atoms)
        self.block_tree = {}  # block -> subtree over its item atoms
        for name, definition in detection.items():
            self.block_tree[name] = self._block_items(name, definition)
        rule = SigmaRule.from_dict({"title": self.title, "logsource": self.logsource,
                                    "detection": doc["detection"]})
        parsed = rule.detection.parsed_condition[0].parse(postprocess=False)
        self.tree = self._convert(parsed)
        self.polarity = {}
        self._walk_polarity(self.tree, True)
        self.atoms = list(self.polarity)
        self.block_of = {a: (a.split(".", 1)[0].split("[", 1)[0]) for a in self.items}

    def _compile_item(self, atom, field_key, value):
        detection = {"_item": {field_key: value}, "condition": "_item"} if field_key is not None \
            else {"_item": value, "condition": "_item"}
        self.items[atom] = _compile_doc({"title": f"{self.title} [{atom}]",
                                         "logsource": self.logsource, "detection": detection})
        self.item_field[atom] = str(field_key).split("|")[0] if field_key is not None else None
        return ("id", atom)

    def _block_items(self, name, definition):
        if isinstance(definition, dict):
            if not definition:
                raise ValueError(f"{self.path}: empty detection block {name}")
            return ("and", [self._compile_item(f"{name}.{str(k).split('|')[0]}", k, v)
                            for k, v in definition.items()])
        if isinstance(definition, list) and definition and all(isinstance(m, dict)
                                                                 for m in definition):
            if len(definition) == 1:
                return self._block_items(name, definition[0])
            return ("or", [("and", [self._compile_item(f"{name}[{i}].{str(k).split('|')[0]}", k, v)
                                    for k, v in m.items()])
                           for i, m in enumerate(definition)])
        return self._compile_item(name, None, definition)  # keyword search

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
        return sum(1 for a in self.positive_atoms() if truth.get(a))

    def _fires_after(self, truth, flips):
        flipped = dict(truth)
        for atom in flips:
            flipped[atom] = not truth[atom]
        return self.evaluate(flipped)

    def verdict(self, event, truth, fired):
        composed = self.evaluate(truth)
        flips = [a for a in self.atoms if self._fires_after(truth, [a]) != composed]
        closeness = self.closeness(truth)
        mismatch = composed != fired
        if fired:
            # For a match, `flips` are the load-bearing atoms (flip one: no match).
            kind = "match"
        elif mismatch:
            kind, flips = "distant", []
        elif any("+" in self.polarity[a] and not truth[a] for a in flips):
            kind = "near-miss"
        elif flips:
            kind = "filtered"
        elif closeness and any(self._fires_after(truth, [a, b])
                               for i, a in enumerate(self.atoms) for b in self.atoms[i + 1:]):
            kind = "distant"  # two flips away
        else:
            kind = "trivial"  # three or more flips away, or nothing of the rule holds
        lines = self.describe(event, truth)
        if mismatch:
            lines.append(f"  !! item-composed verdict ({composed}) disagrees with the "
                         f"compiled rule ({fired}); trust the compiled rule")
        return Verdict(fired, kind, flips, lines, mismatch, closeness)

    def describe(self, event, truth):
        lines = []
        for block in self.blocks_in_condition():
            negated = self.block_negated(block)
            held = _eval(self.block_tree[block], truth)
            if negated:
                mark, role = ("!", "filter matched: suppresses") if held \
                    else (".", "filter not matched")
            else:
                mark, role = ("+", "holds") if held else ("-", "FAILS")
            lines.append(f"  {mark} {block} [{role}]")
            for atom in (a for a in self.items if self.block_of[a] == block):
                field = self.item_field[atom]
                shown = f"{field}={_short(event.get(field))}" if field else "(keyword search)"
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


def _compile_doc(doc):
    queries = sqliteBackend().convert(SigmaCollection.from_dicts([doc]))
    if len(queries) != 1:
        raise ValueError(f"expected one query, got {len(queries)}")
    return queries[0]


# ---- correlation rules -------------------------------------------------------


def _parse_time(value):
    if value is None:
        return None
    text = str(value).replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.fromisoformat(text) if fmt is None else datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class CorrelationRule:
    """A Sigma correlation rule plus the base rules it references (one file)."""

    is_correlation = True

    def __init__(self, docs, path=None):
        self.path = path
        corr = next(d for d in docs if "correlation" in d)
        self.doc = corr
        self.title = corr.get("title", "")
        self.level = corr.get("level")
        spec = corr["correlation"]
        self.type = spec.get("type")
        refs = spec.get("rules") or []
        refs = [refs] if isinstance(refs, str) else refs
        group_by = spec.get("group-by") or []
        self.group_by = [group_by] if isinstance(group_by, str) else list(group_by)
        span = str(spec.get("timespan", "0s"))
        self.timespan = int(span[:-1]) * _UNITS.get(span[-1], 1) if span[:-1].isdigit() else 0
        self.threshold = spec.get("condition") or {}
        named = {d.get("name"): d for d in docs if "detection" in d and d.get("name")}
        self.bases = {ref: PlainRule(named[ref], path) for ref in refs}
        first = next(iter(self.bases.values()), None)
        self.logsource = first.logsource if first else {}
        self.sql = sigma_eval.compile_rule(path) if path else None
        self.atoms = [f"base:{r}" for r in refs] + (["group-by"] if self.group_by else []) \
            + (["timespan"] if self.timespan else []) \
            + (["threshold"] if self.type in ("event_count", "value_count") else [])

    def positive_atoms(self):
        return list(self.atoms)

    def negated_atoms(self):
        return []

    def fields(self, atom):
        if atom.startswith("base:"):
            base = self.bases.get(atom[5:])
            return [f for a in base.atoms for f in base.fields(a)] if base else []
        if atom == "group-by":
            return list(self.group_by)
        return []

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
        missing = [r for r, idx in matched.items() if not idx]
        if fired:
            return Verdict(True, "match", [], lines)
        if len(missing) == len(matched):
            return Verdict(False, "trivial", [], lines)
        if missing:
            kind = "near-miss" if len(missing) == 1 else "distant"
            return Verdict(False, kind, [f"base:{r}" for r in missing] if kind == "near-miss" else [],
                           lines, closeness=len(matched) - len(missing))
        # Every base matched somewhere: the group-by, the timespan or the count failed.
        groups = {}
        for ref, idx in matched.items():
            for i in idx:
                key = tuple(events[i].get(f) for f in self.group_by)
                groups.setdefault(key, {}).setdefault(ref, []).append(i)
        complete = {k: v for k, v in groups.items() if len(v) == len(matched)}
        if self.group_by and not complete:
            lines.append(f"  - group-by {self.group_by}: no single group holds every base "
                         f"(groups seen: {', '.join(str(k) for k in list(groups)[:5])})")
            return Verdict(False, "near-miss", ["group-by"], lines, closeness=len(matched))
        if self.type in ("event_count", "value_count"):
            sizes = {k: sum(len(v) for v in g.values()) for k, g in complete.items()}
            lines.append(f"  - threshold {self.threshold} not reached (largest group: "
                         f"{max(sizes.values(), default=0)} event(s))")
            return Verdict(False, "near-miss", ["threshold"], lines, closeness=len(matched))
        lines.append(f"  - timespan {self.timespan}s: every base matched in one group, "
                     "but not within the window")
        return Verdict(False, "near-miss", ["timespan"], lines, closeness=len(matched))

    @staticmethod
    def _label(event):
        bits = [str(event.get(k)) for k in ("syscall", "pid", "eventName", "verb") if event.get(k)]
        return "/".join(bits) or "event"


# ---- loading and the public helpers -----------------------------------------


_CACHE = {}


def load(path):
    """Load a rule file as a PlainRule or a CorrelationRule (cached per path)."""
    path = os.path.abspath(path)
    if path not in _CACHE:
        with open(path, encoding="utf-8") as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d]
        if any("correlation" in d for d in docs):
            _CACHE[path] = CorrelationRule(docs, path)
        else:
            if len(docs) != 1:
                raise ValueError(f"{path}: expected one rule document, got {len(docs)}")
            _CACHE[path] = PlainRule(docs[0], path)
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
