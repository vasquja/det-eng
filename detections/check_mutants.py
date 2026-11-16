#!/usr/bin/env python3
"""
The change proof (docs/ROADMAP.md, item R6): each change to the logic of a rule,
undone alone, must change a verdict on the head's own evidence.

A pull request that adds a dead item, an allowlist name with no case, or a value
that no positive needs passes every other offline gate: its cases still hold, its
benign hits do not rise, and the sufficiency ratchet compares cases, not what the
rule matches. This gate compares the rule itself with the rule of the base branch.

INPUT. --base-tree DIR is a checkout of the base branch (the sufficiency-ratchet
job makes it with `git worktree add`). Its rule files are read as data only: no
script and no requirement of the base runs. The head is this checkout.

PAIRS. A head rule file and a base rule file are a pair when they have the same
Sigma `id` (the id of the correlation document in a correlation file), and the id
is on one file of each side. Else they are a pair when they have the same path
under detections/sigma/. A head rule with no pair is NEW. A pair whose
`detection`, `correlation` and `logsource` blocks are equal in each document is
UNCHANGED, and it is not judged: a reworded title, description, tag or
falsepositive, or a new id, is no change. The documents of a correlation file are
paired by `name`, then by `id`; when one base rule of the head and one of the base
are left, they are a pair (a base rule with a new name and a new id). More base
rules left on both sides fail closed.

UNDO MUTANTS. For each changed pair, the gate builds one mutant for each change,
in each document: the head rule with that one change undone.

  an added block            gets the value that the operator above it in the head
                            condition ignores: under an or (also `1 of x_*`) it never
                            holds (its one item reads a field that no record has);
                            under an and (also `all of x_*`) it always holds (the
                            field is absent or present). Each `not` between the
                            block and the operator turns this round. A block that
                            must hold in one place and must not hold in another
                            fails closed. A block that is the whole condition has no
                            undo of its own: the undo of the condition holds it.
  an added map              (of a list of maps) is dropped.
  an added item             is dropped. A map that loses its last item holds on
                            every record (an empty AND).
  an added list value       is dropped.
  a changed item            (its value or its modifiers) gets its base item back in
                            place. A list that gains values and loses others is a
                            changed item.
  a removed item, value, map or block
                            is added back where its container still exists. A
                            removed block that the head condition cannot reach
                            comes back with the base condition (below).
  a changed condition       gets the base condition, with the removed blocks back.
  a changed correlation key (type, rules, group-by, timespan, condition) gets its
                            base value.

A list that is only reordered is no change (but the `rules` of a temporal_ordered
correlation keep their order: it reads the order). A change that cannot be undone
alone fails closed with a line that says that a human decides: a block that was
renamed (a removed block and an added block with the same definition), maps that
moved, maps that changed where maps were also added or removed, a mutant that does
not compile. A changed `logsource` is a change that is never proven (key `logsource`):
the compiled query does not read it, so no evidence can tell the two rules apart
(check_sufficiency.py --baseline also fails it).

KEYS. A mutant is named `<side>-<change>:<item>[=<value>]`, for example
`flt-value:allowed_processes.comm="nc"`. The item is named as rule_cases.py names
an atom (`block.field`, `block[i].field`, `field|mods` when a field repeats; in a
correlation file `<base rule>/` comes first). The side is `sel` (the items hold
under no `not`), `flt` (under a `not`), `mix` or `unused` (the condition does not
reach the item).

KILLED. A mutant is killed when one event set of the HEAD tells it apart from the
head rule:
  - a positive case of the sidecar stops firing;
  - any other case of the sidecar starts firing;
  - the attack fixture of a cloud rule (validate_cloud_detections.MANIFEST) loses
    a hit;
  - the benign fixture, or a slice of the benign corpus that the rule reads
    (score_benign.reads), gains a hit.
A fixture or a corpus slice compares the events that the hits hold, not the hits:
a correlation can group the same events in other alerts (a wider timespan), and
that is no hit gained or lost. A corpus slice that loses a hit does not kill: such
a mutant is better on the corpus. Evidence on which the head itself fails (a
positive that does not fire, a negative or a benign fixture that fires) is
skipped. Each event set is judged under
the default representation and under each variant of check_variants.py (compact,
sorted, multi, cs_like, and re2 when the module re2 is installed); a mutant is
killed when one representation kills it. So a correction that only a variant can
prove (an anchored value for a multi-valued list, a letter-case fix that a
case-sensitive LIKE sees) is proven. A mutant is EQUIVALENT, and it is not gated,
when its compiled query is the query of the head rule, or when each of its items
compiles to the query of the same item of the head and the two conditions give the
same value for each assignment of true, false and NULL to the items (at most 10
items: a condition with its terms in another order). An equivalent rewrite that
the gate cannot see as equivalent (a regular expression written in another form)
fails as a change not proven: no case can prove it, and a human decides.

COST. The head and all its undo mutants share one store for each event set: its
records and tables under each representation, and the records on which each item
holds. An undo pays only for its own query and for the items that it changes.

OUTPUT. For each mutant that is not killed:

  [RATCHET] <rule>: change not proven: <key>

and for each change that cannot be undone alone:

  [RATCHET] <rule>: change cannot be undone alone: <what>; a human decides

then a summary line. A NEW rule gets a report-only line: the discriminating items
(check_sufficiency.discriminating_atoms) whose drop no evidence tells apart. It has
no gate: the other gates judge a new rule. Exit 0 when no [RATCHET] line is
printed, 1 when one is, 2 on a structural fault (no base tree, a base tree with no
rule file, a rule file that cannot be read, a changed or new rule whose head does
not compile or whose sidecar has an error, a variant that is not in force).

The gate path is deterministic: it samples no regex and searches no witness record.
The evidence is the head's own, so a pull request can add an item with the case
that kills its undo mutant (docs/ROADMAP.md, R6 note).

Usage:
    python3 detections/check_mutants.py --base-tree "$RUNNER_TEMP/base-tree"
    python3 detections/check_mutants.py --base-tree ../base --json report.json
    python3 detections/check_mutants.py --self-test   # the undo builder and the kill test
"""

import os
import sys

# Running this script puts detections/ first on sys.path. Import the standard
# library before it is there (as check_variants.py does).
_HERE = os.path.dirname(os.path.abspath(__file__))
if sys.path and os.path.abspath(sys.path[0] or os.curdir) == _HERE:
    del sys.path[0]

import argparse  # noqa: E402
import copy  # noqa: E402
import fnmatch  # noqa: E402
import glob  # noqa: E402
import itertools  # noqa: E402
import json  # noqa: E402

sys.path.insert(0, _HERE)
import sigma_eval  # noqa: E402  (checks detections/ before pySigma loads)
import sigma_explain  # noqa: E402
import check_variants  # noqa: E402
import check_sufficiency  # noqa: E402
import score_benign  # noqa: E402
import benign_corpus  # noqa: E402
import yaml  # noqa: E402

REPO = os.path.dirname(_HERE)
SIGMA = os.path.join(REPO, "detections", "sigma")

# The block that never holds: one item on a field that no record has.
NEVER = {"check_mutants_never_field": "never"}
REPRESENTATIONS = ("default",) + check_variants.VARIANTS
CORRELATION_KEYS = ("type", "rules", "group-by", "timespan", "condition")
UNORDERED_KEYS = ("group-by",)      # a list whose order the correlation does not read


class Fault(Exception):
    """A structural fault: the gate cannot judge (exit 2)."""


def remember_compiles():
    """sigma_explain compiles a rule and each of its items alone with pySigma, and an
    undo mutant has all the items of the head but the one it changes. The query of a
    document is a function of the document: keep each one, keyed by the JSON text of
    the document (in its own key order), for the rest of this process."""
    compile_doc = sigma_explain._compile_doc
    if getattr(compile_doc, "remembers", False):
        return
    known = {}

    def remembered(doc):
        key = json.dumps(doc, default=str)
        if key not in known:
            known[key] = compile_doc(doc)
        return known[key]

    remembered.remembers = True
    sigma_explain._compile_doc = remembered


# ---- rule files as data ------------------------------------------------------


def read_docs(path):
    """The YAML documents of a rule file (empty documents left out)."""
    try:
        with open(path, encoding="utf-8") as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d is not None]
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        text = " ".join(str(e).split())
        raise Fault(f"{path}: cannot read the rule file: {type(e).__name__}: {text}") from None
    if not docs or not all(isinstance(d, dict) for d in docs):
        raise Fault(f"{path}: the rule file holds no rule document, or a document that "
                    "is not a mapping")
    return docs


def rule_id(docs):
    """The Sigma id of a rule file: the id of its correlation document, else of its
    first document. None when it is not text."""
    doc = next((d for d in docs if "correlation" in d), docs[0])
    value = doc.get("id")
    return value if isinstance(value, str) and value else None


def base_rule_files(base_tree):
    """{T<id>/<name>.yml: path} of the base tree, by the glob of the gates."""
    sigma = os.path.join(base_tree, "detections", "sigma")
    return {os.path.relpath(p, sigma).replace(os.sep, "/"): p
            for p in sorted(glob.glob(os.path.join(sigma, "*", "*.yml")))}


def head_rule_files():
    """{T<id>/<name>.yml: path} of this checkout (sigma_eval.rule_files())."""
    return {rel: os.path.join(SIGMA, *rel.split("/")) for rel in sigma_eval.rule_files()}


def pair_rules(head, base):
    """{head rel: (base rel, "id" or "path")} for each head rule with a pair.

    head, base: {rel: docs}. An id pairs only when one file of each side has it; a
    path pairs only a base file that no id paired."""
    def by_id(side):
        found = {}
        for rel, docs in side.items():
            found.setdefault(rule_id(docs), []).append(rel)
        return {i: rels[0] for i, rels in found.items() if i and len(rels) == 1}

    head_ids, base_ids = by_id(head), by_id(base)
    pairs, claimed = {}, set()
    for ident, rel in head_ids.items():
        if ident in base_ids:
            pairs[rel] = (base_ids[ident], "id")
            claimed.add(base_ids[ident])
    for rel in head:
        if rel not in pairs and rel in base and rel not in claimed:
            pairs[rel] = (rel, "path")
            claimed.add(rel)
    return pairs


# ---- canonical forms ---------------------------------------------------------


def canon(value):
    return json.dumps(value, sort_keys=True, default=str)


def as_list(value):
    return list(value) if isinstance(value, list) else [value]


def minus(values, others):
    """[(index, value)] of `values` that are not matched by a value of `others`
    (a multiset difference, in the order of `values`)."""
    left = [canon(v) for v in others]
    out = []
    for i, value in enumerate(values):
        text = canon(value)
        if text in left:
            left.remove(text)
        else:
            out.append((i, value))
    return out


def doc_label(doc):
    if "correlation" in doc:
        return "correlation"
    return doc.get("name") or doc.get("id") or "rule"


def logic(docs):
    """What the gate compares to call a pair unchanged. The documents of a plain file
    are read by position (a new id is no change); the base rules of a correlation by
    name or id (its `rules` name them)."""
    if not any("correlation" in d for d in docs):
        return [(canon(d.get("detection")), canon(d.get("logsource"))) for d in docs]
    return sorted((doc_label(d), canon(d.get("detection")), canon(d.get("correlation")),
                   canon(d.get("logsource"))) for d in docs)


def maps_of(definition):
    """The maps of a detection block (a dict is one map), or None for a keyword block."""
    if isinstance(definition, dict):
        return [definition]
    if isinstance(definition, list) and definition and all(isinstance(m, dict) for m in definition):
        return list(definition)
    return None


def field_of(key):
    return str(key).split("|")[0]


def item_name(prefix, mapping, key):
    """The atom name that sigma_explain gives the item `key` of a map."""
    fields = [field_of(k) for k in mapping]
    return f"{prefix}.{key if fields.count(field_of(key)) > 1 else field_of(key)}"


def map_prefix(block, count, index):
    return block if count == 1 else f"{block}[{index}]"


def block_atoms(definition, block):
    """The atom names of one block, as sigma_explain names them."""
    maps = maps_of(definition)
    if maps is None:
        return [block]
    return [item_name(map_prefix(block, len(maps), i), m, k)
            for i, m in enumerate(maps) for k in m]


def head_map(detection, block, index):
    value = detection[block]
    return value if isinstance(value, dict) else value[index]


def tautology(field):
    """A block value that holds on every record: the field is absent, or present."""
    return [{field: None}, {field + "|exists": True}]


ALWAYS = tautology("check_mutants_always_field")


def block_places(detection, block):
    """[(operator, nots)]: one entry for each place where the condition reaches
    `block`. The operator is "and" or "or": the nearest operator above the block that
    has more than one operand (`all of x_*` is an and, `1 of x_*` an or). nots is the
    number of `not` between the block and that operator. The operator is None when
    no such operator is above the block (the block is the whole condition, under
    zero or more `not`)."""
    from sigma.conditions import (ConditionAND, ConditionIdentifier, ConditionNOT,
                                  ConditionOR, ConditionSelector)
    from sigma.rule import SigmaRule

    rule = SigmaRule.from_dict({"title": "t", "logsource": {"product": "check_mutants"},
                                "detection": detection})
    names = [n for n in detection if n != "condition"]
    places = []

    def reached(chain):
        nots = 0
        for step in reversed(chain):
            if step == "not":
                nots += 1
            elif step[1] > 1:
                return (step[0], nots)
        return (None, nots)

    def walk(node, chain):
        if isinstance(node, ConditionIdentifier):
            if node.identifier == block:
                places.append(reached(chain))
        elif isinstance(node, ConditionSelector):
            if node.pattern == "them":
                found = [n for n in names if not n.startswith("_")]
            else:
                found = [n for n in names if fnmatch.fnmatchcase(n, node.pattern)]
            if block in found:
                op = "and" if node.cond_class is ConditionAND else "or"
                places.append(reached(chain + [(op, len(found))]))
        elif isinstance(node, ConditionNOT):
            walk(node.args[0], chain + ["not"])
        elif isinstance(node, (ConditionAND, ConditionOR)):
            op = "and" if isinstance(node, ConditionAND) else "or"
            for arg in node.args:
                walk(arg, chain + [(op, len(node.args))])

    for parsed in rule.detection.parsed_condition:
        walk(parsed.parse(postprocess=False), [])
    return places


def drop_key(detection, block, index, key):
    """Delete one item of a map; a map that is then empty holds on every record."""
    mapping = head_map(detection, block, index)
    del mapping[key]
    if mapping:
        return
    if isinstance(detection[block], dict):
        detection[block] = tautology(field_of(key))
    else:
        detection[block][index:index + 1] = tautology(field_of(key))


def lcs(left, right):
    """[(i, j)] of a longest common subsequence of two lists of texts."""
    n, m = len(left), len(right)
    table = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            table[i][j] = (table[i + 1][j + 1] + 1 if left[i] == right[j]
                           else max(table[i + 1][j], table[i][j + 1]))
    out, i, j = [], 0, 0
    while i < n and j < m:
        if left[i] == right[j]:
            out.append((i, j))
            i, j = i + 1, j + 1
        elif table[i + 1][j] >= table[i][j + 1]:
            i += 1
        else:
            j += 1
    return out


# ---- the undo builder --------------------------------------------------------


class Undo:
    """One change of the head, undone alone.

    kind    what is undone: block, map, item, value, changed, changed-block,
            removed, removed-value, removed-map, removed-block, condition, corr-<key>.
    target  the item, map or block (an atom name, `block`, `block[i]`), with the
            prefix `<base rule>/` in a correlation file; empty for a condition.
    value   the list value (kinds value and removed-value), else None.
    docs    the head documents with the change undone.
    side    (where, ref, atoms): the model ("head" or "mutant"), the base rule of a
            correlation (None for a plain rule) and the atoms whose polarity gives
            the side; None for a key without a side.
    reach   the mutant counts only when the mutant's condition reaches one of the
            atoms of `side` (a removed block that comes back).
    """

    _NO_VALUE = object()

    def __init__(self, kind, target, docs, side=None, value=_NO_VALUE, reach=False):
        self.kind, self.target, self.docs, self.side = kind, target, docs, side
        self.value, self.reach = value, reach
        self.key = None
        self.status, self.killed_by, self.detail = None, None, ""

    def name(self, side_text):
        head = f"{side_text}-{self.kind}" if side_text else self.kind
        text = f"{head}:{self.target}" if self.target else head
        if self.value is not Undo._NO_VALUE:
            text += "=" + json.dumps(self.value, sort_keys=True, default=str)
        return text


class Builder:
    """The undo mutants of one pair: base documents and head documents."""

    def __init__(self, base_docs, head_docs):
        self.base, self.head = base_docs, head_docs
        self.undos, self.faults = [], []

    def mutant(self, n, edit):
        """The head documents with edit() applied to a copy of document n."""
        docs = copy.deepcopy(self.head)
        edit(docs[n])
        return docs

    # -- documents -------------------------------------------------------------

    def build(self):
        base_kind = any("correlation" in d for d in self.base)
        head_kind = any("correlation" in d for d in self.head)
        if base_kind != head_kind:
            self.faults.append("the file changed between a plain rule and a correlation")
            return self
        if not head_kind:
            if len(self.base) != 1 or len(self.head) != 1:
                self.faults.append("a plain rule file must hold one document")
                return self
            self.doc(self.base[0], 0, None)
            return self
        self.correlation()
        return self

    def correlation(self):
        bc = next(i for i, d in enumerate(self.base) if "correlation" in d)
        hc = next(i for i, d in enumerate(self.head) if "correlation" in d)
        pairs, unmatched_head = {}, []
        free = [i for i, d in enumerate(self.base) if "detection" in d]
        for n, doc in enumerate(self.head):
            if "detection" not in doc:
                continue
            match = next((i for i in free if doc.get("name") and self.base[i].get("name")
                          == doc.get("name")), None)
            if match is None:
                match = next((i for i in free if doc.get("id") and self.base[i].get("id")
                              == doc.get("id")), None)
            if match is None:
                unmatched_head.append(n)
            else:
                free.remove(match)
                pairs[n] = match
        if len(unmatched_head) == 1 and len(free) == 1:
            # One base rule with a new name and a new id: it is that base rule.
            pairs[unmatched_head.pop()] = free.pop()
        elif unmatched_head and free:
            self.faults.append(
                "base rule(s) " + ", ".join(sorted(str(doc_label(self.head[n]))
                                                   for n in unmatched_head))
                + " of the head have no pair among base rule(s) "
                + ", ".join(sorted(str(doc_label(self.base[i])) for i in free))
                + " of the base (no name or id is the same)")
        self.logsource(self.base[bc], self.head[hc], "")
        rules_changed = self.correlation_keys(bc, hc, pairs)
        if (unmatched_head or free) and not rules_changed:
            self.faults.append("the base rules of the correlation changed (a document was "
                               "added or removed) while its `rules` did not")
        refs = as_list(self.head[hc]["correlation"].get("rules") or [])
        for n, b in pairs.items():
            doc = self.head[n]
            ref = next((r for r in refs if r in (doc.get("name"), doc.get("id"))),
                       doc.get("name") or doc.get("id"))
            self.doc(self.base[b], n, ref)

    def correlation_keys(self, bc, hc, pairs):
        """Undo each changed key of the correlation. True when `rules` changed.

        pairs: {head document: base document} of the base rules. A base rule that has
        a new name or id is the same rule in `rules`."""
        bspec = self.base[bc].get("correlation") or {}
        hspec = self.head[hc].get("correlation") or {}

        def head_ref(ref):
            for n, b in pairs.items():
                bdoc, hdoc = self.base[b], self.head[n]
                if ref and ref == bdoc.get("name"):
                    return hdoc.get("name") or hdoc.get("id")
                if ref and ref == bdoc.get("id"):
                    return hdoc.get("id") or hdoc.get("name")
            return ref

        # Only temporal_ordered reads the order of `rules`.
        ordered = "temporal_ordered" in (bspec.get("type"), hspec.get("type"))
        changed_rules = False
        keys = list(CORRELATION_KEYS) + sorted((set(bspec) | set(hspec)) - set(CORRELATION_KEYS))
        for key in keys:
            old, new = bspec.get(key), hspec.get(key)
            if key == "rules" and old is not None and new is not None:
                left = [canon(head_ref(r)) for r in as_list(old)]
                right = [canon(r) for r in as_list(new)]
                same = left == right if ordered else sorted(left) == sorted(right)
            elif key in UNORDERED_KEYS and old is not None and new is not None:
                same = sorted(map(canon, as_list(old))) == sorted(map(canon, as_list(new)))
            else:
                same = canon(old) == canon(new)
            if same:
                continue
            if key == "rules":
                changed_rules = True
            self.undos.append(Undo(f"corr-{key}", "", self.reverted_key(hc, key, old)))
        return changed_rules

    def reverted_key(self, hc, key, old):
        docs = copy.deepcopy(self.head)
        spec = docs[hc]["correlation"]
        if old is None:
            spec.pop(key, None)
        else:
            spec[key] = copy.deepcopy(old)
        if key != "rules":
            return docs
        # The base rules come back too, and a head document that no rule names goes.
        refs = as_list(old or [])
        named = {k for d in docs if "detection" in d for k in (d.get("name"), d.get("id")) if k}
        for ref in refs:
            if ref not in named:
                docs += [copy.deepcopy(d) for d in self.base if "detection" in d
                         and ref in (d.get("name"), d.get("id"))]
        return [d for d in docs if "detection" not in d
                or any(r in (d.get("name"), d.get("id")) for r in refs)]

    def logsource(self, bdoc, hdoc, tag):
        if canon(bdoc.get("logsource")) != canon(hdoc.get("logsource")):
            self.undos.append(Undo("logsource", tag.rstrip("/"), None))

    def doc(self, bdoc, n, ref):
        """The changes of one detection document (n: its index in the head)."""
        hdoc = self.head[n]
        tag = f"{ref}/" if ref else ""
        self.logsource(bdoc, hdoc, tag)
        bd, hd = bdoc.get("detection") or {}, hdoc.get("detection") or {}
        added = [b for b in hd if b != "condition" and b not in bd]
        removed = [b for b in bd if b != "condition" and b not in hd]
        renamed = [(r, a) for r in removed for a in added if canon(bd[r]) == canon(hd[a])]
        for r, a in renamed:
            self.faults.append(f"block {tag}{r} renamed to {tag}{a}")
        gone = {r for r, _ in renamed} | {a for _, a in renamed}
        condition_changed = canon(bd.get("condition")) != canon(hd.get("condition"))
        for block in added:
            if block in gone:
                continue
            neutral = self.neutral(hd, block, tag, condition_changed)
            if neutral is None:
                continue
            self.undos.append(Undo(
                "block", tag + block,
                self.mutant(n, lambda d, b=block, v=neutral:
                            d["detection"].__setitem__(b, copy.deepcopy(v))),
                side=("head", ref, block_atoms(hd[block], block))))
        for block in removed:
            if block in gone:
                continue
            self.undos.append(Undo(
                "removed-block", tag + block,
                self.mutant(n, lambda d, b=block: d["detection"].__setitem__(b, copy.deepcopy(bd[b]))),
                side=("mutant", ref, block_atoms(bd[block], block)), reach=True))
        for block in hd:
            if block != "condition" and block in bd and canon(bd[block]) != canon(hd[block]):
                self.block(n, ref, tag, block, bd[block], hd[block])
        if canon(bd.get("condition")) != canon(hd.get("condition")) and not renamed:
            def condition(d):
                d["detection"]["condition"] = copy.deepcopy(bd.get("condition"))
                for b in removed:
                    d["detection"][b] = copy.deepcopy(bd[b])
            self.undos.append(Undo("condition", tag.rstrip("/"), self.mutant(n, condition)))

    def neutral(self, hd, block, tag, condition_changed):
        """The value that undoes an added block where the head condition reads it: the
        value that its operator ignores. Under an or (`1 of x_*`) the block never
        holds (NEVER); under an and (`all of x_*`) it always holds (ALWAYS); each
        `not` between the block and the operator turns this round. None: no undo of
        the block alone (a fault is recorded, or the block is the whole condition and
        the undo of the condition holds it)."""
        places = block_places(hd, block)
        if not places:
            return NEVER                # no condition reads it: the undo is equivalent
        values = {None if op is None else (op == "and") != (nots % 2 == 1) for op, nots in places}
        if values == {None} and condition_changed:
            return None
        if None in values:
            self.faults.append(f"block {tag}{block} is the whole condition, or a part of it "
                               "that no undo of the block alone can take out")
            return None
        if len(values) > 1:
            self.faults.append(f"block {tag}{block} must hold in one place of the condition "
                               "and must not hold in another")
            return None
        return copy.deepcopy(ALWAYS if values == {True} else NEVER)

    # -- blocks, maps, items, values --------------------------------------------

    def block(self, n, ref, tag, block, bdef, hdef):
        bmaps, hmaps = maps_of(bdef), maps_of(hdef)
        if bmaps is None and hmaps is None:
            self.values(n, tag + block, bdef, hdef, lambda d: d["detection"], block,
                        ("head", ref, [block]))
            return
        if bmaps is None or hmaps is None:
            self.undos.append(Undo(
                "changed-block", tag + block,
                self.mutant(n, lambda d: d["detection"].__setitem__(block, copy.deepcopy(bdef))),
                side=("mutant", ref, block_atoms(bdef, block))))
            return
        btext, htext = [canon(m) for m in bmaps], [canon(m) for m in hmaps]
        if sorted(btext) == sorted(htext):
            return                                      # only reordered
        common = lcs(btext, htext)
        loose_b = [i for i in range(len(bmaps)) if i not in {p[0] for p in common}]
        loose_h = [j for j in range(len(hmaps)) if j not in {p[1] for p in common}]
        if {btext[i] for i in loose_b} & {htext[j] for j in loose_h}:
            self.faults.append(f"maps of {tag}{block} moved")
            return
        anchors = [(-1, -1)] + common + [(len(bmaps), len(hmaps))]
        for (b0, h0), (b1, h1) in zip(anchors, anchors[1:]):
            bgap, hgap = list(range(b0 + 1, b1)), list(range(h0 + 1, h1))
            if bgap and hgap and len(bgap) != len(hgap):
                self.faults.append(f"maps of {tag}{block} changed where maps were also added "
                                   "or removed")
                continue
            if bgap and hgap:
                for i, j in zip(bgap, hgap):
                    self.items(n, ref, tag, block, len(hmaps), j, bmaps[i], hmaps[j])
                continue
            for j in hgap:
                def drop_map(d, j=j):
                    maps = d["detection"][block]
                    d["detection"][block] = [m for k, m in enumerate(maps) if k != j]
                prefix = map_prefix(block, len(hmaps), j)
                self.undos.append(Undo(
                    "map", f"{tag}{block}[{j}]", self.mutant(n, drop_map),
                    side=("head", ref, [item_name(prefix, hmaps[j], k) for k in hmaps[j]])))
            for offset, i in enumerate(bgap):
                at = h0 + 1 + offset

                def add_map(d, i=i, at=at):
                    value = d["detection"][block]
                    maps = [value] if isinstance(value, dict) else value
                    d["detection"][block] = maps[:at] + [copy.deepcopy(bmaps[i])] + maps[at:]
                prefix = map_prefix(block, len(hmaps) + 1, at)
                self.undos.append(Undo(
                    "removed-map", f"{tag}{block}[{i}]", self.mutant(n, add_map),
                    side=("mutant", ref, [item_name(prefix, bmaps[i], k) for k in bmaps[i]])))

    def items(self, n, ref, tag, block, count, j, bmap, hmap):
        """The changes between one base map and the head map j (of count) of a block."""
        prefix = map_prefix(block, count, j)

        def holder(d):
            return head_map(d["detection"], block, j)

        loose_b = [k for k in bmap if k not in hmap]
        loose_h = [k for k in hmap if k not in bmap]
        changed = {}                                    # head key -> base key (modifiers)
        for field in dict.fromkeys(field_of(k) for k in loose_h):
            bs = [k for k in loose_b if field_of(k) == field]
            hs = [k for k in loose_h if field_of(k) == field]
            if len(bs) == 1 and len(hs) == 1:
                changed[hs[0]] = bs[0]
        for key in hmap:
            name = item_name(prefix, hmap, key)
            side = ("head", ref, [name])
            if key in bmap:
                if canon(bmap[key]) != canon(hmap[key]):
                    self.values(n, tag + name, bmap[key], hmap[key], holder, key, side)
            elif key in changed:
                def revert(d, key=key, old=changed[key]):
                    mapping = holder(d)
                    items = list(mapping.items())
                    mapping.clear()
                    for k, v in items:
                        mapping[old if k == key else k] = copy.deepcopy(bmap[old]) if k == key else v
                self.undos.append(Undo("changed", tag + name, self.mutant(n, revert), side=side))
            else:
                self.undos.append(Undo(
                    "item", tag + name,
                    self.mutant(n, lambda d, key=key: drop_key(d["detection"], block, j, key)),
                    side=side))
        for key in loose_b:
            if key in changed.values():
                continue

            def add_back(d, key=key):
                holder(d)[key] = copy.deepcopy(bmap[key])
            grown = dict(hmap)
            grown[key] = bmap[key]
            name = item_name(prefix, grown, key)
            self.undos.append(Undo("removed", tag + name, self.mutant(n, add_back),
                                   side=("mutant", ref, [name])))

    def values(self, n, atom, old, new, container, key, side):
        """The changes of the values of one item, or of a keyword block. old, new: the
        base and the head value; container(d) is the dict that holds the value under
        `key` in a copy of head document n."""
        added, removed = minus(as_list(new), as_list(old)), minus(as_list(old), as_list(new))
        if not added and not removed:
            return                                      # only reordered
        if added and not removed:
            for index, value in added:
                def drop(d, index=index):
                    values = as_list(container(d)[key])
                    container(d)[key] = [v for i, v in enumerate(values) if i != index]
                self.undos.append(Undo("value", atom, self.mutant(n, drop), side=side,
                                       value=value))
        elif removed and not added:
            for _index, value in removed:
                def add(d, value=value):
                    container(d)[key] = as_list(container(d)[key]) + [copy.deepcopy(value)]
                self.undos.append(Undo("removed-value", atom, self.mutant(n, add), side=side,
                                       value=value))
        else:
            self.undos.append(Undo(
                "changed", atom,
                self.mutant(n, lambda d: container(d).__setitem__(key, copy.deepcopy(old))),
                side=side))


# ---- the kill test ------------------------------------------------------------


class Evidence:
    """One event set of the head: a sidecar case, a cloud fixture or a corpus slice."""

    def __init__(self, source, name, kind, raw):
        self.source, self.name, self.kind, self.raw = source, name, kind, raw

    @property
    def label(self):
        return f"{self.source} {self.kind} {self.name}"


def head_fails(evidence, hits):
    """Does the head itself fail this event set (so the set cannot kill)?"""
    if evidence.source == "corpus":
        return False
    if evidence.kind in ("positive", "attack"):
        return not hits
    return bool(hits)


def covered(hits):
    """The indices of the events that the hits hold. A hit of a plain rule is one
    event; a hit of a correlation is the group of events of one alert."""
    return {i for hit in hits for i in hit}


def kills(evidence, head, mutant):
    """Do the mutant's hits tell it apart from the head's (sets of hits)?

    A fixture or a corpus slice compares the events that the hits hold, not the
    hits: a correlation with a wider timespan or group-by can group the same events
    in other alerts, and that is no hit gained or lost."""
    if evidence.source == "case":
        return not mutant if evidence.kind == "positive" else bool(mutant)
    if evidence.source == "fixture" and evidence.kind == "attack":
        return bool(covered(head) - covered(mutant))
    if evidence.source == "fixture":
        return bool(mutant)
    return bool(covered(mutant) - covered(head))        # a corpus slice gains a hit


class Store:
    """What one event set gives to every rule that is judged on it: its records and
    tables under each representation, and the records on which each item holds
    (keyed by the item's SQL). The head and all its undo mutants share one store, so
    an undo pays only for the items that it changes and for its own query."""

    def __init__(self, raw, ctx):
        self.raw, self.ctx = raw, ctx
        self.flat = ctx.default_records(raw)
        self.table = sigma_eval.EventTable(self.flat)
        self.lists = any(check_variants.has_list(e) for e in raw)
        self.records = {}       # compact, sorted -> the flattened records
        self.tables = {}        # input -> EventTable
        self.inputs = {}        # compact, sorted -> the input (check_variants.Run.input_of)
        self.holds = {}         # (input, item SQL) -> {record index}
        self.elements = None    # the table of the multi-valued model, see element_rows()
        self.fields = None      # the list fields of the records (lower case)
        self.computed = 0       # item queries run on this store (the self-test reads it)

    def record_input(self, variant, run):
        if variant not in self.inputs:
            self.inputs[variant] = check_variants.Run.input_of(run, variant)
        return self.inputs[variant]

    def item_holds(self, key, sql, table):
        if (key, sql) not in self.holds:
            self.computed += 1
            self.holds[(key, sql)] = {i for hit in table.hit_indices(sql) for i in hit}
        return self.holds[(key, sql)]

    def list_fields(self):
        _table, _base, element = self.element_rows()
        if self.fields is None:
            self.fields = {name for ids in element for name in ids}
        return self.fields

    def multi_holds(self, field, sql):
        """The records on which an item on `field` holds in the multi-valued model: on
        one element of the list when the record holds the field as a list, else on
        the record's scalar row."""
        if ("multi", field, sql) not in self.holds:
            table, base, element = self.element_rows()
            rows = self.item_holds("multi-rows", sql, table)
            self.holds[("multi", field, sql)] = {
                i for i in range(len(self.raw))
                if (any(r in rows for r in element[i][field]) if element[i].get(field)
                    else base[i] in rows)}
        return self.holds[("multi", field, sql)]

    def element_rows(self):
        """(table, base, element) as check_variants.multi_truth() builds them: one row
        for each record (its scalar fields) and one for each element of a list."""
        if self.elements is None:
            rows, base, element = [], [], []
            for raw in self.raw:
                scalars, lists = check_variants.split_lists(raw)
                base.append(len(rows))
                rows.append(scalars)
                ids = {}
                for name, values in lists.items():
                    ids[name.lower()] = list(range(len(rows), len(rows) + len(values)))
                    rows += [dict(scalars, **{name: v}) for v in values]
                element.append(ids)
            self.elements = (sigma_eval.EventTable(rows), base, element)
        return self.elements


def holding(node, sets, every):
    """The records on which a condition tree of sigma_explain holds, from the records
    on which each item holds: two-valued, as PlainRule.evaluate() reads a row."""
    op = node[0]
    if op == "id":
        return sets[node[1]]
    if op == "not":
        return every - holding(node[1], sets, every)
    parts = [holding(child, sets, every) for child in node[1]]
    if op == "and":
        return set.intersection(every, *parts)
    return set().union(*parts)


class SharedRun(check_variants.Run):
    """check_variants.Run on a Store. It gives the same hits as Run: the tables and
    the records on which each item holds come from the store, and the hits of the
    multi variant are composed from sets of records, not from one row per record."""

    def __init__(self, rule, sql, store):     # noqa: super().__init__ builds new tables
        self.rule, self.sql, self.raw, self.ctx = rule, sql, store.raw, store.ctx
        self.store = store
        self.flat, self.table, self.lists = store.flat, store.table, store.lists
        self.hits = check_variants._canon(self.table.hit_indices(sql))
        self.words = check_variants.sql_words(rule, sql)
        self._records, self._tables = store.records, store.tables
        self._input, self._hits, self._truth, self._flips = {}, {}, {}, {}

    def input_of(self, variant):
        if variant in ("compact", "sorted") and self.ctx.shortcuts:
            return self.store.record_input(variant, self)
        return super().input_of(variant)

    def item_sets(self, key):
        """{atom: records on which the item holds} on one input: None (the default
        records) or "multi" (check_variants.multi_truth(): an item on a list field
        holds when it holds on one element)."""
        rule = self.rule
        if key != "multi":
            table = self.variant_table(key)
            return {atom: self.store.item_holds(key, sql, table) for atom, sql in rule.items.items()}
        out = {}
        for atom in rule.items:
            field = (rule.item_field[atom] or "").lower()
            if field in self.store.list_fields() and rule.item_negates(atom):
                raise ValueError(f"item {atom} negates inside itself (`|neq`) on a list: the "
                                 "multi-valued model does not say if one value or every value "
                                 "must differ")
            out[atom] = self.store.multi_holds(field, rule.item_sql(atom))
        return out

    def variant_hits(self, variant):
        if variant != "multi" or self.rule.is_correlation or self.input_of(variant) is None:
            return super().variant_hits(variant)
        if variant not in self._hits:
            every = set(range(len(self.raw)))
            composed = [[i] for i in sorted(holding(self.rule.tree, self.item_sets(None), every))]
            if composed != self.hits:
                raise ValueError("internal error: the items' default values, composed "
                                 f"through the condition, give hits {composed}; the "
                                 f"compiled rule gives {self.hits} (report it)")
            self._hits[variant] = [[i] for i in sorted(holding(self.rule.tree,
                                                                self.item_sets("multi"), every))]
        return self._hits[variant]


class Verdicts:
    """The hits of one rule on one event set, for each representation, computed when
    asked. None: the representation cannot judge the set (check_variants.py names
    such a rule itself)."""

    def __init__(self, rule, sql, evidence, ctx, store=None):
        self.rule, self.sql, self.evidence, self.ctx = rule, sql, evidence, ctx
        self.store = store
        self.run, self.cache = None, {}

    def get(self, representation):
        if representation not in self.cache:
            try:
                if self.run is None:
                    self.run = (check_variants.Run(self.rule, self.sql, self.evidence.raw, self.ctx)
                                if self.store is None else
                                SharedRun(self.rule, self.sql, self.store.get()))
                hits = (self.run.hits if representation == "default"
                        else self.run.variant_hits(representation))
                self.cache[representation] = {tuple(h) for h in hits}
            except Exception:  # noqa: BLE001 - that representation does not judge the set
                self.cache[representation] = None
        return self.cache[representation]


class LazyStore:
    """The Store of one event set, built on first use (an undo that the first event
    set kills needs no table of the others)."""

    def __init__(self, raw, ctx):
        self.raw, self.ctx, self.store = raw, ctx, None

    def get(self):
        if self.store is None:
            self.store = Store(self.raw, self.ctx)
        return self.store


SAME_LOGIC_ITEMS = 10   # at most 3**10 assignments of the items


def kleene(node, truth):
    """The value of a condition tree of sigma_explain when each item is True, False or
    None (SQL NULL: the item reads a field that the record does not have)."""
    op = node[0]
    if op == "id":
        return truth[node[1]]
    if op == "not":
        value = kleene(node[1], truth)
        return None if value is None else not value
    values = [kleene(child, truth) for child in node[1]]
    if op == "and":
        return False if False in values else None if None in values else True
    return True if True in values else None if None in values else False


def same_logic(head, mutant):
    """Do two plain rules give the same hits on every record? True when each item
    compiles to the same query in both, and the two conditions give the same value
    for each assignment of True, False and NULL to the items (so a condition with its
    terms in another order is no change). A record set judges each item once, in
    each representation, so no representation can tell the two rules apart."""
    if head.is_correlation or mutant.is_correlation or head.items != mutant.items:
        return False
    atoms = sorted(head.items)
    if len(atoms) > SAME_LOGIC_ITEMS:
        return False
    for values in itertools.product((True, False, None), repeat=len(atoms)):
        truth = dict(zip(atoms, values))
        if bool(kleene(head.tree, truth)) != bool(kleene(mutant.tree, truth)):
            return False
    return True


class Judge:
    """Judges the undo mutants of one head rule on the head's evidence."""

    def __init__(self, ctx, head_docs, evidence, model=None):
        self.ctx = ctx
        self.representations = ["default"] + list(ctx.variants)
        self.rule = model or sigma_explain.from_docs(copy.deepcopy(head_docs))
        self.sql = self.rule.sql
        self.evidence = evidence
        self.stores = [LazyStore(e.raw, ctx) for e in evidence]
        self.head = [Verdicts(self.rule, self.sql, e, ctx, s)
                     for e, s in zip(evidence, self.stores)]
        self.failing = set()        # (evidence label, representation) that the head fails

    def judge(self, undo):
        """Set undo.status (killed, not-killed, equivalent or invalid); return the
        mutant's model, or None when it does not compile."""
        try:
            rule = sigma_explain.from_docs(copy.deepcopy(undo.docs))
            sql = rule.sql
        except Exception as e:  # noqa: BLE001 - the mutant is not a rule
            undo.status, undo.detail = "invalid", f"{type(e).__name__}: {e}"
            return None
        if sql == self.sql or same_logic(self.rule, rule):
            undo.status = "equivalent"
            return rule
        for evidence, head, store in zip(self.evidence, self.head, self.stores):
            mutant = Verdicts(rule, sql, evidence, self.ctx, store)
            for representation in self.representations:
                before = head.get(representation)
                if before is None:
                    continue
                if head_fails(evidence, before):
                    self.failing.add((evidence.label, representation))
                    continue
                after = mutant.get(representation)
                if after is not None and kills(evidence, before, after):
                    undo.status = "killed"
                    undo.killed_by = {"evidence": evidence.label, "representation": representation}
                    return rule
        undo.status = "not-killed"
        return rule


def side_of(model, ref, atoms):
    if model is None:
        return "unused"
    part = model.bases.get(ref) if model.is_correlation else model
    if part is None:
        return "unused"
    marks = set()
    for atom in atoms:
        marks |= part.polarity.get(atom, set())
    if not marks:
        return "unused"
    return {frozenset("+"): "sel", frozenset("-"): "flt"}.get(frozenset(marks), "mix")


def finish(undo, head_model, mutant_model):
    """Give the undo its key (after the mutant is judged)."""
    side = None
    if undo.side is not None:
        where, ref, atoms = undo.side
        side = side_of(head_model if where == "head" else mutant_model, ref, atoms)
    undo.key = undo.name(side)
    return side


# ---- one pair, one new rule ------------------------------------------------------


class Report:
    """The result of one head rule: unchanged, changed (its undo mutants and the
    changes that cannot be undone alone) or new (the report-only items)."""

    def __init__(self, rel, base_rel=None, how=None):
        self.rel, self.base_rel, self.how = rel, base_rel, how
        self.status = "unchanged"
        self.undos, self.faults = [], []
        self.failing = []
        self.report_only = []

    def ratchet_lines(self):
        out = [f"  [RATCHET] {self.rel}: change cannot be undone alone: {f}; a human decides"
               for f in self.faults]
        for u in self.undos:
            if u.status == "not-killed":
                out.append(f"  [RATCHET] {self.rel}: change not proven: {u.key}")
            elif u.status == "invalid":
                out.append(f"  [RATCHET] {self.rel}: change cannot be undone alone: {u.key} "
                           f"(the mutant does not compile: {u.detail}); a human decides")
        return out

    def as_dict(self):
        return {"rule": self.rel, "base_rule": self.base_rel, "paired_by": self.how,
                "status": self.status, "faults": self.faults,
                "mutants": [{"key": u.key, "status": u.status, "killed_by": u.killed_by,
                             **({"detail": u.detail} if u.detail else {})} for u in self.undos],
                "head_fails": [{"evidence": e, "representation": r} for e, r in self.failing],
                "report_only": self.report_only}


def evidence_of(rule_path, logsource, fixtures, corpus):
    """[Evidence] of a head rule: its sidecar cases, its cloud fixtures, and the corpus
    slices that it reads. A sidecar error is a fault."""
    sets, errors = check_variants.event_sets(rule_path, fixtures)
    if errors:
        raise Fault(f"{os.path.relpath(rule_path, REPO)}: {errors[0]}"
                    + (f" (and {len(errors) - 1} more)" if len(errors) > 1 else ""))
    out = [Evidence(source, name, kind, raw) for source, name, kind, raw, _ in sets]
    out += [Evidence("corpus", s.id, "benign", s.raw) for s in corpus
            if score_benign.reads(s.logsource, logsource)]
    return out


def judge_pair(report, base_docs, head_docs, ctx, evidence, model=None):
    """Build the undo mutants of one changed pair and judge each one."""
    builder = Builder(base_docs, head_docs).build()
    report.faults += builder.faults
    judge = None
    for undo in builder.undos:
        if undo.kind == "logsource":
            # The compiled query does not read the logsource: no evidence tells the
            # two rules apart.
            undo.status, undo.key = "not-killed", undo.name(None)
            report.undos.append(undo)
            continue
        judge = judge or Judge(ctx, head_docs, evidence, model)
        mutant_model = judge.judge(undo)
        finish(undo, judge.rule, mutant_model)
        if undo.reach and undo.status != "invalid":
            _, ref, atoms = undo.side
            if side_of(mutant_model, ref, atoms) == "unused":
                continue        # the head condition cannot reach it: the condition undo holds it
        report.undos.append(undo)
    if judge is not None:
        report.failing = sorted(judge.failing)
    return report


def locate(detection):
    """{atom: (block, index or None, key)} of the map items of a detection."""
    out = {}
    for block, definition in detection.items():
        maps = None if block == "condition" else maps_of(definition)
        if not maps:
            continue
        for i, mapping in enumerate(maps):
            prefix = map_prefix(block, len(maps), i)
            for key in mapping:
                out[item_name(prefix, mapping, key)] = (block, None if len(maps) == 1 else i, key)
    return out


def new_rule_report(report, head_docs, ctx, evidence, model=None):
    """Report only: the discriminating items whose drop no evidence tells apart."""
    model = model or sigma_explain.from_docs(copy.deepcopy(head_docs))
    if model.is_correlation:
        targets = [(ref, atoms) for ref, (atoms, _) in check_sufficiency.base_items(model).items()]
    else:
        targets = [(None, check_sufficiency.discriminating_atoms(model))]
    judge = None
    for ref, atoms in targets:
        n = next((i for i, d in enumerate(head_docs) if "detection" in d and
                  (ref is None or ref in (d.get("name"), d.get("id")))), None)
        if n is None:
            continue
        where = locate(head_docs[n]["detection"])
        for atom in atoms:
            if atom not in where:
                continue
            block, index, key = where[atom]
            docs = copy.deepcopy(head_docs)
            drop_key(docs[n]["detection"], block, 0 if index is None else index, key)
            undo = Undo("drop", (f"{ref}/" if ref else "") + atom, docs)
            judge = judge or Judge(ctx, head_docs, evidence, model)
            judge.judge(undo)
            if undo.status in ("not-killed", "equivalent"):
                report.report_only.append(undo.target)
    return report


# ---- the run -------------------------------------------------------------------


def run(base_tree, ctx):
    """(reports, header facts). Raises Fault."""
    remember_compiles()
    if not os.path.isdir(base_tree):
        raise Fault(f"--base-tree {base_tree}: no such directory (give a checkout of the base "
                    "branch)")
    base_files = base_rule_files(base_tree)
    if not base_files:
        raise Fault(f"--base-tree {base_tree}: the tree holds no rule file "
                    "(detections/sigma/*/*.yml): it is not a checkout of the base branch")
    base = {rel: read_docs(path) for rel, path in base_files.items()}
    head_files = head_rule_files()
    head = {rel: read_docs(path) for rel, path in head_files.items()}
    pairs = pair_rules(head, base)
    reports, work = [], []
    for rel in head:
        if rel in pairs:
            brel, how = pairs[rel]
            report = Report(rel, brel, how)
            if logic(base[brel]) != logic(head[rel]):
                report.status = "changed"
                work.append(report)
        else:
            report = Report(rel)
            report.status = "new"
            work.append(report)
        reports.append(report)
    gone = sorted(set(base) - {brel for brel, _ in pairs.values()})
    if work:
        fixtures, corpus = check_variants.cloud_fixtures(), benign_corpus.load_corpus()
        dead = check_variants.in_force(ctx)
        if dead:
            raise Fault("variant(s) not in force: " + "; ".join(f"{v}: {w}" for v, w in dead.items()))
        for report in work:
            docs = head[report.rel]
            try:
                model = sigma_explain.from_docs(copy.deepcopy(docs))
            except Exception as e:  # noqa: BLE001 - a head rule that does not compile
                raise Fault(f"{report.rel}: the head rule does not compile: "
                            f"{type(e).__name__}: {e}") from None
            evidence = evidence_of(head_files[report.rel], model.logsource, fixtures, corpus)
            if report.status == "changed":
                judge_pair(report, base[report.base_rel], docs, ctx, evidence, model)
            else:
                new_rule_report(report, docs, ctx, evidence, model)
    return reports, {"head": len(head), "base": len(base), "gone": gone}


def print_report(reports, facts, base_tree, ctx):
    counts = {s: sum(1 for r in reports if r.status == s) for s in ("changed", "unchanged", "new")}
    print(f"Change proof against the base tree {base_tree}: {facts['head']} rule file(s) on "
          f"the head, {facts['base']} on the base; {counts['changed']} changed, "
          f"{counts['unchanged']} unchanged, {counts['new']} new, {len(facts['gone'])} gone.")
    lines, failed, proven, equivalent = [], [], 0, 0
    for r in reports:
        if r.how == "id" and r.base_rel != r.rel:
            print(f"  pair  {r.rel}: the base rule {r.base_rel} has its id")
        if r.status == "changed":
            for u in r.undos:
                if u.status == "killed":
                    proven += 1
                    print(f"  ok    {r.rel}: {u.key}: proven by {u.killed_by['evidence']} "
                          f"[{u.killed_by['representation']}]")
                elif u.status == "equivalent":
                    equivalent += 1
                    print(f"  same  {r.rel}: {u.key}: equivalent (the undo gives the query of "
                          "the head; nothing to prove)")
            if not r.undos and not r.faults:
                print(f"  same  {r.rel}: no change of the logic to undo (a list that is only "
                      "reordered, or a block that no condition reached)")
            ratchet = r.ratchet_lines()
            if ratchet:
                failed.append(r.rel)
                lines += ratchet
        elif r.status == "new":
            shown = ", ".join(r.report_only) if r.report_only else "none"
            print(f"  new   {r.rel}: no base rule has its id or its path: no change to prove. "
                  f"Report only: discriminating items whose drop no evidence tells apart: {shown}")
    for rel in facts["gone"]:
        print(f"  gone  {rel}: on the base, not on the head (check_sufficiency.py --baseline "
              "reports it)")
    for line in lines:
        print(line)
    print()
    for variant, why in ctx.skipped.items():
        print(f"NOT RUN: variant {variant}: {why}. No mutant is judged under it.")
    if lines:
        print(f"FAILED: {len(lines)} change(s) in {len(failed)} rule(s) not proven by the "
              "head's evidence, or not undone alone (the [RATCHET] lines). A human decides: "
              "add the case that tells the change apart from the head rule, or merge the "
              "pull request by hand.")
        return 1
    print(f"OK: {counts['changed']} changed rule(s), {proven} change(s), each proven by a "
          f"case, a fixture or a corpus record of the head ({equivalent} equivalent); "
          f"{counts['unchanged']} unchanged rule(s); {counts['new']} new rule(s), report only.")
    return 0


def write_json(path, reports, facts, base_tree, ctx, code):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"schema": 1, "base_tree": base_tree, "ok": code == 0,
                   "representations": ["default"] + list(ctx.variants),
                   "not_run": ctx.skipped, "gone": facts["gone"],
                   "rules": [r.as_dict() for r in reports if r.status != "unchanged"],
                   "unchanged": sum(1 for r in reports if r.status == "unchanged")},
                  fh, indent=2)
        fh.write("\n")


# ---- self-test -------------------------------------------------------------------


def self_test():
    remember_compiles()
    results = []

    def check(name, cond, detail=""):
        results.append(bool(cond))
        print(f"{'ok   ' if cond else 'FAIL '} {name}" + ("" if cond else f": {detail}"))

    def plain(detection, **extra):
        return dict({"title": "t", "id": "11111111-1111-1111-1111-111111111111",
                     "logsource": {"product": "linux", "service": "auditd"},
                     "detection": detection}, **extra)

    def build(base_docs, head_docs):
        return Builder(base_docs if isinstance(base_docs, list) else [base_docs],
                       head_docs if isinstance(head_docs, list) else [head_docs]).build()

    def kinds(b):
        return [(u.kind, u.target, None if u.value is Undo._NO_VALUE else u.value)
                for u in b.undos]

    def det(b, k=0):
        return b.undos[k].docs[0]["detection"]

    base = plain({"sel": {"syscall": "socket", "a0": ["2", "a"]},
                  "flt": {"comm": ["ping", "ping6"]},
                  "condition": "sel and not flt"})

    def head(change):
        doc = copy.deepcopy(base)
        change(doc["detection"])
        return doc

    # -- the undo builder --------------------------------------------------------
    b = build(base, copy.deepcopy(base))
    check("an equal rule has no undo and no fault", not b.undos and not b.faults, kinds(b))
    b = build(base, dict(base, title="other", description="other", tags=["x"]))
    check("a reworded title, description or tag is no change",
          logic([base]) == logic([dict(base, title="other", description="other")])
          and not b.undos and not b.faults, kinds(b))
    check("a new id or name of a plain rule is no change of its logic",
          logic([base]) == logic([dict(base, id="22222222-2222-2222-2222-222222222222",
                                       name="other")]))
    b = build(base, head(lambda d: d["flt"].__setitem__("comm", ["ping6", "ping"])))
    check("a reordered list is no change", not b.undos and not b.faults, kinds(b))
    b = build(base, head(lambda d: d["flt"]["comm"].append("nc")))
    check("an added list value is dropped", kinds(b) == [("value", "flt.comm", "nc")]
          and det(b)["flt"]["comm"] == ["ping", "ping6"], kinds(b))
    b = build(base, head(lambda d: d["flt"]["comm"].remove("ping6")))
    check("a removed list value is added back",
          kinds(b) == [("removed-value", "flt.comm", "ping6")]
          and det(b)["flt"]["comm"] == ["ping", "ping6"], kinds(b))
    b = build(base, head(lambda d: d["flt"].__setitem__("comm", ["ping*", "ping6"])))
    check("a list that gains and loses values is a changed item, set back in place",
          kinds(b) == [("changed", "flt.comm", None)]
          and det(b)["flt"]["comm"] == ["ping", "ping6"], kinds(b))
    b = build(base, head(lambda d: d.__setitem__("flt", {"comm|re": "^(ping|ping6|nc)$"})))
    check("changed modifiers are a changed item, set back with the base key",
          kinds(b) == [("changed", "flt.comm", None)]
          and det(b)["flt"] == {"comm": ["ping", "ping6"]}, kinds(b))
    b = build(base, head(lambda d: d["sel"].__setitem__("success", "yes")))
    check("an added item is dropped", kinds(b) == [("item", "sel.success", None)]
          and "success" not in det(b)["sel"], kinds(b))
    b = build(plain({"sel": {"a": "1"}, "condition": "sel"}),
              plain({"sel": {"b": "2"}, "condition": "sel"}))
    check("an item replaced by an item on another field: the new one is dropped (the "
          "empty map then holds on every record) and the old one comes back",
          kinds(b) == [("item", "sel.b", None), ("removed", "sel.a", None)]
          and det(b)["sel"] == tautology("b") and det(b, 1)["sel"] == {"b": "2", "a": "1"},
          kinds(b))
    b = build(base, head(lambda d: d["sel"].pop("a0")))
    check("a removed item is added back", kinds(b) == [("removed", "sel.a0", None)]
          and det(b)["sel"]["a0"] == ["2", "a"], kinds(b))
    b = build(base, head(lambda d: d.__setitem__("sel", [d["sel"], {"syscall": "socketpair"}])))
    check("an added map is dropped", kinds(b) == [("map", "sel[1]", None)]
          and det(b)["sel"] == [base["detection"]["sel"]], kinds(b))
    two = plain({"sel": [{"a": "1"}, {"b": "2"}], "condition": "sel"})
    b = build(two, plain({"sel": [{"b": "2"}], "condition": "sel"}))
    check("a removed map is added back in its place",
          kinds(b) == [("removed-map", "sel[0]", None)]
          and det(b)["sel"] == [{"a": "1"}, {"b": "2"}], kinds(b))
    b = build(two, plain({"sel": [{"b": "2"}, {"a": "1"}], "condition": "sel"}))
    check("maps that are only reordered are no change", not b.undos and not b.faults, kinds(b))
    three = plain({"sel": [{"a": "1"}, {"b": "2"}, {"c": "3"}], "condition": "sel"})
    b = build(three, plain({"sel": [{"b": "2"}, {"a": "1"}, {"c": "3"}, {"d": "4"}],
                            "condition": "sel"}))
    check("maps that moved fail closed", not b.undos and b.faults == ["maps of sel moved"],
          (kinds(b), b.faults))
    b = build(three, plain({"sel": [{"a": "1"}, {"b": "5"}, {"e": "6"}], "condition": "sel"}))
    check("maps changed in place are paired in order, item by item",
          kinds(b) == [("changed", "sel[1].b", None), ("item", "sel[2].e", None),
                       ("removed", "sel[2].c", None)], (kinds(b), b.faults))
    b = build(two, plain({"sel": [{"a": "1"}, {"b": "2", "c": "3"}], "condition": "sel"}))
    check("an item added to map 1 of a list is named block[1].field",
          kinds(b) == [("item", "sel[1].c", None)], kinds(b))
    b = build(base, head(lambda d: (d.__setitem__("sel_b", {"exe": "/x"}),
                                    d.__setitem__("condition", "1 of sel* and not flt"))))
    check("an added block never holds, and a changed condition gets the base condition",
          kinds(b) == [("block", "sel_b", None), ("condition", "", None)]
          and det(b)["sel_b"] == NEVER and det(b, 1)["condition"] == "sel and not flt", kinds(b))
    b = build(base, head(lambda d: (d.__setitem__("sel_ok", {"success": "yes"}),
                                    d.__setitem__("condition", "sel and sel_ok and not flt"))))
    check("an added block under an and always holds (an undo that never held would stop "
          "every positive)", kinds(b) == [("block", "sel_ok", None), ("condition", "", None)]
          and det(b)["sel_ok"] == ALWAYS, kinds(b))
    b = build(base, head(lambda d: (d.__setitem__("flt_b", {"exe": "/x"}),
                                    d.__setitem__("condition", "sel and not all of flt*"))))
    check("an added block under `not all of` always holds",
          kinds(b)[0] == ("block", "flt_b", None) and det(b)["flt_b"] == ALWAYS, kinds(b))
    b = build(base, head(lambda d: (d.__setitem__("flt_b", {"exe": "/x"}),
                                    d.__setitem__("condition", "sel and not (flt or flt_b)"))))
    check("an added block under `not (... or ...)` never holds",
          kinds(b)[0] == ("block", "flt_b", None) and det(b)["flt_b"] == NEVER, kinds(b))
    b = build(base, head(lambda d: (d.__setitem__("x", {"exe": "/x"}),
                                    d.__setitem__("condition", "(sel and x) or (flt and not x)"))))
    check("an added block that must hold in one place and must not in another fails closed",
          [k for k, _, _ in kinds(b)] == ["condition"] and len(b.faults) == 1
          and "block x must hold in one place" in b.faults[0], (kinds(b), b.faults))
    b = build(base, head(lambda d: (d.__setitem__("only", {"exe": "/x"}),
                                    d.__setitem__("condition", "only"))))
    check("an added block that is the whole condition has no undo of its own (the undo of "
          "the condition holds it)", [k for k, _, _ in kinds(b)] == ["condition"]
          and not b.faults, (kinds(b), b.faults))
    b = build(base, head(lambda d: (d.__setitem__("allowed", d.pop("flt")),
                                    d.__setitem__("condition", "sel and not allowed"))))
    check("a renamed block fails closed, and its condition is not undone alone",
          not b.undos and b.faults == ["block flt renamed to allowed"], (kinds(b), b.faults))
    b = build(base, head(lambda d: (d.pop("flt"), d.__setitem__("condition", "sel"))))
    check("a removed block comes back, also with the base condition",
          [k for k, _, _ in kinds(b)] == ["removed-block", "condition"]
          and det(b, 1)["flt"] == base["detection"]["flt"]
          and det(b, 1)["condition"] == "sel and not flt", kinds(b))
    b = build(base, dict(base, logsource={"product": "linux", "category": "process_creation"}))
    check("a changed logsource is a change that no evidence can prove",
          kinds(b) == [("logsource", "", None)], kinds(b))
    b = build(plain({"kw": ["a", "b"], "condition": "kw"}),
              plain({"kw": ["a", "b", "c"], "condition": "kw"}))
    check("a value added to a keyword block is dropped", kinds(b) == [("value", "kw", "c")]
          and det(b)["kw"] == ["a", "b"], kinds(b))

    corr = {"title": "c", "id": "c", "correlation": {"type": "temporal", "rules": ["x", "y"],
                                                     "group-by": ["pid", "ppid"],
                                                     "timespan": "5s"}}
    bx = plain({"s": {"syscall": "socket"}, "condition": "s"}, name="x", id="x1")
    by = plain({"s": {"syscall": "splice"}, "f": {"comm": ["a"]}, "condition": "s and not f"},
               name="y", id="y1")
    cdocs = [corr, bx, by]

    def changed(edit):
        docs = copy.deepcopy(cdocs)
        edit(docs)
        return docs

    b = build(cdocs, changed(lambda d: d[0]["correlation"].__setitem__("timespan", "50s")))
    check("a changed timespan gets its base value", kinds(b) == [("corr-timespan", "", None)]
          and b.undos[0].docs[0]["correlation"]["timespan"] == "5s", kinds(b))
    b = build(cdocs, changed(lambda d: d[0]["correlation"].__setitem__("group-by", ["ppid", "pid"])))
    check("a reordered group-by is no change", not b.undos, kinds(b))
    b = build(cdocs, changed(lambda d: d[0]["correlation"].__setitem__("rules", ["y", "x"])))
    check("reordered `rules` of a temporal correlation are no change", not b.undos, kinds(b))
    ordered = changed(lambda d: d[0]["correlation"].__setitem__("type", "temporal_ordered"))
    b = build(ordered, changed(lambda d: d[0]["correlation"].update(type="temporal_ordered",
                                                                     rules=["y", "x"])))
    check("reordered `rules` of a temporal_ordered correlation are a change (it reads the "
          "order)", kinds(b) == [("corr-rules", "", None)], kinds(b))

    def rename_y(d, name="y2", ident="y2id"):
        d[2].update(name=name, id=ident)
        d[0]["correlation"]["rules"] = ["x", name]
    b = build(cdocs, changed(rename_y))
    check("a base rule with a new name and id and the same logic is no change",
          not b.undos and not b.faults, (kinds(b), b.faults))
    b = build(cdocs, changed(lambda d: (rename_y(d), d[2]["detection"]["f"]["comm"].append("b"))))
    check("a base rule with a new name and id is paired with the one base rule left: its "
          "changes are undone one by one", kinds(b) == [("value", "y2/f.comm", "b")]
          and not b.faults, (kinds(b), b.faults))
    b = build(cdocs, changed(lambda d: (rename_y(d), d[1].update(name="x2", id="x2id"),
                                        d[0]["correlation"].__setitem__("rules", ["x2", "y2"]))))
    check("two base rules with new names and ids fail closed",
          len(b.faults) == 1 and "x2, y2 of the head have no pair among base rule(s) x, y"
          in b.faults[0], (kinds(b), b.faults))
    b = build(cdocs, changed(lambda d: d[2]["detection"]["f"]["comm"].append("b")))
    check("an added value in a base rule is named after the base rule",
          kinds(b) == [("value", "y/f.comm", "b")]
          and b.undos[0].docs[2]["detection"]["f"]["comm"] == ["a"], kinds(b))
    bz = plain({"s": {"syscall": "bind"}, "condition": "s"}, name="z", id="z1")
    b = build(cdocs, changed(lambda d: (d.append(bz), d[0]["correlation"]["rules"].append("z"))))
    check("an added base rule goes with the base `rules`",
          kinds(b) == [("corr-rules", "", None)]
          and [d.get("name") for d in b.undos[0].docs] == [None, "x", "y"], kinds(b))
    b = build(cdocs, changed(lambda d: d.append(bz)))
    check("a base rule added while `rules` did not change fails closed",
          not b.undos and len(b.faults) == 1, (kinds(b), b.faults))

    # -- pairs ---------------------------------------------------------------------
    rule = plain({"condition": "s", "s": {"a": 1}})
    check("the id pairs a renamed file, and the path pairs a file whose id changed",
          pair_rules({"T1/new.yml": [rule], "T1/same.yml": [dict(rule, id="z")]},
                     {"T1/old.yml": [rule], "T1/same.yml": [dict(rule, id="y")]})
          == {"T1/new.yml": ("T1/old.yml", "id"), "T1/same.yml": ("T1/same.yml", "path")})
    check("a path that an id already paired is not paired again (the head file is new)",
          pair_rules({"T1/a.yml": [dict(rule, id="q")], "T1/b.yml": [dict(rule, id="p")]},
                     {"T1/a.yml": [dict(rule, id="p")]}) == {"T1/b.yml": ("T1/a.yml", "id")})

    # -- the kill test, on constructed evidence (no corpus, no fixture) ----------------
    ctx = check_variants.Context()

    def verdict(base_doc, head_doc, evidence):
        return judge_pair(Report("T0000/r.yml", "T0000/r.yml", "path"), [base_doc], [head_doc],
                          ctx, evidence)

    def states(report):
        return [(u.key, u.status, (u.killed_by or {}).get("representation")) for u in report.undos]

    raw = {"type": "SYSCALL", "syscall": "socket", "a0": "2", "comm": "x"}
    pos = Evidence("case", "pos", "positive", [raw])
    widened = head(lambda d: d["flt"]["comm"].append("nc"))
    report = verdict(base, widened, [pos])
    check("an allowlist value with no case is not proven",
          states(report) == [('flt-value:flt.comm="nc"', "not-killed", None)], states(report))
    report = verdict(base, widened, [pos, Evidence("case", "nc", "filtered", [dict(raw, comm="nc")])])
    check("a filtered case of the value kills its undo",
          states(report) == [('flt-value:flt.comm="nc"', "killed", "default")]
          and report.undos[0].killed_by["evidence"] == "case filtered nc", states(report))
    report = verdict(base, widened, [Evidence("case", "loud", "near-miss", [dict(raw, comm="y")])])
    check("evidence on which the head fails is skipped (the head fires on a near-miss, and "
          "so does the undo)", states(report) == [('flt-value:flt.comm="nc"', "not-killed", None)]
          and ("case near-miss loud", "default") in report.failing, states(report))
    report = verdict(base, widened, [Evidence("corpus", "slice", "benign", [dict(raw, comm="nc")])])
    check("a corpus slice that gains a hit under the undo kills",
          [s for _, s, _ in states(report)] == ["killed"], states(report))
    report = verdict(base, widened, [Evidence("fixture", "b.json", "benign", [dict(raw, comm="nc")])])
    check("a benign fixture that gains a hit under the undo kills",
          [s for _, s, _ in states(report)] == ["killed"], states(report))
    noisy = head(lambda d: d["sel"].__setitem__("syscall", ["socket", "bind"]))
    bind = dict(raw, syscall="bind")
    report = verdict(base, noisy, [pos, Evidence("corpus", "slice", "benign", [bind])])
    check("a corpus slice that loses a hit under the undo does not kill (the undo is the "
          "quieter rule)", [s for _, s, _ in states(report)] == ["not-killed"], states(report))
    report = verdict(base, noisy, [Evidence("fixture", "a.json", "attack", [raw, bind])])
    check("an attack fixture that loses a hit under the undo kills",
          [s for _, s, _ in states(report)] == ["killed"], states(report))
    report = verdict(base, noisy, [Evidence("case", "bind", "positive", [bind])])
    check("a positive that stops firing under the undo kills",
          [s for _, s, _ in states(report)] == ["killed"], states(report))
    lowered = plain({"sel": {"name|contains": "abc"}, "condition": "sel"})
    upper = plain({"sel": {"name|contains": "ABC"}, "condition": "sel"})
    report = verdict(lowered, upper, [Evidence("case", "p", "positive", [{"name": "xABCx"}])])
    check("a letter-case fix is killed only under cs_like",
          [(s, r) for _, s, r in states(report)] == [("killed", "cs_like")], states(report))
    listed = plain({"sel": {"user.groups|re": ['\\"system:masters\\"']}, "condition": "sel"})
    anchored = plain({"sel": {"user.groups|re": ['\\"system:masters\\"', "^system:masters$"]},
                      "condition": "sel"})
    element = Evidence("case", "p", "positive", [{"user": {"groups": ["system:masters", "dev"]}}])
    report = verdict(listed, anchored, [element])
    check("an anchored value for a list element is killed only under multi",
          [(s, r) for _, s, r in states(report)] == [("killed", "multi")], states(report))
    report = verdict(plain({"sel": {"name": "*abc*"}, "condition": "sel"}),
                     plain({"sel": {"name|contains": "abc"}, "condition": "sel"}),
                     [Evidence("case", "p", "positive", [{"name": "abc"}])])
    check("an undo that compiles to the query of the head is equivalent",
          [s for _, s, _ in states(report)] == ["equivalent"], states(report))
    listed = head(lambda d: d["flt"]["comm"].extend(["nc", "socat"]))
    judge = Judge(ctx, [listed], [Evidence("case", "pos", "positive", [dict(raw, tags=["a", "b"])])])
    for value in ("nc", "socat"):
        docs = [copy.deepcopy(listed)]
        docs[0]["detection"]["flt"]["comm"].remove(value)
        judge.judge(Undo("value", "flt.comm", docs, value=value))
    computed = judge.stores[0].get().computed
    check("an undo pays only for the item that it changes: 3 items of the head on 2 tables "
          "(the default records and the elements of the list `tags`), then 1 item on 2 "
          "tables for each of the 2 undos", computed == 3 * 2 + 2 * 2, computed)
    report = verdict(base, head(lambda d: d.__setitem__("condition", "not flt and sel")), [pos])
    check("a condition with its terms in another order is equivalent (the same value for "
          "each assignment of true, false and NULL to its items)",
          [s for _, s, _ in states(report)] == ["equivalent"], states(report))
    check("a condition that is the same only in two-valued logic is not equivalent (flt or "
          "not flt is NULL where the record has no comm)",
          not same_logic(sigma_explain.from_docs([plain(dict(base["detection"],
                                                             condition="sel"))]),
                         sigma_explain.from_docs([plain(dict(base["detection"],
                                                             condition="sel and (flt or not flt)"))])))
    corpus, attack = Evidence("corpus", "s", "benign", []), Evidence("fixture", "a", "attack", [])
    check("a correlation that groups the same events in other alerts gains no corpus hit",
          not kills(corpus, {(1, 2), (3, 4)}, {(1, 2, 3), (4,)})
          and kills(corpus, {(1, 2)}, {(1, 2), (5, 6)}), "")
    check("a correlation that groups the same events in other alerts loses no fixture hit",
          not kills(attack, {(1, 2), (3, 4)}, {(1, 2, 3, 4)})
          and kills(attack, {(1, 2), (3, 4)}, {(1, 2)}), "")
    report = verdict(base, head(lambda d: (d.pop("flt"), d.__setitem__("condition", "sel"))),
                     [pos])
    check("a removed block that the head condition cannot reach comes back only with the "
          "base condition", [k for k, _, _ in states(report)] == ["condition"], states(report))

    for variant, why in ctx.skipped.items():
        print(f"self-test: variant {variant} NOT RUN ({why}): its kills are not proven")
    if all(results):
        print(f"self-test: all {len(results)} checks hold")
        return 0
    print(f"self-test: {results.count(False)} of {len(results)} checks FAILED")
    return 1


# ---- main ------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Fail a change to a rule's logic that no case, "
                                             "fixture or corpus record of the head tells "
                                             "apart from the head rule with the change undone.")
    ap.add_argument("--base-tree", metavar="DIR",
                    help="a checkout of the base branch (its rule files are read as data)")
    ap.add_argument("--json", metavar="PATH", help="write the report as JSON")
    ap.add_argument("--self-test", action="store_true",
                    help="check the undo builder and the kill test on constructed rules")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.base_tree:
        ap.error("--base-tree DIR is required (or --self-test)")
    ctx = check_variants.Context()
    try:
        reports, facts = run(args.base_tree, ctx)
    except Fault as e:
        print(f"ERROR: {e}")
        return 2
    code = print_report(reports, facts, args.base_tree, ctx)
    if args.json:
        write_json(args.json, reports, facts, args.base_tree, ctx, code)
    return code


if __name__ == "__main__":
    sys.exit(main())
