#!/usr/bin/env python3
"""
Run the offline test cases that ship next to a Sigma rule.

A rule `detections/sigma/<T>/<stem>.yml` may carry a sidecar file
`detections/sigma/<T>/<stem>.cases.jsonl`: one JSON object per line, each a small
event set with a declared expectation. The cases run through the same pySigma
SQLite backend as every validator (sigma_eval), and sigma_explain checks that
each negative case really tests what it says it tests.

Case fields:

  name     unique within the file.
  kind     positive    the rule must fire (expect "match").
           near-miss   keeps part of the technique's surface (some selection item
                       holds) but breaks one required part (a wrong argument, a
                       missing field, half a correlation).
           filtered    the selections hold and an allowlist / `not filter` item
                       alone suppresses it (an allowlisted look-alike).
           confounder  a look-alike that must not fire for a reason that is not
                       one atom (e.g. a different provenance); must not be trivial
                       (some positive item must hold).
           benign      ordinary activity that must not fire. Any shape.
  breaks   near-miss / filtered only: the condition atom(s) the case is built to
           flip. For a plain rule an atom is one detection ITEM, named
           `<block>.<field>` (`afinet_raw_socket.a1`, `allowed_processes.comm`),
           `<block>[i].<field>` inside a list of maps, or `<block>` for a keyword
           list; when one map holds several items on the same field, each keeps
           its modifiers (`selection.exe|startswith`, `selection.exe|endswith`).
           For a correlation rule it is `base:<ref>` (the base rule's name or id,
           as the correlation's `rules:` lists it), `group-by`, `timespan`,
           `order` (temporal_ordered) or `threshold` (event_count / value_count).
           The runner computes which single flips would fire the rule (for a
           correlation: which single-atom repairs make the compiled rule fire)
           and fails the case unless every declared atom is among them. A case
           where no positive item holds is trivial however few flips away it is,
           and a flip only counts through a branch the event already shares, so
           an unrelated event cannot be passed off as a near-miss. An item of a
           null guard or a null-safe copy (sigma_explain's null_helpers()) only
           makes a `not` null-safe, and no record flips it alone, so a case that
           names one fails: name the filter's item.
           (`rule_cases.py --atoms RULE` lists a rule's atoms.)
  why      one line: what the case proves.
  events   the event set, as the log source writes it (nested JSON is flattened
           the way the validators flatten it; flat auditd events stay flat).
  source   optional provenance note ("synthetic: ..." or "recorded: ...").

Usage:
    python3 detections/rule_cases.py                  # every rule that has cases
    python3 detections/rule_cases.py detections/sigma/T1040/afinet_raw_socket.yml
    python3 detections/rule_cases.py --explain ...    # print every case's block table
"""

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigma_eval  # noqa: E402
import sigma_explain  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA = os.path.join(REPO, "detections", "sigma")
KINDS = {"positive", "near-miss", "filtered", "confounder", "benign"}
REQUIRED = ("name", "kind", "why", "events")


def cases_path(rule_path):
    return rule_path[:-len(".yml")] + ".cases.jsonl"


def load_cases(path):
    """Parse a sidecar file. Returns (cases, errors)."""
    cases, errors, names = [], [], set()
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                case = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"line {n}: not JSON ({e})")
                continue
            missing = [k for k in REQUIRED if k not in case]
            if missing:
                errors.append(f"line {n}: missing {', '.join(missing)}")
                continue
            if case["kind"] not in KINDS:
                errors.append(f"line {n}: unknown kind {case['kind']!r}")
                continue
            if case["name"] in names:
                errors.append(f"line {n}: duplicate name {case['name']!r}")
                continue
            if not isinstance(case["events"], list) or not case["events"]:
                errors.append(f"line {n}: events must be a non-empty list")
                continue
            if case["kind"] in ("near-miss", "filtered") and not case.get("breaks"):
                errors.append(f"line {n}: a {case['kind']} case must declare `breaks`")
                continue
            names.add(case["name"])
            case["_line"] = n
            cases.append(case)
    return cases, errors


class CaseResult:
    def __init__(self, case, ok, detail, verdict):
        self.case, self.ok, self.detail, self.verdict = case, ok, detail, verdict


def run_case(rule, case):
    """Judge one case. Returns a CaseResult.

    The case is graded on the rule without its null guards and null-safe copies
    (sigma_explain's stripped()): on a real record the verdict is the same, and a
    helper item is no item a case can break."""
    events = [sigma_eval.flatten(e) for e in case["events"]]
    helpers, rule = rule.null_helpers(), rule.stripped()
    verdicts = sigma_explain.judge_events(rule, events)
    if rule.is_correlation:
        verdict = verdicts[0]
    else:
        # The case fires if any of its events fires; otherwise it is as close as
        # its closest event.
        verdict = min(verdicts, key=lambda v: (sigma_explain.KIND_RANK[v.kind], -v.closeness))
    if any(v.mismatch for v in verdicts):
        return CaseResult(case, False, "sigma_explain's item-by-item verdict disagrees with the "
                          "compiled rule on this case; the grading cannot be trusted (report it)",
                          verdict)
    kind = case["kind"]
    if kind == "positive":
        if verdict.fired:
            return CaseResult(case, True, "fires", verdict)
        return CaseResult(case, False, f"expected a match, got {verdict.kind}"
                          + (f" (one flip would fire it: {', '.join(verdict.atoms)})"
                             if verdict.atoms else ""), verdict)
    if verdict.fired:
        return CaseResult(case, False, f"expected no match, but the rule fires ({kind} case)",
                          verdict)
    if kind in ("near-miss", "filtered"):
        declared = case["breaks"] if isinstance(case["breaks"], list) else [case["breaks"]]
        named = [a for a in declared if a in helpers]
        if named:
            return CaseResult(case, False, "`breaks` names a null-safety item, which only makes "
                              "a `not` null-safe and which no record flips alone: "
                              + "; ".join(_helper_text(a, helpers[a]) for a in named)
                              + ". Name the filter's item instead (for a record that the filter "
                              "alone suppresses, as kind filtered)", verdict)
        unknown = [a for a in declared if a not in rule.atoms]
        if unknown:
            ambiguous = {a: [b for b in rule.atoms if b.startswith(a + "|")] for a in unknown}
            hint = "; ".join(f"{a} is ambiguous, name one of: {', '.join(b)}"
                             for a, b in ambiguous.items() if b)
            return CaseResult(case, False, f"`breaks` names no condition atom: {unknown} "
                              + (f"({hint})" if hint else f"(atoms: {', '.join(rule.atoms)})"),
                              verdict)
        if verdict.kind not in sigma_explain.NON_TRIVIAL:
            return CaseResult(case, False, f"declared {kind} on {declared}, but the analysis "
                              f"grades it {verdict.kind}: {_why_not(rule, verdict)}", verdict)
        wrong = [a for a in declared if a not in verdict.atoms]
        if wrong:
            lone = [a for a in wrong if a in verdict.lone]
            if lone:
                return CaseResult(case, False, f"declared to break {lone}: flipping that alone "
                                  "fires the rule, but through a branch the case holds no item "
                                  "of, so it is no closer to firing it than an unrelated event "
                                  f"(single flips that count: {', '.join(verdict.atoms)})",
                                  verdict)
            how = "repairing that alone does not make the compiled correlation fire" \
                if rule.is_correlation else "flipping that alone does not fire the rule"
            return CaseResult(case, False, f"declared to break {wrong}, but {how} "
                              f"(single atoms that do: {', '.join(verdict.atoms)})", verdict)
        if kind == "filtered" and rule.is_correlation is False and not all(
                "-" in rule.polarity[a] for a in declared):
            return CaseResult(case, False, "a filtered case must break a `not` (filter) "
                              f"block; {declared} is a selection, so use kind near-miss",
                              verdict)
        return CaseResult(case, True, f"{verdict.kind} on {', '.join(declared)}", verdict)
    if kind == "confounder" and verdict.kind == "trivial":
        return CaseResult(case, False, "a confounder must share the rule's surface, but no "
                          f"positive {'base' if rule.is_correlation else 'item'} holds (trivial); "
                          "call it benign or make it closer", verdict)
    return CaseResult(case, True, f"no match ({verdict.kind})", verdict)


def _helper_text(atom, role):
    kind, instead = role
    if kind == "guard":
        return (f"{atom} is a null guard of {', '.join(instead)} (a record without that field "
                "also fails the filter's item on it)")
    return (f"{atom} is a null-safe copy of {', '.join(instead)} (it holds exactly where that "
            "item holds)")


def _why_not(rule, verdict):
    """Why a non-matching verdict is not one atom away, in the grader's own terms."""
    if verdict.mismatch:
        return "the item-composed verdict disagrees with the compiled rule"
    if rule.is_correlation:
        if verdict.unseen:
            return (f"event(s) #{', #'.join(str(i) for i in verdict.unseen)} carry no parseable "
                    "timestamp or no group-by value, so the correlation never sees them; a "
                    "near-miss needs every event of the set visible to it")
        if verdict.kind == "trivial":
            return "no base rule matches any event of the set"
        return f"no single-atom repair ({', '.join(rule.atoms)}) makes the compiled " \
               "correlation fire"
    if verdict.kind == "trivial":
        return "no positive item of the rule holds, so it is no closer to firing it than an " \
               "unrelated event" + (f" (a flip of {', '.join(verdict.lone)} alone would fire it, "
                                    "as it would for any event)" if verdict.lone else "")
    return "some positive item holds, but no single item flip fires the rule" \
        + (f" through a branch the case shares (a flip of {', '.join(verdict.lone)} would, "
           "through a branch it holds nothing of)" if verdict.lone else "")


def run_rule(rule_path):
    """Run one rule's sidecar. Returns (rule, results, errors) or None if no sidecar."""
    path = cases_path(rule_path)
    if not os.path.exists(path):
        return None
    rule = sigma_explain.load(rule_path)
    cases, errors = load_cases(path)
    return rule, [run_case(rule, c) for c in cases], errors


def summarize(rule, results):
    """What the sidecar proves: positives, verified near-misses, atom coverage."""
    positives = sum(1 for r in results if r.ok and r.case["kind"] == "positive")
    verified = [r for r in results if r.ok and r.case["kind"] in ("near-miss", "filtered")]
    covered = sorted({a for r in verified
                      for a in (r.case["breaks"] if isinstance(r.case["breaks"], list)
                                else [r.case["breaks"]])})
    # A null guard or null-safe copy is not an item of the rule (check_sufficiency.py
    # counts the same way).
    return {"positives": positives, "near_misses": len(verified), "covered_atoms": covered,
            "atoms": list(rule.stripped().atoms)}


def main():
    ap = argparse.ArgumentParser(description="Run the rule test cases (<rule>.cases.jsonl).")
    ap.add_argument("rules", nargs="*", help="rule files (default: every rule with cases)")
    ap.add_argument("--explain", action="store_true", help="print every case's block table")
    ap.add_argument("--atoms", action="store_true",
                    help="list each rule's condition atoms (for `breaks`) and exit")
    args = ap.parse_args()

    if args.atoms:
        for rule_path in args.rules:
            rule = sigma_explain.load(rule_path)
            print(os.path.relpath(rule_path, SIGMA))
            helpers = rule.null_helpers()
            for atom in rule.atoms:
                fields = ", ".join(rule.fields(atom)) or "-"
                negated = not rule.is_correlation and "+" not in rule.polarity[atom]
                role = (f"  ({'null guard' if helpers[atom][0] == 'guard' else 'null-safe copy'}"
                        f" of {', '.join(helpers[atom][1])}: not for `breaks`)") \
                    if atom in helpers else ""
                print(f"  {atom:<48} {'filter' if negated else 'select'}  reads: {fields}{role}")
        return 0

    rules = args.rules or sorted(p[:-len(".cases.jsonl")] + ".yml"
                                 for p in glob.glob(os.path.join(SIGMA, "*", "*.cases.jsonl")))
    failures = 0
    for rule_path in rules:
        rel = os.path.relpath(rule_path, SIGMA)
        if not os.path.exists(rule_path):
            print(f"ERROR {rel}: a cases file exists but the rule does not")
            failures += 1
            continue
        out = run_rule(rule_path)
        if out is None:
            print(f"NONE  {rel}: no {os.path.basename(cases_path(rule_path))}")
            continue
        rule, results, errors = out
        for err in errors:
            print(f"ERROR {rel}: {err}")
            failures += 1
        for r in results:
            status = "ok  " if r.ok else "FAIL"
            print(f"{status}  {rel} :: {r.case['kind']:<10} {r.case['name']}: {r.detail}")
            if not r.ok:
                failures += 1
                print(f"        why: {r.case['why']}")
            if not r.ok or args.explain:
                for line in r.verdict.lines:
                    print("      " + line)
        s = summarize(rule, results)
        print(f"      -> {s['positives']} positive, {s['near_misses']} verified near-miss; "
              f"atoms exercised {len(s['covered_atoms'])}/{len(s['atoms'])}"
              + (f" ({', '.join(s['covered_atoms'])})" if s["covered_atoms"] else ""))
    print()
    if failures:
        print(f"FAILED: {failures} case problem(s).")
        return 1
    print(f"All cases hold ({len(rules)} rule file(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
