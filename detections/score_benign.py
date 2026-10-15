#!/usr/bin/env python3
"""
Score every Sigma rule against the benign corpus: the false-positive layer.

The validators are the hard gate: a rule must fire on its emulation and stay
silent on its broken variants (binary, fast, strict). This is the second,
softer layer. It runs every rule over the benign corpus
(detections/benign/slices/, see benign_corpus.py) through the same pySigma
SQLite backend, and reports for each rule:

  hits             alerts the rule raised on benign activity
  rate_per_10k     hits per 10,000 events of the rule's logsource
  actors           who is behind those hits: the first field present of ACTOR_FIELDS
                   for the logsource (auditd exe, else comm; Kubernetes audit
                   user.username; Kubernetes CRI the pod's metadata.namespace, not a
                   principal; CloudTrail the session issuer's role ARN before
                   userIdentity.arn, so one role counts once across its sessions;
                   the Azure / GCP caller or principal fields)
  slices           which slices they came from

Budgets (detections/benign/budgets.json) set, per rule, how many benign hits are
acceptable and whether going over is a warning (mode "shadow") or a failure
(mode "enforce", with --enforce). budgets.json's `default` (enforce at 0 hits)
applies to a rule with no entry; shadow at 0 is only the fallback when the file
names no default. Every per-rule entry is "enforce" today, so a rule that gets
noisier on the committed corpus fails CI; "shadow" is for a rule a human accepts
while its corpus is not yet trusted. Raising a budget is a human decision: it
means "this much noise is acceptable", so a budget change needs a human approval
before merge. Set max_hits from the most hits over several seeds of the
synthetic slices (--reseeds 10), not from one seed's exact count, or a routine
version bump of a slice trips the budget. Every entry's `why` starts
"documented noise:" or "rule defect, tracked in detections/RULE_DEFECTS.md
<ID>:" (an ID the tracker's summary lists); any other entry is an error.

A rule is scored against every slice whose product and service match its own
logsource (category counts only when neither side names a service), so adding a
`category:` to a rule cannot move it out of scoring. A rule that no slice reads
is "not scored": --check and --enforce fail unless budgets.json lists it under
`unscored` with the reason, because leaving the false-positive layer is a human
decision like a budget.

The committed snapshot (detections/benign/scores.json) records every rule's
score, so a change that moves a rule's false-positive count shows up in the pull
request diff, and the git history of that file is the trend. --check fails when
the snapshot is stale; --update rewrites it.

A live capture (the kind cluster's pre-emulation audit log, a recorded Linux
benign workload) can be scored with --extra-slice. Extra slices are reported in
shadow mode only and never enter the snapshot.

Usage:
    python3 detections/score_benign.py                 # report
    python3 detections/score_benign.py --check         # snapshot is current
    python3 detections/score_benign.py --update        # rewrite the snapshot
    python3 detections/score_benign.py --enforce       # fail on enforce-mode overruns
    python3 detections/score_benign.py --reseeds 10    # most hits over 10 reseeds
    python3 detections/score_benign.py --extra-slice /tmp/pre-emulation-audit.log \\
        --extra-logsource kubernetes/audit --extra-label kind-bootstrap
"""

import argparse
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benign_corpus  # noqa: E402
import sigma_eval  # noqa: E402
import sigma_explain  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA = os.path.join(REPO, "detections", "sigma")
BUDGETS = os.path.join(benign_corpus.ROOT, "budgets.json")
DEFECTS = os.path.join(REPO, "detections", "RULE_DEFECTS.md")
SNAPSHOT = os.path.join(benign_corpus.ROOT, "scores.json")
TOP_ACTORS = 10

# Who did it, per logsource: the first field present on a hit event.
ACTOR_FIELDS = {
    ("linux", "auditd"): ["exe", "comm"],
    ("kubernetes", "audit"): ["user.username"],
    ("kubernetes", "cri"): ["metadata.namespace"],
    # The session issuer (the role) before the per-session ARN, so one role used by
    # many instances or pods counts as one actor, not one per session.
    ("aws", "cloudtrail"): ["userIdentity.sessionContext.sessionIssuer.arn", "userIdentity.arn",
                            "userIdentity.principalId", "userIdentity.invokedBy",
                            "userIdentity.type"],
    ("azure", "auditlogs"): ["properties.initiatedBy.user.userPrincipalName",
                             "properties.initiatedBy.app.servicePrincipalName",
                             "properties.initiatedBy.app.displayName"],
    ("azure", "signinlogs"): ["properties.userPrincipalName", "properties.servicePrincipalName",
                              "properties.appDisplayName"],
    ("azure", "activitylogs"): ["caller", "identity.claims.name", "identity.claims.appid"],
    # Federated callers (Workload / Workforce Identity Federation, STS token
    # exchange) log no principalEmail, only principalSubject.
    ("gcp", "gcp.audit"): ["protoPayload.authenticationInfo.principalEmail",
                           "protoPayload.authenticationInfo.principalSubject",
                           "protoPayload.authenticationInfo.serviceAccountDelegationInfo"],
}


def actor(event, logsource):
    key = (logsource.get("product"), logsource.get("service"))
    for field in ACTOR_FIELDS.get(key, []):
        if event.get(field) not in (None, ""):
            return str(event[field])
    return "<unknown>"


def reads(slice_logsource, rule_logsource):
    """True if a rule with rule_logsource is scored against a slice with slice_logsource.

    Product and service decide. Category counts only when neither side names a
    service: the compiled query ignores logsource, so an extra `category:` on a
    rule must not take it out of scoring.
    """
    mine, theirs = slice_logsource or {}, rule_logsource or {}
    if mine.get("product") != theirs.get("product"):
        return False
    if mine.get("service") or theirs.get("service"):
        return mine.get("service") == theirs.get("service")
    return mine.get("category") == theirs.get("category")


def rule_key(path):
    return os.path.relpath(path, SIGMA).replace(os.sep, "/")


def load_rules(paths=None):
    rules = []
    for path in paths or sorted(glob.glob(os.path.join(SIGMA, "*", "*.yml"))):
        model = sigma_explain.load(path)
        rules.append({"key": rule_key(path), "path": path, "model": model,
                      "sql": model.sql, "logsource": model.logsource,
                      "level": model.level})
    return rules


def load_budgets():
    with open(BUDGETS, encoding="utf-8") as fh:
        doc = json.load(fh)
    default = doc.get("default", {"mode": "shadow", "max_hits": 0})
    return default, doc.get("rules", {}), doc.get("unscored", {})


_DEFECT_WHY = re.compile(r"rule defect, tracked in detections/RULE_DEFECTS\.md ([A-Z]\d+):")


def budget_problems(budgets):
    """Each per-rule entry: a known mode, an integer max_hits, and a why that names
    its class: 'documented noise:' or 'rule defect, tracked in
    detections/RULE_DEFECTS.md <ID>:' with an ID that the tracker's summary lists."""
    try:
        with open(DEFECTS, encoding="utf-8") as fh:
            tracked = set(re.findall(r"^\| \[([A-Z]\d+)\]\(", fh.read(), re.M))
    except OSError:
        tracked = set()
    problems = []
    for key, b in sorted(budgets.items()):
        if not isinstance(b, dict):
            problems.append(f"{key}: not an object")
            continue
        if b.get("mode") not in ("enforce", "shadow"):
            problems.append(f"{key}: mode must be 'enforce' or 'shadow'")
        if not isinstance(b.get("max_hits"), int) or isinstance(b.get("max_hits"), bool) \
                or b["max_hits"] < 0:
            problems.append(f"{key}: max_hits must be a non-negative integer")
        why = b.get("why")
        why = why.strip() if isinstance(why, str) else ""
        m = _DEFECT_WHY.match(why)
        if m and m.group(1) not in tracked:
            problems.append(f"{key}: why cites RULE_DEFECTS.md {m.group(1)}, which the "
                            "tracker's summary table does not list")
        elif not m and not why.startswith("documented noise:"):
            problems.append(f"{key}: why must start 'documented noise:' or 'rule defect, "
                            "tracked in detections/RULE_DEFECTS.md <ID>:'")
    return problems


def budget_for(key, default, budgets):
    b = dict(default)
    b.update(budgets.get(key, {}))
    return b


def score(rules, slices):
    """{rule key: score dict} over the given slices, plus a few example hits."""
    scores, examples = {}, {}
    for s in slices:
        readers = [r for r in rules if reads(s.logsource, r["logsource"])]
        if not readers:
            continue
        table = sigma_eval.EventTable(s.events)
        for r in readers:
            sc = scores.setdefault(r["key"], {"events": 0, "hits": 0, "actors": {},
                                              "slices": {}})
            sc["events"] += len(s.events)
            hits = table.hit_indices(r["sql"])
            sc["slices"][s.id] = len(hits)
            sc["hits"] += len(hits)
            for hit in hits:
                who = actor(s.events[hit[0]], r["logsource"])
                sc["actors"][who] = sc["actors"].get(who, 0) + 1
            if hits:
                examples.setdefault(r["key"], []).append((s, [s.events[i] for i in hits[0]]))
    for sc in scores.values():
        sc["rate_per_10k"] = round(sc["hits"] * 10000 / sc["events"], 2) if sc["events"] else 0.0
        top = sorted(sc["actors"].items(), key=lambda kv: (-kv[1], kv[0]))
        sc["distinct_actors"] = len(top)
        sc["actors"] = dict(top[:TOP_ACTORS])
    return scores, examples


def reseeded(s, k):
    """Slice s expanded at version v+k from a copy of its spec (a recorded slice as is)."""
    if s.fidelity != "synthetic" or not k:
        return s
    spec = dict(s.spec, version=s.version + k)
    return benign_corpus.Slice(spec, s.path, benign_corpus.expand(spec))


def reseed_max(rules, slices, n):
    """{rule key: most hits} over the committed corpus and n reseeds of each synthetic slice.

    Every synthetic slice is expanded again at versions v+1..v+n (the committed specs are
    not touched). A rule's figure is the most hits it raises with every slice at the same
    offset, or with any one slice bumped alone, so a budget set from it holds across a
    routine version bump, where one seed's exact count would not.
    """
    per = {}  # rule key -> slice id -> [hits at v, v+1, ..., v+n]
    for s in slices:
        for k in range(n + 1):
            for key, sc in score(rules, [reseeded(s, k)])[0].items():
                per.setdefault(key, {}).setdefault(s.id, [0] * (n + 1))[k] = sc["hits"]
    most = {}
    for key, by_slice in per.items():
        now = sum(h[0] for h in by_slice.values())
        together = max(sum(h[k] for h in by_slice.values()) for k in range(n + 1))
        alone = max(now - h[0] + h[k] for h in by_slice.values() for k in range(n + 1))
        most[key] = max(together, alone)
    return most


def snapshot(scores, slices):
    return {
        "_doc": "Generated by detections/score_benign.py --update. Do not edit by hand.",
        "corpus_digest": benign_corpus.corpus_digest(slices),
        "slices": {s.id: {"version": s.version, "fidelity": s.fidelity,
                          "logsource": s.logsource, "events": len(s.events),
                          "digest": s.digest} for s in slices},
        "rules": {k: {"events": v["events"], "hits": v["hits"],
                      "rate_per_10k": v["rate_per_10k"],
                      "distinct_actors": v["distinct_actors"], "actors": v["actors"],
                      "slices": dict(sorted(v["slices"].items()))}
                  for k, v in sorted(scores.items())},
    }


def diff_snapshots(old, new):
    lines = []
    if old.get("corpus_digest") != new.get("corpus_digest"):
        lines.append("corpus changed:")
        for sid in sorted(set(old.get("slices", {})) | set(new.get("slices", {}))):
            a, b = old.get("slices", {}).get(sid), new.get("slices", {}).get(sid)
            if a != b:
                lines.append(f"  slice {sid}: "
                             f"{'(new)' if a is None else 'v%s %s events' % (a['version'], a['events'])}"
                             f" -> {'(removed)' if b is None else 'v%s %s events' % (b['version'], b['events'])}")
    for key in sorted(set(old.get("rules", {})) | set(new.get("rules", {}))):
        a, b = old.get("rules", {}).get(key), new.get("rules", {}).get(key)
        if a == b:
            continue
        if a is None or b is None:
            lines.append(f"  {key}: {'(new)' if a is None else 'hits %s' % a['hits']} -> "
                         f"{'(not scored)' if b is None else 'hits %s' % b['hits']}")
        else:
            lines.append(f"  {key}: hits {a['hits']} -> {b['hits']}, "
                         f"rate/10k {a['rate_per_10k']} -> {b['rate_per_10k']}, "
                         f"actors {a['distinct_actors']} -> {b['distinct_actors']}")
    return lines


def load_extra(path, logsource, label):
    """A live capture as a slice: JSONL raw events (or one JSON array)."""
    product, _, service = logsource.partition("/")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        doc = json.loads(text)
        raw = doc if isinstance(doc, list) else [doc]
    except json.JSONDecodeError:
        raw = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    raw.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    spec = {"id": label, "version": 0, "logsource": {"product": product, "service": service},
            "fidelity": "recorded"}
    return benign_corpus.Slice(spec, path, raw)


def annotate(level, message):
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level} title=benign-corpus::{message}")


def main():
    ap = argparse.ArgumentParser(description="Score every rule against the benign corpus.")
    ap.add_argument("rules", nargs="*", help="rule files (default: all)")
    ap.add_argument("--check", action="store_true", help="fail if scores.json is stale")
    ap.add_argument("--update", action="store_true", help="rewrite scores.json")
    ap.add_argument("--enforce", action="store_true",
                    help="fail when a rule in enforce mode exceeds its budget")
    ap.add_argument("--extra-slice", help="also score a live capture (JSONL), shadow only")
    ap.add_argument("--extra-logsource", default="kubernetes/audit",
                    help="product/service of --extra-slice (default kubernetes/audit)")
    ap.add_argument("--extra-label", default="live-capture", help="name for --extra-slice")
    ap.add_argument("--markdown", help="append a markdown report to this file")
    ap.add_argument("--json", help="write the full report as JSON to this file")
    ap.add_argument("--examples", type=int, default=1,
                    help="explained example hits to print per rule (default 1)")
    ap.add_argument("--reseeds", type=int, default=0, metavar="N",
                    help="also report each rule's most hits over the committed corpus and N "
                         "reseeds of every synthetic slice: the basis for a budget's max_hits")
    args = ap.parse_args()

    rules = load_rules(args.rules or None)
    slices = benign_corpus.load_corpus()
    default, budgets, exempt = load_budgets()
    unknown = sorted((set(budgets) | set(exempt)) - {r["key"] for r in load_rules()})
    if unknown:
        print(f"ERROR: budgets.json names rule(s) that do not exist: {', '.join(unknown)}")
        return 1
    no_why = sorted(k for k, why in exempt.items() if not isinstance(why, str) or not why.strip())
    if no_why:
        print("ERROR: budgets.json `unscored` entries need a why (a non-empty string): "
              + ", ".join(no_why))
        return 1
    bad_budgets = budget_problems(budgets)
    if bad_budgets:
        print("ERROR: budgets.json `rules` entries are malformed:\n  " + "\n  ".join(bad_budgets))
        return 1
    scores, examples = score(rules, slices)

    print(f"Benign corpus: {len(slices)} slice(s), "
          f"{sum(len(s.events) for s in slices)} event(s), digest "
          f"{benign_corpus.corpus_digest(slices)[:12]}")
    for s in slices:
        print(f"  {s.id:<38} v{s.version}  {s.fidelity:<9} "
              f"{s.logsource.get('product')}/{s.logsource.get('service') or s.logsource.get('category')}"
              f"  {len(s.events)} event(s)")
    print()

    rows, over_enforce, over_shadow, unscored = [], [], [], []
    for r in rules:
        sc = scores.get(r["key"])
        b = budget_for(r["key"], default, budgets)
        if sc is None:
            unscored.append(r["key"])
            continue
        over = sc["hits"] > b.get("max_hits", 0) or (
            "max_rate_per_10k" in b and sc["rate_per_10k"] > b["max_rate_per_10k"])
        status = "ok" if not over else ("OVER" if b["mode"] == "enforce" else "over")
        rows.append((r, sc, b, status))
        if over:
            (over_enforce if b["mode"] == "enforce" else over_shadow).append((r, sc, b))

    width = max((len(r["key"]) for r, *_ in rows), default=10)
    print(f"{'rule':<{width}}  {'level':<13} {'mode':<7} {'events':>7} {'hits':>5} "
          f"{'per10k':>7} {'budget':>6}  status  actors")
    for r, sc, b, status in rows:
        actors = ", ".join(f"{a} x{n}" for a, n in list(sc["actors"].items())[:3])
        more = sc["distinct_actors"] - min(3, len(sc["actors"]))
        print(f"{r['key']:<{width}}  {str(r['level']):<13} {b['mode']:<7} {sc['events']:>7} "
              f"{sc['hits']:>5} {sc['rate_per_10k']:>7} {b.get('max_hits', 0):>6}  {status:<6}  "
              f"{actors}{f' (+{more} more)' if more > 0 else ''}")
    unexempt = [k for k in unscored if k not in exempt]
    stale_exempt = sorted(k for k in exempt if k in scores)
    if unscored:
        print(f"\nNot scored (no benign slice for their logsource): {len(unscored)} rule(s)")
        for key in unscored:
            print(f"  {key}  " + (f"exempt: {exempt[key]}" if key in exempt
                                  else "NOT EXEMPT (no `unscored` entry in budgets.json)"))

    if args.reseeds:
        most = reseed_max(rules, slices, args.reseeds)
        print(f"\nMost hits over the committed corpus and {args.reseeds} reseed(s) of every "
              "synthetic slice (set max_hits from this, not from one seed's count):")
        for r, sc, b, status in rows:
            m = most.get(r["key"], 0)
            if m or sc["hits"]:
                low = "  (budget below it)" if b.get("max_hits", 0) < m else ""
                print(f"  {r['key']:<{width}}  {b['mode']:<7} hits {sc['hits']:>5}  "
                      f"most {m:>5}  budget {b.get('max_hits', 0):>5}{low}")

    if args.examples:
        for r, sc, b, status in rows:
            if not sc["hits"]:
                continue
            for s, hit in examples.get(r["key"], [])[:args.examples]:
                print(f"\n{r['key']}: example benign hit in slice {s.id} "
                      f"(actor {actor(hit[0], r['logsource'])})")
                if r["model"].is_correlation:
                    print(f"  correlation alert over {len(hit)} event(s)")
                else:
                    for line in sigma_explain.explain_hit(r["model"], hit[0]):
                        print("  " + line)

    extra_rows = []
    if args.extra_slice:
        extra = load_extra(args.extra_slice, args.extra_logsource, args.extra_label)
        xscores, xexamples = score(rules, [extra])
        print(f"\nLive capture {args.extra_label} ({args.extra_logsource}, "
              f"{len(extra.events)} event(s)) - shadow only:")
        for key, sc in sorted(xscores.items(), key=lambda kv: (-kv[1]["hits"], kv[0])):
            actors = ", ".join(f"{a} x{n}" for a, n in list(sc["actors"].items())[:3])
            print(f"  {key:<{width}} hits {sc['hits']:>5}  per10k {sc['rate_per_10k']:>8}  {actors}")
            extra_rows.append((key, sc))
            if sc["hits"]:
                annotate("warning", f"{key} fired {sc['hits']} time(s) on the live benign "
                         f"capture {args.extra_label} (shadow)")

    for r, sc, b in over_shadow:
        annotate("warning", f"{r['key']} fired {sc['hits']} time(s) on the benign corpus "
                 f"(budget {b.get('max_hits', 0)}, shadow mode)")
    for r, sc, b in over_enforce:
        annotate("error", f"{r['key']} fired {sc['hits']} time(s) on the benign corpus "
                 f"(budget {b.get('max_hits', 0)}, enforce mode)")

    snap = snapshot(scores, slices) if not args.rules else None
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"snapshot": snap or snapshot(scores, slices),
                       "unscored": unscored,
                       "unscored_not_exempt": unexempt,
                       "over_budget": {"enforce": [r["key"] for r, *_ in over_enforce],
                                       "shadow": [r["key"] for r, *_ in over_shadow]},
                       "extra": {k: v for k, v in extra_rows}}, fh, indent=2, sort_keys=True)
    if args.markdown:
        with open(args.markdown, "a", encoding="utf-8") as fh:
            fh.write("## Benign corpus false-positive scores\n\n")
            fh.write(f"{len(slices)} slice(s), {sum(len(s.events) for s in slices)} event(s). "
                     "Shadow-mode overruns warn; enforce-mode overruns fail.\n\n")
            fh.write("| rule | level | mode | events | hits | per 10k | budget | status | top actors |\n")
            fh.write("|---|---|---|---:|---:|---:|---:|---|---|\n")
            for r, sc, b, status in rows:
                actors = "; ".join(f"`{a}` x{n}" for a, n in list(sc["actors"].items())[:3])
                fh.write(f"| `{r['key']}` | {r['level']} | {b['mode']} | {sc['events']} | "
                         f"{sc['hits']} | {sc['rate_per_10k']} | {b.get('max_hits', 0)} | "
                         f"{status} | {actors} |\n")
            if unscored:
                fh.write(f"\nNot scored (no slice for their logsource): "
                         f"{', '.join(f'`{k}`' + ('' if k in exempt else ' (NOT EXEMPT)') for k in unscored)}\n")
            if extra_rows:
                fh.write(f"\n### Live capture `{args.extra_label}` (shadow)\n\n"
                         "| rule | hits | per 10k | top actors |\n|---|---:|---:|---|\n")
                for key, sc in extra_rows:
                    actors = "; ".join(f"`{a}` x{n}" for a, n in list(sc["actors"].items())[:3])
                    fh.write(f"| `{key}` | {sc['hits']} | {sc['rate_per_10k']} | {actors} |\n")
            fh.write("\n")

    status = 0
    if args.update:
        if args.rules:
            print("ERROR: --update scores every rule; do not pass rule paths.")
            return 1
        with open(SNAPSHOT, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"\nWrote {os.path.relpath(SNAPSHOT, REPO)}.")
    elif args.check:
        if args.rules:
            print("ERROR: --check compares every rule; do not pass rule paths.")
            return 1
        try:
            with open(SNAPSHOT, encoding="utf-8") as fh:
                old = json.load(fh)
        except (OSError, json.JSONDecodeError):
            old = {}
        changes = diff_snapshots(old, snap)
        if changes:
            print("\nSTALE: detections/benign/scores.json does not match the current rules "
                  "and corpus:")
            print("\n".join(changes))
            print("Run `python3 detections/score_benign.py --update` and commit the result, so "
                  "the false-positive change is visible in review.")
            status = 1
        else:
            print("\nscores.json is current.")
    if (args.check or args.enforce) and unexempt:
        print(f"\nFAILED: {len(unexempt)} rule(s) are not scored (no benign slice reads their "
              "logsource) and budgets.json does not exempt them: " + ", ".join(unexempt))
        print("Leaving the false-positive layer is a human decision: add a slice for the "
              "logsource, or list the rule under `unscored` in budgets.json with the reason "
              "(a protected path that needs a human approval).")
        status = 1
    if (args.check or args.enforce) and stale_exempt:
        print("\nFAILED: budgets.json `unscored` exempts rule(s) that are scored now; remove "
              "the stale exemption: " + ", ".join(stale_exempt))
        status = 1
    if args.enforce and over_enforce:
        print(f"\nFAILED: {len(over_enforce)} enforce-mode rule(s) over their benign budget: "
              + ", ".join(r["key"] for r, *_ in over_enforce))
        status = 1
    elif over_shadow or over_enforce:
        print(f"\n{len(over_shadow)} shadow-mode rule(s) over budget (warning only)"
              + (f"; {len(over_enforce)} enforce-mode (not enforced without --enforce)"
                 if over_enforce else "") + ".")
    return status


if __name__ == "__main__":
    sys.exit(main())
