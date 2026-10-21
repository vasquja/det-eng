#!/usr/bin/env python3
"""
Write the procedure-level coverage report: research/COVERAGE.md and the chart that
the top-level README shows (docs/coverage/coverage-{light,dark}.svg).

ATT&CK marks a technique covered when one rule maps to it. This report counts the
execution paths (procedures) of each TRR instead, and gives each one status:

  Proven               the procedure's own emulation is built, and a rule that the
                       TRR's Detections table says covers it proves it in CI,
                       passes check_sufficiency.py with a verified negative, and no
                       open entry in detections/RULE_DEFECTS.md names it. For a TRR
                       whose validator exposes a per-procedure gate map (PROCEDURES),
                       "proves it in CI" means the emulation cell is exactly 'built'
                       and the rule gates this one procedure with a gate of its own;
                       for every other TRR, the rule runs in a validator
  Proven, open defect  as Proven, but every proving rule has an open defect
  Claimed              a rule maps to the procedure, but the procedure is not
                       emulated, or (gated TRR) no gate proves this one procedure,
                       or the rule is in no validator
  Sensor only          only a sensor strategy with no Sigma rule covers it
  Gap                  no strategy in the TRR's Detections table covers it

Severity and grader strategies do not count: they rank what a chokepoint rule
already raised.

    python3 research/tools/coverage_report.py           # rewrite the outputs
    python3 research/tools/coverage_report.py --check   # fail if they are stale

Needs pySigma (it runs detections/check_sufficiency.py); offline otherwise.
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REPORT = REPO / "research" / "COVERAGE.md"
CHARTS = {theme: REPO / "docs" / "coverage" / f"coverage-{theme}.svg" for theme in ("light", "dark")}

STATUSES = ["Proven", "Proven, open defect", "Claimed", "Sensor only", "Gap"]
MEANING = {
    "Proven": "emulated, validated in CI, no open defect",
    "Proven, open defect": "validated in CI; a known miss or noise is tracked",
    "Claimed": "a rule maps to it, but this procedure is not emulated, has no per-procedure gate "
               "yet, or the rule is in no validator",
    "Sensor only": "needs a sensor that no Sigma rule reads",
    "Gap": "researched, no detection",
}
PLATFORM_CODE = {"Linux": "LIN", "Kubernetes": "K8S", "AWS": "AWS", "Azure": "AZR", "GCP": "GCP"}


def sufficiency():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "suff.json"
        subprocess.run([sys.executable, str(REPO / "detections" / "check_sufficiency.py"), "--json", str(out)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if not out.exists():
            sys.exit("coverage_report: check_sufficiency.py wrote no report (is pySigma installed?)")
        return {r["rule"]: r for r in json.loads(out.read_text())["rules"]}


# Validators that expose a per-procedure gate map: each PROCEDURES entry maps
# (TRR id, procedure letter) to the rule files whose MANIFEST entry gates that one
# procedure with a gate of its own (C1-1, C1-2). A TRR whose validator exposes such
# a map is "gated": a procedure of it is Proven only when it has a gate here. A
# listed validator without the attribute (the API-server validator until item A
# lands) is skipped, and its TRRs fall back to the rule-level test (the rule runs in
# some validator), stated in the report; a listed validator that fails to import
# stops the report. The Linux and cloud validators are not listed: they have no
# per-procedure gates today, so their TRRs keep the rule-level test.
GATING_VALIDATORS = ("validate_k8s_detections", "validate_staticpod_detections",
                     "validate_apiserver_detections")


def procedure_gates():
    """({(TRR id, letter): {rule rel path, ...}}, {gated TRR id, ...})."""
    import importlib
    det = str(REPO / "detections")
    if det not in sys.path:
        sys.path.insert(0, det)
    gates, gated = {}, set()
    for name in GATING_VALIDATORS:
        # Only "imported, but no PROCEDURES map" is the documented fallback. A
        # validator that fails to import must stop the report: a silent fallback
        # to the looser rule-level test would raise statuses with no message.
        try:
            module = importlib.import_module(name)
        except Exception as e:  # noqa: BLE001
            sys.exit(f"coverage_report: detections/{name}.py failed to import "
                     f"({type(e).__name__}: {e}); its per-procedure gate map cannot be read")
        pm = getattr(module, "PROCEDURES", None)
        if not isinstance(pm, dict):
            continue
        for key, paths in pm.items():
            trr, _letter = key
            gated.add(trr)
            gates.setdefault(key, set()).update(paths)
    return gates, gated


def open_defects(rule_stems):
    """{defect ID: set of rule stems} from the Summary table of RULE_DEFECTS.md."""
    text = (REPO / "detections" / "RULE_DEFECTS.md").read_text()
    summary = text.split("## Summary", 1)[1].split("\n## ", 1)[0]
    sections = re.split(r"\n### ", text)
    out = {}
    for line in summary.splitlines():
        m = re.match(r"\|\s*\[(\w+)\]", line)
        if not m:
            continue
        did = m.group(1)
        body = next((s for s in sections if s.startswith(did + ".")), "")
        rules = re.search(r"^- \*\*Rules?\*\*:(.*?)(?=^- \*\*)", body, re.M | re.S)
        named = (rules.group(1) if rules else "") + line.split("|")[2]
        out[did] = set(re.findall(r"(\w+)(?:\.yml|`|\])", named)) & rule_stems
    return out


def letters(covers):
    found = set()
    for a, b in re.findall(r"\b([A-H])\s*[–-]\s*([A-H])\b", covers):
        found |= {chr(c) for c in range(ord(a), ord(b) + 1)}
    return sorted(found | set(re.findall(r"\b([A-H])\b", covers)))


def section(readme, heading):
    parts = readme.split(f"## {heading}", 1)
    return parts[1].split("\n## ", 1)[0] if len(parts) == 2 else ""


def collect():
    suff = sufficiency()
    rule_files = sorted(p.relative_to(REPO / "detections" / "sigma").as_posix()
                        for p in (REPO / "detections" / "sigma").glob("*/*.yml"))
    defects = open_defects({Path(r).stem for r in rule_files})
    validators = "".join(p.read_text() for p in (REPO / "detections").glob("validate_*.py"))
    gates, gated_trrs = procedure_gates()

    def suff_ok(rel):
        s = suff.get(rel, {})
        negatives = [n for n in s.get("negatives", []) if n["kind"] in ("near-miss", "filtered")]
        return s.get("status") in ("PASS", "WARN") and bool(negatives)

    def sound(rel):
        # Rule-level test (ungated TRRs): the rule runs in some validator and has a
        # verified negative. The validators prove it against the TRR's emulation, not
        # per procedure.
        return Path(rel).name in validators and suff_ok(rel)

    def rule_defects(rel):
        return sorted(d for d, stems in defects.items() if Path(rel).stem in stems)

    index = json.loads((REPO / "research" / "index.json").read_text())["trrs"]
    trrs, mapped = [], set()
    for t in sorted(index, key=lambda t: t["id"]):
        readme = (REPO / "research" / t["path"]).read_text()
        emulation = {m.group(1): m.group(2).strip("* ").lower() for m in re.finditer(
            r"^\|\s*TRR\d+\.\w+\.([A-H])\s*\|.*\|\s*([^|]+?)\s*\|\s*$", section(readme, "Available Emulation Tests"), re.M)}
        strategies = []
        for line in section(readme, "Detections").splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) < 4 or not re.match(r"\d", cells[0]):
                continue
            rels = list(dict.fromkeys(re.findall(r"detections/sigma/([^)`\s]+\.yml)", cells[2])))
            mapped.update(rels)
            strategies.append({"covers": letters(cells[1]), "rules": rels,
                               "grader": bool(re.search(r"sever|grad", cells[0] + cells[1], re.I))})
        procs = []
        gated = t["id"] in gated_trrs
        for letter, name in t["procedures"].items():
            hits = [s for s in strategies if letter in s["covers"]]
            rules = sorted({r for s in hits if not s["grader"] for r in s["rules"]})
            cell = emulation.get(letter, "")
            if gated:
                # Proven needs the emulation cell to be exactly 'built' AND a
                # per-procedure CI gate: a covering rule that gates THIS procedure
                # with a gate of its own, and has a verified negative.
                emulated = cell == "built"
                gate_rules = gates.get((t["id"], letter), set())
                proving = [r for r in rules if r in gate_rules and suff_ok(r)]
            else:
                emulated = cell.startswith("built")
                proving = [r for r in rules if sound(r)]
            if emulated and any(not rule_defects(r) for r in proving):
                status = "Proven"
            elif emulated and proving:
                status = "Proven, open defect"
            elif rules:
                status = "Claimed"
            elif hits:
                status = "Sensor only"
            else:
                status = "Gap"
            procs.append({"id": f"{t['id']}.{PLATFORM_CODE[t['platforms'][0]]}.{letter}", "letter": letter,
                          "name": name, "status": status, "emulation": emulation.get(letter, "not listed"),
                          "rules": rules, "defects": sorted({d for r in proving for d in rule_defects(r)})})
        trrs.append({"id": t["id"], "name": t["name"], "platform": t["platforms"][0], "attack": t["external_ids"],
                     "path": t["path"], "procedures": procs})
    return trrs, [r for r in rule_files if r not in mapped], len(rule_files)


def esc(text):
    return str(text).replace("|", "\\|")


def pct(n, d):
    return f"{round(100 * n / d)}%" if d else "–"


def markdown(trrs, unmapped, nrules):
    procs = [p for t in trrs for p in t["procedures"]]
    count = Counter(p["status"] for p in procs)
    techniques = {a for t in trrs for a in t["attack"]}
    with_rule = {a for t in trrs if any(p["rules"] for p in t["procedures"]) for a in t["attack"]}
    out = [
        "# Detection coverage by procedure",
        "",
        "<!-- Generated by research/tools/coverage_report.py. Do not edit by hand. -->",
        "",
        f"Mapped to ATT&CK, {len(with_rule)} of {len(techniques)} techniques have a rule "
        f"({pct(len(with_rule), len(techniques))}). Counted by execution path, CI proves "
        f"{count['Proven']} of {len(procs)} procedures ({pct(count['Proven'], len(procs))}), and "
        f"{count['Gap']} researched procedures have no detection. A technique is the wrong unit: one rule can "
        "turn a technique green while it sees only one of the ways to perform it.",
        "",
        "| Status | Procedures | Share | Meaning |",
        "|--------|-----------:|------:|---------|",
    ]
    out += [f"| {s} | {count[s]} | {pct(count[s], len(procs))} | {MEANING[s]} |" for s in STATUSES]
    out += ["", "## By platform", "", "| Platform | Procedures | " + " | ".join(STATUSES) + " |",
            "|----------|-----------:|" + "------:|" * len(STATUSES)]
    for plat in PLATFORM_CODE:
        ps = [p for t in trrs if t["platform"] == plat for p in t["procedures"]]
        if ps:
            c = Counter(p["status"] for p in ps)
            out.append(f"| {plat} | {len(ps)} | " + " | ".join(str(c[s]) for s in STATUSES) + " |")
    out += ["", "## By TRR", "",
            "Each procedure letter is followed by its status: **P** proven, **D** proven with an open defect, "
            "**C** claimed, **S** sensor only, **G** gap.", "",
            "| TRR | Technique | ATT&CK | Platform | Proven | Procedures |",
            "|-----|-----------|--------|----------|-------:|------------|"]
    code = {"Proven": "P", "Proven, open defect": "D", "Claimed": "C", "Sensor only": "S", "Gap": "G"}
    for t in trrs:
        c = Counter(p["status"] for p in t["procedures"])
        marks = " ".join(f"{p['letter']}:{'**' + code[p['status']] + '**' if p['status'] != 'Proven' else 'P'}"
                         for p in t["procedures"])
        out.append(f"| [{t['id']}]({t['path']}) | {esc(t['name'])} | {', '.join(t['attack'])} | {t['platform']} | "
                   f"{c['Proven']}/{len(t['procedures'])} | {marks} |")
    out += ["", "## Procedures not yet proven", "",
            "| Procedure | Execution path | Status | Emulation | Covering rules |",
            "|-----------|----------------|--------|-----------|----------------|"]
    for s in STATUSES[:0:-1]:
        for p in (p for t in trrs for p in t["procedures"] if p["status"] == s):
            rules = ", ".join(f"`{Path(r).stem}`" for r in p["rules"]) or "–"
            if p["defects"]:
                rules += " (" + ", ".join(p["defects"]) + ")"
            out.append(f"| `{p['id']}` | {esc(p['name'])} | {s} | {esc(p['emulation'])} | {rules} |")
    out += [
        "", "## How the statuses are set", "",
        "- **Proven**: the procedure's own emulation is built, a rule that the TRR's Detections table "
        "says covers it passes `check_sufficiency.py` with a verified near-miss or filtered negative, "
        "no open entry in [`RULE_DEFECTS.md`](../detections/RULE_DEFECTS.md) names it (in the entry's "
        "Summary row or its Rules bullet), and the rule proves this procedure in CI. For a TRR whose "
        "validator exposes a per-procedure gate map (the Kubernetes TRR9002 and TRR9003 validators "
        "today, each API-server TRR once that validator exposes the map), *proves this procedure* "
        "means the emulation cell is exactly `built` (not `built (read-only)` or a cross-reference) "
        "and a covering rule gates this one procedure with a gate of its own. For every other TRR it "
        "keeps the rule-level test: the emulation cell starts with `built` and the rule runs in a "
        "validator, which proves the rule against the TRR's emulation but not against each procedure "
        "separately.",
        "- **Proven, open defect**: as Proven, but every proving rule has an open defect.",
        "- **Claimed**: a rule maps to the procedure, but the procedure's emulation is in the backlog or "
        "documented only, or (for a gated TRR) no gate proves this one procedure yet, or the rule is in "
        "no validator. The rule can be proven on a sibling procedure.",
        "- **Sensor only**: only a sensor strategy (node runtime, file integrity) with no Sigma rule covers it.",
        "- **Gap**: no strategy in the TRR's Detections table covers the procedure.",
        "",
        "Limits of this report:",
        "",
        "- Severity and grader rules do not count as coverage. They rank hits that a chokepoint rule already raised.",
        "- Per-procedure proof is available only where the validator exposes a gate map. The Kubernetes "
        "TRR9002 and TRR9003 validators do; the API-server validator gains it with plan item C1-1, and "
        "the Linux (`validate_detections.py`) and cloud (`validate_cloud_detections.py`) validators have "
        "no per-procedure gates today, so their TRRs keep the rule-level test above (a follow-up can add "
        "maps there). A rule-level Proven means the rule is proven against the TRR's emulation as a "
        "whole, not against the single procedure.",
        "- An open audit-policy gap that blinds every rule on a resource names no rule, so it does not mark "
        "procedures: [`RULE_DEFECTS.md` K23](../detections/RULE_DEFECTS.md#k23-apply-patches-with-a-yaml-body-no-audit-record-at-request-level-or-higher) "
        "(an apply patch with a YAML body is not logged at Request level or higher, so no rule sees that write, "
        "the chokepoints included) is such a gap, and a procedure that sends such a patch can still show Proven.",
        "- The procedure-to-rule map comes from each TRR's Detections table, as written. For a gated "
        "TRR the validator then confirms the covering rule fired on that one procedure's own records "
        "(a per-procedure gate bound to the procedure's emulation-ledger window); for every other TRR "
        "the validator proves the rule against the TRR's emulation as a whole, not each procedure.",
        f"- {len(unmapped)} of {nrules} rules map to no TRR procedure and are not counted: "
        + ", ".join(f"`{r}`" for r in unmapped) + ".",
        "",
        "Regenerate with `python3 research/tools/coverage_report.py`. CI fails when this file or the chart "
        "is stale (`--check`).",
        "",
    ]
    return "\n".join(out)


THEMES = {
    "light": {"bg": "#ffffff", "fg": "#1f2328", "muted": "#59636e", "track": "#eef1f4",
              "Proven": "#1a7f37", "Proven, open defect": "#bf8700", "Claimed": "#8c959f",
              "Sensor only": "#0969da", "Gap": "#cf222e"},
    "dark": {"bg": "#0d1117", "fg": "#e6edf3", "muted": "#9198a1", "track": "#21262d",
             "Proven": "#3fb950", "Proven, open defect": "#d29922", "Claimed": "#6e7681",
             "Sensor only": "#4493f8", "Gap": "#f85149"},
}


def svg(trrs, theme):
    c = THEMES[theme]
    procs = [p for t in trrs for p in t["procedures"]]
    techniques = {a for t in trrs for a in t["attack"]}
    with_rule = {a for t in trrs if any(p["rules"] for p in t["procedures"]) for a in t["attack"]}
    proven = sum(p["status"] == "Proven" for p in procs)
    W, L, R = 820, 250, 130
    x0, x1 = L, W - R
    font = "font-family=\"-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif\""
    el = [f'<rect width="{W}" height="__H__" rx="8" fill="{c["bg"]}"/>']

    def text(x, y, s, fill=c["muted"], anchor="start", size=13, weight=400):
        el.append(f'<text x="{x}" y="{y}" fill="{fill}" font-size="{size}" font-weight="{weight}" '
                  f'text-anchor="{anchor}">{s}</text>')

    def bar(y, parts, total, h=18):
        el.append(f'<rect x="{x0}" y="{y}" width="{x1 - x0}" height="{h}" rx="4" fill="{c["track"]}"/>')
        x = x0
        for color, n in parts:
            w = (x1 - x0) * n / total
            if w > 0:
                el.append(f'<rect x="{x:.1f}" y="{y}" width="{max(w - 1.5, 1):.1f}" height="{h}" fill="{color}"/>')
            x += w

    y = 28
    text(20, y, "Two ways to count the same repository", c["fg"], size=15, weight=600)
    y += 26
    for label, n, d, color in (("ATT&amp;CK techniques with a rule", len(with_rule), len(techniques), c["Claimed"]),
                               ("Procedures proven in CI", proven, len(procs), c["Proven"])):
        text(20, y + 14, label, c["fg"])
        bar(y, [(color, n)], d)
        text(W - 20, y + 14, f"{n}/{d} · {pct(n, d)}", c["fg"], "end", weight=600)
        y += 30
    y += 16
    text(20, y, "Procedures by platform and status", c["fg"], size=15, weight=600)
    y += 14
    lx = 20
    for s in STATUSES:
        el.append(f'<rect x="{lx}" y="{y}" width="10" height="10" rx="2" fill="{c[s]}"/>')
        text(lx + 15, y + 9.5, s, size=12)
        lx += 15 + 7.2 * len(s) + 22
    y += 26
    for plat in PLATFORM_CODE:
        ps = [p for t in trrs if t["platform"] == plat for p in t["procedures"]]
        if not ps:
            continue
        cnt = Counter(p["status"] for p in ps)
        text(20, y + 14, plat, c["fg"])
        bar(y, [(c[s], cnt[s]) for s in STATUSES], len(ps))
        text(W - 20, y + 14, f"{cnt['Proven']}/{len(ps)} proven", anchor="end")
        y += 28
    H = y + 12
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" {font} '
            f'role="img" aria-label="Procedure coverage: {proven} of {len(procs)} procedures proven in CI">')
    return "\n".join([head] + [e.replace("__H__", str(H)) for e in el] + ["</svg>", ""])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="fail if the committed outputs are not current")
    args = ap.parse_args()
    trrs, unmapped, nrules = collect()
    outputs = {REPORT: markdown(trrs, unmapped, nrules), **{p: svg(trrs, th) for th, p in CHARTS.items()}}
    stale = [p for p, body in outputs.items() if not p.exists() or p.read_text() != body]
    if args.check:
        for p in stale:
            print(f"STALE: {p.relative_to(REPO)} is not current; run python3 research/tools/coverage_report.py")
        if not stale:
            print("Coverage report is current.")
        return 1 if stale else 0
    for p, body in outputs.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    procs = [p for t in trrs for p in t["procedures"]]
    print(f"{sum(p['status'] == 'Proven' for p in procs)}/{len(procs)} procedures proven; "
          f"wrote {', '.join(str(p.relative_to(REPO)) for p in outputs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
