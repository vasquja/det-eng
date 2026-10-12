#!/usr/bin/env python3
"""
Print the upstream-contribution readiness table from research/index.json.

For each TRR it lists the platform, ATT&CK IDs, the Sigma rule files that carry
its detections, and whether an atomics/<ATT&CK> directory exists -- so the table
in UPSTREAM.md can be regenerated instead of hand-maintained:

    python3 research/tools/upstream_report.py

Pure stdlib, offline. The authoritative destinations and submission steps are in
UPSTREAM.md; this only reports what exists and where it lives locally.
"""
import glob
import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    doc = json.load(open(os.path.join(REPO, "research", "index.json"), encoding="utf-8"))
    print(f"{'TRR':8} {'Platform':11} {'ATT&CK':16} {'Sigma rule files':40} atomics")
    print("-" * 95)
    for e in doc["trrs"]:
        eids = e["external_ids"]
        rules = []
        atoms = []
        for eid in eids:
            rules += [os.path.basename(p)
                      for p in sorted(glob.glob(os.path.join(REPO, "detections", "sigma", eid, "*.yml")))]
            if os.path.isdir(os.path.join(REPO, "atomics", eid)):
                atoms.append(eid)
        rules = sorted(set(rules))
        rule_str = (rules[0] + (f" (+{len(rules) - 1})" if len(rules) > 1 else "")) if rules else "-"
        print(f"{e['id']:8} {e['platforms'][0]:11} {','.join(eids):16} {rule_str:40} {','.join(sorted(set(atoms)))}")
    print("-" * 95)
    nrules = len(glob.glob(os.path.join(REPO, "detections", "sigma", "*", "*.yml")))
    print(f"{len(doc['trrs'])} TRRs | {nrules} Sigma rule files | "
          f"{len(glob.glob(os.path.join(REPO, 'atomics', '*', '')))} atomic technique dirs")


if __name__ == "__main__":
    main()
