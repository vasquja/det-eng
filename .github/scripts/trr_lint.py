#!/usr/bin/env python3
"""
TRR linter — structural/semantic validation of Technique Research Reports.

Yes, this is linting: it checks that each TRR under research/trr*/<platform>/
follows the required format and that its Detection Data Models (DDMs) are
present and well-formed. It is offline and deterministic, so it is a reliable
CI gate.

For every research/trr*/<platform>/README.md it checks:

  1. Required sections are present and in order:
     Metadata, Technique Overview, Technical Background, Procedures,
     Available Emulation Tests, References.
     (Scope Statement, Detection Strategy and Detections are allowed extras.)
  2. The Metadata table carries ID, External IDs, Tactics, Platforms,
     Contributors, and the ID matches the folder (trr9001/lin -> TRR9001).
  3. Procedure IDs use the TRRID.PLATFORM.LETTER form and agree with the
     folder's ID and platform.
  4. DDMs are PRESENT: every procedure has a "Detection Data Model" subsection
     that contains a ```mermaid diagram.
  5. DDMs WORK (structurally): each mermaid block has balanced quotes,
     brackets and pipes, at least one edge, and no dotted link that carries
     both inline text and a pipe label (`-. text .->|label|`) — the exact
     construct that silently fails to render on GitHub.
  6. Every referenced ddms/*.json exists and parses, and every *.json in the
     folder's ddms/ parses.
  7. research/index.json has a matching entry (id, platform, procedure keys).

NOTE: check 5 is a STRUCTURAL check, not a full render. It catches the class
of error that broke rendering in practice; a full mermaid-cli render could be
added later as a heavier, optional step.

Exit 0 if every TRR passes; exit 1 with a report otherwise.
"""

import glob
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RESEARCH = os.path.join(REPO, "research")

REQUIRED_SECTIONS = [
    "## Metadata",
    "## Technique Overview",
    "## Technical Background",
    "## Procedures",
    "## Available Emulation Tests",
    "## References",
]
META_ROWS = ["ID", "External IDs", "Tactics", "Platforms", "Contributors"]
PROC_ID_RE = re.compile(r"\bTRR\d{4}\.[A-Z]{2,4}\.[A-Z]\b")
FENCE_RE = re.compile(r"^\s*```(\w*)")


def mermaid_blocks(lines):
    """Yield (start_lineno, [body lines]) for each ```mermaid fence."""
    i, n = 0, len(lines)
    while i < n:
        m = FENCE_RE.match(lines[i])
        if m and m.group(1) == "mermaid":
            start = i + 1
            body = []
            i += 1
            while i < n and not FENCE_RE.match(lines[i]):
                body.append(lines[i])
                i += 1
            yield start, body
        i += 1


def check_mermaid(body):
    """Return a list of structural problems in one mermaid block."""
    problems = []
    edges = 0
    for off, line in enumerate(body, 1):
        s = line.strip()
        if not s:
            continue
        if line.count('"') % 2:
            problems.append(f"line {off}: unbalanced quotes")
        if line.count("[") != line.count("]"):
            problems.append(f"line {off}: unbalanced [ ]")
        if line.count("(") != line.count(")"):
            problems.append(f"line {off}: unbalanced ( )")
        if line.count("|") % 2:
            problems.append(f"line {off}: unbalanced | | label")
        # A link with MID-TEXT (`-. text .->` or `== text ==>`) must not also
        # carry a `|label|` — Mermaid rejects both on one edge and the diagram
        # silently fails to render. (The valid dotted form `-.->|label|` has no
        # space inside the arrow and is not matched here.)
        if (re.search(r"-\.\s.+?\s\.-?->", line)
                or re.search(r"==\s.+?\s==>", line)) and "|" in line:
            problems.append(f"line {off}: link has inline mid-text AND a pipe "
                            f"label (e.g. `-. text .->|...|`) — will not render")
        if any(a in line for a in ("-->", "-.->", "==>", "---", "===")):
            edges += 1
    if edges == 0:
        problems.append("no edges found (not a graph?)")
    return problems


def section_body(text, heading, all_headings):
    """Return the text of one '## heading' section up to the next '## '."""
    start = text.find(heading)
    if start < 0:
        return None
    rest = text[start + len(heading):]
    nxt = re.search(r"\n## ", rest)
    return rest[:nxt.start()] if nxt else rest


def lint_report(path, index):
    errs = []
    rel = os.path.relpath(path, REPO)
    folder = os.path.dirname(path)                       # .../trrNNNN/<plat>
    plat = os.path.basename(folder)
    trr_dir = os.path.basename(os.path.dirname(folder))  # trrNNNN
    exp_id = trr_dir.upper()
    exp_plat = plat.upper()

    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    lines = text.splitlines()

    # 1. required sections present and in order
    positions = {}
    for sec in REQUIRED_SECTIONS:
        idx = text.find(sec)
        if idx < 0:
            errs.append(f"missing required section: {sec}")
        else:
            positions[sec] = idx
    present = [s for s in REQUIRED_SECTIONS if s in positions]
    if [positions[s] for s in present] != sorted(positions[s] for s in present):
        errs.append("required sections are out of order")

    # 2. metadata rows + ID match
    meta = section_body(text, "## Metadata", positions) or ""
    for row in META_ROWS:
        if not re.search(rf"\|\s*{re.escape(row)}\s*\|", meta):
            errs.append(f"Metadata table missing row: {row}")
    m = re.search(r"\|\s*ID\s*\|\s*([A-Za-z0-9]+)\s*\|", meta)
    if m and m.group(1) != exp_id:
        errs.append(f"Metadata ID '{m.group(1)}' != folder-derived '{exp_id}'")

    # 3. procedure IDs well-formed and consistent with folder
    proc_ids = set(PROC_ID_RE.findall(text))
    if not proc_ids:
        errs.append("no procedure IDs (TRRID.PLATFORM.LETTER) found")
    letters = set()
    for pid in sorted(proc_ids):
        pfx, pl, letter = pid.split(".")
        letters.add(letter)
        if pfx != exp_id:
            errs.append(f"procedure {pid}: prefix != {exp_id}")
        if pl != exp_plat:
            errs.append(f"procedure {pid}: platform != {exp_plat}")

    # 4 + 5. each procedure has a DDM subsection with a valid mermaid block
    #        (split doc into '### ' subsections and inspect each procedure's)
    sub = re.split(r"\n(?=### )", text)
    proc_sections = {}
    for chunk in sub:
        head = chunk.splitlines()[0] if chunk.splitlines() else ""
        if head.startswith("### "):
            for pid in PROC_ID_RE.findall(head):
                proc_sections[pid.split(".")[-1]] = chunk
    for letter in sorted(letters):
        chunk = proc_sections.get(letter)
        if chunk is None:
            errs.append(f"procedure {exp_id}.{exp_plat}.{letter}: "
                        f"no '### ' subsection heading carrying its ID")
            continue
        if "Detection Data Model" not in chunk:
            errs.append(f"procedure .{letter}: no 'Detection Data Model' heading")
        blocks = list(mermaid_blocks(chunk.splitlines()))
        if not blocks:
            errs.append(f"procedure .{letter}: DDM has no ```mermaid diagram")

    # 5. validate ALL mermaid blocks in the file structurally
    for start, body in mermaid_blocks(lines):
        for p in check_mermaid(body):
            errs.append(f"mermaid block at line {start}: {p}")

    # 6. referenced ddms/*.json and all json in ddms/ parse
    for ref in re.findall(r"\]\(\s*(ddms/[^)\s]+\.json)\s*\)", text):
        jp = os.path.join(folder, ref)
        if not os.path.exists(jp):
            errs.append(f"referenced DDM json missing: {ref}")
    for jp in glob.glob(os.path.join(folder, "ddms", "*.json")):
        try:
            json.load(open(jp, encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            errs.append(f"DDM json does not parse: {os.path.basename(jp)}: {e}")

    # 7. index.json consistency
    if index is not None:
        entry = next((e for e in index if e.get("id") == exp_id), None)
        if entry is None:
            errs.append(f"research/index.json has no entry with id {exp_id}")
        else:
            idx_letters = set((entry.get("procedures") or {}).keys())
            if idx_letters != letters:
                errs.append(f"index.json procedures {sorted(idx_letters)} "
                            f"!= report procedures {sorted(letters)}")
    return rel, errs


def main():
    reports = sorted(glob.glob(os.path.join(RESEARCH, "trr*", "*", "README.md")))
    if not reports:
        print("No TRRs found under research/trr*/<platform>/ — nothing to lint.")
        return 0

    index = None
    idx_path = os.path.join(RESEARCH, "index.json")
    if os.path.exists(idx_path):
        try:
            doc = json.load(open(idx_path, encoding="utf-8"))
            index = doc.get("trrs", doc) if isinstance(doc, dict) else doc
        except Exception as e:  # noqa: BLE001
            print(f"WARNING: research/index.json does not parse: {e}")

    total_errs = 0
    for path in reports:
        rel, errs = lint_report(path, index)
        if errs:
            total_errs += len(errs)
            print(f"\nFAIL  {rel}  ({len(errs)} issue(s))")
            for e in errs:
                print(f"    - {e}")
        else:
            print(f"OK    {rel}")

    print()
    if total_errs:
        print(f"TRR lint failed: {total_errs} issue(s) across "
              f"{len(reports)} report(s).")
        return 1
    print(f"TRR lint passed: {len(reports)} report(s) conform.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
