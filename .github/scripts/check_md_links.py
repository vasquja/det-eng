#!/usr/bin/env python3
"""
Offline Markdown link checker.

Scans every *.md file in the repo and verifies that each RELATIVE link target
(a file or directory the link points at) exists on disk. It is deliberately
offline and deterministic — no network — so it is a reliable CI gate:

  * Relative links  -> the target path must exist (file or directory).
  * http / https / mailto / tel links -> skipped (not network-checked here).
  * Pure "#anchor" links -> skipped (anchor slugs are renderer-specific).
  * "path#anchor" / "path?query" links -> only the path part is checked.

Fenced code blocks (``` ... ```) are stripped before scanning so link-like
text inside code samples does not cause false positives. Files under any
"templates/" directory are skipped: a template legitimately contains
placeholder links such as (../../../atomics/T####/).

Exit 0 if every relative link resolves; exit 1 and print a report otherwise.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

LINK_RE = re.compile(r"\]\(\s*([^)]+?)\s*\)")      # [text](target) and ![alt](target)
FENCE_RE = re.compile(r"^\s*```")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "tel:", "#")


def strip_fences(text):
    out, in_fence = [], False
    for line in text.splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            out.append("")           # keep line count stable
            continue
        out.append("" if in_fence else line)
    return "\n".join(out)


def targets_in(text):
    for m in LINK_RE.finditer(strip_fences(text)):
        raw = m.group(1).strip()
        # drop an optional link title:  (path "Title")
        url = raw.split()[0] if raw else raw
        # strip surrounding angle brackets: (<path>)
        if url.startswith("<") and url.endswith(">"):
            url = url[1:-1]
        yield raw, url


def md_files():
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in (".git", "templates")]
        for f in files:
            if f.endswith(".md"):
                yield os.path.join(root, f)


def main():
    broken = []
    checked = 0
    for path in sorted(md_files()):
        base = os.path.dirname(path)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for raw, url in targets_in(text):
            if not url or url.startswith(SKIP_PREFIXES):
                continue
            target = url.split("#", 1)[0].split("?", 1)[0]
            if not target:
                continue
            checked += 1
            resolved = os.path.normpath(os.path.join(base, target))
            if not os.path.exists(resolved):
                broken.append((os.path.relpath(path, REPO), raw,
                               os.path.relpath(resolved, REPO)))

    rel = lambda p: os.path.relpath(p, REPO)  # noqa: E731
    if broken:
        print(f"Broken relative links ({len(broken)}):\n")
        for src, raw, resolved in broken:
            print(f"  {src}")
            print(f"      link:    ]({raw})")
            print(f"      missing: {resolved}\n")
        print(f"Checked {checked} relative links; {len(broken)} broken.")
        return 1

    print(f"OK: {checked} relative links across the repo all resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
