#!/usr/bin/env python3
"""
Portable-regex lint for the Sigma rules.

The validators prove every rule with pySigma's SQLite backend, whose REGEXP is
Python's `re`. Python accepts constructs that other Sigma backends reject or
read differently, so a rule that is green here can fail to convert, or convert
to a query that matches something else, on Elasticsearch, Splunk or Sentinel.
This lint walks detections/sigma/**/*.yml, finds every `|re` value (in any
detection item, list or correlation document), and fails on anything outside
the portable subset below.

The subset is the intersection of:

  * the Sigma specification (`re` modifier: `.`, `^ $`, `* + ? {n,m}`,
    `[a-z] [^a-z]`, `|`, `()`; sub-modifiers `i`, `m`, `s`);
  * RE2 (Go-based backends such as Loki), and the KQL dialect (Microsoft Sentinel),
    which differs from RE2 on `\\<` `\\>` and class set operators: no
    lookaround, backreferences, possessive quantifiers or atomic groups;
  * Lucene RegExp (Elasticsearch query_string `/re/` and ES|QL RLIKE): no
    anchors (every pattern matches the whole value), no `(?` groups or inline
    flags, `"` `#` `@` `&` `~` `<` `>` are operators, and a backslash before a
    letter other than d D s S w W is an error;
  * PCRE (Splunk), which accepts all of the above.

Allowed:
  literal characters; `\\` + a punctuation character (a literal); `.`;
  `^` only as the first character and `$` only as the last; greedy `* + ?`
  and `{n}` `{n,}` `{n,m}` (n, m <= 1000); `[...]` and `[^...]` classes with
  ranges; `|`; plain `( )` groups; `\\s` and `\\S`; sub-modifiers `i` and `s`.

Rejected (each with a message naming the rule, the field and the construct):
  any `(?` group: lookahead, lookbehind, atomic, named, non-capturing,
  comment, conditional, inline flags; backreferences; `\\A \\Z \\z \\G \\b \\B`;
  `\\d \\D \\w \\W` (spell the ASCII class: Python and KQL read them as
  Unicode classes); `\\n \\t \\x.. \\u.... \\p{..}` and every other backslash
  before a letter or digit; lazy and possessive quantifiers; a bare `"` `#`
  `@` `&` `~` (write `\\"`, ...); a bare `<` `>` (write `[<]` `[>]`: `\\<` is
  a word boundary in KQL); a bare `{` `}` `]` outside a quantifier or class;
  `[` and the set operators `&& -- ~~ ||` inside a class; a raw control
  character (tab, line break); the `m` sub-modifier; and a pattern longer
  than MAX_LEN (1000) characters, Elasticsearch's index.max_regex_length
  default.

Every pattern must also compile with Python `re` (the proving backend). When
the `re2` module (pip install google-re2) is importable, every pattern must
also compile with RE2; `--require-re2` makes its absence an error (CI).

See detections/README.md "Portable regular expressions" for the sources and
the semantic differences (anchoring, `.` and `\\s`) that no lint can remove.

Exit 0 when every `|re` value is portable; exit 1 and print each finding
otherwise.
"""

import argparse
import os
import re
import sys
import warnings

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install -r detections/requirements.txt")

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES = os.path.join(REPO, "detections", "sigma")

MAX_LEN = 1000         # Elasticsearch index.max_regex_length default
MAX_REPEAT = 1000      # RE2 rejects a larger {n,m} count
ALLOWED_SUBMODIFIERS = {"i", "s"}

# `\` + letter: the only portable shorthand.
SHORTHAND_OK = set("sS")
LETTER_ESCAPES = {
    "A": "string anchor \\A (write ^ as the first character)",
    "Z": "string anchor \\Z (write $ as the last character)",
    "z": "string anchor \\z (write $ as the last character)",
    "G": "match-continuation anchor \\G",
    "b": "word boundary \\b",
    "B": "word boundary \\B",
    "d": "shorthand \\d (write [0-9]: Python and KQL read \\d as any Unicode digit)",
    "D": "shorthand \\D (write [^0-9])",
    "w": "shorthand \\w (write [A-Za-z0-9_]: Python and KQL read \\w as Unicode)",
    "W": "shorthand \\W (write [^A-Za-z0-9_])",
    "p": "Unicode class \\p{..}",
    "P": "Unicode class \\P{..}",
    "Q": "quoting \\Q...\\E",
    "E": "quoting \\Q...\\E",
    "K": "match reset \\K",
    "R": "line break \\R",
    "X": "grapheme \\X",
    "h": "horizontal space \\h",
    "H": "horizontal space \\H",
    "k": "named backreference \\k",
    "g": "backreference or subroutine \\g",
    "N": "named character \\N",
    "x": "hex escape \\x (Lucene rejects it)",
    "u": "Unicode escape \\u (Lucene rejects it)",
    "U": "Unicode escape \\U (Lucene rejects it)",
    "c": "control escape \\c",
    "o": "octal escape \\o",
}
# Lucene rejects a backslash before these letters; RE2/PCRE read a control char.
for _c, _name in (("n", "newline"), ("t", "tab"), ("r", "carriage return"),
                  ("f", "form feed"), ("v", "vertical tab"), ("a", "bell"),
                  ("e", "escape")):
    LETTER_ESCAPES[_c] = (f"character escape \\{_c} ({_name}; Lucene rejects it: "
                          "use \\s / \\S or a class without it)")

# Bare outside a class: Lucene operators (string literal, empty language, any
# string, intersection, complement). A backslash makes each a literal everywhere.
LUCENE_OPERATORS = set('"#@&~')
# Bare `<` `>` are Lucene's interval operator, and `\<` `\>` are word boundaries
# in KQL, so the only portable spelling is a one-character class.
ANGLE = set("<>")

GROUP_KINDS = (
    ("(?<=", "lookbehind (?<="),
    ("(?<!", "negative lookbehind (?<!"),
    ("(?=", "lookahead (?="),
    ("(?!", "negative lookahead (?!"),
    ("(?>", "atomic group (?>"),
    ("(?P<", "named group (?P<"),
    ("(?P=", "named backreference (?P="),
    ("(?P>", "recursion (?P>"),
    ("(?<", "named group (?<"),
    ("(?'", "named group (?'"),
    ("(?:", "non-capturing group (?: (write a plain ( ) group)"),
    ("(?#", "comment (?#"),
    ("(?(", "conditional (?("),
    ("(?|", "branch reset (?|"),
    ("(?R", "recursion (?R"),
    ("(?&", "recursion (?&"),
)

_QUANT = re.compile(r"\{(\d+)(,(\d*))?\}")


def scan(pattern):
    """Yield (offset, construct) for every non-portable construct in pattern."""
    n = len(pattern)
    i = 0
    prev_quant = False   # the previous token was a quantifier
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                yield i, "trailing backslash"
                break
            nxt = pattern[i + 1]
            if nxt.isdigit():
                yield i, f"backreference or octal escape \\{nxt}"
            elif nxt.isalpha():
                if nxt not in SHORTHAND_OK:
                    yield i, LETTER_ESCAPES.get(nxt, f"escape \\{nxt}")
            elif nxt in ANGLE:
                yield i, f"escape \\{nxt} (a word boundary in KQL: write [{nxt}])"
            elif not nxt.isascii():
                yield i, f"escape before non-ASCII {nxt!r}"
            i += 2
            prev_quant = False
            continue
        if ch == "[":
            i, findings = _scan_class(pattern, i)
            yield from findings
            prev_quant = False
            continue
        if ch == "(":
            step = 1
            if pattern.startswith("(?", i):
                for prefix, name in GROUP_KINDS:
                    if pattern.startswith(prefix, i):
                        yield i, name
                        step = len(prefix)
                        break
                else:
                    m = re.match(r"\(\?[a-zA-Z-]*[:)]", pattern[i:])
                    if m:
                        yield i, ("inline flags " + m.group(0) +
                                  " (use the |re|i or |re|s sub-modifier)")
                        step = len(m.group(0))
                    else:
                        yield i, "group syntax (?"
                        step = 2
            i += step
            prev_quant = False
            continue
        if ord(ch) < 0x20 or ch == "\x7f":
            yield i, (f"raw control character U+{ord(ch):04X} (invisible in review, and a raw "
                      "line break ends a KQL or SPL string literal: use \\s or \\S)")
            i += 1
            prev_quant = False
            continue
        if ch in "*+?":
            if prev_quant:
                kind = "lazy" if ch == "?" else "possessive" if ch == "+" else "repeated"
                yield i - 1, f"{kind} quantifier {pattern[i - 1]}{ch}"
            i += 1
            prev_quant = True
            continue
        if ch == "{":
            m = _QUANT.match(pattern, i)
            if not m:
                yield i, "bare { (write \\{)"
                i += 1
                prev_quant = False
                continue
            for num in (m.group(1), m.group(3)):
                if num and int(num) > MAX_REPEAT:
                    yield i, f"repetition count {num} > {MAX_REPEAT} (RE2 limit)"
            if prev_quant:
                yield i, f"repeated quantifier {m.group(0)}"
            i = m.end()
            prev_quant = True
            continue
        if ch == "}":
            yield i, "bare } (write \\})"
        elif ch == "]":
            yield i, "bare ] (write \\])"
        elif ch in LUCENE_OPERATORS:
            yield i, f'bare {ch} (a Lucene operator: write \\{ch})'
        elif ch in ANGLE:
            yield i, f"bare {ch} (Lucene interval operator: write [{ch}])"
        elif ch == "^" and i != 0:
            yield i, "^ not at the start (Lucene has no anchors; a backend can only translate edge anchors)"
        elif ch == "$" and i != n - 1:
            yield i, "$ not at the end (Lucene has no anchors; a backend can only translate edge anchors)"
        i += 1
        prev_quant = False


def _scan_class(pattern, start):
    """Scan the class that opens at pattern[start]; return (end, findings)."""
    findings = []
    n = len(pattern)
    i = start + 1
    if i < n and pattern[i] == "^":
        i += 1
    if i < n and pattern[i] == "]":
        findings.append((i, "] first in a class (write \\])"))
        i += 1
    while i < n and pattern[i] != "]":
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                findings.append((i, "trailing backslash"))
                return n, findings
            nxt = pattern[i + 1]
            if nxt.isdigit():
                findings.append((i, f"octal or backreference escape \\{nxt} in a class"))
            elif nxt.isalpha() and nxt not in SHORTHAND_OK:
                findings.append((i, LETTER_ESCAPES.get(nxt, f"escape \\{nxt}") + " in a class"))
            elif nxt in ANGLE:
                findings.append((i, f"escape \\{nxt} in a class (write {nxt} bare inside [ ])"))
            i += 2
            continue
        if ord(ch) < 0x20 or ch == "\x7f":
            findings.append((i, f"raw control character U+{ord(ch):04X} in a class (use \\s or \\S)"))
        elif ch == "[":
            findings.append((i, "[ inside a class (nested or POSIX class; write \\[)"))
        elif pattern.startswith(("&&", "--", "~~", "||"), i):
            findings.append((i, f"class set operator {pattern[i:i + 2]} (KQL reads it as set algebra)"))
            i += 2
            continue
        i += 1
    if i >= n:
        findings.append((start, "unterminated class ["))
        return n, findings
    return i + 1, findings


def check_value(pattern, submods, re2mod):
    """All findings for one |re value."""
    out = []
    for mod in submods:
        if mod not in ALLOWED_SUBMODIFIERS:
            out.append(f"sub-modifier |{mod} (only |i and |s are portable; Lucene has no line anchors)")
    if len(pattern) > MAX_LEN:
        out.append(f"pattern is {len(pattern)} characters (limit {MAX_LEN}; split it into Sigma items)")
    for off, what in scan(pattern):
        out.append(f"{what} at offset {off}: ...{pattern[max(0, off - 12):off + 12]}...")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)  # nested-set warnings; scan() reports them
            re.compile(pattern)
    except re.error as e:
        out.append(f"does not compile with Python re: {e}")
    if re2mod is not None:
        try:
            opts = re2mod.Options()
            opts.case_sensitive = "i" not in submods
            opts.dot_nl = "s" in submods
            opts.log_errors = False
            re2mod.compile(pattern, opts)
        except Exception as e:  # re2.error, or an options/compile failure
            out.append(f"does not compile with RE2: {e}")
    return out


def iter_re_values(node, path):
    """Yield (path, modifiers after re, value) for every |re value under node."""
    if isinstance(node, dict):
        for key, val in node.items():
            key_s = str(key)
            here = f"{path}.{key_s}" if path else key_s
            parts = key_s.split("|")
            if "re" in parts[1:]:
                submods = parts[parts.index("re") + 1:]
                values = val if isinstance(val, list) else [val]
                for idx, v in enumerate(values):
                    label = f"{here}[{idx}]" if isinstance(val, list) else here
                    yield label, submods, v
            else:
                yield from iter_re_values(val, here)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            yield from iter_re_values(item, f"{path}[{idx}]")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0].strip())
    ap.add_argument("paths", nargs="*", help="rule files or directories (default: detections/sigma)")
    ap.add_argument("--require-re2", action="store_true",
                    help="fail if the re2 module (google-re2) is not importable")
    args = ap.parse_args(argv)

    try:
        import re2 as re2mod  # google-re2
        if not hasattr(re2mod, "Options"):
            re2mod = None
    except ImportError:
        re2mod = None
    if re2mod is None and args.require_re2:
        print("ERROR: --require-re2 given but the re2 module is missing (pip install google-re2)")
        return 1

    files = []
    for p in args.paths or [RULES]:
        if os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                files += [os.path.join(root, f) for f in names if f.endswith((".yml", ".yaml"))]
        else:
            files.append(p)

    problems, values = 0, 0
    for path in sorted(files):
        rel = os.path.relpath(path, REPO)
        try:
            with open(path, encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))
        except (OSError, yaml.YAMLError) as e:
            print(f"FAIL {rel}: cannot parse: {e}")
            problems += 1
            continue
        for d_idx, doc in enumerate(docs):
            where = rel if len(docs) == 1 else f"{rel} (document {d_idx + 1})"
            for label, submods, value in iter_re_values(doc, ""):
                values += 1
                if not isinstance(value, str):
                    print(f"FAIL {where}: {label}: value {value!r} is not a string")
                    problems += 1
                    continue
                for msg in check_value(value, submods, re2mod):
                    print(f"FAIL {where}: {label}: {msg}")
                    problems += 1

    engine = "Python re + RE2" if re2mod is not None else "Python re only (RE2 not installed)"
    if problems:
        print(f"check_sigma_regex: {problems} problem(s) in {values} |re value(s) "
              f"across {len(files)} rule file(s); compiled with {engine}")
        return 1
    print(f"check_sigma_regex: OK, {values} |re value(s) across {len(files)} rule file(s) "
          f"are portable; compiled with {engine}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
