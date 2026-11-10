#!/usr/bin/env python3
"""
gatelib: the harness of the gate tests (detections/tests/).

A gate is a check that CI runs to decide if work is done (rule_cases.py,
check_sufficiency.py, the validators, the lints). The tests in this directory
plant one bad artifact in a throwaway copy of the repository and prove that the
gate rejects it for the intended reason. A control proves that the same gate
accepts the copy before the artifact is planted. Without the control a rejection
proves nothing.

What a test gets from this module:

  Tree            a throwaway copy of the repository (or of some of its parts).
                  tree.plant() copies an artifact from detections/tests/known_bad/
                  into it; tree.edit() / tree.replace() / tree.edit_json() change a
                  file in it and fail when nothing changed. tree.run() runs a gate
                  in it as a CI step does: `python <script> <arguments>` from the
                  root of the copy, in a child process, with the Python that runs
                  the tests. It returns a Result (exit code, stdout, stderr).
  GateCase        the unittest.TestCase to derive from: good() is the unmodified
                  copy that the class shares (read-only: a change fails the class),
                  tree() is a private copy for one test.
  assert_rejects  the exit code is not 0 AND the output names the intended reason.
                  A Python traceback, a wrong command line and a timeout are not
                  rejections.
  assert_accepts  the exit code is 0 AND the output proves that the gate looked at
                  something (a gate that checked nothing also exits 0).
  known_gap       marks a test of an artifact that a gate should reject and does
                  not reject today. The test body states the WANTED behaviour
                  (assert_rejects). The test passes while the gap exists and fails,
                  with a message that says what to do, when the gate starts to
                  reject the artifact. KNOWN_GAPS lists every gap:
                      python3 detections/tests/gatelib.py --gaps
  ci_steps        the `run:` steps of the workflows, to prove that the command a
                  test runs is the command CI runs. Tree.run_step() runs one step
                  with the shell that GitHub Actions would use.

Rules that keep the suite hermetic:

  - A gate never runs in the repository itself. It runs in a copy under the
    system temporary directory, which is deleted afterwards (also on failure).
  - The child process gets no token and no GitHub variable, a proxy that refuses
    every connection, and a TMPDIR and HOME inside the sandbox of the copy.
  - GateCase fails a test class that changed a file of the repository.

Run the suite from the repository root (README.md in this directory):

    python3 -B -m unittest discover -s detections/tests -v
"""

import argparse
import atexit
import collections
import concurrent.futures
import dataclasses
import functools
import glob as _glob
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TESTS))      # the checkout that holds this suite
KNOWN_BAD = os.path.join(TESTS, "known_bad")        # the planted artifacts
PYTHON = sys.executable                             # the gates run with the tests' Python
DEFAULT_TIMEOUT = 300                               # seconds, for one gate run

# Parts of the repository for Tree(parts) and GateCase.PARTS. A part is a path
# relative to the repository root (a file, a directory, or a glob pattern).
ALL = (".",)                     # the whole checkout (about 900 files; under 0.5 s to copy)
DETECTIONS = ("detections",)     # every gate under detections/ and all that it reads

# Never copied: version control, bytecode, local caches, the kind bind sources.
_IGNORED_NAMES = frozenset({".git", "__pycache__", ".kind", ".pytest_cache", ".mypy_cache"})
_IGNORED_SUFFIXES = (".pyc", ".pyo")

# Environment variables that a gate must not inherit from the test process: tokens
# and GitHub context (a gate must not call an API, or print ::error annotations in
# the name of the test job), the validators' gate constants, and Python settings.
_DROPPED_PREFIXES = ("GITHUB_", "GH_", "ACTIONS_", "RUNNER_", "TRR9", "DETENG_", "PYTHON")
_DROPPED_NAMES = frozenset({"no_proxy", "pip_index_url", "pip_extra_index_url"})
# Nothing listens on the discard port: a gate that tries the network fails at once.
_NO_NETWORK = "http://127.0.0.1:9"

# The roadmap items that can close a known gap: R<n> is item n of section 4
# ("Trust architecture") of the operating design. "unplanned": no item closes it.
ROADMAP = {
    "R1": "gate code runs from main, not from the pull request",
    "R2": "the gates test themselves (this suite, and the gate defects it finds)",
    "R3": "external records that the agent did not write",
    "R4": "CI captures harvested into committed evidence",
    "R5": "provenance tiers read by the merge policy",
    "R6": "mutation as a ratchet",
    "R7": "representation variants in the oracle (JSON text, letter case, RE2)",
    "R8": "approvals as verifiable properties (waivers, budgets, expected losses)",
    "R9": "sandbox cloud capture",
    "R10": "deferred: blind cases, schema oracle",
    "unplanned": "no roadmap item closes it: a human decides",
}

_TRACEBACK = "Traceback (most recent call last)"
# Output lines worth showing in a failure message even when they are far from the end.
_VERDICT = re.compile(r"^\s*(FAIL|FAILED|ERROR|STALE|BROKEN|BAD ANCHOR|RISE|NOT EXEMPT|PENDING|"
                      r"::error|::warning|Traceback|refusing)\b|\[(ERROR|RATCHET|BROKEN| FAIL |R\d)\]"
                      r"|\bFAILED\b|Error:")
# unittest leaves the frames of this module out of a failure's traceback.
__unittest = True


# --------------------------------------------------------------------------- results

@dataclasses.dataclass
class Result:
    """One finished gate run."""

    argv: list
    cwd: str
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool = False

    @property
    def output(self):
        """stdout, then stderr: the text that the assertions search."""
        return self.stdout + ("\n" if self.stdout and not self.stdout.endswith("\n") else "") \
            + self.stderr

    @property
    def crashed(self):
        """True when the child printed a Python traceback (an uncaught exception)."""
        return _TRACEBACK in self.output

    def describe(self, tail=40, notable=30):
        """The command, its exit code and its output, for a failure message: the last
        `tail` lines of each stream and, from the lines before them, up to `notable`
        lines that look like a verdict (FAIL, ERROR, STALE, a traceback, ...).

        Each output line gets a prefix, so that a `::error` line of a gate is not
        read as a workflow command when the suite runs in GitHub Actions.
        """
        def block(name, text):
            lines = text.rstrip("\n").split("\n") if text.strip() else []
            if not lines:
                return [f"  {name}: (empty)"]
            cut = max(0, len(lines) - tail)
            marked = [(n, line) for n, line in enumerate(lines[:cut], 1) if _VERDICT.search(line)]
            out = [f"  {name}: {len(lines)} line(s)"
                   + (f"; the last {tail}, and before them {min(len(marked), notable)} of "
                      f"{len(marked)} line(s) that look like a verdict" if cut else "")]
            out += [f"    {n:>5} | {line}" for n, line in marked[:notable]]
            if cut:
                out.append("          ...")
            return out + [f"    {n:>5} | {line}" for n, line in enumerate(lines[cut:], cut + 1)]

        code = "timeout" if self.timed_out else self.returncode
        return "\n".join(
            [f"  command: {' '.join(self.argv)}", f"  cwd: {self.cwd}",
             f"  exit code: {code} after {self.seconds:.1f} s"]
            + block("stdout", self.stdout) + block("stderr", self.stderr))


class Pending:
    """A gate run that Tree.start() put in the background. result() waits for it."""

    def __init__(self, future):
        self._future = future

    def result(self):
        return self._future.result()


class NotRejected(AssertionError):
    """assert_rejects: the gate did not reject the artifact for the intended reason.

    kind: "accepts"       the gate exited 0.
          "wrong-reason"  the gate exited non-zero, and its output does not name the
                          intended reason (for example, only a stale-file message).
          "crash"         the gate exited non-zero with a Python traceback: an
                          uncaught exception, not a designed rejection.
    """

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


GAP_KINDS = ("accepts", "wrong-reason", "crash")


# ------------------------------------------------------------------------ assertions

def _harness_faults(result):
    """Faults of the test itself: they are never a verdict of the gate."""
    if result.timed_out:
        raise AssertionError("the gate did not finish in time (a timeout is no verdict):\n"
                             + result.describe())
    if result.returncode < 0:
        raise AssertionError(f"the gate was killed by signal {-result.returncode}:\n"
                             + result.describe())
    if result.returncode == 2 and re.search(r"can't open file|\[Errno 2\] No such file or "
                                            r"directory: '[^']*\.py'", result.stderr):
        raise AssertionError("the gate script was not found (wrong path, or its part is "
                             "not in the copy):\n" + result.describe())


def assert_rejects(result, reason, *, exit_code=None, crash_ok=False):
    """The gate rejected the planted artifact for the intended reason.

    result     what Tree.run() returned.
    reason     a regular expression (re.MULTILINE) that the output must hold: the
               words of the gate's message that name THIS defect, as specific as
               the message allows (the rule, the case, the reason). A message that
               any failure prints (`FAILED:`) is not a reason.
    exit_code  the exact exit code, when the gate documents one (default: not 0).
    crash_ok   True only where the gate's rejection today is an uncaught exception
               and the test pins that as accepted behaviour. By default a
               traceback is a crash, not a rejection.

    Raises NotRejected (an AssertionError) with the kind `accepts`, `crash` or
    `wrong-reason`; @known_gap reads the kind.
    """
    _harness_faults(result)
    if result.returncode == 0:
        raise NotRejected("accepts", "the gate ACCEPTED the artifact (exit code 0); wanted a "
                          f"rejection that names /{reason}/:\n" + result.describe())
    named = re.search(reason, result.output, re.MULTILINE)
    if result.crashed and not crash_ok:
        raise NotRejected("crash", "the gate exited non-zero with a Python traceback: a "
                          "crash is not a rejection (wanted a message that names "
                          f"/{reason}/; the traceback {'does' if named else 'does not'} "
                          "hold it):\n" + result.describe())
    if not named:
        if result.returncode == 2 and result.stderr.lstrip().startswith("usage:"):
            raise AssertionError("the gate refused its command line (a usage error, not a "
                                 "verdict on the artifact):\n" + result.describe())
        raise NotRejected("wrong-reason", "the gate exited non-zero, but its output does not "
                          f"name the intended reason /{reason}/: a failure for another "
                          "reason does not count:\n" + result.describe())
    if exit_code is not None and result.returncode != exit_code:
        raise AssertionError(f"the gate named the reason, but exited {result.returncode}, "
                             f"not {exit_code}:\n" + result.describe())


def assert_accepts(result, proof):
    """The gate accepted the tree: exit code 0, no traceback, and `proof` in the output.

    proof  a regular expression (re.MULTILINE) for the line that shows WHAT the gate
           checked (`All cases hold \\(85 rule file\\(s\\)\\)`), with the count taken
           from the tree where the line has one. Several gates exit 0 when they
           found nothing to check; a control that asserts only the exit code would
           pass on an empty tree.
    """
    _harness_faults(result)
    if result.returncode != 0:
        raise AssertionError("the gate REJECTED a tree that it must accept (exit code "
                             f"{result.returncode}):\n" + result.describe())
    if result.crashed:
        raise AssertionError("the gate exited 0 but printed a traceback:\n" + result.describe())
    if not re.search(proof, result.output, re.MULTILINE):
        raise AssertionError(f"the gate exited 0, but its output does not hold /{proof}/, so "
                             "nothing shows what it checked:\n" + result.describe())


def assert_saw(result, pattern):
    """The output shows that the gate read the planted artifact (re.MULTILINE).

    For a @known_gap test: an artifact that the gate never read (a wrong path, a
    file that it does not glob) is also `accepted`, and that would hide a real
    rejection for ever. This is a plain assertion: when it fails, the test fails.
    """
    if not re.search(pattern, result.output, re.MULTILINE):
        raise AssertionError(f"the output does not hold /{pattern}/, so nothing shows that "
                             "the gate read the planted artifact:\n" + result.describe())


# ------------------------------------------------------------------------- known gaps

@dataclasses.dataclass
class Gap:
    id: str
    gate: str
    reason: str
    closes: str
    today: str
    test: str
    origin: tuple = ()          # (file, line, qualified name) of the test function
    state: str = "not run"      # "open" after its test saw the gap in this process


KNOWN_GAPS = {}     # id -> Gap: every @known_gap of every imported test module


def known_gap(gap_id, *, gate, reason, closes, today="accepts", _registry=None):
    """Mark a test of an artifact that the gate SHOULD reject and does not reject today.

    Write the test body as the wanted behaviour, ending in one assert_rejects():

        @gatelib.known_gap("hidden-rule-file", gate="detections/rule_cases.py",
                           reason="a rule in a dotfile is never read", closes="unplanned")
        def test_gap_hidden_rule_file(self):
            tree = self.tree()
            tree.plant("sufficiency/hidden_rule/hidden.yml", "detections/sigma/T1040/.hidden.yml")
            self.assert_rejects(tree.run("detections/rule_cases.py"), r"\\.hidden\\.yml")

    gap_id  unique in the suite (the case id).
    gate    the script (or workflow job) that should reject the artifact.
    reason  one sentence: what passes today, and why that is wrong.
    closes  the roadmap item that closes the gap: a key of ROADMAP (`R7`), or
            `unplanned` when no item does.
    today   what the gate does today, a NotRejected kind: `accepts` (exit 0, the
            default), `wrong-reason` (it fails, but not for this reason) or `crash`
            (it fails with a traceback only).

    The test PASSES while assert_rejects raises NotRejected of that kind. It FAILS:
      - when the body passes: the gate rejects the artifact now, so the gap is
        closed. Remove the marker; the body is then an ordinary rejection test.
      - when the kind differs from `today`: the gap changed shape. Read the output
        and update `today` (or the gate).
      - on any other failure or error (a planted file that is missing, assert_saw):
        a broken test must not count as an open gap.
    """
    registry = KNOWN_GAPS if _registry is None else _registry
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", gap_id or ""):
        raise ValueError(f"known_gap id {gap_id!r}: use lower-case letters, digits and hyphens")
    if closes not in ROADMAP:
        raise ValueError(f"known_gap {gap_id}: closes={closes!r} is not a roadmap item "
                         f"({', '.join(ROADMAP)})")
    if today not in GAP_KINDS:
        raise ValueError(f"known_gap {gap_id}: today={today!r} is not one of {GAP_KINDS}")
    if not (isinstance(reason, str) and len(reason.strip()) >= 20):
        raise ValueError(f"known_gap {gap_id}: give a reason (one full sentence)")
    if not (isinstance(gate, str) and gate.strip()):
        raise ValueError(f"known_gap {gap_id}: name the gate")

    def decorate(fn):
        where = f"{fn.__module__}.{fn.__qualname__}"
        origin = (fn.__code__.co_filename, fn.__code__.co_firstlineno, fn.__qualname__)
        # The same test registered again is one gap (a module that unittest imported
        # under two names: `test_x` and `detections.tests.test_x`).
        if gap_id in registry and registry[gap_id].origin != origin:
            raise ValueError(f"known_gap id {gap_id!r} is used twice: {registry[gap_id].test} "
                             f"and {where}")
        gap = registry[gap_id] = Gap(gap_id, gate.strip(), " ".join(reason.split()), closes,
                                     today, where, origin)

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                fn(*args, **kwargs)
            except NotRejected as not_rejected:
                if not_rejected.kind != today:
                    raise AssertionError(
                        f"KNOWN GAP CHANGED SHAPE: {gap_id} ({gap.gate}) is recorded as "
                        f"today={today!r}, and the gate's behaviour is now "
                        f"{not_rejected.kind!r}. Read the output below; then update "
                        f"`today` in the @known_gap marker, or the gate.\n{not_rejected}"
                    ) from None
                gap.state = "open"
                return
            except AssertionError as failure:
                raise AssertionError(
                    f"{failure}\n(This is the @known_gap test {gap_id}: a failure here is "
                    "not the gap. If the gate now rejects the artifact, make the test "
                    "body pass and remove the marker.)") from None
            raise AssertionError(
                f"KNOWN GAP CLOSED: {gap_id}. {gap.gate} now rejects this artifact for the "
                f"intended reason. Recorded gap: {gap.reason} (closes: {closes}). Remove "
                f"the @gatelib.known_gap marker from {where}; the test is then an ordinary "
                "rejection test. Update the lists that name this gap as open.")

        wrapper.known_gap = gap
        return wrapper

    return decorate


def gap_report(gaps=None, markdown=False):
    """The list of known gaps as text (or a Markdown table)."""
    gaps = sorted((KNOWN_GAPS if gaps is None else gaps).values(), key=lambda g: (g.gate, g.id))
    if markdown:
        lines = [f"### Known gaps of the gates ({len(gaps)})", "",
                 "A gate should reject the artifact and does not reject it today. Each test "
                 "passes while its gap exists and fails when the gate starts to reject.", "",
                 "| Gap | Gate | Today | Closed by | What passes today |", "|---|---|---|---|---|"]
        lines += [f"| `{g.id}` | `{g.gate}` | {g.today} | {g.closes} | "
                  + g.reason.replace("|", "\\|") + " |" for g in gaps]
        return "\n".join(lines) + "\n"
    lines = [f"Known gaps of the gates: {len(gaps)} (a gate should reject the artifact, and "
             "does not reject it today)"]
    for g in gaps:
        lines += [f"  {g.id}", f"      gate:   {g.gate}", f"      today:  {g.today}",
                  f"      closes: {g.closes} ({ROADMAP[g.closes]})",
                  f"      reason: {g.reason}", f"      test:   {g.test}"]
    return "\n".join(lines) + "\n"


@atexit.register
def _say_open_gaps():
    still_open = sorted(g.id for g in KNOWN_GAPS.values() if g.state == "open")
    if still_open:
        print(f"\n{len(still_open)} known gap(s) still open (a gate should reject, and does "
              "not): " + ", ".join(still_open)
              + "\nDetails: python3 detections/tests/gatelib.py --gaps", file=sys.stderr)


# ------------------------------------------------------------------------------ trees

def _ignored(name):
    return name in _IGNORED_NAMES or name.endswith(_IGNORED_SUFFIXES)


def _ignore(_directory, names):
    return [n for n in names if _ignored(n)]


def fingerprint(root, skip=()):
    """{relative path: (size, mtime_ns)} of every file under root (ignored names and
    the relative directories in `skip` left out). Two equal results: no file was
    added, removed or written between them."""
    out = {}
    skip = {os.path.normpath(s) for s in skip}
    for directory, dirs, files in os.walk(root):
        rel_dir = os.path.relpath(directory, root)
        dirs[:] = sorted(d for d in dirs if not _ignored(d)
                         and os.path.normpath(os.path.join(rel_dir, d)) not in skip)
        for name in files:
            if _ignored(name):
                continue
            full = os.path.join(directory, name)
            try:
                stat = os.lstat(full)
            except FileNotFoundError:
                continue
            out[os.path.normpath(os.path.join(rel_dir, name))] = (stat.st_size, stat.st_mtime_ns)
    return out


def _changes(before, after):
    return sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))


_pool = None


def _executor():
    global _pool
    if _pool is None:
        _pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(2, os.cpu_count() or 2))
    return _pool


class Tree:
    """A throwaway copy of parts of the repository, with a sandbox around it.

        <sandbox>/repo/   the copy: `root`, the working directory of every gate run
        <sandbox>/tmp/    TMPDIR of the gate runs
        <sandbox>/home/   HOME of the gate runs
        <sandbox>/out/    out(name): files beside the copy (--json, --baseline, ...)

    parts   repository-relative paths (files, directories, glob patterns). ALL (the
            default) copies the whole checkout; () gives an empty tree. Bytecode,
            .git and local caches are never copied. Files are copied, not linked:
            a gate must not reach the repository through the copy.
    source  the checkout to copy from (default: the one that holds this suite).

    Call cleanup() when done; GateCase.tree() and GateCase.good() do that.
    """

    def __init__(self, parts=ALL, source=REPO):
        self.source = os.path.abspath(source)
        self.sandbox = os.path.realpath(tempfile.mkdtemp(prefix="deteng-gates-"))
        if os.path.commonpath([self.sandbox, os.path.realpath(self.source)]) \
                == os.path.realpath(self.source):
            shutil.rmtree(self.sandbox, ignore_errors=True)
            raise RuntimeError("the temporary directory is inside the repository; set TMPDIR "
                               "to a directory outside it")
        self.root = os.path.join(self.sandbox, "repo")
        self.tmp = os.path.join(self.sandbox, "tmp")
        self.home = os.path.join(self.sandbox, "home")
        self._out = os.path.join(self.sandbox, "out")
        self._bin = os.path.join(self.sandbox, "bin")
        self._steps = 0
        try:
            for directory in (self.root, self.tmp, self.home, self._out):
                os.makedirs(directory)
            for part in ([parts] if isinstance(parts, str) else parts):
                self._copy_part(part)
        except BaseException:
            self.cleanup()
            raise

    def _copy_part(self, part):
        pattern = os.path.join(self.source, part)
        found = sorted(_glob.glob(pattern)) if any(c in part for c in "*?[") else \
            ([pattern] if os.path.lexists(pattern) else [])
        if not found:
            raise FileNotFoundError(f"Tree part {part!r} names nothing in {self.source}")
        for src in found:
            rel = os.path.relpath(src, self.source)
            if _ignored(os.path.basename(src)):
                continue
            dst = self.root if rel == "." else os.path.join(self.root, rel)
            if os.path.isdir(src):
                shutil.copytree(src, dst, ignore=_ignore, symlinks=True, dirs_exist_ok=True)
            else:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)

    def cleanup(self):
        """Delete the sandbox (the copy and everything the gate runs wrote)."""
        shutil.rmtree(self.sandbox, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.cleanup()

    # -- paths and files ---------------------------------------------------------

    def path(self, rel="."):
        """The absolute path of `rel` in the copy. A path that leaves the copy is refused."""
        if os.path.isabs(rel):
            raise ValueError(f"{rel!r}: give a path relative to the repository root")
        full = os.path.normpath(os.path.join(self.root, rel))
        if full != self.root and not full.startswith(self.root + os.sep):
            raise ValueError(f"{rel!r} leaves the copy")
        return full

    def _target(self, rel):
        """path(rel) for a write: also refuses to follow a symbolic link out of the copy."""
        full = self.path(rel)
        parent = os.path.realpath(os.path.dirname(full))
        if parent != self.root and not parent.startswith(self.root + os.sep):
            raise ValueError(f"{rel!r} resolves outside the copy")
        return full

    def out(self, name):
        """A path beside the copy, inside the sandbox: for --json / --baseline files."""
        if os.path.isabs(name) or ".." in name.split("/"):
            raise ValueError(f"{name!r}: give a plain relative name")
        full = os.path.join(self._out, name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        return full

    def exists(self, rel):
        return os.path.lexists(self.path(rel))

    def glob(self, pattern):
        """The repository-relative paths in the copy that match `pattern`, sorted."""
        return sorted(os.path.relpath(p, self.root)
                      for p in _glob.glob(os.path.join(self.root, pattern), recursive=True))

    def read(self, rel):
        with open(self.path(rel), encoding="utf-8") as fh:
            return fh.read()

    def write(self, rel, text):
        """Create or replace a file of the copy (parent directories are made)."""
        full = self._target(rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(text)

    def append(self, rel, text):
        """Add text to the end of an existing file (a new line is started first)."""
        old = self.read(rel)
        self.write(rel, old + ("" if not old or old.endswith("\n") else "\n") + text)

    def remove(self, rel):
        """Delete a file or a directory of the copy. It must exist."""
        full = self._target(rel)
        if os.path.isdir(full) and not os.path.islink(full):
            shutil.rmtree(full)
        else:
            os.remove(full)

    def rename(self, rel, new_rel):
        """Move a file or a directory inside the copy. The target must not exist."""
        src, dst = self._target(rel), self._target(new_rel)
        if not os.path.lexists(src):
            raise FileNotFoundError(f"{rel} is not in the copy")
        if os.path.lexists(dst):
            raise FileExistsError(f"{new_rel} is already in the copy")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        os.rename(src, dst)

    # -- planting ----------------------------------------------------------------

    def plant(self, artifact, dest, append=False):
        """Copy a planted artifact from detections/tests/known_bad/ into the copy.

        artifact  a path under known_bad/: a file, or a directory (copied with all
                  that it holds; files of the copy with the same names are replaced).
        dest      where it goes, relative to the repository root. The destination
                  name can differ from the artifact's name (`hidden.yml` planted as
                  `detections/sigma/T1040/.hidden.yml`).
        append    True: add the artifact file's text to the end of the existing
                  file `dest` (one more case line in a real sidecar).
        """
        src = os.path.normpath(os.path.join(KNOWN_BAD, artifact))
        if not src.startswith(KNOWN_BAD + os.sep) or not os.path.lexists(src):
            raise FileNotFoundError(f"no planted artifact {artifact!r} under "
                                    f"{os.path.relpath(KNOWN_BAD, REPO)}/")
        dst = self._target(dest)
        if os.path.isdir(src):
            if append:
                raise ValueError("append=True needs a file artifact")
            shutil.copytree(src, dst, ignore=_ignore, dirs_exist_ok=True)
        elif append:
            with open(src, encoding="utf-8") as fh:
                self.append(dest, fh.read())
        else:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)

    def edit(self, rel, change):
        """Replace the text of a file with change(text). An edit that changes nothing
        fails: the artifact would not be planted, and the test would prove nothing."""
        old = self.read(rel)
        new = change(old)
        if not isinstance(new, str):
            raise TypeError(f"edit({rel!r}): the function must return the new text")
        if new == old:
            raise ValueError(f"edit({rel!r}) changed nothing: the artifact is not planted")
        self.write(rel, new)

    def replace(self, rel, old, new, count=1):
        """Replace `count` occurrences of `old` in a file (count=0: every one). Fails
        when the file holds fewer, so a planted edit cannot silently miss."""
        text = self.read(rel)
        found = text.count(old)
        if found == 0 or found < count:
            raise ValueError(f"replace({rel!r}): {old!r} occurs {found} time(s), "
                             f"wanted {count or 'at least 1'}")
        self.edit(rel, lambda t: t.replace(old, new, count) if count else t.replace(old, new))

    def read_json(self, rel):
        return json.loads(self.read(rel))

    def edit_json(self, rel, change, indent=2):
        """Load a JSON file, apply change(data) (change in place, or return the new
        data), and write it back. Fails when the data did not change."""
        data = self.read_json(rel)
        before = json.dumps(data, sort_keys=True)
        returned = change(data)
        data = data if returned is None else returned
        if json.dumps(data, sort_keys=True) == before:
            raise ValueError(f"edit_json({rel!r}) changed nothing: the artifact is not planted")
        self.write(rel, json.dumps(data, indent=indent) + "\n")

    def read_jsonl(self, rel):
        """The objects of a JSON-lines file (a sidecar): one per non-empty line."""
        return [json.loads(line) for line in self.read(rel).splitlines() if line.strip()]

    def write_jsonl(self, rel, rows):
        self.write(rel, "".join(json.dumps(row) + "\n" for row in rows))

    def fingerprint(self):
        return fingerprint(self.root)

    # -- running gates -----------------------------------------------------------

    def env(self, extra=None):
        """The environment of a gate run: the test process's own, without tokens,
        GitHub variables, gate constants and Python settings; with a TMPDIR and a
        HOME in the sandbox, no bytecode, and a proxy that refuses every connection."""
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(_DROPPED_PREFIXES) and k.lower() not in _DROPPED_NAMES}
        env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", TMPDIR=self.tmp, HOME=self.home,
                   PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1")
        for name in ("http_proxy", "https_proxy", "all_proxy"):
            env[name] = env[name.upper()] = _NO_NETWORK
        env.update({k: str(v) for k, v in (extra or {}).items()})
        return env

    def run_command(self, argv, env=None, timeout=DEFAULT_TIMEOUT, cwd="."):
        """Run any command in the copy (cwd: relative to its root). Returns a Result."""
        argv = [str(a) for a in argv]
        cwd = self.path(cwd)
        start = time.monotonic()
        proc = subprocess.Popen(argv, cwd=cwd, env=self.env(env), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        timed_out = False
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, err = proc.communicate()
        return Result(argv, cwd, proc.returncode, out.decode("utf-8", "replace"),
                      err.decode("utf-8", "replace"), time.monotonic() - start, timed_out)

    def run(self, script, *args, env=None, timeout=DEFAULT_TIMEOUT):
        """Run a gate as a CI step does: `python <script> <args>` at the root of the copy.

        script  the gate, relative to the repository root, as the workflow names it
                (`detections/rule_cases.py`). It must be in the copy.
        args    its arguments, as in the workflow. Give a path in the copy as
                tree.path(rel), and an output file as tree.out(name).
        """
        if not os.path.isfile(self.path(script)):
            raise FileNotFoundError(f"{script} is not in the copy (parts copied from "
                                    f"{self.source}); add its part to the Tree")
        return self.run_command([PYTHON, script, *args], env=env, timeout=timeout)

    def run_python(self, code, *args, env=None, timeout=DEFAULT_TIMEOUT):
        """Run a snippet with `python -c` at the root of the copy: for a function of a
        gate that no command line reaches. The snippet must put the gate's directory
        on sys.path itself (`sys.path.insert(0, "detections")`)."""
        return self.run_command([PYTHON, "-c", code, *args], env=env, timeout=timeout)

    def start(self, script, *args, env=None, timeout=DEFAULT_TIMEOUT):
        """run() in the background; returns a Pending, and pending.result() waits.

        For the slow gates: start several runs (in setUpClass, or at the top of a
        test), then collect them. The runs share the machine's cores.
        """
        if not os.path.isfile(self.path(script)):
            raise FileNotFoundError(f"{script} is not in the copy; add its part to the Tree")
        return Pending(_executor().submit(self.run, script, *args, env=env, timeout=timeout))

    def run_step(self, step, env=None, expressions=None, timeout=DEFAULT_TIMEOUT):
        """Run one workflow step (from ci_steps()) with the shell GitHub Actions uses.

        No `shell:` means `bash -e`; `shell: bash` means `bash --noprofile --norc -eo
        pipefail`. So a step that pipes a gate into `tee` without `shell: bash` loses
        the gate's exit code here as it does in CI. `python3` and `python` are the
        tests' Python. /tmp/ in the script is the sandbox's tmp directory, and
        GITHUB_STEP_SUMMARY, GITHUB_OUTPUT, GITHUB_ENV and RUNNER_TEMP are files and a
        directory in the sandbox. Give the value of each `${{ ... }}` expression in
        `expressions` ({"github.event.pull_request.base.sha": "abc"}).
        """
        script = step.run
        for expression, value in (expressions or {}).items():
            script = re.sub(r"\$\{\{\s*" + re.escape(expression) + r"\s*\}\}",
                            lambda _m, v=str(value): v, script)
        if "${{" in script:
            raise ValueError(f"step {step.name!r} of {step.workflow}: give a value for every "
                             "${{ ... }} expression (expressions=...)")
        script = re.sub(r"(?<![\w.$/-])/tmp/", lambda _m: self.tmp + "/", script)
        if step.shell in (None, ""):
            shell = ["bash", "-e"]
        elif step.shell == "bash":
            shell = ["bash", "--noprofile", "--norc", "-eo", "pipefail"]
        else:
            raise ValueError(f"step {step.name!r} of {step.workflow}: shell {step.shell!r} "
                             "is not modelled")
        if not os.path.isdir(self._bin):
            os.makedirs(self._bin)
            for name in ("python3", "python"):
                shim = os.path.join(self._bin, name)
                with open(shim, "w", encoding="utf-8") as fh:
                    fh.write(f'#!/bin/sh\nexec "{PYTHON}" "$@"\n')
                os.chmod(shim, 0o755)
        self._steps += 1
        path = self.out(f"steps/{self._steps}.sh")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(script if script.endswith("\n") else script + "\n")
        runner_temp = os.path.join(self._out, "runner-temp")
        os.makedirs(runner_temp, exist_ok=True)
        step_env = {"PATH": self._bin + os.pathsep + os.environ.get("PATH", ""),
                    "RUNNER_TEMP": runner_temp}
        for name in ("GITHUB_STEP_SUMMARY", "GITHUB_OUTPUT", "GITHUB_ENV"):
            step_env[name] = self.out(f"github/{name.lower()}")
            open(step_env[name], "a", encoding="utf-8").close()
        step_env.update(env or {})
        return self.run_command(shell + [path], env=step_env, timeout=timeout)


# --------------------------------------------------------------------------- workflows

Step = collections.namedtuple("Step", "workflow job name shell run")


def ci_steps(script=None, root=REPO):
    """The `run:` steps of the workflows under .github/workflows/, as Step tuples
    (workflow file, job id, step name, shell or None, run text).

    script  keep only the steps whose text holds this string (`detections/rule_cases.py`).
    shell   the step's `shell:`, or the job's or the workflow's `defaults.run.shell`.
    """
    import yaml     # PyYAML: in detections/requirements.txt

    steps = []
    for path in sorted(_glob.glob(os.path.join(root, ".github", "workflows", "*.y*ml"))):
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}

        def default_shell(node):
            return ((node.get("defaults") or {}).get("run") or {}).get("shell")

        for job_id, job in (doc.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                run = step.get("run")
                if isinstance(run, str) and (script is None or script in run):
                    steps.append(Step(os.path.basename(path), job_id, step.get("name") or "",
                                      step.get("shell") or default_shell(job)
                                      or default_shell(doc), run))
    return steps


def ci_step(workflow, job, script, root=REPO):
    """The one step of `job` in `workflow` (a file name) whose text holds `script`.
    Fails when there is none, or more than one: the test must name the step it runs."""
    found = [s for s in ci_steps(script, root) if s.workflow == workflow and s.job == job]
    if len(found) != 1:
        raise LookupError(f"{workflow}, job {job}: {len(found)} step(s) run {script}; wanted 1"
                          + "".join(f"\n  - {s.name}" for s in found))
    return found[0]


def ci_commands(script, root=REPO):
    """The command lines of the workflows that RUN `script` with Python: comments
    removed, lines that end in a backslash joined, white space collapsed. One string
    per command. A line that only names the script (a list of paths) is left out."""
    runs = re.compile(r"python[\d.]*\s+(?:-\S+\s+)*[\"']?(?:\S*/)?" + re.escape(script)
                      + r"(?![\w.-])")
    commands = []
    for step in ci_steps(script, root):
        logical, pending = [], ""
        for line in step.run.splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            if line.endswith("\\"):
                pending += line[:-1] + " "
                continue
            logical.append(pending + line)
            pending = ""
        if pending:
            logical.append(pending)
        commands += [" ".join(c.split()) for c in logical if runs.search(c)]
    return commands


# ----------------------------------------------------------------------------- GateCase

class GateCase(unittest.TestCase):
    """Base class of the gate tests.

    PARTS  what a copy holds (Tree parts); the default is the whole checkout.

    good()   the unmodified copy that the tests of the class share. It is read-only:
             the class fails when a test or a gate changed a file in it.
    tree()   a private copy for one test, deleted when the test ends.

    The class also fails when a file of the REPOSITORY changed while its tests ran
    (detections/tests/ and ignored files excepted): gates run only in copies.
    """

    PARTS = ALL
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        before = fingerprint(REPO, skip=("detections/tests",))
        cls.addClassCleanup(cls._repository_unchanged, before)

    @classmethod
    def _repository_unchanged(cls, before):
        changed = _changes(before, fingerprint(REPO, skip=("detections/tests",)))
        if changed:
            raise AssertionError(
                f"{cls.__name__}: file(s) of the repository changed while the tests ran (a "
                "gate must run only in a copy; or someone edited the repository during the "
                "run): " + ", ".join(changed[:10])
                + (f" (+{len(changed) - 10} more)" if len(changed) > 10 else ""))

    @classmethod
    def good(cls):
        """The shared, unmodified copy of cls.PARTS. Never change it: use tree()."""
        if "_good" not in cls.__dict__:
            tree = Tree(cls.PARTS)
            cls._good = tree
            cls.addClassCleanup(cls._drop_good, tree, tree.fingerprint())
        return cls._good

    @classmethod
    def _drop_good(cls, tree, before):
        changed = _changes(before, tree.fingerprint())
        tree.cleanup()
        del cls._good
        if changed:
            raise AssertionError(
                f"{cls.__name__}: the shared good() tree was changed ({', '.join(changed[:10])}"
                f"{', ...' if len(changed) > 10 else ''}); a test that plants or runs a gate "
                "that writes must use self.tree()")

    def tree(self, *parts):
        """A private copy of `parts` (default: the class's PARTS) for this test."""
        tree = Tree(parts or self.PARTS)
        self.addCleanup(tree.cleanup)
        return tree

    # The module's assertions, as methods: self.assert_rejects(result, reason), ...
    assert_rejects = staticmethod(assert_rejects)
    assert_accepts = staticmethod(assert_accepts)
    assert_saw = staticmethod(assert_saw)

    def assert_ci_runs(self, script, *words):
        """A workflow runs `script` in one command line that holds every one of `words`
        (flags or other text). Proves that the command of a test is the command of CI:
        a gate that CI calls without `--enforce` gates nothing."""
        commands = ci_commands(script)
        if not any(all(word in command for word in words) for command in commands):
            self.fail(f"no workflow step runs {script} with {' '.join(words) or '(any)'}; "
                      f"the workflows run: {commands or 'nothing that names it'}")


# ---------------------------------------------------------------------------------- CLI

def _discover():
    """{`module.Class`: number of tests} of every test class under TESTS. A test
    module that does not import is an error: its tests would silently not run."""
    loader = unittest.TestLoader()
    suite = loader.discover(TESTS, pattern="test_*.py", top_level_dir=TESTS)
    if loader.errors:
        raise ImportError("a test module does not import:\n" + "\n".join(loader.errors))
    classes = collections.OrderedDict()

    def walk(tests):
        for test in tests:
            if isinstance(test, unittest.TestSuite):
                walk(test)
            else:
                name = test.id().rsplit(".", 1)[0]
                classes[name] = classes.get(name, 0) + 1

    walk(suite)
    return classes


def run_suite(jobs=None, only=(), timeout=1200, out=sys.stdout):
    """Run the suite with one `python -m unittest` process for each test class, `jobs`
    at a time, and print each class's output when it ends. The tests and their
    verdicts are those of `python -m unittest discover`; only the wall time differs,
    because the gates of different classes run at the same time.

    Returns 0 only when every class ran all of its tests and none failed.
    """
    classes = collections.OrderedDict(
        (name, count) for name, count in _discover().items()
        if not only or any(word in name for word in only))
    if not classes:
        print("no test class" + (f" matches {' '.join(only)}" if only else " found"), file=out)
        return 1
    jobs = max(1, jobs or os.cpu_count() or 2)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

    def run_class(name):
        start = time.monotonic()
        try:
            done = subprocess.run([PYTHON, "-B", "-m", "unittest", "-v", name], cwd=TESTS, env=env,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=timeout)
            code, text = done.returncode, done.stdout.decode("utf-8", "replace")
        except subprocess.TimeoutExpired as expired:
            code = "timeout"
            text = (expired.stdout or b"").decode("utf-8", "replace")
        ran = re.search(r"^Ran (\d+) tests? in", text, re.MULTILINE)
        return name, code, int(ran.group(1)) if ran else 0, time.monotonic() - start, text

    start = time.monotonic()
    failed, total = [], 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for name, code, ran, seconds, text in pool.map(run_class, classes):
            total += ran
            verdict = "ok"
            if code != 0:
                verdict = f"FAILED (exit code {code})"
            elif ran != classes[name]:
                verdict = f"FAILED (ran {ran} of {classes[name]} test(s))"
            if verdict != "ok":
                failed.append(name)
            print(f"===== {name}: {verdict}, {ran} test(s), {seconds:.1f} s", file=out)
            print("".join(f"    {line}\n" for line in text.rstrip("\n").split("\n")), end="", file=out)
            out.flush()
    print(f"\n{len(classes)} test class(es), {total} test(s), {jobs} at a time, "
          f"{time.monotonic() - start:.1f} s", file=out)
    if failed:
        print(f"FAILED: {len(failed)} test class(es): {', '.join(failed)}", file=out)
        return 1
    print("OK", file=out)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="The gate tests: list the known gaps, or run the suite in parallel.")
    ap.add_argument("--gaps", action="store_true", help="print every @known_gap of the suite")
    ap.add_argument("--markdown", action="store_true", help="with --gaps: a Markdown table")
    ap.add_argument("--json", action="store_true", help="with --gaps: JSON")
    ap.add_argument("--run", action="store_true",
                    help="run the suite, one process for each test class, in parallel")
    ap.add_argument("--jobs", type=int, default=None,
                    help="with --run: classes at a time (default: the number of CPUs)")
    ap.add_argument("only", nargs="*",
                    help="with --run: only the classes whose `module.Class` holds one of these")
    args = ap.parse_args(argv)
    if not (args.gaps or args.run):
        ap.print_help()
        return 0
    # The test modules import `gatelib`, not `__main__`: use the registry of that module.
    sys.path.insert(0, TESTS)
    import gatelib as lib

    code = 0
    try:
        if args.run:
            code = lib.run_suite(args.jobs, args.only)
        else:
            lib._discover()
    except ImportError as error:
        print(error, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps([{"id": g.id, "gate": g.gate, "today": g.today, "closes": g.closes,
                           "reason": g.reason, "test": g.test, "state": g.state} for g in
                          sorted(lib.KNOWN_GAPS.values(), key=lambda g: (g.gate, g.id))], indent=2))
    elif args.gaps or args.run:
        print(("\n" if args.run else "") + lib.gap_report(markdown=args.markdown), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
