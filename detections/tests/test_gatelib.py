"""
Tests of the harness itself (gatelib.py). The harness decides if a gate test is
green, so it is a gate too: these tests plant faults in constructed gates (small
scripts in an empty tree) and prove that the assertions and the known-gap marker
tell a rejection from an acceptance, a crash, a wrong reason and a broken test.

No test here runs a gate of the repository; the whole file takes about ten seconds.

    python3 -B -m unittest discover -s detections/tests -p 'test_gatelib.py' -v
"""

import ast
import glob
import json
import os
import re
import select
import shutil
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gatelib  # noqa: E402

# Constructed gates: each prints what a real gate prints in that situation.
ACCEPTING = "print('All cases hold (3 rule file(s)).')\n"
REJECTING = ("import sys\n"
             "print('FAIL  T9999/x.yml :: near-miss  n: the analysis grades it trivial')\n"
             "print('FAILED: 1 case problem(s).')\n"
             "sys.exit(1)\n")
OTHER_REASON = ("import sys\n"
                "print('STALE: scores.json does not match the current rules')\n"
                "sys.exit(1)\n")
CRASHING = "raise ValueError('the analysis grades it trivial')\n"
USAGE = ("import argparse\n"
         "argparse.ArgumentParser().parse_args(['--no-such-flag'])\n")
REASON = r"FAIL  T9999/x\.yml .* grades it trivial"


def not_collected(gaps):
    """The line of `gatelib.py --run` (of the whole suite, or of a shard) for the
    known gaps `gaps` (a list of ids), whose test no class collects."""
    return ("FAILED: no test class collects the marked test of these known gap(s): "
            + ", ".join(gaps) + ". The likely causes: the marked method is not a method "
            "`test_...` of a TestCase; a decorator above @gatelib.known_gap does not use "
            "functools.wraps; a class overrides the marked test without the marker.")


def constructed(test, source):
    """An empty tree with one constructed gate; returns the Result of its run."""
    tree = gatelib.Tree(())
    test.addCleanup(tree.cleanup)
    tree.write("gate.py", source)
    return tree.run("gate.py")


class Assertions(unittest.TestCase):

    def test_rejection_for_the_intended_reason(self):
        gatelib.assert_rejects(constructed(self, REJECTING), REASON)
        gatelib.assert_rejects(constructed(self, REJECTING), REASON, exit_code=1)

    def test_acceptance_is_not_a_rejection(self):
        with self.assertRaises(gatelib.NotRejected) as caught:
            gatelib.assert_rejects(constructed(self, ACCEPTING), REASON)
        self.assertEqual(caught.exception.kind, "accepts")

    def test_failure_for_another_reason_is_not_a_rejection(self):
        with self.assertRaises(gatelib.NotRejected) as caught:
            gatelib.assert_rejects(constructed(self, OTHER_REASON), REASON)
        self.assertEqual(caught.exception.kind, "wrong-reason")

    def test_crash_is_not_a_rejection_even_when_it_names_the_reason(self):
        result = constructed(self, CRASHING)
        with self.assertRaises(gatelib.NotRejected) as caught:
            gatelib.assert_rejects(result, r"grades it trivial")
        self.assertEqual(caught.exception.kind, "crash")
        gatelib.assert_rejects(result, r"ValueError: the analysis grades it trivial",
                               crash_ok=True)

    def test_wrong_exit_code(self):
        with self.assertRaisesRegex(AssertionError, "exited 1, not 2"):
            gatelib.assert_rejects(constructed(self, REJECTING), REASON, exit_code=2)

    def test_usage_error_and_missing_script_are_faults_of_the_test(self):
        for result in (constructed(self, USAGE),):
            with self.assertRaises(AssertionError) as caught:
                gatelib.assert_rejects(result, REASON)
            self.assertNotIsInstance(caught.exception, gatelib.NotRejected)
            self.assertIn("usage error", str(caught.exception))
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        with self.assertRaises(FileNotFoundError):
            tree.run("no_such_gate.py")
        missing = tree.run_command([gatelib.PYTHON, "no_such_gate.py"])
        for check in (lambda: gatelib.assert_rejects(missing, REASON),
                      lambda: gatelib.assert_accepts(missing, "x")):
            with self.assertRaises(AssertionError) as caught:
                check()
            self.assertNotIsInstance(caught.exception, gatelib.NotRejected)
            self.assertIn("was not found", str(caught.exception))

    def test_timeout_is_no_verdict(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        tree.write("gate.py", "import time\ntime.sleep(30)\n")
        result = tree.run("gate.py", timeout=0.5)
        self.assertTrue(result.timed_out)
        self.assertLess(result.seconds, 10)
        for check in (lambda: gatelib.assert_rejects(result, REASON),
                      lambda: gatelib.assert_accepts(result, "x")):
            with self.assertRaises(AssertionError) as caught:
                check()
            self.assertNotIsInstance(caught.exception, gatelib.NotRejected)
            self.assertIn("did not finish in time", str(caught.exception))

    def test_gate_killed_by_a_signal_is_no_verdict(self):
        """A gate that a signal ended (the kernel's OOM killer, a `kill`) gave no
        verdict: that is a fault of the run, not a rejection and not an acceptance."""
        result = constructed(self, "import os, signal\n"
                                   "print('FAIL  T9999/x.yml :: near-miss  n: the analysis "
                                   "grades it trivial', flush=True)\n"
                                   "os.kill(os.getpid(), signal.SIGKILL)\n")
        self.assertEqual(result.returncode, -9)
        self.assertIn("grades it trivial", result.stdout)       # the reason is in the output
        for check in (lambda: gatelib.assert_rejects(result, REASON),
                      lambda: gatelib.assert_accepts(result, "grades it trivial")):
            with self.assertRaises(AssertionError) as caught:
                check()
            self.assertNotIsInstance(caught.exception, gatelib.NotRejected)
            self.assertIn("the gate was killed by signal 9", str(caught.exception))

    def test_accepts_needs_exit_0_and_a_proof(self):
        gatelib.assert_accepts(constructed(self, ACCEPTING), r"All cases hold \(3 rule file")
        with self.assertRaisesRegex(AssertionError, "nothing shows what it checked"):
            gatelib.assert_accepts(constructed(self, ACCEPTING), r"All cases hold \(85 rule file")
        with self.assertRaisesRegex(AssertionError, "REJECTED a tree"):
            gatelib.assert_accepts(constructed(self, REJECTING), r"FAILED")

    def test_saw(self):
        result = constructed(self, ACCEPTING)
        gatelib.assert_saw(result, r"3 rule file")
        with self.assertRaisesRegex(AssertionError, "nothing shows that the gate read"):
            gatelib.assert_saw(result, r"T9999/planted\.yml")

    def test_failure_text_cannot_be_a_workflow_command(self):
        result = constructed(self, "import sys\nprint('::error title=x::boom')\nsys.exit(1)\n")
        text = result.describe()
        self.assertIn("::error title=x::boom", text)
        self.assertFalse([line for line in text.splitlines() if line.lstrip().startswith("::")])


class KnownGap(unittest.TestCase):
    """@known_gap: green while the gap exists, red when it closes or changes shape,
    and never green for a broken test."""

    def marked(self, source, today="accepts", body=None):
        registry = {}

        @gatelib.known_gap("constructed-gap", gate="gate.py", closes="R7", today=today,
                           reason="A constructed gate accepts a trivial near-miss.",
                           _registry=registry)
        def test(case):
            if body is not None:
                return body(case)
            gatelib.assert_rejects(constructed(case, source), REASON)

        return test, registry["constructed-gap"]

    def test_passes_while_the_gate_accepts(self):
        test, gap = self.marked(ACCEPTING)
        self.assertEqual(gap.state, "not run")
        test(self)
        self.assertEqual(gap.state, "open")

    def test_fails_loudly_when_the_gate_starts_to_reject(self):
        test, gap = self.marked(REJECTING)
        with self.assertRaisesRegex(AssertionError, "KNOWN GAP CLOSED: constructed-gap") as caught:
            test(self)
        self.assertIn("Remove the @gatelib.known_gap marker", str(caught.exception))
        self.assertEqual(gap.state, "not run")

    def test_fails_when_the_gap_changes_shape(self):
        test, _gap = self.marked(OTHER_REASON)       # recorded: accepts; now: wrong-reason
        with self.assertRaisesRegex(AssertionError, "KNOWN GAP CHANGED SHAPE") as caught:
            test(self)
        self.assertIn("'wrong-reason'", str(caught.exception))
        test, _gap = self.marked(ACCEPTING, today="crash")
        with self.assertRaisesRegex(AssertionError, "KNOWN GAP CHANGED SHAPE"):
            test(self)

    def test_each_recorded_shape_passes(self):
        for source, today in ((OTHER_REASON, "wrong-reason"), (CRASHING, "crash")):
            test, gap = self.marked(source, today=today)
            test(self)
            self.assertEqual(gap.state, "open")

    def test_broken_test_is_not_an_open_gap(self):
        def missing_artifact(case):
            tree = gatelib.Tree(())
            case.addCleanup(tree.cleanup)
            tree.plant("no/such/artifact.yml", "x.yml")

        test, gap = self.marked(None, body=missing_artifact)
        with self.assertRaises(FileNotFoundError):
            test(self)

        def gate_did_not_read_the_artifact(case):
            result = constructed(case, ACCEPTING)
            gatelib.assert_saw(result, r"T9999/planted\.yml")
            gatelib.assert_rejects(result, REASON)

        test, gap = self.marked(None, body=gate_did_not_read_the_artifact)
        with self.assertRaisesRegex(AssertionError, "a failure here is not the gap"):
            test(self)
        self.assertEqual(gap.state, "not run")

    def test_marker_needs_a_reason_a_roadmap_item_and_a_unique_id(self):
        ok = dict(gate="gate.py", reason="A constructed gate accepts a trivial near-miss.",
                  closes="R7", _registry={})
        for change, message in (
                (dict(closes="R99"), "not a roadmap item"),
                (dict(closes=""), "not a roadmap item"),
                # Every gap names a roadmap item: `unplanned` is not a value, and R2 is
                # the suite itself.
                (dict(closes="unplanned"), "`unplanned` is not a value"),
                (dict(closes="R2"), "not a roadmap item"),
                (dict(reason="todo"), "give a reason"),
                (dict(gate=" "), "name the gate"),
                # The gate goes into a code span of a Markdown table cell.
                (dict(gate="lint-trr.yml, step `Lint TRRs`"), "holds a backtick"),
                (dict(gate="gate.py --check | tee"), "holds a backtick"),
                (dict(gate="gate.py\n--check"), "holds a backtick"),
                (dict(today="skipped"), "is not one of")):
            with self.assertRaisesRegex(ValueError, message):
                gatelib.known_gap("constructed-gap", **{**ok, **change})
        self.assertEqual(ok["_registry"], {})       # a refused marker registers nothing
        with self.assertRaisesRegex(ValueError, "lower-case letters"):
            gatelib.known_gap("Constructed Gap", **ok)
        gatelib.known_gap("constructed-gap", **ok)(lambda case: None)
        with self.assertRaisesRegex(ValueError, "used twice"):
            gatelib.known_gap("constructed-gap", **ok)(lambda case: None)

    def test_same_test_registered_twice_is_one_gap(self):
        """unittest can import one test module under two names; that is not a duplicate."""
        registry = {}
        ok = dict(gate="gate.py", reason="A constructed gate accepts a trivial near-miss.",
                  closes="R7", _registry=registry)

        def test(case):
            pass

        gatelib.known_gap("constructed-gap", **ok)(test)
        gatelib.known_gap("constructed-gap", **ok)(test)
        self.assertEqual(list(registry), ["constructed-gap"])

    def test_report_prints_every_registered_gap(self):
        registry = {}
        gaps = (("gap-one", "R7", "accepts"), ("gap-two", "R2d", "crash"))
        for gap_id, closes, today in gaps:
            gatelib.known_gap(gap_id, gate=f"{gap_id}.py", closes=closes, today=today,
                              reason=f"The constructed gate of {gap_id} accepts | rejects nothing.",
                              _registry=registry)(lambda case: None)
        text = gatelib.gap_report(registry)
        table = gatelib.gap_report(registry, markdown=True)
        self.assertIn("Known gaps of the gates: 2", text)
        for gap_id, closes, today in gaps:
            self.assertRegex(text, rf"(?s)  {gap_id}\n.*today:  {today}\n\s+closes: {closes} \(")
            self.assertIn(f"| `{gap_id}` | `{gap_id}.py` | {today} | {closes} | ", table)
        self.assertIn("accepts \\| rejects nothing", table)      # a `|` cannot break the table
        # Every row of the table has the cells of the heading row, and no more.
        rows = [line for line in table.splitlines() if line.startswith("|")]
        self.assertEqual(len(rows), 2 + len(gaps))
        self.assertEqual({len(line.replace("\\|", "").split("|")) for line in rows}, {7})

    @staticmethod
    def markers_in_the_sources():
        """{gap ID: `module.Class.test`} for each known_gap marker on a test method of
        a test module (detections/tests/test_*.py), read from the source text with
        ast: a list that does not depend on the discovery of the tests (_discover())."""
        markers = {}
        for path in sorted(glob.glob(os.path.join(gatelib.TESTS, "test_*.py"))):
            module = os.path.basename(path)[:-len(".py")]
            with open(path, encoding="utf-8") as fh:
                source = ast.parse(fh.read(), path)
            for cls in (node for node in source.body if isinstance(node, ast.ClassDef)):
                for method in (node for node in cls.body if isinstance(node, ast.FunctionDef)):
                    for marker in method.decorator_list:
                        if (isinstance(marker, ast.Call)
                                and isinstance(marker.func, ast.Attribute)
                                and marker.func.attr == "known_gap"
                                and isinstance(marker.func.value, ast.Name)
                                and marker.func.value.id == "gatelib"):
                            markers[marker.args[0].value] = f"{module}.{cls.name}.{method.name}"
        return markers

    def test_command_line_lists_the_gaps_of_every_test_module(self):
        """KNOWN_GAPS is the one list of the suite: `gatelib.py --gaps` imports every
        test module and prints each marker with a roadmap item."""
        listed = subprocess.run(
            [gatelib.PYTHON, os.path.join(gatelib.TESTS, "gatelib.py"), "--gaps", "--json"],
            capture_output=True, text=True, timeout=60, cwd=gatelib.REPO,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(listed.returncode, 0, listed.stderr)
        gaps = json.loads(listed.stdout)
        # The command lists each marker of each test module, on its test: the markers
        # in the source text (a property of the list, not one gap, which a later change
        # can close; and not the list of the same discovery that the command uses).
        markers = self.markers_in_the_sources()
        self.assertGreater(len(markers), 0, "no test module has a known gap: vacuous")
        self.assertEqual({gap["id"]: gap["test"] for gap in gaps}, markers)
        for gap in gaps:
            self.assertIn(gap["closes"], gatelib.ROADMAP)
            self.assertNotRegex(gap["gate"], r"[`|]")
            self.assertIn(gap["today"], gatelib.GAP_KINDS)
            self.assertGreaterEqual(len(gap["reason"]), 20)
            self.assertEqual(gap["state"], "not run")


class Trees(unittest.TestCase):

    def test_copies_the_named_parts_only_and_no_bytecode(self):
        tree = gatelib.Tree((".github/scripts", "detections/*_cases.py", "AGENTS.md"))
        self.addCleanup(tree.cleanup)
        self.assertTrue(tree.exists(".github/scripts/trr_lint.py"))
        self.assertTrue(tree.exists("detections/rule_cases.py"))        # from the glob
        self.assertTrue(tree.exists("AGENTS.md"))
        self.assertFalse(tree.exists(".github/workflows"))
        self.assertFalse(tree.exists("detections/sigma_eval.py"))
        self.assertEqual(tree.glob("**/__pycache__") + tree.glob("**/*.pyc"), [])
        with open(os.path.join(gatelib.REPO, "AGENTS.md"), encoding="utf-8") as fh:
            self.assertEqual(tree.read("AGENTS.md"), fh.read())
        with self.assertRaises(FileNotFoundError):
            gatelib.Tree(("detections/no_such_part",))
        with self.assertRaises(FileNotFoundError):
            gatelib.Tree(("detections/no_such_*.py",))

    def test_whole_checkout_is_the_default(self):
        tree = gatelib.Tree()
        self.addCleanup(tree.cleanup)
        for rel in ("AGENTS.md", "detections/rule_cases.py", ".github/workflows/lint-trr.yml",
                    "research/index.json", "detections/tests/gatelib.py"):
            self.assertTrue(tree.exists(rel), rel)
        self.assertFalse(tree.exists(".git"))
        self.assertEqual(tree.glob("**/__pycache__"), [])

    def test_copy_is_not_linked_to_the_repository(self):
        tree = gatelib.Tree(("AGENTS.md", ".github/scripts"))
        self.addCleanup(tree.cleanup)
        for rel in ("AGENTS.md", ".github/scripts/trr_lint.py"):
            copy, real = os.stat(tree.path(rel)), os.stat(os.path.join(gatelib.REPO, rel))
            self.assertFalse(os.path.islink(tree.path(rel)))
            self.assertNotEqual((copy.st_dev, copy.st_ino), (real.st_dev, real.st_ino))
        self.assertFalse(os.path.islink(tree.path(".github/scripts")))

    def test_cleanup_removes_the_sandbox(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)       # also when an assertion below fails
        tree.write("a/b.txt", "x\n")
        self.assertTrue(os.path.isdir(tree.sandbox))
        tree.cleanup()
        self.assertFalse(os.path.exists(tree.sandbox))
        with gatelib.Tree(()) as other:
            sandbox = other.sandbox
        self.assertFalse(os.path.exists(sandbox))

    def test_paths_cannot_leave_the_copy(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        for rel in ("../x", "a/../../x", "/etc/passwd", gatelib.REPO + "/AGENTS.md"):
            with self.assertRaises(ValueError):
                tree.write(rel, "x")
        os.symlink(gatelib.REPO, tree.path("link"))
        with self.assertRaisesRegex(ValueError, "resolves outside the copy"):
            tree.write("link/planted.txt", "x")
        self.assertFalse(os.path.exists(os.path.join(gatelib.REPO, "planted.txt")))

    def test_planting_must_change_the_copy(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        tree.write("f.txt", "alpha beta alpha\n")
        with self.assertRaisesRegex(ValueError, "changed nothing"):
            tree.edit("f.txt", lambda text: text)
        # The text of a replace() is an anchor in the file. The message names the file
        # and the text, and says what to do when a change to the file removed it.
        with self.assertRaisesRegex(ValueError, r"^replace\('f\.txt'\): 'gamma' occurs 0 time\(s\), "
                                    r"wanted 1\. .* the test is out of date: correct the test "
                                    r"\(detections/tests/README\.md, Limits\)$"):
            tree.replace("f.txt", "gamma", "delta")
        with self.assertRaisesRegex(ValueError, "occurs 2 time"):
            tree.replace("f.txt", "alpha", "x", count=3)
        tree.replace("f.txt", "alpha", "x")
        self.assertEqual(tree.read("f.txt"), "x beta alpha\n")
        tree.replace("f.txt", "a", "A", count=0)
        self.assertEqual(tree.read("f.txt"), "x betA AlphA\n")
        tree.write("d.json", '{"rules": {"a": 1}}\n')
        with self.assertRaisesRegex(ValueError, "changed nothing"):
            tree.edit_json("d.json", lambda data: None)
        tree.edit_json("d.json", lambda data: data["rules"].update(a=2))
        self.assertEqual(tree.read_json("d.json"), {"rules": {"a": 2}})
        with self.assertRaises(FileNotFoundError):
            tree.plant("no/such/artifact.yml", "x.yml")
        with self.assertRaises(FileNotFoundError):
            tree.plant("../gatelib.py", "x.py")

    def test_plant_file_directory_and_append(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        tree.plant("gatelib/case.jsonl", "sigma/T9999/.renamed.cases.jsonl")
        self.assertEqual([row["name"] for row in tree.read_jsonl("sigma/T9999/.renamed.cases.jsonl")],
                         ["planted-case"])
        tree.plant("gatelib/pair", "sigma/T9998")
        self.assertEqual(tree.glob("sigma/T9998/*"),
                         ["sigma/T9998/planted.cases.jsonl", "sigma/T9998/planted.yml"])
        tree.write("side.cases.jsonl", '{"name": "first"}')        # no final newline
        tree.plant("gatelib/case.jsonl", "side.cases.jsonl", append=True)
        self.assertEqual([row["name"] for row in tree.read_jsonl("side.cases.jsonl")],
                         ["first", "planted-case"])
        with self.assertRaisesRegex(ValueError, "needs a file artifact"):
            tree.plant("gatelib/pair", "sigma/T9997", append=True)

    def test_gate_environment_is_fenced(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        tree.write("gate.py", "import json, os, sys, tempfile\n"
                              "print(json.dumps({'env': dict(os.environ), 'cwd': os.getcwd(),\n"
                              "                  'tmp': tempfile.gettempdir(), 'exe': sys.executable,\n"
                              "                  'bytecode': sys.dont_write_bytecode}))\n")
        leaked = {"GITHUB_ACTIONS": "true", "GITHUB_TOKEN": "t", "GH_TOKEN": "t",
                  "GITHUB_REPOSITORY": "o/r", "TRR9002_POD": "x", "PYTHONPATH": "/nowhere",
                  "PYTHON_COLORS": "1", "DETENG_GATES_OPEN_GAPS": "/nowhere/gaps"}
        old = {name: os.environ.get(name) for name in leaked}
        os.environ.update(leaked)
        try:
            seen = json.loads(tree.run("gate.py").stdout)
        finally:
            for name, value in old.items():
                os.environ.pop(name, None) if value is None else os.environ.__setitem__(name, value)
        for name in leaked:
            self.assertNotIn(name, seen["env"])
        self.assertEqual(seen["cwd"], tree.root)
        self.assertEqual(seen["tmp"], tree.tmp)
        self.assertEqual(seen["env"]["HOME"], tree.home)
        self.assertEqual(seen["exe"], gatelib.PYTHON)
        self.assertTrue(seen["bytecode"])
        self.assertEqual(seen["env"]["HTTPS_PROXY"], "http://127.0.0.1:9")
        self.assertEqual(seen["env"]["NO_COLOR"], "1")
        self.assertEqual(json.loads(tree.run("gate.py", env={"TRR9002_POD": "y"}).stdout)
                         ["env"]["TRR9002_POD"], "y")

    def test_gate_cannot_reach_the_network(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        result = tree.run_python(
            "import urllib.request\n"
            "urllib.request.urlopen('https://api.github.com/', timeout=5)\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr, r"URLError|ConnectionRefusedError|OSError")
        self.assertLess(result.seconds, 5)

    def test_background_runs(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        tree.write("gate.py", ACCEPTING)
        pending = [tree.start("gate.py") for _ in range(3)]
        pending.append(tree.start_step(gatelib.Step("w.yml", "job", "step", "bash",
                                                    "python3 gate.py\n")))
        for run in pending:
            gatelib.assert_accepts(run.result(), r"All cases hold")
        with self.assertRaises(FileNotFoundError):
            tree.start("no_such_gate.py")
        # What a background call raises comes out of result(), in the caller.
        with self.assertRaisesRegex(ZeroDivisionError, "division"):
            gatelib.background(lambda: 1 / 0).result()
        self.assertEqual(gatelib.background(lambda a, b=0: a + b, 1, b=2).result(), 3)

    # Linux refuses to run a file that a process holds open for writing ("Text file
    # busy"), and a child holds each open file of its parent until it runs its own
    # program. A run in the background starts children while another thread writes the
    # programs of a step, so each start of a child takes a lock until the child runs
    # its program, and write_program() writes under the same lock. Each test below
    # holds the lock, or tries to take it, and shows that the other side waits. No
    # test depends on how fast the machine is: a slow machine can only make a test pass
    # that should fail.

    def test_no_child_process_starts_while_a_program_is_written(self):
        """Each start of a child process (subprocess.run here) waits for the lock."""
        codes = []
        child = threading.Thread(target=lambda: codes.append(
            subprocess.run([sys.executable, "-c", "pass"]).returncode))
        with gatelib._EXEC_LOCK:
            child.start()
            child.join(0.5)
            self.assertTrue(child.is_alive())
            self.assertEqual(codes, [])
        child.join(60)
        self.assertEqual(codes, [0])

    def test_the_start_keeps_the_lock_until_the_child_runs_its_program(self):
        """Until the child runs its own program, it holds the open files of its parent,
        so the start must keep the lock until then, not only take it. The child here
        tells the test that it has started, and runs python only when the test lets it."""
        started_read, started_write = os.pipe()
        go_read, go_write = os.pipe()
        for fd in (started_read, started_write, go_read, go_write):
            self.addCleanup(os.close, fd)

        def before_the_program():                   # runs in the child
            os.write(started_write, b"started")
            os.read(go_read, 1)                     # waits for the test

        codes = []
        child = threading.Thread(target=lambda: codes.append(subprocess.run(
            [sys.executable, "-c", "pass"], preexec_fn=before_the_program).returncode),
            daemon=True)
        child.start()
        self.addCleanup(child.join, 60)
        self.addCleanup(os.write, go_write, b"g")   # first cleanup: also when a check fails
        ready, _, _ = select.select([started_read], [], [], 60)
        self.assertTrue(ready, "the child did not start in 60 s")
        self.assertEqual(os.read(started_read, 7), b"started")
        free = gatelib._EXEC_LOCK.acquire(timeout=0.3)
        if free:
            gatelib._EXEC_LOCK.release()
        self.assertFalse(free, "the lock was free before the child ran its program")
        os.write(go_write, b"g")
        child.join(60)
        self.assertEqual(codes, [0])

    def test_a_second_load_of_the_module_keeps_the_one_lock(self):
        """gatelib.py --run runs this module as __main__, and a test imports it again as
        gatelib: the second load must use the lock of the first and must not wrap the
        start of a child twice."""
        probe = ("import importlib.util, subprocess, sys\n"
                 "sys.path.insert(0, sys.argv[1])\n"
                 "import gatelib\n"
                 "spec = importlib.util.spec_from_file_location('gatelib_again', "
                 "gatelib.__file__)\n"
                 "again = importlib.util.module_from_spec(spec)\n"
                 "spec.loader.exec_module(again)\n"
                 "start = subprocess.Popen._execute_child\n"
                 "print(again._EXEC_LOCK is gatelib._EXEC_LOCK,\n"
                 "      start.gatelib_exec_lock is gatelib._EXEC_LOCK,\n"
                 "      hasattr(start.__wrapped__, 'gatelib_exec_lock'))\n")
        done = subprocess.run([sys.executable, "-B", "-c", probe, gatelib.TESTS],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual((done.returncode, done.stdout), (0, "True True False\n"),
                         done.stderr)

    def test_write_program_waits_while_a_child_process_starts(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        path = tree.path("stub")
        writer = threading.Thread(target=gatelib.write_program,
                                  args=(path, "#!/bin/sh\necho stub output\n"))
        with gatelib._EXEC_LOCK:
            writer.start()
            writer.join(0.5)
            self.assertTrue(writer.is_alive())
            self.assertFalse(os.path.exists(path))
        writer.join(60)
        self.assertFalse(writer.is_alive())
        ran = tree.run_command([path])
        self.assertEqual((ran.returncode, ran.stdout), (0, "stub output\n"), ran.describe())

    def test_run_step_writes_the_programs_of_the_step_under_the_lock(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        step = gatelib.Step("w.yml", "job", "step", "bash", "python3 -c 'print(1)'\nstub\n")
        with gatelib._EXEC_LOCK:
            pending = tree.start_step(step, programs={"stub": "echo stub output"})
            time.sleep(0.5)
            self.assertFalse(pending.done())
            self.assertEqual(glob.glob(os.path.join(tree.sandbox, "**", "bin", "*"),
                                       recursive=True), [])
        ran = pending.result()
        self.assertEqual((ran.returncode, ran.stdout), (0, "1\nstub output\n"), ran.describe())

    def test_cleanup_waits_for_a_background_run(self):
        """No copy is deleted under a running gate: cleanup() waits for the runs that
        nobody collected."""
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)       # also when an assertion below fails
        tree.write("gate.py", "import time\ntime.sleep(0.5)\n" + ACCEPTING)
        slow = tree.start("gate.py")
        self.assertFalse(slow.done())
        tree.cleanup()
        self.assertTrue(slow.done())
        self.assertFalse(os.path.exists(tree.sandbox))
        gatelib.assert_accepts(slow.result(), r"All cases hold")

    def test_tmp_path_is_tmp_of_a_gate_and_of_a_step(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        with open(tree.tmp_path("captured.log"), "w", encoding="utf-8") as fh:
            fh.write("one record\n")
        tree.write("gate.py", "import os, tempfile\n"
                              "print(open(os.path.join(tempfile.gettempdir(), 'captured.log')).read())\n")
        gatelib.assert_accepts(tree.run("gate.py"), r"^one record$")
        step = gatelib.Step("w.yml", "job", "step", "bash", "cat /tmp/captured.log\n")
        gatelib.assert_accepts(tree.run_step(step), r"^one record$")
        for name in ("/etc/passwd", "../x"):
            with self.assertRaises(ValueError):
                tree.tmp_path(name)


class Workflows(unittest.TestCase):

    def test_ci_commands_are_the_lines_that_run_the_script(self):
        self.assertEqual(gatelib.ci_commands("detections/rule_cases.py"),
                         ["python3 detections/rule_cases.py | tee /tmp/rule-cases.out"])
        joined = gatelib.ci_commands("detections/check_sufficiency.py")
        self.assertIn('python3 detections/check_sufficiency.py --markdown "$GITHUB_STEP_SUMMARY" '
                      '| tee /tmp/sufficiency.out', joined)
        self.assertEqual(gatelib.ci_commands("detections/no_such_gate.py"), [])

    def test_step_shell_decides_if_a_pipe_keeps_the_exit_code(self):
        """run_step models the two shells of GitHub Actions: `bash -e` (no `shell:`)
        loses the exit code of `gate | tee`, and `shell: bash` (pipefail) keeps it."""
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        tree.write("gate.py", REJECTING)
        run = "python3 gate.py | tee /tmp/gate.out\n"
        masked = tree.run_step(gatelib.Step("w.yml", "job", "step", None, run))
        kept = tree.run_step(gatelib.Step("w.yml", "job", "step", "bash", run))
        self.assertEqual((masked.returncode, kept.returncode), (0, 1))
        for result in (masked, kept):
            self.assertIn("FAILED: 1 case problem(s).", result.stdout)
        # Both shells have -e: a command that fails ends the step, also when it is
        # not the last line. Without -e the step would take the exit code of `echo`.
        for shell in (None, "bash"):
            ended = tree.run_step(gatelib.Step("w.yml", "job", "step", shell,
                                               "python3 gate.py\necho after the gate\n"))
            self.assertEqual(ended.returncode, 1, ended.describe())
            self.assertIn("FAILED: 1 case problem(s).", ended.stdout)
            self.assertNotIn("after the gate", ended.stdout)
        # /tmp/ of the step is the sandbox's tmp directory, not the machine's.
        with open(os.path.join(tree.tmp, "gate.out"), encoding="utf-8") as fh:
            self.assertIn("FAILED: 1 case problem(s).", fh.read())
        with self.assertRaisesRegex(ValueError, "give a value for every"):
            tree.run_step(gatelib.Step("w.yml", "job", "step", "bash", "echo ${{ github.sha }}\n"))
        told = tree.run_step(gatelib.Step("w.yml", "job", "step", "bash",
                                          'echo "base=${{ github.sha }}" >> "$GITHUB_OUTPUT"\n'),
                             expressions={"github.sha": "abc123"})
        self.assertEqual(told.returncode, 0)
        with open(tree.out("github/github_output"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "base=abc123\n")

    def test_step_programs(self):
        """A step gets the tests' Python, and a `pip` that installs nothing. They stay
        first on PATH when the test gives a PATH; programs= adds or replaces one."""
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        tree.write("requirements.txt", "no-such-package-of-the-gate-tests==9.9\n")
        step = gatelib.Step("w.yml", "job", "step", "bash",
                            "pip install --quiet -r requirements.txt\n"
                            "python3 -c 'import sys; print(sys.executable)'\n"
                            "command -v python3 pip\n")
        for env in (None, {"PATH": "/usr/bin:/bin"}):
            result = tree.run_step(step, env=env)
            self.assertEqual(result.returncode, 0, result.describe())
            lines = result.stdout.splitlines()
            self.assertEqual(lines[0], gatelib.PYTHON)
            self.assertEqual({os.path.dirname(line) for line in lines[1:]},
                             {os.path.dirname(lines[1])})
            self.assertTrue(lines[1].startswith(tree.sandbox + os.sep), lines)
        replaced = tree.run_step(step, programs={"pip": 'echo "pip $*"; exit 3'})
        self.assertEqual(replaced.returncode, 3, replaced.describe())
        self.assertEqual(replaced.stdout, "pip install --quiet -r requirements.txt\n")
        added = tree.run_step(gatelib.Step("w.yml", "job", "step", None, "kubectl get pods\n"),
                              programs={"kubectl": 'echo "kubectl $*"'})
        self.assertEqual((added.returncode, added.stdout), (0, "kubectl get pods\n"))
        with self.assertRaisesRegex(ValueError, "not a program name"):
            tree.run_step(step, programs={"../pip": "exit 0"})

    def test_ci_step_finds_one_step(self):
        step = gatelib.ci_step("detection-quality.yml", "rule-cases", "detections/rule_cases.py")
        self.assertEqual(step.shell, "bash")
        with self.assertRaises(LookupError):
            gatelib.ci_step("detection-quality.yml", "rule-cases", "detections/no_such_gate.py")

    def test_ci_step_is_chosen_by_a_command_line(self):
        """Two steps of a job can name one script. More of the command line tells them
        apart; a comment and a list of paths do not make a step `the step that runs`."""
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        tree.write(".github/workflows/w.yml", """\
name: w
on: [push]
jobs:
  job:
    runs-on: ubuntu-latest
    steps:
      - name: Decide
        run: |
          patterns=$(printf '%s\\n' \\
            'detections/gate.py' \\
            'detections/sigma/')
      - name: Self-test
        run: python3 detections/gate.py --self-test
      - name: Check
        shell: bash
        run: |
          # python3 detections/gate.py --self-test runs in the step above.
          python3 detections/gate.py --check \\
            --markdown "$GITHUB_STEP_SUMMARY" | tee /tmp/gate.out
""")

        def step(command):
            return gatelib.ci_step("w.yml", "job", command, root=tree.root)

        with self.assertRaisesRegex(LookupError, r"3 step\(s\) have a command line"):
            step("detections/gate.py")
        self.assertEqual(step("python3 detections/gate.py --self-test").name, "Self-test")
        check = step("python3   detections/gate.py --check --markdown")     # the joined line
        self.assertEqual((check.name, check.shell), ("Check", "bash"))
        self.assertEqual(step("tee /tmp/gate.out").name, "Check")
        self.assertEqual(gatelib.ci_commands("detections/gate.py", root=tree.root), [
            "python3 detections/gate.py --self-test",
            'python3 detections/gate.py --check --markdown "$GITHUB_STEP_SUMMARY" '
            "| tee /tmp/gate.out"])
        with self.assertRaisesRegex(LookupError, r"0 step\(s\)"):
            step("python3 detections/gate.py --update")

    def test_ci_step_refuses_a_step_that_cannot_fail_its_job(self):
        """`continue-on-error` on a step leaves its job green when the step fails, and
        on a job it leaves the workflow run green. Tree.run_step() runs only the
        text of the step, so ci_step() does not give such a step to a test."""
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        tree.write(".github/workflows/w.yml", """\
name: w
on: [push]
jobs:
  hard:
    runs-on: ubuntu-latest
    steps:
      - name: Check
        run: python3 detections/gate.py --check
      - name: Shadow
        continue-on-error: true
        run: python3 detections/gate.py --shadow
      - name: Strict
        continue-on-error: false
        run: python3 detections/gate.py --strict
  soft:
    runs-on: ubuntu-latest
    continue-on-error: ${{ matrix.experimental }}
    steps:
      - name: Check
        run: python3 detections/gate.py --check
""")
        self.assertEqual([(step.job, step.name, step.soft)
                          for step in gatelib.ci_steps(root=tree.root)],
                         [("hard", "Check", False), ("hard", "Shadow", True),
                          ("hard", "Strict", False), ("soft", "Check", True)])
        # A Step that a test constructs with five values is not soft.
        self.assertFalse(gatelib.Step("w.yml", "job", "step", None, "true\n").soft)

        def step(job, command):
            return gatelib.ci_step("w.yml", job, command, root=tree.root)

        # CONTROL: the steps of the same file that can fail their job are found.
        self.assertEqual(step("hard", "--check").name, "Check")
        self.assertEqual(step("hard", "--strict").name, "Strict")
        for job, command, name in (("hard", "--shadow", "Shadow"), ("soft", "--check", "Check")):
            with self.assertRaisesRegex(
                    LookupError, rf"^w\.yml, job {job}, step '{name}': the step or its job has "
                                 r"`continue-on-error`, so a gate that fails there leaves the "
                                 r"job \(for a step\) or the workflow run \(for a job\) green$"):
                step(job, command)


class Runner(unittest.TestCase):
    """`gatelib.py --run`: the parallel runner must fail when any class fails, when a
    class did not run all of its tests, when a test module does not import, and when
    a run of the whole suite did not run the test of a known gap."""

    def suite(self):
        tree = gatelib.Tree(("detections/tests/gatelib.py",))
        self.addCleanup(tree.cleanup)
        tree.write("detections/tests/test_one.py",
                   "import unittest\n\n\n"
                   "class Good(unittest.TestCase):\n"
                   "    def test_a(self):\n        pass\n\n"
                   "    def test_b(self):\n        pass\n\n\n"
                   "class AlsoGood(unittest.TestCase):\n"
                   "    def test_c(self):\n        pass\n")
        return tree

    def test_green_suite(self):
        result = self.suite().run("detections/tests/gatelib.py", "--run", "--jobs", "2")
        gatelib.assert_accepts(result, r"^2 test class\(es\), 3 test\(s\), 2 at a time")
        # The line of each class: its verdict, its tests, its wall seconds and its CPU
        # seconds (_ONE_CLASS writes them).
        self.assertRegex(result.stdout, r"(?m)^===== test_one\.Good: ok, 2 test\(s\), "
                                        r"[0-9]+\.[0-9] s \(CPU [0-9]+\.[0-9] s\)$")
        self.assertRegex(result.stdout, r"(?m)^===== test_one\.AlsoGood: ok, 1 test\(s\), "
                                        r"[0-9]+\.[0-9] s \(CPU [0-9]+\.[0-9] s\)$")
        self.assertRegex(result.stdout, r"(?m)^OK$")

    def test_the_cpu_seconds_of_a_class_are_a_finite_number_of_0_or_more(self):
        """The runner reads the CPU seconds of a class from its counts file. A value
        that is not a finite number of 0 or more, no value, and no counts (a class
        that was stopped, or whose process died) give None: `CPU not known`."""
        for counts, cpu in (({"ran": 1, "skipped": 0, "cpu": 1.25}, 1.25), ({"cpu": 0}, 0.0),
                            ({"cpu": 3}, 3.0), ({"ran": 1, "skipped": 0}, None),
                            ({"cpu": -0.5}, None), ({"cpu": "1.5"}, None), ({"cpu": True}, None),
                            ({"cpu": None}, None), ({"cpu": [1.0]}, None),
                            ({"cpu": float("nan")}, None), ({"cpu": float("inf")}, None),
                            ({"cpu": 10 ** 400}, None), ({"cpu": -0.0}, 0.0),
                            ([1.0], None), ("cpu", None), (None, None)):
            with self.subTest(counts=counts):
                self.assertEqual(gatelib._cpu_seconds(counts), cpu)
                if cpu is not None:
                    self.assertIs(type(gatelib._cpu_seconds(counts)), float)
                    # Not -0.0, which prints as `CPU -0.0 s`.
                    self.assertFalse(str(gatelib._cpu_seconds(counts)).startswith("-"))

    def test_a_failing_class_fails_the_run(self):
        tree = self.suite()
        tree.write("detections/tests/test_two.py",
                   "import unittest\n\n\n"
                   "class Bad(unittest.TestCase):\n"
                   "    def test_d(self):\n        self.fail('planted failure')\n")
        result = tree.run("detections/tests/gatelib.py", "--run")
        gatelib.assert_rejects(result, r"^FAILED: 1 test class\(es\): test_two\.Bad$",
                               exit_code=1, crash_ok=True)
        self.assertIn("===== test_two.Bad: FAILED (exit code 1), 1 test(s)", result.stdout)
        self.assertIn("AssertionError: planted failure", result.stdout)
        self.assertIn("===== test_one.Good: ok, 2 test(s)", result.stdout)
        only = tree.run("detections/tests/gatelib.py", "--run", "test_one")
        gatelib.assert_accepts(only, r"^2 test class\(es\), 3 test\(s\)")
        none = tree.run("detections/tests/gatelib.py", "--run", "no_such_class")
        gatelib.assert_rejects(none, r"^no test class matches no_such_class$", exit_code=1)

    def test_a_class_that_does_not_set_up_fails_the_run(self):
        tree = self.suite()
        tree.write("detections/tests/test_two.py",
                   "import unittest\n\n\n"
                   "class Broken(unittest.TestCase):\n"
                   "    @classmethod\n"
                   "    def setUpClass(cls):\n        raise RuntimeError('planted')\n\n"
                   "    def test_d(self):\n        pass\n")
        result = tree.run("detections/tests/gatelib.py", "--run")
        gatelib.assert_rejects(result, r"^FAILED: 1 test class\(es\): test_two\.Broken$",
                               exit_code=1, crash_ok=True)

    def test_a_class_that_runs_fewer_tests_than_were_found_fails_the_run(self):
        """The runner counts the tests of a class before it starts them. A class whose
        process runs fewer of them, and exits 0, did not run all of its tests."""
        tree = self.suite()
        tree.write("detections/tests/test_two.py",
                   "import os\nimport unittest\n\n\n"
                   "class Shrinks(unittest.TestCase):\n"
                   "    def test_d(self):\n        pass\n\n"
                   # The runner sets this variable in the process of a class only.
                   f"    if not os.environ.get({gatelib._OPEN_GAPS_FILE!r}):\n"
                   "        def test_e(self):\n            pass\n")
        result = tree.run("detections/tests/gatelib.py", "--run")
        gatelib.assert_rejects(result, r"^FAILED: 1 test class\(es\): test_two\.Shrinks$",
                               exit_code=1)
        self.assertIn("===== test_two.Shrinks: FAILED (ran 1 of 2 test(s)), 1 test(s)",
                      result.stdout)
        # CONTROL: the class's own process is green, so only the count fails the run.
        # Its counts file also holds its CPU seconds.
        counts = tree.out("counts.json")
        alone = tree.run_command(
            [gatelib.PYTHON, "-c", gatelib._ONE_CLASS, "test_two.Shrinks", counts],
            cwd="detections/tests", env={gatelib._OPEN_GAPS_FILE: os.devnull})
        self.assertEqual(alone.returncode, 0, alone.describe())
        with open(counts, encoding="utf-8") as fh:
            written = json.load(fh)
        self.assertEqual(sorted(written), ["cpu", "ran", "skipped"])
        self.assertEqual((written["ran"], written["skipped"]), (1, 0))
        self.assertIs(type(written["cpu"]), float)
        self.assertGreater(written["cpu"], 0)

    def test_counts_come_from_the_result_of_a_class_and_not_from_its_output(self):
        """The runner reads no line of the text that unittest prints: the format of
        that text differs between Python versions, and a test can print such a line
        itself. The counts are those of the TestResult of the class."""
        tree = self.suite()
        tree.write("detections/tests/test_two.py",
                   "import sys\nimport unittest\n\n\n"
                   "class Prints(unittest.TestCase):\n"
                   "    def test_d(self):\n"
                   "        print('\\nRan 7 tests in 0.001s\\n\\nOK (skipped=3)', file=sys.stderr)\n")
        result = tree.run("detections/tests/gatelib.py", "--run", "--no-skips")
        gatelib.assert_accepts(result, r"^3 test class\(es\), 4 test\(s\), ")
        self.assertRegex(result.stdout, r"(?m)^===== test_two\.Prints: ok, 1 test\(s\), ")
        self.assertRegex(result.stdout, r"(?m)^OK$")
        # The lines of the test are in the output of its class (not vacuous).
        self.assertIn("\n    Ran 7 tests in 0.001s\n", result.stdout)
        self.assertIn("\n    OK (skipped=3)\n", result.stdout)
        # The process of a class that ends without its counts did not run its tests.
        tree.write("detections/tests/test_two.py",
                   "import os\nimport unittest\n\n\n"
                   "class Leaves(unittest.TestCase):\n"
                   "    def test_d(self):\n"
                   f"        if os.environ.get({gatelib._OPEN_GAPS_FILE!r}):\n"
                   "            os._exit(0)\n")
        left = tree.run("detections/tests/gatelib.py", "--run")
        gatelib.assert_rejects(left, r"^FAILED: 1 test class\(es\): test_two\.Leaves$",
                               exit_code=1)
        # It wrote no CPU seconds either.
        self.assertRegex(left.stdout, r"(?m)^===== test_two\.Leaves: FAILED \(ran 0 of 1 "
                                      r"test\(s\)\), 0 test\(s\), [0-9.]+ s \(CPU not known\)$")

    def test_a_class_that_hangs_is_stopped_and_fails_the_run(self):
        """A class that does not end is stopped after --class-timeout seconds. The run
        fails, the output that the class gave until then is printed, the classes
        after it still run, and the summary is written."""
        tree = self.suite()
        tree.write("detections/tests/test_hang.py",
                   "import time\nimport unittest\n\n\n"
                   "class Hangs(unittest.TestCase):\n"
                   "    def test_d(self):\n        pass\n\n"
                   "    def test_e(self):\n        time.sleep(60)\n")
        summary = tree.out("summary.md")
        result = tree.run("detections/tests/gatelib.py", "--run", "--class-timeout", "3",
                          "--summary", summary, timeout=50)
        gatelib.assert_rejects(result, r"^FAILED: 1 test class\(es\): test_hang\.Hangs$",
                               exit_code=1)
        self.assertLess(result.seconds, 40)
        # A class that was stopped wrote no counts: its CPU seconds are not known.
        self.assertRegex(result.stdout, r"(?m)^===== test_hang\.Hangs: FAILED \(stopped after "
                                        r"3 s\), 0 test\(s\), [0-9.]+ s \(CPU not known\)$")
        # The line of unittest for the test that passed: Python 3.10 prints
        # `test_d (test_hang.Hangs) ... ok`, later versions add `.test_d` to the class.
        self.assertRegex(result.stdout, r"(?m)^    test_d \(test_hang\.Hangs\b[^)\n]*\) \.\.\. ok$")
        self.assertIn("    (stopped: the class did not end in 3 s; the output above is what it "
                      "gave until then)", result.stdout)
        self.assertIn("===== test_one.Good: ok, 2 test(s)", result.stdout)
        with open(summary, encoding="utf-8") as fh:
            self.assertRegex(fh.read(), r"(?m)^## Gate tests: FAILED$")
        # CONTROL: with the default timeout the same suite, without the class that
        # hangs, passes; and the default is what the CI job gets (it gives no option).
        gatelib.assert_accepts(tree.run("detections/tests/gatelib.py", "--run", "test_one"),
                               r"^2 test class\(es\), 3 test\(s\), ")
        self.assertEqual(gatelib.run_suite.__defaults__[2], gatelib.CLASS_TIMEOUT)
        refused = tree.run("detections/tests/gatelib.py", "--run", "--class-timeout", "0")
        self.assertEqual(refused.returncode, 2, refused.describe())
        self.assertIn("give a number of seconds above 0", refused.stderr)

    def test_a_module_that_does_not_import_fails_the_run_and_the_gap_list(self):
        tree = self.suite()
        tree.write("detections/tests/test_two.py", "import no_such_module_of_the_suite\n")
        summary = tree.out("summary.md")
        for arguments in (("--run", "--summary", summary), ("--gaps",)):
            result = tree.run("detections/tests/gatelib.py", *arguments)
            gatelib.assert_rejects(result, r"^a test module does not import:", exit_code=1,
                                   crash_ok=True)
            self.assertIn("no_such_module_of_the_suite", result.stderr)
        # No test ran, so run_suite() wrote no summary: the job summary still says
        # that the run failed, and why.
        with open(summary, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "## Gate tests: FAILED\n\nA test module does not "
                             "import, so no test ran. The log of the step holds the error.\n")

    def test_skipped_tests_are_counted_and_no_skips_fails_the_run(self):
        """A skipped test is not a failure, and the run says how many were skipped. With
        --no-skips (the CI job) a skipped test fails the run: in CI every tool is
        installed, so a skip there is lost coverage that would look green."""
        tree = self.suite()
        tree.write("detections/tests/test_two.py",
                   "import unittest\n\n\n"
                   "class OneSkipped(unittest.TestCase):\n"
                   "    def test_d(self):\n        pass\n\n"
                   "    @unittest.skip('planted skip')\n"
                   "    def test_e(self):\n        pass\n\n\n"
                   "class AllSkipped(unittest.TestCase):\n"
                   "    @classmethod\n"
                   "    def setUpClass(cls):\n"
                   "        raise unittest.SkipTest('gcc is not installed')\n\n"
                   "    def test_f(self):\n        pass\n\n"
                   "    def test_g(self):\n        pass\n")
        result = tree.run("detections/tests/gatelib.py", "--run")
        gatelib.assert_accepts(result, r"^4 test class\(es\), 7 test\(s\), ")
        self.assertIn("===== test_two.OneSkipped: ok, 2 test(s) (1 skipped)", result.stdout)
        self.assertIn("===== test_two.AllSkipped: ok, 2 test(s) (2 skipped)", result.stdout)
        self.assertRegex(result.stdout, r"(?m)^3 test\(s\) skipped: test_two\.AllSkipped \(2\), "
                                        r"test_two\.OneSkipped \(1\)$")
        self.assertRegex(result.stdout, r"(?m)^OK$")
        strict = tree.run("detections/tests/gatelib.py", "--run", "--no-skips")
        gatelib.assert_rejects(strict, r"^FAILED: --no-skips is set, and test\(s\) were skipped",
                               exit_code=1)
        self.assertNotRegex(strict.stdout, r"(?m)^OK$")
        # Without a skipped test, --no-skips changes nothing.
        gatelib.assert_accepts(tree.run("detections/tests/gatelib.py", "--run", "--no-skips",
                                        "test_one"), r"^2 test class\(es\), 3 test\(s\), ")

    GAPPY = (
        "import os, sys, unittest\n"
        "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
        "import gatelib\n\n\n"
        "class Gappy(unittest.TestCase):\n"
        "    def run_gate(self, source):\n"
        "        tree = gatelib.Tree(())\n"
        "        self.addCleanup(tree.cleanup)\n"
        "        tree.write('gate.py', source)\n"
        "        return tree.run('gate.py')\n\n"
        "    @gatelib.known_gap('constructed-open-gap', gate='gate.py', closes='R7',\n"
        "                       reason='A constructed gate accepts every artifact.')\n"
        "    def test_gap_open(self):\n"
        "        gatelib.assert_rejects(self.run_gate('print(1)'), r'FAIL')\n\n"
        "    @gatelib.known_gap('constructed-other-gap', gate='other.py', closes='R2d',\n"
        "                       reason='A second constructed gate accepts every artifact.')\n"
        "    def test_gap_other(self):\n"
        "        gatelib.assert_rejects(self.run_gate(GATE), r'FAIL  planted')\n\n\n"
        "GATE = 'print(1)'\n")

    def test_run_reports_the_known_gaps_and_their_state(self):
        """The run prints the one list of known gaps, with the state that the tests of
        this run gave each gap; --summary writes it as Markdown, --json as data."""
        tree = self.suite()
        tree.write("detections/tests/test_gappy.py", self.GAPPY)
        summary = tree.out("summary.md")
        result = tree.run("detections/tests/gatelib.py", "--run", "--summary", summary)
        gatelib.assert_accepts(result, r"^3 test class\(es\), 5 test\(s\), ")
        self.assertRegex(result.stdout, r"(?m)^Known gaps of the gates: 2 ")
        self.assertRegex(result.stdout, r"(?s)\n  constructed-open-gap\n.*?closes: R7 \(.*?"
                                        r"\n      state:  open in this run\n")
        with open(summary, encoding="utf-8") as fh:
            text = fh.read()
        self.assertRegex(text, r"(?m)^## Gate tests: passed$")
        self.assertIn("2 known gap(s), 2 seen open in this run.", text)
        self.assertIn("| `constructed-open-gap` | `gate.py` | accepts | R7 | open | ", text)
        # A class filter runs one module: the gaps of the other are `not run`.
        partly = tree.run("detections/tests/gatelib.py", "--run", "--json", "test_one")
        self.assertEqual(partly.returncode, 0, partly.describe())
        self.assertEqual({gap["id"]: gap["state"] for gap in json.loads(partly.stdout)},
                         {"constructed-open-gap": "not run", "constructed-other-gap": "not run"})
        self.assertRegex(partly.stderr, r"(?m)^2 test class\(es\), 3 test\(s\), ")
        everything = tree.run("detections/tests/gatelib.py", "--run", "--json")
        self.assertEqual({gap["state"] for gap in json.loads(everything.stdout)}, {"open"})

    def test_a_gap_that_closed_fails_the_run_and_the_summary_says_so(self):
        """The loud end of a known gap: its gate starts to reject the artifact, the
        test fails with KNOWN GAP CLOSED, and so does the run."""
        tree = self.suite()
        tree.write("detections/tests/test_gappy.py", self.GAPPY.replace(
            "GATE = 'print(1)'", "GATE = 'import sys; print(\"FAIL  planted\"); sys.exit(1)'"))
        summary = tree.out("summary.md")
        result = tree.run("detections/tests/gatelib.py", "--run", "--summary", summary)
        gatelib.assert_rejects(result, r"^FAILED: 1 test class\(es\): test_gappy\.Gappy$",
                               exit_code=1, crash_ok=True)
        self.assertIn("AssertionError: KNOWN GAP CLOSED: constructed-other-gap. other.py now "
                      "rejects this artifact", result.stdout)
        with open(summary, encoding="utf-8") as fh:
            text = fh.read()
        self.assertRegex(text, r"(?m)^## Gate tests: FAILED$")
        self.assertIn("- FAILED: 1 test class(es): test_gappy.Gappy\n", text)
        self.assertIn("| `constructed-other-gap` | `other.py` | accepts | R2d | not run | ",
                      text)
        self.assertIn("| `constructed-open-gap` | `gate.py` | accepts | R7 | open | ", text)

    NOT_COLLECTED = (
        "import os, sys, unittest\n"
        "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
        "import gatelib\n\n\n"
        "def accepted(case):\n"
        "    tree = gatelib.Tree(())\n"
        "    case.addCleanup(tree.cleanup)\n"
        "    tree.write('gate.py', 'print(1)')\n"
        "    return tree.run('gate.py')\n\n\n"
        "class Collected(unittest.TestCase):\n"
        "    def test_a(self):\n        pass\n\n"
        "    @gatelib.known_gap('gap-on-a-method-that-is-no-test', gate='gate.py', closes='R7',\n"
        "                       reason='A constructed gate accepts every artifact.')\n"
        "    def check_gap_never_collected(self):\n"
        "        gatelib.assert_rejects(accepted(self), r'FAIL')\n\n\n"
        "class Mixin:\n"
        "    @gatelib.known_gap('gap-in-a-class-that-is-no-testcase', gate='gate.py', closes='R7',\n"
        "                       reason='A constructed gate accepts every artifact.')\n"
        "    def test_gap_never_loaded(self):\n"
        "        gatelib.assert_rejects(accepted(self), r'FAIL')\n")
    # The same two markers, on tests that unittest collects.
    COLLECTED = NOT_COLLECTED.replace("def check_gap_never_collected(", "def test_gap_collected(") \
        .replace("class Mixin:\n", "class Mixin(unittest.TestCase):\n")

    def test_a_known_gap_whose_test_did_not_run_fails_a_full_run(self):
        """A marker registers its gap when the module is imported. When unittest does
        not collect the marked method (its name is not `test_...`, or its class is no
        TestCase), no test tests the gap, and the list would still show it. A run of
        the whole suite fails then; every class of it passed. It names the gaps whose
        test did not run, and the gaps whose test no class collects, with the likely
        causes."""
        tree = self.suite()
        tree.write("detections/tests/test_gappy.py", self.NOT_COLLECTED)
        gaps = ["gap-in-a-class-that-is-no-testcase", "gap-on-a-method-that-is-no-test"]
        summary = tree.out("summary.md")
        result = tree.run("detections/tests/gatelib.py", "--run", "--no-skips",
                          "--summary", summary)
        gatelib.assert_rejects(
            result, r"^FAILED: the test of these known gap\(s\) did not run: "
                    r"gap-in-a-class-that-is-no-testcase, gap-on-a-method-that-is-no-test$",
            exit_code=1)
        self.assertRegex(result.stdout, "(?m)^" + re.escape(not_collected(gaps)) + "$")
        self.assertRegex(result.stdout, r"(?m)^3 test class\(es\), 4 test\(s\), ")
        self.assertNotIn("test class(es): ", result.stdout)     # no class failed
        self.assertNotRegex(result.stdout, r"(?m)^OK$")
        self.assertEqual(result.stdout.count("      state:  not run in this run\n"), 2)
        with open(summary, encoding="utf-8") as fh:
            text = fh.read()
        self.assertRegex(text, r"(?m)^## Gate tests: FAILED$")
        self.assertIn("- FAILED: the test of these known gap(s) did not run: "
                      "gap-in-a-class-that-is-no-testcase, gap-on-a-method-that-is-no-test\n", text)
        self.assertIn(f"- {not_collected(gaps)}\n", text)
        # A class that skips in setUpClass, and does not collect the test of a gap,
        # does not excuse the gap: without --no-skips the run fails for it, as before.
        tree.write("detections/tests/test_skipped.py",
                   "import unittest\n\n\n"
                   "class Skipped(unittest.TestCase):\n"
                   "    @classmethod\n"
                   "    def setUpClass(cls):\n"
                   "        raise unittest.SkipTest('gcc is not installed')\n\n"
                   "    def test_s(self):\n        pass\n")
        skipped = tree.run("detections/tests/gatelib.py", "--run")
        gatelib.assert_rejects(
            skipped, r"^FAILED: the test of these known gap\(s\) did not run: "
                     r"gap-in-a-class-that-is-no-testcase, gap-on-a-method-that-is-no-test$",
            exit_code=1)
        self.assertRegex(skipped.stdout, r"(?m)^1 test\(s\) skipped: test_skipped\.Skipped \(1\)$")
        tree.remove("detections/tests/test_skipped.py")
        # A class that fails: the run does not say that the test of a gap did not run
        # (the class that failed can hold it), and it still names the gaps that no
        # class collects.
        tree.write("detections/tests/test_failing.py",
                   "import unittest\n\n\n"
                   "class Failing(unittest.TestCase):\n"
                   "    def test_f(self):\n        self.fail('planted failure')\n")
        failing = tree.run("detections/tests/gatelib.py", "--run")
        gatelib.assert_rejects(failing, r"^FAILED: 1 test class\(es\): test_failing\.Failing$",
                               exit_code=1, crash_ok=True)
        self.assertRegex(failing.stdout, "(?m)^" + re.escape(not_collected(gaps)) + "$")
        self.assertNotIn("did not run", failing.stdout)
        tree.remove("detections/tests/test_failing.py")
        # A class filter runs a part of the suite: a gap that did not run, or that no
        # class collects, is no failure.
        gatelib.assert_accepts(tree.run("detections/tests/gatelib.py", "--run", "test_one"),
                               r"^2 test class\(es\), 3 test\(s\), ")
        # CONTROL: the same markers on tests that unittest collects. The run passes
        # and saw both gaps open.
        tree.write("detections/tests/test_gappy.py", self.COLLECTED)
        collected = tree.run("detections/tests/gatelib.py", "--run", "--no-skips")
        gatelib.assert_accepts(collected, r"^4 test class\(es\), 6 test\(s\), ")
        self.assertEqual(collected.stdout.count("      state:  open in this run\n"), 2)
        self.assertNotIn("no test class collects", collected.stdout)

    def test_a_known_gap_whose_test_was_skipped_is_a_skipped_test(self):
        """A skipped test is not a failure outside CI (--no-skips makes it one). So the
        gap of a test that was skipped is `not run`, and the run does not fail for it
        a second time."""
        tree = self.suite()
        tree.write("detections/tests/test_gappy.py", self.COLLECTED.replace(
            "class Mixin(unittest.TestCase):\n",
            "class Mixin(unittest.TestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls):\n"
            "        raise unittest.SkipTest('gcc is not installed')\n\n"))
        result = tree.run("detections/tests/gatelib.py", "--run")
        gatelib.assert_accepts(result, r"^4 test class\(es\), 6 test\(s\), ")
        self.assertRegex(result.stdout, r"(?m)^1 test\(s\) skipped: test_gappy\.Mixin \(1\)$")
        self.assertRegex(result.stdout, r"(?s)\n  gap-in-a-class-that-is-no-testcase\n.*?"
                                        r"\n      state:  not run in this run\n")
        self.assertRegex(result.stdout, r"(?s)\n  gap-on-a-method-that-is-no-test\n.*?"
                                        r"\n      state:  open in this run\n")
        self.assertNotIn("did not run", result.stdout)
        strict = tree.run("detections/tests/gatelib.py", "--run", "--no-skips")
        gatelib.assert_rejects(strict, r"^FAILED: --no-skips is set, and test\(s\) were skipped",
                               exit_code=1)
        self.assertNotIn("did not run", strict.stdout)

    def test_options_of_the_run_need_run(self):
        tree = self.suite()
        for option in (("--no-skips",), ("--class-timeout", "5"), ("--jobs", "2"),
                       ("--summary", tree.out("summary.md")), ("test_one",), ("--shard", "1/2")):
            result = tree.run("detections/tests/gatelib.py", "--gaps", *option)
            self.assertEqual(result.returncode, 2, result.describe())
            self.assertIn("need --run", result.stderr)


class Shards(unittest.TestCase):
    """`gatelib.py --run --shard K/N` on a constructed suite of five classes and a
    constructed table of class weights. A run of shard K runs exactly the classes of
    shard K, the heaviest first, and prints them in the order of discovery. Its
    summary line gives the CPU seconds of its classes: the sum of the CPU seconds of
    their lines, also when they run at the same time, and the number of the classes
    whose CPU is not known. It counts the known gaps whose test a class of shard K
    collects (also a test that a class inherits from a mixin), and those whose test
    no class of the suite collects; a gap whose test only the classes of other
    shards collect does not fail it. A gap whose test no class collects fails each
    shard and the run of the whole suite, also when its test ran."""

    # Each class writes its name into the file $SHARD_ORDER when it starts. Then it
    # burns $SHARD_BURN seconds of CPU in its own process and as many in a child
    # process that it waits for, and then sleeps $SHARD_SLEEP seconds (when the test
    # gives the variables). burn() counts CPU time (time.process_time()), so the CPU
    # seconds of a class do not change when the machine is busy.
    RECORDED = (
        "import os, subprocess, sys, time, unittest\n\n\n"
        "def burn(seconds):\n"
        "    end = time.process_time() + seconds\n"
        "    while time.process_time() < end:\n"
        "        pass\n\n\n"
        "class Recorded(unittest.TestCase):\n"
        "    @classmethod\n"
        "    def setUpClass(cls):\n"
        "        with open(os.environ['SHARD_ORDER'], 'a', encoding='utf-8') as fh:\n"
        "            fh.write(cls.__module__ + '.' + cls.__name__ + '\\n')\n"
        "        own = float(os.environ.get('SHARD_BURN', '0'))\n"
        "        child = float(os.environ.get('SHARD_CHILD_BURN', '0'))\n"
        "        if own:\n"
        "            burn(own)\n"
        "        if child:\n"
        "            subprocess.run([sys.executable, '-B', '-c',\n"
        "                            f'import recorded; recorded.burn({child!r})'],\n"
        "                           check=True)\n"
        "        time.sleep(float(os.environ.get('SHARD_SLEEP', '0')))\n")
    GAPPY = (
        "import os, sys, unittest\n"
        "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
        "import gatelib\n"
        "from recorded import Recorded\n\n\n"
        "def accepted(case):\n"
        "    tree = gatelib.Tree(())\n"
        "    case.addCleanup(tree.cleanup)\n"
        "    tree.write('gate.py', 'print(1)')\n"
        "    return tree.run('gate.py')\n\n\n"
        "class Collected(Recorded):\n"
        "    def test_a(self):\n        pass\n\n"
        "    @gatelib.known_gap('gap-on-a-method-that-is-no-test', gate='gate.py', closes='R7',\n"
        "                       reason='A constructed gate accepts every artifact.')\n"
        "    def check_gap_never_collected(self):\n"
        "        gatelib.assert_rejects(accepted(self), r'FAIL')\n")
    # The weights: shard 1 of 2 holds Heavy and Collected (10 + 3), shard 2 Good,
    # AlsoGood and Light (6 + 5 + 1). Of equal weights, the shards would differ.
    SECONDS = {"test_two.Heavy": 10, "test_one.Good": 6, "test_one.AlsoGood": 5.0,
               "test_gappy.Collected": 3, "test_two.Light": 1}
    FIRST = ["test_gappy.Collected", "test_two.Heavy"]
    SECOND = ["test_one.AlsoGood", "test_one.Good", "test_two.Light"]

    def suite(self, seconds=None):
        tree = gatelib.Tree(("detections/tests/gatelib.py",))
        self.addCleanup(tree.cleanup)
        tree.write("detections/tests/recorded.py", self.RECORDED)
        tree.write("detections/tests/test_one.py",
                   "from recorded import Recorded\n\n\n"
                   "class Good(Recorded):\n"
                   "    def test_a(self):\n        pass\n\n"
                   "    def test_b(self):\n        pass\n\n\n"
                   "class AlsoGood(Recorded):\n"
                   "    def test_c(self):\n        pass\n")
        tree.write("detections/tests/test_two.py",
                   "from recorded import Recorded\n\n\n"
                   "class Heavy(Recorded):\n"
                   "    def test_d(self):\n        pass\n\n\n"
                   "class Light(Recorded):\n"
                   "    def test_e(self):\n        pass\n")
        tree.write("detections/tests/test_gappy.py", self.GAPPY)
        self.table(tree, {"about": "Constructed.",
                          "seconds": self.SECONDS if seconds is None else seconds})
        return tree

    @staticmethod
    def table(tree, doc):
        tree.write("detections/tests/class_seconds.json",
                   doc if isinstance(doc, str) else json.dumps(doc))

    def run_shard(self, tree, shard, *options, burn=0, child=None, sleep=0):
        """(result, the classes in the order they started) of a run of one shard. Each
        class of Recorded burns `burn` seconds of CPU in its process and `child`
        seconds (default: `burn`) in a child process that it waits for, and then
        sleeps `sleep` seconds."""
        order = tree.out("order.txt")
        open(order, "w", encoding="utf-8").close()
        result = tree.run("detections/tests/gatelib.py", "--run", "--shard", shard, *options,
                          env={"SHARD_ORDER": order, "SHARD_BURN": str(burn),
                               "SHARD_CHILD_BURN": str(burn if child is None else child),
                               "SHARD_SLEEP": str(sleep)})
        with open(order, encoding="utf-8") as fh:
            return result, fh.read().split()

    @staticmethod
    def printed(result):
        return re.findall(r"(?m)^===== (\S+): ", result.stdout)

    def test_the_shards_hold_each_class_one_time_by_their_weights(self):
        self.assertEqual(gatelib.shard_classes(
            ["test_gappy.Collected", "test_one.AlsoGood", "test_one.Good", "test_two.Heavy",
             "test_two.Light"], self.SECONDS, 2), [self.FIRST, self.SECOND])
        # Two classes of the same weight in the order of their names; of two shards
        # with the same weight, the one with the lower number.
        self.assertEqual(gatelib.shard_classes(["d", "b", "a", "c"], {}, 2), [["a", "c"], ["d", "b"]])
        self.assertEqual(gatelib.shard_classes(["d", "b", "a", "c"], {}, 3), [["d", "a"], ["b"], ["c"]])
        # A class that the table does not hold weighs the median of the table (5.5
        # here, not 1, not 0): Light then goes to shard 2 before AlsoGood.
        without = {name: seconds for name, seconds in self.SECONDS.items() if name != "test_two.Light"}
        self.assertEqual(gatelib.shard_classes(sorted(self.SECONDS), without, 2),
                         [["test_one.AlsoGood", "test_two.Heavy"],
                          ["test_gappy.Collected", "test_one.Good", "test_two.Light"]])
        # The median (2), not the mean (11) and not 1: x and b weigh the same.
        self.assertEqual(gatelib.shard_classes(["a", "b", "c", "x"], {"a": 1, "b": 2, "c": 30}, 3),
                         [["c"], ["a", "b"], ["x"]])
        # Each shard in the order of the names given; the same sets in each order.
        names = sorted(self.SECONDS)
        for count in (1, 2, 3, 5, 7):
            shards = gatelib.shard_classes(names, self.SECONDS, count)
            self.assertEqual(len(shards), count)
            self.assertEqual(sorted(name for shard in shards for name in shard), names)
            self.assertEqual([sorted(shard) for shard in gatelib.shard_classes(
                names[::-1], self.SECONDS, count)], [sorted(shard) for shard in shards])
            for shard in shards:
                self.assertEqual(shard, [name for name in names if name in shard])

    def test_a_shard_runs_its_classes_heaviest_first(self):
        tree = self.suite()
        tree.write("detections/tests/test_gappy.py", self.GAPPY.replace(
            "def check_gap_never_collected(", "def test_gap_collected("))
        summary = tree.out("summary.md")
        result, started = self.run_shard(tree, "2/2", "--jobs", "1", "--summary", summary)
        gatelib.assert_accepts(result, r"^shard 2/2: 3 of 5 test class\(es\), 4 test\(s\), "
                                       r"1 at a time, [0-9.]+ s; the CPU seconds of its classes: "
                                       r"[0-9.]+ in this run, 12\.0 by class_seconds\.json$")
        self.assertEqual(started, ["test_one.Good", "test_one.AlsoGood", "test_two.Light"])
        self.assertEqual(self.printed(result), self.SECOND)
        self.assertRegex(result.stdout, r"(?m)^classes of shard 2/2: test_one\.AlsoGood, "
                                        r"test_one\.Good, test_two\.Light$")
        self.assertRegex(result.stdout, r"(?m)^OK$")
        # The gap of shard 1 did not run here, and that is no failure.
        self.assertIn("\n  gap-on-a-method-that-is-no-test\n", result.stdout)
        self.assertIn("      state:  in shard 1/2, not in this run\n", result.stdout)
        with open(summary, encoding="utf-8") as fh:
            text = fh.read()
        self.assertRegex(text, r"(?m)^## Gate tests, shard 2/2: passed$")
        self.assertRegex(text, r"(?m)^shard 2/2: 3 of 5 test class\(es\), .*, 12\.0 by "
                               r"class_seconds\.json; 1 known gap\(s\), 0 of them in this shard, "
                               r"0 seen open in this run\.$")
        self.assertIn("- classes of shard 2/2: test_one.AlsoGood, test_one.Good, test_two.Light\n",
                      text)
        self.assertIn("| `gap-on-a-method-that-is-no-test` | `gate.py` | accepts | R7 | "
                      "in shard 1/2 | ", text)
        # Shard 1 runs the test of the gap and sees it open.
        result, started = self.run_shard(tree, "1/2", "--jobs", "1")
        gatelib.assert_accepts(result, r"^shard 1/2: 2 of 5 test class\(es\), 3 test\(s\), "
                               r".*, 13\.0 by class_seconds\.json$")
        self.assertEqual(started, ["test_two.Heavy", "test_gappy.Collected"])
        self.assertEqual(self.printed(result), self.FIRST)
        self.assertIn("      state:  open in this run\n", result.stdout)
        # CONTROL: without --shard, each class, in the order of discovery.
        order = tree.out("order.txt")
        open(order, "w", encoding="utf-8").close()
        whole = tree.run("detections/tests/gatelib.py", "--run", "--jobs", "1",
                         env={"SHARD_ORDER": order})
        gatelib.assert_accepts(whole, r"^5 test class\(es\), 7 test\(s\), 1 at a time, ")
        with open(order, encoding="utf-8") as fh:
            self.assertEqual(fh.read().split(), sorted(self.FIRST + self.SECOND))
        self.assertEqual(self.printed(whole), sorted(self.FIRST + self.SECOND))
        # A class that the table does not hold weighs the median of the table (5.5
        # without Light), and the line says so.
        self.table(tree, {"about": "Constructed.", "seconds": {
            name: seconds for name, seconds in self.SECONDS.items() if name != "test_two.Light"}})
        result, started = self.run_shard(tree, "2/2", "--jobs", "1")
        self.assertEqual(self.printed(result),
                         ["test_gappy.Collected", "test_one.Good", "test_two.Light"])
        gatelib.assert_accepts(result, r"^shard 2/2: .*, 14\.5 by class_seconds\.json \(1 "
                                       r"class\(es\) not in it, at the median 5\.5 s\)$")
        # Of equal weights (an empty table) the shards differ: the table is read. A
        # class that the table does not hold weighs 1 here.
        self.table(tree, {"about": "Constructed.", "seconds": {}})
        result, started = self.run_shard(tree, "1/2", "--jobs", "1")
        self.assertEqual(self.printed(result),
                         ["test_gappy.Collected", "test_one.Good", "test_two.Light"])
        gatelib.assert_accepts(result, r"^shard 1/2: .*, 3\.0 by class_seconds\.json \(3 "
                                       r"class\(es\) not in it, at 1\.0 s, as the table is "
                                       r"empty\)$")

    # The line of a class that ends with its CPU seconds: (wall seconds, CPU seconds).
    CLASS_LINE = r"(?m)^===== \S+: ok, \d+ test\(s\), ([0-9.]+) s \(CPU ([0-9.]+) s\)$"
    # The summary line of shard 2/2 with the table of SECONDS: the CPU seconds of its
    # classes in this run.
    CPU_IN_THIS_RUN = (r"(?m)^shard 2/2: 3 of 5 test class\(es\), \d+ test\(s\), {jobs} at a "
                       r"time, [0-9.]+ s; the CPU seconds of its classes: ([0-9.]+) in this "
                       r"run{without}, 12\.0 by class_seconds\.json$")

    def test_a_shard_gives_the_cpu_seconds_of_its_classes(self):
        """The summary line of a shard gives the CPU seconds of its classes in this run:
        the sum of the CPU seconds of the lines of its classes. The CPU seconds of a
        class are those of its process and of the processes that it waited for. Each
        class of shard 2/2 burns 0.3 s of CPU in its process and 0.3 s in a child
        process, and then sleeps 0.3 s (wall time without CPU). With --jobs 1 the
        classes run one after the other, with --jobs 3 at the same time (CI runs 4 at
        a time)."""
        burn, sleep = 0.3, 0.3
        # Each value of a line is rounded to 0.1 s, so the sum of the three lines is
        # within 0.15 s of the sum of the CPU seconds, and the summary line within
        # 0.05 s: 0.2 s in all.
        rounding = 0.2
        tree = self.suite()
        tree.replace("detections/tests/test_gappy.py", "def check_gap_never_collected(",
                     "def test_gap_collected(")
        for jobs in ("1", "3"):
            with self.subTest(jobs=jobs):
                result, _started = self.run_shard(tree, "2/2", "--jobs", jobs, burn=burn,
                                                  sleep=sleep)
                gatelib.assert_accepts(result, self.CPU_IN_THIS_RUN.format(jobs=jobs, without=""))
                lines = [(float(wall), float(cpu))
                         for wall, cpu in re.findall(self.CLASS_LINE, result.stdout)]
                spent = float(re.search(self.CPU_IN_THIS_RUN.format(jobs=jobs, without=""),
                                        result.stdout).group(1))
                cpus = [cpu for _wall, cpu in lines]
                self.assertEqual(len(lines), 3)
                # The CPU of each class holds its burn in its own process and in its
                # child. Kills: CPU without RUSAGE_CHILDREN (or without RUSAGE_SELF),
                # each then about one burn.
                self.assertGreaterEqual(min(cpus), 2 * burn)
                # The CPU of a class is not its wall time: the class also slept.
                # Kills: the wall seconds of a class given as its CPU.
                for wall, cpu in lines:
                    self.assertGreater(wall - cpu, sleep - 0.15)
                # The summary line gives the sum of the CPU of the lines. Kills: X = the
                # wall time of the run (with --jobs 3, about that of one class, on a
                # machine with 3 CPUs or more; with --jobs 1, the CPU of the classes and
                # their sleep); X = the sum of the wall seconds of the classes (that
                # holds their sleep).
                self.assertAlmostEqual(spent, sum(cpus), delta=rounding)
                # It is more than the CPU of any one class by more than the rounding.
                # Kills: X = the CPU of the last class (or of any one class).
                self.assertGreater(spent, max(cpus) + rounding)
        # Each part of the CPU on its own: 0.6 s only in the class process, then 0.6 s
        # only in a child. A class process alone needs about 0.1 s (it imports the
        # test module), so each line is between 0.6 and 0.6 + LIMIT s.
        limit = 0.4
        for own, child in ((0.6, 0), (0, 0.6)):
            with self.subTest(own=own, child=child):
                result, _started = self.run_shard(tree, "2/2", "--jobs", "3", burn=own,
                                                  child=child)
                gatelib.assert_accepts(result, self.CPU_IN_THIS_RUN.format(jobs="3", without=""))
                cpus = [float(cpu) for _wall, cpu in re.findall(self.CLASS_LINE, result.stdout)]
                self.assertEqual(len(cpus), 3)
                # Kills: RUSAGE_SELF counted two times in place of RUSAGE_CHILDREN (the
                # own-only run gives about 1.4 s, the child-only run about 0.2 s), and
                # RUSAGE_CHILDREN two times in place of RUSAGE_SELF (about 0 s and
                # about 1.2 s).
                self.assertGreaterEqual(min(cpus), 0.6 - 0.05)
                self.assertLessEqual(max(cpus), 0.6 + limit)

    def test_a_class_without_a_cpu_time_is_named_and_left_out_of_the_sum(self):
        """A class whose process wrote no CPU seconds: its line says `CPU not known`,
        and the summary line leaves it out of the sum and gives the number of such
        classes. The run ends as it would end without that number. In shard 2/2,
        test_two.Light writes its counts without `cpu` (at exit, after _ONE_CLASS) and
        passes; test_one.AlsoGood ends its process in its test, so it writes no
        counts and fails; test_one.Good burns CPU and passes."""
        tree = self.suite()
        tree.replace("detections/tests/test_gappy.py", "def check_gap_never_collected(",
                     "def test_gap_collected(")
        tree.write("detections/tests/test_one.py",
                   "import os\n"
                   "from recorded import Recorded\n\n\n"
                   "class Good(Recorded):\n"
                   "    def test_a(self):\n        pass\n\n"
                   "    def test_b(self):\n        pass\n\n\n"
                   "class AlsoGood(Recorded):\n"
                   "    def test_c(self):\n        os._exit(0)\n")
        tree.write("detections/tests/test_two.py",
                   "import atexit, json, sys\n"
                   "from recorded import Recorded\n\n\n"
                   "def drop_cpu(path):\n"
                   "    with open(path, encoding='utf-8') as fh:\n"
                   "        counts = json.load(fh)\n"
                   "    del counts['cpu']\n"
                   "    with open(path, 'w', encoding='utf-8') as fh:\n"
                   "        json.dump(counts, fh)\n\n\n"
                   "class Heavy(Recorded):\n"
                   "    def test_d(self):\n        pass\n\n\n"
                   "class Light(Recorded):\n"
                   "    def test_e(self):\n"
                   # The counts file of the class: argument 2 of _ONE_CLASS.
                   "        atexit.register(drop_cpu, sys.argv[2])\n")
        summary = tree.out("summary.md")
        result, _started = self.run_shard(tree, "2/2", "--jobs", "3", "--summary", summary,
                                          burn=0.1)
        gatelib.assert_rejects(result, r"^FAILED: 1 test class\(es\): test_one\.AlsoGood$",
                               exit_code=1)
        self.assertNotIn("Traceback", result.output)
        self.assertRegex(result.stdout, r"(?m)^===== test_two\.Light: ok, 1 test\(s\), "
                                        r"[0-9.]+ s \(CPU not known\)$")
        self.assertRegex(result.stdout, r"(?m)^===== test_one\.AlsoGood: FAILED \(ran 0 of 1 "
                                        r"test\(s\)\), 0 test\(s\), [0-9.]+ s \(CPU not known\)$")
        cpus = [float(cpu) for _wall, cpu in re.findall(self.CLASS_LINE, result.stdout)]
        self.assertEqual(len(cpus), 1)          # test_one.Good
        line = self.CPU_IN_THIS_RUN.format(jobs="3",
                                           without=r" \(2 class\(es\) without a CPU time\)")
        spent = float(re.search(line, result.stdout).group(1))
        # The sum of the classes whose CPU is known: that of test_one.Good (the same
        # number, so the same text).
        self.assertEqual(spent, cpus[0])
        with open(summary, encoding="utf-8") as fh:
            text = fh.read()
        self.assertRegex(text, r"(?m)^## Gate tests, shard 2/2: FAILED$")
        self.assertRegex(text, r"(?m)^shard 2/2: .* in this run \(2 class\(es\) without a CPU "
                               r"time\), 12\.0 by class_seconds\.json; 1 known gap\(s\), ")
        # A class that fails an assertion still writes its counts: its line has its
        # CPU, and the sum holds it. One class (Light) is then without a CPU time.
        tree.replace("detections/tests/test_one.py", "        os._exit(0)\n",
                     "        self.fail('planted failure')\n")
        result, _started = self.run_shard(tree, "2/2", "--jobs", "3", burn=0.1)
        # crash_ok: the output of the class holds the traceback of its failure.
        gatelib.assert_rejects(result, r"^FAILED: 1 test class\(es\): test_one\.AlsoGood$",
                               exit_code=1, crash_ok=True)
        failing = re.search(r"(?m)^===== test_one\.AlsoGood: FAILED \(exit code 1\), "
                            r"1 test\(s\), [0-9.]+ s \(CPU ([0-9.]+) s\)$", result.stdout)
        self.assertIsNotNone(failing, result.stdout)
        cpus = [float(cpu) for _wall, cpu in re.findall(self.CLASS_LINE, result.stdout)]
        self.assertEqual(len(cpus), 1)          # test_one.Good
        cpus.append(float(failing.group(1)))
        line = self.CPU_IN_THIS_RUN.format(jobs="3",
                                           without=r" \(1 class\(es\) without a CPU time\)")
        spent = float(re.search(line, result.stdout).group(1))
        self.assertAlmostEqual(spent, sum(cpus), delta=0.15)
        self.assertGreater(spent, max(cpus) + 0.05)
        # CONTROL: the same classes, with the CPU seconds of each: no class without
        # a CPU time, and the run passes.
        tree.replace("detections/tests/test_one.py", "        self.fail('planted failure')\n",
                     "        pass\n")
        tree.replace("detections/tests/test_two.py", "        atexit.register(drop_cpu, "
                     "sys.argv[2])\n", "        pass\n")
        result, _started = self.run_shard(tree, "2/2", "--jobs", "3")
        gatelib.assert_accepts(result, self.CPU_IN_THIS_RUN.format(jobs="3", without=""))
        self.assertEqual(len(re.findall(self.CLASS_LINE, result.stdout)), 3)
        self.assertNotIn("CPU not known", result.stdout)

    def test_a_known_gap_whose_test_no_class_collects_fails_each_shard(self):
        """No class collects the test of a gap whose marker is on a method that is no
        test, or in a class that is no TestCase. No shard runs such a test, so each
        shard fails for the gap, as the run of the whole suite does, and names the
        likely causes. The count of the gaps of a shard holds it."""
        tree = self.suite()
        summary = tree.out("summary.md")
        known = ["gap-on-a-method-that-is-no-test"]

        def leg(shard, gaps, counted, seen):
            open(summary, "w", encoding="utf-8").close()
            result, _started = self.run_shard(tree, shard, "--summary", summary)
            gatelib.assert_rejects(result, r"^FAILED: the test of these known gap\(s\) did not "
                                           r"run: " + re.escape(gaps) + "$", exit_code=1)
            self.assertRegex(result.stdout, "(?m)^" + re.escape(not_collected([gaps])) + "$")
            with open(summary, encoding="utf-8") as fh:
                text = fh.read()
            self.assertRegex(text, rf"(?m)^## Gate tests, shard {shard}: FAILED$")
            self.assertIn(f"; {len(known)} known gap(s), {counted} of them in this shard, "
                          f"{seen} seen open in this run.", text)
            self.assertIn(f"- {not_collected([gaps])}\n", text)
            return result

        self.assertEqual(self.printed(leg("1/2", known[0], 1, 0)), self.FIRST)
        self.assertEqual(self.printed(leg("2/2", known[0], 1, 0)), self.SECOND)
        # A gap in a class that is no TestCase too: each shard counts both.
        tree.append("detections/tests/test_gappy.py",
                    "\n\nclass Mixin:\n"
                    "    @gatelib.known_gap('gap-in-a-class-that-is-no-testcase', gate='gate.py',\n"
                    "                       closes='R7', reason='A constructed gate accepts every "
                    "artifact.')\n"
                    "    def test_gap_never_loaded(self):\n"
                    "        gatelib.assert_rejects(accepted(self), r'FAIL')\n")
        known.insert(0, "gap-in-a-class-that-is-no-testcase")
        for shard in ("1/2", "2/2"):
            leg(shard, ", ".join(known), 2, 0)
        whole = tree.run("detections/tests/gatelib.py", "--run", env={"SHARD_ORDER": os.devnull})
        gatelib.assert_rejects(whole, r"^FAILED: the test of these known gap\(s\) did not run: "
                                      + re.escape(", ".join(known)) + "$", exit_code=1)
        self.assertRegex(whole.stdout, "(?m)^" + re.escape(not_collected(known)) + "$")
        # CONTROL: Collected collects the test of the other gap now. Shard 1 runs it
        # and sees it open; shard 2 does not count it.
        tree.replace("detections/tests/test_gappy.py", "def check_gap_never_collected(",
                     "def test_gap_collected(")
        leg("1/2", known[0], 2, 1)
        result = leg("2/2", known[0], 1, 0)
        self.assertIn("      state:  in shard 1/2, not in this run\n", result.stdout)

    MIXED = (
        "import os, sys, unittest\n"
        "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
        "import gatelib\n\n\n"
        "def accepted(case):\n"
        "    tree = gatelib.Tree(())\n"
        "    case.addCleanup(tree.cleanup)\n"
        "    tree.write('gate.py', 'print(1)')\n"
        "    return tree.run('gate.py')\n\n\n"
        "class Mixin:\n"
        "    @gatelib.known_gap('gap-in-a-mixin', gate='gate.py', closes='R7',\n"
        "                       reason='A constructed gate accepts every artifact.')\n"
        "    def test_gap(self):\n"
        "        gatelib.assert_rejects(accepted(self), r'FAIL')\n\n\n"
        "class A(Mixin, unittest.TestCase):\n"
        "    def test_a(self):\n        pass\n\n\n"
        "class B(unittest.TestCase):\n"
        "    def test_b(self):\n        pass\n\n\n"
        "class C(unittest.TestCase):\n"
        "    def test_c(self):\n        pass\n")

    def test_a_gap_on_a_mixin_counts_in_the_shards_of_the_classes_that_collect_it(self):
        """The test of a known gap on a mixin (no TestCase) is collected by each
        TestCase that inherits it: the shards of those classes run the gap, and the
        other shards pass, as the run of the whole suite does. The weights put A in
        shard 1, B in shard 2 and C in shard 3 of 3."""
        tree = gatelib.Tree(("detections/tests/gatelib.py",))
        self.addCleanup(tree.cleanup)
        tree.write("detections/tests/test_mix.py", self.MIXED)
        self.table(tree, {"about": "Constructed.",
                          "seconds": {"test_mix.A": 3, "test_mix.B": 2, "test_mix.C": 1}})
        summary = tree.out("summary.md")

        def leg(shard):
            open(summary, "w", encoding="utf-8").close()
            result = tree.run("detections/tests/gatelib.py", "--run", "--shard", shard,
                              "--summary", summary)
            with open(summary, encoding="utf-8") as fh:
                return result, fh.read()

        result, text = leg("2/3")
        gatelib.assert_accepts(result, r"^OK$")
        self.assertIn("\n  gap-in-a-mixin\n", result.stdout)
        self.assertIn("      state:  in shard 1/3, not in this run\n", result.stdout)
        self.assertIn("; 1 known gap(s), 0 of them in this shard, 0 seen open in this run.", text)
        self.assertIn("| `gap-in-a-mixin` | `gate.py` | accepts | R7 | in shard 1/3 | ", text)
        result, text = leg("1/3")
        gatelib.assert_accepts(result, r"^shard 1/3: 1 of 3 test class\(es\), 2 test\(s\), ")
        self.assertIn("      state:  open in this run\n", result.stdout)
        self.assertIn("; 1 known gap(s), 1 of them in this shard, 1 seen open in this run.", text)
        gatelib.assert_accepts(tree.run("detections/tests/gatelib.py", "--run"),
                               r"^3 test class\(es\), 4 test\(s\), ")
        # C inherits the gap too: shards 1 and 3 run it, and shard 2 names both.
        tree.replace("detections/tests/test_mix.py", "class C(unittest.TestCase):",
                     "class C(Mixin, unittest.TestCase):")
        for shard in ("1/3", "3/3"):
            result, text = leg(shard)
            gatelib.assert_accepts(result, r"^OK$")
            self.assertIn("      state:  open in this run\n", result.stdout)
        result, text = leg("2/3")
        gatelib.assert_accepts(result, r"^OK$")
        self.assertIn("      state:  in shards 1/3 and 3/3, not in this run\n", result.stdout)
        self.assertIn("; 1 known gap(s), 0 of them in this shard, 0 seen open in this run.", text)
        # A overrides the test without the marker: A does not collect the gap.
        tree.replace("detections/tests/test_mix.py", "    def test_a(self):\n",
                     "    def test_gap(self):\n        pass\n\n    def test_a(self):\n")
        result, text = leg("1/3")
        gatelib.assert_accepts(result, r"^shard 1/3: 1 of 3 test class\(es\), 2 test\(s\), ")
        self.assertIn("      state:  in shard 3/3, not in this run\n", result.stdout)
        gatelib.assert_accepts(leg("3/3")[0], r"^OK$")

    # Two shapes in which the test of a gap runs and sees the gap open, and no class
    # collects it with its marker (_discover() credits the gap to no class).
    UNCREDITED = {
        # A decorator without functools.wraps above the marker: the method that the
        # class runs does not hold the marker.
        "plain-decorator": (
            "def plain(fn):\n"
            "    def inner(self):\n"
            "        return fn(self)\n"
            "    return inner\n\n\n"
            "class A(unittest.TestCase):\n"
            "    @plain\n"
            "    @gatelib.known_gap('gap-under-a-plain-decorator', gate='gate.py', closes='R7',\n"
            "                       reason='A constructed gate accepts every artifact.')\n"
            "    def test_gap(self):\n"
            "        gatelib.assert_rejects(accepted(self), r'FAIL')\n\n\n"),
        # The only TestCase overrides the marked test of a mixin without the marker,
        # and calls it with super().
        "override-without-marker": (
            "class Mixin:\n"
            "    @gatelib.known_gap('gap-of-an-override', gate='gate.py', closes='R7',\n"
            "                       reason='A constructed gate accepts every artifact.')\n"
            "    def test_gap(self):\n"
            "        gatelib.assert_rejects(accepted(self), r'FAIL')\n\n\n"
            "class A(Mixin, unittest.TestCase):\n"
            "    def test_gap(self):\n"
            "        super().test_gap()\n\n\n"),
    }

    def test_a_gap_that_no_class_collects_fails_also_when_its_test_ran(self):
        """The test of the gap runs in class A (shard 1 of 3) and sees the gap open,
        but no class collects it with its marker. A run of a shard cannot tell where
        such a test runs, so the run of the whole suite and each shard fail, and name
        the likely causes. CONTROL: with functools.wraps, A collects the gap."""
        head = self.MIXED.split("class Mixin:\n")[0]
        others = "class B(unittest.TestCase):\n" + self.MIXED.split("class B(unittest.TestCase):\n")[1]

        def runs(source):
            """{shard (None: the whole suite): the result of its run}, A in shard 1/3."""
            tree = gatelib.Tree(("detections/tests/gatelib.py",))
            self.addCleanup(tree.cleanup)
            tree.write("detections/tests/test_mix.py", head + source + others)
            self.table(tree, {"about": "Constructed.",
                              "seconds": {"test_mix.A": 3, "test_mix.B": 2, "test_mix.C": 1}})
            return {shard: tree.run("detections/tests/gatelib.py", "--run",
                                    *(("--shard", shard) if shard else ()))
                    for shard in (None, "1/3", "2/3", "3/3")}

        for shape, source in self.UNCREDITED.items():
            gap = re.search(r"known_gap\('([a-z-]+)'", source).group(1)
            for shard, result in runs(source).items():
                with self.subTest(shape=shape, shard=shard):
                    gatelib.assert_rejects(result, "^" + re.escape(not_collected([gap])) + "$",
                                           exit_code=1)
                    self.assertNotIn("test class(es): ", result.stdout)    # no class failed
                    # The whole run and shard 1 ran the test, and it saw the gap open.
                    self.assertIn("      state:  open in this run\n" if shard in (None, "1/3")
                                  else "      state:  not run in this run\n", result.stdout)
        # CONTROL: the decorator with functools.wraps keeps the marker, so A collects
        # the gap: each run passes, and shards 2 and 3 name shard 1.
        wrapped = "import functools\n\n\n" + self.UNCREDITED["plain-decorator"].replace(
            "def plain(fn):\n", "def plain(fn):\n    @functools.wraps(fn)\n")
        for shard, result in runs(wrapped).items():
            with self.subTest(shape="wrapped", shard=shard):
                gatelib.assert_accepts(result, r"^OK$")
                self.assertIn("      state:  open in this run\n" if shard in (None, "1/3")
                              else "      state:  in shard 1/3, not in this run\n", result.stdout)

    def test_a_wrong_shard_is_refused(self):
        tree = self.suite()
        tree.replace("detections/tests/test_gappy.py", "def check_gap_never_collected(",
                     "def test_gap_collected(")
        for shard in ("0/3", "4/3", "1/0", "0/0", "junk", "1/3/4", "1/ 3", " 1/3", "1/3 ", "+1/3",
                      "-1/3", "1.0/3", "01/3", "1/03", "\u0661/\u0663", "1/3\n", "3", "1/", ""):
            with self.subTest(shard=shard):
                result = tree.run("detections/tests/gatelib.py", "--run", "--shard=" + shard)
                self.assertEqual(result.returncode, 2, result.describe())
                self.assertRegex(result.stderr, r"argument --shard: .* give K/N, two whole "
                                                r"numbers with 1 <= K <= N")
        named = tree.run("detections/tests/gatelib.py", "--run", "--shard", "1/2", "test_one")
        self.assertEqual(named.returncode, 2, named.describe())
        self.assertIn("--shard runs the classes of one shard: give no class names with it",
                      named.stderr)
        # CONTROL: values in the form K/N with 1 <= K <= N are taken (5/5: one class).
        for shard, classes in (("1/1", 5), ("2/2", 3), ("5/5", 1)):
            gatelib.assert_accepts(tree.run("detections/tests/gatelib.py", "--run",
                                            "--shard", shard, env={"SHARD_ORDER": os.devnull}),
                                   rf"^shard {shard}: {classes} of 5 test class\(es\), ")
        # A shard that holds no class fails: without --summary, the line and no
        # traceback; with --summary, the file says the same.
        empty = tree.run("detections/tests/gatelib.py", "--run", "--shard", "6/6",
                         env={"SHARD_ORDER": os.devnull})
        gatelib.assert_rejects(empty, r"^shard 6/6 holds no test class: the suite has 5 test "
                                      r"class\(es\)$", exit_code=1)
        self.assertNotIn("Traceback", empty.output)
        summary = tree.out("summary.md")
        empty = tree.run("detections/tests/gatelib.py", "--run", "--shard", "6/6",
                         "--summary", summary, env={"SHARD_ORDER": os.devnull})
        gatelib.assert_rejects(empty, r"^shard 6/6 holds no test class: the suite has 5 test "
                                      r"class\(es\)$", exit_code=1)
        with open(summary, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "## Gate tests, shard 6/6: FAILED\n\nshard 6/6 holds no "
                                        "test class: the suite has 5 test class(es).\n")

    def test_a_table_that_cannot_be_used_fails_the_run(self):
        tree = self.suite()
        tree.replace("detections/tests/test_gappy.py", "def check_gap_never_collected(",
                     "def test_gap_collected(")
        summary = tree.out("summary.md")
        good = json.dumps({"about": "Constructed.", "seconds": self.SECONDS})
        for doc, reason in (
                ({"about": "x", "seconds": {"test_two.Heavy": 0}}, r"Heavy are 0, not a number above 0"),
                ({"about": "x", "seconds": {"test_two.Heavy": -1}}, r"Heavy are -1, not a number"),
                ({"about": "x", "seconds": {"test_two.Heavy": "5"}}, r"Heavy are '5', not a number"),
                ({"about": "x", "seconds": {"test_two.Heavy": True}}, r"Heavy are True, not a number"),
                ({"about": "x", "seconds": {"test_two.Heavy": None}}, r"Heavy are None, not a number"),
                ('{"about": "x", "seconds": {"test_two.Heavy": NaN}}', r"Heavy are nan, not a number"),
                ('{"about": "x", "seconds": {"test_two.Heavy": Infinity}}', r"Heavy are inf, not a"),
                ('{"about": "x", "seconds": {"a.B": 1, "a.B": 2}}', r"holds the key 'a\.B' two times"),
                ('{"about": "x", "about": "y", "seconds": {}}', r"holds the key 'about' two times"),
                ({"seconds": {}}, r"not an object with the keys `about` \(a text\) and `seconds`"),
                ({"about": "x", "seconds": {}, "more": 1}, r"not an object with the keys `about`"),
                ({"about": 1, "seconds": {}}, r"not an object with the keys `about`"),
                ({"about": "x", "seconds": [1]}, r"not an object with the keys `about`"),
                ([], r"not an object with the keys `about`"),
                ("{", r"Expecting property name"),
                (None, r"No such file or directory")):
            with self.subTest(reason=reason):
                if doc is None:
                    tree.remove("detections/tests/class_seconds.json")
                else:
                    self.table(tree, doc)
                open(summary, "w", encoding="utf-8").close()
                result, started = self.run_shard(tree, "1/2", "--summary", summary)
                gatelib.assert_rejects(result, r"^--shard: the table of class weights cannot be "
                                               r"used: .*" + reason, exit_code=1)
                self.assertEqual((started, self.printed(result)), ([], []))
                with open(summary, encoding="utf-8") as fh:
                    self.assertEqual(fh.read(), "## Gate tests, shard 1/2: FAILED\n\nThe table of "
                                     "class weights cannot be used, so no test ran. The log of "
                                     "the step holds the error.\n")
                self.table(tree, good)
        # Without --summary too: the same error line, and no traceback.
        self.table(tree, {"about": "x", "seconds": {"test_two.Heavy": 0}})
        result, started = self.run_shard(tree, "1/2")
        gatelib.assert_rejects(result, r"^--shard: the table of class weights cannot be used: "
                                       r"class_seconds\.json: the seconds of test_two\.Heavy are 0, "
                                       r"not a number above 0$", exit_code=1)
        self.assertEqual((started, self.printed(result)), ([], []))
        # CONTROL: the good table again, and a whole number of seconds.
        self.table(tree, {"about": "x", "seconds": {**self.SECONDS, "test_one.AlsoGood": 5}})
        gatelib.assert_accepts(self.run_shard(tree, "2/2")[0], r"^shard 2/2: 3 of 5 ")


class GateCaseGuards(unittest.TestCase):
    """GateCase fails a class that wrote into the shared good() tree, or into the
    repository."""

    def run_class(self, body):
        class Case(gatelib.GateCase):
            PARTS = ("AGENTS.md",)

            def test_it(self):
                body(self)

        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(Case).run(result)
        return result

    def test_good_tree_is_shared_and_deleted_after_the_class(self):
        seen = []
        result = self.run_class(lambda case: seen.append((case.good(), case.good(), case.tree())))
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        good, again, private = seen[0]
        self.assertIs(good, again)
        self.assertIsNot(good, private)
        self.assertFalse(os.path.exists(good.sandbox))
        self.assertFalse(os.path.exists(private.sandbox))

    def test_change_to_the_good_tree_fails_the_class(self):
        result = self.run_class(lambda case: case.good().write("AGENTS.md", "changed\n"))
        self.assertFalse(result.wasSuccessful())
        self.assertIn("the shared good() tree was changed (AGENTS.md)", result.errors[0][1])
        result = self.run_class(lambda case: case.good().write("new.txt", "x\n"))
        self.assertIn("the shared good() tree was changed (new.txt)", result.errors[0][1])

    def test_class_tree_lives_as_long_as_the_class(self):
        seen = []

        class Case(gatelib.GateCase):
            PARTS = ("AGENTS.md",)

            @classmethod
            def setUpClass(cls):
                super().setUpClass()
                cls.planted = cls.class_tree()
                cls.planted.write("gate.py", "import time\ntime.sleep(0.5)\n" + ACCEPTING)
                cls.run_nobody_collects = cls.in_background(cls.planted.run, "gate.py")
                cls.run_of_test_a = cls.planted.start("gate.py")

            def test_a(self):
                seen.append((self.planted, self.run_nobody_collects, self.run_of_test_a.result()))
                self.assertTrue(self.planted.exists("AGENTS.md"))

            def test_b(self):
                self.assertIs(self.planted, seen[0][0])
                self.assertIsNot(self.planted, self.good())

        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(Case).run(result)
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertEqual(result.testsRun, 2)
        planted, uncollected, collected = seen[0]
        gatelib.assert_accepts(collected, r"All cases hold")
        # The class waited for the run that no test collected, then deleted the copy.
        self.assertTrue(uncollected.done())
        gatelib.assert_accepts(uncollected.result(), r"All cases hold")
        self.assertFalse(os.path.exists(planted.sandbox))

    def test_assert_documented_reads_the_commands_of_agents_md(self):
        class Case(gatelib.GateCase):
            def runTest(self):
                pass

        case = Case()
        case.assert_documented("python3 detections/rule_cases.py")
        case.assert_documented("python3   detections/validate_detections.py --dry-run")
        with self.assertRaisesRegex(AssertionError, "AGENTS.md does not give the command"):
            case.assert_documented("python3 detections/rule_cases.py --no-such-flag")

    def test_assert_ci_runs_needs_every_word_in_one_command_line(self):
        """assert_ci_runs() is the one assertion behind the `test_ci_runs_...` tests of
        the gates: it must fail when no single command line of the workflows runs the
        script with every word. The workflow steps here are constructed."""
        class Case(gatelib.GateCase):
            def runTest(self):
                pass

        steps = [
            gatelib.Step("w.yml", "check", "Check", "bash",
                         "python3 detections/gate.py --check --enforce | tee /tmp/gate.out\n"),
            gatelib.Step("w.yml", "ratchet", "Ratchet", "bash",
                         "# python3 detections/gate.py --check --update is not run here\n"
                         "python3 detections/gate.py --examples 0 \\\n"
                         "  --baseline-scores /tmp/base.json\n"),
            gatelib.Step("w.yml", "ratchet", "Decide", None,
                         "patterns='detections/other.py --check'\n")]

        def constructed_steps(script=None, root=None):
            return [step for step in steps if script is None or script in step.run]

        case = Case()
        with mock.patch.object(gatelib, "ci_steps", constructed_steps):
            case.assert_ci_runs("detections/gate.py")
            case.assert_ci_runs("detections/gate.py", "--check", "--enforce")
            case.assert_ci_runs("detections/gate.py", "--examples 0", "--baseline-scores")
            for script, words in (
                    ("detections/gate.py", ("--check", "--no-such-flag")),
                    # Each word is in a command line of the script; no line has both.
                    ("detections/gate.py", ("--check", "--baseline-scores")),
                    # In a comment only: a comment runs nothing.
                    ("detections/gate.py", ("--update",)),
                    # Named in a list of paths, and never run.
                    ("detections/other.py", ()),
                    ("detections/no_such_gate.py", ())):
                with self.assertRaisesRegex(AssertionError, "no workflow step runs "
                                            + script.replace(".", r"\.")):
                    case.assert_ci_runs(script, *words)
        # Without the constructed steps it reads the workflows of the repository.
        case.assert_ci_runs("detections/rule_cases.py", "| tee /tmp/rule-cases.out")
        with self.assertRaisesRegex(AssertionError, "no workflow step runs"):
            case.assert_ci_runs("detections/rule_cases.py", "--no-such-flag")

    def test_require_program_skips_here_and_fails_in_ci(self):
        self.assertEqual(gatelib.require_program("sh", "x"), shutil.which("sh"))
        with mock.patch.dict(os.environ, clear=False):
            os.environ.pop("CI", None)
            with self.assertRaisesRegex(unittest.SkipTest, "no-such-program-x is not installed"):
                gatelib.require_program("no-such-program-x", "a test needs it")
            os.environ["CI"] = "true"
            # Not assertRaises: a SkipTest that left this method would skip THIS test,
            # and a skipped test is green outside CI.
            try:
                gatelib.require_program("no-such-program-x", "a test needs it")
            except unittest.SkipTest:
                self.fail("in CI a missing program must fail the test, and it was skipped")
            except AssertionError as error:
                self.assertIn("no-such-program-x is not installed in CI: a test needs it",
                              str(error))
            else:
                self.fail("a missing program was found")

    def test_fingerprint_names_added_changed_and_removed_files(self):
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        tree.write("kept.txt", "x\n")
        tree.write("changed.txt", "x\n")
        tree.write("removed.txt", "x\n")
        tree.write("tests/skipped.txt", "x\n")
        before = gatelib.fingerprint(tree.root, skip=("tests",))
        self.assertEqual(sorted(before), ["changed.txt", "kept.txt", "removed.txt"])
        tree.write("changed.txt", "longer\n")
        tree.remove("removed.txt")
        tree.write("added/new.txt", "x\n")
        tree.write("tests/also_skipped.txt", "x\n")
        tree.write("__pycache__/ignored.pyc", "x\n")
        after = gatelib.fingerprint(tree.root, skip=("tests",))
        self.assertEqual(gatelib._changes(before, after),
                         ["added/new.txt", "changed.txt", "removed.txt"])

    def test_change_to_the_repository_fails_the_class(self):
        """The guard reads gatelib.REPO: point it at a constructed repository, and let
        a test write there (never into the real one)."""
        fake = gatelib.Tree(())
        self.addCleanup(fake.cleanup)
        fake.write("detections/rule_cases.py", "# a gate\n")
        fake.write("detections/tests/known_bad/x.yml", "a: 1\n")
        with mock.patch.object(gatelib, "REPO", fake.root):
            quiet = self.run_class(lambda case: fake.write("detections/tests/known_bad/y.yml", "b: 2\n"))
            loud = self.run_class(lambda case: fake.write("detections/benign/scores.json", "{}\n"))
        self.assertTrue(quiet.wasSuccessful(), quiet.errors)
        self.assertFalse(loud.wasSuccessful())
        self.assertIn("file(s) of the repository changed while the tests ran", loud.errors[0][1])
        self.assertIn("detections/benign/scores.json", loud.errors[0][1])


class StartedTogetherRuns(unittest.TestCase):
    """gatelib.StartedTogether: the slow runs of a class start together, each test
    gets its own run, and a run that cannot start fails only the tests that ask for
    it."""

    def run_class(self, **methods):
        log = []

        class Case(gatelib.StartedTogether):
            PARTS = ("AGENTS.md",)
            RUNS = ("rejecting", "broken", "skipped")

            @classmethod
            def start_gate(cls, tree):
                log.append(("start", tree))
                return tree.start("gate.py")

            @classmethod
            def begin_rejecting(cls, tree):
                tree.write("gate.py", "import time\ntime.sleep(0.3)\n" + REJECTING)
                return cls.start_gate(tree)

            @classmethod
            def begin_broken(cls, tree):
                tree.plant("no/such/artifact.yml", "x.yml")

            @classmethod
            def begin_skipped(cls, tree):
                raise unittest.SkipTest("git is not installed")

            def test_rejecting(self):
                tree, result = self.started("rejecting")
                log.append(("rejecting", tree, result))
                self.assert_rejects(result, REASON)

            def test_rejecting_again(self):
                self.assertIs(self.started("rejecting")[1], self.started("rejecting")[1])

            def test_broken(self):
                self.started("broken")

            def test_skipped(self):
                self.started("skipped")

            def test_no_slow_run(self):
                pass

        for name, method in methods.items():
            setattr(Case, name, method)
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(Case).run(result)
        return result, log

    def test_each_test_gets_its_own_run(self):
        result, log = self.run_class()
        self.assertEqual(result.testsRun, 5)
        self.assertEqual(result.failures, [])
        # The run that could not start is an error of the test that asked for it only.
        self.assertEqual([test.id().rsplit(".", 1)[1] for test, _ in result.errors], ["test_broken"])
        self.assertIn("no planted artifact 'no/such/artifact.yml'", result.errors[0][1])
        self.assertEqual([(test.id().rsplit(".", 1)[1], why) for test, why in result.skipped],
                         [("test_skipped", "git is not installed")])
        # One copy for the planted run and good() for the control: two starts, once.
        starts = [entry[1] for entry in log if entry[0] == "start"]
        self.assertEqual(len(starts), 2)
        planted = next(entry for entry in log if entry[0] == "rejecting")
        self.assertIs(planted[1], starts[0])
        self.assertTrue(planted[1].root.startswith(planted[1].sandbox))
        for tree in starts:
            self.assertFalse(os.path.exists(tree.sandbox))      # deleted after the class

    def test_the_control_runs_the_same_command_in_the_good_copy(self):
        seen = []

        def test_control(case):
            good, result = case.started()
            seen.append((good is case.good(), result.returncode, result.argv[-1]))

        result, _log = self.run_class(test_control=test_control)
        # good() has no gate.py: the start of the control fails, in the control only.
        self.assertEqual(sorted(test.id().rsplit(".", 1)[1] for test, _ in result.errors),
                         ["test_broken", "test_control"])
        self.assertIn("gate.py is not in the copy", dict(
            (test.id().rsplit(".", 1)[1], text) for test, text in result.errors)["test_control"])
        self.assertEqual(seen, [])


if __name__ == "__main__":
    unittest.main()
