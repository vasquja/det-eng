"""
Tests of the harness itself (gatelib.py). The harness decides if a gate test is
green, so it is a gate too: these tests plant faults in constructed gates (small
scripts in an empty tree) and prove that the assertions and the known-gap marker
tell a rejection from an acceptance, a crash, a wrong reason and a broken test.

No test here runs a gate of the repository; the whole file takes about a second.

    python3 -B -m unittest discover -s detections/tests -p 'test_gatelib.py' -v
"""

import json
import os
import subprocess
import sys
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

        @gatelib.known_gap("constructed-gap", gate="gate.py", closes="R2", today=today,
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
                  closes="R2", _registry={})
        for change, message in (
                (dict(closes="R99"), "not a roadmap item"),
                (dict(closes=""), "not a roadmap item"),
                (dict(reason="todo"), "give a reason"),
                (dict(gate=" "), "name the gate"),
                (dict(today="skipped"), "is not one of")):
            with self.assertRaisesRegex(ValueError, message):
                gatelib.known_gap("constructed-gap", **{**ok, **change})
        with self.assertRaisesRegex(ValueError, "lower-case letters"):
            gatelib.known_gap("Constructed Gap", **ok)
        gatelib.known_gap("constructed-gap", **ok)(lambda case: None)
        with self.assertRaisesRegex(ValueError, "used twice"):
            gatelib.known_gap("constructed-gap", **ok)(lambda case: None)

    def test_same_test_registered_twice_is_one_gap(self):
        """unittest can import one test module under two names; that is not a duplicate."""
        registry = {}
        ok = dict(gate="gate.py", reason="A constructed gate accepts a trivial near-miss.",
                  closes="R2", _registry=registry)

        def test(case):
            pass

        gatelib.known_gap("constructed-gap", **ok)(test)
        gatelib.known_gap("constructed-gap", **ok)(test)
        self.assertEqual(list(registry), ["constructed-gap"])

    def test_report_prints_every_registered_gap(self):
        registry = {}
        for gap_id, closes, today in (("gap-one", "R7", "accepts"), ("gap-two", "unplanned", "crash")):
            gatelib.known_gap(gap_id, gate=f"{gap_id}.py", closes=closes, today=today,
                              reason=f"The constructed gate of {gap_id} accepts | rejects nothing.",
                              _registry=registry)(lambda case: None)
        text = gatelib.gap_report(registry)
        table = gatelib.gap_report(registry, markdown=True)
        self.assertIn("Known gaps of the gates: 2", text)
        for gap_id, closes, today in (("gap-one", "R7", "accepts"), ("gap-two", "unplanned", "crash")):
            self.assertRegex(text, rf"(?s)  {gap_id}\n.*today:  {today}\n\s+closes: {closes} \(")
            self.assertIn(f"| `{gap_id}` | `{gap_id}.py` | {today} | {closes} | ", table)
        self.assertIn("accepts \\| rejects nothing", table)      # a `|` cannot break the table

    def test_command_line_lists_the_gaps_of_every_test_module(self):
        """KNOWN_GAPS is the one list of the suite: `gatelib.py --gaps` imports every
        test module and prints each marker with a roadmap item."""
        listed = subprocess.run(
            [gatelib.PYTHON, os.path.join(gatelib.TESTS, "gatelib.py"), "--gaps", "--json"],
            capture_output=True, text=True, timeout=60, cwd=gatelib.REPO,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(listed.returncode, 0, listed.stderr)
        gaps = json.loads(listed.stdout)
        self.assertIn("hidden-rule-file", [gap["id"] for gap in gaps])
        for gap in gaps:
            self.assertIn(gap["closes"], gatelib.ROADMAP)
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
        with self.assertRaisesRegex(ValueError, "occurs 0 time"):
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
                  "GITHUB_REPOSITORY": "o/r", "TRR9002_POD": "x", "PYTHONPATH": "/nowhere"}
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
        for run in pending:
            gatelib.assert_accepts(run.result(), r"All cases hold")
        with self.assertRaises(FileNotFoundError):
            tree.start("no_such_gate.py")


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

    def test_ci_step_finds_one_step(self):
        step = gatelib.ci_step("detection-quality.yml", "rule-cases", "detections/rule_cases.py")
        self.assertEqual(step.shell, "bash")
        with self.assertRaises(LookupError):
            gatelib.ci_step("detection-quality.yml", "rule-cases", "detections/no_such_gate.py")


class Runner(unittest.TestCase):
    """`gatelib.py --run`: the parallel runner must fail when any class fails, when a
    class did not run all of its tests, and when a test module does not import."""

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
        self.assertIn("===== test_one.Good: ok, 2 test(s)", result.stdout)
        self.assertIn("===== test_one.AlsoGood: ok, 1 test(s)", result.stdout)
        self.assertRegex(result.stdout, r"(?m)^OK$")

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

    def test_a_module_that_does_not_import_fails_the_run_and_the_gap_list(self):
        tree = self.suite()
        tree.write("detections/tests/test_two.py", "import no_such_module_of_the_suite\n")
        for arguments in (("--run",), ("--gaps",)):
            result = tree.run("detections/tests/gatelib.py", *arguments)
            gatelib.assert_rejects(result, r"^a test module does not import:", exit_code=1,
                                   crash_ok=True)
            self.assertIn("no_such_module_of_the_suite", result.stderr)


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


if __name__ == "__main__":
    unittest.main()
