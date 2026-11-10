"""
Tests of the harness itself (gatelib.py). The harness decides if a gate test is
green, so it is a gate too: these tests plant faults in constructed gates (small
scripts in an empty tree) and prove that the assertions and the known-gap marker
tell a rejection from an acceptance, a crash, a wrong reason and a broken test.

No test here runs a gate of the repository; the whole file takes about ten seconds.

    python3 -B -m unittest discover -s detections/tests -p 'test_gatelib.py' -v
"""

import json
import os
import shutil
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
                  closes="R7", _registry=registry)

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

    def test_cleanup_waits_for_a_background_run(self):
        """No copy is deleted under a running gate: cleanup() waits for the runs that
        nobody collected."""
        tree = gatelib.Tree(())
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
        "    @gatelib.known_gap('constructed-other-gap', gate='other.py', closes='unplanned',\n"
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
        self.assertIn("| `constructed-other-gap` | `other.py` | accepts | unplanned | not run | ",
                      text)
        self.assertIn("| `constructed-open-gap` | `gate.py` | accepts | R7 | open | ", text)

    def test_options_of_the_run_need_run(self):
        result = self.suite().run("detections/tests/gatelib.py", "--gaps", "--no-skips")
        self.assertEqual(result.returncode, 2, result.describe())
        self.assertIn("need --run", result.stderr)


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

    def test_require_program_skips_here_and_fails_in_ci(self):
        self.assertEqual(gatelib.require_program("sh", "x"), shutil.which("sh"))
        with mock.patch.dict(os.environ, clear=False):
            os.environ.pop("CI", None)
            with self.assertRaisesRegex(unittest.SkipTest, "no-such-program-x is not installed"):
                gatelib.require_program("no-such-program-x", "a test needs it")
            os.environ["CI"] = "true"
            with self.assertRaisesRegex(AssertionError, "is not installed in CI: a test needs it"):
                gatelib.require_program("no-such-program-x", "a test needs it")

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
