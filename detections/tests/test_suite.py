"""
Gate tests, group `suite`: rules that hold for the gates and the suite as a whole.

    SelfTests         every script with a `--self-test` mode has a runner: a workflow
                      step, or one test of this class for each self-test that no
                      workflow runs
    GateTestsJob      the gate-tests job of detection-quality.yml runs every test of
                      this suite, on every pull request, and fails when a test fails
    PipedSteps        no step of any workflow pipes a command into `tee` with a
                      shell that loses the exit code of the command
    KnownGapList      every @known_gap names an item of section 1 of docs/ROADMAP.md,
                      and no open gap names an item that is `done`
    PlantedArtifacts  every file under known_bad/ is planted by a test, and none has
                      a name that a gate or a lint of the repository reads

How the harness works: gatelib.py and README.md in this directory.

    python3 -B -m unittest discover -s detections/tests -p 'test_suite.py' -v
"""

import json
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gatelib  # noqa: E402  (the line above makes it importable with `-t .` too)


class SelfTests(gatelib.GateCase):
    """A self-test checks a gate on constructed inputs. It protects nothing when
    nothing runs it. Each script that has a `--self-test` mode must have a runner:
    a workflow step, or a test of this class."""

    PARTS = gatelib.ALL
    DECLARES = re.compile(r"""add_argument\(\s*["']--self-test["']""")
    # The self-tests that no workflow runs, and the last line of a run that passed.
    # Add a script here when test_every_self_test_has_a_runner names it: the class
    # then has a test that runs its self-test.
    RUN_HERE = {
        "detections/sigma_explain.py": r"^All self-test checks hold\.$",
    }

    def self_test_scripts(self):
        """Every Python script of the copy that declares the option --self-test (the
        suite's own files left out)."""
        good = self.good()
        return [rel for rel in good.glob("**/*.py") + good.glob(".github/**/*.py")
                if not rel.startswith("detections/tests/") and self.DECLARES.search(good.read(rel))]

    def test_every_self_test_has_a_runner(self):
        scripts = self.self_test_scripts()
        # The search finds the self-tests that are known today (not vacuous).
        for known in ("detections/sigma_explain.py", "detections/check_null_safety.py",
                      ".github/scripts/check_schedule_freshness.py"):
            self.assertIn(known, scripts)
        without = [script for script in scripts if script not in self.RUN_HERE
                   and not any("--self-test" in command for command in gatelib.ci_commands(script))]
        self.assertEqual(without, [], "no workflow step runs the self-test of these scripts, and "
                         "the suite does not run it: add each to SelfTests.RUN_HERE")
        self.assertEqual(sorted(set(self.RUN_HERE) - set(scripts)), [],
                         "RUN_HERE names a script that has no --self-test mode")

    def run_self_test(self, script):
        self.assert_accepts(self.good().run(script, "--self-test"), self.RUN_HERE[script])


def _self_test_of(script):
    def test(self):
        self.run_self_test(script)
    test.__doc__ = f"`python3 {script} --self-test` passes (no workflow runs this self-test)."
    return test


for _script in SelfTests.RUN_HERE:
    setattr(SelfTests, "test_self_test_of_" + re.sub(r"\W", "_", os.path.basename(_script)[:-3]),
            _self_test_of(_script))


class GateTestsJob(gatelib.GateCase):
    """The gate-tests job of detection-quality.yml: the job that runs this suite."""

    WORKFLOW = "detection-quality.yml"
    COMMAND = "detections/tests/gatelib.py"

    def suite(self, verdict):
        """A constructed suite of one test, which passes or fails, beside a copy of
        the harness."""
        tree = gatelib.Tree(("detections/tests/gatelib.py",))
        self.addCleanup(tree.cleanup)
        tree.write("detections/tests/test_one.py",
                   "import unittest\n\n\n"
                   "class One(unittest.TestCase):\n"
                   f"    def test_a(self):\n        {verdict}\n")
        return tree

    def test_ci_runs_every_test_and_allows_no_skip(self):
        commands = gatelib.ci_commands(self.COMMAND)
        self.assertEqual(commands, ["python3 -B detections/tests/gatelib.py --run --no-skips "
                                    '--summary "$GITHUB_STEP_SUMMARY"'])
        # The same command, without the two options of CI, is the documented one.
        self.assert_documented("python3 -B detections/tests/gatelib.py --run")

    def workflow(self):
        import yaml     # PyYAML: in detections/requirements.txt

        path = os.path.join(gatelib.REPO, ".github", "workflows", self.WORKFLOW)
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def test_job_runs_on_every_pull_request(self):
        """A path filter or a condition could skip the job on the change that breaks a
        gate. The workflow has none for pull requests, and the job and its steps
        have no `if:` and no `continue-on-error:`."""
        doc = self.workflow()
        triggers = doc.get("on", doc.get(True))     # YAML 1.1 reads the key `on` as true
        self.assertIn("pull_request", triggers)
        self.assertIsNone(triggers["pull_request"], "pull_request has a filter")
        self.assertEqual(triggers["push"], {"branches": ["main"]})
        job = doc["jobs"]["gate-tests"]
        for node in [job] + job["steps"]:
            self.assertNotIn("if", node)
            self.assertNotIn("continue-on-error", node)

    def test_runner_stops_a_class_that_hangs_before_github_stops_the_job(self):
        """When GitHub stops the job at `timeout-minutes`, the log holds no output of
        the classes after the one that hangs, and no job summary. So the runner's
        timeout for one class (the step gives no --class-timeout, so it is
        gatelib.CLASS_TIMEOUT) must end first, with time left for the other classes
        (about two minutes) and for the steps before the tests."""
        job_seconds = self.workflow()["jobs"]["gate-tests"]["timeout-minutes"] * 60
        self.assertNotIn("--class-timeout", gatelib.ci_commands(self.COMMAND)[0])
        self.assertGreaterEqual(job_seconds - gatelib.CLASS_TIMEOUT, 240,
                                "the class timeout of the runner is not well below the "
                                "timeout of the gate-tests job")
        # One gate run that hangs is reported by its own test, with the gate's output.
        self.assertLess(gatelib.DEFAULT_TIMEOUT, gatelib.CLASS_TIMEOUT)

    def test_ci_step_passes_and_writes_the_summary(self):
        """CONTROL of the step: a suite that passes."""
        step = gatelib.ci_step(self.WORKFLOW, "gate-tests", self.COMMAND)
        tree = self.suite("pass")
        gatelib.assert_accepts(tree.run_step(step), r"^1 test class\(es\), 1 test\(s\), ")
        with open(tree.out("github/github_step_summary"), encoding="utf-8") as fh:
            self.assertRegex(fh.read(), r"(?m)^## Gate tests: passed$")

    def test_ci_step_fails_when_a_test_fails(self):
        """Run the step as GitHub Actions does, on a suite with one failing test: the
        exit code of the runner must reach the step."""
        step = gatelib.ci_step(self.WORKFLOW, "gate-tests", self.COMMAND)
        tree = self.suite("self.fail('planted failure')")
        gatelib.assert_rejects(tree.run_step(step), r"^FAILED: 1 test class\(es\): test_one\.One$",
                               exit_code=1, crash_ok=True)
        with open(tree.out("github/github_step_summary"), encoding="utf-8") as fh:
            self.assertRegex(fh.read(), r"(?m)^## Gate tests: FAILED$")


class PipedSteps(unittest.TestCase):
    """`command | tee file` has the exit code of `tee`. GitHub Actions runs a step
    that has no `shell:` with `bash -e`, without pipefail, so a gate that fails in
    such a step leaves the job green (test_gatelib.py proves that Tree.run_step()
    models this). The rule has no exception: every step that pipes into `tee` has
    `shell: bash` (which sets pipefail) or sets pipefail itself."""

    TEE = re.compile(r"\|&?\s*tee\b")
    PIPEFAIL = re.compile(r"^set\s+(?:-\w+\s+)*-\w*o\s+pipefail\b")

    @classmethod
    def loses_the_exit_code(cls, step):
        """True when a command line of the step pipes into `tee` while the shell of
        the step does not have pipefail."""
        pipefail = step.shell == "bash" or "pipefail" in (step.shell or "")
        for line in gatelib._command_lines(step.run):
            if cls.PIPEFAIL.search(line):
                pipefail = True
            elif re.search(r"^set\s+\+o\s+pipefail\b", line):
                pipefail = False
            elif cls.TEE.search(line) and not pipefail:
                return True
        return False

    def test_the_rule_finds_a_step_that_loses_the_exit_code(self):
        """CONTROL of the rule, on constructed steps: it names the steps that lose
        the exit code, and no other step."""
        def step(name, shell, run):
            return gatelib.Step("w.yml", "job", name, shell, run)

        gate = "python3 detections/gate.py --check"
        loses = [
            step("no shell", None, f"{gate} | tee /tmp/gate.out\n"),
            step("no shell, joined line", None, f"{gate} \\\n  | tee /tmp/gate.out\n"),
            step("no shell, stderr too", None, f"{gate} 2>&1 |tee -a /tmp/gate.out\n"),
            step("sh", "sh", f"{gate} | tee /tmp/gate.out\n"),
            step("pipefail after the pipe", None, f"{gate} | tee /tmp/gate.out\nset -o pipefail\n"),
            step("pipefail switched off", "bash", f"set +o pipefail\n{gate} | tee /tmp/gate.out\n"),
            step("pipefail in a comment", None, f"# set -o pipefail\n{gate} | tee /tmp/gate.out\n")]
        keeps = [
            step("shell: bash", "bash", f"{gate} | tee /tmp/gate.out\n"),
            step("set -o pipefail", None, f"set -o pipefail\n{gate} | tee /tmp/gate.out\n"),
            step("set -euo pipefail", None, f"set -euo pipefail\n{gate} | tee /tmp/gate.out\n"),
            step("explicit shell", "bash --noprofile --norc -eo pipefail {0}",
                 f"{gate} | tee /tmp/gate.out\n"),
            step("no pipe", None, f"{gate} > /tmp/gate.out\n"),
            step("tee in a comment", None, f"# {gate} | tee /tmp/gate.out\n{gate}\n")]
        self.assertEqual([s.name for s in loses + keeps if self.loses_the_exit_code(s)],
                         [s.name for s in loses])

    def test_no_step_pipes_into_tee_without_pipefail(self):
        steps = gatelib.ci_steps()
        piped = [step for step in steps
                 if any(self.TEE.search(line) for line in gatelib._command_lines(step.run))]
        # The search finds the steps of the gates (not vacuous): today more than ten
        # steps pipe a gate into `tee`, and the lint of the TRRs is one of them.
        self.assertGreater(len(piped), 10, "the workflows were not read")
        self.assertIn(("lint-trr.yml", "trr-lint", "Lint TRRs"),
                      [(step.workflow, step.job, step.name) for step in piped])
        self.assertEqual(
            [(step.workflow, step.job, step.name) for step in piped
             if self.loses_the_exit_code(step)], [],
            "these steps pipe a command into `tee` and have no pipefail, so the step takes "
            "the exit code of `tee`: a gate that fails there leaves the job green. Add "
            "`shell: bash` to the step")


class KnownGapList(unittest.TestCase):
    """gatelib.KNOWN_GAPS is the one list of the known gaps. Each gap names the item
    of section 1 ("Trust") of docs/ROADMAP.md that closes it. A gap without an item
    is a gap that nobody will close, so there is no value for `no item`."""

    SECTION = re.compile(r"^## 1\. [^\n]*\n(.*?)^## ", re.MULTILINE | re.DOTALL)
    ITEM = re.compile(r"^\| ([A-Z]\d+[a-z]?) \| \*\*[^|]+ \| ([^|]+?) \| ", re.MULTILINE)
    STATUS = ("done", "in progress", "not started", "owner", "blocked")    # of ROADMAP.md
    SUITE = "R2"        # the item that is this suite: no gap can name it

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(gatelib.REPO, "docs", "ROADMAP.md"), encoding="utf-8") as fh:
            section = cls.SECTION.search(fh.read())
        if not section:
            raise AssertionError("docs/ROADMAP.md: section 1 was not found")
        cls.items = dict(cls.ITEM.findall(section.group(1)))    # ID -> status, section 1
        # Every test module's markers, from a process that imported nothing else.
        listed = subprocess.run(
            [gatelib.PYTHON, "-B", os.path.join(gatelib.TESTS, "gatelib.py"), "--gaps", "--json"],
            capture_output=True, text=True, timeout=120, cwd=gatelib.REPO, check=False)
        if listed.returncode != 0:
            raise AssertionError("gatelib.py --gaps --json failed:\n" + listed.stderr)
        cls.gaps = json.loads(listed.stdout)

    def test_roadmap_table_holds_the_items_of_section_1(self):
        """gatelib.ROADMAP holds exactly the items of section 1 that a gap can name:
        every item but the suite itself. `unplanned` is not an item."""
        self.assertGreater(len(self.items), 10, "docs/ROADMAP.md: section 1 was not read")
        self.assertIn(self.SUITE, self.items)
        for item, status in self.items.items():
            self.assertIn(status, self.STATUS, f"docs/ROADMAP.md: the status of {item}")
        self.assertEqual(sorted(gatelib.ROADMAP), sorted(set(self.items) - {self.SUITE}),
                         "gatelib.ROADMAP and section 1 of docs/ROADMAP.md do not hold the "
                         "same items")

    def test_every_gap_names_an_open_item(self):
        """Each gap names an item of the roadmap, and that item is not `done`. A gap
        whose item is `done` is a contradiction: the item did not close it. Close
        the gap (fix the gate, remove the marker) or name another item."""
        self.assertGreater(len(self.gaps), 0, "the suite has no known gap: check the list")
        for gap in self.gaps:
            with self.subTest(gap=gap["id"]):
                self.assertIn(gap["closes"], gatelib.ROADMAP,
                              f"the gap {gap['id']} names no item of gatelib.ROADMAP")
                self.assertIn(gap["closes"], self.items,
                              f"the gap {gap['id']} names no item of section 1 of "
                              "docs/ROADMAP.md")
                self.assertNotEqual(self.items[gap["closes"]], "done",
                                    f"{gap['closes']} is done in docs/ROADMAP.md, and the "
                                    f"gap {gap['id']} is still recorded as open")

    def test_every_gap_test_is_named_as_a_gap(self):
        """`test_gap_...`: a reader of a test run can tell a gap from a rejection."""
        for gap in self.gaps:
            with self.subTest(gap=gap["id"]):
                self.assertRegex(gap["test"], r"\.test_gap_\w+$")


class PlantedArtifacts(unittest.TestCase):
    """detections/tests/known_bad/ holds what the tests plant, and nothing else."""

    @classmethod
    def setUpClass(cls):
        cls.files = sorted(
            os.path.relpath(os.path.join(directory, name), gatelib.KNOWN_BAD).replace(os.sep, "/")
            for directory, _dirs, names in os.walk(gatelib.KNOWN_BAD) for name in names)
        cls.tests = ""
        for name in sorted(os.listdir(gatelib.TESTS)):
            if re.fullmatch(r"test_\w+\.py", name):
                with open(os.path.join(gatelib.TESTS, name), encoding="utf-8") as fh:
                    cls.tests += fh.read()

    def planted(self, rel):
        """True when the text of a test module names the artifact: its path, a
        directory above it (planted whole), or its directory and its name without
        the extension (a name that a test puts together)."""
        if rel in self.tests:
            return True
        directory, name = rel.rsplit("/", 1)
        parts = directory.split("/")
        if any(f'"{"/".join(parts[:n])}"' in self.tests for n in range(2, len(parts) + 1)):
            return True
        return directory + "/" in self.tests and f'"{name.split(".")[0]}"' in self.tests

    def test_every_artifact_is_planted_by_a_test(self):
        self.assertGreater(len(self.files), 20, "known_bad/ was not read")
        orphans = [rel for rel in self.files if not self.planted(rel)]
        self.assertEqual(orphans, [], "no test names these files of known_bad/: an artifact "
                         "that no test plants proves nothing. Plant it, or delete it")

    def test_no_artifact_has_a_name_that_the_repository_reads(self):
        """check_md_links.py, the anchors check and the merge policy read every .md
        file of the repository, and Python can import a .py file: store a planted
        page as `.md.txt` and a planted module as `.txt`, and plant it under its
        real name."""
        self.assertEqual([rel for rel in self.files if rel.endswith((".md", ".py"))], [])


if __name__ == "__main__":
    unittest.main()
