"""
Gate tests, group `suite`: rules that hold for the gates and the suite as a whole.

    SelfTests         every script with a `--self-test` mode has a runner: a workflow
                      step, or one test of this class for each self-test that no
                      workflow runs
    GateTestsJob      the gate-tests job of detection-quality.yml runs every test of
                      this suite, on every pull request, and fails when a test fails
    KnownGapList      every @known_gap names a roadmap item of docs/ROADMAP.md, and
                      no open gap names an item that is `done`
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

    def test_job_runs_on_every_pull_request(self):
        """A path filter or a condition could skip the job on the change that breaks a
        gate. The workflow has none for pull requests, and the job and its steps
        have no `if:` and no `continue-on-error:`."""
        import yaml     # PyYAML: in detections/requirements.txt

        path = os.path.join(gatelib.REPO, ".github", "workflows", self.WORKFLOW)
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        triggers = doc.get("on", doc.get(True))     # YAML 1.1 reads the key `on` as true
        self.assertIn("pull_request", triggers)
        self.assertIsNone(triggers["pull_request"], "pull_request has a filter")
        self.assertEqual(triggers["push"], {"branches": ["main"]})
        job = doc["jobs"]["gate-tests"]
        for node in [job] + job["steps"]:
            self.assertNotIn("if", node)
            self.assertNotIn("continue-on-error", node)

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


class KnownGapList(unittest.TestCase):
    """gatelib.KNOWN_GAPS is the one list of the known gaps. Each gap names what
    closes it: an item of section 1 of docs/ROADMAP.md, or `unplanned`."""

    ITEM = re.compile(r"^\| ([A-Z]\d+[a-z]?) \| \*\*[^|]+ \| ([^|]+?) \| ", re.MULTILINE)

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(gatelib.REPO, "docs", "ROADMAP.md"), encoding="utf-8") as fh:
            cls.items = dict(cls.ITEM.findall(fh.read()))       # ID -> status
        # Every test module's markers, from a process that imported nothing else.
        listed = subprocess.run(
            [gatelib.PYTHON, "-B", os.path.join(gatelib.TESTS, "gatelib.py"), "--gaps", "--json"],
            capture_output=True, text=True, timeout=120, cwd=gatelib.REPO, check=False)
        if listed.returncode != 0:
            raise AssertionError("gatelib.py --gaps --json failed:\n" + listed.stderr)
        cls.gaps = json.loads(listed.stdout)

    def test_roadmap_table_names_items_of_the_roadmap(self):
        self.assertGreater(len(self.items), 10, "docs/ROADMAP.md: the item tables were not read")
        planned = sorted(set(gatelib.ROADMAP) - {"unplanned"})
        self.assertEqual([item for item in planned if item not in self.items], [],
                         "gatelib.ROADMAP holds an ID that docs/ROADMAP.md does not have")

    def test_every_gap_names_an_open_item(self):
        """A gap whose roadmap item is `done` is a contradiction: the item did not
        close it. Close the gap (fix the gate, remove the marker) or name another
        item."""
        self.assertGreater(len(self.gaps), 0, "the suite has no known gap: check the list")
        for gap in self.gaps:
            with self.subTest(gap=gap["id"]):
                self.assertIn(gap["closes"], gatelib.ROADMAP)
                if gap["closes"] != "unplanned":
                    self.assertNotEqual(self.items[gap["closes"]].lower(), "done",
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
