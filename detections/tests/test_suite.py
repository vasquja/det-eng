"""
Gate tests, group `suite`: rules that hold for the gates and the suite as a whole.

    SelfTests         every script with a `--self-test` mode has a runner: a workflow
                      step, or one test of this class for each self-test that no
                      workflow runs
    GateTestsJob      the gate-tests job of detection-quality.yml runs every test of
                      this suite, on every pull request, and fails when a test fails
    EmulationScriptsJob  the emulation-scripts job of lint-trr.yml runs every test of
                      atomics/tests/ on every pull request, fails when a test fails
                      or a test module does not load, and the suite loses no test
    PipedSteps        no step of any workflow pipes a command into `tee` with a
                      shell that loses the exit code of the command
    ProgramWrites     no module of the suite calls a chmod but gatelib.write_program(),
                      which writes a program under the lock that each start of a
                      child process takes
    SoftSteps         no step that runs a script or the unit tests of the repository
                      has `continue-on-error` (on the step or on its job), but the
                      shadow steps that the class lists
    ValidatorSelection  the four validator workflows select their validator fail
                      safe: the push list and the changes-job lists agree, each git
                      diff of a changes job passes --no-renames, a validator job runs
                      when its changes job did not succeed, and the lists cover the
                      inputs of the job that rule 4 of the class names (JobCondition
                      reads the `if:` of a job)
    JobTimeouts       every job of every workflow has an integer `timeout-minutes`
                      that is larger than the sum of the timeouts of its steps, but
                      a job that calls a reusable workflow (the class lists it); each
                      step of the `changes` job of the four validator workflows has
                      an integer `timeout-minutes` more than 0
    KnownGapList      every @known_gap names an item of section 1 of docs/ROADMAP.md,
                      and no open gap names an item that is `done`
    PlantedArtifacts  every file under known_bad/ is planted by a test, and none has
                      a name that a gate or a lint of the repository reads
    Readme            README.md of this directory agrees with the suite: its example
                      of a known-gap test is a real test, and the content files that
                      it lists are in the repository

How the harness works: gatelib.py and README.md in this directory.

    python3 -B -m unittest discover -s detections/tests -p 'test_suite.py' -v
"""

import ast
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
        "detections/check_mutants.py": r"^self-test: all \d+ checks hold$",
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
        have no `if:` and no `continue-on-error:`. The job has no `needs:`: GitHub
        skips a job when a job that it needs failed."""
        doc = self.workflow()
        triggers = doc.get("on", doc.get(True))     # YAML 1.1 reads the key `on` as true
        self.assertIn("pull_request", triggers)
        self.assertIsNone(triggers["pull_request"], "pull_request has a filter")
        self.assertEqual(triggers["push"], {"branches": ["main"]})
        job = doc["jobs"]["gate-tests"]
        self.assertNotIn("needs", job)
        for node in [job] + job["steps"]:
            self.assertNotIn("if", node)
            self.assertNotIn("continue-on-error", node)

    def test_runner_stops_a_class_that_hangs_before_github_stops_the_job(self):
        """When GitHub stops the job at `timeout-minutes`, the log holds no output of
        the classes after the one that hangs, and no job summary. So the runner's
        timeout for one class (the step gives no --class-timeout, so it is
        gatelib.CLASS_TIMEOUT) must end first, with time left for the other classes
        (the suite must run in less than four minutes on a GitHub runner; today it
        takes about three and a half) and one minute for the steps before the tests."""
        job_seconds = self.workflow()["jobs"]["gate-tests"]["timeout-minutes"] * 60
        self.assertNotIn("--class-timeout", gatelib.ci_commands(self.COMMAND)[0])
        self.assertGreaterEqual(job_seconds - gatelib.CLASS_TIMEOUT, 300,
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


class EmulationScriptsJob(gatelib.GateCase):
    """The emulation-scripts job of lint-trr.yml: the job that runs atomics/tests/, the
    tests of the cloud emulation scripts with a stub in the place of each cloud CLI.

    What the tests prove of a script is their own matter (atomics/tests/README.md).
    The rules here are for the job. It runs every test on every pull request. It
    fails when a test fails, when a test module does not load, and when it finds no
    test. The suite does not lose tests, and no test is skipped.

    Limits. These rules read the workflow and the names in the test modules. They do
    not see code that hides a failure at run time: a test that returns early, a
    decorator or a `run()` of a test class that swallows the failure, `os._exit(0)`
    in a test, a patched TestResult."""

    WORKFLOW = "lint-trr.yml"
    JOB = "emulation-scripts"
    SUITE = "atomics/tests"
    COMMAND = "python3 -B -m unittest discover -s atomics/tests"
    PARTS = (".github/workflows/lint-trr.yml", "atomics")
    # The number of tests of the suite when this number was last changed. A lower
    # count fails: a test that goes away needs a reason in the pull request, and then
    # a lower number here. Raise the number when the suite grows.
    TESTS = 254
    # The whole job: the version of each action, the names of the steps and the
    # Python version (which has its own rule) are left out. A step more, a line more
    # in the test step, an `env:`, a `working-directory:` or a different runner can
    # make the job run fewer tests, or tests of a different tree.
    JOB_FORM = {"name": "emulation-scripts", "runs-on": "ubuntu-latest", "timeout-minutes": 10,
                "steps": [{"uses": "actions/checkout"},
                          {"uses": "actions/setup-python", "with": {"python-version": "3.12 or later"}},
                          {"run": COMMAND + " -v"}]}
    # Names that skip a test or let a failing test pass: unittest ends with 0 for both.
    SKIP_NAMES = {"skip", "skipIf", "skipUnless", "skipTest", "SkipTest", "expectedFailure"}
    SKIP_TEXT = ("__unittest_skip__", "__unittest_expecting_failure__")
    ONE = "import unittest\n\n\nclass One(unittest.TestCase):\n    def test_a(self):\n        {}\n"
    # What the discovery of the step loads. A module that did not load, and a module
    # that is skipped as a whole, are one entry of the class unittest.loader gives.
    LOADED = (
        "import inspect, os, sys, unittest\n"
        "def cases(suite):\n"
        "    for item in suite:\n"
        "        if isinstance(item, unittest.TestSuite):\n"
        "            yield from cases(item)\n"
        "        else:\n"
        "            yield item\n"
        "found = list(cases(unittest.defaultTestLoader.discover(sys.argv[1])))\n"
        "real = [case for case in found if type(case).__module__ != 'unittest.loader']\n"
        "print('tests loaded:', len(real))\n"
        "print('modules that did not load:', len(found) - len(real))\n"
        "for path in sorted({inspect.getfile(type(case)) for case in real}):\n"
        "    print('file:', os.path.relpath(path, sys.argv[1]).replace(os.sep, '/'))\n")

    def step(self):
        return gatelib.ci_step(self.WORKFLOW, self.JOB, self.COMMAND)

    def workflow(self):
        import yaml     # PyYAML: in detections/requirements.txt

        path = os.path.join(gatelib.REPO, ".github", "workflows", self.WORKFLOW)
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def suite(self, **modules):
        """A constructed atomics/tests/ that holds the given modules, beside a copy of
        the workflow."""
        tree = gatelib.Tree((".github/workflows/" + self.WORKFLOW,))
        self.addCleanup(tree.cleanup)
        for name, text in modules.items():
            tree.write(f"{self.SUITE}/{name}.py", text)
        return tree

    def modules(self):
        """{file under atomics/tests/, relative to it: its text}, for each Python file."""
        root = os.path.join(gatelib.REPO, *self.SUITE.split("/"))
        found = {}
        for directory, _dirs, names in os.walk(root):
            for name in names:
                if name.endswith(".py"):
                    path = os.path.join(directory, name)
                    with open(path, encoding="utf-8") as fh:
                        found[os.path.relpath(path, root).replace(os.sep, "/")] = fh.read()
        self.assertGreater(len(found), 5, "atomics/tests/ was not read")
        return found

    def loaded(self, env=None):
        """(number of tests, files that hold them) that the discovery of the step loads
        from a copy of the real suite. The tests do not run here: the job runs them."""
        result = self.good().run_python(self.LOADED, self.SUITE, env=env)
        gatelib.assert_accepts(result, r"^modules that did not load: 0$")
        count = int(re.search(r"^tests loaded: (\d+)$", result.stdout, re.MULTILINE).group(1))
        return count, re.findall(r"^file: (.+)$", result.stdout, re.MULTILINE)

    @staticmethod
    def the_tests_of(text):
        """The test methods of a module: (name, is it `async def`), from its syntax tree."""
        return [(item.name, isinstance(item, ast.AsyncFunctionDef))
                for node in ast.walk(ast.parse(text)) if isinstance(node, ast.ClassDef)
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test")]

    @classmethod
    def skips(cls, text):
        """The names in a module that skip a test, from its syntax tree: also under an
        alias (`import unittest as ut`, `from unittest import skip as later`)."""
        names = set()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.alias):
                names.add(node.name.rsplit(".", 1)[-1])
        return sorted(names & cls.SKIP_NAMES) + [word for word in cls.SKIP_TEXT if word in text]

    def test_ci_runs_the_documented_command(self):
        """The step runs the discovery of unittest on the whole directory: no pattern,
        no name of one module. The same command, without `-v`, is the documented
        one. `python -m` reads modules from the root first: no file there may take
        the place of unittest."""
        self.assertEqual(gatelib._command_lines(self.step().run), [self.COMMAND + " -v"])
        self.assert_documented(self.COMMAND)
        for name in ("unittest.py", "unittest"):
            self.assertFalse(os.path.exists(os.path.join(gatelib.REPO, name)),
                             f"{name} at the root of the repository takes the place of unittest")

    def test_job_runs_on_every_pull_request(self):
        """The workflow has no path filter for pull requests and no setting above its
        jobs (a `concurrency:` group can cancel a run, `defaults:` and `env:` change
        each step). The job is JOB_FORM and nothing more: no `if:`, no `needs:`
        (GitHub skips a job when a job that it needs failed), no
        `continue-on-error:`, no step that is not in the form."""
        doc = self.workflow()
        triggers = doc.get("on", doc.get(True))     # YAML 1.1 reads the key `on` as true
        self.assertIn("pull_request", triggers)
        self.assertIsNone(triggers["pull_request"], "pull_request has a filter")
        self.assertEqual({key for key in doc if key not in (True, "on")}, {"name", "permissions", "jobs"},
                         f"{self.WORKFLOW} has a setting above its jobs that this test does not know")
        job = json.loads(json.dumps(doc["jobs"][self.JOB]))      # a copy
        for step in job["steps"]:
            step.pop("name", None)
            if "uses" in step:
                step["uses"] = step["uses"].split("@")[0]
            version = str((step.get("with") or {}).get("python-version", ""))
            # unittest ends with 5 when it ran no test from Python 3.12; "3.x" is the newest.
            if version == "3.x" or re.fullmatch(r"3\.(1[2-9]|[2-9]\d)", version):
                step["with"]["python-version"] = "3.12 or later"
        self.assertEqual(job, self.JOB_FORM,
                         f"the job {self.JOB} is not the form that this test holds. Change the "
                         "job back, or change JOB_FORM and say in the pull request why the job "
                         "still runs every test of atomics/tests/ on every pull request")

    def test_every_test_is_in_a_module_that_the_discovery_loads(self):
        """A file under atomics/tests/ that holds a test method, and from which the
        discovery of the step loads no test, holds tests that never run: a name that
        is not `test*.py`, or a directory below that is not a package."""
        modules = self.modules()
        with_tests = sorted(name for name, text in modules.items() if self.the_tests_of(text))
        self.assertEqual(with_tests, self.loaded()[1],
                         "left: the files of atomics/tests/ that hold a test method; right: the "
                         "files from which `unittest discover -s atomics/tests` loads a test")
        # unittest does not wait for an `async def` test of a plain TestCase: it passes.
        self.assertEqual({name: [test for test, is_async in self.the_tests_of(text) if is_async]
                          for name, text in modules.items()
                          if any(is_async for _test, is_async in self.the_tests_of(text))}, {})

    def test_no_test_of_the_suite_is_skipped(self):
        """unittest ends with 0 when it skipped a test, and the step has no option that
        refuses a skip. So the suite holds no name that skips a test, and none that
        makes a failure an expected one."""
        skipped = {     # CONTROL: each form is found
            "import unittest\n\n\nclass A(unittest.TestCase):\n    @unittest.skip('x')\n    def test_a(self): pass\n": ["skip"],
            "import unittest as ut\n\n\nclass A(ut.TestCase):\n    @ut.skipUnless(False, 'x')\n    def test_a(self): pass\n": ["skipUnless"],
            "from unittest import TestCase, skipIf as only_when\n\n\nclass A(TestCase):\n    @only_when(True, 'x')\n    def test_a(self): pass\n": ["skipIf"],
            "import unittest\n\n\nclass A(unittest.TestCase):\n    def test_a(self):\n        self.skipTest('x')\n": ["skipTest"],
            "import unittest\nraise unittest.SkipTest('x')\n": ["SkipTest"],
            "import unittest\n\n\nclass A(unittest.TestCase):\n    @unittest.case.expectedFailure\n    def test_a(self): pass\n": ["expectedFailure"],
            "import unittest\n\n\nclass A(unittest.TestCase):\n    def test_a(self): pass\nA.test_a.__unittest_skip__ = True\n": ["__unittest_skip__"],
        }
        not_skipped = [
            "import unittest\n\n\nclass A(unittest.TestCase):\n    def test_a_signal_does_not_skip_the_undo(self): pass\n",
            "# Do not add unittest.skip here.\nunexpectedFailure = None\nskipped = 'a skip in a text'\n"]
        self.assertEqual({text: self.skips(text) for text in list(skipped) + not_skipped if self.skips(text)}, skipped)
        self.assertEqual({name: self.skips(text) for name, text in self.modules().items() if self.skips(text)}, {})

    def test_the_suite_does_not_lose_tests(self):
        """The count of the tests that the discovery of the step loads. It is the same
        with the variables of a GitHub runner: a test that is there only outside of
        CI is not a test of the job."""
        count, _files = self.loaded()
        self.assertGreaterEqual(count, self.TESTS,
                                f"atomics/tests/ holds {count} test(s); it held {self.TESTS}. "
                                "A test that goes away needs a reason in the pull request, "
                                "and then a lower EmulationScriptsJob.TESTS")
        on_a_runner = self.loaded(env={"CI": "true", "GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux"})[0]
        self.assertEqual(on_a_runner, count, "the discovery loads a different number of tests "
                         "with the variables CI, GITHUB_ACTIONS and RUNNER_OS of a GitHub runner")

    def test_control_ci_step_passes_on_a_suite_that_passes(self):
        """CONTROL of the step, on a constructed suite of one test."""
        tree = self.suite(test_one=self.ONE.format("pass"))
        gatelib.assert_accepts(tree.run_step(self.step()), r"^Ran 1 test in ")

    def test_ci_step_fails_when_a_test_fails(self):
        tree = self.suite(test_one=self.ONE.format("self.fail('planted failure')"))
        gatelib.assert_rejects(tree.run_step(self.step()), r"^AssertionError: planted failure$",
                               exit_code=1, crash_ok=True)

    def test_ci_step_fails_when_a_test_module_does_not_load(self):
        """A module that does not import must not make the suite smaller with no word."""
        tree = self.suite(test_one=self.ONE.format("pass"),
                          test_two="import no_such_module_of_the_gate_tests\n")
        gatelib.assert_rejects(tree.run_step(self.step()),
                               r"^ImportError: Failed to import test module: test_two$",
                               exit_code=1, crash_ok=True)

    def test_ci_step_fails_when_the_suite_holds_no_test(self):
        """unittest of Python 3.12 and later ends with 5 when it ran no test. An older
        Python ends with 0 there: the job would pass on an empty directory. The job
        asks for Python 3.12 or later (test_job_runs_on_every_pull_request). This
        test runs the step with the Python of the tests, so it needs 3.12 too."""
        if sys.version_info < (3, 12):
            why = ("the step is run with the Python of the tests, and unittest of Python "
                   f"{sys.version_info.major}.{sys.version_info.minor} ends with 0 when it ran no test")
            if os.environ.get("CI"):
                self.fail("Python 3.12 or later is necessary in CI: " + why)
            self.skipTest(why)
        tree = self.suite(helper="VALUE = 1\n")
        gatelib.assert_rejects(tree.run_step(self.step()), r"^NO TESTS RAN$", exit_code=5)


def chmod_calls(source, filename):
    """(line, innermost function) of each call of a chmod in a module: os.chmod(),
    os.fchmod(), os.lchmod(), a bare chmod() and a method chmod() (pathlib)."""
    found = []

    class Visit(ast.NodeVisitor):
        def __init__(self):
            self.functions = []

        def visit_FunctionDef(self, node):
            self.functions.append(node.name)
            self.generic_visit(node)
            self.functions.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            func = node.func
            name = (func.attr if isinstance(func, ast.Attribute)
                    else func.id if isinstance(func, ast.Name) else None)
            if name in ("chmod", "fchmod", "lchmod"):
                found.append((node.lineno, self.functions[-1] if self.functions else None))
            self.generic_visit(node)

    Visit().visit(ast.parse(source, filename))
    return found


class ProgramWrites(unittest.TestCase):
    """Linux refuses to run a file that a process holds open for writing ("Text file
    busy"), and a child process holds each open file of its parent until it runs its
    own program. Each start of a child process of the suite keeps a lock until the
    child runs its program, so a new child never finds a program held by another
    child (test_gatelib.py proves the lock). gatelib.write_program() writes a program
    under the same lock, so that a child that already runs can also run it. A test
    that writes a program writes it with write_program(): the usual way to make a
    program is a write and a chmod, so no module of the suite calls a chmod outside
    write_program(). The rule sees only a chmod: not a copy that keeps the mode of a
    program (shutil.copy2, which Tree uses), os.open() with a mode, or a chmod
    through a program."""

    ALLOWED = {("gatelib.py", "write_program")}

    def offenders(self, filename, source):
        return [f"{filename}:{line}" for line, function in chmod_calls(source, filename)
                if (filename, function) not in self.ALLOWED]

    def test_the_rule_reads_each_call_of_a_chmod(self):
        source = ("import os, pathlib\nfrom os import chmod\n"
                  "def stub(path):\n"
                  "    os.chmod(path, 0o755)\n"             # line 4
                  "    chmod(path, 0o755)\n"                # line 5
                  "    pathlib.Path(path).chmod(0o755)\n"   # line 6
                  "    os.fchmod(3, 0o755)\n"               # line 7
                  "    text = 'os.chmod(path, 0o755)'\n"    # a text, not a call
                  "def write_program(path):\n"
                  "    os.chmod(path, 0o755)\n")            # line 10
        self.assertEqual(self.offenders("test_x.py", source),
                         ["test_x.py:4", "test_x.py:5", "test_x.py:6", "test_x.py:7",
                          "test_x.py:10"])
        # Only write_program() of gatelib.py may call it.
        self.assertEqual(self.offenders("gatelib.py", source),
                         ["gatelib.py:4", "gatelib.py:5", "gatelib.py:6", "gatelib.py:7"])

    def test_no_module_of_the_suite_sets_a_mode_but_write_program(self):
        offenders, allowed = [], 0
        for name in sorted(os.listdir(gatelib.TESTS)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(gatelib.TESTS, name), encoding="utf-8") as fh:
                source = fh.read()
            offenders += self.offenders(name, source)
            allowed += sum((name, function) in self.ALLOWED
                           for _, function in chmod_calls(source, name))
        self.assertEqual(offenders, [], "write the program with gatelib.write_program()")
        self.assertEqual(allowed, 1)        # the rule reads the one real call


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


class SoftSteps(unittest.TestCase):
    """A step with `continue-on-error` leaves its job green when it fails, and a job
    with it leaves its workflow run green. A gate in such a step gates nothing.
    gatelib.ci_step() refuses such a step, but only for the steps that a test asks
    for. The rule here is for every step of every workflow: no step that runs a
    script of the repository with Python, or its unit tests (`python -m unittest`:
    the tests of the emulation scripts), is soft, but the shadow steps of SHADOW (a
    check that must not block yet)."""

    RUNS = re.compile(r"python[\d.]*\s+(?:-\S+\s+)*(?:[\"']?\S*(?:detections|\.github/scripts|"
                      r"research/tools)/\S+\.py\b|unittest\b)")
    SHADOW = [("validate-apiserver-detections.yml", "validate",
               "Score the pre-emulation log as a live benign slice (shadow)")]

    @classmethod
    def soft_gate_steps(cls, steps):
        """(workflow, job, step name) of the soft steps that run a script of the
        repository."""
        return [(step.workflow, step.job, step.name) for step in steps if step.soft
                and any(cls.RUNS.search(line) for line in gatelib._command_lines(step.run))]

    def test_the_rule_finds_a_soft_step_that_runs_a_gate(self):
        """CONTROL of the rule, on constructed steps: it names the soft steps that run
        a script of the repository, and no other step."""
        def step(name, run, soft):
            return gatelib.Step("w.yml", "job", name, "bash", run, soft)

        found = [
            step("gate", "python3 detections/gate.py --check | tee /tmp/gate.out\n", True),
            step("lint", "python3 -B .github/scripts/lint.py\n", True),
            step("report, base tree", 'python3 "$base/research/tools/report.py" --check\n', True),
            step("joined line", "python3 \\\n  detections/gate.py --check\n", True),
            step("unit tests", "python3 -B -m unittest discover -s atomics/tests -v\n", True)]
        not_found = [
            step("the same gate, not soft", "python3 detections/gate.py --check\n", False),
            step("no script", "sudo systemctl start auditd\nkubectl get pods\n", True),
            step("in a comment", "# python3 detections/gate.py --check\ntrue\n", True),
            step("a list of paths", "patterns='detections/gate.py'\n", True),
            step("a module that is not unittest", "python3 -m pip install -r requirements.txt\n", True),
            step("the unit tests, not soft", "python3 -B -m unittest discover -s atomics/tests\n", False)]
        self.assertEqual(self.soft_gate_steps(found + not_found),
                         [("w.yml", "job", s.name) for s in found])

    def test_no_gate_step_has_continue_on_error(self):
        steps = gatelib.ci_steps()
        # The workflows have soft steps today (the search is not vacuous).
        self.assertGreater(sum(1 for step in steps if step.soft), 0, "no soft step was read")
        self.assertEqual(
            self.soft_gate_steps(steps), self.SHADOW,
            "these steps run a script of the repository, and the step or its job has "
            "`continue-on-error`: a gate that fails there leaves the job (for a step) or "
            "the workflow run (for a job) green. Remove `continue-on-error`; for a check "
            "that must not block yet, add the step to SoftSteps.SHADOW")


class JobCondition:
    """The value of the `if:` of a job, for the forms of the GitHub Actions expression
    language that the validator jobs use: literals ('text', numbers, true, false,
    null), property names (`needs.changes.result`), `!`, `==`, `!=`, `&&`, `||`,
    parentheses and the four status functions. A form that it does not read (another
    function, an index, `<`, a context that the caller does not give) is a
    ValueError: the test then fails, and does not guess.

    The rules of GitHub that it models: an `if:` with no status function gets
    `success() &&` in front; at the level of a job, success() is true when the run
    is not cancelled and each job of `needs` ended in success, failure() when one of
    them failed, cancelled() when the run is cancelled, always() always; `&&` and
    `||` give one of their operands; `==` compares text without letter case, and
    values of two types as numbers; '', 0, null and false are false.

    One of these rules is an assumption that no run on GitHub has shown: at the
    level of a job, cancelled() is true only when the whole run is cancelled (the
    GitHub docs: "Returns true if the workflow was canceled"). It is not verified
    for a job of `needs` that its own job-level `timeout-minutes` stops. That job
    ends as "cancelled", and if cancelled() is then true in a job that needs it,
    `!cancelled()` skips that job. A step that hits its step-level
    `timeout-minutes` fails: the runner (actions/runner, StepsRunner.cs) logs "The
    action '<name>' has timed out after <N> minutes." and marks the step as failed.
    Thus a changes job whose steps all have a step timeout
    ends a hang as a failure, and for a failure the `if:` of each validator job
    runs the validator."""

    TOKEN = re.compile(r"\s*(?:(?P<text>'(?:[^']|'')*')|(?P<number>\d+(?:\.\d+)?)"
                       r"|(?P<op>==|!=|&&|\|\||[!().])|(?P<name>[A-Za-z_][\w-]*))")
    STATUS = ("success", "failure", "cancelled", "always")

    def __init__(self, text):
        text = str(text).strip()
        whole = re.fullmatch(r"\$\{\{(.*)\}\}", text, re.DOTALL)
        text = whole.group(1) if whole else text
        if "${{" in text or "}}" in text:
            raise ValueError(f"{text!r}: an `if:` that mixes text and ${{{{ }}}} is not read")
        self.tokens, at = [], 0
        while text[at:].strip():
            found = self.TOKEN.match(text, at)
            if not found:
                raise ValueError(f"{text!r}: no token at {text[at:]!r}")
            self.tokens.append((found.lastgroup, found.group(found.lastgroup)))
            at = found.end()
        self.text = text.strip()

    def value(self, needs, inputs=None, cancelled=False):
        """True when the job runs. needs: {job id: (result, {output: value})}."""
        self._needs, self._inputs, self._cancelled = needs, inputs or {}, cancelled
        self._at = 0
        result = self._or()
        if self._at != len(self.tokens):
            raise ValueError(f"{self.text!r}: tokens after the end: {self.tokens[self._at:]}")
        if not any(kind == "name" and word.lower() in self.STATUS
                   for kind, word in self.tokens):
            result = self._status("success") and result
        return self.truth(result)

    @staticmethod
    def truth(value):
        if isinstance(value, float) and value != value:        # NaN
            return False
        return value not in (None, False, 0, "")

    @staticmethod
    def _number(value):
        if value is None or isinstance(value, bool):
            return float(bool(value))
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip()) if value.strip() else 0.0
            except ValueError:
                return float("nan")
        return float("nan")

    @classmethod
    def equal(cls, left, right):
        kinds = [None if v is None else bool if isinstance(v, bool) else
                 float if isinstance(v, (int, float)) else type(v) for v in (left, right)]
        if kinds[0] is kinds[1] is str:
            return left.casefold() == right.casefold()
        if kinds[0] is kinds[1]:
            return left == right
        return cls._number(left) == cls._number(right)

    def _peek(self):
        return self.tokens[self._at] if self._at < len(self.tokens) else (None, None)

    def _take(self, word=None):
        kind, found = self._peek()
        if kind is None or (word is not None and found != word):
            raise ValueError(f"{self.text!r}: wanted {word or 'a token'} at token {self._at}")
        self._at += 1
        return kind, found

    def _or(self):
        value = self._and()
        while self._peek() == ("op", "||"):
            self._take()
            right = self._and()
            value = value if self.truth(value) else right
        return value

    def _and(self):
        value = self._equality()
        while self._peek() == ("op", "&&"):
            self._take()
            right = self._equality()
            value = right if self.truth(value) else value
        return value

    def _equality(self):
        value = self._unary()
        while self._peek() in (("op", "=="), ("op", "!=")):
            _, op = self._take()
            same = self.equal(value, self._unary())
            value = same if op == "==" else not same
        return value

    def _unary(self):
        if self._peek() == ("op", "!"):
            self._take()
            return not self.truth(self._unary())
        return self._primary()

    def _primary(self):
        kind, word = self._take()
        if kind == "text":
            return word[1:-1].replace("''", "'")
        if kind == "number":
            return float(word)
        if (kind, word) == ("op", "("):
            value = self._or()
            self._take(")")
            return value
        if kind != "name":
            raise ValueError(f"{self.text!r}: {word!r} is not read here")
        if word in ("true", "false", "null"):
            return {"true": True, "false": False, "null": None}[word]
        if self._peek() == ("op", "("):
            if word.lower() not in self.STATUS:
                raise ValueError(f"{self.text!r}: the function {word}() is not modelled")
            self._take()
            self._take(")")
            return self._status(word.lower())
        names = [word]
        while self._peek() == ("op", "."):
            self._take()
            names.append(self._take()[1])
        if names[0] == "needs":
            value = {job: {"result": result, "outputs": outputs}
                     for job, (result, outputs) in self._needs.items()}
        elif names[0] == "inputs":
            value = self._inputs
        else:
            raise ValueError(f"{self.text!r}: the context {names[0]!r} is not modelled")
        for name in names[1:]:
            value = value.get(name) if isinstance(value, dict) else None
        return value

    def _status(self, name):
        results = [result for result, _ in self._needs.values()]
        if name == "success":
            return not self._cancelled and all(r == "success" for r in results)
        if name == "failure":
            return any(r == "failure" for r in results)
        if name == "cancelled":
            return self._cancelled
        if name == "always":
            return True
        raise ValueError(f"{self.text!r}: the function {name}() is not modelled")


class ValidatorSelection(gatelib.GateCase):
    """The four validator workflows run their heavy, required validator only when a
    pull request changes a file that it reads. A cheap `changes` job decides that
    from `git diff --name-only` of the pull request and a list of paths, and the
    validator job reads its output. A skipped required check counts as passed, so
    each fault in that selection lets a change that breaks a detection merge green.
    The class holds four rules for each workflow of WORKFLOWS:

    1. The lists agree. The `push: paths:` list and the list of the changes job hold
       the same paths (`dir/**` there is `dir/` here). In
       validate-apiserver-detections.yml, step f is the list of validate-apiserver
       and step r the list of validate-apiserver-recommended: the push list is the
       two together, step r holds each rule folder and atomics folder of step f, and
       they differ by the lab-only and recommended-only inputs (APISERVER_ONLY; rule
       4 checks that only that job reads each of them). Each entry names a file or a
       folder of the repository.
    2. Each git command of a changes job that lists changed files passes
       --no-renames. Without it, a rule moved out of a listed folder gives only its
       new path, and the validator is skipped. A test runs each changes step in a
       constructed git repository to show that, and to show that a step whose git
       diff fails writes true. The step gets its `env:` from the workflow (each
       `${{ }}` from a table of the event), for a pull request, a push and a
       scheduled run.
    3. The `if:` of each validator job runs it unless the changes job succeeded and
       said `false`: it runs when the changes job failed (or ended in another way, or
       wrote no output), and not when the run is cancelled (`!cancelled()`, not
       `always()`). The test evaluates the `if:` with JobCondition for each case of
       CASES, so an `if:` of another spelling with the same truth table passes, and
       a form that JobCondition does not read fails. The job keeps its required
       check name and `needs: changes`. The rows of CASES for a changes job that
       ended as cancelled while the run goes on use an assumption about
       cancelled(): the JobCondition docstring records it.
    4. The list of each validator job covers what it reads (job_inputs()): each rule
       file of the validator's MANIFEST and MISS_MANIFEST (check_sufficiency.py reads
       their paths), the atomics folder of each rule folder, each local Python
       module that a script of the job imports (also inside a function; a dynamic
       import is not followed), each path under detections/, atomics/ or .github/
       that a step of the job names, each file that a kind config of the job mounts, and the workflow.

    The rules read text. They do not see a file that a program reads by a name that
    it builds at run time, a step that a different job runs, or the list of
    detections/k8s/ in validate-k8s-detections.yml, which is wider than what the job
    reads (a wider list only runs the validator more often). Two examples of what a
    job reads and rule 4 does not see: the files that score_benign.py reads in the
    soft shadow step of validate-apiserver (detections/benign/budgets.json, the
    corpus slices, detections/RULE_DEFECTS.md and the rule files outside the lists;
    the step is in SoftSteps.SHADOW and cannot change the verdict of the job), and
    the entries of detections/ and detections/sigma/ that the import guard of
    sigma_eval.py lists (the required rule-cases job, which runs on each pull
    request, imports sigma_eval too)."""

    PARTS = ()      # the tests read the repository; the git test uses an empty tree

    WORKFLOWS = {
        "validate-cloud-detections.yml": "detections/validate_cloud_detections.py",
        "validate-k8s-detections.yml": "detections/validate_k8s_detections.py",
        "validate-staticpod-detections.yml": "detections/validate_staticpod_detections.py",
        "validate-apiserver-detections.yml": "detections/validate_apiserver_detections.py",
    }
    # The jobs that the changes job selects: job id -> (required check name, or the
    # name of a check that is not required; the output of the changes job; the step
    # of the changes job that writes it and holds the list of the job).
    JOBS = {
        "validate-cloud-detections.yml": {"validate": ("validate-cloud", "relevant", "f")},
        "validate-k8s-detections.yml": {"validate": ("validate-k8s", "relevant", "f")},
        "validate-staticpod-detections.yml": {"validate": ("validate-staticpod", "relevant", "f")},
        "validate-apiserver-detections.yml": {
            "validate": ("validate-apiserver", "relevant", "f"),
            "validate-recommended": ("validate-apiserver-recommended", "recommended", "r")},
    }
    # validate-apiserver-detections.yml: the inputs of one of its two jobs only. Step f
    # holds the first, step r the second, and the push list both.
    APISERVER_ONLY = {
        "validate": ("detections/k8s/audit-policy-apiserver.yaml",
                     "detections/k8s/kind-apiserver-cluster.yaml",
                     "detections/score_benign.py", "detections/benign_corpus.py"),
        "validate-recommended": ("detections/k8s/audit-policy-recommended.yaml",
                                 "detections/k8s/kind-apiserver-recommended-cluster.yaml"),
    }
    # (case, run cancelled, result of the changes job, its outputs, the job runs). OUT
    # is the output that the job reads. The first rows are the property: run unless
    # the changes job succeeded and said 'false'; never in a cancelled run.
    CASES = (
        ("the changes job failed before its step wrote the output", False, "failure", {}, True),
        ("the changes job failed after its step wrote 'false'", False, "failure",
         {"OUT": "false"}, True),
        ("the changes job ended as cancelled, and the run goes on", False, "cancelled", {}, True),
        ("the changes job ended as cancelled after its step wrote 'false'", False, "cancelled",
         {"OUT": "false"}, True),
        ("the changes job was skipped", False, "skipped", {}, True),
        ("the changes job found a file that the job reads", False, "success", {"OUT": "true"}, True),
        ("the changes job found no file that the job reads", False, "success",
         {"OUT": "false"}, False),
        ("the changes job succeeded and wrote no output", False, "success", {}, True),
        ("the run is cancelled (the output says true)", True, "success", {"OUT": "true"}, False),
        ("the run is cancelled (the changes job failed)", True, "failure", {}, False),
        ("the run is cancelled (the changes job was cancelled)", True, "cancelled", {}, False),
    )
    # A dispatch of the version matrix gives node_image: validate-recommended never
    # runs then (its own condition), and every other job runs as for the other events.
    NODE_IMAGE_ONLY = {"validate-recommended"}
    FOLDER = re.compile(r"(?:detections/sigma|atomics)/[^/]+/")      # a rule or atomics folder
    LISTING = re.compile(r"\bgit\s+(?:-\S+\s+)*(?:diff|diff-tree|log|show|whatchanged)\b")
    REPO_PATH = re.compile(r"(?<![\w./-])(?:\./)?((?:detections|atomics|\.github)/[\w.-]+"
                           r"(?:/[\w.-]+)*/?)")
    PYTHON_SCRIPT = re.compile(r"\bpython[\d.]*\s+(?:-\S+\s+)*([\w./-]+\.py)\b")

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.texts = {}
        for workflow in cls.WORKFLOWS:
            with open(os.path.join(gatelib.REPO, ".github", "workflows", workflow),
                      encoding="utf-8") as fh:
                cls.texts[workflow] = fh.read()
        cls.rules = cls.manifest_rules(sorted(set(cls.WORKFLOWS.values())))

    # -- what the workflows say --------------------------------------------------

    @staticmethod
    def manifest_rules(scripts):
        """{validator script: [repository path of each rule file of its MANIFEST and
        MISS_MANIFEST]}, as R1 of check_sufficiency.py reads them
        (_entry_rule_path), from a process of its own."""
        code = ("import json, os, sys\n"
                "sys.path.insert(0, 'detections')\n"
                "import importlib, check_sufficiency as cs\n"
                "out = {}\n"
                "for script in sys.argv[1:]:\n"
                "    mod = importlib.import_module(os.path.basename(script)[:-3])\n"
                "    out[script] = sorted({os.path.relpath(cs._entry_rule_path(mod, e), cs.REPO)"
                ".replace(os.sep, '/')\n"
                "                          for table in ('MANIFEST', 'MISS_MANIFEST')\n"
                "                          for e in getattr(mod, table, [])})\n"
                "print(json.dumps(out))\n")
        done = subprocess.run([gatelib.PYTHON, "-B", "-c", code, *scripts], cwd=gatelib.REPO,
                              capture_output=True, text=True, timeout=120, check=False)
        if done.returncode != 0:
            raise AssertionError("the MANIFEST tables were not read:\n" + done.stderr)
        rules = json.loads(done.stdout.strip().splitlines()[-1])
        for script in scripts:
            if not rules.get(script):
                raise AssertionError(f"{script}: no rule file was read from its MANIFEST")
        return rules

    _parsed, _imports = {}, {}

    @classmethod
    def docs(cls, texts=None):
        """{workflow: parsed YAML} of the real texts, or of `texts`. Do not change a
        document: the parse of a text is kept for the next call."""
        import yaml     # PyYAML: in detections/requirements.txt

        for text in (texts or cls.texts).values():
            if text not in cls._parsed:
                cls._parsed[text] = yaml.safe_load(text)
        return {workflow: cls._parsed[text] for workflow, text in (texts or cls.texts).items()}

    @staticmethod
    def changes_steps(doc):
        """{step id: run text} of the steps of the changes job that have an id."""
        return {step["id"]: step.get("run") or "" for step in doc["jobs"]["changes"]["steps"]
                if step.get("id")}

    @staticmethod
    def patterns(run):
        """The entries of the `patterns=$(printf '%s\\n' ...)` list of a step, or None."""
        found = re.findall(r"^\s*patterns=\$\(printf '%s\\n' \\\n(.*?)\)\s*$", run,
                           re.MULTILINE | re.DOTALL)
        return re.findall(r"'([^']*)'", found[0]) if len(found) == 1 else None

    @classmethod
    def lists(cls, workflow, doc):
        """(push list as changes-job entries, {step id: entries}, faults). A push
        path `dir/**` is the entry `dir/`; a path without a wildcard is itself."""
        faults, push = [], []
        triggers = doc.get("on", doc.get(True))     # YAML 1.1 reads the key `on` as true
        for path in (triggers.get("push") or {}).get("paths") or []:
            if path.endswith("/**") and not re.search(r"[*?\[\]!]", path[:-3]):
                push.append(path[:-2])
            elif not re.search(r"[*?\[\]!]", path):
                push.append(path)
            else:
                faults.append(f"{workflow}: push: paths: holds {path!r}, a form that the "
                              "changes job cannot mirror (use a path, or dir/**)")
        steps = {}
        for step_id in sorted({step for _, _, step in cls.JOBS[workflow].values()}):
            entries = cls.patterns(cls.changes_steps(doc).get(step_id, ""))
            if entries is None:
                faults.append(f"{workflow}: step {step_id} of the changes job has no "
                              "patterns=$(printf ...) list")
                entries = []
            steps[step_id] = entries
        return push, steps, faults

    # -- rule 1: the lists agree --------------------------------------------------

    @classmethod
    def sync_faults(cls, docs, root=gatelib.REPO):
        faults = []
        for workflow, doc in docs.items():
            push, steps, found = cls.lists(workflow, doc)
            faults += found
            named = {"the push list": push, **{f"step {s}": e for s, e in steps.items()}}
            for where, entries in named.items():
                for entry in sorted({e for e in entries if entries.count(e) > 1}):
                    faults.append(f"{workflow}, {where}: {entry!r} is listed twice")
                for entry in entries:
                    if re.search(r"[*?\[\]]", entry):
                        faults.append(f"{workflow}, {where}: {entry!r} holds a wildcard, which "
                                      "the changes job does not read")
                    elif not (os.path.isdir(os.path.join(root, entry)) if entry.endswith("/")
                              else os.path.isfile(os.path.join(root, entry))):
                        faults.append(f"{workflow}, {where}: {entry!r} names no "
                                      f"{'folder' if entry.endswith('/') else 'file'} of the "
                                      "repository")
            union = set().union(*map(set, steps.values()))
            for entry in sorted(set(push) - union):
                faults.append(f"{workflow}: {entry!r} is in push: paths: and in no list of the "
                              "changes job")
            for entry in sorted(union - set(push)):
                faults.append(f"{workflow}: {entry!r} is in a list of the changes job and not in "
                              "push: paths:")
            if workflow == "validate-apiserver-detections.yml" and {"f", "r"} <= set(steps):
                f, r = set(steps["f"]), set(steps["r"])
                for mine, other, a, b in ((f, r, "f", "r"), (r, f, "r", "f")):
                    for entry in sorted(e for e in mine - other if cls.FOLDER.fullmatch(e)):
                        faults.append(f"{workflow}: step {b} does not hold {entry!r} of step {a} "
                                      "(AGENTS.md, CI wiring: each rule folder and atomics "
                                      "folder is in step f and in step r)")
                for job, step, other in (("validate", f, r), ("validate-recommended", r, f)):
                    only = set(cls.APISERVER_ONLY[job])
                    for entry in sorted((step - other) - only):
                        if not cls.FOLDER.fullmatch(entry):
                            faults.append(f"{workflow}: {entry!r} is only in the list of {job}; "
                                          "add it to the other list, or to "
                                          "ValidatorSelection.APISERVER_ONLY")
                    for entry in sorted(only - (step - other)):
                        faults.append(f"{workflow}: {entry!r} (APISERVER_ONLY, {job}) is not "
                                      f"only in the list of {job}")
        return faults

    # -- rule 2: --no-renames -----------------------------------------------------

    @staticmethod
    def commands(run):
        """The commands of a step (a line cut at `;`, `&&` and `||`), without the
        messages: a command whose first word is echo or printf (after then, else, do,
        `!`) is left out, so `echo "git diff failed; ..."` is not a git command."""
        found = []
        for line in gatelib._command_lines(run):
            for command in re.split(r";|&&|\|\|", line):
                words = command.split()
                while words and words[0] in ("then", "else", "do", "{", "(", "!"):
                    words.pop(0)
                if words and words[0] not in ("echo", "printf"):
                    found.append(" ".join(words))
        return found

    @classmethod
    def rename_faults(cls, docs):
        faults = []
        for workflow, doc in docs.items():
            listings = 0
            for step in doc["jobs"]["changes"]["steps"]:
                for command in cls.commands(step.get("run") or ""):
                    if cls.LISTING.search(command):
                        listings += 1
                        if "--no-renames" not in command.split():
                            faults.append(f"{workflow}, job changes, step "
                                          f"{step.get('id') or step.get('name')!r}: `{command}` "
                                          "does not pass --no-renames")
            if listings == 0:
                faults.append(f"{workflow}: the changes job runs no git command that lists "
                              "changed files (the rule read nothing)")
        return faults

    # -- rule 3: the `if:` of the validator jobs ----------------------------------

    @classmethod
    def condition_faults(cls, docs):
        faults = []
        for workflow, doc in docs.items():
            triggers = doc.get("on", doc.get(True))
            if "pull_request" not in triggers or triggers["pull_request"] is not None:
                faults.append(f"{workflow}: pull_request is not a trigger without a filter, so a "
                              "required check may report no status on a pull request")
            outputs = doc["jobs"]["changes"].get("outputs") or {}
            for job_id, (name, output, step) in cls.JOBS[workflow].items():
                job = doc["jobs"].get(job_id)
                if job is None:
                    faults.append(f"{workflow}: no job {job_id}")
                    continue
                if job.get("name") != name:
                    faults.append(f"{workflow}, job {job_id}: name {job.get('name')!r}, wanted "
                                  f"{name!r} (the name of the check)")
                if job.get("needs") not in ("changes", ["changes"]):
                    faults.append(f"{workflow}, job {job_id}: needs {job.get('needs')!r}, "
                                  "wanted changes")
                wanted = "${{ steps.%s.outputs.%s }}" % (step, output)
                if " ".join(str(outputs.get(output)).split()) != wanted:
                    faults.append(f"{workflow}: the output {output} of the changes job is "
                                  f"{outputs.get(output)!r}, wanted {wanted!r}")
                try:
                    condition = JobCondition(job.get("if", ""))
                    for inputs in ({}, {"node_image": "kindest/node:v9.9.9@sha256:" + "0" * 64}):
                        for case, cancelled, result, values, runs in cls.CASES:
                            values = {output if k == "OUT" else k: v for k, v in values.items()}
                            if inputs and job_id in cls.NODE_IMAGE_ONLY:
                                runs = False
                            got = condition.value({"changes": (result, values)}, inputs,
                                                  cancelled)
                            if got != runs:
                                faults.append(
                                    f"{workflow}, job {job_id}: `if: {job.get('if')}` "
                                    f"{'runs' if got else 'skips'} the job when {case}"
                                    f"{' (node_image given)' if inputs else ''}; wanted "
                                    f"{'run' if runs else 'skip'}")
                except ValueError as e:
                    faults.append(f"{workflow}, job {job_id}: JobCondition cannot read the "
                                  f"`if:`: {e}")
        return faults

    # -- rule 4: the lists cover what each job reads -------------------------------

    @classmethod
    def imported_modules(cls, script, root=gatelib.REPO):
        """The Python files beside `script` that it imports, directly or through such a
        file: each `import x` and `from x import ...` (also in a function), where x.py
        is in the folder of the script. A dynamic import (importlib) is not followed."""
        if (script, root) not in cls._imports:
            cls._imports[script, root] = cls._walk_imports(script, root)
        return cls._imports[script, root]

    @staticmethod
    def _walk_imports(script, root):
        folder, seen, todo = os.path.dirname(script), set(), [script]
        while todo:
            path = todo.pop()
            if path in seen:
                continue
            seen.add(path)
            with open(os.path.join(root, path), encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module.split(".")[0]]
                else:
                    continue
                for name in names:
                    module = f"{folder}/{name}.py" if folder else f"{name}.py"
                    if os.path.isfile(os.path.join(root, module)):
                        todo.append(module)
        return sorted(seen - {script})

    @classmethod
    def job_inputs(cls, workflow, job_id, doc, root=gatelib.REPO):
        """{repository path: why}: what the job reads, as rule 4 says. A path that
        ends with '/' is a folder."""
        validator = cls.WORKFLOWS[workflow]
        needed = {f".github/workflows/{workflow}": "the workflow itself"}
        for rule in cls.rules[validator]:
            needed[rule] = f"a rule of the MANIFEST of {validator}"
            atomics = "atomics/" + rule.split("/")[2] + "/"
            if os.path.isdir(os.path.join(root, atomics)):
                needed[atomics] = f"the atomics folder of {rule}"
        for step in doc["jobs"][job_id].get("steps") or []:
            where = f"named by the step {step.get('name') or step.get('id')!r}"
            for line in gatelib._command_lines(step.get("run") or ""):
                for path in cls.REPO_PATH.findall(line):
                    path = path.rstrip(".")
                    full = os.path.join(root, path)
                    if os.path.isfile(full):
                        needed.setdefault(path, where)
                    elif os.path.isdir(full):
                        needed.setdefault(path.rstrip("/") + "/", where)
                for script in cls.PYTHON_SCRIPT.findall(line):
                    if os.path.isfile(os.path.join(root, script)):
                        for module in cls.imported_modules(script, root):
                            needed.setdefault(module, f"imported by {script}")
        import yaml     # PyYAML: in detections/requirements.txt

        for config in [p for p in needed if re.fullmatch(r"detections/k8s/kind-[\w.-]+\.yaml", p)]:
            with open(os.path.join(root, config), encoding="utf-8") as fh:
                stack = [yaml.safe_load(fh)]
            while stack:
                node = stack.pop()
                if isinstance(node, dict):
                    mount = node.get("hostPath")
                    if isinstance(mount, str) and mount.startswith("./") \
                            and os.path.isfile(os.path.join(root, mount[2:])):
                        needed.setdefault(mount[2:], f"mounted by {config}")
                    stack.extend(node.values())
                elif isinstance(node, list):
                    stack.extend(node)
        return needed

    @staticmethod
    def covered(path, entries):
        if path.endswith("/"):
            return any(e.endswith("/") and path.startswith(e) for e in entries)
        return any(path == e or (e.endswith("/") and path.startswith(e)) for e in entries)

    @classmethod
    def coverage_faults(cls, docs, root=gatelib.REPO, only=None):
        """The faults of rule 4. Also: each path of APISERVER_ONLY (or `only`) is read
        by its job and not by the other job, so the exceptions of rule 1 are true."""
        faults = []
        for workflow, doc in docs.items():
            push, steps, _ = cls.lists(workflow, doc)
            inputs = {job_id: cls.job_inputs(workflow, job_id, doc, root)
                      for job_id in cls.JOBS[workflow]}
            for job_id, (_, _, step) in cls.JOBS[workflow].items():
                for path, why in sorted(inputs[job_id].items()):
                    for where, entries in ((f"step {step}", steps.get(step, [])),
                                           ("the push list", push)):
                        if not cls.covered(path, entries):
                            faults.append(f"{workflow}, {where}: no entry covers {path} ({why}; "
                                          f"read by the job {job_id})")
            if workflow == "validate-apiserver-detections.yml":
                for job_id, paths in (only or cls.APISERVER_ONLY).items():
                    other = next(j for j in inputs if j != job_id)
                    for path in paths:
                        if path not in inputs[job_id] or path in inputs[other]:
                            faults.append(f"{workflow}: APISERVER_ONLY names {path} as an input "
                                          f"of {job_id} only, but {job_id} reads it: "
                                          f"{path in inputs[job_id]}, {other} reads it: "
                                          f"{path in inputs[other]}")
        return faults

    # -- the tests ----------------------------------------------------------------

    def assert_no_faults(self, faults, rule):
        self.assertEqual(faults, [], f"{rule}. A fault lets a pull request skip a required "
                         "validator that it needed (a skipped required check counts as passed)")

    def test_push_and_changes_lists_agree(self):
        self.assert_no_faults(self.sync_faults(self.docs()),
                              "the lists of these workflows do not agree")

    def test_every_listing_of_a_changes_job_passes_no_renames(self):
        self.assert_no_faults(self.rename_faults(self.docs()),
                              "a git command of a changes job detects renames")

    def test_validator_runs_unless_the_changes_job_said_false(self):
        self.assert_no_faults(self.condition_faults(self.docs()),
                              "the `if:` of a validator job does not fail safe")

    def test_lists_cover_what_each_validator_reads(self):
        docs = self.docs()
        # The rule reads what the jobs read (not vacuous): the rules of each
        # MANIFEST, the modules of the import closure, and a mounted audit policy.
        inputs = self.job_inputs("validate-apiserver-detections.yml", "validate",
                                 docs["validate-apiserver-detections.yml"])
        self.assertGreater(sum(p.startswith("detections/sigma/") for p in inputs), 30)
        for path in ("detections/sigma_explain.py", "detections/rule_cases.py",
                     "detections/benign_corpus.py", "atomics/T1557/",
                     "detections/k8s/audit-policy-apiserver.yaml"):
            self.assertIn(path, inputs)
        self.assertIn("detections/check_sufficiency.py", self.imported_modules(
            "detections/validate_cloud_detections.py"))
        self.assert_no_faults(self.coverage_faults(docs),
                              "a list of the changes job does not cover a file that its job "
                              "reads: add the path to the list and to push: paths:")

    def test_the_rules_find_a_fault_of_each_kind(self):
        """CONTROL of the four rules: one fault planted in the text of a real workflow
        at a time. Each rule names that fault, and each fault is found by its rule."""
        def planted(workflow, old, new, count=1):
            text = self.texts[workflow]
            self.assertEqual(text.count(old), count, f"{workflow}: the anchor {old!r} of the "
                             "CONTROL is not in the workflow: correct the CONTROL")
            return self.docs({**self.texts, workflow: text.replace(old, new)})

        cloud, k8s = "validate-cloud-detections.yml", "validate-k8s-detections.yml"
        api = "validate-apiserver-detections.yml"
        for rule, docs, fault in (
                (self.rename_faults, planted(k8s, "git diff --no-renames", "git diff"),
                 r"validate-k8s-detections\.yml, job changes, step 'f': `.*git diff --name-only"),
                (self.rename_faults, planted(api, '--no-renames --name-only "${range}"',
                                             '--name-only "${range}"'),
                 r"step 'r': .* does not pass --no-renames"),
                (self.sync_faults, planted(k8s, "            'detections/sigma/T1609/' \\\n", ""),
                 r"'detections/sigma/T1609/' is in push: paths: and in no list"),
                (self.sync_faults, planted(cloud, "      - 'detections/sigma_explain.py'\n", ""),
                 r"'detections/sigma_explain\.py' is in a list of the changes job and not in push"),
                (self.sync_faults, planted(api, "            'atomics/T1557/' \\\n", "", count=2),
                 r"'atomics/T1557/' is in push: paths: and in no list"),
                (self.sync_faults, planted(api, "            'atomics/T1557/' \\\n            "
                                           "'.github/workflows/validate-apiserver-detections.yml')"
                                           "\n          range=",
                                           "            '.github/workflows/validate-apiserver-"
                                           "detections.yml')\n          range="),
                 r"step r does not hold 'atomics/T1557/' of step f"),
                (self.sync_faults, planted(k8s, "'detections/k8s/' \\", "'detections/k8z/' \\"),
                 r"step f: 'detections/k8z/' names no folder"),
                (self.condition_faults, planted(
                    cloud, "if: ${{ !cancelled() && (needs.changes.result != 'success' || "
                           "needs.changes.outputs.relevant != 'false') }}",
                    "if: needs.changes.outputs.relevant == 'true'"),
                 r"validate-cloud-detections\.yml, job validate: .* skips the job when the "
                 r"changes job failed before"),
                (self.condition_faults, planted(cloud, "!cancelled() &&", "always() &&"),
                 r"runs the job when the run is cancelled"),
                (self.condition_faults, planted(api, "!cancelled() && !inputs.node_image &&",
                                                "!cancelled() &&"),
                 r"job validate-recommended: .* runs the job when the changes job found a file "
                 r"that the job reads \(node_image given\)"),
                (self.condition_faults, planted(cloud, "name: validate-cloud\n",
                                                "name: validate-cloud-detections\n"),
                 r"name 'validate-cloud-detections', wanted 'validate-cloud'"),
                (self.coverage_faults, planted(k8s, "'detections/sigma_explain.py'",
                                               "'detections/sigma_eval.py'", count=2),
                 r"validate-k8s-detections\.yml, step f: no entry covers "
                 r"detections/sigma_explain\.py \(imported by"),
                (self.coverage_faults, planted(api, "'detections/rule_cases.py'",
                                               "'detections/sigma_eval.py'", count=3),
                 r"step r: no entry covers detections/rule_cases\.py \(imported by .*"
                 r"validate-recommended\)"),
                (self.coverage_faults, planted(cloud, "'.github/workflows/validate-cloud-"
                                               "detections.yml'", "'detections/sigma_eval.py'",
                                               count=2),
                 r"no entry covers \.github/workflows/validate-cloud-detections\.yml \(the "
                 r"workflow itself"),
                (self.coverage_faults, planted(cloud, "'atomics/T1537/", "'atomics/T1537x/",
                                               count=2),
                 r"no entry covers atomics/T1537/ \(the atomics folder of "
                 r"detections/sigma/T1537/"),
                (self.coverage_faults, planted(cloud, "'detections/sigma/T1199/",
                                               "'atomics/T1199/", count=2),
                 r"no entry covers detections/sigma/T1199/\w+\.yml \(a rule of the MANIFEST"),
                (self.coverage_faults, planted(
                    "validate-staticpod-detections.yml",
                    "'detections/k8s/audit-policy-staticpod.yaml'", "'detections/sigma_eval.py'",
                    count=2),
                 r"no entry covers detections/k8s/audit-policy-staticpod\.yaml \(mounted by "
                 r"detections/k8s/kind-staticpod-cluster\.yaml"),
                (self.coverage_faults, planted(
                    "validate-staticpod-detections.yml", "'detections/k8s/cri-pod-sensor.sh'",
                    "'detections/sigma_eval.py'", count=2),
                 r"no entry covers detections/k8s/cri-pod-sensor\.sh \(named by the step")):
            with self.subTest(rule=rule.__name__, fault=fault):
                faults = rule(docs)
                self.assertTrue(any(re.search(fault, f) for f in faults),
                                f"{rule.__name__} did not name the planted fault; it gave "
                                f"{faults}")
        # An exception of APISERVER_ONLY that is not true: the recommended job does not
        # read score_benign.py, and validate-apiserver reads cri-pod-sensor.sh too.
        faults = self.coverage_faults(self.docs(), only={
            "validate": self.APISERVER_ONLY["validate"],
            "validate-recommended": ("detections/score_benign.py",
                                     "detections/k8s/cri-pod-sensor.sh")})
        self.assertEqual([f.split(" as an input")[0] for f in faults], [
            "validate-apiserver-detections.yml: APISERVER_ONLY names detections/score_benign.py",
            "validate-apiserver-detections.yml: APISERVER_ONLY names "
            "detections/k8s/cri-pod-sensor.sh"])

    def test_job_condition_reads_the_rules_of_github(self):
        """CONTROL of JobCondition, on constructed expressions."""
        failed = {"changes": ("failure", {})}
        failed_true = {"changes": ("failure", {"relevant": "true"})}
        said_false = {"changes": ("success", {"relevant": "false"})}
        said_true = {"changes": ("success", {"relevant": "TRUE"})}
        for text, needs, cancelled, wanted in (
                # The implicit success(): an `if:` without a status function skips the
                # job when a job of `needs` failed, whatever the rest says.
                ("needs.changes.result != 'success'", failed, False, False),
                ("needs.changes.outputs.relevant == 'true'", failed_true, False, False),
                ("needs.changes.outputs.relevant == 'true'", failed, False, False),
                ("needs.changes.outputs.relevant == 'true'", said_true, False, True),
                ("${{ needs.changes.outputs.relevant == 'true' }}", said_true, False, True),
                ("always() && needs.changes.result != 'success'", failed, True, True),
                ("!cancelled() && needs.changes.result != 'success'", failed, True, False),
                ("failure()", failed, False, True),
                ("success()", said_false, True, False),
                ("!cancelled() && (needs.changes.result != 'success' || "
                 "needs.changes.outputs.relevant != 'false')", said_false, False, False),
                ("!cancelled() && needs.changes.result != 'success' || "
                 "needs.changes.outputs.relevant != 'false'", said_true, True, True),
                ("!cancelled() && needs.changes.outputs.nothing", said_true, False, False),
                ("!cancelled() && !inputs.node_image", said_true, False, True),
                ("!cancelled() && 'a' && ''", said_true, False, False),
                # `&&` and `||` give one of their operands, not true or false.
                ("!cancelled() && ('a' && 'b') == 'b'", said_true, False, True),
                ("!cancelled() && ('' || 'x') == 'x'", said_true, False, True),
                ("!cancelled() && null == 0 && 1 == '1' && true == 1 && 'x' != 0", failed,
                 False, True),
                ("!cancelled() && 'it''s' == 'IT''S'", failed, False, True)):
            with self.subTest(text=text, cancelled=cancelled):
                self.assertIs(JobCondition(text).value(needs, {}, cancelled), wanted)
        for text in ("contains(needs.changes.result, 'fail')", "github.event_name == 'push'",
                     "needs.changes.result < 'z'", "needs['changes'].result",
                     "x${{ always() }}", "(always()", "always() always()"):
            with self.subTest(refused=text):
                with self.assertRaises(ValueError):
                    JobCondition(text).value(failed)

    def test_a_moved_rule_selects_the_validator(self):
        """Each changes step (step f, and step r of validate-apiserver-detections.yml),
        run as GitHub Actions runs it, in a constructed git repository whose head moves
        a rule out of a folder of the step's list to detections/sigma/T9999/: the
        output is true. CONTROLs: a head that changes only README.md gives false, and
        the same step without --no-renames gives false on the moved rule (so git in
        this test detects renames, and --no-renames is what selects the validator).
        The step also fails safe: with a BASE_SHA that names no commit of the
        repository, its git diff fails, and the output is true. The environment of
        the step comes from its `env:` in the workflow, with a value for each
        `${{ }}` from a table of the event (an expression that the table does not
        hold fails the test), and a push of the moved rule and a scheduled run give
        true too."""
        gatelib.require_program("git", "the changes steps run git diff")
        for workflow, jobs in self.JOBS.items():
            doc = self.docs()[workflow]
            for _, output, step_id in jobs.values():
                with self.subTest(workflow=workflow, step=step_id):
                    run = self.changes_steps(doc)[step_id]
                    folder = next(e for e in self.patterns(run)
                                  if re.fullmatch(r"detections/sigma/T[\d.]+/", e))
                    self.assertFalse(self.covered("detections/sigma/T9999/moved_rule.yml",
                                                  self.patterns(run)),
                                     "the list covers the target of the move: the test "
                                     "needs a target outside the list")
                    tree = self.tree()
                    env = {"GIT_DIR": tree.path(".git"), "GIT_WORK_TREE": tree.root,
                           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}

                    def git(*args):
                        result = tree.run_command(["git", *args], env=env)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        return result.stdout.strip()

                    git("init", "-q")
                    tree.write("README.md", "base\n")
                    tree.write(folder + "moved_rule.yml", "title: moved rule\n" * 20)
                    git("add", "-A")
                    git("commit", "-q", "-m", "base")
                    base = git("rev-parse", "HEAD")
                    tree.rename(folder + "moved_rule.yml", "detections/sigma/T9999/moved_rule.yml")
                    git("add", "-A")
                    git("commit", "-q", "-m", "move")
                    moved = git("rev-parse", "HEAD")
                    git("checkout", "-q", base)
                    tree.write("README.md", "changed\n")
                    git("commit", "-q", "-am", "readme")
                    readme = git("rev-parse", "HEAD")
                    step = gatelib.Step(workflow, "changes", step_id, "bash", run)
                    renames = step._replace(run=run.replace("--no-renames ", ""))
                    self.assertNotEqual(renames.run, run)
                    # A commit id that is not in the repository: the listing of the
                    # step fails (CONTROL), so the step must take its fail-safe way.
                    lost = "1" * 40
                    listing = tree.run_command(["git", "diff", "--no-renames", "--name-only",
                                                f"{lost}...{moved}"], env=env)
                    self.assertNotEqual(listing.returncode, 0,
                                        f"git diff of {lost}...{moved} did not fail")
                    step_env = next(s for s in doc["jobs"]["changes"]["steps"]
                                    if s.get("id") == step_id).get("env") or {}
                    pr = lambda start, head: {
                        "github.event_name": "pull_request",
                        "github.event.pull_request.base.sha": start,
                        "github.event.pull_request.head.sha": head,
                        "github.event.before": "", "github.sha": head}
                    for case, ran, event, wanted in (
                            ("moved rule", step, pr(base, moved), "true"),
                            ("README.md only", step, pr(base, readme), "false"),
                            ("moved rule, without --no-renames", renames, pr(base, moved), "false"),
                            ("the git listing fails (BASE_SHA names no commit)", step,
                             pr(lost, moved), "true"),
                            ("a push of the moved rule", step, {
                                "github.event_name": "push",
                                "github.event.pull_request.base.sha": "",
                                "github.event.pull_request.head.sha": "",
                                "github.event.before": base, "github.sha": moved}, "true"),
                            ("a scheduled run", step, {
                                "github.event_name": "schedule",
                                "github.event.pull_request.base.sha": "",
                                "github.event.pull_request.head.sha": "",
                                "github.event.before": "", "github.sha": moved}, "true")):
                        values = {}
                        for name, text in step_env.items():
                            found = re.fullmatch(r"\$\{\{\s*([\w.]+)\s*\}\}", str(text))
                            self.assertTrue(found and found.group(1) in event,
                                            f"env {name}: {text!r} is not modelled")
                            values[name] = event[found.group(1)]
                        out = tree.out("github/github_output")
                        open(out, "w", encoding="utf-8").close()
                        result = tree.run_step(ran, env={**env, **values})
                        self.assertEqual(result.returncode, 0, f"{case}: {result.stderr}")
                        with open(out, encoding="utf-8") as fh:
                            written = [line for line in fh.read().splitlines()
                                       if line.startswith(output + "=")]
                        self.assertEqual(written, [f"{output}={wanted}"],
                                         f"{case}: the step wrote {written}; wanted "
                                         f"{output}={wanted}, one time\n{result.stdout}")


class JobTimeouts(unittest.TestCase):
    """GitHub stops a job that has no `timeout-minutes` after 360 minutes. Until then
    a job that hangs holds a runner (the account runs about 20 jobs at one time), a
    required check stays pending, and a job in a concurrency group (automerge.yml)
    makes each later job of its group wait. So each job of each workflow has a
    `timeout-minutes` that is an integer, more than 0 and less than 360. The
    timeouts of its steps are integers too, and the timeout of the job is larger
    than their sum: when each step with a timeout uses all of it, the job still has
    time for its other steps.

    A job that calls a reusable workflow (`uses:` on the job) cannot have
    `timeout-minutes`: the jobs of the called workflow have their own. Such a job
    must be in CALLS_A_WORKFLOW, by its workflow file and its id, and each entry of
    CALLS_A_WORKFLOW must be such a job.

    A step that gets to its `timeout-minutes` fails, so its job ends as a failure. A
    job that gets to its `timeout-minutes` is cancelled. The `changes` job of each
    workflow in SELECTORS tells the validator job of its workflow if it must run, and
    the fail-safe condition of the validator job runs it when the `changes` job
    fails. So each step of such a `changes` job has an integer `timeout-minutes` more
    than 0: a step that hangs then fails the job, and the timeout of the job does not
    cancel it.

    The rule reads the YAML. It does not see whether a value is large enough for a
    slow run, or too large: the pull request that sets a value says how it was
    measured, and a comment beside a value gives the reason when it is not plain.
    The class reads the files with PyYAML, which applies merge keys (`<<:`) and keeps
    the last of two equal keys; the parser of GitHub does not accept these forms, and
    a workflow that GitHub rejects does not run (a required check then blocks the
    merge)."""

    LIMIT = 360     # minutes: GitHub stops each job of a GitHub-hosted runner here
    # (workflow file, job id) of each job that calls a reusable workflow. None today.
    CALLS_A_WORKFLOW = []
    # The workflows whose job `changes` tells the validator job if it must run.
    SELECTORS = ("validate-cloud-detections.yml", "validate-k8s-detections.yml",
                 "validate-staticpod-detections.yml", "validate-apiserver-detections.yml")

    @classmethod
    def faults(cls, workflow, doc, callers=None):
        """What is wrong with the timeouts of the jobs of one workflow (its file name
        and its parsed YAML), as one sentence per fault (empty: nothing). `callers`
        replaces CALLS_A_WORKFLOW."""
        callers = cls.CALLS_A_WORKFLOW if callers is None else callers
        faults = []
        for job_id, job in ((doc or {}).get("jobs") or {}).items():
            where = f"{workflow}, job {job_id}"
            if not isinstance(job, dict):
                faults.append(f"{where} is not a mapping")
                continue
            if "uses" in job:
                if (workflow, job_id) not in callers:
                    faults.append(f"{where} calls a reusable workflow and is not in "
                                  "JobTimeouts.CALLS_A_WORKFLOW")
                continue
            minutes = job.get("timeout-minutes")
            if minutes is None:
                faults.append(f"{where} has no timeout-minutes (GitHub stops it after "
                              f"{cls.LIMIT} minutes)")
                continue
            if type(minutes) is not int:        # a bool is an int to isinstance()
                faults.append(f"{where}: timeout-minutes is {minutes!r}, not an integer")
                continue
            if not 0 < minutes < cls.LIMIT:
                faults.append(f"{where}: timeout-minutes is {minutes}, not more than 0 "
                              f"and less than {cls.LIMIT}")
                continue
            steps = [step.get("timeout-minutes") for step in job.get("steps") or []
                     if isinstance(step, dict) and "timeout-minutes" in step]
            not_int = [value for value in steps if type(value) is not int]
            if not_int:
                faults.append(f"{where}: a step has timeout-minutes {not_int[0]!r}, not an "
                              "integer")
            elif sum(steps) >= minutes:
                faults.append(f"{where}: timeout-minutes is {minutes}, not larger than the "
                              f"sum of the timeouts of its steps ({sum(steps)})")
        return faults

    @classmethod
    def stale_callers(cls, workflows, callers=None):
        """Each entry of `callers` (default CALLS_A_WORKFLOW) that is not a job that
        calls a reusable workflow in `workflows` ({file name: parsed YAML}), or that
        the list holds two times, as one sentence per entry (empty: nothing)."""
        callers = cls.CALLS_A_WORKFLOW if callers is None else callers
        faults = []
        for number, (workflow, job_id) in enumerate(callers):
            job = ((workflows.get(workflow) or {}).get("jobs") or {}).get(job_id)
            if (workflow, job_id) in callers[:number]:
                faults.append(f"JobTimeouts.CALLS_A_WORKFLOW names {workflow}, job {job_id}, "
                              "two times")
            elif not (isinstance(job, dict) and "uses" in job):
                faults.append(f"JobTimeouts.CALLS_A_WORKFLOW names {workflow}, job {job_id}, "
                              "which is not a job that calls a reusable workflow")
        return faults

    @classmethod
    def changes_step_faults(cls, workflows):
        """Each step of the job `changes` of each workflow in SELECTORS that has no
        integer `timeout-minutes` more than 0, as one sentence per step (empty:
        nothing). `workflows` is {file name: parsed YAML}. A workflow of SELECTORS
        that is not in `workflows`, or whose job `changes` has no steps, is a fault
        too: the rule then checks nothing."""
        faults = []
        for workflow in cls.SELECTORS:
            job = ((workflows.get(workflow) or {}).get("jobs") or {}).get("changes")
            steps = job.get("steps") if isinstance(job, dict) else None
            if not isinstance(steps, list) or not steps:
                faults.append(f"{workflow} has no job changes with steps")
                continue
            for number, step in enumerate(steps, 1):
                step = step if isinstance(step, dict) else {}
                minutes = step.get("timeout-minutes")
                if type(minutes) is not int or minutes <= 0:
                    label = step.get("id") or step.get("name") or step.get("uses") or "?"
                    faults.append(f"{workflow}, job changes, step {number} ({label}): "
                                  f"timeout-minutes is {minutes!r}, not an integer more than "
                                  "0 (the timeout of the job then cancels the job, and a "
                                  "cancel does not fail it)")
        return faults

    @staticmethod
    def workflows(root=gatelib.REPO):
        """{file name: parsed YAML} of each workflow under <root>/.github/workflows/."""
        import glob
        import yaml     # PyYAML: in detections/requirements.txt

        found = {}
        for path in sorted(glob.glob(os.path.join(root, ".github", "workflows", "*.y*ml"))):
            with open(path, encoding="utf-8") as fh:
                found[os.path.basename(path)] = yaml.safe_load(fh) or {}
        return found

    def test_the_rule_finds_a_job_without_a_timeout(self):
        """CONTROL of the rule, on constructed workflows: it names each job whose
        timeout is missing or wrong, and no other job."""
        import yaml     # PyYAML: in detections/requirements.txt

        doc = yaml.safe_load(
            "on: push\n"
            "jobs:\n"
            "  good:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n"
            "    steps:\n      - run: 'true'\n        timeout-minutes: 4\n"
            "      - run: 'true'\n        timeout-minutes: 5\n"
            "  none:\n    runs-on: ubuntu-latest\n    steps:\n      - run: 'true'\n"
            "  expression:\n    runs-on: ubuntu-latest\n    timeout-minutes: ${{ 5 }}\n"
            "  text:\n    runs-on: ubuntu-latest\n    timeout-minutes: '5'\n"
            "  fraction:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5.5\n"
            "  boolean:\n    runs-on: ubuntu-latest\n    timeout-minutes: true\n"
            "  zero:\n    runs-on: ubuntu-latest\n    timeout-minutes: 0\n"
            "  default:\n    runs-on: ubuntu-latest\n    timeout-minutes: 360\n"
            "  steps-fill-it:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n"
            "    steps:\n      - run: 'true'\n        timeout-minutes: 10\n"
            "      - run: 'true'\n        timeout-minutes: 5\n"
            "  step-expression:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n"
            "    steps:\n      - run: 'true'\n        timeout-minutes: ${{ 5 }}\n"
            "  step-null:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n"
            "    steps:\n      - run: 'true'\n        timeout-minutes:\n"
            "  null-job:\n"
            "  listed-caller:\n    uses: ./.github/workflows/called.yml\n"
            "  caller:\n    uses: ./.github/workflows/called.yml\n")
        faults = self.faults("w.yml", doc, callers=[("w.yml", "listed-caller")])
        named = [re.match(r"w\.yml, job ([\w-]+)", fault).group(1) for fault in faults]
        self.assertEqual(named, ["none", "expression", "text", "fraction", "boolean", "zero",
                                 "default", "steps-fill-it", "step-expression", "step-null",
                                 "null-job", "caller"])
        self.assertIn("has no timeout-minutes", faults[0])
        # A value of 0 is out of range; the sum rule (0 steps, 0 >= 0) is not the reason.
        self.assertIn("timeout-minutes is 0, not more than 0 and less than 360", faults[5])
        self.assertIn("not larger than the sum of the timeouts of its steps (15)", faults[7])
        self.assertIn("a step has timeout-minutes None, not an integer", faults[9])
        self.assertIn("w.yml, job null-job is not a mapping", faults[10])
        self.assertIn("calls a reusable workflow and is not in", faults[-1])
        # Without the list, the listed caller is a fault too.
        self.assertIn("w.yml, job listed-caller calls a reusable workflow",
                      " / ".join(self.faults("w.yml", doc)))
        # An entry of the list that is not a job that calls a reusable workflow is stale,
        # and an entry that the list holds two times is a fault.
        stale = self.stale_callers({"w.yml": doc}, callers=[
            ("w.yml", "listed-caller"), ("w.yml", "good"), ("w.yml", "null-job"),
            ("gone.yml", "caller"), ("w.yml", "listed-caller")])
        self.assertEqual(stale, [
            f"JobTimeouts.CALLS_A_WORKFLOW names {name}, job {job_id}, which is not a job "
            "that calls a reusable workflow"
            for name, job_id in (("w.yml", "good"), ("w.yml", "null-job"), ("gone.yml", "caller"))]
            + ["JobTimeouts.CALLS_A_WORKFLOW names w.yml, job listed-caller, two times"])
        self.assertEqual(self.stale_callers({"w.yml": doc}, callers=[("w.yml", "caller")]), [])

    def test_the_rule_finds_a_step_of_a_changes_job_without_a_timeout(self):
        """CONTROL of the rule on the steps of the job `changes`, on constructed
        workflows: it names each step whose timeout is missing or wrong, each
        workflow of SELECTORS without such a job, and no other step."""
        import yaml     # PyYAML: in detections/requirements.txt

        def changes(*steps):
            return yaml.safe_load("jobs:\n  changes:\n    runs-on: ubuntu-latest\n"
                                  "    timeout-minutes: 15\n    steps:\n" + "".join(steps))

        good = ("      - uses: actions/checkout@v4\n        timeout-minutes: 5\n"
                "      - id: f\n        run: 'true'\n        timeout-minutes: 3\n")
        cloud, k8s, staticpod, apiserver = JobTimeouts.SELECTORS
        workflows = {
            cloud: changes("      - uses: actions/checkout@v4\n        timeout-minutes: 5\n",
                           "      - id: f\n        run: 'true'\n"),
            k8s: changes(good),
            staticpod: changes("      - id: a\n        run: 'true'\n        timeout-minutes:\n",
                               "      - id: b\n        run: 'true'\n        timeout-minutes: 0\n",
                               "      - id: c\n        run: 'true'\n        timeout-minutes: true\n",
                               "      - id: d\n        run: 'true'\n        timeout-minutes: '3'\n",
                               "      - id: e\n        run: 'true'\n        timeout-minutes: 1\n"),
            # Not a workflow of SELECTORS: its job changes is not checked.
            "other.yml": changes("      - id: f\n        run: 'true'\n"),
        }
        faults = self.changes_step_faults(workflows)
        self.assertEqual([fault.split(":")[0] for fault in faults], [
            f"{cloud}, job changes, step 2 (f)",
            f"{staticpod}, job changes, step 1 (a)", f"{staticpod}, job changes, step 2 (b)",
            f"{staticpod}, job changes, step 3 (c)", f"{staticpod}, job changes, step 4 (d)",
            f"{apiserver} has no job changes with steps"])
        self.assertIn("timeout-minutes is None, not an integer more than 0", faults[0])
        # Each workflow of SELECTORS with a good job changes: no fault.
        self.assertEqual(self.changes_step_faults(dict.fromkeys(JobTimeouts.SELECTORS,
                                                                changes(good))), [])

    def test_workflows_reads_each_yml_and_yaml_file(self):
        """CONTROL of workflows(): it reads a `.yml` and a `.yaml` file under
        <root>/.github/workflows/, and no other file."""
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            folder = os.path.join(root, ".github", "workflows")
            os.makedirs(folder)
            for name in ("a.yml", "b.yaml", "c.txt"):
                with open(os.path.join(folder, name), "w", encoding="utf-8") as fh:
                    fh.write("jobs:\n  j:\n    runs-on: ubuntu-latest\n")
            found = self.workflows(root)
        self.assertEqual(sorted(found), ["a.yml", "b.yaml"])
        self.assertEqual(found["b.yaml"], {"jobs": {"j": {"runs-on": "ubuntu-latest"}}})

    def test_every_job_has_a_timeout(self):
        workflows = self.workflows()
        jobs = [(name, job_id) for name, doc in workflows.items()
                for job_id in (doc.get("jobs") or {})]
        # The workflows were read (not vacuous): today 13 files with 40 jobs.
        self.assertGreater(len(workflows), 10, "the workflows were not read")
        self.assertGreater(len(jobs), 30, "the jobs of the workflows were not read")
        for known in (("validate-detections.yml", "validate"), ("automerge.yml", "automerge"),
                      ("detection-quality.yml", "gate-tests")):
            self.assertIn(known, jobs)
        self.assertEqual(
            [fault for name, doc in workflows.items() for fault in self.faults(name, doc)], [],
            "give each of these jobs a `timeout-minutes` (an integer of minutes) that is "
            "larger than the sum of the timeouts of its steps; GitHub stops a job without "
            "one after 360 minutes")
        self.assertEqual(self.stale_callers(workflows), [],
                         "JobTimeouts.CALLS_A_WORKFLOW must name only jobs that call a "
                         "reusable workflow")
        self.assertEqual(self.changes_step_faults(workflows), [],
                         "give each step of these jobs `changes` a `timeout-minutes` (an "
                         "integer of minutes): a step that gets to its timeout fails its job")


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
        # The text of the test modules that plant. This module plants nothing: it
        # holds the rule and the names of its control, which must not count.
        cls.tests = ""
        for name in sorted(os.listdir(gatelib.TESTS)):
            if re.fullmatch(r"test_\w+\.py", name) and name != os.path.basename(__file__):
                with open(os.path.join(gatelib.TESTS, name), encoding="utf-8") as fh:
                    cls.tests += fh.read()

    def planted(self, rel):
        """True when the text of a test module names the artifact: its path, a
        directory above it (planted whole), or a name that a test puts together. For
        such a name the text holds an f-string that starts with the directory, and a
        call of a helper `plant_...()` or `run_...()` with the name, without the
        extension, as its first argument (`self.run_bad_cases("line_not_json")`)."""
        if rel in self.tests:
            return True
        directory, name = rel.rsplit("/", 1)
        parts = directory.split("/")
        if any(f'"{"/".join(parts[:n])}"' in self.tests for n in range(2, len(parts) + 1)):
            return True
        return (f'f"{directory}/{{' in self.tests and re.search(
            rf'\b(?:plant|run)_\w+\("{re.escape(name.split(".")[0])}"[,)]', self.tests)
            is not None)

    def test_every_artifact_is_planted_by_a_test(self):
        self.assertGreater(len(self.files), 20, "known_bad/ was not read")
        orphans = [rel for rel in self.files if not self.planted(rel)]
        self.assertEqual(orphans, [], "no test names these files of known_bad/: an artifact "
                         "that no test plants proves nothing. Plant it, or delete it")

    def test_the_rule_finds_a_file_that_no_test_plants(self):
        """CONTROL of the rule, on constructed names beside real ones. A name that is
        a quoted word of some test (`positive`, a kind of case; `name_keyed`, a run of
        CheckSufficiency) is not a planted artifact."""
        for rel in ("sufficiency/bad_cases/line_not_json.cases.jsonl",      # put together
                    "sufficiency/bad_cases/sound.cases.jsonl",              # named by its path
                    "sufficiency/hidden_rule/hidden.yml",                   # named by its path
                    "sufficiency/trivial_near_miss/planted_trivial_near_miss.yml"):    # whole
            self.assertIn(rel, self.files)
            self.assertTrue(self.planted(rel), rel)
        for word in ("positive", "name_keyed"):
            self.assertIn(f'"{word}"', self.tests)
        for rel in ("sufficiency/bad_cases/positive.cases.jsonl",
                    "sufficiency/bad_cases/name_keyed.cases.jsonl",
                    "sufficiency/bad_cases/no_such_case.cases.jsonl",
                    "sufficiency/hidden_rule/never_planted.yml",
                    "quality/orphan_rule.yml"):
            self.assertNotIn(rel, self.files)
            self.assertFalse(self.planted(rel), rel)

    def test_no_artifact_has_a_name_that_the_repository_reads(self):
        """check_md_links.py, the anchors check and the merge policy read every .md
        file of the repository, and Python can import a .py file: store a planted
        page as `.md.txt` and a planted module as `.txt`, and plant it under its
        real name."""
        self.assertEqual([rel for rel in self.files if rel.endswith((".md", ".py"))], [])


class Readme(unittest.TestCase):
    """detections/tests/README.md says how to write a test. A reader copies what it
    shows, so where it shows a test or lists files, it must agree with the suite."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(gatelib.TESTS, "README.md"), encoding="utf-8") as fh:
            cls.readme = fh.read()

    @staticmethod
    def section(readme, heading):
        """The text of the section `## heading` of a README text, or None."""
        found = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", readme,
                          re.MULTILINE | re.DOTALL)
        return found.group(1) if found else None

    @classmethod
    def example_faults(cls, readme, modules):
        """What is wrong with the example of a known-gap test in a README text, as a
        list of sentences (empty: nothing). `modules` is {file name: text} of the
        test modules.

        The example must be the text of one test of the suite, word for word (a
        method of a class, so with four more spaces in the module). It must also
        show the rules that the section gives: the marker, the proof that the gate
        read the artifact or that the artifact is bad, and one assert_rejects() as
        its last statement."""
        section = cls.section(readme, "Known gaps")
        if section is None:
            return ["README.md has no section `## Known gaps`"]
        blocks = re.findall(r"^```python\n(.*?)^```$", section, re.MULTILINE | re.DOTALL)
        if len(blocks) != 1:
            return [f"the section `Known gaps` holds {len(blocks)} Python examples; wanted 1"]
        example, faults = blocks[0], []
        if not example.startswith("@gatelib.known_gap("):
            faults.append("the example does not start with the @gatelib.known_gap marker")
        in_module = "".join("    " + line if line.strip() else line
                            for line in example.splitlines(keepends=True))
        homes = [name for name, text in sorted(modules.items()) if in_module in text]
        if len(homes) != 1:
            faults.append(f"the example is the text of a test in {len(homes)} test module(s); "
                          "wanted 1 (copy the test again: the marker and the whole body)")
        if "self.assert_saw(" not in example and "if result.returncode == 0:" not in example:
            faults.append("the example has no assert_saw() and no proof inside "
                          "`if result.returncode == 0:`")
        last = [line.strip() for line in example.splitlines() if line.strip()][-1:]
        if not (last and last[0].startswith("self.assert_rejects(")):
            faults.append("the last statement of the example is not self.assert_rejects()")
        return faults

    @staticmethod
    def modules_of_the_suite():
        modules = {}
        for name in sorted(os.listdir(gatelib.TESTS)):
            if re.fullmatch(r"test_\w+\.py", name):
                with open(os.path.join(gatelib.TESTS, name), encoding="utf-8") as fh:
                    modules[name] = fh.read()
        return modules

    def test_the_example_check_finds_an_example_that_is_not_a_real_test(self):
        """CONTROL of the check, on constructed README texts and one constructed
        test module."""
        test = ('@gatelib.known_gap("constructed-gap", gate="gate.py", closes="R7",\n'
                '                   reason="A constructed gate accepts every artifact.")\n'
                "def test_gap_constructed(self):\n"
                "    result = self.tree().run(self.GATE)\n"
                '    self.assert_saw(result, r"^Loaded 0 record")\n\n'
                '    self.assert_rejects(result, r"^FAIL  planted")\n')
        modules = {"test_one.py": "class One(gatelib.GateCase):\n" + "".join(
            "    " + line if line.strip() else line for line in test.splitlines(keepends=True))}

        def readme(example, heading="Known gaps"):
            return f"# Gate tests\n\n## {heading}\n\nText.\n\n```python\n{example}```\n\n## CI\n"

        self.assertEqual(self.example_faults(readme(test), modules), [])
        for example, fault in (
                # The example of the first README: no proof that the gate read the artifact.
                (test.replace('    self.assert_saw(result, r"^Loaded 0 record")\n\n', ""),
                 "is the text of a test in 0 test module(s)"),
                (test.replace('    self.assert_saw(result, r"^Loaded 0 record")\n\n', ""),
                 "no assert_saw() and no proof inside"),
                (test.replace("closes=\"R7\"", "closes=\"unplanned\""),
                 "is the text of a test in 0 test module(s)"),
                (test.replace("    self.assert_rejects(", "    self.assert_accepts("),
                 "the last statement of the example is not self.assert_rejects()"),
                (test.split("\n", 2)[2], "does not start with the @gatelib.known_gap marker")):
            self.assertIn(fault, " / ".join(self.example_faults(readme(example), modules)))
        self.assertIn("holds 2 Python examples",
                      self.example_faults(readme(test + "```\n\n```python\n" + test), modules)[0])
        self.assertIn("no section `## Known gaps`",
                      self.example_faults(readme(test, "Gaps"), modules)[0])

    def test_known_gap_example_is_a_real_test(self):
        self.assertEqual(self.example_faults(self.readme, self.modules_of_the_suite()), [])

    def test_content_files_that_limits_lists_are_in_the_repository(self):
        """`Limits` lists the content files whose text the tests depend on. A file
        that was renamed or deleted must leave the lists (the test that named it
        was corrected in the same change)."""
        limits = self.section(self.readme, "Limits")
        self.assertIsNotNone(limits, "README.md has no section `## Limits`")
        listed = re.findall(r"^  - `([^`\n]+)`$", limits, re.MULTILINE)
        # The lists were read (not vacuous): today they hold more than 20 files, and
        # the rule that most tests change is one of them.
        self.assertGreater(len(listed), 20, "the lists of content files were not read")
        self.assertIn("detections/sigma/T1040/afinet_raw_socket.yml", listed)
        self.assertEqual(len(listed), len(set(listed)), "a file is listed twice")
        self.assertEqual(
            [rel for rel in listed if not os.path.isfile(os.path.join(gatelib.REPO, rel))], [],
            "`Limits` of detections/tests/README.md lists these files, and the repository "
            "does not have them: correct the lists")


if __name__ == "__main__":
    unittest.main()
