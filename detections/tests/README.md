# Gate tests

The gates are the checks that CI runs to decide if work is done: `rule_cases.py`,
`check_sufficiency.py`, `score_benign.py`, the validators, the lints. A change to
a gate can stop it from rejecting bad work, and no other check sees that. This
suite holds planted bad artifacts and proves, for each one, that its gate rejects
it for the intended reason. A control proves that the same gate accepts the tree
before the artifact is planted.

A planted artifact that is rejected for another reason proves nothing. For
example, a stale generated file fails many gates, whatever else is in the tree.
Thus each test asserts the words of the gate's message that name the planted
defect, and not only the exit code.

## Run

From the repository root, with the Python that has `detections/requirements.txt`:

```bash
python3 -B detections/tests/gatelib.py --run                                     # all, in parallel (CI)
python3 -B detections/tests/gatelib.py --run test_quality                        # the classes of one group
python3 -B -m unittest discover -s detections/tests -v                           # all, in sequence
python3 -B -m unittest discover -s detections/tests -p 'test_sufficiency.py' -v  # one group
python3 -B -m unittest discover -s detections/tests -k trivial -v                # by name
python3 -B detections/tests/gatelib.py --gaps                                    # the known gaps
```

`gatelib.py --run` runs the same tests as `unittest discover`, with one Python
process for each test class, as many at a time as the machine has CPUs. Then it
prints the known gaps. It takes about 100 seconds on a development machine with four
CPUs, and about three and a half minutes on a GitHub runner (four CPUs). The
tests in sequence take about four minutes on the development machine. It fails:

- when a class fails;
- when a class did not run all of its tests;
- when a class does not end in ten minutes (`--class-timeout SECONDS` changes
  the limit);
- when a test module does not import;
- when a run of the whole suite did not run the test of a known gap (a marker
  on a method that `unittest` does not collect).

`--no-skips` also fails the run when a test was skipped, and `--summary PATH`
adds the result and the known gaps to a file as Markdown. CI uses both.

The runner takes the counts of a class (tests that ran, tests that were skipped)
from the `TestResult` of the class. It reads no line of the text that `unittest`
prints, because the format of that text differs between Python versions.

`-B` stops Python from writing `__pycache__/` beside the tests. The suite uses
only the standard library (`unittest`), PyYAML and pySigma. It needs no network
and no root. It runs on Python 3.10 and later (3.10 is the minimum of pySigma).

Five conditions skip a test:

- `gcc` is not installed. The class `LinuxValidatorDryRun` is skipped: the Linux
  dry run compiles the atomics.
- `git` is not installed. One test of `SufficiencyRatchet` is skipped: it runs
  the steps of the sufficiency-ratchet job, which make a worktree of the base
  commit.
- The environment pins git to a repository: `GIT_DIR`, `GIT_WORK_TREE`,
  `GIT_INDEX_FILE` or a variable like them is set (git sets them for a hook). The
  same test is skipped, because the gate runs would work on that repository.
- The Python of the tests is older than 3.12. One test of `EmulationScriptsJob` is
  skipped: it runs the step of the `emulation-scripts` job on a directory with no
  test, and unittest ends with 5 there only from Python 3.12.
- `bash` is older than 5.0. Two tests of `LedgerClock` are skipped: they run the
  clock function of the emulation scripts with the clock of bash
  (`EPOCHREALTIME`, from bash 5.0). A third test is skipped when `bash` is older
  than 4.2: it needs `printf '%(...)T'`.

In CI (the variable `CI` is set) each of these conditions fails the test in
place of a skip, and `--no-skips` fails the run when a test was skipped. So no
test is skipped in CI.

The `re2` module (the package google-re2) skips no test. With it, the tests of
`check_sigma_regex.py` and `check_provider_mappings.py` pass `--require-re2`, as
their CI jobs do. Without it, they run the default path. The gate-tests job
installs `detections/requirements.txt` only.

The copies are made under the system temporary directory (`TMPDIR`) and deleted
after each test or test class.

## Layout

| Path | Content |
|------|---------|
| `gatelib.py` | The harness: `Tree`, `GateCase`, `StartedTogether`, `assert_rejects`, `assert_accepts`, `assert_saw`, `known_gap`, `ci_step`, `ci_commands`, and the parallel runner. |
| `test_gatelib.py` | Tests of the harness, on constructed gates. |
| `test_sufficiency.py` | `rule_cases.py` (and through it the event table of `sigma_eval.py`), the import guard of `sigma_eval.py`, `check_sufficiency.py` (R0 to R4 and the waiver digests), the sufficiency ratchet, the self-test of `sigma_explain.py`. |
| `test_quality.py` | `score_benign.py` and the benign ratchet, `check_null_safety.py`, `check_provider_mappings.py`, `k8s_policy_coverage.py`, `k8s_platforms_md.py`, `coverage_report.py`. |
| `test_validators.py` | The cloud validator, the Linux validator (dry run, with the check of its `CONTROLS` table; and its verdict code on canned results: the detections; the no-op baseline, which must own a record; each mutant and each re-run, which must be held by what it declares (an item of its rule, or the success gate); the limits of the exemption for a rule whose emulation is a SKIP; a live negative control for each rule), the three Kubernetes validators (dry run and negative control), `trr_lint.py`, `check_md_links.py`, `check_sigma_regex.py`, `check_schedule_freshness.py`. |
| `test_suite.py` | Rules of the suite as a whole: each self-test has a runner, the CI job runs every test on every pull request, the `emulation-scripts` job does the same for `atomics/tests/`, no workflow step pipes a command into `tee` without pipefail, no step that runs a gate or the unit tests has `continue-on-error`, each known gap names a roadmap item, each planted artifact is used, this file agrees with the tests. |
| `test_apt_install.py` | Tests of `.github/scripts/apt_install.sh`, the step that installs `auditd`, with a stub for `sudo`, `apt-get`, `unshare`, `mount`, `getent` and `timeout`. When the runner cannot resolve the package mirror, or apt printed a message about name resolution, or the mirror does not resolve after a failed run, apt gets one run with public resolvers in a private mount namespace; the script fails only after apt failed in a run with the resolver of the runner (but in the forced way of the CI job); a necessary package that is not installed fails the step; a text that is not a package name (also a name that ends with `-`, which apt reads as a removal) or not an address is refused. The class `DirectInstalls` (with two CONTROLs) fails when a workflow (a `run:` text, a `with:` or `env:` value), a composite action or a shell script (`*.sh`, or a shell on its first line) installs packages in a usual form (`apt-get install`, `apt update`, `dpkg -i`, `snap install`, also with options, a path or quotes) without the script. The one line that is allowed is `apt-get update -qq` in `detections/benign/linux/workload.sh`. It is a rule on text: a command that is built at run time, or that a different program starts, is not seen. The stubs do not show that the namespace works on a runner: the CI job `apt-install-fallback` does. It forces that way, and its CONTROL step gives a resolver that does not answer (`APT_INSTALL_RESOLVERS`) and fails if the install then passes. |
| `test_labs.py` | Rules for the lab jobs that run on a GitHub runner (auditd on the runner, a kind cluster). No offline gate runs these jobs, and a new runner image can break them with no change in the repository. `AuditdStart`: each workflow step that starts auditd waits for `audit-rules.service` before its first line that adds or loads an audit rule or runs a validator (auditd 4 loads its rule files in that oneshot unit, the start of auditd does not wait for it, and its rule file starts with `-D`). The wait is in a guard, because auditd 3 has no such unit, and a unit that ends with an error gives a `::warning` line and does not stop the step. The class also runs the start of each such step, and the whole sensor step of the static pod lab, with a stub for `sudo`, `systemctl`, `service` and `auditctl`. The stubs model the fault that CI showed on 2026-11-13: a run of the unit that nobody waited for deletes the rule after the step saw it in the list. `FileSensorRule`: the two steps of the static pod lab that read the file events print an `::error` line when `auditctl -l` does not list the rule of the file sensor, and they go on. The line says which check of the validator fails when: the file gate, or the file control too. `DateWidth`: no shell script, workflow or composite action gives `%N` a width (`%6N`, `%3N`): `date` of uutils coreutils 0.10.0 prints such a field without the leading zeros of the fraction. `LedgerClock`: the function that gives the times of the emulation ledger (`now_utc()`, or `now()`) is one accepted text in each emulation script and in each workflow step that defines it, and a script that writes a ledger defines it one time. The class runs that text in bash with a stub `date` that prints a wrong time: the result is the time of the test in UTC, a fraction that starts with zero keeps its zeros, and `date` is not called; without the clock of bash the function calls `date` with `%N` only. The stubs do not show what systemd, auditd and the `date` of a runner image do: the lab jobs show that. |
| `known_bad/<group>/` | The planted artifacts of that group. `known_bad/gatelib/` holds samples for `test_gatelib.py`. |

The planted artifacts are outside `detections/sigma/`, the fixtures and the
benign corpus, so the gates do not read them in the repository. Do not give a
planted file the extension `.md` or `.py`: `check_md_links.py` reads every `.md`
file of the repository, and Python can import a `.py` file. Name it `.md.txt` or
`.txt` and plant it under its real name.

## How a test works

1. `self.good()` is an unmodified copy of the repository that the test class
   shares. `self.tree()` is a private copy for one test. A copy of the whole
   checkout takes less than half a second; set `PARTS` to copy less.
2. The test plants one artifact: `tree.plant(artifact, dest)` copies a file or a
   directory from `known_bad/`, and `tree.edit()`, `tree.replace()` and
   `tree.edit_json()` change a file of the copy. Each fails when nothing changed.
3. `tree.run(script, *args)` runs the gate as the CI step does: the same command
   line, from the root of the copy, in a child process, with the Python that runs
   the tests. The child has no token, no GitHub variable and no network.
   `tree.run_step(step)` runs the text of a whole workflow step with the shell
   that GitHub Actions uses, so a step that loses the exit code of a gate loses
   it here too. `gatelib.ci_step()` gives the step. It refuses a step that has
   `continue-on-error`, on the step or on its job: a gate that fails there
   leaves the job (for a step) or the workflow run (for a job) green.
   [Limits](#limits) says what `run_step()` does not model.
4. `self.assert_rejects(result, reason)` needs a non-zero exit code and the
   intended reason in the output. A traceback, a wrong command line and a timeout
   are not rejections. `self.assert_accepts(result, proof)` needs exit code 0 and
   a line that shows what the gate checked.

```python
class RuleCases(gatelib.GateCase):
    GATE = "detections/rule_cases.py"
    PARTS = gatelib.DETECTIONS

    def test_control_good_tree_is_accepted(self):
        good = self.good()
        count = len(good.glob("detections/sigma/*/*.cases.jsonl"))
        self.assertGreater(count, 0)
        self.assert_accepts(good.run(self.GATE), rf"^All cases hold \({count} rule file")

    def test_rejects_trivial_near_miss(self):
        tree = self.tree()
        tree.plant("sufficiency/trivial_near_miss", "detections/sigma/T9999")
        self.assert_rejects(tree.run(self.GATE),
                            r"^FAIL  T9999/planted_trivial_near_miss\.yml :: near-miss .*"
                            r"the analysis grades it trivial", exit_code=1)
```

## Add a known-bad case

1. Find the gate that must reject the artifact, and the test class of that gate.
   For a gate that has no class, make one, with a control (see the rules below).
2. Make the smallest artifact that has the defect. Put it under
   `known_bad/<group>/`. When the artifact is one changed value of a real file,
   make the change in the test (`tree.replace()`), with a comment that says what
   is bad. The text that the test replaces is then an anchor in a content file:
   add the file to the list in [Limits](#limits).
3. Write the test: plant the artifact in `self.tree()`, run the command of CI,
   and assert the reason with `self.assert_rejects()`.
4. Run the test. Then prove that it is not vacuous: in a scratch copy of the
   repository (not in the repository), disable the check of the gate that must
   reject the artifact, and run the test there. It must fail.
5. When the gate does not reject the artifact, do not change the gate in the
   same change and do not weaken the test: the case is a known gap (see below).

## Rules for a case

- **One control for each gate.** The control runs the command of the rejection
  tests on the unmodified copy and asserts a line that shows what the gate checked.
  Take a count from the tree. Several gates exit 0 when they found nothing to check.
- **One defect for each test.** Where the gate prints a count of problems,
  assert that it is 1. If the artifact must have a second difference from the good
  tree, prove that the second difference alone is accepted.
- **The reason names the defect.** Match the words of the gate's message that
  name this rule, this case and this reason. `FAILED:` is not a reason. Do not
  match text that changes from run to run (random tokens, temporary paths).
- **The command is the command of CI.** Use the arguments of the workflow step
  (`gatelib.ci_commands(script)` lists them; `self.assert_ci_runs()` asserts
  them). The first rejection of each gate uses that command. More variants of the
  same gate can use a faster path of the gate (a rule path as an argument) when
  that path runs the same code. For a mode that no workflow runs, use the command
  of `AGENTS.md` (`self.assert_documented()`).
- **Never change the good tree.** A test that plants, or runs a gate that writes
  (`--update`, `--write`), uses `self.tree()`.
- **Never weaken a test to get green.** When a gate does not reject an artifact
  that it should reject, the case is a known gap.
- **Stay fast.** The suite must run in less than four minutes on a CI runner
  (today: about three and a half).
  Give each gate its own test class: `gatelib.py --run` runs the classes at the
  same time. For a gate that needs several seconds for one run, start the runs
  of the class together (see below).

### Slow gates

A gate is a child process, so runs that start together use the CPUs together.

- In one test: `pending = tree.start(script, *args)` or `tree.start_step(step)`,
  then `pending.result()`.
- For a class, in `setUpClass`: `cls.class_tree()` is a private copy that lives
  as long as the class, and `cls.in_background(call, *args)` starts any call on a
  thread. The class waits for these runs before it deletes its copies.
- `gatelib.StartedTogether` does the same from a list: `RUNS` names the runs,
  `begin_<name>(tree)` plants one artifact and starts the gate, and
  `self.started(name)` gives the test its copy and its result. `test_sufficiency.py`
  uses it.

## Known gaps

A known gap is an artifact that a gate should reject and does not reject today.
Its test states the wanted behaviour and carries the marker. This is the test of
the gap `hidden-rule-file` (`test_sufficiency.py`, class `RuleCases`):

```python
@gatelib.known_gap(
    "hidden-rule-file",
    gate="detections/sigma_eval.py import guard (through detections/rule_cases.py)",
    reason="A rule and its sidecar in dotfiles under detections/sigma/T<id>/ pass the "
           "import guard, and the globs of the gates (`*/*.yml`, `*/*.cases.jsonl`) "
           "skip them, so rule_cases.py accepts a tree with a rule that it did not "
           "check. Only R0 of check_sufficiency.py refuses the two files: the "
           "check-sufficiency, sufficiency-ratchet and coverage-report jobs, which run "
           "that script, fail on the planted tree, and every other gate accepts it.",
    closes="R2d")
def test_gap_hidden_rule_file(self):
    """WANTED: a rule file that the gates do not read is refused (as R0 refuses it),
    or it is read, and then its positive that cannot fire fails."""
    tree = self.tree()
    tree.plant("sufficiency/hidden_rule/hidden.yml", "detections/sigma/T1040/.hidden.yml")
    tree.plant("sufficiency/hidden_rule/hidden.cases.jsonl",
               "detections/sigma/T1040/.hidden.cases.jsonl")
    result = tree.run(self.GATE)
    if result.returncode == 0:
        # The gate accepted the copy, and it printed nothing about the pair. Prove
        # that the pair it did not read is bad: the gate fails the positive when
        # the hidden rule is its argument (then it does not need the glob).
        named = tree.run(self.GATE, "detections/sigma/T1040/.hidden.yml")
        self.assertEqual(named.returncode, 1, named.describe())
        self.assertIn("FAIL  T1040/.hidden.yml :: positive   stream-socket-declared-positive: "
                      "expected a match, got near-miss", named.stdout)
    self.assert_rejects(result, r"T1040/\.hidden\.(yml|cases\.jsonl)")
```

The test passes while the gate accepts the artifact. It fails with `KNOWN GAP
CLOSED` when the gate starts to reject it. It also fails when the behaviour of
the gate changes in another way (`today=` records `accepts`, `wrong-reason` or
`crash`), and when the test itself is broken. A broken test never counts as an
open gap.

Rules for a known gap:

- **The last assertion is the wanted behaviour**: one `assert_rejects()`. Every
  assertion before it is a plain one.
- **Prove that the artifact is bad**, with plain assertions (the planted baseline
  holds no record; the gate fails the hidden rule when it gets the rule as an
  argument). The gate has no check for the artifact, so without this proof the
  test passes for a sound artifact too.
- **Prove that the gate read the artifact**, with `self.assert_saw(result,
  pattern)` before the last assertion. An artifact that the gate never read is
  also accepted. The pattern must hold today and after the gate is fixed (a row
  that the gate prints for a pass and for a failure). Where the gate prints
  nothing about the artifact, prove inside `if result.returncode == 0:` that the
  artifact is bad, as the example does.
- **Prove the marker.** In a scratch copy of the repository, correct the gate
  and run the test. It must fail with `KNOWN GAP CLOSED`, and not with a message
  of an assertion before the last one.
- **Name what closes it.** `closes=` is an item of section 1 of
  [`docs/ROADMAP.md`](../../docs/ROADMAP.md) (the table `gatelib.ROADMAP`).
  `unplanned` is not a value. For a gap that no item closes, add an item to the
  roadmap and to the table first. `test_suite.py` fails when a gap names no item
  of the roadmap, and when the item is `done` and the gap is still open. It also
  fails when section 1 of the roadmap gets, loses or renames an item and the
  table does not follow (see [Limits](#limits)).
- **Say only what is true.** `reason=` says what passes today and why that is
  wrong, for the planted artifact and for the repository. Where another job or
  the merge policy still stops the planted change, say so. A test can prove
  such a sentence with plain assertions inside `if result.returncode == 0:`, so
  that the text cannot go out of date (the two known gaps of `CloudValidator`
  do). `gate=` is plain text on one line, without a backtick and without `|`:
  the Markdown list of the gaps puts it in a code span of a table cell.
- **A gap is closed by a change to the gate, never by deleting the case.** Fix
  the gate, and in the same pull request remove the marker: the test fails with
  `KNOWN GAP CLOSED` until you do. The same test is then an ordinary rejection
  test, and it keeps the gate from losing the check again. Do not delete the
  test, and do not change its artifact or its reason to make it pass.
- **A gap is a finding.** Report it in the pull request that adds it.

`gatelib.KNOWN_GAPS` is the one list of all gaps; the markers are its source.
`gatelib.py --gaps` prints it (`--markdown` for a table, `--json` for a script),
and `gatelib.py --run` prints it after the tests, with the state that the run
gave each gap: `open`, or `not run`. A run of the whole suite fails when the test
of a gap did not run and was not skipped: the marker is then on a method that
`unittest` does not collect, and nothing tests the gap.

## CI

The `gate-tests` job of `.github/workflows/detection-quality.yml` runs
`python3 -B detections/tests/gatelib.py --run --no-skips --summary "$GITHUB_STEP_SUMMARY"`
on each pull request, on each push to `main`, and weekly. The workflow has no
path filter, so the job runs when a gate, a test, a planted artifact or a
workflow changes. The job summary holds the result and the list of known gaps.
When a test module does not import, no test runs: the summary says so, and the
log of the step holds the error.

The runner stops a test class after ten minutes (`gatelib.CLASS_TIMEOUT`). The
job has 20 minutes. Thus a class that hangs fails the run, the log holds the
output of every class, and the job summary is written. `test_suite.py` compares
the two timeouts.

`test_suite.py` keeps three more rules for the workflows:

- A script with a `--self-test` mode must have a runner. When no workflow step
  runs the self-test, the suite runs it (the table `SelfTests.RUN_HERE`; today
  `sigma_explain.py`).
- No step pipes a command into `tee` without pipefail. GitHub Actions runs a
  step that has no `shell:` with `bash -e`, so `gate | tee file` takes the exit
  code of `tee`, and a gate that fails leaves the job green. Such a step needs
  `shell: bash`.
- No step that runs a script of the repository with Python, or its unit tests
  (`python -m unittest`), has `continue-on-error`, on the step or on its job. A
  step that has it leaves its job green when it fails, and a job that has it
  leaves its workflow run green.
  The shadow steps are the exception, by name (the table `SoftSteps.SHADOW`;
  today one step of `validate-apiserver-detections.yml`).

The `gate-tests` job itself has no `if:`, no `continue-on-error` and no `needs:`
(GitHub skips a job when a job that it needs failed), and its workflow has no
path filter. `test_suite.py` checks that too.

`test_labs.py` keeps the rules for the lab jobs (auditd on the runner, a kind
cluster). A planted script or workflow step shows that each rule finds its fault:

- A step that starts auditd (`systemctl start auditd`) waits for
  `audit-rules.service` after that start and before its first line that adds or
  loads an audit rule or runs a validator. The wait is these lines, and a new step
  that starts auditd needs them too:

  ```bash
  if systemctl cat audit-rules.service >/dev/null 2>&1; then
    sudo systemctl start audit-rules.service \
      || echo "::warning title=auditd::audit-rules.service ended with an error ..."
  fi
  ```

  It is a rule on text: it does not see a start of auditd that a script or a
  different program makes.
- No line of a shell script, a workflow or a composite action holds `%N` with a
  width of one digit (`%6N`, `%3N`, `%06N`). A comment does not count. It is a
  rule on text: it does not see a format that is built at run time, and it does
  not find a width of two digits (in a URL, `%20N` is a space before an `N`).
- Each definition of `now_utc()` or `now()` in `atomics/*/src/*.sh` and in a
  workflow step is the text `LedgerClock.ACCEPTED` (the name can be `now()`). A
  script that writes a ledger (`DETENG_LEDGER`) defines the function one time. To
  change the function, change that text and each copy in the same pull request.

The job `emulation-scripts` of `lint-trr.yml` runs a second suite: the tests of the
cloud emulation scripts in [`atomics/tests/`](../../atomics/tests/README.md). The
gate tests do not run that suite. They hold the rules of its job (class
`EmulationScriptsJob`): the same rules as for `gate-tests`, and these.

- The job is one fixed form (`EmulationScriptsJob.JOB_FORM`): checkout, Python
  3.12 or later, and one step with the one command. A step more, a line more in
  that step, an `env:`, a different runner or a `concurrency:` group fails the
  test. Change the form in the same pull request, and say why the job still runs
  every test.
- The step runs the discovery of unittest on the whole directory. The step fails
  when a test fails, when a test module does not load, and when the directory
  holds no test.
- Each file that holds a test method is a file from which the discovery loads a
  test. No test is an `async def` (unittest does not wait for it).
- No test is skipped, and none is an expected failure: unittest ends with 0 for
  both. The rule reads the names in each module, so an alias
  (`import unittest as ut`) is found too.
- The suite does not lose tests. The class holds the count
  (`EmulationScriptsJob.TESTS`). A lower count fails. Raise the number when the
  suite grows. The count is the same with the variables of a GitHub runner.

These rules do not see code that hides a failure when the tests run: a test that
returns early, a decorator or a `run()` of a test class that swallows the
failure, `os._exit(0)` in a test, a patched `TestResult`. The count is a floor:
it does not see one test in the place of a different one.

## Limits

- The suite proves that a gate rejects the artifacts that are planted here. It
  does not prove that a gate rejects every bad artifact.
- A gate that needs a host or a cluster runs only in its offline modes: the dry
  runs, the negative-control steps on logs that the test writes, and the verdict
  code of the Linux validator on canned events. The live runs stay in the
  `validate-*` workflows.
- No offline check compares the item that a row of the `CONTROLS` table of
  `detections/validate_detections.py` declares with the C program of that row.
  The canned events of a Linux control come from a rule sidecar, not from the C
  source: the driver takes the case that breaks the declared item, so the grade
  follows the declaration. No gate test fails because a row declares the wrong
  item for its program. (A test that quotes the declared item of a row, such as
  `afxdp_socket.a0`, fails when that row changes, whatever the program does.)
  Only the job `validate` (`validate-detections.yml`) runs the programs in
  `detections/controls/` and grades the records that they leave.
- No gate reads the live emulation scripts (`atomics/*/src/emulate*.sh`, the
  parts behind `TRR90NN_LIVE=1`). A live script that lost its undo trap
  (`trap revert EXIT`) passes every gate. The design (4.2) names that artifact
  for this suite, and the suite has no case for it: there is no gate to test.
  Roadmap item R9 adds `atomics/lib/live.sh` and its lint; the case comes with
  them.
- The network fence of a gate run is a proxy setting. It does not stop a gate
  that opens a socket without the proxy.
- `tree.run_step()` runs the `run:` text of a step. It models the shell of the
  step: `bash -e` when the step has no `shell:`, and bash with `-eo pipefail`
  for `shell: bash`. It also models `/tmp/`, the files behind
  `GITHUB_STEP_SUMMARY`, `GITHUB_OUTPUT` and `GITHUB_ENV`, and the `${{ ... }}`
  expressions whose values the test gives. It does not evaluate an `if:`
  condition of the step or of its job: the step always runs here. So a step
  that a condition switches off in CI still passes its step test. It does not
  read the `env:` or the `working-directory:` of the step: the test gives the
  values. It does not model `continue-on-error`: `gatelib.ci_step()` refuses a
  step that has it, and `test_suite.py` (class `SoftSteps`) refuses it for each
  step that runs a gate.
- The tests depend on the text of real content files. A test changes a rule, a
  fixture or a report in its copy, and it finds the place of the change by an
  exact text (`tree.replace()`), by a JSON key or by the name of a case. A
  change to that text can pass every content gate and make `gate-tests` red,
  with a message such as:

  ```text
  ValueError: replace('detections/sigma/T1040/afinet_raw_socket.yml'): '      - traceroute6\n'
  occurs 0 time(s), wanted 1. The test finds the place of its change by this text. If a
  change to the file removed the text, the test is out of date: correct the test
  (detections/tests/README.md, Limits)
  ```

  That failure means that a test is out of date. It does not mean that the
  content is wrong. The repair is a change to the test, and a test module is not
  content for the merge policy (no `.py` file is): the maintainer merges the
  repair by hand. `gate-tests` is not a required check and is one of the slower
  checks (about four minutes), so GitHub can merge a content-only pull request
  before the job fails. The job is then red on `main` until the repair. Thus,
  before you change one of these files, run the suite.

  A test changes these files in its copy:

  - `detections/sigma/T1040/afinet_raw_socket.yml`
  - `detections/sigma/T1040/afinet_raw_socket.cases.jsonl`
  - `detections/sigma/T1040/afpacket_raw_socket.yml`
  - `detections/sigma/T1040/afpacket_raw_socket.cases.jsonl`
  - `detections/sigma/T1040/afxdp_socket.yml`
  - `detections/sigma/T1040/afxdp_socket.cases.jsonl`
  - `detections/sigma/T1078.004/aws_cognito_unauthenticated_identity_use.yml`
  - `detections/sigma/T1078.004/aws_leaked_access_key_recon.yml`
  - `detections/sigma/T1098.006/k8s_rbac_write.yml`
  - `detections/sigma/T1537/aws_snapshot_or_ami_made_public.yml`
  - `detections/sigma/T1543.005/k8s_cri_static_pod_start.yml`
  - `detections/sigma/T1543.005/k8s_static_pod_mirror_create.yml`
  - `detections/sigma/T1609/k8s_pod_exec_attach.yml`
  - `detections/cloud/fixtures/trr9011/attack.json`
  - `detections/cloud/fixtures/trr9012/attack.json`
  - `detections/cloud/fixtures/trr9012/benign.json`
  - `detections/RULE_DEFECTS.md`
  - `detections/k8s/PLATFORMS.md`
  - `research/trr9001/lin/README.md`
  - `research/trr9012/aws/README.md`

  A test of the validators takes cases by name from these sidecars, as the
  records of a log:

  - `detections/sigma/T1609/k8s_pod_exec_attach.cases.jsonl`
  - `detections/sigma/T1543.005/k8s_static_pod_mirror_create.cases.jsonl`
  - `detections/sigma/T1543.005/k8s_cri_static_pod_start.cases.jsonl`
  - `detections/sigma/T1543.005/linux_static_pod_manifest_write.cases.jsonl`
  - `detections/sigma/T1098.006/k8s_rbac_write.cases.jsonl`
  - `detections/sigma/T1053.007/k8s_cri_job_pod.cases.jsonl`
  - `detections/sigma/T1552.007/linux_k8s_sa_token_read.cases.jsonl`

  `NullSafety` (`test_quality.py`) takes one case by name from this sidecar, for
  its probe of the two JSON texts of a list:

  - `detections/sigma/T1537/aws_snapshot_or_ami_made_public.cases.jsonl`

  `CheckSufficiency` (`test_sufficiency.py`) takes the positive cases of this
  sidecar, for its proof that a rule that needs one account id is bad:

  - `detections/sigma/T1078.004/aws_leaked_access_key_recon.cases.jsonl`

  The offline run of the Linux validator takes its canned events from the
  sidecar of each rule of the `MANIFEST` of `detections/validate_detections.py`:
  the first `positive` case and, for each mutant control, the first `near-miss`
  case whose `breaks` is the item that the control declares in the `CONTROLS`
  table. For a control that declares one item of a base of a correlation
  (`base:<name>/<item>`), that is the first `near-miss` case that breaks
  `base:<name>`, and its event must miss the base by that item. A mutant that
  declares `success` takes the first `positive` case, with each syscall
  rejected. The validator must give each canned mutant the grade that it
  declares: a change to one of these cases can make the control
  `test_control_canned_run_is_accepted` fail. Six tests also need one record
  in such a case. The two tests with `--split`, and the tests with `--late` and
  `--without`, need a `socket` record in the case of the control of
  `copyfail_af_alg_authencesn.yml` (for `--split` and `--late`, with a record of
  another syscall). The test with `--refused ... unshare` needs an `unshare`
  record in the case of the control of `dirtyfrag_xfrm_unshare_netlink.yml`. The
  test with `--refused ... execveat` needs an `execveat` record in the case of
  the control of `memfd_create_execveat.yml`. The driver stops with exit code 3
  when the case holds no such record.

  `KnownGapList` (`test_suite.py`) reads section 1 of this file, the item IDs
  and the Status cells:

  - `docs/ROADMAP.md`

  The IDs must be the keys of the table `ROADMAP` in `gatelib.py`, and `R2`,
  which is this suite. Each Status cell must hold one status word and no other
  text. An item that an open known gap names cannot be `done`. Thus a pull
  request that changes only the roadmap can make `gate-tests` red. That failure
  says nothing about a gate. It means one of three things. An item of section 1
  is new, gone or renamed: make the same change to the table `ROADMAP` in
  `gatelib.py`, in the same pull request. `gatelib.py` is not content, so the
  maintainer merges that pull request by hand. A Status cell holds a reason:
  move the reason to the Needs cell. An item is `done` while
  `gatelib.py --gaps` lists a gap that it closes: the item is not done, so set
  its status back, or close the gap (see [Known gaps](#known-gaps)).

  `test_suite.py` fails when a file of these lists is not in the repository.

## Not covered yet

These are facts for the next session. They are not known gaps: no run showed
that a gate accepts a bad artifact here.

These rejections have no planted artifact and no test:

- `score_benign.py --check --enforce` has three of them: an `unscored` entry of
  `budgets.json` for a rule that is scored now, an entry of `budgets.json` for
  a rule that does not exist, and an `unscored` entry without a why.
- The fail-closed errors of `score_benign.py --baseline-scores` and of
  `check_sufficiency.py --baseline`: a base file that is missing, that is not a
  report of the gate, or that holds no rule.
- The digest check of the `COMPILE_ONLY` table of `check_sufficiency.py`. The
  table is empty today, so there is no entry to make stale.

The suite does not run these checks:

- The RE2 branches of `check_sigma_regex.py` and `check_provider_mappings.py`.
  google-re2 is not in `detections/requirements.txt`, so the `gate-tests` job
  runs the default path. For `check_sigma_regex.py`, one test proves that
  `--require-re2` fails when the module is missing.
- `sigma check`. sigma-cli is not in `detections/requirements.txt`.
- The live modes of the validators (auditd on a host, a kind cluster). They
  stay in the `validate-*` workflows.

One fault of the runner is open:

- When the runner stops a class at its timeout, the gate processes of that
  class continue, and their sandboxes stay under `TMPDIR`. Each gate run has a
  session of its own, so the runner does not reach it. In CI the machine of
  the job is deleted after the job.
