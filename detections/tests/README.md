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

`gatelib.py --run` runs the same tests as `unittest discover`, with one
`python -m unittest` process for each test class, as many at a time as the
machine has CPUs. Then it prints the known gaps. It takes about 90 seconds on
four CPUs; the tests in sequence take about four minutes. It fails when a class
fails, when a class did not run all of its tests, and when a test module does
not import. `--no-skips` also fails the run when a test was skipped, and
`--summary PATH` adds the result and the known gaps to a file as Markdown. CI
uses both.

`-B` stops Python from writing `__pycache__/` beside the tests. The suite uses
only the standard library (`unittest`), PyYAML and pySigma. It needs no network
and no root. Two test classes need a tool: `gcc` (the Linux dry run compiles the
atomics) and `git` (the ratchet job makes a worktree). Without the tool those
tests are skipped; in CI a missing tool fails them.

The copies are made under the system temporary directory (`TMPDIR`) and deleted
after each test or test class.

## Layout

| Path | Content |
|------|---------|
| `gatelib.py` | The harness: `Tree`, `GateCase`, `StartedTogether`, `assert_rejects`, `assert_accepts`, `assert_saw`, `known_gap`, `ci_step`, `ci_commands`, and the parallel runner. |
| `test_gatelib.py` | Tests of the harness, on constructed gates. |
| `test_sufficiency.py` | `rule_cases.py`, the import guard of `sigma_eval.py`, `check_sufficiency.py`, the sufficiency ratchet, the self-test of `sigma_explain.py`. |
| `test_quality.py` | `score_benign.py` and the benign ratchet, `check_null_safety.py`, `check_provider_mappings.py`, `k8s_policy_coverage.py`, `k8s_platforms_md.py`, `coverage_report.py`. |
| `test_validators.py` | The cloud validator, the Linux validator (dry run, and its verdict code on canned results), the three Kubernetes validators (dry run and negative control), `trr_lint.py`, `check_md_links.py`, `check_sigma_regex.py`, `check_schedule_freshness.py`. |
| `test_suite.py` | Rules of the suite as a whole: each self-test has a runner, the CI job runs every test on every pull request, each known gap names a roadmap item, each planted artifact is used. |
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
   `tree.run_step(step)` runs a whole workflow step with the shell that GitHub
   Actions uses, so a step that loses the exit code of a gate loses it here too.
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
   is bad.
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
- **Stay fast.** The suite must run in less than three minutes on a CI runner.
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
Its test states the wanted behaviour and carries the marker:

```python
@gatelib.known_gap("hidden-rule-file",
                   gate="detections/sigma_eval.py import guard",
                   reason="A rule in a dotfile under detections/sigma/ is never read.",
                   closes="unplanned")          # or a roadmap item: "R7"
def test_gap_hidden_rule_file(self):
    tree = self.tree()
    tree.plant("sufficiency/hidden_rule/hidden.yml", "detections/sigma/T1040/.hidden.yml")
    self.assert_rejects(tree.run(self.GATE), r"T1040/\.hidden\.yml")
```

The test passes while the gate accepts the artifact. It fails with `KNOWN GAP
CLOSED` when the gate starts to reject it. It also fails when the behaviour of
the gate changes in another way (`today=` records `accepts`, `wrong-reason` or
`crash`), and when the test itself is broken. A broken test never counts as an
open gap.

Rules for a known gap:

- **The last assertion is the wanted behaviour**: one `assert_rejects()`. Every
  assertion before it is a plain one.
- **Prove that the gate read the artifact**, with `self.assert_saw(result,
  pattern)` before the last assertion. An artifact that the gate never read is
  also accepted. The pattern must hold today and after the gate is fixed (a row
  that the gate prints for a pass and for a failure). Where the gate prints
  nothing about the artifact, prove inside `if result.returncode == 0:` that the
  artifact is bad.
- **Name what closes it.** `closes=` is an item of section 1 of
  [`docs/ROADMAP.md`](../../docs/ROADMAP.md) (the table `gatelib.ROADMAP`), or
  `unplanned`. `test_suite.py` fails when the item is `done` and the gap is
  still open.
- **A gap is closed by a change to the gate, never by deleting the case.** Fix
  the gate in a change of its own. The test then fails with `KNOWN GAP CLOSED`.
  Remove the marker: the same test is then an ordinary rejection test, and it
  keeps the gate from losing the check again. Do not delete the test, and do not
  change its artifact or its reason to make it pass.
- **A gap is a finding.** Report it in the pull request that adds it.

`gatelib.KNOWN_GAPS` is the one list of all gaps; the markers are its source.
`gatelib.py --gaps` prints it (`--markdown` for a table, `--json` for a script),
and `gatelib.py --run` prints it after the tests, with the state that the run
gave each gap.

## CI

The `gate-tests` job of `.github/workflows/detection-quality.yml` runs
`python3 -B detections/tests/gatelib.py --run --no-skips --summary "$GITHUB_STEP_SUMMARY"`
on each pull request, on each push to `main`, and weekly. The workflow has no
path filter, so the job runs when a gate, a test, a planted artifact or a
workflow changes. The job summary holds the result and the list of known gaps.

`test_suite.py` keeps one more rule: a script with a `--self-test` mode must have
a runner. When no workflow step runs the self-test, the suite runs it (the table
`SelfTests.RUN_HERE`; today `sigma_explain.py`).

## Limits

- The suite proves that a gate rejects the artifacts that are planted here. It
  does not prove that a gate rejects every bad artifact.
- A gate that needs a host or a cluster runs only in its offline modes: the dry
  runs, the negative-control steps on logs that the test writes, and the verdict
  code of the Linux validator on canned results. The live runs stay in the
  `validate-*` workflows.
- `sigma check`, the RE2 branch of `check_sigma_regex.py` and
  `check_provider_mappings.py --require-re2` need packages that are not in
  `detections/requirements.txt`. The suite does not run them.
- The network fence of a gate run is a proxy setting. It does not stop a gate
  that opens a socket without the proxy.
