# Gate tests

The gates are the checks that CI runs to decide if work is done: `rule_cases.py`,
`check_sufficiency.py`, `score_benign.py`, the validators, the lints. A change to
a gate can stop it from rejecting bad work, and no other check sees that. This
suite holds planted bad artifacts and proves, for each one, that its gate rejects
it for the intended reason. A control proves that the same gate accepts the tree
before the artifact is planted.

## Run

From the repository root, with the Python that has `detections/requirements.txt`:

```bash
python3 -B -m unittest discover -s detections/tests -v                           # all, in sequence
python3 -B -m unittest discover -s detections/tests -p 'test_sufficiency.py' -v  # one group
python3 -B -m unittest discover -s detections/tests -k trivial -v                # by name
python3 -B detections/tests/gatelib.py --run                                     # all, in parallel
python3 -B detections/tests/gatelib.py --gaps                                    # known gaps
```

`-B` stops Python from writing `__pycache__/` beside the tests. The form with
`-t .` works too. `gatelib.py --run` runs the same tests with one
`python -m unittest` process for each test class, as many at a time as the
machine has CPUs, and then prints the known gaps: use it in CI. It fails when a
class fails, when a class did not run all of its tests, and when a test module
does not import. The suite uses only the standard library (`unittest`), PyYAML
and pySigma. It needs no network and no root.

## Layout

| Path | Content |
|------|---------|
| `gatelib.py` | The harness: `Tree`, `GateCase`, `assert_rejects`, `assert_accepts`, `assert_saw`, `known_gap`, `ci_steps`. |
| `test_gatelib.py` | Tests of the harness, on constructed gates. |
| `test_<group>.py` | The gate tests of one group: `sufficiency`, `quality`, `validators`. |
| `known_bad/<group>/` | The planted artifacts of that group. `known_bad/gatelib/` holds samples for `test_gatelib.py`. |

The planted artifacts are outside `detections/sigma/`, the fixtures and the
benign corpus, so the gates do not read them in the repository. Do not put a
planted Markdown file with the extension `.md` here: `check_md_links.py` reads
every `.md` file of the repository. Name it `.md.txt` and plant it as `.md`.

## How a test works

1. `self.good()` is an unmodified copy of the repository that the test class
   shares. `self.tree()` is a private copy for one test. Both are under the
   system temporary directory and are deleted afterwards. A copy of the whole
   checkout takes less than half a second; set `PARTS` to copy less.
2. The test plants one artifact: `tree.plant(artifact, dest)` copies a file or a
   directory from `known_bad/`, and `tree.edit()`, `tree.replace()` and
   `tree.edit_json()` change a file of the copy. Each fails when nothing changed.
3. `tree.run(script, *args)` runs the gate as the CI step does: the same command
   line, from the root of the copy, in a child process, with the Python that runs
   the tests. The child has no token, no GitHub variable and no network.
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

## Rules for a case

- **One control for each gate.** The control runs the command of the rejection
  tests on the unmodified copy and asserts a line that shows what the gate checked.
  Take a count from the tree. Several gates exit 0 when they found nothing to check.
- **One defect for each test.** Plant the smallest artifact that has the defect.
  Where the gate prints a count of problems, assert that it is 1.
- **The reason names the defect.** Match the words of the gate's message that
  name this rule, this case and this reason. `FAILED:` is not a reason. Do not
  match text that changes from run to run (random tokens, temporary paths).
- **The command is the command of CI.** Use the arguments of the workflow step
  (`gatelib.ci_commands(script)` lists them; `self.assert_ci_runs()` asserts
  them). The first rejection of each gate uses that command. More variants of the
  same gate can use a faster path of the gate (a rule path as an argument) when
  that path runs the same code.
- **Never change the good tree.** A test that plants, or runs a gate that writes
  (`--update`, `--write`), uses `self.tree()`.
- **Never weaken a test to get green.** When a gate does not reject an artifact
  that it should reject, the case is a known gap.
- **Stay fast.** The suite must run in less than three minutes on a CI runner.
  Give each gate its own test class: `gatelib.py --run` runs the classes at the
  same time. Inside one test, start slow runs together with `tree.start()` and
  collect them with `.result()`.

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
CLOSED` when the gate starts to reject it: remove the marker then, and the test
is an ordinary rejection test. It also fails when the gate's behaviour changes
in another way (`today=` records `accepts`, `wrong-reason` or `crash`), and when
the test itself is broken. Use `self.assert_saw(result, pattern)` before the
last assertion to prove that the gate read the artifact.

`gatelib.KNOWN_GAPS` is the one list of all gaps. `gatelib.py --gaps` prints it
(`--markdown` for a job summary, `--json` for a script). A gap is a finding:
report it in the pull request, and fix the gate in a change of its own.
