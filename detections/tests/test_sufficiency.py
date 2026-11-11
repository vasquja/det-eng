"""
Gate tests, group `sufficiency`: the gates that decide if a rule's own cases are
enough (detection-quality.yml jobs rule-cases, check-sufficiency and
sufficiency-ratchet) and the libraries under them (sigma_eval, sigma_explain).

    RuleCases             detections/rule_cases.py, and through it the event table of
                          detections/sigma_eval.py (EventTable)
    SigmaEvalImportGuard  the import guard of detections/sigma_eval.py, reached
                          through detections/rule_cases.py
    CheckSufficiency      detections/check_sufficiency.py (R0, R1, R2 and its
                          waivers, R3, R4)
    SufficiencyRatchet    the sufficiency-ratchet job: check_sufficiency.py --json
                          for the base, --baseline for the head
    SigmaExplainSelfTest  detections/sigma_explain.py --self-test (the grader)

Planted artifacts: detections/tests/known_bad/sufficiency/.
How the harness works: gatelib.py and README.md in this directory.

    python3 -B -m unittest discover -s detections/tests -p 'test_sufficiency.py' -v
"""

import json
import os
import re
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gatelib  # noqa: E402  (the line above makes it importable with `-t .` too)

# A @gatelib.known_gap test states the wanted behaviour in its LAST assertion, one
# assert_rejects(). Every assertion before it is a plain one (assertEqual, assert_saw):
# it proves that the planted artifact is bad, or that the gate read it, and when it
# fails the test fails, whatever the gate does.

# The real rule that several tests change in a copy, and its sidecar.
AFINET_RULE = "detections/sigma/T1040/afinet_raw_socket.yml"
AFINET_CASES = "detections/sigma/T1040/afinet_raw_socket.cases.jsonl"
# A real cloud rule, and the hard benign fixture of its MANIFEST row.
LEAKED_KEY = "T1078.004/aws_leaked_access_key_recon.yml"
LEAKED_KEY_BENIGN = "detections/cloud/fixtures/trr9012/benign.json"


def drop_cases(tree, sidecar, drop):
    """Delete from a sidecar of the copy every case for which drop(case) is true.
    At least one case must go and one must stay; returns the names of those gone."""
    cases = tree.read_jsonl(sidecar)
    gone = [case["name"] for case in cases if drop(case)]
    if not gone or len(gone) == len(cases):
        raise ValueError(f"drop_cases({sidecar}): {len(gone)} of {len(cases)} case(s) match")
    tree.write_jsonl(sidecar, [case for case in cases if case["name"] not in gone])
    return gone


def edit_cases(tree, sidecar, change):
    """Apply change(case) to every case of a sidecar of the copy (change the case in
    place). An edit that changes no case fails: the artifact would not be planted."""
    cases = tree.read_jsonl(sidecar)
    before = json.dumps(cases, sort_keys=True)
    for case in cases:
        change(case)
    if json.dumps(cases, sort_keys=True) == before:
        raise ValueError(f"edit_cases({sidecar}) changed nothing: the artifact is not planted")
    tree.write_jsonl(sidecar, cases)


def report_row(result, rule):
    """The row of `rule` (`T1040/afinet_raw_socket.yml`) in the table that
    check_sufficiency.py prints, as {column: text}."""
    for line in result.stdout.splitlines():
        cells = line.split()
        if len(cells) >= 7 and cells[0] == rule:
            return dict(zip(("rule", "platform", "positive", "cases", "neg", "items", "status"),
                            cells))
    raise AssertionError(f"check_sufficiency.py printed no row for {rule}:\n" + result.describe())


class RuleCases(gatelib.GateCase):
    """detections/rule_cases.py, as the rule-cases job runs it: no argument, every
    sidecar under detections/sigma/."""

    GATE = "detections/rule_cases.py"
    PARTS = gatelib.DETECTIONS      # the gate reads nothing outside detections/

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the unmodified copy passes, and the gate ran every sidecar in it."""
        good = self.good()
        sidecars = good.glob("detections/sigma/*/*.cases.jsonl")
        self.assertGreater(len(sidecars), 0, "the copy holds no sidecar: the control is vacuous")
        result = good.run(self.GATE)
        self.assert_accepts(result, rf"^All cases hold \({len(sidecars)} rule file\(s\)\)\.$")

    def test_ci_runs_the_gate_without_arguments(self):
        """The command of these tests is the command of the rule-cases job."""
        self.assertEqual(gatelib.ci_commands(self.GATE),
                         ["python3 detections/rule_cases.py | tee /tmp/rule-cases.out"])

    def test_rejects_trivial_near_miss(self):
        """A near-miss whose only event shares nothing with the rule proves no single
        flip: the gate must grade it trivial and fail."""
        tree = self.tree()
        tree.plant("sufficiency/trivial_near_miss", "detections/sigma/T9999")
        result = tree.run(self.GATE)
        self.assert_rejects(
            result,
            r"^FAIL  T9999/planted_trivial_near_miss\.yml :: near-miss  unrelated-file-read: "
            r"declared near-miss on \['sel\.a0'\], but the analysis grades it trivial: "
            r"no positive item of the rule holds",
            exit_code=1)
        # One planted defect, one problem: nothing else in the copy failed.
        self.assertIn("\nFAILED: 1 case problem(s).\n", result.stdout)
        # The sound positive of the planted rule still passes: the gate ran the rule.
        self.assertIn("ok    T9999/planted_trivial_near_miss.yml :: positive   packet-socket: fires",
                      result.stdout)

    def test_ci_step_fails_when_the_gate_fails(self):
        """The rule-cases step pipes the gate into `tee`. Run that step as GitHub
        Actions does: the gate's exit code must reach the step."""
        step = gatelib.ci_step("detection-quality.yml", "rule-cases", self.GATE)
        tree = self.tree()
        tree.plant("sufficiency/trivial_near_miss", "detections/sigma/T9999")
        self.assert_rejects(tree.run_step(step), r"but the analysis grades it trivial", exit_code=1)

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

    # ---- more defects of a sidecar ------------------------------------------------
    # known_bad/sufficiency/bad_cases/ holds one sound rule (two discriminating items,
    # a0 and a1, and one filter), one sidecar without a defect (sound.cases.jsonl) and
    # sidecars with one defect each. A test plants the rule and ONE sidecar as
    # detections/sigma/T9999/planted_rule.{yml,cases.jsonl}. The glob of the CI
    # command is proven by test_rejects_trivial_near_miss; these variants name the
    # planted rule as the argument, which runs the same checks in 0.3 s.

    PLANTED_RULE = "detections/sigma/T9999/planted_rule.yml"
    PLANTED_CASES = "detections/sigma/T9999/planted_rule.cases.jsonl"
    POSITIVE_FIRES = "ok    T9999/planted_rule.yml :: positive   packet-raw-socket: fires\n"

    def plant_bad_cases(self, sidecar):
        tree = self.tree()
        tree.plant("sufficiency/bad_cases/planted_rule.yml", self.PLANTED_RULE)
        tree.plant(f"sufficiency/bad_cases/{sidecar}.cases.jsonl", self.PLANTED_CASES)
        return tree

    def run_bad_cases(self, sidecar):
        return self.plant_bad_cases(sidecar).run(self.GATE, self.PLANTED_RULE)

    def test_control_planted_rule_with_sound_cases_is_accepted(self):
        """CONTROL of the variants below: the planted rule is sound. With the sidecar
        that has no defect the gate accepts the pair, and it judged every case. So
        each rejection below comes from the one defect of its sidecar."""
        tree = self.plant_bad_cases("sound")
        cases = tree.read_jsonl(self.PLANTED_CASES)
        self.assertEqual(sorted({case["kind"] for case in cases}),
                         ["benign", "filtered", "near-miss", "positive"])
        result = tree.run(self.GATE, self.PLANTED_RULE)
        self.assert_accepts(result, r"^All cases hold \(1 rule file\(s\)\)\.$")
        self.assertEqual(re.findall(r"(?m)^ok    T9999/planted_rule\.yml :: \S+ +(\S+): ",
                                    result.stdout), [case["name"] for case in cases])

    def test_rejects_near_miss_that_declares_the_wrong_item(self):
        """`breaks` must name the single flip that fires the rule. The planted
        near-miss keeps a0 and breaks a1, and it declares `breaks: ["sel.a0"]`."""
        result = self.run_bad_cases("near_miss_wrong_item")
        self.assert_rejects(
            result,
            r"^FAIL  T9999/planted_rule\.yml :: near-miss  packet-dgram-socket: declared to "
            r"break \['sel\.a0'\], but flipping that alone does not fire the rule "
            r"\(single atoms that do: sel\.a1\)$",
            exit_code=1)
        self.assertIn("\nFAILED: 1 case problem(s).\n", result.stdout)
        self.assertIn("ok    T9999/planted_rule.yml :: positive   packet-raw-socket: fires",
                      result.stdout)

    def test_rejects_near_miss_two_flips_from_firing(self):
        """A near-miss is ONE flip from firing. The planted one breaks a0 and a1."""
        result = self.run_bad_cases("near_miss_two_items")
        self.assert_rejects(
            result,
            r"^FAIL  T9999/planted_rule\.yml :: near-miss  inet-stream-socket: declared "
            r"near-miss on \['sel\.a0'\], but the analysis grades it distant: some positive "
            r"item holds, but no single item flip fires the rule$",
            exit_code=1)
        self.assertIn("\nFAILED: 1 case problem(s).\n", result.stdout)
        self.assertIn("ok    T9999/planted_rule.yml :: positive   packet-raw-socket: fires",
                      result.stdout)

    def test_rejects_positive_that_does_not_fire(self):
        """A positive case must fire the rule. The planted one has a0 '2'; the rule
        needs '11'."""
        result = self.run_bad_cases("positive_does_not_fire")
        self.assert_rejects(
            result,
            r"^FAIL  T9999/planted_rule\.yml :: positive   inet-raw-socket-declared-positive: "
            r"expected a match, got near-miss \(one flip would fire it: sel\.a0\)$",
            exit_code=1)
        self.assertIn("\nFAILED: 1 case problem(s).\n", result.stdout)

    def test_rejects_benign_case_on_which_the_rule_fires(self):
        """A declared negative must not fire the rule. The planted benign case holds
        the event of the positive case."""
        result = self.run_bad_cases("benign_that_fires")
        self.assert_rejects(
            result,
            r"^FAIL  T9999/planted_rule\.yml :: benign     packet-raw-socket-declared-benign: "
            r"expected no match, but the rule fires \(benign case\)$",
            exit_code=1)
        self.assertIn("\nFAILED: 1 case problem(s).\n", result.stdout)
        self.assertIn(self.POSITIVE_FIRES, result.stdout)

    def test_rejects_each_other_kind_of_negative_on_which_the_rule_fires(self):
        """The same defect for the three other kinds of negative: one more case in the
        sound sidecar, which holds the event of the positive case and declares it a
        confounder, a near-miss or a filtered case."""
        tree = self.plant_bad_cases("sound")
        sound = tree.read_jsonl(self.PLANTED_CASES)
        for kind, breaks in (("confounder", None), ("near-miss", ["sel.a1"]),
                             ("filtered", ["allow.comm"])):
            with self.subTest(kind=kind):
                planted = dict(sound[0], name="packet-raw-socket-declared-negative", kind=kind,
                               why="PLANTED DEFECT: the event of the positive case")
                if breaks:
                    planted["breaks"] = breaks
                tree.write_jsonl(self.PLANTED_CASES, sound + [planted])
                result = tree.run(self.GATE, self.PLANTED_RULE)
                self.assert_rejects(
                    result,
                    rf"^FAIL  T9999/planted_rule\.yml :: {kind} +packet-raw-socket-declared-"
                    rf"negative: expected no match, but the rule fires \({kind} case\)$",
                    exit_code=1)
                self.assertIn("\nFAILED: 1 case problem(s).\n", result.stdout)

    def test_rejects_sidecar_line_that_is_not_json(self):
        """Each line of a sidecar is one case. The planted second line is cut off in
        the middle of its events (a write that did not end, a bad merge), so the
        case that it was is not judged: the gate must fail the file."""
        result = self.run_bad_cases("line_not_json")
        self.assert_rejects(result, r"^ERROR T9999/planted_rule\.yml: line 2: not JSON \(",
                            exit_code=1)
        self.assertIn("\nFAILED: 1 case problem(s).\n", result.stdout)
        self.assertIn(self.POSITIVE_FIRES, result.stdout)

    # One changed value in the second line of the sound sidecar (its near-miss), and
    # the words of the gate for it. Without the check, the first, the second and the
    # last would pass as cases, and the others would end the gate with a traceback.
    MALFORMED_LINES = (
        ("a kind that is no kind", lambda case: case.update(kind="negative"),
         r"unknown kind 'negative'"),
        ("no why", lambda case: case.pop("why"), r"missing why"),
        ("a near-miss without breaks", lambda case: case.pop("breaks"),
         r"a near-miss case must declare `breaks`"),
        ("no event", lambda case: case.update(events=[]), r"events must be a non-empty list"),
        ("the name of another case", lambda case: case.update(name="packet-raw-socket"),
         r"duplicate name 'packet-raw-socket'"),
    )

    def test_rejects_case_line_that_is_not_a_case(self):
        """A line that is JSON and not a well-formed case fails the file: the gate
        does not judge it as something else, and does not skip it."""
        tree = self.plant_bad_cases("sound")
        sound = tree.read(self.PLANTED_CASES)
        for label, change, message in self.MALFORMED_LINES:
            with self.subTest(label):
                tree.write(self.PLANTED_CASES, sound)
                cases = tree.read_jsonl(self.PLANTED_CASES)
                self.assertEqual(cases[1]["kind"], "near-miss")
                change(cases[1])
                tree.write_jsonl(self.PLANTED_CASES, cases)
                result = tree.run(self.GATE, self.PLANTED_RULE)
                self.assert_rejects(result, rf"^ERROR T9999/planted_rule\.yml: line 2: {message}$",
                                    exit_code=1)
                self.assertIn("\nFAILED: 1 case problem(s).\n", result.stdout)
                self.assertIn(self.POSITIVE_FIRES, result.stdout)

    def test_rejects_sidecar_without_its_rule(self):
        """A sidecar whose rule is gone (deleted, or renamed without it) tests nothing.
        The planted sidecar is the sound one, without the rule. The command is the
        command of CI: the gate finds the sidecars with a glob."""
        tree = self.tree()
        tree.plant("sufficiency/bad_cases/sound.cases.jsonl", self.PLANTED_CASES)
        result = tree.run(self.GATE)
        self.assert_rejects(
            result, r"^ERROR T9999/planted_rule\.yml: a cases file exists but the rule does not$",
            exit_code=1)
        self.assertIn("\nFAILED: 1 case problem(s).\n", result.stdout)

    @gatelib.known_gap(
        "rc-case-clash-is-a-traceback",
        gate="detections/rule_cases.py (the event table of detections/sigma_eval.py)",
        reason="A sidecar event with two keys that differ only in letter case (`comm` and "
               "`Comm`) ends rule_cases.py with an uncaught ValueError of "
               "sigma_eval.EventTable. The rule-cases job fails, but with a traceback: no "
               "FAIL or ERROR line names the rule and the case, and the gate judges no "
               "case after it. check_sufficiency.py catches the same error and reports "
               "it as an R3 failure of the rule.",
        closes="R2d", today="crash")
    def test_gap_event_keys_that_differ_only_in_letter_case(self):
        """WANTED: the gate reports the event as a failure of its rule, in a FAIL or
        ERROR line that names the rule and says that two keys differ only by case."""
        tree = self.plant_bad_cases("keys_differ_by_case")
        # The artifact is bad in one way: one event has the keys `comm` and `Comm`.
        case, = tree.read_jsonl(self.PLANTED_CASES)
        keys = list(case["events"][0])
        self.assertEqual(sorted(key for key in keys if key.lower() == "comm"), ["Comm", "comm"])
        self.assertEqual(len({key.lower() for key in keys}), len(keys) - 1)
        # Without the key `Comm` the gate accepts the same pair.
        sound = self.plant_bad_cases("keys_differ_by_case")
        edit_cases(sound, self.PLANTED_CASES, lambda case: case["events"][0].pop("Comm"))
        accepted = sound.run(self.GATE, self.PLANTED_RULE)
        self.assert_accepts(accepted, r"^All cases hold \(1 rule file\(s\)\)\.$")
        self.assertIn(f"ok    T9999/planted_rule.yml :: positive   {case['name']}: fires\n",
                      accepted.stdout)
        result = tree.run(self.GATE, self.PLANTED_RULE)
        # The gate read the planted event: its output names the two keys (today in
        # the last line of the traceback).
        self.assert_saw(result, r"differ only by case.*\bComm / comm\b")
        self.assert_rejects(result, r"^(FAIL|ERROR) +T9999/planted_rule\.yml.*differ only by case")


class SigmaEvalImportGuard(gatelib.GateCase):
    """The import guard of detections/sigma_eval.py. It is no script: it runs when a
    gate or a validator imports sigma_eval, before pySigma is imported and before
    any rule is read, and it ends the process with a message on stderr. The tests
    reach it through detections/rule_cases.py, with the command of the rule-cases
    job. (The known gap hidden-rule-file, in RuleCases, is a gap of this guard too.)"""

    GATE = "detections/rule_cases.py"
    PARTS = gatelib.DETECTIONS

    def test_control_good_tree_passes_the_guard(self):
        """CONTROL: in the unmodified copy the guard refuses nothing: the same command
        imports pySigma, runs every sidecar and prints nothing on stderr."""
        good = self.good()
        sidecars = good.glob("detections/sigma/*/*.cases.jsonl")
        self.assertGreater(len(sidecars), 0, "the copy holds no sidecar: the control is vacuous")
        result = good.run(self.GATE)
        self.assert_accepts(result, rf"^All cases hold \({len(sidecars)} rule file\(s\)\)\.$")
        self.assertEqual(result.stderr, "", "the guard (or the gate) wrote to stderr")

    def assert_guard_refuses(self, result, path):
        """The guard named `path`, and only it, before the gate read a rule."""
        self.assert_rejects(
            result, r"^refusing to import pySigma: .* Move or delete:\n  " + re.escape(path) + "$",
            exit_code=1)
        self.assertEqual(result.stderr.split("Move or delete:\n")[1], f"  {path}\n",
                         "the guard names more than the planted file")
        self.assertEqual(result.stdout, "", "the gate printed something before the guard "
                         "stopped it: the guard must run before any rule is read")

    def test_rejects_sigma_module_beside_the_gates(self):
        """Nothing beside the gates may replace pySigma: a detections/sigma.py wins
        over pySigma's `sigma` namespace package in every gate."""
        tree = self.tree()
        tree.plant("sufficiency/shadow/sigma_py.txt", "detections/sigma.py")
        self.assert_guard_refuses(tree.run(self.GATE), "detections/sigma.py")

    def test_rejects_module_in_a_rule_directory(self):
        """The rule directory is a portion of pySigma's namespace: only rule material
        (*.yml, *.cases.jsonl, *.md) may be in it. CheckSufficiency plants the same
        file: the two hygiene checks agree on this one."""
        tree = self.tree()
        tree.plant("sufficiency/shadow/evil_py.txt", "detections/sigma/T1040/evil.py")
        self.assert_guard_refuses(tree.run(self.GATE), "detections/sigma/T1040/evil.py")

    BAD_POSITIVE = (r"^FAIL  T1040/afinet_raw_socket\.yml :: positive   "
                    r"planted-stream-socket-declared-positive: expected a match, got near-miss")

    @gatelib.known_gap(
        "se-plain-source-shadow",
        gate="detections/sigma_eval.py import guard (through detections/rule_cases.py)",
        reason="A plain-source detections/glob.py is imported by rule_cases.py in place of "
               "the standard-library module, because detections/ is first on sys.path and "
               "the import guard refuses only sigma.* and compiled modules; the gate then "
               "skips one sidecar, which holds a positive that cannot fire, and passes. On "
               "the planted tree check_sufficiency.py still fails that positive (R3) and "
               "score_benign.py stops, because budgets.json names the rule that the module "
               "hides; and the merge policy needs a human approval for a new .py file. So "
               "the planted change does not pass CI. The gap is that the rule-cases job "
               "passes: it does not judge the sidecar that the module hides.",
        closes="R1")
    def test_gap_plain_source_module_replaces_a_library_module(self):
        """WANTED: the gate refuses a module in detections/ that replaces a library
        module, or it still reads every sidecar and fails on the bad positive."""
        tree = self.tree()
        tree.plant("sufficiency/shadow/afinet_bad_positive.jsonl", AFINET_CASES, append=True)
        tree.plant("sufficiency/shadow/glob_py.txt", "detections/glob.py")
        result = tree.run(self.GATE)
        if result.returncode == 0:
            # The gate accepted the copy. Prove that this is the gap: the planted
            # module hid one sidecar, ...
            sidecars = len(tree.glob("detections/sigma/*/*.cases.jsonl"))
            self.assert_saw(result, rf"^All cases hold \({sidecars - 1} rule file\(s\)\)\.$")
            # ... and the planted positive is bad: the gate fails it when the rule is
            # its argument (then the gate does not call glob).
            named = tree.run(self.GATE, AFINET_RULE)
            self.assertEqual(named.returncode, 1, named.describe())
            self.assertRegex(named.stdout, re.compile(self.BAD_POSITIVE, re.MULTILINE))
        self.assert_rejects(result, r"^  detections/glob\.py$|" + self.BAD_POSITIVE)


class CheckSufficiency(gatelib.StartedTogether):
    """detections/check_sufficiency.py, as the check-sufficiency job runs it: every
    rule, with --markdown. One full run takes about 6 s, so the full runs of the
    class start together (gatelib.StartedTogether)."""

    GATE = "detections/check_sufficiency.py"
    PARTS = gatelib.DETECTIONS      # the gate and the validators it imports read only detections/
    RUNS = ("unregistered_rule", "no_verified_negative", "stale_waiver", "failing_case",
            "emulation_name", "name_keyed", "fixture_constant", "self_added_waiver")

    @classmethod
    def start_gate(cls, tree):
        return tree.start(cls.GATE, "--markdown", tree.out("summary.md"))

    def assert_one_rule_fails(self, tree, result, check):
        """One planted defect: one rule of the copy fails, and only on `check`."""
        rules = len(tree.glob("detections/sigma/*/*.yml"))
        self.assertRegex(result.stdout, re.compile(
            rf"^FAILED: {rules} rule\(s\): \d+ pass, \d+ pass with warnings, 1 fail "
            rf"\(rules failing {check} 1\)\. ", re.MULTILINE))

    # ---- control and CI wiring ------------------------------------------------------

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the unmodified copy passes, and the gate checked every rule in it."""
        good, result = self.started()
        rules = len(good.glob("detections/sigma/*/*.yml"))
        self.assertGreater(rules, 0, "the copy holds no rule: the control is vacuous")
        self.assert_accepts(
            result, rf"^OK: {rules} rule\(s\): \d+ pass, \d+ pass with warnings, 0 fail\. ")

    def test_ci_runs_the_gate_with_the_arguments_of_these_tests(self):
        self.assertIn('python3 detections/check_sufficiency.py --markdown "$GITHUB_STEP_SUMMARY" '
                      "| tee /tmp/sufficiency.out", gatelib.ci_commands(self.GATE))

    def test_ci_step_fails_when_the_gate_fails(self):
        """The check-sufficiency step pipes the gate into `tee`. Run that step as
        GitHub Actions does: the gate's exit code must reach the step, and the
        failure must be in the job summary."""
        step = gatelib.ci_step("detection-quality.yml", "check-sufficiency", self.GATE)
        tree = self.tree()
        tree.plant("sufficiency/shadow/evil_py.txt", "detections/sigma/T1040/evil.py")
        result = tree.run_step(step, env={"GITHUB_STEP_SUMMARY": tree.out("summary.md")})
        self.assert_rejects(result, r"^  \[ERROR\] R0: unexpected `detections/sigma/T1040/evil\.py`",
                            exit_code=1)
        with open(tree.out("summary.md"), encoding="utf-8") as fh:
            self.assertIn("**FAIL**: 1 unexpected file(s) in detections/ (R0)", fh.read())

    # ---- R0: repository hygiene -----------------------------------------------------

    def test_rejects_hidden_rule_file(self):
        """R0 names each file that is not rule material. This is the artifact of the
        known gap hidden-rule-file (RuleCases), planted the same way: the import guard
        of sigma_eval.py accepts it, and R0 of this gate refuses it. The artifact is
        two files, so the count is 2."""
        tree = self.tree()
        tree.plant("sufficiency/hidden_rule/hidden.yml", "detections/sigma/T1040/.hidden.yml")
        tree.plant("sufficiency/hidden_rule/hidden.cases.jsonl",
                   "detections/sigma/T1040/.hidden.cases.jsonl")
        result = tree.run(self.GATE, "--markdown", tree.out("summary.md"))
        self.assert_rejects(
            result, r"^  \[ERROR\] R0: unexpected `detections/sigma/T1040/\.hidden\.yml`: "
                    r"detections/sigma/ holds only", exit_code=1)
        self.assertIn("  [ERROR] R0: unexpected `detections/sigma/T1040/.hidden.cases.jsonl`: ",
                      result.stdout)
        self.assertIn("\nFAILED: 2 unexpected file(s) in detections/ (R0); no rule was checked.\n",
                      result.stdout)

    def test_rejects_module_in_a_rule_directory(self):
        """R0 refuses a Python module among the rules (SigmaEvalImportGuard plants the
        same file for the import guard)."""
        tree = self.tree()
        tree.plant("sufficiency/shadow/evil_py.txt", "detections/sigma/T1040/evil.py")
        result = tree.run(self.GATE, "--markdown", tree.out("summary.md"))
        self.assert_rejects(
            result, r"^  \[ERROR\] R0: unexpected `detections/sigma/T1040/evil\.py`: "
                    r"detections/sigma/ holds only", exit_code=1)
        self.assertIn("\nFAILED: 1 unexpected file(s) in detections/ (R0); no rule was checked.\n",
                      result.stdout)

    # ---- R1: a registered positive --------------------------------------------------

    @classmethod
    def begin_unregistered_rule(cls, tree):
        # A copy of the real T1040/afinet_raw_socket rule and three of its cases, under
        # a new file name, id and title. No validator MANIFEST names the file.
        tree.plant("sufficiency/unregistered_rule", "detections/sigma/T1040")
        return cls.start_gate(tree)

    def test_rejects_rule_in_no_validator_manifest(self):
        """R1: a rule needs a registered positive (an emulation that a validator runs)."""
        tree, result = self.started("unregistered_rule")
        self.assert_rejects(
            result, r"^  \[R1\] T1040/planted_unregistered\.yml: no registered positive: register "
                    r"the rule and its emulation in validate_detections\.py MANIFEST", exit_code=1)
        self.assert_one_rule_fails(tree, result, "R1")

    # ---- R2: a verified negative ----------------------------------------------------

    @classmethod
    def begin_no_verified_negative(cls, tree):
        # The real sidecar without its near-miss and filtered cases: the positives and
        # the benign case stay, and each still passes.
        drop_cases(tree, AFINET_CASES, lambda case: case["kind"] in ("near-miss", "filtered"))
        return cls.start_gate(tree)

    def test_rejects_rule_without_verified_negative(self):
        """R2 (definition of done 3): a rule needs at least one verified near-miss or
        filtered negative."""
        tree, result = self.started("no_verified_negative")
        self.assert_rejects(
            result, r"^  \[R2\] T1040/afinet_raw_socket\.yml: no verified near-miss or filtered "
                    r"negative \(no passing near-miss/filtered case in "
                    r"`detections/sigma/T1040/afinet_raw_socket\.cases\.jsonl`\)", exit_code=1)
        self.assert_one_rule_fails(tree, result, "R2")

    # ---- waivers: the digest that a human approved ----------------------------------

    EXEC_RULE = "T1609/k8s_pod_exec_attach.yml"     # a rule that CHOKEPOINT excuses from R2
    # The digest that the CHOKEPOINT waiver of a rule approves, and the digest of the
    # rule file of the copy, by the gate's own code.
    WAIVER = ("import sys\n"
              "sys.path.insert(0, 'detections')\n"
              "import check_sufficiency as gate\n"
              "print(gate.CHOKEPOINT[sys.argv[1]].digest,\n"
              "      gate.detection_digest('detections/sigma/' + sys.argv[1]))\n")

    def waiver_digests(self, tree):
        probe = tree.run_python(self.WAIVER, self.EXEC_RULE)
        self.assertEqual(probe.returncode, 0, probe.describe())
        approved, now = probe.stdout.split()
        return approved, now

    @classmethod
    def begin_stale_waiver(cls, tree):
        # The real chokepoint rule with one more subresource: it now fires on
        # pods/proxy too. Its waiver approves the digest of the rule as a human read
        # it. No case is touched, and every case of its sidecar still passes.
        tree.replace("detections/sigma/" + cls.EXEC_RULE,
                     "      - 'attach'\n", "      - 'attach'\n      - 'proxy'\n")
        return cls.start_gate(tree)

    def test_rejects_rule_that_changed_after_its_waiver_was_approved(self):
        """A waiver (CHOKEPOINT, PRESENCE, COMPILE_ONLY, PLATFORM_NAMING) excuses the
        rule content that a human approved, by its digest. A rule that changed under
        its waiver fails the check of that waiver (here R2) until a human approves
        the new content."""
        tree, result = self.started("stale_waiver")
        approved, before = self.waiver_digests(self.good())
        self.assertEqual(before, approved, "the waiver of the unmodified copy is not current: "
                         "the rejection would not come from the planted change")
        now = self.waiver_digests(tree)[1]
        self.assertNotEqual(now, approved)
        self.assert_rejects(
            result,
            r"^  \[R2\] T1609/k8s_pod_exec_attach\.yml: the CHOKEPOINT waiver for "
            r"`T1609/k8s_pod_exec_attach\.yml` was approved for rule digest "
            rf"{approved[:16]}\.\.\., and the rule's name/id/logsource/detection/correlation now "
            rf"digest to {now}: the rule changed since a human approved the waiver ",
            exit_code=1)
        self.assert_one_rule_fails(tree, result, "R2")

    # The same check for the other waiver tables that hold a rule (COMPILE_ONLY is
    # empty): (table, check, a rule of the table).
    OTHER_WAIVERS = (
        ("PRESENCE", "R2", "T1543.005/k8s_cri_static_pod_start.yml"),
        ("PLATFORM_NAMING", "R4", "T1078.004/aws_cognito_unauthenticated_identity_use.yml"),
    )

    def test_rejects_changed_rule_under_each_other_kind_of_waiver(self):
        """The planted change is the smallest one that the digest covers: the first
        character of the rule's id. What the gate says about the one rule comes from
        its own check_rule() (ONE_RULE below); a full run would repeat 90 rules."""
        for table, check, key in self.OTHER_WAIVERS:
            with self.subTest(table=table):
                rule = "detections/sigma/" + key
                good = self.good().run_python(self.ONE_RULE, rule)
                self.assertEqual(good.returncode, 0, good.describe())
                self.assertEqual(len(good.stdout.splitlines()), 1,
                                 "the unmodified rule fails a check:\n" + good.describe())
                tree = self.tree()
                tree.edit(rule, lambda text: re.sub(
                    r"(?m)^id: ([0-9a-f])",
                    lambda found: "id: " + ("1" if found.group(1) == "0" else "0"), text, count=1))
                result = tree.run_python(self.ONE_RULE, rule)
                self.assertEqual(result.returncode, 0, result.describe())
                failures = re.findall(r"(?m)^\[R\d\] .*$", result.stdout)
                self.assertEqual(len(failures), 1, result.describe())
                self.assertRegex(
                    failures[0],
                    rf"^\[{check}\] {re.escape(key)}: the {table} waiver for `{re.escape(key)}` "
                    r"was approved for rule digest [0-9a-f]{16}\.\.\., and the rule's "
                    r"name/id/logsource/detection/correlation now digest to [0-9a-f]{64}: the "
                    r"rule changed since a human approved the waiver ")

    # ---- R3: every sidecar case passes ----------------------------------------------

    @classmethod
    def begin_failing_case(cls, tree):
        # One more case in the real sidecar: a positive that cannot fire the rule.
        tree.plant("sufficiency/shadow/afinet_bad_positive.jsonl", AFINET_CASES, append=True)
        return cls.start_gate(tree)

    def test_rejects_rule_with_a_failing_sidecar_case(self):
        """R3: every sidecar case passes. rule_cases.py fails the same case in the
        rule-cases job; this gate must fail it too, because it counts the cases."""
        tree, result = self.started("failing_case")
        line = len(tree.read_jsonl(AFINET_CASES))       # the planted case is the last line
        self.assert_rejects(
            result,
            r"^  \[R3\] T1040/afinet_raw_socket\.yml: case 'planted-stream-socket-declared-"
            r"positive' \(positive, `detections/sigma/T1040/afinet_raw_socket\.cases\.jsonl` "
            rf"line {line}\) fails: expected a match, got near-miss ",
            exit_code=1)
        self.assert_one_rule_fails(tree, result, "R3")

    # ---- R4: not keyed on the emulation's names -------------------------------------

    @classmethod
    def begin_emulation_name(cls, tree):
        # The real rule with one more filter, which names an emulation literally.
        tree.replace(AFINET_RULE,
                     "  condition: afinet_raw_socket and not allowed_processes\n",
                     "  emu:\n"
                     "    exe|contains: 'trr9999'\n"
                     "  condition: afinet_raw_socket and not allowed_processes and not emu\n")
        return cls.start_gate(tree)

    def test_rejects_rule_that_names_an_emulation(self):
        """R4: a rule must not key on the names that the emulations give their objects."""
        tree, result = self.started("emulation_name")
        self.assert_rejects(
            result, r"^  \[R4\] T1040/afinet_raw_socket\.yml: the detection matches emulation "
                    r"naming \(trr9999\)", exit_code=1)
        self.assert_one_rule_fails(tree, result, "R4")

    # The path that the Linux validator gives the binary of this rule's emulation
    # (the first positive of the real sidecar carries it).
    EMULATION_EXE = "/tmp/deteng_val_x/deteng_afinet_raw_socket_behavioral"

    @classmethod
    def emulation_exe_in_the_cases(cls, tree):
        """Every case of the real sidecar that is not benign gets the path of the
        emulation's binary as the exe of its events."""
        def change(case):
            for event in case["events"] if case["kind"] != "benign" else ():
                event["exe"] = cls.EMULATION_EXE
        edit_cases(tree, AFINET_CASES, change)

    @classmethod
    def begin_name_keyed(cls, tree):
        # The real rule with one more required item: the end of the name that the
        # Linux validator gives every emulation binary (deteng_<atomic>_behavioral).
        # The rule holds no literal emulation name (trr9NNN, deteng_), so only the
        # rename test of R4 can see what it keys on. The sidecar follows the rule,
        # as its author would write it: with the real exe values one positive would
        # not fire and each near-miss would be two flips from firing, so the gate
        # would fail the rule on R3 first.
        tree.replace(AFINET_RULE, "  allowed_processes:\n",
                     "    exe|endswith: '_behavioral'\n  allowed_processes:\n")
        cls.emulation_exe_in_the_cases(tree)
        return cls.start_gate(tree)

    def test_rejects_rule_keyed_on_the_name_of_the_emulation_binary(self):
        """R4, the rename test: the gate renames the emulation's identities in every
        positive unit to random tokens. A rule that then stops firing keys on the
        names, however it spells them."""
        tree, result = self.started("name_keyed")
        # The change has two parts. The second part alone is accepted: with the real
        # rule, the gate has no failure for the cases that carry the emulation's path.
        cases_only = self.tree()
        self.emulation_exe_in_the_cases(cases_only)
        alone = cases_only.run_python(self.ONE_RULE, AFINET_RULE)
        self.assertEqual(alone.returncode, 0, alone.describe())
        self.assertEqual(len(alone.stdout.splitlines()), 1,
                         "the changed sidecar alone fails a check:\n" + alone.describe())
        # The message names random tokens (deteng_val_<8 characters>): not matched.
        self.assert_rejects(
            result,
            r"^  \[R4\] T1040/afinet_raw_socket\.yml: renaming the emulation's identities \(.*\) "
            r"to random tokens \(same-shape and neutral rename\) stops the rule firing on "
            r"(\d+)/\1 positive unit\(s\): .* Items that flip: afinet_raw_socket\.exe\. ",
            exit_code=1)
        self.assert_one_rule_fails(tree, result, "R4")

    @classmethod
    def begin_fixture_constant(cls, tree):
        # The real rule with one more required item: the account id that every cloud
        # fixture and every sidecar case of the repository carries.
        tree.replace("detections/sigma/" + LEAKED_KEY,
                     "  selection_iam_user:\n    userIdentity.type: 'IAMUser'\n",
                     "  selection_iam_user:\n    userIdentity.type: 'IAMUser'\n"
                     "    recipientAccountId: '123456789012'\n")
        return cls.start_gate(tree)

    @gatelib.known_gap(
        "cs-rule-keyed-on-fixture-constant",
        gate="detections/check_sufficiency.py (R4)",
        reason="R4 renames only the emulation's names, so a rule that requires a constant of "
               "the recorded emulation run (recipientAccountId 123456789012, the account of "
               "every fixture and sidecar case) passes, although it can fire in no other "
               "account; the docstring of R4 records this as residual.",
        closes="R3")
    def test_gap_rule_keyed_on_a_constant_of_the_emulation_run(self):
        """WANTED: R4 names a rule that keys on a constant of the emulation run."""
        _, result = self.started("fixture_constant")
        _, control = self.started()
        items = int(report_row(control, LEAKED_KEY)["items"].split("/")[1])
        # The gate read the planted rule: it counts one item more than in the good copy.
        self.assert_saw(result, r"^  " + re.escape(LEAKED_KEY)
                        + rf"\s+\S+\s+\S+\s+\S+\s+\S+\s+\d+/{items + 1}\s")
        self.assert_rejects(result, r"^  \[R4\] " + re.escape(LEAKED_KEY) + ": ")

    # ---- R2 waivers: an entry that arrives with its rule -----------------------------

    # What the gate says about one rule, by its own check_rule(): for a rule of a copy
    # whose full run would only repeat the other 90 rules (6 s).
    ONE_RULE = ("import sys\n"
                "sys.path.insert(0, 'detections')\n"
                "import check_sufficiency as gate\n"
                "positives, cloud, proven, atomics, errors = gate.load_manifests()\n"
                "report = gate.check_rule(sys.argv[1], positives, cloud, proven, atomics)\n"
                "print('digest', gate.detection_digest(sys.argv[1]))\n"
                "for check, message in report.failures:\n"
                "    print(f'[{check}] {report.key}: {message}')\n")
    PURE_SURFACE = r"^\[R2\] T1040/afinet_raw_socket\.yml: every positive item is a surface field"

    @classmethod
    def begin_self_added_waiver(cls, tree):
        # 1. The real rule without its two arguments (a0, a1), and the cases that still
        #    pass: a pure-surface rule, which R2 fails.
        tree.plant("sufficiency/self_added_waiver", "detections/sigma/T1040")
        # 2. In the same copy, a CHOKEPOINT entry for that rule in the gate itself, with
        #    the digest that the gate computes for the changed rule.
        before = tree.run_python(cls.ONE_RULE, AFINET_RULE)
        digest = re.search(r"^digest ([0-9a-f]{64})$", before.stdout, re.MULTILINE)
        if before.returncode != 0 or not digest:
            raise AssertionError("no digest of the planted rule:\n" + before.describe())
        tree.replace(cls.GATE, "CHOKEPOINT = {\n",
                     "CHOKEPOINT = {\n"
                     '    "T1040/afinet_raw_socket.yml": Waiver(\n'
                     '        "PLANTED by detections/tests: socket(2) itself is the surface",\n'
                     f'        "{digest.group(1)}"),\n')
        return cls.start_gate(tree)

    @gatelib.known_gap(
        "cs-self-added-waiver",
        gate="detections/check_sufficiency.py (R2 waivers)",
        reason="check_sufficiency.py reads its waiver tables from the tree that it checks, so "
               "a CHOKEPOINT entry that arrives in the same change as a rule that lost its "
               "arguments excuses that rule in this gate. The planted change does not pass "
               "CI: the sufficiency-ratchet job fails (the rule lost cases and verified "
               "negatives), the benign-corpus job fails (the rule is over its budget), and "
               "the merge policy needs a human approval for a change to the script.",
        closes="R1")
    def test_gap_waiver_added_with_the_rule_it_excuses(self):
        """WANTED: a waiver that arrives in the same change as the rule it excuses does
        not excuse it: the gate fails the rule as it does without the entry."""
        _, result = self.started("self_added_waiver")
        # Without the entry the gate fails the planted rule on R2 (a second copy, with
        # the script unchanged).
        plain = self.tree()
        plain.plant("sufficiency/self_added_waiver", "detections/sigma/T1040")
        before = plain.run_python(self.ONE_RULE, AFINET_RULE)
        self.assertEqual(before.returncode, 0, before.describe())
        self.assertRegex(before.stdout, re.compile(self.PURE_SURFACE, re.MULTILINE))
        # The gate read the planted rule: 4 cases, 1 verified negative, 3 items.
        self.assert_saw(result, r"^  T1040/afinet_raw_socket\.yml\s+linux\s+auditd\s+4/4\s+1\s+1/3\s")
        self.assert_rejects(result, r"^  " + self.PURE_SURFACE[1:])


class SufficiencyRatchet(gatelib.StartedTogether):
    """The sufficiency-ratchet job of detection-quality.yml (pull requests only): the
    base tree's check_sufficiency.py writes a report with --json, and the head runs
    with --baseline on that report. Here the base is the unmodified copy and each
    head is a copy with one planted decrease."""

    GATE = "detections/check_sufficiency.py"
    PARTS = gatelib.DETECTIONS
    # pull_request first: it does not need base_report(), which the others wait for.
    RUNS = ("pull_request", "deleted_near_miss", "edited_case", "changed_negative",
            "renamed_rule", "widened_allowlist")

    @classmethod
    def base_report(cls):
        """The --json report of the unmodified copy (the first step of the job)."""
        if "_base" not in cls.__dict__:
            good = cls.good()
            cls._base = (good.out("base.json"), good.run(cls.GATE, "--json", good.out("base.json")))
            cls.addClassCleanup(delattr, cls, "_base")      # the file goes with good()
        return cls._base[0]

    @classmethod
    def start_gate(cls, tree):
        return tree.start(cls.GATE, "--baseline", cls.base_report())

    @staticmethod
    def delete_one_near_miss(tree):
        """The planted decrease: the real sidecar without the near-miss on a0. The
        head alone still passes (the rule keeps three verified negatives)."""
        return drop_cases(tree, AFINET_CASES, lambda case: case["name"] == "packet-socket-raw")

    def lost_case(self):
        """The [RATCHET] line for delete_one_near_miss(), with the counts of the copy."""
        negatives = sum(1 for case in self.good().read_jsonl(AFINET_CASES)
                        if case["kind"] in ("near-miss", "filtered"))
        return (r"^  \[RATCHET\] T1040/afinet_raw_socket\.yml: sidecar case\(s\) gone: "
                rf"packet-socket-raw; verified negatives {negatives} -> {negatives - 1} "
                r"\(gone: case:packet-socket-raw\)")

    def assert_only_the_ratchet_fails(self, tree, result):
        """One planted decrease: the head alone passes the gate (every rule of the
        copy, no failure), and the comparison with the base names one rule."""
        rules = len(tree.glob("detections/sigma/*/*.yml"))
        self.assertRegex(result.stdout, re.compile(
            rf"^OK: {rules} rule\(s\): \d+ pass, \d+ pass with warnings, 0 fail\. ", re.MULTILINE))
        self.assertEqual(len(re.findall(r"(?m)^  \[(?:RATCHET|ERROR)\] ", result.stdout)), 1,
                         result.describe())
        self.assertIn("\nFAILED: 1 rule(s) lost or changed checks against the base branch. ",
                      result.stdout)

    # ---- control and CI wiring ------------------------------------------------------

    def test_control_unchanged_head_is_accepted(self):
        """CONTROL: the base report holds every rule, and the same tree as the head
        passes the gate and the ratchet, with the content of every case compared."""
        good, result = self.started()
        rules = len(good.glob("detections/sigma/*/*.yml"))
        self.assertGreater(rules, 0, "the copy holds no rule: the control is vacuous")
        self.assert_accepts(self._base[1], rf"^OK: {rules} rule\(s\): ")
        with open(self.base_report(), encoding="utf-8") as fh:
            self.assertEqual(len(json.load(fh)["rules"]), rules)
        self.assert_accepts(result, rf"^OK: {rules} rule\(s\): .* 0 fail\. ")
        self.assert_accepts(result, r"^OK: every base rule is on the head, and none has fewer "
                                    r"verified negatives, .* that is gone or changed\.$")

    def test_ci_runs_the_two_commands_of_these_tests(self):
        commands = gatelib.ci_commands(self.GATE)
        self.assertIn('python3 "$base/detections/check_sufficiency.py" --json '
                      '"$RUNNER_TEMP/base.json" > "$RUNNER_TEMP/base.out" 2>&1 || true', commands)
        self.assertIn('python3 detections/check_sufficiency.py --baseline "$RUNNER_TEMP/base.json" '
                      "> /tmp/ratchet.out 2>&1 || rc=$?", commands)

    @classmethod
    def begin_pull_request(cls, tree):
        """The job as a pull request runs it, in a throwaway git repository in the
        sandbox. Base: the unmodified copy, as a commit. Head: the working tree,
        without one near-miss. Returns the (step, Result) pairs of the steps that ran,
        up to the step with --baseline."""
        pinned = sorted(set(os.environ) & {
            "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
            "GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_ALTERNATE_OBJECT_DIRECTORIES"})
        if pinned:
            # A gate run inherits these, and git would then work on that repository.
            # As for a missing tool (gatelib.require_program): a skip here, and a
            # failure in CI, where the suite must run every test.
            why = "the environment pins git to a repository: " + ", ".join(pinned)
            if os.environ.get("CI"):
                raise AssertionError(why + " (in CI no test is skipped: unset the variable)")
            raise unittest.SkipTest(why)
        gatelib.require_program("git", "the job makes a worktree of the base commit")
        env = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CEILING_DIRECTORIES": tree.sandbox,
               "GITHUB_OUTPUT": tree.out("github-output")}

        def git(*args):
            done = tree.run_command(["git", "-c", "user.name=gate-tests",
                                     "-c", "user.email=gate-tests@example.com", *args], env=env)
            if done.returncode != 0:
                raise AssertionError("git failed in the throwaway repository:\n" + done.describe())
            return done.stdout.strip()

        git("init", "--quiet")
        if os.path.realpath(git("rev-parse", "--show-toplevel")) != os.path.realpath(tree.root):
            raise AssertionError("git does not work on the copy; nothing was committed")
        git("add", "--all", "--force")
        git("commit", "--quiet", "--message", "base: the unmodified copy")
        env["BASE_SHA"] = git("rev-parse", "HEAD")      # ${{ github.event.pull_request.base.sha }}
        cls.delete_one_near_miss(tree)

        # The job installs the requirements of the base and of the head with pip:
        # run_step() gives the step a `pip` that installs nothing.
        steps = [step for step in gatelib.ci_steps()
                 if (step.workflow, step.job) == ("detection-quality.yml", "sufficiency-ratchet")]
        last = max(n for n, step in enumerate(steps) if "check_sufficiency.py --baseline" in step.run)

        def job():
            ran = []
            for step in steps[:last + 1]:
                ran.append((step, tree.run_step(step, env=env)))
                if ran[-1][1].returncode != 0:
                    break       # GitHub Actions does not run the next step
            return ran

        return cls.in_background(job)

    def test_ci_job_fails_when_a_near_miss_is_deleted(self):
        """The real steps of the job: `git worktree add` of the base commit, the base's
        own report, then the head with --baseline. The exit code of the gate must
        reach the last step (`|| rc=$?` ... `exit "$rc"`)."""
        tree, ran = self.started("pull_request")
        base, last = ran[0], ran[-1]
        self.assertIn("check_sufficiency.py\" --json", base[0].run)
        self.assertEqual(base[1].returncode, 0, base[1].describe())
        with open(tree.out("github-output"), encoding="utf-8") as fh:
            self.assertIn("present=true\n", fh.read())      # the `if:` of the later steps
        self.assertIn("check_sufficiency.py --baseline", last[0].run,
                      f"the job stopped at the step {last[0].name!r}:\n" + last[1].describe())
        self.assert_rejects(last[1], self.lost_case(), exit_code=1)
        self.assertIn("\nFAILED: 1 rule(s) lost or changed checks against the base branch. ",
                      last[1].stdout)

    # ---- the ratchet ----------------------------------------------------------------

    @classmethod
    def begin_deleted_near_miss(cls, tree):
        cls.delete_one_near_miss(tree)
        return cls.start_gate(tree)

    def test_rejects_deleted_near_miss(self):
        """A content-only change must not delete a verified negative. The head alone
        passes the gate: only the comparison with the base rejects it."""
        tree, result = self.started("deleted_near_miss")
        self.assert_rejects(result, self.lost_case(), exit_code=1)
        self.assert_only_the_ratchet_fails(tree, result)

    @classmethod
    def begin_edited_case(cls, tree):
        # One value of the event of a real near-miss is changed: the protocol argument
        # a2, which the rule does not read. The case still passes, as a near-miss on
        # the same item; its content is not the content of the base branch.
        def change(case):
            if case["name"] == "stream-socket":
                case["events"][0]["a2"] = "11"      # IPPROTO_UDP in place of IPPROTO_TCP ('6')
        edit_cases(tree, AFINET_CASES, change)
        return cls.start_gate(tree)

    def test_rejects_edited_case(self):
        """A content-only change must not change what a sidecar case holds (its kind,
        its `breaks` or its events): the case that a human read is not the case that
        runs. The head alone passes."""
        tree, result = self.started("edited_case")
        self.assert_rejects(
            result, r"^  \[RATCHET\] T1040/afinet_raw_socket\.yml: sidecar case\(s\) changed "
                    r"\(kind, breaks or events\): stream-socket$", exit_code=1)
        self.assert_only_the_ratchet_fails(tree, result)

    @classmethod
    def begin_changed_negative(cls, tree):
        # One record of a hard benign fixture is a verified negative of its rule. Its
        # userAgent, which the rule does not read, is changed: the record is still a
        # negative on the same item, with another content than on the base branch.
        def change(records):
            records[1]["userAgent"] = "PLANTED by detections/tests"
        tree.edit_json(LEAKED_KEY_BENIGN, change)
        return cls.start_gate(tree)

    def test_rejects_changed_fixture_negative(self):
        """A verified negative that is a fixture record must keep its content too."""
        tree, result = self.started("changed_negative")
        source = (f"fixture:{LEAKED_KEY_BENIGN} record #1 "
                  f"({tree.read_json(LEAKED_KEY_BENIGN)[1]['eventName']})")
        # On the base branch that record is a verified negative of the rule.
        with open(self.base_report(), encoding="utf-8") as fh:
            base = next(rule for rule in json.load(fh)["rules"] if rule["rule"] == LEAKED_KEY)
        self.assertIn(source, [negative["source"] for negative in base["negatives"]])
        self.assert_rejects(
            result, rf"^  \[RATCHET\] {re.escape(LEAKED_KEY)}: verified negative\(s\) changed: "
                    rf"{re.escape(source)}$", exit_code=1)
        self.assert_only_the_ratchet_fails(tree, result)

    RENAMED = "detections/sigma/T1040/afinet_raw_socket_v2"

    @classmethod
    def begin_renamed_rule(cls, tree):
        # The real rule and its sidecar under another file name. The rows of the
        # Linux validator's MANIFEST that register the rule follow the name, so the
        # head alone is consistent: the gate takes the file for a new rule, and a new
        # rule has nothing to compare. (A rule that is deleted takes the same branch
        # of the ratchet; the head then fails too, on its MANIFEST rows.)
        tree.rename(AFINET_RULE, cls.RENAMED + ".yml")
        tree.rename(AFINET_CASES, cls.RENAMED + ".cases.jsonl")
        tree.replace("detections/validate_detections.py", f'"{AFINET_RULE}"',
                     f'"{cls.RENAMED}.yml"', count=0)
        return cls.start_gate(tree)

    def test_rejects_rule_that_is_gone_from_the_head(self):
        """A rule of the base branch that the head does not have (deleted, or renamed)
        takes its verified negatives out of the comparison. A human decides."""
        tree, result = self.started("renamed_rule")
        negatives = sum(1 for case in self.good().read_jsonl(AFINET_CASES)
                        if case["kind"] in ("near-miss", "filtered"))
        self.assert_rejects(
            result, r"^  \[RATCHET\] T1040/afinet_raw_socket\.yml: on the base branch but not on "
                    rf"the head: deleted or renamed; its {negatives} verified negative\(s\) are "
                    r"not compared$", exit_code=1)
        self.assert_only_the_ratchet_fails(tree, result)

    @classmethod
    def begin_widened_allowlist(cls, tree):
        # The real rule with one more allowlisted process name. No case is touched.
        tree.replace(AFINET_RULE, "      - traceroute6\n", "      - traceroute6\n      - nc\n")
        return cls.start_gate(tree)

    # A raw socket made by nc: the base rule fires on it, and the planted rule does not.
    NC_RAW_SOCKET = {
        "name": "nc-raw-socket", "kind": "positive",
        "why": "socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) by nc, which the base rule does not "
               "allowlist",
        "source": "synthetic: probe of detections/tests",
        "events": [{"type": "SYSCALL", "syscall": "socket", "success": "yes", "exit": "3",
                    "a0": "2", "a1": "3", "a2": "1", "a3": "0", "comm": "nc",
                    "exe": "/usr/bin/nc"}]}

    def probe(self, tree):
        """Run the probe case against the copy's rule (a pair outside detections/sigma/)."""
        rule = tree.out("probe/afinet_raw_socket.yml")
        shutil.copyfile(tree.path(AFINET_RULE), rule)
        with open(tree.out("probe/afinet_raw_socket.cases.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(self.NC_RAW_SOCKET) + "\n")
        return tree.run("detections/rule_cases.py", rule)

    @gatelib.known_gap(
        "ra-allowlist-widened-no-case",
        gate="sufficiency-ratchet job: detections/check_sufficiency.py --baseline",
        reason="The ratchet compares cases, verified negatives, exercised items and "
               "logsources, not what the rule matches, so a rule whose allowlist grew (it "
               "detects less than on the base branch) passes when no case was touched. No "
               "other offline gate rejects the planted rule.",
        closes="R6")
    def test_gap_allowlist_widened_without_a_case(self):
        """WANTED: a rule that detects less than on the base branch goes to a human: a
        [RATCHET] line names the rule."""
        tree, result = self.started("widened_allowlist")
        # The planted rule detects less than the rule of the base.
        on_base, on_head = self.probe(self.good()), self.probe(tree)
        self.assertEqual(on_base.returncode, 0, on_base.describe())
        self.assertIn(":: positive   nc-raw-socket: fires\n", on_base.stdout)
        self.assertEqual(on_head.returncode, 1, on_head.describe())
        self.assertIn(":: positive   nc-raw-socket: expected a match, got filtered (one flip "
                      "would fire it: allowed_processes.comm)\n", on_head.stdout)
        # The head was compared with the base report (the gate prints nothing else
        # about the planted line: the rule keeps its cases, negatives and items).
        self.assert_saw(result, r"^Ratchet against .+ \(the base branch's report\):$")
        self.assert_rejects(result, r"^  \[RATCHET\] T1040/afinet_raw_socket\.yml: ")


class SigmaExplainSelfTest(gatelib.GateCase):
    """detections/sigma_explain.py --self-test: the grader that decides if a negative
    is a near-miss, checked on constructed rules. No workflow runs this command: the
    gate tests are where CI runs it (test_suite.py, SelfTests, keeps the list of
    such self-tests). The control below is the control of the planted grader."""

    GATE = "detections/sigma_explain.py"
    PARTS = gatelib.DETECTIONS      # the self-test also grades every rule under detections/sigma/
    BRANCH_CHECK = "OR of branches: a flip counts only through a branch the event shares"

    def test_control_good_grader_passes_its_self_test(self):
        """CONTROL: the unmodified grader passes, the self-test graded every rule of
        the copy, and the check that the rejection test needs ran."""
        good = self.good()
        rules = len(good.glob("detections/sigma/*/*.yml"))
        self.assertGreater(rules, 0, "the copy holds no rule: the control is vacuous")
        result = good.run(self.GATE, "--self-test")
        self.assert_accepts(result, r"^All self-test checks hold\.$")
        self.assert_accepts(result, r'^ok    \{"x": 1\} is trivial for every rule under '
                                    rf"detections/sigma/ \({rules} rules\)$")
        self.assert_accepts(result, rf"^ok    {re.escape(self.BRANCH_CHECK)}$")

    def test_rejects_grader_that_counts_a_flip_through_an_unshared_branch(self):
        """In `a or b`, an event that holds nothing of branch b is not a near-miss on b.
        The planted grader says that every flip shares a branch: PlainRule._shares_branch
        returns True at once. Its self-test must turn red."""
        tree = self.tree()
        tree.edit(self.GATE, lambda text: re.sub(
            r'(\n    def _shares_branch\(self, truth, atom\):\n        """.*?"""\n)',
            lambda found: found.group(1) + "        return True     # PLANTED by detections/tests\n",
            text, count=1, flags=re.DOTALL))
        result = tree.run(self.GATE, "--self-test")
        self.assert_rejects(
            result, rf"^FAIL  {re.escape(self.BRANCH_CHECK)}: got near-miss "
                    r"\['sel_put\.flag', 'sel_delete\.eventName'\] lone \[\]$", exit_code=1)
        # The one planted change fails two checks: the grade, and the case that
        # rule_cases.py would accept with it.
        self.assertIn("\nFAIL  rule_cases: declaring the lone branch fails, and says why: ",
                      result.stdout)
        self.assertIn("\nFAILED: 2 self-test check(s).\n", result.stdout)


if __name__ == "__main__":
    unittest.main()
