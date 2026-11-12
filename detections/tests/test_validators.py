"""
Gate tests, group `validators`: the validators that prove a detection on telemetry
(validate-*.yml) and the lints (lint-trr.yml, validate-detections.yml,
detection-quality.yml job schedule-freshness).

    CloudValidator         detections/validate_cloud_detections.py (and --dry-run)
    LinuxValidatorDryRun   detections/validate_detections.py --dry-run (needs gcc)
    LinuxValidatorOffline  detections/validate_detections.py, real mode, with the
                           host replaced by canned events (no root, no auditd)
    K8sValidator           detections/validate_k8s_detections.py: --dry-run, and
                           the negative-control step (--expect-miss)
    StaticPodValidator     detections/validate_staticpod_detections.py: the same two
    ApiserverValidator     detections/validate_apiserver_detections.py: the same two
    TrrLint                .github/scripts/trr_lint.py, and its step in lint-trr.yml
    MarkdownLinks          .github/scripts/check_md_links.py
    SigmaRegexLint         .github/scripts/check_sigma_regex.py
    ScheduleFreshness      .github/scripts/check_schedule_freshness.py, on recorded
                           API answers only (never the live API)

Planted artifacts: detections/tests/known_bad/validators/. A small change to a real
file of the copy is made in the test, with a comment that says what is bad.
How the harness works: gatelib.py and README.md in this directory.

    python3 -B -m unittest discover -s detections/tests -p 'test_validators.py' -v
"""

import importlib.util
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gatelib  # noqa: E402  (the line above makes it importable with `-t .` too)

# A @gatelib.known_gap test states the wanted behaviour in its LAST assertion, one
# assert_rejects(). Every assertion before it is a plain one (assertEqual, assert_saw):
# it proves that the planted artifact is bad, or that the gate read it, and when it
# fails the test fails, whatever the gate does.


def in_source(tree, script, pattern):
    """Every match of `pattern` (re.MULTILINE) in a script of the copy, as a list.

    For the size of a validator's MANIFEST: a control takes its count from the
    tree, not from the output of the gate that it checks."""
    found = re.findall(pattern, tree.read(script), re.MULTILINE)
    if not found:
        raise AssertionError(f"{script} of the copy holds no match of /{pattern}/: the "
                             "count for the control cannot be taken from the tree")
    return found


def without_the_manifest_entry(test, tree, gate):
    """Remove the MANIFEST entry of afxdp_socket.yml from the Linux validator of a
    copy. Its CONTROLS row stays: a row for a rule that no atomic proves."""
    def change(text):
        # BAD: MANIFEST holds no atomic for afxdp_socket.yml; CONTROLS has its row.
        text, found = re.subn(
            r'    \("detections/sigma/T1040/afxdp_socket\.yml",\n'
            r'     "atomics/T1040/src/afxdp_socket_behavioral\.c", \[\],\n'
            r'     \[socket_family\(AF_XDP, socket\.SOCK_RAW, 0, "AF_XDP"\)\]\),\n', "", text)
        test.assertEqual(found, 1, "the MANIFEST entry of afxdp_socket.yml was not found")
        test.assertIn('"detections/controls/afxdp_netlink_socket.c"', text)
        return text

    tree.edit(gate, change)


def write_log(tree, name, sidecar=None, *cases):
    """Write a sensor log for a workflow step that reads /tmp/<name>.

    Tree.run_step() gives the step the sandbox's tmp directory as /tmp/
    (Tree.tmp_path()). The log holds the events of the named cases of a rule
    sidecar of the copy, one JSON object per line, as the capture steps write them.
    Without a sidecar the log is an empty file. Returns the number of records."""
    events = []
    if sidecar:
        by_name = {case["name"]: case for case in tree.read_jsonl(sidecar)}
        for case in cases:
            if case not in by_name:
                raise AssertionError(f"{sidecar} holds no case {case!r}: choose another "
                                     "case for the log of this test")
            events += by_name[case]["events"]
        if not events:
            raise AssertionError(f"write_log({name}): name at least one case")
    with open(tree.tmp_path(name), "w", encoding="utf-8") as fh:
        fh.write("".join(json.dumps(event) + "\n" for event in events))
    return len(events)


class CloudValidator(gatelib.GateCase):
    """detections/validate_cloud_detections.py, as the validate-cloud job runs it:
    every rule of MANIFEST on its recorded attack fixture and its benign baseline.

    The planted defects are in the fixtures of TRR9012 (the leaked access key)."""

    GATE = "detections/validate_cloud_detections.py"
    PARTS = gatelib.DETECTIONS      # the gate reads nothing outside detections/
    ATTACK = "detections/cloud/fixtures/trr9012/attack.json"
    BENIGN = "detections/cloud/fixtures/trr9012/benign.json"
    MARKER = "trr9012-leaked-key-user"

    RULE = "detections/sigma/T1078.004/aws_leaked_access_key_recon.yml"
    # Other gates that read the rule or its fixtures. The `reason` of a known gap of
    # this class says what they do with the planted tree, and the test proves it.
    SUFFICIENCY = "detections/check_sufficiency.py"
    NULL_SAFETY = "detections/check_null_safety.py"
    RATCHET = (r"^  \[RATCHET\] T1078\.004/aws_leaked_access_key_recon\.yml: verified negatives "
               r"(\d+) -> (\d+) \(gone: fixture:detections/cloud/fixtures/trr9012/benign\.json "
               r"record #1 ")

    def manifest_rules(self, tree):
        """The (folder, rule file) pairs of the gate's MANIFEST, read from its source."""
        return set(in_source(tree, self.GATE, r'^\s+\("TRR\d+", "(T[\d.]+)", "([^"]+\.yml)",'))

    @classmethod
    def start_base_report(cls):
        """Start, once for the class and in the background, the report that the
        sufficiency-ratchet job makes for the base branch: check_sufficiency.py
        --json on the unmodified copy. It is the report of RULE only (--rule), the
        faster path of the same code. ratchet() waits for it."""
        if "_base" not in cls.__dict__:
            good = cls.good()
            report = good.out("base-report.json")
            cls._base = (report, good.start(cls.SUFFICIENCY, "--rule", cls.RULE,
                                            "--json", report))
            cls.addClassCleanup(delattr, cls, "_base")

    def ratchet(self, tree):
        """The last step of the sufficiency-ratchet job in a copy, for RULE: the head
        against the report of the base (check_sufficiency.py --baseline). The run
        prints the verdict of check_sufficiency.py first, then that of the ratchet."""
        self.start_base_report()
        report, base = self._base
        self.assert_accepts(base.result(),
                            r"^OK: 1 rule\(s\): 1 pass, 0 pass with warnings, 0 fail\. ")
        return tree.run(self.SUFFICIENCY, "--rule", self.RULE, "--baseline", report)

    def test_ci_runs_the_dry_run_and_the_validation(self):
        """The commands of these tests are the two commands of the validate-cloud job."""
        self.assertEqual(gatelib.ci_commands(self.GATE), [
            "python3 detections/validate_cloud_detections.py --dry-run | tee /tmp/clouddry.out",
            "python3 detections/validate_cloud_detections.py | tee /tmp/cloudval.out"])

    def test_control_good_tree_is_accepted(self):
        """CONTROL: every MANIFEST rule fires on its attack fixture and on no benign
        record. A rule or a fixture that is missing is PENDING and exits 0, so the
        proof is the count of rules and the PASS line of the rule that the other
        tests break."""
        good = self.good()
        rules = self.manifest_rules(good)
        attack, benign = good.read_json(self.ATTACK), good.read_json(self.BENIGN)
        self.assertGreater(len(benign), 0, "the good baseline is empty: the control is vacuous")
        result = good.run(self.GATE)
        self.assert_accepts(
            result,
            rf"^All {len(rules)} external-cloud detection\(s\) fired on their recorded attack "
            r"fixtures, and every negative control held\.$")
        self.assert_saw(
            result,
            rf"^PASS  \[TRR9012 AWS\] aws_leaked_access_key_recon\.yml: {len(attack)}/"
            rf"{len(attack)} attack record\(s\) match; benign baseline clean "
            rf"\({len(benign)} record\(s\)\) ")
        self.assertNotIn("PENDING", result.stdout)

    def test_control_dry_run_compiles_every_rule(self):
        """CONTROL of the first step of the job: every MANIFEST rule compiles."""
        good = self.good()
        self.assert_accepts(
            good.run(self.GATE, "--dry-run"),
            rf"^Dry run OK: {len(self.manifest_rules(good))} cloud rule\(s\) compile with "
            r"pySigma\.$")

    def test_rejects_rule_that_fires_on_a_benign_record(self):
        """Definition of done 2 (stays quiet). The first attack record is appended to
        the benign baseline: the rule now fires on a record of its negative control."""
        tree = self.tree()
        attack = tree.read_json(self.ATTACK)
        tree.edit_json(self.BENIGN, lambda rows: rows + [attack[0]])
        result = tree.run(self.GATE)
        self.assert_rejects(
            result,
            r"^FAIL  \[TRR9012 AWS\] aws_leaked_access_key_recon\.yml: NEGATIVE CONTROL FAILED: "
            r"rule fired on 1 benign record\(s\) ",
            exit_code=1)
        self.assertIn("\nFAILED: 1 technique(s) did not satisfy attack-fires + control-holds.",
                      result.stdout)

    def test_rejects_attack_that_does_not_carry_the_emulation_marker(self):
        """Definition of done 1 (fires on its own emulation). The user name of the
        emulation is replaced in every attack record: the rule still fires, but on
        no record that the emulation marked, so nothing ties the hit to the attack."""
        tree = self.tree()
        tree.replace(self.ATTACK, self.MARKER, "ordinary-user", count=0)
        attack = tree.read_json(self.ATTACK)
        result = tree.run(self.GATE)
        self.assert_rejects(
            result,
            rf"^FAIL  \[TRR9012 AWS\] aws_leaked_access_key_recon\.yml: rule fired "
            rf"\({len(attack)}\) but no match carried the emulation marker ",
            exit_code=1)
        self.assertIn("\nFAILED: 1 technique(s) did not satisfy attack-fires + control-holds.",
                      result.stdout)
        self.assertIn(f"must contain '{self.MARKER}'", result.stdout)

    def test_ci_step_fails_when_the_gate_fails(self):
        """The validate step pipes the gate into `tee`. Run that step as GitHub
        Actions does: the gate's exit code must reach the step."""
        step = gatelib.ci_step("validate-cloud-detections.yml", "validate",
                               "validate_cloud_detections.py | tee /tmp/cloudval.out")
        tree = self.tree()
        attack = tree.read_json(self.ATTACK)
        tree.edit_json(self.BENIGN, lambda rows: rows + [attack[0]])
        self.assert_rejects(
            tree.run_step(step),
            r"aws_leaked_access_key_recon\.yml: NEGATIVE CONTROL FAILED: rule fired on 1 benign",
            exit_code=1)

    @gatelib.known_gap(
        "cloud-benign-empty",
        gate="detections/validate_cloud_detections.py",
        reason="A benign baseline that holds no record passes as `benign baseline clean "
               "(0 record(s))`: a negative control with nothing in it cannot fail. "
               "check_sufficiency.py, rule_cases.py, check_null_safety.py and score_benign.py "
               "accept the same tree. The sufficiency-ratchet job rejects the planted change "
               "on a pull request, because the records that are gone were verified negatives "
               "of a rule of the base branch. So the gap is open for a new rule that comes "
               "with an empty baseline, and on every push and weekly run.",
        closes="R2c")
    def test_gap_empty_benign_baseline(self):
        """WANTED: a rule whose benign baseline holds no record fails, because its
        negative control is vacuous (definition of done 2 needs a hard baseline)."""
        tree = self.tree()
        self.start_base_report()        # for the proof of the `reason`, below
        tree.write(self.BENIGN, "[]\n")
        # The artifact is bad: the negative control of the rule has no record.
        self.assertEqual(tree.read_json(self.BENIGN), [])
        others = {script: tree.start(script, *arguments) for script, arguments in (
            ("detections/rule_cases.py", (self.RULE,)),
            (self.NULL_SAFETY, (self.RULE,)),
            ("detections/score_benign.py", ("--check", "--enforce")))}
        result = tree.run(self.GATE)
        # The gate judged the rule: it prints this row for a PASS, a FAIL and an ERROR.
        self.assert_saw(result, r"^(?:PASS|FAIL|ERROR)\s+\[TRR9012 AWS\] aws_leaked_access_key_recon"
                                r"\.yml: ")
        if result.returncode == 0:
            # Today the row shows that the gate read the planted file: no benign record.
            self.assert_saw(result, r"^PASS  \[TRR9012 AWS\] aws_leaked_access_key_recon\.yml: "
                                    r".*benign baseline clean \(0 record\(s\)\) ")
            # Today. The `reason` of the marker says what the other jobs do with the
            # planted tree; prove each sentence, so that the text cannot go out of
            # date. Three gates accept the tree (for the one rule: the faster path
            # of the same code).
            for script, pending in others.items():
                self.assertEqual(pending.result().returncode, 0,
                                 f"{script} does not accept the tree any more: correct the "
                                 "`reason` of the marker\n" + pending.result().describe())
            # check_sufficiency.py accepts it too, and the ratchet of the pull request
            # rejects it: the records of the good baseline were verified negatives.
            ratchet = self.ratchet(tree)
            self.assertRegex(ratchet.stdout,
                             r"(?m)^OK: 1 rule\(s\): 1 pass, 0 pass with warnings, 0 fail\. ")
            self.assertEqual(ratchet.returncode, 1, ratchet.describe())
            gone = re.search(self.RATCHET, ratchet.stdout, re.MULTILINE)
            self.assertIsNotNone(gone, ratchet.describe())
            self.assertGreater(int(gone.group(1)), int(gone.group(2)))
        self.assert_rejects(
            result,
            r"^(FAIL|ERROR)\s+\[TRR9012 AWS\] aws_leaked_access_key_recon\.yml: .*benign.*"
            r"(empty|no record|0 record|vacuous|proves nothing)")

    @gatelib.known_gap(
        "cloud-fixture-missing-is-pending",
        gate="detections/validate_cloud_detections.py",
        reason="A rule of MANIFEST whose benign fixture is missing is `PENDING`, and the run "
               "exits 0 with `All N-1 external-cloud detection(s) fired`: the rule has no "
               "proof, and the validate job is green. A missing attack fixture takes the "
               "same path. Other jobs still stop the planted change: null-safety fails, with "
               "a FileNotFoundError traceback and no message that names the rule, and the "
               "sufficiency-ratchet job fails on a pull request (verified negatives are "
               "gone). check_sufficiency.py passes with a warning (its check R2: the "
               "records of the fixture cannot count as negatives).",
        closes="R2c")
    def test_gap_missing_fixture_is_pending(self):
        """WANTED: a rule of MANIFEST that exists, and whose fixture does not, fails.
        PENDING is for a rule that is not built yet."""
        tree = self.tree()
        self.start_base_report()        # for the proof of the `reason`, below
        rules = self.manifest_rules(tree)
        self.assertIn(tuple(self.RULE.split("/")[-2:]), rules)
        tree.remove(self.BENIGN)
        no_attack = self.tree()         # the same defect in the other fixture
        no_attack.remove(self.ATTACK)
        others = (no_attack.start(self.GATE), tree.start(self.NULL_SAFETY, self.RULE))
        # The artifact is bad: the rule and its attack fixture are in the tree, and the
        # baseline that MANIFEST names for its negative control is not.
        self.assertTrue(tree.exists(self.RULE) and tree.exists(self.ATTACK))
        self.assertFalse(tree.exists(self.BENIGN))
        self.assertIn(f'"{self.BENIGN.split("fixtures/")[1]}"', tree.read(self.GATE))
        result = tree.run(self.GATE)
        # The gate reached the rule (it compiled it) and gave it no PASS: nothing in
        # this run proved the rule. Both hold for a PENDING line and for a failure.
        self.assert_saw(result, r"^OK \(compile\)  T1078\.004/aws_leaked_access_key_recon\.yml  "
                                r"\[TRR9012\]$")
        self.assertNotRegex(result.stdout, r"(?m)^PASS +\[TRR9012\b")
        if result.returncode == 0:
            # Today: a green run that counts one detection fewer than MANIFEST holds.
            green = (rf"^All {len(rules) - 1} external-cloud detection\(s\) fired on their "
                     r"recorded attack fixtures, and every negative control held\.$")
            self.assert_saw(result, green)
            # The `reason` of the marker says more; prove each sentence, so that the
            # text cannot go out of date. A missing attack fixture takes the same path.
            without_attack, null_safety = (pending.result() for pending in others)
            self.assert_accepts(without_attack, green)
            self.assert_saw(without_attack, r"^PENDING \[TRR9012\] aws_leaked_access_key_recon"
                                            r"\.yml: fixtures not present -- skipped$")
            # null-safety stops the planted tree, with a traceback that does not name
            # the rule (for the one rule: the faster path of the same code).
            self.assertEqual(null_safety.returncode, 1, null_safety.describe())
            self.assertTrue(null_safety.crashed, null_safety.describe())
            self.assertRegex(null_safety.stderr,
                             r"(?m)^FileNotFoundError: .*/cloud/fixtures/trr9012/benign\.json'$")
            self.assertNotIn("aws_leaked_access_key_recon", null_safety.output)
            # check_sufficiency.py passes with a warning of its check R2, and the
            # ratchet of the pull request rejects: verified negatives are gone.
            ratchet = self.ratchet(tree)
            self.assertRegex(ratchet.stdout,
                             r"(?m)^  \[R2\] T1078\.004/aws_leaked_access_key_recon\.yml: benign "
                             r"fixture detections/cloud/fixtures/trr9012/benign\.json is missing; "
                             r"its records cannot count as negatives$")
            self.assertRegex(ratchet.stdout,
                             r"(?m)^OK: 1 rule\(s\): 0 pass, 1 pass with warnings, 0 fail\. ")
            self.assertEqual(ratchet.returncode, 1, ratchet.describe())
            gone = re.search(self.RATCHET, ratchet.stdout, re.MULTILINE)
            self.assertIsNotNone(gone, ratchet.describe())
            self.assertGreater(int(gone.group(1)), int(gone.group(2)))
        self.assert_rejects(
            result,
            r"^(FAIL|ERROR)\s+\[TRR9012[^\]]*\] aws_leaked_access_key_recon\.yml: .*"
            r"(fixture|benign\.json)")


class LinuxValidatorDryRun(gatelib.GateCase):
    """detections/validate_detections.py --dry-run: the CONTROLS table has no bad
    row, every rule of MANIFEST and CONTROLS compiles with pySigma, and every atomic
    and control compiles with gcc.

    No workflow runs --dry-run. The validate job (validate-detections.yml) runs the
    real mode, which does the same check of the table and the same compile step
    first, and stops on their errors."""

    GATE = "detections/validate_detections.py"
    PARTS = ("detections", "atomics")
    ATOMIC = "atomics/T1622/src/ptrace_traceme_behavioral.c"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        gatelib.require_program("gcc", "the Linux dry run compiles the atomics")

    def test_control_good_tree_compiles(self):
        """CONTROL: the counts are those of the rules and C sources that the
        validator's MANIFEST, CONTROLS and NOOP name, and each source is in the copy."""
        good = self.good()
        rules = set(in_source(good, self.GATE, r'"(detections/sigma/[^"]+\.yml)"'))
        sources = set(in_source(good, self.GATE,
                                r'"((?:atomics|detections/controls)/[^"]+\.c)"'))
        self.assertIn(self.ATOMIC, sources)
        self.assert_documented(f"python3 {self.GATE} --dry-run")
        for path in sorted(rules | sources):
            self.assertTrue(good.exists(path), f"{path} is not in the copy")
        self.assert_accepts(
            good.run(self.GATE, "--dry-run"),
            rf"^OK: {len(rules)} rules compiled by pySigma, {len(sources)} atomics/controls "
            r"compiled\.$")

    def test_rejects_atomic_that_does_not_compile(self):
        """An emulation that does not build produces no telemetry. The atomic of
        ptrace_traceme.yml is replaced by a C file that names an undeclared symbol."""
        tree = self.tree()
        tree.plant("validators/broken_atomic.c.txt", self.ATOMIC)
        result = tree.run(self.GATE, "--dry-run")
        self.assert_rejects(
            result,
            r"^  \[ERROR \] ptrace_traceme_behavioral\.c  compile failed for "
            r"atomics/T1622/src/ptrace_traceme_behavioral\.c:$",
            exit_code=1)
        self.assertIn("undeclared_symbol", result.stdout)     # gcc's own message follows
        self.assertEqual(len(re.findall(r"^  \[ERROR \] ", result.stdout, re.MULTILINE)), 1)
        self.assertNotIn("atomics/controls compiled.", result.stdout)

    # The four tests below plant one bad row in the CONTROLS table. The validator
    # checks the table before it compiles or runs anything, in every mode. The row
    # is the one of afxdp_socket.yml (its rule has no other built control).
    AFXDP_ROW = (r"^  \[ERROR \] CONTROLS row \d+ \({source} -> afxdp_socket\.yml\)  ")
    AFXDP_DECLARED = '''"the a0 (AF_XDP) argument constraint was not enforced",
     ["afxdp_socket.a0"]),'''

    def rejects_the_table(self, tree, fault, source=r"afxdp_netlink_socket\.c"):
        """The dry run of `tree` ends with exit code 1, one [ERROR ] line that names
        the CONTROLS row of afxdp_socket.yml with `fault`, and nothing compiled."""
        result = tree.run(self.GATE, "--dry-run")
        self.assert_rejects(result, self.AFXDP_ROW.format(source=source) + fault, exit_code=1)
        self.assertEqual(len(re.findall(r"^  \[ERROR \] ", result.stdout, re.MULTILINE)), 1)
        self.assert_saw(result, r"^ERROR: the CONTROLS table of validate_detections\.py has "
                                r"1 fault\(s\); nothing was compiled and no stimulus ran\.$")
        self.assertNotIn("atomics/controls compiled.", result.stdout)
        return result

    def test_rejects_controls_row_that_declares_nothing(self):
        """A built control must declare what holds it. A row whose declaration is an
        empty list can never be held as declared: an empty list is equal to the grade
        of a control that no item of the rule holds. (At commit 95e3ddc the real mode
        printed `held` for such a control when no item of its rule held it, and
        counted it as live.)"""
        tree = self.tree()
        # BAD: the row declares nothing.
        tree.replace(self.GATE, self.AFXDP_DECLARED,
                     self.AFXDP_DECLARED.replace('["afxdp_socket.a0"]', "[]"))
        self.rejects_the_table(
            tree, r"declares nothing: the fifth field must be a non-empty list of the "
                  r"item\(s\) that hold the control ")

    def test_rejects_controls_row_with_four_fields(self):
        """A row without its declaration (four fields) is refused with a message that
        names the row. (At commit 95e3ddc the dry run accepted the table, and the real
        mode ended with a traceback after every atomic had run.)"""
        tree = self.tree()
        # BAD: the fifth field of the row is gone.
        tree.replace(self.GATE, self.AFXDP_DECLARED,
                     self.AFXDP_DECLARED.replace(',\n     ["afxdp_socket.a0"]', ""))
        self.rejects_the_table(tree, r"has 4 field\(s\), not five \(rule, C source, arguments, "
                                     r"meaning of a pass, declared items\)$")

    def test_rejects_controls_row_for_a_rule_that_is_not_in_manifest(self):
        """A control is graded against a rule that an atomic proves. The planted
        MANIFEST has no entry for afxdp_socket.yml, and the CONTROLS row of that rule
        stays: no emulation proves the rule, and the validator counts the live
        negative controls for the rules of MANIFEST only."""
        tree = self.tree()
        without_the_manifest_entry(self, tree, self.GATE)
        self.rejects_the_table(
            tree, r"its rule 'detections/sigma/T1040/afxdp_socket\.yml' is not a rule of "
                  r"MANIFEST: ")

    def test_rejects_controls_row_whose_source_does_not_exist(self):
        """A row that names a C source that is not in the repository is refused with
        a message that names the row, before gcc runs. (Without the check the compile
        step fails on that source, with the message of an atomic that does not
        compile.)"""
        tree = self.tree()
        # BAD: the row names a control that does not exist.
        tree.replace(self.GATE, '"detections/controls/afxdp_netlink_socket.c", [],',
                     '"detections/controls/afxdp_no_such_control.c", [],')
        result = self.rejects_the_table(
            tree, r"its C source 'detections/controls/afxdp_no_such_control\.c' does not "
                  r"exist$", source=r"afxdp_no_such_control\.c")
        self.assertNotIn("compile failed", result.stdout)


class LinuxValidatorOffline(gatelib.GateCase):
    """detections/validate_detections.py in its real mode (the validate job:
    `--require-audit`), with the host replaced by canned results.

    The real mode needs root and auditd, so no test can run it. The driver
    known_bad/validators/linux_offline_run_py.txt is planted at the root of a copy.
    It replaces the five functions that touch the host (audit_available,
    load_audit_rules, unload_audit_rules, compile_atomic, run) and takes the canned
    events from the rule sidecars of the copy. The verdict code is the validator's
    own: process_tree() (which records are the stimulus's own), judge(), the control
    table, grade_control() and the exit code. Without an argument the canned run is
    healthy; one argument plants one defect in it (and `--missing` is a host that
    lacks a kernel feature, which is not a defect).

    What these tests cannot show: that a C program in detections/controls/ makes
    the calls that its CONTROLS row declares. The canned events of a mutant come
    from the sidecar case of the item that the row declares, so the grade follows
    the row: no test here compares a row with its program. Only the job `validate`
    grades the programs."""

    GATE = "detections/validate_detections.py"
    DRIVER = "linux_offline_run.py"
    PARTS = gatelib.DETECTIONS      # the driver compiles nothing: no atomics, no gcc
    NOOP = "detections/controls/noop.c"
    # The mutants, the re-runs and the atomics in which a test plants a defect, and
    # two lines of the validator's output.
    AFINET = "detections/controls/afinet_stream_socket.c"        # a second control: `ping`
    PTRACE = "detections/controls/ptrace_attach_child.c"         # the only control
    PTRACE_ATOMIC = "atomics/T1622/src/ptrace_traceme_behavioral.c"
    COPYFAIL = "detections/controls/copyfail_unix_socket_splice.c"   # of a correlation
    AFXDP = "detections/controls/afxdp_netlink_socket.c"         # an AF_NETLINK socket only
    AFXDP_ATOMIC = "atomics/T1040/src/afxdp_socket_behavioral.c"
    USERFAULTFD = "detections/controls/userfaultfd_bad_flags.c"  # declares the success gate
    # setns_namespace_join.yml: its only built control is the re-run as `runc`.
    SETNS_RERUN = "atomics/T1611/src/setns_namespace_join_behavioral.c as runc"
    # afpacket_raw_socket.yml: the one rule with two emulations (two MANIFEST entries).
    AFPACKET_FIRST = "atomics/T1040/src/afpacket_rawsocket_behavioral.c"
    AFPACKET_SECOND = "atomics/T1040/src/afpacket_mmap_ring_behavioral.c"
    BROKEN_ROW = r"^  \[BROKEN\] "
    SUMMARY = (r"^{passed} passed, {skipped} skipped \(kernel feature missing\), 0 failed; "
               r"{broken} control\(s\) broken\.$")

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # One copy with the driver for all tests: the validator writes nothing in it
        # (its build directory is under TMPDIR), and each run names its own defect.
        cls.offline = cls.class_tree()
        cls.offline.plant("validators/linux_offline_run_py.txt", cls.DRIVER)

    def canned_run(self, *scenario, report=None):
        """The validator on the canned run, with the argument of the CI step (and
        --json PATH for its machine-readable report)."""
        more = ("--json", report) if report else ()
        return self.offline.run(self.DRIVER, *scenario, "--require-audit", *more)

    def test_ci_runs_the_validator_with_require_audit(self):
        """The validator argument of these tests is the one of the validate job.
        Without --require-audit a host that cannot audit is a SKIP with exit 0."""
        self.assert_ci_runs(self.GATE, "--require-audit")

    def negatives(self, report):
        """{rule file name: its entry} of `negatives` in a --json report: for each
        rule of MANIFEST, the built controls that are live, and a status."""
        with open(report, encoding="utf-8") as fh:
            return {os.path.basename(row["rule"]): row for row in json.load(fh)["negatives"]}

    @staticmethod
    def row_label(control):
        """The start of the validator's label for a control that the driver names
        `SRC` (a mutant) or `ATOMIC as NAME` (a re-run under an allowlisted name)."""
        src, _, name = control.partition(" as ")
        return os.path.basename(src) + (f" as '{name}'" if name else "") + " -> "

    def control_row(self, report, control):
        """The row of one built control in a --json report."""
        with open(report, encoding="utf-8") as fh:
            rows = [row for row in json.load(fh)["controls"]
                    if row["control"].startswith(self.row_label(control))]
        self.assertEqual(len(rows), 1, f"{control}: one row wanted in the report")
        return rows[0]

    def graded(self, report, control):
        """What the validator read for one control, from a --json report: (the kind
        of its grade, the items that hold it, the lines that grade its nearest event
        item by item). The report holds them for a control that is held and for one
        that is broken."""
        row = self.control_row(report, control)
        return row["kind"], row["graded"], "\n".join(row["verdict"])

    def test_control_canned_run_is_accepted(self):
        """CONTROL: every atomic passes on the records of its own process tree, and
        every control holds: the no-op on each rule, each mutant, and each re-run
        under an allowlisted name. Each mutant and each re-run is held by the item
        that it declares, so each rule has a live negative control."""
        tree = self.offline
        atomics = in_source(tree, self.GATE, r'"(atomics/[^"]+\.c)"')      # one per entry
        rules = set(in_source(tree, self.GATE, r'"(detections/sigma/[^"]+\.yml)"'))
        mutants = set(in_source(tree, self.GATE, r'"(detections/controls/[^"]+\.c)"'))
        mutants.discard(self.NOOP)
        report = tree.out("control.json")
        result = self.canned_run(report=report)
        self.assert_accepts(
            result,
            rf"^{len(atomics)} passed, 0 skipped \(kernel feature missing\), 0 failed; "
            r"0 control\(s\) broken\.$")
        self.assertEqual(len(re.findall(r"^  \[ PASS \] ", result.stdout, re.MULTILINE)),
                         len(atomics))
        with open(report, encoding="utf-8") as fh:
            controls = json.load(fh)["controls"]
        self.assertEqual({row["status"] for row in controls}, {"held"})
        # The no-op ran on every rule; its window holds its own record and one of
        # another process. It is graded (it owns a record), and it is never live.
        noop = [row for row in controls if row["control"].startswith("noop -> ")]
        self.assertEqual(len(noop), len(rules))
        self.assertEqual({row["detail"] for row in noop},
                         {"no hit from the stimulus (2 events in window)"})
        self.assertEqual({(row["kind"], row["live"]) for row in noop}, {("baseline", False)})
        # Each mutant and each allowlisted re-run holds for the reason it is built
        # for, and so it is live.
        built = [row for row in controls if row not in noop]
        stimuli = {row["control"].split(" -> ")[0] for row in built}
        for mutant in sorted(mutants):
            self.assertIn(os.path.basename(mutant), stimuli)
        self.assertIn("afinet_raw_socket_behavioral.c as 'ping'", stimuli)
        for row in built:
            self.assertEqual(sorted(row["graded"]), sorted(row["expected"]), row["control"])
            self.assertTrue(row["expected"], row["control"])
            self.assertIs(row["live"], True, row["control"])
        # Each rule has a live negative control, and it is one of those rows.
        negatives = self.negatives(report)
        self.assertEqual(set(negatives), {os.path.basename(rule) for rule in rules})
        labels = {row["control"] for row in built}
        for name, entry in sorted(negatives.items()):
            self.assertEqual(entry["status"], "live", name)
            self.assertTrue(entry["live"], name)
            self.assertLessEqual(set(entry["live"]), labels, name)
            for label in entry["live"]:
                self.assertTrue(label.endswith(f" -> {name}"), label)
        self.assert_saw(result, r"^Live negative control \(a mutant or a re-run that is held as "
                                rf"declared\): {len(rules)} of {len(rules)} rule\(s\)\.$")

    def test_rejects_detection_fired_by_another_process(self):
        """Definition of done 1 (fires on its own emulation). The records that fire
        afinet_raw_socket.yml are in the window, but they carry the pid of another
        process: the atomic's own process tree produced nothing."""
        result = self.canned_run("--foreign", "atomics/T1040/src/afinet_raw_socket_behavioral.c")
        self.assert_rejects(
            result,
            r"^  \[ FAIL \] afinet_raw_socket\.yml +no hit from the stimulus "
            r"\(2 events in window\)$",
            exit_code=1)
        self.assert_saw(result, r"^\d+ passed, 0 skipped \(kernel feature missing\), 1 failed; "
                                r"0 control\(s\) broken\.$")
        # The rule itself matches the foreign record: only the process tree rejects it.
        self.assert_saw(result, r"closest event in the whole window \(NOT from the stimulus "
                                r"tree\):")

    def test_rejects_mutant_control_that_made_no_audited_syscall(self):
        """A control whose process tree made no audited syscall proves nothing (a
        mutant that crashes before its first syscall). detections/README.md: it
        counts as a broken control and fails the run."""
        result = self.canned_run("--vacuous", "detections/controls/afinet_stream_socket.c")
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] afinet_stream_socket\.c -> afinet_raw_socket\.yml +vacuous: the "
            r"control made no audited syscall$",
            exit_code=1)
        self.assert_saw(result, r"^\d+ passed, 0 skipped \(kernel feature missing\), 0 failed; "
                                r"1 control\(s\) broken\.$")

    def test_rejects_atomic_whose_syscalls_the_kernel_rejected(self):
        """Definition of done 1 (fires). The logic of afinet_raw_socket.yml matches the
        atomic's own record, but the kernel rejected the syscall (success=no, EPERM).
        That is an attempt, not an execution: it does not prove the detection."""
        result = self.canned_run("--rejected", "atomics/T1040/src/afinet_raw_socket_behavioral.c")
        self.assert_rejects(
            result,
            r"^  \[ FAIL \] afinet_raw_socket\.yml +fired only on syscalls the kernel rejected "
            r"\(socket: EPERM\): an attempt, not an execution$",
            exit_code=1)
        self.assert_saw(result, r"^\d+ passed, 0 skipped \(kernel feature missing\), 1 failed; "
                                r"0 control\(s\) broken\.$")
        # The rejected record is the stimulus's own: only the success gate fails it.
        self.assert_saw(result, r"^ +audited syscalls from the tree: socket x1 \(EPERM\)$")

    def test_rejects_mutant_control_that_fires_the_rule(self):
        """Definition of done 2 (stays quiet). The process tree of a mutant makes the
        events of the attack itself: the rule fires on its own negative control, so
        the control is broken."""
        result = self.canned_run("--fires", "detections/controls/afinet_stream_socket.c")
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] afinet_stream_socket\.c -> afinet_raw_socket\.yml +passed: the a1 "
            r"\(SOCK_RAW\) argument constraint was not enforced$",
            exit_code=1)
        self.assert_saw(result, r"^\d+ passed, 0 skipped \(kernel feature missing\), 0 failed; "
                                r"1 control\(s\) broken\.$")

    def test_rejects_allowlisted_rerun_that_fires_the_rule(self):
        """Definition of done 2 (stays quiet). The atomic runs again under a name of
        the rule's allowlist (`ping`), and its records still fire the rule: the
        allowlist filter does not suppress what it is written to suppress."""
        result = self.canned_run("--fires",
                                 "atomics/T1040/src/afinet_raw_socket_behavioral.c as ping")
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] afinet_raw_socket_behavioral\.c as 'ping' -> afinet_raw_socket\.yml "
            r"+passed: the allowlist filter did not suppress an allowlisted process$",
            exit_code=1)
        self.assert_saw(result, r"^\d+ passed, 0 skipped \(kernel feature missing\), 0 failed; "
                                r"1 control\(s\) broken\.$")

    def test_rejects_host_that_cannot_audit(self):
        """With --require-audit (the CI argument) a host where auditd does not run
        fails. Without the argument the validator prints SKIP and exits 0."""
        result = self.canned_run("--no-audit", "auditd is not running")
        self.assert_rejects(
            result,
            r"^ERROR: audit validation unavailable \(auditd is not running\) and "
            r"--require-audit set\.$",
            exit_code=1)
        self.assertNotIn("[ PASS ]", result.stdout)

    def test_rejects_noop_control_that_made_no_audited_syscall(self):
        """The no-op is graded for vacuity as the mutants are. A no-op whose process
        tree made no audited syscall is a broken control, and the run fails. (Until
        roadmap item R2b this was the known gap linux-noop-control-vacuous: the
        validator did not grade the no-op, and the real noop.c made no audited
        syscall.)"""
        report = self.offline.out("noop-vacuous.json")
        result = self.canned_run("--vacuous", self.NOOP, report=report)
        # The validator read the canned no-op: on every rule, its window holds only
        # the record of the other process (the control run has 2 events there).
        with open(report, encoding="utf-8") as fh:
            rows = [row for row in json.load(fh)["controls"]
                    if row["control"].startswith("noop -> ")]
        rules = set(in_source(self.offline, self.GATE, r'"(detections/sigma/[^"]+\.yml)"'))
        self.assertEqual(len(rows), len(rules))
        self.assertEqual({row["detail"] for row in rows},
                         {"no hit from the stimulus (1 events in window)"})
        self.assert_rejects(result, r"^  \[BROKEN\] noop -> \S+\.yml +vacuous", exit_code=1)
        # One defect: the no-op row of each rule is broken, and no other row is.
        self.assertEqual({row["status"] for row in rows}, {"BROKEN"})
        self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)),
                         len(rules))

    def test_rejects_rule_that_has_no_built_control(self):
        """Definition of done 2 (stays quiet). Each rule of MANIFEST needs a live
        negative control: a mutant or a re-run that is held by the item it declares.
        The no-op does not count. The planted validator has no CONTROLS row for
        afxdp_socket.yml, and that rule has no allowlist to re-run (the state of seven
        rules before roadmap item R2b)."""
        tree = self.tree()
        tree.plant("validators/linux_offline_run_py.txt", self.DRIVER)

        def without_the_row(text):
            # BAD: the row of CONTROLS for afxdp_socket.yml is gone.
            text, found = re.subn(r'    \("detections/sigma/T1040/afxdp_socket\.yml",\n'
                                  r'     "detections/controls/afxdp_netlink_socket\.c", .*?\]\),\n',
                                  "", text, flags=re.DOTALL)
            self.assertEqual(found, 1, "the CONTROLS row of afxdp_socket.yml was not found")
            return text

        tree.edit(self.GATE, without_the_row)
        report = tree.out("no-control.json")
        result = tree.run(self.DRIVER, "--require-audit", "--json", report)
        # The validator read the rule (its atomic passes and the no-op holds on it),
        # and it ran no built control for it.
        self.assert_saw(result, r"^  \[ PASS \] afxdp_socket\.yml ")
        self.assert_saw(result, r"^  \[ held \] noop -> afxdp_socket\.yml ")
        with open(report, encoding="utf-8") as fh:
            rows = [row for row in json.load(fh)["controls"]
                    if row["rule"].endswith("/afxdp_socket.yml")]
        self.assertEqual([row["control"] for row in rows], ["noop -> afxdp_socket.yml"])
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] afxdp_socket\.yml +no live negative control: no control is built "
            r"for this rule ", exit_code=1)
        self.assert_saw(result, self.SUMMARY.format(passed=r"\d+", skipped=0, broken=1))
        self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)), 1)
        self.assertEqual(self.negatives(report)["afxdp_socket.yml"],
                         {"rule": "detections/sigma/T1040/afxdp_socket.yml",
                          "status": "BROKEN", "live": []})

    def test_rejects_wrong_argument_control_that_no_longer_reaches_its_rule(self):
        """Definition of done 2 (stays quiet). The only built control of
        ptrace_traceme.yml does not make its ptrace call: its one record is far from
        the rule. The rule stays quiet, but not for the reason that the control
        declares (the a0 item), so the control is broken and the rule has no live
        negative control. Before roadmap item R2b the validator printed a WARNING
        for such a control and passed."""
        report = self.offline.out("distant-only-control.json")
        result = self.canned_run("--distant", self.PTRACE, report=report)
        # The validator read the planted record: an ioctl call, not a ptrace call.
        kind, items, nearest = self.graded(report, self.PTRACE)
        self.assertEqual((kind, items), ("distant", []))
        self.assertRegex(nearest,
                         r"(?m)^ +no +syscall +syscall='ioctl' +\(rule wants: 'ptrace'\)$")
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] ptrace_attach_child\.c -> ptrace_traceme\.yml +not held as "
            r"declared: built to break ptrace_traceme\.a0, but graded distant$", exit_code=1)
        self.assert_saw(result, self.SUMMARY.format(passed=r"\d+", skipped=0, broken=1))
        self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)), 1)
        self.assertEqual(self.negatives(report)["ptrace_traceme.yml"]["live"], [])
        self.assertEqual(self.negatives(report)["ptrace_traceme.yml"]["status"], "BROKEN")
        self.assert_saw(result, r"^  none for ptrace_traceme\.yml: see the BROKEN row\(s\) above$")

    def test_rejects_control_held_for_another_reason_on_a_rule_with_a_second_control(self):
        """EVERY built control must be held by the item it declares, not only one for
        each rule. afinet_raw_socket.yml has two built controls. Its mutant does not
        make its SOCK_STREAM call, and the re-run as `ping` is still live: the rule
        has a live negative control, and the run fails all the same."""
        report = self.offline.out("distant-second-control.json")
        result = self.canned_run("--distant", self.AFINET, report=report)
        # The validator read the planted record: an ioctl call, not a socket call.
        kind, items, nearest = self.graded(report, self.AFINET)
        self.assertEqual((kind, items), ("distant", []))
        self.assertRegex(nearest,
                         r"(?m)^ +no +syscall +syscall='ioctl' +\(rule wants: 'socket'\)$")
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] afinet_stream_socket\.c -> afinet_raw_socket\.yml +not held as "
            r"declared: built to break afinet_raw_socket\.a1, but graded distant$", exit_code=1)
        self.assert_saw(result, self.SUMMARY.format(passed=r"\d+", skipped=0, broken=1))
        self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)), 1)
        # A verdict for each rule alone would pass: the rule keeps a live control.
        self.assertEqual(self.negatives(report)["afinet_raw_socket.yml"],
                         {"rule": "detections/sigma/T1040/afinet_raw_socket.yml",
                          "status": "live",
                          "live": ["afinet_raw_socket_behavioral.c as 'ping' -> "
                                   "afinet_raw_socket.yml"]})

    def test_rejects_correlation_control_that_lost_its_wrong_argument_call(self):
        """A mutant of a correlation declares one argument item of one base
        (`base:<name>/<item>`). The control of copyfail_af_alg_authencesn.yml makes
        no socket call: its splice alone leaves the AF_ALG base missing, so the rule
        stays quiet, but no call of the control is one argument away from that
        base. The control is not held by the a0 item that it declares."""
        report = self.offline.out("correlation-without-socket.json")
        result = self.canned_run("--without", self.COPYFAIL, "socket", report=report)
        # The validator read the planted records: the splice, and no socket call.
        kind, items, nearest = self.graded(report, self.COPYFAIL)
        self.assertEqual((kind, items), ("near-miss", ["base:copyfail_af_alg_socket"]))
        self.assertRegex(nearest, r"(?m)^ +\+ base:copyfail_splice matched 1 event\(s\)")
        self.assertRegex(nearest, r"(?m)^ +- base:copyfail_af_alg_socket matched 0 event\(s\)$")
        self.assertRegex(nearest,
                         r"(?m)^ +no +syscall +syscall='splice' +\(rule wants: 'socket'\)$")
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] copyfail_unix_socket_splice\.c -> copyfail_af_alg_authencesn\.yml "
            r"+not held as declared: built to break "
            r"base:copyfail_af_alg_socket/af_alg_socket\.a0, but graded "
            r"base:copyfail_af_alg_socket$", exit_code=1)
        self.assert_saw(result, self.SUMMARY.format(passed=r"\d+", skipped=0, broken=1))
        self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)), 1)

    def test_rejects_built_control_that_cannot_be_graded(self):
        """The grade of a built control is a verdict, not an explanation. In the
        planted tree the grader (sigma_explain.py) does not load. The detections pass
        as before, but nothing shows that a mutant or a re-run is held by the item it
        declares, so each one that an item of its rule must hold is broken. The
        controls that the success gate holds need no grader, and the no-op needs
        none."""
        tree = self.tree()
        tree.plant("validators/linux_offline_run_py.txt", self.DRIVER)
        # BAD: the module that grades the controls fails at import.
        tree.write("detections/sigma_explain.py",
                   "raise ImportError('planted: the grader does not load')\n")
        atomics = in_source(tree, self.GATE, r'"(atomics/[^"]+\.c)"')
        report = tree.out("no-grader.json")
        result = tree.run(self.DRIVER, "--require-audit", "--json", report)
        self.assert_saw(result, r"^\[diag\] sigma_explain failed to import \(ImportError: "
                                r"planted: the grader does not load\)")
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] afinet_stream_socket\.c -> afinet_raw_socket\.yml +not graded: "
            r"nothing shows that the control is held as declared$", exit_code=1)
        with open(report, encoding="utf-8") as fh:
            controls = json.load(fh)["controls"]
        by_item = [row for row in controls if row["expected"] not in (None, ["success"])]
        others = [row for row in controls if row not in by_item]
        self.assertGreater(len(by_item), 10)
        self.assertGreater(len(others), 15)
        self.assertEqual({row["status"] for row in by_item}, {"BROKEN"})
        self.assertEqual({row["kind"] for row in by_item}, {"not graded"})
        self.assertEqual({row["status"] for row in others}, {"held"})
        self.assert_saw(result, self.SUMMARY.format(passed=len(atomics), skipped=0,
                                                    broken=len(by_item)))

    def test_rejects_correlation_control_whose_wrong_argument_call_is_in_another_pid(self):
        """`base:<name>/<item>` means more than a call that misses the base by that
        item: the call must be in the group of the other calls. The control of
        copyfail_af_alg_authencesn.yml makes its AF_UNIX socket call in a child
        process and its splice in the parent. The correlation groups by pid, so the
        rule would stay quiet with an AF_ALG socket in that child too: the a0 item
        is not what holds the control."""
        report = self.offline.out("correlation-split.json")
        result = self.canned_run("--split", self.COPYFAIL, "socket", report=report)
        # The validator read the planted records: the socket call is in the window
        # (3 events, as in the control run) and it misses the base by a0 alone.
        row = self.control_row(report, self.COPYFAIL)
        self.assertEqual(row["detail"], "no hit from the stimulus (3 events in window)")
        kind, items, nearest = self.graded(report, self.COPYFAIL)
        self.assertEqual((kind, items), ("near-miss", ["base:copyfail_af_alg_socket"]))
        self.assertRegex(nearest, r"(?m)^ +nearest event #0 for base:copyfail_af_alg_socket "
                                  r"\(near-miss, one flip: af_alg_socket\.a0\):$")
        self.assertRegex(nearest, r"(?m)^ +yes +syscall +syscall='socket'$")
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] copyfail_unix_socket_splice\.c -> copyfail_af_alg_authencesn\.yml "
            r"+not held as declared: built to break "
            r"base:copyfail_af_alg_socket/af_alg_socket\.a0, but graded "
            r"base:copyfail_af_alg_socket$", exit_code=1)
        self.assert_saw(result, self.SUMMARY.format(passed=r"\d+", skipped=0, broken=1))
        self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)), 1)

    def test_rejects_correlation_control_whose_wrong_argument_call_is_outside_the_window(self):
        """The same for the time window. The control of copyfail_af_alg_authencesn.yml
        makes its AF_UNIX socket call 60 s after its splice, and the correlation has
        a window of 5 s: the rule would stay quiet with an AF_ALG socket at that
        time too."""
        report = self.offline.out("correlation-late.json")
        result = self.canned_run("--late", self.COPYFAIL, "socket", report=report)
        row = self.control_row(report, self.COPYFAIL)
        self.assertEqual(row["detail"], "no hit from the stimulus (3 events in window)")
        kind, items, nearest = self.graded(report, self.COPYFAIL)
        self.assertEqual((kind, items), ("near-miss", ["base:copyfail_af_alg_socket"]))
        self.assertRegex(nearest, r"(?m)^ +nearest event #0 for base:copyfail_af_alg_socket "
                                  r"\(near-miss, one flip: af_alg_socket\.a0\):$")
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] copyfail_unix_socket_splice\.c -> copyfail_af_alg_authencesn\.yml "
            r"+not held as declared: built to break "
            r"base:copyfail_af_alg_socket/af_alg_socket\.a0, but graded "
            r"base:copyfail_af_alg_socket$", exit_code=1)
        self.assert_saw(result, self.SUMMARY.format(passed=r"\d+", skipped=0, broken=1))
        self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)), 1)

    def test_rejects_rerun_under_an_allowlisted_name_that_is_not_held_as_declared(self):
        """A re-run under an allowlisted name declares the allowlist filter
        (`<block>.comm`), and it must be held by that filter, as a mutant by its
        item. The re-run of the atomic of setns_namespace_join.yml as `runc` does not
        make its setns call. The rule stays quiet, but the filter is not what holds
        the process. That re-run is the only built control of the rule, so the rule
        has no live negative control."""
        report = self.offline.out("distant-rerun.json")
        result = self.canned_run("--distant", self.SETNS_RERUN, report=report)
        # The validator read the planted record: an ioctl call under the name `runc`.
        row = self.control_row(report, self.SETNS_RERUN)
        self.assertEqual(row["expected"], ["runtime_processes.comm"])
        kind, items, nearest = self.graded(report, self.SETNS_RERUN)
        self.assertEqual((kind, items), ("distant", []))
        self.assertRegex(nearest,
                         r"(?m)^ +no +syscall +syscall='ioctl' +\(rule wants: 'setns'\)$")
        self.assertRegex(nearest, r"(?m)^ +yes +comm +comm='runc' +\(rule wants: ")
        # The rule has no other built control.
        with open(report, encoding="utf-8") as fh:
            built = [other["control"] for other in json.load(fh)["controls"]
                     if other["rule"].endswith("/setns_namespace_join.yml")
                     and other["expected"] is not None]
        self.assertEqual(built, [row["control"]])
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] setns_namespace_join_behavioral\.c as 'runc' -> "
            r"setns_namespace_join\.yml +not held as declared: built to break "
            r"runtime_processes\.comm, but graded distant$", exit_code=1)
        self.assert_saw(result, self.SUMMARY.format(passed=r"\d+", skipped=0, broken=1))
        self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)), 1)
        self.assertEqual(self.negatives(report)["setns_namespace_join.yml"],
                         {"rule": "detections/sigma/T1611/setns_namespace_join.yml",
                          "status": "BROKEN", "live": []})

    def test_rejects_success_gate_control_that_the_success_gate_does_not_hold(self):
        """A control that declares `success` must be held by the success gate of the
        validator: the logic of its rule matches a call of the control, and the
        kernel rejected that call. The control of userfaultfd_syscall.yml does not
        make its userfaultfd call, so nothing of it reaches that gate. The rule
        reads only the name of the syscall, and the validator grades the planted
        record as a near-miss on that item, which is not what the control declares."""
        report = self.offline.out("distant-success-gate.json")
        result = self.canned_run("--distant", self.USERFAULTFD, report=report)
        row = self.control_row(report, self.USERFAULTFD)
        self.assertEqual(row["expected"], ["success"])
        # The validator read the planted record: an accepted ioctl call.
        kind, items, nearest = self.graded(report, self.USERFAULTFD)
        self.assertEqual((kind, items), ("near-miss", ["userfaultfd_syscall.syscall"]))
        self.assertRegex(nearest,
                         r"(?m)^ +no +syscall +syscall='ioctl' +\(rule wants: 'userfaultfd'\)$")
        self.assert_rejects(
            result,
            r"^  \[BROKEN\] userfaultfd_bad_flags\.c -> userfaultfd_syscall\.yml +not held as "
            r"declared: built to break success, but graded userfaultfd_syscall\.syscall$",
            exit_code=1)
        self.assert_saw(result, self.SUMMARY.format(passed=r"\d+", skipped=0, broken=1))
        self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)), 1)
        self.assertEqual(self.negatives(report)["userfaultfd_syscall.yml"]["status"], "BROKEN")

    def test_rejects_each_built_control_that_does_not_make_its_calls(self):
        """No built control is held by a record that is not of its rule. For each
        mutant of CONTROLS and each re-run of the control run, in a run of its own,
        the process makes only an accepted ioctl call: a syscall that no rule of
        MANIFEST reads. Each of these runs must fail with that control BROKEN, and
        with no other row BROKEN."""
        tree = self.offline
        sources = {os.path.basename(path): path for path in in_source(
            tree, self.GATE, r'"((?:atomics|detections/controls)/[^"]+\.c)"')}
        healthy = tree.out("each-distant-healthy.json")
        self.assert_accepts(self.canned_run(report=healthy), r"0 control\(s\) broken\.$")
        with open(healthy, encoding="utf-8") as fh:
            built = [row for row in json.load(fh)["controls"] if row["expected"] is not None]
        mutants = set(in_source(tree, self.GATE, r'"(detections/controls/[^"]+\.c)"'))
        mutants.discard(self.NOOP)
        # The driver's name of each built control, from the validator's label.
        names = {}
        for row in built:
            found = re.fullmatch(r"(\S+\.c)(?: as '([^']+)')? -> \S+\.yml", row["control"])
            self.assertIsNotNone(found, row["control"])
            names[row["control"]] = (sources[found.group(1)]
                                     + (f" as {found.group(2)}" if found.group(2) else ""))
        self.assertLessEqual(mutants, set(names.values()))      # each row of CONTROLS
        self.assertGreater(len(names), len(mutants))            # and the re-runs
        runs = {label: (tree.out(f"each-distant-{number}.json"),
                        tree.start(self.DRIVER, "--distant", name, "--require-audit", "--json",
                                   tree.out(f"each-distant-{number}.json")))
                for number, (label, name) in enumerate(sorted(names.items()))}
        for row in built:
            label = row["control"]
            report, pending = runs[label]
            result = pending.result()
            with self.subTest(control=label):
                planted = self.control_row(report, names[label])
                # The validator read the planted record: it is alone in the tree of
                # the control, and no item that the control declares holds it.
                self.assertEqual(planted["detail"],
                                 "no hit from the stimulus (2 events in window)")
                self.assertIn(planted["kind"], ("distant", "trivial", "near-miss"))
                if planted["kind"] == "near-miss":      # a rule that reads only the name
                    self.assertEqual(len(planted["graded"]), 1, label)
                    self.assertTrue(planted["graded"][0].endswith(".syscall"), label)
                else:
                    self.assertEqual(planted["graded"], [], label)
                self.assertNotEqual(sorted(planted["graded"]), sorted(planted["expected"]))
                self.assert_rejects(
                    result,
                    rf"^  \[BROKEN\] {re.escape(label)} +not held as declared: built to break "
                    rf"{re.escape(', '.join(row['expected']))}, but graded ", exit_code=1)
                self.assert_saw(result, self.SUMMARY.format(passed=r"\d+", skipped=0, broken=1))
                self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)),
                                 1)
                self.assertIs(planted["live"], False)

    def test_control_refused_mutant_of_a_skipped_rule_is_not_applicable(self):
        """CONTROL of the one exemption. The kernel-feature probe turns the emulation
        of ptrace_traceme.yml into a SKIP, and the kernel rejects the one call of the
        rule's mutant too (the model: Yama refuses the PTRACE_ATTACH of
        ptrace_attach_child.c). The mutant is not held as declared, and this host
        cannot exercise it: its row is N/A, with the reason, and the run passes. The
        rejection tests below hold the limits of the exemption."""
        atomics = in_source(self.offline, self.GATE, r'"(atomics/[^"]+\.c)"')
        report = self.offline.out("skipped-rule.json")
        result = self.canned_run("--missing", self.PTRACE_ATOMIC, "--refused", self.PTRACE,
                                 report=report)
        self.assert_accepts(result, self.SUMMARY.format(passed=len(atomics) - 1, skipped=1,
                                                        broken=0))
        self.assert_saw(result, r"^  \[ SKIP \] ptrace_traceme\.yml +the kernel lacks the feature "
                                r"\(canned\)$")
        self.assert_saw(
            result,
            r"^  \[ N/A  \] ptrace_attach_child\.c -> ptrace_traceme\.yml +not held as declared "
            r"\(built to break ptrace_traceme\.a0, graded all rejected\)\. The emulation of this "
            r"rule was SKIPPED \(kernel feature missing\), and the kernel rejected every call of "
            r"the control that the rule reads \(ptrace: EPERM\): this host cannot exercise the "
            r"control$")
        self.assertNotRegex(result.stdout, re.compile(self.BROKEN_ROW, re.MULTILINE))
        self.assertEqual(self.control_row(report, self.PTRACE)["refused"], ["ptrace: EPERM"])
        self.assertEqual(self.negatives(report)["ptrace_traceme.yml"]["status"], "N/A")
        # The exemption is for that rule only: every other rule keeps its live control.
        self.assertEqual({name for name, entry in self.negatives(report).items()
                          if entry["status"] != "live"}, {"ptrace_traceme.yml"})

    def skipped_and_broken(self, result, skipped, broken):
        """The run failed with one emulation SKIPPED (`skipped`: its rule file name)
        and one control BROKEN (`broken`: the row, as a regular expression)."""
        self.assert_saw(result, rf"^  \[ SKIP \] {re.escape(skipped)} +the kernel lacks the "
                                r"feature \(canned\)$")
        self.assert_rejects(result, broken, exit_code=1)
        self.assert_saw(result, self.SUMMARY.format(passed=r"\d+", skipped=1, broken=1))
        self.assertEqual(len(re.findall(self.BROKEN_ROW, result.stdout, re.MULTILINE)), 1)
        self.assertNotRegex(result.stdout, re.compile(r"^  \[ N/A  \] \S+\.c -> ", re.MULTILINE))

    def test_rejects_refused_mutant_of_a_rule_that_is_not_skipped(self):
        """The exemption is for a skipped rule only. The emulation of afxdp_socket.yml
        is SKIPPED, the emulation of ptrace_traceme.yml passes, and the kernel rejects
        the call of the mutant of ptrace_traceme.yml: the artifact of the CONTROL
        above, on a rule that the host proves. That mutant is BROKEN."""
        report = self.offline.out("refused-not-skipped.json")
        result = self.canned_run("--missing", self.AFXDP_ATOMIC, "--refused", self.PTRACE,
                                 report=report)
        self.assert_saw(result, r"^  \[ PASS \] ptrace_traceme\.yml ")
        self.assertEqual(self.control_row(report, self.PTRACE)["refused"], ["ptrace: EPERM"])
        self.skipped_and_broken(
            result, "afxdp_socket.yml",
            r"^  \[BROKEN\] ptrace_attach_child\.c -> ptrace_traceme\.yml +not held as "
            r"declared: built to break ptrace_traceme\.a0, but graded all rejected$")
        self.assertEqual(self.negatives(report)["ptrace_traceme.yml"]["status"], "BROKEN")
        self.assertEqual(self.negatives(report)["afxdp_socket.yml"]["status"], "live")

    def test_rejects_vacuous_mutant_of_a_skipped_rule(self):
        """A control that left no record is BROKEN on every host, also when the
        emulation of its rule is SKIPPED: nothing shows that the kernel rejected a
        call of it."""
        result = self.canned_run("--missing", self.PTRACE_ATOMIC, "--vacuous", self.PTRACE)
        self.skipped_and_broken(
            result, "ptrace_traceme.yml",
            r"^  \[BROKEN\] ptrace_attach_child\.c -> ptrace_traceme\.yml +vacuous: the control "
            r"made no audited syscall$")

    def test_rejects_mutant_of_a_skipped_rule_that_fires_the_rule(self):
        """A control on which its rule fires is BROKEN on every host, also when the
        emulation of the rule is SKIPPED."""
        result = self.canned_run("--missing", self.PTRACE_ATOMIC, "--fires", self.PTRACE)
        self.skipped_and_broken(
            result, "ptrace_traceme.yml",
            r"^  \[BROKEN\] ptrace_attach_child\.c -> ptrace_traceme\.yml +passed: the a0 "
            r"\(PTRACE_TRACEME\) argument constraint was not enforced$")

    def test_rejects_mutant_of_a_skipped_rule_that_made_no_call_of_the_rule(self):
        """The exemption needs a call that the kernel rejected. The emulation of
        afxdp_socket.yml is SKIPPED (no AF_XDP). The mutant of that rule opens only an
        AF_NETLINK socket, which needs no AF_XDP; here it does not make that call, and
        its one call is accepted. The missing feature does not explain that, so the
        mutant is BROKEN. (At commit 95e3ddc it was N/A, and the run passed.)"""
        report = self.offline.out("skipped-not-refused.json")
        result = self.canned_run("--missing", self.AFXDP_ATOMIC, "--distant", self.AFXDP,
                                 report=report)
        row = self.control_row(report, self.AFXDP)
        self.assertEqual((row["kind"], row["graded"], row["refused"]), ("distant", [], []))
        self.skipped_and_broken(
            result, "afxdp_socket.yml",
            r"^  \[BROKEN\] afxdp_netlink_socket\.c -> afxdp_socket\.yml +not held as declared: "
            r"built to break afxdp_socket\.a0, but graded distant$")
        self.assert_saw(result, r"^ +the emulation of this rule was SKIPPED, but that does not "
                                r"explain the grade: ")
        self.assertEqual(self.negatives(report)["afxdp_socket.yml"]["status"], "BROKEN")

    def test_rejects_mutant_of_a_skipped_rule_with_an_accepted_call_of_the_rule(self):
        """The exemption needs that the kernel rejected EVERY call of the mutant that
        the rule reads. The emulation of dirtyfrag_xfrm_unshare_netlink.yml is SKIPPED
        (no NETLINK_XFRM). The kernel rejects the unshare call of the rule's mutant
        and accepts its NETLINK_ROUTE socket call: the mutant is not held as declared,
        and not because of the missing feature. It is BROKEN."""
        dirtyfrag = "detections/controls/dirtyfrag_netlink_route_socket.c"
        report = self.offline.out("skipped-partly-refused.json")
        result = self.canned_run("--missing", "atomics/T1068/src/dirtyfrag_xfrm_behavioral.c",
                                 "--refused", dirtyfrag, "unshare", report=report)
        # The validator read the planted records: a rejected unshare, an accepted socket.
        row = self.control_row(report, dirtyfrag)
        self.assertEqual(row["refused"], [])
        self.assertRegex(row["explanation"][0], r"\(rejected syscalls not graded: unshare: "
                                                r"EPERM\)$")
        self.assertRegex("\n".join(row["verdict"]), r"(?m)^ +yes +syscall +syscall='socket'$")
        self.skipped_and_broken(
            result, "dirtyfrag_xfrm_unshare_netlink.yml",
            r"^  \[BROKEN\] dirtyfrag_netlink_route_socket\.c -> "
            r"dirtyfrag_xfrm_unshare_netlink\.yml +not held as declared: built to break "
            r"base:dirtyfrag_xfrm_netlink_xfrm_socket/netlink_xfrm_socket\.a2, but graded ")

    def test_control_rerun_uses_an_emulation_that_passed(self):
        """CONTROL. afpacket_raw_socket.yml has two emulations. The first is SKIPPED
        and the second passes: the rule is proven on this host, so its re-run under
        an allowlisted name runs, with the emulation that passed, and the rule has a
        live negative control. (At commit 95e3ddc the first emulation alone decided:
        the re-run did not run, and the rule ended as not applicable. The two
        emulations have the same kernel-feature probe in MANIFEST; the driver gives
        the canned probe to the first one only.)"""
        atomics = in_source(self.offline, self.GATE, r'"(atomics/[^"]+\.c)"')
        self.assertEqual(self.offline.read(self.GATE).count(
            '"detections/sigma/T1040/afpacket_raw_socket.yml"'), 2)
        report = self.offline.out("second-emulation.json")
        result = self.canned_run("--missing", self.AFPACKET_FIRST, report=report)
        self.assert_accepts(result, self.SUMMARY.format(passed=len(atomics) - 1, skipped=1,
                                                        broken=0))
        with open(report, encoding="utf-8") as fh:
            results = [(row["atomic"], row["status"]) for row in json.load(fh)["results"]
                       if row["rule"].endswith("/afpacket_raw_socket.yml")]
        self.assertEqual(results, [(self.AFPACKET_FIRST, "SKIP"), (self.AFPACKET_SECOND, "PASS")])
        rerun = self.control_row(report, self.AFPACKET_SECOND + " as tcpdump")
        self.assertEqual((rerun["status"], rerun["live"], rerun["graded"]),
                         ("held", True, ["sniffer_processes.comm"]))
        self.assertNotRegex(result.stdout, re.compile(r"^  \[ N/A  \] ", re.MULTILINE))
        self.assertEqual(self.negatives(report)["afpacket_raw_socket.yml"],
                         {"rule": "detections/sigma/T1040/afpacket_raw_socket.yml",
                          "status": "live", "live": [rerun["control"]]})

    def test_rejects_refused_rerun_of_a_rule_with_one_skipped_emulation(self):
        """A rule is skipped only when EVERY emulation of it is SKIPPED. The first
        emulation of afpacket_raw_socket.yml is SKIPPED and the second passes, and the
        kernel rejects the socket call of the re-run as `tcpdump`. The rule is proven
        on this host, so the exemption does not apply: the re-run is BROKEN."""
        report = self.offline.out("second-emulation-refused.json")
        result = self.canned_run("--missing", self.AFPACKET_FIRST, "--refused",
                                 self.AFPACKET_SECOND + " as tcpdump", report=report)
        self.assert_saw(result, r"^  \[ PASS \] afpacket_raw_socket\.yml ")
        rerun = self.control_row(report, self.AFPACKET_SECOND + " as tcpdump")
        self.assertEqual(rerun["refused"], ["socket: EPERM"])
        self.skipped_and_broken(
            result, "afpacket_raw_socket.yml",
            r"^  \[BROKEN\] afpacket_mmap_ring_behavioral\.c as 'tcpdump' -> "
            r"afpacket_raw_socket\.yml +not held as declared: built to break "
            r"sniffer_processes\.comm, but graded all rejected$")
        self.assertEqual(self.negatives(report)["afpacket_raw_socket.yml"]["status"], "BROKEN")

    # control_row() with one control that no item of its rule holds (grade []), and
    # the declaration that the test gives. Prints the status, the detail and `live`.
    CONTROL_ROW = (
        "import json, sys\n"
        "sys.path.insert(0, 'detections')\n"
        "import validate_detections as v\n"
        "info = {'control': 'c -> r', 'rule': 'r', 'judge': 'FAIL', 'graded': json.loads("
        "sys.argv[2]), 'expected': json.loads(sys.argv[1]), 'kind': 'distant', 'grade': "
        "'distant', 'verdict': [], 'explanation': []}\n"
        "row = v.control_row('c -> r', 'no hit', 'meaning', info, set())\n"
        "print(json.dumps([row[0], row[2], info['live']]))\n")

    def test_control_row_never_holds_a_control_that_declares_nothing(self):
        """The second barrier against an empty declaration. The check of the CONTROLS
        table refuses such a row before a stimulus runs, so no run of the validator
        reaches control_row() with it; the test calls the function. A control that no
        item of its rule holds has the grade [], which is equal to an empty
        declaration: the function must say BROKEN, not `held`."""
        def row(expected, graded):
            result = self.offline.run_python(self.CONTROL_ROW, json.dumps(expected),
                                             json.dumps(graded))
            self.assertEqual((result.returncode, result.stderr), (0, ""), result.describe())
            return json.loads(result.stdout)

        # CONTROL of the snippet: a declaration that is equal to the grade is held.
        self.assertEqual(row(["x.a0"], ["x.a0"]), ["held", "no hit", True])
        self.assertEqual(row(["x.a0"], [])[0], "BROKEN")
        self.assertEqual(row([], []), ["BROKEN", "declares nothing: a built control must "
                                                 "declare what holds it", False])

    # refused_calls() on the records of one process tree (pid 10 and its child 11),
    # for a rule that reads `ptrace`. Each record is [syscall, pid, accepted].
    REFUSED_CALLS = (
        "import json, sys\n"
        "sys.path.insert(0, 'detections')\n"
        "import validate_detections as v\n"
        "events = [{'syscall': name, 'pid': pid, 'ppid': pid - 1, 'success': 'yes' if ok else "
        "'no', 'exit': '0' if ok else '-1'} for name, pid, ok in json.loads(sys.argv[1])]\n"
        "print(json.dumps(v.refused_calls({'ptrace'}, events, v.process_tree(10, events))))\n")

    def test_exemption_reads_only_the_calls_of_the_rule(self):
        """The exemption for a skipped rule asks one question of a mutant: did the
        kernel reject EVERY call that the mutant made and that the rule reads, and did
        the mutant make one? No canned control makes an audited call that its rule
        does not read, so the driver cannot plant that state; the test calls
        refused_calls(). An accepted call of another syscall does not change the
        answer; an accepted call of the rule, or no call of the rule, gives `no`."""
        def refused(*records):
            result = self.offline.run_python(self.REFUSED_CALLS, json.dumps(records))
            self.assertEqual((result.returncode, result.stderr), (0, ""), result.describe())
            return json.loads(result.stdout)

        self.assertEqual(refused(["ptrace", 10, False]), ["ptrace: EPERM"])
        # An accepted ioctl, which the rule does not read, in the same tree.
        self.assertEqual(refused(["ptrace", 10, False], ["ioctl", 10, True]), ["ptrace: EPERM"])
        # One call of the rule is accepted (in a child of the stimulus): no.
        self.assertEqual(refused(["ptrace", 10, False], ["ptrace", 11, True]), [])
        # No call of the rule at all: no. A rejected call of another process: no.
        self.assertEqual(refused(["ioctl", 10, False]), [])
        self.assertEqual(refused(["ptrace", 500, False], ["ioctl", 10, True]), [])

    def test_rejects_controls_row_for_a_rule_that_is_not_in_manifest_before_a_stimulus(self):
        """The CONTROLS table is checked in the real mode too, before the first
        stimulus runs. The planted MANIFEST has no entry for afxdp_socket.yml, and the
        CONTROLS row of that rule stays. (At commit 95e3ddc the validator ran that
        control, printed `held`, and gave the rule no entry in `negatives`.)"""
        tree = self.tree()
        tree.plant("validators/linux_offline_run_py.txt", self.DRIVER)
        without_the_manifest_entry(self, tree, self.GATE)
        result = tree.run(self.DRIVER, "--require-audit")
        self.assert_rejects(
            result,
            r"^  \[ERROR \] CONTROLS row \d+ \(afxdp_netlink_socket\.c -> afxdp_socket\.yml\)  "
            r"its rule 'detections/sigma/T1040/afxdp_socket\.yml' is not a rule of MANIFEST: ",
            exit_code=1)
        self.assert_saw(result, r"^ERROR: the CONTROLS table of validate_detections\.py has "
                                r"1 fault\(s\); nothing was compiled and no stimulus ran\.$")
        # No stimulus ran: no probe line, no detection row and no control row.
        for line in ("Kernel-feature probes", "Detections (", "[ PASS ]", "Controls (",
                     "[ held ]", "control(s) broken"):
            self.assertNotIn(line, result.stdout)


class K8sValidator(gatelib.GateCase):
    """detections/validate_k8s_detections.py (TRR9002, detections/sigma/T1609/).

    --dry-run is the offline command of AGENTS.md; no workflow runs it, and a live
    run does the same compile step first. The negative control is the step of the
    validate job (validate-k8s-detections.yml) that reads the audit log captured
    before the emulation; the tests run that step, with a log at /tmp/ built from
    the cases of the rule sidecar."""

    GATE = "detections/validate_k8s_detections.py"
    PARTS = gatelib.DETECTIONS
    RULE = "detections/sigma/T1609/k8s_pod_exec_attach.yml"
    CASES = "detections/sigma/T1609/k8s_pod_exec_attach.cases.jsonl"
    LOG = "pre-emulation-audit.log"
    BENIGN = ("pod-logs-read", "pod-get-describe")      # near-misses: no rule fires

    def negative_control_step(self):
        return gatelib.ci_step("validate-k8s-detections.yml", "validate", "--expect-miss")

    def test_control_dry_run_compiles_every_rule(self):
        """CONTROL: the dry run compiles the rules of MANIFEST."""
        good = self.good()
        rules = set(in_source(good, self.GATE, r'^    \("(k8s_\w+\.yml)", "'))
        self.assertIn(os.path.basename(self.RULE), rules)
        self.assert_documented(f"python3 {self.GATE} --dry-run")
        result = good.run(self.GATE, "--dry-run")
        self.assert_accepts(result, rf"^Dry run OK: {len(rules)} rule\(s\) compile with "
                                    r"pySigma\.$")
        self.assert_saw(result, r"^OK \(compile\)  k8s_pod_exec_attach\.yml  ")

    def test_rejects_rule_whose_condition_names_no_selection(self):
        """A rule that does not compile can match nothing. The condition gets a
        `not filter_missing`, and the rule defines no selection of that name."""
        tree = self.tree()
        tree.replace(self.RULE, "condition: select_exec_attach",
                     "condition: select_exec_attach and not filter_missing")
        result = tree.run(self.GATE, "--dry-run")
        self.assert_rejects(
            result,
            r"^ERROR compile k8s_pod_exec_attach\.yml: Detection 'filter_missing' not defined "
            r"in detections$",
            exit_code=1)
        # The count is not asserted: the folder loop compiles a MANIFEST rule again.
        self.assert_saw(result, r"^Dry run FAILED: \d+ compile error\(s\)\.$")

    def test_ci_runs_the_negative_control_on_the_pre_emulation_log(self):
        self.assert_ci_runs(self.GATE, "--audit-log /tmp/pre-emulation-audit.log",
                            "--expect-miss")

    def test_control_negative_control_holds_on_a_benign_log(self):
        """CONTROL of the negative control: a log with records, none from the
        emulation. The proof is the number of records that the gate loaded."""
        good = self.good()
        count = write_log(good, self.LOG, self.CASES, *self.BENIGN)
        result = good.run_step(self.negative_control_step())
        self.assert_accepts(result, r"^Negative control held: no procedure gate matches "
                                    r"without the emulation\.$")
        self.assert_saw(result, rf"^Loaded {count} audit event\(s\) from ")

    def test_rejects_pre_emulation_log_that_holds_an_emulation_record(self):
        """Definition of done 2 for Kubernetes. The log captured before the emulation
        already holds an exec into the target pod: a rule passes without the
        emulation, so a pass after it proves nothing."""
        good = self.good()
        write_log(good, self.LOG, self.CASES, *self.BENIGN, "exec-websocket-get-procA")
        result = good.run_step(self.negative_control_step())
        self.assert_rejects(
            result,
            r"^PASS  \[A/B/C\] k8s_pod_exec_attach\.yml: 1 emulation event\(s\) match$[\s\S]*"
            r"^NEGATIVE CONTROL FAILED: 1 rule\(s\) passed on a log captured before the "
            r"emulation ran \(a procedure gate matched\)\.$",
            exit_code=1)

    @gatelib.known_gap(
        "k8s-negative-control-empty-log",
        gate="detections/validate_k8s_detections.py --expect-miss",
        reason="The negative control holds on an empty pre-emulation audit log (`Loaded 0 "
               "audit event(s)`): no rule can match a log without records, so the control "
               "proves nothing, and the step passes.",
        closes="R2c")
    def test_gap_negative_control_on_an_empty_log(self):
        """WANTED: a negative control that read no record fails as vacuous. The
        capture step always creates the file (a shell redirect), so an empty file
        is what a capture that recorded nothing leaves."""
        good = self.good()
        # The artifact is bad: the log of the negative control holds no record.
        self.assertEqual(write_log(good, self.LOG), 0)
        result = good.run_step(self.negative_control_step())
        # The gate read that log (the line is printed before any verdict).
        self.assert_saw(result, r"^Loaded 0 audit event\(s\) from ")
        self.assert_rejects(
            result,
            r"(?i)^\s*(NEGATIVE CONTROL FAILED|CONTROL FAILED|FAILED|ERROR)\b.*\b(empty|vacuous|"
            r"proves nothing|(no|0) (audit )?(event|record))")


class StaticPodValidator(gatelib.GateCase):
    """detections/validate_staticpod_detections.py (TRR9003, sigma/T1543.005/).

    --dry-run, and the negative-control step of validate-staticpod-detections.yml
    on three logs captured before the emulation (audit, CRI sensor, file sensor)."""

    GATE = "detections/validate_staticpod_detections.py"
    PARTS = gatelib.DETECTIONS
    FOLDER = "detections/sigma/T1543.005/"
    RULE = FOLDER + "k8s_static_pod_mirror_create.yml"
    AUDIT, CRI, FILE = "pre-emulation-audit.log", "pre-emulation-cri.jsonl", \
        "pre-emulation-file.jsonl"

    def negative_control_step(self):
        return gatelib.ci_step("validate-staticpod-detections.yml", "validate", "--expect-miss")

    def write_logs(self, tree, audit=True, cri=True):
        """Benign logs for the three sensors, from the sidecars of the three rules:
        records of the API server, an API-scheduled sandbox and a kubeadm manifest
        write (the two records that the false-positive controls need). audit=False
        or cri=False leaves that log empty. Returns the three record counts."""
        return (
            write_log(tree, self.AUDIT, *((self.FOLDER + "k8s_static_pod_mirror_create.cases.jsonl",
                                          "user-creates-pod", "scheduler-binding")
                                         if audit else ())),
            write_log(tree, self.CRI, *((self.FOLDER + "k8s_cri_static_pod_start.cases.jsonl",
                                        "api-scheduled-target-pod", "coredns-deployment-pod")
                                       if cri else ())),
            write_log(tree, self.FILE, self.FOLDER + "linux_static_pod_manifest_write.cases.jsonl",
                      "kubeadm-bootstrap-manifest", "writes-pki-not-manifests"))

    def test_control_dry_run_compiles_every_rule(self):
        """CONTROL: the dry run compiles the match-gated rules of MANIFEST."""
        good = self.good()
        rules = set(in_source(good, self.GATE, r'^    \("(\w+\.yml)", "(?:cri|audit|file)", '))
        self.assertIn(os.path.basename(self.RULE), rules)
        self.assert_documented(f"python3 {self.GATE} --dry-run")
        result = good.run(self.GATE, "--dry-run")
        self.assert_accepts(result, rf"^Dry run OK: {len(rules)} match-gated rule\(s\) compile "
                                    r"with pySigma\.$")
        self.assert_saw(result, r"^OK \(compile\)  k8s_static_pod_mirror_create\.yml  ")

    def test_rejects_rule_that_is_not_yaml(self):
        """The `detection:` key of a rule gets a flow sequence that never closes: the
        file is not YAML, so no backend can read the rule."""
        tree = self.tree()
        tree.replace(self.RULE, "\ndetection:\n", "\ndetection: [unclosed\n")
        result = tree.run(self.GATE, "--dry-run")
        self.assert_rejects(
            result,
            r"^ERROR compile k8s_static_pod_mirror_create\.yml: while parsing a flow sequence$",
            exit_code=1)
        self.assert_saw(result, r"^Dry run FAILED: \d+ compile error\(s\)\.$")

    def test_ci_runs_the_negative_control_on_the_three_pre_emulation_logs(self):
        self.assert_ci_runs(self.GATE, "--audit-log /tmp/pre-emulation-audit.log",
                            "--cri-log /tmp/pre-emulation-cri.jsonl",
                            "--file-log /tmp/pre-emulation-file.jsonl", "--expect-miss")

    def test_control_negative_control_holds_on_benign_logs(self):
        """CONTROL of the negative control: three logs with records, none from the
        emulation, and the records that the two false-positive controls need."""
        good = self.good()
        audit, cri, files = self.write_logs(good)
        result = good.run_step(self.negative_control_step())
        self.assert_accepts(result, r"^Negative control held: the baseline alone does not pass "
                                    r"any rule\.$")
        self.assert_saw(result, rf"^Loaded {audit} audit event\(s\) from ")
        self.assert_saw(result, rf"^Loaded {cri} pod sandbox\(es\) from ")
        self.assert_saw(result, rf"^Loaded {files} file event\(s\) from ")
        self.assert_saw(result, r"^  control held: the CRI rule matched none of the \d+ "
                                r"API-scheduled sandbox\(es\)\.$")

    def test_rejects_negative_control_on_an_empty_cri_log(self):
        """A CRI log without one API-scheduled sandbox gives the false-positive
        control nothing to test: this validator fails it as vacuous. (The other two
        Kubernetes validators have no such check: see their known gaps.)"""
        good = self.good()
        self.write_logs(good, cri=False)
        result = good.run_step(self.negative_control_step())
        self.assert_rejects(
            result,
            r"^  CONTROL FAILED: no API-scheduled sandbox \(config\.source=api\) in the CRI "
            r"log, so the false-positive control proves nothing",
            exit_code=1)
        self.assert_saw(result, r"^FAILED: 1 control\(s\) failed\.$")

    @gatelib.known_gap(
        "staticpod-negative-control-empty-audit-log",
        gate="detections/validate_staticpod_detections.py --expect-miss",
        reason="The negative control holds when the pre-emulation audit log is empty "
               "(`Loaded 0 audit event(s)`): the validator fails an empty CRI log and a "
               "file log without a kubeadm write as vacuous, but it has no such check "
               "for the audit log.",
        closes="R2c")
    def test_gap_negative_control_on_an_empty_audit_log(self):
        """WANTED: an audit log without records fails the negative control, as an
        empty CRI log does."""
        good = self.good()
        # The artifact is bad: the audit log holds no record. The other two logs
        # hold the records of the control, so this is the one defect.
        audit, cri, files = self.write_logs(good, audit=False)
        self.assertEqual(audit, 0)
        self.assertGreater(min(cri, files), 0)
        result = good.run_step(self.negative_control_step())
        # The gate read the three logs (the lines are printed before any verdict).
        self.assert_saw(result, r"^Loaded 0 audit event\(s\) from ")
        self.assert_saw(result, rf"^Loaded {cri} pod sandbox\(es\) from ")
        self.assert_saw(result, rf"^Loaded {files} file event\(s\) from ")
        self.assert_rejects(
            result,
            r"(?i)^\s*(NEGATIVE CONTROL FAILED|CONTROL FAILED|FAILED|ERROR)\b.*(\baudit\b.*"
            r"(empty|vacuous|proves nothing|no (event|record))|(no|0) audit (event|record))")


class ApiserverValidator(gatelib.GateCase):
    """detections/validate_apiserver_detections.py (TRR9004 and later).

    --dry-run, and the negative-control step of the validate job of
    validate-apiserver-detections.yml on the three pre-emulation logs."""

    GATE = "detections/validate_apiserver_detections.py"
    PARTS = gatelib.DETECTIONS
    RULE = "detections/sigma/T1098.006/k8s_rbac_write.yml"
    AUDIT, CRI, FILE = "pre-emulation-audit.log", "pre-emulation-cri.jsonl", \
        "pre-emulation-file.jsonl"

    def negative_control_step(self):
        return gatelib.ci_step("validate-apiserver-detections.yml", "validate", "--expect-miss")

    def write_logs(self, tree, *more_audit_cases, empty=False):
        """Benign logs for the three sensors, from rule sidecars: RBAC reads for the
        audit log (and the cases of `more_audit_cases`), sandboxes that are not Job
        pods, and file reads that are not a token read by another process.
        empty=True writes three empty files. Returns the three record counts."""
        if empty:
            return tuple(write_log(tree, name) for name in (self.AUDIT, self.CRI, self.FILE))
        return (
            write_log(tree, self.AUDIT, "detections/sigma/T1098.006/k8s_rbac_write.cases.jsonl",
                      "crb-get-recon", "selfsubjectaccessreview-can-i", *more_audit_cases),
            write_log(tree, self.CRI, "detections/sigma/T1053.007/k8s_cri_job_pod.cases.jsonl",
                      "deployment-pod", "static-pod-no-job-label"),
            write_log(tree, self.FILE,
                      "detections/sigma/T1552.007/linux_k8s_sa_token_read.cases.jsonl",
                      "reads-ca-crt-not-token", "kubelet-writes-projected-token"))

    def test_control_dry_run_compiles_every_rule(self):
        """CONTROL: the dry run compiles every rule of MANIFEST and MISS_MANIFEST."""
        good = self.good()
        rules = set(in_source(good, self.GATE, r'^    \("(T[\d.]+)", "(\w+\.yml)", "'))
        self.assertIn(("T1098.006", "k8s_rbac_write.yml"), rules)
        self.assert_documented(f"python3 {self.GATE} --dry-run")
        result = good.run(self.GATE, "--dry-run")
        self.assert_accepts(result, rf"^Dry run OK: {len(rules)} match-gated rule\(s\) compile "
                                    r"with pySigma\.$")
        self.assert_saw(result, r"^OK \(compile\)  T1098\.006/k8s_rbac_write\.yml  ")

    def test_rejects_rule_file_with_two_rules(self):
        """A second rule document is appended to a rule file (a copy of the first).
        A rule file holds one rule: the validators run one query for each file, so
        the second rule would never be evaluated."""
        tree = self.tree()
        tree.append(self.RULE, "---\n" + tree.read(self.RULE))
        result = tree.run(self.GATE, "--dry-run")
        self.assert_rejects(
            result,
            r"^ERROR compile T1098\.006/k8s_rbac_write\.yml: expected one query from "
            r".*k8s_rbac_write\.yml, got 2$",
            exit_code=1)
        self.assert_saw(result, r"^Dry run FAILED: \d+ compile, EXPECTED_MISS or POLICY_GATES "
                                r"error\(s\)\.$")

    def test_ci_runs_the_negative_control_on_the_three_pre_emulation_logs(self):
        self.assert_ci_runs(self.GATE, "--audit-log /tmp/pre-emulation-audit.log",
                            "--cri-log /tmp/pre-emulation-cri.jsonl",
                            "--file-log /tmp/pre-emulation-file.jsonl", "--expect-miss")

    def test_control_negative_control_holds_on_benign_logs(self):
        """CONTROL of the negative control: three logs with records, none from the
        emulation."""
        good = self.good()
        audit, cri, files = self.write_logs(good)
        result = good.run_step(self.negative_control_step())
        self.assert_accepts(result, r"^Negative control held: the baseline alone does not pass "
                                    r"any rule\.$")
        self.assert_saw(result, rf"^Loaded {audit} audit event\(s\) from ")
        self.assert_saw(result, rf"^Loaded {cri} pod sandbox\(es\) from ")
        self.assert_saw(result, rf"^Loaded {files} file event\(s\) from ")

    def test_rejects_pre_emulation_log_that_holds_an_emulation_record(self):
        """Definition of done 2 for Kubernetes. The audit log captured before the
        emulation already holds the ClusterRoleBinding create of Procedure A."""
        good = self.good()
        self.write_logs(good, "crb-create-view-procA")
        result = good.run_step(self.negative_control_step())
        self.assert_rejects(
            result,
            r"^PASS  \[9004 A-E,G\] k8s_rbac_write\.yml: 1 emulation record\(s\) match$[\s\S]*"
            r"^NEGATIVE CONTROL FAILED: 1 rule\(s\) passed on logs captured before the "
            r"emulation ran\.$",
            exit_code=1)

    @gatelib.known_gap(
        "apiserver-negative-control-empty-logs",
        gate="detections/validate_apiserver_detections.py --expect-miss",
        reason="The negative control holds when the three pre-emulation logs are empty "
               "files (`Loaded 0 audit event(s)`, 0 sandboxes, 0 file events): no rule can "
               "match, so the control proves nothing, and the step passes.",
        closes="R2c")
    def test_gap_negative_control_on_empty_logs(self):
        """WANTED: a negative control that read no record fails as vacuous (variant of
        k8s-negative-control-empty-log, with the CRI and file logs empty too)."""
        good = self.good()
        # The artifact is bad: no log of the negative control holds a record.
        self.assertEqual(self.write_logs(good, empty=True), (0, 0, 0))
        result = good.run_step(self.negative_control_step())
        # The gate read the three logs (the lines are printed before any verdict).
        self.assert_saw(result, r"^Loaded 0 audit event\(s\) from ")
        self.assert_saw(result, r"^Loaded 0 pod sandbox\(es\) from ")
        self.assert_saw(result, r"^Loaded 0 file event\(s\) from ")
        self.assert_rejects(
            result,
            r"(?i)^\s*(NEGATIVE CONTROL FAILED|CONTROL FAILED|FAILED|ERROR)\b.*\b(empty|vacuous|"
            r"proves nothing|(no|0) (audit )?(event|record))")


class TrrLint(gatelib.GateCase):
    """.github/scripts/trr_lint.py, and the `Lint TRRs` step of lint-trr.yml."""

    GATE = ".github/scripts/trr_lint.py"
    PARTS = (".github", "research")
    REPORT = "research/trr9012/aws/README.md"

    def step(self):
        return gatelib.ci_step("lint-trr.yml", "trr-lint", self.GATE)

    def reports(self, tree):
        reports = tree.glob("research/trr*/*/README.md")
        self.assertIn(self.REPORT, reports)
        return reports

    def without_a_required_section(self):
        """A copy in which one report has no `## Technical Background` section (the
        heading is renamed `## Background`): the TRR format requires that section."""
        tree = self.tree()
        tree.replace(self.REPORT, "\n## Technical Background\n", "\n## Background\n")
        return tree

    def test_ci_runs_the_lint_without_arguments(self):
        self.assertEqual(gatelib.ci_commands(self.GATE),
                         ["python3 .github/scripts/trr_lint.py | tee /tmp/trr-lint.out"])

    def test_control_good_tree_is_accepted(self):
        """CONTROL: every report of the copy conforms. With no report the lint
        exits 0 too, so the proof is the number of reports."""
        good = self.good()
        self.assert_accepts(
            good.run(self.GATE),
            rf"^TRR lint passed: {len(self.reports(good))} report\(s\) conform\.$")

    def test_rejects_report_without_a_required_section(self):
        tree = self.without_a_required_section()
        result = tree.run(self.GATE)
        self.assert_rejects(
            result,
            r"^FAIL  research/trr9012/aws/README\.md  \(1 issue\(s\)\)\n"
            r"    - missing required section: ## Technical Background$",
            exit_code=1)
        self.assertIn(f"\nTRR lint failed: 1 issue(s) across {len(self.reports(tree))} "
                      "report(s).\n", result.stdout)

    def test_control_ci_step_passes_on_the_good_tree(self):
        """CONTROL of the workflow step: the good copy through the `Lint TRRs` step."""
        good = self.good()
        self.assert_accepts(
            good.run_step(self.step()),
            rf"^TRR lint passed: {len(self.reports(good))} report\(s\) conform\.$")

    def test_ci_step_fails_when_the_lint_fails(self):
        """The step pipes the lint into `tee`. Run it as GitHub Actions does: the exit
        code of the lint must reach the step. The step sets `shell: bash`, which
        enables pipefail; without it the step takes the exit code of `tee`, and a
        failed lint leaves the job green. (This was the known gap
        trr-ci-exit-code-masked until the step got `shell: bash`.)"""
        tree = self.without_a_required_section()
        result = tree.run_step(self.step())
        # The lint ran in the step and named the planted defect.
        self.assert_saw(result, r"^    - missing required section: ## Technical Background$")
        self.assert_rejects(result, r"^TRR lint failed: 1 issue\(s\) across \d+ report\(s\)\.$",
                            exit_code=1)


class MarkdownLinks(gatelib.GateCase):
    """.github/scripts/check_md_links.py: every relative link of every .md file of
    the checkout names a file or a directory that exists."""

    GATE = ".github/scripts/check_md_links.py"
    PARTS = gatelib.ALL             # the gate walks the whole checkout
    PAGE = "docs/planted.md"

    def links(self, result):
        """The number of relative links that the gate checked on a tree it accepts."""
        self.assert_accepts(result, r"^OK: \d+ relative links across the repo all resolve\.$")
        return int(re.search(r"^OK: (\d+) relative links", result.stdout, re.MULTILINE).group(1))

    def test_ci_runs_the_gate_without_arguments(self):
        self.assertEqual(gatelib.ci_commands(self.GATE),
                         ["python3 .github/scripts/check_md_links.py"])

    def test_control_good_tree_is_accepted_and_a_new_page_is_read(self):
        """CONTROL: the good copy passes, and one more page with one link that
        resolves makes the count one higher: the gate reads a page at this path."""
        good = self.good()
        self.assertFalse(good.exists(self.PAGE))
        before = self.links(good.run(self.GATE))
        self.assertGreater(before, len(good.glob("**/README.md")))  # several links a page
        tree = self.tree()
        tree.write(self.PAGE, "# Planted page\n\nSee [the agent guide](../AGENTS.md).\n")
        self.assertEqual(self.links(tree.run(self.GATE)), before + 1)

    def test_rejects_link_to_a_file_that_does_not_exist(self):
        tree = self.tree()
        tree.plant("validators/broken_link.md.txt", self.PAGE)
        result = tree.run(self.GATE)
        self.assert_rejects(
            result,
            r"^Broken relative links \(1\):\n\n"
            r"  docs/planted\.md\n"
            r"      link:    \]\(no-such-file\.md\)\n"
            r"      missing: docs/no-such-file\.md$",
            exit_code=1)
        self.assert_saw(result, r"^Checked \d+ relative links; 1 broken\.$")


class SigmaRegexLint(gatelib.GateCase):
    """.github/scripts/check_sigma_regex.py: every `|re` value of the rules stays in
    the regex subset that all the backends read the same way.

    The sigma-lint job passes --require-re2, and google-re2 is not in
    detections/requirements.txt. With the re2 module the tests pass the argument of
    CI; without it they run the default path. One test proves that the argument of
    CI fails closed: it hides the module from the gate, so it runs with and
    without google-re2."""

    GATE = ".github/scripts/check_sigma_regex.py"
    PARTS = (".github", "detections/sigma")
    RULE = "detections/sigma/T1078.004/aws_leaked_access_key_recon.yml"
    RE2 = importlib.util.find_spec("re2") is not None
    ARGS = ("--require-re2",) if RE2 else ()
    ENGINE = r"Python re \+ RE2" if RE2 else r"Python re only \(RE2 not installed\)"

    def test_ci_runs_the_lint_with_require_re2(self):
        self.assert_ci_runs(self.GATE, "--require-re2")

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the default path (detections/sigma/) holds every rule file of the
        copy. A directory without rules passes with `0 rule file(s)`."""
        good = self.good()
        rules = good.glob("detections/sigma/**/*.yml")
        self.assertIn(self.RULE, rules)
        result = good.run(self.GATE, *self.ARGS)
        self.assert_accepts(
            result,
            rf"^check_sigma_regex: OK, \d+ \|re value\(s\) across {len(rules)} rule file\(s\) "
            rf"are portable; compiled with {self.ENGINE}$")
        self.assertNotIn("OK, 0 |re value(s)", result.stdout)

    def test_rejects_inline_flag_in_a_regex(self):
        """The `endswith` filter of a rule is rewritten as a regular expression with
        the inline flag (?i). Not every backend reads an inline flag: the portable
        form is the |re|i sub-modifier."""
        tree = self.tree()
        tree.replace(self.RULE, "sourceIPAddress|endswith: '.amazonaws.com'",
                     r"sourceIPAddress|re: '(?i)\.amazonaws\.com$'")
        result = tree.run(self.GATE, *self.ARGS)
        self.assert_rejects(
            result,
            r"^FAIL detections/sigma/T1078\.004/aws_leaked_access_key_recon\.yml: "
            r"detection\.filter_service_source\.sourceIPAddress\|re: inline flags \(\?i\) ",
            exit_code=1)
        self.assert_saw(result, r"^check_sigma_regex: 1 problem\(s\) in \d+ \|re value\(s\) ")

    def test_rejects_require_re2_without_the_re2_module(self):
        """The argument of CI fails closed when the second engine is missing: the
        lint does not pass on Python `re` alone.

        A module `re2` that cannot be imported is planted beside the gate. Python
        looks in the directory of the script first, so the gate gets an ImportError
        for `import re2`, as on a machine without google-re2, also when the tests'
        Python has the package."""
        tree = self.tree()
        self.assertFalse(tree.exists(".github/scripts/re2.py"))
        tree.write(".github/scripts/re2.py",
                   "raise ImportError('PLANTED by detections/tests: no module named re2')\n")
        result = tree.run(self.GATE, "--require-re2")
        self.assert_rejects(
            result, r"^ERROR: --require-re2 given but the re2 module is missing", exit_code=1)
        self.assertNotIn("check_sigma_regex: OK", result.stdout)
        # CONTROL of the planted module: without the argument of CI the same copy
        # passes on Python `re` alone, so the argument is what rejects.
        self.assert_accepts(
            tree.run(self.GATE),
            r"^check_sigma_regex: OK, \d+ \|re value\(s\) across \d+ rule file\(s\) are "
            r"portable; compiled with Python re only \(RE2 not installed\)$")


class ScheduleFreshness(gatelib.GateCase):
    """.github/scripts/check_schedule_freshness.py: the scheduled workflows still run.

    The check reads the GitHub API. The tests never do: every graded run gets
    --fixtures (recorded answers), --now, --repo and --workflows-dir. The recorded
    answers (known_bad/validators/stale_schedule/) hold one workflow with a weekly
    schedule, whose newest successful scheduled run is of 2026-10-05T06:17:00Z.
    The value of --now is the one thing that differs between control and defect."""

    GATE = ".github/scripts/check_schedule_freshness.py"
    PARTS = (".github",)
    RUN = "2026-10-05T06:17:00Z"        # created_at of the run in answers.json

    def graded(self, tree, now):
        """The check on the recorded answers, with the thresholds of the CI step."""
        tree.plant("validators/stale_schedule", "planted_schedule")
        self.assertIn(self.RUN, tree.read("planted_schedule/answers.json"))
        return tree.run(self.GATE, "--repo", "example/det-eng",
                        "--fixtures", tree.path("planted_schedule/answers.json"),
                        "--workflows-dir", tree.path("planted_schedule/workflows"),
                        "--warn-days", "8", "--fail-days", "15", "--now", now)

    def test_ci_runs_the_self_test_and_the_check_with_these_thresholds(self):
        self.assert_ci_runs(self.GATE, "--self-test")
        step = gatelib.ci_step("detection-quality.yml", "schedule-freshness",
                               'check_schedule_freshness.py "${args[@]}"')
        self.assertIn("args=(--warn-days 8 --fail-days 15 ", step.run)

    def test_control_self_test_passes(self):
        """CONTROL: the grading on the script's own constructed API answers."""
        result = self.good().run(self.GATE, "--self-test")
        self.assert_accepts(result, r"^schedule-freshness self-test: (\d+) of \1 passed$")
        self.assertNotIn("  FAIL  ", result.stdout)
        self.assertGreater(len(re.findall(r"^  PASS  ", result.stdout, re.MULTILINE)), 50)

    def test_control_fresh_run_is_accepted(self):
        """CONTROL: graded one day after the run, the same answers pass."""
        result = self.graded(self.tree(), "2026-10-06T06:17:00Z")
        self.assert_accepts(result, r"^schedule-freshness: 1 checked: 1 ok, 0 warn, 0 fail, "
                                    r"0 error\(s\)$")
        self.assert_saw(result, r"^  OK     weekly-validation\.yml +17 6 \* \* 1 +the newest "
                                r"successful scheduled run: 2026-10-05T06:17:00Z \(1\.00 days ago")

    def test_rejects_newest_successful_run_16_days_old(self):
        """Graded sixteen days after the run: a weekly schedule has missed two runs,
        so the weekly regression of that workflow does not run any more."""
        result = self.graded(self.tree(), "2026-10-21T06:17:00Z")
        self.assert_rejects(
            result,
            r"^  FAIL   weekly-validation\.yml +17 6 \* \* 1 +the newest successful scheduled "
            r"run is more than 15 days old: 2026-10-05T06:17:00Z \(16\.00 days ago",
            exit_code=1)
        self.assert_saw(result, r"^schedule-freshness: 1 checked: 0 ok, 0 warn, 1 fail, "
                                r"0 error\(s\)$")


if __name__ == "__main__":
    unittest.main()
