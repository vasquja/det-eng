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

    def manifest_rules(self, tree):
        """The (folder, rule file) pairs of the gate's MANIFEST, read from its source."""
        return set(in_source(tree, self.GATE, r'^\s+\("TRR\d+", "(T[\d.]+)", "([^"]+\.yml)",'))

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
        tree.write(self.BENIGN, "[]\n")
        # The artifact is bad: the negative control of the rule has no record.
        self.assertEqual(tree.read_json(self.BENIGN), [])
        result = tree.run(self.GATE)
        # The gate read the planted file: it graded no benign record for this rule
        # (the grade line names no kind; it is printed for a PASS and for a FAIL).
        self.assert_saw(result, r"^(?:PASS|FAIL)  \[TRR9012 AWS\] aws_leaked_access_key_recon"
                                r"\.yml: .*\n(?: {8}.*\n)*? {8}benign baseline graded "
                                r"\(informational\): ; atoms exercised 0/\d+$")
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
               "gone). check_sufficiency.py only warns (R2).",
        closes="R2c")
    def test_gap_missing_fixture_is_pending(self):
        """WANTED: a rule of MANIFEST that exists, and whose fixture does not, fails.
        PENDING is for a rule that is not built yet."""
        tree = self.tree()
        rules = self.manifest_rules(tree)
        self.assertIn(tuple(self.RULE.split("/")[-2:]), rules)
        tree.remove(self.BENIGN)
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
            self.assert_saw(result, rf"^All {len(rules) - 1} external-cloud detection\(s\) "
                                    r"fired on their recorded attack fixtures, and every "
                                    r"negative control held\.$")
        self.assert_rejects(
            result,
            r"^(FAIL|ERROR)\s+\[TRR9012[^\]]*\] aws_leaked_access_key_recon\.yml: .*"
            r"(fixture|benign\.json)")


class LinuxValidatorDryRun(gatelib.GateCase):
    """detections/validate_detections.py --dry-run: every rule of MANIFEST and
    CONTROLS compiles with pySigma, and every atomic and control compiles with gcc.

    No workflow runs --dry-run. The validate job (validate-detections.yml) runs the
    real mode, which does the same compile step first and stops on its errors."""

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
    healthy; one argument plants one defect in it."""

    GATE = "detections/validate_detections.py"
    DRIVER = "linux_offline_run.py"
    PARTS = gatelib.DETECTIONS      # the driver compiles nothing: no atomics, no gcc
    NOOP = "detections/controls/noop.c"

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

    def test_control_canned_run_is_accepted(self):
        """CONTROL: every atomic passes on the records of its own process tree, and
        every control holds: the no-op on each rule, each mutant, and each re-run
        under an allowlisted name."""
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
        # another process.
        noop = [row for row in controls if row["control"].startswith("noop -> ")]
        self.assertEqual(len(noop), len(rules))
        self.assertEqual({row["detail"] for row in noop},
                         {"no hit from the stimulus (2 events in window)"})
        # Each mutant and each allowlisted re-run holds for the reason it is built for.
        built = [row for row in controls if row not in noop]
        stimuli = {row["control"].split(" -> ")[0] for row in built}
        for mutant in sorted(mutants):
            self.assertIn(os.path.basename(mutant), stimuli)
        self.assertIn("afinet_raw_socket_behavioral.c as 'ping'", stimuli)
        for row in built:
            self.assertEqual(sorted(row["graded"]), sorted(row["expected"]), row["control"])
            self.assertFalse(row.get("warning"), row["control"])

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

    @gatelib.known_gap(
        "linux-noop-control-vacuous",
        gate="detections/validate_detections.py",
        reason="The no-op control is `held` on every rule when its process tree made no "
               "audited syscall: vacuity is graded only for a control with an `expected` "
               "list (mutants and allowlisted re-runs). The real controls/noop.c makes no "
               "syscall that audit/atomic.rules audits, so on every real run the no-op "
               "rows cannot fail, and detections/README.md says such a control fails the run.",
        closes="R2b")
    def test_gap_noop_control_that_made_no_audited_syscall(self):
        """WANTED: the no-op is graded for vacuity as the mutants are. A no-op whose
        process tree made no audited syscall is a broken control, and the run fails."""
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
