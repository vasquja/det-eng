"""
Gate tests, group `quality`: the gates that judge a rule beyond its own cases
(detection-quality.yml jobs benign-corpus, sufficiency-ratchet (the benign half and
the expected-difference half), null-safety, representation-variants,
provider-mappings, platform-coverage and coverage-report, and the
anchors step of validate-detections.yml job markdown-links).

    score_benign.py           ScoreBenign, BenignRatchet
    check_null_safety.py      NullSafety
    check_variants.py         Variants
    check_provider_mappings.py  ProviderMappings
    k8s_policy_coverage.py    K8sPolicyCoverage
    k8s_platforms_md.py       K8sPlatformsMdCheck (--check), K8sPlatformsMdAnchors (--anchors)
    coverage_report.py        CoverageReport

Planted artifacts: detections/tests/known_bad/quality/. An artifact that is one
changed value of a real file is an edit in the test (tree.replace, tree.edit_json);
the test says what it changes and why that is bad.
How the harness works: gatelib.py and README.md in this directory.

The docstring of each rejection test and known-gap test starts with its case id
(`sb-over-budget`, ...).

The slow gates (15 to 20 s for one run, whatever is planted) start their runs in
setUpClass (cls.in_background(), in cls.good() and in cls.class_tree() copies), so
that the runs of a class overlap.

    python3 -B -m unittest discover -s detections/tests -p 'test_quality.py' -v
"""

import importlib.util
import json
import os
import re
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gatelib  # noqa: E402  (the line above makes it importable with `-t .` too)


# --------------------------------------------------------------------------- helpers

def rule_keys(tree):
    """`T<id>/<file>.yml` of every rule file in the copy, as the gates print a rule."""
    return sorted(rel[len("detections/sigma/"):] for rel in tree.glob("detections/sigma/*/*.yml"))


def k8s_audit_rules(tree, sidecar=False):
    """The Kubernetes audit rules of the copy (logsource product kubernetes, service
    audit), as `T<id>/<file>.yml`. sidecar=True: only those with a cases file."""
    import yaml     # PyYAML: in detections/requirements.txt

    out = []
    for key in rule_keys(tree):
        rel = "detections/sigma/" + key
        docs = [d for d in yaml.safe_load_all(tree.read(rel)) if isinstance(d, dict)]
        logsource = next((d["logsource"] for d in docs if d.get("logsource")), {})
        if logsource.get("product") == "kubernetes" and logsource.get("service") == "audit" \
                and (not sidecar or tree.exists(rel[:-len(".yml")] + ".cases.jsonl")):
            out.append(key)
    return out


def found(result, pattern):
    """re.findall of `pattern` (re.MULTILINE) in the gate's standard output: the lines
    that match, or the text of the pattern's one group."""
    return re.findall(pattern, result.stdout, re.MULTILINE)


def assert_cases_hold(tree, rule):
    """detections/rule_cases.py accepts the planted pair `rule` (`T<id>/<file>.yml`):
    its positive fires and each declared break is the single flip. So the pair has
    the one defect that its test names; rule_cases.py does not see that defect."""
    sidecar = "detections/sigma/" + rule[:-len(".yml")] + ".cases.jsonl"
    cases = len(tree.read_jsonl(sidecar))
    result = tree.run("detections/rule_cases.py", "detections/sigma/" + rule)
    gatelib.assert_accepts(result, r"^All cases hold \(1 rule file\(s\)\)\.$")
    held = found(result, rf"^ok    {re.escape(rule)} :: \S+ +\S+: ")
    if len(held) != cases:
        raise AssertionError(f"rule_cases.py judged {len(held)} of the {cases} case(s) of "
                             f"{sidecar}:\n" + result.describe())


# ---------------------------------------------------------------------- score_benign.py

RAW_SOCKET_RULE = "T1040/afinet_raw_socket.yml"     # a real rule with benign hits and a budget


def broaden_raw_socket_rule(tree):
    """SOCK_DGRAM ('2') is added to the socket types of the real raw-socket rule, so
    the rule also fires on ordinary UDP sockets (the benign corpus has tracepath).
    The rule raises more benign hits, and stays inside its budget of 13 hits."""
    tree.replace("detections/sigma/" + RAW_SOCKET_RULE,
                 "    a1:\n      - '3' ",
                 "    a1:\n      - '2'       # SOCK_DGRAM: PLANTED, not a raw socket\n      - '3' ")


class ScoreBenign(gatelib.GateCase):
    """detections/score_benign.py --check --enforce, as the benign-corpus job runs it:
    scores.json is current, every rule is scored or exempt, and no enforce-mode rule
    is over its budget (definition of done 4)."""

    GATE = "detections/score_benign.py"
    PARTS = gatelib.DETECTIONS      # the gate reads nothing outside detections/
    SCORES = "detections/benign/scores.json"
    BUDGETS = "detections/benign/budgets.json"
    BUDGET_RULE = "T1014/bpf_prog_load.yml"     # has a `documented noise:` budget today

    def run_ci(self, tree):
        return tree.run(self.GATE, "--check", "--enforce", "--markdown", tree.out("summary.md"))

    def test_ci_passes_check_and_enforce(self):
        """Without --enforce an overrun only warns; without --check a stale snapshot
        and an unscored rule pass. The job must pass both."""
        self.assert_ci_runs(self.GATE, "--check", "--enforce")

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the unmodified copy passes, and the gate scored every rule of the
        copy on every slice of the copy."""
        good = self.good()
        rules = rule_keys(good)
        slices = good.glob("detections/benign/slices/**/*.json")
        self.assertGreater(len(rules), 0, "the copy holds no rule: the control is vacuous")
        self.assertGreater(len(slices), 0, "the copy holds no slice: the control is vacuous")
        result = self.run_ci(good)
        self.assert_accepts(result, r"^scores\.json is current\.$")
        self.assertRegex(result.stdout, rf"(?m)^Benign corpus: {len(slices)} slice\(s\), [1-9]")
        scored = found(result, r"^(T\S+\.yml) +\S+ +(?:enforce|shadow) +\d+ +\d+ +[\d.]+ +\d+  "
                               r"(?:ok|over|OVER)\b")
        exempt = found(result, r"^  (T\S+\.yml)  exempt: ")
        self.assertEqual(sorted(scored + exempt), rules,
                         "the gate did not score (or exempt) every rule of the copy")

    def test_rejects_rule_over_budget(self):
        """sb-over-budget. A new rule that matches every `get` of a Kubernetes audit
        log has no budget entry, so the default governs it: enforce at 0 hits. The
        snapshot is regenerated first (as the author of the rule would), so the
        budget is the one reason left."""
        tree = self.tree()
        tree.plant("quality/over_budget/k8s_any_get.yml", "detections/sigma/T9999/k8s_any_get.yml")
        self.assert_accepts(tree.run(self.GATE, "--update", "--examples", "0"),
                            r"^Wrote detections/benign/scores\.json\.$")
        result = self.run_ci(tree)
        self.assert_rejects(
            result,
            r"^FAILED: 1 enforce-mode rule\(s\) over their benign budget: T9999/k8s_any_get\.yml$",
            exit_code=1)
        # The row: enforce mode, some hits, budget 0, OVER.
        self.assertRegex(result.stdout,
                         r"(?m)^T9999/k8s_any_get\.yml +low +enforce +\d+ +[1-9]\d* +[\d.]+ +0  OVER\b")
        # One planted defect, one reason: the snapshot is current, nothing else failed.
        self.assertIn("\nscores.json is current.\n", result.stdout)
        self.assertEqual(len(found(result, r"^(?:FAILED|STALE|ERROR)\b.*$")), 1, result.describe())

    def test_rejects_snapshot_that_is_not_current(self):
        """sb-stale-snapshot (definition of done 4: `scores.json` is current). A rule
        is broadened (see broaden_raw_socket_rule()) and the snapshot is not
        regenerated, so the pull request does not show that the rule raises more
        benign hits. The rule stays inside its budget: the snapshot is the one
        reason."""
        tree = self.tree()
        hits = tree.read_json(self.SCORES)["rules"][RAW_SOCKET_RULE]["hits"]
        budget = tree.read_json(self.BUDGETS)["rules"][RAW_SOCKET_RULE]["max_hits"]
        broaden_raw_socket_rule(tree)
        result = self.run_ci(tree)
        # The difference holds one line, for the one rule, and no `corpus changed:`.
        stale = (r"^STALE: detections/benign/scores\.json does not match the current rules and "
                 rf"corpus:\n  {re.escape(RAW_SOCKET_RULE)}: hits {hits} -> (\d+), rate/10k \S+ -> "
                 r"\S+, actors \d+ -> \d+\nRun `python3 detections/score_benign\.py --update` ")
        self.assert_rejects(result, stale, exit_code=1)
        now = int(re.search(stale, result.stdout, re.MULTILINE).group(1))
        self.assertTrue(hits < now <= budget, "the planted rise must stay inside the budget: "
                        f"{hits} -> {now}, budget {budget}")
        self.assertEqual(len(found(result, r"^(?:FAILED|STALE|ERROR)\b.*$")), 1, result.describe())

    def test_rejects_rule_that_no_slice_scores(self):
        """sb-rule-not-scored. A new rule on a log source that no slice of the benign
        corpus reads has no false-positive evidence. It needs an entry under
        `unscored` in budgets.json, which a human approves; the planted rule has
        none. The snapshot holds only the rules that are scored, so it stays
        current: the rule that is not scored is the one reason."""
        tree = self.tree()
        tree.plant("quality/not_scored/planted_unread_logsource.yml",
                   "detections/sigma/T9999/planted_unread_logsource.yml")
        result = self.run_ci(tree)
        self.assert_rejects(
            result,
            r"^FAILED: 1 rule\(s\) are not scored \(no benign slice reads their logsource\) and "
            r"budgets\.json does not exempt them: T9999/planted_unread_logsource\.yml$",
            exit_code=1)
        self.assertIn("\n  T9999/planted_unread_logsource.yml  NOT EXEMPT (no `unscored` entry in "
                      "budgets.json)\n", result.stdout)
        self.assertIn("\nscores.json is current.\n", result.stdout)
        self.assertEqual(len(found(result, r"^(?:FAILED|STALE|ERROR)\b.*$")), 1, result.describe())

    def plant_unclassed_budget(self, tree):
        """sb-budget-why-no-class: the reason of a real rule's budget is replaced by
        one that names neither class (documented noise, or a defect that
        detections/RULE_DEFECTS.md tracks). Its mode and max_hits stay as they are:
        a raised max_hits is another defect (the known gap below)."""
        def change(doc):
            entry = doc["rules"][self.BUDGET_RULE]
            self.assertTrue(entry["why"].startswith("documented noise:"), entry)
            entry["why"] = "raised so CI is green"
        tree.edit_json(self.BUDGETS, change)

    WHY_NO_CLASS = (r"^  T1014/bpf_prog_load\.yml: why must start 'documented noise:' or 'rule "
                    r"defect, tracked in detections/RULE_DEFECTS\.md <ID>:'$")

    def test_rejects_budget_whose_why_names_no_class(self):
        """sb-budget-why-no-class. A budget needs a classed reason. The gate refuses
        the file before it scores anything."""
        tree = self.tree()
        self.plant_unclassed_budget(tree)
        result = self.run_ci(tree)
        self.assert_rejects(result, self.WHY_NO_CLASS, exit_code=1)
        self.assertEqual(result.stdout.splitlines()[0],
                         "ERROR: budgets.json `rules` entries are malformed:")
        self.assertEqual(len(result.stdout.splitlines()), 2, "one planted entry, one problem line:\n"
                         + result.describe())

    def test_ci_step_fails_when_the_gate_fails(self):
        """The benign-corpus step pipes the gate into `tee`. Run that step as GitHub
        Actions does: the gate's exit code must reach the step."""
        step = gatelib.ci_step("detection-quality.yml", "benign-corpus", self.GATE)
        tree = self.tree()
        self.plant_unclassed_budget(tree)
        self.assert_rejects(tree.run_step(step), self.WHY_NO_CLASS, exit_code=1)

    @gatelib.known_gap(
        "sb-budget-raised-as-documented-noise",
        gate="detections/score_benign.py --check --enforce",
        reason="A budget raised from 3 to 300 hits passes when its `why` keeps the prefix "
               "`documented noise:`: the gate checks the form of the reason, and nothing "
               "compares max_hits with the hits that the rule raises or with the base "
               "branch, so the raise needs no defect and no evidence. Every offline gate "
               "accepts the planted tree. Only the merge policy stands behind this gate: "
               "budgets.json is not content, so the pull request needs a human approval.",
        closes="R8")
    def test_gap_budget_raised_as_documented_noise(self):
        """sb-budget-raised-as-documented-noise. WANTED: a budget far above what the
        rule raises (1 hit; at most 3 over the reseeds) is refused, or sent to a
        human, in words that name the rule and its budget."""
        tree = self.tree()

        def change(doc):
            entry = doc["rules"][self.BUDGET_RULE]
            self.assertTrue(entry["why"].startswith("documented noise:"), entry)
            self.assertLess(entry["max_hits"], 300)
            entry["max_hits"] = 300      # the only change: `why` and `mode` stay

        tree.edit_json(self.BUDGETS, change)
        result = self.run_ci(tree)
        # The gate read the planted budget: the rule's row shows it (or a message names it).
        self.assert_saw(result, r"^T1014/bpf_prog_load\.yml +\S+ +enforce +\d+ +\d+ +[\d.]+ +300 "
                                r"|T1014/bpf_prog_load\.yml: .*\b300\b")
        self.assert_rejects(result, r"T1014/bpf_prog_load\.yml.*\b(max_hits|budget)\b")


class BenignRatchet(gatelib.GateCase):
    """The benign half of the sufficiency-ratchet job (pull requests only):
    detections/score_benign.py --examples 0 --baseline-scores <the base branch's
    scores.json>. A rule that raises more benign hits than on the base branch fails
    the job, also inside its budget, so that a human decides."""

    GATE = "detections/score_benign.py"
    PARTS = gatelib.DETECTIONS
    SCORES = "detections/benign/scores.json"
    BUDGETS = "detections/benign/budgets.json"
    KEY = RAW_SOCKET_RULE

    def run_ratchet(self, tree, base):
        return tree.run(self.GATE, "--examples", "0", "--baseline-scores", base)

    def broaden(self, tree):
        """rb-benign-rise-inside-budget: see broaden_raw_socket_rule()."""
        broaden_raw_socket_rule(tree)

    def expected_rise(self, tree):
        """The RISE line for KEY, with the base hits and the budget of the copy."""
        hits = tree.read_json(self.SCORES)["rules"][self.KEY]["hits"]
        budget = tree.read_json(self.BUDGETS)["rules"][self.KEY]["max_hits"]
        return hits, budget, (rf"^  RISE {re.escape(self.KEY)}: hits {hits} -> (\d+) "
                              rf"\(budget {budget}\); new or grown actors: \S")

    def test_ci_runs_the_ratchet_command(self):
        self.assert_ci_runs(self.GATE, "--examples 0", "--baseline-scores")

    def test_control_unchanged_tree_is_accepted(self):
        """CONTROL: the unmodified copy against its own committed snapshot passes, and
        the gate compared every rule of the snapshot."""
        good = self.good()
        compared = len(good.read_json(self.SCORES)["rules"])
        self.assertGreater(compared, 0, "the snapshot holds no rule: the control is vacuous")
        result = self.run_ratchet(good, good.path(self.SCORES))
        self.assert_accepts(result, r"^OK: no rule raises more benign hits than on the base branch "
                                    rf"\({compared} rule\(s\) compared\)\.$")

    def test_rejects_rise_inside_budget(self):
        """rb-benign-rise-inside-budget. The base snapshot is the copy's committed
        scores.json; the head is the copy with the broadened rule (see broaden())."""
        tree = self.tree()
        base = tree.out("base-scores.json")     # the base branch's snapshot: saved before the change
        shutil.copyfile(tree.path(self.SCORES), base)
        hits, budget, rise = self.expected_rise(tree)
        self.broaden(tree)
        result = self.run_ratchet(tree, base)
        self.assert_rejects(result, rise, exit_code=1)
        now = int(re.search(rise, result.stdout, re.MULTILINE).group(1))
        self.assertTrue(hits < now <= budget,
                        "the planted rise must stay inside the budget: "
                        f"{hits} -> {now}, budget {budget}")
        # The budget alone accepts it: the rule's row says `ok`.
        self.assertRegex(result.stdout, rf"(?m)^{re.escape(self.KEY)} +\S+ +enforce +\d+ +{now} "
                                        rf"+[\d.]+ +{budget}  ok\b")
        self.assertIn("\nFAILED: 1 rule(s) raise more benign hits than on the base branch: "
                      f"{self.KEY}\n", result.stdout)

    def test_ci_step_fails_on_a_rise(self):
        """The job's step saves the gate's exit code and ends with `exit "$rc"`. Run the
        step as GitHub Actions does, with a stand-in for the worktree of the base
        commit ($RUNNER_TEMP/base-tree): the rise must fail the step. (The step also
        runs `pip install`; run_step() gives it a `pip` that installs nothing.)"""
        step = gatelib.ci_step("detection-quality.yml", "sufficiency-ratchet", self.GATE)
        tree = self.tree()
        worktree_mark = tree.out("ratchet-runner-temp/base-tree/.git")
        with open(worktree_mark, "w", encoding="utf-8") as fh:
            fh.write("gitdir: (a stand-in: the step only tests that the base tree exists)\n")
        shutil.copyfile(tree.path(self.SCORES),
                        tree.out("ratchet-runner-temp/base-tree/" + self.SCORES))
        _hits, _budget, rise = self.expected_rise(tree)
        self.broaden(tree)
        result = tree.run_step(step, env={
            "RUNNER_TEMP": os.path.dirname(os.path.dirname(worktree_mark))})
        self.assert_rejects(result, rise, exit_code=1)


# ----------------------------------------------------------------- check_null_safety.py

class NullSafety(gatelib.GateCase):
    """detections/check_null_safety.py, as the null-safety job runs it: every rule
    gives the same hits in two-valued logic (the validators' SQLite query) and in
    three-valued logic (ES|QL and other SQL backends), on every sidecar case and
    cloud fixture."""

    GATE = "detections/check_null_safety.py"
    PARTS = gatelib.DETECTIONS
    IMDS = "T1552.005/aws_imds_creds_used_off_instance.yml"     # a cloud rule with fixtures

    def run_ci(self, tree):
        return tree.run(self.GATE, "--markdown", tree.out("summary.md"))

    def test_ci_runs_the_self_test_and_every_rule(self):
        self.assertEqual(gatelib.ci_commands(self.GATE), [
            "python3 detections/check_null_safety.py --self-test",
            'python3 detections/check_null_safety.py --markdown "$GITHUB_STEP_SUMMARY" '
            "| tee /tmp/null-safety.out"])

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the unmodified copy passes; the gate checked every rule of the
        copy, each on one event set or more, and at least every sidecar case."""
        good = self.good()
        rules = rule_keys(good)
        cases = sum(len(good.read_jsonl(rel)) for rel in good.glob("detections/sigma/*/*.cases.jsonl"))
        self.assertGreater(len(rules), 0, "the copy holds no rule: the control is vacuous")
        result = self.run_ci(good)
        self.assert_accepts(result, rf"^OK: {len(rules)} rule\(s\), \d+ event set\(s\): every hit is "
                                    r"the same in two- and three-valued logic\.$")
        checked = found(result, r"^ok    (T\S+\.yml): [1-9]\d* event set\(s\), same hits in two- and "
                                r"three-valued logic$")
        self.assertEqual(sorted(checked), rules)
        sets = int(re.search(r"(?m)^OK: \d+ rule\(s\), (\d+) event set", result.stdout).group(1))
        self.assertGreaterEqual(sets, cases, "fewer event sets than sidecar cases in the copy")

    def test_control_self_test_passes(self):
        """CONTROL of the job's first step (--self-test)."""
        self.assert_accepts(self.good().run(self.GATE, "--self-test"),
                            r"^self-test: all [1-9]\d* checks hold$")

    def test_control_one_rule_with_cloud_fixtures(self):
        """CONTROL of the rule-path form: one cloud rule, its sidecar cases and the
        attack and benign fixtures of its MANIFEST row."""
        good = self.good()
        cases = len(good.read_jsonl("detections/sigma/" + self.IMDS[:-len(".yml")] + ".cases.jsonl"))
        result = good.run(self.GATE, "detections/sigma/" + self.IMDS)
        self.assert_accepts(result, r"^OK: 1 rule\(s\), \d+ event set\(s\): every hit is the same")
        sets = re.search(rf"(?m)^ok    {re.escape(self.IMDS)}: (\d+) event set\(s\), same hits",
                         result.stdout)
        self.assertIsNotNone(sets, result.describe())
        self.assertGreaterEqual(int(sets.group(1)), cases + 2)

    def test_rejects_negation_on_a_field_the_record_lacks(self):
        """ns-unsafe-not. `select_namespace_delete and not filter_dry_run_body`, where
        the filter reads requestObject.dryRun and the positive record (Metadata level)
        has no request body. The sidecar is sound: rule_cases.py passes it."""
        tree = self.tree()
        before = len(rule_keys(tree))
        tree.plant("quality/unsafe_not", "detections/sigma/T9999")
        assert_cases_hold(tree, "T9999/planted_unsafe_not.yml")
        result = self.run_ci(tree)
        self.assert_rejects(
            result,
            r"^FAIL  T9999/planted_unsafe_not\.yml :: case positive namespace-delete-metadata-level: "
            r"fires in two-valued logic, not in three-valued logic$",
            exit_code=1)
        # The explanation names the negation, the item and the absent field.
        self.assertRegex(result.stdout, r"(?m)^ +`not filter_dry_run_body` is NULL \(block "
                                        r"filter_dry_run_body\):$")
        self.assertRegex(result.stdout, r"(?m)^ +filter_dry_run_body\.requestObject\.dryRun is NULL: "
                                        r"requestObject\.dryRun = <absent>$")
        # One planted defect, one problem: the filtered case of the planted rule holds.
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())
        self.assertIn(f"\nFAILED: 1 of {before + 1} rule(s) are not null-safe: "
                      "T9999/planted_unsafe_not.yml.\n", result.stdout)

    def test_rejects_fixture_field_in_another_letter_case(self):
        """ns-field-case-cloud-fixture. The attack fixture of TRR9011 writes
        `SourceIPAddress`; the rule reads `sourceIPAddress`. SQLite matches column
        names without regard to case, so the rule still fires offline (the cloud
        validator passes this tree: asserted below), but Lucene, Splunk and ES|QL
        would not read the field."""
        tree = self.tree()
        fixture = "detections/cloud/fixtures/trr9011/attack.json"
        tree.replace(fixture, '"sourceIPAddress"', '"SourceIPAddress"', count=0)
        records = len(tree.read_json(fixture))
        self.assertGreater(records, 0)
        # Only this gate sees the defect: every attack record still matches offline.
        self.assert_accepts(
            tree.run("detections/validate_cloud_detections.py"),
            rf"^PASS  \[TRR9011 AWS\] aws_imds_creds_used_off_instance\.yml: {records}/{records} "
            r"attack record\(s\) match; benign baseline clean ")
        result = tree.run(self.GATE, "detections/sigma/" + self.IMDS)
        self.assert_rejects(
            result,
            rf"^FAIL  {re.escape(self.IMDS)} :: fixture attack trr9011/attack\.json: the rule reads "
            r"`sourceIPAddress`, and the records carry `SourceIPAddress`: SQLite matches column "
            r"names without regard to case",
            exit_code=1)
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())
        self.assertIn(f"\nFAILED: 1 of 1 rule(s) are not null-safe: {self.IMDS}.\n", result.stdout)


# ----------------------------------------------------------------- check_variants.py

class Variants(gatelib.GateCase):
    """detections/check_variants.py, as the representation-variants job runs it: every
    rule gives the same hits on every sidecar case and cloud fixture when a list is
    JSON text without blanks (compact), with sorted keys too (sorted), one value for
    each element (multi), when LIKE does not fold case (cs_like) and when `|re` is a
    search with RE2 (re2, where google-re2 is installed), or the difference is an
    entry of detections/variants/expected.json."""

    GATE = "detections/check_variants.py"
    PARTS = gatelib.DETECTIONS
    EXPECTED = "detections/variants/expected.json"
    RE2 = importlib.util.find_spec("re2") is not None
    OK = (r"^OK: {rules} rule\(s\), \d+ event set\(s\), variants compact, sorted, multi, cs_like"
          r"(, re2)?: no new difference; {known} expected\.$")
    # A rule with one entry in the expected list (variant multi, a sidecar case), and
    # a rule whose entry names an open entry of RULE_DEFECTS.md (K43).
    LISTED = "T1134/k8s_impersonation_privileged.yml"
    LISTED_CASE = "impersonate-system-masters-group-procB"
    TRACKED = "T1098.006/k8s_rbac_privileged_grant.yml"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # CI passes --require-re2 (google-re2 is not in detections/requirements.txt).
        # Pass it here too when the tests' Python has RE2, as ProviderMappings does.
        cls.ci_arguments = ("--require-re2",) if cls.RE2 else ()
        # One full run takes about 10 s: start it now.
        cls.full_run = cls.in_background(cls.good().run, cls.GATE, *cls.ci_arguments)

    def entry(self, tree, rule):
        """The one entry of the expected list of the copy for `rule`."""
        entries = [e for e in tree.read_json(self.EXPECTED)["expected"] if e["rule"] == rule]
        self.assertEqual(len(entries), 1, f"the test needs one expected entry for {rule}")
        return entries[0]

    def change_entry(self, tree, rule, **values):
        """Change the one entry of the expected list of the copy for `rule`."""
        self.entry(tree, rule)

        def change(doc):
            next(e for e in doc["expected"] if e["rule"] == rule).update(values)
        tree.edit_json(self.EXPECTED, change)

    def test_ci_runs_the_self_test_and_every_rule_with_re2(self):
        self.assertEqual(gatelib.ci_commands(self.GATE), [
            "python3 detections/check_variants.py --require-re2 --self-test",
            'python3 detections/check_variants.py --require-re2 --markdown "$GITHUB_STEP_SUMMARY" '
            "| tee /tmp/variants.out",
            "python3 detections/check_variants.py "
            '--baseline-expected "$base/detections/variants/expected.json" '
            "> /tmp/variants-ratchet.out 2>&1 || rc=$?"])

    def test_job_fails_from_the_first_day_and_has_re2(self):
        """The representation-variants job is a hard gate, not a shadow check: the job
        and its steps have no `continue-on-error`, the job has no `if:` and no
        `needs:`, and no step that runs the gate has an `if:`. Its Python has RE2:
        the job installs google-re2 (one fixed version), on a Python for which that
        version has a wheel. Without the module the two gate steps stop
        (--require-re2: test_ci_runs_the_self_test_and_every_rule_with_re2)."""
        import yaml     # PyYAML: in detections/requirements.txt

        with open(os.path.join(gatelib.REPO, ".github", "workflows", "detection-quality.yml"),
                  encoding="utf-8") as fh:
            job = yaml.safe_load(fh)["jobs"]["representation-variants"]
        self.assertNotIn("if", job)
        self.assertNotIn("needs", job)
        self.assertNotIn("continue-on-error", job)
        gate_steps = [s for s in job["steps"] if "detections/check_variants.py" in s.get("run", "")]
        self.assertEqual(len(gate_steps), 2)
        for step in job["steps"]:
            self.assertNotIn("continue-on-error", step)
            if step in gate_steps or "pip install" in step.get("run", ""):
                self.assertNotIn("if", step)
        python = [s["with"]["python-version"] for s in job["steps"]
                  if str(s.get("uses", "")).startswith("actions/setup-python@")]
        self.assertEqual(python, ["3.14"])
        installs = [line.strip() for s in job["steps"] for line in s.get("run", "").splitlines()
                    if "google-re2" in line and not line.strip().startswith("#")]
        self.assertEqual(installs, ["pip install --quiet google-re2==1.1.20251105"])

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the unmodified copy passes; the gate checked every rule of the
        copy, and each entry of the expected list is a difference that it shows."""
        good = self.good()
        rules = rule_keys(good)
        known = len(good.read_json(self.EXPECTED)["expected"])
        self.assertGreater(known, 0, "the expected list is empty: the control of the "
                                     "stale-entry test below would be vacuous")
        result = self.full_run.result()
        self.assert_accepts(result, self.OK.format(rules=len(rules), known=known))
        checked = found(result, r"^ok    (T\S+\.yml): [1-9]\d* event set\(s\), same hits as ")
        self.assertEqual(sorted(checked), rules)
        self.assertEqual(len(found(result, r"^known T\S+\.yml :: .*, expected \(")), known)
        cases = sum(len(good.read_jsonl(rel)) for rel in good.glob("detections/sigma/*/*.cases.jsonl"))
        sets = int(re.search(r"(?m)^OK: \d+ rule\(s\), (\d+) event set", result.stdout).group(1))
        self.assertGreaterEqual(sets, cases, "fewer event sets than sidecar cases in the copy")
        if not self.RE2:
            # Without google-re2 the report must say that the variant did not run.
            self.assertIn("\nNOT RUN: variant re2: ", result.stdout)

    def test_control_self_test_passes(self):
        """CONTROL of the job's first step (--self-test): the golden probes and the
        constructed rules."""
        self.assert_accepts(self.good().run(self.GATE, *self.ci_arguments, "--self-test"),
                            r"^self-test: all [1-9]\d* checks hold$")

    def test_rejects_run_without_re2_when_ci_requires_it(self):
        """vr-re2-missing. CI passes --require-re2: without the module the gate must
        stop, not run four of five variants and say OK."""
        if self.RE2:
            self.assert_accepts(self.good().run(self.GATE, "--require-re2", "--probes"),
                                r"^\| `re-space-class` \| .* \| quiet \|$")
            return
        result = self.good().run(self.GATE, "--require-re2")
        self.assert_rejects(result, r"^ERROR: --require-re2 given but the module re2 "
                                    r"\(google-re2\) is not installed", exit_code=2)
        self.assertNotRegex(result.stdout, r"(?m)^OK: ")

    PUBLIC_SNAPSHOT = "T1537/aws_snapshot_or_ami_made_public.yml"
    # The hits of a rule (argument 1) on one case (argument 3) of a sidecar (argument
    # 2), with each list field as the JSON text that sigma_eval.flatten() writes
    # (`default`), and as JSON text without blanks (`compact`).
    HITS_BY_JSON_TEXT = (
        "import json, sys\n"
        "sys.path.insert(0, 'detections')\n"
        "import sigma_eval\n"
        "sql = sigma_eval.compile_rule(sys.argv[1])\n"
        "with open(sys.argv[2], encoding='utf-8') as fh:\n"
        "    cases = [json.loads(line) for line in fh if line.strip()]\n"
        "case = next(c for c in cases if c['name'] == sys.argv[3])\n"
        "for name, separators in (('default', None), ('compact', (',', ':'))):\n"
        "    events = [{k: json.dumps(json.loads(v), separators=separators)\n"
        "               if isinstance(v, str) and v[:1] == '[' else v\n"
        "               for k, v in sigma_eval.flatten(e).items()} for e in case['events']]\n"
        "    print(name, len(sigma_eval.evaluate(sql, events)))\n")

    def hits_by_json_text(self, tree, rule, case):
        probe = tree.run_python(self.HITS_BY_JSON_TEXT, "detections/sigma/" + rule,
                                "detections/sigma/" + rule[:-len(".yml")] + ".cases.jsonl", case)
        self.assertEqual(probe.returncode, 0, probe.describe())
        return probe.stdout.split()

    def test_rejects_one_json_serialisation_cloud(self):
        """ns-one-json-serialisation. Until roadmap item R7 this was a known gap, and
        its marker named detections/check_null_safety.py: no gate varied the JSON text
        of a list for a rule that is not a Kubernetes audit rule. The gap closed in
        another gate, this one. check_null_safety.py has no check for the artifact
        and still accepts it (asserted below). The artifact and the wanted row are
        those of the gap: the planted rule is the real
        T1537/aws_snapshot_or_ami_made_public.yml without its second form (a
        content-only change), and the positive case is reported, because it fires
        for one JSON serialisation of
        requestParameters.createVolumePermission.add.items only."""
        rule, case = self.PUBLIC_SNAPSHOT, "ebs-snapshot-made-public"
        tree = self.tree()
        # The real rule lists two forms of the list's JSON text. The planted rule
        # lost the form without blanks.
        items = "    requestParameters.createVolumePermission.add.items|contains:\n"
        tree.replace("detections/sigma/" + rule,
                     items + "      - '\"group\": \"all\"'\n      - '\"group\":\"all\"'\n",
                     items + "      - '\"group\": \"all\"'\n")
        # The artifact is bad: the real rule fires on the positive case for both JSON
        # texts of the list, and the planted rule is silent for the text without
        # blanks. (Plain assertions: they hold whatever the gate does.)
        self.assertEqual(self.hits_by_json_text(self.good(), rule, case),
                         ["default", "1", "compact", "1"])
        self.assertEqual(self.hits_by_json_text(tree, rule, case),
                         ["default", "1", "compact", "0"])
        # Every case of the real sidecar still holds offline: rule_cases.py does not
        # see the defect. CONTROL: the gate that the gap named does not see it either.
        assert_cases_hold(tree, rule)
        self.assert_accepts(tree.run("detections/check_null_safety.py", "detections/sigma/" + rule),
                            r"^OK: 1 rule\(s\), \d+ event set\(s\): every hit is the same")
        result = tree.run(self.GATE, "detections/sigma/" + rule)
        self.assert_saw(result, rf"^(ok   |FAIL ) {re.escape(rule)}\b")
        # The wanted row of the gap (`FAIL  <rule> :: case positive <case>: `), with
        # the words of this gate that name the defect.
        self.assert_rejects(
            result, rf"^FAIL  {re.escape(rule)} :: case positive {case}: \[compact\] loss: fires "
                    r"by default, quiet as compact; the rule misses the technique on that "
                    r"representation$", exit_code=1)
        # The explanation names the item and the value that it read.
        self.assertRegex(result.stdout, r"(?m)^ +record #0: selection_ec2_snapshot\.requestParameters"
                                        r"\.createVolumePermission\.add\.items: yes -> no; ")
        # A filtered case of the sidecar holds the same list: it stays quiet, and the
        # gate says that it no longer proves its filter there (a note, not a failure).
        self.assertRegex(result.stdout, r"(?m)^note  \S+ :: case filtered \S+: \[compact\] weakened: ")
        # One planted defect: the same case is lost with sorted keys too (that text has
        # no blanks), and no other row fails. The entry of the real rule in the
        # expected list (the multi variant) still holds.
        self.assertEqual(found(result, r"^FAIL  (.*?): \[(\w+)\] "),
                         [(f"{rule} :: case positive {case}", "compact"),
                          (f"{rule} :: case positive {case}", "sorted")])
        self.assertEqual(len(found(result, r"^FAIL .*$")), 2, result.describe())
        self.assertEqual(len(found(result, rf"^known {re.escape(rule)} :: .*\[multi\] loss, "
                                           r"expected \(LIST_TEXT\)$")), 1)

    def test_rejects_expected_entry_that_shows_no_difference(self):
        """vr-stale-entry. An entry of the expected list for a difference that the run
        does not show (here: a case name that the sidecar does not hold). A list that
        may hold such entries can excuse a later difference in advance."""
        tree = self.tree()
        rule = self.LISTED
        self.change_entry(tree, rule, name="a-case-that-is-not-in-the-sidecar")
        result = tree.run(self.GATE, "detections/sigma/" + rule)
        self.assert_rejects(
            result, rf"^FAIL  {re.escape(rule)}: expected \[multi\] case "
                    r"a-case-that-is-not-in-the-sidecar: stale: this run shows no such "
                    r"difference; delete the entry$", exit_code=1)
        # The difference that the entry excused before is now new.
        self.assertRegex(result.stdout, rf"(?m)^FAIL  {re.escape(rule)} :: case positive "
                                        rf"{self.LISTED_CASE}: \[multi\] loss: ")

    def test_rejects_expected_entry_with_a_reason_of_another_variant(self):
        """vr-wrong-reason. The reason of an entry must be a reason of its variant, with
        the proof that the gate makes for it: KEY_ORDER on a difference of the multi
        variant is refused, and the difference stays new."""
        tree = self.tree()
        rule = self.LISTED
        self.change_entry(tree, rule, reason="KEY_ORDER")
        result = tree.run(self.GATE, "detections/sigma/" + rule)
        self.assert_rejects(result, rf"^FAIL  {re.escape(rule)}: expected \[multi\] case "
                                    rf"{self.LISTED_CASE}: reason 'KEY_ORDER' "
                                    r"is not a reason of the variant multi \(LIST_TEXT\)$",
                            exit_code=1)
        self.assertRegex(result.stdout, rf"(?m)^FAIL  {re.escape(rule)} :: case positive "
                                        rf"{self.LISTED_CASE}: \[multi\] loss: .* \(listed, but "
                                        r"the entry does not hold\)$")

    def test_rejects_expected_entry_for_other_hits(self):
        """vr-entry-other-hits. An entry names the hits that are lost and gained (each
        hit: the record numbers in the event set). An entry that lists a loss of
        record 1 does not excuse the loss of record 0: an entry for one record of a
        fixture must not excuse the loss of a second one."""
        tree = self.tree()
        rule = self.LISTED
        self.assertEqual(self.entry(tree, rule)["lost"], [[0]])
        self.change_entry(tree, rule, lost=[[1]])
        result = tree.run(self.GATE, "detections/sigma/" + rule)
        self.assert_rejects(result, rf"^FAIL  {re.escape(rule)}: expected \[multi\] case "
                                    rf"{self.LISTED_CASE}: the hits changed: listed lost "
                                    r"\[\[1\]\], gained \[\]; this run shows lost \[\[0\]\], "
                                    r"gained \[\]$", exit_code=1)

    def test_rejects_expected_entry_without_a_why(self):
        """vr-entry-no-why. A human approves an entry by its `why`. An entry with an
        empty `why` excuses nothing."""
        tree = self.tree()
        rule = self.LISTED
        self.change_entry(tree, rule, why=" ")
        result = tree.run(self.GATE, "detections/sigma/" + rule)
        self.assert_rejects(result, rf"^FAIL  {re.escape(rule)}: expected \[multi\] case "
                                    rf"{self.LISTED_CASE}: `why` is empty$", exit_code=1)

    def test_rejects_expected_entry_whose_defect_is_not_open(self):
        """vr-entry-defect-not-open. An entry can name the entry of RULE_DEFECTS.md that
        tracks its difference. That entry must be open (a row of the Summary table)
        and must name the rule. `K13` is a closed entry: when a defect closes, the
        difference must be gone, and the expected entry with it."""
        tree = self.tree()
        rule = self.TRACKED
        self.assertEqual(self.entry(tree, rule)["defect"], "K43")
        self.assertIn("\n| K13 | ", tree.read("detections/RULE_DEFECTS.md"))
        self.change_entry(tree, rule, defect="K13")
        result = tree.run(self.GATE, "detections/sigma/" + rule)
        self.assert_rejects(result, rf"^FAIL  {re.escape(rule)}: expected \[sorted\] case \S+: "
                                    r"defect 'K13' is not an open entry of "
                                    r"detections/RULE_DEFECTS\.md \(its Summary table\)$",
                            exit_code=1)

    # -- the ratchet: the third comparison of the sufficiency-ratchet job ----------

    RATCHET_OK = (r"^OK: each of the {known} expected difference\(s\) is on the base branch as it "
                  r"is here \(the list did not grow\)\.$")
    NOT_ON_BASE = (r"^FAIL  \S+: expected \[\w+\] \w+ one-more-case: the base branch does not "
                   r"list this entry as it is here; a new or changed expected difference is a "
                   r"human decision$")

    @staticmethod
    def add_entry(doc):
        doc["expected"].append(dict(doc["expected"][0], name="one-more-case"))

    def test_control_ratchet_accepts_the_list_of_the_base(self):
        """CONTROL of the ratchet: the list of the copy against a copy of itself, and
        against a list that holds one entry more (the list of the head lost one)."""
        tree = self.tree()
        known = len(tree.read_json(self.EXPECTED)["expected"])
        base = tree.out("base/detections/variants/expected.json")
        shutil.copyfile(tree.path(self.EXPECTED), base)
        self.assert_accepts(tree.run(self.GATE, "--baseline-expected", base),
                            self.RATCHET_OK.format(known=known))
        with open(base, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.add_entry(doc)
        with open(base, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        self.assert_accepts(tree.run(self.GATE, "--baseline-expected", base),
                            self.RATCHET_OK.format(known=known))

    def test_rejects_new_expected_entry_against_the_base(self):
        """vr-entry-not-on-base. The ratchet (--baseline-expected): the list of the
        head holds an entry that the list of the base does not hold. The head alone
        passes the gate when the entry is true, so only this comparison shows that
        the list grew."""
        tree = self.tree()
        base = tree.out("base/detections/variants/expected.json")
        shutil.copyfile(tree.path(self.EXPECTED), base)
        tree.edit_json(self.EXPECTED, self.add_entry)
        result = tree.run(self.GATE, "--baseline-expected", base)
        self.assert_rejects(result, self.NOT_ON_BASE, exit_code=1)
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())

    def test_rejects_changed_expected_entry_against_the_base(self):
        """vr-entry-changed-against-base. An entry of the base with another `why` (or
        other hits, or another reason) is a changed approval: it fails as a new one."""
        tree = self.tree()
        base = tree.out("base/detections/variants/expected.json")
        shutil.copyfile(tree.path(self.EXPECTED), base)
        self.change_entry(tree, self.LISTED, why="Other words for the same difference.")
        result = tree.run(self.GATE, "--baseline-expected", base)
        self.assert_rejects(result, rf"^FAIL  {re.escape(self.LISTED)}: expected \[multi\] case "
                                    rf"{self.LISTED_CASE}: the base branch does not list this "
                                    r"entry as it is here", exit_code=1)
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())

    def test_ratchet_passes_with_a_notice_when_the_base_has_no_list(self):
        """The pull request that adds the gate: the base tree is there and has no
        expected list. The comparison has nothing to compare with, says so, and
        passes (as the two other comparisons of the job do)."""
        tree = self.tree()
        os.makedirs(tree.out("base/detections/sigma"))
        result = tree.run(self.GATE, "--baseline-expected",
                          tree.out("base/detections/variants/expected.json"))
        self.assert_accepts(result, r"^::notice title=variants-ratchet::the base has no "
                                    r"detections/variants/expected\.json; no expected list to "
                                    r"ratchet against \([1-9]\d* entr\(ies\) here\)$")

    def test_rejects_ratchet_path_with_no_base_tree(self):
        """vr-ratchet-no-base-tree. A path that names no file and no base tree (a wrong
        path, a base that was not checked out) must not pass as `the base has no
        list`: then every entry of the head would pass the comparison."""
        tree = self.tree()
        result = tree.run(self.GATE, "--baseline-expected",
                          os.path.join(tree.out("no-such-tree"), "detections/variants/expected.json"))
        self.assert_rejects(result, r"^ERROR: --baseline-expected \S+: the file is not there, and "
                                    r"the base tree is not there either", exit_code=2)
        self.assertNotIn("::notice", result.stdout)

    def ratchet_step(self, tree, base_list):
        """Run the third step of the sufficiency-ratchet job as GitHub Actions does,
        with a stand-in for the worktree of the base commit ($RUNNER_TEMP/base-tree).
        base_list: the text of the base's expected list, or None (the base has none).
        (The step also runs `pip install`; run_step() gives it a `pip` that installs
        nothing.)"""
        step = gatelib.ci_step("detection-quality.yml", "sufficiency-ratchet", self.GATE)
        mark = tree.out("ratchet-runner-temp/base-tree/.git")
        with open(mark, "w", encoding="utf-8") as fh:
            fh.write("gitdir: (a stand-in: the step only tests that the base tree exists)\n")
        os.makedirs(tree.out("ratchet-runner-temp/base-tree/detections/sigma"), exist_ok=True)
        if base_list is not None:
            with open(tree.out("ratchet-runner-temp/base-tree/" + self.EXPECTED), "w",
                      encoding="utf-8") as fh:
                fh.write(base_list)
        return tree.run_step(step, env={"RUNNER_TEMP": os.path.dirname(os.path.dirname(mark))})

    def test_ci_step_fails_on_a_new_entry(self):
        """The job's step saves the gate's exit code and ends with `exit "$rc"`: the new
        entry must fail the step. CONTROL: the step passes while the list of the
        head is the list of the base."""
        tree = self.tree()
        base_list = tree.read(self.EXPECTED)
        known = len(json.loads(base_list)["expected"])
        self.assert_accepts(self.ratchet_step(tree, base_list),
                            self.RATCHET_OK.format(known=known))
        tree.edit_json(self.EXPECTED, self.add_entry)
        self.assert_rejects(self.ratchet_step(tree, base_list), self.NOT_ON_BASE, exit_code=1)

    def test_ci_step_passes_with_a_notice_when_the_base_has_no_list(self):
        """The step on the pull request that adds the gate: the base tree has no
        expected list."""
        self.assert_accepts(self.ratchet_step(self.tree(), None),
                            r"^::notice title=variants-ratchet::the base has no "
                            r"detections/variants/expected\.json")

    def test_ci_step_fails_when_the_base_tree_is_not_checked_out(self):
        """The step tests that the worktree of the base commit is there before it
        compares: without it the step fails, also when the gate would give a notice."""
        step = gatelib.ci_step("detection-quality.yml", "sufficiency-ratchet", self.GATE)
        tree = self.tree()
        result = tree.run_step(step, env={"RUNNER_TEMP": tree.out("empty-runner-temp")})
        self.assert_rejects(result, r"^::error title=sufficiency-ratchet::the base tree was not "
                                    r"checked out$", exit_code=1)


# ------------------------------------------------------------ check_provider_mappings.py

class ProviderMappings(gatelib.GateCase):
    """detections/check_provider_mappings.py, the provider-mappings job: every
    Kubernetes audit rule keeps its verdicts when each sidecar case is rewritten to
    the record shape of AKS and of GKE. This is the gate that varies the JSON text
    of a list (no blanks; keys sorted)."""

    GATE = "detections/check_provider_mappings.py"
    # The gate loads .github/scripts/check_sigma_regex.py by path.
    PARTS = ("detections", ".github/scripts/check_sigma_regex.py")
    REAL = "T1611/k8s_podspec_host_access.yml"      # the rule the planted one is derived from
    PLANTED = "T9999/planted_json_separator_k8s.yml"
    OK = (r"^OK: every mapped rule keeps its verdicts and block truth on every case, or the "
          r"difference is approved\.$")

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # CI passes --require-re2 (google-re2 is not in detections/requirements.txt).
        # Pass it here too when the tests' Python has RE2; else the lint of the
        # pipelines' regular expressions runs with Python re only.
        cls.ci_arguments = ("--check", "--require-re2") if importlib.util.find_spec("re2") \
            else ("--check",)
        # A full run takes about 18 s whatever is planted: start both now.
        cls.full_run = cls.in_background(cls.good().run, cls.GATE, *cls.ci_arguments)
        # pm-one-json-serialisation: the planted rule matches the volumes list as the
        # text `"hostPath": {"path": "/"`, with the blank that json.dumps writes after
        # a colon. The native shape holds that text; the AKS and GKE shapes hold the
        # list without blanks, so the positive is silent there.
        cls.bad = cls.class_tree()
        cls.bad.plant("quality/one_json_serialisation_k8s", "detections/sigma/T9999")
        cls.rejection = cls.in_background(cls.bad.run, cls.GATE, *cls.ci_arguments)

    def test_ci_passes_check_and_require_re2(self):
        self.assert_ci_runs(self.GATE, "--check", "--require-re2")

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the full run of the job on the unmodified copy passes, and it
        judged every Kubernetes audit rule of the copy that has a sidecar, for both
        gating providers."""
        good = self.good()
        rules = k8s_audit_rules(good, sidecar=True)
        self.assertGreater(len(rules), 0, "the copy holds no Kubernetes audit rule: vacuous")
        result = self.full_run.result()
        self.assert_accepts(result, self.OK)
        for provider in ("aks", "gke"):
            judged = found(result, rf"^\[{provider}\] (?:SAME|EXPECTED LOSS|NOT PORTABLE) +"
                                   r"(T\S+\.yml) \([1-9]\d* cases")
            self.assertEqual(sorted(judged), rules, provider)
            counts = re.search(rf"\b{provider} (\d+) same, (\d+) with approved losses, (\d+) not "
                               r"portable, 0 diverging;", result.stdout)
            self.assertIsNotNone(counts, result.describe())
            self.assertEqual(sum(map(int, counts.groups())), len(rules), provider)

    def test_control_one_rule_is_accepted(self):
        """CONTROL of the rule-path form, on the real rule that the planted rule is
        derived from: every case of its sidecar is compared in both shapes."""
        good = self.good()
        cases = len(good.read_jsonl("detections/sigma/" + self.REAL[:-len(".yml")] + ".cases.jsonl"))
        result = good.run(self.GATE, "detections/sigma/" + self.REAL)
        self.assert_accepts(result, self.OK)
        for provider in ("aks", "gke"):
            self.assertRegex(result.stdout, rf"(?m)^\[{provider}\] (SAME|EXPECTED LOSS) +"
                                            rf"{re.escape(self.REAL)} \({cases} cases")

    def difference(self, provider):
        """The problem line for the planted positive in the record shape of `provider`."""
        return (rf"^  \[{provider}\] {re.escape(self.PLANTED)}: positive hostpath-root-pod: "
                rf"unexpected difference: all: native fires, {provider} quiet; "
                r"blocks sel_hostpath_root$")

    def test_rejects_match_on_one_json_serialisation(self):
        """pm-one-json-serialisation, with the command line of the job (the full run).
        rule_cases.py passes the pair: only this gate varies the JSON text."""
        assert_cases_hold(self.bad, self.PLANTED)
        result = self.rejection.result()
        for provider in ("aks", "gke"):
            self.assert_rejects(result, self.difference(provider), exit_code=1)
        # One planted defect: one problem for each gating provider, on the positive
        # only. The third problem of the full run is the results file, which has no
        # entry for the new rule; it is not the reason.
        listed = result.stdout.rstrip("\n").split("\nFAILED: 3 problem(s).\n")
        self.assertEqual(len(listed), 2, result.describe())
        others = [line for line in listed[1].splitlines() if self.PLANTED not in line]
        self.assertEqual(len(listed[1].splitlines()), 3, result.describe())
        self.assertEqual(len(others), 1, result.describe())
        self.assertRegex(others[0], r"^  detections/pipelines/mapping_results\.json is stale: ")
        self.assertNotIn("configmap-emptydir-volumes", result.stdout)

    def test_rejects_match_on_one_json_serialisation_by_rule_path(self):
        """The same pair with the rule-path form, which skips the results file: the
        two differences are the only problems."""
        result = self.bad.run(self.GATE, "detections/sigma/" + self.PLANTED)
        for provider in ("aks", "gke"):
            self.assert_rejects(result, self.difference(provider), exit_code=1)
        self.assertIn("\nFAILED: 2 problem(s).\n", result.stdout)
        self.assertNotIn("configmap-emptydir-volumes", result.stdout)


# -------------------------------------------------------------- k8s_policy_coverage.py

class K8sPolicyCoverage(gatelib.GateCase):
    """detections/k8s_policy_coverage.py --self-test --check, the first check of the
    platform-coverage job: policy_coverage.json is current, and every Kubernetes
    audit rule fires on all its positives (and on no negative) under the lab audit
    policy that its validator proves it on (the home check)."""

    GATE = "detections/k8s_policy_coverage.py"
    PARTS = gatelib.DETECTIONS
    COMMAND = "python3 detections/k8s_policy_coverage.py --self-test --check"
    EXEC_RULE = "T1609/k8s_pod_exec_attach.yml"     # home policy: lab-k8s (audit-policy.yaml)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Each run takes about 20 s whatever is planted: start both now.
        cls.control = cls.in_background(cls.good().run, cls.GATE, "--self-test", "--check")
        cls.bad = cls.class_tree()
        # pc-home-policy-loses-positives: the lab policy stops logging pods/exec and
        # pods/attach (level Metadata -> None), so the API server writes no record
        # of the requests that the exec rule's positives are.
        cls.bad.replace("detections/k8s/audit-policy.yaml",
                        '  - level: Metadata\n    resources:\n      - group: ""\n'
                        '        resources: ["pods/exec", "pods/attach"]\n',
                        '  - level: None\n    resources:\n      - group: ""\n'
                        '        resources: ["pods/exec", "pods/attach"]\n')
        # The rejection runs through the job's own step (`... | tee`, shell: bash).
        step = gatelib.ci_step("detection-quality.yml", "platform-coverage", cls.COMMAND)
        cls.rejection = cls.in_background(cls.bad.run_step, step)

    def test_ci_runs_self_test_and_check(self):
        self.assertIn(self.COMMAND + " | tee /tmp/platform-coverage.out",
                      gatelib.ci_commands(self.GATE))

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the unmodified copy passes, for every Kubernetes audit rule of the
        copy, after the evaluator's own unit cases."""
        rules = k8s_audit_rules(self.good())
        self.assertGreater(len(rules), 0, "the copy holds no Kubernetes audit rule: vacuous")
        result = self.control.result()
        self.assert_accepts(
            result,
            rf"^OK: detections/k8s/policy_coverage\.json is current \({len(rules)} rule\(s\), "
            r"[1-9]\d* policies; every rule fires on all its positives and on no negative under "
            r"its home lab policy; ")
        self.assertRegex(result.stdout, r"(?m)^self-test: [1-9]\d* checks, 0 failed$")

    def test_rejects_lab_policy_that_drops_the_records_of_a_rule(self):
        """pc-home-policy-loses-positives (planted in setUpClass). The home check
        names the rule, its home policy and the lost positives. The stale-file
        failure prints too (the policy file changed); it is not the reason. The run
        is the workflow step itself, so the exit code must also pass `tee`."""
        sidecar = "detections/sigma/" + self.EXEC_RULE[:-len(".yml")] + ".cases.jsonl"
        positives = [c["name"] for c in self.bad.read_jsonl(sidecar) if c["kind"] == "positive"]
        self.assertGreater(len(positives), 0)
        result = self.rejection.result()
        self.assert_rejects(
            result,
            rf"^  {re.escape(self.EXEC_RULE)}: under its home policy lab-k8s only 0 of "
            rf"{len(positives)} positives fire; lost: {re.escape(positives[0])} \(no-record\)",
            exit_code=1)
        # One planted defect, one home-check problem: no other rule lost a positive.
        self.assertEqual(len(found(result, r"^  T\S+\.yml: under its home policy .*$")), 1,
                         result.describe())
        self.assertNotIn("FAIL: recommended check", result.stdout)


# ---------------------------------------------------------------- k8s_platforms_md.py

class K8sPlatformsMdCheck(gatelib.GateCase):
    """detections/k8s_platforms_md.py --check, the second check of the
    platform-coverage job: the generated blocks of detections/k8s/PLATFORMS.md are
    what the generator writes now from its inputs."""

    GATE = "detections/k8s_platforms_md.py"
    PARTS = gatelib.DETECTIONS
    DOC = "detections/k8s/PLATFORMS.md"
    STALE = (r"^STALE: the platform-coverage block of detections/k8s/PLATFORMS\.md differs from "
             r"the inputs; run python3 detections/k8s_platforms_md\.py --write$")

    def hand_edit(self, tree):
        """md-stale-generated-block: inside the generated platform-coverage block, the
        first cell that says **partial** is edited by hand to say **full**: the page
        then claims coverage that the inputs do not give."""
        def change(text):
            begin = text.index("<!-- platform-coverage:begin -->")
            end = text.index("<!-- platform-coverage:end -->")
            block = text[begin:end].replace("| **partial** ", "| **full** ", 1)
            return text[:begin] + block + text[end:]
        tree.edit(self.DOC, change)

    def test_ci_runs_self_test_then_check(self):
        commands = gatelib.ci_commands(self.GATE)
        self.assertIn("python3 detections/k8s_platforms_md.py --self-test", commands)
        self.assertIn("python3 detections/k8s_platforms_md.py --check", commands)

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the unmodified copy passes, for every generated block of the page
        and every Kubernetes audit rule of the copy."""
        good = self.good()
        rules = k8s_audit_rules(good)
        blocks = len(re.findall(r"(?m)^<!-- [\w-]+:begin -->$", good.read(self.DOC)))
        self.assertGreater(len(rules), 0, "the copy holds no Kubernetes audit rule: vacuous")
        self.assertGreater(blocks, 0, "the page holds no generated block: vacuous")
        self.assert_accepts(
            good.run(self.GATE, "--check"),
            rf"^OK: detections/k8s/PLATFORMS\.md: {blocks} generated blocks are current "
            rf"\({len(rules)} rules, [1-9]\d* policies, ")

    def test_control_self_test_passes(self):
        """CONTROL of the step's first command (--self-test)."""
        self.assert_accepts(self.good().run(self.GATE, "--self-test"), r"^self-test passed$")

    def test_rejects_hand_edited_generated_block(self):
        """md-stale-generated-block (see hand_edit())."""
        tree = self.tree()
        self.hand_edit(tree)
        result = tree.run(self.GATE, "--check")
        self.assert_rejects(result, self.STALE, exit_code=1)
        # One edited block, one STALE line: the other four blocks are current.
        self.assertEqual(len(found(result, r"^STALE: .*$")), 1, result.describe())

    def test_ci_step_fails_when_the_gate_fails(self):
        """The step runs --self-test and then --check with no `shell:` (bash -e). Run it
        as GitHub Actions does: the exit code of --check must end the step."""
        step = gatelib.ci_step("detection-quality.yml", "platform-coverage",
                               "python3 detections/k8s_platforms_md.py --check")
        tree = self.tree()
        self.hand_edit(tree)
        result = tree.run_step(step)
        self.assert_rejects(result, self.STALE, exit_code=1)
        self.assertRegex(result.stdout, r"(?m)^self-test passed$")


class K8sPlatformsMdAnchors(gatelib.GateCase):
    """detections/k8s_platforms_md.py --anchors, the second step of the
    markdown-links job (validate-detections.yml): every link with an anchor into,
    inside and out of detections/k8s/PLATFORMS.md names a heading. The gate walks
    every .md file of the checkout, so the copy is the whole checkout."""

    GATE = "detections/k8s_platforms_md.py"
    PARTS = gatelib.ALL
    DOC = "detections/k8s/PLATFORMS.md"
    OK = (r"^OK: (\d+) anchored link\(s\) into, inside and out of detections/k8s/PLATFORMS\.md "
          r"resolve to a heading$")

    def anchored_links(self, tree):
        result = tree.run(self.GATE, "--anchors")
        self.assert_accepts(result, self.OK)
        return int(re.search(self.OK, result.stdout, re.MULTILINE).group(1))

    def test_ci_runs_the_anchors_check(self):
        self.assertIn("python3 detections/k8s_platforms_md.py --anchors",
                      gatelib.ci_commands(self.GATE))

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the unmodified copy passes, and the gate checked links."""
        self.assertGreater(self.anchored_links(self.good()), 0,
                           "the gate checked no link: the control is vacuous")

    def test_control_counts_a_link_in_a_new_root_file(self):
        """CONTROL: a new Markdown file at the root of the copy, with one link to a
        heading that exists, passes and adds one to the number of links checked. So
        the gate reads the place where the bad anchor is planted."""
        good = self.good()
        anchor = None
        for rel in good.glob("research/trr*/*/README.md"):
            link = re.search(r"\]\(\S*detections/k8s/PLATFORMS\.md#([\w-]+)\)", good.read(rel))
            if link:
                anchor = link.group(1)
                break
        self.assertIsNotNone(anchor, "no TRR links to a heading of the page: take another source")
        tree = self.tree()
        tree.write("PLANTED_OK.md", f"A link to a real heading: [platforms]({self.DOC}#{anchor}).\n")
        self.assertEqual(self.anchored_links(tree), self.anchored_links(good) + 1)

    def expected_bad_anchor(self):
        artifact = os.path.join(gatelib.KNOWN_BAD, "quality", "bad_anchor.md.txt")
        with open(artifact, encoding="utf-8") as fh:
            line = next(n for n, text in enumerate(fh, 1) if "#no-such-heading)" in text)
        return (rf"^BAD ANCHOR: PLANTED\.md:{line}: detections/k8s/PLATFORMS\.md#no-such-heading "
                r"\(no heading of detections/k8s/PLATFORMS\.md has the anchor #no-such-heading\)$")

    LINKS_OK = r"^OK: (\d+) relative links across the repo all resolve\.$"

    def relative_links(self, tree):
        """The number of links that .github/scripts/check_md_links.py finds good in the
        copy (the first step of the same job)."""
        result = tree.run(".github/scripts/check_md_links.py")
        self.assert_accepts(result, self.LINKS_OK)
        return int(re.search(self.LINKS_OK, result.stdout, re.MULTILINE).group(1))

    def test_rejects_link_to_an_anchor_that_no_heading_has(self):
        """an-bad-anchor. check_md_links.py reads the planted link and passes it: the
        file exists. Only this gate reads the anchor."""
        tree = self.tree()
        tree.plant("quality/bad_anchor.md.txt", "PLANTED.md")
        self.assertEqual(self.relative_links(tree), self.relative_links(self.good()) + 1)
        result = tree.run(self.GATE, "--anchors")
        self.assert_rejects(result, self.expected_bad_anchor(), exit_code=1)
        self.assertEqual(len(found(result, r"^BAD ANCHOR: .*$")), 1, result.describe())

    def test_ci_step_fails_when_the_gate_fails(self):
        step = gatelib.ci_step("validate-detections.yml", "markdown-links",
                               "python3 detections/k8s_platforms_md.py --anchors")
        tree = self.tree()
        tree.plant("quality/bad_anchor.md.txt", "PLANTED.md")
        self.assert_rejects(tree.run_step(step), self.expected_bad_anchor(), exit_code=1)


# -------------------------------------------------------------------- coverage_report.py

class CoverageReport(gatelib.GateCase):
    """research/tools/coverage_report.py --check, the coverage-report job:
    research/COVERAGE.md and the two README charts are what the generator writes now
    from the TRRs, the rules, check_sufficiency.py and detections/RULE_DEFECTS.md.
    The gate reads research/, detections/ and docs/, so the copy is the whole
    checkout."""

    GATE = "research/tools/coverage_report.py"
    PARTS = gatelib.ALL
    REPORT = "research/COVERAGE.md"
    DEFECTS = "detections/RULE_DEFECTS.md"
    STALE = (r"^STALE: research/COVERAGE\.md is not current; run python3 "
             r"research/tools/coverage_report\.py$")
    # The Summary row that the planted section lacks. Its Rule cell names no rule
    # file, so the rule comes from the section's own Rule bullet.
    SUMMARY_ROW = ("| [L99](#l99-planted-known-bad-artifact-afpacket_raw_socket-has-an-open-defect-"
                   "with-no-summary-row) | one Linux rule | PLANTED artifact of detections/tests "
                   "| evasion | medium |\n")

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Each run takes about 7 s (it runs check_sufficiency.py): start them all now,
        # one thread for each copy.
        cls.control = cls.in_background(cls.good().run, cls.GATE, "--check")

        # cr-emulation-not-built: the emulation of TRR9001.LIN.A is no longer `built`.
        cls.not_built = cls.class_tree()
        cls.not_built.replace("research/trr9001/lin/README.md",
                              "afpacket_rawsocket_behavioral.c) | **built** |",
                              "afpacket_rawsocket_behavioral.c) | backlog |")
        cls.not_built_runs = cls.in_background(cls.check_then_write, cls.not_built)

        # cr-defect-heading-without-summary-row: a new entry of the defect tracker
        # names a rule that proves TRR9001.LIN.A and B, and has no Summary row.
        cls.no_row = cls.class_tree()
        cls.no_row.plant("quality/defect_without_summary_row/section.md.txt", cls.DEFECTS, append=True)
        cls.no_row_run = cls.in_background(cls.no_row.run, cls.GATE, "--check")

        # The same entry with its Summary row: what the gate does when it reads it.
        cls.with_row = cls.class_tree()
        cls.with_row.plant("quality/defect_without_summary_row/section.md.txt", cls.DEFECTS, append=True)
        separator = "|----|------|---------|------|----------|\n"
        cls.with_row.replace(cls.DEFECTS, separator, separator + cls.SUMMARY_ROW)
        cls.with_row_run = cls.in_background(cls.with_row.run, cls.GATE, "--check")

    @classmethod
    def check_then_write(cls, tree):
        """The gate's --check, and then the generator itself, in a private copy. The
        STALE line of --check names a file and no reason; the report that the
        generator writes next for the same copy shows what was stale."""
        check = tree.run(cls.GATE, "--check")
        return check, tree.run(cls.GATE)

    def control_is_current(self):
        """A STALE on a planted copy is a verdict on the artifact only when the same
        gate finds the unmodified copy current. (A plain assertion: the control test
        reports the same failure.)"""
        self.assert_accepts(self.control.result(), r"^Coverage report is current\.$")

    @staticmethod
    def proven(report):
        """(proven, all) procedures, from the first paragraph of a COVERAGE.md."""
        counts = re.search(r"CI proves (\d+) of (\d+) procedures \(", report)
        if not counts:
            raise AssertionError("COVERAGE.md does not say `CI proves N of M procedures`")
        return int(counts.group(1)), int(counts.group(2))

    def test_ci_runs_the_check(self):
        self.assertEqual(gatelib.ci_commands(self.GATE),
                         ["python3 research/tools/coverage_report.py --check"])

    def test_control_good_tree_is_accepted(self):
        """CONTROL: the unmodified copy passes. The gate's line has no count, so the
        test reads it from the report that the gate found current: it counts every
        procedure of research/index.json, and proves some."""
        good = self.good()
        procedures = sum(len(t["procedures"]) for t in good.read_json("research/index.json")["trrs"])
        self.assertGreater(procedures, 0, "the index holds no procedure: the control is vacuous")
        self.control_is_current()
        proven, counted = self.proven(good.read(self.REPORT))
        self.assertEqual(counted, procedures)
        self.assertGreater(proven, 0, "the report proves no procedure: the control is vacuous")

    def test_rejects_proven_claim_for_an_emulation_that_is_not_built(self):
        """cr-emulation-not-built (planted in setUpClass). COVERAGE.md shows
        TRR9001.LIN.A as Proven. With its emulation in the backlog the generator
        writes Claimed, so the committed report (and the two charts, which draw the
        proven count) is stale."""
        self.control_is_current()
        report = self.good().read(self.REPORT)
        # Proven today: the only way the edit can change the report is the status.
        self.assertRegex(report, r"(?m)^\| \[TRR9001\]\(trr9001/lin/README\.md\) \|.*\| A:P ")
        self.assertNotIn("`TRR9001.LIN.A`", report)
        check, written = self.not_built_runs.result()
        self.assert_rejects(check, self.STALE, exit_code=1)
        self.assertEqual(sorted(found(check, r"^STALE: (\S+) is not current; ")),
                         ["docs/coverage/coverage-dark.svg", "docs/coverage/coverage-light.svg",
                          self.REPORT], check.describe())
        # The reason for STALE: the generator now writes one proven procedure fewer,
        # and that procedure is TRR9001.LIN.A, Claimed, with its emulation in the backlog.
        proven, counted = self.proven(report)
        self.assert_accepts(written, rf"^{proven - 1}/{counted} procedures proven; wrote "
                                     r"research/COVERAGE\.md, ")
        now = self.not_built.read(self.REPORT)
        self.assertEqual(self.proven(now), (proven - 1, counted))
        self.assertRegex(now, r"(?m)^\| \[TRR9001\]\(trr9001/lin/README\.md\) \|.*\| A:\*\*C\*\* ")
        self.assertRegex(now, r"(?m)^\| `TRR9001\.LIN\.A` \| [^|]+ \| Claimed \| backlog \| ")

    @gatelib.known_gap(
        "cr-defect-heading-without-summary-row",
        gate="research/tools/coverage_report.py --check",
        reason="An entry of detections/RULE_DEFECTS.md that has a section and no Summary row "
               "is not an open defect for the report: open_defects() reads only the Summary "
               "table, so COVERAGE.md keeps `Proven` for the procedures that the named rule "
               "proves, and the gate says the report is current.",
        closes="R2d")
    def test_gap_defect_section_without_summary_row(self):
        """cr-defect-heading-without-summary-row (planted in setUpClass). WANTED: the
        entry marks the procedures of its rule (COVERAGE.md is stale), or the gate
        refuses an entry that has no Summary row."""
        # The entry is effective when the gate reads it: with its Summary row the
        # report is stale, and the unmodified copy is current. (Plain assertions:
        # they must not count as the gap, and a copy that is stale for another
        # reason must not count as the gap closed.)
        self.control_is_current()
        with_row = self.with_row_run.result()
        self.assertEqual(with_row.returncode, 1, with_row.describe())
        self.assertRegex(with_row.stdout, "(?m)" + self.STALE, with_row.describe())
        self.assertIn("\n### L99. PLANTED known-bad artifact", self.no_row.read(self.DEFECTS))
        self.assertNotIn("| [L99](", self.no_row.read(self.DEFECTS))
        self.assert_rejects(self.no_row_run.result(),
                            self.STALE + r"|^coverage_report: .*RULE_DEFECTS\.md.*\bL99\b")


if __name__ == "__main__":
    unittest.main()
