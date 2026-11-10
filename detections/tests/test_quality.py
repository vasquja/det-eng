"""
Gate tests, group `quality`: the gates that judge a rule beyond its own cases
(detection-quality.yml jobs benign-corpus, sufficiency-ratchet (the benign half),
null-safety, provider-mappings, platform-coverage and coverage-report, and the
anchors step of validate-detections.yml job markdown-links).

    score_benign.py           ScoreBenign, BenignRatchet
    check_null_safety.py      NullSafety
    check_provider_mappings.py  ProviderMappings
    k8s_policy_coverage.py    K8sPolicyCoverage
    k8s_platforms_md.py       K8sPlatformsMdCheck (--check), K8sPlatformsMdAnchors (--anchors)
    coverage_report.py        CoverageReport

Planted artifacts: detections/tests/known_bad/quality/. An artifact that is one
changed value of a real file is an edit in the test (tree.replace, tree.edit_json);
the test says what it changes and why that is bad.
How the harness works: gatelib.py and README.md in this directory.

    python3 -B -m unittest discover -s detections/tests -p 'test_quality.py' -v
"""

import concurrent.futures
import importlib.util
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


def class_tree(cls):
    """A private copy that lives as long as the test class: for a slow gate whose
    runs start in setUpClass, so that they overlap. Never plant in cls.good()."""
    tree = gatelib.Tree(cls.PARTS)
    cls.addClassCleanup(tree.cleanup)
    return tree


def in_background(cls, call, *args):
    """Start call(*args) on a thread and return its future; future.result() is the
    Result. The class waits for the run before it deletes its copies (this cleanup
    is registered after them, so it runs first), also when a test did not ask for
    the result (`-k`)."""
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = pool.submit(call, *args)
    cls.addClassCleanup(pool.shutdown, wait=True)
    return future


def step_running(workflow, job, command):
    """The one step of `job` in `workflow` (a file name) with a line that holds
    `command`, the start of a command line (`python3 <script> <flags>`). Unlike
    gatelib.ci_step(), a step that only lists the script as a path does not count
    (job platform-coverage has such a step for each of its scripts)."""
    steps = [s for s in gatelib.ci_steps(command.split()[1])
             if s.workflow == workflow and s.job == job
             and any(command in " ".join(line.split()) for line in s.run.splitlines()
                     if not line.strip().startswith("#"))]
    if len(steps) != 1:
        raise LookupError(f"{workflow}, job {job}: {len(steps)} step(s) run `{command}`; wanted 1")
    return steps[0]


def step_path_with_pip(tree):
    """A PATH for Tree.run_step() where `pip`, `python3` and `python` are the tests'
    Python. run_step() gives the step the tests' python3, but `pip` comes from the
    machine's PATH and can belong to another Python: a step that runs
    `pip install -r detections/requirements.txt` then fails before the gate runs."""
    bin_dir = os.path.dirname(tree.out("quality-bin/pip"))
    for name, arguments in (("pip", '-m pip "$@"'), ("python3", '"$@"'), ("python", '"$@"')):
        shim = os.path.join(bin_dir, name)
        with open(shim, "w", encoding="utf-8") as fh:
            fh.write(f'#!/bin/sh\nexec "{gatelib.PYTHON}" {arguments}\n')
        os.chmod(shim, 0o755)
    return bin_dir + os.pathsep + os.environ.get("PATH", "")


# ---------------------------------------------------------------------- score_benign.py

class ScoreBenign(gatelib.GateCase):
    """detections/score_benign.py --check --enforce, as the benign-corpus job runs it:
    scores.json is current, every rule is scored or exempt, and no enforce-mode rule
    is over its budget (definition of done 4)."""

    GATE = "detections/score_benign.py"
    PARTS = gatelib.DETECTIONS      # the gate reads nothing outside detections/
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

    def plant_unclassed_budget(self, tree):
        """sb-budget-why-no-class: the budget of a real rule is raised from 3 to 300
        hits with a reason that names neither class (documented noise, or a defect
        that detections/RULE_DEFECTS.md tracks)."""
        def change(doc):
            doc["rules"][self.BUDGET_RULE] = {"mode": "enforce", "max_hits": 300,
                                              "why": "raised so CI is green"}
        tree.edit_json(self.BUDGETS, change)

    WHY_NO_CLASS = (r"^  T1014/bpf_prog_load\.yml: why must start 'documented noise:' or 'rule "
                    r"defect, tracked in detections/RULE_DEFECTS\.md <ID>:'$")

    def test_rejects_budget_whose_why_names_no_class(self):
        """A budget needs a classed reason. The gate refuses the file before it
        scores anything."""
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
               "branch, so the raise needs no defect, no evidence and no human.",
        closes="R8")
    def test_gap_budget_raised_as_documented_noise(self):
        """WANTED: a budget far above what the rule raises (1 hit; at most 3 over the
        reseeds) is refused, or sent to a human, in words that name the rule and its
        budget."""
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
    KEY = "T1040/afinet_raw_socket.yml"

    def run_ratchet(self, tree, base):
        return tree.run(self.GATE, "--examples", "0", "--baseline-scores", base)

    def broaden(self, tree):
        """rb-benign-rise-inside-budget: SOCK_DGRAM ('2') is added to the socket types
        of the raw-socket rule, so the rule also fires on ordinary UDP sockets (the
        corpus has tracepath). The rule stays inside its budget of 13 hits."""
        tree.replace("detections/sigma/" + self.KEY,
                     "    a1:\n      - '3' ",
                     "    a1:\n      - '2'       # SOCK_DGRAM: PLANTED, not a raw socket\n      - '3' ")

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
        tree = self.tree()
        base = tree.out("base-scores.json")     # the base branch's snapshot: saved before the change
        shutil.copyfile(tree.path(self.SCORES), base)
        hits, budget, rise = self.expected_rise(tree)
        self.broaden(tree)
        result = self.run_ratchet(tree, base)
        self.assert_rejects(result, rise, exit_code=1)
        now = int(re.search(rise, result.stdout, re.MULTILINE).group(1))
        self.assertTrue(hits < now <= budget,
                        f"the planted rise must stay inside the budget: {hits} -> {now}, budget {budget}")
        # The budget alone accepts it: the rule's row says `ok`.
        self.assertRegex(result.stdout, rf"(?m)^{re.escape(self.KEY)} +\S+ +enforce +\d+ +{now} "
                                        rf"+[\d.]+ +{budget}  ok\b")
        self.assertIn("\nFAILED: 1 rule(s) raise more benign hits than on the base branch: "
                      f"{self.KEY}\n", result.stdout)

    @unittest.skipUnless(importlib.util.find_spec("pip"), "the step runs `pip install`; the "
                         "tests' Python has no pip")
    def test_ci_step_fails_on_a_rise(self):
        """The job's step saves the gate's exit code and ends with `exit "$rc"`. Run the
        step as GitHub Actions does, with a stand-in for the worktree of the base
        commit ($RUNNER_TEMP/base-tree): the rise must fail the step."""
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
            "RUNNER_TEMP": os.path.dirname(os.path.dirname(worktree_mark)),
            "PATH": step_path_with_pip(tree)})
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
        names without regard to case, so the rule still fires offline (verified on
        2026-11-10: validate_cloud_detections.py passes this tree), but Lucene,
        Splunk and ES|QL would not read the field."""
        tree = self.tree()
        tree.replace("detections/cloud/fixtures/trr9011/attack.json",
                     '"sourceIPAddress"', '"SourceIPAddress"', count=0)
        result = tree.run(self.GATE, "detections/sigma/" + self.IMDS)
        self.assert_rejects(
            result,
            rf"^FAIL  {re.escape(self.IMDS)} :: fixture attack trr9011/attack\.json: the rule reads "
            r"`sourceIPAddress`, and the records carry `SourceIPAddress`: SQLite matches column "
            r"names without regard to case",
            exit_code=1)
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())
        self.assertIn(f"\nFAILED: 1 of 1 rule(s) are not null-safe: {self.IMDS}.\n", result.stdout)

    @gatelib.known_gap(
        "ns-one-json-serialisation",
        gate="detections/check_null_safety.py (no gate varies the JSON text of a list for a rule "
             "that is not a Kubernetes audit rule)",
        reason="A cloud rule whose item matches the JSON text of a list with a blank after the "
               "colon (`\"group\": \"all\"`, the form json.dumps writes by default) passes every "
               "gate, because sigma_eval.flatten() gives each gate that one serialisation; a "
               "store that writes the list without blanks never matches, and only "
               "check_provider_mappings.py varies the text, for Kubernetes audit rules.",
        closes="R7")
    def test_gap_one_json_serialisation_cloud(self):
        """WANTED: the positive case is reported, because it fires for one JSON
        serialisation of requestParameters.createVolumePermission.add.items only."""
        tree = self.tree()
        tree.plant("quality/one_json_serialisation_cloud", "detections/sigma/T9999")
        result = tree.run(self.GATE, "detections/sigma/T9999/planted_json_separator_cloud.yml")
        self.assert_saw(result, r"^(ok   |FAIL ) T9999/planted_json_separator_cloud\.yml\b")
        self.assert_rejects(result, r"^FAIL  T9999/planted_json_separator_cloud\.yml :: case positive "
                                    r"ebs-snapshot-made-public: ")


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
        # The full run takes about 18 s: start it now, the other tests overlap it.
        cls.full_run = in_background(cls, cls.good().run, cls.GATE, *cls.ci_arguments)

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

    def test_rejects_match_on_one_json_serialisation(self):
        """pm-one-json-serialisation. The planted rule matches the volumes list as the
        text `"hostPath": {"path": "/"`, with the blank that json.dumps writes after a
        colon. The native shape holds that text; the AKS and GKE shapes hold the list
        without blanks, so the positive is silent there. rule_cases.py passes the pair."""
        tree = self.tree()
        tree.plant("quality/one_json_serialisation_k8s", "detections/sigma/T9999")
        result = tree.run(self.GATE, "detections/sigma/T9999/planted_json_separator_k8s.yml")
        for provider in ("aks", "gke"):
            self.assert_rejects(
                result,
                rf"^  \[{provider}\] T9999/planted_json_separator_k8s\.yml: positive hostpath-root-pod: "
                rf"unexpected difference: all: native fires, {provider} quiet; blocks sel_hostpath_root$",
                exit_code=1)
        # One planted defect: one problem for each gating provider, on the positive
        # only (the near-miss is quiet in every shape).
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
        cls.control = in_background(cls, cls.good().run, cls.GATE, "--self-test", "--check")
        cls.bad = class_tree(cls)
        # pc-home-policy-loses-positives: the lab policy stops logging pods/exec and
        # pods/attach (level Metadata -> None), so the API server writes no record
        # of the requests that the exec rule's positives are.
        cls.bad.replace("detections/k8s/audit-policy.yaml",
                        '  - level: Metadata\n    resources:\n      - group: ""\n'
                        '        resources: ["pods/exec", "pods/attach"]\n',
                        '  - level: None\n    resources:\n      - group: ""\n'
                        '        resources: ["pods/exec", "pods/attach"]\n')
        # The rejection runs through the job's own step (`... | tee`, shell: bash).
        step = step_running("detection-quality.yml", "platform-coverage", cls.COMMAND)
        cls.rejection = in_background(cls, cls.bad.run_step, step)

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
        """The home check names the rule, its home policy and the lost positives. The
        stale-file failure prints too (the policy file changed); it is not the reason.
        The run is the workflow step itself, so the exit code must also pass `tee`."""
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
            return text[:begin] + text[begin:end].replace("| **partial** ", "| **full** ", 1) + text[end:]
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
        tree = self.tree()
        self.hand_edit(tree)
        result = tree.run(self.GATE, "--check")
        self.assert_rejects(result, self.STALE, exit_code=1)
        # One edited block, one STALE line: the other four blocks are current.
        self.assertEqual(len(found(result, r"^STALE: .*$")), 1, result.describe())

    def test_ci_step_fails_when_the_gate_fails(self):
        """The step runs --self-test and then --check with no `shell:` (bash -e). Run it
        as GitHub Actions does: the exit code of --check must end the step."""
        step = step_running("detection-quality.yml", "platform-coverage",
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
            found = re.search(r"\]\(\S*detections/k8s/PLATFORMS\.md#([\w-]+)\)", good.read(rel))
            if found:
                anchor = found.group(1)
                break
        self.assertIsNotNone(anchor, "no TRR links to a heading of the page: take another source")
        tree = self.tree()
        tree.write("PLANTED_OK.md", f"A link to a real heading: [platforms]({self.DOC}#{anchor}).\n")
        self.assertEqual(self.anchored_links(tree), self.anchored_links(good) + 1)

    def expected_bad_anchor(self):
        with open(os.path.join(gatelib.KNOWN_BAD, "quality", "bad_anchor.md.txt"), encoding="utf-8") as fh:
            line = next(n for n, text in enumerate(fh, 1) if "#no-such-heading)" in text)
        return (rf"^BAD ANCHOR: PLANTED\.md:{line}: detections/k8s/PLATFORMS\.md#no-such-heading "
                r"\(no heading of detections/k8s/PLATFORMS\.md has the anchor #no-such-heading\)$")

    def test_rejects_link_to_an_anchor_that_no_heading_has(self):
        """an-bad-anchor. check_md_links.py passes this link: the file exists. Only
        this gate reads the anchor."""
        tree = self.tree()
        tree.plant("quality/bad_anchor.md.txt", "PLANTED.md")
        result = tree.run(self.GATE, "--anchors")
        self.assert_rejects(result, self.expected_bad_anchor(), exit_code=1)
        self.assertEqual(len(found(result, r"^BAD ANCHOR: .*$")), 1, result.describe())

    def test_ci_step_fails_when_the_gate_fails(self):
        step = step_running("validate-detections.yml", "markdown-links",
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
        # Each run takes about 7 s (it runs check_sufficiency.py): start all four now.
        cls.control = in_background(cls, cls.good().run, cls.GATE, "--check")

        # cr-emulation-not-built: the emulation of TRR9001.LIN.A is no longer `built`.
        cls.not_built = class_tree(cls)
        cls.not_built.replace("research/trr9001/lin/README.md",
                              "afpacket_rawsocket_behavioral.c) | **built** |",
                              "afpacket_rawsocket_behavioral.c) | backlog |")
        cls.not_built_run = in_background(cls, cls.not_built.run, cls.GATE, "--check")

        # cr-defect-heading-without-summary-row: a new entry of the defect tracker
        # names a rule that proves TRR9001.LIN.A and B, and has no Summary row.
        cls.no_row = class_tree(cls)
        cls.no_row.plant("quality/defect_without_summary_row/section.md.txt", cls.DEFECTS, append=True)
        cls.no_row_run = in_background(cls, cls.no_row.run, cls.GATE, "--check")

        # The same entry with its Summary row: what the gate does when it reads it.
        cls.with_row = class_tree(cls)
        cls.with_row.plant("quality/defect_without_summary_row/section.md.txt", cls.DEFECTS, append=True)
        separator = "|----|------|---------|------|----------|\n"
        cls.with_row.replace(cls.DEFECTS, separator, separator + cls.SUMMARY_ROW)
        cls.with_row_run = in_background(cls, cls.with_row.run, cls.GATE, "--check")

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
        self.assert_accepts(self.control.result(), r"^Coverage report is current\.$")
        self.assertRegex(good.read(self.REPORT),
                         rf"CI proves [1-9]\d* of {procedures} procedures \(")

    def test_rejects_proven_claim_for_an_emulation_that_is_not_built(self):
        """COVERAGE.md shows TRR9001.LIN.A as Proven. With its emulation in the
        backlog the generator writes Claimed, so the committed report (and the two
        charts, which draw the proven count) is stale."""
        report = self.good().read(self.REPORT)
        # Proven today: the only way the edit can change the report is the status.
        self.assertRegex(report, r"(?m)^\| \[TRR9001\]\(trr9001/lin/README\.md\) \|.*\| A:P ")
        self.assertNotIn("`TRR9001.LIN.A`", report)
        result = self.not_built_run.result()
        self.assert_rejects(result, self.STALE, exit_code=1)
        self.assertEqual(sorted(found(result, r"^STALE: (\S+) is not current; ")),
                         ["docs/coverage/coverage-dark.svg", "docs/coverage/coverage-light.svg",
                          self.REPORT], result.describe())

    @gatelib.known_gap(
        "cr-defect-heading-without-summary-row",
        gate="research/tools/coverage_report.py --check",
        reason="An entry of detections/RULE_DEFECTS.md that has a section and no Summary row "
               "is not an open defect for the report: open_defects() reads only the Summary "
               "table, so COVERAGE.md keeps `Proven` for the procedures that the named rule "
               "proves, and the gate says the report is current.",
        closes="unplanned")
    def test_gap_defect_section_without_summary_row(self):
        """WANTED: the entry marks the procedures of its rule (COVERAGE.md is stale),
        or the gate refuses an entry that has no Summary row."""
        # The entry is effective when the gate reads it: with its Summary row the
        # report is stale. (Plain assertions: they must not count as the gap.)
        with_row = self.with_row_run.result()
        self.assertEqual(with_row.returncode, 1, with_row.describe())
        self.assertRegex(with_row.stdout, "(?m)" + self.STALE, with_row.describe())
        self.assertIn("\n### L99. PLANTED known-bad artifact", self.no_row.read(self.DEFECTS))
        self.assertNotIn("| [L99](", self.no_row.read(self.DEFECTS))
        self.assert_rejects(self.no_row_run.result(),
                            self.STALE + r"|^coverage_report: .*RULE_DEFECTS\.md.*\bL99\b")


if __name__ == "__main__":
    unittest.main()
