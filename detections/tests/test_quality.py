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

    def test_rejects_extra_slice_line_that_is_not_an_object(self):
        """score_benign.py --extra-slice, with the options of the shadow step that scores
        the pre-emulation audit log of the API server lab, on a capture of audit events
        and one more line that is JSON and not an object (`[]`). Before, the run ended
        with an AttributeError of sigma_eval.flatten, and no line named the capture or
        the line. Now an ERROR line names both, the run exits 1, and no rule is scored
        on the capture. Control: the same capture without that line is scored (the two
        runs start together)."""
        good = self.good()
        name, control = "pre-emulation-audit.log", "pre-emulation-audit-control.log"
        events = [event for case in
                  good.read_jsonl("detections/sigma/T1609/k8s_pod_exec_attach.cases.jsonl")
                  if case["name"] in ("pod-logs-read", "pod-get-describe")
                  for event in case["events"]]
        records = len(events)
        with open(good.tmp_path(name), "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(event) + "\n" for event in events) + "[]\n")
        with open(good.tmp_path(control), "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(event) + "\n" for event in events))
        # The artifact is bad in one way: the last line of the log is a JSON list. The
        # lines before it are audit events (the log is not one JSON array).
        with open(good.tmp_path(name), encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        self.assertEqual(len(lines), records + 1)
        self.assertEqual(json.loads(lines[-1]), [])
        self.assertTrue(all(json.loads(line)["kind"] == "Event" for line in lines[:-1]))
        # The command of the shadow step, on that log.
        self.assert_ci_runs(self.GATE, "--extra-slice /tmp/pre-emulation-audit.log",
                            "--extra-logsource kubernetes/audit", "--extra-label kind-live",
                            "--examples 0")
        runs = [good.start(self.GATE, "--extra-slice", good.tmp_path(log), "--extra-logsource",
                           "kubernetes/audit", "--extra-label", "kind-live", "--examples", "0")
                for log in (name, control)]
        result, accepted = (run.result() for run in runs)
        self.assert_accepts(accepted, rf"^Live capture kind-live \(kubernetes/audit, {records} "
                                      r"event\(s\)\) - shadow only")
        self.assertNotRegex(result.stdout, r"(?m)^Live capture ")
        self.assertEqual(len(re.findall(r"^ERROR", result.stdout, re.MULTILINE)), 1,
                         result.describe())
        self.assert_rejects(result, rf"^ERROR: the live capture \S+/{re.escape(name)}, line "
                                    rf"{records + 1}: JSON that is not an object \(a list\)\. "
                                    r"No rule is scored on the live capture\.$", exit_code=1)

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

    PLANTED_SLICE = "detections/benign/slices/aws/planted-key-case-clash.json"

    def test_rejects_slice_event_keys_that_differ_only_in_letter_case(self):
        """A benign slice whose event holds `eventName` and `EventName`: one event table
        cannot hold it (two values for one column of SQLite). The gate names the slice,
        the event and the two keys in one ERROR line, scores no rule and exits 1.
        (This was the known gap sb-slice-keys-differ-by-case: the gate ended with a
        ValueError of sigma_eval.EventTable, and no line named the slice.)"""
        tree = self.tree()
        tree.plant("quality/slice_keys_differ_by_case/planted-key-case-clash.json",
                   self.PLANTED_SLICE)
        # The artifact is bad in one way: its one event has `eventName` and `EventName`.
        spec = tree.read_json(self.PLANTED_SLICE)
        (template,) = spec["templates"]
        self.assertEqual((spec["count"], sorted(template["event"])),
                         (1, ["EventName", "eventName", "eventSource"]))
        # Without the key `EventName` the corpus loads and the gate scores the slice.
        sound = self.tree()
        sound.plant("quality/slice_keys_differ_by_case/planted-key-case-clash.json",
                    self.PLANTED_SLICE)
        sound.edit_json(self.PLANTED_SLICE,
                        lambda doc: [doc["templates"][0]["event"].pop("EventName"), doc][1])
        scored = sound.run(self.GATE, "--examples", "0")
        self.assert_accepts(scored, r"^  planted-key-case-clash +v1 +synthetic +aws/cloudtrail "
                                    r"+1 event\(s\)$")
        result = self.run_ci(tree)
        # The gate read the planted event: its output names the two keys.
        self.assert_saw(result, r"differ only by case.*\bEventName / eventName\b")
        self.assertNotIn("Traceback", result.output)
        self.assertNotRegex(result.stdout, r"(?m)^Benign corpus: ")
        self.assert_rejects(result, r"^ERROR: the slice planted-key-case-clash v1 \(detections/"
                                    r"benign/slices/aws/planted-key-case-clash\.json\), event 1 "
                                    r"of 1: keys that differ only by case: EventName / eventName, "
                                    r"which SQLite reads as one column name\. No rule is scored on "
                                    r"the benign corpus\.$", exit_code=1)

    def test_rejects_slice_that_no_rule_reads_whose_event_keys_differ_only_in_letter_case(self):
        """The planted slice of the test above with a log source that no rule reads
        (okta/system), as a sequence of two steps: the first event holds `eventName`
        only, the second `eventName` and `EventName`. The gate tests each event of each
        slice before it scores, also of a slice that no rule reads: the ERROR line names
        the slice, the second event and the two keys, with --update and with --check
        --enforce."""
        tree = self.tree()
        tree.plant("quality/slice_keys_differ_by_case/planted-key-case-clash.json",
                   self.PLANTED_SLICE)

        def unread_two_steps(doc):
            event = doc["templates"][0].pop("event")
            first = {key: value for key, value in event.items() if key != "EventName"}
            doc["templates"][0]["events"] = [{"event": first}, {"event": event}]
            doc["logsource"] = {"product": "okta", "service": "system"}
            return doc
        tree.edit_json(self.PLANTED_SLICE, unread_two_steps)
        steps = tree.read_json(self.PLANTED_SLICE)["templates"][0]["events"]
        self.assertEqual([sorted(step["event"]) for step in steps],
                         [["eventName", "eventSource"],
                          ["EventName", "eventName", "eventSource"]])
        self.assertNotRegex("\n".join(tree.read(rel) for rel in
                                       tree.glob("detections/sigma/*/*.yml")),
                            r"(?m)^\s*product: *okta\b")
        update = tree.start(self.GATE, "--update")
        line = (r"^ERROR: the slice planted-key-case-clash v1 \(detections/benign/slices/aws/"
                r"planted-key-case-clash\.json\), event 2 of 2: keys that differ only by case: "
                r"EventName / eventName, which SQLite reads as one column name\. No rule is "
                r"scored on the benign corpus\.$")
        for result in (self.run_ci(tree), update.result()):
            with self.subTest(result.argv[-1]):
                self.assertNotIn("Traceback", result.output)
                self.assert_rejects(result, line, exit_code=1)
        self.assertEqual(tree.read("detections/benign/scores.json"),
                         self.good().read("detections/benign/scores.json"))

    def test_control_slice_events_whose_keys_differ_only_in_letter_case(self):
        """CONTROL of the test above: two events of the planted slice, one with the key
        `eventName` and one with `EventName` (a sequence of two steps). No event holds
        both, so the two keys share one column, and the gate scores the slice."""
        tree = self.tree()
        tree.plant("quality/slice_keys_differ_by_case/planted-key-case-clash.json",
                   self.PLANTED_SLICE)

        def two_events(doc):
            event = doc["templates"][0].pop("event")
            first = {key: value for key, value in event.items() if key != "EventName"}
            second = {key: value for key, value in event.items() if key != "eventName"}
            doc["templates"][0]["events"] = [{"event": first}, {"event": second}]
            return doc
        tree.edit_json(self.PLANTED_SLICE, two_events)
        steps = tree.read_json(self.PLANTED_SLICE)["templates"][0]["events"]
        self.assertEqual([sorted(step["event"]) for step in steps],
                         [["eventName", "eventSource"], ["EventName", "eventSource"]])
        result = tree.run(self.GATE, "--examples", "0")
        self.assertNotIn("Traceback", result.output)
        self.assert_accepts(result, r"^  planted-key-case-clash +v1 +synthetic +aws/cloudtrail "
                                    r"+2 event\(s\)$")

    def test_rejects_reseed_whose_event_keys_differ_only_in_letter_case(self):
        """--reseeds expands each synthetic slice again at later versions. The planted
        slice draws one of two objects for a field: at its version 7 the object
        `{"x": "1"}`, at version 8 `{"x": "1", "X": "2"}`, whose two keys differ only in
        letter case. The committed corpus scores, and the reseed at version 8 is an
        ERROR line that names the slice, its version, the event and the keys."""
        tree = self.tree()
        tree.write("detections/benign/slices/aws/planted-reseed-key-case.json", json.dumps({
            "id": "planted-reseed-key-case", "version": 7,
            "logsource": {"product": "aws", "service": "cloudtrail"}, "fidelity": "synthetic",
            "represents": "PLANTED DEFECT of detections/tests: a reseed draws an object whose "
                          "two keys differ only in letter case",
            "provenance": "synthetic: planted artifact of detections/tests (test_quality.py)",
            "count": 1, "vars": {"obj": [{"x": "1"}, {"x": "1", "X": "2"}]},
            "templates": [{"weight": 1, "event": {
                "eventSource": "sts.amazonaws.com", "eventName": "GetCallerIdentity",
                "detail": "{{obj}}"}}]}, indent=2) + "\n")
        result = tree.run(self.GATE, "--reseeds", "1", "--examples", "0")
        self.assert_saw(result, r"^  planted-reseed-key-case +v7 +synthetic +aws/cloudtrail +1 "
                                r"event\(s\)$")
        self.assertNotIn("Traceback", result.output)
        self.assertNotRegex(result.stdout, r"(?m)^Most hits over ")
        self.assert_rejects(result, r"^ERROR: the slice planted-reseed-key-case v8 \(detections/"
                                    r"benign/slices/aws/planted-reseed-key-case\.json\), event 1 "
                                    r"of 1: keys that differ only by case: detail\.X / detail\.x, "
                                    r"which SQLite reads as one column name \(a reseed\)\. No rule "
                                    r"is scored on the reseeds\.$", exit_code=1)

    def test_rejects_slice_with_an_object_that_holds_a_key_two_times(self):
        """A slice of the benign corpus whose file holds an object with one key two
        times: json keeps only the last value, so the gate would score events that the
        files do not show. Two plants, each in a copy: a synthetic slice whose template
        event holds `eventName` two times, and a recorded slice whose data line 2
        holds `verb` two times. Each is an ERROR line that names the file (and the
        line), the run scores no rule and exits 1. (Before, the gate read each object
        without a word.)"""
        spec = {"id": "planted-twice", "version": 1,
                "logsource": {"product": "aws", "service": "cloudtrail"},
                "fidelity": "synthetic",
                "represents": "PLANTED DEFECT of detections/tests: a key two times",
                "provenance": "synthetic: planted artifact of detections/tests (test_quality.py)",
                "count": 1, "templates": [{"weight": 1, "event": {
                    "eventSource": "sts.amazonaws.com", "eventName": "GetCallerIdentity"}}]}
        synthetic = json.dumps(spec).replace('"eventName": "GetCallerIdentity"',
                                             '"eventName": "AssumeRole", "eventName": '
                                             '"GetCallerIdentity"')
        recorded = dict(spec, fidelity="recorded", data="planted-twice.jsonl",
                        provenance="recorded: planted artifact of detections/tests "
                                   "(test_quality.py)",
                        logsource={"product": "kubernetes", "service": "audit"})
        for key in ("count", "templates"):
            recorded.pop(key)
        event = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "verb": "get"}
        data = (json.dumps(event) + "\n" + json.dumps(event)[:-1] + ', "verb": "list"}\n')
        plants = {
            "synthetic": ({"detections/benign/slices/aws/planted-twice.json": synthetic},
                          r"detections/benign/slices/aws/planted-twice\.json: an object holds "
                          r"the key 'eventName' two times"),
            "recorded": ({"detections/benign/slices/kubernetes/planted-twice.json":
                          json.dumps(recorded),
                          "detections/benign/slices/kubernetes/planted-twice.jsonl": data},
                         r"detections/benign/slices/kubernetes/planted-twice\.jsonl, line 2: an "
                         r"object holds the key 'verb' two times")}
        runs = []
        for label, (files, problem) in plants.items():
            tree = self.tree()
            for rel, text in files.items():
                tree.write(rel, text)
            runs.append((label, problem, tree.start(self.GATE, "--check", "--enforce")))
        for label, problem, pending in runs:
            with self.subTest(label):
                result = pending.result()
                self.assertNotIn("Traceback", result.output)
                self.assertNotRegex(result.stdout, r"(?m)^Benign corpus: ")
                self.assert_rejects(result, r"^ERROR: the benign corpus: " + problem
                                    + r" \(json keeps only the last value\)\. No rule is "
                                      r"scored on the benign corpus\.$", exit_code=1)

    def extra_slice_runs(self, captures):
        """Runs of --extra-slice with the options of the shadow step, started together:
        {label: (capture path, result)}. `captures`: {label: the bytes of the capture,
        None for a directory, or False for a path that does not exist}."""
        good = self.good()
        runs = {}
        for n, (label, data) in enumerate(captures.items()):
            path = good.tmp_path(f"capture-{n}.log")
            if data is None:
                os.makedirs(path, exist_ok=True)
            elif data is False:
                self.assertFalse(os.path.lexists(path))
            else:
                with open(path, "wb") as fh:
                    fh.write(data)
            runs[label] = (path, good.start(self.GATE, "--extra-slice", path,
                                            "--extra-logsource", "kubernetes/audit",
                                            "--extra-label", "kind-live", "--examples", "0"))
        return {label: (path, pending.result()) for label, (path, pending) in runs.items()}

    def test_rejects_extra_slice_that_the_loader_cannot_read(self):
        """--extra-slice on a capture that is a directory or does not exist, that holds a
        byte that is not UTF-8, whose line 1 or line 2 starts with the byte order mark of
        UTF-8, or whose audit event holds two keys that differ only in letter case (also
        in a nested object), or that holds JSON that the gate cannot read (too deep for
        json or for flatten(), a number with too many digits, in a line or in one
        document), or whose line 2 or 3 is not JSON and is not a line that a capture
        cut (NUL bytes before an event, also on the last line without a line feed; a
        cut line before other lines, and as the last line with a line feed). Each is
        an ERROR line that names the capture (and the line), the run exits 1, and no
        rule is scored on the capture. Before roadmap item R2d the first three ended
        with a traceback, the fourth lost line 1 without a word (and before the check
        of the corrections, the mark at line 2 lost line 2), the key clashes ended with a
        ValueError of sigma_eval.EventTable, the JSON too deep or too long with a
        traceback, and the document was a capture of no event; before the second check
        of the corrections, a line that json refused was skipped as a cut line, and its
        event was lost without a word. Controls: a capture whose two events hold the
        keys `verb` and `Verb` (no event holds both) is scored, and so is a capture
        whose line holds U+2028, U+2029 and U+0085 in a string (before R2d
        str.splitlines() cut the line, and the event was lost without a word), and a
        capture whose last line is cut and has no line feed (the two events before it
        are scored). The last line without a line end is skipped only when it is cut
        JSON, with the verdicts of the rows of K8sValidator for the same lines: an
        event and the start of an event, U+200B after the brace, a carriage return
        alone at the end, and a byte that is not UTF-8 before the end or at the end are
        ERROR lines (before, the first two lost an event without a word); a cut inside
        an escape, a blank before the brace and a cut inside a character of UTF-8 are
        skipped (before, the last was an ERROR line)."""
        good = self.good()
        events = [event for case in
                  good.read_jsonl("detections/sigma/T1609/k8s_pod_exec_attach.cases.jsonl")
                  if case["name"] in ("pod-logs-read", "pod-get-describe")
                  for event in case["events"]]
        lines = [json.dumps(event).encode() + b"\n" for event in events]
        inside = lines[1].replace(b'"verb": "', b'"verb": "\xe9', 1)
        self.assertNotEqual(inside, lines[1])
        at = inside.index(b"\xe9") + 1      # the character of the byte, from 1
        respelled = {("Verb" if key == "verb" else key): value for key, value in events[1].items()}
        nested = json.loads(lines[1])
        nested["objectRef"]["Name"] = nested["objectRef"]["name"]
        deep = {}
        for _ in range(1500):
            deep = {"a": deep}
        separators = dict(events[1], userAgent="kubectl/v1.31 \u2028 \u2029 \u0085 x")
        cut = b'{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "verb": "ge'
        twice = json.dumps(events[1])[:-1].encode() + b', "verb": "create"}'
        event = lines[1].rstrip(b"\n")
        escaped = json.dumps(dict(events[1], userAgent="a&b")).replace("&", "\\u0026").encode()
        not_cut = "; the line is not the start of one JSON object, so a capture did not cut it"
        try:
            json.loads(cut)
        except json.JSONDecodeError as e:
            cut_error = f"not JSON ({e.msg}, at character {e.colno})"
        runs = self.extra_slice_runs({
            "a directory": None,
            "a path that does not exist": False,
            "not UTF-8": lines[0] + inside,
            "a byte order mark": b"\xef\xbb\xbf" + b"".join(lines),
            # Two captures joined: the mark at the start of line 2. json refuses that
            # line (a reader that skipped each line that json refused lost the event).
            "a byte order mark at line 2": lines[0] + b"\xef\xbb\xbf" + lines[1],
            "two keys of one event": lines[0] + json.dumps(dict(events[1], Verb="get")).encode()
            + b"\n",
            "two events": lines[0] + json.dumps(respelled).encode() + b"\n",
            "two keys of a nested object": lines[0] + json.dumps(nested).encode() + b"\n",
            "an object too deep to flatten": lines[0]
            + json.dumps(dict(events[1], deep=deep)).encode() + b"\n",
            # Python 3.13 and older stop json.loads() at the limit of the recursion; from
            # Python 3.14 (with a large stack) json reads it, and flatten() stops.
            "JSON too deep": lines[0] + b'{"a": ' * 100000 + b"1" + b"}" * 100000 + b"\n",
            "a number with too many digits": lines[0] + b'{"n": 1' + b"0" * 5000 + b"}\n",
            # No line of the document is JSON alone: the line `2, 1000...0]` is the
            # number 2 and more, so json does not read the long number there.
            "one document with a number with too many digits": b"[1,\n2, 1" + b"0" * 5000
            + b"]\n",
            # A line of the capture ends at a line break of the file: U+2028, U+2029 and
            # U+0085 in a JSON string are characters of the line.
            "line separators in a string": lines[0]
            + json.dumps(separators, ensure_ascii=False).encode() + b"\n",
            # A capture can cut only its last line, at its end: NUL bytes before an
            # event (a copytruncate rotation leaves them; also on the last line, which
            # then does not start with "{"), a cut line before other lines and a cut
            # line with a line feed are errors. The last line, cut and without its
            # line feed, is skipped (a control).
            "NUL bytes before an event at line 2": lines[0] + b"\x00" * 8 + lines[1],
            "NUL bytes before an event on the last line without a line feed": lines[0]
            + lines[1] + b"\x00" * 8 + lines[1].rstrip(b"\n"),
            "a cut line before other lines": lines[0] + cut + b"\n" + lines[1],
            "a cut last line with a line feed": lines[0] + lines[1] + cut + b"\n",
            "a cut last line": lines[0] + lines[1] + cut,
            # json keeps only the last value of a key that an object holds two times, so
            # the event that the gate scored was not the event of the line.
            "an event that holds a key two times": lines[0] + twice + b"\n",
            "an array with an event that holds a key two times": b"[" + lines[0].rstrip()
            + b", " + twice + b"]\n",
            # The last line without a line end is skipped only when it is cut JSON (the
            # rows of K8sValidator, with the same verdicts): an event and the start of an
            # event, U+200B after the brace, a carriage return alone at the end (a line
            # end), a byte that is not UTF-8 before the end or that starts no character
            # at the end are errors; a cut inside an escape of Go, a blank before the
            # brace and a cut inside a character of UTF-8 are skipped.
            "an event and the start of an event on the last line": lines[0] + lines[1]
            + event + b'{"kind": "Ev',
            "U+200B after the brace on the last line": lines[0] + lines[1] + b"{\xe2\x80\x8b"
            + event[1:],
            "a carriage return alone at the end of the last line": lines[0] + lines[1] + cut
            + b"\r",
            "a byte that is not UTF-8 before the end of the last line": lines[0] + lines[1]
            + cut.replace(b"Event", b"Ev\xe9ent"),
            "a byte that is not UTF-8 at the end of the last line": lines[0] + lines[1] + cut
            + b"\xff",
            "a cut inside an escape on the last line": lines[0] + lines[1]
            + escaped[:escaped.index(b"\\u0026") + 4],
            "a blank before the brace of a cut last line": lines[0] + lines[1] + b" " + cut,
            "a cut inside a character of UTF-8 on the last line": lines[0] + lines[1] + cut
            + b"\xc3"})
        cannot_read = {
            "an object too deep to flatten": r", line 2: JSON that the gate cannot read "
                                             r"\(RecursionError: [^)]*\)",
            "JSON too deep": r", line 2: JSON that the gate cannot read \(RecursionError: "
                             r"[^)]*\)",
            "a number with too many digits": r", line 2: JSON that the gate cannot read "
                                             r"\(ValueError: Exceeds the limit \(4300 digits\)"
                                             r"[^)]*\)",
            "one document with a number with too many digits":
                r": JSON that the gate cannot read \(ValueError: Exceeds the limit \(4300 "
                r"digits\)[^)]*\)"}
        wanted = {
            "a directory": " is a directory, not a file",
            "a path that does not exist": " cannot be read (No such file or directory)",
            "not UTF-8": f", line 2: bytes that are not UTF-8 (the byte 0xe9 at character "
                         f"{at} of the line)",
            "a byte order mark": ", line 1: the line starts with the byte order mark of UTF-8 "
                                 "(EF BB BF)",
            "a byte order mark at line 2": ", line 2: the line starts with the byte order mark "
                                           "of UTF-8 (EF BB BF)",
            "two keys of one event": ", line 2: an event that one event table cannot hold: keys "
                                     "that differ only by case: Verb / verb, which SQLite reads "
                                     "as one column name",
            "two keys of a nested object": ", line 2: an event that one event table cannot "
                                           "hold: keys that differ only by case: objectRef.Name "
                                           "/ objectRef.name, which SQLite reads as one column "
                                           "name",
            "NUL bytes before an event at line 2": ", line 2: not JSON (Expecting value, at "
                                                   "character 1)",
            "NUL bytes before an event on the last line without a line feed":
                ", line 3: not JSON (Expecting value, at character 1)",
            "a cut line before other lines": f", line 2: {cut_error}; a capture can cut only "
                                             "the last line of a log, and a cut line has no "
                                             "line feed",
            "a cut last line with a line feed": f", line 3: {cut_error}; a capture can cut "
                                                "only the last line of a log, and a cut line "
                                                "has no line feed",
            "an event that holds a key two times": ", line 2: an object holds the key 'verb' two "
                                                   "times (json keeps only the last value)",
            "an array with an event that holds a key two times":
                ", element 2 of the array: an object holds the key 'verb' two times (json keeps "
                "only the last value)",
            "an event and the start of an event on the last line":
                f", line 3: not JSON (Extra data, at character {len(event) + 1}){not_cut}",
            "U+200B after the brace on the last line":
                ", line 3: not JSON (Expecting property name enclosed in double quotes, at "
                f"character 2){not_cut}",
            "a carriage return alone at the end of the last line":
                f", line 3: {cut_error}; a capture can cut only the last line of a log, and a "
                "cut line has no line feed",
            "a byte that is not UTF-8 before the end of the last line":
                ", line 3: bytes that are not UTF-8 (the byte 0xe9 at character 13 of the line)",
            "a byte that is not UTF-8 at the end of the last line":
                f", line 3: bytes that are not UTF-8 (the byte 0xff at character {len(cut) + 1} "
                "of the line)"}
        for label, (path, result) in runs.items():
            with self.subTest(label):
                self.assertNotIn("Traceback", result.output)
                if label in ("two events", "line separators in a string", "a cut last line",
                             "a cut inside an escape on the last line",
                             "a blank before the brace of a cut last line",
                             "a cut inside a character of UTF-8 on the last line"):
                    self.assert_accepts(result, r"^Live capture kind-live \(kubernetes/audit, 2 "
                                                r"event\(s\)\) - shadow only")
                    continue
                self.assertNotRegex(result.stdout, r"(?m)^Live capture ")
                self.assertEqual(len(re.findall(r"^ERROR", result.stdout, re.M)), 1,
                                 result.describe())
                problem = cannot_read.get(label) or re.escape(wanted[label])
                self.assert_rejects(result, "^ERROR: the live capture " + re.escape(path)
                                    + problem + r"\. No rule is scored on the live capture\.$",
                                    exit_code=1)


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

    def test_rejects_case_whose_one_record_spells_a_field_in_another_letter_case(self):
        """Planted cases. In T1609, a case of two records: a quiet record that holds
        `objectRef.resource` (its subresource is `log`) and the exec record with
        `ObjectRef` in the place of `objectRef`. The rule fires only on the second
        record, through SQLite, which reads `ObjectRef.resource` as the field. The test
        is for each record: the first record has the field, and the second does not.
        In T1620 (a correlation), the execveat event spells its group-by key `PID` in
        one case and its time `Timestamp` in another: the compiled correlation reads
        each as the key that it reads, Lucene, Splunk and ES|QL do not. A planted
        value_count rule (known_bad/quality/counted_field_case) whose cases spell its
        counted field `User`. Each is a FAIL that names the case, the field and the key;
        the time has its own text, because the rule writes no time field. (Before
        roadmap item R2d the table refused each case; the first R2d text read the keys
        of the whole case and skipped the first case, and read no field of a
        correlation that is not a field of an item.)"""
        tree = self.tree()
        exec_rel = "detections/sigma/T1609/k8s_pod_exec_attach.cases.jsonl"
        exec_case = next(c for c in tree.read_jsonl(exec_rel)
                         if c["name"] == "exec-websocket-get-procA")
        (record,) = exec_case["events"]
        self.assertEqual(record["objectRef"]["subresource"], "exec")
        quiet = json.loads(json.dumps(record))
        quiet["objectRef"]["subresource"] = "log"
        respelled = {("ObjectRef" if key == "objectRef" else key): value
                     for key, value in record.items()}
        tree.append(exec_rel, json.dumps({
            "name": "planted-ObjectRef-with-decoy", "kind": "positive", "why": "planted",
            "events": [quiet, respelled]}) + "\n")
        memfd_rel = "detections/sigma/T1620/memfd_create_execveat.cases.jsonl"
        memfd_case = tree.read_jsonl(memfd_rel)[0]
        first, second = memfd_case["events"]
        self.assertEqual(memfd_case["kind"], "positive")
        self.assertEqual(first["pid"], second["pid"])
        second = {("PID" if key == "pid" else key): value for key, value in second.items()}
        tree.append(memfd_rel, json.dumps({
            "name": "planted-group-by-PID", "kind": "positive", "why": "planted",
            "events": [first, second]}) + "\n")
        _, second = memfd_case["events"]
        self.assertIn("timestamp", second)
        second = {("Timestamp" if key == "timestamp" else key): value
                  for key, value in second.items()}
        tree.append(memfd_rel, json.dumps({
            "name": "planted-time-Timestamp", "kind": "positive", "why": "planted",
            "events": [first, second]}) + "\n")
        tree.plant("quality/counted_field_case", "detections/sigma/T9999")
        counted = "detections/sigma/T9999/planted_counted_field.yml"
        self.assertTrue(all("User" in event and "user" not in event
                            for case in tree.read_jsonl(counted[:-4] + ".cases.jsonl")
                            for event in case["events"]))
        # The oracle judges the cases: each positive fires, and the near-miss of the
        # planted rule is a near-miss on threshold.
        cases = tree.run("detections/rule_cases.py", "detections/sigma/T1609/k8s_pod_exec_attach.yml",
                         "detections/sigma/T1620/memfd_create_execveat.yml", counted)
        self.assert_accepts(cases, r"^All cases hold \(3 rule file\(s\)\)\.$")
        self.assert_saw(cases, r"^ok    T1609/k8s_pod_exec_attach\.yml :: positive   "
                               r"planted-ObjectRef-with-decoy: fires$")
        for name in ("planted-group-by-PID", "planted-time-Timestamp"):
            self.assert_saw(cases, r"^ok    T1620/memfd_create_execveat\.yml :: positive   "
                                   rf"{name}: fires$")
        self.assert_saw(cases, r"^ok    T9999/planted_counted_field\.yml :: near-miss  "
                               r"one-user-twice-spelled-User: near-miss on threshold$")
        result = tree.run(self.GATE, "detections/sigma/T1609/k8s_pod_exec_attach.yml",
                          "detections/sigma/T1620/memfd_create_execveat.yml", counted)
        for rule, field, key, case in (
                ("T1609/k8s_pod_exec_attach.yml", "objectRef.resource", "ObjectRef.resource",
                 "positive planted-ObjectRef-with-decoy"),
                ("T1609/k8s_pod_exec_attach.yml", "objectRef.subresource",
                 "ObjectRef.subresource", "positive planted-ObjectRef-with-decoy"),
                ("T1620/memfd_create_execveat.yml", "pid", "PID", "positive planted-group-by-PID"),
                ("T9999/planted_counted_field.yml", "user", "User",
                 "positive two-users-spelled-User")):
            self.assert_rejects(result, rf"^FAIL  {re.escape(rule)} :: case {case}: the rule reads "
                                        rf"`{re.escape(field)}`, and the records carry "
                                        rf"`{re.escape(key)}`: SQLite matches column names",
                                exit_code=1)
        self.assert_rejects(result, r"^FAIL  T1620/memfd_create_execveat\.yml :: case positive "
                                    r"planted-time-Timestamp: the records carry the time as "
                                    r"`Timestamp`, and the offline correlation reads the time from "
                                    r"the key `timestamp` \(the timestamp field of the SQLite "
                                    r"backend of pySigma\): SQLite matches column names without "
                                    r"regard to case, so it reads that key\. The rule writes no "
                                    r"time field, and each other backend reads its own\. Write the "
                                    r"time of the case as `timestamp`$", exit_code=1)
        self.assertEqual(len(found(result, r"^FAIL .*$")), 5, result.describe())

    def test_rejects_case_that_spells_a_time_item_of_a_base_in_another_letter_case(self):
        """Planted in a copy: the execveat base of the correlation of T1620 also reads
        `timestamp` as an item field (`timestamp|startswith: '20'`), and a case spells
        it `Timestamp` in its second record. The rule reads the field, so the FAIL has
        the text of a field of the rule (`the rule reads `timestamp``), not the text
        of the time that a rule does not write. (A gate that gave the time text to
        each correlation said that the rule writes no time field, which is false
        here.)"""
        tree = self.tree()
        rule = "detections/sigma/T1620/memfd_create_execveat.yml"
        base = ("  execveat_syscall:\n"
                "    type: SYSCALL\n"
                "    syscall: execveat\n")
        text = tree.read(rule)
        self.assertEqual(text.count(base), 1)
        tree.write(rule, text.replace(base, base + "    timestamp|startswith: '20'\n"))
        sidecar = rule[:-4] + ".cases.jsonl"
        first, second = tree.read_jsonl(sidecar)[0]["events"]
        self.assertIn("timestamp", second)
        second = {("Timestamp" if key == "timestamp" else key): value
                  for key, value in second.items()}
        tree.append(sidecar, json.dumps({
            "name": "planted-Timestamp", "kind": "positive", "why": "planted",
            "events": [first, second]}) + "\n")
        result = tree.run(self.GATE, rule)
        self.assert_rejects(result, r"^FAIL  T1620/memfd_create_execveat\.yml :: case positive "
                                    r"planted-Timestamp: the rule reads `timestamp`, and the "
                                    r"records carry `Timestamp`: SQLite matches column names",
                            exit_code=1)
        self.assertNotIn("The rule writes no time field", result.stdout)
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())


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
    # A sidecar case with an entry in the expected list (variant multi, a loss of
    # record 0), of a rule that has one more entry; and a rule whose one entry names
    # an open entry of RULE_DEFECTS.md (K43).
    LISTED = "T1685/k8s_enforcer_workload_removed.yml"
    LISTED_CASE = "scale-smp-root-alias-retain-keys-with-count"
    TRACKED = "T1098.006/k8s_rbac_privileged_grant.yml"
    # A rule file that is not in the repository, for an entry of a rule that is gone.
    GONE = "T9999/gone.yml"
    # The closing line of a run whose only problems are problems of the expected list.
    LIST_FAILED = ("\nFAILED: 1 problem(s) of the expected list name no rule of this run (the "
                   "list itself, or an entry of a rule file that is not there).\n")
    # The rows of the cloud MANIFEST of the copy for each rule file (`T<id>/<file>.yml`):
    # the gate reads the attack fixture and the benign fixture of each row.
    MANIFEST_ROWS = (
        "import collections, json, sys\n"
        "sys.path.insert(0, 'detections')\n"
        "import validate_cloud_detections as cloud\n"
        "print(json.dumps(collections.Counter(f'{row[1]}/{row[2]}' for row in cloud.MANIFEST)))\n")

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # CI passes --require-re2 (google-re2 is not in detections/requirements.txt).
        # Pass it here too when the tests' Python has RE2, as ProviderMappings does.
        cls.ci_arguments = ("--require-re2",) if cls.RE2 else ()
        # One full run takes about 10 s: start it now.
        cls.full_run = cls.in_background(cls.good().run, cls.GATE, *cls.ci_arguments)
        # A second full run, on a copy whose list holds an entry of a rule file that
        # is not there (test_rejects_expected_entry_of_a_rule_file_that_is_gone).
        cls.gone = cls.class_tree()
        cls.gone.edit_json(cls.EXPECTED, cls.add_entry_of_a_rule_that_is_gone)
        cls.gone_run = cls.in_background(cls.gone.run, cls.GATE, *cls.ci_arguments)

    @classmethod
    def add_entry_of_a_rule_that_is_gone(cls, doc):
        doc["expected"].append(dict(doc["expected"][0], rule=cls.GONE))

    def entry(self, tree, rule, case=None):
        """The one entry of the expected list of the copy for `rule` and, when it is
        given, for the event set `case` (a rule can have more than one entry)."""
        entries = [e for e in tree.read_json(self.EXPECTED)["expected"]
                   if e["rule"] == rule and case in (None, e["name"])]
        self.assertEqual(len(entries), 1, f"the test needs one expected entry for {rule}"
                                          + (f", {case}" if case else ""))
        return entries[0]

    def change_entry(self, tree, rule, case=None, **values):
        """Change the one entry of the expected list of the copy for `rule` (and
        `case`)."""
        self.entry(tree, rule, case)

        def change(doc):
            next(e for e in doc["expected"]
                 if e["rule"] == rule and case in (None, e["name"])).update(values)
        tree.edit_json(self.EXPECTED, change)

    def entries_of(self, tree, rule):
        """The count of the entries of the expected list of the copy for `rule`."""
        return sum(1 for e in tree.read_json(self.EXPECTED)["expected"] if e["rule"] == rule)

    def test_ci_runs_the_self_test_and_every_rule_with_re2(self):
        self.assertEqual(gatelib.ci_commands(self.GATE), [
            "python3 detections/check_variants.py --require-re2 --self-test",
            "python3 detections/check_variants.py --require-re2 --check-doc",
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
        version has a wheel. Without the module the three gate steps stop
        (--require-re2: test_ci_runs_the_self_test_and_every_rule_with_re2)."""
        import yaml     # PyYAML: in detections/requirements.txt

        with open(os.path.join(gatelib.REPO, ".github", "workflows", "detection-quality.yml"),
                  encoding="utf-8") as fh:
            job = yaml.safe_load(fh)["jobs"]["representation-variants"]
        self.assertNotIn("if", job)
        self.assertNotIn("needs", job)
        self.assertNotIn("continue-on-error", job)
        gate_steps = [s for s in job["steps"] if "detections/check_variants.py" in s.get("run", "")]
        self.assertEqual(len(gate_steps), 3)
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
        copy, on each event set of the rule and on no other one (each case of its
        sidecar, and the attack fixture and the benign fixture of each of its rows
        in the cloud MANIFEST), and each entry of the expected list is a difference
        that it shows."""
        good = self.good()
        rules = rule_keys(good)
        known = len(good.read_json(self.EXPECTED)["expected"])
        self.assertGreater(known, 0, "the expected list is empty: the control of the "
                                     "stale-entry test below would be vacuous")
        result = self.full_run.result()
        self.assert_accepts(result, self.OK.format(rules=len(rules), known=known))
        self.assertEqual(len(found(result, r"^known T\S+\.yml :: .*, expected \(")), known)
        # The event sets that the copy holds for each rule, counted without the gate.
        probe = good.run_python(self.MANIFEST_ROWS)
        self.assertEqual(probe.returncode, 0, probe.describe())
        rows = json.loads(probe.stdout)
        self.assertGreater(sum(rows.values()), 0, "the cloud MANIFEST of the copy is empty")
        self.assertLessEqual(set(rows), set(rules), "a MANIFEST row names no rule of the copy")
        wanted = {}
        for rule in rules:
            sidecar = "detections/sigma/" + rule[:-len(".yml")] + ".cases.jsonl"
            cases = len(good.read_jsonl(sidecar)) if good.exists(sidecar) else 0
            wanted[rule] = cases + 2 * rows.get(rule, 0)
        self.assertGreater(sum(1 for rule in rules if rule in rows and wanted[rule] > 2 * rows[rule]),
                           0, "no rule of the copy has a sidecar and a MANIFEST row")
        checked = found(result, r"^ok    (T\S+\.yml): (\d+) event set\(s\), same hits as ")
        self.assertEqual(sorted(rule for rule, _ in checked), rules)
        self.assertEqual({rule: int(count) for rule, count in checked}, wanted,
                         "the gate did not read each case and each fixture of a rule")
        sets = int(re.search(r"(?m)^OK: \d+ rule\(s\), (\d+) event set", result.stdout).group(1))
        self.assertEqual(sets, sum(wanted.values()))
        if not self.RE2:
            # Without google-re2 the report must say that the variant did not run.
            self.assertIn("\nNOT RUN: variant re2: ", result.stdout)

    def test_control_self_test_passes(self):
        """CONTROL of the job's first step (--self-test): the golden probes and the
        constructed rules."""
        self.assert_accepts(self.good().run(self.GATE, *self.ci_arguments, "--self-test"),
                            r"^self-test: all [1-9]\d* checks hold$")

    def test_probes_table_is_one_text_with_and_without_re2(self):
        """--probes prints the golden probes as a Markdown table (the probe table of
        detections/SEMANTICS.md is this text). A row holds the probe, its statement,
        its detection, its record and one answer for the default run and for each
        variant, re2 too, also where the module is missing: the same text on a
        development machine and in CI. Each row has the same count of cells: a `|`
        in a statement or a detection (`|contains`) is escaped, or it would end the
        cell."""
        result = self.good().run(self.GATE, *self.ci_arguments, "--probes")
        self.assert_accepts(result, r"^\| probe \| statement \| detection \| record \| default "
                                    r"\| compact \| sorted \| multi \| cs_like \| re2 \|$")
        rows = found(result, r"^\| .*\|$")
        self.assertGreater(len(rows), 20, "the table holds fewer rows than the probes")
        self.assertEqual({len(re.split(r"(?<!\\)\|", row)) for row in rows}, {12},
                         "a row does not have 10 cells:\n" + result.stdout)
        self.assertIn("| `contains-case` | \\|contains ignores ASCII case (LIKE) | "
                      "`verb\\|contains: 'Create'` | `{\"verb\": \"create\"}` | fires | fires "
                      "| fires | fires | quiet | fires |\n", result.stdout)
        self.assertRegex(result.stdout, r"(?m)^\| `re-space-class` \| .* \| quiet \|$")
        self.assertNotIn("WANT", result.stdout)
        if not self.RE2:
            self.assertIn("\nNOT RUN: variant re2: ", result.stdout)

    # -- the probe table of detections/SEMANTICS.md (--check-doc) ------------------

    DOC = "detections/SEMANTICS.md"
    DOC_OK = (r"^OK: detections/SEMANTICS\.md: the table of the {probes} golden probes is "
              r"current, and each of the [1-9]\d* probe name\(s\) in the text is a row of it\.$")
    DOC_FAILED = ("\nFAILED: detections/SEMANTICS.md does not agree with the golden probes: "
                  "1 problem(s).\n")

    def probe_rows(self, tree):
        """The rows of the probe table of the document of the copy."""
        text = tree.read(self.DOC)
        block = text[text.index("<!-- probes:begin -->"):text.index("<!-- probes:end -->")]
        return re.findall(r"(?m)^\| `[a-z0-9-]+` \|.*\|$", block)

    def test_control_probe_table_of_the_document_is_current(self):
        """CONTROL of the job's second step (--check-doc): the unmodified copy passes,
        for each row of the probe table of detections/SEMANTICS.md."""
        good = self.good()
        rows = self.probe_rows(good)
        self.assertGreater(len(rows), 20, "the document holds no probe table: vacuous")
        self.assert_accepts(good.run(self.GATE, *self.ci_arguments, "--check-doc"),
                            self.DOC_OK.format(probes=len(rows)))

    def test_rejects_stale_probe_table_in_the_document(self):
        """vr-stale-probe-table. Inside the generated probe table of
        detections/SEMANTICS.md, the default answer of the row `eq-case` is changed by
        hand from `quiet` to `fires`: the document then says that equality ignores
        letter case, and the gate proves the opposite on each run."""
        tree = self.tree()
        row = next(r for r in self.probe_rows(tree) if r.startswith("| `eq-case` |"))
        answers = "| quiet | quiet | quiet | quiet | quiet | quiet |"
        self.assertTrue(row.endswith(answers), row)
        planted = row[:-len(answers)] + "| fires | quiet | quiet | quiet | quiet | quiet |"
        tree.replace(self.DOC, row + "\n", planted + "\n")
        result = tree.run(self.GATE, *self.ci_arguments, "--check-doc")
        self.assert_rejects(
            result, r"^STALE: the probe table of detections/SEMANTICS\.md differs from the "
                    r"golden probes of detections/check_variants\.py \(the table PROBES\); run "
                    r"python3 detections/check_variants\.py --write-doc$", exit_code=1)
        # The report shows the row of the document and the row of the run.
        self.assertIn("\n    -" + planted + "\n    +" + row + "\n", result.stdout)
        # One planted defect: one problem, and no other row differs.
        self.assertEqual(len(found(result, r"^    [-+]\| ")), 2, result.describe())
        self.assertIn(self.DOC_FAILED, result.stdout)

    def test_rejects_probe_name_in_the_document_that_is_not_a_probe(self):
        """vr-unknown-probe-name. The text of detections/SEMANTICS.md proves a statement
        with the name of a golden probe. A sentence is added that names
        `eq-letter-case`, which is not a probe: nothing proves that sentence (a probe
        was renamed or deleted, and the text did not follow)."""
        tree = self.tree()
        tree.append(self.DOC, "\nPLANTED: equality folds letter case (probe `eq-letter-case`).\n")
        result = tree.run(self.GATE, *self.ci_arguments, "--check-doc")
        self.assert_rejects(
            result, r"^UNKNOWN: detections/SEMANTICS\.md line \d+ names the probe "
                    r"`eq-letter-case`, and the table PROBES holds no such probe\.", exit_code=1)
        self.assertEqual(len(found(result, r"^(STALE|UNKNOWN|UNUSED|ERROR|MISSING): .*$")), 1,
                         result.describe())
        self.assertIn(self.DOC_FAILED, result.stdout)

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
        report_path = tree.out("variants.json")
        result = tree.run(self.GATE, "--json", report_path, "detections/sigma/" + rule)
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
        # no blanks), and no other row fails. The real rule has no entry in the
        # expected list (closed entry C20), so no row of the run is `known`.
        self.assertEqual(found(result, r"^FAIL  (.*?): \[(\w+)\] "),
                         [(f"{rule} :: case positive {case}", "compact"),
                          (f"{rule} :: case positive {case}", "sorted")])
        self.assertEqual(len(found(result, r"^FAIL .*$")), 2, result.describe())
        self.assertEqual(self.entries_of(tree, rule), 0)
        self.assertNotRegex(result.stdout, r"(?m)^known ")
        # The report of --json holds the same two differences, and says that each
        # variant that needs no module ran: `multi` gives no difference here because it
        # ran on each list of the rule, not because it did not run.
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual([(d["variant"], d["name"]) for d in report["differences"]],
                         [("compact", case), ("sorted", case)])
        self.assertEqual([v for v in ("compact", "sorted", "multi", "cs_like")
                          if report["variants"].get(v, {}).get("ran")],
                         ["compact", "sorted", "multi", "cs_like"])

    def test_rejects_expected_entry_that_shows_no_difference(self):
        """vr-stale-entry. An entry of the expected list for a difference that the run
        does not show (here: a case name that the sidecar does not hold). A list that
        may hold such entries can excuse a later difference in advance."""
        tree = self.tree()
        rule = self.LISTED
        self.change_entry(tree, rule, self.LISTED_CASE, name="a-case-that-is-not-in-the-sidecar")
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
        self.change_entry(tree, rule, self.LISTED_CASE, reason="KEY_ORDER")
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
        self.assertEqual(self.entry(tree, rule, self.LISTED_CASE)["lost"], [[0]])
        self.change_entry(tree, rule, self.LISTED_CASE, lost=[[1]])
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
        self.change_entry(tree, rule, self.LISTED_CASE, why=" ")
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

    def test_rejects_expected_entry_whose_defect_names_another_rule(self):
        """vr-entry-defect-of-another-rule. The `defect` of an entry must be an open
        entry of RULE_DEFECTS.md that names the rule of the entry. `C6` is open, and
        it is the entry of another rule: an entry that points to it says that the
        difference is tracked, and nothing tracks it."""
        tree = self.tree()
        rule = self.TRACKED
        stem = os.path.basename(rule)[:-len(".yml")]
        defects = tree.read("detections/RULE_DEFECTS.md")
        self.assertIn("\n| [C6](#c6-", defects, "C6 is not a row of the Summary table")
        start = defects.index("\n### C6. ")
        section = defects[start:defects.index("\n### ", start + 1)]
        self.assertNotIn(stem, section, "the entry C6 names the rule: the test needs another entry")
        self.change_entry(tree, rule, defect="C6")
        result = tree.run(self.GATE, "detections/sigma/" + rule)
        self.assert_rejects(result, rf"^FAIL  {re.escape(rule)}: expected \[sorted\] case \S+: "
                                    rf"the entry C6 of RULE_DEFECTS\.md does not name {stem}$",
                            exit_code=1)
        # The difference that the entry excused before is now new.
        self.assertRegex(result.stdout, rf"(?m)^FAIL  {re.escape(rule)} :: case positive \S+: "
                                        r"\[sorted\] loss: .* \(listed, but the entry does not "
                                        r"hold\)$")

    def test_rejects_expected_entry_of_a_rule_file_that_is_gone(self):
        """vr-entry-of-a-rule-that-is-gone. On a run of every rule, an entry whose rule
        file is not in the repository is stale: the rule was deleted or renamed, and
        the entry would excuse a difference of a later rule file with that name. The
        closing line counts it as a problem of the list, not as one of the rules
        that the run checked."""
        tree = self.gone
        rules = rule_keys(tree)
        self.assertNotIn(self.GONE, rules)
        self.assertFalse(tree.exists("detections/sigma/" + self.GONE))
        result = self.gone_run.result()
        self.assert_rejects(result, rf"^FAIL  {re.escape(self.GONE)}: expected \[\w+\] \w+ \S+: "
                                    r"stale: no rule file detections/sigma/"
                                    rf"{re.escape(self.GONE)}; delete the entry$", exit_code=1)
        # One planted defect: one problem. Each rule of the copy passed, and the
        # entry that was copied still holds for its own rule.
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())
        self.assertEqual(sorted(found(result, r"^ok    (T\S+\.yml): ")), rules)
        self.assertIn(self.LIST_FAILED, result.stdout)
        self.assertNotRegex(result.stdout, r"(?m)^FAILED: .* rule\(s\) have a new difference")
        # CONTROL: on a run of some rule files the entry is left alone (the run did
        # not look for the rule file).
        some = tree.run(self.GATE, "detections/sigma/" + self.LISTED)
        self.assert_accepts(some, self.OK.format(rules=1, known=self.entries_of(tree, self.LISTED)))

    def test_rejects_second_expected_entry_for_one_event_set(self):
        """vr-entry-second-for-one-event-set. The list holds one entry for one event
        set under one variant. A second entry for the same one (a copy with another
        `why`) is an error of the list: which of the two a person approved is not
        known. The first entry still holds; the closing line counts the error as a
        problem of the list, not as a rule."""
        tree = self.tree()
        rule = self.LISTED
        entries = len(tree.read_json(self.EXPECTED)["expected"])
        known = self.entries_of(tree, rule)
        self.entry(tree, rule, self.LISTED_CASE)

        def duplicate(doc):
            doc["expected"].append(dict(next(e for e in doc["expected"] if e["rule"] == rule
                                             and e["name"] == self.LISTED_CASE),
                                        why="PLANTED: other words for the same difference."))
        tree.edit_json(self.EXPECTED, duplicate)
        result = tree.run(self.GATE, "detections/sigma/" + rule)
        self.assert_rejects(result, rf"^FAIL  -: detections/variants/expected\.json entry {entries}: "
                                    rf"a second entry for \('multi', '{re.escape(rule)}', 'case', "
                                    rf"'{self.LISTED_CASE}'\)$", exit_code=1)
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())
        self.assertRegex(result.stdout, rf"(?m)^ok    {re.escape(rule)}: \d+ event set\(s\), same "
                                        rf"hits as .*; {known} expected difference\(s\)$")
        self.assertIn(self.LIST_FAILED, result.stdout)

    def test_rejects_run_with_a_variant_that_is_not_in_force(self):
        """vr-variant-not-in-force. sigma_eval.flatten() of the copy lost the key sort
        (`sort_keys`), so the variant `sorted` writes the text of `compact`: the gate
        would run, and a rule that needs the key order of the record would pass. The
        gate must stop before it checks a rule, with exit code 2, and name `sorted`
        and no other variant (`compact` is in force)."""
        tree = self.tree()
        tree.replace("detections/sigma_eval.py",
                     " = json.dumps(val, separators=separators, sort_keys=sort_keys)\n",
                     " = json.dumps(val, separators=separators)   # PLANTED: no key sort\n")
        # The artifact is bad: the planted hook gives one text with and without the
        # key sort, and the real one gives two. (Plain assertions.)
        texts = ("import sys\n"
                 "sys.path.insert(0, 'detections')\n"
                 "import sigma_eval\n"
                 "record = {'rules': [{'verbs': ['*'], 'apiGroups': ['']}]}\n"
                 "for sort_keys in (False, True):\n"
                 "    flat = sigma_eval.flatten(record, separators=(',', ':'), sort_keys=sort_keys)\n"
                 "    print(flat['rules'])\n")
        self.assertEqual(self.good().run_python(texts).stdout.split(),
                         ['[{"verbs":["*"],"apiGroups":[""]}]', '[{"apiGroups":[""],"verbs":["*"]}]'])
        self.assertEqual(tree.run_python(texts).stdout.split(),
                         ['[{"verbs":["*"],"apiGroups":[""]}]'] * 2)
        result = tree.run(self.GATE, *self.ci_arguments)
        self.assert_rejects(result, r"^ERROR: variant\(s\) not in force: sorted\. A variant that "
                                    r"changes nothing, or less than the table PROBES declares, "
                                    r"passes rules that it must fail\. No rule was checked\.$",
                            exit_code=2)
        self.assertIn("\n  sorted: as this variant, the probe(s) list-key-order do not give the "
                      "answer that the table PROBES declares\n", result.stdout)
        # No rule was checked, and no line says OK.
        self.assertNotRegex(result.stdout, r"(?m)^(ok   |known|FAIL |OK:|FAILED:)")

    # -- the ratchet: the third comparison of the sufficiency-ratchet job ----------

    RATCHET_OK = (r"^OK: each of the {known} expected difference\(s\) is on the base branch as it "
                  r"is here \(the list did not grow\)\.$")
    NOT_ON_BASE = (r"^FAIL  \S+: expected \[\w+\] \w+ one-more-case: the base branch does not "
                   r"list this entry as it is here; a new or changed expected difference is a "
                   r"human decision$")

    @staticmethod
    def add_entry(doc):
        doc["expected"].append(dict(doc["expected"][0], name="one-more-case"))

    def test_rejects_sidecar_line_and_fixture_list_that_it_cannot_check(self):
        """Two planted problems, each named with its source. A sidecar line of T1609 that
        is not JSON: the FAIL line says `sidecar error:` and names the line. A record of
        the benign fixture of TRR9012 whose list holds an integer outside 64 bits: the
        default text of the list holds it (the validator passes the tree), and the
        multi-valued model, which holds each element as a value, cannot. The record is
        the third of the fixture: before it, the first record and a copy of it whose
        list of two values gives two more rows of the table of that model. The FAIL line
        names the record of the fixture, and not a row of that table (the first text of
        roadmap item R2d named the row) or another record."""
        tree = self.tree()
        sidecar = "detections/sigma/T1609/k8s_pod_exec_attach.cases.jsonl"
        line = len(tree.read_jsonl(sidecar)) + 1
        tree.append(sidecar, "{not json\n")
        benign = "detections/cloud/fixtures/trr9012/benign.json"
        rows = tree.read_json(benign)
        tree.edit_json(benign, lambda doc: doc[:1] + [dict(rows[0], y=["a", "b"]),
                                                      dict(rows[0], x=[1, 2 ** 64])] + doc[1:])
        self.assertGreater(len(rows), 1)
        cloud = tree.start("detections/validate_cloud_detections.py")
        result = tree.run(self.GATE, "detections/sigma/T1609/k8s_pod_exec_attach.yml",
                          "detections/sigma/T1078.004/aws_leaked_access_key_recon.yml",
                          *self.ci_arguments)
        self.assert_saw(cloud.result(), r"^PASS  \[TRR9012 AWS\] aws_leaked_access_key_recon\.yml: "
                                        rf".* benign baseline clean \({len(rows) + 2} record\(s\)\)")
        self.assertNotIn("Traceback", result.output)
        self.assert_rejects(result, rf"^FAIL  T1609/k8s_pod_exec_attach\.yml: sidecar error: line "
                                    rf"{line}: not JSON \(", exit_code=1)
        self.assert_rejects(result, r"^FAIL  T1078\.004/aws_leaked_access_key_recon\.yml: fixture "
                                    r"benign trr9012/benign\.json: \[multi\] cannot check: "
                                    rf"EventError: event 3 of {len(rows) + 2}: the "
                                    r"value of x is an integer outside the 64 bits of an INTEGER "
                                    r"of SQLite \(a value of an element of a list, as the "
                                    r"multi-valued model holds it\)$", exit_code=1)

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
        self.change_entry(tree, self.LISTED, self.LISTED_CASE,
                          why="Other words for the same difference.")
        result = tree.run(self.GATE, "--baseline-expected", base)
        self.assert_rejects(result, rf"^FAIL  {re.escape(self.LISTED)}: expected \[multi\] case "
                                    rf"{self.LISTED_CASE}: the base branch does not list this "
                                    r"entry as it is here", exit_code=1)
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())

    CANNOT_COMPARE = ("\nFAILED: the lists cannot be compared: 1 problem(s) of the expected "
                      "list of this tree or of the base branch (the FAIL rows above).\n")

    def test_rejects_ratchet_against_a_base_list_that_cannot_be_read(self):
        """vr-ratchet-base-list-unreadable. The list of the base is not JSON (a cut
        file). No entry can be compared with it, so the comparison fails, and its
        closing line says that: it does not say that N entries are not on the base."""
        tree = self.tree()
        base = tree.out("base/detections/variants/expected.json")
        with open(base, "w", encoding="utf-8") as fh:
            fh.write("{\n")
        result = tree.run(self.GATE, "--baseline-expected", base)
        self.assert_rejects(result, r"^FAIL  -: the expected list of the base cannot be read: "
                                    r"\S+expected\.json: cannot read: ", exit_code=1)
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())
        self.assertIn(self.CANNOT_COMPARE, result.stdout)
        self.assertNotIn("are not on the base branch as they are here", result.stdout)
        self.assertNotRegex(result.stdout, r"(?m)^OK: ")

    def test_rejects_ratchet_of_a_list_with_a_second_entry(self):
        """vr-ratchet-list-with-a-second-entry. The list of the head holds a second
        entry for one event set and variant. The gate reads the first one only, so a
        comparison of what it read would pass: the error of the list must fail the
        comparison, with a closing line that names the list."""
        tree = self.tree()
        base = tree.out("base/detections/variants/expected.json")
        shutil.copyfile(tree.path(self.EXPECTED), base)
        entries = len(tree.read_json(self.EXPECTED)["expected"])
        tree.edit_json(self.EXPECTED, lambda doc: doc["expected"].append(dict(doc["expected"][0])))
        result = tree.run(self.GATE, "--baseline-expected", base)
        self.assert_rejects(result, rf"^FAIL  -: detections/variants/expected\.json entry {entries}: "
                                    r"a second entry for \(", exit_code=1)
        self.assertEqual(len(found(result, r"^FAIL .*$")), 1, result.describe())
        self.assertIn(self.CANNOT_COMPARE, result.stdout)
        self.assertNotIn("are not on the base branch as they are here", result.stdout)

    def test_rejects_ratchet_of_a_list_with_a_second_entry_when_the_base_has_no_list(self):
        """vr-ratchet-bad-list-and-no-base-list. The base tree has no expected list, so
        there is nothing to compare with. That is a notice only for a list of the
        head that can be read: a list with an error (here a second entry for one
        event set) fails, also on the pull request that adds the list."""
        tree = self.tree()
        os.makedirs(tree.out("base/detections/sigma"))
        entries = len(tree.read_json(self.EXPECTED)["expected"])
        tree.edit_json(self.EXPECTED, lambda doc: doc["expected"].append(dict(doc["expected"][0])))
        result = tree.run(self.GATE, "--baseline-expected",
                          tree.out("base/detections/variants/expected.json"))
        self.assert_rejects(result, rf"^FAIL  -: detections/variants/expected\.json entry {entries}: "
                                    r"a second entry for \(", exit_code=1)
        self.assertNotIn("::notice", result.stdout)
        self.assertIn(self.CANNOT_COMPARE, result.stdout)

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
    # A rule with approvals for GKE (an EXPECTED_LOSS entry and a NOT_PORTABLE entry)
    # whose sidecar no other list of detections/tests/README.md (Limits) names.
    CLASH_RULE = "T1485/k8s_volume_reclaim_set_to_delete.yml"
    CLASH_CASES = "detections/sigma/T1485/k8s_volume_reclaim_set_to_delete.cases.jsonl"
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
        # pm-sidecar-case-clash: one more case in the sidecar of a rule that has
        # approvals, whose event has the keys `verb` and `Verb`. rule_cases.load_cases()
        # refuses that case; the gate must name it, check every other rule, and leave
        # the results file as it is (--write) and not compare it (--check).
        cls.clash, cls.clash_write = cls.class_tree(), cls.class_tree()
        for tree in (cls.clash, cls.clash_write):
            tree.plant("quality/provider_case_clash.jsonl", cls.CLASH_CASES, append=True)
        cls.clash_run = cls.in_background(cls.clash.run, cls.GATE, *cls.ci_arguments)
        cls.clash_write_run = cls.in_background(cls.clash_write.run, cls.GATE, "--write")

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

    def clash_error(self):
        """The ERROR line for the planted case: the rule, the line and the case."""
        line = len(self.good().read_jsonl(self.CLASH_CASES)) + 1
        return (rf"^ERROR {re.escape(self.CLASH_RULE)}: sidecar error: line {line}: case "
                r"'planted-two-verb-keys': event 1 of 1: keys that differ only by case: Verb / "
                r"verb, which SQLite reads as one column name \(one event table cannot hold the "
                r"event\)$")

    def test_rejects_sidecar_case_that_one_table_cannot_hold(self):
        """pm-sidecar-case-clash (planted in setUpClass), with the command line of the
        job: an ERROR line names the rule, the line and the case, with no traceback.
        It is the one problem: the gate checks every other rule for both gating
        providers, and the approvals of the rule are not stale."""
        result = self.clash_run.result()
        self.assert_rejects(result, self.clash_error(), exit_code=1)
        self.assertIn("\nFAILED: 1 problem(s).\n", result.stdout)
        rules = [rule for rule in k8s_audit_rules(self.good(), sidecar=True)
                 if rule != self.CLASH_RULE]
        for provider in ("aks", "gke"):
            judged = found(result, rf"^\[{provider}\] (?:SAME|EXPECTED LOSS|NOT PORTABLE) +"
                                   r"(T\S+\.yml) \([1-9]\d* cases")
            self.assertEqual(sorted(judged), rules, provider)

    def test_write_keeps_the_results_file_when_a_sidecar_case_is_refused(self):
        """pm-sidecar-case-clash with --write: the results would not hold the rule, so
        the gate does not write them, and fails."""
        result = self.clash_write_run.result()
        self.assert_rejects(result, self.clash_error(), exit_code=1)
        self.assertIn("\ndid not write detections/pipelines/mapping_results.json: 1 rule(s) with "
                      "a sidecar error were not checked\n", result.stdout)
        results = "detections/pipelines/mapping_results.json"
        self.assertEqual(self.clash_write.read(results), self.good().read(results))

    def test_rejects_anchor_with_an_object_that_holds_a_key_two_times(self):
        """An anchor of GKE whose object holds the key `provenance` two times, first
        with no source. json keeps only the last value, so the check would read
        another anchor than the file shows. The anchor is FAILED with the key, and the
        run fails (the rule-path form checks the anchors too). (Before, the gate read
        the anchor without a word.)"""
        tree = self.tree()
        rel = "detections/pipelines/anchors/gke/method-and-resource-names.json"
        text = tree.read(rel)
        self.assertTrue(text.startswith("{"))
        self.assertIn('"provenance"', text)
        tree.write(rel, '{"provenance": {}, ' + text[1:])
        result = tree.run(self.GATE, "detections/sigma/" + self.REAL)
        self.assertNotIn("Traceback", result.output)
        self.assert_saw(result, r"^\[gke\] ANCHOR FAILED anchors/gke/method-and-resource-names"
                                r"\.json$")
        self.assert_rejects(result, r"^ +an object holds the key 'provenance' two times \(json "
                                    r"keeps only the last value\)$", exit_code=1)
        self.assertIn("\nFAILED: 1 problem(s).\n", result.stdout)

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

    # The words of the gate for an entry of the defect tracker that it cannot read.
    ENTRY = r"^coverage_report: RULE_DEFECTS\.md L99: "

    def assert_one_entry_problem(self, result, problem):
        """The gate stops with one error line, for entry L99, before it writes or
        compares anything."""
        self.assert_rejects(result, self.ENTRY + problem, exit_code=1)
        self.assertEqual(len(result.stderr.splitlines()), 1, result.describe())
        self.assertEqual(result.stdout, "", result.describe())

    def test_rejects_defect_section_without_summary_row(self):
        """cr-defect-heading-without-summary-row (planted in setUpClass): an entry of
        the defect tracker that has a section and no Summary row. The report reads the
        Summary table, so it would not count the entry: the gate refuses it."""
        # The entry is effective when the gate reads it: with its Summary row the
        # report is stale, and the unmodified copy is current.
        self.control_is_current()
        with_row = self.with_row_run.result()
        self.assertEqual(with_row.returncode, 1, with_row.describe())
        self.assertRegex(with_row.stdout, "(?m)" + self.STALE, with_row.describe())
        self.assertIn("\n### L99. PLANTED known-bad artifact", self.no_row.read(self.DEFECTS))
        self.assertNotIn("| [L99](", self.no_row.read(self.DEFECTS))
        self.assert_one_entry_problem(
            self.no_row_run.result(),
            r"the entry has a section \(### L99\.\) and no row in the Summary table, so the "
            r"report would not count it; add its row to the Summary table$")

    def test_generator_refuses_defect_section_without_summary_row(self):
        """The same entry stops the generator (no --check), and it writes nothing."""
        tree = self.tree()
        tree.plant("quality/defect_without_summary_row/section.md.txt", self.DEFECTS, append=True)
        before = tree.fingerprint()
        self.assert_one_entry_problem(tree.run(self.GATE),
                                      r"the entry has a section \(### L99\.\) and no row ")
        self.assertEqual(tree.fingerprint(), before, "the generator wrote a file")

    def test_rejects_defect_section_whose_id_starts_the_id_of_a_row(self):
        """The ID of a section must be the ID of a row, not the start of one: the
        section `### L1.` has no row while the row L14 is in the table."""
        tree = self.tree()
        self.assertIn("| [L14](", tree.read(self.DEFECTS))
        tree.plant("quality/defect_without_summary_row/section.md.txt", self.DEFECTS, append=True)
        tree.replace(self.DEFECTS, "\n### L99. PLANTED", "\n### L1. PLANTED")
        result = tree.run(self.GATE, "--check")
        self.assert_rejects(result, r"^coverage_report: RULE_DEFECTS\.md L1: the entry has a "
                                    r"section \(### L1\.\) and no row in the Summary table",
                            exit_code=1)
        self.assertEqual(len(result.stderr.splitlines()), 1, result.describe())

    def test_rejects_summary_row_without_a_section(self):
        """A Summary row whose entry has no section: the report would read the entry
        from its row alone. The planted row is the row of L99, without the section."""
        tree = self.tree()
        separator = "|----|------|---------|------|----------|\n"
        tree.replace(self.DEFECTS, separator, separator + self.SUMMARY_ROW)
        self.assert_one_entry_problem(
            tree.run(self.GATE, "--check"),
            r"the Summary table has a row for it and the file has no section \(### L99\.\); "
            r"add its section, or delete the row of an entry that is closed$")

    def test_rejects_two_rows_or_two_sections_for_one_entry(self):
        """Entry L99 with its section and its row, and then a second row or a second
        section: the report would read one entry in two ways."""
        separator = "|----|------|---------|------|----------|\n"
        for twice, problem in (
                ("row", r"the Summary table has 2 rows for it; give each entry one row$"),
                ("section", r"the file has 2 sections for it \(### L99\.\); give each entry "
                            r"one section$")):
            with self.subTest(twice):
                tree = self.tree()
                tree.plant("quality/defect_without_summary_row/section.md.txt", self.DEFECTS,
                           append=True)
                tree.replace(self.DEFECTS, separator, separator + self.SUMMARY_ROW
                             * (2 if twice == "row" else 1))
                if twice == "section":
                    tree.plant("quality/defect_without_summary_row/section.md.txt", self.DEFECTS,
                               append=True)
                self.assert_one_entry_problem(tree.run(self.GATE, "--check"), problem)

    def test_names_each_entry_that_it_cannot_read(self):
        """Two entries that the gate cannot read, L98 and L99 (each a section without a
        Summary row): one error line for each entry, in the order of the IDs."""
        tree = self.tree()
        tree.plant("quality/defect_without_summary_row/section.md.txt", self.DEFECTS, append=True)
        tree.replace(self.DEFECTS, "\n### L99. PLANTED", "\n### L98. PLANTED")
        tree.plant("quality/defect_without_summary_row/section.md.txt", self.DEFECTS, append=True)
        result = tree.run(self.GATE, "--check")
        self.assert_rejects(result, r"^coverage_report: RULE_DEFECTS\.md L99: the entry has a "
                                    r"section \(### L99\.\) and no row ", exit_code=1)
        self.assertEqual(result.stderr.splitlines(), [
            f"coverage_report: RULE_DEFECTS.md {did}: the entry has a section (### {did}.) and "
            "no row in the Summary table, so the report would not count it; add its row to "
            "the Summary table" for did in ("L98", "L99")], result.describe())
        self.assertEqual(result.stdout, "", result.describe())

    def test_rejects_heading_that_starts_with_an_id_and_is_not_an_entry(self):
        """A heading of a section that starts with an ID and is not the heading of an
        entry (`### L99. <title>`): the planted section with `### L99:` and no Summary
        row. The report would read it as no entry, and count nothing for it."""
        tree = self.tree()
        tree.plant("quality/defect_without_summary_row/section.md.txt", self.DEFECTS, append=True)
        tree.replace(self.DEFECTS, "\n### L99. PLANTED", "\n### L99: PLANTED")
        self.assertNotRegex(tree.read(self.DEFECTS), r"(?m)^### L99\. |^\| \[L99\]")
        self.assert_one_entry_problem(
            tree.run(self.GATE, "--check"),
            r"the heading `### L99: PLANTED known-bad artifact: [^`]+` starts with an ID and is "
            r"not the heading of an entry \(### L99\. <title>\), so the report does not read "
            r"it; write it as `### L99\. <title>`$")

if __name__ == "__main__":
    unittest.main()
