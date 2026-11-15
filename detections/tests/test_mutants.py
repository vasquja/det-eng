"""
Gate tests, group `mutants`: detections/check_mutants.py, the change proof of the
sufficiency-ratchet job of detection-quality.yml (pull requests only). Each change
to the logic of a rule, undone alone, must change a verdict on the head's own
evidence (a sidecar case, a cloud fixture or a benign corpus record).

    ChangeProofRejects  one planted change in the head that no evidence of the head
                        tells apart from its undo: the gate names the change (its key).
                        Also a dead block under an and beside a proven filter, a
                        narrowing with no negative, a wider correlation timespan, and a
                        value in a correlation base rule with a new name and id
    ChangeProofAccepts  changes that the gate passes: the unmodified copy, an
                        allowlist name with its filtered case, a reorder, reworded
                        texts, three corrections that only a representation variant
                        proves (compact, multi, cs_like; planted in the base), a
                        narrowing and an added and-block, each with its negative, a
                        condition with its terms in another order (equivalent), a new
                        id, and a new rule (report only)
    ChangeProofFaults   changes that go to a human (a renamed block, a switch between
                        a plain rule and a correlation, an undo that does not compile)
                        and the structural faults (exit 2)
    ChangeProofStep     the step of the job, as GitHub Actions runs it

The base tree is the unmodified copy (good()), which the gate reads as data, except
where a test plants its change in the base. The rejection test of the known gap that
R6 closed (ra-allowlist-widened-no-case: an allowlist name with no case) is in
test_sufficiency.py, class SufficiencyRatchet.

    python3 -B -m unittest discover -s detections/tests -p 'test_mutants.py' -v
"""

import json
import os
import re
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gatelib  # noqa: E402  (the line above makes it importable with `-t .` too)

GATE = "detections/check_mutants.py"
AFINET_RULE = "detections/sigma/T1040/afinet_raw_socket.yml"
AFINET_CASES = "detections/sigma/T1040/afinet_raw_socket.cases.jsonl"
EXEC_RULE = "detections/sigma/T1609/k8s_pod_exec_attach.yml"
COPYFAIL_RULE = "detections/sigma/T1068/copyfail_af_alg_authencesn.yml"
RBAC_RULE = "detections/sigma/T1098.006/k8s_rbac_privileged_grant.yml"
CONFINEMENT_RULE = "detections/sigma/T1611/k8s_podspec_confinement_disabled.yml"
IMPERSONATION_RULE = "detections/sigma/T1134/k8s_impersonation_privileged.yml"
GCP_IAM_RULE = "detections/sigma/T1098.003/gcp_public_iam_member_grant.yml"
GCP_WIF_RULE = "detections/sigma/T1098.001/gcp_workload_identity_federation_sa_binding.yml"
DIRTYPIPE_RULE = "detections/sigma/T1068/dirtypipe_splice_readonly.yml"
DIRTYPIPE_CASES = "detections/sigma/T1068/dirtypipe_splice_readonly.cases.jsonl"

ALLOWLIST = "    comm:\n      - ping\n      - ping6\n      - traceroute\n      - traceroute6\n"
AFINET_CONDITION = "condition: afinet_raw_socket and not allowed_processes"
CLOEXEC_NONBLOCK = "      - '80803'   # SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK\n"
# One afinet record: an AF_INET raw socket that the head rule fires on.
RAW_SOCKET = {"type": "SYSCALL", "syscall": "socket", "success": "yes", "exit": "3", "a0": "2",
              "a1": "3", "a2": "1", "a3": "0", "comm": "nc", "exe": "/usr/bin/nc"}


def afinet_case(name, kind, breaks, **fields):
    return {"name": name, "kind": kind, "breaks": breaks, "why": "planted by test_mutants.py",
            "source": "synthetic", "events": [dict(RAW_SOCKET, **fields)]}


def plant_dead_block_beside_a_proven_filter(tree):
    """B1: one change of the condition adds the dead AND block afinet_ok (every
    record of the rule has success 'yes') and a new filter allowed_nc with its
    filtered case. Only the undo of the filter has evidence."""
    tree.replace(AFINET_RULE, "  allowed_processes:\n",
                 "  afinet_ok:\n    success: 'yes'\n  allowed_nc:\n    comm: nc\n"
                 "  allowed_processes:\n")
    tree.replace(AFINET_RULE, AFINET_CONDITION, "condition: afinet_raw_socket and afinet_ok and "
                                                "not allowed_processes and not allowed_nc")
    tree.append(AFINET_CASES, json.dumps(afinet_case("nc-raw-socket-allowlisted", "filtered",
                                                     ["allowed_nc.comm"])) + "\n")


def plant_renamed_correlation_base(tree):
    """S1: the splice base rule of dirtypipe gets a new name and a new id (`rules`
    follow), the value 'tee' that no case needs, and a new filter with its case."""
    tree.replace(DIRTYPIPE_RULE, "    - dirtypipe_splice\n", "    - dirtypipe_splice_v2\n")
    tree.replace(DIRTYPIPE_RULE, "id: 563182b9-6db4-46a8-bb0a-5786959273f8\nname: dirtypipe_splice\n",
                 "id: 563182b9-6db4-46a8-bb0a-000000000002\nname: dirtypipe_splice_v2\n")
    tree.replace(DIRTYPIPE_RULE, "    syscall: splice\n  condition: splice_syscall",
                 "    syscall:\n      - splice\n      - tee\n  allowed_haproxy:\n    comm: haproxy\n"
                 "  condition: splice_syscall and not allowed_haproxy")
    cases = tree.read_jsonl(DIRTYPIPE_CASES)
    for case in cases:
        if case.get("breaks") == ["base:dirtypipe_splice"]:
            case["breaks"] = ["base:dirtypipe_splice_v2"]
    cases.append({"name": "haproxy-filtered", "kind": "filtered",
                  "breaks": ["dirtypipe_splice_v2/allowed_haproxy.comm"],
                  "why": "planted by test_mutants.py", "source": "synthetic", "events": [
                      {"type": "SYSCALL", "syscall": "pipe2", "pid": "9461", "comm": "haproxy",
                       "timestamp": "2026-10-12 13:00:40.000"},
                      {"type": "SYSCALL", "syscall": "splice", "pid": "9461", "comm": "haproxy",
                       "timestamp": "2026-10-12 13:00:40.200"}]})
    tree.write_jsonl(DIRTYPIPE_CASES, cases)


def key(rule):
    """The name of a rule in the output of the gate: its path under detections/sigma/."""
    return rule[len("detections/sigma/"):]


def ratchet_lines(result):
    return re.findall(r"(?m)^  \[RATCHET\] .*$", result.stdout)


class ChangeProofRejects(gatelib.StartedTogether):
    """One planted change in a copy of the head; the base tree is good(). No case,
    fixture or corpus record of the head tells the change apart from its undo. The
    gate names it with one [RATCHET] line: the rule and the key of the undo mutant."""

    PARTS = gatelib.DETECTIONS
    # (rule, [(old text, new text)], key of the undo that no evidence kills)
    PLANTS = {
        # A dead item: every case and corpus record of the rule holds it (P2).
        "dead_item": (AFINET_RULE, [("    syscall: socket\n",
                                     "    syscall: socket\n    success: 'yes'\n")],
                      "sel-item:afinet_raw_socket.success"),
        # A list value that no positive needs (P3b).
        "unused_value": (EXEC_RULE, [("      - 'attach'\n", "      - 'attach'\n      - 'proxy'\n")],
                         'sel-value:select_exec_attach.objectRef.subresource="proxy"'),
        # An allowlist name with no filtered case, in a base rule of a correlation (P6).
        "correlation_base_value": (COPYFAIL_RULE, [("        - sm3hmac\n",
                                                    "        - sm3hmac\n        - kcapi-enc\n")],
                                   'flt-value:copyfail_af_alg_socket/kcapi_hash_tools[0].comm='
                                   '"kcapi-enc"'),
        # An allowlist name widened in place (P7): ping becomes ping*.
        "widened_in_place": (AFINET_RULE, [("      - ping\n", "      - 'ping*'\n")],
                             "flt-changed:allowed_processes.comm"),
        # A list of verbs becomes a wildcard (P10): no new key in a survivor count.
        "verb_wildcard": (RBAC_RULE, [("    verb:\n      - 'create'\n      - 'update'\n"
                                       "      - 'patch'\n", "    verb: '*'\n")],
                          "sel-changed:select_rbac_write.verb"),
        # The names of an identity filter become a wildcard (P11).
        "identity_wildcard": (RBAC_RULE, [("    objectRef.name:\n      - 'admin'\n"
                                           "      - 'edit'\n", "    objectRef.name: '*'\n")],
                              "flt-changed:filter_aggregation_controller.objectRef.name"),
        # One more alternative inside a regular expression (P12).
        "regex_alternative": (RBAC_RULE, [(r"""    requestObject|re: '\"(\*|escalate|bind|impersonate)\"'""",
                                           r"""    requestObject|re: '\"(\*|escalate|bind|impersonate|approve)\"'""")],
                              "sel-changed:sel_jsonpatch_rules_grant.requestObject"),
        # An allowlist rewritten as one regular expression with one more name (P13).
        "list_as_regex": (AFINET_RULE, [(ALLOWLIST,
                                         "    comm|re: '^(ping|ping6|traceroute|traceroute6|nc)$'\n")],
                          "flt-changed:allowed_processes.comm"),
        # A new OR branch that the condition reaches through `1 of sel_pod_*` (P16).
        "new_or_branch": (CONFINEMENT_RULE, [("  sel_pod_seccomp:\n",
                                              "  sel_pod_procmount:\n"
                                              "    requestObject.spec.containers|contains: "
                                              "'\"procMount\": \"Unmasked\"'\n"
                                              "  sel_pod_seccomp:\n")],
                          "sel-block:sel_pod_procmount"),
        # A narrowing: a value is removed, and no negative of the head holds it, so
        # nothing shows that the base rule fired where the head is quiet.
        "removed_value": (AFINET_RULE, [(CLOEXEC_NONBLOCK, "")],
                          'sel-removed-value:afinet_raw_socket.a1="80803"'),
        # A wider timespan of a correlation (B2): the undo groups the corpus events of
        # the head in other alerts, but it holds no event that the head does not.
        "timespan_widened": (DIRTYPIPE_RULE, [("  timespan: 5s\n", "  timespan: 20s\n")],
                             "corr-timespan"),
    }
    RUNS = tuple(PLANTS) + ("dead_item_beside_a_failing_case", "dead_block_beside_a_proven_filter",
                            "renamed_correlation_base")

    @classmethod
    def start_gate(cls, tree):
        return tree.start(GATE, "--base-tree", cls.good().root)

    @classmethod
    def _begin(cls, name, tree):
        rule, edits, _key = cls.PLANTS[name]
        for old, new in edits:
            tree.replace(rule, old, new)
        return cls.start_gate(tree)

    def assert_one_unproven(self, name):
        """The run of one plant names its change with one [RATCHET] line."""
        rule, _edits, wanted = self.PLANTS[name]
        tree, result = self.started(name)
        self.assert_saw(result, r"^Change proof against the base tree .+: \d+ rule file\(s\) on "
                                r"the head, \d+ on the base; 1 changed, ")
        self.assert_rejects(result, rf"^  \[RATCHET\] {re.escape(key(rule))}: change not proven: "
                                    rf"{re.escape(wanted)}$", exit_code=1)
        self.assertEqual(len(ratchet_lines(result)), 1, result.describe())
        self.assertIn("\nFAILED: 1 change(s) in 1 rule(s) not proven by the head's evidence",
                      result.stdout)

    def test_control_unchanged_head_is_accepted(self):
        """CONTROL: the head is the base: every rule is unchanged, and none is judged."""
        good, result = self.started()
        rules = len(good.glob("detections/sigma/*/*.yml"))
        self.assertGreater(rules, 0, "the copy holds no rule: the control is vacuous")
        self.assert_accepts(result, rf"^Change proof against the base tree .+: {rules} rule "
                                    rf"file\(s\) on the head, {rules} on the base; 0 changed, "
                                    rf"{rules} unchanged, 0 new, 0 gone\.$")
        self.assert_accepts(result, rf"^OK: 0 changed rule\(s\), 0 change\(s\), .*; {rules} "
                                    r"unchanged rule\(s\); 0 new rule\(s\), report only\.$")

    def test_rejects_dead_item(self):
        self.assert_one_unproven("dead_item")

    def test_rejects_list_value_that_no_positive_needs(self):
        self.assert_one_unproven("unused_value")

    def test_rejects_allowlist_name_in_a_correlation_base(self):
        self.assert_one_unproven("correlation_base_value")

    def test_rejects_allowlist_widened_in_place(self):
        self.assert_one_unproven("widened_in_place")

    def test_rejects_verb_list_made_a_wildcard(self):
        self.assert_one_unproven("verb_wildcard")

    def test_rejects_identity_filter_made_a_wildcard(self):
        self.assert_one_unproven("identity_wildcard")

    def test_rejects_new_alternative_inside_a_regex(self):
        self.assert_one_unproven("regex_alternative")

    def test_rejects_allowlist_rewritten_as_a_regex(self):
        self.assert_one_unproven("list_as_regex")

    def test_rejects_new_or_branch(self):
        self.assert_one_unproven("new_or_branch")

    @classmethod
    def begin_dead_item_beside_a_failing_case(cls, tree):
        # Two changes: SOCK_STREAM ('1') joins the a1 list, so the head fires on its
        # own near-miss stream-socket; and the dead item of dead_item. The undo of the
        # dead item still fires on that near-miss.
        tree.replace(AFINET_RULE, "      - '3'       # SOCK_RAW\n",
                     "      - '3'       # SOCK_RAW\n      - '1'\n")
        tree.replace(AFINET_RULE, "    syscall: socket\n", "    syscall: socket\n    success: 'yes'\n")
        return cls.start_gate(tree)

    def test_rejects_dead_item_beside_a_case_that_the_head_fails(self):
        """Evidence on which the head itself fails does not kill: the undo of the dead
        item fires on the near-miss that the head fires on too. And a corpus slice
        that loses a hit does not kill: the undo of SOCK_STREAM loses the stream
        sockets of the Linux slice, and is the quieter rule."""
        _tree, result = self.started("dead_item_beside_a_failing_case")
        self.assert_rejects(result, r"^  \[RATCHET\] T1040/afinet_raw_socket\.yml: change not "
                                    r"proven: sel-item:afinet_raw_socket\.success$", exit_code=1)
        self.assertIn('  [RATCHET] T1040/afinet_raw_socket.yml: change not proven: '
                      'sel-value:afinet_raw_socket.a1="1"\n', result.stdout)
        self.assertEqual(len(ratchet_lines(result)), 2, result.describe())

    def test_rejects_a_narrowing_that_no_negative_proves(self):
        self.assert_one_unproven("removed_value")

    def test_rejects_correlation_timespan_widened_with_no_case(self):
        """The undo (5s) and the head (20s) group the corpus events of the slice in
        other alerts. The gate compares the events that the alerts hold: the undo
        holds no event that the head does not, so the corpus does not prove the
        change."""
        self.assert_one_unproven("timespan_widened")

    @classmethod
    def begin_dead_block_beside_a_proven_filter(cls, tree):
        plant_dead_block_beside_a_proven_filter(tree)
        return cls.start_gate(tree)

    def test_rejects_dead_and_block_beside_a_proven_filter(self):
        """B1: the undo of an added block under an and always holds. (An undo that
        never held would stop every positive, and so 'prove' the dead block.) The
        filter and the condition are proven by the filtered case of nc."""
        _tree, result = self.started("dead_block_beside_a_proven_filter")
        self.assert_rejects(result, r"^  \[RATCHET\] T1040/afinet_raw_socket\.yml: change not "
                                    r"proven: sel-block:afinet_ok$", exit_code=1)
        for key in ("flt-block:allowed_nc", "condition"):
            self.assertIn(f"  ok    T1040/afinet_raw_socket.yml: {key}: proven by case filtered "
                          "nc-raw-socket-allowlisted [default]\n", result.stdout)
        self.assertEqual(len(ratchet_lines(result)), 1, result.describe())

    @classmethod
    def begin_renamed_correlation_base(cls, tree):
        plant_renamed_correlation_base(tree)
        return cls.start_gate(tree)

    def test_rejects_value_in_a_renamed_correlation_base(self):
        """S1: the one base rule with a new name and id is paired with the one base
        rule of the base that is left, and its changes are undone one by one: the
        filtered case proves the filter, and no case proves 'tee'."""
        _tree, result = self.started("renamed_correlation_base")
        self.assert_rejects(result, r"^  \[RATCHET\] T1068/dirtypipe_splice_readonly\.yml: change "
                                    r"not proven: sel-value:dirtypipe_splice_v2/splice_syscall"
                                    r'\.syscall="tee"$', exit_code=1)
        self.assertIn("  ok    T1068/dirtypipe_splice_readonly.yml: "
                      "flt-block:dirtypipe_splice_v2/allowed_haproxy: proven by case filtered "
                      "haproxy-filtered [default]\n", result.stdout)
        self.assertEqual(len(ratchet_lines(result)), 1, result.describe())


for _name in ChangeProofRejects.PLANTS:
    setattr(ChangeProofRejects, "begin_" + _name,
            classmethod(lambda cls, tree, name=_name: cls._begin(name, tree)))


class ChangeProofAccepts(gatelib.StartedTogether):
    """Changes that the gate passes, each with the line that shows what it judged."""

    PARTS = gatelib.DETECTIONS
    RUNS = ("value_with_its_case", "reorder", "reworded", "anchored_value", "case_fix",
            "new_rule", "blank_fix", "removed_value_with_its_case", "and_block_with_its_case",
            "condition_reordered", "new_id")
    NC_FILTERED = ('{"name": "nc-raw-socket-allowlisted", "kind": "filtered", "breaks": '
                   '["allowed_processes.comm"], "why": "nc opens the same raw ICMP socket; the '
                   'allowlist alone must suppress it", "source": "synthetic", "events": '
                   '[{"type": "SYSCALL", "syscall": "socket", "success": "yes", "exit": "3", '
                   '"a0": "2", "a1": "3", "a2": "1", "a3": "0", "comm": "nc", '
                   '"exe": "/usr/bin/nc"}]}\n')
    NEW_RULE = "detections/sigma/T1040/afinet_raw_socket_v2.yml"

    @classmethod
    def start_gate(cls, tree):
        return tree.start(GATE, "--base-tree", cls.good().root)

    @classmethod
    def start_with_base(cls, base):
        """The gate in the unmodified copy (the head), with `base` as the base tree."""
        return cls.good().start(GATE, "--base-tree", base.root)

    @classmethod
    def begin_value_with_its_case(cls, tree):
        tree.replace(AFINET_RULE, "      - traceroute6\n", "      - traceroute6\n      - nc\n")
        tree.append(AFINET_CASES, cls.NC_FILTERED)
        return cls.start_gate(tree)

    def test_accepts_allowlist_name_with_its_filtered_case(self):
        _tree, result = self.started("value_with_its_case")
        self.assert_accepts(result, r'^  ok    T1040/afinet_raw_socket\.yml: '
                                    r'flt-value:allowed_processes\.comm="nc": proven by case '
                                    r"filtered nc-raw-socket-allowlisted \[default\]$")
        self.assert_accepts(result, r"^OK: 1 changed rule\(s\), 1 change\(s\), ")

    @classmethod
    def begin_reorder(cls, tree):
        tree.replace(AFINET_RULE, "      - ping\n      - ping6\n", "      - ping6\n      - ping\n")
        return cls.start_gate(tree)

    def test_accepts_list_that_is_only_reordered(self):
        _tree, result = self.started("reorder")
        self.assert_accepts(result, r"^  same  T1040/afinet_raw_socket\.yml: no change of the "
                                    r"logic to undo ")
        self.assert_accepts(result, r"^OK: 1 changed rule\(s\), 0 change\(s\), ")

    @classmethod
    def begin_reworded(cls, tree):
        tree.replace(AFINET_RULE, "title: AF_INET Raw Socket Created By Non-Ping/Traceroute "
                                  "Process\n", "title: AF_INET Raw Socket From a Process That "
                                               "Is Not Ping or Traceroute\n")
        tree.replace(AFINET_RULE, "  - attack.discovery\n", "")
        tree.replace(AFINET_RULE, "binaries after baselining.", "binaries after a baseline.")
        cases = tree.read_jsonl(AFINET_CASES)
        cases[0]["why"] = "reworded: " + cases[0]["why"]
        tree.write_jsonl(AFINET_CASES, cases)
        return cls.start_gate(tree)

    def test_accepts_reworded_title_tags_texts_and_why(self):
        """A reworded title, a tag less, a reworded falsepositive and the reworded why
        of a case are no change of the logic: the rule is unchanged."""
        tree, result = self.started("reworded")
        rules = len(tree.glob("detections/sigma/*/*.yml"))
        self.assert_accepts(result, rf"; 0 changed, {rules} unchanged, 0 new, 0 gone\.$")

    @classmethod
    def begin_anchored_value(cls, tree):
        # The base without the anchored value of K72: the head (the real rule) adds it.
        tree.replace(IMPERSONATION_RULE,
                     "      - '^(system:masters|cluster-admin|system:cluster-admins)$'\n", "")
        return cls.start_with_base(tree)

    def test_accepts_anchored_value_that_only_the_multi_variant_proves(self):
        """K72: the anchored value reads one element of a multi-valued list. By default
        the head and its undo give the same hits; under the variant multi a positive
        stops firing without the value."""
        _tree, result = self.started("anchored_value")
        self.assert_accepts(result, r"^  ok    T1134/k8s_impersonation_privileged\.yml: "
                                    r'sel-value:sel_priv_groups\.impersonatedUser\.groups='
                                    r'"\^\(system:masters\|cluster-admin\|system:cluster-admins\)\$": '
                                    r"proven by case positive \S+ \[multi\]$")

    @classmethod
    def begin_case_fix(cls, tree):
        # The base with the endings in lower case, as before C18.
        tree.replace(GCP_IAM_RULE, "      - 'SetIamPolicy'\n      - 'setIamPermissions'\n",
                     "      - 'setiampolicy'\n      - 'setiampermissions'\n")
        return cls.start_with_base(tree)

    def test_accepts_case_fix_that_only_the_cs_like_variant_proves(self):
        """C18: the default LIKE ignores letter case, so only a LIKE that compares letter
        case loses the attack fixture's hit when the fix is undone."""
        _tree, result = self.started("case_fix")
        self.assert_accepts(result, r"^  ok    T1098\.003/gcp_public_iam_member_grant\.yml: "
                                    r"sel-changed:selection_set_iam\.protoPayload\.methodName: "
                                    r"proven by \S+ \S+ \S+ \[cs_like\]$")

    @classmethod
    def begin_blank_fix(cls, tree):
        # The base with one blank after the colon of "action", as before C17.
        tree.replace(GCP_WIF_RULE, r'\"action\"\s*:\s*\"ADD\"', r'\"action\": \"ADD\"', count=0)
        return cls.start_with_base(tree)

    def test_accepts_blank_fix_that_only_the_compact_variant_proves(self):
        """C17: the head reads the JSON text of the delta list with or without the
        blanks. Only the compact text (no blank after a colon) loses a positive when
        the fix is undone."""
        _tree, result = self.started("blank_fix")
        self.assert_accepts(result, r"^  ok    T1098\.001/gcp_workload_identity_federation_sa_"
                                    r"binding\.yml: sel-changed:selection_wif_binding_added\."
                                    r"protoPayload\.serviceData\.policyDelta\.bindingDeltas: proven "
                                    r"by case positive \S+ \[compact\]$")

    @classmethod
    def begin_removed_value_with_its_case(cls, tree):
        tree.replace(AFINET_RULE, CLOEXEC_NONBLOCK, "")
        tree.append(AFINET_CASES, json.dumps(afinet_case(
            "raw-socket-cloexec-nonblock-not-listed", "near-miss", ["afinet_raw_socket.a1"],
            a1="80803", comm="sniffer")) + "\n")
        return cls.start_gate(tree)

    def test_accepts_narrowing_with_a_negative_that_the_base_rule_fires_on(self):
        _tree, result = self.started("removed_value_with_its_case")
        self.assert_accepts(result, r'^  ok    T1040/afinet_raw_socket\.yml: sel-removed-value:'
                                    r'afinet_raw_socket\.a1="80803": proven by case near-miss '
                                    r"raw-socket-cloexec-nonblock-not-listed \[default\]$")

    @classmethod
    def begin_and_block_with_its_case(cls, tree):
        tree.replace(AFINET_RULE, "  allowed_processes:\n",
                     "  afinet_ok:\n    success: 'yes'\n  allowed_processes:\n")
        tree.replace(AFINET_RULE, AFINET_CONDITION,
                     "condition: afinet_raw_socket and afinet_ok and not allowed_processes")
        tree.append(AFINET_CASES, json.dumps(afinet_case(
            "failed-raw-socket", "near-miss", ["afinet_ok.success"], success="no",
            exit="-1", comm="sniffer")) + "\n")
        return cls.start_gate(tree)

    def test_accepts_and_block_with_a_near_miss_that_it_tells_apart(self):
        """The undo of the added block under an and holds on every record: the
        near-miss of a failed socket fires then. (An undo that never held would be
        killed by a positive, not by this near-miss.)"""
        _tree, result = self.started("and_block_with_its_case")
        for key in ("sel-block:afinet_ok", "condition"):
            self.assert_accepts(result, rf"^  ok    T1040/afinet_raw_socket\.yml: {key}: proven by "
                                        r"case near-miss failed-raw-socket \[default\]$")

    @classmethod
    def begin_condition_reordered(cls, tree):
        tree.replace(AFINET_RULE, AFINET_CONDITION,
                     "condition: not allowed_processes and afinet_raw_socket")
        return cls.start_gate(tree)

    def test_accepts_condition_with_its_terms_in_another_order(self):
        """N1: the two conditions give the same value for each assignment of true,
        false and NULL to the items: the undo is equivalent."""
        _tree, result = self.started("condition_reordered")
        self.assert_accepts(result, r"^  same  T1040/afinet_raw_socket\.yml: condition: equivalent ")
        self.assert_accepts(result, r"^OK: 1 changed rule\(s\), 0 change\(s\), .* \(1 equivalent\)")

    @classmethod
    def begin_new_id(cls, tree):
        tree.replace(AFINET_RULE, "id: 3f6d2a94-8c1e-4b0a-9d2e-7c5a1f0b4e8d",
                     "id: 3f6d2a94-8c1e-4b0a-9d2e-000000000002")
        return cls.start_gate(tree)

    def test_accepts_new_id_as_no_change(self):
        """N2: a plain rule with a new id at the same path is paired by its path, and
        a new id is no change of its logic."""
        tree, result = self.started("new_id")
        rules = len(tree.glob("detections/sigma/*/*.yml"))
        self.assert_accepts(result, rf"; 0 changed, {rules} unchanged, 0 new, 0 gone\.$")

    @classmethod
    def begin_new_rule(cls, tree):
        # A copy of the rule with another id and one item that no evidence needs.
        text = tree.read(AFINET_RULE).replace("id: 3f6d2a94-8c1e-4b0a-9d2e-7c5a1f0b4e8d",
                                              "id: 3f6d2a94-8c1e-4b0a-9d2e-000000000001")
        tree.write(cls.NEW_RULE, text.replace("    syscall: socket\n",
                                              "    syscall: socket\n    a3: '0'\n"))
        shutil.copyfile(tree.path(AFINET_CASES), tree.path(cls.NEW_RULE[:-4] + ".cases.jsonl"))
        return cls.start_gate(tree)

    def test_new_rule_is_report_only(self):
        """A rule with no base pair has no change to prove: the gate passes, and lists
        the discriminating item whose drop no evidence tells apart."""
        _tree, result = self.started("new_rule")
        self.assert_accepts(result, r"^  new   T1040/afinet_raw_socket_v2\.yml: no base rule has "
                                    r"its id or its path: no change to prove\. Report only: "
                                    r"discriminating items whose drop no evidence tells apart: "
                                    r"afinet_raw_socket\.a3$")
        self.assert_accepts(result, r"; 0 changed, \d+ unchanged, 1 new, 0 gone\.$")


class ChangeProofFaults(gatelib.GateCase):
    """A change that the gate cannot undo alone goes to a human (exit 1); a tree that
    it cannot judge is a structural fault (exit 2)."""

    PARTS = gatelib.DETECTIONS

    def test_rejects_renamed_block(self):
        """A renamed block cannot be undone alone: undoing the new name or the
        condition alone gives a rule that no base held."""
        tree = self.tree()
        tree.replace(AFINET_RULE, "  allowed_processes:\n", "  allowed_tools:\n")
        tree.replace(AFINET_RULE, "and not allowed_processes", "and not allowed_tools")
        result = tree.run(GATE, "--base-tree", self.good().root)
        self.assert_rejects(result, r"^  \[RATCHET\] T1040/afinet_raw_socket\.yml: change cannot "
                                    r"be undone alone: block allowed_processes renamed to "
                                    r"allowed_tools; a human decides$", exit_code=1)
        self.assertEqual(len(ratchet_lines(result)), 1, result.describe())

    def test_rejects_switch_between_a_plain_rule_and_a_correlation(self):
        """The base holds the splice base rule alone at the path of the dirtypipe
        correlation: the two rules have no changes that can be undone one by one."""
        base = self.tree()
        docs = base.read(DIRTYPIPE_RULE).split("\n---\n")
        base.write(DIRTYPIPE_RULE, docs[-1])
        result = self.good().run(GATE, "--base-tree", base.root)
        self.assert_rejects(result, r"^  \[RATCHET\] T1068/dirtypipe_splice_readonly\.yml: change "
                                    r"cannot be undone alone: the file changed between a plain rule "
                                    r"and a correlation; a human decides$", exit_code=1)
        self.assertEqual(len(ratchet_lines(result)), 1, result.describe())

    def test_rejects_undo_that_does_not_compile(self):
        """The base counts the events (event_count, condition gte 2); the head is
        temporal, with no condition. The undo of the type alone is an event_count with
        no condition, which is not a rule."""
        base = self.tree()
        base.replace(DIRTYPIPE_RULE, "  type: temporal\n", "  type: event_count\n")
        base.replace(DIRTYPIPE_RULE, "  timespan: 5s\n", "  timespan: 5s\n  condition:\n    gte: 2\n")
        result = self.good().run(GATE, "--base-tree", base.root)
        self.assert_rejects(result, r"^  \[RATCHET\] T1068/dirtypipe_splice_readonly\.yml: change "
                                    r"cannot be undone alone: corr-type \(the mutant does not "
                                    r"compile: .+\); a human decides$", exit_code=1)

    def test_fault_when_a_variant_is_not_in_force(self):
        """A variant that does not change what it must change would judge nothing:
        the gate stops (check_variants.in_force)."""
        tree = self.tree()
        tree.replace("detections/check_variants.py",
                     "    named = {ident: expect for ident, _, _, _, expect in PROBES}\n",
                     "    return {'compact': 'planted by test_mutants.py'}\n")
        tree.replace(AFINET_RULE, "      - traceroute6\n", "      - traceroute6\n      - nc\n")
        result = tree.run(GATE, "--base-tree", self.good().root)
        self.assert_rejects(result, r"^ERROR: variant\(s\) not in force: compact: planted by "
                                    r"test_mutants\.py$", exit_code=2)

    def test_fault_when_a_changed_rule_has_a_sidecar_error(self):
        tree = self.tree()
        tree.replace(AFINET_RULE, "      - traceroute6\n", "      - traceroute6\n      - nc\n")
        tree.append(AFINET_CASES, "not a JSON object\n")
        result = tree.run(GATE, "--base-tree", self.good().root)
        self.assert_rejects(result, r"^ERROR: detections/sigma/T1040/afinet_raw_socket\.yml: "
                                    r"sidecar error: ", exit_code=2)

    def test_fault_when_there_is_no_base_tree(self):
        good = self.good()
        result = good.run(GATE, "--base-tree", good.out("no-such-tree"))
        self.assert_rejects(result, r"^ERROR: --base-tree \S+: no such directory", exit_code=2)

    def test_fault_when_the_base_tree_holds_no_rule(self):
        good = self.good()
        empty = os.path.dirname(good.out("empty-tree/detections/sigma/README.md"))
        result = good.run(GATE, "--base-tree", os.path.dirname(os.path.dirname(empty)))
        self.assert_rejects(result, r"^ERROR: --base-tree \S+: the tree holds no rule file",
                            exit_code=2)

    def test_fault_when_a_head_rule_cannot_be_read(self):
        tree = self.tree()
        tree.write("detections/sigma/T1040/broken.yml", "title: [not closed\n")
        result = tree.run(GATE, "--base-tree", self.good().root)
        self.assert_rejects(result, r"^ERROR: \S+/detections/sigma/T1040/broken\.yml: cannot read "
                                    r"the rule file: ", exit_code=2)

    def test_fault_when_a_changed_head_rule_does_not_compile(self):
        tree = self.tree()
        tree.replace(AFINET_RULE, "and not allowed_processes", "and not no_such_block")
        result = tree.run(GATE, "--base-tree", self.good().root)
        self.assert_rejects(result, r"^ERROR: T1040/afinet_raw_socket\.yml: the head rule does "
                                    r"not compile: ", exit_code=2)


class ChangeProofStep(gatelib.GateCase):
    """The step of the sufficiency-ratchet job that runs the gate."""

    PARTS = gatelib.DETECTIONS
    COMMAND = ('python3 detections/check_mutants.py --base-tree "$RUNNER_TEMP/base-tree" '
               '> /tmp/mutants.out 2>&1 || rc=$?')

    def step(self):
        return gatelib.ci_step("detection-quality.yml", "sufficiency-ratchet", GATE)

    def test_ci_runs_the_command_of_these_tests(self):
        self.assertEqual(gatelib.ci_commands(GATE), [self.COMMAND])
        self.assert_documented("python3 detections/check_mutants.py --base-tree <base checkout>")

    def test_step_runs_without_the_report_of_the_base(self):
        """The step needs only the base tree: it runs when the base has no
        check_sufficiency.py (the pull request that adds this gate), and when a step
        above failed. It runs after the sufficiency step."""
        import yaml     # PyYAML: in detections/requirements.txt

        with open(os.path.join(gatelib.REPO, ".github", "workflows", "detection-quality.yml"),
                  encoding="utf-8") as fh:
            steps = yaml.safe_load(fh)["jobs"]["sufficiency-ratchet"]["steps"]
        names = [s.get("name") for s in steps]
        mine = names.index(self.step().name)
        self.assertEqual(steps[mine].get("if"), "${{ !cancelled() }}")
        self.assertEqual(names[mine - 1],
                         "Fail on any rule that lost or changed checks against the base")

    def run_step(self, tree):
        """The step with a stand-in for the worktree of the base commit: the rule
        files of the unmodified copy under $RUNNER_TEMP/base-tree. (The step also
        runs `pip install`; run_step() gives it a `pip` that installs nothing.)"""
        mark = tree.out("ratchet-runner-temp/base-tree/.git")
        with open(mark, "w", encoding="utf-8") as fh:
            fh.write("gitdir: (a stand-in: the step only tests that the base tree exists)\n")
        shutil.copytree(self.good().path("detections/sigma"),
                        tree.out("ratchet-runner-temp/base-tree/detections/sigma"))
        return tree.run_step(self.step(), env={"RUNNER_TEMP": os.path.dirname(os.path.dirname(mark))})

    def test_ci_step_fails_on_a_change_that_is_not_proven(self):
        """The step saves the gate's exit code and ends with `exit "$rc"`. CONTROL: the
        step passes on the unmodified head."""
        tree = self.tree()
        self.assert_accepts(self.run_step(tree), r"^OK: 0 changed rule\(s\), ")
        tree.replace(AFINET_RULE, "      - traceroute6\n", "      - traceroute6\n      - nc\n")
        shutil.rmtree(tree.out("ratchet-runner-temp"))
        self.assert_rejects(self.run_step(tree), r'^  \[RATCHET\] T1040/afinet_raw_socket\.yml: '
                                                 r'change not proven: '
                                                 r'flt-value:allowed_processes\.comm="nc"$',
                            exit_code=1)
        with open(tree.out("github/github_step_summary"), encoding="utf-8") as fh:
            self.assertIn("## Change proof (vs the base branch)", fh.read())

    def test_ci_step_fails_when_the_base_tree_is_not_checked_out(self):
        tree = self.tree()
        result = tree.run_step(self.step(), env={"RUNNER_TEMP": tree.out("empty-runner-temp")})
        self.assert_rejects(result, r"^::error title=sufficiency-ratchet::the base tree was not "
                                    r"checked out$", exit_code=1)


if __name__ == "__main__":
    unittest.main()
