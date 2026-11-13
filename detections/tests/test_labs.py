"""
Gate tests, group `labs`: rules for the lab jobs that run on a GitHub runner (auditd
on the runner, a kind cluster). No offline gate runs these jobs, and a change of the
runner image can break them with no change in the repository: on 2026-11-12 the label
`ubuntu-latest` moved from Ubuntu 24.04 to Ubuntu 26.04, and four lab jobs failed.
Each class holds the rule that one of those faults gave.

    AuditdStart     each workflow step that starts auditd waits for audit-rules.service
                    before a rule is added or loaded: auditd 4 loads its rule files in
                    that oneshot unit, the start of auditd starts the unit again and
                    does not wait for it, and the rule file of the unit starts with -D
    FileSensorRule  the two steps of the static pod lab that read the file events name
                    the cause when the audit rule of the file sensor is not loaded

The steps run here with a stub in the place of sudo, systemctl, service, auditctl and
docker. A stub does not show what systemd and auditd do on a runner: the lab jobs do.

How the harness works: gatelib.py and README.md in this directory.

    python3 -B -m unittest discover -s detections/tests -p 'test_labs.py' -v
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gatelib  # noqa: E402  (the line above makes it importable with `-t .` too)

# Stubs for Tree.run_step(programs=...), as shell lines. Each reads and writes the
# directory $STATE. No stub starts a real program as root: `sudo` starts only the
# other stubs, and writes each other command to `calls` without a run.
#
#   UNIT    the state of audit-rules.service: `ok` (auditd 4), `error` (auditd 4, the
#           unit ends with an error) or `absent` (auditd 3: no such unit)
#   calls   one line for each call of systemctl, service and auditctl, and for each
#           command that sudo did not run
#   rules   the audit rules that are loaded, as `auditctl -l` lists them
#   unit    it is there while a run of audit-rules.service is in progress
#
# The model of the fault. On auditd 4, `systemctl start auditd` starts the unit and
# returns at once. `systemctl start audit-rules.service` returns when that run has
# ended: its -D has deleted the rules by then. A run that nobody waited for ends
# after the next `auditctl -l`: in CI the rule of the sensor was in the list of the
# step, and the unit deleted it 1 ms later.
STUBS = {
    "sudo": r'''
case "$1" in
  systemctl|service|auditctl) exec "$@" ;;
  cat) cat "$STATE/audit.log"; exit 0 ;;
  tee) exec "$@" ;;
esac
echo "sudo did not run: $*" >> "$STATE/calls"
''',
    "systemctl": r'''
echo "systemctl $*" >> "$STATE/calls"
case "$*" in
  "start auditd") [ "$UNIT" = absent ] || : > "$STATE/unit" ;;
  "cat audit-rules.service") [ "$UNIT" != absent ] || exit 1 ;;
  "start audit-rules.service")
    [ "$UNIT" != absent ] || { echo "Failed to start audit-rules.service: Unit audit-rules.service not found." >&2; exit 5; }
    : > "$STATE/rules"
    rm -f "$STATE/unit"
    [ "$UNIT" = ok ] || { echo "Job for audit-rules.service failed because the control process exited with error code." >&2; exit 1; }
    ;;
esac
exit 0
''',
    "service": 'echo "service $*" >> "$STATE/calls"',
    "auditctl": r'''
echo "auditctl $*" >> "$STATE/calls"
case "$1" in
  -a|-w) echo "$*" >> "$STATE/rules" ;;
  -l)
    if [ -s "$STATE/rules" ]; then cat "$STATE/rules"; else echo "No rules"; fi
    if [ -e "$STATE/unit" ]; then : > "$STATE/rules"; rm -f "$STATE/unit"; fi
    ;;
esac
exit 0
''',
    # No step of these tests may reach a cluster, and none may wait.
    "docker": "exit 0",
    "kubectl": "exit 0",
    "kind": "exit 0",
    "sleep": "exit 0",
}
UNIT_STATES = ("ok", "error", "absent")
APT_INSTALL = ".github/scripts/apt_install.sh"


class LabSteps(unittest.TestCase):
    """What the two classes share: a small copy of the repository, and a run of one
    step text in it with the stubs."""

    PARTS = (".github", "detections/k8s")
    maxDiff = None

    def lab(self, unit="ok", rules="", audit_log=""):
        """A private copy for one run, with the state of the stubs. The script that
        installs packages does nothing here but write its call."""
        tree = gatelib.Tree(self.PARTS)
        self.addCleanup(tree.cleanup)
        tree.write(APT_INSTALL, 'echo "apt_install.sh $*" >> "$STATE/calls"\n')
        tree.state = os.path.dirname(tree.out("state/calls"))
        tree.unit = unit
        for name, text in (("calls", ""), ("rules", rules), ("audit.log", audit_log)):
            with open(os.path.join(tree.state, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        return tree

    @staticmethod
    def state(tree, name):
        """The lines of a state file of the stubs; None when the file is not there."""
        path = os.path.join(tree.state, name)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return fh.read().splitlines()

    def run_text(self, tree, step, run=None, env=None):
        """Run the text of a step (or `run`, a part of it) with the shell of the step
        and the stubs."""
        values = {"STATE": tree.state, "UNIT": tree.unit, "GITHUB_WORKSPACE": tree.root,
                  "CLUSTER_NAME": "trr9003"}
        values.update(env or {})
        return tree.run_step(step if run is None else step._replace(run=run), env=values,
                             programs=STUBS, timeout=60)

    @staticmethod
    def the_step(workflow, job, name):
        found = [s for s in gatelib.ci_steps() if (s.workflow, s.job, s.name) == (workflow, job, name)]
        if len(found) != 1:
            raise LookupError(f"{workflow}, job {job}: {len(found)} step(s) with the name {name!r}; wanted 1")
        return found[0]


class AuditdStart(LabSteps):
    """auditd 4 (the ubuntu-26.04 runner image) has a oneshot unit, audit-rules.service,
    that loads the rule files. auditd.service wants that unit and does not wait for
    it, so `systemctl start auditd` starts the unit again and returns. The rule file
    of the package starts with -D. In the static pod lab the step added its rule at
    once: the rule was in the list of `auditctl -l`, the unit deleted it 1 ms later,
    and the lab had no file event.

    The rule: a step that starts auditd waits for the unit (`systemctl start` of a
    oneshot unit returns when the unit has ended) before its first line that adds or
    loads an audit rule or runs a validator. The wait is in a guard, because auditd 3
    has no such unit, and a unit that ends with an error gives a warning and does not
    stop the step.

    It is a rule on text. It does not see a start of auditd that a script or a
    different program makes."""

    START = re.compile(r"(?<![\w./-])systemctl\s+(?:-\S+\s+)*(?:re)?start\s+(?:-\S+\s+)*"
                       r"auditd(?:\.service)?(?![\w.-])")
    WAIT = re.compile(r"(?<![\w./-])systemctl\s+start\s+audit-rules\.service(?![\w.-])")
    GUARD = "if systemctl cat audit-rules.service >/dev/null 2>&1; then"
    SOFT = re.compile(r"systemctl\s+start\s+audit-rules\.service\s*\|\|\s*echo\s+\"::warning ")
    # A line that adds or loads an audit rule, or runs a program that loads the rules.
    USES = re.compile(r"(?<![\w./-])auditctl\s+(?:\S+\s+)*?-[aAwR](?![\w-])"
                      r"|python[\d.]*\s+(?:-\S+\s+)*\S*detections/(?:validate_\w+|benign/linux/capture)\.py")
    # (workflow, job, step) of each step that starts auditd today. The step of the API
    # server lab is one text that two jobs run (a YAML alias).
    STEPS = [
        ("detection-quality.yml", "benign-linux-live", "Start auditd (room for the whole capture window)"),
        ("validate-apiserver-detections.yml", "validate",
         "Start the node file-event sensor (auditd, TRR9006 Strategy 3)"),
        ("validate-apiserver-detections.yml", "validate-recommended",
         "Start the node file-event sensor (auditd, TRR9006 Strategy 3)"),
        ("validate-detections.yml", "validate", "Start auditd"),
        ("validate-staticpod-detections.yml", "validate", "Start the node file-event sensor (auditd, Strategy 3)"),
    ]
    SENSOR = STEPS[4]
    WARNING = "::warning title=auditd::audit-rules.service ended with an error"

    @classmethod
    def faults(cls, step):
        """What is wrong with a step that starts auditd, as a list of sentences (empty:
        nothing, or the step does not start auditd)."""
        lines = gatelib._command_lines(step.run)
        found = []
        for start in [i for i, line in enumerate(lines) if cls.START.search(line)]:
            after = lines[start + 1:]
            wait = next((i for i, line in enumerate(after) if cls.WAIT.search(line)), None)
            if wait is None:
                found.append("starts auditd and does not wait for audit-rules.service")
                continue
            early = [line for line in [lines[start]] + after[:wait] if cls.USES.search(line)]
            if early:
                found.append("adds or loads a rule, or runs a validator, before the wait for "
                             "audit-rules.service: " + early[0])
            if wait == 0 or after[wait - 1] != cls.GUARD:
                found.append("the wait for audit-rules.service is not in the guard `" + cls.GUARD + "`")
            if not cls.SOFT.search(after[wait]):
                found.append("a unit that ends with an error does not give a ::warning line "
                             "(`... || echo \"::warning ...\"`)")
        return found

    @classmethod
    def all_faults(cls, root=gatelib.REPO):
        return [f"{step.workflow}, job {step.job}, step {step.name!r}: {fault}"
                for step in gatelib.ci_steps(root=root) for fault in cls.faults(step)]

    def test_the_rule_finds_a_start_without_the_wait(self):
        """CONTROL of the rule, on constructed steps: it names the fault of each step
        that has one, and no other step."""
        start = "sudo systemctl start auditd || sudo service auditd start\n"
        wait = (self.GUARD + "\n"
                "  sudo systemctl start audit-rules.service \\\n"
                '    || echo "::warning title=auditd::audit-rules.service ended with an error"\n'
                "fi\n")
        add = "sudo auditctl -a always,exit -F dir=/x -F perm=wa -F key=k8s_node_file\n"
        no_wait = "starts auditd and does not wait"
        faulty = {
            "the step of 2026-11-12": (start + add, no_wait),
            "no rule in the step": (start + "sudo auditctl -s\n", no_wait),
            "restart": ("sudo systemctl restart auditd\n" + add, no_wait),
            "the unit name": ("sudo systemctl start auditd.service\n" + add, no_wait),
            "the wait in a comment": (start + "# sudo systemctl start audit-rules.service\n" + add, no_wait),
            "the wait before the start": (wait + start + add, no_wait),
            "the rule before the wait": (start + add + wait, "before the wait for audit-rules.service: sudo auditctl -a"),
            "a watch before the wait": (start + "sudo auditctl -w /etc/passwd -p wa\n" + wait, "before the wait"),
            "a rule file before the wait": (start + "sudo auditctl -R detections/audit/atomic.rules\n" + wait,
                                            "before the wait"),
            "the validator before the wait": (
                start + "sudo /tmp/venv/bin/python detections/validate_detections.py --require-audit\n" + wait,
                "before the wait"),
            "no guard": (start + 'sudo systemctl start audit-rules.service || echo "::warning x"\n' + add,
                         "is not in the guard"),
            "a hard failure": (start + self.GUARD + "\n  sudo systemctl start audit-rules.service\nfi\n" + add,
                               "does not give a ::warning line"),
            "a failure with no word": (start + self.GUARD + "\n  sudo systemctl start audit-rules.service || true\nfi\n"
                                       + add, "does not give a ::warning line"),
        }
        sound = {
            "the wait, then the rule": start + wait + add,
            "the wait, and no rule in the step": start + wait + "sudo auditctl -s\n",
            "a setting that is not a rule, before the wait": start + "sudo auditctl -b 32768\n" + wait + add,
            "no start of auditd": add + "sudo auditctl -l\n",
            "the start in a comment": "# sudo systemctl start auditd\n" + add,
            "a different unit": "sudo systemctl start docker\nsudo systemctl start auditd-exporter\n" + add,
            "only the unit": wait + add,
        }

        def step(run):
            return gatelib.Step("w.yml", "job", "step", "bash", run)

        for name, (run, fault) in faulty.items():
            with self.subTest(step=name):
                found = self.faults(step(run))
                self.assertEqual(len(found), 1, found)
                self.assertIn(fault, found[0])
        self.assertEqual({name: self.faults(step(run)) for name, run in sound.items() if self.faults(step(run))}, {})

    def test_each_step_that_starts_auditd_waits_for_the_rule_unit(self):
        steps = gatelib.ci_steps()
        # The steps were read (not vacuous): these start auditd today.
        self.assertEqual(sorted((s.workflow, s.job, s.name) for s in steps
                                if any(self.START.search(line) for line in gatelib._command_lines(s.run))),
                         self.STEPS)
        self.assertEqual(self.all_faults(), [], "these steps start auditd, and a rule that is added "
                         "after that start can be deleted by audit-rules.service (auditd 4). Add the "
                         "wait that the other steps have, after the start")

    def test_a_planted_step_without_the_wait_is_rejected(self):
        """Two planted steps in a copy of the workflows: the step of the static pod lab
        as it was on 2026-11-12, and a step that waits after it added its rule."""
        tree = gatelib.Tree((".github",))
        self.addCleanup(tree.cleanup)
        self.assertEqual(self.all_faults(tree.root), [])        # CONTROL: the copy has no fault
        tree.write(".github/workflows/planted-lab.yml", (
            "on: push\njobs:\n  lab:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - name: Start the sensor\n        shell: bash\n        run: |\n"
            "          set -euo pipefail\n"
            "          bash .github/scripts/apt_install.sh auditd\n"
            "          sudo systemctl start auditd || sudo service auditd start\n"
            "          sudo auditctl -a always,exit -F dir=\"${GITHUB_WORKSPACE}/.kind/x\" -F perm=wa -F key=k8s_node_file\n"
            "          rules=\"$(sudo auditctl -l)\"\n"
            "          grep -qF k8s_node_file <<<\"${rules}\" || { echo \"::error::auditd watch not set\"; exit 1; }\n"
            "      - name: Start the sensor, wait too late\n        run: |\n"
            "          sudo systemctl start auditd\n"
            "          sudo auditctl -w /etc/kubernetes/manifests -p wa -k k8s_node_file\n"
            "          " + self.GUARD + "\n"
            "            sudo systemctl start audit-rules.service || echo \"::warning title=auditd::the unit ended with an error\"\n"
            "          fi\n"))
        self.assertEqual(self.all_faults(tree.root), [
            "planted-lab.yml, job lab, step 'Start the sensor': starts auditd and does not wait for "
            "audit-rules.service",
            "planted-lab.yml, job lab, step 'Start the sensor, wait too late': adds or loads a rule, or runs a "
            "validator, before the wait for audit-rules.service: sudo auditctl -w /etc/kubernetes/manifests "
            "-p wa -k k8s_node_file"])

    def wait_of(self, step):
        """(first, last) line numbers of the wait in the text of a step: from the guard
        to its `fi`. The test fails when the step has no such lines."""
        lines = [line.strip() for line in step.run.splitlines()]
        if self.GUARD not in lines or "fi" not in lines[lines.index(self.GUARD):]:
            self.fail(f"{step.workflow}, job {step.job}, step {step.name!r}: no wait for "
                      "audit-rules.service in the guard `" + self.GUARD + "`")
        first = lines.index(self.GUARD)
        return first, lines.index("fi", first)

    def start_of(self, step):
        """The text of a step from its first line to the end of its wait."""
        return "\n".join(step.run.splitlines()[:self.wait_of(step)[1] + 1]) + "\n"

    def test_the_wait_ends_in_each_state_of_the_unit(self):
        """Each step of the workflows that starts auditd, from its first line to the end
        of its wait, with the stubs: the step goes on in each state of the unit, and
        when it goes on no run of the unit is in progress. A unit that ends with an
        error gives one warning. Where there is no unit, the step does not start it."""
        for name in self.STEPS:
            step = self.the_step(*name)
            for unit in UNIT_STATES:
                with self.subTest(step=name, unit=unit):
                    tree = self.lab(unit)
                    done = self.run_text(tree, step, self.start_of(step) + 'echo "the step goes on"\n')
                    self.assertEqual(done.returncode, 0, done.describe())
                    self.assertEqual(done.stdout.splitlines()[-1:], ["the step goes on"], done.describe())
                    calls = [c for c in self.state(tree, "calls") if c.startswith(("systemctl", "service"))]
                    wanted = ["systemctl start auditd", "systemctl cat audit-rules.service"]
                    self.assertEqual(calls, wanted + ([] if unit == "absent" else ["systemctl start audit-rules.service"]))
                    self.assertIsNone(self.state(tree, "unit"), "a run of audit-rules.service is in progress")
                    self.assertEqual([line for line in done.stdout.splitlines() if line.startswith("::")],
                                     [line for line in done.stdout.splitlines() if line.startswith(self.WARNING)])
                    self.assertEqual(done.stdout.count(self.WARNING), 1 if unit == "error" else 0, done.describe())

    def test_the_sensor_step_of_the_static_pod_lab_keeps_its_rule(self):
        """The whole step of the static pod lab, with the model of the fault in the
        stubs: the rule of the sensor is loaded when the step has ended, in each
        state of the unit. CONTROL: the step as it was (no wait) passes its own
        check, and the rule is gone when the step has ended, as in CI on 2026-11-12."""
        step = self.the_step(*self.SENSOR)
        for unit in UNIT_STATES:
            with self.subTest(unit=unit):
                tree = self.lab(unit)
                done = self.run_text(tree, step)
                self.assertEqual(done.returncode, 0, done.describe())
                rules = self.state(tree, "rules")
                self.assertEqual(len(rules), 1, "the rule of the sensor is not loaded when the step has "
                                 "ended:\n" + done.describe())
                self.assertRegex(rules[0], r"^-a always,exit -F dir=\S+/\.kind/trr9003-manifests -F perm=wa "
                                           r"-F key=k8s_node_file$")
                calls = self.state(tree, "calls")
                self.assertEqual(calls[0], "apt_install.sh auditd")
                # The rule is added after the unit has ended (or where there is no unit).
                add = next(i for i, call in enumerate(calls) if call.startswith("auditctl -a"))
                if unit != "absent":
                    self.assertLess(calls.index("systemctl start audit-rules.service"), add)
                self.assertEqual(done.stdout.count(self.WARNING), 1 if unit == "error" else 0, done.describe())
                self.assertNotIn("::error", done.output)
        first, last = self.wait_of(step)
        lines = step.run.splitlines()
        old = "\n".join(lines[:first] + lines[last + 1:]) + "\n"
        self.assertEqual(self.faults(step._replace(run=old)),
                         ["starts auditd and does not wait for audit-rules.service"])
        tree = self.lab("ok")
        done = self.run_text(tree, step, old)
        self.assertEqual(done.returncode, 0, done.describe())           # its check saw the rule
        self.assertEqual(self.state(tree, "rules"), [], "the model of the fault did not delete the rule")
        # On auditd 3 the old step kept its rule: the fault came with the unit.
        tree = self.lab("absent")
        self.assertEqual(self.run_text(tree, step, old).returncode, 0)
        self.assertEqual(len(self.state(tree, "rules")), 1)


class FileSensorRule(LabSteps):
    """The second line of defence of the static pod lab. The step that captures the
    file events before the emulation, and the step that collects them after it, ask
    `auditctl -l` for the rule of the file sensor. When the key k8s_node_file is not
    in the list, each prints an ::error line that names the cause. Neither stops: the
    file gate and the file control of the validator fail closed without events."""

    WORKFLOW, JOB = "validate-staticpod-detections.yml", "validate"
    STEPS = ("Capture the node file events before the emulation (negative control)",
             "Collect the audit log and the node sensor log")
    RULE = "-w /home/runner/work/det-eng/det-eng/.kind/trr9003-manifests -p wa -k k8s_node_file\n"
    ERROR = ("::error title=file sensor::the audit rule of the file sensor is not loaded "
             "('auditctl -l' does not list the key k8s_node_file)")
    # One record of the marked writer: the collect step stops its poll when it sees one.
    RECORD = ('type=SYSCALL msg=audit(1794601947.257:300): arch=c000003e syscall=257 success=yes exit=3 '
              'pid=4242 comm="trr9003-tee" exe="/usr/local/bin/trr9003-tee" key="k8s_node_file"\n')

    def run_the_step(self, name, rules):
        tree = self.lab(rules=rules, audit_log=self.RECORD)
        done = self.run_text(tree, self.the_step(self.WORKFLOW, self.JOB, name),
                             env={"FILESENSOR_OUTCOME": "success"})
        self.assertIn("auditctl -l", self.state(tree, "calls"), done.describe())
        return done

    def test_control_a_rule_that_is_loaded_gives_no_error(self):
        for name in self.STEPS:
            with self.subTest(step=name):
                done = self.run_the_step(name, self.RULE)
                self.assertEqual(done.returncode, 0, done.describe())
                self.assertNotIn("::error", done.output, done.describe())

    def test_a_rule_that_is_not_loaded_is_named_and_the_step_goes_on(self):
        last = {self.STEPS[0]: r"^Captured \d+ pre-emulation file event\(s\)\.$",
                self.STEPS[1]: r"^Collected \d+ file event\(s\)\.$"}
        for name in self.STEPS:
            with self.subTest(step=name):
                done = self.run_the_step(name, "")
                self.assertEqual(done.returncode, 0, done.describe())
                errors = [line for line in done.stdout.splitlines() if line.startswith("::error")]
                self.assertEqual(len(errors), 1, done.describe())
                self.assertTrue(errors[0].startswith(self.ERROR), errors[0])
                self.assertIn("the file gate and the file control", errors[0])
                # The step went on to its last line.
                self.assertRegex(done.stdout.splitlines()[-1], last[name])

    def test_the_sensor_step_adds_the_rule_that_the_two_steps_look_for(self):
        """The key of the two checks is the key of the rule that the sensor step adds."""
        sensor = self.the_step(*AuditdStart.SENSOR)
        self.assertIn("-F perm=wa -F key=k8s_node_file", sensor.run)
        for name in self.STEPS:
            self.assertIn('grep -qF k8s_node_file <<<"${rules}"', self.the_step(self.WORKFLOW, self.JOB, name).run)


if __name__ == "__main__":
    unittest.main()
