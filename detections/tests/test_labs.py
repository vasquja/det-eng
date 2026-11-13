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
    DateWidth       no shell script and no workflow gives `date` a width with %N (%6N,
                    %3N): `date` of uutils coreutils 0.10.0 prints such a field without
                    the leading zeros of the fraction
    LedgerClock     the function that gives the times of the emulation ledger (now_utc()
                    or now()) is one accepted text in each emulation script and in each
                    workflow step; that text takes the time from bash and calls no
                    `date`, and it keeps the zeros of the fraction

The steps run here with a stub in the place of sudo, systemctl, service, auditctl,
docker and date. A stub does not show what systemd, auditd and the `date` of a runner
image do: the lab jobs do.

How the harness works: gatelib.py and README.md in this directory.

    python3 -B -m unittest discover -s detections/tests -p 'test_labs.py' -v
"""

import datetime
import glob
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gatelib  # noqa: E402  (the line above makes it importable with `-t .` too)
import test_apt_install as apt  # noqa: E402  (its rule on text reads the same files)

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


class DateWidth(unittest.TestCase):
    """GNU `date` prints %6N as the first six digits of the nanoseconds. `date` of
    uutils coreutils 0.10.0 (the ubuntu-26.04 runner image) drops the leading zeros
    of the fraction first: at 0.005613 s it printed `.561317` for %6N, and at about
    0.0125 s it printed `125` for %3N. The times of the emulation ledger were then up
    to 0.9 s late, and the record of a procedure was outside its window. %N with no
    width is right in both programs.

    The rule: no line of a shell script, a workflow or a composite action holds %N
    with a width (and its flags) of one digit: %6N, %3N, %06N, %-3N. A comment does
    not count. Shell scripts are the files that DirectInstalls reads (test_apt_install.py).

    It is a rule on text. It does not see a format that is built at run time, and it
    does not ask if the line calls `date`. It does not find a width of two digits
    (%10N): in a URL, the same text is a percent-encoded character before an N
    (`%20New`)."""

    WIDTH = re.compile(r"%[-_0^#+]*[1-9]N")

    @classmethod
    def hits(cls, root=gatelib.REPO):
        """`file:line: text` of each line that gives %N a width, in the shell scripts,
        the workflows and the composite actions under `root`."""
        files = [os.path.join(root, rel) for rel in apt.DirectInstalls.shell_scripts(root)]
        files += glob.glob(os.path.join(root, ".github", "workflows", "*.y*ml"))
        files += glob.glob(os.path.join(root, ".github", "actions", "**", "*.y*ml"), recursive=True)
        found = []
        for path in sorted(set(files)):
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            with open(path, encoding="utf-8", errors="replace") as fh:
                for number, raw in enumerate(fh, 1):
                    line = raw.strip()
                    if not line.startswith("#") and cls.WIDTH.search(apt.DirectInstalls.no_comment(line)):
                        found.append(f"{rel}:{number}: {line}")
        return found

    def test_the_rule_finds_a_width_before_N(self):
        """CONTROL of the rule, on constructed lines."""
        found = ["now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }",
                 'echo "BENIGN_START=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)" >> "$GITHUB_ENV"',
                 "t0=$(date +%s.%3N)", "date +%s%3N", "date '+%H:%M:%S.%06N'", "date +%-3N", "date +%_6N",
                 "stamp='+%s.%9N'", 'echo "step #1: $(date +%3N)"', "run: date +%T.%3N",
                 "STAMP: $(date +%s%3N)   # a value of env:"]
        not_found = ["now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }", "date +%s.%N", "date +%s%N",
                     't="$(date -u +%Y-%m-%dT%H:%M:%S.%N)"; printf \'%sZ\\n\' "${t:0:26}"',
                     "date +%s  # not %3N", "printf '%6d %3s\\n' 5 N",
                     "TZ=UTC0 printf '%(%Y-%m-%dT%H:%M:%S)T.%sZ\\n' 1794601386 003423",
                     'curl "https://example.com/find?q=a%20New"', "date +%Y%m%d%H%M%S", "date +%-H:%M",
                     'STAMP="$(date +%Y%m%d%H%M%S)"']
        self.assertEqual([line for line in found + not_found
                          if self.WIDTH.search(apt.DirectInstalls.no_comment(line))], found)

    def test_a_planted_script_and_a_planted_step_are_rejected(self):
        """In a copy of the repository: a script with %6N (the function of 2026-11-12), a
        script with no .sh in its name, a workflow step with %3N, an `env:` value and
        a composite action. The message names the file and the line. A comment with
        %6N in the same files is not found."""
        tree = gatelib.Tree((".github", "atomics", "detections/benign", "detections/k8s"))
        self.addCleanup(tree.cleanup)
        self.assertEqual(self.hits(tree.root), [])              # CONTROL: the copy has no hit
        tree.write("atomics/T9999/src/emulate.sh",
                   "#!/usr/bin/env bash\nset -euo pipefail\n# The old form: date +%6N.\n"
                   "now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }\n")
        tree.write("atomics/T9999/src/stamp", "#!/bin/sh\n\necho \"$(date +%s).$(date +%3N)\"\n")
        tree.write(".github/workflows/planted-lab.yml",
                   "on: push\njobs:\n  lab:\n    runs-on: ubuntu-latest\n    env:\n"
                   "      STAMP_FORMAT: +%s.%6N\n    steps:\n"
                   "      - name: Mark the start\n        run: |\n"
                   "          # Milliseconds (not with %3N of uutils date).\n"
                   "          echo \"T0=$(date +%s.%3N)\" >> \"$GITHUB_ENV\"\n")
        tree.write(".github/actions/stamp/action.yml",
                   "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: date -u +%T.%6N\n")
        self.assertEqual(self.hits(tree.root), [
            ".github/actions/stamp/action.yml:5: run: date -u +%T.%6N",
            ".github/workflows/planted-lab.yml:6: STAMP_FORMAT: +%s.%6N",
            '.github/workflows/planted-lab.yml:11: echo "T0=$(date +%s.%3N)" >> "$GITHUB_ENV"',
            "atomics/T9999/src/emulate.sh:4: now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }",
            'atomics/T9999/src/stamp:3: echo "$(date +%s).$(date +%3N)"'])

    def test_no_shell_script_and_no_workflow_gives_date_a_width_with_N(self):
        scripts = apt.DirectInstalls.shell_scripts()
        # The files were read (not vacuous): the emulation scripts are shell scripts, and
        # today some of their comments name %6N.
        self.assertGreater(len(scripts), 10, "the shell scripts were not read")
        self.assertIn("atomics/T1609/src/emulate.sh", scripts)
        with open(os.path.join(gatelib.REPO, "atomics", "T1609", "src", "emulate.sh"), encoding="utf-8") as fh:
            self.assertRegex(fh.read(), r"(?m)^# .*%6N")
        self.assertEqual(self.hits(), [], "these lines give %N a width. `date` of uutils coreutils "
                         "0.10.0 (Ubuntu 26.04) prints such a field without the leading zeros of "
                         "the fraction. Use the function of LedgerClock.ACCEPTED, or %N and cut the text")


class LedgerClock(unittest.TestCase):
    """Each Kubernetes emulation script writes one ledger line for each procedure, with
    its start and its end. The validators read the two times as the window of the
    procedure. The function that gives the time is one text, the same in each script
    (the name is now_utc(), or now() in two scripts) and in each workflow step that
    defines it.

    The text takes the time from bash: EPOCHREALTIME (bash 5.0) is seconds, a
    separator (`.` or `,`, by the locale) and six digits. It starts no `date`. A
    bash that does not have the variable calls `date` with %N (nine digits) and keeps
    six: no width, which `date` of uutils coreutils 0.10.0 prints wrongly (DateWidth)."""

    ACCEPTED = r"""now_utc() {
  local t="${EPOCHREALTIME:-}"
  if [ -n "$t" ]; then TZ=UTC0 printf '%(%Y-%m-%dT%H:%M:%S)T.%sZ\n' "${t%[.,]*}" "${t#*[.,]}"
  else t="$(date -u +%Y-%m-%dT%H:%M:%S.%N)"; printf '%sZ\n' "${t:0:26}"; fi
}
"""
    OLD = "now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }\n"       # until 2026-11-13
    DEFINES = re.compile(r"^[ \t]*(?:function[ \t]+(?:now_utc|now)\b|(?:now_utc|now)[ \t]*\(\))")
    NAME = re.compile(r"^(?:function[ \t]+)?(now_utc|now)\b")
    SCRIPTS = "atomics/*/src/*.sh"
    FORMAT = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z"
    BENIGN = ("validate-apiserver-detections.yml", "validate", "Benign operator workload (live false-positive slice)")
    WRONG = "1999-12-31T23:59:59.987654321"      # what the stub `date` prints

    @classmethod
    def definitions(cls, text):
        """(line number, name, text) of each definition of now_utc() or now() in a shell
        text. The text is the definition from its first line to its closing brace,
        without the indent of the first line, with the name now_utc."""
        lines = text.splitlines()
        found = []
        for first, line in enumerate(lines):
            if not cls.DEFINES.match(line):
                continue
            indent = len(line) - len(line.lstrip())
            last = first
            if not line.rstrip().endswith("}"):
                last = next((i for i in range(first + 1, len(lines)) if lines[i].strip() == "}"), len(lines) - 1)
            body = [part[indent:] if part[:indent].strip() == "" else part for part in lines[first:last + 1]]
            name = cls.NAME.match(body[0]).group(1)
            body[0] = re.sub(r"^" + name + r"\b", "now_utc", body[0], count=1)
            found.append((first + 1, name, "\n".join(body) + "\n"))
        return found

    @classmethod
    def faults(cls, root=gatelib.REPO):
        """What is wrong with the clock functions under `root`, as a list of sentences."""
        found = []
        for path in sorted(glob.glob(os.path.join(root, *cls.SCRIPTS.split("/")))):
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            definitions = cls.definitions(text)
            found += [f"{rel}:{number}: the function {name}() is not the accepted text (LedgerClock.ACCEPTED)"
                      for number, name, body in definitions if body != cls.ACCEPTED]
            if "DETENG_LEDGER" in text and len(definitions) != 1:
                found.append(f"{rel}: the script writes a ledger (DETENG_LEDGER) and defines now_utc() or "
                             f"now() {len(definitions)} time(s); wanted 1")
        for step in gatelib.ci_steps(root=root):
            found += [f"{step.workflow}, job {step.job}, step {step.name!r}: the function {name}() is not "
                      "the accepted text (LedgerClock.ACCEPTED)"
                      for _number, name, body in cls.definitions(step.run) if body != cls.ACCEPTED]
        return found

    def test_the_rule_finds_a_function_that_is_not_the_accepted_text(self):
        """CONTROL of the rule, on constructed texts."""
        accepted = self.ACCEPTED
        other = {
            "the function of 2026-11-12": self.OLD,
            "the old function, with the name now": self.OLD.replace("now_utc", "now"),
            "a width in the fallback": accepted.replace("%S.%N)", "%S.%6N)"),
            "no UTC for printf": accepted.replace("TZ=UTC0 printf", "printf"),
            "date in each case": "now_utc() {\n  date -u +%Y-%m-%dT%H:%M:%SZ\n}\n",
            "two reads of the clock": accepted.replace('"${t%[.,]*}"', '"${EPOCHREALTIME%[.,]*}"'),
            "the keyword form": accepted.replace("now_utc() {", "function now_utc {"),
            "a line more": accepted.replace("}\n", "  sleep 0\n}\n"),
        }
        same = {
            "the accepted text": accepted,
            "the name now": accepted.replace("now_utc() {", "now() {"),
            "in a workflow step, after other lines": "set -euo pipefail\n# The split point.\n" + accepted
                                                     + 'echo "BENIGN_START=$(now_utc)" >> "$GITHUB_ENV"\n',
            "with an indent": "".join("    " + line for line in accepted.splitlines(keepends=True)),
        }
        for name, text in other.items():
            with self.subTest(text=name):
                found = self.definitions("TRR=TRR9999\n" + text + "must() {\n  return 0\n}\n")
                self.assertEqual(len(found), 1, found)
                self.assertEqual(found[0][0], 2)                 # the line of the definition
                self.assertNotEqual(found[0][2], accepted)
        for name, text in same.items():
            with self.subTest(text=name):
                self.assertEqual([body for _number, _name, body in self.definitions(text)], [accepted])
        # A call, a comment and a different function are not definitions.
        self.assertEqual(self.definitions('start="$(now_utc)"\n# now_utc() { date; }\nknown() { :; }\nnow=1\n'), [])

    def test_each_clock_function_is_the_accepted_text(self):
        scripts = {}
        for path in sorted(glob.glob(os.path.join(gatelib.REPO, *self.SCRIPTS.split("/")))):
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            if self.definitions(text) or "DETENG_LEDGER" in text:
                scripts[os.path.relpath(path, gatelib.REPO).replace(os.sep, "/")] = \
                    [name for _number, name, _body in self.definitions(text)]
        # The scripts were read (not vacuous): today 20 scripts write a ledger, and two
        # of them name the function now().
        self.assertGreaterEqual(len(scripts), 20, "the emulation scripts were not read")
        self.assertEqual(scripts["atomics/T1609/src/emulate.sh"], ["now"])
        self.assertEqual(scripts["atomics/T1611/src/emulate_k8s.sh"], ["now_utc"])
        in_steps = [(s.workflow, s.job, s.name) for s in gatelib.ci_steps() if self.definitions(s.run)]
        self.assertIn(self.BENIGN, in_steps)
        self.assertEqual(self.faults(), [], "the clock function of the ledger is one text. Copy "
                         "LedgerClock.ACCEPTED (the name can be now() or now_utc()); to change the "
                         "function, change that text and each copy in the same pull request")

    def test_a_planted_script_with_the_old_function_is_rejected(self):
        """In a copy of the repository: a script with the function of 2026-11-12, a
        script that writes a ledger with no such function, and a workflow step with
        the old function."""
        tree = gatelib.Tree((".github", "atomics"))
        self.addCleanup(tree.cleanup)
        self.assertEqual(self.faults(tree.root), [])            # CONTROL: the copy has no fault
        head = "#!/usr/bin/env bash\nset -euo pipefail\nTRR=\"TRR9999\"\nFAILED=()\n"
        ledger = ('run_proc() {\n  local start end\n  start="$(STAMP)"\n  "procedure_$1"\n  end="$(STAMP)"\n'
                  '  printf \'{"trr":"%s","start":"%s","end":"%s"}\\n\' "$TRR" "$start" "$end" >> "$DETENG_LEDGER"\n}\n')
        tree.write("atomics/T9999/src/emulate.sh", head + self.OLD + ledger.replace("STAMP", "now_utc"))
        tree.write("atomics/T9999/src/emulate_other.sh", head + ledger.replace("STAMP", "date -u +%FT%T.%NZ"))
        tree.write(".github/workflows/planted-lab.yml",
                   "on: push\njobs:\n  lab:\n    runs-on: ubuntu-latest\n    steps:\n"
                   "      - name: Mark the start\n        shell: bash\n        run: |\n"
                   "          now() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }\n"
                   "          echo \"T0=$(now)\" >> \"$GITHUB_ENV\"\n")
        self.assertEqual(self.faults(tree.root), [
            "atomics/T9999/src/emulate.sh:5: the function now_utc() is not the accepted text (LedgerClock.ACCEPTED)",
            "atomics/T9999/src/emulate_other.sh: the script writes a ledger (DETENG_LEDGER) and defines "
            "now_utc() or now() 0 time(s); wanted 1",
            "planted-lab.yml, job lab, step 'Mark the start': the function now() is not the accepted text "
            "(LedgerClock.ACCEPTED)"])

    # -- the accepted text, run in bash ----------------------------------------------

    def need_bash(self, major, minor, why):
        """Skip the test when `bash` is older than major.minor (in CI: fail)."""
        done = subprocess.run(["bash", "-c", 'echo "${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"'],
                              capture_output=True, text=True, timeout=60, check=True)
        version = tuple(int(part) for part in done.stdout.split())
        if version < (major, minor):
            why = f"bash is {version[0]}.{version[1]}, and {why} needs bash {major}.{minor} or later"
            if os.environ.get("CI"):
                self.fail("in CI: " + why)
            self.skipTest(why)

    def run_function(self, lines, date_says=WRONG, zone="America/New_York"):
        """Run `lines` after the accepted function, as an emulation script does (bash,
        set -euo pipefail), with a stub `date` first on PATH. The stub prints
        `date_says` and writes its arguments to a file. Returns (the lines that the
        run printed, the calls of the stub)."""
        with tempfile.TemporaryDirectory(prefix="deteng-clock-") as work:
            stubs = os.path.join(work, "bin")
            os.mkdir(stubs)
            with open(os.path.join(stubs, "date"), "w", encoding="utf-8") as fh:
                fh.write('#!/bin/sh\necho "$*" >> "$CALLS"\necho "$DATE_SAYS"\n')
            os.chmod(os.path.join(stubs, "date"), 0o755)
            script = os.path.join(work, "clock.sh")
            with open(script, "w", encoding="utf-8") as fh:
                fh.write("set -euo pipefail\n" + self.ACCEPTED + lines)
            calls = os.path.join(work, "calls")
            done = subprocess.run(
                ["bash", "--noprofile", "--norc", script], capture_output=True, text=True, timeout=60,
                check=False, env={"PATH": stubs + os.pathsep + os.environ.get("PATH", ""), "TZ": zone,
                                  "CALLS": calls, "DATE_SAYS": date_says, "LC_ALL": "C"})
            self.assertEqual((done.returncode, done.stderr), (0, ""), done.stdout)
            called = []
            if os.path.exists(calls):
                with open(calls, encoding="utf-8") as fh:
                    called = fh.read().splitlines()
            return done.stdout.splitlines(), called

    def test_the_time_comes_from_bash_and_not_from_date(self):
        """The function as a script calls it (`start="$(now_utc)"`), with the clock of
        bash and a `date` that prints a wrong time: the result is the time of the
        test, in UTC (the zone of the run is not UTC), and `date` was not called."""
        self.need_bash(5, 0, "EPOCHREALTIME")
        before = time.time()
        printed, called = self.run_function('start="$(now_utc)"\nprintf \'%s\\n\' "$start"\nnow_utc\n')
        after = time.time()
        self.assertEqual(called, [], "the function called `date`")
        self.assertEqual(len(printed), 2, printed)
        for value in printed:
            self.assertRegex(value, "^" + self.FORMAT + "$")
            at = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=datetime.timezone.utc).timestamp()
            self.assertTrue(before - 2 <= at <= after + 2,
                            f"{value} is not within two seconds of the time of the test")
        self.assertLessEqual(printed[0], printed[1])

    def test_a_fraction_that_starts_with_zero_keeps_its_zeros(self):
        """The function with a fixed value of the clock. bash gives EPOCHREALTIME its
        value at each read, so a test cannot set it; after `unset` it is a plain
        variable, and the function reads the value that the test gives. The values:
        the EPOCHREALTIME of the sample of the CI log in which `date +%6N` printed
        .561317, the same with the comma of a locale, one microsecond, the last
        microsecond of a second, and a fraction of zero."""
        self.need_bash(4, 2, "printf '%(...)T'")
        values = {"1794601386.003423": "2026-11-13T20:23:06.003423Z",
                  "1794601386,003423": "2026-11-13T20:23:06.003423Z",
                  "1794601386.000001": "2026-11-13T20:23:06.000001Z",
                  "1794601386.999999": "2026-11-13T20:23:06.999999Z",
                  "1794528000.000000": "2026-11-13T00:00:00.000000Z"}
        lines = "unset EPOCHREALTIME\n" + "".join(f"EPOCHREALTIME={value}\nnow_utc\n" for value in values)
        for zone in ("America/New_York", "Asia/Kolkata", "UTC"):
            with self.subTest(zone=zone):
                printed, called = self.run_function(lines + 'printf \'%s\\n\' "$TZ"\n', zone=zone)
                self.assertEqual(printed, list(values.values()) + [zone])       # and TZ is as it was
                self.assertEqual(called, [])

    def test_without_the_clock_of_bash_the_function_calls_date_with_N_only(self):
        """A bash older than 5.0 has no EPOCHREALTIME: here the variable is unset, and
        the function is the same text. It calls `date` one time, with %N and no
        width, and keeps six of the nine digits."""
        printed, called = self.run_function("unset EPOCHREALTIME\nnow_utc\n",
                                            date_says="2026-11-13T20:23:06.003423789")
        self.assertEqual(printed, ["2026-11-13T20:23:06.003423Z"])
        self.assertEqual(called, ["-u +%Y-%m-%dT%H:%M:%S.%N"])
        self.assertIsNone(DateWidth.WIDTH.search(called[0]))
        # A `date` that has no %N (BSD date prints the letter): no valid time, and no
        # time that looks valid.
        printed, _called = self.run_function("unset EPOCHREALTIME\nnow_utc\n", date_says="2026-11-13T20:23:06.N")
        self.assertEqual(printed, ["2026-11-13T20:23:06.NZ"])
        self.assertNotRegex(printed[0], "^" + self.FORMAT + "$")

    def test_the_benign_step_writes_its_split_point_without_date(self):
        """The step of the API server lab that writes BENIGN_START, to that line: the
        value is the time of the test in the format that the step that scores the
        slice accepts, and `date` was not called."""
        self.need_bash(5, 0, "EPOCHREALTIME")
        step = AuditdStart.the_step(*self.BENIGN)
        lines = step.run.splitlines()
        write = [i for i, line in enumerate(lines) if "BENIGN_START=" in line and not line.strip().startswith("#")]
        self.assertEqual(len(write), 1, "one line of the step writes BENIGN_START")
        self.assertEqual(lines[write[0]].strip(), 'echo "BENIGN_START=$(now_utc)" >> "$GITHUB_ENV"')
        tree = gatelib.Tree(())
        self.addCleanup(tree.cleanup)
        calls = tree.out("date-calls")
        before = time.time()
        done = tree.run_step(step._replace(run="\n".join(lines[:write[0] + 1]) + "\n"), timeout=60,
                             env={"TZ": "America/New_York", "CALLS": calls, "DATE_SAYS": self.WRONG},
                             programs={"date": 'echo "$*" >> "$CALLS"\necho "$DATE_SAYS"'})
        after = time.time()
        self.assertEqual(done.returncode, 0, done.describe())
        self.assertFalse(os.path.exists(calls), "the step called `date`")
        with open(tree.out("github/github_env"), encoding="utf-8") as fh:
            written = fh.read().splitlines()
        self.assertEqual(len(written), 1, written)
        self.assertRegex(written[0], "^BENIGN_START=" + self.FORMAT + "$")
        value = written[0].split("=", 1)[1]
        at = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=datetime.timezone.utc).timestamp()
        self.assertTrue(before - 2 <= at <= after + 2, f"{value} is not within two seconds of the time of the test")
        # The step that scores the slice reads the value with this pattern.
        score = AuditdStart.the_step("validate-apiserver-detections.yml", "validate",
                                     "Score the pre-emulation log as a live benign slice (shadow)")
        pattern = re.search(r"^\s*utc='(\^[^']+\$)'$", score.run, re.MULTILINE)
        self.assertTrue(pattern, "the pattern of the scoring step was not found")
        self.assertRegex(value, pattern.group(1))


if __name__ == "__main__":
    unittest.main()
