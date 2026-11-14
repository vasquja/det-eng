"""
Gate tests, group `labs`: rules for the lab jobs that run on a GitHub runner (auditd
on the runner, a kind cluster). No offline gate runs these jobs, and a change of the
runner image can break them with no change in the repository: on 2026-11-12 the label
`ubuntu-latest` moved from Ubuntu 24.04 to Ubuntu 26.04, and four lab jobs failed.
Each class holds the rule that one of those faults gave.

    AuditdStart     each workflow step that starts auditd waits for audit-rules.service
                    before it changes a rule or a setting of the audit system: auditd 4
                    loads its rule files in that oneshot unit, the start of auditd
                    starts the unit again and does not wait for it, and the rule file
                    of the unit starts with -D and sets the backlog limit
    FileSensorRule  the two steps of the static pod lab that read the file events name
                    the cause when the audit rule of the file sensor is not loaded
    DateWidth       no shell script, no file under atomics/ and no workflow gives `date`
                    a width with %N (%6N, %3N): `date` of uutils coreutils 0.10.0 prints
                    such a field without the leading zeros of the fraction
    LedgerClock     the function that gives the times of the emulation ledger (now_utc()
                    or now()) is one accepted text in each emulation script and in each
                    workflow step; that text takes the time from bash and calls no
                    `date`, and it keeps the zeros of the fraction

The steps run here with a stub in the place of sudo, systemctl, service, auditctl,
docker and date. A stub does not show what systemd, auditd and the `date` of a runner
image do: the lab jobs do.

The tests find a step of a workflow by its name (AuditdStart.STEPS, FileSensorRule.STEPS,
LedgerClock.BENIGN and SCORE). A step with a new name needs the new name here: the_step()
says so.

How the harness works: gatelib.py and README.md in this directory.

    python3 -B -m unittest discover -s detections/tests -p 'test_labs.py' -v
"""

import datetime
import difflib
import glob
import json
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
# directory $STATE. `sudo` starts the other stubs, by their names (a path such as
# /usr/bin/systemctl gives the stub too), and one real program: `tee`, when each file
# that it names is in the sandbox of the test ($SANDBOX; a step names /tmp/, and
# run_step() puts that there). `sudo` writes each other command to `calls` without a
# run, and also a `tee` to a different place: the tests can run as root, and a step
# text must not write a file of the machine.
#
#   UNIT     the state of audit-rules.service: `ok` (auditd 4), `error` (auditd 4, the
#            unit ends with an error) or `absent` (auditd 3: no such unit)
#   calls    one line for each call of systemctl, service and auditctl, and for each
#            command that sudo did not run
#   rules    the audit rules that are loaded, as `auditctl -l` lists them
#   backlog  the backlog limit of the kernel (`auditctl -b`); 64 before the first run
#   unit     it is there while a run of audit-rules.service is in progress
#
# The model of the fault. On auditd 4, a start of auditd (`systemctl start auditd`, and
# the other forms that AuditdStart knows) starts the unit and returns at once.
# `systemctl start audit-rules.service` returns when that run has ended. A run of the
# unit loads the rule file of the image: -D deletes the rules, and -b sets the backlog
# limit to 8192. A run that nobody waited for ends after the next `auditctl -l` or
# `auditctl -s`: in CI the rule of the sensor was in the list of the step, and the
# unit deleted it 1 ms later.
#
# The model of root. `sudo` gives AS_ROOT to the stub that it starts. Without it
# auditctl does nothing and fails, and so does each systemctl and service command that
# changes a unit (`systemctl cat` and the status commands need no root): a wait that
# is not `sudo systemctl ...` fails at once, and the run of the unit goes on. (That
# is what systemd does for a user who cannot give an authorization. It was not tried
# on a runner.)
_UNIT_RUN = r"""
unit_run() {
  : > "$STATE/rules"
  echo 8192 > "$STATE/backlog"
  rm -f "$STATE/unit"
}
"""
STUBS = {
    "sudo": r"""
case "${1##*/}" in
  systemctl|service|auditctl)
    program="${1##*/}"; shift
    AS_ROOT=1; export AS_ROOT
    exec "$program" "$@" ;;
  cat) cat "$STATE/audit.log"; exit 0 ;;
  tee)
    shift
    outside=""
    [ -n "${SANDBOX:-}" ] || outside=1
    for word in "$@"; do
      case "$word" in
        -*) ;;
        */../*|*/..) outside=1 ;;
        "$SANDBOX"/*) ;;
        *) outside=1 ;;
      esac
    done
    if [ -z "$outside" ]; then exec tee "$@"; fi
    cat > /dev/null
    echo "sudo did not run: tee $*" >> "$STATE/calls"
    exit 0 ;;
esac
echo "sudo did not run: $*" >> "$STATE/calls"
""",
    "systemctl": _UNIT_RUN + r"""
echo "systemctl $*" >> "$STATE/calls"
verb=""; now=""; auditd=""; rules_unit=""
for word in "$@"; do
  case "$word" in
    --now) now=1 ;;
    -*) ;;
    *)
      if [ -z "$verb" ]; then verb="$word"; continue; fi
      case "$word" in
        auditd|auditd.service) auditd=1 ;;
        audit-rules|audit-rules.service) rules_unit=1 ;;
      esac ;;
  esac
done
case "$verb" in
  cat) [ -z "$rules_unit" ] || [ "$UNIT" != absent ] || exit 1; exit 0 ;;
  status|show|is-active|is-enabled|is-failed|list-units|list-unit-files) exit 0 ;;
esac
if [ -z "${AS_ROOT:-}" ]; then
  echo "Failed to $verb: Interactive authentication required. (the stub systemctl: not root)" >&2
  exit 1
fi
case "$verb" in
  start|restart|try-restart|reload-or-restart|try-reload-or-restart|condrestart|force-reload) ;;
  enable) [ -n "$now" ] || exit 0 ;;
  *) exit 0 ;;
esac
if [ -n "$auditd" ] && [ "$UNIT" != absent ]; then : > "$STATE/unit"; fi
if [ -n "$rules_unit" ]; then
  [ "$UNIT" != absent ] || { echo "Failed to start audit-rules.service: Unit audit-rules.service not found." >&2; exit 5; }
  unit_run
  [ "$UNIT" = ok ] || { echo "Job for audit-rules.service failed because the control process exited with error code." >&2; exit 1; }
fi
exit 0
""",
    # On a host with systemd, `service auditd start` is `systemctl start auditd`.
    "service": r"""
echo "service $*" >> "$STATE/calls"
[ -n "${AS_ROOT:-}" ] || { echo "service: not root (the stub)" >&2; exit 1; }
case "$1 $2" in
  "auditd start"|"auditd restart"|"auditd try-restart"|"auditd condrestart"|"auditd force-reload")
    [ "$UNIT" = absent ] || : > "$STATE/unit" ;;
esac
exit 0
""",
    "auditctl": _UNIT_RUN + r"""
echo "auditctl $*" >> "$STATE/calls"
[ -n "${AS_ROOT:-}" ] || { echo "You must be root to run this program." >&2; exit 4; }
late_run() { if [ -e "$STATE/unit" ]; then unit_run; fi; }
case "$1" in
  -a|-A|-w) echo "$*" >> "$STATE/rules" ;;
  -b) echo "$2" > "$STATE/backlog" ;;
  -l)
    if [ -s "$STATE/rules" ]; then cat "$STATE/rules"; else echo "No rules"; fi
    late_run ;;
  -s)
    echo "enabled 1"
    echo "backlog_limit $(cat "$STATE/backlog")"
    late_run ;;
esac
exit 0
""",
    # No step of these tests may reach a cluster, and none may wait.
    "docker": "exit 0",
    "kubectl": "exit 0",
    "kind": "exit 0",
    "sleep": "exit 0",
}
UNIT_STATES = ("ok", "error", "absent")
APT_INSTALL = ".github/scripts/apt_install.sh"


def no_faults(test, faults, advice):
    """Fail `test` when `faults` (a list of sentences) is not empty. The message is
    the advice and then each sentence as plain text: unittest shows a list that is
    not equal to [] as Python writes it, with each long sentence cut in parts."""
    if faults:
        test.fail(advice + "".join("\n  - " + fault for fault in faults))


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
        for name, text in (("calls", ""), ("rules", rules), ("backlog", "64\n"), ("audit.log", audit_log)):
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

    # A program that has a stub, named with a path: the shell would start the real one.
    REAL = re.compile(r"(?<![\w.-])/\S*/(?:" + "|".join(STUBS) + r")(?![\w./-])")
    AS_STUB = re.compile(r"\bsudo\s+/\S*/(systemctl|service|auditctl)(?![\w./-])")    # the stub `sudo` gives the stub

    def run_text(self, tree, step, run=None, env=None):
        """Run the text of a step (or `run`, a part of it) with the shell of the step
        and the stubs. The test fails, and the text does not run, when a line names
        a program that has a stub with a path (`/usr/bin/systemctl start ...`): that
        is the real program of the machine of the test."""
        real = [line for line in gatelib._command_lines(step.run if run is None else run)
                if self.REAL.search(self.AS_STUB.sub(r"sudo \1", apt.DirectInstalls.no_comment(line)))]
        if real:
            self.fail(f"{step.workflow}, job {step.job}, step {step.name!r}: the test does not run this step, "
                      "because a line names a program with a path and no stub can stand in for it: "
                      + real[0])
        values = {"STATE": tree.state, "UNIT": tree.unit, "SANDBOX": tree.sandbox,
                  "GITHUB_WORKSPACE": tree.root, "CLUSTER_NAME": "trr9003"}
        values.update(env or {})
        return tree.run_step(step if run is None else step._replace(run=run), env=values,
                             programs=STUBS, timeout=60)

    @staticmethod
    def the_step(workflow, job, name):
        found = [s for s in gatelib.ci_steps() if (s.workflow, s.job, s.name) == (workflow, job, name)]
        if len(found) != 1:
            raise LookupError(f"{workflow}, job {job}: {len(found)} step(s) with the name {name!r}; wanted 1. "
                              "The tests of test_labs.py find this step by its name. If the step has a new "
                              "name, put the new name in the test (AuditdStart.STEPS, FileSensorRule.STEPS, "
                              "LedgerClock.BENIGN, LedgerClock.SCORE): that says nothing about the lab")
        return found[0]


class AuditdStart(LabSteps):
    """auditd 4 (the ubuntu-26.04 runner image) has a oneshot unit, audit-rules.service,
    that loads the rule files. auditd.service wants that unit and does not wait for
    it, so `systemctl start auditd` starts the unit again and returns. The rule file
    of the package starts with -D, and it sets the backlog limit (-b 8192), the
    failure mode (-f 1) and --backlog_wait_time. In the static pod lab the step added
    its rule at once: the rule was in the list of `auditctl -l`, the unit deleted it
    1 ms later, and the lab had no file event.

    The rule, for each step that starts auditd:
      - after the start, the step waits for the unit (`sudo systemctl start` of a
        oneshot unit returns when the unit has ended). The wait is the lines of WAIT
        between the guard and its `fi`: auditd 3 has no such unit; the wait runs as
        root, because systemd starts a unit for a different user only with an
        authorization, which a step cannot give (the start then fails at once: that
        is known of systemd, and it was not tried on a runner); a unit that ends
        with an error gives a ::warning line and does not stop the step;
      - the wait is at the top level of the step: not in an outer `if`, a loop, a
        function, a subshell, a here-document or a quoted text, also when the start
        is in the same block. A step does not reach a wait in a block whose condition
        is false or in a function that nothing calls, and it does not wait for a
        subshell in the background. The rule asks `bash -n`: the command lines of
        the step to the `fi` of the wait are complete shell. (It does not ask when
        bash does not read the whole step: the tests that run the step then fail
        with the message of bash);
      - before the wait, and before the start, no line changes the rules or a setting
        of the audit system (an `auditctl` command that is not a status or a list),
        and between the start and the wait no line runs a validator.

    A start of auditd is `systemctl` with start, restart, try-restart,
    reload-or-restart (and the other verbs of STARTS) or `enable --now`, and auditd
    as one of its units; or `service auditd start` (restart, ...). The program can
    have a path, and options. A redirect that is joined to a word is not a part of
    the word (`systemctl start auditd>/dev/null`).

    A message can name a command (`echo "::error::the step Start auditd (sudo
    systemctl start auditd) failed"`), so the rule does not look for a start or an
    `auditctl` command in the words of a message. A message is a command whose first
    word is `echo` or `printf`, and whose output no different command takes: it is
    not before a pipe (`echo "..." | bash`) and not in a command substitution or a
    process substitution. A command substitution in a message is a command, and the
    rule reads it (`echo "$(sudo auditctl -l)"`). The check for a validator reads
    the whole line, so a message that names a validator between the start and the
    wait counts.

    It is a rule on text, one step at a time and one line at a time. It does not see:
      - a start that a script, a shell function or a different program makes (an
        init script such as /etc/init.d/auditd, `invoke-rc.d`; a file that a message
        wrote);
      - a command that is built at run time (`"$SYSTEMCTL" start auditd`, `systemctl
        start "$UNIT"`, a message in a group or a subshell whose output a pipe
        gives to a shell), or a unit that pulls auditd in (a target);
      - a start in a different step of the job than the rule;
      - before the wait, a change of the rules that has no option as a word of its
        `auditctl` command (`auditctl "${RULE[@]}"`, `xargs auditctl`), or that a
        different program makes (`augenrules --load`);
      - a wait at the top level that the step does not reach (a `&&` or a `||` at
        the end of the line before the guard): the tests that run each step of
        STEPS see that."""

    GUARD = "if systemctl cat audit-rules.service >/dev/null 2>&1; then"
    # The wait, as one command line (white space collapsed, the backslash line joined).
    WAIT = re.compile(r'sudo systemctl start audit-rules\.service \|\| echo "::warning [^"]*"')
    SPLIT = re.compile(r"\|\||&&|[;|&()`]|\$\(")        # where a command of a line ends
    MESSAGE = frozenset({"echo", "printf"})             # a command that prints its words
    # The words of the shell that can come before the first word of a command.
    BEFORE = frozenset({"{", "}", "if", "then", "elif", "else", "while", "until", "do", "!", "time"})
    STARTS = frozenset({"start", "restart", "try-restart", "reload-or-restart", "try-reload-or-restart",
                        "condrestart", "force-reload"})
    AUDITD = frozenset({"auditd", "auditd.service"})
    RULES_UNIT = frozenset({"audit-rules", "audit-rules.service"})
    # The options of auditctl that only read (-k is the key of a list).
    READS = frozenset({"-s", "-l", "-k", "-v", "-h", "--help"})
    # A program that loads its own audit rules.
    VALIDATOR = re.compile(r"python[\d.]*\s+(?:-\S+\s+)*\S*detections/(?:validate_\w+|benign/linux/capture)\.py")
    # (workflow, job, step) of each step that starts auditd today. The tests run the
    # text of these steps with the stubs. The step of the API server lab is one text
    # that two jobs run (a YAML alias).
    CAPTURE = ("detection-quality.yml", "benign-linux-live", "Start auditd (room for the whole capture window)")
    SENSOR = ("validate-staticpod-detections.yml", "validate", "Start the node file-event sensor (auditd, Strategy 3)")
    STEPS = [
        CAPTURE,
        ("validate-apiserver-detections.yml", "validate",
         "Start the node file-event sensor (auditd, TRR9006 Strategy 3)"),
        ("validate-apiserver-detections.yml", "validate-recommended",
         "Start the node file-event sensor (auditd, TRR9006 Strategy 3)"),
        ("validate-detections.yml", "validate", "Start auditd"),
        SENSOR,
    ]
    WARNING = "::warning title=auditd::audit-rules.service ended with an error"
    NO_WAIT = "starts auditd and does not wait for audit-rules.service"
    NESTED = ("the wait for audit-rules.service is not at the top level of the step: it is inside a "
              "compound command or a longer text (an outer `if`, a loop, a function, a subshell, a "
              "here-document, a quoted text). Put the wait at the top level of the step")

    @classmethod
    def top_commands(cls, line):
        """(text, alone) of each command of a command line, split outside quotes only
        (at the places of SPLIT). A command substitution (`$(...)`, backticks) is a
        command of its own, also inside double quotes, and the command around it
        goes on after it. `alone` is False for a command that gives its output to a
        different command: a command in a command substitution or in a process
        substitution (`<(...)`, `>(...)`), and a command before a pipe or before
        `>(...)`. The line is read alone: a quote that starts on a different line is
        not seen."""
        def command(closer=""):
            return {"text": "", "quote": "", "closer": closer, "depth": 0}

        found, stack, i = [], [command()], 0
        while i < len(line):
            top, char = stack[-1], line[i]
            substitution = line.startswith("$(", i)
            if top["quote"] == "'":                         # in single quotes: plain text
                top["quote"] = "" if char == "'" else "'"
                top["text"] += char
            elif char == "\\":                              # the next character is plain text
                top["text"] += line[i:i + 2]
                i += 1
            elif top["quote"] and not substitution and char not in '"`':
                top["text"] += char                         # in double quotes: plain text
            elif char in "\"'":
                top["quote"] = "" if top["quote"] else char
                top["text"] += char
            elif substitution or (char == "`" and top["closer"] != "`"):
                stack.append(command(")" if substitution else "`"))
                i += 1 if substitution else 0
            elif char == "`" or (char == ")" and top["closer"] == ")" and not top["depth"]):
                found.append((stack.pop()["text"], False))  # the end of a substitution
                stack[-1]["text"] += " "
            elif char in ";|&()":
                process = char == "(" and line[i - 1:i] in ("<", ">")
                pipe = (char == "|" and "|" not in (line[i - 1:i], line[i + 1:i + 2])) \
                    or (process and line[i - 1] == ">")
                found.append((top["text"], len(stack) == 1 and not pipe))
                top["text"] = ""
                if process:
                    stack.append(command(")"))
                else:
                    top["depth"] += (char == "(") - (char == ")" and top["depth"] > 0)
            else:
                top["text"] += char
            i += 1
        found += [(top["text"], number == 0) for number, top in enumerate(stack)]
        return [(text, alone) for text, alone in found if text.strip()]

    @staticmethod
    def word_of(text):
        """A word of a command without its quotes, and without a redirect that is
        joined to it (`auditd>/dev/null` is `auditd`; `2>/dev/null` is no word)."""
        whole = text.strip("\"'")
        word = re.split(r"[<>]", whole, maxsplit=1)[0]
        return "" if word != whole and word.isdigit() else word

    @classmethod
    def commands(cls, line, program):
        """The words after `program` in each command of a command line that names it:
        one list for each command. A word names the program when its last path part
        is the name (`sudo systemctl`, `/usr/bin/systemctl`, `"systemctl"`). A
        message is not read: a command whose first word is `echo` or `printf`, and
        whose output no different command takes. Each other command is split at
        each place of SPLIT, also inside quotes (`bash -c "systemctl start auditd;
        auditctl -l"`)."""
        found = []
        for command, alone in cls.top_commands(apt.DirectInstalls.no_comment(line)):
            if alone and next((word for word in command.split() if word not in cls.BEFORE), "") in cls.MESSAGE:
                continue
            for part in cls.SPLIT.split(command):
                words = [word for word in map(cls.word_of, part.split()) if word]
                at = next((i for i, word in enumerate(words) if word.rsplit("/", 1)[-1] == program), None)
                if at is not None:
                    found.append(words[at + 1:])
        return found

    @staticmethod
    def not_shell(text):
        """What `bash -n` says of a shell text: "" when bash reads the text to its end
        as complete shell. bash runs no command of the text. For a text that ends in
        a here-document, bash gives a warning and the exit code 0: that is a message."""
        done = subprocess.run(["bash", "--noprofile", "--norc", "-n"], input=text.encode("utf-8"),
                              capture_output=True, timeout=60, check=False)
        said = done.stderr.decode("utf-8", errors="replace").strip()
        return said or ("" if done.returncode == 0 else f"bash -n ended with {done.returncode}")

    @classmethod
    def nested(cls, lines, last):
        """True when line `last` of the lines of a step (the `fi` of a wait) is not at
        the top level of the step: bash reads all the lines as complete shell, and
        the lines to `last` are not complete shell."""
        return bool(cls.not_shell("\n".join(lines[:last + 1]) + "\n")) and not cls.not_shell("\n".join(lines) + "\n")

    @classmethod
    def starts_auditd(cls, line):
        """True when a command of the line starts auditd with systemctl or service."""
        for words in cls.commands(line, "systemctl"):
            plain = [word for word in words if not word.startswith("-")]
            if plain and cls.AUDITD.intersection(plain[1:]) and (
                    plain[0] in cls.STARTS or (plain[0] == "enable" and "--now" in words)):
                return True
        for words in cls.commands(line, "service"):
            plain = [word for word in words if not word.startswith("-")]
            if len(plain) > 1 and plain[0] in cls.AUDITD and plain[1] in cls.STARTS:
                return True
        return False

    @classmethod
    def starts_the_unit(cls, line):
        """True when a command of the line starts audit-rules.service: the place of
        the wait. faults() then asks if the line is the accepted wait."""
        for words in cls.commands(line, "systemctl"):
            plain = [word for word in words if not word.startswith("-")]
            if plain and plain[0] in cls.STARTS and cls.RULES_UNIT.intersection(plain[1:]):
                return True
        return False

    @classmethod
    def changes(cls, line):
        """True when an auditctl command of the line changes the rules or a setting:
        each auditctl command with an option that is not in READS (-a, -w, -R, -D,
        -b, -f, -e, -r, --backlog_wait_time, ...)."""
        return any(word.startswith("-") and word not in cls.READS
                   for words in cls.commands(line, "auditctl") for word in words)

    @classmethod
    def uses(cls, line):
        """True when the line changes the rules or a setting, or runs a validator."""
        return cls.changes(line) or bool(cls.VALIDATOR.search(line))

    @classmethod
    def faults(cls, step):
        """What is wrong with a step that starts auditd, as a list of sentences (empty:
        nothing, or the step does not start auditd)."""
        lines = gatelib._command_lines(step.run)
        starts = [i for i, line in enumerate(lines) if cls.starts_auditd(line)]
        if not starts:
            return []
        found = []
        early = [line for line in lines[:starts[-1]] if cls.changes(line)]
        if early:
            found.append("changes the audit rules or a setting of the audit system before a start of "
                         "auditd; the run of audit-rules.service that the start causes loads the rule "
                         "file of the image in their place: " + early[0])
        for start in starts:
            after = lines[start + 1:]
            wait = next((i for i, line in enumerate(after) if cls.starts_the_unit(line)), None)
            if wait is None:
                found.append(cls.NO_WAIT)
                continue
            early = [line for line in [lines[start]] + after[:wait] if cls.uses(line)]
            if early:
                found.append("changes the audit rules or a setting of the audit system, or runs a "
                             "validator, before the wait for audit-rules.service: " + early[0])
            if wait == 0 or after[wait - 1] != cls.GUARD or after[wait + 1:wait + 2] != ["fi"]:
                found.append("the wait for audit-rules.service is not between the guard `" + cls.GUARD
                             + "` and its `fi`")
            elif cls.nested(lines, start + wait + 2):
                found.append(cls.NESTED)
            if cls.WAIT.fullmatch(after[wait]):
                continue
            if "sudo" not in after[wait].split("systemctl", 1)[0].split():
                found.append("the wait for audit-rules.service does not run as root (`sudo systemctl start "
                             "audit-rules.service`): systemd refuses such a start, and the step goes on "
                             "with no wait")
            elif '|| echo "::warning ' not in after[wait]:
                found.append("a unit that ends with an error does not give a ::warning line "
                             "(`... || echo \"::warning ...\"`)")
            else:
                found.append("the wait line is not `sudo systemctl start audit-rules.service || echo "
                             "\"::warning ...\"` and no more (a `&` after it puts the wait in the "
                             "background): " + after[wait])
        return found

    @classmethod
    def starting_steps(cls, root=gatelib.REPO):
        """Each step of the workflows under `root` that starts auditd."""
        return [step for step in gatelib.ci_steps(root=root)
                if any(cls.starts_auditd(line) for line in gatelib._command_lines(step.run))]

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
        no_wait = self.NO_WAIT
        before_the_wait = "before the wait for audit-rules.service: "
        faulty = {
            "the step of 2026-11-12": (start + add, no_wait),
            "no rule in the step": (start + "sudo auditctl -s\n", no_wait),
            "restart": ("sudo systemctl restart auditd\n" + add, no_wait),
            "the unit name": ("sudo systemctl start auditd.service\n" + add, no_wait),
            "the wait in a comment": (start + "# sudo systemctl start audit-rules.service\n" + add, no_wait),
            "the wait before the start": (wait + start + add, no_wait),
            # Other forms of the start.
            "service, and no systemctl": ("sudo service auditd start\n" + add, no_wait),
            "service restart": ("sudo service auditd restart\n" + add, no_wait),
            "enable --now": ("sudo systemctl enable --now auditd\n" + add, no_wait),
            "enable, with --now after the unit": ("sudo systemctl enable auditd --now\n" + add, no_wait),
            "try-restart": ("sudo systemctl try-restart auditd\n" + add, no_wait),
            "reload-or-restart": ("sudo systemctl reload-or-restart auditd.service\n" + add, no_wait),
            "a path": ("sudo /usr/bin/systemctl start auditd\n" + add, no_wait),
            "service with a path": ("sudo /usr/sbin/service auditd start\n" + add, no_wait),
            "an option": ("sudo systemctl --no-block start auditd\n" + add, no_wait),
            "two units": ("sudo systemctl start docker auditd\n" + add, no_wait),
            "in a condition": ("if ! sudo systemctl start auditd; then exit 1; fi\n" + add, no_wait),
            "a second start after the wait": (start + wait + "sudo service auditd restart\n" + add, no_wait),
            "a second start, with a path": (start + wait + "sudo /usr/bin/systemctl restart auditd\n" + add, no_wait),
            "a second start, reload-or-restart": (start + wait + "sudo systemctl reload-or-restart auditd\n" + add,
                                                  no_wait),
            # The wait is there, and a line before it changes a rule or a setting.
            "the rule before the wait": (start + add + wait, before_the_wait + "sudo auditctl -a"),
            "a watch before the wait": (start + "sudo auditctl -w /etc/passwd -p wa\n" + wait, before_the_wait),
            "a rule file before the wait": (start + "sudo auditctl -R detections/audit/atomic.rules\n" + wait,
                                            before_the_wait),
            "auditctl with a path": (start + "sudo /usr/sbin/auditctl -a always,exit -F dir=/x -F perm=wa\n" + wait,
                                     before_the_wait + "sudo /usr/sbin/auditctl -a"),
            "the validator before the wait": (
                start + "sudo /tmp/venv/bin/python detections/validate_detections.py --require-audit\n" + wait,
                before_the_wait),
            # The rule file of the unit also sets -b, -f and --backlog_wait_time.
            "the backlog limit before the wait": (start + "sudo auditctl -b 32768 || true\n" + wait + add,
                                                  before_the_wait + "sudo auditctl -b 32768"),
            "the failure mode before the wait": (start + "sudo auditctl -f 2\n" + wait, before_the_wait),
            "the wait time before the wait": (start + "sudo auditctl --backlog_wait_time 0\n" + wait,
                                              before_the_wait),
            "enabled before the wait": (start + "sudo auditctl -e 1\n" + wait, before_the_wait),
            "the rate before the wait": (start + "sudo auditctl -r 0\n" + wait, before_the_wait),
            "the rule before the start": (add + start + wait, "before a start of auditd"),
            "the backlog limit before the start": ("sudo auditctl -b 32768\n" + start + wait,
                                                   "before a start of auditd"),
            # The form of the wait.
            "no guard": (start + 'sudo systemctl start audit-rules.service || echo "::warning x"\n' + add,
                         "is not between the guard"),
            "the guard goes to the background": (start + wait.replace("fi\n", "fi &\n") + add,
                                                 "is not between the guard"),
            "a hard failure": (start + self.GUARD + "\n  sudo systemctl start audit-rules.service\nfi\n" + add,
                               "does not give a ::warning line"),
            "a failure with no word": (start + self.GUARD + "\n  sudo systemctl start audit-rules.service || true\nfi\n"
                                       + add, "does not give a ::warning line"),
            "the wait without sudo": (start + wait.replace("  sudo systemctl start audit-rules",
                                                           "  systemctl start audit-rules") + add,
                                      "does not run as root"),
            "the wait in the background": (start + wait.replace('error"\n', 'error" &\n') + add,
                                           "and no more"),
            # The wait is not at the top level of the step.
            "the wait in an outer if that the step reaches": (
                start + "if [ -d /run/systemd/system ] || true; then\n" + wait + "fi\n" + add, self.NESTED),
            "the wait in an outer if that is false": (
                start + 'if [ -n "${WAIT_FOR_RULES:-}" ]; then\n' + wait + "fi\n" + add, self.NESTED),
            "the wait in a subshell in the background": (start + "(\n" + wait + ") &\n" + add, self.NESTED),
            "the wait in a function that nothing calls": (start + "wait_rules() {\n" + wait + "}\n" + add,
                                                          self.NESTED),
            "the wait in a loop": (start + "for unit in audit-rules; do\n" + wait + "done\n" + add, self.NESTED),
            "the wait in a here-document": (start + ": <<'SKIP'\n" + wait + "SKIP\n" + add, self.NESTED),
            "the wait in a quoted text": (start + "bash -c '\n" + wait + "'\n" + add, self.NESTED),
            "the start and the wait in one block": (
                'if [ "${RUNNER_OS}" = Linux ]; then\n' + start + wait + add + "fi\n", self.NESTED),
            # A command in a message, and a message before a command.
            "a start in a command substitution of a message": (
                'echo "started: $(sudo systemctl start auditd)"\n' + add, no_wait),
            "a start in backticks in a message": ('echo "started: `sudo systemctl start auditd`"\n' + add, no_wait),
            "a rule in a command substitution of a message": (
                start + 'echo "rules: $(sudo auditctl -D) deleted"\n' + wait, before_the_wait + "echo"),
            "a start after a message": ('echo "start auditd; then the rules" && sudo systemctl start auditd\n' + add,
                                        no_wait),
            "a start after a message in a block": (
                '{ echo "::group::auditd"; sudo systemctl start auditd; }\n' + add, no_wait),
            "a message that a pipe gives to a shell": ('echo "sudo systemctl start auditd" | sudo bash\n' + add,
                                                       no_wait),
            "a message that eval runs": ('eval "$(echo "sudo systemctl start auditd")"\n' + add, no_wait),
            "a message that a shell reads as a file": ('sudo bash <(echo "systemctl start auditd")\n' + add, no_wait),
            "a start in the text of a shell": ('sudo bash -c "systemctl start auditd; auditctl -l"\n' + add, no_wait),
            "a rule in the text of a shell": (start + "sudo sh -c 'auditctl -l; auditctl -D'\n" + wait,
                                              before_the_wait),
            # A redirect that is joined to a word.
            "a redirect joined to the unit": ("sudo systemctl start auditd>/dev/null\n" + add, no_wait),
            "redirects before the verb": ("sudo systemctl 2>/dev/null >/dev/null start auditd\n" + add, no_wait),
            "a redirect joined to an option": (start + "sudo auditctl -D>/dev/null\n" + wait, before_the_wait),
        }
        sound = {
            "the wait, then the rule": start + wait + add,
            "the wait, and no rule in the step": start + wait + "sudo auditctl -s\n",
            "a status and a list before the wait": start + "sudo auditctl -s\nsudo auditctl -l -k x\n" + wait + add,
            "a list before the start": 'rules="$(sudo auditctl -l 2>/dev/null || true)"\n' + start + wait + add,
            "the wait, then a setting": start + wait + "sudo auditctl -b 32768 || true\n" + add,
            "no start of auditd": add + "sudo auditctl -l\n",
            "the start in a comment": "# sudo systemctl start auditd\n" + add,
            "the start in a comment at the end of a line": "sudo auditctl -l   # not: systemctl start auditd\n" + add,
            "a different unit": "sudo systemctl start docker\nsudo systemctl start auditd-exporter\n" + add,
            "a different program": "sudo my-systemctl start auditd\nsudo systemctl.old start auditd\n" + add,
            "enable, and no --now": "sudo systemctl enable auditd\n" + add,
            "a status of the unit": "systemctl is-active auditd\nsudo systemctl status auditd\n"
                                    "sudo service auditd status\n" + add,
            "a stop": "sudo systemctl stop auditd\n" + add,
            "only the unit": wait + add,
            # A message that names a command is not the command.
            "the start in a message": 'echo "::error::auditd is down (sudo systemctl start auditd failed in the '
                                      'step before)"\n' + add,
            "the start in a message after a command": (
                'sudo auditctl -l | tee /tmp/rules.out || { echo "::error::no list; the step Start auditd (sudo '
                'systemctl start auditd) failed first"; exit 1; }\n' + add),
            "the start in a message of printf": "printf '%s\\n' 'next: sudo service auditd restart'\n" + add,
            "the start in a message in a condition": (
                'if ! sudo auditctl -s; then echo "run: sudo systemctl restart auditd"; fi\n' + add),
            "a rule in a message before the wait": (
                start + 'echo "next: sudo auditctl -a always,exit -F dir=/x -F perm=wa"\n' + wait + add),
            "a list with a redirect before the wait": start + "sudo auditctl -l>/tmp/rules.out 2>&1\n" + wait + add,
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
        no_faults(self, self.all_faults(), "these steps start auditd, and audit-rules.service (auditd 4) can "
                  "put back a rule or a setting that the step changes after that start. Add the wait that "
                  "the other steps have, after the start and before the first such line "
                  "(detections/tests/README.md, `CI`, shows the lines). The rule reads the words of a "
                  "message (`echo`, `printf`) as a command only when a pipe takes the output of the "
                  "message, or when the message is in a command substitution")
        # The steps were read (not vacuous), and the tests that run a step run each one.
        found = [(step.workflow, step.job, step.name) for step in self.starting_steps()]
        no_faults(self, [f"{name}: the step starts auditd and is not in STEPS. It has the wait (the rule found "
                         "no fault). Read its lines to the end of the wait, then add it to STEPS: the tests "
                         "then run those lines with the stubs of test_labs.py"
                         for name in found if name not in self.STEPS]
                  + [f"{name}: the entry is in STEPS, and the rule finds no start of auditd in such a step. "
                     "If the step has a new name, put the new name in the entry; if the step is gone, "
                     "delete the entry" for name in self.STEPS if name not in found],
                  "AuditdStart.STEPS is not the list of the steps that start auditd")

    def test_a_planted_step_without_the_wait_is_rejected(self):
        """Planted steps in a copy of the workflows: the step of the static pod lab as
        it was on 2026-11-12, a step that waits after it added its rule, a step that
        starts auditd with `service` and waits without sudo, and a step with the wait
        in an outer `if`. CONTROL: a new step with the wait has no fault, and a step
        with a message that names the start is not a step that starts auditd."""
        tree = gatelib.Tree((".github",))
        self.addCleanup(tree.cleanup)
        self.assertEqual(self.all_faults(tree.root), [])        # CONTROL: the copy has no fault
        head = "on: push\njobs:\n  lab:\n    runs-on: ubuntu-latest\n    steps:\n"
        wait = ("          " + self.GUARD + "\n"
                "            sudo systemctl start audit-rules.service \\\n"
                "              || echo \"::warning title=auditd::audit-rules.service ended with an error\"\n"
                "          fi\n")
        tree.write(".github/workflows/sound-lab.yml", (
            head + "      - name: Start a new sensor\n        shell: bash\n        run: |\n"
            "          sudo systemctl start auditd || sudo service auditd start\n" + wait
            + "          sudo auditctl -a always,exit -F dir=/srv/x -F perm=wa -F key=new_lab\n"
            "      - name: Read the rules\n        shell: bash\n        run: |\n"
            "          sudo auditctl -l | tee /tmp/rules.out || { echo \"::error::no list of the rules; if auditd "
            "is down, the step Start a new sensor (sudo systemctl start auditd) failed first\"; exit 1; }\n"))
        self.assertEqual(self.all_faults(tree.root), [])        # CONTROL: a new step with the wait
        starting = [(step.workflow, step.job, step.name) for step in self.starting_steps(tree.root)]
        self.assertIn(("sound-lab.yml", "lab", "Start a new sensor"), starting)
        self.assertNotIn(("sound-lab.yml", "lab", "Read the rules"), starting)     # CONTROL: a message
        tree.write(".github/workflows/planted-lab.yml", (
            head + "      - name: Start the sensor\n        shell: bash\n        run: |\n"
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
            "          fi\n"
            "      - name: Start the sensor with service, wait without sudo\n        run: |\n"
            "          sudo /usr/sbin/service auditd start\n"
            + wait.replace("sudo systemctl start audit-rules", "systemctl start audit-rules")
            + "          sudo /usr/sbin/auditctl -a always,exit -F dir=/srv/x -F perm=wa -F key=new_lab\n"
            "      - name: Start the sensor, wait in an outer block\n        run: |\n"
            "          sudo systemctl start auditd\n"
            "          if [ -d /run/systemd/system ] || true; then\n"
            + wait
            + "          fi\n"
            "          sudo auditctl -a always,exit -F dir=/srv/x -F perm=wa -F key=new_lab\n"))
        self.assertEqual(self.all_faults(tree.root), [
            "planted-lab.yml, job lab, step 'Start the sensor': " + self.NO_WAIT,
            "planted-lab.yml, job lab, step 'Start the sensor, wait too late': changes the audit rules or a "
            "setting of the audit system, or runs a validator, before the wait for audit-rules.service: sudo "
            "auditctl -w /etc/kubernetes/manifests -p wa -k k8s_node_file",
            "planted-lab.yml, job lab, step 'Start the sensor with service, wait without sudo': the wait for "
            "audit-rules.service does not run as root (`sudo systemctl start audit-rules.service`): systemd "
            "refuses such a start, and the step goes on with no wait",
            "planted-lab.yml, job lab, step 'Start the sensor, wait in an outer block': " + self.NESTED])

    def a_part(self, step, text, cause):
        """`text`, a part of the text of `step` that a test runs. The test fails when
        the part is not complete shell: bash would only say `unexpected end of file`
        of a text that the test made. The message is `cause` when bash reads the
        whole step, and what `bash -n` says of the step when it does not."""
        if self.not_shell(text):
            said = self.not_shell(step.run)
            self.fail(f"{step.workflow}, job {step.job}, step {step.name!r}: "
                      + (cause if not said else "bash does not read the text of the step as complete shell. "
                                                "`bash -n` says: " + said))
        return text

    def wait_of(self, step):
        """(first, last) line numbers of the wait in the text of a step: from the guard
        to its `fi`. The test fails when the step has no such lines, and when the
        wait is not at the top level of the step."""
        lines = [line.strip() for line in step.run.splitlines()]
        if self.GUARD not in lines or "fi" not in lines[lines.index(self.GUARD):]:
            self.fail(f"{step.workflow}, job {step.job}, step {step.name!r}: no wait for "
                      "audit-rules.service in the guard `" + self.GUARD + "`")
        first = lines.index(self.GUARD)
        last = lines.index("fi", first)
        self.a_part(step, "\n".join(step.run.splitlines()[:last + 1]) + "\n", self.NESTED)
        return first, last

    def start_of(self, step):
        """The text of a step from its first line to the end of its wait."""
        return "\n".join(step.run.splitlines()[:self.wait_of(step)[1] + 1]) + "\n"

    def without_the_wait(self, step):
        """The text of a step without the lines of its wait: the step as it was."""
        first, last = self.wait_of(step)
        lines = step.run.splitlines()
        return self.a_part(step, "\n".join(lines[:first] + lines[last + 1:]) + "\n",
                           "the step without the lines of its wait is not complete shell: the wait is a part of "
                           "a longer command (a `&&`, a `||` or a `|` at the end of the line before the guard). "
                           "Put the wait on lines of its own")

    WAIT_AS_ROOT = re.compile(r"^([ \t]*)sudo (systemctl start audit-rules\.service)", re.MULTILINE)

    def without_sudo(self, step, text):
        """`text` (the text of `step`, or a part of it) with its wait line without
        `sudo`. The test fails when the text does not have one such line."""
        changed, count = self.WAIT_AS_ROOT.subn(r"\1\2", text)
        self.assertEqual(count, 1, f"{step.workflow}, job {step.job}, step {step.name!r}: the test takes "
                         "`sudo` from the one line that starts with `sudo systemctl start audit-rules.service`; "
                         f"the text has {count} such line(s)")
        return changed

    def test_the_wait_ends_in_each_state_of_the_unit(self):
        """Each step of the workflows that starts auditd, from its first line to the end
        of its wait, with the stubs: the step goes on in each state of the unit, and
        when it goes on no run of the unit is in progress. A unit that ends with an
        error gives one warning. Where there is no unit, the step does not start it."""
        wait = "systemctl start audit-rules.service"
        for name in self.STEPS:
            step = self.the_step(*name)
            for unit in UNIT_STATES:
                with self.subTest(step=name, unit=unit):
                    tree = self.lab(unit)
                    done = self.run_text(tree, step, self.start_of(step) + 'echo "the step goes on"\n')
                    why = ("the step, from its first line to the end of its wait, with the stubs of "
                           "test_labs.STUBS (a program of these lines that has no stub there needs "
                           "one):\n" + done.describe())
                    self.assertEqual(done.returncode, 0, why)
                    self.assertEqual(done.stdout.splitlines()[-1:], ["the step goes on"], why)
                    self.assertIsNone(self.state(tree, "unit"), "a run of audit-rules.service is in "
                                      "progress after the wait of the step:\n" + done.describe())
                    calls = self.state(tree, "calls")
                    if unit == "absent":
                        self.assertNotIn(wait, calls, "the step started a unit that the host does not have")
                    else:
                        self.assertIn(wait, calls)
                    self.assertEqual([line for line in done.stdout.splitlines() if line.startswith("::")],
                                     [line for line in done.stdout.splitlines() if line.startswith(self.WARNING)],
                                     "to the end of its wait, the step prints no `::` line but the warning of the "
                                     "wait, and that line starts with `" + self.WARNING + "` (AuditdStart.WARNING: "
                                     "the tests find the warning of a run by this text):\n" + done.describe())
                    self.assertEqual(done.stdout.count(self.WARNING), 1 if unit == "error" else 0, done.describe())

    def test_a_wait_that_is_not_at_the_top_level_is_named_before_a_run(self):
        """CONTROL of the parts of a step that the tests run. For a constructed step
        with the wait in an outer `if`, in a subshell, in a function, in a
        here-document or in a quoted text, the cut at the `fi` of the wait is not
        complete shell, and bash would only say `unexpected end of file`. The
        functions that cut a step fail first, with the sentence of the rule. A step
        whose wait is the last part of a longer command, and a step that is not
        shell, fail with a sentence too. CONTROL: a step with the wait at the top
        level gives its parts."""
        start = "sudo systemctl start auditd || sudo service auditd start\n"
        wait = (self.GUARD + "\n"
                "  sudo systemctl start audit-rules.service \\\n"
                '    || echo "' + self.WARNING + '"\n'
                "fi\n")
        add = "sudo auditctl -a always,exit -F dir=/x -F perm=wa -F key=k8s_node_file\n"

        def step(run):
            return gatelib.Step("w.yml", "job", "step", "bash", run)

        def refused(call, run):
            with self.assertRaises(AssertionError) as caught:
                call(step(run))
            return str(caught.exception)

        sound = step(start + wait + add)
        self.assertEqual(self.wait_of(sound), (1, 4))
        self.assertEqual(self.start_of(sound), start + wait)
        self.assertEqual(self.without_the_wait(sound), start + add)
        nested = {
            "an outer if that the step reaches": "if [ -d /run/systemd/system ] || true; then\n" + wait + "fi\n",
            "an outer if that is false": 'if [ -n "${WAIT_FOR_RULES:-}" ]; then\n' + wait + "fi\n",
            "a subshell in the background": "(\n" + wait + ") &\n",
            "a function that nothing calls": "wait_rules() {\n" + wait + "}\n",
            "a here-document": ": <<'SKIP'\n" + wait + "SKIP\n",
            "a quoted text": "bash -c '\n" + wait + "'\n",
        }
        for name, block in nested.items():
            with self.subTest(wait_in=name):
                for call in (self.wait_of, self.start_of, self.without_the_wait):
                    self.assertEqual(refused(call, start + block + add),
                                     "w.yml, job job, step 'step': " + self.NESTED)
                self.assertEqual(self.faults(step(start + block + add)), [self.NESTED])
        # The wait is the last part of a longer command: the cut to its `fi` is shell.
        longer = step(start + add + '[ -n "${WAIT_FOR_RULES:-}" ] &&\n' + wait)
        self.assertEqual(self.start_of(longer), longer.run)
        self.assertIn("the wait is a part of a longer command", refused(self.without_the_wait, longer.run))
        # A step that bash does not read: the message is what bash says of the step.
        for call in (self.wait_of, self.start_of, self.without_the_wait):
            said = refused(call, start + "if true; then\n" + wait + add)
            self.assertIn("bash does not read the text of the step as complete shell. `bash -n` says: ", said)
            self.assertNotIn(self.NESTED, said)

    def test_a_wait_that_is_not_root_does_not_wait(self):
        """CONTROL of the stubs. A constructed step that starts auditd and waits
        without `sudo`: the wait fails at once, the step prints the warning and goes
        on, and the run of the unit is still in progress. The same change to the
        start of each step: the rule on text refuses it, and in the run the stub
        refuses the start of the unit."""
        refused = "(the stub systemctl: not root)"
        tree = self.lab("ok")
        done = self.run_text(tree, gatelib.Step("w.yml", "job", "step", "bash", ""), (
            "sudo systemctl start auditd || sudo service auditd start\n" + self.GUARD + "\n"
            "  systemctl start audit-rules.service \\\n"
            '    || echo "' + self.WARNING + '"\nfi\necho "the step goes on"\n'))
        self.assertEqual((done.returncode, done.stdout.splitlines()), (0, [self.WARNING, "the step goes on"]),
                         done.describe())
        self.assertIn(refused, done.stderr)
        self.assertEqual(self.state(tree, "unit"), [], "the model: a start of the unit that is not root "
                         "does not wait for the run in progress")
        for name in self.STEPS:
            step = self.the_step(*name)
            with self.subTest(step=name):
                text = self.without_sudo(step, self.start_of(step))
                self.assertIn("does not run as root", " / ".join(self.faults(step._replace(run=text))))
                done = self.run_text(self.lab("ok"), step, text + 'echo "the step goes on"\n')
                self.assertEqual(done.returncode, 0, done.describe())
                self.assertEqual(done.stdout.count(self.WARNING), 1, "with a wait that is not root, the step "
                                 "prints the warning of the wait one time: a line that starts with `"
                                 + self.WARNING + "` (AuditdStart.WARNING):\n" + done.describe())
                self.assertIn(refused, done.stderr)

    def test_a_line_that_names_a_real_program_does_not_run(self):
        """CONTROL of the stubs: a step text that names a program that has a stub with
        a path does not run (the shell would start the program of the machine). After
        `sudo`, the stub gives the stub of systemctl, service and auditctl."""
        step = gatelib.Step("w.yml", "job", "step", "bash", "")
        tree = self.lab()
        for run in ("/usr/bin/systemctl start auditd\n", "sudo /usr/bin/docker ps\n",
                    'rules="$(/usr/sbin/auditctl -l)"\n', "true && /bin/sleep 600\n", "/usr/bin/sudo auditctl -l\n"):
            with self.subTest(run=run):
                with self.assertRaises(AssertionError) as caught:
                    self.run_text(tree, step, "echo before\n" + run)
                self.assertIn("a line names a program with a path", str(caught.exception))
        self.assertEqual(self.state(tree, "calls"), [])
        done = self.run_text(tree, step, "sudo /usr/bin/systemctl start auditd\nsudo /usr/sbin/auditctl -s\n"
                             "# /usr/bin/systemctl start auditd\necho /var/lib/docker/x /usr/bin/systemctl-old\n")
        self.assertEqual(done.returncode, 0, done.describe())
        self.assertEqual(self.state(tree, "calls"), ["systemctl start auditd", "auditctl -s"])
        self.assertIn("backlog_limit 64", done.stdout.splitlines())         # the stub answered

    def test_sudo_tee_writes_no_file_outside_the_sandbox(self):
        """CONTROL of the stubs: `tee` is the one real program that the stub `sudo`
        starts. It writes a file of the sandbox (a step names /tmp/). For a file in
        a different place, also through `..`, and for a relative path, the stub
        starts nothing: it reads its input to the end (the command before the pipe
        does not fail) and writes the command to `calls`."""
        tree = self.lab()
        with tempfile.TemporaryDirectory(prefix="deteng-outside-") as outside:
            target = os.path.join(outside, "x.rules")
            through = os.path.join(tree.sandbox, os.path.relpath(os.path.realpath(outside), tree.sandbox), "y.rules")
            self.assertTrue(through.startswith(tree.sandbox + "/../"), through)
            done = self.run_text(tree, gatelib.Step("w.yml", "job", "step", "bash", ""), (
                "echo inside | sudo tee /tmp/inside.log >/dev/null\n"
                'echo outside | sudo tee "$OUTSIDE" >/dev/null\n'
                'seq 1 20000 | sudo tee -a "$THROUGH" >/dev/null\n'
                "echo relative | sudo tee z.rules >/dev/null\n"
                'echo "the step goes on"\n'), env={"OUTSIDE": target, "THROUGH": through})
            self.assertEqual((done.returncode, done.stdout), (0, "the step goes on\n"), done.describe())
            self.assertEqual(os.listdir(outside), [], "the stub `sudo` wrote a file outside the sandbox")
        with open(tree.tmp_path("inside.log"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "inside\n")
        self.assertFalse(tree.exists("z.rules"))
        self.assertEqual(self.state(tree, "calls"), ["sudo did not run: tee " + target,
                                                     "sudo did not run: tee -a " + through,
                                                     "sudo did not run: tee z.rules"])

    def test_the_sensor_step_of_the_static_pod_lab_keeps_its_rule(self):
        """The whole step of the static pod lab, with the model of the fault in the
        stubs: the rule of the sensor is loaded when the step has ended, in each
        state of the unit. CONTROL: the step as it was (no wait) passes its own
        check, and the rule is gone when the step has ended, as in CI on 2026-11-13.
        The same is true for the step with a wait that is not root."""
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
                    wait = "systemctl start audit-rules.service"
                    self.assertIn(wait, calls, "the step did not call `" + wait + "`, with these words and no "
                                  "more:\n" + done.describe())
                    self.assertLess(calls.index(wait), add, "the step added the rule of the sensor before "
                                    "audit-rules.service ended:\n" + done.describe())
                self.assertEqual(done.stdout.count(self.WARNING), 1 if unit == "error" else 0, done.describe())
                self.assertNotIn("::error", done.output)
        old = self.without_the_wait(step)
        self.assertEqual(self.faults(step._replace(run=old)), [self.NO_WAIT])
        tree = self.lab("ok")
        done = self.run_text(tree, step, old)
        self.assertEqual(done.returncode, 0, done.describe())           # its check saw the rule
        self.assertEqual(self.state(tree, "rules"), [], "the model of the fault did not delete the rule")
        # On auditd 3 the old step kept its rule: the fault came with the unit.
        tree = self.lab("absent")
        self.assertEqual(self.run_text(tree, step, old).returncode, 0)
        self.assertEqual(len(self.state(tree, "rules")), 1)
        # A wait that is not root: the step passes its own check, and the rule is gone.
        tree = self.lab("ok")
        done = self.run_text(tree, step, self.without_sudo(step, step.run))
        self.assertEqual(done.returncode, 0, done.describe())
        self.assertEqual(self.state(tree, "rules"), [], "the model of the fault did not delete the rule")

    def test_the_capture_step_keeps_its_backlog_limit(self):
        """The whole step of the benign-linux-live job, with the model of the fault: the
        backlog limit that the step sets is the limit when the step has ended, in
        each state of the unit. CONTROL: with the wait after `auditctl -b`, and with
        no wait, the unit sets the limit back to the 8192 of its rule file; with no
        wait the status of the step still shows the limit of the step."""
        step = self.the_step(*self.CAPTURE)
        first, last = self.wait_of(step)
        lines = step.run.splitlines()
        sets = [i for i, line in enumerate(lines) if re.match(r"sudo auditctl -b \d+(?: |$)", line.strip())]
        self.assertEqual(len(sets), 1, "the test reads the backlog limit of the step from its one line "
                         "`sudo auditctl -b N`; the step has " + str(len(sets)) + " such line(s)")
        limit = lines[sets[0]].split()[3]
        self.assertNotEqual(limit, "8192", "the limit of the step is the limit of the rule file of the unit, "
                            "so this test cannot show which of the two is in force")
        for unit in UNIT_STATES:
            with self.subTest(unit=unit):
                tree = self.lab(unit)
                done = self.run_text(tree, step)
                self.assertEqual(done.returncode, 0, done.describe())
                self.assertEqual(self.state(tree, "backlog"), [limit], "the backlog limit of the step "
                                 "is not the limit when the step has ended:\n" + done.describe())
                self.assertIsNone(self.state(tree, "unit"), "a run of audit-rules.service is in progress")
                self.assertIn("backlog_limit " + limit, done.stdout.splitlines())
        self.assertLess(last, sets[0], "the CONTROL moves the wait after the line that sets the limit")
        late = self.a_part(step, "\n".join(lines[:first] + lines[last + 1:sets[0] + 1] + lines[first:last + 1]
                                            + lines[sets[0] + 1:]) + "\n",
                           "the test moves the wait after the line `sudo auditctl -b N`, and that text is not "
                           "complete shell. Write that line as one line, with no `\\` at its end")
        found = self.faults(step._replace(run=late))
        self.assertEqual(len(found), 1, found)
        self.assertIn("before the wait for audit-rules.service: sudo auditctl -b " + limit, found[0])
        tree = self.lab("ok")
        self.assertEqual(self.run_text(tree, step, late).returncode, 0)
        self.assertEqual(self.state(tree, "backlog"), ["8192"], "the model of the fault did not set the limit back")
        tree = self.lab("ok")
        done = self.run_text(tree, step, self.without_the_wait(step))
        self.assertEqual(done.returncode, 0, done.describe())
        self.assertIn("backlog_limit " + limit, done.stdout.splitlines())       # the status of the step
        self.assertEqual(self.state(tree, "backlog"), ["8192"], "the model of the fault did not set the limit back")
        # On auditd 3 the step without the wait kept its limit: the fault came with the unit.
        tree = self.lab("absent")
        self.assertEqual(self.run_text(tree, step, self.without_the_wait(step)).returncode, 0)
        self.assertEqual(self.state(tree, "backlog"), [limit])


class FileSensorRule(LabSteps):
    """The second line of defence of the static pod lab. The step that captures the
    file events before the emulation, and the step that collects them after it, ask
    `auditctl -l` for the rule of the file sensor. When the key k8s_node_file is not
    in the list, each prints an ::error line that names the cause. Neither stops: the
    validator fails closed without events. Its file gate needs the record of the
    emulation: the write of the manifest of Procedure A, which is the first procedure.
    Its file control needs the manifest writes of kubeadm, which are in the log from
    the time when the cluster was created: the control fails only when the rule was
    gone before that. Each ::error line says which of the two fails when."""

    WORKFLOW, JOB = "validate-staticpod-detections.yml", "validate"
    STEPS = ("Capture the node file events before the emulation (negative control)",
             "Collect the audit log and the node sensor log")
    RULE = "-w /home/runner/work/det-eng/det-eng/.kind/trr9003-manifests -p wa -k k8s_node_file\n"
    ERROR = ("::error title=file sensor::the audit rule of the file sensor is not loaded "
             "('auditctl -l' does not list the key k8s_node_file)")
    # What each step says of the two checks of the validator.
    FAILS = {STEPS[0]: "the file gate will fail, and the file control too if the rule was gone before the "
                       "cluster was created",
             STEPS[1]: "the file gate fails if that was before Procedure A wrote its manifest, and the file "
                       "control if it was before the cluster was created"}
    # One record of the marked writer: the collect step stops its poll when it sees one.
    RECORD = ('type=SYSCALL msg=audit(1794601947.257:300): arch=c000003e syscall=257 success=yes exit=3 '
              'pid=4242 comm="trr9003-tee" exe="/usr/local/bin/trr9003-tee" key="k8s_node_file"\n')

    def run_the_step(self, name, rules):
        """Run the step `name` with the stubs. Returns (the Result, the first words
        of a failure message: the step, and what its check is)."""
        tree = self.lab(rules=rules, audit_log=self.RECORD)
        done = self.run_text(tree, self.the_step(self.WORKFLOW, self.JOB, name),
                             env={"FILESENSOR_OUTCOME": "success"})
        where = (f"{self.WORKFLOW}, job {self.JOB}, step {name!r}. The step asks `sudo auditctl -l` for the "
                 "rule of the file sensor. When the key k8s_node_file is not in the list, it prints one line "
                 "that starts with FileSensorRule.ERROR and ends with FileSensorRule.FAILS of the step, and "
                 "it goes on to its last line. ")
        self.assertIn("auditctl -l", self.state(tree, "calls"), where + "The step did not call `auditctl -l`:\n"
                      + done.describe())
        return done, where

    def test_control_a_rule_that_is_loaded_gives_no_error(self):
        for name in self.STEPS:
            with self.subTest(step=name):
                done, where = self.run_the_step(name, self.RULE)
                self.assertEqual(done.returncode, 0, where + "The step did not end with 0:\n" + done.describe())
                self.assertNotIn("::error", done.output, where + "The rule is loaded, and the step prints an "
                                 "::error line:\n" + done.describe())

    def test_a_rule_that_is_not_loaded_is_named_and_the_step_goes_on(self):
        last = {self.STEPS[0]: r"^Captured \d+ pre-emulation file event\(s\)\.$",
                self.STEPS[1]: r"^Collected \d+ file event\(s\)\.$"}
        for name in self.STEPS:
            with self.subTest(step=name):
                done, where = self.run_the_step(name, "")
                self.assertEqual(done.returncode, 0, where + "The step did not end with 0:\n" + done.describe())
                errors = [line for line in done.stdout.splitlines() if line.startswith("::error")]
                self.assertEqual(len(errors), 1, where + f"The rule is not loaded, and the step prints "
                                 f"{len(errors)} ::error line(s):\n" + done.describe())
                self.assertTrue(errors[0].startswith(self.ERROR), where + "The line does not start with "
                                "FileSensorRule.ERROR: " + errors[0])
                self.assertTrue(errors[0].endswith(self.FAILS[name]), where + "The line does not end with `"
                                + self.FAILS[name] + "`: " + errors[0])
                self.assertNotIn("the file gate and the file control", errors[0])
                # The step went on to its last line.
                self.assertRegex(done.stdout.splitlines()[-1], last[name], where + "The step did not go on to "
                                 "its last line:\n" + done.describe())

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
    0.0125 s it printed `125` for %3N. A time of the emulation ledger was then almost
    1 s late (a fraction below 0.01 s lost two zeros or more), and the record of a
    procedure was outside its window. %N with no width is right in both programs.

    The rule: no line of a shell script, a file under atomics/, a workflow or a
    composite action holds %N with a width (and its flags) of one digit: %6N, %3N,
    %06N, %-3N. A `#` comment (a line or the end of a line after `#`) does not count.
    Shell scripts are the files that DirectInstalls reads (test_apt_install.py: the
    name *.sh, or a shell on the first line) and the files with the name *.bash. Under
    atomics/ the rule reads each file that is text and not Markdown: also a file that
    a script sources, and a program in a different language that starts `date`.

    It is a rule on text. It does not see a format that is built at run time, and it
    does not ask if the line calls `date` or what the language of the file is. So a
    mention in prose (a YAML description, a text note, a Python docstring), or in a
    comment that does not start with `#` (`/* */`, `//`), counts too: write the
    format in two parts there (`%6` and `N`), or move the note to a Markdown file.
    The rule does not find a width of two digits (%10N): in a URL, the same text is
    a percent-encoded character before an N (`%20New`). Outside atomics/ it does not
    read a file that a script sources when the file has no shell on its first line
    and no name *.sh or *.bash."""

    WIDTH = re.compile(r"%[-_0^#+]*[1-9]N")
    SKIPPED = (".git", ".kind", "known_bad")        # as DirectInstalls.shell_scripts

    @classmethod
    def files(cls, root=gatelib.REPO):
        """The files that the rule reads, as paths relative to `root`."""
        found = set(apt.DirectInstalls.shell_scripts(root))
        for pattern in (".github/workflows/*.y*ml", ".github/actions/**/*.y*ml"):
            found.update(os.path.relpath(path, root).replace(os.sep, "/")
                         for path in glob.glob(os.path.join(root, *pattern.split("/")), recursive=True))
        for folder, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in cls.SKIPPED]
            for name in names:
                rel = os.path.relpath(os.path.join(folder, name), root).replace(os.sep, "/")
                if name.endswith(".bash") or (rel.startswith("atomics/") and not name.endswith(".md")):
                    found.add(rel)
        return sorted(found)

    @classmethod
    def hits(cls, root=gatelib.REPO):
        """`file:line: text` of each line that gives %N a width, in the files of
        files(). A file that is not text (it holds a NUL byte) is not read."""
        found = []
        for rel in cls.files(root):
            with open(os.path.join(root, rel), "rb") as fh:
                data = fh.read()
            if b"\0" in data:
                continue
            for number, raw in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
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
        script with no .sh in its name, a file that a script sources (no shell on its
        first line), a *.bash file outside atomics/, a Python program under atomics/
        that starts `date`, a workflow step with %3N, an `env:` value and a composite
        action. The message names the file and the line. A `#` comment with %6N in
        the same files, a Markdown file and a file that is not text are not found. A
        comment of C and a description in a YAML file under atomics/ are found: the
        rule does not ask what the language of a file is."""
        tree = gatelib.Tree((".github", "atomics", "detections/benign", "detections/k8s"))
        self.addCleanup(tree.cleanup)
        self.assertEqual(self.hits(tree.root), [])              # CONTROL: the copy has no hit
        tree.write("atomics/T9999/src/emulate.sh",
                   "#!/usr/bin/env bash\nset -euo pipefail\n# The old form: date +%6N.\n"
                   "now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }\n")
        tree.write("atomics/T9999/src/stamp", "#!/bin/sh\n\necho \"$(date +%s).$(date +%3N)\"\n")
        tree.write("atomics/T9999/src/lib.inc", "# Sourced by emulate.sh.\nstamp() { date -u +%T.%6N; }\n")
        tree.write("atomics/T9999/src/clock.py",
                   "import subprocess\n# Not %3N.\nprint(subprocess.run(['date', '+%s.%3N']))\n")
        tree.write("atomics/T9999/README.md", "Do not use `date +%6N` in a script.\n")
        tree.write("atomics/T9999/src/note.c", "/* The time comes from bash, not from date +%6N. */\n"
                                               "int main(void) { return 0; }  /* `%6` and `N`: two parts */\n")
        tree.write("atomics/T9999/crd.yaml", "# Not %3N.\ndescription: \"The stamp is not strftime %6N.\"\n")
        tree.write("atomics/T9999/src/blob.bin", "date +%6N\0\n")
        tree.write("detections/k8s/helper.bash", "stamp() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }\n")
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
            'atomics/T9999/crd.yaml:2: description: "The stamp is not strftime %6N."',
            "atomics/T9999/src/clock.py:3: print(subprocess.run(['date', '+%s.%3N']))",
            "atomics/T9999/src/emulate.sh:4: now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }",
            "atomics/T9999/src/lib.inc:2: stamp() { date -u +%T.%6N; }",
            "atomics/T9999/src/note.c:1: /* The time comes from bash, not from date +%6N. */",
            'atomics/T9999/src/stamp:3: echo "$(date +%s).$(date +%3N)"',
            "detections/k8s/helper.bash:1: stamp() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }"])

    def test_no_shell_script_and_no_workflow_gives_date_a_width_with_N(self):
        files = self.files()
        # The files were read (not vacuous): the emulation scripts and the workflows are
        # among them. (The planted test shows that a comment with %6N is not a hit.)
        self.assertGreater(len([rel for rel in files if rel.startswith("atomics/") and rel.endswith(".sh")]), 10,
                           "the shell scripts under atomics/ were not read")
        self.assertGreater(len([rel for rel in files if rel.startswith(".github/workflows/")]), 3,
                           "the workflows were not read")
        no_faults(self, self.hits(), "these lines give %N a width. `date` of uutils coreutils 0.10.0 "
                  "(Ubuntu 26.04) prints such a field without the leading zeros of the fraction. Use "
                  "the function of LedgerClock.ACCEPTED, or %N and cut the text. The rule does not ask "
                  "what the language of a file is: a mention in prose, or in a comment that does not "
                  "start with `#`, counts too. Write the format in two parts there (`%6` and `N`), or "
                  "move the note to a Markdown file")


class LedgerClock(unittest.TestCase):
    """Each Kubernetes emulation script writes one ledger line for each procedure, with
    its start and its end. The validators read the two times as the window of the
    procedure. The function that gives the time is one text, the same in each script
    (the name is now_utc(), or now() in two scripts) and in each workflow step that
    defines it.

    The text takes the time from bash: EPOCHREALTIME (bash 5.0) is seconds, the
    decimal point of the locale and six digits. The text reads `.` and `,`. It
    starts no `date`. A bash that does not have the variable calls `date` with %N
    (nine digits) and keeps six: no width, which `date` of uutils coreutils 0.10.0
    prints wrongly (DateWidth). Not handled: a locale with a different decimal point
    (glibc has one, ps_AF). There printf fails, and a script stops at its first call
    of the function.

    The rule reads each *.sh file under atomics/ and each workflow step. A script
    writes a ledger when a line of it appends to DETENG_LEDGER (`>> "$DETENG_LEDGER"`,
    `tee -a`). It is a rule on text: it does not see a definition that `eval` or a
    sourced file makes, and it does not see a script that keeps the function and
    takes the times of its ledger from a different command."""

    ACCEPTED = r"""now_utc() {
  local t="${EPOCHREALTIME:-}"
  if [ -n "$t" ]; then TZ=UTC0 printf '%(%Y-%m-%dT%H:%M:%S)T.%sZ\n' "${t%[.,]*}" "${t#*[.,]}"
  else t="$(date -u +%Y-%m-%dT%H:%M:%S.%N)"; printf '%sZ\n' "${t:0:26}"; fi
}
"""
    OLD = "now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }\n"       # until 2026-11-13
    DEFINES = re.compile(r"^[ \t]*(?:function[ \t]+(?:now_utc|now)\b|(?:now_utc|now)[ \t]*\([ \t]*\))")
    NAME = re.compile(r"^(?:function[ \t]+)?(now_utc|now)\b")
    SCRIPTS = "atomics/**/*.sh"
    APPENDS = re.compile(r"(?:>>|\btee[ \t]+(?:-a|--append))[ \t]*[\"']?\$\{?DETENG_LEDGER\b")
    FORMAT = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z"
    BENIGN = ("validate-apiserver-detections.yml", "validate", "Benign operator workload (live false-positive slice)")
    SCORE = ("validate-apiserver-detections.yml", "validate",
             "Score the pre-emulation log as a live benign slice (shadow)")     # it reads BENIGN_START
    WRONG = "1999-12-31T23:59:59.987654321"      # what the stub `date` prints
    # The zones of the runs, as POSIX texts: the C library needs no zone file for them
    # (with a name such as America/New_York and no zone file, the zone is UTC, and a
    # function that does not ask for UTC passes). {TZ: what printf '%(%z)T' gives}.
    ZONES = {"XYZ5": "-0500", "XYZ-5:30": "+0530", "UTC0": "+0000"}
    ZONE = "XYZ5"
    SAY_ZONE = "printf 'zone %(%z)T\\n' -1\n"       # a shell line: the zone of the run is in force
    # A child Python at the root of a copy: _ts() of each validator that reads a ledger,
    # for each argument. Prints {validator: [the time as ISO 8601 text, or None]}.
    VALIDATORS = ("validate_k8s_detections", "validate_staticpod_detections", "validate_apiserver_detections")
    READ = ("import importlib, json, sys\n"
            "sys.path.insert(0, 'detections')\n"
            "read = {}\n"
            "for name in sys.argv[1].split(','):\n"
            "    times = [importlib.import_module(name)._ts(text) for text in sys.argv[2:]]\n"
            "    read[name] = [t.isoformat(timespec='microseconds') if t else None for t in times]\n"
            "print(json.dumps(read))\n")

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
    def writes_a_ledger(cls, text):
        """True when a line of a shell text, without its comment, appends to DETENG_LEDGER."""
        return any(cls.APPENDS.search(apt.DirectInstalls.no_comment(line.strip())) for line in text.splitlines())

    @classmethod
    def scripts(cls, root=gatelib.REPO):
        """{path relative to `root`: text} of each shell script under atomics/."""
        found = {}
        for path in sorted(glob.glob(os.path.join(root, *cls.SCRIPTS.split("/")), recursive=True)):
            with open(path, encoding="utf-8", errors="replace") as fh:
                found[os.path.relpath(path, root).replace(os.sep, "/")] = fh.read()
        return found

    @classmethod
    def difference(cls, body):
        """The difference between ACCEPTED and the text of a definition, for a message.
        Each line is shown as Python writes a string, so white space is visible."""
        lines = difflib.unified_diff([repr(line) for line in cls.ACCEPTED.splitlines()],
                                     [repr(line) for line in body.splitlines()],
                                     "LedgerClock.ACCEPTED", "found", lineterm="", n=1)
        return "".join("\n    " + line for line in lines)

    @classmethod
    def faults(cls, root=gatelib.REPO):
        """What is wrong with the clock functions under `root`, as a list of sentences.
        The first line of a sentence names the place; for a function that is not the
        accepted text, the lines after it show the difference."""
        found = []
        for rel, text in cls.scripts(root).items():
            definitions = cls.definitions(text)
            found += [f"{rel}:{number}: the function {name}() is not the accepted text (LedgerClock.ACCEPTED)"
                      + cls.difference(body) for number, name, body in definitions if body != cls.ACCEPTED]
            if cls.writes_a_ledger(text) and len(definitions) != 1:
                found.append(f"{rel}: the script appends to the ledger (DETENG_LEDGER) and defines now_utc() "
                             f"or now() {len(definitions)} time(s); wanted 1")
        for step in gatelib.ci_steps(root=root):
            found += [f"{step.workflow}, job {step.job}, step {step.name!r}: the function {name}() is not "
                      "the accepted text (LedgerClock.ACCEPTED)" + cls.difference(body)
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
            "a blank between the parentheses": accepted.replace("now_utc() {", "now_utc( ) {"),
            "a blank before the parentheses": accepted.replace("now_utc() {", "now_utc () {"),
            "a blank at the end of a line": accepted.replace('local t="${EPOCHREALTIME:-}"\n',
                                                             'local t="${EPOCHREALTIME:-}" \n'),
            "a second definition on one line, with a blank": "now_utc( ) { date -u +%Y-%m-%dT%H:%M:%S.000000Z; }\n",
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
        self.assertEqual(self.definitions('start="$(now_utc)"\n# now_utc() { date; }\nknown() { :; }\nnow=1\n'
                                          "undo_now() {\n  :\n}\n"), [])
        # The message for a function that differs shows the difference, with white space.
        shown = self.difference(accepted.replace('local t="${EPOCHREALTIME:-}"\n', 'local t="${EPOCHREALTIME:-}" \n'))
        self.assertIn("\n    -'  local t=\"${EPOCHREALTIME:-}\"'", shown)
        self.assertIn("\n    +'  local t=\"${EPOCHREALTIME:-}\" '", shown)
        self.assertEqual(self.difference(accepted), "")
        # A script writes a ledger when a line appends to it. A script that only names
        # the variable (a wrapper that exports it, a comment) does not.
        writes = ['  "$TRR" "$p" "$start" "$end" "$rc" >> "$DETENG_LEDGER"\n', '  >> "${DETENG_LEDGER}"\n',
                  "echo x >>$DETENG_LEDGER\n", 'echo x | tee -a "$DETENG_LEDGER" >/dev/null\n']
        names = ['export DETENG_LEDGER="${DETENG_LEDGER:-/tmp/ledger.jsonl}"\nbash "$(dirname "$0")/emulate.sh" a\n',
                 '# appends one line: >> "$DETENG_LEDGER"\n', 'if [ -n "${DETENG_LEDGER:-}" ]; then :; fi\n',
                 ': > "$DETENG_LEDGER"\n', 'cat "$DETENG_LEDGER" >> /tmp/copy\n']
        self.assertEqual([text for text in writes + names if self.writes_a_ledger(text)], writes)

    def test_each_clock_function_is_the_accepted_text(self):
        scripts = self.scripts()
        # The scripts were read (not vacuous). Today 20 scripts append to a ledger, and
        # each of them defines the function. The floor has room, as in DateWidth: it is
        # not the count, and a script less does not fail.
        writers = [rel for rel, text in scripts.items() if self.writes_a_ledger(text)]
        defined = [rel for rel, text in scripts.items() if self.definitions(text)]
        floor = ("; the test wants more than 10, to show that the rule read the emulation scripts (it is a "
                 "floor with room, not the count of the scripts)")
        self.assertGreater(len(writers), 10, f"{len(writers)} of the {len(scripts)} script(s) that match "
                           f"{self.SCRIPTS} append to a ledger (DETENG_LEDGER)" + floor)
        self.assertGreater(len(defined), 10, f"{len(defined)} of the {len(scripts)} script(s) that match "
                           f"{self.SCRIPTS} define now_utc() or now()" + floor)
        in_steps = [(s.workflow, s.job, s.name) for s in gatelib.ci_steps() if self.definitions(s.run)]
        self.assertIn(self.BENIGN, in_steps, "the step that writes BENIGN_START does not define the function "
                      "(or has a new name: then put the new name in LedgerClock.BENIGN)")
        no_faults(self, self.faults(), "the clock function of the ledger is one text. Copy "
                  "LedgerClock.ACCEPTED (the name can be now() or now_utc()); to change the function, "
                  "change that text and each copy in the same pull request")

    def test_a_planted_script_with_the_old_function_is_rejected(self):
        """In a copy of the repository: a script with the function of 2026-11-12, a
        script that writes a ledger with no such function, a script outside src/ with
        a second definition after the accepted one, and a workflow step with the old
        function. CONTROL: a script that only gives DETENG_LEDGER to a different
        script is accepted."""
        tree = gatelib.Tree((".github", "atomics"))
        self.addCleanup(tree.cleanup)
        self.assertEqual(self.faults(tree.root), [])            # CONTROL: the copy has no fault
        head = "#!/usr/bin/env bash\nset -euo pipefail\nTRR=\"TRR9999\"\nFAILED=()\n"
        ledger = ('run_proc() {\n  local start end\n  start="$(STAMP)"\n  "procedure_$1"\n  end="$(STAMP)"\n'
                  '  printf \'{"trr":"%s","start":"%s","end":"%s"}\\n\' "$TRR" "$start" "$end" >> "$DETENG_LEDGER"\n}\n')
        tree.write("atomics/T9999/src/run_all.sh", "#!/usr/bin/env bash\n"
                   'export DETENG_LEDGER="${DETENG_LEDGER:-/tmp/ledger.jsonl}"\nbash "$(dirname "$0")/emulate.sh" a\n')
        self.assertEqual(self.faults(tree.root), [])            # CONTROL: the wrapper has no fault
        tree.write("atomics/T9999/src/emulate.sh", head + self.OLD + ledger.replace("STAMP", "now_utc"))
        tree.write("atomics/T9999/src/emulate_other.sh", head + ledger.replace("STAMP", "date -u +%FT%T.%NZ"))
        tree.write("atomics/T9999/emulate_top.sh", head + self.ACCEPTED
                   + "now_utc( ) { date -u +%Y-%m-%dT%H:%M:%S.000000Z; }\n" + ledger.replace("STAMP", "now_utc"))
        tree.write(".github/workflows/planted-lab.yml",
                   "on: push\njobs:\n  lab:\n    runs-on: ubuntu-latest\n    steps:\n"
                   "      - name: Mark the start\n        shell: bash\n        run: |\n"
                   "          now() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }\n"
                   "          echo \"T0=$(now)\" >> \"$GITHUB_ENV\"\n")
        found = self.faults(tree.root)
        self.assertEqual([fault.splitlines()[0] for fault in found], [
            "atomics/T9999/emulate_top.sh:10: the function now_utc() is not the accepted text (LedgerClock.ACCEPTED)",
            "atomics/T9999/emulate_top.sh: the script appends to the ledger (DETENG_LEDGER) and defines "
            "now_utc() or now() 2 time(s); wanted 1",
            "atomics/T9999/src/emulate.sh:5: the function now_utc() is not the accepted text (LedgerClock.ACCEPTED)",
            "atomics/T9999/src/emulate_other.sh: the script appends to the ledger (DETENG_LEDGER) and defines "
            "now_utc() or now() 0 time(s); wanted 1",
            "planted-lab.yml, job lab, step 'Mark the start': the function now() is not the accepted text "
            "(LedgerClock.ACCEPTED)"])
        # The message shows the old line in the place of the accepted lines.
        self.assertIn("\n    +'now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }'", found[2])
        self.assertIn("\n    -'  local t=\"${EPOCHREALTIME:-}\"'", found[2])

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

    def run_function(self, lines, date_says=WRONG, zone=ZONE):
        """Run `lines` after the accepted function, as an emulation script does (bash,
        set -euo pipefail), with a stub `date` first on PATH and with the zone `zone`
        (a key of ZONES). The stub prints `date_says` and writes its arguments to a
        file. Returns (the lines that the run printed, the calls of the stub)."""
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
        test, in UTC (the zone of the run is five hours from UTC, and the run shows
        that), and `date` was not called."""
        self.need_bash(5, 0, "EPOCHREALTIME")
        before = time.time()
        printed, called = self.run_function('start="$(now_utc)"\nprintf \'%s\\n\' "$start"\nnow_utc\n'
                                            + self.SAY_ZONE)
        after = time.time()
        self.assertEqual(called, [], "the function called `date`")
        self.assertEqual(printed[2:], ["zone " + self.ZONES[self.ZONE]], "the zone of the run is not in force")
        del printed[2:]
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
        for zone, offset in self.ZONES.items():
            with self.subTest(zone=zone):
                printed, called = self.run_function(lines + 'printf \'%s\\n\' "$TZ"\n' + self.SAY_ZONE, zone=zone)
                # The times are UTC, TZ is as it was, and the zone of the run was in force.
                self.assertEqual(printed, list(values.values()) + [zone, "zone " + offset])
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
        # A `date` that has no %N (BSD date prints the letter N): the text of the
        # function is not in the format of the ledger.
        printed, _called = self.run_function("unset EPOCHREALTIME\nnow_utc\n", date_says="2026-11-13T20:23:06.N")
        self.assertEqual(printed, ["2026-11-13T20:23:06.NZ"])
        self.assertNotRegex(printed[0], "^" + self.FORMAT + "$")
        # detections/README.md (`The emulation scripts take ...`) says what the
        # validators do with that text: they read it as the whole second, so the window
        # of the procedure starts and ends up to 1 s early. That is true from Python
        # 3.11 (an older Python is not asked here). CONTROL: they read a text in the
        # format of the ledger with its fraction.
        if sys.version_info >= (3, 11):
            tree = gatelib.Tree(("detections/*.py",))
            self.addCleanup(tree.cleanup)
            done = tree.run_python(self.READ, ",".join(self.VALIDATORS), "2026-11-13T20:23:06.003423Z", printed[0])
            self.assertEqual(done.returncode, 0, done.describe())
            self.assertEqual(json.loads(done.stdout.splitlines()[-1]), dict.fromkeys(
                self.VALIDATORS, ["2026-11-13T20:23:06.003423+00:00", "2026-11-13T20:23:06.000000+00:00"]),
                "detections/README.md (`The emulation scripts take ...`) says that the validators read `"
                + printed[0] + "` as the whole second, with Python 3.11 and later. With this Python ("
                + sys.version.split()[0] + ") a validator reads it differently: correct that sentence, and "
                "this assertion")

    def test_the_benign_step_writes_its_split_point_without_date(self):
        """The step of the API server lab that writes BENIGN_START, to that line: the
        value is the time of the test in the format that the step that scores the
        slice accepts, and `date` was not called. The run has the locale C, as the
        runs of run_function(): the decimal point of the locale of the machine of
        the test is not the subject (the comma has its own test)."""
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
        part = "\n".join(lines[:write[0] + 1]) + "\n"
        self.assertEqual(AuditdStart.not_shell(part), "", "the test runs the step to the line that writes "
                         "BENIGN_START, and `bash -n` does not read that part as complete shell. Put the line "
                         "at the top level of the step (not in an `if`, a loop or a function)")
        done = tree.run_step(step._replace(run=part + self.SAY_ZONE), timeout=60,
                             env={"TZ": self.ZONE, "CALLS": calls, "DATE_SAYS": self.WRONG, "LC_ALL": "C"},
                             programs={"date": 'echo "$*" >> "$CALLS"\necho "$DATE_SAYS"'})
        after = time.time()
        self.assertEqual(done.returncode, 0, done.describe())
        self.assertEqual(done.stdout.splitlines()[-1:], ["zone " + self.ZONES[self.ZONE]],
                         "the zone of the run is not in force:\n" + done.describe())
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
        score = AuditdStart.the_step(*self.SCORE)
        pattern = re.search(r"^\s*utc='(\^[^']+\$)'$", score.run, re.MULTILINE)
        self.assertTrue(pattern, "the pattern of the scoring step was not found")
        self.assertRegex(value, pattern.group(1))


if __name__ == "__main__":
    unittest.main()
