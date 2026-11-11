"""Offline tests of the cloud emulation scripts, with a stub for each cloud CLI.

A test runs one script of `atomics/<ATT&CK-ID>/src/` with stub programs first on
PATH: `gcloud`, `az`, `aws`, `curl` and the other names of STUBS. A stub makes no
cloud call. It writes its arguments (and the text that came to it on a pipe) to a
log, prints the text that the test gave for its command line, and exits with the
code that the test gave.

So a test can prove, with no cloud account:

- that the default (dry) mode of a script makes no call and exits 0;
- which commands the LIVE mode runs, and in which sequence;
- that a command that fails in the middle of a live run does not leave a change
  behind: the undo commands of the changes before it run;
- what a stop signal (HUP, INT, TERM) does when it comes while a command runs.

A test cannot prove that the provider accepts a command. That is checked against
the provider reference when a script is written (see README.md in this directory).

The script does not get the PATH of the caller. Its PATH has two directories of the
harness: the stubs, and links to the programs of TOOLS. A script that calls a
program that is in neither list stops with "command not found", so no test can run
a real network program by accident.

    import livetest

    class Workforce(unittest.TestCase):
        def test_dry_mode_makes_no_call(self):
            run = livetest.run_script("atomics/T1199/src/emulate_gcp_workforce.sh", "a")
            self.assertEqual(run.returncode, 0, run.text)
            self.assertEqual(run.calls, [])

Run all tests:  python3 -B -m unittest discover -s atomics/tests -v
"""

import collections
import json
import os
import pty
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TESTS))

# The programs that a stub replaces. `sleep` is one of them: a test does not wait.
STUBS = ("gcloud", "gsutil", "bq", "az", "aws", "curl", "kubectl", "sleep")

# The programs of the machine that a script can call. Each one works on local text or
# local files only. Add a program here only if it cannot open a network connection.
TOOLS = ("bash", "cat", "chmod", "date", "dirname", "grep", "head", "mktemp", "rm",
         "sed", "tr")

UNDO_BLOCK = os.path.join(TESTS, "undo_block.sh")
UNDO_START = "# >>> live undo"
UNDO_END = "# <<< live undo"

_STUB = r'''#!/usr/bin/env python3
import json, os, re, signal, stat, sys
name = os.path.basename(sys.argv[0])
argv = [name] + sys.argv[1:]
line = " ".join(argv)
home = os.environ["LIVETEST_DIR"]
with open(os.path.join(home, "rules.json"), encoding="utf-8") as fh:
    rules = json.load(fh)
# The text on stdin is read only from a pipe: a terminal or /dev/null is left alone.
piped = None
if stat.S_ISFIFO(os.fstat(0).st_mode):
    piped = sys.stdin.read()
with open(os.path.join(home, "calls.jsonl"), "a", encoding="utf-8") as fh:
    fh.write(json.dumps({"argv": argv, "stdin": piped}) + "\n")
for pattern, signame, scope in rules["signal"]:
    if re.search(pattern, line):
        number = getattr(signal, "SIG" + signame)
        with open(os.path.join(home, "pid"), encoding="utf-8") as fh:
            script = int(fh.read())
        if scope == "group":
            # The signal comes to the script and to this command, as with Ctrl-C. The
            # command stops in the middle: it prints nothing and ends by the signal.
            signal.signal(number, signal.SIG_DFL)
            os.killpg(os.getpgid(script), number)
            os._exit(128 + number)      # not reached: the signal ended this command
        # scope "shell": the signal comes to the script only. This command runs to its end.
        os.kill(script, number)
        break
for rule in rules["fail"]:
    if re.search(rule[0], line):
        if len(rule) > 2:
            sys.stdout.write(rule[2])
            sys.stdout.flush()
        sys.stderr.write(f"ERROR: (stub) {name} was told to fail: {line}\n")
        sys.exit(rule[1])
for number, (pattern, text) in enumerate(rules["outputs"]):
    if re.search(pattern, line):
        if isinstance(text, list):
            # A list gives one text for each call that matches; the last one repeats.
            count_file = os.path.join(home, "count-%d" % number)
            done = 0
            if os.path.exists(count_file):
                with open(count_file, encoding="utf-8") as fh:
                    done = int(fh.read())
            with open(count_file, "w", encoding="utf-8") as fh:
                fh.write(str(done + 1))
            text = text[min(done, len(text) - 1)]
        sys.stdout.write(text if text.endswith("\n") or not text else text + "\n")
        break
sys.exit(0)
'''

Run = collections.namedtuple("Run", "returncode stdout stderr calls stdins tmp_files home_files")
Run.text = property(lambda self: f"exit {self.returncode}\n--- stdout\n{self.stdout}\n--- stderr\n{self.stderr}"
                                 f"\n--- calls\n" + "\n".join(" ".join(c) for c in self.calls))
Run.lines = property(lambda self: [" ".join(call) for call in self.calls])


def default_signals():
    """Give HUP, INT, TERM and PIPE their default action in a child process. A test
    runner that was started with nohup, or in the background, gives its children
    ignored signals, and bash cannot trap a signal that was ignored at its start."""
    for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGPIPE):
        signal.signal(number, signal.SIG_DFL)


def _which(name):
    return shutil.which(name, path="/usr/bin:/bin") or shutil.which(name)


def run_script(script, *args, env=None, outputs=(), fail=(), signals=(), files=(),
               tty=False, stubs=STUBS, timeout=60):
    """Run `script` (a path from the root of the repository) with bash and the stubs.

    env      {name: value}: more environment variables, such as TRR9020_LIVE=1. The
             script does not get the variables of the caller: only PATH (the stubs and
             the programs of TOOLS), HOME (an empty directory, also the working
             directory), TMPDIR (an empty directory) and these.
    outputs  [(regex, text)]: a stub whose command line matches the regex prints the
             text. The command line is the program name and its arguments, joined
             with one blank. The first match counts. A list of texts in place of one
             text gives one text for each call that matches; the last one repeats.
    fail     [regex], [(regex, exit code)] or [(regex, exit code, text)]: a stub whose
             command line matches prints the text (if one is given) on stdout, prints
             an error on stderr, and exits with the code (1 if none is given).
    signals  [(regex, name, scope)]: a stub whose command line matches sends the
             signal (HUP, INT or TERM) while it runs. Scope "shell": to the script
             only; the command then runs to its end (its `fail` or `outputs` rule
             applies). Scope "group": to the script and to the command, as Ctrl-C
             does; the command stops in the middle and ends by the signal.
    files    [path]: empty files to make in the working directory before the run.
    tty      True: the standard input of the script is a terminal on which a person
             pressed Enter one time. False: it is /dev/null.
    stubs    the names of the stub programs (default STUBS). Leave one out to test
             what a script does when that program is not installed.

    Returns a Run: returncode, stdout, stderr, calls (a list of argument lists; the
    first item of each is the program name), stdins (for each call, the text that
    came to the stub on a pipe, or None), tmp_files (the paths that stay in TMPDIR
    after the run), home_files (the paths that stay in HOME, which is also the working
    directory, without the files of `files`) and `lines` (each call as one string).
    """
    home = tempfile.mkdtemp(prefix="deteng-livetest-")
    try:
        bin_dir = os.path.join(home, "bin")
        tool_dir = os.path.join(home, "tools")
        user_home = os.path.join(home, "home")
        tmp_dir = os.path.join(home, "tmp")
        for folder in (bin_dir, tool_dir, user_home, tmp_dir):
            os.mkdir(folder)
        for name in stubs:
            stub = os.path.join(bin_dir, name)
            with open(stub, "w", encoding="utf-8") as fh:
                fh.write(_STUB.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
            os.chmod(stub, 0o755)
        for name in TOOLS:
            real = _which(name)
            if real:
                os.symlink(real, os.path.join(tool_dir, name))
        for name in files:
            path = os.path.join(user_home, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8"):
                pass
        rules = {"outputs": [list(item) for item in outputs],
                 "fail": [[item, 1] if isinstance(item, str) else list(item) for item in fail],
                 "signal": [list(item) for item in signals]}
        with open(os.path.join(home, "rules.json"), "w", encoding="utf-8") as fh:
            json.dump(rules, fh)
        environment = {"PATH": bin_dir + os.pathsep + tool_dir, "HOME": user_home,
                       "TMPDIR": tmp_dir, "LANG": "C.UTF-8", "LIVETEST_DIR": home}
        environment.update(env or {})
        # The first bash writes its process ID for the stubs, then becomes the script
        # (exec keeps the process ID). The script is the leader of a new process group,
        # so a signal with the scope "group" cannot come to the test runner.
        command = [_which("bash"), "-c", 'echo $$ > "$LIVETEST_DIR/pid"; exec "$BASH" "$@"',
                   "livetest", os.path.join(REPO, script), *args]
        master = slave = None
        if tty:
            master, slave = pty.openpty()
            os.write(master, b"\n")
        try:
            done = subprocess.run(command, cwd=user_home, env=environment,
                                  stdin=slave if tty else subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=timeout,
                                  start_new_session=True, preexec_fn=default_signals)
        finally:
            for fd in (master, slave):
                if fd is not None:
                    os.close(fd)
        calls, stdins = [], []
        log = os.path.join(home, "calls.jsonl")
        if os.path.exists(log):
            with open(log, encoding="utf-8") as fh:
                for line in fh:
                    item = json.loads(line)
                    calls.append(item["argv"])
                    stdins.append(item["stdin"])
        tmp_files = sorted(os.path.relpath(os.path.join(folder, name), tmp_dir)
                           for folder, dirs, names in os.walk(tmp_dir) for name in dirs + names)
        given = {os.path.normpath(name) for name in files}
        home_files = sorted(set(os.path.relpath(os.path.join(folder, name), user_home)
                                for folder, _dirs, names in os.walk(user_home) for name in names) - given)
        return Run(done.returncode, done.stdout, done.stderr, calls, stdins, tmp_files, home_files)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def each_undo_failure(case, script, *args, **rules):
    """Make each undo command of a good live run fail, one at a time.

    The first run has no failure: it must end with exit 0, and its last calls are the undo
    commands (one call for each `[live] undo:` line). Then, for each of these calls, one
    run in which that call fails. Such a run must end with exit 1, must not print "done",
    must print one LEFT BEHIND line, and must run the other undo commands all the same.
    This holds an undo line that hides the failure of its command in a way that the text
    of the line does not show (a helper function that returns 0, a pipe, a variable).
    A name with the time of the run is different in each run, so digits are compared as
    "one or more digits". Returns the number of undo commands.
    """
    def shape(calls):
        return [re.sub(r"\d+", "N", " ".join(call)) for call in calls]
    good = run_script(script, *args, **rules)
    case.assertEqual(good.returncode, 0, good.text)
    count = good.stdout.count("[live] undo: ")
    case.assertGreater(count, 0, good.text)
    tail = good.calls[-count:]
    case.assertEqual(len(tail), count, good.text)
    for call in tail:
        line = " ".join(call)
        pattern = "^" + re.sub(r"\d+", lambda _m: r"\d+", re.escape(line)) + "$"
        with case.subTest(undo_that_fails=line):
            fail = list(rules.get("fail", ())) + [(pattern, 9)]
            run = run_script(script, *args, **dict(rules, fail=fail))
            case.assertEqual(run.returncode, 1, run.text)
            case.assertNotIn("[live] done", run.stdout, run.text)
            case.assertEqual(run.stderr.count("[live] LEFT BEHIND, this command failed: "), 1, run.text)
            case.assertIn("[live] FAILED (exit 1)", run.stderr, run.text)
            case.assertEqual(shape(run.calls[-count:]), shape(tail), run.text)
    return count


def undo_block(path=UNDO_BLOCK):
    """The undo block of a file (the lines from UNDO_START to UNDO_END), without its
    indentation. None when the file has no such block."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    start = [n for n, line in enumerate(lines) if line.strip().startswith(UNDO_START)]
    end = [n for n, line in enumerate(lines) if line.strip().startswith(UNDO_END)]
    if not start and not end:
        return None
    if len(start) != 1 or len(end) != 1 or end[0] < start[0]:
        raise ValueError(f"{path}: the markers of the undo block are not one pair")
    return textwrap.dedent("\n".join(lines[start[0]:end[0] + 1])) + "\n"


def live_scripts():
    """Each shell script under atomics/ and upstream/ (paths from the root), sorted."""
    found = []
    for top in ("atomics", "upstream"):
        for folder, _dirs, files in os.walk(os.path.join(REPO, top)):
            found += [os.path.relpath(os.path.join(folder, name), REPO)
                      for name in files if name.endswith(".sh")]
    return sorted(found)
