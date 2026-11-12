"""The undo block of the live scripts: what it does, and that each script that has
it holds the reference text (atomics/tests/undo_block.sh) with no change.

The block in three sentences. Before a command that makes a change, the script says
`change_next <what>`; immediately after the command, it registers the revert with
`undo <command>`; at its planned end it calls `undo_now`. On each other end (a command
that fails, a stop signal, a reader of the output that is gone) the block runs the
registered commands, last registered first.
"""

import os
import re
import signal
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import livetest     # noqa: E402

# The scripts that must hold the block: each one makes a change in LIVE mode. A script
# that is not in this list and holds the markers is checked too. A new script that
# makes a change in LIVE mode must be added here.
MUST_HAVE = (
    "atomics/T1098.001/src/emulate_entra.sh",
    "atomics/T1098.001/src/emulate_gcp_wif.sh",
    "atomics/T1199/src/emulate_gcp_workforce.sh",
    "atomics/T1528/src/emulate_entra_consent.sh",
    "atomics/T1562.008/src/emulate_gcp_log_sink.sh",
)

SIGNALS = (("HUP", 129), ("INT", 130), ("TERM", 143))

# Text for `sh -c '...'` in a body. The script writes its process ID to the file
# script.pid before the body starts. (A body does not use $PPID: if a defect made the
# script run this text itself, $PPID would be the test runner.)
# TO_SHELL: the signal comes to the script only; the command then runs to its end.
TO_SHELL = "kill -%s $(cat script.pid); sleep 0.2"
# TO_BOTH: the signal comes to the script and to the command, as with Ctrl-C. The
# command stops in the middle: it ends by the signal.
TO_BOTH = "kill -%s $(cat script.pid); kill -%s $$; sleep 5"
# SIGNAL_BEFORE: body lines that send one TERM to the script immediately before the first
# command whose text holds the given words (a DEBUG trap, also inside the functions).
SIGNAL_BEFORE = ("set -o functrace\n_sent=0\n"
                 "trap 'if [[ $_sent -eq 0 && \"$BASH_COMMAND\" == *\"%s\"* ]]; then _sent=1; kill -TERM $$; fi' DEBUG\n")


class Behaviour(unittest.TestCase):
    """A small script made of the reference block and a body."""

    block = livetest.UNDO_BLOCK

    def write(self, home, body):
        with open(self.block, encoding="utf-8") as fh:
            block = fh.read()
        path = os.path.join(home, "script.sh")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/usr/bin/env bash\nset -euo pipefail\necho $$ > script.pid\n" + block + body)
        return path

    def run_body(self, body):
        """Run the body. Returns the result; `files` holds the names that stay in the
        working directory (without the script) and `content` the text of each."""
        with tempfile.TemporaryDirectory(prefix="deteng-undo-") as home:
            done = subprocess.run(["bash", self.write(home, body)], cwd=home, capture_output=True,
                                  text=True, stdin=subprocess.DEVNULL, timeout=30,
                                  env={"PATH": "/usr/bin:/bin", "HOME": home},
                                  start_new_session=True, preexec_fn=livetest.default_signals)
            done.files = sorted(set(os.listdir(home)) - {"script.sh", "script.pid"})
            done.content = {}
            for name in done.files:
                with open(os.path.join(home, name), encoding="utf-8") as fh:
                    done.content[name] = fh.read()
            return done

    def run_until_the_reader_goes(self, body, then_signal=None):
        """Run the body with its standard output on a pipe. Read the first line, close
        the pipe (the reader is gone), optionally send a signal to the process group
        of the script, then make the file `go`, for which the body waits."""
        with tempfile.TemporaryDirectory(prefix="deteng-undo-") as home:
            with open(os.path.join(home, "stderr.txt"), "w", encoding="utf-8") as err:
                proc = subprocess.Popen(["bash", self.write(home, body)], cwd=home,
                                        stdout=subprocess.PIPE, stderr=err,
                                        stdin=subprocess.DEVNULL,
                                        env={"PATH": "/usr/bin:/bin", "HOME": home},
                                        start_new_session=True, preexec_fn=livetest.default_signals)
                try:
                    first = proc.stdout.readline()
                    proc.stdout.close()
                    if then_signal:
                        os.killpg(proc.pid, then_signal)
                    with open(os.path.join(home, "go"), "w", encoding="utf-8"):
                        pass
                    proc.wait(timeout=30)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
            with open(os.path.join(home, "stderr.txt"), encoding="utf-8") as fh:
                stderr = fh.read()
            files = sorted(set(os.listdir(home)) - {"script.sh", "script.pid", "stderr.txt", "go"})
            return first, proc.returncode, stderr, files

    def test_control_no_change_no_undo(self):
        done = self.run_body("echo body\n")
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "body\n", ""))

    def test_undo_runs_last_first_at_the_end(self):
        done = self.run_body("undo echo 'revert 1' >&2\nundo echo 'revert  2' >&2\necho body\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.split("\n")[:3],
                         ["body", "[live] undo: echo revert\\ \\ 2 ", "[live] undo: echo revert\\ 1 "])
        self.assertEqual(done.stderr, "")

    def test_arguments_come_back_as_they_were_given(self):
        done = self.run_body("undo sh -c 'printf \"<%s>\\n\" \"$@\" > out.txt' sh 'a b' '$HOME' '*' \"it's\"\n"
                             "undo_now >/dev/null\ncat out.txt\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "<a b>\n<$HOME>\n<*>\n<it's>\n")

    def test_undo_now_runs_each_command_one_time(self):
        done = self.run_body("undo touch reverted\nundo_now\nls reverted\nrm reverted\necho end\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.count("[live] undo: "), 1)
        self.assertTrue(done.stdout.endswith("reverted\nend\n"), done.stdout)

    def test_a_command_that_fails_runs_the_undo_and_keeps_its_exit_code(self):
        done = self.run_body("undo touch reverted-1\nundo touch reverted-2\n"
                             "sh -c 'exit 7'\necho not reached\n")
        self.assertEqual(done.returncode, 7)
        self.assertNotIn("not reached", done.stdout)
        self.assertIn("[live] undo: touch reverted-2 \n[live] undo: touch reverted-1 \n", done.stdout)
        self.assertIn("[live] FAILED (exit 7)", done.stderr)
        # No command that makes a change was in progress: the block names none.
        self.assertNotIn("has no undo", done.stderr)

    def test_an_undo_that_fails_does_not_stop_the_others_and_fails_the_script(self):
        # The body has no check of its own after undo_now: undo_now itself stops the run,
        # so the last message is not printed.
        done = self.run_body("undo echo first-registered\nundo false\nundo echo last-registered\n"
                             "undo_now\necho '[live] done.'\n")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(done.stdout.count("[live] undo: "), 3)
        self.assertNotIn("[live] done.", done.stdout)
        self.assertIn("[live] LEFT BEHIND, this command failed: false ", done.stderr)
        self.assertNotIn("starts again", done.stderr)
        self.assertIn("[live] FAILED (exit 1)", done.stderr)

    def test_an_undo_that_fails_on_the_exit_path_fails_a_run_that_ended_with_0(self):
        # The body ends with no undo_now, so the exit path does the undo.
        done = self.run_body("undo false\necho body\n")
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("[live] LEFT BEHIND, this command failed: false ", done.stderr)
        self.assertIn("[live] FAILED (exit 1)", done.stderr)

    def test_a_signal_runs_the_undo(self):
        # The signal comes between two commands (no change is in progress): the run
        # stops at once.
        for name, code in SIGNALS:
            with self.subTest(signal=name):
                done = self.run_body(f"undo echo reverted\nkill -{name} $$\nsleep 5\necho not reached\n")
                self.assertEqual(done.returncode, code)
                self.assertIn("[live] undo: echo reverted", done.stdout)
                self.assertNotIn("not reached", done.stdout)
                self.assertIn(f"[live] FAILED (exit {code})", done.stderr)

    def test_the_signal_tests_do_not_depend_on_the_signals_of_the_runner(self):
        # A runner that was started with nohup or in the background has ignored signals.
        # bash cannot trap a signal that was ignored at its start, so the harness gives
        # the script the default actions.
        before = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            done = self.run_body("undo echo reverted\nkill -INT $$\nsleep 5\necho not reached\n")
        finally:
            signal.signal(signal.SIGINT, before)
        self.assertEqual(done.returncode, 130, done.stderr)
        self.assertNotIn("not reached", done.stdout)

    def test_a_signal_during_a_change_waits_until_the_change_has_its_undo(self):
        # The signal comes to the script while the command that makes a change runs. The
        # command runs to its end, so the change is made. The run must not stop before
        # the undo of that change is registered, or the change stays with no undo.
        shapes = {
            "plain": "sh -c '%s; touch object'\n",
            "in $( )": "NAME=\"$(sh -c '%s; touch object; echo object')\"\ntest \"$NAME\" = object\n",
        }
        for name, code in SIGNALS:
            for shape, command in shapes.items():
                with self.subTest(signal=name, shape=shape):
                    done = self.run_body("change_next 'the object'\n" + command % (TO_SHELL % name)
                                         + "undo rm object\necho not reached\n")
                    self.assertEqual(done.returncode, code, done.stderr)
                    self.assertIn("[live] undo: rm object", done.stdout)
                    self.assertEqual(done.files, [], "the change stays")
                    self.assertNotIn("not reached", done.stdout)
                    self.assertNotIn("has no undo", done.stderr)
                    self.assertIn(f"[live] FAILED (exit {code})", done.stderr)
                    # The person is told that the signal came and why the run goes on.
                    self.assertIn("[live] stop signal during a change: the run stops after this change",
                                  done.stderr)

    def test_a_signal_that_stops_the_change_command_names_the_change(self):
        # The signal comes to the script and to the command (Ctrl-C). The command stops
        # in the middle: the block cannot know if the provider made the change. It
        # reverts the earlier changes and names the change that has no undo.
        for name, code in SIGNALS:
            with self.subTest(signal=name):
                done = self.run_body("touch first\nundo rm first\nchange_next 'the second object'\n"
                                     "sh -c '%s'\nundo rm second\necho not reached\n"
                                     % (TO_BOTH % (name, name)))
                self.assertEqual(done.returncode, code, done.stderr)
                self.assertEqual(done.files, [])
                self.assertNotIn("[live] undo: rm second", done.stdout)
                self.assertIn("The run stopped before the undo of this change was registered: "
                              "the second object", done.stderr)
                self.assertIn("has no undo", done.stderr)
                self.assertNotIn("not reached", done.stdout)

    def test_a_change_command_that_fails_names_the_change_and_keeps_its_exit_code(self):
        done = self.run_body("touch first\nundo rm first\nchange_next 'the second object'\n"
                             "sh -c 'exit 7'\nundo rm second\necho not reached\n")
        self.assertEqual(done.returncode, 7, done.stderr)
        self.assertEqual(done.files, [])
        self.assertIn("The run stopped before the undo of this change was registered: the second object",
                      done.stderr)
        self.assertNotIn("[live] undo: rm second", done.stdout)

    def test_a_signal_during_a_change_command_that_fails_gives_the_code_of_the_signal(self):
        done = self.run_body("change_next 'the object'\nsh -c '%s; exit 7'\nundo rm object\n"
                             % (TO_SHELL % "TERM"))
        self.assertEqual(done.returncode, 143, done.stderr)
        self.assertIn("[live] FAILED (exit 143)", done.stderr)
        self.assertIn("The run stopped before the undo of this change was registered: the object", done.stderr)

    def test_after_the_undo_registration_a_signal_stops_the_run_at_once(self):
        # change_next applies to one command: after its undo line, a signal is not held.
        done = self.run_body("change_next 'the object'\ntouch object\nundo rm object\n"
                             "kill -TERM $$\nsleep 5\necho not reached\n")
        self.assertEqual(done.returncode, 143, done.stderr)
        self.assertEqual(done.files, [])
        self.assertNotIn("not reached", done.stdout)

    def test_a_signal_during_the_undo_does_not_stop_the_other_undo_commands(self):
        # The run stops on INT. While the second undo command runs, a TERM comes to the
        # shell. The undo command that was registered first must run all the same.
        done = self.run_body("undo sh -c 'echo reverted-1 >&2'\n"
                             "undo sh -c '%s; echo reverted-2 >&2'\n" % (TO_SHELL % "TERM") +
                             "undo sh -c 'echo reverted-3 >&2'\n"
                             "kill -INT $$\nsleep 5\necho not reached\n")
        self.assertEqual(done.returncode, 130, done.stderr)
        self.assertNotIn("not reached", done.stdout)
        reverted = [line for line in done.stderr.split("\n") if line.startswith("reverted-")]
        self.assertEqual(reverted, ["reverted-3", "reverted-2", "reverted-1"], done.stderr)
        self.assertIn("[live] FAILED (exit 130)", done.stderr)

    def test_an_undo_command_that_ran_to_its_end_does_not_run_again_after_a_signal(self):
        # At the planned end and on the exit path, a signal comes to the script only
        # while the second undo command runs. That command runs to its end. It must run
        # ONE time: a second run of a real delete fails and gives a false LEFT BEHIND.
        # Each `[live] undo:` line must be printed, and the last message must not.
        ends = {"the planned end": ("undo_now\necho '[live] done.'\n", 143),
                "the exit path": ("sh -c 'exit 7'\n", 7)}
        for end, (tail, code) in ends.items():
            with self.subTest(end=end):
                done = self.run_body("undo sh -c 'echo run >> runs-1'\n"
                                     "undo sh -c 'echo run >> runs-2; %s'\n" % (TO_SHELL % "TERM")
                                     + "undo sh -c 'echo run >> runs-3'\n" + tail)
                self.assertEqual(done.returncode, code, done.stderr)
                self.assertEqual(done.content, {"runs-1": "run\n", "runs-2": "run\n", "runs-3": "run\n"})
                self.assertEqual(done.stdout.count("[live] undo: "), 3, done.stdout)
                self.assertNotIn("[live] done.", done.stdout)
                self.assertNotIn("LEFT BEHIND", done.stderr)
                self.assertNotIn("starts again", done.stderr)
                self.assertIn("signal during the undo: the undo continues", done.stderr)

    def test_the_exit_code_is_the_code_of_the_first_signal(self):
        done = self.run_body("undo sh -c '%s'\nundo sh -c '%s'\nundo_now\necho '[live] done.'\n"
                             % (TO_SHELL % "HUP", TO_SHELL % "TERM"))
        self.assertEqual(done.returncode, 143, done.stderr)
        self.assertEqual(done.stderr.count("signal during the undo: the undo continues"), 2)
        self.assertNotIn("[live] done.", done.stdout)

    def test_an_undo_command_that_a_signal_stopped_starts_again(self):
        # The signal comes to the script and to the undo command that runs (a second
        # Ctrl-C). The command stops in the middle, so its change is not reverted. It
        # must start again; the commands that ran to their end must not.
        again = ("if test -e stopped; then rm object-2; else touch stopped; %s; fi"
                 % (TO_BOTH % ("INT", "INT")))
        ends = {"the planned end": ("undo_now\necho '[live] done.'\n", 130),
                "the exit path": ("sh -c 'exit 7'\n", 7)}
        for end, (tail, code) in ends.items():
            with self.subTest(end=end):
                done = self.run_body("touch object-1 object-2 object-3\n"
                                     "undo rm object-1\nundo sh -c '%s'\nundo rm object-3\n" % again
                                     + tail)
                self.assertEqual(done.returncode, code, done.stderr)
                self.assertEqual(done.files, ["stopped"], "an object stays")
                self.assertIn("it starts again", done.stderr)
                self.assertNotIn("LEFT BEHIND", done.stderr)
                self.assertNotIn("[live] done.", done.stdout)

    def test_a_signal_after_the_last_undo_command_does_not_print_done(self):
        # In undo_now, after the undo commands and before the line that ignores the stop
        # signals: the run must stop with the code of the signal and must not print "done".
        for where in ("_SIG -ne 0", "_LEFT -ne 0", "HUP INT TERM"):
            with self.subTest(signal_before=where):
                done = self.run_body("touch object\nundo rm object\n" + SIGNAL_BEFORE % where
                                     + "undo_now\necho '[live] done.'\n")
                self.assertEqual(done.returncode, 143, done.stderr)
                self.assertEqual(done.files, [], "the change stays")
                self.assertNotIn("[live] done.", done.stdout)
                self.assertIn("[live] FAILED (exit 143)", done.stderr)

    def test_a_signal_after_undo_now_does_not_fail_a_good_run(self):
        # undo_now returned: each change is reverted and no stop signal came. A stop signal
        # that comes after that (the person presses Ctrl-C at the last message) has no
        # effect: the run is good, and it must not print "done" and then FAILED.
        for name, _code in SIGNALS:
            with self.subTest(signal=name):
                done = self.run_body("touch object\nundo rm object\nundo_now\n"
                                     f"kill -{name} $$\necho '[live] done.'\nkill -{name} $$\n")
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.files, [], "the change stays")
                self.assertTrue(done.stdout.endswith("[live] done.\n"), done.stdout)
                self.assertEqual(done.stderr, "")

    def test_a_signal_at_the_start_of_the_exit_path_does_not_skip_the_undo(self):
        # The run ends (a command failed, the script stopped itself, or undo_now stopped
        # the run), and a stop signal comes before the first command of the exit path. bash
        # does not start the EXIT trap a second time, so a plain `exit` in the signal trap
        # would end the run there: no undo command, no line. The undo must run, and the
        # FAILED line must be printed.
        at_exit = ("set -o functrace\n"
                   "trap 'if [[ ${FUNCNAME[0]:-} == _on_exit ]]; then trap - DEBUG; kill -%s $$; fi' DEBUG\n")
        ends = {"a command that fails": "sh -c 'exit 7'\n",
                "the script stops itself": "echo 'no record' >&2\nexit 1\n",
                "the end of the script with no undo_now": "echo body\n"}
        for name, code in SIGNALS:
            for end, tail in ends.items():
                with self.subTest(signal=name, end=end):
                    done = self.run_body("touch object\nundo rm object\n" + at_exit % name + tail)
                    self.assertEqual(done.returncode, code, done.stderr)
                    self.assertEqual(done.files, [], "the undo did not run")
                    self.assertEqual(done.stdout.count("[live] undo: rm object"), 1, done.stdout)
                    self.assertIn(f"[live] FAILED (exit {code})", done.stderr)
        # undo_now stopped the run because an undo command failed: the FAILED line must
        # not be lost.
        done = self.run_body("undo false\n" + at_exit % "TERM" + "undo_now\necho '[live] done.'\n")
        self.assertEqual(done.returncode, 143, done.stderr)
        self.assertIn("[live] LEFT BEHIND, this command failed: false ", done.stderr)
        self.assertIn("[live] FAILED (exit 143)", done.stderr)
        self.assertNotIn("[live] done.", done.stdout)

    def test_a_signal_while_the_undo_is_registered_does_not_lose_it(self):
        # The change is made and the signal comes inside `undo`, before the command is in
        # the list. The run must stop only after the registration, and then revert.
        for where in ("printf -v quoted", "_UNDO+="):
            with self.subTest(signal_before=where):
                done = self.run_body("change_next 'the object'\ntouch object\n" + SIGNAL_BEFORE % where
                                     + "undo rm object\necho not reached\n")
                self.assertEqual(done.returncode, 143, done.stderr)
                self.assertEqual(done.files, [], "the change stays")
                self.assertNotIn("not reached", done.stdout)
                self.assertNotIn("has no undo", done.stderr)
                self.assertIn("[live] FAILED (exit 143)", done.stderr)

    def test_an_undo_command_that_a_signal_stops_each_time_is_left_behind_after_three_runs(self):
        # An undo command that hangs: the person presses Ctrl-C, the command stops and
        # starts again. That must have an end, or only a kill -9 stops the run, and then the
        # run prints nothing. After the third run the block names the command (LEFT BEHIND)
        # and goes on with the other undo commands.
        each_time = "echo run >> runs; " + TO_BOTH % ("INT", "INT")
        ends = {"the planned end": ("undo_now\necho '[live] done.'\n", 130),
                "the exit path": ("sh -c 'exit 7'\n", 7)}
        for end, (tail, code) in ends.items():
            with self.subTest(end=end):
                done = self.run_body("touch object-1 object-3\n"
                                     "undo rm object-1\nundo sh -c '%s'\nundo rm object-3\n" % each_time
                                     + tail)
                self.assertEqual(done.returncode, code, done.stderr)
                self.assertEqual(done.content, {"runs": "run\nrun\nrun\n"})
                self.assertEqual(done.stderr.count("it starts again"), 2, done.stderr)
                self.assertEqual(done.stderr.count("[live] LEFT BEHIND, this command failed: sh -c "), 1,
                                 done.stderr)
                self.assertNotIn("[live] done.", done.stdout)
                self.assertIn(f"[live] FAILED (exit {code})", done.stderr)

    def test_an_undo_command_that_fails_with_no_signal_does_not_start_again_after_an_earlier_signal(self):
        # A signal came while an earlier undo command ran (that command ran to its end). A
        # later undo command fails, and no signal came during it: it must not start again.
        done = self.run_body("undo sh -c 'echo run >> runs-1; exit 1'\n"
                             "undo sh -c '%s'\n" % (TO_SHELL % "TERM") + "undo_now\necho '[live] done.'\n")
        self.assertEqual(done.returncode, 143, done.stderr)
        self.assertEqual(done.content, {"runs-1": "run\n"})
        self.assertNotIn("starts again", done.stderr)
        self.assertEqual(done.stderr.count("[live] LEFT BEHIND, this command failed: sh -c "), 1, done.stderr)

    def test_a_signal_between_two_commands_prints_the_failed_line_one_time(self):
        done = self.run_body("touch object\nundo rm object\nkill -TERM $$\nsleep 5\necho not reached\n")
        self.assertEqual(done.returncode, 143, done.stderr)
        self.assertEqual(done.stderr.count("[live] FAILED (exit 143)"), 1, done.stderr)

    def test_a_reader_of_the_output_that_is_gone_does_not_stop_the_undo(self):
        # `script | head -1`: after the first line the reader is gone. The next write of
        # the script fails. The undo must run all the same (a SIGPIPE must not end it).
        body = ("touch object-1 object-2\nundo rm object-1\nundo rm object-2\necho first\n"
                "while ! test -e go; do sleep 0.05; done\necho second\necho third > reached\n")
        first, code, stderr, files = self.run_until_the_reader_goes(body)
        self.assertEqual(first, b"first\n")
        self.assertEqual(files, [], "the undo did not run: " + stderr)
        self.assertEqual(code, 1, stderr)
        self.assertIn("[live] FAILED (exit 1)", stderr)

    def test_a_reader_that_is_gone_and_a_signal_to_the_group_do_not_stop_the_undo(self):
        # `script | tee run.log`, then Ctrl-C: tee stops, and the script gets the signal
        # with nobody to read its output.
        body = ("touch object-1 object-2\nundo rm object-1\nundo rm object-2\necho first\n"
                "while ! test -e go; do sleep 0.05; done\nsleep 5\necho third > reached\n")
        first, code, stderr, files = self.run_until_the_reader_goes(body, signal.SIGINT)
        self.assertEqual(first, b"first\n")
        self.assertEqual(files, [], "the undo did not run: " + stderr)
        self.assertEqual(code, 130, stderr)
        self.assertIn("[live] FAILED (exit 130)", stderr)

    def test_a_closed_standard_output_does_not_stop_the_undo(self):
        # The exit path must go on after a command of its own fails (here: each echo).
        for end, tail in (("the exit path", "sh -c 'exit 7'\n"), ("the planned end", "undo_now\n")):
            with self.subTest(end=end):
                done = self.run_body("touch object-1 object-2\nundo rm object-1\nundo rm object-2\n"
                                     "exec >&-\n" + tail)
                self.assertNotEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.files, [], "the undo did not run: " + done.stderr)
                self.assertIn("[live] FAILED", done.stderr)


class Scripts(unittest.TestCase):

    def test_each_listed_script_holds_the_reference_block(self):
        reference = livetest.undo_block()
        self.assertTrue(reference)
        for script in MUST_HAVE:
            with self.subTest(script=script):
                self.assertEqual(livetest.undo_block(os.path.join(livetest.REPO, script)), reference)

    def test_no_script_holds_a_changed_block(self):
        reference = livetest.undo_block()
        for script in livetest.live_scripts():
            found = livetest.undo_block(os.path.join(livetest.REPO, script))
            if found is not None:
                with self.subTest(script=script):
                    self.assertEqual(found, reference)

    def test_each_change_next_has_its_undo_line_before_the_next_one(self):
        # change_next holds a stop signal until the next `undo` line. A change_next with
        # no `undo` line after it would hold the signal for the rest of the run.
        for script in MUST_HAVE:
            with self.subTest(script=script):
                with open(os.path.join(livetest.REPO, script), encoding="utf-8") as fh:
                    text = fh.read()
                body = text[text.index(livetest.UNDO_END):]
                # `change_next ""` says that no change is in progress: it closes like `undo`.
                words = [("undo" if rest.startswith('""') else word) for word, rest in
                         re.findall(r"^\s*(change_next|undo)\s+(.*)$", body, flags=re.M)]
                self.assertTrue("change_next" in words, "the script has no change_next line")
                open_change = False
                for word in words:
                    if word == "change_next":
                        self.assertFalse(open_change, "two change_next lines with no undo line between them")
                        open_change = True
                    else:
                        open_change = False
                self.assertFalse(open_change, "the last change_next has no undo line")

    def test_no_undo_line_hides_the_failure_of_its_command(self):
        # Rule: no cleanup command carries "|| true". An undo line is one command and its
        # arguments, with no "||", no ";" and no eval.
        for script in MUST_HAVE:
            with self.subTest(script=script):
                with open(os.path.join(livetest.REPO, script), encoding="utf-8") as fh:
                    text = fh.read()
                body = text[text.index(livetest.UNDO_END):].replace("\\\n", " ")
                lines = [ln for ln in body.split("\n") if re.match(r"\s*undo\s", ln)]
                self.assertTrue(lines)
                for line in lines:
                    self.assertNotRegex(line, r"\|\||;|\beval\b", line)

    def test_the_block_holds_no_command_substitution(self):
        # bash 5.2 can end with a syntax error when a stop signal comes while it reads a
        # "$( )" (seen in `undo`, which then lost the registration). The block has none.
        self.assertIsNone(re.search(r"\$\((?!\()|`", livetest.undo_block()))

    def test_after_undo_now_a_script_only_prints_and_ends(self):
        # undo_now ignores the stop signals when it returns (each change is reverted). A
        # command that can hang must not come after it: Ctrl-C would not stop that command.
        for script in MUST_HAVE:
            with self.subTest(script=script):
                with open(os.path.join(livetest.REPO, script), encoding="utf-8") as fh:
                    text = fh.read()
                lines = text[text.index(livetest.UNDO_END):].split("\n")
                calls = [i for i, ln in enumerate(lines) if ln.strip() == "undo_now"]
                self.assertTrue(calls, "the script does not call undo_now")
                for at in calls:
                    depth = len(lines[at]) - len(lines[at].lstrip())
                    for line in lines[at + 1:]:
                        word = line.strip()
                        if not word or word.startswith("#"):
                            continue
                        if word == ";;" or len(line) - len(line.lstrip()) < depth:
                            break
                        self.assertRegex(word, r"^(echo |printf |exit \d|if \[|else$|fi$)", line)
                        self.assertNotRegex(word, r"\$\(|`", line)     # no command in the text

    def test_no_script_checks_the_result_of_the_undo_itself(self):
        # undo_now stops the run when an undo command failed or a stop signal came. A
        # script that repeats that check can do it wrong.
        for script in MUST_HAVE:
            with self.subTest(script=script):
                with open(os.path.join(livetest.REPO, script), encoding="utf-8") as fh:
                    text = fh.read()
                body = text[text.index(livetest.UNDO_END):]
                self.assertFalse("_LEFT" in body, "the script reads _LEFT after the block")
                self.assertTrue("undo_now\n" in body, "the script does not call undo_now")


if __name__ == "__main__":
    unittest.main()
