"""Offline tests of atomics/T1562.008/src/emulate_gcp_log_sink.sh (TRR9038).

The script disrupts GCP Cloud Logging in a throwaway project and then restores it.
These tests run it with the livetest stubs (no cloud call) and prove:

  * dry mode makes no call and exits 0 for each procedure letter;
  * an invalid letter prints the usage line and exits 1;
  * --show-fixture prints the committed fixture and makes no call;
  * a live run with a required variable not set stops with exit 2 and no change;
  * the live happy path runs the exact sequence of commands (tamper then restore);
  * procedure a reads the state of the _Default sink first and stops when the sink is
    disabled before the run;
  * procedure b deletes only a bucket whose name starts with trr9038-;
  * procedure c calls the REST API (no 'gcloud logging exclusions' command), gives the
    access token to curl on its standard input (not on a command line, not in a file,
    never printed), and removes the exclusion also when the create request got no answer;
  * a failure or a stop signal at each command that makes a change reverts the change,
    or names the change that can stay, and exits != 0.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import livetest     # noqa: E402

SCRIPT = "atomics/T1562.008/src/emulate_gcp_log_sink.sh"
PROJECT = "trr9038-sandbox"
BUCKET = "trr9038-custom"
URL = "https://logging.googleapis.com/v2/projects/%s/exclusions" % PROJECT
# A value that stands for the access token. It must be in no command line and in no output.
TOKEN = "ya29.SENTINEL-abc_DEF-123"
HEADER = 'header = "Authorization: Bearer %s"\n' % TOKEN

# A live run reads TRR9038_PROJECT (the account-naming value); procedure b also
# reads TRR9038_CUSTOM_BUCKET.
LIVE_AB = {"TRR9038_LIVE": "1", "TRR9038_PROJECT": PROJECT, "TRR9038_CUSTOM_BUCKET": BUCKET}
LIVE_C = {"TRR9038_LIVE": "1", "TRR9038_PROJECT": PROJECT}

DESCRIBE = ["gcloud", "logging", "sinks", "describe", "_Default", "--project=" + PROJECT,
            "--format=value(disabled)"]
DISABLE = ["gcloud", "logging", "sinks", "update", "_Default", "--disabled", "--project=" + PROJECT]
ENABLE = ["gcloud", "logging", "sinks", "update", "_Default", "--no-disabled", "--project=" + PROJECT]
BUCKET_DELETE = ["gcloud", "logging", "buckets", "delete", BUCKET, "--location=global",
                 "--project=" + PROJECT, "--quiet"]
BUCKET_UNDELETE = ["gcloud", "logging", "buckets", "undelete", BUCKET, "--location=global",
                   "--project=" + PROJECT]

GET_TOKEN = ["gcloud", "auth", "print-access-token"]
BODY = '{"name":"trr9038-drop-audit","filter":"logName:\\"cloudaudit.googleapis.com\\"","disabled":true}'
# curl gets -q first (no curl config file of the user), the token on stdin (--config -),
# and prints the HTTP status after the answer (-w).
CURL = ["curl", "-q", "-sS", "--max-time", "60", "-w", "\\n%{http_code}", "--config", "-"]
POST = CURL + ["-X", "POST", "-H", "Content-Type: application/json", "-d", BODY, URL]
DELETE = CURL + ["-X", "DELETE", URL + "/trr9038-drop-audit"]
FULL_C = [GET_TOKEN, POST, DELETE]

# The stub curl prints what the real curl prints with -w: the answer, then the status.
TOKEN_OUT = [(r"gcloud auth print-access-token", TOKEN)]
POST_OK = (r"curl .*-X POST", '{"name": "trr9038-drop-audit", "disabled": true}\n200')
DELETE_OK = (r"curl .*-X DELETE", "{}\n200")
OK_C = TOKEN_OUT + [POST_OK, DELETE_OK]


def answer(method, status, text="{}"):
    return (r"curl .*-X %s" % method, "%s\n%s" % (text, status))


class Dry(unittest.TestCase):

    def test_each_letter_exits_0_and_makes_no_call(self):
        for proc in ("a", "b", "c"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc)
                self.assertEqual(run.returncode, 0, run.text)
                self.assertEqual(run.calls, [], run.text)

    def test_an_invalid_letter_prints_usage_and_exits_1(self):
        run = livetest.run_script(SCRIPT, "nope")
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("usage: emulate_gcp_log_sink.sh {a|b|c}", run.stdout)
        self.assertEqual(run.calls, [], run.text)

    def test_dry_c_prints_the_rest_call_and_never_runs_gcloud(self):
        # The $(gcloud ...) in the printed template must stay literal: no call.
        run = livetest.run_script(SCRIPT, "c")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [], run.text)
        # The URL is in double quotes, so $PROJECT expands when a person runs the line.
        self.assertIn('"https://logging.googleapis.com/v2/projects/$PROJECT/exclusions"', run.stdout)
        # The old, non-existent command line must not be printed as a step to run.
        self.assertNotIn("gcloud logging exclusions create trr9038", run.stdout)
        # The printed command gives the token to curl on its standard input (a config
        # line), as the live run does: not on the command line of curl.
        self.assertIn("printf 'header = \"Authorization: Bearer %s\"\\n' \"$(gcloud auth print-access-token)\"",
                      run.stdout)
        self.assertIn("| curl -q --config - -X POST", run.stdout)
        self.assertNotRegex(run.stdout, r"curl[^\n|]*Authorization")
        self.assertNotRegex(run.stdout, r"curl[^\n|]*(print-access-token|[Bb]earer)")


class ShowFixture(unittest.TestCase):

    def test_show_fixture_prints_the_committed_record_and_makes_no_call(self):
        run = livetest.run_script(SCRIPT, "a", "--show-fixture")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [], run.text)
        with open(os.path.join(livetest.REPO,
                  "detections/cloud/fixtures/trr9038/attack.json"), encoding="utf-8") as fh:
            self.assertEqual(run.stdout, fh.read())

    def test_show_fixture_works_as_the_first_argument_too(self):
        run = livetest.run_script(SCRIPT, "--show-fixture")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [], run.text)
        self.assertIn("ConfigServiceV2.CreateExclusion", run.stdout)


class LiveGuards(unittest.TestCase):

    def test_project_not_set_stops_with_exit_2_and_no_call(self):
        for proc in ("a", "b", "c"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env={"TRR9038_LIVE": "1"})
                self.assertEqual(run.returncode, 2, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("TRR9038_PROJECT", run.stderr)

    def test_b_custom_bucket_not_set_stops_with_exit_2_and_no_call(self):
        run = livetest.run_script(SCRIPT, "b", env={"TRR9038_LIVE": "1", "TRR9038_PROJECT": PROJECT})
        self.assertEqual(run.returncode, 2, run.text)
        self.assertEqual(run.calls, [], run.text)
        self.assertIn("TRR9038_CUSTOM_BUCKET", run.stderr)

    def test_b_refuses_a_bucket_that_is_not_a_throwaway_bucket_of_this_emulation(self):
        # The reserved names, in each spelling, and a bucket of the user.
        for name in ("_Default", "_Required", "_default", "_REQUIRED", " _Default",
                     "audit-archive-prod", "x/../_Default", "my-trr9038-bucket"):
            with self.subTest(bucket=name):
                env = {"TRR9038_LIVE": "1", "TRR9038_PROJECT": PROJECT, "TRR9038_CUSTOM_BUCKET": name}
                run = livetest.run_script(SCRIPT, "b", env=env)
                self.assertEqual(run.returncode, 2, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("TRR9038_CUSTOM_BUCKET must start with trr9038-", run.stderr)

    def test_a_stops_before_any_change_when_the_sink_is_disabled_before_the_run(self):
        # The undo of procedure a enables the sink. If the sink was disabled before the
        # run, that undo would change the project, and the run would say "done".
        for state in ("True", "true"):
            with self.subTest(state=state):
                run = livetest.run_script(SCRIPT, "a", env=LIVE_AB,
                                          outputs=[(r"sinks describe", state)])
                self.assertEqual(run.returncode, 2, run.text)
                self.assertEqual(run.calls, [DESCRIBE], run.text)
                self.assertIn("is disabled before the run", run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_a_stops_before_any_change_when_the_state_of_the_sink_cannot_be_read(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_AB, fail=[(r"sinks describe", 4)])
        self.assertEqual(run.returncode, 4, run.text)
        self.assertEqual(run.calls, [DESCRIBE], run.text)

    def test_without_gcloud_a_live_run_makes_no_call_and_exits_1(self):
        # gcloud is not installed: no record can be caused, so the run is not a success.
        stubs = tuple(name for name in livetest.STUBS if name != "gcloud")
        for proc, env in (("a", LIVE_AB), ("b", LIVE_AB), ("c", LIVE_C)):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env=env, outputs=OK_C, stubs=stubs)
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("gcloud not found", run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_c_without_curl_stops_with_exit_1_and_no_call(self):
        stubs = tuple(name for name in livetest.STUBS if name != "curl")
        run = livetest.run_script(SCRIPT, "c", env=LIVE_C, outputs=OK_C, stubs=stubs)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertEqual(run.calls, [], run.text)
        self.assertIn("curl not found", run.stderr)


class LiveHappyPath(unittest.TestCase):

    def test_a_reads_the_state_then_disables_then_re_enables_the_default_sink(self):
        # The stub prints nothing for the describe: an enabled sink has no value there.
        for state in ("", "False"):
            with self.subTest(state=state):
                run = livetest.run_script(SCRIPT, "a", env=LIVE_AB, outputs=[(r"sinks describe", state)])
                self.assertEqual(run.returncode, 0, run.text)
                self.assertEqual(run.calls, [DESCRIBE, DISABLE, ENABLE], run.text)
                self.assertTrue(run.stdout.rstrip("\n").split("\n")[-1].startswith("[live] done."), run.text)

    def test_a_live_via_second_argument(self):
        run = livetest.run_script(SCRIPT, "a", "--live", env={"TRR9038_PROJECT": PROJECT})
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [DESCRIBE, DISABLE, ENABLE], run.text)

    def test_b_deletes_then_undeletes_the_custom_bucket(self):
        run = livetest.run_script(SCRIPT, "b", env=LIVE_AB)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [BUCKET_DELETE, BUCKET_UNDELETE], run.text)

    def test_b_says_that_the_rule_does_not_fire_on_the_record_of_a_custom_bucket(self):
        run = livetest.run_script(SCRIPT, "b", env=LIVE_AB)
        self.assertEqual(run.returncode, 0, run.text)      # the record is written: exit 0 by design
        self.assertIn("the rule does NOT fire on it, by design", run.stdout)

    def test_c_creates_then_removes_the_exclusion_via_rest_with_the_exact_calls(self):
        run = livetest.run_script(SCRIPT, "c", env=LIVE_C, outputs=OK_C)
        self.assertEqual(run.returncode, 0, run.text)
        # read the token, POST (create), DELETE (the undo).
        self.assertEqual(run.calls, FULL_C, run.text)
        self.assertTrue(run.stdout.rstrip("\n").split("\n")[-1].startswith("[live] done."), run.text)

    def test_c_creates_the_exclusion_disabled_so_that_it_drops_no_log(self):
        # Stop before harm: a disabled exclusion drops nothing, and its audit record
        # has the method that the rule reads.
        run = livetest.run_script(SCRIPT, "c", env=LIVE_C, outputs=OK_C)
        self.assertEqual(run.returncode, 0, run.text)
        body = run.calls[1][run.calls[1].index("-d") + 1]
        self.assertEqual(json.loads(body), {"name": "trr9038-drop-audit", "disabled": True,
                                            "filter": 'logName:"cloudaudit.googleapis.com"'})


class LiveToken(unittest.TestCase):
    """The access token of procedure c: on the standard input of curl only."""

    # The ways that a run of procedure c can end: stub rules -> exit code. A new end of
    # the script must get a line here.
    ENDS = {
        "the happy path": (dict(outputs=OK_C), 0),
        "the create is refused": (dict(outputs=TOKEN_OUT + [answer("POST", 403), DELETE_OK]), 1),
        "the exclusion is there before the run": (dict(outputs=TOKEN_OUT + [answer("POST", 409), DELETE_OK]), 1),
        "the create gets a server error": (dict(outputs=TOKEN_OUT + [answer("POST", 500), DELETE_OK]), 1),
        "the create gets no answer": (dict(outputs=TOKEN_OUT + [DELETE_OK], fail=[(r"curl .*-X POST", 56)]), 1),
        "the create answer has no HTTP status": (dict(outputs=TOKEN_OUT + [(r"curl .*-X POST", "ANSWER-WITH-NO-STATUS"),
                                                                           DELETE_OK]), 1),
        "the delete is refused": (dict(outputs=TOKEN_OUT + [POST_OK, answer("DELETE", 500)]), 1),
        "the delete gets no answer": (dict(outputs=TOKEN_OUT + [POST_OK], fail=[(r"curl .*-X DELETE", 7)]), 1),
        "a stop signal during the create": (dict(outputs=OK_C, signals=[(r"curl .*-X POST", "TERM", "shell")]), 143),
    }

    def test_the_token_is_in_no_command_line_in_no_output_and_in_no_file(self):
        for end, (rules, code) in self.ENDS.items():
            with self.subTest(end=end):
                run = livetest.run_script(SCRIPT, "c", env=LIVE_C, **rules)
                self.assertEqual(run.returncode, code, run.text)
                for call in run.calls:
                    for arg in call:
                        self.assertNotIn(TOKEN, arg, run.text)
                        self.assertNotIn("Authorization", arg, run.text)
                        self.assertNotIn("Bearer", arg, run.text)
                self.assertNotIn(TOKEN, run.stdout)
                self.assertNotIn(TOKEN, run.stderr)
                # The run leaves no file: not in the directory for temporary files, not in
                # HOME and not in the working directory.
                self.assertEqual(run.tmp_files, [], run.text)
                self.assertEqual(run.home_files, [], run.text)

    def test_curl_gets_the_token_header_on_its_standard_input(self):
        run = livetest.run_script(SCRIPT, "c", env=LIVE_C, outputs=OK_C)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.stdins, [None, HEADER, HEADER], run.text)

    def test_curl_does_not_read_the_curl_config_file_of_the_user(self):
        # -q must be the first argument. A config file of the user can hold "verbose",
        # which prints the token header.
        run = livetest.run_script(SCRIPT, "c", env=LIVE_C, outputs=OK_C)
        curls = [call for call in run.calls if call[0] == "curl"]
        self.assertEqual(len(curls), 2, run.text)
        for call in curls:
            self.assertEqual(call[1], "-q", run.text)

    def test_a_token_that_cannot_be_read_stops_before_any_request(self):
        cases = {"gcloud fails": (dict(outputs=OK_C, fail=[(r"gcloud auth print-access-token", 3)]), 3),
                 "gcloud prints nothing": (dict(outputs=[POST_OK, DELETE_OK]), 1)}
        for what, (rules, code) in cases.items():
            with self.subTest(what=what):
                run = livetest.run_script(SCRIPT, "c", env=LIVE_C, **rules)
                self.assertEqual(run.returncode, code, run.text)
                self.assertEqual(run.calls, [GET_TOKEN], run.text)
                self.assertNotIn("[live] done", run.stdout)
                # No change was in progress, so the run names no change that can stay.
                self.assertNotIn("has no undo", run.stderr)


class LiveExclusionCreate(unittest.TestCase):
    """What procedure c does with each answer to the create request."""

    def test_a_refused_create_registers_no_undo_and_shows_the_answer_of_the_api(self):
        refusal = '{"error": {"code": 403, "status": "PERMISSION_DENIED"}}'
        run = livetest.run_script(SCRIPT, "c", env=LIVE_C,
                                  outputs=TOKEN_OUT + [answer("POST", 403, refusal), DELETE_OK])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertEqual(run.calls, [GET_TOKEN, POST], run.text)
        self.assertIn("exclusion create failed: HTTP 403", run.stderr)
        self.assertIn("PERMISSION_DENIED", run.stderr)
        self.assertNotIn("[live] done", run.stdout)
        # The run has no undo for this change, and the undo block says so and tells the
        # person to do the check. The script must not say the opposite in the line before.
        self.assertIn("That change has no undo. If the provider made it, it stays", run.stderr)
        self.assertNotIn("No exclusion was made", run.stderr)

    def test_a_server_error_at_the_create_runs_the_delete_because_the_exclusion_can_exist(self):
        # A status that is not 2xx and not 4xx (for example 500, 503): the request was not
        # refused, so the provider possibly made the exclusion. The delete accepts "not
        # found" (404), so it is safe, and the run is not a success.
        for code in (500, 503, 302, 100):
            with self.subTest(code=code):
                run = livetest.run_script(SCRIPT, "c", env=LIVE_C,
                                          outputs=TOKEN_OUT + [answer("POST", code, '{"error": "backend"}'),
                                                               answer("DELETE", 404)])
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, FULL_C, run.text)
                self.assertIn("exclusion create failed: HTTP %d" % code, run.stderr)
                self.assertIn("The exclusion possibly exists", run.stderr)
                self.assertIn('{"error": "backend"}', run.stderr)
                self.assertNotIn("LEFT BEHIND", run.stderr)      # 404: it was not there
                self.assertNotIn("has no undo", run.stderr)      # the undo was registered
                self.assertNotIn("[live] done", run.stdout)

    def test_each_refusal_status_registers_no_undo(self):
        # 4xx that is not 409: the API refused the request, and it would refuse the delete.
        for code in (400, 401, 403, 404, 429):
            with self.subTest(code=code):
                run = livetest.run_script(SCRIPT, "c", env=LIVE_C,
                                          outputs=TOKEN_OUT + [answer("POST", code), DELETE_OK])
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, [GET_TOKEN, POST], run.text)
                self.assertIn("exclusion create failed: HTTP %d. The API refused" % code, run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_an_exclusion_that_an_earlier_run_left_is_removed_and_the_run_fails(self):
        # HTTP 409: the name is taken. The run caused no record. It removes the leftover,
        # so the next run can cause one.
        run = livetest.run_script(SCRIPT, "c", env=LIVE_C,
                                  outputs=TOKEN_OUT + [answer("POST", 409), DELETE_OK])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertEqual(run.calls, FULL_C, run.text)
        self.assertIn("was there before this run (HTTP 409)", run.stderr)
        self.assertIn("NO CreateExclusion record", run.stderr)
        self.assertNotIn("LEFT BEHIND", run.stderr)
        self.assertNotIn("[live] done", run.stdout)

    def test_a_create_with_no_answer_runs_the_delete_because_the_exclusion_can_exist(self):
        # curl fails after the request left (exit 56), or prints no status. The provider
        # possibly made the exclusion. The delete accepts "not found" (404), so it is safe.
        cases = {
            "curl fails": dict(outputs=TOKEN_OUT + [answer("DELETE", 404)], fail=[(r"curl .*-X POST", 56)]),
            "no status line": dict(outputs=TOKEN_OUT + [(r"curl .*-X POST", "ANSWER-WITH-NO-STATUS"),
                                                        answer("DELETE", 404)]),
        }
        says = {"curl fails": "the create request got no answer (curl exit 56)",
                "no status line": "the answer to the create request has no HTTP status"}
        for what, rules in cases.items():
            with self.subTest(what=what):
                run = livetest.run_script(SCRIPT, "c", env=LIVE_C, **rules)
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, FULL_C, run.text)
                self.assertIn(says[what], run.stderr)
                self.assertIn("The exclusion possibly exists", run.stderr)
                # An answer with no status line is not printed: the script does not know
                # what it holds.
                self.assertNotIn("ANSWER-WITH-NO-STATUS", run.stdout + run.stderr)
                self.assertNotIn("LEFT BEHIND", run.stderr)      # 404: it was not there
                self.assertNotIn("has no undo", run.stderr)      # the undo was registered
                self.assertNotIn("[live] done", run.stdout)

    def test_a_delete_that_fails_is_left_behind_with_the_command_that_removes_it(self):
        cases = {
            "HTTP 500": dict(outputs=TOKEN_OUT + [POST_OK, answer("DELETE", 500)]),
            "HTTP 403": dict(outputs=TOKEN_OUT + [POST_OK, answer("DELETE", 403)]),
            "curl fails": dict(outputs=TOKEN_OUT + [POST_OK], fail=[(r"curl .*-X DELETE", 7)]),
            "no status line": dict(outputs=TOKEN_OUT + [POST_OK, (r"curl .*-X DELETE", "{}")]),
        }
        for what, rules in cases.items():
            with self.subTest(what=what):
                run = livetest.run_script(SCRIPT, "c", env=LIVE_C, **rules)
                self.assertEqual(run.returncode, 1, run.text)
                self.assertNotIn("[live] done", run.stdout)
                self.assertIn("LEFT BEHIND, this command failed: _delete_exclusion", run.stderr)
                # The person gets a command that removes the exclusion, with the token
                # on the standard input of curl.
                self.assertIn('| curl -q --config - -X DELETE "%s/trr9038-drop-audit"' % URL, run.stderr)
                self.assertIn("it is disabled and drops no log", run.stderr)


class LiveUndoFailureAtEnd(unittest.TestCase):

    def test_an_undo_failure_at_the_planned_end_does_not_print_done(self):
        # The re-enable (undo of a) fails: the run must not print "done" and must exit != 0.
        run = livetest.run_script(SCRIPT, "a", env=LIVE_AB,
                                  fail=[r"sinks update _Default --no-disabled"])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        self.assertIn("LEFT BEHIND", run.stderr, run.text)

    def test_each_undo_command_that_fails_is_left_behind_and_fails_the_run(self):
        for proc, rules in (("a", dict(env=LIVE_AB)), ("b", dict(env=LIVE_AB)),
                            ("c", dict(env=LIVE_C, outputs=OK_C))):
            with self.subTest(proc=proc):
                self.assertEqual(livetest.each_undo_failure(self, SCRIPT, proc, **rules), 1)

    def test_b_an_undelete_that_fails_does_not_print_done(self):
        run = livetest.run_script(SCRIPT, "b", env=LIVE_AB, fail=[r"buckets undelete"])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        self.assertIn("LEFT BEHIND", run.stderr, run.text)


class LiveFailureAtTheChange(unittest.TestCase):
    """The command that makes the change fails: its undo does not run, and the run
    names the change that has no undo."""

    def test_a_failure_at_disable_runs_no_undo(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_AB,
                                  fail=[(r"sinks update _Default --disabled", 7)])
        self.assertEqual(run.returncode, 7, run.text)
        self.assertEqual(run.calls, [DESCRIBE, DISABLE], run.text)
        self.assertIn("The run stopped before the undo of this change was registered: the _Default sink",
                      run.stderr)

    def test_b_failure_at_delete_runs_no_undelete(self):
        run = livetest.run_script(SCRIPT, "b", env=LIVE_AB, fail=[(r"buckets delete", 7)])
        self.assertEqual(run.returncode, 7, run.text)
        self.assertEqual(run.calls, [BUCKET_DELETE], run.text)
        self.assertIn("The run stopped before the undo of this change was registered: the log bucket " + BUCKET,
                      run.stderr)


class LiveStopSignal(unittest.TestCase):
    """A stop signal that comes while a command that makes a change runs."""

    SIGNALS = (("HUP", 129), ("INT", 130), ("TERM", 143))

    def test_a_signal_to_the_script_during_a_change_reverts_that_change_too(self):
        # The command runs to its end, so the provider made the change. The run must
        # register the undo of that change before it stops.
        cases = {
            "a": (LIVE_AB, [], r"sinks update _Default --disabled", [DESCRIBE, DISABLE, ENABLE]),
            "b": (LIVE_AB, [], r"buckets delete", [BUCKET_DELETE, BUCKET_UNDELETE]),
            "c": (LIVE_C, OK_C, r"curl .*-X POST", FULL_C),
        }
        for name, code in self.SIGNALS:
            for proc, (env, outputs, pattern, expected) in cases.items():
                with self.subTest(signal=name, proc=proc):
                    run = livetest.run_script(SCRIPT, proc, env=env, outputs=outputs,
                                              signals=[(pattern, name, "shell")])
                    self.assertEqual(run.returncode, code, run.text)
                    self.assertEqual(run.calls, expected, run.text)
                    self.assertNotIn("[live] done", run.stdout, run.text)
                    self.assertNotIn("has no undo", run.stderr, run.text)

    def test_c_a_signal_that_stops_curl_during_the_create_runs_the_delete(self):
        # Ctrl-C when the request is possibly sent: the exclusion can exist. The delete
        # accepts "not found", so the run does it.
        for name, code in self.SIGNALS:
            with self.subTest(signal=name):
                run = livetest.run_script(SCRIPT, "c", env=LIVE_C, outputs=OK_C,
                                          signals=[(r"curl .*-X POST", name, "group")])
                self.assertEqual(run.returncode, code, run.text)
                self.assertEqual(run.calls, FULL_C, run.text)
                self.assertNotIn("[live] done", run.stdout, run.text)
                self.assertNotIn("LEFT BEHIND", run.stderr, run.text)

    def test_a_and_b_a_signal_that_stops_gcloud_names_the_change_that_can_stay(self):
        cases = {
            "a": (r"sinks update _Default --disabled", [DESCRIBE, DISABLE], "the _Default sink"),
            "b": (r"buckets delete", [BUCKET_DELETE], "the log bucket " + BUCKET),
        }
        for proc, (pattern, expected, what) in cases.items():
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env=LIVE_AB, signals=[(pattern, "INT", "group")])
                self.assertEqual(run.returncode, 130, run.text)
                self.assertEqual(run.calls, expected, run.text)
                self.assertIn("The run stopped before the undo of this change was registered: " + what, run.stderr)
                self.assertIn("That change has no undo", run.stderr)


if __name__ == "__main__":
    unittest.main()
