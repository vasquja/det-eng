"""Offline tests of atomics/T1078.004/src/emulate_entra_sp_fic_signin.sh (TRR9023).

The script makes no change in the tenant: it performs a workload-identity-federation
token exchange (a sign-in) and reads the result. These tests prove the dry contract and
the corrections from the "Problems in the live scripts" table:

  * a live run requires the real tenant, appId and OIDC token (exit 2, no request, no
    placeholder ID when one is missing);
  * the external OIDC token is sent on curl's stdin, never on a command line;
  * the script reads the HTTP status: it prints "done" only on a 200 with an access_token,
    and on a refusal it prints the Entra error code and description and exits non-zero;
  * the access token of a success is never printed, and neither is a body that came with no
    HTTP status line (curl that did not honour -w);
  * a live run of b, c or d (no live run) makes no request and exits 1.

The stub `curl` cannot run `-w`, so a test that exercises the response path feeds the
combined `<body>\n<status>` that real curl would emit (body + the -w status line).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import livetest     # noqa: E402

SCRIPT = "atomics/T1078.004/src/emulate_entra_sp_fic_signin.sh"

# Placeholder IDs that must NEVER reach a live request.
PLACEHOLDER_TENANT = "a17c0ff3-11aa-4bb2-8cc3-99ddeeff0011"
PLACEHOLDER_APPID = "c4d5e6f7-9023-4a0b-9c1d-2e3f4a5b6c7d"
# Real-ish values a person would set.
TENANT = "99999999-aaaa-bbbb-cccc-111122223333"
APPID = "88888888-dddd-eeee-ffff-444455556666"
TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0cnI5MDIzLWVtdWxhdGlvbiJ9.sig-trr9023-fake"
SECRET = "ACCESS-TOKEN-MUST-NOT-LEAK"

LIVE = {"TRR9023_LIVE": "1", "TRR9023_TENANT": TENANT, "TRR9023_APPID": APPID,
        "TRR9023_OIDC_TOKEN": TOKEN}
OK_BODY = ('{"token_type":"Bearer","expires_in":3599,"access_token":"%s"}\n200' % SECRET)
FAIL_BODY = ('{"error":"invalid_client","error_description":"AADSTS700213: No matching '
             'federated identity record found for presented assertion."}\n401')
TOKEN_ENDPOINT = ("https://login.microsoftonline.com/%s/oauth2/v2.0/token" % TENANT)


class Dry(unittest.TestCase):

    def test_each_procedure_letter_exits_0_and_makes_no_call(self):
        for proc in ("a", "b", "c", "d"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc)
                self.assertEqual(run.returncode, 0, run.text)
                self.assertEqual(run.calls, [], run.text)

    def test_the_dry_text_does_not_print_a_token_that_is_set(self):
        # A person can have the variables set from an earlier live run.
        for proc in ("a", "b", "c", "d"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env={k: v for k, v in LIVE.items()
                                                             if k != "TRR9023_LIVE"})
                self.assertEqual(run.returncode, 0, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertNotIn(TOKEN, run.stdout + run.stderr)

    def test_an_invalid_letter_prints_usage_and_exits_1(self):
        run = livetest.run_script(SCRIPT, "z")
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("usage: emulate_entra_sp_fic_signin.sh {a|b|c|d}", run.stdout)
        self.assertEqual(run.calls, [])

    def test_show_fixture_prints_the_committed_fixture_and_makes_no_call(self):
        run = livetest.run_script(SCRIPT, "--show-fixture")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [])
        with open(os.path.join(livetest.REPO,
                  "detections/cloud/fixtures/trr9023/attack.json"), encoding="utf-8") as fh:
            self.assertEqual(run.stdout, fh.read())


class LiveGuards(unittest.TestCase):

    def test_a_missing_required_variable_stops_before_any_request_with_exit_2(self):
        for drop in ("TRR9023_TENANT", "TRR9023_APPID", "TRR9023_OIDC_TOKEN"):
            with self.subTest(missing=drop):
                env = {k: v for k, v in LIVE.items() if k != drop}
                run = livetest.run_script(SCRIPT, "a", env=env)
                self.assertEqual(run.returncode, 2, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn(drop, run.stderr)
                self.assertNotIn(TOKEN, run.stdout + run.stderr)

    def test_a_missing_variable_never_falls_back_to_a_placeholder_id(self):
        env = {k: v for k, v in LIVE.items() if k != "TRR9023_TENANT"}
        run = livetest.run_script(SCRIPT, "a", env=env)
        self.assertEqual(run.calls, [])
        self.assertNotIn(PLACEHOLDER_TENANT, run.text)

    def test_without_curl_a_live_run_makes_no_request_and_exits_1(self):
        # curl is not installed: no sign-in can be made, so the run is not a success.
        stubs = tuple(name for name in livetest.STUBS if name != "curl")
        run = livetest.run_script(SCRIPT, "a", env=LIVE, stubs=stubs,
                                  outputs=[("login.microsoftonline", OK_BODY)])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertEqual(run.calls, [], run.text)
        self.assertIn("curl not found", run.stderr)
        self.assertNotIn("[live] done", run.stdout)
        self.assertNotIn(TOKEN, run.stdout + run.stderr)

    def test_a_procedure_with_no_live_run_makes_no_request_and_exits_1(self):
        # b, c and d have no live run. The script knows that it caused no record, so a
        # live run of them must not end with exit 0 (the dry mode of them does).
        for proc in ("b", "c", "d"):
            for how in ("variable", "argument"):
                with self.subTest(proc=proc, live=how):
                    if how == "variable":
                        run = livetest.run_script(SCRIPT, proc, env=LIVE)
                    else:
                        env = {k: v for k, v in LIVE.items() if k != "TRR9023_LIVE"}
                        run = livetest.run_script(SCRIPT, proc, "--live", env=env)
                    self.assertEqual(run.returncode, 1, run.text)
                    self.assertEqual(run.calls, [], run.text)
                    self.assertIn("procedure %s has no live run: no record was caused" % proc,
                                  run.stderr)
                    self.assertNotIn("[live] done", run.stdout)
                    self.assertNotIn(TOKEN, run.stdout + run.stderr)


class LiveExchange(unittest.TestCase):

    def test_happy_path_makes_one_request_with_the_exact_argv(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                  outputs=[("login.microsoftonline", OK_BODY)])
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(len(run.calls), 1, run.text)
        self.assertEqual(run.calls[0], [
            "curl", "-sS", "-w", "\n%{http_code}", "-X", "POST", TOKEN_ENDPOINT,
            "--data-urlencode", "client_id=%s" % APPID,
            "--data-urlencode", "scope=https://graph.microsoft.com/.default",
            "--data-urlencode",
            "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "--data-urlencode", "grant_type=client_credentials",
            "--data-urlencode", "client_assertion@-"], run.text)

    def test_the_token_is_sent_on_curls_stdin_with_no_newline_after_it(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                  outputs=[("login.microsoftonline", OK_BODY)])
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(len(run.calls), 1, run.text)
        # The assertion value comes to curl on its standard input (--data-urlencode name@-).
        # It must be the token exactly, with no newline after it (a newline would break the JWT).
        self.assertEqual(run.stdins[0], TOKEN, run.text)

    def test_the_token_is_never_on_a_command_line(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                  outputs=[("login.microsoftonline", OK_BODY)])
        # Check the token is not a substring of any argument, not merely absent as a
        # whole element: "client_assertion=<TOKEN>" would hide it from an element test.
        for call in run.calls:
            for arg in call:
                self.assertNotIn(TOKEN, arg, " ".join(call))

    def test_the_external_oidc_token_is_never_printed(self):
        # Neither a success body nor an error body response causes the OIDC token to appear
        # in the script's own output.
        for body in (OK_BODY, FAIL_BODY):
            with self.subTest(body=body[:20]):
                run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                          outputs=[("login.microsoftonline", body)])
                self.assertNotIn(TOKEN, run.stdout, run.text)
                self.assertNotIn(TOKEN, run.stderr, run.text)

    def test_live_as_second_argument_runs_one_request(self):
        env = {k: v for k, v in LIVE.items() if k != "TRR9023_LIVE"}
        run = livetest.run_script(SCRIPT, "a", "--live", env=env,
                                  outputs=[("login.microsoftonline", OK_BODY)])
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(len(run.calls), 1, run.text)
        self.assertEqual(run.calls[0][0], "curl", run.text)

    def test_no_placeholder_id_reaches_the_request(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                  outputs=[("login.microsoftonline", OK_BODY)])
        self.assertNotIn(PLACEHOLDER_TENANT, run.text)
        self.assertNotIn(PLACEHOLDER_APPID, run.text)

    def test_success_prints_done_and_never_the_access_token(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                  outputs=[("login.microsoftonline", OK_BODY)])
        self.assertEqual(run.returncode, 0, run.text)
        self.assertIn("done", run.stdout)
        self.assertNotIn(SECRET, run.stdout)
        self.assertNotIn(SECRET, run.stderr)

    def test_a_refused_exchange_prints_the_error_and_exits_nonzero(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                  outputs=[("login.microsoftonline", FAIL_BODY)])
        self.assertNotEqual(run.returncode, 0, run.text)
        self.assertNotIn("done", run.stdout)
        self.assertIn("invalid_client", run.stderr)
        self.assertIn("AADSTS700213", run.stderr)

    def test_a_refused_exchange_prints_the_two_error_fields_only_not_the_body(self):
        # An error body of Entra holds no token today. All the same, the script prints the
        # error code and the error description only: a value in another field of the body
        # must not come out.
        sentinel = "SENTINEL-FIELD-MUST-NOT-PRINT"
        body = ('{"error":"invalid_client","error_description":"AADSTS700213: no match.",'
                '"trace_id":"%s"}\n401' % sentinel)
        run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                  outputs=[("login.microsoftonline", body)])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("invalid_client", run.stderr)
        self.assertIn("AADSTS700213", run.stderr)
        self.assertNotIn(sentinel, run.stdout + run.stderr, run.text)

    def test_a_transport_failure_does_not_print_done_and_exits_nonzero(self):
        # The stub fails and prints a line; the script must say the request could not be sent
        # (curl exit 7) and must not leak the token. Real curl appends "\n000" on a dead
        # connection, so the message names the curl exit, not a status.
        run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                  fail=[("login.microsoftonline", 7, "\n000")])
        self.assertNotEqual(run.returncode, 0, run.text)
        self.assertNotIn("done", run.stdout)
        self.assertIn("curl exit 7", run.stderr)
        self.assertNotIn(TOKEN, run.stdout + run.stderr)
        # curl can fail after the answer came (exit 56): the answer holds the access token.
        run = livetest.run_script(SCRIPT, "a", env=LIVE, fail=[("login.microsoftonline", 56, OK_BODY)])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertNotIn("done", run.stdout)
        self.assertNotIn(SECRET, run.stdout + run.stderr)
        self.assertNotIn(TOKEN, run.stdout + run.stderr)

    def test_a_response_with_no_status_line_is_not_printed_and_fails(self):
        # A curl that did not honour -w leaves the body as the last line. That body can hold
        # the access token on success, so the script must not print it, and must exit 1.
        no_status = '{"token_type":"Bearer","access_token":"%s"}' % SECRET
        run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                  outputs=[("login.microsoftonline", no_status)])
        self.assertNotEqual(run.returncode, 0, run.text)
        self.assertNotIn("done", run.stdout)
        self.assertNotIn(SECRET, run.stdout + run.stderr)
        self.assertIn("no HTTP status line", run.stderr)
        self.assertNotIn(TOKEN, run.stdout + run.stderr)

    def test_a_code_on_the_same_line_as_the_body_is_not_printed_and_fails(self):
        same_line = '{"access_token":"%s"}200' % SECRET
        run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                  outputs=[("login.microsoftonline", same_line)])
        self.assertNotEqual(run.returncode, 0, run.text)
        self.assertNotIn(SECRET, run.stdout + run.stderr)
        self.assertNotIn(TOKEN, run.stdout + run.stderr)
        self.assertNotIn("done", run.stdout)

    def test_a_200_with_no_access_token_is_not_a_success(self):
        # A 200 body with no access_token is not a sign-in. The body is not printed: it can
        # hold a different token.
        for body in ("\n200", '{"token_type":"Bearer","id_token":"%s"}\n200' % SECRET):
            with self.subTest(body=body):
                run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                          outputs=[("login.microsoftonline", body)])
                self.assertNotEqual(run.returncode, 0, run.text)
                self.assertNotIn("done", run.stdout)
                self.assertIn("no access_token", run.stderr)
                self.assertNotIn(SECRET, run.stdout + run.stderr)
                self.assertNotIn(TOKEN, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
