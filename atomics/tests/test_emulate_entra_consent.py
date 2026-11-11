"""Offline tests of atomics/T1528/src/emulate_entra_consent.sh (TRR9017).

The script makes no cloud call in dry mode and, in LIVE mode, drives the stub `az` and
`curl` of livetest. These tests prove the dry contract and the corrections from the
"Problems in the live scripts" table:

  * procedures a, b, c, e now CAUSE the record the rule reads instead of only registering
    and deleting an app -- b/c/e via Microsoft Graph (`az rest`), a via the browser
    consent screen (a person is needed; the script says so when none is present and never
    claims a record it did not cause);
  * procedure d no longer runs `az login --use-device-code` (which changes the shell's
    signed-in account and hides its failure with `|| true`): it drives the device-code
    flow with `curl` and a public client, discards every token, and reports truthfully
    when the flow is blocked (a tenant created on 2026-07-01 or later);
  * every change registers its undo, and a failure at any change reverts the earlier
    changes, last first; a live run with TRR9017_TENANT unset stops before any change;
  * a run that knows that it caused no record (no person, no acceptance, a missing app
    role, a device-code flow that did not record a successful sign-in, an answer of `az`
    or of the endpoint that the script cannot use) ends with exit 1, not with exit 0;
  * the device code of procedure d goes to curl on its standard input: it is on no command
    line and in no output.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import livetest     # noqa: E402

SCRIPT = "atomics/T1528/src/emulate_entra_consent.sh"
TENANT = "11111111-2222-3333-4444-555555555555"
GRAPH_APP = "00000003-0000-0000-c000-000000000000"

APP = "trr9017-illicit-consent-app"
APP_OBJECT = "appobj-oid"
APPID = "appid-xxxx"
CLIENT_SP = "clientsp-oid"
GRAPH_SP = "graphsp-oid"
USER_OID = "user-oid"
GRANT = "grant-id-1"
ASSIGN = "assign-id-1"
APPROLE_ID = "approle-id-1"
SCOPES = "offline_access Mail.ReadWrite Mail.Send Files.ReadWrite.All"

LIVE = {"TRR9017_LIVE": "1", "TRR9017_TENANT": TENANT}

CREATE_APP = ["az", "ad", "app", "create", "--display-name", APP, "--sign-in-audience",
              "AzureADMyOrg", "--web-redirect-uris", "http://localhost",
              "--query", "[id, appId]", "-o", "tsv"]
CREATE_SP = ["az", "ad", "sp", "create", "--id", APPID, "--query", "id", "-o", "tsv"]
DEL_SP = ["az", "ad", "sp", "delete", "--id", CLIENT_SP]
# The app delete uses the OBJECT id, not the appId.
DEL_APP = ["az", "ad", "app", "delete", "--id", APP_OBJECT]
SHOW_GRAPH = ["az", "ad", "sp", "show", "--id", GRAPH_APP, "--query", "id", "-o", "tsv"]
SHOW_APPROLE = ["az", "ad", "sp", "show", "--id", GRAPH_APP, "--query",
                "appRoles[?value=='Mail.Read'].id | [0]", "-o", "tsv"]
SIGNED_IN = ["az", "ad", "signed-in-user", "show", "--query", "id", "-o", "tsv"]

BODY_B = ('{"clientId":"%s","consentType":"AllPrincipals","resourceId":"%s","scope":"%s"}'
          % (CLIENT_SP, GRAPH_SP, SCOPES))
POST_B = ["az", "rest", "--method", "post", "--uri",
          "https://graph.microsoft.com/v1.0/oauth2PermissionGrants",
          "--headers", "Content-Type=application/json", "--body", BODY_B, "--query", "id", "-o", "tsv"]
BODY_E = ('{"clientId":"%s","consentType":"Principal","resourceId":"%s","principalId":"%s","scope":"%s"}'
          % (CLIENT_SP, GRAPH_SP, USER_OID, SCOPES))
POST_E = ["az", "rest", "--method", "post", "--uri",
          "https://graph.microsoft.com/v1.0/oauth2PermissionGrants",
          "--headers", "Content-Type=application/json", "--body", BODY_E, "--query", "id", "-o", "tsv"]
UNDO_GRANT = ["az", "rest", "--method", "delete", "--uri",
              "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/%s" % GRANT]

BODY_C = ('{"principalId":"%s","resourceId":"%s","appRoleId":"%s"}'
          % (CLIENT_SP, GRAPH_SP, APPROLE_ID))
POST_C = ["az", "rest", "--method", "post", "--uri",
          "https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoleAssignedTo" % GRAPH_SP,
          "--headers", "Content-Type=application/json", "--body", BODY_C, "--query", "id", "-o", "tsv"]
UNDO_ASSIGN = ["az", "rest", "--method", "delete", "--uri",
               "https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoleAssignedTo/%s"
               % (GRAPH_SP, ASSIGN)]
AZ_REST_GET = ["az", "rest", "--method", "get", "--uri",
               "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=clientId eq '%s'" % CLIENT_SP,
               "--query", "value[0].id", "-o", "tsv"]

# Stub outputs. The first matching regex wins, so the appRoles lookup is listed before the
# plain `ad sp show`. For --query '[id, appId]' -o tsv, the tsv format prints each value of
# the list on its own line (Microsoft Learn, "Set shell variables from Azure CLI output"),
# so the stub prints the object id and the appId on two lines.
APP_SP_OUT = [(r"ad app create", "%s\n%s" % (APP_OBJECT, APPID)), (r"ad sp create", CLIENT_SP)]
OUT_B = APP_SP_OUT + [(r"ad sp show", GRAPH_SP), (r"post .*oauth2PermissionGrants", GRANT)]
OUT_E = APP_SP_OUT + [(r"signed-in-user", USER_OID), (r"ad sp show", GRAPH_SP),
                      (r"post .*oauth2PermissionGrants", GRANT)]
OUT_C = APP_SP_OUT + [(r"ad sp show .*appRoles", APPROLE_ID), (r"ad sp show", GRAPH_SP),
                      (r"appRoleAssignedTo", ASSIGN)]

# The device code is the secret that the token request redeems. It must be in no command
# line and in no output.
DEVICE_CODE = "DEVCODE-SENTINEL-must+stay/secret"
DEVICECODE_JSON = ('{"user_code":"ABCD-EFGH","device_code":"' + DEVICE_CODE + '","verification_uri":'
                   '"https://microsoft.com/devicelogin","interval":5,"expires_in":900,'
                   '"message":"To sign in use microsoft.com/devicelogin and enter ABCD-EFGH"}')
TOKEN_SECRET = "SECRET-ACCESS-TOKEN-VALUE"
TOKEN_OK = '{"token_type":"Bearer","access_token":"%s"}' % TOKEN_SECRET
TOKEN_PENDING = '{"error":"authorization_pending","error_description":"waiting"}'
TOKEN_BLOCKED = ('{"error":"invalid_grant","error_description":"AADSTS50199 the device code '
                 'flow is blocked by a Conditional Access policy"}')
TOKEN_DECLINED = ('{"error":"authorization_declined","error_description":"The user denied the request."}')
DC_OK = [(r"oauth2/v2.0/devicecode", DEVICECODE_JSON), (r"oauth2/v2.0/token", TOKEN_OK)]
DC_BLOCKED = [(r"oauth2/v2.0/devicecode", DEVICECODE_JSON), (r"oauth2/v2.0/token", TOKEN_BLOCKED)]
DC_DECLINED = [(r"oauth2/v2.0/devicecode", DEVICECODE_JSON), (r"oauth2/v2.0/token", TOKEN_DECLINED)]
DC_PENDING = [(r"oauth2/v2.0/devicecode", DEVICECODE_JSON), (r"oauth2/v2.0/token", TOKEN_PENDING)]


class Dry(unittest.TestCase):

    def test_each_procedure_letter_exits_0_and_makes_no_call(self):
        for proc in ("a", "b", "c", "d", "e"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc)
                self.assertEqual(run.returncode, 0, run.text)
                self.assertEqual(run.calls, [], run.text)

    def test_an_invalid_letter_prints_usage_and_exits_1(self):
        run = livetest.run_script(SCRIPT, "q")
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("usage: emulate_entra_consent.sh {a|b|c|d|e}", run.stdout)
        self.assertEqual(run.calls, [])

    def test_show_fixture_prints_the_audit_fixture_and_makes_no_call(self):
        run = livetest.run_script(SCRIPT, "--show-fixture")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [])
        with open(os.path.join(livetest.REPO,
                  "detections/cloud/fixtures/trr9017/attack.json"), encoding="utf-8") as fh:
            self.assertEqual(run.stdout, fh.read())

    def test_show_fixture_signin_prints_the_signin_fixture(self):
        run = livetest.run_script(SCRIPT, "d", "--show-fixture", "signin")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [])
        with open(os.path.join(livetest.REPO,
                  "detections/cloud/fixtures/trr9017/attack_signin.json"), encoding="utf-8") as fh:
            self.assertEqual(run.stdout, fh.read())


class LiveTenantGate(unittest.TestCase):

    def test_tenant_not_set_stops_before_any_change_with_exit_2(self):
        for proc in ("a", "b", "c", "d", "e"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env={"TRR9017_LIVE": "1"},
                                          outputs=OUT_B + DC_OK)
                self.assertEqual(run.returncode, 2, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("TRR9017_TENANT", run.stderr)

    def test_an_app_name_without_the_prefix_stops_before_any_change_with_exit_2(self):
        # az uses an application with the same display name again, and the undo then deletes
        # it. A name that does not start with trr9017- can be an application of the person.
        for proc in ("a", "b", "c", "e"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env=dict(LIVE, TRR9017_APP_NAME="my-real-app"),
                                          outputs=OUT_B)
                self.assertEqual(run.returncode, 2, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("TRR9017_APP_NAME must start with trr9017- (it is 'my-real-app')", run.stderr)
                self.assertNotIn("[live] done", run.stdout)
        # The name must START with trr9017- : the prefix in the middle, the prefix with no
        # hyphen, capital letters and a blank before it are not that.
        for name in ("my-trr9017-app", "trr9017", "trr9017x-app", "TRR9017-app", " trr9017-app"):
            with self.subTest(name=name):
                run = livetest.run_script(SCRIPT, "b", env=dict(LIVE, TRR9017_APP_NAME=name), outputs=OUT_B)
                self.assertEqual(run.returncode, 2, run.text)
                self.assertEqual(run.calls, [], run.text)
        # --live as the second argument starts a live run too: the same stop.
        run = livetest.run_script(SCRIPT, "b", "--live",
                                  env={"TRR9017_TENANT": TENANT, "TRR9017_APP_NAME": "my-real-app"},
                                  outputs=OUT_B)
        self.assertEqual(run.returncode, 2, run.text)
        self.assertEqual(run.calls, [], run.text)

    def test_an_app_name_with_the_prefix_is_used_for_the_application(self):
        run = livetest.run_script(SCRIPT, "b", env=dict(LIVE, TRR9017_APP_NAME="trr9017-other"),
                                  outputs=OUT_B)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls[0][:6], ["az", "ad", "app", "create", "--display-name", "trr9017-other"],
                         run.text)

    def test_d_makes_no_application_so_it_does_not_read_the_app_name(self):
        run = livetest.run_script(SCRIPT, "d",
                                  env=dict(LIVE, TRR9017_DEVICECODE_POLL="1", TRR9017_APP_NAME="my-real-app"),
                                  outputs=DC_OK)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertIn("SUCCEEDED", run.stdout)


class LiveToolGate(unittest.TestCase):
    """The CLI of the procedure is not installed: no record can be caused, so the run
    makes no call and is not a success."""

    def test_without_az_a_live_run_of_a_b_c_e_makes_no_call_and_exits_1(self):
        stubs = tuple(name for name in livetest.STUBS if name != "az")
        for proc in ("a", "b", "c", "e"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env=LIVE, outputs=OUT_B, stubs=stubs)
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("az CLI not found", run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_without_curl_a_live_run_of_d_makes_no_call_and_exits_1(self):
        stubs = tuple(name for name in livetest.STUBS if name != "curl")
        run = livetest.run_script(SCRIPT, "d", env=dict(LIVE, TRR9017_DEVICECODE_POLL="1"),
                                  outputs=DC_OK, stubs=stubs)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertEqual(run.calls, [], run.text)
        self.assertIn("curl not found", run.stderr)
        self.assertNotIn("SUCCEEDED", run.stdout)


class LiveHappyPath(unittest.TestCase):

    def test_b_tenant_wide_grant_runs_the_exact_sequence_then_reverts(self):
        run = livetest.run_script(SCRIPT, "b", env=LIVE, outputs=OUT_B)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [CREATE_APP, CREATE_SP, SHOW_GRAPH, POST_B,
                                     UNDO_GRANT, DEL_SP, DEL_APP], run.text)

    def test_b_grant_body_is_tenant_wide_and_carries_the_high_privilege_scope(self):
        run = livetest.run_script(SCRIPT, "b", env=LIVE, outputs=OUT_B)
        post = next(c for c in run.calls if c[:4] == ["az", "rest", "--method", "post"])
        body = post[post.index("--body") + 1]
        self.assertIn('"consentType":"AllPrincipals"', body)
        self.assertIn("Mail.ReadWrite", body)

    def test_c_app_role_assignment_runs_the_exact_sequence_then_reverts(self):
        run = livetest.run_script(SCRIPT, "c", env=LIVE, outputs=OUT_C)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [CREATE_APP, CREATE_SP, SHOW_GRAPH, SHOW_APPROLE, POST_C,
                                     UNDO_ASSIGN, DEL_SP, DEL_APP], run.text)

    def test_c_posts_to_app_role_assigned_to_with_the_resolved_role(self):
        run = livetest.run_script(SCRIPT, "c", env=LIVE, outputs=OUT_C)
        post = next(c for c in run.calls if c[:4] == ["az", "rest", "--method", "post"])
        uri = post[post.index("--uri") + 1]
        self.assertTrue(uri.endswith("/appRoleAssignedTo"), uri)
        body = post[post.index("--body") + 1]
        self.assertIn('"appRoleId":"%s"' % APPROLE_ID, body)

    def test_e_single_user_grant_runs_the_exact_sequence_then_reverts(self):
        run = livetest.run_script(SCRIPT, "e", env=LIVE, outputs=OUT_E)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [CREATE_APP, CREATE_SP, SHOW_GRAPH, SIGNED_IN, POST_E,
                                     UNDO_GRANT, DEL_SP, DEL_APP], run.text)

    def test_e_grant_body_is_principal_and_names_the_signed_in_user(self):
        run = livetest.run_script(SCRIPT, "e", env=LIVE, outputs=OUT_E)
        post = next(c for c in run.calls if c[:4] == ["az", "rest", "--method", "post"])
        body = post[post.index("--body") + 1]
        self.assertIn('"consentType":"Principal"', body)
        self.assertIn('"principalId":"%s"' % USER_OID, body)

    def test_a_without_a_person_reverts_claims_no_record_and_exits_1(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE, outputs=APP_SP_OUT)
        # stdin is not a terminal under the harness: the end-user consent branch cannot
        # run, so the script knows no record was caused. It must remove the objects it made
        # and exit 1 (it does not know the record was caused: that is not a success).
        self.assertEqual(run.returncode, 1, run.text)
        self.assertEqual(run.calls, [CREATE_APP, CREATE_SP, DEL_SP, DEL_APP], run.text)
        self.assertIn("no 'Consent to application'", run.stdout + run.stderr)
        self.assertNotIn("[live] done", run.stdout)
        self.assertIn("login.microsoftonline.com/%s/oauth2/v2.0/authorize" % TENANT, run.stdout)

    def test_a_uses_the_object_id_for_the_app_delete_and_the_appid_for_the_sp(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE, outputs=APP_SP_OUT)
        self.assertIn(CREATE_SP, run.calls, run.text)         # az ad sp create --id <appId>
        self.assertIn(DEL_APP, run.calls, run.text)           # az ad app delete --id <objectId>
        self.assertNotIn(["az", "ad", "app", "delete", "--id", APPID], run.calls, run.text)
        # The consent URL carries the appId, not the object id.
        self.assertIn("client_id=%s" % APPID, run.stdout)

    def test_the_two_ids_of_the_app_are_read_from_two_lines_or_from_one_line(self):
        # The tsv format prints a list of two values on two lines. A tab between them (one
        # line) is accepted too. In each form the object id goes to the delete and the
        # appId goes to `az ad sp create`.
        for form, sep in (("two lines", "\n"), ("one line, a tab", "\t")):
            with self.subTest(form=form):
                out = [(r"ad app create", APP_OBJECT + sep + APPID)] + OUT_B[1:]
                run = livetest.run_script(SCRIPT, "b", env=LIVE, outputs=out)
                self.assertEqual(run.returncode, 0, run.text)
                self.assertEqual(run.calls, [CREATE_APP, CREATE_SP, SHOW_GRAPH, POST_B,
                                             UNDO_GRANT, DEL_SP, DEL_APP], run.text)

    def test_a_tells_the_person_which_user_can_accept_the_default_scopes(self):
        # On a new tenant, a user who is not an administrator cannot accept Mail.ReadWrite
        # and Files.ReadWrite.All. The script must not tell the person to sign in as such a
        # user with the default scopes; it gives the two ways that work.
        run = livetest.run_script(SCRIPT, "a", env=LIVE, outputs=APP_SP_OUT)
        self.assertNotIn("NON-admin", run.stdout)
        self.assertIn("sign in as an administrator", run.stdout)
        self.assertIn("TRR9017_SCOPES='offline_access Mail.Send'", run.stdout)

    def test_the_grant_or_assignment_is_always_removed(self):
        for proc, out, undo in (("b", OUT_B, UNDO_GRANT), ("e", OUT_E, UNDO_GRANT),
                                ("c", OUT_C, UNDO_ASSIGN)):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env=LIVE, outputs=out)
                self.assertIn(undo, run.calls, run.text)
                self.assertIn(DEL_SP, run.calls, run.text)
                self.assertIn(DEL_APP, run.calls, run.text)


class LiveDeviceCode(unittest.TestCase):

    def test_poll_success_requests_a_code_then_a_token_and_never_prints_the_token(self):
        run = livetest.run_script(SCRIPT, "d", env=dict(LIVE, TRR9017_DEVICECODE_POLL="1"),
                                  outputs=DC_OK)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual([c[4] for c in run.calls],
                         ["https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode" % TENANT,
                          "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % TENANT], run.text)
        self.assertIn("SUCCEEDED", run.stdout)
        self.assertNotIn(TOKEN_SECRET, run.stdout)
        self.assertNotIn(TOKEN_SECRET, run.stderr)

    def test_the_device_code_goes_to_curl_on_its_standard_input_only(self):
        # Each way that the poll can end. The device code must be in no command line and in
        # no output; each token request gets it on the standard input, with no newline.
        ends = {"success": (DC_OK, 0), "refusal": (DC_BLOCKED, 1), "declined": (DC_DECLINED, 1),
                "time-out": (DC_PENDING, 1),
                "no usable answer": ([DC_OK[0], (r"oauth2/v2.0/token", "{}")], 1)}
        for end, (outputs, code) in ends.items():
            with self.subTest(end=end):
                run = livetest.run_script(SCRIPT, "d", env=dict(LIVE, TRR9017_DEVICECODE_POLL="1"),
                                          outputs=outputs, timeout=60)
                self.assertEqual(run.returncode, code, run.text)
                for call in run.calls:
                    for arg in call:
                        self.assertNotIn(DEVICE_CODE, arg, " ".join(call))
                self.assertNotIn(DEVICE_CODE, run.stdout)
                self.assertNotIn(DEVICE_CODE, run.stderr)
                polls = [(call, stdin) for call, stdin in zip(run.calls, run.stdins)
                         if call[0] == "curl" and call[4].endswith("/token")]
                self.assertTrue(polls, run.text)
                for call, stdin in polls:
                    self.assertEqual(stdin, DEVICE_CODE, run.text)
                    self.assertEqual(call[-2:], ["--data-urlencode", "device_code@-"], run.text)

    def test_the_device_code_is_not_printed_when_no_person_is_there(self):
        run = livetest.run_script(SCRIPT, "d", env=LIVE, outputs=DC_OK)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertNotIn(DEVICE_CODE, run.stdout + run.stderr, run.text)
        self.assertIn("ABCD-EFGH", run.stdout)       # the user code is for the person

    def test_does_not_run_az_login_so_the_shell_session_is_not_changed(self):
        run = livetest.run_script(SCRIPT, "d", env=dict(LIVE, TRR9017_DEVICECODE_POLL="1"),
                                  outputs=DC_OK)
        for call in run.calls:
            self.assertNotEqual(call[0], "az", "procedure d must not call az: " + " ".join(call))
            self.assertNotIn("--use-device-code", call, " ".join(call))

    def test_a_blocked_tenant_reverts_nothing_names_the_date_and_exits_1(self):
        # The flow is refused. The rule reads only a successful sign-in, so the script must
        # not say the record was caused, and exits 1 (a FAILED sign-in record, which the
        # refusal can leave, is not what the rule reads).
        run = livetest.run_script(SCRIPT, "d", env=dict(LIVE, TRR9017_DEVICECODE_POLL="1"),
                                  outputs=DC_BLOCKED)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("did NOT succeed", run.stdout)
        self.assertIn("No successful device-code sign-in was recorded", run.stdout)
        self.assertNotIn("NO record was caused", run.stdout)
        self.assertIn("2026-07-01", run.stdout)
        self.assertIn("security defaults", run.stdout)
        self.assertNotIn(TOKEN_SECRET, run.stdout)

    def test_a_declined_code_does_not_name_the_date_and_exits_1(self):
        # A declined or expired code is a different cause: report that no successful sign-in
        # was recorded, exit 1, but do NOT attribute it to the 2026-07-01 security-defaults
        # block.
        run = livetest.run_script(SCRIPT, "d", env=dict(LIVE, TRR9017_DEVICECODE_POLL="1"),
                                  outputs=DC_DECLINED)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("did NOT succeed", run.stdout)
        self.assertIn("No successful device-code sign-in was recorded", run.stdout)
        self.assertNotIn("2026-07-01", run.stdout)
        self.assertNotIn("security defaults", run.stdout)

    def test_without_a_person_it_requests_a_code_but_does_not_poll_and_exits_1(self):
        run = livetest.run_script(SCRIPT, "d", env=LIVE, outputs=DC_OK)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertEqual([c[4].rsplit("/", 1)[-1] for c in run.calls], ["devicecode"], run.text)
        self.assertIn("No person is here", run.stdout + run.stderr)
        self.assertNotIn("[live] done", run.stdout)

    def test_polling_is_bounded_when_the_sign_in_never_completes(self):
        run = livetest.run_script(SCRIPT, "d", env=dict(LIVE, TRR9017_DEVICECODE_POLL="1"),
                                  outputs=DC_PENDING, timeout=60)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("gave up", run.stderr)
        self.assertIn("No successful device-code sign-in was recorded", run.stderr)
        self.assertNotIn("NO record was caused", run.stdout + run.stderr)
        self.assertNotIn("[live] done", run.stdout)
        token_calls = [c for c in run.calls if c[0] == "curl" and c[4].endswith("/token")]
        self.assertEqual(len(token_calls), 60, run.text)

    def test_a_success_on_the_last_poll_does_not_also_print_gave_up(self):
        # The 60th poll succeeds. The loop ends at the limit, but the "gave up" message must
        # not print, and the run must exit 0.
        pending59_then_ok = [(r"oauth2/v2.0/devicecode", DEVICECODE_JSON),
                             (r"oauth2/v2.0/token", [TOKEN_PENDING] * 59 + [TOKEN_OK])]
        run = livetest.run_script(SCRIPT, "d", env=dict(LIVE, TRR9017_DEVICECODE_POLL="1"),
                                  outputs=pending59_then_ok, timeout=60)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertIn("SUCCEEDED", run.stdout)
        self.assertNotIn("gave up", run.stdout + run.stderr)
        token_calls = [c for c in run.calls if c[0] == "curl" and c[4].endswith("/token")]
        self.assertEqual(len(token_calls), 60, run.text)

    def test_a_refusal_on_the_last_poll_does_not_also_print_gave_up(self):
        # The 60th poll ends with a refusal. The run reports the refusal and exits 1; it
        # must not also say that it gave up waiting.
        pending59_then_declined = [(r"oauth2/v2.0/devicecode", DEVICECODE_JSON),
                                   (r"oauth2/v2.0/token", [TOKEN_PENDING] * 59 + [TOKEN_DECLINED])]
        run = livetest.run_script(SCRIPT, "d", env=dict(LIVE, TRR9017_DEVICECODE_POLL="1"),
                                  outputs=pending59_then_declined, timeout=60)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("did NOT succeed (error: authorization_declined)", run.stdout)
        self.assertNotIn("gave up", run.stdout + run.stderr)
        token_calls = [c for c in run.calls if c[0] == "curl" and c[4].endswith("/token")]
        self.assertEqual(len(token_calls), 60, run.text)


class LiveKnownNoRecord(unittest.TestCase):
    """Each end at which the script knows that it caused no record: exit 1, never exit 0,
    and no `[live] done.` line. What the script made before that end is reverted."""

    POLL = dict(LIVE, TRR9017_DEVICECODE_POLL="1")

    def assert_no_record(self, run):
        self.assertEqual(run.returncode, 1, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        self.assertNotIn("SUCCEEDED", run.stdout, run.text)

    def assert_no_device_code(self, run):
        self.assertNotIn(DEVICE_CODE, run.stdout + run.stderr, run.text)
        for call in run.calls:
            for arg in call:
                self.assertNotIn(DEVICE_CODE, arg, " ".join(call))

    def test_d_a_device_code_answer_with_no_user_code_does_not_print_the_device_code(self):
        answer = '{"device_code":"%s","interval":5}' % DEVICE_CODE
        run = livetest.run_script(SCRIPT, "d", env=self.POLL,
                                  outputs=[(r"oauth2/v2.0/devicecode", answer)])
        self.assert_no_record(run)
        self.assert_no_device_code(run)
        self.assertEqual(len(run.calls), 1, run.text)

    def test_c_an_app_role_that_graph_does_not_have_reverts_sp_and_app_and_exits_1(self):
        # The appRoles query gives nothing: there is no role to assign, so no POST.
        out = APP_SP_OUT + [(r"ad sp show .*appRoles", ""), (r"ad sp show", GRAPH_SP)]
        run = livetest.run_script(SCRIPT, "c", env=LIVE, outputs=out)
        self.assert_no_record(run)
        self.assertEqual(run.calls, [CREATE_APP, CREATE_SP, SHOW_GRAPH, SHOW_APPROLE,
                                     DEL_SP, DEL_APP], run.text)
        self.assertIn("exposes no app role 'Mail.Read'", run.stderr)

    def test_d_a_device_code_answer_with_no_code_exits_1_after_one_request(self):
        answer = '{"error":"invalid_client","error_description":"AADSTS7000218"}'
        run = livetest.run_script(SCRIPT, "d", env=self.POLL,
                                  outputs=[(r"oauth2/v2.0/devicecode", answer)])
        self.assert_no_record(run)
        self.assertEqual(len(run.calls), 1, run.text)
        self.assertIn("returned no code (error: invalid_client)", run.stderr)
        self.assertIn("No sign-in was started", run.stderr)

    def test_d_a_device_code_request_that_fails_exits_1_after_one_request(self):
        # curl can fail after the answer came (exit 56): the answer holds the device code.
        for rule in ((r"oauth2/v2.0/devicecode", 7), (r"oauth2/v2.0/devicecode", 56, DEVICECODE_JSON)):
            with self.subTest(curl_exit=rule[1]):
                run = livetest.run_script(SCRIPT, "d", env=self.POLL, outputs=DC_OK, fail=[rule])
                self.assert_no_record(run)
                self.assertEqual(len(run.calls), 1, run.text)
                self.assertIn("could not reach the device-code endpoint", run.stderr)
                self.assert_no_device_code(run)

    def test_d_a_token_request_that_fails_exits_1(self):
        # curl can fail after the answer came (exit 56): the answer holds the tokens.
        for rule in ((r"oauth2/v2.0/token", 7), (r"oauth2/v2.0/token", 56, TOKEN_OK)):
            with self.subTest(curl_exit=rule[1]):
                run = livetest.run_script(SCRIPT, "d", env=self.POLL, outputs=DC_OK, fail=[rule])
                self.assert_no_record(run)
                self.assertEqual([c[4].rsplit("/", 1)[-1] for c in run.calls], ["devicecode", "token"],
                                 run.text)
                self.assertIn("could not reach the token endpoint", run.stderr)
                self.assertIn("No successful device-code sign-in was recorded", run.stderr)
                self.assert_no_device_code(run)
                self.assertNotIn(TOKEN_SECRET, run.stdout + run.stderr, run.text)

    def test_d_a_token_answer_with_no_token_and_no_error_exits_1(self):
        # The answer is not printed: with no access_token it can hold a different token.
        other = '{"token_type":"Bearer","id_token":"%s","refresh_token":"%s"}' % (TOKEN_SECRET, TOKEN_SECRET)
        for answer in ("{}", other):
            with self.subTest(answer=answer[:20]):
                run = livetest.run_script(SCRIPT, "d", env=self.POLL,
                                          outputs=[DC_OK[0], (r"oauth2/v2.0/token", answer)])
                self.assert_no_record(run)
                self.assertEqual([c[4].rsplit("/", 1)[-1] for c in run.calls], ["devicecode", "token"],
                                 run.text)
                self.assertIn("unexpected token response", run.stderr)
                self.assert_no_device_code(run)
                self.assertNotIn(TOKEN_SECRET, run.stdout + run.stderr, run.text)

    def test_an_app_create_answer_that_is_not_two_ids_stops_and_names_the_app(self):
        # `az ad app create` gave exit 0, so the application exists, but the script has no
        # object id for the delete. It must stop after that one call, exit 1, and give the
        # person two commands that work (the delete does not take a display name).
        answers = {"nothing": "", "one value": APP_OBJECT,
                   "three values": "%s\n%s\nmore" % (APP_OBJECT, APPID)}
        for proc in ("a", "b", "c", "e"):
            for what, text in answers.items():
                with self.subTest(proc=proc, answer=what):
                    out = [(r"ad app create", text)] + OUT_B[1:]
                    run = livetest.run_script(SCRIPT, proc, env=LIVE, outputs=out)
                    self.assert_no_record(run)
                    self.assertEqual(run.calls, [CREATE_APP], run.text)
                    self.assertIn("LEFT BEHIND: the application '%s'" % APP, run.stderr)
                    self.assertIn("az ad app list --display-name '%s' --query \"[].id\" -o tsv" % APP,
                                  run.stderr)
                    self.assertNotIn("az ad app delete --id %s" % APP, run.stderr)

    def test_a_create_that_gives_no_id_stops_names_the_change_and_sends_no_delete_with_no_id(self):
        # The command gave exit 0 and not one id, so the run cannot register the undo of
        # that change. It must stop (exit 1, no "done"), name the change as one that can
        # stay, revert the earlier changes, and send no delete request with such an id.
        role = [(r"ad sp show .*appRoles", APPROLE_ID), (r"ad sp show", GRAPH_SP)]
        cases = {
            "service principal": (
                "b", [APP_SP_OUT[0]], [CREATE_APP, CREATE_SP, DEL_APP],
                "the service principal of the application %s" % APP,
                "az ad sp create did not return one object id"),
            "grant, tenant-wide": (
                "b", APP_SP_OUT + [(r"ad sp show", GRAPH_SP)],
                [CREATE_APP, CREATE_SP, SHOW_GRAPH, POST_B, DEL_SP, DEL_APP],
                "the delegated permission grant to Microsoft Graph",
                "the POST to /oauth2PermissionGrants did not return one id"),
            "grant, one user": (
                "e", APP_SP_OUT + [(r"signed-in-user", USER_OID), (r"ad sp show", GRAPH_SP)],
                [CREATE_APP, CREATE_SP, SHOW_GRAPH, SIGNED_IN, POST_E, DEL_SP, DEL_APP],
                "the delegated permission grant to Microsoft Graph",
                "the POST to /oauth2PermissionGrants did not return one id"),
            "app role assignment": (
                "c", APP_SP_OUT + role,
                [CREATE_APP, CREATE_SP, SHOW_GRAPH, SHOW_APPROLE, POST_C, DEL_SP, DEL_APP],
                "the app role assignment of Mail.Read to the throwaway service principal",
                "the POST to /appRoleAssignedTo did not return one id"),
        }
        # The stub rule that gives the answer of the create command, for each case.
        create = {"service principal": r"ad sp create", "grant, tenant-wide": r"post .*oauth2PermissionGrants",
                  "grant, one user": r"post .*oauth2PermissionGrants",
                  "app role assignment": r"post .*appRoleAssignedTo"}
        # No answer, and answers that are not one word: only blanks, a tab in it, two
        # lines, a blank in it. None of them is an ID.
        answers = {"nothing": None, "blanks": "   ", "a tab": "id-one\tid-two",
                   "two lines": "id-one\nid-two", "a blank": "id one"}
        for what, (proc, out, calls, change, message) in cases.items():
            for kind, text in answers.items():
                with self.subTest(what=what, answer=kind):
                    rules = out if text is None else [(create[what], text)] + out
                    run = livetest.run_script(SCRIPT, proc, env=LIVE, outputs=rules)
                    self.assert_no_record(run)
                    self.assertEqual(run.calls, calls, run.text)
                    self.assertIn(message, run.stderr)
                    self.assertIn("The run stopped before the undo of this change was registered: %s"
                                  % change, run.stderr)
                    self.assertIn("That change has no undo", run.stderr)
                    self.assertNotIn("LEFT BEHIND, this command failed", run.stderr)


class LiveWithAPerson(unittest.TestCase):
    """Procedure a, with a terminal: the harness gives a pty on which Enter was pressed."""

    def test_a_with_a_person_who_consents_removes_the_grant_then_the_objects(self):
        out = APP_SP_OUT + [(r"rest --method get", GRANT)]
        run = livetest.run_script(SCRIPT, "a", env=LIVE, outputs=out, tty=True)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [CREATE_APP, CREATE_SP, AZ_REST_GET, UNDO_GRANT, DEL_SP, DEL_APP],
                         run.text)
        self.assertIn("[live] done.", run.stdout)

    def test_a_grant_answer_that_is_not_one_id_stops_and_sends_no_delete_with_it(self):
        for text in ("id-one\nid-two", "id one"):
            with self.subTest(answer=text):
                out = APP_SP_OUT + [(r"rest --method get", text)]
                run = livetest.run_script(SCRIPT, "a", env=LIVE, outputs=out, tty=True)
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, [CREATE_APP, CREATE_SP, AZ_REST_GET, DEL_SP, DEL_APP], run.text)
                self.assertIn("the read of the delegated grants did not return one id", run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_each_undo_command_that_fails_is_left_behind_and_fails_the_run(self):
        out = APP_SP_OUT + [(r"rest --method get", GRANT)]
        self.assertEqual(livetest.each_undo_failure(self, SCRIPT, "a", env=LIVE, outputs=out, tty=True), 3)

    def test_a_with_a_person_who_does_not_consent_reverts_and_exits_1(self):
        # The person pressed Enter but no grant exists: the consent was not caused.
        run = livetest.run_script(SCRIPT, "a", env=LIVE, outputs=APP_SP_OUT, tty=True)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertEqual(run.calls, [CREATE_APP, CREATE_SP, AZ_REST_GET, DEL_SP, DEL_APP], run.text)
        self.assertNotIn("[live] done", run.stdout)
        self.assertIn("no 'Consent to application'", run.stdout + run.stderr)


class LiveStopSignal(unittest.TestCase):
    """A stop signal that comes while a change-making az command runs."""

    SIGNALS = (("HUP", 129), ("INT", 130), ("TERM", 143))

    def test_b_a_signal_to_the_script_during_a_change_reverts_that_change_too(self):
        changes = {
            r"ad app create": [CREATE_APP, DEL_APP],
            r"ad sp create": [CREATE_APP, CREATE_SP, DEL_SP, DEL_APP],
            r"post .*oauth2PermissionGrants":
                [CREATE_APP, CREATE_SP, SHOW_GRAPH, POST_B, UNDO_GRANT, DEL_SP, DEL_APP],
        }
        for name, code in self.SIGNALS:
            for pattern, expected in changes.items():
                with self.subTest(signal=name, during=pattern):
                    run = livetest.run_script(SCRIPT, "b", env=LIVE, outputs=OUT_B,
                                              signals=[(pattern, name, "shell")])
                    self.assertEqual(run.returncode, code, run.text)
                    self.assertEqual(run.calls, expected, run.text)
                    self.assertNotIn("[live] done", run.stdout, run.text)
                    self.assertNotIn("has no undo", run.stderr, run.text)

    def test_b_a_signal_that_stops_the_create_names_the_change_that_can_stay(self):
        run = livetest.run_script(SCRIPT, "b", env=LIVE, outputs=OUT_B,
                                  signals=[(r"ad app create", "INT", "group")])
        self.assertEqual(run.returncode, 130, run.text)
        self.assertEqual(run.calls, [CREATE_APP], run.text)
        self.assertIn("The run stopped before the undo of this change was registered: "
                      "the throwaway application", run.stderr)
        self.assertIn("That change has no undo", run.stderr)


class LiveFailureReverts(unittest.TestCase):

    def test_b_a_failure_at_each_change_reverts_the_earlier_changes_last_first(self):
        cases = {
            r"ad app create": [],
            r"ad sp create": [DEL_APP],
            r"post .*oauth2PermissionGrants": [DEL_SP, DEL_APP],
        }
        for pattern, undos in cases.items():
            with self.subTest(fail=pattern):
                # The command that fails prints a text on stdout: it is not an ID.
                run = livetest.run_script(SCRIPT, "b", env=LIVE, outputs=OUT_B,
                                          fail=[(pattern, 7, "half-an-answer")])
                # The run ends with the exit code of the command that failed. A run that
                # hides the failure and stops later for a different reason does not.
                self.assertEqual(run.returncode, 7, run.text)
                self.assertNotIn("[live] done", run.stdout, run.text)
                tail = run.calls[-len(undos):] if undos else []
                self.assertEqual(tail, undos, run.text)
                # the grant that never got created is never deleted
                self.assertNotIn(UNDO_GRANT, run.calls, run.text)
                if pattern == r"ad app create":
                    self.assertNotIn(DEL_APP, run.calls, run.text)
                    self.assertNotIn(DEL_SP, run.calls, run.text)

    def test_c_a_failure_at_the_assignment_reverts_sp_and_app_and_leaves_no_assignment(self):
        # The pattern matches the POST only: the undo of the assignment (a DELETE) must not fail.
        run = livetest.run_script(SCRIPT, "c", env=LIVE, outputs=OUT_C,
                                  fail=[(r"post .*appRoleAssignedTo", 7, "half-an-answer")])
        self.assertEqual(run.returncode, 7, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        self.assertEqual(run.calls[-3:], [POST_C, DEL_SP, DEL_APP], run.text)
        self.assertNotIn(UNDO_ASSIGN, run.calls, run.text)

    def test_e_a_failure_at_the_grant_reverts_sp_and_app_and_leaves_no_grant(self):
        run = livetest.run_script(SCRIPT, "e", env=LIVE, outputs=OUT_E,
                                  fail=[(r"post .*oauth2PermissionGrants", 7, "half-an-answer")])
        self.assertEqual(run.returncode, 7, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        self.assertEqual(run.calls[-2:], [DEL_SP, DEL_APP], run.text)
        self.assertNotIn(UNDO_GRANT, run.calls, run.text)

    def test_a_failure_creating_the_sp_reverts_only_the_app(self):
        run = livetest.run_script(SCRIPT, "b", env=LIVE, outputs=OUT_B,
                                  fail=[(r"ad sp create", 7, "half-an-answer")])
        self.assertEqual(run.returncode, 7, run.text)
        self.assertEqual(run.calls, [CREATE_APP, CREATE_SP, DEL_APP], run.text)

    def test_an_undo_failure_at_the_planned_end_does_not_print_done(self):
        # The grant-delete undo fails: the run must not print "done", must still run the sp/app
        # deletes, and must exit != 0 with a LEFT BEHIND note.
        run = livetest.run_script(SCRIPT, "b", env=LIVE, outputs=OUT_B,
                                  fail=[(r"delete .*oauth2PermissionGrants", 5)])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        self.assertIn("LEFT BEHIND", run.stderr, run.text)
        self.assertIn(DEL_SP, run.calls, run.text)
        self.assertIn(DEL_APP, run.calls, run.text)

    def test_each_undo_command_that_fails_is_left_behind_and_fails_the_run(self):
        # The grant or the assignment, the service principal, the application.
        for proc, out in (("b", OUT_B), ("c", OUT_C), ("e", OUT_E)):
            with self.subTest(proc=proc):
                self.assertEqual(livetest.each_undo_failure(self, SCRIPT, proc, env=LIVE, outputs=out), 3)


if __name__ == "__main__":
    unittest.main()
