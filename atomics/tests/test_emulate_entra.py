"""Offline tests of atomics/T1098.001/src/emulate_entra.sh (TRR9013).

The script makes no cloud call in dry mode and, in LIVE mode, drives the stub `az` of
livetest. These tests prove the dry contract, the LIVE call sequences for Procedure A
(app FIC) and Procedure C (managed-identity FIC), the undo of a failed run, and the
correction from the "Problems in the live scripts" table:

  * the FIC subject is an exact value, never a wildcard `*` (Microsoft does not support a
    wildcard in any federated-credential property); and
  * the live run registers an undo command for each change it makes, and runs each one
    when a command fails, so a failure before the planned end does not skip the removal
    of the app / managed identity / resource group. (An undo command can itself fail, and
    a change whose command was stopped in the middle can stay: the run says so.)

This script creates its own throwaway objects, so a live run needs no account-naming
variable (the az CLI carries the signed-in tenant); there is no exit-2 path to test.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import livetest     # noqa: E402

SCRIPT = "atomics/T1098.001/src/emulate_entra.sh"
ISSUER = "https://oidc.trr9013-attacker.example.com"
SUBJECT = "repo:trr9013-attacker/emulation:ref:refs/heads/main"
APP_ID = "aaaa1111-bbbb-2222-cccc-333344445555"
APP_OUT = [("ad app create", APP_ID)]

CREATE_APP = ["az", "ad", "app", "create", "--display-name", "trr9013-victim-app",
              "--query", "id", "-o", "tsv"]
PARAMS = ('{"name":"trr9013-backdoor","issuer":"%s","subject":"%s",'
          '"audiences":["api://AzureADTokenExchange"]}' % (ISSUER, SUBJECT))
CREATE_FIC = ["az", "ad", "app", "federated-credential", "create", "--id", APP_ID,
              "--parameters", PARAMS]
UNDO_FIC = ["az", "ad", "app", "federated-credential", "delete", "--id", APP_ID,
            "--federated-credential-id", "trr9013-backdoor"]
UNDO_APP = ["az", "ad", "app", "delete", "--id", APP_ID]

LIVE_A = {"TRR9013_LIVE": "1"}


class Dry(unittest.TestCase):

    def test_each_procedure_letter_exits_0_and_makes_no_call(self):
        for proc in ("a", "c"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc)
                self.assertEqual(run.returncode, 0, run.text)
                self.assertEqual(run.calls, [], run.text)

    def test_an_invalid_letter_prints_usage_and_exits_1(self):
        run = livetest.run_script(SCRIPT, "q")
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("usage: emulate_entra.sh {a|c}", run.stdout)
        self.assertEqual(run.calls, [])

    def test_the_dry_text_shows_an_exact_subject_not_a_wildcard(self):
        for proc in ("a", "c"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc)
                self.assertIn(SUBJECT, run.stdout)
                self.assertNotIn("trr9013-attacker/*", run.stdout)

    def test_show_fixture_prints_both_committed_fixtures_and_makes_no_call(self):
        run = livetest.run_script(SCRIPT, "--show-fixture")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [])
        for name in ("attack.json", "attack_mi.json"):
            with open(os.path.join(livetest.REPO,
                      "detections/cloud/fixtures/trr9013", name), encoding="utf-8") as fh:
                self.assertIn(fh.read(), run.stdout)


class LiveToolGate(unittest.TestCase):

    def test_without_az_a_live_run_makes_no_call_and_exits_1(self):
        # az is not installed: no record can be caused, so the run is not a success.
        stubs = tuple(name for name in livetest.STUBS if name != "az")
        for proc in ("a", "c"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env=LIVE_A, outputs=APP_OUT, stubs=stubs)
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("az CLI not found", run.stderr)
                self.assertNotIn("[live] done", run.stdout)


class LiveAppFic(unittest.TestCase):

    def test_happy_path_runs_the_exact_sequence_then_reverts(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_A, outputs=APP_OUT)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [CREATE_APP, CREATE_FIC, UNDO_FIC, UNDO_APP], run.text)

    def test_the_fic_subject_is_exact_and_holds_no_wildcard(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_A, outputs=APP_OUT)
        create = next(c for c in run.calls if c[:5] ==
                      ["az", "ad", "app", "federated-credential", "create"])
        params = create[-1]
        self.assertIn('"subject":"%s"' % SUBJECT, params)
        self.assertNotIn("*", params)

    def test_the_app_and_its_fic_are_always_removed(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_A, outputs=APP_OUT)
        self.assertIn(UNDO_FIC, run.calls, run.text)
        self.assertIn(UNDO_APP, run.calls, run.text)

    def test_a_failure_at_each_change_reverts_the_earlier_changes_last_first(self):
        # Exact call list for each failure point: the undo of the command that FAILED never
        # runs, and every change made before it is reverted.
        cases = {
            r"ad app create": [CREATE_APP],
            r"federated-credential create": [CREATE_APP, CREATE_FIC, UNDO_APP],
        }
        for pattern, expected in cases.items():
            with self.subTest(fail=pattern):
                run = livetest.run_script(SCRIPT, "a", env=LIVE_A, outputs=APP_OUT,
                                          fail=[(pattern, 7)])
                self.assertEqual(run.returncode, 7, run.text)
                self.assertEqual(run.calls, expected, run.text)
                self.assertNotIn("[live] done", run.stdout, run.text)
                self.assertNotIn(UNDO_FIC, run.calls, run.text)

    def test_the_planned_end_reverts_every_change_before_it_prints_done(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_A, outputs=APP_OUT)
        self.assertEqual(run.returncode, 0, run.text)
        lines = [ln for ln in run.stdout.split("\n") if ln]
        self.assertEqual(lines[-1], "[live] done.", run.text)
        self.assertTrue(all(ln.startswith("[live] undo: ") for ln in lines[-3:-1]), run.text)

    def test_an_undo_failure_at_the_planned_end_does_not_print_done(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_A, outputs=APP_OUT,
                                  fail=[(r"federated-credential delete", 5)])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        self.assertIn("LEFT BEHIND", run.stderr, run.text)

    def test_each_undo_command_that_fails_is_left_behind_and_fails_the_run(self):
        self.assertEqual(livetest.each_undo_failure(self, SCRIPT, "a", env=LIVE_A, outputs=APP_OUT), 2)

    def test_app_create_with_no_object_id_stops_and_names_the_app(self):
        # az ad app create gave no object id: the app may exist, so the run stops, names it,
        # and makes no FIC. The guard prevents a FIC command with an empty --id.
        # An answer that is not one word (two lines, a blank or a tab in it) is not an ID either.
        for text in (None, "id-one\nid-two", "id one", "id-one\tid-two", "id-one\r", "../id-one"):
            with self.subTest(answer=text):
                out = [] if text is None else [("ad app create", text)]
                run = livetest.run_script(SCRIPT, "a", env=LIVE_A, outputs=out)
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual([c[:4] for c in run.calls], [["az", "ad", "app", "create"]], run.text)
                self.assertIn("did not return one object ID", run.stderr)
                self.assertIn("trr9013-victim-app", run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_live_as_second_argument_runs_the_flow(self):
        run = livetest.run_script(SCRIPT, "a", "--live", outputs=APP_OUT)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [CREATE_APP, CREATE_FIC, UNDO_FIC, UNDO_APP], run.text)

    def test_the_undo_block_sits_after_the_cli_check_inside_the_live_branch(self):
        with open(os.path.join(livetest.REPO, SCRIPT), encoding="utf-8") as fh:
            text = fh.read()
        self.assertLess(text.index('if [[ "${TRR9013_LIVE:-0}"'), text.index("command -v az"))
        self.assertLess(text.index("command -v az"), text.index(livetest.UNDO_START))


class LiveAppFicStopSignal(unittest.TestCase):
    """A stop signal that comes while a change-making az command runs (procedure A)."""

    def test_a_signal_to_the_script_during_a_change_reverts_that_change_too(self):
        changes = {
            r"ad app create": [CREATE_APP, UNDO_APP],
            r"federated-credential create": [CREATE_APP, CREATE_FIC, UNDO_FIC, UNDO_APP],
        }
        for name, code in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            for pattern, expected in changes.items():
                with self.subTest(signal=name, during=pattern):
                    run = livetest.run_script(SCRIPT, "a", env=LIVE_A, outputs=APP_OUT,
                                              signals=[(pattern, name, "shell")])
                    self.assertEqual(run.returncode, code, run.text)
                    self.assertEqual(run.calls, expected, run.text)
                    self.assertNotIn("[live] done", run.stdout, run.text)
                    self.assertNotIn("has no undo", run.stderr, run.text)

    def test_a_signal_that_stops_the_create_names_the_change_that_can_stay(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_A, outputs=APP_OUT,
                                  signals=[(r"ad app create", "INT", "group")])
        self.assertEqual(run.returncode, 130, run.text)
        self.assertEqual(run.calls, [CREATE_APP], run.text)
        self.assertIn("The run stopped before the undo of this change was registered: "
                      "the throwaway application trr9013-victim-app", run.stderr)


class LiveManagedIdentityFic(unittest.TestCase):

    def _run(self, **kw):
        return livetest.run_script(SCRIPT, "c", env={"TRR9013_LIVE": "1"}, **kw)

    def test_happy_path_creates_rg_mi_fic_then_reverts_last_first(self):
        run = self._run()
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(len(run.calls), 6, run.text)
        gcreate, icreate, fcreate, fdel, idel, gdel = run.calls

        self.assertEqual(gcreate[:4], ["az", "group", "create", "--name"])
        rg = gcreate[4]
        self.assertRegex(rg, r"^trr9013-rg-\d{14}$")
        self.assertIn("--location", gcreate)
        self.assertEqual(gcreate[gcreate.index("--location") + 1], "eastus")

        self.assertEqual(icreate[:4], ["az", "identity", "create", "--name"])
        mi = icreate[4]
        self.assertRegex(mi, r"^trr9013-mi-\d{14}$")
        self.assertEqual(icreate[5:], ["--resource-group", rg])
        self.assertEqual(rg.split("-")[-1], mi.split("-")[-1])   # same run stamp

        self.assertEqual(fcreate, ["az", "identity", "federated-credential", "create",
                                   "--name", "trr9013-mi-backdoor", "--identity-name", mi,
                                   "--resource-group", rg, "--issuer", ISSUER,
                                   "--subject", SUBJECT, "--audiences", "api://AzureADTokenExchange"])
        # Teardown, last change first: FIC, then identity, then resource group.
        self.assertEqual(fdel, ["az", "identity", "federated-credential", "delete",
                                "--name", "trr9013-mi-backdoor", "--identity-name", mi,
                                "--resource-group", rg, "--yes"])
        self.assertEqual(idel, ["az", "identity", "delete", "--name", mi, "--resource-group", rg])
        self.assertEqual(gdel, ["az", "group", "delete", "--name", rg, "--yes"])

    def test_the_fic_subject_is_exact_and_holds_no_wildcard(self):
        run = self._run()
        fcreate = next(c for c in run.calls if c[:4] ==
                       ["az", "identity", "federated-credential", "create"])
        self.assertIn("--subject", fcreate)
        self.assertEqual(fcreate[fcreate.index("--subject") + 1], SUBJECT)
        self.assertNotIn("*", " ".join(fcreate))

    def test_the_location_is_configurable(self):
        run = livetest.run_script(SCRIPT, "c",
                                  env={"TRR9013_LIVE": "1", "TRR9013_LOCATION": "westeurope"})
        self.assertEqual(run.returncode, 0, run.text)
        gcreate = run.calls[0]
        self.assertEqual(gcreate[:3], ["az", "group", "create"])
        self.assertEqual(gcreate[gcreate.index("--location") + 1], "westeurope")

    def test_the_planned_end_reverts_every_change_before_it_prints_done(self):
        run = self._run()
        self.assertEqual(run.returncode, 0, run.text)
        lines = [ln for ln in run.stdout.split("\n") if ln]
        self.assertEqual(lines[-1], "[live] done.", run.text)
        self.assertTrue(all(ln.startswith("[live] undo: ") for ln in lines[-4:-1]), run.text)

    def test_an_undo_failure_at_the_planned_end_does_not_print_done(self):
        run = self._run(fail=[(r"identity federated-credential delete", 5)])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        self.assertIn("LEFT BEHIND", run.stderr, run.text)

    def test_each_undo_command_that_fails_is_left_behind_and_fails_the_run(self):
        self.assertEqual(livetest.each_undo_failure(self, SCRIPT, "c", env={"TRR9013_LIVE": "1"}), 3)

    def test_a_failure_at_each_change_reverts_the_earlier_changes_last_first(self):
        # names carry a timestamp, so match the full sequence of command shapes. The undo of
        # the command that FAILED never runs, and every earlier change is reverted last-first.
        def shapes(calls):
            return [tuple(c[:4]) for c in calls]
        GCREATE = ("az", "group", "create", "--name")
        ICREATE = ("az", "identity", "create", "--name")
        FCREATE = ("az", "identity", "federated-credential", "create")
        GDEL = ("az", "group", "delete", "--name")
        IDEL = ("az", "identity", "delete", "--name")
        cases = {
            r"group create": [GCREATE],
            r"identity create": [GCREATE, ICREATE, GDEL],
            r"identity federated-credential create": [GCREATE, ICREATE, FCREATE, IDEL, GDEL],
        }
        for pattern, expected in cases.items():
            with self.subTest(fail=pattern):
                run = self._run(fail=[(pattern, 7)])
                self.assertEqual(run.returncode, 7, run.text)
                self.assertEqual(shapes(run.calls), expected, run.text)
                self.assertNotIn("[live] done", run.stdout, run.text)


class LiveManagedIdentityFicStopSignal(unittest.TestCase):
    """A stop signal that comes while a change-making az command runs (procedure C)."""

    GCREATE = ("az", "group", "create", "--name")
    ICREATE = ("az", "identity", "create", "--name")
    FCREATE = ("az", "identity", "federated-credential", "create")
    FDEL = ("az", "identity", "federated-credential", "delete")
    IDEL = ("az", "identity", "delete", "--name")
    GDEL = ("az", "group", "delete", "--name")

    @staticmethod
    def shapes(calls):
        return [tuple(c[:4]) for c in calls]

    def test_a_signal_to_the_script_during_a_change_reverts_that_change_too(self):
        # The command runs to its end, so the provider made the change. The run must
        # register the undo of that change before it stops.
        changes = {
            r"group create": [self.GCREATE, self.GDEL],
            r"identity create": [self.GCREATE, self.ICREATE, self.IDEL, self.GDEL],
            r"identity federated-credential create":
                [self.GCREATE, self.ICREATE, self.FCREATE, self.FDEL, self.IDEL, self.GDEL],
        }
        for name, code in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            for pattern, expected in changes.items():
                with self.subTest(signal=name, during=pattern):
                    run = livetest.run_script(SCRIPT, "c", env={"TRR9013_LIVE": "1"},
                                              signals=[(pattern, name, "shell")])
                    self.assertEqual(run.returncode, code, run.text)
                    self.assertEqual(self.shapes(run.calls), expected, run.text)
                    self.assertNotIn("[live] done", run.stdout, run.text)
                    self.assertNotIn("has no undo", run.stderr, run.text)

    def test_a_signal_that_stops_the_command_names_the_change_that_can_stay(self):
        cases = {
            r"group create": ([self.GCREATE], "the resource group trr9013-rg-"),
            r"identity create": ([self.GCREATE, self.ICREATE, self.GDEL], "the managed identity trr9013-mi-"),
            r"identity federated-credential create":
                ([self.GCREATE, self.ICREATE, self.FCREATE, self.IDEL, self.GDEL],
                 "the federated credential trr9013-mi-backdoor on the managed identity trr9013-mi-"),
        }
        for pattern, (expected, what) in cases.items():
            with self.subTest(during=pattern):
                run = livetest.run_script(SCRIPT, "c", env={"TRR9013_LIVE": "1"},
                                          signals=[(pattern, "INT", "group")])
                self.assertEqual(run.returncode, 130, run.text)
                self.assertEqual(self.shapes(run.calls), expected, run.text)
                self.assertIn("The run stopped before the undo of this change was registered: " + what,
                              run.stderr)
                self.assertIn("That change has no undo", run.stderr)
                self.assertNotIn("[live] done", run.stdout, run.text)

    def test_a_command_that_fails_names_the_change_that_can_stay(self):
        cases = {r"group create": "the resource group trr9013-rg-",
                 r"identity create": "the managed identity trr9013-mi-",
                 r"identity federated-credential create":
                     "the federated credential trr9013-mi-backdoor on the managed identity trr9013-mi-"}
        for pattern, what in cases.items():
            with self.subTest(fail=pattern):
                run = livetest.run_script(SCRIPT, "c", env={"TRR9013_LIVE": "1"}, fail=[(pattern, 7)])
                self.assertEqual(run.returncode, 7, run.text)
                self.assertIn("The run stopped before the undo of this change was registered: " + what,
                              run.stderr)


if __name__ == "__main__":
    unittest.main()
