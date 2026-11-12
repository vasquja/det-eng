"""Offline tests of atomics/T1098.001/src/emulate_gcp_wif.sh (TRR9018).

The script makes no cloud call in dry mode and, in LIVE mode, drives the stub `gcloud`
of livetest. These tests prove the dry contract, the LIVE call sequence, the undo of a
failed run, and the corrections from the "Problems in the live scripts" table:

  * the default issuer is a single-tenant example.com issuer, not the GitHub issuer, so
    Google needs no attribute condition and the provider is made with an empty one;
  * the default provider name is 4-32 characters (not `gh`);
  * the binding it adds is written and removed with `--condition=None`;
  * when TRR9018_SA is not set the run makes a throwaway service account FIRST (so it has
    time to propagate), reads its address from the create command, and removes it last;
  * only procedures a and c have a live run; b, d and e make no change and stop with exit 1;
  * a live run needs TRR9018_PROJECT (no placeholder), stops when the project number
    lookup gives nothing, and makes a unique pool name;
  * a stop signal during a command that makes a change does not leave that change
    with no undo.
"""

import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import livetest     # noqa: E402

SCRIPT = "atomics/T1098.001/src/emulate_gcp_wif.sh"
PROJECT = "my-sandbox-proj"
POOL = "trr9018-fixed"
PNUM = "123456789012"
SA = "picked@my-sandbox-proj.iam.gserviceaccount.com"
SA_T = "trr9018-sa-made@my-sandbox-proj.iam.gserviceaccount.com"   # the throwaway create output
PNUM_OUT = [("projects describe", PNUM)]
THROWAWAY_OUT = PNUM_OUT + [("service-accounts create", SA_T)]
MEMBER = (f"principalSet://iam.googleapis.com/projects/{PNUM}"
          f"/locations/global/workloadIdentityPools/{POOL}/*")
# LIVE with a provided SA: fully deterministic (no throwaway SA with a timestamp).
LIVE_SA = {"TRR9018_LIVE": "1", "TRR9018_PROJECT": PROJECT, "TRR9018_POOL": POOL, "TRR9018_SA": SA}
LIVE_THROWAWAY = {"TRR9018_LIVE": "1", "TRR9018_PROJECT": PROJECT, "TRR9018_POOL": POOL}

DESCRIBE = ["gcloud", "projects", "describe", PROJECT, "--format=value(projectNumber)"]
CREATE_POOL = ["gcloud", "iam", "workload-identity-pools", "create", POOL,
               f"--project={PROJECT}", "--location=global", "--display-name=trr9018 ext pool"]
CREATE_PROVIDER = ["gcloud", "iam", "workload-identity-pools", "providers", "create-oidc",
                   "trr9018-oidc", f"--project={PROJECT}", "--location=global",
                   f"--workload-identity-pool={POOL}", "--issuer-uri=https://attacker.example.com",
                   "--attribute-mapping=google.subject=assertion.sub"]


def add_binding(sa):
    return ["gcloud", "iam", "service-accounts", "add-iam-policy-binding", sa,
            f"--project={PROJECT}", "--role=roles/iam.workloadIdentityUser",
            f"--member={MEMBER}", "--condition=None"]


def undo_binding(sa):
    return ["gcloud", "iam", "service-accounts", "remove-iam-policy-binding", sa,
            f"--project={PROJECT}", "--role=roles/iam.workloadIdentityUser",
            f"--member={MEMBER}", "--condition=None"]


def sa_delete(sa):
    return ["gcloud", "iam", "service-accounts", "delete", sa, f"--project={PROJECT}", "--quiet"]


UNDO_PROVIDER = ["gcloud", "iam", "workload-identity-pools", "providers", "delete", "trr9018-oidc",
                 f"--project={PROJECT}", "--location=global", f"--workload-identity-pool={POOL}", "--quiet"]
UNDO_POOL = ["gcloud", "iam", "workload-identity-pools", "delete", POOL,
             f"--project={PROJECT}", "--location=global", "--quiet"]

# The given-SA flow: no throwaway SA create, so pool/provider/binding and their reverts.
GIVEN_FULL = [DESCRIBE, CREATE_POOL, CREATE_PROVIDER, add_binding(SA),
              undo_binding(SA), UNDO_PROVIDER, UNDO_POOL]


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
        self.assertIn("usage: emulate_gcp_wif.sh {a|b|c|d|e}", run.stdout)
        self.assertEqual(run.calls, [])

    def test_show_fixture_prints_the_committed_fixture_and_makes_no_call(self):
        run = livetest.run_script(SCRIPT, "--show-fixture")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [])
        with open(os.path.join(livetest.REPO,
                  "detections/cloud/fixtures/trr9018/attack.json"), encoding="utf-8") as fh:
            self.assertEqual(run.stdout, fh.read())

    def test_show_fixture_as_second_argument_prints_the_same_fixture(self):
        run = livetest.run_script(SCRIPT, "a", "--show-fixture")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [])
        with open(os.path.join(livetest.REPO,
                  "detections/cloud/fixtures/trr9018/attack.json"), encoding="utf-8") as fh:
            self.assertEqual(run.stdout, fh.read())


class Live(unittest.TestCase):

    def test_project_not_set_stops_before_any_change_with_exit_2(self):
        run = livetest.run_script(SCRIPT, "a", env={"TRR9018_LIVE": "1"}, outputs=PNUM_OUT)
        self.assertEqual(run.returncode, 2, run.text)
        self.assertEqual(run.calls, [], run.text)
        self.assertIn("TRR9018_PROJECT", run.stderr)

    def test_live_as_second_argument_also_requires_the_project(self):
        run = livetest.run_script(SCRIPT, "a", "--live")
        self.assertEqual(run.returncode, 2, run.text)
        self.assertEqual(run.calls, [])

    def test_live_as_second_argument_runs_the_flow(self):
        env = {"TRR9018_PROJECT": PROJECT, "TRR9018_POOL": POOL, "TRR9018_SA": SA}
        run = livetest.run_script(SCRIPT, "a", "--live", env=env, outputs=PNUM_OUT)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, GIVEN_FULL, run.text)

    def test_without_gcloud_a_live_run_makes_no_call_and_exits_1(self):
        # gcloud is not installed: no record can be caused, so the run is not a success.
        stubs = tuple(name for name in livetest.STUBS if name != "gcloud")
        for proc in ("a", "c"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env=LIVE_SA, outputs=PNUM_OUT, stubs=stubs)
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("gcloud not found", run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_a_procedure_with_no_live_run_makes_no_call_and_exits_1(self):
        # The script knows that it caused no record: that is not a success (exit 0).
        for proc in ("b", "d", "e"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc,
                                          env={"TRR9018_LIVE": "1", "TRR9018_PROJECT": PROJECT})
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("no live run: no record was caused", run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_a_name_that_does_not_start_with_the_trr_prefix_stops_before_any_change(self):
        for name in ("TRR9018_POOL", "TRR9018_PROVIDER"):
            with self.subTest(variable=name):
                run = livetest.run_script(SCRIPT, "a", env=dict(LIVE_SA, **{name: "my-own-name"}),
                                          outputs=PNUM_OUT)
                self.assertEqual(run.returncode, 2, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn(name, run.stderr)

    def test_a_failed_project_number_lookup_stops_before_any_change(self):
        # The stub gives no output for 'projects describe', so PNUM is empty.
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=[])
        self.assertNotEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [DESCRIBE], run.text)

    def test_happy_path_with_a_given_sa_runs_the_exact_sequence_then_reverts(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, GIVEN_FULL, run.text)

    def test_a_given_sa_is_not_created_or_deleted(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT)
        for call in run.calls:
            line = " ".join(call)
            self.assertNotIn("service-accounts create", line, line)
            self.assertNotIn("service-accounts delete", line, line)

    def test_procedure_c_runs_the_same_flow(self):
        run = livetest.run_script(SCRIPT, "c", env=LIVE_SA, outputs=PNUM_OUT)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, GIVEN_FULL, run.text)

    def test_the_binding_is_written_and_removed_with_condition_none(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT)
        add = next(c for c in run.calls if "add-iam-policy-binding" in c)
        remove = next(c for c in run.calls if "remove-iam-policy-binding" in c)
        self.assertIn("--condition=None", add)
        self.assertIn("--condition=None", remove)

    def test_a_throwaway_sa_is_created_first_from_its_own_output_and_deleted_last(self):
        # The script gets TZ=UTC and the test compares in UTC: the test must not depend on
        # the time zone of the runner (the script does not get the TZ of the caller).
        run = livetest.run_script(SCRIPT, "a", env=dict(LIVE_THROWAWAY, TZ="UTC"), outputs=THROWAWAY_OUT)
        self.assertEqual(run.returncode, 0, run.text)
        create = next(c for c in run.calls if c[:4] ==
                      ["gcloud", "iam", "service-accounts", "create"])
        # The throwaway SA is made with a trr9018-sa- name and its email read from the output.
        # The name holds the time of the run (a constant name in the same format fails here),
        # so it cannot be the name of an account that an earlier run left.
        self.assertRegex(create[4], r"^trr9018-sa-\d{14}$")
        self.assertLessEqual(len(create[4]), 30)      # the limit of a service account ID
        made = datetime.datetime.strptime(create[4][len("trr9018-sa-"):], "%Y%m%d%H%M%S")
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        self.assertLess(abs((now - made).total_seconds()), 300, create[4])
        self.assertIn("--format=value(email)", create)
        expected = [DESCRIBE, create, CREATE_POOL, CREATE_PROVIDER, add_binding(SA_T),
                    undo_binding(SA_T), UNDO_PROVIDER, UNDO_POOL, sa_delete(SA_T)]
        self.assertEqual(run.calls, expected, run.text)
        # The SA create is the FIRST change, before the pool.
        self.assertLess(run.calls.index(create),
                        run.calls.index(CREATE_POOL), run.text)
        # The binding and the SA delete use the create-OUTPUT email (SA_T), not an address
        # built from the project id, so an unusual project id cannot misname the account.
        self.assertIn(add_binding(SA_T), run.calls)
        self.assertIn(sa_delete(SA_T), run.calls)

    def test_the_default_issuer_is_not_the_github_issuer(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT)
        create = next(c for c in run.calls if "create-oidc" in " ".join(c))
        line = " ".join(create)
        self.assertNotIn("githubusercontent", line, line)
        self.assertIn("--issuer-uri=https://attacker.example.com", create)

    def test_the_default_provider_name_is_at_least_four_characters(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT)
        create = next(c for c in run.calls if "create-oidc" in " ".join(c))
        name = create[5]
        self.assertGreaterEqual(len(name), 4)
        self.assertLessEqual(len(name), 32)
        self.assertEqual(name, "trr9018-oidc")

    def test_no_attribute_condition_is_passed(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT)
        create = next(c for c in run.calls if "create-oidc" in " ".join(c))
        self.assertNotIn("--attribute-condition", " ".join(create))

    def test_no_command_uses_the_organization_flag(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT)
        for call in run.calls:
            self.assertNotIn("--organization", " ".join(call), " ".join(call))

    def test_an_unset_pool_name_is_unique_and_starts_with_the_trr_prefix(self):
        env = {"TRR9018_LIVE": "1", "TRR9018_PROJECT": PROJECT, "TRR9018_SA": SA}
        names = []
        for _ in range(3):
            run = livetest.run_script(SCRIPT, "a", env=env, outputs=PNUM_OUT)
            self.assertEqual(run.returncode, 0, run.text)
            create = next(c for c in run.calls if c[:4] ==
                          ["gcloud", "iam", "workload-identity-pools", "create"])
            self.assertRegex(create[4], r"^trr9018-\d{14}-\d+$")
            self.assertLessEqual(len(create[4]), 32)      # the limit of a workload identity pool ID
            self.assertIn(["gcloud", "iam", "workload-identity-pools", "delete", create[4],
                           f"--project={PROJECT}", "--location=global", "--quiet"], run.calls)
            names.append(create[4])
        # Three runs give three names (a constant name in the same format fails here).
        self.assertEqual(len(set(names)), 3, names)

    def test_the_member_string_keeps_its_star_when_a_file_matches_the_pattern(self):
        # An unquoted member string is a file name pattern for the shell. The run has a
        # file that the pattern matches; the commands must get the literal string.
        trap = (f"--member=principalSet:/iam.googleapis.com/projects/{PNUM}/locations/global/"
                f"workloadIdentityPools/{POOL}/GLOBBED")
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT, files=[trap])
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, GIVEN_FULL, run.text)

    def test_a_create_that_gives_no_address_names_the_service_account_that_stays(self):
        # The create command ends with exit 0, so the account exists, but the answer is
        # not one address. The run cannot delete the account: it must say so and stop
        # before the next change. A second line must not go into a later command.
        answers = {"no answer": "", "two lines": SA_T + "\nWARNING something",
                   "not an address": "created", "an account with another name": SA}
        for what, answer in answers.items():
            with self.subTest(answer=what):
                run = livetest.run_script(SCRIPT, "a", env=LIVE_THROWAWAY,
                                          outputs=PNUM_OUT + [("service-accounts create", answer)])
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(len(run.calls), 2, run.text)
                sa_id = run.calls[1][4]
                self.assertEqual(run.calls[1][:4], ["gcloud", "iam", "service-accounts", "create"])
                self.assertIn(f"LEFT BEHIND: the service account '{sa_id}' in the project '{PROJECT}'",
                              run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_the_planned_end_reverts_every_change_before_it_prints_done(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT)
        self.assertEqual(run.returncode, 0, run.text)
        lines = [ln for ln in run.stdout.split("\n") if ln]
        self.assertEqual(lines[-1], "[live] done.", run.text)
        self.assertTrue(all(ln.startswith("[live] undo: ") for ln in lines[-4:-1]), run.text)

    def test_the_undo_block_sits_after_the_cli_check_inside_the_live_branch(self):
        with open(os.path.join(livetest.REPO, SCRIPT), encoding="utf-8") as fh:
            text = fh.read()
        self.assertLess(text.index('if [[ "$LIVE" == "1" ]]'), text.index("command -v gcloud"))
        self.assertLess(text.index("command -v gcloud"), text.index(livetest.UNDO_START))

    def test_an_undo_failure_at_the_planned_end_does_not_print_done(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT,
                                  fail=[(r"remove-iam-policy-binding", 5)])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        self.assertIn("LEFT BEHIND", run.stderr, run.text)

    def test_each_undo_command_that_fails_is_left_behind_and_fails_the_run(self):
        # A given service account: binding, provider, pool. A throwaway one: its delete too.
        self.assertEqual(livetest.each_undo_failure(self, SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT), 3)
        self.assertEqual(livetest.each_undo_failure(self, SCRIPT, "c", env=LIVE_SA, outputs=PNUM_OUT), 3)
        self.assertEqual(livetest.each_undo_failure(self, SCRIPT, "a", env=LIVE_THROWAWAY,
                                                    outputs=THROWAWAY_OUT), 4)

    def test_a_failure_at_each_change_given_sa_reverts_last_first(self):
        cases = {
            r"workload-identity-pools create ": [DESCRIBE, CREATE_POOL],
            r"providers create-oidc": [DESCRIBE, CREATE_POOL, CREATE_PROVIDER, UNDO_POOL],
            r"service-accounts add-iam-policy-binding":
                [DESCRIBE, CREATE_POOL, CREATE_PROVIDER, add_binding(SA), UNDO_PROVIDER, UNDO_POOL],
        }
        for pattern, expected in cases.items():
            with self.subTest(fail=pattern):
                run = livetest.run_script(SCRIPT, "a", env=LIVE_SA, outputs=PNUM_OUT,
                                          fail=[(pattern, 7)])
                self.assertEqual(run.returncode, 7, run.text)
                self.assertEqual(run.calls, expected, run.text)
                self.assertNotIn("[live] done", run.stdout, run.text)

    def test_a_failure_creating_the_throwaway_sa_reverts_nothing_since_it_is_first(self):
        # The command that fails prints a text that looks like the address of the account. A
        # run that hides the failure would go on with that address.
        run = livetest.run_script(SCRIPT, "a", env=LIVE_THROWAWAY, outputs=THROWAWAY_OUT,
                                  fail=[(r"service-accounts create", 7, SA_T)])
        self.assertEqual(run.returncode, 7, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        create = run.calls[-1]
        self.assertEqual(run.calls, [DESCRIBE, create], run.text)
        self.assertEqual(create[:4], ["gcloud", "iam", "service-accounts", "create"])

    def test_a_binding_failure_with_the_throwaway_sa_deletes_provider_pool_then_sa(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_THROWAWAY, outputs=THROWAWAY_OUT,
                                  fail=[(r"service-accounts add-iam-policy-binding", 7)])
        self.assertEqual(run.returncode, 7, run.text)
        create = next(c for c in run.calls if c[:4] ==
                      ["gcloud", "iam", "service-accounts", "create"])
        expected = [DESCRIBE, create, CREATE_POOL, CREATE_PROVIDER, add_binding(SA_T),
                    UNDO_PROVIDER, UNDO_POOL, sa_delete(SA_T)]
        self.assertEqual(run.calls, expected, run.text)


class LiveStopSignal(unittest.TestCase):
    """A stop signal that comes while a command that makes a change runs."""

    def run_throwaway(self, **kw):
        run = livetest.run_script(SCRIPT, "a", env=LIVE_THROWAWAY, outputs=THROWAWAY_OUT, **kw)
        create = run.calls[1]
        self.assertEqual(create[:4], ["gcloud", "iam", "service-accounts", "create"], run.text)
        return run, create

    def test_a_signal_to_the_script_during_a_change_reverts_that_change_too(self):
        # The command runs to its end, so the provider made the change. The run must
        # register the undo of that change before it stops.
        changes = {
            r"service-accounts create": lambda create: [DESCRIBE, create, sa_delete(SA_T)],
            r"workload-identity-pools create ":
                lambda create: [DESCRIBE, create, CREATE_POOL, UNDO_POOL, sa_delete(SA_T)],
            r"providers create-oidc":
                lambda create: [DESCRIBE, create, CREATE_POOL, CREATE_PROVIDER,
                                UNDO_PROVIDER, UNDO_POOL, sa_delete(SA_T)],
            r"service-accounts add-iam-policy-binding":
                lambda create: [DESCRIBE, create, CREATE_POOL, CREATE_PROVIDER, add_binding(SA_T),
                                undo_binding(SA_T), UNDO_PROVIDER, UNDO_POOL, sa_delete(SA_T)],
        }
        for name, code in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            for pattern, expected in changes.items():
                with self.subTest(signal=name, during=pattern):
                    run, create = self.run_throwaway(signals=[(pattern, name, "shell")])
                    self.assertEqual(run.returncode, code, run.text)
                    self.assertEqual(run.calls, expected(create), run.text)
                    self.assertNotIn("[live] done", run.stdout, run.text)
                    self.assertNotIn("has no undo", run.stderr, run.text)

    def test_a_signal_that_stops_the_change_command_names_the_change_that_can_stay(self):
        # Ctrl-C: the signal stops gcloud in the middle. The script cannot know if the
        # provider made the change, so it reverts the earlier changes and names this one.
        cases = {
            r"service-accounts create":
                (lambda create: [DESCRIBE, create], "service account trr9018-sa-"),
            r"workload-identity-pools create ":
                (lambda create: [DESCRIBE, create, CREATE_POOL, sa_delete(SA_T)],
                 "workload identity pool " + POOL),
            r"service-accounts add-iam-policy-binding":
                (lambda create: [DESCRIBE, create, CREATE_POOL, CREATE_PROVIDER, add_binding(SA_T),
                                 UNDO_PROVIDER, UNDO_POOL, sa_delete(SA_T)],
                 "binding of " + MEMBER + " to roles/iam.workloadIdentityUser on the service account " + SA_T),
        }
        for pattern, (expected, what) in cases.items():
            with self.subTest(during=pattern):
                run, create = self.run_throwaway(signals=[(pattern, "INT", "group")])
                self.assertEqual(run.returncode, 130, run.text)
                self.assertEqual(run.calls, expected(create), run.text)
                self.assertIn("The run stopped before the undo of this change was registered: " + what, run.stderr)
                self.assertIn("That change has no undo", run.stderr)
                self.assertNotIn("[live] done", run.stdout, run.text)


if __name__ == "__main__":
    unittest.main()
