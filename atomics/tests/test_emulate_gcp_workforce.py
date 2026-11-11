"""Offline tests of atomics/T1199/src/emulate_gcp_workforce.sh (TRR9020).

The script makes no cloud call in dry mode and, in LIVE mode, drives the stub `gcloud`
of livetest. These tests prove the dry contract, the LIVE call sequence, the undo of a
failed run, and the corrections from the "Problems in the live scripts" table:

  * no `--organization` on `providers create-oidc`, `providers delete` or
    `workforce-pools delete` (only `workforce-pools create` takes it);
  * `providers create-oidc` carries `--client-id` and uses the implicit flow
    (`--web-sso-response-type=id-token`), so no client secret is on any command line;
  * every throwaway object name starts with trr9020- (pool, provider, client id);
  * the organization binding is written and reverted with `--condition=None`;
  * only procedures a and c have a live run; b and d make no change and stop with exit 1;
  * a live run needs TRR9020_ORG (no placeholder), and makes a unique pool name;
  * a stop signal during a command that makes a change does not leave that change
    with no undo.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import livetest     # noqa: E402

SCRIPT = "atomics/T1199/src/emulate_gcp_workforce.sh"
ORG = "987654321000"
POOL = "trr9020-fixed"
MEMBER = f"principalSet://iam.googleapis.com/locations/global/workforcePools/{POOL}/*"
LIVE = {"TRR9020_LIVE": "1", "TRR9020_ORG": ORG, "TRR9020_POOL": POOL}

# The exact LIVE sequence with ORG and POOL set (role defaults to the safe roles/viewer).
CREATE_POOL = ["gcloud", "iam", "workforce-pools", "create", POOL, f"--organization={ORG}",
               "--location=global", "--display-name=trr9020 ext pool"]
CREATE_PROVIDER = ["gcloud", "iam", "workforce-pools", "providers", "create-oidc", "trr9020-idp",
                   "--location=global", f"--workforce-pool={POOL}",
                   "--issuer-uri=https://attacker.example.com", "--client-id=trr9020-client",
                   "--attribute-mapping=google.subject=assertion.sub",
                   "--web-sso-response-type=id-token",
                   "--web-sso-assertion-claims-behavior=only-id-token-claims"]
ADD_BINDING = ["gcloud", "organizations", "add-iam-policy-binding", ORG,
               "--role=roles/viewer", f"--member={MEMBER}", "--condition=None"]
UNDO_BINDING = ["gcloud", "organizations", "remove-iam-policy-binding", ORG,
                "--role=roles/viewer", f"--member={MEMBER}", "--condition=None"]
UNDO_PROVIDER = ["gcloud", "iam", "workforce-pools", "providers", "delete", "trr9020-idp",
                 "--location=global", f"--workforce-pool={POOL}", "--quiet"]
UNDO_POOL = ["gcloud", "iam", "workforce-pools", "delete", POOL, "--location=global", "--quiet"]

FULL = [CREATE_POOL, CREATE_PROVIDER, ADD_BINDING, UNDO_BINDING, UNDO_PROVIDER, UNDO_POOL]


class Dry(unittest.TestCase):

    def test_each_procedure_letter_exits_0_and_makes_no_call(self):
        for proc in ("a", "b", "c", "d"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc)
                self.assertEqual(run.returncode, 0, run.text)
                self.assertEqual(run.calls, [], run.text)

    def test_an_invalid_letter_prints_usage_and_exits_1(self):
        run = livetest.run_script(SCRIPT, "z")
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("usage: emulate_gcp_workforce.sh {a|b|c|d}", run.stdout)
        self.assertEqual(run.calls, [])

    def test_an_invalid_letter_is_still_rejected_in_live_mode(self):
        run = livetest.run_script(SCRIPT, "z", env=LIVE)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertEqual(run.calls, [])

    def test_show_fixture_prints_the_committed_fixture_and_makes_no_call(self):
        run = livetest.run_script(SCRIPT, "--show-fixture")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [])
        with open(os.path.join(livetest.REPO,
                  "detections/cloud/fixtures/trr9020/attack.json"), encoding="utf-8") as fh:
            self.assertEqual(run.stdout, fh.read())

    def test_show_fixture_as_second_argument_prints_the_same_fixture(self):
        run = livetest.run_script(SCRIPT, "a", "--show-fixture")
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [])
        with open(os.path.join(livetest.REPO,
                  "detections/cloud/fixtures/trr9020/attack.json"), encoding="utf-8") as fh:
            self.assertEqual(run.stdout, fh.read())


class Live(unittest.TestCase):

    def test_org_not_set_stops_before_any_change_with_exit_2(self):
        run = livetest.run_script(SCRIPT, "a", env={"TRR9020_LIVE": "1"})
        self.assertEqual(run.returncode, 2, run.text)
        self.assertEqual(run.calls, [], run.text)
        self.assertIn("TRR9020_ORG", run.stderr)

    def test_live_as_second_argument_also_requires_the_org(self):
        run = livetest.run_script(SCRIPT, "a", "--live")
        self.assertEqual(run.returncode, 2, run.text)
        self.assertEqual(run.calls, [])

    def test_live_as_second_argument_runs_the_full_flow(self):
        run = livetest.run_script(SCRIPT, "a", "--live",
                                  env={"TRR9020_ORG": ORG, "TRR9020_POOL": POOL})
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, FULL, run.text)

    def test_without_gcloud_a_live_run_makes_no_call_and_exits_1(self):
        # gcloud is not installed: no record can be caused, so the run is not a success.
        stubs = tuple(name for name in livetest.STUBS if name != "gcloud")
        for proc in ("a", "c"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env=LIVE, stubs=stubs)
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("gcloud not found", run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_a_procedure_with_no_live_run_makes_no_call_and_exits_1(self):
        # The script knows that it caused no record: that is not a success (exit 0).
        for proc in ("b", "d"):
            with self.subTest(proc=proc):
                run = livetest.run_script(SCRIPT, proc, env={"TRR9020_LIVE": "1", "TRR9020_ORG": ORG})
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("no live run: no record was caused", run.stderr)
                self.assertNotIn("[live] done", run.stdout)

    def test_a_name_that_does_not_start_with_the_trr_prefix_stops_before_any_change(self):
        for name in ("TRR9020_POOL", "TRR9020_PROVIDER"):
            with self.subTest(variable=name):
                run = livetest.run_script(SCRIPT, "a", env=dict(LIVE, **{name: "my-own-name"}))
                self.assertEqual(run.returncode, 2, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn(name, run.stderr)

    def test_procedure_c_runs_the_binding_flow(self):
        run = livetest.run_script(SCRIPT, "c", env=LIVE)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, FULL, run.text)

    def test_happy_path_runs_the_exact_sequence_then_reverts_last_first(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, FULL, run.text)

    def test_the_undo_commands_omit_the_organization_flag(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertIn(UNDO_PROVIDER, run.calls)
        self.assertIn(UNDO_POOL, run.calls)

    def test_only_workforce_pools_create_takes_the_organization_flag(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE)
        for call in run.calls:
            line = " ".join(call)
            if "workforce-pools create " in line:
                self.assertIn(f"--organization={ORG}", call, line)
            if "providers create-oidc" in line or "providers delete" in line \
                    or ("workforce-pools delete" in line):
                self.assertNotIn("--organization", line, line)

    def test_provider_create_has_a_client_id_and_the_implicit_flow(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE)
        create = next(c for c in run.calls if "create-oidc" in " ".join(c))
        self.assertIn("--client-id=trr9020-client", create)
        self.assertIn("--web-sso-response-type=id-token", create)

    def test_no_client_secret_is_on_any_command_line(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE)
        for call in run.calls:
            line = " ".join(call)
            self.assertNotIn("--client-secret", line, line)
            self.assertNotIn("--web-sso-response-type=code", line, line)

    def test_no_attribute_condition_is_passed_so_the_rule_reads_an_empty_one(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE)
        create = next(c for c in run.calls if "create-oidc" in " ".join(c))
        self.assertNotIn("--attribute-condition", " ".join(create))

    def test_the_binding_is_written_and_reverted_with_condition_none(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE)
        add = next(c for c in run.calls if "add-iam-policy-binding" in c)
        remove = next(c for c in run.calls if "remove-iam-policy-binding" in c)
        self.assertIn("--condition=None", add)
        self.assertIn("--condition=None", remove)

    def test_the_bound_role_defaults_to_the_safe_viewer_role(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE)
        add = next(c for c in run.calls if "add-iam-policy-binding" in c)
        self.assertIn("--role=roles/viewer", add)

    def test_every_created_object_name_starts_with_the_trr_prefix(self):
        run = livetest.run_script(SCRIPT, "a", env={"TRR9020_LIVE": "1", "TRR9020_ORG": ORG})
        pool = next(c for c in run.calls if c[:4] == ["gcloud", "iam", "workforce-pools", "create"])[4]
        provider = next(c for c in run.calls if "create-oidc" in " ".join(c))[5]
        self.assertTrue(pool.startswith("trr9020-"), pool)
        self.assertTrue(provider.startswith("trr9020-"), provider)

    def test_an_unset_pool_name_is_unique_and_starts_with_the_trr_prefix(self):
        env = {"TRR9020_LIVE": "1", "TRR9020_ORG": ORG}
        names = []
        for _ in range(3):
            run = livetest.run_script(SCRIPT, "a", env=env)
            self.assertEqual(run.returncode, 0, run.text)
            create = next(c for c in run.calls if c[:4] == ["gcloud", "iam", "workforce-pools", "create"])
            self.assertRegex(create[4], r"^trr9020-\d{14}-\d+$")
            self.assertLessEqual(len(create[4]), 63)      # the limit of a workforce pool ID
            # The undo deletes the pool of this run, not a fixed name.
            self.assertIn(["gcloud", "iam", "workforce-pools", "delete", create[4],
                           "--location=global", "--quiet"], run.calls)
            names.append(create[4])
        # Three runs give three names (a constant name in the same format fails here).
        self.assertEqual(len(set(names)), 3, names)

    def test_the_member_string_keeps_its_star_when_a_file_matches_the_pattern(self):
        # An unquoted member string is a file name pattern for the shell. The run has a
        # file that the pattern matches; the commands must get the literal string.
        trap = f"--member=principalSet:/iam.googleapis.com/locations/global/workforcePools/{POOL}/GLOBBED"
        run = livetest.run_script(SCRIPT, "a", env=LIVE, files=[trap])
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, FULL, run.text)

    def test_the_default_role_says_that_the_binding_rule_does_not_fire(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE)
        self.assertEqual(run.returncode, 0, run.text)      # the record is written: exit 0 by design
        self.assertIn("the binding rule\n[live] does NOT fire, by design", run.stdout)

    def test_a_role_that_the_rule_matches_does_not_print_the_safe_role_note(self):
        run = livetest.run_script(SCRIPT, "a", env=dict(LIVE, TRR9020_ROLE="roles/pubsub.editor"))
        self.assertEqual(run.returncode, 0, run.text)
        self.assertIn("--role=roles/pubsub.editor", next(c for c in run.calls if "add-iam-policy-binding" in c))
        self.assertNotIn("does NOT fire", run.stdout)
        self.assertIn("the binding rule reads this record", run.stdout)

    def test_the_role_note_agrees_with_the_role_parts_of_the_binding_rule(self):
        # What the paired rule does for a binding of each role to the full pool (the rule
        # file: detections/sigma/T1199/gcp_workforce_principalset_privileged_binding.yml).
        # The rule fires for a name that holds owner, editor or admin, and for a roles/iam.
        # role that ends with Creator or User. The note of the script must say the same.
        fires = ("roles/owner", "roles/editor", "roles/pubsub.editor", "roles/container.admin",
                 "roles/iam.securityAdmin", "roles/iam.serviceAccountTokenCreator",
                 "roles/iam.serviceAccountUser", "roles/iam.workloadIdentityUser",
                 "organizations/123456789012/roles/trr9020CustomOwner")
        quiet = ("roles/viewer", "roles/browser", "roles/logging.viewer", "roles/iam.roleViewer",
                 "roles/iam.securityReviewer", "roles/storage.objectCreator",
                 "roles/serviceusage.serviceUsageConsumer")
        for role in fires + quiet:
            with self.subTest(role=role):
                run = livetest.run_script(SCRIPT, "c", env=dict(LIVE, TRR9020_ROLE=role))
                self.assertEqual(run.returncode, 0, run.text)
                if role in fires:
                    self.assertIn("the binding rule reads this record", run.stdout)
                    self.assertNotIn("does NOT fire", run.stdout)
                else:
                    self.assertIn("the binding rule\n[live] does NOT fire, by design", run.stdout)
                    self.assertNotIn("reads this record", run.stdout)
                # The name of a role does not show its power: no role is called safe by name.
                self.assertNotIn("is a safe role", run.stdout)

    def test_the_planned_end_reverts_every_change_before_it_prints_done(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE)
        self.assertEqual(run.returncode, 0, run.text)
        lines = [ln for ln in run.stdout.split("\n") if ln]
        self.assertTrue(lines[-1].startswith("[live] done."), run.text)
        self.assertTrue(all(ln.startswith("[live] undo: ") for ln in lines[-4:-1]), run.text)

    def test_the_undo_block_sits_after_the_cli_check_inside_the_live_branch(self):
        with open(os.path.join(livetest.REPO, SCRIPT), encoding="utf-8") as fh:
            text = fh.read()
        self.assertLess(text.index('if [[ "$LIVE" == "1" ]]'), text.index("command -v gcloud"))
        self.assertLess(text.index("command -v gcloud"), text.index(livetest.UNDO_START))

    def test_an_undo_failure_at_the_planned_end_does_not_print_done(self):
        run = livetest.run_script(SCRIPT, "a", env=LIVE, fail=[(r"remove-iam-policy-binding", 5)])
        self.assertEqual(run.returncode, 1, run.text)
        self.assertNotIn("[live] done", run.stdout, run.text)
        self.assertIn("LEFT BEHIND", run.stderr, run.text)

    def test_each_undo_command_that_fails_is_left_behind_and_fails_the_run(self):
        # The given pool name, and the default one (it holds the time of the run).
        self.assertEqual(livetest.each_undo_failure(self, SCRIPT, "a", env=LIVE), 3)
        default_pool = {k: v for k, v in LIVE.items() if k != "TRR9020_POOL"}
        self.assertEqual(livetest.each_undo_failure(self, SCRIPT, "a", env=default_pool), 3)

    def test_a_failure_at_each_change_reverts_the_earlier_changes_last_first(self):
        # pattern of the failing command : the exact call list expected.
        cases = {
            r"workforce-pools create ": [CREATE_POOL],
            r"providers create-oidc": [CREATE_POOL, CREATE_PROVIDER, UNDO_POOL],
            r"organizations add-iam-policy-binding":
                [CREATE_POOL, CREATE_PROVIDER, ADD_BINDING, UNDO_PROVIDER, UNDO_POOL],
        }
        for pattern, expected in cases.items():
            with self.subTest(fail=pattern):
                run = livetest.run_script(SCRIPT, "a", env=LIVE, fail=[(pattern, 7)])
                self.assertEqual(run.returncode, 7, run.text)
                # The full call list is exact: the undo of the command that FAILED never runs,
                # and no change made before it is left without its undo.
                self.assertEqual(run.calls, expected, run.text)
                self.assertNotIn("[live] done", run.stdout, run.text)


class LiveStopSignal(unittest.TestCase):
    """A stop signal that comes while a command that makes a change runs."""

    CHANGES = {
        r"workforce-pools create ": [CREATE_POOL, UNDO_POOL],
        r"providers create-oidc": [CREATE_POOL, CREATE_PROVIDER, UNDO_PROVIDER, UNDO_POOL],
        r"organizations add-iam-policy-binding": FULL,
    }

    def test_a_signal_to_the_script_during_a_change_reverts_that_change_too(self):
        # The command runs to its end, so the provider made the change. The run must
        # register the undo of that change before it stops.
        for name, code in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            for pattern, expected in self.CHANGES.items():
                with self.subTest(signal=name, during=pattern):
                    run = livetest.run_script(SCRIPT, "a", env=LIVE,
                                              signals=[(pattern, name, "shell")])
                    self.assertEqual(run.returncode, code, run.text)
                    self.assertEqual(run.calls, expected, run.text)
                    self.assertNotIn("[live] done", run.stdout, run.text)
                    self.assertNotIn("has no undo", run.stderr, run.text)

    def test_a_signal_that_stops_the_change_command_names_the_change_that_can_stay(self):
        # Ctrl-C: the signal stops gcloud in the middle. The script cannot know if the
        # provider made the change, so it reverts the earlier changes and names this one.
        cases = {
            r"workforce-pools create ": ([CREATE_POOL], "workforce pool " + POOL),
            r"providers create-oidc": ([CREATE_POOL, CREATE_PROVIDER, UNDO_POOL], "provider trr9020-idp"),
            r"organizations add-iam-policy-binding":
                ([CREATE_POOL, CREATE_PROVIDER, ADD_BINDING, UNDO_PROVIDER, UNDO_POOL],
                 "binding of " + MEMBER + " to roles/viewer on the organization " + ORG),
        }
        for pattern, (expected, what) in cases.items():
            with self.subTest(during=pattern):
                run = livetest.run_script(SCRIPT, "a", env=LIVE, signals=[(pattern, "INT", "group")])
                self.assertEqual(run.returncode, 130, run.text)
                self.assertEqual(run.calls, expected, run.text)
                self.assertIn("The run stopped before the undo of this change was registered: " + what, run.stderr)
                self.assertIn("That change has no undo", run.stderr)
                self.assertNotIn("[live] done", run.stdout, run.text)

    def test_a_reader_of_the_output_that_is_gone_does_not_stop_the_undo(self):
        # `script 2>&1 | head -10`: the reader goes away after the line that announces
        # the second change. The next write of the script fails. The undo of each change
        # that was made must run all the same (a SIGPIPE must not end the script).
        script = os.path.join(livetest.REPO, SCRIPT)
        run = livetest.run_script("atomics/tests/pipe_to_head.sh", script, "10", "a", env=LIVE)
        undo_of = ((CREATE_POOL, UNDO_POOL), (CREATE_PROVIDER, UNDO_PROVIDER), (ADD_BINDING, UNDO_BINDING))
        made = [change for change, _undo in undo_of if change in run.calls]
        self.assertTrue(made, run.text)
        self.assertEqual(run.calls, made + [undo for change, undo in reversed(undo_of) if change in made],
                         run.text)


if __name__ == "__main__":
    unittest.main()
