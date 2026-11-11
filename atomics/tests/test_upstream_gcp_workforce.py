"""Offline tests of upstream/atomic-red-team/T1199/src/emulate_gcp_workforce.sh.

This is the packaged Atomic Red Team variant of the TRR9020 workforce emulation. Unlike
the det-eng copy it has no dry/LIVE guard and no undo block: it is a plain atomic with a
`create` path and an idempotent `cleanup` path, driven by positional arguments
(ORG POOL PROVIDER ISSUER ROLE). These tests, run with the livetest stubs, prove:

  * `create` reaches the three gcloud commands (the usage-message bug that made `${1:?...}`
    swallow the mode and always print usage is fixed);
  * the default pool/provider IDs carry the organization ID, so they are unique across
    Google Cloud with no saved state (create and cleanup compute the same value);
  * `cleanup` reaches the three revert commands; a revert that fails because the object is
    already gone is silent and keeps exit 0 (idempotent), but a revert that fails for
    another reason makes cleanup exit 1 and name what stays;
  * an unknown mode, a missing mode, and a missing organization each stop with exit 1;
  * the organization binding is written and removed with `--condition=None`;
  * no `--organization` is on `providers create-oidc` / the two delete commands.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import livetest     # noqa: E402

SCRIPT = "upstream/atomic-red-team/T1199/src/emulate_gcp_workforce.sh"
ORG = "0000000000"
POOL = "atomic-ext-pool"
PROVIDER = "atomic-ext-idp"
ISSUER = "https://issuer.example.com"
ROLE = "roles/browser"
MEMBER = f"principalSet://iam.googleapis.com/locations/global/workforcePools/{POOL}/*"
ARGS = (ORG, POOL, PROVIDER, ISSUER, ROLE)

CREATE_POOL = ["gcloud", "iam", "workforce-pools", "create", POOL, f"--organization={ORG}",
               "--location=global", "--display-name=atomic ext pool"]
CREATE_PROVIDER = ["gcloud", "iam", "workforce-pools", "providers", "create-oidc", PROVIDER,
                   "--location=global", f"--workforce-pool={POOL}", f"--issuer-uri={ISSUER}",
                   f"--client-id={POOL}", "--attribute-mapping=google.subject=assertion.sub",
                   "--web-sso-response-type=id-token",
                   "--web-sso-assertion-claims-behavior=only-id-token-claims"]
ADD_BINDING = ["gcloud", "organizations", "add-iam-policy-binding", ORG, f"--role={ROLE}",
               f"--member={MEMBER}", "--condition=None"]
REMOVE_BINDING = ["gcloud", "organizations", "remove-iam-policy-binding", ORG, f"--role={ROLE}",
                  f"--member={MEMBER}", "--condition=None", "--quiet"]
DEL_PROVIDER = ["gcloud", "iam", "workforce-pools", "providers", "delete", PROVIDER,
                "--location=global", f"--workforce-pool={POOL}", "--quiet"]
DEL_POOL = ["gcloud", "iam", "workforce-pools", "delete", POOL, "--location=global", "--quiet"]

NOT_FOUND = "ERROR: (gcloud.iam.workforce-pools.delete) NOT_FOUND: Requested entity was not found."


class Create(unittest.TestCase):

    def test_create_runs_the_three_commands(self):
        run = livetest.run_script(SCRIPT, "create", *ARGS)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [CREATE_POOL, CREATE_PROVIDER, ADD_BINDING], run.text)

    def test_only_workforce_pools_create_takes_the_organization_flag(self):
        run = livetest.run_script(SCRIPT, "create", *ARGS)
        for call in run.calls:
            line = " ".join(call)
            if "providers create-oidc" in line:
                self.assertNotIn("--organization", line, line)
            if "workforce-pools create " in line:
                self.assertIn(f"--organization={ORG}", call, line)

    def test_the_binding_carries_condition_none(self):
        run = livetest.run_script(SCRIPT, "create", *ARGS)
        add = next(c for c in run.calls if "add-iam-policy-binding" in c)
        self.assertIn("--condition=None", add)

    def test_the_default_pool_and_provider_ids_carry_the_organization_id(self):
        # With no POOL/PROVIDER argument the IDs are unique across Google Cloud without
        # saved state, so two organizations do not collide on the globally unique pool ID.
        run = livetest.run_script(SCRIPT, "create", ORG)
        self.assertEqual(run.returncode, 0, run.text)
        pool = run.calls[0][4]
        self.assertEqual(pool, f"atomic-ext-pool-{ORG}", run.text)
        self.assertLessEqual(len(pool), 63)      # the limit of a workforce pool ID
        provider = next(c for c in run.calls if "create-oidc" in " ".join(c))[5]
        self.assertEqual(provider, f"atomic-ext-idp-{ORG}", run.text)

    def test_create_and_cleanup_compute_the_same_default_pool_id(self):
        created = livetest.run_script(SCRIPT, "create", ORG)
        cleaned = livetest.run_script(SCRIPT, "cleanup", ORG)
        self.assertEqual(created.calls[0][4],
                         next(c for c in cleaned.calls if "workforce-pools delete" in " ".join(c))[4])


class Cleanup(unittest.TestCase):

    def test_cleanup_runs_the_three_revert_commands(self):
        run = livetest.run_script(SCRIPT, "cleanup", *ARGS)
        self.assertEqual(run.returncode, 0, run.text)
        self.assertEqual(run.calls, [REMOVE_BINDING, DEL_PROVIDER, DEL_POOL], run.text)

    def test_the_delete_commands_omit_the_organization_flag(self):
        run = livetest.run_script(SCRIPT, "cleanup", *ARGS)
        for call in run.calls:
            if "providers delete" in " ".join(call) or "workforce-pools delete" in " ".join(call):
                self.assertNotIn("--organization", " ".join(call), " ".join(call))

    def test_a_revert_that_fails_because_the_object_is_gone_keeps_exit_0(self):
        # gcloud exits non-zero for NOT_FOUND; the idempotent cleanup reads the error text
        # and stays silent for a missing object.
        for pattern in (r"remove-iam-policy-binding", r"providers delete", r"workforce-pools delete"):
            with self.subTest(gone=pattern):
                run = livetest.run_script(SCRIPT, "cleanup", *ARGS, fail=[(pattern, 1, NOT_FOUND)])
                self.assertEqual(run.returncode, 0, run.text)
                self.assertNotIn("not removed", run.stderr, run.text)

    def test_a_revert_that_fails_for_another_reason_makes_cleanup_exit_1(self):
        # Each of the three reverts, and all three at once: a failure that is not NOT_FOUND
        # (for example no permission) is surfaced and makes cleanup non-zero.
        labels = {
            r"remove-iam-policy-binding": "organization binding",
            r"providers delete": "provider",
            r"workforce-pools delete": "workforce pool",
        }
        for pattern, label in labels.items():
            with self.subTest(fails=pattern):
                run = livetest.run_script(SCRIPT, "cleanup", *ARGS, fail=[(pattern, 1)])
                self.assertEqual(run.returncode, 1, run.text)
                self.assertIn("not removed: " + label, run.stderr, run.text)
        run = livetest.run_script(SCRIPT, "cleanup", *ARGS, fail=[(r"gcloud", 1)])
        self.assertEqual(run.returncode, 1, run.text)
        for label in labels.values():
            self.assertIn("not removed: " + label, run.stderr, run.text)


class Usage(unittest.TestCase):

    def test_an_unknown_mode_prints_usage_and_exits_1_and_makes_no_call(self):
        run = livetest.run_script(SCRIPT, "frobnicate", *ARGS)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("usage: emulate_gcp_workforce.sh {create|cleanup}", run.stderr)
        self.assertEqual(run.calls, [], run.text)

    def test_no_mode_stops_with_exit_1_and_names_the_usage(self):
        run = livetest.run_script(SCRIPT)
        self.assertEqual(run.returncode, 1, run.text)
        self.assertIn("usage: emulate_gcp_workforce.sh {create|cleanup}", run.stderr)
        self.assertEqual(run.calls, [], run.text)

    def test_without_gcloud_each_mode_makes_no_call_and_exits_1(self):
        stubs = tuple(name for name in livetest.STUBS if name != "gcloud")
        for mode in ("create", "cleanup"):
            with self.subTest(mode=mode):
                run = livetest.run_script(SCRIPT, mode, *ARGS, stubs=stubs)
                self.assertEqual(run.returncode, 1, run.text)
                self.assertEqual(run.calls, [], run.text)
                self.assertIn("gcloud CLI not found", run.stderr)

    def test_create_without_an_organization_stops_with_exit_1(self):
        run = livetest.run_script(SCRIPT, "create")
        self.assertEqual(run.returncode, 1, run.text)
        self.assertEqual(run.calls, [], run.text)


if __name__ == "__main__":
    unittest.main()
