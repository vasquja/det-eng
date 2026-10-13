# Atomic Red Team — staged contributions

These are **upstream-shaped** copies of two atomics, prepared for filing to
[redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) from a personal
fork. They are *not* det-eng's own atomics (those live under [`atomics/`](../../atomics) and keep
the repo's CI shape — the dry-by-default `*_LIVE` guard, the `--show-fixture` hook, the internal
rule/chokepoint references). The files here are the transformed versions to copy into the fork.

Opening the pull requests is a human step (fork + PR under your own account). File **one PR per
technique**.

## What is staged

| Technique | File | Upstream status (checked 2026-10-13) |
|-----------|------|--------------------------------------|
| T1098.006 — Account Manipulation: Additional Container Cluster Roles | [`T1098.006/T1098.006.yaml`](./T1098.006/T1098.006.yaml) (+ [`src/emulate.sh`](./T1098.006/src/emulate.sh)) | **New file** — `atomics/T1098.006/` returns 404 upstream |
| T1199 — Trusted Relationship | [`T1199/T1199.yaml`](./T1199/T1199.yaml) (+ [`src/emulate_gcp_workforce.sh`](./T1199/src/emulate_gcp_workforce.sh)) | **New file** — `atomics/T1199/` returns 404 upstream |

Both IDs have no existing atomics upstream (confirmed by a raw-content fetch against a control
file that returned 200 through the same path), so each is a brand-new `atomics/<ID>/` directory,
not an append to an existing file.

## Transforms applied (vs the det-eng `atomics/` copies)

Common to both:

- **Dropped `auto_generated_guid`.** Atomic Red Team's post-merge `generate-docs` GitHub Action
  assigns GUIDs via `runner.py generate-guids`; new tests must omit them. Do **not** hand-add a
  GUID — it appears on the bot's commit after merge.
- **Stripped the `TRRxxxx.PLAT.X —` name prefixes** and removed internal
  `Rule:` / `Chokepoint:` / `Severity rule:` / strategy references from descriptions.
- **Auth/precondition checks moved into a `dependencies` entry** (`prereq_command` /
  `get_prereq_command` with `dependency_executor_name: bash`), per house style — not inline in
  `command`.
- Helper scripts are invoked by the runner path token `$PathToAtomicsFolder/<ID>/src/...`.

T1098.006 specifics:

- Renamed every created object from the internal `trr9004-*` prefix to `atomic-t1098006-*` so
  cleanup matches exactly what each test creates.
- Fixed an undeclared-input reference (`#{source_dir}` was used but never declared) by switching
  to the `$PathToAtomicsFolder` runner token.

T1199 specifics:

- Reshaped from the dry-by-default `*_LIVE` / `--show-fixture` emulation into a real atomic: the
  `create` path performs the behaviour, a `gcloud` auth check gates it as a dependency, and
  `cleanup` removes the binding, provider, and pool.
- Parameterised the org, pool, provider, issuer, and bound role as `input_arguments`. The bound
  role defaults to the low-privilege `roles/browser` (the detectable shape — external
  principalSet bound with no attribute condition — is identical to the `roles/owner` form a real
  intrusion uses).

## Before filing

- **Contributor:** Jason Vasquez.
- **DCO / CLA:** none required. Atomic Red Team is MIT-licensed with no DCO check and no CLA bot;
  the only merge gate is maintainer review. (Verified against the wiki Contributing page, the PR
  template, and the repository's six workflows on 2026-10-13.)
- **Validate locally** (the actual CI gate) from a checkout of the fork:
  `cd atomic_red_team && PYTHONPATH=.. poetry run python runner.py validate`
- **Smoke-test the T1199 detonation** on a Google Cloud organization you control before (or at)
  PR time. It makes real `gcloud` calls that cannot run in this repo's CI, so it has not been
  executed end-to-end here — only its YAML and shell syntax are checked. The T1098.006 tests run
  against any cluster where you can write RBAC (a local kind/minikube cluster is enough).
- **One PR per technique.** `.yaml` extension; only `src`/`bin` subdirectories alongside it.

See [`../../UPSTREAM.md`](../../UPSTREAM.md) for the full three-project contribution plan.
