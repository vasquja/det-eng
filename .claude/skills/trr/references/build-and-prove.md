# Build & prove mechanics

Read this once you have a GO and the pinned telemetry. It is the how-to for turning a
vetted technique into green, reviewed detection artifacts. Everything here is enforced by
the repo's CI, so following it is what makes a PR mergeable.

## Contents
- [The proof contract](#the-proof-contract)
- [The pySigma backend and its gotchas](#the-pysigma-backend-and-its-gotchas)
- [Reusable rule patterns](#reusable-rule-patterns)
- [Fixtures and the validator MANIFEST](#fixtures-and-the-validator-manifest)
- [TRR README + DDMs (trr_lint)](#trr-readme--ddms-trr_lint)
- [Atomics](#atomics)
- [CI wiring](#ci-wiring)
- [Adversarial review](#adversarial-review)
- [Environment](#environment)

## The proof contract

For each rule, `detections/validate_cloud_detections.py` asserts, over committed fixtures:

> the recorded **attack** fixture makes the rule fire **and** the firing record carries the
> emulation **marker**; AND the **benign** baseline makes the rule fire on **nothing**.

The benign baseline must be **hard**: same log source / method / structural fields as the
attack, differing only on the discriminating field (the off-instance source IP, the
identity type, the public-vs-scoped principal, the `oidc.eks` provenance, etc.). A pass
then proves the rule keys on the technique's chokepoint and not on the fixture's shape or
marker. Add **provenance confounders** — look-alikes that must NOT fire (e.g. an EKS Pod
Identity call with empty `webIdFederationData`, a GitHub-OIDC exchange with a non-`oidc.eks`
provider) — to prove the discriminator, not just the IP.

Kubernetes/auditd TRRs use sibling validators (`validate_apiserver_detections.py`,
`validate_detections.py`) that run the real emulation on a live kind cluster / auditd VM in
CI rather than recorded fixtures.

## The pySigma backend and its gotchas

`detections/sigma_eval.py` compiles each rule with pySigma's SQLite backend and runs it
over events loaded into an in-memory table — so a rule passes only if its real Sigma
semantics match. Reproduce any behavior question with it directly:

```python
import sys, json; sys.path.insert(0, "detections"); import sigma_eval
q = sigma_eval.compile_rule("detections/sigma/<T...>/<rule>.yml")
ev = sigma_eval.flatten(json.loads(open("detections/cloud/fixtures/<trr>/attack.json").read())[0])
print(bool(sigma_eval.evaluate(q, [ev])))
```

- **`flatten()`**: nested dicts → dotted keys (`userIdentity.sessionContext.x`); lists →
  `json.dumps` text (so list contents are matchable with `|contains`); scalars kept
  (bools/ints preserved). An empty `{}` yields no key at all — so a rule keying on a field
  inside it simply does not match (this is how IRSA's non-empty `federatedProvider`
  excludes Pod Identity's empty `webIdFederationData`).
- **`|cidr`** compiles to a textual `LIKE '<prefix>%'`. IPv4 CIDRs on octet boundaries are
  exact; IPv6 only matches the canonical compressed lowercase form on a nibble boundary —
  document that in any IPv6 allowlist.
- **`|re`** works (a `REGEXP` function is registered, full Python `re`, look-around OK).

**The Sigma-wildcard trap (has bitten this repo twice).** In a plain value or `|contains`,
`*` is a Sigma WILDCARD. `|contains: '"AWS":"*"'` compiles to `LIKE '%"AWS":"%"%'` and
matches ANY named principal — a false positive. To match a LITERAL asterisk (a public
principal), use `|re` with an escaped star, and cover the array form:
`|re: '"(?:Principal|AWS)"\s*:\s*\[?\s*"\*"'`. Pair a public-principal match with an
`Effect":"Allow"` guard so a deny-only policy doesn't fire.

**Presence vs. value.** `field: '*'` is a PRESENCE test and matches an empty string too;
for non-empty use `|re: '.+'`. A field the provider serializes as a string when you expect
an int is a silent dead rule against real logs — e.g. Azure `resultType` is `"0"` (string)
in the diagnostic stream; match `|re: '^0$'` to catch int or string. CloudTrail normalizes
`requestParameters`/`responseElements` to **lowerCamelCase** even though the API model is
PascalCase — match `subjectFromWebIdentityToken`, not `SubjectFromWebIdentityToken`.

## Reusable rule patterns

- **Off-egress "used from a source we don't own"** (TRR9011, TRR9022): match the trusted
  provenance marker, then `not filter_<owned>_source` where the filter is a
  `sourceIPAddress|cidr` allowlist (RFC1918 + CGNAT + the account's NAT/EIP + IPv6 egress,
  as documented placeholders the operator baselines).
- **AWS service-source guard (REQUIRED on any off-egress allowlist rule).** An AWS service
  acting on behalf of a session logs `sourceIPAddress` as a service DNS name
  (`athena.amazonaws.com`) or the literal `AWS Internal`, which is neither RFC1918 nor an
  egress CIDR and would bypass the allowlist. Add, and AND into the condition:
  ```yaml
  filter_service_source:
    sourceIPAddress|endswith: '.amazonaws.com'
  filter_internal_source:
    sourceIPAddress: 'AWS Internal'
  ```
  It can never suppress a true positive — a real attacker always presents a client IP.
- **`not filter_failed` (`errorCode: '*'`)** to drop failed attempts where a successful
  action is the signal.
- **Provenance is not a detection.** Fields true of ~100% of benign activity (an
  `AssumedRole` type, a provider ARN) scope the rule; the discriminator is what fires it.
  Say which is which in the description.

## Fixtures and the validator MANIFEST

- Fixtures are schema-faithful recorded logs under `detections/cloud/fixtures/<trr>/`.
  Safe markers only: RFC 5737 TEST-NET IPs (`198.51.100.x` off-net, `203.0.113.0/24` as
  the allowlisted egress placeholder), RFC 2606 `example.com`, the AWS doc account
  `123456789012`, and `trr90NN-` resource names. The marker substring must appear in a
  field the rule's firing record carries.
- Register each rule in the `MANIFEST` in `detections/validate_cloud_detections.py`:
  `(TRR, folder, rulefile, attack.json, benign.json, provider, note, marker(substr, *fields))`.
  The `marker()` gate checks that at least one named flattened field of a firing attack
  record contains the substring.

## TRR README + DDMs (trr_lint)

`.github/scripts/trr_lint.py` (offline) enforces the tired-labs report shape. A README at
`research/trr<NNNN>/<platform>/README.md` must have, in order: `## Metadata` (table rows
ID, External IDs, Tactics, Platforms, Contributors; ID matches the folder),
`## Technique Overview`, `## Technical Background`, `## Procedures`,
`## Available Emulation Tests`, `## References`. (`Scope Statement`, `Detection Strategy`,
`Detections` are allowed extras.) Each procedure needs a `### ...` heading carrying a
`TRR<NNNN>.<PLATFORM>.<LETTER>` ID and a `#### Detection Data Model` subsection embedding a
`ddms/*.png`. `research/index.json` must have a matching entry (id + procedure keys).

**DDMs** are Arrows-app JSON (`ddms/<trr>_<plat>_<letter>.json`: `style`, `nodes` with
`position`/`caption`/`labels`/`properties`/`style`, `relationships`). Render with
`python3 research/tools/render_ddm.py <json...>` — it draws the PNG and stamps the JSON's
sha256 into it; `--check` verifies freshness without a browser (trr_lint runs `--check`).
Convention: green border = unlogged theft, blue border + yellow fill = the CloudTrail
chokepoint, black = outcome, grey = out-of-scope/gap.

## Atomics

The repo's `atomics/<T...>/` copy is det-eng staging shape: dry-by-default with a
`TRR90NN_LIVE=1` guard for the real (operator-account) run and a `--show-fixture` that
prints the committed fixture. ART format (`attack_technique`, `display_name`,
`atomic_tests[]` with `supported_platforms` `iaas:aws`/`iaas:azure`/`iaas:gcp`/`containers`,
`executor`). Keep GUIDs unique; `bash -n` clean. (The upstream-shaped copy differs — see
`references/upstream.md`.)

## CI wiring

Three workflows gate PRs: `validate-detections.yml` (auditd loop + `sigma check` +
`markdown-links`, runs on every PR), `validate-cloud-detections.yml` (the fixture loop,
**path-filtered** — add the new `detections/sigma/<T...>/**` and `atomics/<T...>/**` globs
to both the `push` and `pull_request` `paths:` lists), and `lint-trr.yml`.

Run locally before pushing:
```bash
python3 detections/validate_cloud_detections.py            # attack fires + benign clean
sigma check -x attacktag -x d3_fendtag -x cartag -x detection_tag detections/sigma/<T...>/
python3 .github/scripts/trr_lint.py
python3 .github/scripts/check_md_links.py
```
The `sigma check` exclusions matter: the egress proxy blocks the ATT&CK/D3FEND/CAR tag
downloads those validators need, so exclude them locally; they re-run server-side.

## Adversarial review

Before a PR is "done", run a skeptic pass — per rule, per fixture, per README — and
**reproduce every finding against `sigma_eval.py`** (a crafted variant event that should or
shouldn't fire). Fan out one dimension per subagent. This has repeatedly found real
defects in rules that already passed CI: a dead int-vs-string match, a Sigma-wildcard
false positive, a service-source bypass, an over-claimed novelty line. Fix the root cause,
re-validate, then push.

## Environment

A fresh container may lack pySigma. Install with:
```bash
pip install --quiet --ignore-installed PyYAML==6.0.3 pySigma==1.5.1 pySigma-backend-sqlite==2.0.0
pip install --quiet --ignore-installed sigma-cli    # for `sigma check`
```
Chromium for `render_ddm.py` is preinstalled (`PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers`);
do not run `playwright install`.
