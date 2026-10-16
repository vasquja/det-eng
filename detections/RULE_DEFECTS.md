# Rule defects and gaps

This is the one tracker of every known rule defect, false negative, dead filter and
audit-policy gap: what the near-miss cases, the benign corpus and the live captures
showed and a rule fix has not closed yet. Each problem below stays in the rule until
a pull request fixes it, with a case that proves the fix.

A sidecar case, a budget `why` or a doc that says a defect is "tracked" points here,
by entry ID (for example `L14`). IDs are not reused: a closed entry's ID stays retired.

## How to read an entry

- **Kind**: *false positive* (fires on benign activity), *false negative* (misses
  the technique), *evasion* (a filter or match that an attacker controls), *dead
  filter* (an allowlist entry that matches nothing real), *policy gap* (the audit
  policy does not record what the rule needs), *description* (the rule text claims
  what the rule does not do).
- **Severity**: *high*: the rule misses a common variant of its technique, or a
  high-level rule fires on routine activity of most hosts or clusters. *medium*: a
  narrower miss, or routine noise in a common setup. *low*: a portability caveat, a
  description mismatch or a rare path.
- **Evidence** names where to look:
  - *case*: a case in the rule's sidecar `<rule>.cases.jsonl`;
  - *corpus*: a slice of the [benign corpus](benign/README.md), with the hits and
    actors that [`benign/scores.json`](benign/scores.json) records at commit `00216e3`
    and the rule's `why` in [`benign/budgets.json`](benign/budgets.json). The slices
    are synthetic, so a count is a presence indicator, not a production rate;
  - *CI capture*: the `benign-linux-live` job (detection-quality run 38692762582,
    commit `a95a35c`) recorded a real Ubuntu runner workload
    ([`benign/linux/workload.sh`](benign/linux/workload.sh)) and annotated each Linux
    rule's hits. The per-process detail is in that run's `linux-benign-capture`
    artifact. No rule changed between that commit and this one;
  - *probe*: an event (set) that was run through the rule with the real pySigma
    backend (`sigma_eval.py`) on the current rule, with the result shown. Reproduce
    one with the snippet in [Reproducing a probe](#reproducing-a-probe);
  - *source*: the upstream source that shows the real behaviour, as the reviewer read
    it. Where nothing in this repository recorded the real telemetry, the entry says
    **unverified**.
- **Fix** is the proposed change. **Then** says which case or budget changes once the
  fix lands, so the fix is proven, not just claimed.

## Summary

| ID | Rule | Problem | Kind | Severity |
|----|------|---------|------|----------|
| [L14](#l14-exe-and-comm-allowlists-trust-the-binary-not-the-code-in-it) | three Linux rules | allowlisted tools that ordinary users run (kcapi, debuggers) hide injected code | evasion | medium |
| [K4](#k4-k8s_admission_webhook_neutered-neuters-the-audit-record-cannot-show) | `T1685/k8s_admission_webhook_neutered` | never-matching selectors, merge-patch list replacement, key-order dependence | false negative, false positive | low |
| [K9](#k9-k8s_coredns_corefile_poisoned-what-the-root-scoped-grader-does-not-grade) | `T1565.001/k8s_coredns_corefile_poisoned` | creates, stub zones and imports are seen by the chokepoint only | description, policy gap | low |
| [K13](#k13-no-rule-matches-a-namespace-delete) | `T1070/k8s_events_deleted` | a user's namespace delete (which destroys its Events) matches no rule | false negative | low |
| [C6](#c6-gcp_workforce_principalset_privileged_binding-group-scoped-admin-grants-fire) | `T1199/gcp_workforce_principalset_privileged_binding` | group-scoped grants of any admin role fire | false positive | medium |
| [C12](#c12-aws_cognito_unauthenticated_identity_use-keyed-on-the-consoles-role-name) | `T1078.004/aws_cognito_unauthenticated_identity_use` | a renamed guest role is a miss | false negative (documented) | low |
| [C13](#c13-entra_app_federated_credential_backdoor-a-credential-removal-fires) | `T1098.001/entra_app_federated_credential_backdoor` | the issuer regex also reads `oldValue`, so a removal fires | false positive (unverified) | low |
| [C14](#c14-aws_resource_policy_made_public-a-single-statement-object) | `T1537/aws_resource_policy_made_public` | a policy whose `Statement` is one object, not a list, misses | false negative | low |

## Linux (auditd and node file events)

### L14. Exe and comm allowlists trust the binary, not the code in it

- **Rules**: [`copyfail_af_alg_authencesn`](sigma/T1068/copyfail_af_alg_authencesn.yml) (level high),
  [`ptrace_traceme`](sigma/T1622/ptrace_traceme.yml),
  [`setns_namespace_join`](sigma/T1611/setns_namespace_join.yml).
- **Kind**: evasion. **Severity**: medium (the copyfail gap is an unprivileged path to
  a high rule); low for the others.
- **Already fixed**: the auditd events and the Linux corpus carry `uid`, `euid` and
  `auid`, and the entries for tools that always run as root require `euid` 0
  (`keyring_add_key_burst`, `memfd_create_execveat`, `bpf_prog_load`'s runc entry,
  `perf_event_open_non_profiler`'s system-probe). Code an ordinary user injects into
  those tools now fires (cases `ldpreload-into-cryptsetup-known-miss` and
  `ldpreload-into-runc-as-exe-known-miss`, now positives).
- **Problem** (what remains):
  1. `copyfail_af_alg_authencesn` `kcapi_hash_tools`: any user runs the libkcapi
     hash tools, and auditd does not decode the AF_ALG cipher name, so an
     unprivileged `LD_PRELOAD` into `kcapi-hasher` or `kcapi-dgst` still hides the
     CopyFail sequence.
  2. `ptrace_traceme` `debugger_images`: gdb, gdbserver and lldb-server run as any
     user, so no id separates a debugger's inferior from injected code.
  3. `setns_namespace_join` `runtime_images` has no `euid` condition by design: an
     unprivileged setns cannot join a namespace it does not own, and rootless runc
     runs as the user.
  4. Every entry: a process that already has `euid` 0 (including root in a container
     without user-namespace remapping) can still inject into an allowlisted binary or
     place a binary at the logged path.
  5. The snap-confine entries (`bpf_prog_load`, `setns_namespace_join`) have no `euid`
     condition, because snap-confine runs as the caller on snapd 2.70 and later.
     Secure-execution mode blocks injection into the real binary, but any user who
     can create a user namespace can run their own binary at a snap-confine path, so
     an unprivileged BPF socket-filter load (with `unprivileged_bpf_disabled=0`) is
     hidden. Remove the snap-confine entries on hosts without snapd.
- **Evidence**: cases `ldpreload-into-kcapi-hasher-known-miss`,
  `ldpreload-into-gdb-known-miss` and `snap-confine-path-in-user-namespace-known-miss`
  (filtered, KNOWN MISS).
- **Fix**: remove the kcapi filter on hosts without the libkcapi tools; baseline
  debugger use per host. No Sigma-level fix is known for 1 and 2.
- **New false positives, documented in the rules**: rootless runc < 1.2 fires
  `memfd_create_execveat` on every container start and exec; a user running
  `cryptsetup open --test-passphrase --link-vk-to-keyring` (cryptsetup 2.7.1 and
  later) fires `keyring_add_key_burst` once per key.

### Live-capture hits not yet attributed

The CI capture also annotated two rules that this tracker does not call defective:
`T1040/afpacket_raw_socket` (2 hits; enforce at 0 on the corpus, so a real fire would
fail if the capture were a committed slice) and `T1040/afinet_raw_socket` (5 hits). The
workload's AF_PACKET users are `tcpdump` (allowlisted) and `arping` (not in
`sniffer_processes`); its raw-socket user is `mtr` (the documented `mtr-packet` noise
in budgets.json). Read the run's `linux-benign-capture` artifact before you decide
whether `arping` belongs in the allowlist.

## Kubernetes (API server audit and CRI)

### K4. k8s_admission_webhook_neutered: neuters the audit record cannot show

- **Rule**: [`sigma/T1685/k8s_admission_webhook_neutered.yml`](sigma/T1685/k8s_admission_webhook_neutered.yml) (level high).
- **Kind**: false negative, false positive. **Severity**: low.
- **Problem**: the rule cannot tell these from a legitimate edit: a
  `namespaceSelector`/`objectSelector` that matches nothing; a `matchConditions`
  expression that is always false but is not the literal `false`; a `--type=merge`
  patch that replaces the webhooks list with a webhook that has no `rules` key (the
  patch type is not logged); a JSON patch that replaces the whole list and drops
  `rules` for only some webhooks. Its update branch (`sel_rules_omitted`) assumes the
  API server's Go field order, so it fires on every full-object update if the log
  pipeline sorts keys.
- **Evidence**: the rule's description and falsepositives ("Key order").
- **Fix**: needs the cluster's labels or the old object (enrichment); none planned in
  Sigma.

### K9. k8s_coredns_corefile_poisoned: what the root-scoped grader does not grade

- **Rule**: [`sigma/T1565.001/k8s_coredns_corefile_poisoned.yml`](sigma/T1565.001/k8s_coredns_corefile_poisoned.yml) (level high).
- **Kind**: description, policy gap. **Severity**: low.
- **Problem**:
  1. The `create` verb grades only under a policy that logs ConfigMap creates at
     Request. The shipped policy logs a create at Metadata, so a delete-and-recreate
     of `coredns` is seen by the chokepoint only.
  2. The forward-to-IP clause grades only the root server block. A stub zone or a
     domain-scoped forward to an IP is graded by the chokepoint only, because its
     record does not differ from a private stub zone.
  3. The clause does not follow `import` (snippets or files), reads at most three
     nested brace levels, and does not treat a quoted `"{"` token as a brace.
- **Evidence**: confounders `poisoned-but-wrong-name`, `-wrong-namespace`,
  `-verb-delete`; near-misses `private-stub-zone-forward`,
  `jsonpatch-private-stub-zone-forward`.
- **Fix**: none planned for 2 and 3; 1 is a policy-scope decision.

### K13. No rule matches a namespace delete

- **Rule**: [`sigma/T1070/k8s_events_deleted.yml`](sigma/T1070/k8s_events_deleted.yml) (and none other).
- **Kind**: false negative. **Severity**: low.
- **Problem**: deleting a namespace destroys its Events. The namespace controller's
  sweep is filtered as teardown, and the actor's own `delete` of the namespace is
  matched by no rule (except `k8s_security_tool_workload_removed` for
  gatekeeper-system, kyverno and falco).
- **Evidence**: case `namespace-delete-known-miss` (confounder, KNOWN MISS); corpus
  `k8s-audit-gitops-ci`, where a CI deployer deletes `preview-pr-*` namespaces
  routinely.
- **Fix**: a low-level hunting rule on `namespaces` `delete` that baselines lifecycle
  identities; its budget is a human decision.
- **Then**: relabel `namespace-delete-known-miss` as that rule's positive.

## Cloud (AWS, Azure, GCP)

### C6. gcp_workforce_principalset_privileged_binding: group-scoped admin grants fire

- **Rule**: [`sigma/T1199/gcp_workforce_principalset_privileged_binding.yml`](sigma/T1199/gcp_workforce_principalset_privileged_binding.yml) (level medium).
- **Kind**: false positive. **Severity**: medium.
- **Problem**: a grant of any role containing `admin` to a group- or attribute-scoped
  workforce principal set fires. The description now says so. Requiring a whole-pool
  member would drop TRR9020 Procedure C, whose backdoor scopes are exactly
  `/group/<id>` and `/attribute.NAME/VALUE`.
- **Evidence**: corpus `gcp-iam-federation-admin` (terraform granting
  `roles/container.admin` to one IdP group); budgets.json `why`.
- **Fix**: a narrower privileged-role list, or a baseline of approved groups; a
  human decision.

### C12. aws_cognito_unauthenticated_identity_use: keyed on the console's role name

- **Rule**: [`sigma/T1078.004/aws_cognito_unauthenticated_identity_use.yml`](sigma/T1078.004/aws_cognito_unauthenticated_identity_use.yml) (level medium).
- **Kind**: false negative (documented). **Severity**: low.
- **Problem**: the rule finds the guest role by the console's naming
  (`Cognito_<pool>Unauth_Role`, Amplify's `...-unauthRole`), so a pool whose guest role
  has a site-specific name is missed. The rule's description says so.
- **Evidence**: the `PLATFORM_NAMING` waiver in
  [`check_sufficiency.py`](check_sufficiency.py) keeps only `Unauth` through the
  rename test for this reason.
- **Fix**: find a signal of a guest identity that does not depend on the role name;
  until then the waiver and the description stay.

### C13. entra_app_federated_credential_backdoor: a credential removal fires

- **Rule**: [`sigma/T1098.001/entra_app_federated_credential_backdoor.yml`](sigma/T1098.001/entra_app_federated_credential_backdoor.yml).
- **Kind**: false positive (unverified). **Severity**: low.
- **Problem**: the issuer regex reads the whole `targetResources` text, including
  `oldValue`, so removing a federated credential with an unapproved issuer fires.
- **Evidence**: reported by the cloud rule-fix review; no recorded removal event.
- **Fix**: key on `newValue` only, once a removal record's shape is documented.

### C14. aws_resource_policy_made_public: a single statement object

- **Rule**: [`sigma/T1537/aws_resource_policy_made_public.yml`](sigma/T1537/aws_resource_policy_made_public.yml) (level high).
- **Kind**: false negative. **Severity**: low.
- **Problem**: a policy whose `Statement` is one object rather than a list flattens to
  `...Statement.*` field names that the rule does not read. It also missed before
  the per-statement fix.
- **Evidence**: reported by the cloud rule-fix review.
- **Fix**: read both flattenings, with a positive case for each.

## Checks to add

- `T1098.001/entra_app_federated_credential_backdoor` warns as thin (R5): it needs a
  near-miss that keeps the unapproved-issuer item and breaks only `targetResources`
  `FederatedIdentityCredentials`. No documented Entra record of that shape is known.

## Closing an entry

1. Fix the rule. If check-sufficiency waives the rule (`CHOKEPOINT`, `PRESENCE`,
   `COMPILE_ONLY`, `PLATFORM_NAMING`), the edit changes its digest, and a human
   re-approves the waiver.
2. Turn the evidence into a case: the probe or the KNOWN MISS confounder becomes a
   positive (false negative), or a filtered, near-miss or benign case (false
   positive). Relabelling or editing an existing case (its kind, `breaks` or events)
   fails `sufficiency-ratchet` on the pull request, which is a human's decision (the
   `automerge` bot turns its auto-merge off when it sees the failure); a new case,
   or a reworded `why`, does not.
3. Run `rule_cases.py`, `check_sufficiency.py`, the rule's validator and
   `score_benign.py --check --enforce`; regenerate `scores.json` with `--update`.
4. Propose the lower budget (`score_benign.py --reseeds 10`) in `budgets.json`,
   which a human approves, and update its `why`.
5. Delete the entry here, and the pointer to it in the sidecar `why`.

## Reproducing a probe

```python
import sys; sys.path.insert(0, "detections")
import sigma_eval, sigma_explain
rule = "detections/sigma/T1068/dirtyfrag_xfrm_unshare_netlink.yml"
base = {"type": "SYSCALL", "success": "yes", "pid": 500, "comm": "x", "exe": "/x"}
events = [dict(base, syscall="unshare", a0="50020000", timestamp="2026-10-12 14:00:00.000"),
          dict(base, syscall="socket", a0="10", a1="3", a2="6", timestamp="2026-10-12 14:00:00.100")]
flat = [sigma_eval.flatten(e) for e in events]
print(bool(sigma_eval.evaluate(sigma_eval.compile_rule(rule), flat)))            # False: L3
print(sigma_explain.judge_events(sigma_explain.load(rule), flat)[0].kind)        # near-miss
```
