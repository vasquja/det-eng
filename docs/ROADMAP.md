# Roadmap

The ordered work for this repository. An AI agent owns and maintains the codebase
(see [`AGENTS.md`](../AGENTS.md)). This file is how one session tells the next
what the direction is.

Last update: 2026-11-18.

## The goal

One owner, little direction. The agent researches, emulates and writes detections.
Coverage grows quickly, and CI, not a person who reads each pull request, shows
that a detection works.

The reasons for each item are in two design records:

- [`design/2026-11-09-design-review.md`](design/2026-11-09-design-review.md): what
  is wrong today, with evidence.
- [`design/2026-11-09-operating-design.md`](design/2026-11-09-operating-design.md):
  the target design. Its sections are cited below as "design 4.2".

## How to use this file

- First read each item that is `in progress`. If its acceptance check is true on
  `main`, set it to `done` in your pull request.
- When you have no other task from a person, take the first item below that is
  `not started` and whose "needs" are `done`. Work top to bottom.
- One item for each pull request. Keep the pull request small enough to review.
- Change the status of the item in the same pull request. Add what you learned
  under the item if it changes a later item.
- An item is `done` only when its acceptance check is true on `main`.
- Do not set an item to `done` while
  `python3 -B detections/tests/gatelib.py --gaps` lists a gap that it closes.
- The gate tests read section 1 of this file (`detections/tests/test_suite.py`,
  class `KnownGapList`). When you add, remove or rename an item of section 1,
  change the table `ROADMAP` in `detections/tests/gatelib.py` in the same pull
  request. Write only a status word in the Status cell, and put a reason in the
  Needs cell.
- If you find that an item is wrong, change the item and say why in the pull
  request. The direction is yours to correct.
- Do not start an item marked `owner`. Tell the owner what it waits for.

Status words: `done`, `in progress`, `not started`, `owner` (only the owner can do
it), `blocked` (with the reason in the Needs cell).

## 1. Trust: make a green run mean something

The order matters. Tests for the gates come before each change to the gates.

| ID | Item | Status | Needs | Acceptance check |
|----|------|--------|-------|------------------|
| R2 | **The gates test themselves** (design 4.2). A set of planted bad artifacts that each gate must reject, and a CI job that runs it with the self-tests that no workflow runs today. | done | | A job on each pull request fails when a gate stops rejecting a planted artifact. Each planted artifact is rejected for its intended reason, not for a side effect. The suite is `detections/tests/` and the job is `gate-tests`. The item is `done` when that job is green on `main`. |
| R2b | **Linux controls are not vacuous** (design 4.2). The Linux validator grades each control. The no-op stays on every rule as a baseline: it makes one audited syscall, its record fires no rule, and it must own that record. It declares no item, so the validator never counts it as the live negative control of a rule. Each mutant and each re-run under an allowlisted name declares what holds it: one required item of the rule (an argument item, the group-by of a correlation, an allowlist filter), or the success gate of the validator for a call that the kernel rejects. A control that is not held by what it declares fails the run. There is one exception: the mutant of a rule whose every emulation is a SKIP on the host is `N/A` when the kernel rejected one or more of the calls of the mutant that the rule reads. Each of the seven rules that had only the no-op gets a mutant: five make the syscall that the rule reads with one wrong argument, and two make a call that the kernel rejects (`userfaultfd_syscall.yml` and `io_uring_setup.yml` read no argument, so that control tests the success gate and no item of the rule). | done | R2 | In the job `validate` on `main`, each rule of the `MANIFEST` of `detections/validate_detections.py` has a control row, other than its no-op row, that prints `held`: the validator holds that control by the one item that it declares, or by its success gate for a rejected call. The run fails on a no-op that left no record, on a mutant or a re-run that is not held as declared or that cannot be graded, on a rule for which no control is built, and on a bad row of the `CONTROLS` table (before a stimulus runs); the gate tests hold each of these rejections. The item is `done` when that job is green on `main`. |
| R2c | **Negative controls and baselines cannot be empty** (design 4.2). A negative control that read no record cannot fail, so it proves nothing. A record is what the loader of the validator returns: for a Kubernetes log, the number that the `Loaded N ...` line prints (the JSON objects of the lines that are not blank; one sandbox for each sandbox object of a CRI log, by id), and for a cloud fixture, the records of the file. With `--expect-miss`, each Kubernetes validator exits 1 when a pre-emulation log is not given (`--audit-log` has no default in this mode) or does not exist. `validate_k8s_detections.py` also exits 1, before it judges a rule, with `NEGATIVE CONTROL FAILED: the pre-emulation audit log <path> holds no audit event (0 records read from N non-blank line(s))`. `validate_staticpod_detections.py` fails an audit log without an audit event with a `CONTROL FAILED` line; its CRI control and its file control failed a CRI log without an API-scheduled sandbox and a file log without a kubeadm write before this item, and the line of each failure now names the log and the number of records that it holds. `validate_apiserver_detections.py` prints one `NEGATIVE CONTROL FAILED` line for each of the audit log, the CRI log and the file log that holds no record. Its file log is the audit trail of one watched token file, and a healthy capture can hold no read of that file, so the capture step of `validate-apiserver-detections.yml` also converts the canary read of `ca.crt` (audit key `k8s_node_canary`) into the pre-emulation file log. `validate_cloud_detections.py` gives a FAIL row with `NEGATIVE CONTROL VACUOUS` to a rule whose benign baseline holds no record (`[]`, a file of zero bytes or of blank lines, an envelope with an empty list), and an ERROR row to a rule of `MANIFEST` whose attack or benign fixture is not a file. Each of the two fails the run, also with `--report`. Not covered: a Kubernetes log whose lines are JSON objects and not records of the log (a log of `{}` lines passes; R2d closes that, see its known gap `k8s-log-object-not-an-audit-event`); a cloud baseline whose records are all far from the rule (`[{}]`; R2e closes that: the cloud validator fails it as `NOT HARD`); a mirror-pod create of the control-plane baseline in the audit log of the static pod validator; a strict Kubernetes run without a log, which prints SKIP and exits 0 (for a local run without a cluster); a `MANIFEST` entry of the cloud validator whose rule file does not exist, which is PENDING and not counted (`check_sufficiency.py` fails that tree). How near the records of a live capture are to a rule is not a claim of the Kubernetes negative control: the near-miss of each rule is proven by its rule cases (item 3 of the definition of done). | done | R2 | Its known-gap tests are rejection tests. Each validator exits with an error that names the empty log, the empty baseline or the missing fixture. The jobs `validate-k8s`, `validate-staticpod`, `validate-apiserver` and `validate-apiserver-recommended` are green on `main` with these checks: only a kind cluster shows that each pre-emulation log of a healthy run holds a record, and that the capture step of the API server lab writes the canary read into the file log (see the note for R2c below). The item is `done` when those jobs are green on `main`. Done: on `main` at `947055a` the four jobs passed (runs 43657464092, 43657464124 and 43657464068). Each pre-emulation log held records: `validate-k8s` 885 audit events; `validate-staticpod` 389 audit events, 11 pod sandboxes and 4 file events; `validate-apiserver` 1488 audit events, 9 pod sandboxes and 1 file event; `validate-apiserver-recommended` 1482 audit events, 9 pod sandboxes and 1 file event. In both API server jobs the capture step wrote the canary read into the file log (`1 event(s) with the key k8s_node_canary; wrote 1 file event(s)`). |
| R2d | **Hygiene and report truth** (design 4.2). No rule file is hidden from the gates: a rule in a dotfile under `detections/sigma/` fails. The coverage report refuses an entry of `detections/RULE_DEFECTS.md` that has a section and no Summary row, and names the entry (also an entry with a row and no section, and an ID with two rows or two sections). `rule_cases.py` names the rule and the case when two keys of an event differ only in letter case, and does not stop with a traceback. The loaders of the three Kubernetes validators and of the cloud validator do the same for a record that is JSON and not an object: they name the log and the line (a `[]` line of an audit, CRI or file log), or the rule and the fixture (a fixture of `null`, or a `null` record of a fixture), and do not stop with a traceback. A line that is a JSON object and not a record of its log (`{}` in an audit, CRI or file log) is named and not counted. The loaders also name the log or the fixture, and do not stop with a traceback, for a Kubernetes log that is a directory, for a log or a cloud fixture that is not UTF-8, and for a cloud fixture that starts with a byte order mark. The readers of the Kubernetes validators and of `score_benign.py --extra-slice` name each line that json refuses, except the last line of a log when it has no line end (a line feed, or a carriage return alone) and is cut JSON, the start of one JSON object without its end (`sigma_eval.cut_json()`, also when the cut splits a character of UTF-8): a capture can cut only that line (NUL bytes or U+200B before a record, and a record with more text after it on the last line, gave a false PASS of the negative control before). (A cloud fixture that is a directory is an ERROR row since R2c.) A ledger window whose start is after its end is an error that names the procedure and the two times, not a `MISS` of the rule: on 2026-11-13 a wrong clock of the runner image gave such windows, and the validators reported misses of rules that matched. The verdict line of the API server validator names every TRR that `MANIFEST` grades (today it leaves out 9039). The event table of `sigma_eval.py` does not refuse a valid log: keys that differ only in the letter case of their ASCII letters, in two records, share one column, as SQLite reads a field. One record with two such keys, a key `rowid` or `_rowid`, a key with a NUL or a lone surrogate, or a value that SQLite does not hold as it is (an integer outside 64 bits, `NaN` or `Infinity`, a text with a lone surrogate) is an error of the table, and each loader names it first, with the test of the table: the log and the line, the fixture and the record, the slice and the event (of each slice, also one that no rule reads), or the rule and the case. The analysis of a correlation in the gates reads its group-by fields and its time as the table does. The cloud loader also names a fixture of JSON that is not an array or an object, an envelope whose list is not a list (also on a line of JSON lines: the loader reads each line as it reads the one object of a file, so the list of an envelope on a line gives the records of the line), an envelope that holds a key beside its list other than these page keys, each with a value of its type: `nextLink`, `@odata.context`, `@odata.nextLink`, `@odata.deltaLink` and `nextPageToken`, each a string or null, and `@odata.count`, an integer of 64 bits (the loader reads only the list, and an attack record with `"items": [<a benign record>]` would give a clean baseline; any other list page, such as Google Workspace Reports, a GCP compute list, a kubectl `List`, Azure DevOps or the legacy Azure AD Graph, is written as a JSON array), a line that is not JSON (a line ends at LF), and JSON that is too deep or a number that is too long (by its record), and the gates that read the fixtures with it (`check_null_safety.py`, `check_sufficiency.py`, `check_variants.py`) name the fixture too. Each loader of records or cases refuses an object that holds one key two times and names its place: the cloud loader, the readers of the Kubernetes validators, `score_benign.py` (its slices and `--extra-slice`), `rule_cases.py` (and the gates that read the sidecars with it) and the anchors of `check_provider_mappings.py`. json keeps only the last value of such a key, so a benign fixture `{"Records": <attack records>, "Records": <benign records>}` gave a clean baseline before. Each of these loaders also refuses a record whose two keys give one field (`{"a.b": X, "a": {"b": Y}}`: `sigma_eval.flatten()` keeps only one value, and `sigma_eval.event_problem()` names the field), so a benign baseline, a pre-emulation log, a case or a slice cannot hide a firing value under a dotted key; a native event that an anchor of `check_provider_mappings.py` evaluates (for a rule that the anchor names, or in a `must_hold`, `must_not_hold` or `known_differences` probe) ends the gate with a traceback of the `EventError` of the table (no hit is lost, but the gate does not name the anchor), and a native event that is only converted is not checked for it (no rule reads it). | done | R2 | Its known-gap tests are rejection tests. Each gate exits with an error that names the hidden file, the defect entry, the case, the log, the log line or the fixture. For a log line that is not a record, the rejection tests must cover each of the three Kubernetes validators and each log of that validator (audit, CRI, file). The two known gaps of such a line (`k8s-log-line-not-an-object`, `k8s-log-object-not-an-audit-event`) have `validate_k8s_detections.py` as their gate: each closes when that validator alone is corrected, and its assertions about the other two validators run only while the gap is open. The four kind jobs are green on the pull request and on `main` and print no ERROR line from the log readers (see the note for R2d below). Pull request 3/3 is the last pull request of the item: the item is `done` when the four kind jobs are green on `main` with it. Done: on `main` at `55ec270` the four jobs passed (runs 44022123643, 44022123646 and 44022123589), and no log reader printed an ERROR line. Each pre-emulation log held records: `validate-k8s` 908 audit events; `validate-staticpod` 392 audit events, 11 pod sandboxes and 4 file events; `validate-apiserver` 1442 audit events, 9 pod sandboxes and 1 file event; `validate-apiserver-recommended` 1519 audit events, 9 pod sandboxes and 1 file event. The logs after the emulation: 1018 audit events (`validate-k8s`); 407 audit events, 14 pod sandboxes and 8 file events (`validate-staticpod`); 5016 audit events, 37 pod sandboxes and 1 file event (`validate-apiserver`); 5061 audit events, 35 pod sandboxes and 1 file event (`validate-apiserver-recommended`). The collect step of `validate-staticpod` removed no cut line. |
| R2e | **Cloud baselines are hard** (design 4.2). The cloud validator fails a benign baseline in which no record is a near-miss or a filtered negative of its rule (`AGENTS.md`: a hard benign baseline differs from the attack only in the discriminating field). A record counts only through a flip item that some marked attack hit differs from it on (the item holds on the one and fails on the other), that is a filter, reads a field outside `SURFACE_FIELDS` or belongs to a rule in `CHOKEPOINT` (both of `check_sufficiency.py`), and that, for a filter, does not hold on the record only through documentation addresses (RFC 5737, RFC 3849: the placeholders of an allowlist). For a correlation rule, only a near-miss set on a base atom counts. The row is `NEGATIVE CONTROL NOT HARD`, and a baseline that sigma_explain cannot grade gets `NEGATIVE CONTROL NOT GRADED` (fail closed). Each fails the run, also with `--report`. Two baselines got one hard record each: `trr9036` (the attack's Start record with Reader in place of Owner) and the exchange rule of `trr9022` (the attack's exchange with the issuer of a self-managed cluster in place of the EKS provider; its only filtered record came from the `203.0.113.0/24` placeholder). Not covered: one hard record is the bar for a rule, not one for each branch; a hard record need not be a copy of an attack record; for a correlation, the items of a base, and a set that only lacks the event of a base; a near-miss on the top-level `resultType` of the Azure Activity Log, which `SURFACE_FIELDS` does not list; `check_sufficiency.py` still counts a fixture record that only a placeholder filters as a verified negative. | done | R2c | Its known-gap test is a rejection test. The baseline of `trr9036` (`azure_privileged_role_assignment.yml`: the validator grades both of its records `distant`, so none is a near-miss or a filtered negative of the rule) is corrected or has an entry in `detections/RULE_DEFECTS.md`. The job `validate-cloud` is green on `main` with the check. The item is `done` when that job is green on `main`. Done: on `main` at `ff195be` (the merge of #81) the job `validate-cloud` passed (run 43999382927), and it passed in each later push run of `validate-cloud-detections.yml` on `main` (the last at `70c8bdb`, run 44150287970). Each of these runs printed 32 `PASS` rows, each with a graded benign baseline, and no `NOT HARD`, `NOT GRADED` or `VACUOUS` row. The baseline of `trr9036` is corrected: it holds a near-miss record (`1 near-miss, 2 distant`). The known gap of the item is the rejection test `test_validators.CloudValidator.test_rejects_benign_baseline_far_from_the_rule`. |
| R7 | **Representation variants in the oracle** (design 4.7). Run each case as compact JSON, sorted JSON, a multi-valued list model, case-sensitive `LIKE` and RE2. Correct the two GCP rules that lose their hit under compact JSON. Write `detections/SEMANTICS.md`. | done | R2 | A check fails on a new divergence between variants. The known losses are listed as expected, each with a reason. Two rules lose their hit under compact JSON today: `T1199/gcp_workforce_principalset_privileged_binding.yml` and `T1098.001/gcp_workload_identity_federation_sa_binding.yml`. This item records both in `detections/RULE_DEFECTS.md` and corrects them. Done: #76 added the check `detections/check_variants.py` (the job `representation-variants` of `detection-quality.yml`) and its expected list `detections/variants/expected.json`, in which each known loss has a reason; it recorded the two compact-JSON losses in `detections/RULE_DEFECTS.md` (entry C17, closed: both rules are corrected), and it wrote `detections/SEMANTICS.md`. On `main` at `3d265bc` the run 43722669388 of `detection-quality.yml` passed, with the job `representation-variants`. |
| R3 | **External records** (design 4.3). Records that the agent did not write, from `splunk/attack_data` (Apache-2.0), pinned by hash. A same-technique record must fire the rule unless a protected file says why not. | in progress | R2 | The check runs in CI in shadow mode and reports each rule's result on each same-technique dataset. The first real-record miss has a defect entry. The item is `done` when the job `external-records` is green on `main`, that defect entry is merged, and `gatelib.py --gaps` lists no gap that names R3 (see the note for R3 below). |
| R3b | **External records are enforced** (design 4.3). After a green shadow period, the job `external-records` runs `--enforce` and is a required check. `SOURCES.json` pins the attack record of each dataset, and a FIRE must come from that record and not from a benign twin of the dataset (the FIC dataset of T1098.001 holds one). Item 1 of the definition of done (`AGENTS.md`, "Fires") names the same-technique external records. A pair that was read on the base branch and is `NOT READ` on the head fails (a change of the log source of a rule hides a `MISS`), and the online run checks the sha256 and the yml of each `excluded` entry too. | not started | R3 | The job runs `--enforce` and is in the ruleset. A hit on a record that is not a pinned attack record is not a FIRE: the known-gap test `ext-fire-on-another-record` is a rejection test. |
| R3c | **A benign view of the external records** (design 4.3). Each rule is scored, as a shadow benign slice, on every dataset of its log source and not only on the datasets of its technique: also on the files that no yml names, deduplicated by sha256 and by event (a file can hold each event two times). A hit is a triage item for a human, never a budget. | not started | R3 | The report gives a row for each hit of a rule on a dataset of another technique. It never changes `detections/benign/scores.json` or `budgets.json`. |
| R4 | **Harvest the captures of CI** (design 4.4). The lab validators write the records that the kernel or the API server produced. A scheduled job commits them as evidence. | not started | R2, T8 | A Linux or Kubernetes rule has a committed captured positive that the agent did not write by hand. |
| R5 | **Provenance tiers** (design 4.5). Each case and fixture says where it came from. The coverage report shows `proven-live`, `proven-recorded`, `proven-synthetic` and `claimed`. Stop calling a hand-written fixture "recorded". | not started | R3 | The coverage report does not call a cloud procedure Proven when its only evidence is a fixture that the agent wrote. |
| R6 | **Mutation ratchet** (design 4.6). Each change to a rule is proven by its evidence: each change to the logic of a rule, undone alone, must change a verdict on a case, a fixture or a corpus record of the head (`detections/check_mutants.py`, a step of the job `sufficiency-ratchet`). | done | R2 | A pull request that adds a dead or over-broad item to a rule fails. The item is `done` when that step has run green on a pull request after this item is merged. Done: #82 merged on 2026-11-16 at 16:11 UTC (`dd494ef`). The step ran and passed in the last run of each of seven pull requests that merged after it (the last run of #83, which merged 9 s after #82, came before it): #84 (run 43905454885), #81 (43908450485), #85 (44004316610), #87 (44030089037), #86 (44041652805), #90 (44146874607) and #91 (44206998886). In each run it judged 0 changed rules, because no pull request after #82 changed a rule file (#81 changed only a sidecar). So CI has not yet shown the step fail on a real dead or over-broad item. The gate tests (`detections/tests/test_mutants.py`) show each rejection. |
| R1 | **Gate code from `main`** (design 4.1). Each checking job runs the gate code of `main`, not of the pull request. | not started | T2, T5 | A pull request that changes a gate and a rule together cannot make its own rule pass. Until T2 and T5 are done, each technique pull request must edit the validators, so this item waits for them. |
| R8 | **Approvals as checked properties** (design 4.8). A waiver or a budget is accepted only when a machine can check its conditions. | not started | R5 | A waiver that does not meet its conditions fails a check. |
| R9 | **Live cloud capture** (design 4.9). | in progress | owner | The setup guides and the smoke test are merged (`docs/setup/`). Open: the owner creates the accounts; `atomics/lib/live.sh` with an undo stack; the capture workflow; one supervised run. The job `emulation-scripts` (L7) tests six live scripts with stub CLIs; the other live scripts have no test. Thus a live script without an undo block has no test until `atomics/lib/live.sh` and its lint exist. |

The gate tests (R2) record known gaps. A known gap is an artifact that a gate
should reject and does not reject today. `python3 -B detections/tests/gatelib.py --gaps`
lists them, each with the item of this table that closes it. To close an item,
correct the gate and, in the same pull request, change each of its known-gap tests
into a rejection test (see [`detections/tests/README.md`](../detections/tests/README.md),
"Known gaps"). The gate tests also read this table: see "How to use this file".

Notes from R7, for the items after it (2026-11-14).

- The gate is `detections/check_variants.py` (job `representation-variants`). The
  list model that it gates is one value for each element of a list, with an object
  as its JSON text. A store that explodes a list into leaf fields or indexed keys is
  not gated: such a store cannot run a rule that reads a list as text, and
  `check_provider_mappings.py` keeps that mode as a warning.
- The gate reads the sidecar cases and the cloud fixtures. It does not read the
  benign corpus. Two probes with the code of the gate on the corpus of this date
  show what that leaves open. Under `multi`,
  `T1528/k8s_pod_token_used_off_source.yml` goes from 0 to 830 hits: its filter
  reads the last element of a list, and a multi-valued field has none. Under
  `cs_like`, `T1078.004/aws_cognito_unauthenticated_identity_use.yml` goes from 27
  to 12 hits. An item that scores the corpus under a variant needs a decision on
  the budgets first (R8).
- [`detections/SEMANTICS.md`](../detections/SEMANTICS.md) says what the oracle
  decides and what other stores do. A statement about the oracle names a golden
  probe of the gate: the self-test proves each probe, and the job fails when the
  probe table of the document is not current (`--check-doc`). The document marks
  what nothing proves on each run. A statement `by hand` was run one time (the
  three-valued run, the group-by fields of a correlation, the record of a rejected
  call on three rules). A statement `not verified` has no primary source that was
  read (each cell about Splunk, the letter case of ES|QL `==`, the text that a real
  store gives for a list). R3 and R9 are the items that can put a real record in
  the place of a `not verified`.
- The known gap `ns-one-json-serialisation` named `check_null_safety.py`. It closed
  in another gate, `check_variants.py`. `check_null_safety.py` still has no
  exemption list.
- Rule corrections removed four `LIST_TEXT` entries of
  `detections/variants/expected.json` (closed entries K72 and C20 of
  `detections/RULE_DEFECTS.md`). An item that names one element of a list now has
  two `|re` values: one with the JSON quotes of the element (the list as text), and
  one anchored with `^` and `$` (one value for each element). The list holds 13
  entries. Three of them name an open entry that tracks a correction (C19, K43).
- A latent miss is open as C19 in `detections/RULE_DEFECTS.md`. The three GCP rules
  that read the binding deltas miss a delta with an IAM condition when a store
  sorts the keys of an object. Two cases hold it, each with an expected entry. No
  real record was read for it. R3 and R9 can show whether a real record carries a
  condition, and in which key order.
- For R8. `detections/variants/expected.json` is a list of human approvals. Two
  things stand behind it today: the file is not content for automerge, and the
  `sufficiency-ratchet` job compares the list with the list of the base branch (an
  entry that the base does not hold as it is on the head fails). But the code that
  reads the list and checks each entry is the code of the head, as for the waivers
  of `check_sufficiency.py` (known gap `cs-self-added-waiver`). R8 must take the list
  over: the conditions of an entry are then checked by code from `main` (R1). An
  entry binds names (the variant, the rule, the case or fixture, the fault, the hits
  and the items), not the values of the item or the records of the case: a change of
  a rule value or of a case, which is content, can keep an approval whose `why` is no
  longer true.

Notes from R6, for the items after it (2026-11-15).

- The gate is a change proof, not a count of surviving mutants. The first design
  built mutants of the whole rule and failed a rule whose count of survivors rose.
  A check of that design found four planted heads that pass `rule_cases.py`, the
  sufficiency ratchet and the benign-score ratchet, and that such a count does not
  see: a list of verbs made `'*'` (27 survivors to 26),
  the names of an identity filter made `'*'` (27 to 27), one more alternative inside
  a `|re` value (27 to 27), and an allowlist rewritten as one `|re` value with one
  more name (9 to 6). Each widens an item in place, so no new mutant key appears.
  An added value that lets the corpus kill old survivors also lowers the count (2
  to 1). An undo of each change against the base rule catches all of them
  (`detections/tests/test_mutants.py`).
- Design 4.6 says that a mutant is killed when the benign hit count changes. The
  gate kills only on a rise: a corpus slice that loses a hit under the undo does
  not kill, because that undo is the quieter rule. With a loss as a kill, a value
  that makes a rule fire on more corpus records proves itself: its undo loses those
  hits (a gate test adds SOCK_STREAM to the `a1` list of
  `T1040/afinet_raw_socket.yml`, and the stream sockets of the Linux slice would
  kill its undo).
- A kill by a synthetic case is self-graded: a pull request can add an item
  together with the sidecar case that kills its undo, and pass. The gate proves
  that the case exists, not that the case is real. When R3 (external records), R4
  (captures of CI) and R5 (provenance tiers) are done, their kills should outrank a
  kill by a sidecar case that the same pull request added.
- A list item that gains values and loses others is undone as a whole (its base
  value in place): one kill proves each value of that change.
- A check of the first build found three ways to pass with no proof, now closed
  (each has a gate test): an added block under an `and` was undone as a block that
  never holds, so every positive "proved" a dead block; its undo now takes the value
  that its operator ignores (an `and`: always holds). The hits of a correlation were
  compared as alerts, so a wider timespan was "proven" by a corpus slice that the
  undo grouped in other alerts; the gate now compares the events that the hits
  hold. A base rule of a correlation with a new name and a new id was undone only
  with `rules`, as one bundle; one such base rule left on each side is now a pair,
  undone item by item.
- An equivalent rewrite fails when the gate cannot see it as equivalent: a regular
  expression written in another form, for example. No case can prove it, so a human
  decides. The gate sees as equivalent an undo with the same query, and an undo with
  the same items whose condition gives the same value for each assignment of true,
  false and NULL (up to 10 items: the terms of a condition in another order).
- A rule split into two files moves logic into a new rule, and a new rule is report
  only: what the new file holds is not gated (an allowlist name that it adds, for
  example). A near-miss of the moved value in the old file's sidecar even proves its
  removal there. A later item can pair a new rule with the base rule whose detection
  it largely copies.
- A kill under a variant can come from an event set that
  `detections/variants/expected.json` lists for that rule and variant (an expected
  difference that the change removes). `check_variants.py` then fails the head in
  the same pull request (an expected entry that does not hold), so this gate does
  not count such kills apart.
- Cost: the head and its undo mutants share the tables of each event set and the
  records on which each item holds, and the gate keeps the pySigma query of each
  document. A rule whose 96 regular expressions are rewritten in place (96 undos, 56
  event sets) took 676 s before and takes 43 s.
- The job `sufficiency-ratchet` runs Python `3.x` and does not install google-re2,
  so the variant `re2` does not judge there (the gate prints `NOT RUN`). A
  correction that only RE2 can prove is not proven there. The portable `|re`
  subset (`check_sigma_regex.py`) keeps out the constructs whose meaning differs
  between RE2 and Python's `re`.
- On the base `947055a` (before #76 and #78) the gate proves each rule change of
  #76 but two: `C17` (two GCP rules, under `compact`), `C18` (under `cs_like`),
  `K71` (two webhook rules, under `cs_like`), `K72` (under `multi`), and of `C20`
  `selection_rds` and the SSM rule (under `multi`). The two legacy selections of
  `T1537/aws_snapshot_or_ami_made_public.yml`
  (`selection_ec2_image_legacy.requestParameters.userGroups`,
  `selection_ec2_snapshot_legacy.requestParameters.groupNames`) are not proven: no
  case holds a legacy record (C20 in `detections/RULE_DEFECTS.md` says so). With
  this gate, #76 would have gone to a human for those two items.
- `T1098.001/aws_github_oidc_role_trust_ref_wildcard.yml`: the filter
  `owner_repo_wildcard_create` is real logic (a CreateRole whose trust policy holds
  one `sub` of `repo:<owner>/*` fires without it), and no filtered case holds it
  (the two filtered cases of that filter are UpdateAssumeRolePolicy). A content
  follow-up adds the filtered case for CreateRole.
- Follow-up: the mutants of the whole rule (drop, any value, a value, a map, a
  block, narrow, for each item) as a report-only weekly job on `main`, for the
  digest of survivors. Build an any-value mutant as `field: '*'` (an item with
  `|exists: true` compiles to other SQL, so an equivalent mutant does not show), and
  build no drop of a one-item any-value filter that has a null guard (the drop
  equals the guard).

Note for R7, from R2b. No rule that `detections/validate_detections.py` proves
reads `success`: the logic of each rule matches a syscall that the kernel
rejected. Only the validator holds a rejected syscall, with its own gate
(`success=yes`). The controls of `userfaultfd_syscall.yml`, `io_uring_setup.yml`
and `bpf_prog_load.yml` test that gate, and no item of a rule.
`detections/SEMANTICS.md` (R7, its section 8) now says what a SIEM does with a
rejected call: it alerts on the attempt. R7 changed no Linux rule.

Note for R2c (done). No offline check shows that the capture step of the API server
lab writes the canary read into the pre-emulation file log: the gate tests run the
converter lines of that step on a constructed audit event, whose SYSCALL record holds
the key of the canary watch of the file sensor step, and get one file event. The runs
on `main` at `947055a` show it on a kind cluster (the row R2c above). If a later run
of the job `validate-apiserver` prints `Captured 0 pre-emulation file event(s).` on a
healthy cluster, its negative control fails. Then first find the cause and correct the
capture. Read these lines:

- In the log of the capture step, the summary line of each of the two converter
  runs (`auditd_file_events: <raw log>: read R audit record(s) of E event(s); K
  event(s) with the key <key>; wrote W file event(s); skipped S PATH item(s)`). R is
  0 when the step could not read the audit log of the runner. K is 0 for the canary
  key when the capture converts another key than the file sensor step set, or when
  the canary read is not in the log that the step read. S is not 0 when the PATH name
  of the canary read is relative to a directory fd; the converter then also prints
  `skipped N PATH item(s) whose relative name is relative to a directory fd`. When
  K is not 0, and W and S are 0, the event holds no `exe` or no PATH item of the
  file itself.
- In the log of the file sensor step, the line `Canary held; ...`: the step saw a
  record of the canary read in the audit log of the runner.

Take the file log out of the check only when a healthy capture cannot hold the canary
read. Then print in the run that the negative control of the file rule was not
exercised, and add a roadmap item for the empty file log. Do not upload the raw audit
log of the runner as an artifact: it can hold a record of each `sudo` command of the
job.

Note for R2d. R2d replaces the R2c definition of a record of a Kubernetes log: a
record is an audit event, a pod sandbox or a file event, as
[`detections/README.md`](../detections/README.md#a-record-of-each-log) defines them,
and not each JSON object of a line. R2d ships as three pull requests, merged one
after the other:

- 1/3, the pull request of this note: the log reader of the three Kubernetes
  validators (a line that is not a record of its log, a log that is a directory,
  bytes that are not UTF-8, a byte order mark), a ledger window whose start is after
  its end (the API server validator now also judges no rule after any ledger
  problem), and the verdict line of the API server validator. The loader of
  `score_benign.py --extra-slice` names a line of a live capture that is JSON and not
  an object. The known gaps `k8s-log-line-not-an-object` and
  `k8s-log-object-not-an-audit-event` are rejection tests.
- 2/3: a rule file that the gates do not read (a dotfile), an entry of
  `detections/RULE_DEFECTS.md` that has no Summary row, and a sidecar case that one
  event table cannot hold, such as two keys that differ only in letter case
  (`rule_cases.py` and the gates that share its loader, and
  `check_provider_mappings.py`). It plants the known gap
  `sb-slice-keys-differ-by-case`: a benign slice with two such keys ends
  `score_benign.py` with a `ValueError` of `sigma_eval.EventTable`.
- 3/3, the last pull request of R2d: the event table of `sigma_eval.py` and the
  loader of the cloud fixtures (`validate_cloud_detections.py`). Keys that differ
  only in the letter case of their ASCII letters, in two records, share one column
  of the table, as SQLite reads a field (`SEMANTICS.md`, "Field names"), and the
  analysis of a correlation (`sigma_explain.py`) reads them in the same way. One
  record that holds two such keys, a key `rowid` or `_rowid`, a key with a NUL or a
  lone surrogate, or a value that SQLite does not hold as it is (an integer outside
  64 bits, `NaN` or `Infinity`, a text with a lone surrogate) is a
  `sigma_eval.EventError`, and each loader asks the same test
  (`sigma_eval.event_problem()`) first and names the record: the readers of the
  three Kubernetes validators (a line that is not a record), `score_benign.py` (the
  slice and the event, of each slice; and a live capture that is a directory, is not
  UTF-8, starts with a byte order mark or holds JSON that it cannot read),
  `rule_cases.py` (and a sidecar line that is not UTF-8 or holds JSON that it cannot
  read) and the cloud loader. The cloud loader names each fixture that it cannot
  read as records, and the validator gives the rule an `ERROR` row, also with
  `--report`; `check_null_safety.py`, `check_sufficiency.py` and `check_variants.py`
  name the fixture too. The three known gaps of R2d that were open are rejection
  tests: `k8s-log-keys-differ-only-in-case` (1/3), `sb-slice-keys-differ-by-case`
  (2/3) and `cloud-fixture-record-not-an-object`. R2d is `done` when the four kind
  jobs are green on `main` with 3/3: only they read a real capture. Done: they
  passed on `main` at `55ec270` (the row R2d above).

Only the kind jobs show that each line of a real capture is a record by the new
definitions. On `main` at `947055a` the healthy jobs loaded 885 audit events
(`validate-k8s`); 389 audit events, 11 pod sandboxes and 4 file events
(`validate-staticpod`); 1488 audit events, 9 pod sandboxes and 1 file event
(`validate-apiserver`); and 1482 audit events, 9 pod sandboxes and 1 file event
(`validate-apiserver-recommended`). The same jobs on the pull request of 1/3 must
print no `ERROR` line of the reader. If a job prints one, read it: it names the log,
the line and the problem. Correct the capture when the line is not a record of its log.
Correct the definition in `RECORDS` (the same text in the three validators) when
the line is a record that the definition refuses.

Note for R3. The gate is `detections/check_external_records.py` (`detections/README.md`,
"External records"). The survey of `splunk/attack_data` at the pinned commit `4b19e4b6`
(2026-11-12) found these files of the log sources of the rules, by yml rows and by
distinct paths: 90 rows and 88 paths labelled CloudTrail (OCSF records and Splunk risk
events among them), 47 Azure, 10 Kubernetes candidates (9 of them audit events), 104
auditd (and 8 auditd files that no yml names) and 3 GCP (all Splunk search exports).
Design 4.3 gives 39, 18, 12, 112 and 6; these numbers match none of these bases.

- **Pairs.** A rule and a dataset are same technique when the ATT&CK ID of the folder
  of the rule is in the `mitre_technique` of the yml, and a record of the dataset goes to
  the log source of the rule by its own shape (not by the sourcetype of the yml). Another
  attack tag of the rule gives `RELATED`; a parent or a sub-technique gives no pair. A
  raw auditd dataset of a CVE exploit has a `procedure` label in `SOURCES.json`, which
  the description of its yml must name; a rule whose `cve.*` tags do not include it
  gives `OTHER-PROCEDURE`. Both are reported, not expected.
- **Formats.** Only native records: CloudTrail, Azure Monitor (Entra) by `category`,
  Kubernetes audit events and raw auditd lines. No adapter: OCSF, Splunk search exports,
  Activity Log records in the shape of the REST API, Splunk risk events and Office 365
  Management Activity go to the `excluded` list with their reason.
- **The first run** (shadow; 27 datasets of 1.2 MB, 1.3 MB with their ymls, the LICENSE
  and the syscall table; 19 excluded): 21 of 91 rules have a same-technique dataset of
  their log source; 37 expected pairs give 7 FIRE and 30 MISS; 18 pairs are related, 30
  other procedure, 14 not read and 35 excluded. The CopyFail
  correlation fires 10 times on the real capture (120 distinct evidence records). The two
  dirtyfrag rules miss both Dirty Frag captures: their audit rules record no `socket()`.
- **The first real-record miss** is `T1098.001/entra_app_federated_credential_backdoor.yml`
  on `T1098.001/azure_ad_federated_identity_credential/azure-audit`: the nearest record
  (line 1) is a near-miss, and one flip of
  `selection_unapproved_issuer.properties.targetResources` would fire the rule. The
  survey probe found two causes, and the record fires only with both changed: the issuer
  is the approved GitHub host and the subject names a repository of another owner, and
  the keys of `newValue` are lower case. The casing is not verified: the yml says that
  the author replaced the tenant details. Design 4.3 gives the casing as the only cause.
  The open entry C21 of `detections/RULE_DEFECTS.md` records the miss (2026-11-18). Two
  captures from other sources and three production queries give PascalCase keys, so the
  lower-case keys are probably a result of how the record was made (unverified); the
  shared GitHub issuer is a real gap of the rule. The rule also misses `T1098.001/azure_ad_service_principal_credentials`
  (a client secret added): C21 says why that is another procedure and not a defect.
- **The pull requests.** PR-0: R4 of `check_sufficiency.py` renames the fixture
  constants, so the known gap `cs-rule-keyed-on-fixture-constant` (it names R3) closes.
  PR-1: this gate in shadow mode, with no declaration. PR-2: the defect entry of the
  first real-record miss in `detections/RULE_DEFECTS.md`, and the coverage report again.
  PR-3: the declarations of the owner, from the drafts that `--suggest` prints.
  PR-2 is the entry C21. PR-3 waits for the owner (section 4).
- **Done.** R3 is `done` when the job `external-records` is green in shadow mode on
  `main`, the defect entry of PR-2 is merged, and `gatelib.py --gaps` lists no gap that
  names R3. R3b (enforce, attack-record pins) and R3c (a benign view over all the
  datasets of a log source) come after it. On 2026-11-18 the job passed on `main` at
  `6cbe66f` (run 44245163826) and no gap names R3, but C21 is not on `main`. So the
  pull request of C21 keeps R3 `in progress`, and the next pull request sets it to
  `done` when the job `external-records` is green on `main` with C21.

## 2. Throughput: many builders, no hand integration

| ID | Item | Status | Needs | Acceptance check |
|----|------|--------|-------|------------------|
| T2 | **A sidecar for each rule** in place of each shared registry (design 5): the `MANIFEST` lists, waivers, budgets, defects. | not started | R2 | A new technique changes no file outside its own directories. |
| T5 | **Workflow wiring derived at run time** (design 5). No hand-copied path list. | not started | T2 | A new technique changes no workflow file. |
| T1 | **One technique for each pull request**, enforced by a check, with the TRR ID from the backlog issue number (design 5). | not started | T2, T5 | A pull request with two new TRR directories fails. |
| T3 | **Fragments for each TRR** for `research/index.json`, the README table and the Atomic Red Team YAML (design 5). | not started | T2 | Two technique pull requests that are open together do not conflict. |
| T4 | **Derived files leave the diff** (design 5): `scores.json`, `policy_coverage.json`, `COVERAGE.md`, the charts. | not started | T2 | A technique pull request holds no generated file. |
| T6 | **Emulate and validate in separate jobs** for the kind workflows (design 5). | not started | R1 | The job that grades a Kubernetes rule runs no code from the pull request. |
| T7 | **The backlog as issues** (design 5), ranked by a script, with the GO or NO-GO result in each issue. | not started | L3 | Each candidate is an issue with its vet result. |
| T8 | **The builder workflow**: the agent opens its pull requests from GitHub Actions. | blocked | owner | Waits for the identity gate (`docs/setup/agent-identity.md`, step A5). Then: a workflow that takes one backlog issue and opens one pull request as the agent's identity, with the off switch and a turn limit. |

CI decisions of 2026-11-17 (owner): `gate-tests` on 2 or 3 runners; it runs on 3,
one shard of the gate tests each (`gatelib.py --shard K/3`;
`detections/tests/README.md`, "CI"). `validate-apiserver-recommended` stays on
pull requests; `automerge.yml` stays as it is.

If `gate-tests` becomes a required check (design 9, days 25 to 30), add a job with
the name `gate-tests` that `needs:` the matrix job, runs with `if: always()`, and
fails unless the result of the matrix job is `success`. Require that one name, and
not the checks of the legs (`gate-tests (shard 1/3)` to `gate-tests (shard 3/3)`):
no check has the name `gate-tests` now, and a ruleset that names the legs must
change when the number of shards changes.

## 3. The life of a detection after it merges

| ID | Item | Status | Needs | Acceptance check |
|----|------|--------|-------|------------------|
| L6 | **Supply chain** (design 8): pin each action in each workflow to a commit, add `dependabot.yml`, pin `sigma-cli` to the pySigma version of the validators. Name the runner image in each job (for example `ubuntu-26.04`, not `ubuntu-latest`): the move of `ubuntu-latest` to Ubuntu 26.04 on 2026-11-12 broke four jobs in three ways. | not started | R2 (the check that no action is used by tag is a gate test, and the `gate-tests` job is one of the jobs to pin) | No workflow uses an action by tag. The lint job and the validators resolve the same pySigma. |
| L7 | **Correct the live scripts** that the sandbox guide lists as defective (`docs/setup/cloud-sandbox.md`, "Problems in the live scripts"). | done | | Each listed script runs to its end in dry-run mode and its live commands agree with the provider reference. The table in the guide is shorter. |
| L2 | **A machine condition to close a defect** (design 6): a `known-miss` case that must not fire today and becomes a positive when the rule is corrected. | not started | R2 | Each open false-negative defect has a case that fails when the defect is fixed without closing it. |
| L1 | **A path to retire or rewrite a rule** (design 6). | not started | T2 | A rule can be retired with a defect citation and no override label. |
| L3 | **What 100 % coverage means** (design 6). | owner | | The owner confirms or changes the recommendation in `docs/setup/README.md`. Then write it into `research/README.md` and report against it. |
| L4 | **The review job** (design 6): make it run the skeptic checks for each changed rule, or remove it. Restore `AGENTS.md` from `main` in it. Name the agent in `allowed_bots`. | not started | | The review job cannot be instructed by the pull request that it reviews. |
| L5 | **Vendor documents drift** (design 6): a hash for each source of a TRR, read again each month. | not started | T8 | A changed vendor page gives a row in a report. |

What L7 did, and what it found for later items:

- Six scripts under `atomics/` were corrected, and the copy of the TRR9020 script
  for upstream filing. The tests in [`atomics/tests/`](../atomics/tests/README.md)
  run each one with a stub in the place of each cloud CLI, and the CI job
  `emulation-scripts` runs the tests. No command ran against a cloud account. The
  provider reference was the Google Cloud SDK (its help and its argument parser) and
  Microsoft Learn. Only a live run shows that a provider accepts a command and
  writes the record: that stays for R9.
- Each of the five scripts that makes a change holds the same undo block
  (`atomics/tests/undo_block.sh`). R9 moves the block to `atomics/lib/live.sh` and
  gives it to the other live scripts. The tests send the signals `HUP`, `INT` and
  `TERM` to a script. No test shows what each CLI does when a browser shell
  disconnects and the undo commands have no terminal to write to.
- R9 must keep these properties of the undo block. A script registers the undo
  after the command that makes the change, so a stop signal during that command
  must wait for the registration (`change_next`). An undo command that a signal
  stops must start again, two times at most, and one that
  ran to its end must not run again. A stop signal that comes when the run already
  ends must not skip the undo: bash does not start the EXIT trap a second time, so
  the signal trap must not call a plain `exit`. A reader of the output that goes
  away (`| head`) must not stop the undo. A create command whose answer is not one
  ID has no undo: the run must stop and name the change. The block holds no command
  substitution: with bash 5.2.21, a stop signal at the start of a `$( )` ends the
  run with a syntax error of bash (exit 2; the exit path runs all the same). The
  lines of a script that read the answer of a create command with `$( )` still
  have that fault: R9 can read such an answer from a file (a process substitution has the same fault). The
  table "What is open" in
  [`setup/cloud-sandbox.md`](setup/cloud-sandbox.md#problems-in-the-live-scripts)
  lists the scripts that do not have the block.
- For R5 and R9, three fixtures hold a record that the provider possibly does not
  write. This is not confirmed, because no live record exists. `trr9018/attack.json`:
  a provider with the GitHub issuer and no attribute condition (Google requires a
  condition for that issuer), and with the provider ID `gh` (the SDK says that an ID
  has 4 to 32 characters). `trr9020/attack.json`: a workforce provider with no
  `oidc.webSsoConfig` (the SDK makes that field necessary). `trr9038/attack.json`: a
  successful delete of the `_Default` sink and of the `_Default` bucket (the
  documents of Google, as far as they were read, say that these cannot be deleted),
  and a `CreateExclusion` record whose user agent names `gcloud logging exclusions
  create`, a command that the Google Cloud SDK 570.0.0 does not have.
  A fourth fixture differs from the live command, not from the provider:
  `trr9013/attack.json` holds the subject `repo:trr9013-attacker/*` and a
  description, and the script now sends an exact subject and no description (the
  paired rule reads the issuer only).
  CI is green because the paired rules match these records, or do not read the
  field that differs (the value of the issuer, `webSsoConfig`, the user agent), and
  no gate compares a fixture with what the provider writes. The first live capture
  of each technique must replace the fixture. For `trr9038`, the two `_Default`
  delete records are the only fixture records for the `DeleteSink` and
  `DeleteBucket` branch of the rule: R5 must decide what holds that branch.
- TRR9038 procedure B has no safe live run that fires its rule. The rule reads a
  bucket operation only on `_Default`, and the script deletes only a spare bucket.
  The live record of B is thus the benign baseline of the rule.

## 4. What waits for the owner

These need a repository setting, a payment card or a decision. An agent session
must not do them. The steps are in [`setup/`](setup/README.md).

| Item | Where | Date |
|------|-------|------|
| The Actions policy that keeps `automerge.yml` in operation | `setup/repository-settings.md`, first section | Before 2026-12-02 |
| The identity probe and the gate | `setup/agent-identity.md`, A1 to A5 | Blocks T8 |
| Labels, the off switch, `null-safety` as a required check | `setup/repository-settings.md`, steps 1 to 5 | |
| What 100 % coverage means | `setup/README.md`, "Decisions" | Blocks T7 |
| Cloud sandbox accounts (optional) | `setup/cloud-sandbox.md` | Blocks the rest of R9 |
| The declarations of `detections/external/expectations.json`, one for each `MISS` of the external-records report: `known-miss` with a defect entry (C21), or `n/a` with its reason. The drafts are what `check_external_records.py --suggest` prints | `detections/external/README.md`, "expectations.json"; the note for R3 (PR-3) | Blocks R3b |

## 5. New detections

New techniques continue to be valid work: load the `trr` skill and follow
[`AGENTS.md`](../AGENTS.md). Until R3 and R5 are done, a cloud rule has no evidence
that the agent did not write. Thus, between a trust item and a new cloud technique,
do the trust item first. A Linux or Kubernetes technique has a live oracle in CI
and does not have that limit.
