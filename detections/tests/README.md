# Gate tests

The gates are the checks that CI runs to decide if work is done: `rule_cases.py`,
`check_sufficiency.py`, `score_benign.py`, the validators, the lints. A change to
a gate can stop it from rejecting bad work, and no other check sees that. This
suite holds planted bad artifacts and proves, for each one, that its gate rejects
it for the intended reason. A control proves that the same gate accepts the tree
before the artifact is planted.

A planted artifact that is rejected for another reason proves nothing. For
example, a stale generated file fails many gates, whatever else is in the tree.
Thus each test asserts the words of the gate's message that name the planted
defect, and not only the exit code.

## Run

From the repository root, with the Python that has `detections/requirements.txt`:

```bash
python3 -B detections/tests/gatelib.py --run                                     # all, in parallel (CI)
python3 -B detections/tests/gatelib.py --run test_quality                        # the classes of one group
python3 -B -m unittest discover -s detections/tests -v                           # all, in sequence
python3 -B -m unittest discover -s detections/tests -p 'test_sufficiency.py' -v  # one group
python3 -B -m unittest discover -s detections/tests -k trivial -v                # by name
python3 -B detections/tests/gatelib.py --gaps                                    # the known gaps
```

`gatelib.py --run` runs the same tests as `unittest discover`, with one Python
process for each test class, as many at a time as the machine has CPUs. Then it
prints the known gaps. It takes about two and a half minutes on a development machine
with four CPUs, and about three and a half minutes on a GitHub runner (four CPUs). The
tests in sequence take about seven minutes on the development machine. It fails:

- when a class fails;
- when a class did not run all of its tests;
- when a class does not end in ten minutes (`--class-timeout SECONDS` changes
  the limit);
- when a test module does not import;
- when a run of the whole suite did not run the test of a known gap (a marker
  on a method that `unittest` does not collect).

`--no-skips` also fails the run when a test was skipped, and `--summary PATH`
adds the result and the known gaps to a file as Markdown. CI uses both.

The runner takes the counts of a class (tests that ran, tests that were skipped)
from the `TestResult` of the class. It reads no line of the text that `unittest`
prints, because the format of that text differs between Python versions.

`-B` stops Python from writing `__pycache__/` beside the tests. The suite uses
only the standard library (`unittest`), PyYAML and pySigma. It needs no network
and no root. It runs on Python 3.10 and later (3.10 is the minimum of pySigma).

Five conditions skip a test:

- `gcc` is not installed. The class `LinuxValidatorDryRun` is skipped: the Linux
  dry run compiles the atomics.
- `git` is not installed. One test of `SufficiencyRatchet` is skipped: it runs
  the steps of the sufficiency-ratchet job, which make a worktree of the base
  commit.
- The environment pins git to a repository: `GIT_DIR`, `GIT_WORK_TREE`,
  `GIT_INDEX_FILE` or a variable like them is set (git sets them for a hook). The
  same test is skipped, because the gate runs would work on that repository.
- The Python of the tests is older than 3.12. One test of `EmulationScriptsJob` is
  skipped: it runs the step of the `emulation-scripts` job on a directory with no
  test, and unittest ends with 5 there only from Python 3.12.
- `bash` is older than 5.0. Two tests of `LedgerClock` are skipped: they run the
  clock function of the emulation scripts with the clock of bash
  (`EPOCHREALTIME`, from bash 5.0). A third test is skipped when `bash` is older
  than 4.2: it needs `printf '%(...)T'`.

In CI (the variable `CI` is set) each of these conditions fails the test in
place of a skip, and `--no-skips` fails the run when a test was skipped. So no
test is skipped in CI.

With Python 3.10, one test of `LedgerClock` does not make one of its assertions:
how the validators read a ledger time whose fraction has no digit
(`detections/README.md` says that for Python 3.11 and later). The test is not
skipped.

The `re2` module (the package google-re2) skips no test. With it, the tests of
`check_sigma_regex.py` and `check_provider_mappings.py` pass `--require-re2`, as
their CI jobs do. Without it, they run the default path. The gate-tests job
installs `detections/requirements.txt` only.

The copies are made under the system temporary directory (`TMPDIR`) and deleted
after each test or test class.

## Layout

| Path | Content |
|------|---------|
| `gatelib.py` | The harness: `Tree`, `GateCase`, `StartedTogether`, `assert_rejects`, `assert_accepts`, `assert_saw`, `known_gap`, `ci_step`, `ci_commands`, and the parallel runner. |
| `test_gatelib.py` | Tests of the harness, on constructed gates. |
| `test_sufficiency.py` | `rule_cases.py` (and through it the event table of `sigma_eval.py`: a sidecar line that is not a case, is not UTF-8 (also a lone byte 0x80) or holds JSON that the gate cannot read (too deep for `json` or for `flatten()`, a number with too many digits), a case whose name, `why` or atom of `breaks` holds a lone surrogate (also in `check_provider_mappings.py`), a sidecar line with an object that holds one key two times (a key of an event, which names the case; the kind or the name of the case object, which names only the line), a case whose events one event table cannot hold (also two keys that give one field, in each order, `NaN`, `Infinity`, a lone surrogate in a value or a key, a NUL in a key), a case whose two events hold keys that differ only in letter case, a correlation case whose second event spells the key of the time or of the group-by in another letter case (a near-miss on the timespan, a near-miss on group-by, a positive), a rule in a dotfile), the event table of `sigma_eval.py` itself (class `EventTableKeys`: keys of two events that differ only in letter case share one column, the values of two events with the same keys in two orders go in the columns of their keys, one event with such keys is refused with the event and the keys, an event whose two keys give one field is refused with the event and the field, letters that are not ASCII are not folded, the names `_rowid` and `rowid` in any letter case, integers outside 64 bits, `NaN`, `-Infinity`, a lone surrogate in a value or a key and a NUL in a key are refused, `oid`, `_rowid_` and `event_ids` are ordinary keys), the import guard of `sigma_eval.py` (each kind of name that it and R0 refuse, compared; each gate that reads the rules stops at it on a rule in a dotfile; the rule lists of the walkers that do not use the globs), `check_sufficiency.py` (R0 to R4 and the waiver digests; also a sidecar line that is not UTF-8), the sufficiency ratchet (also a hard benign fixture that lost its verified negatives), the self-test of `sigma_explain.py` (also the counted field of a `value_count` and a group-by field spelled in another letter case, which the analysis reads as SQLite does, and a group-by key with the Kelvin sign, which is another column). |
| `test_mutants.py` | `check_mutants.py`, the change proof of the `sufficiency-ratchet` job. One planted change in the head that no case, fixture or corpus record of the head tells apart from its undo, each rejected with its key: a dead item, a list value that no positive needs, an allowlist name in a base rule of a correlation, an allowlist name widened in place, a list of verbs made a wildcard, the names of an identity filter made a wildcard, one more alternative inside a `\|re` value, an allowlist rewritten as one `\|re` value, a new OR branch that `1 of sel_pod_*` reaches, a dead item beside a value that makes the head fire on its own near-miss and on corpus records (evidence that the head fails does not kill, and a corpus slice that loses a hit does not kill), a dead block under an `and` beside a proven filter, a removed value with no negative, a wider timespan of a correlation, and a value in a correlation base rule with a new name and id. The changes that the gate passes: an allowlist name with its filtered case, a list that is only reordered, reworded texts, a blank fix that only the variant `compact` proves, an anchored value that only `multi` proves and a letter-case fix that only `cs_like` proves (all three planted in the base), a removed value and an added `and` block, each with its negative, a condition with its terms in another order (equivalent), a new id, and a new rule (report only). The changes that go to a human (a renamed block, a switch between a plain rule and a correlation, an undo that does not compile), the structural faults (exit 2: also a variant that is not in force and a sidecar error), and the step of the job. |
| `test_quality.py` | `score_benign.py` (also a slice whose spec, or a line of the data of a recorded slice, holds an object with one key two times: an ERROR line names the file (and the line), and no rule is scored; a slice whose event holds two keys that give one field: an ERROR line names the slice, the event and the field, and no rule is scored; a slice whose event holds two keys that differ only in letter case: an ERROR line names the slice, the event and the keys, and no rule is scored, also for a slice that no rule reads and with `--update`; so does a reseed (`--reseeds`) whose event holds such keys; two events of a slice with such keys are scored; and a live capture, `--extra-slice`, that is a directory or does not exist, holds a byte that is not UTF-8, starts with a byte order mark (also at line 2), or holds a line that is JSON and not an object, an event with two keys that differ only in letter case (also in a nested object), an event that holds one key two times (a line, and an element of an array), an event whose two keys give one field, or JSON that the gate cannot read (in a line or in one document), or a line that json refuses and that a capture cannot have cut (NUL bytes before an event, also on the last line without a line feed; a cut line before other lines, and as the last line with a line feed; on the last line without a line end, an event and the start of an event, U+200B after the brace, a carriage return alone at the end, and a byte that is not UTF-8 before or at the end; a word or a number before a blank at the end; the start of a character of UTF-8 at the end of a middle line; one JSON document, an array on one line or an object of many lines, before a cut last line, with a cut on an ASCII byte and inside a character, which give the same text; a last line too deep for json and cut inside a character): an ERROR line names the capture and the line (the character of the error counts the blanks before the line, and the error of a document of many lines names its line), and no rule is scored on it; two events with such keys are scored, and so is a line that holds U+2028, U+2029 and U+0085 in a string, and the events before a cut last line without a line feed (also a cut inside an escape, after a blank, after U+00A0, and inside a character of UTF-8)) and the benign ratchet, `check_null_safety.py` (also a case whose one record carries a field of the rule in another letter case beside a record that holds the field, and a correlation case whose group-by key, time or counted field is in another letter case; the time has its own text, because the rule writes no time field; a case of a correlation whose first or last base reads `timestamp` as an item field gets the text of a field of the rule; a case whose two records spell a field in two other ways names both spellings), `check_variants.py` (also a sidecar line that is not JSON, and a list of a fixture with an integer outside 64 bits, named with its record), `check_provider_mappings.py` (also a sidecar case that one event table cannot hold, with `--check` and `--write`, and an anchor with an object that holds one key two times), `k8s_policy_coverage.py`, `k8s_platforms_md.py`, `coverage_report.py` (also an entry of the defect tracker without its Summary row or its section, or with two of either, and a heading that starts with an ID and is not the heading of an entry, with `--check` and the generator; one error line for each such entry). |
| `test_validators.py` | The cloud validator (a rule must fire on a marked record of its attack fixture and on no benign record; an attack or benign fixture that is missing or is a directory, and a benign baseline without a record, fail the run, also with `--report`; so does a benign baseline that is not hard: `[{}]`, a near-miss on a surface field only, a near-miss of a branch that the attack does not use, a near-miss of a branch that only an attack hit without the marker uses, a record that only a placeholder allowlist entry (IPv4 or IPv6) filters, a baseline whose only near-miss `sigma_explain.py` misjudges (the row says so), a benign hit on the only hard record (also with `--report`), and a correlation set (a planted rule) that is a near-miss only on its timespan; a record that a real allowlist entry filters, and a correlation set that misses a base, are hard; a baseline that `sigma_explain.py` cannot grade fails too; the `--json` report says which; a fixture that the loader cannot read is an ERROR row that names the fixture and the line or the element, also with `--report` and in `--json`: JSON that is not an array or an object, a record that is not an object in an array, an envelope or JSON lines, a line that is not JSON, a document with an error, bytes that are not UTF-8, a byte order mark, JSON too deep to read (also in the first line of JSON lines) or to flatten, a number with too many digits (named by its record: an element of a document of many lines, a JSON line, also the first, and an element of an envelope), an integer outside 64 bits, `NaN` (also in each record of the attack fixture, which gave a false PASS before), `-Infinity`, a lone surrogate in a value or a key, a NUL in a key, a record with two keys that differ only in letter case (also the one object of a file), a key `rowid`, an envelope whose list is null or a number (also on each line of JSON lines, and the one object of a file that holds the key `value` as a string), a record that is not an object in the envelope of a JSON line, an envelope that holds another key beside its list (a key `source`, a second list, a key that holds a number with too many digits, also on a JSON line) or a page key whose value is not of its type (an object, a list of attack records, a number of 5000 digits, the number 7 and `true` in a string page key, an object in `@odata.context`, `true`, a string and a number above or below 64 bits in `@odata.count`, a list of attack records in `@odata.deltaLink` and in `@odata.nextLink`, and a row for each key of `PAGE_KEYS`; also a page key in another letter case, a JSON line of an attack record with `"items": []`, a key of 60 characters, cut at 40, and another key beside a page key of a wrong type, which names the other key), an object that holds one key two times (an envelope with its list two times, also on a JSON line; a record with its `eventName` two times; a page key two times, first with a number with too many digits), a benign record that holds the attack value under the dotted key `userIdentity.type` and a benign value in the object `userIdentity` (two keys that give one field), the attack records each with `"items": [<a benign record>]` as JSON lines and the fields of an attack record with `"value": [<the benign records>]` as one object (each gave a clean baseline before), a character of two bytes before a byte that is not UTF-8, a blank line before the bad line of JSON lines; two such fixtures are one row; `check_null_safety.py`, `check_variants.py` and `check_sufficiency.py` name the fixture too (also a directory, and for the first two a fixture that does not exist; R4 of `check_sufficiency.py` with an attack fixture that it cannot read says that the rename test ran on the sidecar positives only; a rule without a sidecar whose two fixtures cannot be read gets the two lines only); records whose keys differ only in letter case share one column; JSON lines whose string holds U+2028, U+2029 and U+0085 are read; JSON lines of envelopes are read, and a benign baseline of the attack records in such lines fails the rule; an Azure page (`value`, `nextLink`, `@odata.context`), a GCP page (`entries`, a `nextPageToken` of null) and three Microsoft Graph pages (with `@odata.nextLink`, with `@odata.count`, and with `@odata.deltaLink`) are read, and so are Graph pages whose `@odata.count` is -2**63 or 2**63 - 1; a record that holds the key `value` as a string is read in an array), the Linux validator (dry run, with the check of its `CONTROLS` table; and its verdict code on canned results: the detections; the no-op baseline, which must own a record; each mutant and each re-run, which must be held by what it declares (an item of its rule, or the success gate); the limits of the exemption for a rule whose emulation is a SKIP; a live negative control for each rule), the three Kubernetes validators (dry run; the negative-control step, which fails when a rule passes on a pre-emulation log, when a pre-emulation log is not given or is missing, and when the audit log holds no record; an empty value of `--audit-log` counts as a log that is not given; with `--report` too, each validator fails a rule that passes on a pre-emulation log, and logs without a record; the `--json` report of each validator says that the control of a log without a record failed; for `validate_k8s_detections.py`, its `--json` report says the same for a log that is missing; for the static pod validator, also when the CRI log holds no API-scheduled sandbox or the file log holds no `kubeadm` write, with a line that names the log and the number of its records, and a strict run fails a CRI log without an API-scheduled sandbox with the same line; the lines of its collect step that join the CRI sensor logs of the two nodes, with a stub of `docker`, keep only the complete lines of each copy (a cut snapshot at the end of the first copy is not in the joined log, and a notice names the node), and the negative control reads the joined log; for the API server validator, also when the CRI log or the file log holds no record, and a CRI snapshot without a sandbox is no record; the lines of the capture step of that validator's workflow that make the pre-emulation file log, on a constructed raw audit log that holds the audit key of the canary watch of the file sensor step, and the line of that step that writes the raw log; and the strict run, which prints SKIP and exits 0 when it finds no log, also when the value of `--audit-log` is empty (a log that does not exist: the run does not read the default log), and gets no check of the negative control when it has a log; a line of a log that is not a record of the log fails each run, and no rule is judged: `[]` and `{}` in each log of each validator, an audit `EventList` and a core Event among records, a CRI snapshot whose item is not a sandbox (also an item with an id and a metadata object without a name, and an item with a name and no id) or whose `items` is not a list, a line of the file log with a `TargetFilename` and no `Image` or the other way round, bytes that are not UTF-8 in a JSON string and outside it, a byte order mark (also at the start of a later line, before a record on which a rule fires: the negative control held before), a record on which a rule fires whose key `objectRef` comes two times, the second time with the value of a benign record (the negative control held before), a record on which a rule fires whose key `objectRef.subresource` holds `exec` before an object `objectRef` whose `subresource` is `log` (two keys that give one field: the negative control held before), a line that json refuses and that a capture cannot have cut (8 NUL bytes or U+200B before a record on which a rule fires, also the NUL bytes on the last line without a line feed; a cut line before a record, as the last line with a line feed, and with a carriage return alone at its end: the negative control held before; a cut line in the middle with three blanks before it, whose character counts the blanks; and lines that are not JSON in a log without a record, beside the failed control of that log), while the last line of a log, cut by the capture and without a line feed, is skipped (the Loaded line counts the records, the negative control holds and its `--json` control says `held`; also a cut inside an escape, after a blank, after U+00A0, inside a character of UTF-8, and with a tab at its end), and a last line without a line end that a capture did not cut is a problem (a record of the rule and the start of a record, U+200B after the brace of that record: the negative control held before; a carriage return alone at the end; a byte that is not UTF-8 before the end, at the end, and the sequence E0 80 at the end; a word and a number before a blank at the end, and a raw VT at the end of a string; a last line too deep for json and cut inside a character, which is no traceback), JSON that is too deep or a number that is too long, a string, a number, `true`, `false` and `null` (each named with its type), and a `[]` line in a strict run with `--report` of each validator; a snapshot of two items that are not sandboxes is one line in the count of the FAILED line (and of the `--json` report), with an ERROR line for each item; a sandbox that a log holds on two lines counts once; the ERROR line names the log and the line, a log gets at most 10 of them and the number of the others, and so does the `--json` report, whose control of the log says `FAILED`; beside a log without a record, the API server and the static pod validator print the failed control line of that log before the FAILED line (for a CRI log or a file log of the static pod validator, the line of its CRI control or file control), and the `--json` control names both; a log that is a directory is an ERROR, in the negative-control step and in a strict run; the step of CI that validates with `--ledger` fails on a ledger row whose start is after its end, with an error that names the procedure and the two times, and judges no rule (the same ledger in order is read, and a row whose start is its end is a window); a `--ledger` that is a directory or holds a byte that is not UTF-8, and a `--json` path that is a directory, are ERROR lines; the verdict line of a strict run of the API server validator, and the description of its `--help`, name the TRRs that its `MANIFEST` grades, also in a copy whose `MANIFEST` holds the entries of two TRRs), the class `LogReaderText` (the log reader of the three Kubernetes validators is one text, and so is each entry of its table of records), the class `CutJson` (`sigma_eval.cut_json()`: each proper prefix of fixed records and of records of a fixed seed is cut, also with the escapes of Go and with tabs as blanks, a complete record, also with more text after it, is not, and neither is text that no object starts with, NaN and Infinity, or JSON too deep for json; `sigma_eval.utf8_cut()` drops only the start of a character at the end), a log whose two audit events hold keys that differ only in letter case (each of the three validators judges its rules on it, and its negative control fails on the emulation record of the log), and a record that one event table cannot hold (an audit event, a sandbox, a file event with two keys that differ only in letter case, and an audit event with `NaN`, `Infinity`, a lone surrogate or a key with a NUL: a line that is not a record), the converter of the node file sensor, `k8s/auditd_file_events.py` (one summary line on stderr for each run that read its log, only the JSON lines on stdout, and no workflow command that sends stderr to the file log), `trr_lint.py`, `check_md_links.py`, `check_sigma_regex.py` (also a name that starts with a dot), `check_schedule_freshness.py`. |
| `test_suite.py` | Rules of the suite as a whole: each self-test has a runner, the CI job runs every test on every pull request, the `emulation-scripts` job does the same for `atomics/tests/`, no workflow step pipes a command into `tee` without pipefail, no step that runs a gate or the unit tests has `continue-on-error`, the four validator workflows select their validator fail safe (`ValidatorSelection`: the `push: paths:` list and the lists of the `changes` job agree, each `git diff` there passes `--no-renames`, a validator job runs when its `changes` job did not succeed, and the lists hold each rule file of the validator's `MANIFEST` and `MISS_MANIFEST` with its atomics folder, each local module that a script of the job imports, each path that a step names or a kind config mounts, and the workflow; the class docstring says what the class does not see), no test sets the mode of a file (a chmod) but `gatelib.write_program()`, each known gap names a roadmap item, each planted artifact is used, this file agrees with the tests. |
| `test_apt_install.py` | Tests of `.github/scripts/apt_install.sh`, the step that installs `auditd`, with a stub for `sudo`, `apt-get`, `unshare`, `mount`, `getent` and `timeout`. When the runner cannot resolve the package mirror, or apt printed a message about name resolution, or the mirror does not resolve after a failed run, apt gets one run with public resolvers in a private mount namespace; the script fails only after apt failed in a run with the resolver of the runner (but in the forced way of the CI job); a necessary package that is not installed fails the step; a text that is not a package name (also a name that ends with `-`, which apt reads as a removal) or not an address is refused. The class `DirectInstalls` (with two CONTROLs) fails when a workflow (a `run:` text, a `with:` or `env:` value), a composite action or a shell script (`*.sh`, or a shell on its first line) installs packages in a usual form (`apt-get install`, `apt update`, `dpkg -i`, `snap install`, also with options, a path or quotes) without the script. The one line that is allowed is `apt-get update -qq` in `detections/benign/linux/workload.sh`. It is a rule on text: a command that is built at run time, or that a different program starts, is not seen. The stubs do not show that the namespace works on a runner: the CI job `apt-install-fallback` does. It forces that way, and its CONTROL step gives a resolver that does not answer (`APT_INSTALL_RESOLVERS`) and fails if the install then passes. |
| `test_labs.py` | Rules for the lab jobs that run on a GitHub runner (auditd on the runner, a kind cluster). No offline gate runs these jobs, and a new runner image can break them with no change in the repository. `AuditdStart`: each workflow step that starts auditd (with `systemctl` or `service`) waits for `audit-rules.service` after the start. Before the wait, and before the start, no line of the step changes the rules or a setting of the audit system (an `auditctl` command that is not a status or a list), and between the start and the wait no line runs a validator. auditd 4 loads its rule files in that oneshot unit, the start of auditd does not wait for it, and its rule file starts with `-D` and sets the backlog limit. The wait is in a guard, because auditd 3 has no such unit. It runs with `sudo`, because systemd refuses the start of a unit for a user that is not root and cannot give an authorization. A unit that ends with an error gives a `::warning` line and does not stop the step. The class also runs each such step from its first line to the end of its wait, the whole sensor step of the static pod lab and the whole start step of the `benign-linux-live` job, with a stub for `sudo`, `systemctl`, `service` and `auditctl`. The stubs model the fault that CI showed on 2026-11-13: a run of the unit that nobody waited for deletes the rule after the step saw it in the list, and sets the backlog limit back to the value of its rule file. They also model root: a start of the unit without `sudo` fails at once and waits for nothing. `FileSensorRule`: the two steps of the static pod lab that read the file events print an `::error` line when `auditctl -l` does not list the rule of the file sensor, and they go on. The line says which check of the validator fails when: the file gate, or the file control too. `DateWidth`: no shell script, file under `atomics/`, workflow or composite action gives `%N` a width (`%6N`, `%3N`): `date` of uutils coreutils 0.10.0 prints such a field without the leading zeros of the fraction. `LedgerClock`: the function that gives the times of the emulation ledger (`now_utc()`, or `now()`) is one accepted text in each shell script under `atomics/` and in each workflow step that defines it, and a script that appends to the ledger defines it one time. The class runs that text in bash with a stub `date` that prints a wrong time, in a zone that is not UTC: the result is the time of the test in UTC, a fraction that starts with zero keeps its zeros, and `date` is not called; without the clock of bash the function calls `date` with `%N` only. The stubs do not show what systemd, auditd and the `date` of a runner image do: the lab jobs show that. |
| `test_external.py` | The external-records gate, `check_external_records.py`. `--lint` on the real `SOURCES.json`, `expectations.json` and syscall table, and on one planted defect of each kind: a path that leaves the datasets, a short commit, an id or bytes listed two times, a sha256 that is not lower-case hex, a size over the cap, another licence, a changed licence copy, a list without a dataset, a declaration for a rule or a dataset that does not exist, a stale digest or sha256 (a row in shadow mode, exit 1 with `--enforce`), an unknown verdict word, a why that is TODO or has no prefix, a defect that the Summary table does not list, a redundant or doubled declaration, a procedure label without CVE IDs, in CVE form and not one of its CVEs, or on a dataset that is not raw auditd. The report on a constructed set of four datasets and one `excluded` entry, made from sidecar cases and put in the cache of the gate: the CI step accepts it and gives a DATASET, FIRE, MISS, NOT READ, RELATED, OTHER-PROCEDURE, EXCLUDED and UNAVAILABLE row (the LICENSE and the syscall table, with no network), and the same rows in the step summary; `--enforce --offline` accepts its four FIREs; the declared verdicts come from one run each, and each run of one planted defect fails (a cached file of other bytes, a MISS, a declaration that a hit contradicts, an unavailable dataset, a line that is not a record or not an object, a file that is not UTF-8, a record count, an integer that one SQLite table cannot hold, an integer of more than 4300 digits, an envelope that holds `Records` two times, keys that differ only in letter case, a yml that does not agree with its entry or does not name the procedure label); a run with an error gives `; 1 error(s)` in its Summary line, its step summary (the ERROR line above the rows) and its JSON report. With no cache and no network the real pins give a run that read nothing, and it fails. The rules of the job `external-records`, and the sums of the network time of the gate against its timeout. The raw auditd loader against `validate_detections.normalize()` on the same lines, and the syscall table against the rules and `k8s/auditd_file_events.py`. The probes of the functions of the report: the loader of each format (also an integer of any length, a doubled key of the envelope, a key `rowid` in a record that a rule reads, keys of two records that differ only in letter case, and keys that differ in a letter that is not ASCII or in the Kelvin sign, which are two keys, records wider than one table, and every rule of a log source on a table at that bound), `check_yml()` (the procedure label as a whole token, and each of its CVEs from the description or from a constructed rule; the labels of `SOURCES.json` against the real rules), the cache (a directory or a FIFO entry, read with a time limit) and the network deadline (a local server that never answers or sends a header a byte at a time, also as the proxy of a whole run). |
| `known_bad/<group>/` | The planted artifacts of that group. `known_bad/gatelib/` holds samples for `test_gatelib.py`. |

The planted artifacts are outside `detections/sigma/`, the fixtures and the
benign corpus, so the gates do not read them in the repository. Do not give a
planted file the extension `.md` or `.py`: `check_md_links.py` reads every `.md`
file of the repository, and Python can import a `.py` file. Name it `.md.txt` or
`.txt` and plant it under its real name.

`test_quality.py` also holds the tests of `check_variants.py` (class `Variants`):
the gate itself (its control counts the event sets of each rule, and one test
proves that the gate stops when a variant is not in force), its expected list
(`detections/variants/expected.json`), the probe
table of [`detections/SEMANTICS.md`](../SEMANTICS.md) (`--check-doc`), the form
of its CI job, and the third comparison of the `sufficiency-ratchet` job. With the
`re2` module these tests pass `--require-re2`, as the job does. Without it they run
the four variants that need no module, and one test proves that `--require-re2`
stops the gate.

One test of that class was a known gap until roadmap item R7:
`ns-one-json-serialisation`. Its marker named `check_null_safety.py`, because no
gate varied the JSON text of a list for a rule that is not a Kubernetes audit rule.
The gap closed in another gate, `check_variants.py`. The test keeps its planted
artifact and its wanted row, and it is now a rejection test of that gate
(`Variants.test_rejects_one_json_serialisation_cloud`). It also asserts that
`check_null_safety.py` still accepts the artifact: that gate has no check for it.

One test of `test_sufficiency.py` was a known gap until roadmap item R6:
`ra-allowlist-widened-no-case` (an allowlist name added to a rule, with no case).
Its marker named `check_sufficiency.py --baseline`, which compares cases and not
what a rule matches. The gap closed in another gate of the same job,
`check_mutants.py`. The test keeps its planted rule and its probe pair, and it is
now a rejection test of that gate
(`SufficiencyRatchet.test_rejects_allowlist_widened_without_a_case`). It also
asserts that `check_sufficiency.py --baseline` still accepts the planted rule: that
gate has no check for it.

## How a test works

1. `self.good()` is an unmodified copy of the repository that the test class
   shares. `self.tree()` is a private copy for one test. A copy of the whole
   checkout takes less than half a second; set `PARTS` to copy less.
2. The test plants one artifact: `tree.plant(artifact, dest)` copies a file or a
   directory from `known_bad/`, and `tree.edit()`, `tree.replace()` and
   `tree.edit_json()` change a file of the copy. Each fails when nothing changed.
3. `tree.run(script, *args)` runs the gate as the CI step does: the same command
   line, from the root of the copy, in a child process, with the Python that runs
   the tests. The child has no token, no GitHub variable and no network.
   `tree.run_step(step)` runs the text of a whole workflow step with the shell
   that GitHub Actions uses, so a step that loses the exit code of a gate loses
   it here too. `gatelib.ci_step()` gives the step. It refuses a step that has
   `continue-on-error`, on the step or on its job: a gate that fails there
   leaves the job (for a step) or the workflow run (for a job) green.
   [Limits](#limits) says what `run_step()` does not model.
4. `self.assert_rejects(result, reason)` needs a non-zero exit code and the
   intended reason in the output. A traceback, a wrong command line and a timeout
   are not rejections. `self.assert_accepts(result, proof)` needs exit code 0 and
   a line that shows what the gate checked.

```python
class RuleCases(gatelib.GateCase):
    GATE = "detections/rule_cases.py"
    PARTS = gatelib.DETECTIONS

    def test_control_good_tree_is_accepted(self):
        good = self.good()
        count = len(good.glob("detections/sigma/*/*.cases.jsonl"))
        self.assertGreater(count, 0)
        self.assert_accepts(good.run(self.GATE), rf"^All cases hold \({count} rule file")

    def test_rejects_trivial_near_miss(self):
        tree = self.tree()
        tree.plant("sufficiency/trivial_near_miss", "detections/sigma/T9999")
        self.assert_rejects(tree.run(self.GATE),
                            r"^FAIL  T9999/planted_trivial_near_miss\.yml :: near-miss .*"
                            r"the analysis grades it trivial", exit_code=1)
```

## Add a known-bad case

1. Find the gate that must reject the artifact, and the test class of that gate.
   For a gate that has no class, make one, with a control (see the rules below).
2. Make the smallest artifact that has the defect. Put it under
   `known_bad/<group>/`. When the artifact is one changed value of a real file,
   make the change in the test (`tree.replace()`), with a comment that says what
   is bad. The text that the test replaces is then an anchor in a content file:
   add the file to the list in [Limits](#limits).
3. Write the test: plant the artifact in `self.tree()`, run the command of CI,
   and assert the reason with `self.assert_rejects()`.
4. Run the test. Then prove that it is not vacuous: in a scratch copy of the
   repository (not in the repository), disable the check of the gate that must
   reject the artifact, and run the test there. It must fail.
5. When the gate does not reject the artifact, do not change the gate in the
   same change and do not weaken the test: the case is a known gap (see below).

## Rules for a case

- **One control for each gate.** The control runs the command of the rejection
  tests on the unmodified copy and asserts a line that shows what the gate checked.
  Take a count from the tree. Several gates exit 0 when they found nothing to check.
  The report of `check_external_records.py` (class `ExternalRecords`) is the one
  exception: the suite has no network, so the CI step on the unmodified copy reads no
  dataset and must fail. Its accepted tree is the constructed set in the cache of the
  gate (the runs `constructed` and `constructed_enforce`), and each planted defect is
  one change from that set.
- **One defect for each test.** Where the gate prints a count of problems,
  assert that it is 1. If the artifact must have a second difference from the good
  tree, prove that the second difference alone is accepted.
- **The reason names the defect.** Match the words of the gate's message that
  name this rule, this case and this reason. `FAILED:` is not a reason. Do not
  match text that changes from run to run (random tokens, temporary paths).
- **The command is the command of CI.** Use the arguments of the workflow step
  (`gatelib.ci_commands(script)` lists them; `self.assert_ci_runs()` asserts
  them). The first rejection of each gate uses that command. More variants of the
  same gate can use a faster path of the gate (a rule path as an argument) when
  that path runs the same code. For a mode that no workflow runs, use the command
  of `AGENTS.md` (`self.assert_documented()`).
- **Never change the good tree.** A test that plants, or runs a gate that writes
  (`--update`, `--write`), uses `self.tree()`.
- **Never weaken a test to get green.** When a gate does not reject an artifact
  that it should reject, the case is a known gap.
- **Stay fast.** The suite must run in less than four minutes on a CI runner
  (today: about three and a half).
  Give each gate its own test class: `gatelib.py --run` runs the classes at the
  same time. For a gate that needs several seconds for one run, start the runs
  of the class together (see below).

### Slow gates

A gate is a child process, so runs that start together use the CPUs together.

- In one test: `pending = tree.start(script, *args)` or `tree.start_step(step)`,
  then `pending.result()`.
- For a class, in `setUpClass`: `cls.class_tree()` is a private copy that lives
  as long as the class, and `cls.in_background(call, *args)` starts any call on a
  thread. The class waits for these runs before it deletes its copies.
- `gatelib.StartedTogether` does the same from a list: `RUNS` names the runs,
  `begin_<name>(tree)` plants one artifact and starts the gate, and
  `self.started(name)` gives the test its copy and its result. `test_sufficiency.py`
  uses it.
- Linux refuses to run a file that a process holds open for writing ("Text file
  busy"), and a child process holds each open file of its parent until it runs its
  own program. So a child that a run in the background starts could hold a program
  that a test has just written, and the program would not run. Each start of a child
  process of the suite (`subprocess.Popen`, which gatelib wraps) takes one lock and
  keeps it until the child runs its program, so a new child that runs a program
  never finds it held by another child. A test that writes a program writes it with
  `gatelib.write_program(path, text)`, under the same lock, so that a child that
  already runs can also run it. `Tree.run_step()` writes the programs of a step in
  this way. `test_suite.py` (class `ProgramWrites`) refuses a chmod in the suite
  outside `write_program()`. The lock is not reentrant: a test does not start a
  child or call `write_program()` while it holds the lock.

## Known gaps

A known gap is an artifact that a gate should reject and does not reject today.
Its test states the wanted behaviour and carries the marker. This is the test of
the gap `se-plain-source-shadow` (`test_sufficiency.py`, class
`SigmaEvalImportGuard`):

```python
@gatelib.known_gap(
    "se-plain-source-shadow",
    gate="detections/sigma_eval.py import guard (through detections/rule_cases.py)",
    reason="A plain-source detections/glob.py is imported by rule_cases.py in place of "
           "the standard-library module, because detections/ is first on sys.path and "
           "the import guard refuses only sigma.* and compiled modules; the gate then "
           "skips one sidecar, which holds a positive that cannot fire, and passes. On "
           "the planted tree check_sufficiency.py still fails that positive (R3) and "
           "score_benign.py stops, because budgets.json names the rule that the module "
           "hides; and the merge policy needs a human approval for a new .py file. So "
           "the planted change does not pass CI. The gap is that the rule-cases job "
           "passes: it does not judge the sidecar that the module hides.",
    closes="R1")
def test_gap_plain_source_module_replaces_a_library_module(self):
    """WANTED: the gate refuses a module in detections/ that replaces a library
    module, or it still reads every sidecar and fails on the bad positive."""
    tree = self.tree()
    tree.plant("sufficiency/shadow/afinet_bad_positive.jsonl", AFINET_CASES, append=True)
    tree.plant("sufficiency/shadow/glob_py.txt", "detections/glob.py")
    result = tree.run(self.GATE)
    if result.returncode == 0:
        # The gate accepted the copy. Prove that this is the gap: the planted
        # module hid one sidecar, ...
        sidecars = len(tree.glob("detections/sigma/*/*.cases.jsonl"))
        self.assert_saw(result, rf"^All cases hold \({sidecars - 1} rule file\(s\)\)\.$")
        # ... and the planted positive is bad: the gate fails it when the rule is
        # its argument (then the gate does not call glob).
        named = tree.run(self.GATE, AFINET_RULE)
        self.assertEqual(named.returncode, 1, named.describe())
        self.assertRegex(named.stdout, re.compile(self.BAD_POSITIVE, re.MULTILINE))
    self.assert_rejects(result, r"^  detections/glob\.py$|" + self.BAD_POSITIVE)
```

The test passes while the gate accepts the artifact. It fails with `KNOWN GAP
CLOSED` when the gate starts to reject it. It also fails when the behaviour of
the gate changes in another way (`today=` records `accepts`, `wrong-reason` or
`crash`), and when the test itself is broken. A broken test never counts as an
open gap.

Rules for a known gap:

- **The last assertion is the wanted behaviour**: one `assert_rejects()`. Every
  assertion before it is a plain one.
- **Prove that the artifact is bad**, with plain assertions (the one record of the
  planted baseline holds no field; the gate fails the planted positive when it
  gets its rule as an argument). The gate has no check for the artifact, so
  without this proof the test passes for a sound artifact too.
- **Prove that the gate read the artifact**, with `self.assert_saw(result,
  pattern)` before the last assertion. An artifact that the gate never read is
  also accepted. The pattern must hold today and after the gate is fixed (a row
  that the gate prints for a pass and for a failure). Where the gate prints
  nothing about the artifact, prove inside `if result.returncode == 0:` that the
  artifact is bad, as the example does.
- **Prove the marker.** In a scratch copy of the repository, correct the gate
  and run the test. It must fail with `KNOWN GAP CLOSED`, and not with a message
  of an assertion before the last one.
- **Name what closes it.** `closes=` is an item of section 1 of
  [`docs/ROADMAP.md`](../../docs/ROADMAP.md) (the table `gatelib.ROADMAP`).
  `unplanned` is not a value. For a gap that no item closes, add an item to the
  roadmap and to the table first. `test_suite.py` fails when a gap names no item
  of the roadmap, and when the item is `done` and the gap is still open. It also
  fails when section 1 of the roadmap gets, loses or renames an item and the
  table does not follow (see [Limits](#limits)).
- **Say only what is true.** `reason=` says what passes today and why that is
  wrong, for the planted artifact and for the repository. Where another job or
  the merge policy still stops the planted change, say so. A test can prove
  such a sentence with plain assertions inside `if result.returncode == 0:`, so
  that the text cannot go out of date (the known gap
  `se-plain-source-shadow` of `SigmaEvalImportGuard` does). `gate=` is plain
  text on one line, without a backtick and without `|`:
  the Markdown list of the gaps puts it in a code span of a table cell.
- **A gap is closed by a change to the gate, never by deleting the case.** Fix
  the gate, and in the same pull request convert the test: it fails with
  `KNOWN GAP CLOSED` until you do. One rule converts every gap:
  - Remove the marker, and its `reason=` with it.
  - Delete each branch that proves only sentences of that reason (a block under
    `if result.returncode == 0:` or `if result.crashed:` that proves what the
    gate did while it accepted the artifact or stopped on it). Such a branch
    cannot run when the gate rejects the artifact, and it states a behaviour
    that is gone. A run or an input that only a deleted branch read goes with it.
  - Keep the artifact that the gate reads, and the plain assertions that prove
    that it is bad.
  - Assert the rejection: `assert_rejects()` with the exit code, and the line
    of the gate that names the defect.
  - When a deleted branch was the only test of another gate on the same
    artifact, give that gate a rejection test of its own in the same change.
    Say in the pull request which runs and inputs were deleted, and why.

  The same test is then an ordinary rejection test, and it keeps the gate from
  losing the check again. Rename it from `test_gap_...` to `test_rejects_...`.
  Do not delete the test, and do not change its artifact, or the reason of an
  open gap, to make it pass.
- **A gap is a finding.** Report it in the pull request that adds it.

`gatelib.KNOWN_GAPS` is the one list of all gaps; the markers are its source.
`gatelib.py --gaps` prints it (`--markdown` for a table, `--json` for a script),
and `gatelib.py --run` prints it after the tests, with the state that the run
gave each gap: `open`, or `not run`. A run of the whole suite fails when the test
of a gap did not run and was not skipped: the marker is then on a method that
`unittest` does not collect, and nothing tests the gap.
A test of the harness (`test_gatelib.py`) compares the list of `--gaps --json`
with the markers that it reads from the source text of each `test_*.py`: a test
module that the discovery of the tests drops makes that test fail.

## CI

The `gate-tests` job of `.github/workflows/detection-quality.yml` runs
`python3 -B detections/tests/gatelib.py --run --no-skips --summary "$GITHUB_STEP_SUMMARY"`
on each pull request, on each push to `main`, and weekly. The workflow has no
path filter, so the job runs when a gate, a test, a planted artifact or a
workflow changes. The job summary holds the result and the list of known gaps.
When a test module does not import, no test runs: the summary says so, and the
log of the step holds the error.

The runner stops a test class after ten minutes (`gatelib.CLASS_TIMEOUT`). The
job has 20 minutes. Thus a class that hangs fails the run, the log holds the
output of every class, and the job summary is written. `test_suite.py` compares
the two timeouts.

`test_suite.py` keeps four more rules for the workflows:

- A script with a `--self-test` mode must have a runner. When no workflow step
  runs the self-test, the suite runs it (the table `SelfTests.RUN_HERE`; today
  `sigma_explain.py` and `check_mutants.py`).
- No step pipes a command into `tee` without pipefail. GitHub Actions runs a
  step that has no `shell:` with `bash -e`, so `gate | tee file` takes the exit
  code of `tee`, and a gate that fails leaves the job green. Such a step needs
  `shell: bash`.
- No step that runs a script of the repository with Python, or its unit tests
  (`python -m unittest`), has `continue-on-error`, on the step or on its job. A
  step that has it leaves its job green when it fails, and a job that has it
  leaves its workflow run green.
  The shadow steps are the exception, by name (the table `SoftSteps.SHADOW`;
  today one step of `validate-apiserver-detections.yml`).
- The four validator workflows (`validate-cloud`, `validate-k8s`,
  `validate-staticpod` and `validate-apiserver`) select their validator fail
  safe (class `ValidatorSelection`). The `push: paths:` list and the lists of the
  `changes` job hold the same paths (in `validate-apiserver-detections.yml`, step
  `r` holds each rule and atomics folder of step `f`, and the two differ only by
  `APISERVER_ONLY`). Each `git diff` of a `changes` job passes `--no-renames`, so a
  rule moved out of a listed folder still selects the validator; a test runs each
  `changes` step in a constructed git repository, also with a base commit that
  the repository does not hold (the `git diff` fails, and the step must write
  `true`). The `if:` of each validator job, read by the class `JobCondition`, runs
  the job unless the `changes` job succeeded and said `false`, and never in a
  cancelled run. The lists hold these inputs of the job: each rule file of the
  validator's `MANIFEST` and `MISS_MANIFEST` with its atomics folder, each local
  module that a script of the job imports, each path that a step names or a kind
  config mounts, and the workflow itself. When you add a technique, a module or a
  lab file, the test names the list that misses it. The class docstring says what
  the class does not see, for example the files that the soft shadow step of
  `validate-apiserver` reads and the names that the import guard of
  `sigma_eval.py` lists.

The `gate-tests` job itself has no `if:`, no `continue-on-error` and no `needs:`
(GitHub skips a job when a job that it needs failed), and its workflow has no
path filter. `test_suite.py` checks that too.

`test_labs.py` keeps the rules for the lab jobs (auditd on the runner, a kind
cluster). A planted script or workflow step shows that each rule finds its fault:

- A step that starts auditd waits for `audit-rules.service` after that start. A
  start is `systemctl` with `start`, `restart`, `try-restart`, `reload-or-restart`
  or `enable --now` and `auditd` as one of its units, or `service auditd start`
  (or `restart`). The program can have a path and options, and a redirect can be
  joined to a word (`systemctl start auditd>/dev/null`). The wait is these
  lines, and a new step that starts auditd needs them too:

  ```bash
  if systemctl cat audit-rules.service >/dev/null 2>&1; then
    sudo systemctl start audit-rules.service \
      || echo "::warning title=auditd::audit-rules.service ended with an error ..."
  fi
  ```

  The wait line is `sudo systemctl start audit-rules.service || echo "::warning ..."`
  and no more. Without `sudo`, systemd refuses the start (the user of a step
  cannot give an authorization), the line prints the warning, and the step does
  not wait. That is known of systemd; it was not tried on a runner. With a `&`
  after the line, the step does not wait.

  The wait is at the top level of the step. It is not in an outer `if`, a loop, a
  function, a subshell, a here-document or a quoted text, also when the start is
  in the same block. A step does not reach a wait in a block whose condition is
  false or in a function that nothing calls, and it does not wait for a subshell
  in the background. The rule asks `bash -n`: the lines of the step to the `fi`
  of the wait are complete shell. The tests that run a step ask that too, before
  they run a part of the step.

  Before the wait, and before the start, no line of the step changes the rules or
  a setting of the audit system: each `auditctl` command but a status (`-s`) and a
  list (`-l`) is such a change (`-a`, `-w`, `-R`, `-D`, `-b`, `-f`, `-e`, `-r`,
  `--backlog_wait_time`). The rule file of the unit starts with `-D`, and it sets
  `-b`, `-f` and `--backlog_wait_time`. Between the start and the wait no line
  runs a validator (`python ... detections/validate_*.py`, or
  `detections/benign/linux/capture.py`).

  A message can name a command
  (`echo "::error::the step Start auditd (sudo systemctl start auditd) failed"`).
  So the rule does not look for a start or an `auditctl` command in the words of
  a message. A message is a command whose first word is `echo` or `printf`, and
  whose output no different command takes: it is not before a pipe
  (`echo "..." | bash`) and not in a command substitution or a process
  substitution. The rule reads a command substitution in a message
  (`echo "$(sudo auditctl -l)"`). The check for a validator reads the whole line,
  so a message that names a validator between the start and the wait counts.

  A new step that starts auditd also goes into the list `AuditdStart.STEPS`: the
  test says so. The tests run each step of that list from its first line to the
  end of its wait, with stubs (`STUBS` in `test_labs.py`) for `sudo`, `systemctl`,
  `service`, `auditctl`, `docker`, `kubectl`, `kind` and `sleep`. A different
  program of those lines runs as the real program, in the copy. So read the
  lines before you add the step, and give a program a stub where it needs one.
  After `sudo`, the stub starts only the other stubs and `tee`, and `tee` only
  for a file of the sandbox (a step names `/tmp/`, which is in the sandbox
  there). For `cat`, the stub prints the audit log of its state and does not
  read the file that the step names. The stub does not run a different command:
  it writes the command to its record.

  It is a rule on text, one step at a time and one line at a time. It does not
  see:

  - a start that a script, a shell function or a different program makes (an
    init script such as `/etc/init.d/auditd`, `invoke-rc.d`, a file that a
    message wrote);
  - a command that is built at run time (`"$SYSTEMCTL" start auditd`,
    `systemctl start "$UNIT"`, a message in a group or a subshell whose output a
    pipe gives to a shell), or a unit that pulls auditd in (a target);
  - a start in a different step of the job than the rule;
  - before the wait, a change of the rules that has no option as a word of its
    `auditctl` command (`auditctl "${RULE[@]}"`, `xargs auditctl`), or that a
    different program makes (`augenrules --load`);
  - a wait at the top level that the step does not reach (a `&&` or a `||` at
    the end of the line before the guard). The tests that run the steps of
    `AuditdStart.STEPS` see that.
- No line of a shell script, a file under `atomics/`, a workflow or a composite
  action holds `%N` with a width of one digit (`%6N`, `%3N`, `%06N`). A `#`
  comment does not count. A shell script is a file with the name `*.sh` or
  `*.bash`, or with a shell on its first line. Under `atomics/` the rule reads
  each file that is text and not Markdown: also a file that a script sources, and
  a program in a different language. It is a rule on text. It does not ask what
  the language of a file is: a mention in prose (a YAML description, a text
  note), or in a comment that does not start with `#` (`/* */`, `//`), counts
  too. Write the format in two parts there (`%6` and `N`), or move the note to a
  Markdown file. The rule does not see a format that is built at run time, and
  it does not find a width of two digits (in a URL, `%20N` is a space before an
  `N`). Outside `atomics/` it does not read a file that a script sources when the
  file has no shell on its first line and no such name.
- Each definition of `now_utc()` or `now()` in a `*.sh` file under `atomics/`
  and in a workflow step is the text `LedgerClock.ACCEPTED` (the name can be
  `now()`). A script that appends to the ledger (`>> "$DETENG_LEDGER"`) defines the
  function one time. To change the function, change that text and each copy in
  the same pull request. When a function is not the accepted text, the message
  shows the difference, line by line. It is a rule on text: it does not see a
  definition that `eval` or a sourced file makes, and it does not see a script
  that keeps the function and takes the times of its ledger from a different
  command.

The job `emulation-scripts` of `lint-trr.yml` runs a second suite: the tests of the
cloud emulation scripts in [`atomics/tests/`](../../atomics/tests/README.md). The
gate tests do not run that suite. They hold the rules of its job (class
`EmulationScriptsJob`): the same rules as for `gate-tests`, and these.

- The job is one fixed form (`EmulationScriptsJob.JOB_FORM`): checkout, Python
  3.12 or later, and one step with the one command. A step more, a line more in
  that step, an `env:`, a different runner or a `concurrency:` group fails the
  test. Change the form in the same pull request, and say why the job still runs
  every test.
- The step runs the discovery of unittest on the whole directory. The step fails
  when a test fails, when a test module does not load, and when the directory
  holds no test.
- Each file that holds a test method is a file from which the discovery loads a
  test. No test is an `async def` (unittest does not wait for it).
- No test is skipped, and none is an expected failure: unittest ends with 0 for
  both. The rule reads the names in each module, so an alias
  (`import unittest as ut`) is found too.
- The suite does not lose tests. The class holds the count
  (`EmulationScriptsJob.TESTS`). A lower count fails. Raise the number when the
  suite grows. The count is the same with the variables of a GitHub runner.

These rules do not see code that hides a failure when the tests run: a test that
returns early, a decorator or a `run()` of a test class that swallows the
failure, `os._exit(0)` in a test, a patched `TestResult`. The count is a floor:
it does not see one test in the place of a different one.

## Limits

- The suite proves that a gate rejects the artifacts that are planted here. It
  does not prove that a gate rejects every bad artifact.
- `ProgramWrites` sees a chmod only. It does not see a copy that keeps the mode of
  a program (`Tree` copies the programs of the repository, such as
  `atomics/*/src/emulate.sh`, with their mode), `os.open()` with a mode, or a chmod
  through a program. The lock on each start of a child still covers such a file
  when a new child runs it. It does not cover a child that already runs and then
  runs such a file; no test does that today. A program that a gate under test writes
  and runs is a child of the gate, not of the suite, and the lock does not cover it.
- A gate that needs a host or a cluster runs only in its offline modes: the dry
  runs, the negative-control steps on logs that the test writes, and the verdict
  code of the Linux validator on canned events. The live runs stay in the
  `validate-*` workflows.
- No test downloads a dataset of splunk/attack_data, and no record of it is in the
  repository. `test_external.py` builds its datasets from sidecar cases (the agent
  wrote them) and puts them in the cache of the gate in the sandbox, each with a
  constructed yml. Only the job `external-records` reads the real datasets, checks
  their sha256 and their ymls at the pinned commit, and compares the LICENSE and the
  kernel's syscall table with their origins. No test shows that the origins serve
  the pinned files.
- The suite runs two lines of the capture step of
  `validate-apiserver-detections.yml`: the lines that convert the runner's audit
  log into the pre-emulation file log. It runs them on a raw audit log that the
  test constructs (one event with the canary key, one event with another key). The
  canary key is the key of the `auditctl` line of the file sensor step: the test
  reads that line, in the two jobs, and does not run the step. The test also reads
  the line of the capture step that copies the audit log of the runner to the raw
  log (it must write the path that the converter lines read; the test knows two
  forms of the line, a pipe into `sudo tee` and a plain redirect), and does not run
  it. No test shows that the runner's auditd records the canary read, or that the
  capture of a real cluster holds it. Only the jobs `validate-apiserver` and
  `validate-apiserver-recommended` show that.
- Three runs read a path outside their sandbox, one for each Kubernetes
  validator. The control of a strict run of a validator runs it without
  `--audit-log`, so the validator looks for `/tmp/kube-apiserver-audit.log` on the
  machine of the test. A CI runner of `gate-tests` does not have that file: the
  test asserts the SKIP line and exit code 0. It asserts the same when the path
  is a symbolic link to nothing, which the validator does not find. A machine
  that ran the lab can have the file: the test then asserts only that the run
  loads that log. When the path is a directory, the test asserts the ERROR line
  that names it, and exit code 1. Each machine runs that check on a directory of
  the sandbox in a test of its own (`test_rejects_strict_run_on_a_log_that_is_a_directory`).
  Two more runs of the same test read no path outside the sandbox: one names a log
  in the sandbox that does not exist, and one gives `--audit-log` an empty value,
  which is a log that does not exist too (the run does not read the default log).
  The test asserts the SKIP line of these two runs on each machine.
- No offline check compares the item that a row of the `CONTROLS` table of
  `detections/validate_detections.py` declares with the C program of that row.
  The canned events of a Linux control come from a rule sidecar, not from the C
  source: the driver takes the case that breaks the declared item, so the grade
  follows the declaration. No gate test fails because a row declares the wrong
  item for its program. (A test that quotes the declared item of a row, such as
  `afxdp_socket.a0`, fails when that row changes, whatever the program does.)
  Only the job `validate` (`validate-detections.yml`) runs the programs in
  `detections/controls/` and grades the records that they leave.
- No gate reads the live emulation scripts (`atomics/*/src/emulate*.sh`, the
  parts behind `TRR90NN_LIVE=1`). A live script that lost its undo trap
  (`trap revert EXIT`) passes every gate. The design (4.2) names that artifact
  for this suite, and the suite has no case for it: there is no gate to test.
  Roadmap item R9 adds `atomics/lib/live.sh` and its lint; the case comes with
  them.
- The network fence of a gate run is a proxy setting. It does not stop a gate
  that opens a socket without the proxy.
- The tests of the event table (`EventTableKeys`) and of the loaders plant keys
  that differ only in the letter case of ASCII letters, the keys `rowid` and
  `_rowid`, integers just outside 64 bits, `NaN` and `Infinity`, lone surrogates in a
  value and in a key, and a NUL in a key. Outside the external-records gate (which
  refuses both), a NUL in a text value has no check and no test (SQLite stores the
  whole text and `=` reads it whole, but `LIKE`, and so `|contains`, `|startswith` and
  `|endswith`, stops at the NUL), and so has a log, a fixture or a slice with more
  than 1999 distinct flat keys (SQLite holds at most 2000 columns in a table, and the
  table ends with an `OperationalError` of sqlite3, `too many columns on logs`, that
  no line names).
- The import guard of `sigma_eval.py` and R0 of `check_sufficiency.py` are two
  implementations of one rule. `SigmaEvalImportGuard` compares them on the kinds of
  names in its table `NOT_RULE_MATERIAL` (and `RULE_MATERIAL`). A kind of name that
  is not in the table can be refused by one of the two and not by the other: add
  each new kind to the table. `sigma check` (sigma-cli, not run by the suite) reads a
  rule in a dotfile. The suite does not run the self-test of
  `pipelines/convert_k8s.py`, which needs pySigma-backend-kusto: `SigmaEvalImportGuard`
  tests its rule list, and not its run.
- `tree.run_step()` runs the `run:` text of a step. It models the shell of the
  step: `bash -e` when the step has no `shell:`, and bash with `-eo pipefail`
  for `shell: bash`. It also models `/tmp/`, the files behind
  `GITHUB_STEP_SUMMARY`, `GITHUB_OUTPUT` and `GITHUB_ENV`, and the `${{ ... }}`
  expressions whose values the test gives. It does not evaluate an `if:`
  condition of the step or of its job: the step always runs here. So a step
  that a condition switches off in CI still passes its step test. It does not
  read the `env:` or the `working-directory:` of the step: the test gives the
  values. It does not model `continue-on-error`: `gatelib.ci_step()` refuses a
  step that has it, and `test_suite.py` (class `SoftSteps`) refuses it for each
  step that runs a gate.
- The tests depend on the text of real content files. A test changes a rule, a
  fixture or a report in its copy, and it finds the place of the change by an
  exact text (`tree.replace()`), by a JSON key or by the name of a case. A
  change to that text can pass every content gate and make `gate-tests` red,
  with a message such as:

  ```text
  ValueError: replace('detections/sigma/T1040/afinet_raw_socket.yml'): '      - traceroute6\n'
  occurs 0 time(s), wanted 1. The test finds the place of its change by this text. If a
  change to the file removed the text, the test is out of date: correct the test
  (detections/tests/README.md, Limits)
  ```

  That failure means that a test is out of date. It does not mean that the
  content is wrong. The repair is a change to the test, and a test module is not
  content for the merge policy (no `.py` file is): the maintainer merges the
  repair by hand. `gate-tests` is not a required check and is one of the slower
  checks (about four minutes), so GitHub can merge a content-only pull request
  before the job fails. The job is then red on `main` until the repair. Thus,
  before you change one of these files, run the suite.

  A test changes these files in its copy:

  - `detections/sigma/T1040/afinet_raw_socket.yml`
  - `detections/sigma/T1040/afinet_raw_socket.cases.jsonl`
  - `detections/sigma/T1040/afpacket_raw_socket.yml`
  - `detections/sigma/T1040/afpacket_raw_socket.cases.jsonl`
  - `detections/sigma/T1040/afxdp_socket.yml`
  - `detections/sigma/T1040/afxdp_socket.cases.jsonl`
  - `detections/sigma/T1078.004/aws_cognito_unauthenticated_identity_use.yml`
  - `detections/sigma/T1078.004/aws_leaked_access_key_recon.yml`
  - `detections/sigma/T1068/copyfail_af_alg_authencesn.yml`
  - `detections/sigma/T1068/dirtypipe_splice_readonly.yml`
  - `detections/sigma/T1068/dirtypipe_splice_readonly.cases.jsonl`
  - `detections/sigma/T1098.001/entra_app_federated_credential_backdoor.yml`
  - `detections/sigma/T1098.001/gcp_workload_identity_federation_sa_binding.yml`
  - `detections/sigma/T1098.001/gcp_workload_identity_pool_provider_created.yml`
  - `detections/sigma/T1098.003/azure_privileged_role_assignment.yml`
  - `detections/sigma/T1098.003/gcp_public_iam_member_grant.yml`
  - `detections/sigma/T1098.006/k8s_rbac_privileged_grant.yml`
  - `detections/sigma/T1098.006/k8s_rbac_write.yml`
  - `detections/sigma/T1134/k8s_impersonation_privileged.yml`
  - `detections/sigma/T1485/k8s_volume_reclaim_set_to_delete.cases.jsonl`
  - `detections/sigma/T1537/aws_efs_file_system_policy_made_public.yml`
  - `detections/sigma/T1537/aws_snapshot_or_ami_made_public.yml`
  - `detections/sigma/T1543.005/k8s_cri_static_pod_start.yml`
  - `detections/sigma/T1543.005/k8s_static_pod_mirror_create.yml`
  - `detections/sigma/T1609/k8s_pod_exec_attach.yml`
  - `detections/sigma/T1611/k8s_podspec_confinement_disabled.yml`
  - `detections/cloud/fixtures/trr9011/attack.json`
  - `detections/cloud/fixtures/trr9012/attack.json`
  - `detections/cloud/fixtures/trr9012/benign.json`
  - `detections/cloud/fixtures/trr9019/attack.json`
  - `detections/cloud/fixtures/trr9036/attack.json`
  - `detections/cloud/fixtures/trr9036/benign.json`
  - `detections/RULE_DEFECTS.md`
  - `detections/variants/expected.json`
  - `detections/SEMANTICS.md`
  - `detections/k8s/PLATFORMS.md`
  - `research/trr9001/lin/README.md`
  - `research/trr9012/aws/README.md`

  A test of the validators takes cases by name from these sidecars, as the
  records of a log (and so does the test of `--extra-slice` in `ScoreBenign`, from
  the first sidecar):

  - `detections/sigma/T1609/k8s_pod_exec_attach.cases.jsonl`
  - `detections/sigma/T1543.005/k8s_static_pod_mirror_create.cases.jsonl`
  - `detections/sigma/T1543.005/k8s_cri_static_pod_start.cases.jsonl`
  - `detections/sigma/T1543.005/linux_static_pod_manifest_write.cases.jsonl`
  - `detections/sigma/T1098.006/k8s_rbac_write.cases.jsonl`
  - `detections/sigma/T1053.007/k8s_cri_job_pod.cases.jsonl`
  - `detections/sigma/T1552.007/linux_k8s_sa_token_read.cases.jsonl`

  `Variants` (`test_quality.py`) takes one case by name from this sidecar, for
  its probe of the two JSON texts of a list:

  - `detections/sigma/T1537/aws_snapshot_or_ami_made_public.cases.jsonl`

  One test also needs `detections/sigma/T1537/aws_snapshot_or_ami_made_public.yml`
  to have no entry in `detections/variants/expected.json`.

  `Variants` also needs two entries of `detections/variants/expected.json`, and
  what each one names. The first is the entry of the case
  `scale-smp-root-alias-retain-keys-with-count` of
  `detections/sigma/T1685/k8s_enforcer_workload_removed.yml`: a loss of record 0
  under the variant `multi`. The tests find that entry by the rule and the case.
  Two tests count the entries of the rule (two today). The second is the one
  entry of `detections/sigma/T1098.006/k8s_rbac_privileged_grant.yml`, which names
  the open entry K43 of `detections/RULE_DEFECTS.md`. One test also needs K13 as a
  row of the closed entries of that file. One more needs C6 as an open entry of
  that file (a row of its Summary table, and a section) that does not name
  `k8s_rbac_privileged_grant`. When a rule correction removes one of these
  differences, give the tests another entry of the list, as the correction of
  `T1134/k8s_impersonation_privileged.yml` did (closed entry K72):

  - `detections/sigma/T1685/k8s_enforcer_workload_removed.cases.jsonl`
  - `detections/sigma/T1098.006/k8s_rbac_privileged_grant.cases.jsonl`

  Two tests of `Variants` read the probe table of `detections/SEMANTICS.md`
  between its two marker lines (`<!-- probes:begin -->`, `<!-- probes:end -->`).
  One of them needs the row of the probe `eq-case`, with the answer `quiet` in each
  of its six answer cells. The table is generated
  (`check_variants.py --write-doc`), so a change to that probe in the gate changes
  the row.

  One test of `Variants` changes one line of the oracle in its copy: the
  `json.dumps` call that `flatten()` makes for a list. The planted line has no key
  sort, so the variant `sorted` is not in force. This file is code, not content. A
  change to that line makes the test fail with the `replace()` message above, and
  the repair is the new text in the test:

  - `detections/sigma_eval.py`

  One test of `ChangeProofFaults` (`test_mutants.py`) changes one line of the
  in-force check in its copy: the line `named = ...` of `in_force()`, which it
  replaces with a return of a variant that is not in force. This file is code, not content,
  and a change to that line gets the same repair:

  - `detections/check_variants.py`

  The tests of `check_mutants.py` (`test_mutants.py`, and one test of
  `SufficiencyRatchet`) judge each planted change on the evidence of the copy: the
  sidecar of the rule, its cloud fixtures and the benign corpus slices of its log
  source. A rejection test needs that no event set tells its planted change apart
  from its undo (for example, no filtered case of `nc` in the sidecar of
  `afinet_raw_socket.yml`, and no positive that needs `proxy` in the sidecar of
  `k8s_pod_exec_attach.yml`). A test that accepts a change needs the event set that
  proves it: a positive of `k8s_impersonation_privileged.yml` with the group
  `system:masters` as an element of a list (variant `multi`), a record of
  `gcp_public_iam_member_grant.yml` whose method ends in `SetIamPolicy` or
  `setIamPermissions` in the letter case of the rule (variant `cs_like`), a positive
  of `gcp_workload_identity_federation_sa_binding.yml` whose delta list has a blank
  after the colon of `"action"` in its default JSON text (variant `compact`), and,
  for the new rule, the value `0` of `a3` in each case of `afinet_raw_socket.yml`.
  The tests of `dirtypipe_splice_readonly.yml` need its two base rules by these
  names and ids, the near-miss `pipe-then-splice-too-late` 30 s apart (so the head
  with a timespan of 20 s still holds its cases), and no case, fixture or corpus
  record that a timespan of 20 s adds to a hit. A new
  case that tells a planted change apart makes a rejection test fail: the test is
  then out of date, and the repair is another planted change in the test. The step
  test of `check_mutants.py` gives the step a stand-in for the worktree of the base
  commit (the rule files of the copy and a `.git` file); the test of the job that
  makes a real worktree (`SufficiencyRatchet`) stops at the step with `--baseline`.

  `CheckSufficiency` (`test_sufficiency.py`) takes the positive cases of these
  sidecars, for its proof that a rule that needs one fixture constant (an account
  id, an organization id, a subscription, a tenant, a project, a node of the lab
  cluster) is bad:

  - `detections/sigma/T1078.004/aws_leaked_access_key_recon.cases.jsonl`
  - `detections/sigma/T1098.001/entra_app_federated_credential_backdoor.cases.jsonl`
  - `detections/sigma/T1098.001/gcp_workload_identity_pool_provider_created.cases.jsonl`
  - `detections/sigma/T1098.003/azure_privileged_role_assignment.cases.jsonl`
  - `detections/sigma/T1134/k8s_impersonation_privileged.cases.jsonl`
  - `detections/sigma/T1537/aws_efs_file_system_policy_made_public.cases.jsonl`

  `CheckSufficiency` also reads every sidecar for the table `FIXTURE_CONSTANTS` of
  `check_sufficiency.py`: each constant of the table must occur in a sidecar. A
  change to the cases that removes the last occurrence of a constant makes
  `gate-tests` red. The repair is to delete the entry from the table
  (`check_sufficiency.py`, which the maintainer merges by hand). If a rejection
  test of `CheckSufficiency` (`KEYED_ON`, or the test of the account) plants that
  constant, that test fails too: point it at another constant of its kind, or
  delete the kind with its test when no constant of the kind is left. No test finds a
  constant that the table does not list: when new cases of two rules share a new
  value of the recording environment, R4 does not rename it until a human adds it
  to the table.

  The test of the verdict line of the API server validator
  (`test_verdict_names_each_trr_that_manifest_grades`) takes every positive case of
  these sidecars as the records of a log, and their MANIFEST entries must pass on
  them without a ledger. It also cuts `MANIFEST` with a line before the text
  `if __name__ == "__main__":` of the validator:

  - `detections/sigma/T1572/k8s_pod_portforward.cases.jsonl`
  - `detections/sigma/T1572/k8s_node_proxy_portforward.cases.jsonl`
  - `detections/sigma/T1133/k8s_service_exposed_nodeport_loadbalancer.cases.jsonl`

  The tests of the hard-baseline check of the cloud validator (`CloudValidator`)
  also need these facts. The rule `aws_leaked_access_key_recon.yml` lists
  `203.0.113.0/24` and `10.0.0.0/8` in one allowlist item, and record #1 of its
  baseline comes from `203.0.113.10`; the item also lists `2001:db8::/32`, and no
  other IPv6 network. `azure_privileged_role_assignment.yml` tests `operationName`
  in its block `selection_write`, and lists its privileged roles after the text
  `'roledefinitions/(8e3af657-`. Record #2 of the `trr9036` baseline is the only
  near-miss of that rule in it, holds the Reader role
  (`/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7`), and has a
  `correlationId` that no other record of the baseline has. `check_sufficiency.py`
  (code, not content) lists `operationName` in `SURFACE_FIELDS`, and `CHOKEPOINT`
  does not list `azure_privileged_role_assignment.yml`. The attack of `trr9019`
  holds a `ModifyImageAttribute` record that shares an AMI with `all`, and no
  `ModifySnapshotAttribute` record. Tests change the `MANIFEST` entry of
  `aws_snapshot_or_ami_made_public.yml` in the cloud validator (code, not content),
  and one adds an entry before the text `FOLDERS = ` of that file. One test changes
  one line of the grader in its copy, `detections/sigma_explain.py` (code, not
  content): the line `composed = self.evaluate(truth)` of `PlainRule.verdict`, and
  the `flips = ` line after it.

  The offline run of the Linux validator takes its canned events from the
  sidecar of each rule of the `MANIFEST` of `detections/validate_detections.py`:
  the first `positive` case and, for each mutant control, the first `near-miss`
  case whose `breaks` is the item that the control declares in the `CONTROLS`
  table. For a control that declares one item of a base of a correlation
  (`base:<name>/<item>`), that is the first `near-miss` case that breaks
  `base:<name>`, and its event must miss the base by that item. A mutant that
  declares `success` takes the first `positive` case, with each syscall
  rejected. The validator must give each canned mutant the grade that it
  declares: a change to one of these cases can make the control
  `test_control_canned_run_is_accepted` fail. Six tests also need one record
  in such a case. The two tests with `--split`, and the tests with `--late` and
  `--without`, need a `socket` record in the case of the control of
  `copyfail_af_alg_authencesn.yml` (for `--split` and `--late`, with a record of
  another syscall). The test with `--refused ... unshare` needs an `unshare`
  record in the case of the control of `dirtyfrag_xfrm_unshare_netlink.yml`. The
  test with `--refused ... execveat` needs an `execveat` record in the case of
  the control of `memfd_create_execveat.yml`. The driver stops with exit code 3
  when the case holds no such record.

  `KnownGapList` (`test_suite.py`) reads section 1 of this file, the item IDs
  and the Status cells:

  - `docs/ROADMAP.md`

  The IDs must be the keys of the table `ROADMAP` in `gatelib.py`, and `R2`,
  which is this suite. Each Status cell must hold one status word and no other
  text. An item that an open known gap names cannot be `done`. Thus a pull
  request that changes only the roadmap can make `gate-tests` red. That failure
  says nothing about a gate. It means one of three things. An item of section 1
  is new, gone or renamed: make the same change to the table `ROADMAP` in
  `gatelib.py`, in the same pull request. `gatelib.py` is not content, so the
  maintainer merges that pull request by hand. A Status cell holds a reason:
  move the reason to the Needs cell. An item is `done` while
  `gatelib.py --gaps` lists a gap that it closes: the item is not done, so set
  its status back, or close the gap (see [Known gaps](#known-gaps)).

  `test_labs.py` reads the lab steps of these workflows, and it finds a step by
  its name (`AuditdStart.STEPS`, `FileSensorRule.STEPS`, `LedgerClock.BENIGN` and
  `LedgerClock.SCORE`):

  - `.github/workflows/validate-detections.yml`
  - `.github/workflows/detection-quality.yml`
  - `.github/workflows/validate-staticpod-detections.yml`
  - `.github/workflows/validate-apiserver-detections.yml`

  A step with a new name makes a test fail with a `LookupError` that says so. The
  repair is the new name in the test. The lab is not wrong. The tests also run
  the text of these steps with stubs: the first lines of each step that starts
  auditd, the whole sensor step of the static pod lab, the whole start step of the
  `benign-linux-live` job, the two steps of the static pod lab that read the file
  events, and the step that writes `BENIGN_START`. A new command in one of these
  steps can need a stub in `test_labs.py`. `LedgerClock` reads each `*.sh` file
  under `atomics/`: a script that appends to the ledger must define the clock
  function one time, as the accepted text.

  `test_external.py` builds its constructed datasets from cases of these sidecars,
  by name (and from the positive and the near-miss of the snapshot rule, whose
  sidecar a list above names):

  - `detections/sigma/T1552.007/k8s_secret_access.cases.jsonl`
  - `detections/sigma/T1528/entra_illicit_oauth_consent_grant.cases.jsonl`
  - `detections/sigma/T1068/copyfail_af_alg_authencesn.cases.jsonl`

  It asserts the FIRE of the rule of each set on its case: the log source of the
  rule, and for the correlation its alerts and evidence records. The procedure label
  of the CopyFail set (`COPYFAIL_CVE`) is the CVE tag of its rule. So it depends on the
  text of these rules too (the snapshot rule, `k8s_secret_access.yml` and
  `copyfail_af_alg_authencesn.yml` are in the other lists):

  - `detections/sigma/T1528/entra_illicit_oauth_consent_grant.yml`

  For the other kinds of row it names no rule: `ExternalRecords.kind()` takes them
  from the folder, the log source and the tags of each rule of the copy. A content
  change can still leave a kind with no rule. The test then fails with a message that
  names this list. It needs a rule of T1528 that reads another Azure log than
  AuditLogs (`NOT READ`, and a declaration on a pair without records), a rule of T1068
  whose `cve.*` tags do not hold the label of the CopyFail set (`OTHER-PROCEDURE`), a
  rule outside T1552.007 with the tag `attack.t1552.007` on the Kubernetes audit log
  that does not fire on the get of a secret (`RELATED`, and a declared fire that
  misses), and a rule in the folder of a constructed set that reads another product
  (no `NOT READ` row for it).

  Its known gap `ext-self-added-declaration` removes the line `      - 'get'` from this
  rule in its copy:

  - `detections/sigma/T1552.007/k8s_secret_access.yml`

  `ExternalLoaders` checks each procedure label of `SOURCES.json` against the titles
  and the `cve.*` tags of the rules of its technique, as the report does: the label
  Copy Fail takes its CVE from `copyfail_af_alg_authencesn.yml` above, and the label
  Dirty Frag its two CVEs from these rules. A title or a tag that drops the exploit
  name fails the test (and the report):

  - `detections/sigma/T1068/dirtyfrag_rxrpc_socket.yml`
  - `detections/sigma/T1068/dirtyfrag_xfrm_unshare_netlink.yml`

  `ExternalLoaders` also runs every rule of `aws/cloudtrail` and of
  `kubernetes/audit` on one table of a record at the bound of keys (1900): it needs
  more than 10 rules of each, and their fields must fit in the 99 columns above the
  bound.

  It also reads `detections/external/SOURCES.json`, `expectations.json` and
  `syscalls_x86_64.json`, which are not content: a pin bump runs the suite.
  `ExternalRecordsJob` needs at most 38 datasets in `SOURCES.json` ((2 + 38) x 15 s
  is the deadline of 600 s): a larger pin needs a new `TIMEOUT` or `DEADLINE`.

  `test_suite.py` fails when a file of these lists is not in the repository.

## Not covered yet

These are facts for the next session. They are not known gaps: no run showed
that a gate accepts a bad artifact here.

These rejections have no planted artifact and no test:

- `score_benign.py --check --enforce` has three of them: an `unscored` entry of
  `budgets.json` for a rule that is scored now, an entry of `budgets.json` for
  a rule that does not exist, and an `unscored` entry without a why.
- The fail-closed errors of `score_benign.py --baseline-scores` and of
  `check_sufficiency.py --baseline`: a base file that is missing, that is not a
  report of the gate, or that holds no rule.
- The digest check of the `COMPILE_ONLY` table of `check_sufficiency.py`. The
  table is empty today, so there is no entry to make stale.
- `check_variants.py` has eight of them: a gain (a negative case or a benign
  fixture that fires under a variant), a change of hits in an event set that still
  fires (a fixture of two records that loses one hit; a positive that loses one hit
  and gains another), a rule that the `multi` variant cannot check (a correlation
  rule on records with a list, or an item with `|neq` on a list), a rule with no
  case and no fixture, a rule file that cannot be checked, an entry with the
  reason `KEY_ORDER` on a set that differs as compact text too, an entry whose
  `why` starts with `TODO` (the text of `--propose`; also after a blank, and after
  a tab with no colon after `TODO`), and a
  `compact`, `cs_like` or `re2` variant that is not in force (for `compact`, also
  a default run that reads the compact text). Its self-test holds a constructed
  rule, or a constructed variant or default run, for each (for `re2`, where the
  module is installed). The gate test of the in-force check plants a `sorted` that
  lost its key sort. No test and no self-test check switches `multi` off.
- Two checks of `check_variants.py` have no test, because no artifact can fail
  them: an entry with the reason `LIKE_CASE` whose changed item is not a `LIKE`
  test, and an entry with the reason `LIST_TEXT` or `KEY_ORDER` whose changed item
  does not read a list. The variant of each reason changes no other item
  ([`detections/SEMANTICS.md`](../SEMANTICS.md), section 9).
- The control of `Variants` counts the event sets of each rule, not their
  records, and no entry of the expected list names a record after record 0. The
  self-test of `check_variants.py` takes each fixture of the cloud `MANIFEST` as
  `check_rule()` gets it (`cloud_fixtures()`, then `event_sets()`), and compares
  its count of records with the JSON list of the file: a gate that reads a fixture
  as its first record only, in the loader or in `event_sets()`, fails it. The
  self-test also proves on constructed sets of two records that `check_rule()`
  reads the second record of a set that it is given. Not proven: that the gate
  reads each record of a sidecar case. A gate that reads each case as its first
  record only passes each test and each self-test check.
- `check_variants.py --check-doc` has three of them: a probe that the text of
  `detections/SEMANTICS.md` does not name, a document without one of its two
  marker lines, and a document that is not there. The self-test holds a
  constructed document for each. The mode `--write-doc` has no gate test: no
  workflow runs it. The self-test proves it on a constructed document.

The suite does not run these checks:

- The RE2 branches of `check_sigma_regex.py` and `check_provider_mappings.py`.
  google-re2 is not in `detections/requirements.txt`, so the `gate-tests` job
  runs the default path. For `check_sigma_regex.py`, one test proves that
  `--require-re2` fails when the module is missing.
- The `re2` variant of `check_variants.py` (the search of each `|re` item with
  RE2, and the `re2` answer of each golden probe), for the same cause. Only the
  `representation-variants` job runs it. Without the module, `--check-doc`
  compares the `re2` column of the document with the answers that the gate
  declares. One test proves that `--require-re2` stops the gate when the module
  is missing.
- `sigma check`. sigma-cli is not in `detections/requirements.txt`.
- The live modes of the validators (auditd on a host, a kind cluster). They
  stay in the `validate-*` workflows.

One fault of the runner is open:

- When the runner stops a class at its timeout, the gate processes of that
  class continue, and their sandboxes stay under `TMPDIR`. Each gate run has a
  session of its own, so the runner does not reach it. In CI the machine of
  the job is deleted after the job.
