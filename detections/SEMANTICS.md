# Semantics of the offline oracle

This document says what the offline oracle of this repository decides when it runs a
rule. It also says where a real log store decides in another way. Read it before you
write an item that depends on letter case, on the text of a list, on a missing field,
on a type or on a regular expression.

| Term | Meaning |
|------|---------|
| oracle | [`sigma_eval.py`](sigma_eval.py) with its defaults, as each validator and each offline gate runs it |
| record | one log record (one JSON object) |
| event set | the records of one case or of one fixture |
| item | one field test of a rule (`field\|modifier: value`) |
| variant | one changed representation of the same records, or one changed matcher |
| store | a product that keeps records and runs queries on them |
| backend | a pySigma converter from a rule to the query of one store |
| fires, is quiet | the rule matches the record or the event set; the rule does not match it |

How to read the evidence:

- Each statement about the oracle has a probe: one detection, one record and the
  answer. A probe with a name (`eq-case`) is a row of the generated table in
  [section 10](#10-the-golden-probes). The self-test of the gate proves each row on
  each run in CI, and the gate fails when the table of this document is not current.
  In this document, a code span of lower-case words joined by hyphens is always the
  name of such a probe.
- A statement with the words "by hand" has no named probe. It was run one time, on
  2026-11-14, with Python 3.13.18 and SQLite 3.53.1, on the code of this repository.
  No gate keeps it true.
- Each statement about a product has a number in brackets, which points to
  [section 12](#12-sources). Words in quotation marks are the words of that source.
  "Not verified" means that no primary source was read for the statement. "Our
  inference" means that the statement follows from the quoted words, and that no
  source says it in those words.

## 1. The oracle

- [`sigma_eval.py`](sigma_eval.py) compiles one rule file into one SQL query. It uses
  pySigma 1.5.1 and pySigma's SQLite backend 2.0.0 ([`requirements.txt`](requirements.txt)).
- It loads the flat records into an in-memory SQLite table and runs the query.
- It is one backend on one representation of the records. A PASS says that this query
  matches these records. A PASS does not say what a different backend or store answers.
- The SQLite library is that of the Python that runs the gate; no file sets its version.
  The built-in `LIKE` "understands case equivalence for the 26 letters of the English
  language alphabet". With the ICU extension, `LIKE` folds "the full range of unicode
  characters" [4]. The probe `contains-non-ascii` shows which of the two is in force.

## 2. The record

`flatten()` changes one record into flat fields.

| In the record | In the table | Probe |
|---------------|--------------|-------|
| an object | one field for each leaf, with a dotted name (`spec.a`). The object has no field of its own | `object-leaf`, `object-no-field`, `object-empty-exists` |
| a list | one text value: the default text of Python's `json.dumps` | `list-contains` |
| a string or a number | the same value | `number-number` |
| `true`, `false` | the integer 1 or 0 (section 6) | `bool-true`, `text-on-bool` |
| JSON `null` | SQL `NULL`, the same as a missing field | `null-json-null` |

The default text of a list has these properties:

- A blank follows each `,` and each `:`. In `json.dumps`, "*separators* defaults to
  `(', ', ': ')` if *indent* is `None`" [5]. Probes `list-blank`, `list-no-blank`.
- The keys of an object keep the order of the record. Probe `list-key-order`.
- A non-ASCII character is an escape (`é` for `é`): "the output is guaranteed
  to have all incoming non-ASCII and non-printable characters escaped" [5]. Probe
  `list-non-ascii`.
- A scalar element is as JSON writes it: `true`, `null`, a string in quotes. Probe
  `list-scalars-text`.
- An empty list is the text `[]`, so the field exists. Probe `list-empty-exists`.
- A name below a list is not a field. Probe `list-leaf-no-field`.

Field names: SQLite compares column names without regard to letter case, so the item
`Verb: create` reads the field `verb` (probe `field-name-case`). The oracle refuses an
event set in which two keys differ in letter case and in nothing else (by hand:
`ValueError`). [`check_null_safety.py`](check_null_safety.py) fails a rule that reads
a field in a letter case that the records do not use.

## 3. Letter case

The Sigma specification says: "All values are treated as case-insensitive strings."
and "Regular expressions are case-sensitive by default." [1] For equality, the
oracle does not obey the sentence about values.

| Item | SQL that the backend writes (by hand) | Letter case in the oracle | Probe |
|------|---------------------------------------|---------------------------|-------|
| `f: Val` | `f='Val'` | case-sensitive | `eq-case` |
| `f: [A, B]` | `f='A' OR f='B'` | case-sensitive | `eq-list-case` |
| `f: a*c` (a wildcard) | `f LIKE 'a%c' ESCAPE '\'` | ASCII letters are folded | `wildcard-case` |
| `f\|contains`, `f\|startswith`, `f\|endswith` | `f LIKE '%Val%' ESCAPE '\'` and its two relatives | ASCII letters are folded | `contains-case`, `startswith-case`, `endswith-case` |
| `f\|cidr` | `f LIKE '192.0.2.%' ESCAPE '\'` | a `LIKE` test on the text of the address | `cidr-like` |
| `f\|cased: Val` | `f GLOB 'Val'` | case-sensitive | `cased-case` |
| `f\|re: ...` | `f REGEXP '...'` | case-sensitive | `re-case` |
| `f\|re\|i: ...` | `f REGEXP '(?i)...'` | folded, with the Unicode rules of Python | `re-i`, `re-i-non-ascii` |
| a field name | a column name | not case-sensitive | `field-name-case` |
| the group-by fields of a correlation | `lower(...)` on a text value | folded | by hand: two records with `user` `Alice` and `alice` are one group |

- "ASCII letters are folded": `name|contains: ÉTÉ` on `{"name": "été"}` is quiet
  (probe `contains-non-ascii`).
- Equality is case-sensitive because the backend writes SQL `=`: "Sigma compares
  strings case-insensitively; SQLite's "=" does not, unless the column is declared
  COLLATE NOCASE" [3]. The backend option `collate_nocase` is off by default. The
  oracle does not set it, and its columns have no collation.
- A wildcard in a value makes the item a `LIKE` test, so its letter-case rule changes.

What the specification and the query languages say:

| Query language | Equality | Part of a value | Regular expression |
|----------------|----------|-----------------|--------------------|
| Sigma specification [1] [2] | not case-sensitive | not case-sensitive; `cased`: "Values are applied case sensitively." | "Regex is matched case-sensitive by default." |
| KQL (Azure Data Explorer documentation) [14] [15] | `==` case-sensitive; `=~` not | `contains`, `startswith`, `endswith`: not case-sensitive | `matches regex`: "a case-sensitive regular expression value" |
| ES\|QL [11] | not verified | `LIKE` on a `text` field "treats the field as a `keyword`"; "the pattern matching is case-sensitive and must match the exact string indexed" | `RLIKE`: the same two sentences |
| EQL [13] | `:` "(equal, case-insensitive)"; "Most EQL operators are case-sensitive by default." | `:` with a wildcard: the same operator | `regex` "(case-sensitive)"; "For case-insensitive matching, use `regex~`." |
| Elasticsearch `wildcard` and `regexp` queries [10] | not verified | `case_insensitive`: "Default is false which means the case sensitivity of matching depends on the underlying field’s mapping." | the same sentence |
| GoogleSQL [17] | "If string not assigned collation, the string comparison is case-sensitive." | `'Foo' LIKE '%foo%'`: "Returns FALSE" | RE2 [7]: flag `i` "case-insensitive (default false)" |
| Splunk SPL | not verified | not verified | not verified |

The GoogleSQL rows quote the documentation of the open GoogleSQL project. Its README
names BigQuery as a product that uses GoogleSQL [17]. That the BigQuery reference has
the same sentences: not verified.

What the installed backends write for one item (conversions run by hand) [24]:

- Kusto: `f =~ "Val"`, `f contains "Val"`, `f matches regex "^Val"`. A wildcard in a
  value becomes `f matches regex "a.*c"`. In KQL that test is case-sensitive, and it
  holds when the value "contains a match" [14].
- ES|QL: `f=="Val"`, `f like "*Val*"`, `f rlike "^Val"`.
- EQL: `f:"Val"`, and `f regex~ "^Val"` for a `|re` item with no `|i`: not case-sensitive.
- `|cased`: the Splunk, Lucene, ES|QL and Kusto backends stop with "Case-sensitive
  string matching is not supported by backend". The EQL backend writes `f == "Val"`.

The variant `cs_like` is the model of a `LIKE` that does not fold letter case. Our
inference: GoogleSQL `LIKE` and ES|QL `LIKE` on a `text` field are such tests. No
variant folds the letter case of equality (section 11).

A rule that reads a value whose letter case the sender chooses relies on that fold.
The expected list of the gate holds one such difference (reason `LIKE_CASE`, section
9): a webhook URL with an upper-case scheme. On a store whose match is case-sensitive,
the query must make the field lower-case first: no list of values holds each mix of
letter cases.

## 4. Lists

A list field is JSON text in the oracle. Thus:

- Equality on a list field does not match an element (probe `list-equality`).
- `|contains` matches in the text (probe `list-contains`).
- A value with JSON punctuation (the quotes of an element, `, `, `: `, the order of
  two keys) matches this one text (probes `list-quotes`, `list-blank`, `list-key-order`).

A search of the two files of the Sigma specification found no sentence about a field
of a record that holds a list or an object (a search for key words, not a reading of
each sentence). Its sentence about a value is about the value in the rule: "the key
is a field in the log data and the value is a string or integer value" [1]. Each
backend and each store decides.

| Store | What a list field is | Words of the source | Nearest variant (our inference) |
|-------|----------------------|---------------------|---------------------------------|
| the oracle | one text value | section 2 | the default |
| GoogleSQL `JSON` value [17] | a parsed value; a function makes the text | "Whitespace characters aren't preserved." "The order of the members of an object isn't guaranteed or preserved." `TO_JSON_STRING` prints `{"id":1,"coordinates":[10,20]}` | `compact`; `sorted` is one sample of a different key order |
| Kusto `dynamic` [16] | a property bag or an array; a function makes the text | "The slots are unordered." `dynamic_to_json()`: "The pairs are sorted by the names"; its example has no blank | `sorted` |
| Elasticsearch, a list of scalars [8] | one field with many values | "there is no dedicated `array` data type. Any field can contain zero or more values by default" | `multi` |
| Elasticsearch, a list of objects [8] | leaf fields; the objects are not kept apart | "By default, arrays of objects are flattened during indexing." "queries may match fields across different objects in the array" | none (section 11) |
| ES\|QL [12] | a multivalued field | "Unless otherwise documented functions will return `null` when applied to a multivalued field." | none |
| Athena table for CloudTrail, AWS example [20] | `requestparameters` is a `STRING` | "are listed as type `STRING` in the query, but are `STRUCT` data type used in JSON. Therefore, to get data out of these fields, use `JSON_EXTRACT` functions." The blanks and the key order of that text: not verified | not known |
| Elastic AWS integration [22] | `aws.cloudtrail.request_parameters` is the result of `requestParameters.toString()` | a rule of Elastic looks for `add=` in that field, so the text is not JSON (our inference) | none (section 11) |
| Splunk | not verified | | |

The variant `multi` is this model: a list field has one value for each element. A
scalar element is the value itself. An element that is an object or a list is its
default JSON text. An item holds when it holds on one value. An empty list has no
value. Under `multi`, `list-equality` fires, and `list-quotes` and `list-empty-exists`
are quiet.

A store that explodes a list into leaf fields (Elasticsearch, for a list of objects)
or into indexed keys (`field.0`, `field.1`) has no field that holds the text of the
list. Such a store cannot run a rule that reads a list as text: the item never
matches there, and the conversion does not fail. The gate does not model that store.
[`check_provider_mappings.py`](check_provider_mappings.py) prints that mode
(`exploded`) as a warning for the Kubernetes audit rules, and
[`pipelines/README.md`](pipelines/README.md) says what a backend pipeline must do.

What a rule can do:

- Do not match a blank after `,` or `:`. Write the white space as optional
  (`"action":\s*"ADD"`), or give the two forms of the text.
- Do not rely on the key order of an object, or record the difference
  ([`variants/expected.json`](variants/expected.json), reason `KEY_ORDER`).
- A value that names one element without JSON punctuation holds as text and as one
  value (probe `list-contains`).

Example. `T1098.001/gcp_workload_identity_federation_sa_binding.yml` and
`T1199/gcp_workforce_principalset_privileged_binding.yml` match the text of
`protoPayload.serviceData.policyDelta.bindingDeltas`. In the IAM API that field is
`repeated BindingDelta binding_deltas` [18]. Sample queries of Google read it as a
structure: `UNNEST(...bindingDeltas)` in BigQuery, `UNNEST(JSON_QUERY_ARRAY(...))` in
Log Analytics [19]. Our inference: a store that gives the field as text must write
the text, and it decides blanks and key order. Which text a real store gives for
this field: not verified. The two rules accept the text with and without a blank
after a colon (closed entry C17 of [`RULE_DEFECTS.md`](RULE_DEFECTS.md)). They still
need the key order of the record when a delta has a condition (open entry C19).

## 5. Null and a missing field

- A missing field and a JSON `null` are the same value, SQL `NULL`. The item `f: null`
  holds on the two (probes `null-absent`, `null-json-null`). `f|exists: false` holds on
  a record without `f` (probe `exists-false-absent`). `f|exists: true` does not hold
  on a JSON `null` (probe `exists-json-null`).
- An empty string is not `NULL`. The item `f: ''` does not hold on a record without
  `f` (probe `empty-absent`), and `f: null` does not hold on an empty string (probe
  `null-empty`). The specification says of `''` and `null`: "The application of
  these values depends on the target SIEM system." [1]
- `not` is two-valued. The backend writes `NOT COALESCE((<test>), 0)` [3], so a test
  on a missing field is false, and `s and not f` keeps a record that has no field of
  `f` (probe `not-absent`).
- In SQL's three-valued logic the same record is lost. By hand: the detection of
  `not-absent`, compiled with `sigma_eval.backend(three_valued=True)`, on
  `EventTable(three_valued=True)`: quiet.
  [`check_null_safety.py`](check_null_safety.py) fails a rule whose hits differ
  between the two logics.

## 6. Types

The table has no column types, and the oracle does no conversion.

- A number and its text are not equal, in each direction (probes `number-text`,
  `text-number`). An integer equals the float of the same value (probe `int-float`).
- `LIKE` and `REGEXP` read a number as its text (probes `like-on-number`,
  `re-on-number`).
- `flag: true` becomes `(flag='true' OR flag=1)` (by hand). It fires on JSON `true`
  and on the text `"true"` (probes `bool-true`, `bool-on-text`). The text item
  `flag: 'true'` does not hold on JSON `true` (probe `text-on-bool`).
- `|gt` and `|lt` are the SQLite operators. There a text value is larger than each
  number, so `n|gt: 5` fires on `{"n": "1"}` (probe `gt-text`). This is the result of
  the run; the SQLite documentation was not read for it.

Write each value in the type of the log source. What a store with typed columns does
with a different type: not verified.

## 7. Regular expressions

- SQLite has no `REGEXP` of its own (by hand: `no such function: REGEXP`). The oracle
  supplies it: `re.search(pattern, str(value))` of Python. The sub-modifiers `|i`, `|m`
  and `|s` become the prefix `(?i)`, `(?m)`, `(?s)` of the pattern (by hand). The
  probes `re-i`, `re-m`, `re-s` and `re-dot-newline` show what each prefix does.
- It is a search: `re.search` gives no match "if no position in the string matches
  the pattern" [6]. Probe `re-search`. A search of the two files of the specification
  found no sentence that says if `|re` is a search or a match of the full value. In
  this repository it is a search. A rule that must match the full value writes `^`
  and `$` (probe `re-anchored`).
- Python accepts constructs that other engines refuse. By hand: `line|re: 'a(?=b)'`
  on `{"line": "ab"}` fires. [`check_sigma_regex.py`](../.github/scripts/check_sigma_regex.py)
  keeps each `|re` value in a portable subset; see
  [Portable regular expressions](README.md#portable-regular-expressions).

| Construct | Python `re` (the oracle) [6] | RE2 [7] | Lucene (Elasticsearch `regexp`) [9] | KQL [14] [15] |
|-----------|------------------------------|---------|-------------------------------------|---------------|
| how much of the value | a search | GoogleSQL `REGEXP_CONTAINS`: "a partial match" [17] | "the regular expression must match the entire string" | `matches regex`: "LHS contains a match for RHS" |
| `^`, `$` | anchors | anchors | "does not support anchor operators" | anchors |
| `$` before a last line break | matches: "the end of the string or just before the newline at the end of the string" | does not match: "at end of text (like `\z` not `\Z`)" | no `$` | "End of a haystack or end-of-line with multi-line mode." |
| `\s` | "Unicode whitespace characters", with "the non-breaking spaces" | `[\t\n\f\r ]` | not verified | "Whitespace (`\p{White_Space}`)" |
| `\d`, `\w` | "any Unicode decimal digit"; "Unicode word characters" | `[0-9]`; `[0-9A-Za-z_]` | not verified | "Digit (`\p{Nd}`)"; a Unicode word character |
| `(?=re)`, `(?!re)`, `(?<=re)`, `(?<!re)`, `\1` | accepted | "(NOT SUPPORTED)" | not verified | the page has no entry for them |
| a repetition count above 1000 | accepted (by hand: `a{1001}`) | rejected | not verified | not verified |

Two differences stay in the portable subset. Python and RE2 accept the pattern and
give different answers:

- `$` as the last character, on a value that ends with a line break (probe
  `re-dollar-newline`).
- `\s` on a blank that is not one of the five characters of RE2, for example a
  no-break space (probe `re-space-class`).

The variant `re2` runs each `|re` item with RE2 where the module `re2` (the package
google-re2) is installed, as in CI. Without the module the gate says `NOT RUN` for
it, and the `re2` column of the table in section 10 is then what the gate declares.
The two probes above were also run by hand with google-re2 1.1.20251105, the version
of the CI job: each gave the declared answer.

## 8. A system call that the kernel rejected

- A `SYSCALL` record of auditd has the fields `success` ("whether the syscall was
  successful or not") and `exit` ("syscall exit code"). "If the exit value is >= 0
  this is true/yes otherwise its false/no." [23]
- The audit rules of this repository ([`audit/atomic.rules`](audit/atomic.rules)) have
  no filter on `success`. So auditd also writes the record of a rejected call. No run
  on the machine of the author proves this sentence (auditd did not run there). It
  rests on the text of [23], on that file, and on the controls of the Linux
  validator, which read such records in CI ("Controls" in [`README.md`](README.md)).
- No auditd rule of this repository reads `success` or `exit`. So the logic of each
  rule matches the record of a rejected call. By hand: one positive case of
  `T1068/userfaultfd_syscall.yml`, of `T1685/io_uring_setup.yml` and of
  `T1014/bpf_prog_load.yml`, with `success` set to `no` and `exit` to `-1`: each fires.
- A store that holds the record runs the same items on it. Thus a SIEM that runs such
  a rule as written alerts on the attempt, not on the completed technique. How the
  pipeline of a given SIEM names `success` and `exit`: not verified.
- The Linux validator ([`validate_detections.py`](validate_detections.py)) is stricter
  than the rule: a case passes when the syscalls succeeded (`success=yes`). That gate
  is in the validator. A SIEM does not have it.
- If a rule must mean "the call succeeded", add the item `success: 'yes'` to the rule.
  Then the rule, its cases and its controls say the same thing. No rule of this
  repository has that item today.
- Cloud logs have the same question. In CloudTrail, `errorCode` is "The AWS service error
  if the request returns an error." [21] A rule that must not match such a request reads it.

## 9. The gate

[`check_variants.py`](check_variants.py) runs each rule again on the same records,
one time for each variant. The event sets are each case of the sidecar and, for a
cloud rule, the attack fixture and the benign fixture of each `MANIFEST` row. In CI
it is the job representation-variants of
[`detection-quality.yml`](../.github/workflows/detection-quality.yml), a hard gate
for each rule.

| Variant | What changes | Section |
|---------|--------------|---------|
| `compact` | the text of a list has no blank: `flatten(separators=(",", ":"))` | 4 |
| `sorted` | as `compact`, and the keys of each object are sorted | 4 |
| `multi` | a list field has one value for each element | 4 |
| `cs_like` | `LIKE` does not fold letter case: `EventTable(case_sensitive_like=True)` | 3 |
| `re2` | RE2 matches each `\|re` item: `EventTable(regexp=...)` | 7 |

- A **difference** is an event set whose hits are not the hits of the default run. The
  hits are the records that fire; for a correlation, they are the alerts.
- A **loss**: a record that fires by default is quiet. On a positive case or an attack
  fixture, the rule misses the technique in that representation.
- A **gain**: a record that is quiet by default fires. On a near-miss, the item in
  `breaks` does not hold the case. On a filtered case, the filter does not apply. On a
  confounder, a benign case or a benign fixture, it is a false positive.
- **Weakened**: a near-miss or a filtered case stays quiet, but its `breaks` item is
  no longer the single flip that fires the rule. This is a note, not a failure.
- Each variant must change the answer of a golden probe that names it. If not, the
  gate stops with exit code 2.
- The variant `multi` cannot check a correlation rule on records with a list, or an
  item with `|neq` on a list. The gate fails such a rule.

[`variants/expected.json`](variants/expected.json) lists the expected differences. One
entry is one event set under one variant: the rule, the case or fixture, the fault,
the hits that are lost and gained (each hit is the list of its record numbers), the
changed items, a reason, a `why` and, where one exists, the open entry of
[`RULE_DEFECTS.md`](RULE_DEFECTS.md). The gate proves each reason on each run:

| Reason | Variant | The gate proves |
|--------|---------|-----------------|
| `KEY_ORDER` | `sorted` | the event set does not differ under `compact`, and each changed item reads a list |
| `LIKE_CASE` | `cs_like` | each changed item is a `LIKE` test |
| `LIST_TEXT` | `multi` | each changed item reads a field that is a list in the record |

The gate fails on a difference that is not in the list. It also fails on an entry
whose fault, hits or items changed, on an entry with no difference (stale), on a
reason that it cannot prove, on an entry with no `why`, and on a `defect` that is not
an open entry which names the rule. An entry is a human decision, as a budget or a
waiver is: propose it in the pull request (`--propose` prints the list of the run).
On a pull request, `--baseline-expected` fails an entry that the list of the base
branch does not hold as it is on the head.

| Exit code | Meaning |
|-----------|---------|
| 0 | no new difference, and the list holds |
| 1 | a rule fails, the list does not hold, or the probe table of this document is not current |
| 2 | a variant is not in force; `--require-re2` was given and the module is missing; `--baseline-expected` names no base tree |

## 10. The golden probes

Each row is one probe: its detection as a rule file writes it, its one record, and the
answer by default and under each variant (`fires` or `quiet`).
`python3 detections/check_variants.py --self-test` proves each cell.
`--write-doc` writes this table, and `--check-doc` fails when the table is not the
table of the run, when the text of this document names a probe that is not a row,
and when a row has no name in the text. CI runs the self-test and `--check-doc`.

<!-- probes:begin -->
<!-- Generated by detections/check_variants.py --write-doc from its table PROBES. Do not edit by hand. -->

| probe | statement | detection | record | default | compact | sorted | multi | cs_like | re2 |
|---|---|---|---|---|---|---|---|---|---|
| `eq-case` | equality is case-sensitive (SQL `=`; Sigma's default is not) | `verb: 'Create'` | `{"verb": "create"}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `eq-list-case` | a list of values is an OR of equalities; each one is case-sensitive | `verb: ['Create', 'Update']` | `{"verb": "update"}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `contains-case` | \|contains ignores ASCII case (LIKE) | `verb\|contains: 'Create'` | `{"verb": "create"}` | fires | fires | fires | fires | quiet | fires |
| `startswith-case` | \|startswith ignores ASCII case (LIKE) | `verb\|startswith: 'CRE'` | `{"verb": "create"}` | fires | fires | fires | fires | quiet | fires |
| `endswith-case` | \|endswith ignores ASCII case (LIKE) | `verb\|endswith: 'ATE'` | `{"verb": "create"}` | fires | fires | fires | fires | quiet | fires |
| `wildcard-case` | a wildcard value is LIKE, so it ignores ASCII case; the same value without the wildcard does not | `verb: 'CRE*'` | `{"verb": "create"}` | fires | fires | fires | fires | quiet | fires |
| `contains-non-ascii` | LIKE folds ASCII letters only | `name\|contains: 'ÉTÉ'` | `{"name": "été"}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `cased-case` | \|cased is case-sensitive (GLOB) | `verb\|cased: 'Create'` | `{"verb": "create"}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `cidr-like` | \|cidr matches an address of the network (a LIKE test on its text) | `ip\|cidr: '192.0.2.0/24'` | `{"ip": "192.0.2.77"}` | fires | fires | fires | fires | fires | fires |
| `list-equality` | equality on a list never matches (the field is the JSON text) | `user.groups: 'system:masters'` | `{"user": {"groups": ["system:masters", "dev"]}}` | quiet | quiet | quiet | fires | quiet | quiet |
| `list-contains` | \|contains matches inside the JSON text of a list | `user.groups\|contains: 'system:MASTERS'` | `{"user": {"groups": ["system:masters", "dev"]}}` | fires | fires | fires | fires | quiet | fires |
| `list-quotes` | a value with the JSON quotes of an element matches the text only | `user.groups\|contains: '"system:masters"'` | `{"user": {"groups": ["system:masters", "dev"]}}` | fires | fires | fires | quiet | fires | fires |
| `list-blank` | the JSON text has a blank after each `,` and `:` | `user.groups\|contains: '"system:masters", "dev"'` | `{"user": {"groups": ["system:masters", "dev"]}}` | fires | quiet | quiet | quiet | fires | fires |
| `list-no-blank` | the text without blanks does not match by default | `user.groups\|contains: '"system:masters","dev"'` | `{"user": {"groups": ["system:masters", "dev"]}}` | quiet | fires | fires | quiet | quiet | quiet |
| `list-key-order` | the JSON text keeps the key order of the record | `rules\|re: '\"verbs\":\s*\[[^\]]*\],\s*\"apiGroups\"'` | `{"rules": [{"verbs": ["*"], "apiGroups": [""]}]}` | fires | fires | quiet | fires | fires | fires |
| `list-scalars-text` | a scalar element is as JSON writes it (`true`, `null`, a string in quotes) | `v: '[1, true, null, "x"]'` | `{"v": [1, true, null, "x"]}` | fires | quiet | quiet | quiet | fires | fires |
| `list-leaf-no-field` | a name below a list is not a field | `rules.verbs\|exists: true` | `{"rules": [{"verbs": ["*"]}]}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `list-empty-exists` | an empty list is the text `[]`, so the field exists | `items\|exists: true` | `{"items": []}` | fires | fires | fires | quiet | fires | fires |
| `object-empty-exists` | an empty object leaves no field | `spec\|exists: true` | `{"spec": {}}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `object-no-field` | an object with a leaf has no field of its own | `spec\|exists: true` | `{"spec": {"a": 1}}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `object-leaf` | a leaf of an object is a field with a dotted name | `spec.a: 1` | `{"spec": {"a": 1}}` | fires | fires | fires | fires | fires | fires |
| `list-non-ascii` | the JSON text escapes a non-ASCII character | `names\|contains: 'é'` | `{"names": ["café"]}` | quiet | quiet | quiet | fires | quiet | quiet |
| `re-case` | \|re is case-sensitive | `verb\|re: 'Create'` | `{"verb": "create"}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `re-i` | \|re\|i ignores case | `verb\|re\|i: 'Create'` | `{"verb": "create"}` | fires | fires | fires | fires | fires | fires |
| `re-i-non-ascii` | \|re\|i folds a non-ASCII letter too | `name\|re\|i: 'ÉTÉ'` | `{"name": "été"}` | fires | fires | fires | fires | fires | fires |
| `re-search` | \|re is a search, not a match of the whole value | `apiVersion\|re: 'v1'` | `{"apiVersion": "apps/v1beta1"}` | fires | fires | fires | fires | fires | fires |
| `re-anchored` | with `^` and `$`, \|re must match the whole value | `apiVersion\|re: '^v1$'` | `{"apiVersion": "apps/v1beta1"}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `re-dot-newline` | `.` does not match a line break | `line\|re: 'a.b'` | `{"line": "a\nb"}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `re-s` | with \|s, `.` matches a line break | `line\|re\|s: 'a.b'` | `{"line": "a\nb"}` | fires | fires | fires | fires | fires | fires |
| `re-m` | with \|m, `^` matches at the start of each line | `line\|re\|m: '^b'` | `{"line": "a\nb"}` | fires | fires | fires | fires | fires | fires |
| `re-space-class` | `\s` matches a no-break space in Python re, not in RE2 | `line\|re: 'rewrite\sname'` | `{"line": "rewrite\u00a0name"}` | fires | fires | fires | fires | fires | quiet |
| `re-dollar-newline` | `$` matches before a final line break in Python re, not in RE2 | `line\|re: 'end$'` | `{"line": "the end\n"}` | fires | fires | fires | fires | fires | quiet |
| `field-name-case` | a field name matches without regard to letter case (SQLite columns); check_null_safety.py fails a rule that needs it | `Verb: 'create'` | `{"verb": "create"}` | fires | fires | fires | fires | fires | fires |
| `number-text` | the text of a number does not equal the number | `code: '200'` | `{"code": 200}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `text-number` | a number does not equal the text of the number | `code: 200` | `{"code": "200"}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `number-number` | a number equals the number | `code: 200` | `{"code": 200}` | fires | fires | fires | fires | fires | fires |
| `int-float` | an integer equals the float of the same value | `code: 200` | `{"code": 200.0}` | fires | fires | fires | fires | fires | fires |
| `like-on-number` | LIKE reads a number as its text | `code\|startswith: '2'` | `{"code": 200}` | fires | fires | fires | fires | fires | fires |
| `re-on-number` | \|re reads a number as its text | `code\|re: '^2[0-9][0-9]$'` | `{"code": 200}` | fires | fires | fires | fires | fires | fires |
| `gt-text` | \|gt puts a text value above each number (the order of SQLite) | `n\|gt: 5` | `{"n": "1"}` | fires | fires | fires | fires | fires | fires |
| `bool-true` | `field: true` holds on a JSON true | `flag: true` | `{"flag": true}` | fires | fires | fires | fires | fires | fires |
| `bool-on-text` | `field: true` holds on the text `true` too | `flag: true` | `{"flag": "true"}` | fires | fires | fires | fires | fires | fires |
| `text-on-bool` | the text `true` does not equal a JSON true (the table holds 1) | `flag: 'true'` | `{"flag": true}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `null-absent` | `field: null` holds on a record without the field | `verb: 'delete', dryRun: null` | `{"verb": "delete"}` | fires | fires | fires | fires | fires | fires |
| `null-json-null` | `field: null` holds on a JSON null | `verb: 'delete', dryRun: null` | `{"verb": "delete", "dryRun": null}` | fires | fires | fires | fires | fires | fires |
| `null-empty` | `field: null` does not hold on an empty string | `f: null` | `{"f": ""}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `empty-absent` | an empty string does not match a record without the field | `verb: 'get', f: ''` | `{"verb": "get"}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `exists-json-null` | `\|exists: true` does not hold on a JSON null | `f\|exists: true` | `{"f": null}` | quiet | quiet | quiet | quiet | quiet | quiet |
| `exists-false-absent` | `\|exists: false` holds on a record without the field | `verb: 'get', f\|exists: false` | `{"verb": "get"}` | fires | fires | fires | fires | fires | fires |
| `not-absent` | `not filter` keeps a record without the filter's field (two-valued; check_null_safety.py runs the three-valued logic) | `(verb: 'delete') and not (dryRun: 'All')` | `{"verb": "delete"}` | fires | fires | fires | fires | fires | fires |

<!-- probes:end -->

## 11. What the gate does not model

- **The benign corpus.** `score_benign.py` scores each rule in the default
  representation. The gate runs cases and fixtures.
- **A list of objects as leaf fields, or a list as indexed keys** (section 4).
  [`check_provider_mappings.py`](check_provider_mappings.py) reports that model
  (`exploded`) for the Kubernetes audit rules, and it does not fail on it.
- **Equality that is not case-sensitive** (KQL `=~`, EQL `:`), and **a `|re` that is
  not case-sensitive** (the EQL backend writes `regex~`). A rule that is quiet because
  of the letter case of such a value can fire there.
- **A regular expression that must match the full value** (Lucene). See
  [Portable regular expressions](README.md#portable-regular-expressions).
- **A text that is not JSON**, such as the text of the Elastic AWS integration (section 4).
- **A key order other than** the order of the record and the sorted order.
- **Typed columns** (section 6).
- **Three-valued logic.** [`check_null_safety.py`](check_null_safety.py) is the gate
  for it (section 5).
- **Splunk.** No statement about Splunk in this document is verified.

## 12. Sources

Each source was read on 2026-11-14. The documentation sites of the products were not
reachable from the machine of the author. So each quotation is from the source file of
the page in the public repository of the product (`raw.githubusercontent.com`), on the
branch that the link names. That the live page says the same today: not verified.
Sources 20 and 21 are archived copies of the AWS user guides. Source 3 was also run.
Source 24 was run, not read.

1. [Sigma specification 2.1.0, rules](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)
2. [Sigma specification 2.1.0, modifiers](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md)
3. [pySigma SQLite backend 2.0.0, `sqlite.py`](https://github.com/SigmaHQ/pySigma-backend-sqlite/blob/v2.0.0/sigma/backends/sqlite/sqlite.py) (the installed file is identical)
4. [SQLite, `ext/icu/README.txt`](https://github.com/sqlite/sqlite/blob/master/ext/icu/README.txt)
5. [Python 3.13, `json`](https://github.com/python/cpython/blob/3.13/Doc/library/json.rst)
6. [Python 3.13, `re`](https://github.com/python/cpython/blob/3.13/Doc/library/re.rst)
7. [RE2 syntax](https://github.com/google/re2/wiki/Syntax)
8. [Elasticsearch, arrays](https://github.com/elastic/elasticsearch/blob/main/docs/reference/elasticsearch/mapping-reference/array.md)
9. [Elasticsearch, regular expression syntax](https://github.com/elastic/elasticsearch/blob/main/docs/reference/query-languages/query-dsl/regexp-syntax.md)
10. Elasticsearch, [`wildcard` query](https://github.com/elastic/elasticsearch/blob/main/docs/reference/query-languages/query-dsl/query-dsl-wildcard-query.md) and [`regexp` query](https://github.com/elastic/elasticsearch/blob/main/docs/reference/query-languages/query-dsl/query-dsl-regexp-query.md)
11. ES|QL, [`LIKE`](https://github.com/elastic/elasticsearch/blob/main/docs/reference/query-languages/esql/_snippets/generated/x-pack-esql/operators/detailedDescription/like.md) and [`RLIKE`](https://github.com/elastic/elasticsearch/blob/main/docs/reference/query-languages/esql/_snippets/generated/x-pack-esql/operators/detailedDescription/rlike.md)
12. [ES|QL, multivalued fields](https://github.com/elastic/elasticsearch/blob/main/docs/reference/query-languages/esql/esql-multivalued-fields.md)
13. [EQL syntax](https://github.com/elastic/elasticsearch/blob/main/docs/reference/query-languages/eql/eql-syntax.md)
14. [KQL, string operators](https://github.com/MicrosoftDocs/dataexplorer-docs/blob/main/data-explorer/kusto/query/datatypes-string-operators.md)
15. KQL, [regex syntax](https://github.com/MicrosoftDocs/dataexplorer-docs/blob/main/data-explorer/kusto/query/regex.md) and [`matches regex`](https://github.com/MicrosoftDocs/dataexplorer-docs/blob/main/data-explorer/kusto/query/matches-regex-operator.md)
16. KQL, [the `dynamic` type](https://github.com/MicrosoftDocs/dataexplorer-docs/blob/main/data-explorer/kusto/query/scalar-data-types/dynamic.md) and [`dynamic_to_json()`](https://github.com/MicrosoftDocs/dataexplorer-docs/blob/main/data-explorer/kusto/query/dynamic-to-json-function.md)
17. [GoogleSQL](https://github.com/google/googlesql/tree/master/docs), "used across several of Google's SQL products, both publicly and internally, including BigQuery" (its `README.md`): `operators.md`, `collation-concepts.md`, `string_functions.md`, `data-types.md`, `json_functions.md`
18. [Google IAM API, `policy.proto`](https://github.com/googleapis/googleapis/blob/master/google/iam/v1/policy.proto)
19. Google Cloud Community Security Analytics, query 2.21 for [BigQuery](https://github.com/GoogleCloudPlatform/security-analytics/blob/main/backends/bigquery/sql/2_21_permissions_granted_to_impersonate_SA.sql) and for [Log Analytics](https://github.com/GoogleCloudPlatform/security-analytics/blob/main/backends/log_analytics/sql/2_21_permissions_granted_to_impersonate_SA.sql)
20. [Amazon Athena User Guide, archived source, `cloudtrail-logs.md`](https://github.com/awsdocs/amazon-athena-user-guide/blob/main/doc_source/cloudtrail-logs.md)
21. [AWS CloudTrail User Guide, archived source, record contents](https://github.com/awsdocs/aws-cloudtrail-user-guide/blob/master/doc_source/cloudtrail-event-reference-record-contents.md)
22. Elastic, [the CloudTrail ingest pipeline of the AWS integration](https://github.com/elastic/integrations/blob/main/packages/aws/data_stream/cloudtrail/elasticsearch/ingest_pipeline/default.yml) and [a detection rule that reads its field](https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_ec2_ebs_snapshot_shared_with_another_account.toml)
23. Linux audit, [`auditctl(8)`](https://github.com/linux-audit/audit-userspace/blob/master/docs/auditctl.8) and [the field dictionary](https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv)
24. pySigma backends as installed on the machine of the author, with pySigma 1.5.1: [the Splunk backend 2.1.0](https://pypi.org/project/pysigma-backend-splunk/2.1.0/), [the Elasticsearch backend 2.1.1](https://pypi.org/project/pySigma-backend-elasticsearch/2.1.1/), [the Kusto backend 1.0.1](https://pypi.org/project/pySigma-backend-kusto/1.0.1/). Each query in section 3 is the output of a conversion run; the package pages were not read. These three packages are not in [`requirements.txt`](requirements.txt).
