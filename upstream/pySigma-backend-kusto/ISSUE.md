# pySigma-backend-kusto: staged issue (not filed)

**Where to file:** [AttackIQ/pySigma-backend-kusto](https://github.com/AttackIQ/pySigma-backend-kusto)
(the `Repository` URL in the PyPI metadata of `pySigma-backend-kusto` 1.0.1; tag `v1.0.1` is
commit `c83f737a39f1084f30022150482f8dbbc035034b`, checked with `git ls-remote` on
2026-10-24). `SigmaHQ/pySigma-backend-kusto` does not resolve as a public repository (`git ls-remote` asks for credentials). Filing is a human step
(see [UPSTREAM.md](../../UPSTREAM.md)): open one issue with the text below from your own account.

All line numbers are in `sigma/backends/kusto/kusto.py` at `v1.0.1` (the file in the PyPI wheel
is the same, SHA-256 `2f50752082402054fbea9fee396da75b36fcd050e5b7b562138fd676f1e0a740`). Each
item reproduces with pySigma 1.5.1, pySigma-backend-kusto 1.0.1 and a pipeline that maps
`objectRef.` to `ObjectRef.` (det-eng's
[`detections/pipelines/kubernetes_aks_auditlogs.yml`](../../detections/pipelines/kubernetes_aks_auditlogs.yml));
`python3 detections/pipelines/convert_k8s.py --self-test` reproduces each one and checks the
workaround (`KqlPathBackend` in [`convert_k8s.py`](../../detections/pipelines/convert_k8s.py)).

---

**Title:** Dotted field names are emitted as string literals (and five related KQL defects)

1. **Dotted field names become string literals.** `field_quote = "'"` with
   `field_quote_pattern = "^\w+$"` and `field_quote_pattern_negation = True` (lines 49-57) put
   every field name that is not one word in single quotes. In KQL `'...'` is a string literal,
   not a column, so a condition on a nested `dynamic` path compares two constants.
   Rule `sel: {objectRef.resource: pods}`: expected `ObjectRef.resource =~ "pods"`, actual
   `'ObjectRef.resource' =~ "pods"`.
   Suggested fix: do not quote a dotted path of identifiers
   (`^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*$`), and write any other key with bracket notation
   (`Col['key.with/dots']`).
2. **A value list with a wildcard value renders the field twice.**
   `convert_condition_as_in_expression` (lines 176-232) quotes the field, then builds a new
   condition with the quoted name for each wildcard value, so it is quoted again:
   `objectRef.name: [kyverno, 'kyverno-*']` gives
   `'ObjectRef.name' in~ ("kyverno") or ''ObjectRef.name'' startswith "kyverno-"`. A value
   with an inner wildcard in such a list (lines 214-225) becomes unordered `contains` terms
   (`a*b` becomes `contains "a" and contains "b"`), which also matches `b...a`.
   Suggested fix: build each wildcard sub-condition from the Sigma field name, with the
   single-value conversion.
3. **A single value with an inner wildcard is unanchored and case-sensitive.**
   `wildcard_match_expression` (line 82) gives `verb: 'a*b'` as `Verb matches regex "a.*b"`.
   Sigma matches the whole value without case; `matches regex` matches a substring and is
   case-sensitive. A Sigma wildcard also matches a line break, and in a KQL regex `.` does
   not match `\n` without the `s` flag (learn.microsoft.com/kusto/query/re2), so a
   multi-line value (a CoreDNS Corefile) does not match `'*forward*8.8.8.8*'`.
   Suggested fix: `{field} matches regex "(?is)^{regex}$"`.
4. **A list of numbers is tested as strings.** `responseStatus.code: [200, 202]` gives
   `'ResponseStatus.code' in~ ("200", "202")` (the numbers go through `convert_value_str`,
   lines 188-197). `in~` takes strings, and the backend's own comment (line 159) says `=~`
   cannot be used with numbers. A value read from a `dynamic` column must also be cast
   ("After subscripting a dynamic object, you must cast the value to a simple type",
   learn.microsoft.com/kusto/query/scalar-data-types/dynamic). Suggested fix:
   `tolong(<path>) in (200, 202)`, and `tolong(<path>) == N` / `tolong(<path>) > N`
   (`todouble()` for a non-integer) for a `dynamic` path. Note: `tolong()` also converts a
   string (`tolong("0") == 0`), so the cast matches a string-typed number too.
5. **A boolean is compared with `=~`.** `requestObject.spec.hostPID: true` gives
   `'RequestObject.spec.hostPID' =~ true`; `=~` takes strings
   (learn.microsoft.com/kusto/query/equals-operator). Suggested fix: `tobool(<path>) == true`
   on a `dynamic` path, `<column> == true` on a column. Note: `tobool()` also gives true for
   the string `"true"` and for any non-zero number (`tobool(123) == true`,
   learn.microsoft.com/kusto/query/tobool-function).
6. **A plain value list under `|all` becomes a term search.** `and_in_operator = "has_all"`
   (lines 138-140) gives `objectRef.name|all: [a, b]` as `'ObjectRef.name' has_all ("a", "b")`.
   `has_all` searches for terms in the field (learn.microsoft.com/kusto/query/has-all-operator);
   Sigma means that the field equals each value. Suggested fix: render each value with the
   single-value conversion, joined by `and` (`ObjectRef.name =~ "a" and ObjectRef.name =~ "b"`).

---

When upstream fixes an item and the pin in `detections/requirements-convert.txt` moves, the
converter self-test fails on purpose at that item's "defect ... reproduces" check: remove that
part of the workaround then.
