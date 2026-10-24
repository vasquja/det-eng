#!/usr/bin/env python3
"""
Convert the Kubernetes audit rules for a managed-cluster log shape (AKS or GKE).

    python3 detections/pipelines/convert_k8s.py aks [--table AKSAudit] RULE.yml...
    python3 detections/pipelines/convert_k8s.py gke [--target sqlite] RULE.yml...
    python3 detections/pipelines/convert_k8s.py --self-test

aks  applies kubernetes_aks_auditlogs.yml and renders KQL with KqlPathBackend:
     pySigma-backend-kusto 1.0.1 plus the fixes below, the table name in front
     ("AKSAudit\\n| where ..."), and an `extend` line for each query-time column the
     query reads (RequestObjectNotBag, ResponseObjectNotBag). AKSAudit is a Log Analytics
     table, queried with KQL only, and only the kusto target writes those `extend` lines,
     so aks with any other --target is refused.
gke  applies the Python pipeline k8s_gke.gke_cloud_audit(). sigma-cli's -p cannot load
     a Python pipeline, so this script is its entry point. --target is any installed
     pySigma backend except kusto (sqlite ships with detections/requirements.txt). GKE
     logs that Microsoft Sentinel reads are in the GCPAuditLogs table, a different shape,
     so gke with --target kusto is refused.

Only rules with logsource product: kubernetes, service: audit convert. Each rule is
converted alone: a query is printed for each rule that converts, and for each rule that
does not, one line on stderr: "NOT PORTABLE: <rule>: <reason>" (the pipeline refuses a
field, or the logsource is not kubernetes/audit) or "CANNOT CONVERT: <rule>: <reason>"
(the converter cannot render a field). The exit code is 1 when a rule failed, 2 on a
usage error or a missing backend, else 0.

KqlPathBackend fixes these defects of pySigma-backend-kusto 1.0.1 (sigma/backends/kusto/
kusto.py; detections/pipelines/README.md has the upstream issue text):
  1. Quoting (lines 49-57): field_quote "'" with field_quote_pattern "^\\w+$" negated, so
     every field name that is not one word is put in single quotes. In KQL a
     single-quoted token is a string literal, so `'ObjectRef.resource' =~ "pods"`
     compares two constants and never reads the column. KqlPathBackend renders a field
     as a KQL path: the column, then `.key` for each identifier key and `['key']` for any
     other key. After a map name in MAP_PARENTS (annotations, labels, data, ...) the rest
     of the field is one key. Under any other key, the field splits at each dot; a part
     that holds a "/" and does not start with "$" (a strategic-merge directive) fails
     conversion, because it is part of a map key under a map the converter does not know.
  2. A value list with a wildcard value (convert_condition_as_in_expression, lines
     176-232): the stock backend renders the field, then renders that output again for
     each wildcard value (`''ObjectRef.name'' startswith ...`), and it splits a value
     with an inner wildcard into unordered `contains` terms. KqlPathBackend renders each
     wildcard value from the Sigma field name with the single-value form.
  3. A value with an inner wildcard (a*b): the stock backend writes an unanchored,
     case-sensitive `matches regex "a.*b"`. KqlPathBackend writes `matches regex
     "(?is)^a.*b$"`: Sigma strings match the whole value, case-insensitive, and a
     wildcard also matches a line break (as SQLite LIKE does in the native model; without
     the s flag, "." in a KQL regex does not match "\\n", so a multi-line value such as a
     Corefile would not match).
  4. Numbers: a number list becomes a string set under in~ (`code in~ ("200", "202")`),
     and in~ takes strings (learn.microsoft.com/kusto/query/in-operator). A value read
     from a dynamic column must be cast (learn.microsoft.com/kusto/query/scalar-data-types/
     dynamic, "Casting dynamic objects"). KqlPathBackend writes `tolong(<path>) in (200,
     202)`, `tolong(<path>) == 201` and `tolong(<path>) > 0` (todouble() for a number that
     is not an integer) on a dynamic path.
  5. Booleans: the stock backend writes `field =~ true`; =~ takes strings
     (learn.microsoft.com/kusto/query/equals-operator). KqlPathBackend writes
     `tobool(<path>) == true` on a dynamic path and `<column> == true` on a column.
     (tobool() and tolong() also convert other values: tobool(123) == true and
     tolong("0") == 0, where the native model does not match; detections/pipelines/
     README.md lists this as unverified on live data.)
  6. A plain value list under |all (and_in_operator, lines 138-140): the stock backend writes
     `field has_all ("a", "b")`, a term search (each value is a term in the field), not
     equality. KqlPathBackend writes `field =~ "a" and field =~ "b"`.
--self-test reproduces each defect with the stock backend where it shows, and proves the
fixes; it needs pySigma-backend-kusto (pip install -r detections/requirements-convert.txt).
"""

import argparse
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SIGMA_DIR = os.path.join(os.path.dirname(HERE), "sigma")
AKS_PIPELINE = os.path.join(HERE, "kubernetes_aks_auditlogs.yml")
RESULTS = os.path.join(HERE, "mapping_results.json")
AKS_TABLES = ("AKSAudit", "AKSAuditAdmin")
INSTALL_HINT = "pip install -r detections/requirements-convert.txt"

from sigma.collection import SigmaCollection  # noqa: E402
from sigma.exceptions import SigmaError  # noqa: E402
from sigma.processing.pipeline import ProcessingPipeline  # noqa: E402


class NotPortable(Exception):
    """The provider cannot express the rule (its logsource, or a field it does not record)."""


class UsageError(Exception):
    """A provider / target / table combination that this converter does not support."""


def load_gke_module():
    """Import k8s_gke.py by path (not via sys.path, so nothing else here can shadow a module)."""
    spec = importlib.util.spec_from_file_location("k8s_gke", os.path.join(HERE, "k8s_gke.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def aks_pipeline():
    with open(AKS_PIPELINE, encoding="utf-8") as fh:
        return ProcessingPipeline.from_yaml(fh.read())


def gke_pipeline():
    return load_gke_module().gke_cloud_audit()


PIPELINES = {"aks": aks_pipeline, "gke": gke_pipeline}

# Maps whose keys are free-form and can hold dots: annotation and label keys
# (kubectl.kubernetes.io/last-applied-configuration), ConfigMap and Secret keys
# (config.yaml, tls.crt), and the user's extra map (user.extra: authentication.
# kubernetes.io/pod-name on every pod-bound ServiceAccount token; also UserInfo.extra in
# a TokenReview or SubjectAccessReview body). After one of these names, the rest of the
# field is one key. A field that walks into a structured object under one of these names
# (a ControllerRevision's `data` is an object, not a map) is rendered wrong: no rule here
# reads one.
MAP_PARENTS = {"Annotations", "annotations", "labels", "matchLabels", "nodeSelector",
               "data", "stringData", "binaryData", "extra"}
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
KQL_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*|\['([^'\\]|\\.)*'\])*")

# Query-time columns: the request / response body unless it is a property bag. The
# native model (sigma_eval.flatten) keeps no value at the path of an object, so a
# whole-body item (requestObject|re, requestObject: null) reads only a JSON-patch list or
# raw text. In KQL an object column is not null and string operators read its JSON text,
# so the AKS pipeline maps the whole-body field to this column instead.
NOT_BAG = {"RequestObjectNotBag": "RequestObject", "ResponseObjectNotBag": "ResponseObject"}


def kql_extends(query):
    """The `| extend` lines that define the query-time columns this query reads."""
    return "".join(f'| extend {col} = iff(gettype({src}) == "dictionary", dynamic(null), {src})\n'
                   for col, src in NOT_BAG.items() if re.search(rf"\b{col}\b", query))


def kql_path(field):
    """A Sigma field name (dotted) as a KQL column path.

    Raises ValueError when the field cannot be split: its column is not an identifier,
    or a part that holds a "/" (and does not start with "$") is not under a map in
    MAP_PARENTS. Any other dotted part is split at each dot."""
    segments = field.split(".")
    if not _IDENT.fullmatch(segments[0]):
        raise ValueError(f"{field!r}: the column {segments[0]!r} is not a KQL identifier")
    out = [segments[0]]
    i = 1
    while i < len(segments):
        parent = segments[i - 1]
        key = ".".join(segments[i:]) if parent in MAP_PARENTS else segments[i]
        if _IDENT.fullmatch(key):
            out.append("." + key)
        else:
            if "/" in key and not key.startswith("$") and parent not in MAP_PARENTS:
                raise ValueError(f"{field!r}: the key {key!r} looks like part of a dotted "
                                 "map key (a label or annotation) under a map the converter "
                                 "does not know; add the map's name to MAP_PARENTS")
            out.append("['" + key.replace("\\", "\\\\").replace("'", "\\'") + "']")
        i += len(key.split(".")) if parent in MAP_PARENTS else 1
    return "".join(out)


def is_dynamic_path(path):
    """A rendered KQL path that subscripts a dynamic column (its value must be cast)."""
    return "." in path or "[" in path


def kql_backend_class():
    """KustoBackend with the fixes above (imported late: an optional dependency)."""
    from sigma.backends.kusto import KustoBackend
    from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR
    from sigma.types import SigmaNumber, SigmaString

    def number_operand(path, number):
        if not is_dynamic_path(path):
            return path
        return f"{'tolong' if isinstance(number, int) else 'todouble'}({path})"

    class KqlPathBackend(KustoBackend):
        """pySigma-backend-kusto, with KQL paths for fields and typed comparisons."""

        # Defect 3: a whole-value, case-insensitive match (Sigma string semantics), in
        # which a wildcard also matches a line break (the s flag), as in the native model.
        wildcard_match_expression = '{field} matches regex "(?is)^{regex}$"'

        def escape_and_quote_field(self, field_name):
            return kql_path(field_name)

        def convert_condition_field_eq_val_bool(self, cond, state):
            # Defect 5.
            path = self.escape_and_quote_field(cond.field)
            operand = f"tobool({path})" if is_dynamic_path(path) else path
            return operand + self.num_eq_token + self.bool_values[cond.value.boolean]

        def convert_condition_field_eq_val_num(self, cond, state):
            # Defect 4 (one number).
            path = self.escape_and_quote_field(cond.field)
            return number_operand(path, cond.value.number) + self.num_eq_token + str(cond.value)

        def convert_condition_field_compare_op_val(self, cond, state):
            # Defect 4 (lt, lte, gt, gte).
            path = self.escape_and_quote_field(cond.field)
            number = cond.value.number.number
            return self.compare_op_expression.format(
                field=number_operand(path, number),
                operator=self.compare_operators[cond.value.op], value=number)

        def convert_condition_as_in_expression(self, cond, state):
            # Defects 2, 4 and 6 (a value list).
            args = cond.args
            sigma_field = args[0].field
            path = self.escape_and_quote_field(sigma_field)
            is_or = isinstance(cond, ConditionOR)
            joiner = f"{self.token_separator}{self.or_token if is_or else self.and_token}" \
                     f"{self.token_separator}"
            numbers = [a.value.number for a in args if isinstance(a.value, SigmaNumber)]
            if numbers:
                if len(numbers) == len(args) and is_or:
                    operand = path if not is_dynamic_path(path) else (
                        "tolong" if all(isinstance(n, int) for n in numbers) else "todouble"
                    ) + f"({path})"
                    return f"{operand} in ({self.list_separator.join(str(n) for n in numbers)})"
                return joiner.join(str(self.convert_condition_field_eq_val(a, state)) for a in args)
            plain = [a.value for a in args
                     if isinstance(a.value, SigmaString) and not a.value.contains_special()]
            wild = [a.value for a in args
                    if isinstance(a.value, SigmaString) and a.value.contains_special()]
            parts = []
            if plain and is_or:
                parts.append(self.field_in_list_expression.format(
                    field=path, op=self.or_in_operator,
                    list=self.list_separator.join(self.convert_value_str(v, state)
                                                  for v in plain)))
            # Defect 6: |all over plain values is equality to each value (has_all would be
            # a term search), so under AND each plain value gets its own =~ term too.
            singles = wild if is_or else plain + wild
            for value in singles:
                parts.append(str(self.convert_condition_field_eq_val_str(
                    ConditionFieldEqualsValueExpression(field=sigma_field, value=value), state)))
            return joiner.join(parts)

    return KqlPathBackend


def installed_backends():
    from sigma.plugins import InstalledSigmaPlugins
    return InstalledSigmaPlugins.autodiscover().backends


def check_logsource(collection, provider):
    for rule in collection.rules:
        ls = rule.logsource
        if (ls.product, ls.service) != ("kubernetes", "audit"):
            raise NotPortable(f"logsource product: {ls.product}, service: {ls.service} is not "
                              f"kubernetes/audit; the {provider} pipeline maps only Kubernetes "
                              "audit rules")


def convert(provider, rule_texts, target=None, table=None):
    """Convert rule YAML texts. Returns a list of query strings (one per rule).

    Raises NotPortable (logsource, or a field the pipeline refuses: a SigmaError), ValueError
    (a field kql_path cannot split), UsageError, or ImportError (no Kusto backend)."""
    pipeline = PIPELINES[provider]()
    target = target or ("kusto" if provider == "aks" else "sqlite")
    if provider == "aks" and target != "kusto":
        raise UsageError(f"aks with --target {target}: AKSAudit is a Log Analytics table, "
                         "queried with KQL only, and the whole-body columns "
                         "(RequestObjectNotBag, ResponseObjectNotBag) are defined only by the "
                         "kusto target's extend lines")
    if provider == "gke" and target == "kusto":
        raise UsageError("gke with --target kusto: the GKE pipeline writes Cloud Logging LogEntry "
                         "names (protoPayload.methodName, ...), and GKE logs in Microsoft "
                         "Sentinel are in the GCPAuditLogs table, a different shape")
    if table and not (provider == "aks" and target == "kusto"):
        raise UsageError("--table is for aks with the kusto target only")
    kql = target == "kusto"
    if kql:
        backend = kql_backend_class()(processing_pipeline=pipeline)
    else:
        backends = installed_backends()
        if target not in backends:
            raise UsageError(f"no installed pySigma backend {target!r} "
                             f"(installed: {', '.join(sorted(backends))})")
        backend = backends[target](processing_pipeline=pipeline)
    out = []
    for text in rule_texts:
        collection = SigmaCollection.from_yaml(text)
        check_logsource(collection, provider)
        try:
            queries = backend.convert(collection)
        except SigmaError as e:
            raise NotPortable(str(e).split("\n")[0]) from e
        for query in queries:
            if kql:
                query = f"{table or 'AKSAudit'}\n{kql_extends(query)}| where {query}"
            out.append(query)
    return out


def admin_table_warning(rule_path):
    """A warning when the rule loses a positive case on AKSAuditAdmin (no get, no list)."""
    try:
        with open(RESULTS, encoding="utf-8") as fh:
            results = json.load(fh)
        rel = os.path.relpath(os.path.abspath(rule_path), SIGMA_DIR)
        lost = results["rules"][rel]["loses_positive_without_reads"]["aksauditadmin"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if lost:
        return (f"WARNING: {rel}: on AKSAuditAdmin (no get and list events) this rule loses "
                "positive cases (detections/pipelines/mapping_results.json, "
                "loses_positive_without_reads); query AKSAudit instead")
    return None


# ---------------------------------------------------------------- self-test
def _regex_search(regex, text):
    """re2.search when google-re2 is installed (KQL regexes use RE2 syntax), else re.search."""
    try:
        import re2
    except ImportError:
        return re.search(regex, text) is not None
    return re2.search(regex, text) is not None


def _rule(fields, logsource=None):
    """A one-selection rule (kubernetes/audit by default) that reads the given items."""
    import yaml
    return yaml.safe_dump({"title": "convert_k8s self-test", "status": "test",
                           "logsource": logsource or {"product": "kubernetes", "service": "audit"},
                           "detection": {"sel": fields, "condition": "sel"}})


def audit_rule_paths():
    """Every rule file whose logsource is product: kubernetes, service: audit."""
    import yaml
    out = []
    for root, _, files in sorted(os.walk(SIGMA_DIR)):
        for name in sorted(files):
            if not name.endswith(".yml"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as fh:
                docs = [d for d in yaml.safe_load_all(fh) if d]
            ls = (docs[0] if docs else {}).get("logsource") or {}
            if ls.get("product") == "kubernetes" and ls.get("service") == "audit":
                out.append(path)
    return out


def self_test():
    try:
        from sigma.backends.kusto import KustoBackend
    except ImportError:
        print(f"SELF-TEST ERROR: pySigma-backend-kusto is not installed ({INSTALL_HINT})")
        return 2
    import contextlib
    import io
    import tempfile
    problems = []

    def check(ok, what):
        print(f"{'ok  ' if ok else 'FAIL'}  {what}")
        if not ok:
            problems.append(what)

    def stock(text):
        return KustoBackend(processing_pipeline=aks_pipeline()).convert(
            SigmaCollection.from_yaml(text))[0]

    def where(fields):
        """The where clause for a one-selection rule; an exception becomes the text (so a
        regression shows as a FAIL line, not as a crash that hides the other checks)."""
        try:
            return convert("aks", [_rule(fields)])[0].split("| where ", 1)[1]
        except Exception as e:  # noqa: BLE001 (any failure is a self-test result)
            return f"<{type(e).__name__}: {str(e).splitlines()[0]}>"

    exec_rule = os.path.join(SIGMA_DIR, "T1609", "k8s_pod_exec_attach.yml")
    with open(exec_rule, encoding="utf-8") as fh:
        text = fh.read()
    print(f"      stock pySigma-backend-kusto: {stock(text)}")
    check("'ObjectRef.resource' =~ \"pods\"" in stock(text),
          "defect 1 reproduces: the stock backend quotes a dotted field as a string literal "
          "(if this fails, upstream fixed it: drop the quoting workaround)")
    fixed = convert("aks", [text])[0]
    print(f"      KqlPathBackend:              {fixed!r}")
    check(fixed == 'AKSAudit\n| where ObjectRef.resource =~ "pods" and '
                   '(ObjectRef.subresource in~ ("exec", "attach"))',
          "fix 1: KqlPathBackend reads the ObjectRef column path (exact query)")
    check(convert("aks", [text], table="AKSAuditAdmin")[0].startswith("AKSAuditAdmin\n| where "),
          "--table names the table")
    special = {
        "annotations.audit.k8s.io/truncated": "true",
        "requestObject.metadata.annotations.kubectl.kubernetes.io/last-applied-configuration|contains": "x",
        "requestObject.$deleteFromPrimitiveList/spec.$deleteFromPrimitiveList/replicas|contains": "0",
        "requestObject.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/pod": "unconfined",
        "requestObject.data.config.yaml|contains": "trr9000-marker",
        "requestObject.data.Corefile|contains": "forward",
        "requestObject.stringData.tls.crt|contains": "BEGIN",
        "user.extra.authentication.kubernetes.io/pod-name|contains": "trr9007-pod",
    }
    query = where(special)
    print(f"      special keys:                {query!r}")
    for want in ("Annotations['audit.k8s.io/truncated'] =~ \"true\"",
                 "RequestObject.metadata.annotations['kubectl.kubernetes.io/"
                 "last-applied-configuration'] contains \"x\"",
                 "RequestObject['$deleteFromPrimitiveList/spec']"
                 "['$deleteFromPrimitiveList/replicas'] contains \"0\"",
                 "RequestObject.spec.template.metadata.annotations['seccomp.security.alpha."
                 "kubernetes.io/pod'] =~ \"unconfined\"",
                 "RequestObject.data['config.yaml'] contains \"trr9000-marker\"",
                 "RequestObject.data.Corefile contains \"forward\"",
                 "RequestObject.stringData['tls.crt'] contains \"BEGIN\"",
                 "User.extra['authentication.kubernetes.io/pod-name'] contains \"trr9007-pod\""):
        check(want in query, f"fix 1 renders {want}")
    try:
        kql_path("RequestObject.spec.selector.example.com/key")
        check(False, "a key with '/' under an unknown map fails conversion")
    except ValueError as e:
        check("MAP_PARENTS" in str(e), f"a key with '/' under an unknown map fails conversion ({e})")
    check(kql_path("RequestObject.spec.foo.bar") == "RequestObject.spec.foo.bar",
          "any other dotted key splits at each dot (documented)")

    # Defect 2: a value list with a wildcard value renders the same path as one value.
    lists = [
        ({"requestObject.spec.$patch|contains": ["delete", "replace"]},
         "RequestObject.spec['$patch'] contains \"delete\" or "
         "RequestObject.spec['$patch'] contains \"replace\""),
        ({"requestObject.data.my-key": ["a", "b*"]},
         "RequestObject.data['my-key'] in~ (\"a\") or RequestObject.data['my-key'] startswith \"b\""),
        ({"annotations.authorization.k8s.io/reason": ["RBAC: allowed", "RBAC*"]},
         "Annotations['authorization.k8s.io/reason'] in~ (\"RBAC: allowed\") or "
         "Annotations['authorization.k8s.io/reason'] startswith \"RBAC\""),
        ({"requestObject.metadata.annotations.kubectl.kubernetes.io/last-applied-configuration"
          "|contains": ["privileged", "hostPID"]},
         "RequestObject.metadata.annotations['kubectl.kubernetes.io/last-applied-configuration'] "
         "contains \"privileged\" or RequestObject.metadata.annotations['kubectl.kubernetes.io/"
         "last-applied-configuration'] contains \"hostPID\""),
        ({"objectRef.name": ["kyverno", "kyverno-*", "a*b"]},
         "ObjectRef.name in~ (\"kyverno\") or ObjectRef.name startswith \"kyverno-\" or "
         "ObjectRef.name matches regex \"(?is)^a.*b$\""),
    ]
    stock_list = stock(_rule({"objectRef.name": ["kyverno", "kyverno-*"]}))
    check("''ObjectRef.name''" in stock_list,
          f"defect 2 reproduces: the stock backend renders a wildcard list's field twice "
          f"({stock_list})")
    for fields, want in lists:
        got = where(fields)
        check(got == want, f"fix 2: {list(fields)[0]} list renders one path per value: {got}")
    check(where({"verb": "a*b"}) == 'Verb matches regex "(?is)^a.*b$"',
          "fix 3: an inner wildcard is a whole-value, case-insensitive regex in which a "
          "wildcard also matches a line break")
    check('matches regex "a.*b"' in stock(_rule({"verb": "a*b"})),
          "defect 3 reproduces: the stock backend writes an unanchored case-sensitive regex")
    # A multi-line value (a Corefile): the native model (SQLite LIKE) matches a wildcard
    # across the line break, so the KQL regex must too. KQL regexes use RE2 syntax, where
    # "." matches "\n" only with the s flag (learn.microsoft.com/kusto/query/re2).
    corefile = "forward .\n  8.8.8.8 {\n}"
    for pattern in ("*forward*8.8.8.8*", "forward*8.8.8.8*"):
        got = where({"requestObject.data.Corefile": pattern})
        m = re.fullmatch(r'RequestObject\.data\.Corefile matches regex "(.*)"', got)
        regex = m.group(1).replace("\\\\", "\\") if m else None
        check(regex is not None and _regex_search(regex, corefile)
              and not _regex_search(regex.replace("(?is)", "(?i)", 1), corefile),
              f"fix 3: {pattern} matches a value with a line break, as natively, and would "
              f"not without the s flag ({got})")
    # Defect 6: a plain value list under |all is equality to each value, not has_all.
    stock_all = stock(_rule({"objectRef.name|all": ["trr9007-a", "trr9007-b"]}))
    check("has_all" in stock_all,
          f"defect 6 reproduces: the stock backend writes a plain |all list as has_all "
          f"({stock_all})")
    for fields, want in (
            ({"objectRef.name|all": ["trr9007-a", "trr9007-b"]},
             'ObjectRef.name =~ "trr9007-a" and ObjectRef.name =~ "trr9007-b"'),
            ({"objectRef.name|all": ["trr9007-a", "trr9007-b*"]},
             'ObjectRef.name =~ "trr9007-a" and ObjectRef.name startswith "trr9007-b"'),
            ({"objectRef.name|contains|all": ["trr9007-a", "trr9007-b"]},
             'ObjectRef.name contains "trr9007-a" and ObjectRef.name contains "trr9007-b"')):
        got = where(fields)
        check(got == want, f"fix 6: {fields} -> {got}")

    # Defects 4 and 5: typed comparisons on a dynamic path.
    typed = [
        ({"responseStatus.code": [200, 202]}, "tolong(ResponseStatus.code) in (200, 202)"),
        ({"responseStatus.code": 201}, "tolong(ResponseStatus.code) == 201"),
        ({"requestObject.spec.replicas|gt": 2147483647},
         "tolong(RequestObject.spec.replicas) > 2147483647"),
        ({"requestObject.spec.replicas|lt": 0}, "tolong(RequestObject.spec.replicas) < 0"),
        ({"requestObject.spec.weight|gte": 1.5}, "todouble(RequestObject.spec.weight) >= 1.5"),
        ({"responseStatus.code": [200, "x"]},
         "tolong(ResponseStatus.code) == 200 or ResponseStatus.code =~ \"x\""),
        ({"requestObject.spec.hostPID": True}, "tobool(RequestObject.spec.hostPID) == true"),
    ]
    stock_num = stock(_rule({"responseStatus.code": [200, 202]}))
    check('in~ ("200", "202")' in stock_num,
          f"defect 4 reproduces: the stock backend tests a number list as strings ({stock_num})")
    stock_bool = stock(_rule({"requestObject.spec.hostPID": True}))
    check(stock_bool.endswith("=~ true"),
          f"defect 5 reproduces: the stock backend writes =~ true ({stock_bool})")
    for fields, want in typed:
        got = where(fields)
        check(got == want, f"fixes 4-5: {fields} -> {got}")

    # The whole-body columns: a body that is an object is null there (native meaning).
    body = convert("aks", [_rule({"requestObject": None, "requestObject|re": "x"})])[0]
    check(body == 'AKSAudit\n| extend RequestObjectNotBag = iff(gettype(RequestObject) == '
                  '"dictionary", dynamic(null), RequestObject)\n| where '
                  'isnull(RequestObjectNotBag) and RequestObjectNotBag matches regex "x"',
          f"a whole-body item reads RequestObjectNotBag, defined by an extend line: {body!r}")
    check("| extend" not in fixed, "no extend line when the query reads no whole body")

    # Fail closed: the logsource, gke with kusto, --table with gke.
    for path, why in (("T1053.007/k8s_cri_job_pod.yml", "CRI"),
                      ("T1078.004/aws_cognito_identity_pool_unauth_enabled.yml", "CloudTrail")):
        with open(os.path.join(SIGMA_DIR, path), encoding="utf-8") as fh:
            rule_text = fh.read()
        for provider in ("aks", "gke"):
            try:
                convert(provider, [rule_text])
                check(False, f"{provider}: a {why} rule ({path}) is refused")
            except NotPortable as e:
                check("not kubernetes/audit" in str(e), f"{provider}: a {why} rule is refused ({e})")
    for provider, kwargs, what in (("gke", {"target": "kusto"}, "gke with --target kusto"),
                                   ("gke", {"table": "AKSAudit"}, "gke with --table"),
                                   ("aks", {"target": "sqlite"}, "aks with --target sqlite")):
        try:
            convert(provider, [text], **kwargs)
            check(False, f"{what} is refused")
        except UsageError as e:
            check(True, f"{what} is refused ({str(e)[:70]}...)")

    # main(): rule by rule; each failure on stderr with its rule; exit 1.
    with tempfile.TemporaryDirectory() as tmp:
        bad_key = os.path.join(tmp, "bad_key.yml")
        with open(bad_key, "w", encoding="utf-8") as fh:
            fh.write(_rule({"requestObject.spec.selector.example.com/key": "x"}))
        imp = os.path.join(SIGMA_DIR, "T1134", "k8s_impersonation.yml")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(["aks", exec_rule, imp, bad_key])
        check(rc == 1 and "ObjectRef.resource" in out.getvalue()
              and f"NOT PORTABLE: {os.path.relpath(imp)}: " in err.getvalue()
              and "CANNOT CONVERT: " in err.getvalue() and "bad_key.yml" in err.getvalue(),
              f"main converts rule by rule, names each failed rule on stderr, exit 1 "
              f"(rc={rc}; stderr: {err.getvalue().strip()[:200]!r})")

    # AKSAuditAdmin: a rule whose positives need get or list is flagged.
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        main(["aks", "--table", "AKSAuditAdmin", exec_rule])
    quiet = io.StringIO()
    host = os.path.join(SIGMA_DIR, "T1611", "k8s_podspec_host_access.yml")
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(quiet):
        main(["aks", "--table", "AKSAuditAdmin", host])
    check("WARNING: T1609/k8s_pod_exec_attach.yml: on AKSAuditAdmin" in err.getvalue()
          and not quiet.getvalue(),
          "--table AKSAuditAdmin warns for a rule that loses positives without get/list "
          "(k8s_pod_exec_attach), and not for one that does not (k8s_podspec_host_access)")

    # Every Kubernetes audit rule: each rendered field is a KQL path from a Sigma field
    # (rendered once), and the stock backend would have quoted every dotted one.
    rendered, inputs, converted, refused = set(), set(), 0, 0
    backend_cls = kql_backend_class()

    class Recording(backend_cls):
        def escape_and_quote_field(self, field_name):
            inputs.add(field_name)
            out = super().escape_and_quote_field(field_name)
            rendered.add(out)
            return out

    refused_rules = set()
    for path in audit_rule_paths():
        rel = os.path.relpath(path, SIGMA_DIR)
        with open(path, encoding="utf-8") as fh:
            rule_text = fh.read()
        try:
            Recording(processing_pipeline=aks_pipeline()).convert(
                SigmaCollection.from_yaml(rule_text))
            converted += 1
        except SigmaError:
            refused += 1
            refused_rules.add(rel)
        except ValueError as e:  # kql_path cannot render a field: a converter gap
            check(False, f"CANNOT CONVERT {rel}: {str(e).splitlines()[0]}")
    bad = sorted(p for p in rendered if not KQL_PATH.fullmatch(p))
    twice = sorted(p for p in inputs if "['" in p)
    quoted = sum(1 for p in rendered if "." in p or "[" in p)
    check(not bad and not twice and converted > 0,
          f"{converted} rule(s) convert ({refused} refused, NOT PORTABLE); "
          f"{len(rendered)} distinct field path(s), all valid KQL paths rendered once, {quoted} "
          "of them dotted (each one a string literal with the stock backend)"
          + (f"; bad: {bad}" if bad else "") + (f"; rendered twice: {twice}" if twice else ""))
    # The converter and the harness must agree: a rule is refused here exactly when
    # mapping_results.json (check_provider_mappings.py) says it is not portable to AKS.
    try:
        with open(RESULTS, encoding="utf-8") as fh:
            rows = json.load(fh)["rules"]
        harness = {rel for rel, row in rows.items()
                   if (row.get("providers", {}).get("aks") or {}).get("status") == "not_portable"}
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        harness = None
        check(False, f"mapping_results.json is readable ({e})")
    if harness is not None:
        mine = refused_rules & set(rows)  # rules with no sidecar are not in the results
        check(mine == harness,
              f"the rules the converter refuses are the rules mapping_results.json marks not "
              f"portable to AKS ({sorted(harness)}"
              + (f"; converter only: {sorted(mine - harness)}" if mine - harness else "")
              + (f"; harness only: {sorted(harness - mine)}" if harness - mine else "") + ")")
    print()
    if problems:
        print(f"SELF-TEST FAILED: {len(problems)} problem(s)")
        return 1
    print("SELF-TEST OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("provider", nargs="?", choices=sorted(PIPELINES))
    ap.add_argument("rules", nargs="*")
    ap.add_argument("--target", help="pySigma backend id (aks: kusto, gke: sqlite by default)")
    ap.add_argument("--table", choices=AKS_TABLES, help="aks/kusto only: the table to query")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.provider or not args.rules:
        ap.error("give a provider and at least one rule file")
    failed = 0
    for path in args.rules:
        rel = os.path.relpath(path)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        try:
            queries = convert(args.provider, [text], args.target, args.table)
        except ImportError as e:
            print(f"ERROR: {e} ({INSTALL_HINT})", file=sys.stderr)
            return 2
        except UsageError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        except NotPortable as e:
            print(f"NOT PORTABLE: {rel}: {e}", file=sys.stderr)
            failed += 1
            continue
        except (SigmaError, ValueError, NotImplementedError) as e:
            print(f"CANNOT CONVERT: {rel}: {str(e).splitlines()[0]}", file=sys.stderr)
            failed += 1
            continue
        if args.table == "AKSAuditAdmin":
            warning = admin_table_warning(path)
            if warning:
                print(warning, file=sys.stderr)
        for query in queries:
            print(f"// {rel}\n{query}\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
