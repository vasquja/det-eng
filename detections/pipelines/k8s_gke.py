"""
pySigma processing pipeline: product kubernetes / service audit rules -> GKE Kubernetes
audit entries in Cloud Logging (LogEntry JSON, protoPayload of type
google.cloud.audit.AuditLog, protoPayload.serviceName "k8s.io").

    from k8s_gke import gke_cloud_audit
    sqliteBackend(processing_pipeline=gke_cloud_audit()).convert(collection)

sigma-cli's -p loads only YAML files and installed plugins, so convert with
detections/pipelines/convert_k8s.py (see detections/pipelines/README.md).

The target names are the LogEntry JSON names that the repository's GCP rules already
use (protoPayload.methodName in detections/sigma/T1098.001/gcp_*.yml). GKE does not
keep the audit.k8s.io/v1 Event. It encodes it as follows (sources below; "unverified"
marks what no public GKE record shows):

  audit.k8s.io/v1 Event      GKE LogEntry
  verb, objectRef.resource,  protoPayload.methodName
  objectRef.subresource        io.k8s.<group>.<version>.<resource>[.<subresource>].<verb>
                               <group> is "core", or the API group with ".k8s.io" removed
                               and its labels reversed (rbac.authorization.k8s.io ->
                               authorization.rbac)
  objectRef.apiGroup,        protoPayload.resourceName
  objectRef.namespace,         <group>/<version>[/namespaces/<ns>]/<resource>[/<name>[/<sub>]]
  objectRef.name               <group> is "core" or the full API group name; a namespace
                               object is core/v1/namespaces/<name>. A create without a
                               subresource: no <name> when it failed; when it succeeded,
                               the created object's name (a generateName create shows the
                               generated name, which the native objectRef never holds).
                               Known loss: objectRef.namespace: X also holds on the create
                               of namespace X (core/v1/namespaces/X is also the prefix of
                               namespace X); the native Event has no namespace there
                               (kube-apiserver v1.36.4 requestinfo.go lines 194-196,
                               audit/request.go lines 130-131). The anchor
                               method-and-resource-names.json holds it (known_differences)
  objectRef.apiGroup: null   protoPayload.methodName io.k8s.core.<version>.* (the core
                               group: the native Event omits an empty apiGroup), or the
                               non-resource form. objectRef.apiGroup: '' never matches the
                               native Event, so it fails conversion
  user.username              protoPayload.authenticationInfo.principalEmail
  impersonatedUser.username  protoPayload.authenticationInfo.authoritySelector (Elastic's
                               GKE rules say so; no public record shows it: unverified)
  sourceIPs                  protoPayload.requestMetadata.callerIp (one address, not a list)
  userAgent                  protoPayload.requestMetadata.callerSuppliedUserAgent
  requestObject/responseObject  protoPayload.request / protoPayload.response (a
                               google.protobuf.Struct: an object; how GKE records a JSON
                               patch, an array body, is unverified)
  annotations.<key>          labels.<key>

Sources (retrieved 2026-10-23; see detections/pipelines/SOURCES.md):
  GoogleCloudPlatform/gke-mcp pkg/tools/logging/schemas/k8s_audit_logs.md (lines 10-34);
  GoogleCloudPlatform/khi test/logs/k8s_audit/*.yaml (real-shape GKE entries) and
  pkg/task/inspection/googlecloud/k8saudit/extractor.go + extractor_test.go
  (parseResourceTarget, parseKubernetesOperation);
  falcosecurity/plugins plugins/k8saudit-gke/pkg/k8sauditgke/convert.go (ConvertLogEntry);
  googleapis google/cloud/audit/audit_log.proto (AuditLog, AuthenticationInfo);
  elastic/detection-rules rules/integrations/gcp/*gke*.toml (methodName values, and the
  impersonation note in privilege_escalation_gcp_gke_api_request_impersonating_privileged_identity.toml);
  kubernetes/kubernetes v1.36.4 staging/src/k8s.io/apiserver (handlers/create.go,
  audit/request.go: objectRef.name of a create; apis/audit/v1/types.go: omitempty;
  endpoints/request/requestinfo.go: the namespace of a request).

No GKE field holds these, so a rule that reads them fails conversion on purpose (the
mapping harness reports the rule as NOT PORTABLE with the reason):
  user.groups, user.uid, user.extra  AuthenticationInfo has principalEmail only
  impersonatedUser.groups/uid/extra  no source shows them
  requestURI                         resourceName is the object path; the query string
                                     (dryRun, command, ...) is not recorded
  responseStatus.*                   the sources conflict: gke-mcp lists
                                     protoPayload.responseStatus.code (the HTTP status,
                                     "if present"); audit_log.proto and the KHI records
                                     have only protoPayload.status (a google.rpc.Status,
                                     0 = OK); Falco's converter infers the HTTP status
  level, stage, auditID              not recorded (auditID: insertId may hold it)
  any other field                    no GKE mapping

Every regular expression this pipeline writes stays in the repository's portable |re
subset (detections/README.md, "Portable regular expressions"): '^' only first, '$' only
last, no lookaround, a hyphen in a class escaped. check_provider_mappings.py lints each
one with .github/scripts/check_sigma_regex.py (RE2 too).
"""

from dataclasses import dataclass

from sigma.conditions import ConditionAND
from sigma.exceptions import SigmaTransformationError
from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    DetectionItemFailureTransformation,
    FieldMappingTransformation,
    FieldPrefixMappingTransformation,
)
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.rule import SigmaDetectionItem
from sigma.types import SigmaNull, SigmaRegularExpression, SigmaString, SpecialChars

# Portable-subset regex pieces.
VERSION = r"v[0-9]+((alpha|beta)[0-9]+)?"
SEG = r"[^/]+"
LABEL = r"[a-z0-9\-]+"            # one label of the methodName group, a resource
METHOD_PREFIX = r"^io\.k8s\.(" + LABEL + r"\.)+" + VERSION + r"\."
# A resourceName segment that is not "namespaces", without lookaround: every string
# that differs from "namespaces" at some position, or is longer.
_WORD = "namespaces"
NOT_NAMESPACES = "(" + "|".join(
    [f"[^{_WORD[0]}/][^/]*"]
    + [f"{_WORD[:i]}([^{_WORD[i]}/][^/]*)?" for i in range(1, len(_WORD))]
    + [f"{_WORD}[^/]+"]) + ")"
# The namespace object's own subresources (k8s.io/apiserver requestinfo.go,
# namespaceSubresources).
NAMESPACE_SUBRESOURCES = "(status|finalize)"


def lit(text):
    """Escape a literal for the portable |re subset: a backslash before punctuation."""
    return "".join(c if c.isalnum() or c == "_" else "\\" + c for c in text)


def value_regex(val, segment_class):
    """A SigmaString (plain, prefix*, *suffix, *infix*) as a regex inside one path segment."""
    if not isinstance(val, SigmaString):
        raise SigmaTransformationError(f"GKE pipeline: only string values map here, got {val!r}")
    out = []
    for part in val.s:
        if part == SpecialChars.WILDCARD_MULTI:
            out.append(segment_class + "*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            out.append(segment_class)
        elif isinstance(part, str):
            out.append(lit(part))
        else:
            raise SigmaTransformationError(f"GKE pipeline: unsupported placeholder in {val!r}")
    return "".join(out)


def gke_group(api_group):
    """objectRef.apiGroup -> the group label that methodName uses."""
    if api_group in ("", None):
        return "core"
    g = api_group[: -len(".k8s.io")] if api_group.endswith(".k8s.io") else api_group
    return ".".join(reversed(g.split(".")))


def _regexes(field, v):
    """The resource/method regexes for one objectRef or verb value (v already escaped)."""
    if field == "verb":
        return [r"\." + v + "$"]
    if field == "objectRef.resource":
        return [METHOD_PREFIX + v + r"(\." + LABEL + r")?\.[a-z]+$"]
    if field == "objectRef.subresource":
        return [METHOD_PREFIX + LABEL + r"\." + v + r"\.[a-z]+$"]
    if field == "objectRef.apiGroup":
        return ["^" + v + "/"]
    if field == "objectRef.namespace":
        # '$' may only end a portable pattern, so two values instead of (/|$).
        return ["^" + SEG + "/" + SEG + "/namespaces/" + v + "/",
                "^" + SEG + "/" + SEG + "/namespaces/" + v + "$"]
    if field == "objectRef.name":
        return [
            # a namespaced object, its subresource and any path after it
            "^" + SEG + "/" + SEG + "/namespaces/" + SEG + "/" + SEG + "/" + v + "(/.*)?$",
            # a cluster-scoped object other than a namespace, the same
            "^" + SEG + "/" + SEG + "/" + NOT_NAMESPACES + "/" + v + "(/.*)?$",
            # a namespace object and its own subresources
            "^" + SEG + "/" + SEG + "/namespaces/" + v + "$",
            "^" + SEG + "/" + SEG + "/namespaces/" + v + "/" + NAMESPACE_SUBRESOURCES + "$",
        ]
    raise KeyError(field)


TARGET = {"verb": "protoPayload.methodName", "objectRef.resource": "protoPayload.methodName",
          "objectRef.subresource": "protoPayload.methodName",
          "objectRef.apiGroup": "protoPayload.resourceName",
          "objectRef.namespace": "protoPayload.resourceName",
          "objectRef.name": "protoPayload.resourceName"}
# The character class a wildcard expands to: one methodName label or one path segment.
WILDCARD_CLASS = {"protoPayload.methodName": "[^.]", "protoPayload.resourceName": "[^/]"}
# `objectRef.subresource: null` (the null-safe selections): a methodName with no
# subresource label, the non-resource form (io.k8s.<verb>, unverified), or no methodName.
NO_SUBRESOURCE = [METHOD_PREFIX + LABEL + r"\.[a-z]+$", r"^io\.k8s\.[a-z]+$"]
# `objectRef.apiGroup: null`: the core group (io.k8s.core.<version>.), the non-resource
# form, or no methodName. A group whose reversed labels start with "core" is followed by
# another label, not a version, so it does not match.
CORE_GROUP = [r"^io\.k8s\.core\." + VERSION + r"\.", r"^io\.k8s\.[a-z]+$"]


@dataclass
class GkeObjectRefTransformation(DetectionItemTransformation):
    """Rewrite verb / objectRef.* items into regexes on methodName / resourceName."""

    def apply_detection_item(self, item: SigmaDetectionItem):
        if item.field not in TARGET:
            return None
        target = TARGET[item.field]
        values = []
        if item.field == "objectRef.apiGroup" and any(isinstance(v, SigmaNull) for v in item.value):
            if not all(isinstance(v, SigmaNull) for v in item.value):
                raise SigmaTransformationError("GKE pipeline: objectRef.apiGroup: null cannot be "
                                               "listed with other values (it maps to methodName)")
            return SigmaDetectionItem("protoPayload.methodName", [],
                                      [SigmaRegularExpression(r) for r in CORE_GROUP] + [SigmaNull()],
                                      value_linking=item.value_linking, negated=item.negated,
                                      source=item.source)
        for val in item.value:
            if isinstance(val, SigmaNull):
                if item.field != "objectRef.subresource":
                    raise SigmaTransformationError(
                        f"GKE pipeline: {item.field}: null has no GKE form")
                values += [SigmaRegularExpression(r) for r in NO_SUBRESOURCE] + [SigmaNull()]
                continue
            if item.field == "objectRef.apiGroup":
                if not isinstance(val, SigmaString) or val.contains_special():
                    raise SigmaTransformationError("GKE pipeline: objectRef.apiGroup must be a "
                                                   "plain value")
                group = val.to_plain()
                if group == "":
                    raise SigmaTransformationError(
                        "GKE pipeline: objectRef.apiGroup: '' never matches the native Event "
                        "(it omits an empty apiGroup); write objectRef.apiGroup: null for the "
                        "core group")
                v = lit(group)
            else:
                v = value_regex(val, WILDCARD_CLASS[target])
            values += [SigmaRegularExpression(r) for r in _regexes(item.field, v)]
        if len(values) > len(item.value) and item.value_linking is ConditionAND:
            raise SigmaTransformationError(f"GKE pipeline: {item.field}|all cannot map: one "
                                           "value becomes several alternative regexes")
        return SigmaDetectionItem(target, [], values, value_linking=item.value_linking,
                                  negated=item.negated, source=item.source)


def _k8s_audit():
    return [LogsourceCondition(product="kubernetes", service="audit")]


# Field (regex on the rule's own field name) -> why GKE has no field for it.
UNAVAILABLE = {
    r"^user\.(groups|uid|extra(\..*)?)$":
        "AuditLog.authenticationInfo records principalEmail only (no groups, uid or extra)",
    r"^impersonatedUser\.(groups|uid|extra(\..*)?)$":
        "no public source shows how GKE records impersonated groups, uid or extra",
    r"^requestURI$":
        "GKE has no request URI: resourceName is the object path, and the query string "
        "(dryRun, command, ...) is not recorded",
    r"^responseStatus(\..*)?$":
        "the sources conflict on the HTTP status: gke-mcp lists protoPayload.responseStatus.code "
        "('if present'); audit_log.proto and the recorded KHI entries have only "
        "protoPayload.status, a google.rpc.Status (code 0 = OK); Falco's converter infers it",
    r"^(level|stage)$": "GKE does not record the audit level or stage",
    r"^auditID$": "GKE records no auditID field (insertId may hold it; not documented)",
}
# The names the pipeline writes; any other field fails conversion (fail closed).
MAPPED = r"^(protoPayload\.|labels\.)"


def gke_cloud_audit() -> ProcessingPipeline:
    items = [
        ProcessingItem(identifier=f"gke_unavailable_{i}",
                       transformation=DetectionItemFailureTransformation(
                           f"GKE pipeline cannot map this field: {why}"),
                       rule_conditions=_k8s_audit(),
                       field_name_conditions=[IncludeFieldCondition(fields=[pattern], mode="re")])
        for i, (pattern, why) in enumerate(UNAVAILABLE.items())
    ]
    items += [
        ProcessingItem(identifier="gke_service",
                       transformation=AddConditionTransformation(
                           conditions={"protoPayload.serviceName": "k8s.io"}, template=False),
                       rule_conditions=_k8s_audit()),
        ProcessingItem(identifier="gke_objectref",
                       transformation=GkeObjectRefTransformation(),
                       rule_conditions=_k8s_audit()),
        ProcessingItem(identifier="gke_fields",
                       transformation=FieldMappingTransformation({
                           "user.username": "protoPayload.authenticationInfo.principalEmail",
                           "impersonatedUser.username":
                               "protoPayload.authenticationInfo.authoritySelector",
                           "sourceIPs": "protoPayload.requestMetadata.callerIp",
                           "userAgent": "protoPayload.requestMetadata.callerSuppliedUserAgent",
                           "requestObject": "protoPayload.request",
                           "responseObject": "protoPayload.response",
                       }),
                       rule_conditions=_k8s_audit()),
        ProcessingItem(identifier="gke_prefixes",
                       transformation=FieldPrefixMappingTransformation({
                           "requestObject.": "protoPayload.request.",
                           "responseObject.": "protoPayload.response.",
                           "annotations.": "labels.",
                       }),
                       rule_conditions=_k8s_audit()),
        ProcessingItem(identifier="gke_unmapped",
                       transformation=DetectionItemFailureTransformation(
                           "GKE pipeline cannot map this field: no GKE LogEntry field holds it"),
                       rule_conditions=_k8s_audit(),
                       field_name_conditions=[IncludeFieldCondition(fields=[MAPPED], mode="re")],
                       field_name_condition_negation=True),
    ]
    return ProcessingPipeline(name="Kubernetes audit to GKE Cloud Audit Logs (LogEntry JSON)",
                              priority=20, items=items)
