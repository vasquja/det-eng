#!/usr/bin/env python3
"""
Which Kubernetes audit rule still works under which audit policy (offline).

Every Kubernetes audit rule (logsource product kubernetes, service audit) is
proven under the repository's lab policies (detections/k8s/audit-policy*.yaml).
A managed cluster runs its own policy, which the user often cannot change. This
script asks, for every sidecar case of every such rule, what the SAME request
leaves in the log under another policy, and replays that record through the real
rule with sigma_eval.py (the pySigma SQLite backend that every gate uses):

  1. It reads the request attributes from the case record (user, groups, verb,
     objectRef, requestURI) the way the API server builds them before it writes the
     record (k8s.io/apiserver pkg/endpoints/request/requestinfo.go and
     pkg/audit/request.go LogRequestMetadata, v1.36.4):
       - the user is `user` (the authenticated caller; impersonation runs after the
         audit filter, so `impersonatedUser` is not what the policy sees);
       - a missing objectRef.apiGroup or objectRef.namespace is "" (the core
         group; a cluster-scoped object), except for a Namespace object itself:
         for /api/v1/namespaces/<n> (and its status and finalize subresources)
         requestinfo.go sets the request namespace to <n>, so a record of such a
         request that leaves out objectRef.namespace is read with namespace <n>;
       - a create with no subresource is a POST to the collection, so the policy
         sees NO name: the record's objectRef.name comes from the body later
         (LogRequestObject), and `resourceNames` cannot select such a create;
       - a record with no objectRef is a non-resource request; its path is
         requestURI up to the first '?'.
  2. It evaluates the policy as the API server does
     (staging/src/k8s.io/apiserver/pkg/audit/policy/checker.go, v1.36.4): the first
     rule that matches wins; no match is level None. A rule matches when each field
     it sets matches: users (the user name), userGroups (any group), verbs, then
     namespaces / resources (resource requests only) or nonResourceURLs
     (non-resource requests only). In `resources`, group "*" is any group, an empty
     resource list is every resource of the group, "res/sub" names a subresource,
     "*" is every resource and subresource, "*/sub" a subresource of any resource,
     "res/*" the resource and all its subresources, and resourceNames (when set)
     must hold the request's name. A nonResourceURLs entry is "*", an exact path,
     or a prefix that ends in "*". Each rule's omitStages is the union of the
     rule's and the policy's (NewPolicyRuleEvaluator). Unknown keys are dropped
     with a warning, as the API server's lenient decoding fallback
     (pkg/audit/policy/reader.go) and library-go's yaml.Unmarshal do; validation
     errors (pkg/apis/audit/validation/validation.go) stop the run.
  3. It builds the records that request produces under that policy:
       - level None: no record;
       - the case record's own stage (ResponseComplete), unless the rule omits that
         stage;
       - a RequestReceived record too, unless the rule omits that stage. At
         RequestReceived the API server has only the request metadata
         (filters/audit.go: the stage is written before the handler runs), so that
         record has no requestObject, responseObject, responseStatus,
         impersonatedUser or annotations, and the objectRef as the policy saw it.
         Its `level` is the policy level (pkg/audit/context.go Init sets the event's
         level once for every stage), also where the case record is lower;
       - at level Metadata no requestObject and no responseObject, at Request no
         responseObject, and `level` set to the level of the record;
       - omitManagedFields (policy or rule) removes metadata.managedFields from the
         responseObject and from a requestObject that is not a patch
         (LogRequestPatch logs the raw patch);
       - a log category filter (AKS kube-audit-admin) drops the records whose
         verb it excludes.
     A record can only lose data: when the policy gives a HIGHER level than the
     case record holds, the record is kept as it is and the event is counted as
     "not modeled" (the simulator cannot invent the body the case lacks). When the
     rule also reads that missing body (a requestObject or responseObject field in
     its detection), the result of that case is unproven on that platform: it is
     counted in "not_modeled_reads" and the table marks the cell with "~".
  4. It runs the rule on the records of each case and reports, per rule and policy:
     positives that still fire, near-misses that stay quiet, and negatives
     (near-miss, filtered, confounder, benign) that START to fire, for example
     because a filter lost the body it reads: a false positive on that platform.
     Where a policy keeps the RequestReceived stage, one request writes two records,
     so a rule that fires on both alerts twice for one request (deduplicate by
     auditID, or filter on stage).
  5. Home check: each rule's home is the lab policy of the one lab validator whose
     MANIFEST registers the rule (the validator that proves it live in CI). Under
     its home policy every positive must fire and no negative may fire, because CI
     proves that live. --check, --update and the table fail when a rule has no
     home, more than one home, or a home column that breaks this.

The simulator models the audit POLICY only. It does not model what a provider does
after the log is written (CloudWatch's 1 MB entry limit on EKS, the AKSAudit table
columns, GKE's Admin Activity / Data Access split, a provider's own field names),
the ResponseStarted record of a long-running request (watch, exec, attach,
port-forward, proxy: it carries the same fields as ResponseComplete), the audit
truncate backend, or a dropped YAML apply body (RULE_DEFECTS.md K23).

Policies (POLICIES below): the three lab policies that a kind config mounts, and
the provider policies vendored under detections/k8s/provider-policies/ (sources,
licenses and digests in its SOURCES.md): EKS (the Best Practices Guide policy),
the GCE kube-up policy (cluster/gce/gci/configure-helper.sh, which the EKS user
guide links as "the audit policy" and the GKE audit-policy page names as the
script that generates GKE's policy), AKS (the policy Microsoft Learn publishes; the
kube-audit and kube-audit-admin categories), OpenShift (the library-go base policy
plus the Default or WriteRequestBodies profile rules, for 4.18 and later and for
4.17), and the k3s hardening-guide starter policy. Whether a provider runs the
published text unchanged is unverified (no live capture; backlog issue #55).

Usage:
    python3 detections/k8s_policy_coverage.py                 # print the table
    python3 detections/k8s_policy_coverage.py --detail        # and every lost case
    python3 detections/k8s_policy_coverage.py --update        # rewrite the JSON
    python3 detections/k8s_policy_coverage.py --check         # fail if it is stale
    python3 detections/k8s_policy_coverage.py --self-test     # evaluator unit cases
    python3 detections/k8s_policy_coverage.py --verify-sources   # network: compare
                                     # each vendored policy with its upstream text

--check recomputes the whole result and fails when detections/k8s/policy_coverage.json
differs from it: a rule's title, id, name, level, logsource or detection, a sidecar
file, a policy file, a validator's MANIFEST (a rule's home policy) or the evaluator's
output changed. A rule's description or comments are not part of it, and neither is
the evaluator's source: an edit of this script that keeps every result passes.
Regenerate it with --update in the same pull request. It also fails the home check
(step 5 above).

Machine-readable result (detections/k8s/policy_coverage.json), schema
"det-eng/k8s-policy-coverage/v1". A later version changes the schema string;
consumers (the generator of detections/k8s/PLATFORMS.md) must check it.

  {
    "schema": "det-eng/k8s-policy-coverage/v1",
    "generator": "detections/k8s_policy_coverage.py",
    "semantics": "<the Kubernetes source the evaluator follows>",
    "policy_order": [<policy id>, ...],          # column order
    "policies": {
      "<policy id>": {
        "kind": "lab" | "provider",
        "platform": "<who runs it>",
        "label": "<one line: what the column is>",
        "version": "<which release or text>",
        "status": "<what is verified about it>",
        "files": [{"path": "<repo path>", "sha256": "<hex>"}],
        "log_filter": null | {"drop_verbs": [...], "source": "<url>"},
        "rule_count": <int>,
        "warnings": ["<lenient-decoding or apiVersion note>", ...]
      }, ...
    },
    "rules": {
      "<T>/<stem>.yml": {
        "title": "...", "level": "<sigma level>",
        "rule_digest": "<hex>",     # sha256 of the rule's title, id, name, level,
                                    # logsource, detection and correlation
                                    # (canonical JSON; description and comments
                                    # are not part of it)
        "cases_sha256": "<hex>",    # sha256 of the sidecar file
        "home_policy": "<the lab policy of the validator whose MANIFEST
                        registers the rule>" | null,   # null fails the home check
        "case_counts": {"positive": n, "near-miss": n, "filtered": n,
                        "confounder": n, "benign": n},
        "results": {
          "<policy id>": {
            "positives": {"total": n, "firing": n,
                          "lost": [{"case": "<name>", "reason": <reason>,
                                    "policy_rules": [<int|null>, ...]}]},
            "near_misses": {"total": n, "quiet": n, "no_record": n},
            "negatives_firing": [{"case": "<name>", "kind": "<kind>",
                                  "reason": <reason>}],
            "not_modeled": n,         # events the policy logs above the case record
            "not_modeled_reads": n    # of those, events where the rule reads the
                                      # body the case record lacks (unproven)
          }, ...
        }
      }, ...
    },
    "summary": {"<policy id>": {"rules": n, "rules_all_positives": n,
                                "rules_some_positives": n, "rules_blind": n,
                                "positives": n, "positives_firing": n,
                                "negatives_firing": n, "not_modeled": n,
                                "not_modeled_reads": n}, ...}
  }

  <reason> is one of:
    "no-record"            every event of the case is dropped (level None, an
                           omitted stage, or the log category);
    "body-removed"         a record that the policy keeps is logged at a lower level
                           than the case record, so a requestObject/responseObject
                           the rule may read is gone;
    "partial-record"       some events of the case are dropped, and every record
                           that is kept holds all that the case record holds;
    "request-received"     (negatives only) only the extra RequestReceived record
                           fires;
    "other"                anything else (not expected; read the case).
  "policy_rules" lists, per event of the case, the 0-based index of the policy rule
  that decided its level (null: no rule matched, so level None).
  "quiet" counts near-misses with a record that do not fire; "no_record" those whose
  records are all dropped (quiet, but they prove nothing on that platform).
  A rule is "blind" under a policy when it has positives and none fires.
"""

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import yaml  # noqa: E402
import sigma_eval  # noqa: E402
import rule_cases  # noqa: E402

SIGMA = os.path.join(HERE, "sigma")
OUT = os.path.join(HERE, "k8s", "policy_coverage.json")
PP = "detections/k8s/provider-policies"
SCHEMA = "det-eng/k8s-policy-coverage/v1"
SEMANTICS = ("kubernetes v1.36.4 staging/src/k8s.io/apiserver: pkg/audit/policy/checker.go "
             "(rule matching), pkg/audit/policy/reader.go (lenient decoding), "
             "pkg/endpoints/filters/audit.go and pkg/audit/request.go (stages, levels)")

LEVELS = ("None", "Metadata", "Request", "RequestResponse")
STAGES = ("RequestReceived", "ResponseStarted", "ResponseComplete", "Panic")
RULE_KEYS = {"level", "users", "userGroups", "verbs", "resources", "namespaces",
             "nonResourceURLs", "omitStages", "omitManagedFields"}
GROUP_KEYS = {"group", "resources", "resourceNames"}
POLICY_KEYS = {"apiVersion", "kind", "metadata", "rules", "omitStages", "omitManagedFields"}
CASE_KINDS = ("positive", "near-miss", "filtered", "confounder", "benign")
RETRIEVED = "2026-10-23"

AKS_DOC = ("https://raw.githubusercontent.com/MicrosoftDocs/azure-aks-docs/main/"
           "articles/aks/monitor-aks.md")
LG = ("https://raw.githubusercontent.com/openshift/library-go/{}/"
      "pkg/operator/apiserver/audit/manifests/{}")

# Each vendored file: where it comes from, how it is cut from the upstream text,
# and the SHA-256 of the vendored bytes (the self-test recomputes it; SOURCES.md
# must list it). "upstream_sha256" is the digest of the whole upstream file on the
# retrieval date. --verify-sources fetches the URL again and compares.
SOURCES = {
    f"{PP}/eks/eks-bpg-audit-policy.yaml": {
        "url": "https://raw.githubusercontent.com/aws/aws-eks-best-practices/master/"
               "latest/bpg/security/detective.adoc",
        "extract": ("fenced-adoc", "audit policy for EKS is as follows:"),
        "license": "MIT-0 (sample code) / CC BY-SA 4.0 (documentation)",
        "upstream_sha256": "8c59ba4b9e847f04568d122eaddb673de50fa43327421d7cc57f7507c2880568",
        "sha256": "858a452342a050cf6e7539b60c9a371af665a177d1b0526f7c1c2bf797247319",
    },
    f"{PP}/gce/gce-kube-up-audit-policy.yaml": {
        "url": "https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.4/"
               "cluster/gce/gci/configure-helper.sh",
        "extract": ("gce-heredoc", "function create-master-audit-policy {"),
        "license": "Apache-2.0",
        "upstream_sha256": "ffe7ab144be24f2490b050e3e23ba3f3bd3185796b0e0ec42a5aeb40f135d1ab",
        "sha256": "dbbba87c7a53483b5ce06310122c8008b5eb39d1e78507c95da27bd3b8932fb1",
        # The file after its comment header (the source's notice and the change
        # notice): the bytes the function writes.
        "body_sha256": "09063bc7e2fcd0f3065fe694cbb124b7998d53e0863ad67565c58227cd608121",
    },
    f"{PP}/aks/aks-audit-policy.yaml": {
        "url": AKS_DOC,
        "extract": ("fenced-md", "<summary>View the complete AKS audit policy</summary>"),
        "license": "MIT (code) / CC BY 4.0 (documentation)",
        "upstream_sha256": "1bf68ed7418379f98f47f4c3c907323c403e8a0f0e8e5df018dfdacdf7eea3f6",
        "sha256": "0b243c3ad50ed4789a4b30bef8e2c361e58e310542bd819134ae58510b18763f",
    },
    f"{PP}/openshift/base-policy-release-4.18.yaml": {
        "url": LG.format("release-4.18", "base-policy.yaml"),
        "extract": ("file", None), "license": "Apache-2.0",
        "upstream_sha256": "964c47ab88c0f23effad73a4dad5514aba7cf77575db0a23e8614c983cfd695b",
        "sha256": "964c47ab88c0f23effad73a4dad5514aba7cf77575db0a23e8614c983cfd695b",
    },
    f"{PP}/openshift/base-policy-release-4.17.yaml": {
        "url": LG.format("release-4.17", "base-policy.yaml"),
        "extract": ("file", None), "license": "Apache-2.0",
        "upstream_sha256": "94042b757e4730846c71e828622f67a75ad6d1bf94e0a88a36cdea2ea307180b",
        "sha256": "94042b757e4730846c71e828622f67a75ad6d1bf94e0a88a36cdea2ea307180b",
    },
    f"{PP}/openshift/default-rules-release-4.18.yaml": {
        "url": LG.format("release-4.18", "default-rules.yaml"),
        "extract": ("file", None), "license": "Apache-2.0",
        "upstream_sha256": "933d827a8d48bda129c7bae53436f6351dad63dc64699d64be7962bcae20c33c",
        "sha256": "933d827a8d48bda129c7bae53436f6351dad63dc64699d64be7962bcae20c33c",
    },
    f"{PP}/openshift/default-rules-release-4.17.yaml": {
        "url": LG.format("release-4.17", "default-rules.yaml"),
        "extract": ("file", None), "license": "Apache-2.0",
        "upstream_sha256": "933d827a8d48bda129c7bae53436f6351dad63dc64699d64be7962bcae20c33c",
        "sha256": "933d827a8d48bda129c7bae53436f6351dad63dc64699d64be7962bcae20c33c",
    },
    f"{PP}/openshift/writerequestbodies-rules-release-4.18.yaml": {
        "url": LG.format("release-4.18", "writerequestbodies-rules.yaml"),
        "extract": ("file", None), "license": "Apache-2.0",
        "upstream_sha256": "d3d6f45bc459bd1364286cc95619b96d648881d1af6d24b5544993ec798f6832",
        "sha256": "d3d6f45bc459bd1364286cc95619b96d648881d1af6d24b5544993ec798f6832",
    },
    f"{PP}/openshift/writerequestbodies-rules-release-4.17.yaml": {
        "url": LG.format("release-4.17", "writerequestbodies-rules.yaml"),
        "extract": ("file", None), "license": "Apache-2.0",
        "upstream_sha256": "7dde3830fa3ac32d94fb700d61e3d6693d011b5fb3673e5fc4101a4de8a968f1",
        "sha256": "7dde3830fa3ac32d94fb700d61e3d6693d011b5fb3673e5fc4101a4de8a968f1",
    },
    f"{PP}/k3s/k3s-hardening-starter-audit-policy.yaml": {
        "url": "https://raw.githubusercontent.com/k3s-io/docs/main/docs/security/"
               "hardening-guide.md",
        "extract": ("fenced-md", "A starter audit policy to log request metadata"),
        "license": "CC BY 4.0",
        "upstream_sha256": "a0818e611091201f5313d768ff3672b2f101435647ca7ca839bbc7afa2714fab",
        "sha256": "4c24658bceb8766ff68ad3fce45906665c140cdf35b0468c10123e2dcdaebd48",
    },
}

# The columns, in order. "files": the first is a Policy document, the others are
# YAML lists of rules appended to it (library-go GetAuditPolicy: base rules, then
# the profile rules). A lab policy names the validator whose kind cluster mounts
# it; its rules' sidecar positives must fire under it ("home").
POLICIES = [
    {"id": "lab-apiserver", "kind": "lab", "platform": "kind lab (CI)",
     "label": "API server lab policy (TRR9004-9010, TRR9025-9027)",
     "files": ["detections/k8s/audit-policy-apiserver.yaml"],
     "validator": "validate_apiserver_detections.py",
     "kind_config": "detections/k8s/kind-apiserver-cluster.yaml",
     "version": "this repository", "status": "proven live in CI"},
    {"id": "lab-k8s", "kind": "lab", "platform": "kind lab (CI)",
     "label": "TRR9002 lab policy (exec, attach, node proxy)",
     "files": ["detections/k8s/audit-policy.yaml"],
     "validator": "validate_k8s_detections.py",
     "kind_config": "detections/k8s/kind-audit-cluster.yaml",
     "version": "this repository", "status": "proven live in CI"},
    {"id": "lab-staticpod", "kind": "lab", "platform": "kind lab (CI)",
     "label": "TRR9003 lab policy (static pods)",
     "files": ["detections/k8s/audit-policy-staticpod.yaml"],
     "validator": "validate_staticpod_detections.py",
     "kind_config": "detections/k8s/kind-staticpod-cluster.yaml",
     "version": "this repository", "status": "proven live in CI"},
    {"id": "eks", "kind": "provider", "platform": "Amazon EKS",
     "label": "EKS audit policy as the EKS Best Practices Guide publishes it",
     "files": [f"{PP}/eks/eks-bpg-audit-policy.yaml"],
     "version": "aws-eks-best-practices master, latest/bpg/security/detective.adoc "
                "(apiVersion audit.k8s.io/v1beta1 in the text)",
     "status": "published text, a variant of the kube-up configure-helper.sh policy (it "
               "adds aws-auth writes at RequestResponse and serviceaccounts/token at "
               "Request, and drops a few kube-up identities); the EKS user guide "
               "(control-plane-logs) links that configure-helper.sh policy as its audit "
               "policy (the gce-kube-up column); neither text is verified on a live EKS "
               "cluster"},
    {"id": "gce-kube-up", "kind": "provider",
     "platform": "GCE kube-up (the policy the EKS user guide links; GKE unverified)",
     "label": "the policy kube-up's configure-helper.sh writes on GCE",
     "files": [f"{PP}/gce/gce-kube-up-audit-policy.yaml"],
     "version": "kubernetes v1.36.4 cluster/gce/gci/configure-helper.sh "
                "create-master-audit-policy (default, no custom policy)",
     "status": "the EKS user guide (control-plane-logs) links this configure-helper.sh "
               "policy as 'the audit policy', and the GKE audit-policy page names "
               "configure-helper.sh as the script that generates the policy; whether EKS "
               "or GKE runs this text unchanged, and GKE's Admin Activity / Data Access "
               "split of reads, are unverified (not modeled)"},
    {"id": "aks-kube-audit", "kind": "provider", "platform": "Azure AKS",
     "label": "AKS audit policy, kube-audit log category",
     "files": [f"{PP}/aks/aks-audit-policy.yaml"],
     "version": "Microsoft Learn 'Monitor Azure Kubernetes Service (AKS)', "
                "'View the complete AKS audit policy' (MicrosoftDocs/azure-aks-docs, "
                "ms.date 08/18/2026)",
     "status": "published text; the page says the policy is managed by AKS and cannot be "
               "customized"},
    {"id": "aks-kube-audit-admin", "kind": "provider", "platform": "Azure AKS",
     "label": "AKS audit policy, kube-audit-admin log category (no get and list)",
     "files": [f"{PP}/aks/aks-audit-policy.yaml"],
     "log_filter": {"drop_verbs": ["get", "list"], "source": AKS_DOC},
     "version": "as aks-kube-audit; the category 'excludes the get and list audit "
                "events' (same page)",
     "status": "published text; whether kube-audit-admin also drops watch is unverified "
               "(the page names get and list only)"},
    {"id": "openshift-default", "kind": "provider", "platform": "Red Hat OpenShift",
     "label": "OpenShift 4.18 and later, Default audit profile",
     "files": [f"{PP}/openshift/base-policy-release-4.18.yaml",
               f"{PP}/openshift/default-rules-release-4.18.yaml"],
     "version": "openshift/library-go release-4.18 (release-4.19 to release-4.21 and "
                "master hold the same text)",
     "status": "source text; the kube-apiserver operator release-4.18 vendors the same "
               "files"},
    {"id": "openshift-default-4.17", "kind": "provider", "platform": "Red Hat OpenShift",
     "label": "OpenShift 4.17 and earlier, Default audit profile (core Events at None)",
     "files": [f"{PP}/openshift/base-policy-release-4.17.yaml",
               f"{PP}/openshift/default-rules-release-4.17.yaml"],
     "version": "openshift/library-go release-4.17 (release-4.14 to release-4.16 differ "
                "only by the /livez URL, which no rule reads)",
     "status": "source text; the kube-apiserver operator release-4.17 vendors the same "
               "files"},
    {"id": "openshift-wrb", "kind": "provider", "platform": "Red Hat OpenShift",
     "label": "OpenShift 4.18 and later, WriteRequestBodies audit profile",
     "files": [f"{PP}/openshift/base-policy-release-4.18.yaml",
               f"{PP}/openshift/writerequestbodies-rules-release-4.18.yaml"],
     "version": "openshift/library-go release-4.18",
     "status": "source text; an admin chooses this profile (the default is Default)"},
    {"id": "openshift-wrb-4.17", "kind": "provider", "platform": "Red Hat OpenShift",
     "label": "OpenShift 4.17 and earlier, WriteRequestBodies audit profile",
     "files": [f"{PP}/openshift/base-policy-release-4.17.yaml",
               f"{PP}/openshift/writerequestbodies-rules-release-4.17.yaml"],
     "version": "openshift/library-go release-4.17",
     "status": "source text; an admin chooses this profile (the default is Default)"},
    {"id": "k3s-starter", "kind": "provider", "platform": "k3s",
     "label": "k3s hardening-guide starter policy (k3s writes no audit log by default)",
     "files": [f"{PP}/k3s/k3s-hardening-starter-audit-policy.yaml"],
     "version": "k3s-io/docs main, docs/security/hardening-guide.md",
     "status": "published text; the guide calls it a starter policy, and a k3s cluster "
               "has no audit policy until the admin writes one"},
]


# --------------------------------------------------------------------------- policy

class PolicyError(ValueError):
    pass


def _strings(rule, key, where):
    val = rule.get(key) or []
    if not isinstance(val, list) or not all(isinstance(v, str) for v in val):
        raise PolicyError(f"{where}: {key} must be a list of strings")
    return list(val)


def _stages(val, where):
    val = val or []
    if not isinstance(val, list):
        raise PolicyError(f"{where}: omitStages must be a list")
    for s in val:
        if s not in STAGES:
            raise PolicyError(f"{where}: omitStages {s!r}: allowed stages are "
                              + ",".join(STAGES))
    return list(val)


def parse_rule(raw, where, warnings):
    """One policy rule, normalized and validated (validation.go validatePolicyRule)."""
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: a rule must be a mapping")
    for key in sorted(set(raw) - RULE_KEYS):
        warnings.append(f"{where}: unknown key {key!r} ignored (lenient decoding)")
    level = raw.get("level")
    if not level:
        raise PolicyError(f"{where}: level is required")
    if level not in LEVELS:
        raise PolicyError(f"{where}: level {level!r} not supported")
    urls = _strings(raw, "nonResourceURLs", where)
    for u in urls:
        if u == "*":
            continue
        if not u.startswith("/"):
            raise PolicyError(f"{where}: non-resource URL {u!r} must begin with '/'")
        if "*" in u[:-1]:
            raise PolicyError(f"{where}: non-resource URL {u!r}: '*' must be the final "
                              "character")
    resources = []
    for i, gr in enumerate(raw.get("resources") or []):
        gwhere = f"{where}.resources[{i}]"
        if not isinstance(gr, dict):
            raise PolicyError(f"{gwhere}: must be a mapping")
        for key in sorted(set(gr) - GROUP_KEYS):
            warnings.append(f"{gwhere}: unknown key {key!r} ignored (lenient decoding)")
        group = gr.get("group") or ""
        if not isinstance(group, str):
            raise PolicyError(f"{gwhere}: group must be a string")
        names = _strings(gr, "resources", gwhere)
        rnames = _strings(gr, "resourceNames", gwhere)
        if rnames and not names:
            raise PolicyError(f"{gwhere}: using resourceNames requires at least one resource")
        resources.append({"group": group, "resources": names, "resourceNames": rnames})
    namespaces = _strings(raw, "namespaces", where)
    if urls and (resources or namespaces):
        raise PolicyError(f"{where}: rules cannot apply to both regular resources and "
                          "non-resource URLs")
    omf = raw.get("omitManagedFields")
    if omf is not None and not isinstance(omf, bool):
        raise PolicyError(f"{where}: omitManagedFields must be a boolean")
    return {"level": level, "users": _strings(raw, "users", where),
            "userGroups": _strings(raw, "userGroups", where),
            "verbs": _strings(raw, "verbs", where), "resources": resources,
            "namespaces": namespaces, "nonResourceURLs": urls,
            "omitStages": _stages(raw.get("omitStages"), where), "omitManagedFields": omf}


def load_policy(paths, root=REPO):
    """A policy from files: the first is a Policy document, the rest rule lists that
    are appended (library-go GetAuditPolicy). Returns a dict with rules (each with its
    omitStages already unioned with the policy's), omitStages, omitManagedFields,
    apiVersion and warnings."""
    warnings, rules = [], []
    with open(os.path.join(root, paths[0]), encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or doc.get("kind") != "Policy":
        raise PolicyError(f"{paths[0]}: not an audit Policy document")
    for key in sorted(set(doc) - POLICY_KEYS):
        warnings.append(f"{paths[0]}: unknown key {key!r} ignored (lenient decoding)")
    api = doc.get("apiVersion")
    if api != "audit.k8s.io/v1":
        warnings.append(f"{paths[0]}: apiVersion {api!r}; the v1.36 API server loads only "
                        "audit.k8s.io/v1, so the rules are evaluated as v1")
    pstages = _stages(doc.get("omitStages"), paths[0])
    pomf = doc.get("omitManagedFields", False)
    if not isinstance(pomf, bool):
        raise PolicyError(f"{paths[0]}: omitManagedFields must be a boolean")
    raws = [(paths[0], i, r) for i, r in enumerate(doc.get("rules") or [])]
    for extra in paths[1:]:
        with open(os.path.join(root, extra), encoding="utf-8") as fh:
            more = yaml.safe_load(fh)
        if not isinstance(more, list):
            raise PolicyError(f"{extra}: expected a YAML list of policy rules")
        raws += [(extra, i, r) for i, r in enumerate(more)]
    for n, (path, i, raw) in enumerate(raws):
        rule = parse_rule(raw, f"{os.path.basename(path)} rule {i} (policy rule #{n})",
                          warnings)
        rule["omitStages"] = sorted(set(rule["omitStages"]) | set(pstages))
        rule["source"] = f"{path} rule {i}"
        rules.append(rule)
    if not rules:
        raise PolicyError(f"{paths[0]}: loaded illegal policy with 0 rules")
    return {"rules": rules, "omitStages": sorted(set(pstages)), "omitManagedFields": pomf,
            "apiVersion": api, "warnings": warnings}


def policy_from_rules(rules, omit_stages=(), omit_managed_fields=False):
    """A policy from in-memory rule mappings (the self-test)."""
    warnings = []
    out = []
    for n, raw in enumerate(rules):
        rule = parse_rule(raw, f"rule #{n}", warnings)
        rule["omitStages"] = sorted(set(rule["omitStages"]) | set(omit_stages))
        rule["source"] = f"rule #{n}"
        out.append(rule)
    return {"rules": out, "omitStages": sorted(set(omit_stages)),
            "omitManagedFields": omit_managed_fields, "apiVersion": "audit.k8s.io/v1",
            "warnings": warnings}


# ------------------------------------------------------------------------ matching

def _path_matches(path, spec):
    if spec == "*" or spec == path:
        return True
    return spec.endswith("*") and path.startswith(spec.rstrip("*"))


def _matches_resource(rule, a):
    if not a["resource_request"]:
        return False
    if rule["namespaces"] and a["namespace"] not in rule["namespaces"]:
        return False
    if not rule["resources"]:
        return True
    res, sub = a["resource"], a["subresource"]
    combined = f"{res}/{sub}" if sub else res
    for gr in rule["resources"]:
        if gr["group"] != a["api_group"] and gr["group"] != "*":
            continue
        if not gr["resources"]:
            return True
        for r in gr["resources"]:
            if gr["resourceNames"] and a["name"] not in gr["resourceNames"]:
                continue
            if r in (combined, "*"):
                return True
            if sub and r.startswith("*/") and sub == r[2:]:
                return True
            if r.endswith("/*") and res == r[:-2]:
                return True
    return False


def rule_matches(rule, a):
    """checker.go ruleMatches for request attributes `a` (see attributes())."""
    if rule["users"] and (a["user"] is None or a["user"] not in rule["users"]):
        return False
    if rule["userGroups"]:
        if a["user"] is None or not set(a["groups"]) & set(rule["userGroups"]):
            return False
    if rule["verbs"] and a["verb"] not in rule["verbs"]:
        return False
    if rule["namespaces"] or rule["resources"]:
        return _matches_resource(rule, a)
    if rule["nonResourceURLs"]:
        if a["resource_request"]:
            return False
        return any(_path_matches(a["path"], u) for u in rule["nonResourceURLs"])
    return True


def evaluate(policy, a):
    """(level, index of the deciding rule or None, omitStages, omitManagedFields):
    checker.go EvaluatePolicyRule."""
    for i, rule in enumerate(policy["rules"]):
        if rule_matches(rule, a):
            omf = rule["omitManagedFields"]
            return (rule["level"], i, frozenset(rule["omitStages"]),
                    policy["omitManagedFields"] if omf is None else omf)
    return "None", None, frozenset(policy["omitStages"]), policy["omitManagedFields"]


def attributes(user=None, groups=(), verb="", namespace="", api_group="", resource="",
               subresource="", name="", resource_request=True, path=""):
    return {"user": user, "groups": list(groups), "verb": verb, "namespace": namespace,
            "api_group": api_group, "resource": resource, "subresource": subresource,
            "name": name, "resource_request": resource_request, "path": path}


def attributes_from_record(ev):
    """The request attributes the policy saw, read back from an audit record."""
    user = ev.get("user") or {}
    o = ev.get("objectRef")
    verb = ev.get("verb") or ""
    if not o:
        return attributes(user=user.get("username"), groups=user.get("groups") or [],
                          verb=verb, resource_request=False,
                          path=(ev.get("requestURI") or "").split("?", 1)[0])
    sub = o.get("subresource") or ""
    name = o.get("name") or ""
    if verb == "create" and not sub:
        name = ""  # a POST to the collection: the name comes from the body later
    resource, group = o.get("resource") or "", o.get("apiGroup") or ""
    namespace = o.get("namespace") or ""
    if not namespace and resource == "namespaces" and not group and name:
        # requestinfo.go (v1.36.4 L194-196): for /api/v1/namespaces/<n>[/status|
        # /finalize] the request namespace is <n> (LogRequestMetadata then writes it
        # to objectRef.namespace), even when a case record leaves it out.
        namespace = name
    return attributes(user=user.get("username"), groups=user.get("groups") or [],
                      verb=verb, namespace=namespace, api_group=group, resource=resource,
                      subresource=sub, name=name, resource_request=True,
                      path=(ev.get("requestURI") or "").split("?", 1)[0])


# ------------------------------------------------------------------------- records

def _strip_managed_fields(obj):
    if not isinstance(obj, dict):
        return
    meta = obj.get("metadata")
    if isinstance(meta, dict):
        meta.pop("managedFields", None)
    for item in obj.get("items") or []:
        _strip_managed_fields(item)


def project(ev, level, omit_managed_fields=False):
    """The record `ev` at `level` (never above the level the record holds)."""
    rec = copy.deepcopy(ev)
    rec["level"] = level
    if level in ("None", "Metadata"):
        rec.pop("requestObject", None)
        rec.pop("responseObject", None)
    elif level == "Request":
        rec.pop("responseObject", None)
    if omit_managed_fields:
        if "responseObject" in rec:
            _strip_managed_fields(rec["responseObject"])
        if "requestObject" in rec and rec.get("verb") != "patch":
            _strip_managed_fields(rec["requestObject"])
    return rec


def request_received(ev, a, level):
    """The RequestReceived-stage record of the same request: request metadata only
    (filters/audit.go writes this stage before the handler runs)."""
    rec = {k: copy.deepcopy(ev[k]) for k in ("kind", "apiVersion", "auditID", "verb",
                                              "requestURI", "userAgent", "sourceIPs",
                                              "user", "requestReceivedTimestamp")
           if k in ev}
    rec["level"] = level
    rec["stage"] = "RequestReceived"
    if "requestReceivedTimestamp" in ev:
        rec["stageTimestamp"] = ev["requestReceivedTimestamp"]
    if a["resource_request"]:
        o = ev.get("objectRef") or {}
        ref = {"resource": a["resource"]}
        for key, val in (("namespace", a["namespace"]), ("name", a["name"]),
                         ("subresource", a["subresource"]), ("apiGroup", a["api_group"]),
                         ("apiVersion", o.get("apiVersion") or "")):
            if val:
                ref[key] = val
        rec["objectRef"] = ref
    return rec


def records_under(policy, ev, log_filter=None):
    """What one recorded request leaves in the log under `policy`.

    Returns (records, info): records are audit events (nested); info says how the
    level was decided: {"policy_rule": i|None, "level": L, "record_level": R,
    "effective": E, "not_modeled": bool, "dropped": None|"level"|"stage"|"category"}.
    """
    a = attributes_from_record(ev)
    level, idx, omit, omf = evaluate(policy, a)
    rlevel = ev.get("level") or "RequestResponse"
    info = {"policy_rule": idx, "level": level, "record_level": rlevel,
            "effective": level, "not_modeled": False, "dropped": None}
    if level == "None":
        info["dropped"] = "level"
        return [], info
    if log_filter and a["verb"] in log_filter.get("drop_verbs", ()):
        info["dropped"] = "category"
        return [], info
    effective = level
    if LEVELS.index(level) > LEVELS.index(rlevel):
        effective, info["not_modeled"] = rlevel, True
    info["effective"] = effective
    out = []
    # The RequestReceived record is at the POLICY level: the API server sets the
    # event's level once (pkg/audit/context.go AuditContext.Init) and writes every
    # stage at it. That record never holds a body, so it is modeled at any level.
    if "RequestReceived" not in omit and ev.get("stage") != "RequestReceived":
        out.append(request_received(ev, a, level))
    if (ev.get("stage") or "ResponseComplete") not in omit:
        out.append(project(ev, effective, omf))
    if not out:
        info["dropped"] = "stage"
    return out, info


# -------------------------------------------------------------------------- rules

def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def rule_digest(path):
    """sha256 of what can change a rule's result or its row: title, id, name, level,
    logsource, detection and correlation of every YAML document (canonical JSON).
    A description or comment edit does not make the result stale."""
    with open(path, encoding="utf-8") as fh:
        docs = [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]
    keys = ("title", "id", "name", "level", "logsource", "detection", "correlation")
    text = json.dumps([{k: d[k] for k in keys if k in d} for d in docs], sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def audit_rules():
    """Repo-relative paths (under detections/sigma/) of every rule whose logsource is
    product kubernetes, service audit, sorted."""
    out = []
    for tdir in sorted(os.listdir(SIGMA)):
        d = os.path.join(SIGMA, tdir)
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".yml"):
                continue
            with open(os.path.join(d, f), encoding="utf-8") as fh:
                docs = [x for x in yaml.safe_load_all(fh) if isinstance(x, dict)]
            ls = next((x.get("logsource") for x in docs if x.get("logsource")), {}) or {}
            if ls.get("product") == "kubernetes" and ls.get("service") == "audit":
                out.append(f"{tdir}/{f}")
    return out


def body_reads(path):
    """The bodies a rule's detection reads: a sorted subset of requestObject and
    responseObject (a field name, before any '|' modifier, that starts with one)."""
    with open(path, encoding="utf-8") as fh:
        docs = [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]
    out = set()

    def walk(val):
        if isinstance(val, dict):
            for key in val:
                top = str(key).split("|", 1)[0].split(".", 1)[0]
                if top in ("requestObject", "responseObject"):
                    out.add(top)
        elif isinstance(val, list):
            for item in val:
                walk(item)

    for d in docs:
        for name, sel in (d.get("detection") or {}).items():
            if name not in ("condition", "timeframe"):
                walk(sel)
    return sorted(out)


def _manifest_rule_file(module, entry):
    """The rule (<T>/<stem>.yml) a validator MANIFEST entry registers: the one .yml
    string of the entry, under its technique folder or the module's RULES_DIR
    (the same reading as check_sufficiency.py's load_manifests)."""
    ymls = [x for x in entry if isinstance(x, str) and x.endswith(".yml")]
    if len(ymls) != 1:
        raise ValueError(f"cannot find the rule file in MANIFEST entry {entry!r:.120}")
    if "/" in ymls[0]:
        full = os.path.join(REPO, ymls[0])
    else:
        folder = next((x for x in entry if isinstance(x, str)
                       and re.fullmatch(r"T\d{4}(\.\d{3})?", x)), None)
        base = os.path.join(SIGMA, folder) if folder else getattr(module, "RULES_DIR", None)
        if base is None:
            raise ValueError(f"MANIFEST entry {entry!r:.120} names no folder and "
                             f"{module.__name__} has no RULES_DIR")
        full = os.path.join(base, ymls[0])
    return os.path.relpath(os.path.normpath(full), SIGMA).replace(os.sep, "/")


def home_candidates(rels):
    """{rule rel: [lab policy id, ...]}: the lab policies whose validator MANIFEST
    registers the rule (a positive that CI proves live under that policy). A
    validator that does not import, or an entry that names no rule, stops the run
    (fail closed)."""
    import importlib
    regs = {}
    for p in POLICIES:
        if p["kind"] != "lab":
            continue
        name = p["validator"][:-3] if p["validator"].endswith(".py") else p["validator"]
        try:
            module = importlib.import_module(name)
            manifest = module.MANIFEST
            for entry in manifest:
                regs.setdefault(_manifest_rule_file(module, entry), set()).add(p["id"])
        except Exception as e:  # noqa: BLE001 - a broken validator must not pass silently
            raise SystemExit(f"k8s_policy_coverage: cannot read the MANIFEST of "
                             f"detections/{p['validator']}: {type(e).__name__}: {e}")
    order = [p["id"] for p in POLICIES]
    return {rel: sorted(regs.get(rel, ()), key=order.index) for rel in rels}


def home_policies(rels):
    """{rule rel: lab policy id | None}: the lab policy of the one lab validator whose
    MANIFEST registers the rule; None when none or more than one does."""
    return {rel: (c[0] if len(c) == 1 else None)
            for rel, c in home_candidates(rels).items()}


def home_errors(result, candidates=None):
    """What breaks the home check (module docstring, step 5): a rule with no single
    home, or a home column with a lost positive or a firing negative."""
    errs = []
    for rel, row in result["rules"].items():
        home = row.get("home_policy")
        if home is None:
            c = (candidates or {}).get(rel)
            errs.append(f"{rel}: no single home lab policy (lab validators whose MANIFEST "
                        f"registers it: {', '.join(c) if c else 'none'})")
            continue
        r = row["results"].get(home)
        if r is None:
            errs.append(f"{rel}: home policy {home} has no result")
            continue
        pos = r["positives"]
        if pos["firing"] != pos["total"]:
            lost = ", ".join(f"{x['case']} ({x['reason']})" for x in pos["lost"])
            errs.append(f"{rel}: under its home policy {home} only {pos['firing']} of "
                        f"{pos['total']} positives fire; lost: {lost}")
        if r["negatives_firing"]:
            neg = ", ".join(f"{x['kind']} {x['case']} ({x['reason']})"
                            for x in r["negatives_firing"])
            errs.append(f"{rel}: under its home policy {home} a negative fires: {neg}")
    return errs


def check_lab_mounts():
    """Each lab policy must be the file its kind config mounts as the audit policy."""
    errors = []
    for p in POLICIES:
        if p["kind"] != "lab":
            continue
        with open(os.path.join(REPO, p["kind_config"]), encoding="utf-8") as fh:
            text = fh.read()
        if f"./{p['files'][0]}" not in text:
            errors.append(f"{p['kind_config']} does not mount {p['files'][0]}")
    return errors


def _body_lost(info):
    """A record that the policy keeps, at a lower level than the case record."""
    return (info["dropped"] is None
            and LEVELS.index(info["effective"]) < LEVELS.index(info["record_level"]))


def missing_bodies(info):
    """The bodies the platform logs for this event but the case record lacks (a
    not-modeled event): requestObject below Request, responseObject below
    RequestResponse."""
    if not info["not_modeled"] or info["dropped"] is not None:
        return set()
    lv, rl = LEVELS.index(info["level"]), LEVELS.index(info["record_level"])
    out = set()
    if rl < LEVELS.index("Request") <= lv:
        out.add("requestObject")
    if rl < LEVELS.index("RequestResponse") == lv:
        out.add("responseObject")
    return out


def reason_lost(infos):
    """Why a positive does not fire, from the per-event info of records_under()."""
    if all(not recs for recs, _ in infos):
        return "no-record"
    if any(_body_lost(i) for _, i in infos):
        return "body-removed"
    if any(i["dropped"] is not None for _, i in infos):
        return "partial-record"
    return "other"


def reason_firing(infos, hit_stages):
    """Why a negative fires under a policy (it is quiet on its case record)."""
    if hit_stages == {"RequestReceived"}:
        return "request-received"
    if any(_body_lost(i) for _, i in infos):
        return "body-removed"
    if any(i["dropped"] is not None for _, i in infos):
        return "partial-record"
    return "other"


def run_rule(rel, policies):
    """{policy id: result} for one rule (see the schema in the module docstring)."""
    path = os.path.join(SIGMA, rel)
    sql = sigma_eval.compile_rule(path)
    reads = set(body_reads(path))
    cases, errors = rule_cases.load_cases(rule_cases.cases_path(path))
    if errors:
        raise SystemExit(f"{rel}: sidecar errors: {errors}")
    results = {}
    for pid, (policy, log_filter) in policies.items():
        pos = {"total": 0, "firing": 0, "lost": []}
        nm = {"total": 0, "quiet": 0, "no_record": 0}
        neg_firing, not_modeled, nm_reads = [], 0, 0
        for case in cases:
            infos, flat, origin = [], [], []
            for ev in case["events"]:
                recs, info = records_under(policy, ev, log_filter)
                infos.append((recs, info))
                not_modeled += info["not_modeled"]
                nm_reads += bool(missing_bodies(info) & reads)
                for rec in recs:
                    flat.append(sigma_eval.flatten(rec))
                    origin.append(rec.get("stage"))
            hits = sigma_eval.EventTable(flat).hit_indices(sql) if flat else []
            fired = bool(hits)
            rules_used = [i["policy_rule"] for _, i in infos]
            kind = case["kind"]
            if kind == "positive":
                pos["total"] += 1
                if fired:
                    pos["firing"] += 1
                else:
                    pos["lost"].append({"case": case["name"], "reason": reason_lost(infos),
                                        "policy_rules": rules_used})
                continue
            if kind == "near-miss":
                nm["total"] += 1
                if not flat:
                    nm["no_record"] += 1
                elif not fired:
                    nm["quiet"] += 1
            if fired:
                stages = {origin[i] for hit in hits for i in hit}
                neg_firing.append({"case": case["name"], "kind": kind,
                                   "reason": reason_firing(infos, stages)})
        results[pid] = {"positives": pos, "near_misses": nm,
                        "negatives_firing": neg_firing, "not_modeled": not_modeled,
                        "not_modeled_reads": nm_reads}
    counts = {k: sum(1 for c in cases if c["kind"] == k) for k in CASE_KINDS}
    return results, counts


def loaded_policies():
    out = {}
    for p in POLICIES:
        out[p["id"]] = (load_policy(p["files"]), p.get("log_filter"))
    return out


def compute():
    """The whole machine-readable result."""
    errors = check_lab_mounts()
    if errors:
        raise SystemExit("k8s_policy_coverage: " + "; ".join(errors))
    pols = loaded_policies()
    rels = audit_rules()
    cands = home_candidates(rels)
    homes = {rel: (c[0] if len(c) == 1 else None) for rel, c in cands.items()}
    out = {"schema": SCHEMA, "generator": "detections/k8s_policy_coverage.py",
           "semantics": SEMANTICS, "policy_order": [p["id"] for p in POLICIES],
           "policies": {}, "rules": {}, "summary": {}}
    for p in POLICIES:
        policy, _ = pols[p["id"]]
        out["policies"][p["id"]] = {
            "kind": p["kind"], "platform": p["platform"], "label": p["label"],
            "version": p["version"], "status": p["status"],
            "files": [{"path": f, "sha256": sha256_file(os.path.join(REPO, f))}
                      for f in p["files"]],
            "log_filter": p.get("log_filter"), "rule_count": len(policy["rules"]),
            "warnings": policy["warnings"]}
    for rel in rels:
        path = os.path.join(SIGMA, rel)
        with open(path, encoding="utf-8") as fh:
            doc = next(x for x in yaml.safe_load_all(fh) if isinstance(x, dict))
        results, counts = run_rule(rel, pols)
        out["rules"][rel] = {
            "title": doc.get("title"), "level": doc.get("level"),
            "rule_digest": rule_digest(path),
            "cases_sha256": sha256_file(rule_cases.cases_path(path)),
            "home_policy": homes[rel], "case_counts": counts, "results": results}
    for p in POLICIES:
        s = {"rules": 0, "rules_all_positives": 0, "rules_some_positives": 0,
             "rules_blind": 0, "positives": 0, "positives_firing": 0,
             "negatives_firing": 0, "not_modeled": 0, "not_modeled_reads": 0}
        for row in out["rules"].values():
            r = row["results"][p["id"]]
            tot, fir = r["positives"]["total"], r["positives"]["firing"]
            s["rules"] += 1
            s["positives"] += tot
            s["positives_firing"] += fir
            s["negatives_firing"] += len(r["negatives_firing"])
            s["not_modeled"] += r["not_modeled"]
            s["not_modeled_reads"] += r["not_modeled_reads"]
            if tot and fir == tot:
                s["rules_all_positives"] += 1
            elif fir:
                s["rules_some_positives"] += 1
            elif tot:
                s["rules_blind"] += 1
        out["summary"][p["id"]] = s
    return out


def dumps(result):
    """Stable JSON text: keys sorted, nesting indented down to one rule x policy
    result, which is one line (so a change shows as a one-line diff)."""
    def enc(val, depth):
        if depth >= 4 or not isinstance(val, (dict, list)) or not val:
            return json.dumps(val, sort_keys=True, separators=(", ", ": "))
        pad, inner = " " * depth, " " * (depth + 1)
        if isinstance(val, list):
            return "[\n" + ",\n".join(inner + enc(v, depth + 1) for v in val) + "\n" + pad + "]"
        return "{\n" + ",\n".join(f"{inner}{json.dumps(k)}: {enc(val[k], depth + 1)}"
                                   for k in sorted(val)) + "\n" + pad + "}"
    return enc(result, 0) + "\n"


# ------------------------------------------------------------------------ output

def bad_selection(result, policy_ids=None, rule_filter=None):
    """The --policy and --rule values that name no column or rule."""
    bad = [f"--policy {i!r} (known: {', '.join(result['policy_order'])})"
           for i in policy_ids or () if i not in result["policies"]]
    bad += [f"--rule {r!r} (write it as <T>/<stem>.yml, for example "
            "T1070/k8s_events_deleted.yml)"
            for r in rule_filter or () if r not in result["rules"]]
    return bad


def print_table(result, policy_ids=None, rule_filter=None, detail=False):
    ids = policy_ids or result["policy_order"]
    rels = [r for r in result["rules"] if not rule_filter or r in rule_filter]
    w = max(len(r) for r in rels) if rels else 10
    cw = max([14] + [len(i) for i in ids])
    print("Positives that fire / positives, per rule and policy (* = the rule's home "
          "lab policy; ! = some negative starts to fire; ~ = the policy logs a body that "
          "the rule reads and some case record lacks, so that case is not proven here):")
    print(f"{'rule':{w}}  " + " ".join(f"{i:>{cw}}" for i in ids))
    for rel in rels:
        row = result["rules"][rel]
        cells = []
        for i in ids:
            r = row["results"][i]
            mark = ("*" if row["home_policy"] == i else " ") + \
                   ("!" if r["negatives_firing"] else " ") + \
                   ("~" if r.get("not_modeled_reads") else " ")
            cells.append(f"{r['positives']['firing']:>5}/{r['positives']['total']:<5}{mark}")
        print(f"{rel:{w}}  " + " ".join(f"{c:>{cw}}" for c in cells))
    print()
    print("Rules with every / some / no positive firing (blind); events logged above the "
          "case record (not modeled), and of those the events whose missing body the rule "
          "reads:")
    for i in ids:
        s = result["summary"][i]
        print(f"  {i:26} {s['rules_all_positives']:>3} / {s['rules_some_positives']:>3} / "
              f"{s['rules_blind']:>3}   positives {s['positives_firing']}/{s['positives']}"
              f"   negatives firing {s['negatives_firing']}"
              f"   not modeled {s.get('not_modeled', 0)} (rule reads the body: "
              f"{s.get('not_modeled_reads', 0)})")
    print()
    print("Negative cases that fire under a policy (a platform false positive):")
    any_neg = False
    for rel in rels:
        for i in ids:
            for n in result["rules"][rel]["results"][i]["negatives_firing"]:
                any_neg = True
                print(f"  {i:26} {rel} :: {n['kind']} {n['case']} ({n['reason']})")
    if not any_neg:
        print("  none")
    if detail:
        print()
        print("Positives lost (reason; deciding policy rule per event):")
        for rel in rels:
            for i in ids:
                for lost in result["rules"][rel]["results"][i]["positives"]["lost"]:
                    print(f"  {i:26} {rel} :: {lost['case']} ({lost['reason']}; "
                          f"rules {lost['policy_rules']})")
    warn = [(i, w) for i in ids for w in result["policies"][i]["warnings"]]
    if warn:
        print()
        print("Policy warnings:")
        for i, msg in warn:
            print(f"  {i}: {msg}")


def diff_summary(old, new):
    """Short list of what differs between two results."""
    out = []
    for key in ("schema", "semantics", "policy_order"):
        if old.get(key) != new.get(key):
            out.append(f"{key} changed")
    for pid in sorted(set(old.get("policies", {})) | set(new.get("policies", {}))):
        if old.get("policies", {}).get(pid) != new.get("policies", {}).get(pid):
            out.append(f"policy {pid} changed (files, digests or metadata)")
    orules, nrules = old.get("rules", {}), new.get("rules", {})
    for rel in sorted(set(orules) | set(nrules)):
        if rel not in orules:
            out.append(f"rule {rel} is new")
        elif rel not in nrules:
            out.append(f"rule {rel} is gone")
        elif orules[rel] != nrules[rel]:
            parts = [k for k in sorted(set(orules[rel]) | set(nrules[rel]))
                     if orules[rel].get(k) != nrules[rel].get(k)]
            out.append(f"rule {rel}: {', '.join(parts)} changed")
    if old.get("summary") != new.get("summary"):
        out.append("summary changed")
    return out


# ------------------------------------------------------------------------ sources

def _fetch(url):
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 (fixed https URLs)
        return resp.read()


GCE_CHANGE_NOTICE = (
    "# Change notice (Apache-2.0 section 4(b)): the notice above is the one of\n"
    "# cluster/gce/gci/configure-helper.sh in kubernetes v1.36.4. This file is not a\n"
    "# copy of that script. It is the audit policy that the script's function\n"
    "# create-master-audit-policy writes when no custom policy is given: the\n"
    "# here-document, with ${known_apis} expanded as bash expands it. The det-eng\n"
    "# repository made this extract and added this header. Source URL, digests and\n"
    "# license: detections/k8s/provider-policies/SOURCES.md.\n")


def extract(method, text):
    """Cut the policy text out of an upstream file (see SOURCES)."""
    kind, marker = method
    if kind == "file":
        return text
    start = text.find(marker)
    if start < 0:
        raise ValueError(f"marker {marker!r} not found")
    rest = text[start:]
    if kind == "gce-heredoc":
        apis = re.search(r"local -r known_apis='(.*?)'", rest, re.S)
        body = re.search(r'\n  cat <<EOF >"\$\{path\}"\n(.*?\n)EOF\n', rest, re.S)
        if not apis or not body:
            raise ValueError("known_apis or the heredoc not found")
        heredoc = body.group(1)
        leftover = heredoc.replace("${known_apis}", "")
        if "$" in leftover or "`" in leftover or "\\" in leftover:
            raise ValueError("the heredoc holds an expansion other than ${known_apis}")
        # The file is a changed extract of an Apache-2.0 file, so it keeps the
        # source's copyright and license notice (section 4(c)) and states the change
        # (section 4(b)) in a YAML comment header above the policy.
        notice = re.search(r"^(# Copyright .*?\n# limitations under the License\.\n)",
                           text, re.S | re.M)
        if not notice:
            raise ValueError("the source file's license notice not found")
        return (notice.group(1) + "#\n" + GCE_CHANGE_NOTICE
                + heredoc.replace("${known_apis}", apis.group(1)))
    if kind == "fenced-md":
        m = re.search(r"\n```yaml\n(.*?\n)```", rest, re.S)
    elif kind == "fenced-adoc":
        m = re.search(r"\n\[source,yaml\]\n----\n(.*?\n)----\n", rest, re.S)
    else:
        raise ValueError(f"unknown extraction {kind}")
    if not m:
        raise ValueError("no fenced YAML block after the marker")
    return m.group(1)


def verify_sources(write=False):
    bad = 0
    for path, src in SOURCES.items():
        try:
            raw = _fetch(src["url"])
            text = extract(src["extract"], raw.decode("utf-8"))
        except Exception as e:  # noqa: BLE001 (report and go on)
            print(f"ERROR {path}: {src['url']}: {e}")
            bad += 1
            continue
        up = hashlib.sha256(raw).hexdigest()
        new = text.encode("utf-8")
        full = os.path.join(REPO, path)
        old = open(full, "rb").read() if os.path.exists(full) else None
        if write:
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(new)
        same = old == new
        print(f"{'ok  ' if same else 'DIFF'} {path}: upstream sha256 {up} "
              f"(recorded {src['upstream_sha256'] or '-'}), extract sha256 "
              f"{hashlib.sha256(new).hexdigest()}"
              + ("" if same else (" (written)" if write else " (vendored copy differs)")))
        bad += 0 if (same or write) else 1
    return 1 if bad else 0


# ----------------------------------------------------------------------- self-test

def _a(**kw):
    return attributes(**kw)


TIM = {"user": "tim@k8s.io", "groups": ["humans", "developers"]}
# checker_test.go's request attributes.
CT_ATTRS = {
    "namespaced": _a(**TIM, verb="get", namespace="default", resource="pods", name="busybox",
                     path="/api/v1/namespaces/default/pods/busybox"),
    "cluster": _a(**TIM, verb="get", api_group="rbac.authorization.k8s.io",
                  resource="clusterroles", name="edit",
                  path="/apis/rbac.authorization.k8s.io/v1beta1/clusterroles/edit"),
    "nonResource": _a(**TIM, verb="get", resource_request=False, path="/logs/kubelet.log"),
    "subresource": _a(**TIM, verb="get", namespace="default", resource="pods",
                      subresource="log", name="busybox",
                      path="/api/v1/namespaces/default/pods/busybox"),
    "Unauthorized": _a(verb="get", namespace="default", resource="pods", name="busybox",
                       path="/api/v1/namespaces/default/pods/busybox"),
    "ClusterRoleUpdate": _a(**TIM, verb="update", api_group="rbac.authorization.k8s.io",
                            resource="clusterroles", subresource="status", name="somerole",
                            path="/apis/rbac.authorization.k8s.io/v1beta1/clusterroles/somerole"),
}
# checker_test.go's rules.
CT_RULES = {
    "default": {"level": "Metadata"},
    "create": {"level": "Request", "verbs": ["create"]},
    "tims": {"level": "Metadata", "users": ["tim@k8s.io"]},
    "humans": {"level": "Metadata", "userGroups": ["humans"]},
    "serviceAccounts": {"level": "Request", "userGroups": ["system:serviceaccounts"]},
    "getPods": {"level": "RequestResponse", "verbs": ["get"],
                "resources": [{"resources": ["pods"]}]},
    "getPodLogs": {"level": "Request", "verbs": ["get"],
                   "resources": [{"resources": ["pods/log"]}]},
    "getPodWildcardMatching": {"level": "Request", "verbs": ["get"],
                               "resources": [{"resources": ["*"]}]},
    "getPodResourceWildcardMatching": {"level": "Request", "verbs": ["get"],
                                       "resources": [{"resources": ["*/log"]}]},
    "getPodSubResourceWildcardMatching": {"level": "Request", "verbs": ["get"],
                                          "resources": [{"resources": ["pods/*"]}]},
    "getClusterRoles": {"level": "RequestResponse", "verbs": ["get"],
                        "resources": [{"group": "rbac.authorization.k8s.io",
                                       "resources": ["clusterroles"]}],
                        "namespaces": [""]},
    "getGroupWildCardMatchingWithSubresourceWildcardMatching": {
        "level": "RequestResponse", "verbs": ["update"],
        "resources": [{"group": "*", "resources": ["*/status"]}]},
    "getLogs": {"level": "RequestResponse", "verbs": ["get"], "nonResourceURLs": ["/logs*"]},
    "getMetrics": {"level": "Request", "verbs": ["get"], "nonResourceURLs": ["/metrics"]},
    "clusterRoleEdit": {"level": "Request",
                        "resources": [{"group": "rbac.authorization.k8s.io",
                                       "resources": ["clusterroles"],
                                       "resourceNames": ["edit"]}]},
    "omit RequestReceived": {"level": "Request", "omitStages": ["RequestReceived"]},
    "only audit panic": {"level": "Request", "omitStages": ["RequestReceived",
                                                           "ResponseStarted",
                                                           "ResponseComplete"]},
}
# testAuditLevel(): (request, expected level, rule names in order).
CT_LEVELS = [
    ("namespaced", "Metadata", ["default"]), ("namespaced", "None", ["create"]),
    ("namespaced", "Metadata", ["tims"]), ("namespaced", "Metadata", ["humans"]),
    ("namespaced", "None", ["serviceAccounts"]),
    ("namespaced", "RequestResponse", ["getPods"]),
    ("namespaced", "None", ["getClusterRoles"]), ("namespaced", "None", ["getLogs"]),
    ("namespaced", "None", ["getMetrics"]),
    ("namespaced", "Metadata", ["getMetrics", "serviceAccounts", "default"]),
    ("namespaced", "RequestResponse", ["getMetrics", "getPods", "default"]),
    ("namespaced", "RequestResponse", ["getPodLogs", "getPods"]),
    ("cluster", "Metadata", ["default"]), ("cluster", "None", ["create"]),
    ("cluster", "Metadata", ["tims"]), ("cluster", "Metadata", ["humans"]),
    ("cluster", "None", ["serviceAccounts"]), ("cluster", "None", ["getPods"]),
    ("cluster", "RequestResponse", ["getClusterRoles"]),
    ("cluster", "Request", ["clusterRoleEdit", "getClusterRoles"]),
    ("cluster", "None", ["getLogs"]), ("cluster", "None", ["getMetrics"]),
    ("cluster", "Metadata", ["getMetrics", "serviceAccounts", "default"]),
    ("cluster", "RequestResponse", ["getMetrics", "getClusterRoles", "default"]),
    ("cluster", "None", ["getPodLogs", "getPods"]),
    ("nonResource", "Metadata", ["default"]), ("nonResource", "None", ["create"]),
    ("nonResource", "Metadata", ["tims"]), ("nonResource", "Metadata", ["humans"]),
    ("nonResource", "None", ["serviceAccounts"]), ("nonResource", "None", ["getPods"]),
    ("nonResource", "None", ["getClusterRoles"]),
    ("nonResource", "RequestResponse", ["getLogs"]),
    ("nonResource", "None", ["getMetrics"]),
    ("nonResource", "Metadata", ["getMetrics", "serviceAccounts", "default"]),
    ("nonResource", "RequestResponse", ["getLogs", "getClusterRoles", "default"]),
    ("nonResource", "None", ["getPodLogs", "getPods"]),
    ("subresource", "Request", ["getPodLogs", "getPods"]),
    ("subresource", "Request", ["getPodWildcardMatching"]),
    ("subresource", "Request", ["getPodResourceWildcardMatching"]),
    ("subresource", "Request", ["getPodSubResourceWildcardMatching"]),
    ("Unauthorized", "None", ["tims"]), ("Unauthorized", "Metadata", ["tims", "default"]),
    ("Unauthorized", "None", ["humans"]), ("Unauthorized", "Metadata", ["humans", "default"]),
    ("ClusterRoleUpdate", "RequestResponse",
     ["getGroupWildCardMatchingWithSubresourceWildcardMatching"]),
]
# TestChecker / TestCheckerPolicyOmitStages: (request, policy stages, rules,
# expected level, expected omitStages).
RR, RS, RC = "RequestReceived", "ResponseStarted", "ResponseComplete"
CT_STAGES = []
for _req in ("namespaced", "cluster", "nonResource"):
    CT_STAGES += [
        (_req, [], ["omit RequestReceived", "getPods", "default"], "Request", {RR}),
        (_req, [], ["only audit panic", "getPods", "default"], "Request", {RR, RS, RC}),
        (_req, [RR, RS], ["only audit panic", "getPods", "default"], "Request", {RR, RS, RC})]
CT_STAGES += [
    ("namespaced", [RR, RS], ["omit RequestReceived", "getPods", "default"], "Request", {RR, RS}),
    ("cluster", [RR, RS], ["omit RequestReceived", "getPods", "default"], "Request", {RR, RS}),
    ("nonResource", [RR, RS], ["default", "omit RequestReceived", "getPods"], "Metadata",
     {RR, RS}),
    # No rule matches: level None with the policy's own stages (checker.go L75-79).
    ("namespaced", [RR], ["create"], "None", {RR}),
]


def _rec(verb, resource, name=None, ns=None, group=None, sub=None, user="alice",
         groups=("system:authenticated",), level="RequestResponse", body=True, uri=None):
    o = {"resource": resource, "apiVersion": "v1"}
    for key, val in (("name", name), ("namespace", ns), ("apiGroup", group),
                     ("subresource", sub)):
        if val:
            o[key] = val
    ev = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": level,
          "auditID": "00000000-0000-4000-8000-000000000001", "stage": "ResponseComplete",
          "requestURI": uri or f"/api/v1/{resource}", "verb": verb,
          "user": {"username": user, "groups": list(groups)},
          "sourceIPs": ["192.0.2.10"], "userAgent": "kubectl/v1.36.4",
          "objectRef": o, "responseStatus": {"code": 200},
          "requestReceivedTimestamp": "2026-10-23T10:00:00.000000Z",
          "stageTimestamp": "2026-10-23T10:00:00.100000Z",
          "annotations": {"authorization.k8s.io/decision": "allow"}}
    if body and level in ("Request", "RequestResponse"):
        ev["requestObject"] = {"kind": "ConfigMap", "metadata": {
            "name": name or "x", "managedFields": [{"manager": "kubectl"}]}}
    if body and level == "RequestResponse":
        ev["responseObject"] = {"kind": "ConfigMap", "metadata": {
            "name": name or "x", "managedFields": [{"manager": "kubectl"}]}}
    return ev


def _at(recs, i):
    """Record i of a list, or {} (so a broken evaluator fails a check, not the run)."""
    return recs[i] if len(recs) > i else {}


def _meta(rec, key):
    return ((rec.get(key) or {}).get("metadata") or {}) if rec else {"managedFields": None}


def self_test():
    """Unit cases of the evaluator against checker.go and its tests (v1.36.4), the
    record semantics, policy facts of the shipped files, and the vendored digests."""
    fails = []

    def check(label, got, want):
        if got != want:
            fails.append(f"{label}: got {got!r}, want {want!r}")

    n = 0
    # 1. checker_test.go testAuditLevel, with no policy stages and with RR+RS.
    for stages in ([], [RR, RS]):
        for req, want, names in CT_LEVELS:
            pol = policy_from_rules([CT_RULES[x] for x in names], omit_stages=stages)
            level, _, omit, _ = evaluate(pol, CT_ATTRS[req])
            check(f"checker_test {req} {names} stages={stages} level", level, want)
            check(f"checker_test {req} {names} stages={stages} omitStages", set(omit),
                  set(stages))
            n += 2
    # 2. checker_test.go TestChecker / TestCheckerPolicyOmitStages (stage union).
    for req, pstages, names, want, want_stages in CT_STAGES:
        pol = policy_from_rules([CT_RULES[x] for x in names], omit_stages=pstages)
        level, _, omit, _ = evaluate(pol, CT_ATTRS[req])
        check(f"stages {req} {names} {pstages} level", level, want)
        check(f"stages {req} {names} {pstages} omitStages", set(omit), want_stages)
        n += 2

    # 3. Matchers that checker_test.go does not cover, from checker.go's code.
    pods = CT_ATTRS["namespaced"]
    exec_ = _a(**TIM, verb="create", namespace="default", resource="pods",
               subresource="exec", name="web")
    other_exec = dict(exec_, name="db")
    m = [
        # "res/*" matches the resource with no subresource too (checker.go L208-210).
        ("res/* matches the bare resource", {"resources": [{"resources": ["pods/*"]}]},
         pods, True),
        ("*/sub needs a subresource", {"resources": [{"resources": ["*/log"]}]}, pods, False),
        ("exact resource does not match a subresource", {"resources": [{"resources": ["pods"]}]},
         exec_, False),
        ("resourceNames with a subresource: the name matches",
         {"resources": [{"resources": ["pods/exec"], "resourceNames": ["web"]}]}, exec_, True),
        ("resourceNames with a subresource: another name",
         {"resources": [{"resources": ["pods/exec"], "resourceNames": ["web"]}]}, other_exec,
         False),
        ("resourceNames with */sub", {"resources": [{"resources": ["*/exec"],
                                                     "resourceNames": ["web"]}]}, exec_, True),
        ("resourceNames with res/* and a subresource",
         {"resources": [{"resources": ["pods/*"], "resourceNames": ["db"]}]}, exec_, False),
        ("group * matches the core group", {"resources": [{"group": "*"}]}, pods, True),
        ("group with no resources matches every resource of the group",
         {"resources": [{"group": ""}]}, exec_, True),
        ("another group", {"resources": [{"group": "apps"}]}, pods, False),
        ("namespaces only", {"namespaces": ["default"]}, pods, True),
        ("namespaces only, another namespace", {"namespaces": ["kube-system"]}, pods, False),
        ('namespaces [""] selects a cluster-scoped request',
         {"namespaces": [""]}, CT_ATTRS["cluster"], True),
        ("namespaces never match a non-resource request",
         {"namespaces": [""]}, CT_ATTRS["nonResource"], False),
        ("resources never match a non-resource request",
         {"resources": [{"group": "*", "resources": ["*"]}]}, CT_ATTRS["nonResource"], False),
        ("nonResourceURLs never match a resource request",
         {"nonResourceURLs": ["*"]}, pods, False),
        ("nonResourceURLs prefix", {"nonResourceURLs": ["/healthz*"]},
         _a(**TIM, verb="get", resource_request=False, path="/healthz/etcd"), True),
        ("nonResourceURLs prefix is a plain string prefix",
         {"nonResourceURLs": ["/api*"]},
         _a(**TIM, verb="get", resource_request=False, path="/apis"), True),
        ("nonResourceURLs exact", {"nonResourceURLs": ["/version"]},
         _a(**TIM, verb="get", resource_request=False, path="/version/x"), False),
        ("a users-only rule matches a non-resource request", {"users": ["tim@k8s.io"]},
         CT_ATTRS["nonResource"], True),
        ("userGroups any group", {"userGroups": ["x", "developers"]}, pods, True),
        ("userGroups with no user", {"userGroups": ["humans"]}, CT_ATTRS["Unauthorized"],
         False),
        # namespaces and resources in one rule: both must match (checker.go L173-178).
        ("namespaces and resources: the namespace differs",
         {"namespaces": ["kube-system"], "resources": [{"resources": ["configmaps"]}]},
         _a(**TIM, verb="patch", namespace="default", resource="configmaps", name="c"),
         False),
        ("namespaces and resources: both match",
         {"namespaces": ["kube-system"], "resources": [{"resources": ["configmaps"]}]},
         _a(**TIM, verb="patch", namespace="kube-system", resource="configmaps", name="c"),
         True),
        ("namespaces and resources: the resource differs",
         {"namespaces": ["kube-system"], "resources": [{"resources": ["configmaps"]}]},
         _a(**TIM, verb="patch", namespace="kube-system", resource="secrets", name="c"),
         False),
        ("resourceNames with */sub: another name",
         {"resources": [{"resources": ["*/exec"], "resourceNames": ["web"]}]}, other_exec,
         False),
        ("resourceNames with *: another name",
         {"resources": [{"resources": ["*"], "resourceNames": ["web"]}]}, other_exec, False),
    ]
    for label, rule, attrs, want in m:
        rule = dict(rule, level="Metadata")
        check(f"matcher: {label}", rule_matches(policy_from_rules([rule])["rules"][0], attrs),
              want)
        n += 1

    # 4. Request attributes read back from a record.
    a = attributes_from_record(_rec("create", "configmaps", name="coredns", ns="kube-system"))
    check("create with no subresource: no name at policy time", a["name"], "")
    a = attributes_from_record(_rec("create", "serviceaccounts", name="sa", ns="ns",
                                    sub="token"))
    check("create of a subresource keeps the name", a["name"], "sa")
    a = attributes_from_record(_rec("patch", "configmaps", name="coredns", ns="kube-system"))
    check("patch keeps the name", a["name"], "coredns")
    a = attributes_from_record(_rec("delete", "events", name="e1", ns="n1"))
    check("missing apiGroup is the core group", a["api_group"], "")
    a = attributes_from_record({"verb": "get", "requestURI": "/healthz?verbose=1",
                                "user": {"username": "u"}})
    check("non-resource path stops at '?'", (a["resource_request"], a["path"]),
          (False, "/healthz"))
    n += 5
    # A Namespace object: requestinfo.go sets the request namespace to its name.
    nsdel = _rec("delete", "namespaces", name="gatekeeper-system",
                 uri="/api/v1/namespaces/gatekeeper-system")
    check("namespace delete with no objectRef.namespace: namespace is the name",
          attributes_from_record(nsdel)["namespace"], "gatekeeper-system")
    check("namespace create: no namespace (POST /api/v1/namespaces)",
          attributes_from_record(_rec("create", "namespaces", name="x",
                                      uri="/api/v1/namespaces"))["namespace"], "")
    check("namespaces/finalize: namespace is the name",
          attributes_from_record(_rec("update", "namespaces", name="n1", sub="finalize"))
          ["namespace"], "n1")
    check("another group's 'namespaces' resource is not a Namespace object",
          attributes_from_record(_rec("delete", "namespaces", name="n1",
                                      group="example.com"))["namespace"], "")
    pol = policy_from_rules([{"level": "None", "namespaces": [""]}, {"level": "Request"}])
    check('namespace delete is not matched by namespaces [""]',
          evaluate(pol, attributes_from_record(nsdel))[:2], ("Request", 1))
    n += 5
    # Impersonation: WithAudit runs before WithImpersonation (server/config.go
    # DefaultBuildHandlerChain), so the policy sees the authenticated user.
    imp = _rec("get", "secrets", name="s", ns="n", user="alice",
               groups=("system:authenticated",))
    imp["impersonatedUser"] = {"username": "system:admin", "groups": ["system:masters"]}
    pol = policy_from_rules([{"level": "None", "users": ["system:admin"]},
                             {"level": "None", "userGroups": ["system:masters"]},
                             {"level": "Metadata"}])
    check("impersonation: the policy sees user, not impersonatedUser",
          evaluate(pol, attributes_from_record(imp))[:2], ("Metadata", 2))
    recs, _ = records_under(pol, imp)
    check("impersonation: the RequestReceived record holds no impersonatedUser",
          [("impersonatedUser" in r, r.get("stage")) for r in recs],
          [(False, "RequestReceived"), (True, "ResponseComplete")])
    n += 2

    # resourceNames cannot select a create (the lab policy's TRR9027 note).
    pol = policy_from_rules([
        {"level": "RequestResponse", "namespaces": ["kube-system"],
         "verbs": ["create", "patch"],
         "resources": [{"resources": ["configmaps"], "resourceNames": ["coredns"]}]},
        {"level": "Metadata"}])
    lvl = evaluate(pol, attributes_from_record(_rec("create", "configmaps", name="coredns",
                                                    ns="kube-system")))[0]
    check("resourceNames rule skips a create", lvl, "Metadata")
    lvl = evaluate(pol, attributes_from_record(_rec("patch", "configmaps", name="coredns",
                                                    ns="kube-system")))[0]
    check("resourceNames rule selects a patch", lvl, "RequestResponse")
    n += 2

    # 5. Records: levels, stages, the RequestReceived twin, managed fields, category.
    ev = _rec("patch", "configmaps", name="coredns", ns="kube-system")
    recs, info = records_under(policy_from_rules([{"level": "Metadata"}]), ev)
    check("no omitStages: RequestReceived and ResponseComplete",
          [r["stage"] for r in recs], ["RequestReceived", "ResponseComplete"])
    rr = _at(recs, 0)
    check("RequestReceived holds no body, status, annotation or impersonation",
          sorted(k for k in ("requestObject", "responseObject", "responseStatus",
                             "annotations", "impersonatedUser") if k in rr), [])
    check("Metadata drops both bodies", sorted(k for k in ("requestObject", "responseObject")
                                               if k in _at(recs, 1)), [])
    check("Metadata sets the level", _at(recs, 1).get("level"), "Metadata")
    recs, _ = records_under(policy_from_rules([{"level": "Metadata"}],
                                              omit_stages=["RequestReceived"]), ev)
    check("policy omitStages RequestReceived", [r["stage"] for r in recs],
          ["ResponseComplete"])
    recs, _ = records_under(policy_from_rules([{"level": "Request",
                                                "omitStages": ["RequestReceived"]}]), ev)
    check("Request drops responseObject only",
          ("requestObject" in _at(recs, 0), "responseObject" in _at(recs, 0)), (True, False))
    recs, info = records_under(policy_from_rules([{"level": "Request", "omitStages": [
        "RequestReceived", "ResponseStarted", "ResponseComplete"]}]), ev)
    check("a rule that omits ResponseComplete leaves no record", (recs, info["dropped"]),
          ([], "stage"))
    recs, info = records_under(policy_from_rules([{"level": "None"}]), ev)
    check("level None leaves no record", (recs, info["dropped"]), ([], "level"))
    recs, info = records_under(policy_from_rules([{"level": "Request", "verbs": ["get"]}]), ev)
    check("no matching rule is level None", (info["level"], info["policy_rule"]),
          ("None", None))
    low = _rec("patch", "configmaps", name="coredns", ns="kube-system", level="Metadata")
    recs, info = records_under(policy_from_rules([{"level": "RequestResponse",
                                                   "omitStages": ["RequestReceived"]}]), low)
    check("a policy above the record keeps the record (not modeled)",
          (_at(recs, 0).get("level"), info["not_modeled"]), ("Metadata", True))
    # Every stage is written at the policy level (context.go Init), so the
    # RequestReceived record of a request logged at Request says Request, also where
    # the case record is at Metadata; a policy below the record lowers both.
    recs, _ = records_under(policy_from_rules([{"level": "Request"}]), low)
    check("RequestReceived is at the policy level when the case record is lower",
          [(r.get("stage"), r.get("level")) for r in recs],
          [("RequestReceived", "Request"), ("ResponseComplete", "Metadata")])
    recs, _ = records_under(policy_from_rules([{"level": "Metadata"}]), ev)
    check("RequestReceived is at the policy level when the case record is higher",
          [(r.get("stage"), r.get("level")) for r in recs],
          [("RequestReceived", "Metadata"), ("ResponseComplete", "Metadata")])
    n += 2
    recs, _ = records_under(policy_from_rules([{"level": "RequestResponse",
                                                "omitStages": ["RequestReceived"]}],
                                              omit_managed_fields=True), ev)
    check("omitManagedFields strips the responseObject",
          "managedFields" in _meta(_at(recs, 0), "responseObject"), False)
    check("omitManagedFields keeps a patch body as sent",
          "managedFields" in _meta(_at(recs, 0), "requestObject"), True)
    pol = policy_from_rules([{"level": "RequestResponse", "omitManagedFields": False,
                              "omitStages": ["RequestReceived"]}], omit_managed_fields=True)
    recs, _ = records_under(pol, ev)
    check("a rule's omitManagedFields overrides the policy",
          "managedFields" in _meta(_at(recs, 0), "responseObject"), True)
    recs, info = records_under(policy_from_rules([{"level": "Metadata"}]),
                               _rec("list", "pods", ns="ns", level="Metadata"),
                               {"drop_verbs": ["get", "list"]})
    check("a category that drops list", (recs, info["dropped"]), ([], "category"))
    create = _rec("create", "configmaps", name="coredns", ns="kube-system", level="Request")
    recs, _ = records_under(policy_from_rules([{"level": "Request"}]), create)
    check("RequestReceived of a create names no object",
          "name" in _at(recs, 0).get("objectRef", {"name": "(no record)"}), False)
    n += 16

    # Reasons of a multi-event case: only kept records count for body-removed.
    pol = policy_from_rules([{"level": "None", "resources": [{"resources": ["events"]}]},
                             {"level": "RequestResponse",
                              "omitStages": ["RequestReceived"]}])
    dropped_ev = _rec("delete", "events", name="e", ns="n", level="Metadata")
    above_ev = _rec("delete", "pods", name="p", ns="n", level="Metadata")
    infos = [records_under(pol, e) for e in (dropped_ev, above_ev)]
    check("two events, one dropped, one logged above its record: partial-record",
          reason_lost(infos), "partial-record")
    check("the event logged above its record is not modeled; it lacks requestObject and "
          "responseObject", (infos[1][1]["not_modeled"], sorted(missing_bodies(infos[1][1]))),
          (True, ["requestObject", "responseObject"]))
    low = policy_from_rules([{"level": "None", "resources": [{"resources": ["events"]}]},
                             {"level": "Metadata", "omitStages": ["RequestReceived"]}])
    infos = [records_under(low, e) for e in (_rec("delete", "events", name="e", ns="n"),
                                             _rec("delete", "pods", name="p", ns="n"))]
    check("two events, one dropped, one kept below its record: body-removed",
          reason_lost(infos), "body-removed")
    infos = [records_under(pol, dropped_ev)]
    check("every event dropped: no-record", reason_lost(infos), "no-record")
    check("a negative whose only hit is the RequestReceived record",
          reason_firing([], {"RequestReceived"}), "request-received")
    n += 5

    # 6. Validation and lenient decoding (validation.go, reader.go).
    bad = [{"level": "Metadata", "nonResourceURLs": ["/x"], "namespaces": ["a"]},
           {"level": "Metadata", "resources": [{"resourceNames": ["a"]}]},
           {"level": "Loud"}, {"verbs": ["get"]},
           {"level": "Metadata", "nonResourceURLs": ["healthz"]},
           {"level": "Metadata", "nonResourceURLs": ["/a*b"]},
           {"level": "Metadata", "omitStages": ["Done"]}]
    for rule in bad:
        try:
            policy_from_rules([rule])
            fails.append(f"validation: {rule} was accepted")
        except PolicyError:
            pass
        n += 1
    pol = policy_from_rules([{"level": "Metadata", "resources": [
        {"group": "machineconfiguration.openshift.io", "resource": ["machineconfig"]}]}])
    check("an unknown key is dropped with a warning",
          (pol["rules"][0]["resources"][0]["resources"], len(pol["warnings"])), ([], 1))
    n += 1
    for label, text, ok in (
            ("policy omitManagedFields as a string is refused",
             'apiVersion: audit.k8s.io/v1\nkind: Policy\nomitManagedFields: "false"\n'
             "rules:\n- level: Metadata\n", False),
            ("policy omitManagedFields as a boolean loads",
             "apiVersion: audit.k8s.io/v1\nkind: Policy\nomitManagedFields: false\n"
             "rules:\n- level: Metadata\n", True)):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "policy.yaml"), "w", encoding="utf-8") as fh:
                fh.write(text)
            try:
                load_policy(["policy.yaml"], root=tmp)
                got = True
            except PolicyError:
                got = False
        check(label, got, ok)
        n += 1

    # 7. Facts of the shipped policy files (file, record, expected level).
    facts = [
        ("lab-apiserver", _rec("create", "pods", sub="exec", name="p", ns="n"), "Metadata"),
        ("lab-apiserver", _rec("list", "configmaps", ns="n"), "None"),
        ("lab-apiserver", _rec("create", "configmaps", name="coredns", ns="kube-system"),
         "Request"),
        ("lab-apiserver", _rec("patch", "configmaps", name="coredns", ns="kube-system"),
         "RequestResponse"),
        ("lab-apiserver", _rec("delete", "namespaces", name="n", ns="n"), "Request"),
        ("lab-apiserver", _rec("get", "secrets", name="s", ns="n"), "Metadata"),
        ("eks", _rec("delete", "events", name="e", ns="n"), "None"),
        ("eks", _rec("delete", "events", name="e", ns="n", group="events.k8s.io"),
         "Metadata"),
        ("eks", _rec("get", "configmaps", name="c", ns="n"), "Metadata"),
        ("eks", _rec("patch", "configmaps", name="coredns", ns="kube-system"), "Metadata"),
        ("eks", _rec("patch", "configmaps", name="aws-auth", ns="kube-system"),
         "RequestResponse"),
        ("eks", _rec("create", "pods", name="p", ns="n"), "RequestResponse"),
        ("eks", _rec("create", "serviceaccounts", sub="token", name="sa", ns="n"), "Request"),
        ("gce-kube-up", _rec("delete", "events", name="e", ns="n"), "None"),
        ("gce-kube-up", _rec("get", "configmaps", name="c", ns="n"), "Metadata"),
        ("gce-kube-up", _rec("create", "pods", name="p", ns="n"), "RequestResponse"),
        ("aks-kube-audit", _rec("deletecollection", "events", ns="n"), "None"),
        ("aks-kube-audit", _rec("delete", "events", name="e", ns="n"), "Metadata"),
        ("aks-kube-audit", _rec("patch", "configmaps", name="coredns-custom",
                                ns="kube-system"), "RequestResponse"),
        ("aks-kube-audit", _rec("create", "configmaps", name="coredns-custom",
                                ns="kube-system"), "Metadata"),
        ("aks-kube-audit", _rec("get", "configmaps", name="c", ns="n"), "Metadata"),
        ("openshift-default", _rec("patch", "configmaps", name="dns-default",
                                   ns="openshift-dns"), "Metadata"),
        ("openshift-default", _rec("delete", "events", name="e", ns="n"), "Metadata"),
        ("openshift-default-4.17", _rec("delete", "events", name="e", ns="n"), "None"),
        ("openshift-wrb", _rec("patch", "configmaps", name="dns-default", ns="openshift-dns"),
         "RequestResponse"),
        ("openshift-wrb", _rec("patch", "dnses", name="default",
                               group="operator.openshift.io"), "RequestResponse"),
        ("openshift-wrb", _rec("get", "secrets", name="s", ns="n"), "Metadata"),
        ("openshift-wrb", _rec("patch", "secrets", name="s", ns="n"), "Metadata"),
        ("k3s-starter", _rec("create", "pods", name="p", ns="n"), "Metadata"),
    ]
    try:
        pols = {p["id"]: load_policy(p["files"]) for p in POLICIES}
    except (PolicyError, yaml.YAMLError, OSError) as e:
        fails.append(f"a shipped policy does not load: {e}")
        pols = {}
    for pid, rec, want in (facts if pols else []):
        o = rec["objectRef"]
        check(f"fact {pid}: {rec['verb']} {o.get('apiGroup', '')}/{o['resource']}"
              f"{'/' + o['subresource'] if o.get('subresource') else ''} "
              f"{o.get('namespace', '')}/{o.get('name', '')}",
              evaluate(pols[pid], attributes_from_record(rec))[0], want)
        n += 1
    if pols:
        check("k3s starter keeps RequestReceived",
              [r["stage"] for r in records_under(pols["k3s-starter"],
                                                 _rec("create", "pods", name="p", ns="n"))[0]],
              ["RequestReceived", "ResponseComplete"])
    n += 1

    # 8. Vendored files: digests match SOURCES, SOURCES.md lists each, and each
    # policy loads without a validation error.
    with open(os.path.join(REPO, PP, "SOURCES.md"), encoding="utf-8") as fh:
        sources_md = fh.read()
    for path, src in SOURCES.items():
        full = os.path.join(REPO, path)
        got = sha256_file(full) if os.path.exists(full) else "(missing)"
        check(f"vendored {path} sha256", got, src["sha256"])
        if src["sha256"] not in sources_md or src["url"] not in sources_md:
            fails.append(f"SOURCES.md does not list {path} with its URL and sha256")
        n += 2
        if "body_sha256" in src:
            body = b""
            if os.path.exists(full):
                with open(full, "rb") as fh:
                    lines = fh.read().splitlines(keepends=True)
                while lines and lines[0].startswith(b"#"):
                    lines.pop(0)
                body = b"".join(lines)
            check(f"vendored {path}: the text after its comment header",
                  hashlib.sha256(body).hexdigest(), src["body_sha256"])
            if src["body_sha256"] not in sources_md:
                fails.append(f"SOURCES.md does not list the body sha256 of {path}")
            n += 2
    listed = {f for p in POLICIES if p["kind"] == "provider" for f in p["files"]}
    check("every provider policy file has a SOURCES entry", sorted(listed - set(SOURCES)), [])
    check("lab mounts", check_lab_mounts(), [])
    n += 2

    # 9. The home check: it holds on the shipped lab policy and fails on a lab policy
    # that blinds a rule in its own column (core Events at None, as EKS does).
    rel = "T1070/k8s_events_deleted.yml"
    if "lab-apiserver" in pols and os.path.exists(os.path.join(SIGMA, rel)):
        lab = pols["lab-apiserver"]
        broken = copy.deepcopy(lab)
        broken["rules"].insert(0, policy_from_rules([{"level": "None", "resources": [
            {"group": "", "resources": ["events"]}]}])["rules"][0])
        for label, pol, want in (
                ("home check holds on the shipped lab policy", lab, []),
                ("home check fails on a lab policy that logs core Events at None", broken,
                 [f"{rel}: under its home policy lab-apiserver"])):
            res, _ = run_rule(rel, {"lab-apiserver": (pol, None)})
            errs = home_errors({"rules": {rel: {"home_policy": "lab-apiserver",
                                                "results": res}}})
            check(label, [e.split(" only ")[0] for e in errs], want)
            n += 1
        check("home check fails on a rule with no home",
              len(home_errors({"rules": {rel: {"home_policy": None, "results": {}}}})), 1)
        n += 1
    else:
        fails.append(f"home check self-test: {rel} or the lab-apiserver policy is missing")

    for f in fails:
        print(f"FAIL  {f}")
    print(f"self-test: {n} checks, {len(fails)} failed")
    return 1 if fails else 0


# ---------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help=f"fail if {os.path.relpath(OUT, REPO)} is stale")
    ap.add_argument("--update", action="store_true",
                    help=f"rewrite {os.path.relpath(OUT, REPO)}")
    ap.add_argument("--output", default=OUT,
                    help="the result file that --check and --update use")
    ap.add_argument("--json", help="also write the result to this file")
    ap.add_argument("--self-test", action="store_true", help="run the evaluator unit cases")
    ap.add_argument("--policy", action="append", help="print only these policy columns")
    ap.add_argument("--rule", action="append", help="print only these rules (<T>/<stem>.yml)")
    ap.add_argument("--detail", action="store_true", help="print every lost positive")
    ap.add_argument("--verify-sources", action="store_true",
                    help="network: fetch each upstream source and compare the vendored copy")
    ap.add_argument("--write-sources", action="store_true",
                    help="network: fetch each upstream source and rewrite the vendored copy")
    args = ap.parse_args()

    if args.verify_sources or args.write_sources:
        return verify_sources(write=args.write_sources)
    rc = 0
    if args.self_test:
        rc |= self_test()
        if not (args.check or args.update or args.json):
            return rc
    try:
        result = compute()
    except (PolicyError, yaml.YAMLError) as e:
        print(f"ERROR: a policy or rule file does not load: {e}")
        return 1
    bad = bad_selection(result, args.policy, args.rule)
    if bad:
        print("ERROR: unknown " + "; ".join(bad))
        return 2
    homes = home_errors(result, home_candidates(list(result["rules"])))
    if homes:
        print("FAIL: home check (a rule must fire on all its positives and on no negative "
              "under the lab policy its validator proves it on; module docstring, step 5):")
        for e in homes:
            print(f"  {e}")
        rc = 1
    text = dumps(result)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(text)
    if args.update:
        if homes:
            print(f"not written: {os.path.relpath(args.output, REPO)} (fix the home check "
                  "first; --json writes the result for inspection)")
            return 1
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {os.path.relpath(args.output, REPO)}")
    if args.check:
        try:
            with open(args.output, encoding="utf-8") as fh:
                old_text = fh.read()
        except FileNotFoundError:
            print(f"FAIL: {os.path.relpath(args.output, REPO)} does not exist; run "
                  "python3 detections/k8s_policy_coverage.py --update")
            return 1
        if old_text != text:
            try:
                changes = diff_summary(json.loads(old_text), result)
            except json.JSONDecodeError:
                changes = ["the committed file is not JSON"]
            print(f"FAIL: {os.path.relpath(args.output, REPO)} is stale "
                  "(a rule, a sidecar case, a policy file, a validator MANIFEST or the "
                  "evaluator's output changed):")
            for c in changes or ["formatting differs"]:
                print(f"  {c}")
            print("Regenerate it: python3 detections/k8s_policy_coverage.py --update")
            return 1
        if homes:
            print(f"{os.path.relpath(args.output, REPO)} matches the recomputed result, "
                  "but the home check above fails.")
        else:
            print(f"OK: {os.path.relpath(args.output, REPO)} is current "
                  f"({len(result['rules'])} rule(s), {len(result['policies'])} policies; "
                  "every rule fires on all its positives and on no negative under its "
                  "home lab policy).")
        return rc
    if not (args.update or args.json):
        print_table(result, args.policy, args.rule, args.detail)
    return rc


if __name__ == "__main__":
    sys.exit(main())
