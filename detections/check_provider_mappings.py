#!/usr/bin/env python3
"""
Prove offline that each managed-cluster field mapping keeps every Kubernetes rule's meaning.

The Kubernetes audit rules are written for the audit.k8s.io/v1 Event, the shape the
API server writes and the shape EKS sends to CloudWatch Logs. AKS (the AKSAudit /
AKSAuditAdmin tables) and GKE (Cloud Audit Logs) store the same event in other shapes,
and a pySigma pipeline in detections/pipelines/ renames the rule's fields for each. A
pipeline written by hand cannot be trusted on data it has never seen, so this check
proves it on every sidecar case (positive, near-miss, filtered, confounder, benign):

  For each product: kubernetes / service: audit rule with a sidecar, and each provider:
  1. TRANSFORM every event of every case into the provider's record shape, with the
     documented transform below (convert_aks, convert_gke). A provider whose stored
     text of a JSON list is not fixed has more than one VARIANT, and each variant is
     checked: "compact" (no blanks, key order kept) and "sorted" (no blanks, keys
     sorted, as Kusto's dynamic_to_json writes it; Kusto does not keep the key order of
     a property bag, learn.microsoft.com/kusto/query/scalar-data-types/dynamic).
  2. COMPILE the rule, each detection block alone and each detection item alone with
     pySigma's SQLite backend: plain (as the validators do) and through the provider
     pipeline. An item the pipeline refuses (a field the provider does not record) is
     NOT PORTABLE, with the pipeline's reason; a rule with such an item cannot convert.
     For AKS, every mapped field name must also be one that the KQL converter
     (convert_k8s.kql_path) can write: a field it cannot write is NOT PORTABLE with the
     reason "CANNOT CONVERT: ...", and an error that no approval excuses.
  3. COMPARE on every case: the case verdict (does the rule fire), and for every block
     the set of events it holds on, must be the same in both shapes. Block equality is
     what keeps a near-miss meaningful: the block it breaks still breaks, and the blocks
     it keeps still hold. Item truth is compared too and printed with -v (a warning).
  4. CHECK the mapped field names case-sensitively against the transformed records
     (SQLite column names are case-insensitive, so a wrong-case mapping would pass step
     3), check that a mapped field is carried by some transformed record whenever the
     native field is carried by a native one, and lint every regular expression the
     pipeline writes with .github/scripts/check_sigma_regex.py (and RE2 when installed).
  5. ANCHORS: detections/pipelines/anchors/<provider>/*.json hold real-shape records and
     source facts (with provenance). The transform must reproduce each anchor from its
     native event, the named rules must give the stated verdicts on both shapes, each
     GKE methodName / resourceName pair from a source must hold (and its "lost" items
     must not), each "must_not_hold" probe must be false on both shapes, each
     "known_differences" probe must give its stated, different truth on each shape (a
     documented loss of the provider's encoding), and each AKS pipeline mapping must
     have a field_map entry that a source shows.
  6. STORES THAT KEEP NO READS: AKSAuditAdmin has no get and list events, and GKE writes
     reads (get, list, watch) only to the Data Access log, which can be off. For each
     rule, the positive cases that stop firing (natively) without those events are
     reported; this never fails (mapping_results.json: loses_positive_without_reads).

A difference that a human accepted is an EXPECTED_LOSS entry, keyed (provider, rule,
case), with the reason and the exact difference; a NOT PORTABLE rule is a NOT_PORTABLE
entry, keyed (provider, rule), with the items. Both are human approvals, like the
waivers in check_sufficiency.py: the check fails on any difference that is not listed,
on a listed difference that changed, on a reason that this run cannot prove, on a listed
entry that no longer applies (stale), and on an entry keyed on a provider that does not
gate. Mode "exploded" never fails: no pipeline, and each element of a JSON list gets
its own indexed key (field.0, field.1, ...) with no field for the list's text, as on a
backend that explodes arrays (Elastic keeps them as multi-valued leaf fields instead).
It reports which rules read a list as its JSON text (detections/pipelines/README.md).

The result is also written as detections/pipelines/mapping_results.json (stable, sorted,
no timestamps, no case counts; schema in detections/pipelines/README.md). --check fails
when that file is not what this run generates. --approvals-table prints every approval
as a Markdown table for a pull request.

Usage:
    python3 detections/check_provider_mappings.py               # the check
    python3 detections/check_provider_mappings.py --check       # the check + stale results file
    python3 detections/check_provider_mappings.py --check --require-re2   # as CI runs it
    python3 detections/check_provider_mappings.py --write       # rewrite mapping_results.json
    python3 detections/check_provider_mappings.py --self-test   # planted errors must be caught
    python3 detections/check_provider_mappings.py --approvals-table   # every approval, for a PR
    python3 detections/check_provider_mappings.py -v --provider gke detections/sigma/T1609/k8s_pod_exec_attach.yml

Record transforms (audit.k8s.io/v1 Event -> provider record):
  aks  one AKSAudit row: each top-level key renamed to its column (verb -> Verb,
       objectRef -> ObjectRef, requestURI -> RequestUri, sourceIPs -> SourceIps, ...;
       the column list of learn.microsoft.com/azure/azure-monitor/reference/tables/aksaudit);
       keys inside a dynamic column unchanged; impersonatedUser dropped (no column).
       The KQL model of a dynamic value: a JSON list AND an object are compared as their
       JSON text (no blanks; keys in order, or sorted), and an object is not null. The
       query-time columns RequestObjectNotBag / ResponseObjectNotBag (convert_k8s.py
       writes their `extend` line) hold the body unless it is an object.
  gke  one Cloud Logging LogEntry: protoPayload {serviceName k8s.io, methodName,
       resourceName (the grammar in detections/pipelines/k8s_gke.py; a create without a
       subresource names the created object from a successful response, else no name),
       authenticationInfo {principalEmail <- user.username, authoritySelector <-
       impersonatedUser.username}, requestMetadata {callerIp <- sourceIPs[0],
       callerSuppliedUserAgent <- userAgent}, request / response <- requestObject /
       responseObject when it is an object (a JSON patch, an array or raw text, is
       dropped: AuditLog.request is a Struct), status}, labels <- annotations. Dropped:
       user.groups/uid/extra, impersonatedUser groups/uid/extra, requestURI's query
       string, the HTTP status, level, stage. The store model is the native one (an
       object has no value of its own), as in a store that flattens the LogEntry JSON
       like sigma_eval.flatten(); a store whose string operators read an object's JSON
       text needs the AKS treatment (detections/pipelines/README.md).
"""

import argparse
import copy
import glob
import importlib.util
import json
import os
import sys
from collections import namedtuple

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import sigma_eval  # noqa: E402  (runs the rule-directory intruder check before pySigma loads)
import rule_cases  # noqa: E402
import yaml  # noqa: E402
from sigma.backends.sqlite import sqliteBackend  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.exceptions import SigmaError  # noqa: E402
from sigma.processing.pipeline import ProcessingPipeline  # noqa: E402
from sigma.rule import SigmaDetection, SigmaRule  # noqa: E402
from sigma.types import SigmaRegularExpression  # noqa: E402

PIPELINES = os.path.join(HERE, "pipelines")
ANCHORS = os.path.join(PIPELINES, "anchors")
RESULTS = os.path.join(PIPELINES, "mapping_results.json")
SIGMA_DIR = os.path.join(HERE, "sigma")


def _load(name, path):
    """Import a module by path, not through sys.path (nothing next to it can shadow)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


k8s_gke = _load("k8s_gke", os.path.join(PIPELINES, "k8s_gke.py"))
convert_k8s = _load("convert_k8s", os.path.join(PIPELINES, "convert_k8s.py"))
check_sigma_regex = _load("check_sigma_regex",
                          os.path.join(REPO, ".github", "scripts", "check_sigma_regex.py"))
try:
    import re2 as _re2  # noqa: E402
except ImportError:
    _re2 = None


# ------------------------------------------------------------------ human approvals
# An accepted difference of one case: `why`, one of the reasons below, and `diff`, the
# exact difference this run must still show (case_signature() below). When the difference
# changes, the entry no longer excuses it. EXPECTED_LOSS is keyed (provider, rule) and
# maps each case name to its ExpectedLoss, so an entry is keyed (provider, rule, case).
# Each entry is a human approval: it changes only with a pull request that a human
# reviews and merges, as for the check_sufficiency.py waivers. The check also proves
# that the reason holds for each entry: a GKE_JSON_PATCH difference must vanish when the
# transform keeps the JSON-patch body (as its JSON text), and a KEY_ORDER difference
# must show in the "sorted" variant only.
ExpectedLoss = namedtuple("ExpectedLoss", "why diff")

GKE_JSON_PATCH = (
    "GKE stores the request body in protoPayload.request, a google.protobuf.Struct (an "
    "object; googleapis google/cloud/audit/audit_log.proto). A JSON-patch body is an array "
    "(or, in a case that models a raw-text pipeline, a string), and no public GKE record "
    "shows how GKE stores it, so the transform drops it, and the "
    "blocks that read the JSON-patch operation list cannot be shown to work on GKE. A live "
    "GKE capture (issue #55) settles it")
KEY_ORDER = (
    "the block matches the JSON text of a list with a pattern that needs the API server's "
    "key order (Go field order), and the provider does not keep the key order of an object "
    "(Kusto: learn.microsoft.com/kusto/query/scalar-data-types/dynamic; Cloud Logging: a "
    "google.protobuf.Struct is a map). The 'sorted' variant shows the miss: "
    "detections/RULE_DEFECTS.md K43")
GKE_CREATE_NAME = (
    "GKE's resourceName for a create (no subresource) has no name when the create failed, "
    "and names the created object when it succeeded (GoogleCloudPlatform/khi: a recorded "
    "generateName create whose resourceName holds the generated name, and extractor tests "
    "of failed creates with no name); the native Event's objectRef.name comes from the "
    "request body (empty for generateName). So an objectRef.name item on such a create can "
    "differ on GKE. A live GKE capture (issue #55) settles it")
REASONS = {"GKE_JSON_PATCH": GKE_JSON_PATCH, "KEY_ORDER": KEY_ORDER,
           "GKE_CREATE_NAME": GKE_CREATE_NAME}

# Proposed in the Wave 4 pull request (managed-cluster portability); a human approves
# the entries by merging it. Regenerate the text with --propose, then review it.
EXPECTED_LOSS = {
    ("aks", "T1098.006/k8s_rbac_privileged_grant.yml"): {
        "aggregation-controller-writes-impersonate-users-into-admin": ExpectedLoss(
            KEY_ORDER, "sorted: native fires, aks quiet; blocks sel_agg_beyond_builtin"),
    },
    ("gke", "T1098.006/k8s_rbac_privileged_grant.yml"): {
        "aggregation-controller-writes-impersonate-users-into-admin": ExpectedLoss(
            KEY_ORDER, "sorted: native fires, gke quiet; blocks sel_agg_beyond_builtin"),
        "clusterrole-json-patch-adds-node-metrics": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_rules_path"),
        "clusterrole-json-patch-adds-node-proxy": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jsonpatch_node_proxy, sel_jsonpatch_rules_path"),
        "clusterrole-json-patch-impersonate-verb": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jsonpatch_rules_grant, sel_jsonpatch_rules_path"),
        "clusterrole-json-patch-read-rule-procE": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_rules_path"),
        "clusterrole-json-patch-wildcard-rule": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jsonpatch_rules_grant, sel_jsonpatch_rules_path"),
        "crb-cluster-admin-json-patch-appends-sa-procE": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_subjects_path"),
        "crb-json-patch-adds-named-user": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_subjects_path"),
        "crb-json-patch-adds-system-authenticated": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jsonpatch_group_subject, sel_jsonpatch_subjects_path"),
        "crb-json-patch-appends-sa-to-tenant-binding": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_subjects_path"),
    },
    ("gke", "T1546/k8s_admission_webhook_repointed_to_url.yml"): {
        "jsonpatch-add-url-value-first": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-clientconfig-unknown-object-before-url": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-index-minus-zero": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-index-plus-zero": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-negative-index": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-remove-service-add-url": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-replace-clientconfig-value-first": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-replace-clientconfig-with-url": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-replace-root-with-url": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-replace-webhooks-list-with-url": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-url-dry-run-query-over-param-limit": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-url-fieldmanager-mentions-dry-run": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-url-op-extra-object-key": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
        "jsonpatch-url-uppercase-scheme": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_url"),
    },
    ("gke", "T1565.001/k8s_coredns_corefile_poisoned.yml"): {
        "jsonpatch-cluster-zone-stub-to-pod-ip": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_cluster_zone_forward_raw"),
        "jsonpatch-env-placeholder-splits-forward": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_env_placeholder_raw"),
        "jsonpatch-restore-k3s-default-corefile": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks filter_default_hosts_raw, sel_poison_hosts_raw"),
        "jsonpatch-rewrite-raw": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_poison_plugin_raw"),
        "jsonpatch-root-after-stub-block": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_public_forward_raw, sel_rogue_forward_raw"),
        "jsonpatch-root-brace-next-line": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_public_forward_raw, sel_rogue_forward_raw"),
        "jsonpatch-root-braceless-block": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_public_forward_raw, sel_rogue_forward_raw"),
        "jsonpatch-root-comma-key-list": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_cluster_zone_forward_raw, sel_public_forward_raw, sel_rogue_forward_raw"),
        "jsonpatch-root-forward-to-ip": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_public_forward_raw, sel_rogue_forward_raw"),
        "jsonpatch-root-tab-separated-keys": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_rogue_forward_raw"),
        "jsonpatch-stub-zone-forward-public-ip": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_public_forward_raw"),
    },
    ("gke", "T1611/k8s_podspec_confinement_disabled.yml"): {
        "cronjob-jobtemplate-seccomp-unconfined-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jpobj_path, sel_jpobj_value"),
        "cronjob-seccomp-pod-annotation-leaf-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_annotation"),
        "daemonset-apparmor-type-leaf-extra-string-key-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_leaf"),
        "daemonset-container-apparmor-unconfined-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jpobj_path, sel_jpobj_value"),
        "daemonset-copy-into-apparmor-profile-path-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_copy, sel_jpobj_path, sel_jpobj_value"),
        "deployment-apparmor-annotation-leaf-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_annotation"),
        "deployment-apparmor-annotation-map-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_annotation"),
        "deployment-apparmor-type-unconfined-jsonpatch-leaf": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_leaf"),
        "deployment-copy-into-apparmor-annotation-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_copy"),
        "deployment-labels-map-type-unconfined-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jpobj_value"),
        "deployment-move-into-seccomp-annotation-path-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_copy"),
        "deployment-move-into-seccomp-profile-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_copy, sel_jpobj_path, sel_jpobj_value"),
        "deployment-root-replace-seccomp-unconfined-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_value"),
        "deployment-seccomp-profile-leaf-extra-brace-string-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jpobj_path, sel_jpobj_value"),
        "deployment-seccomp-profile-leaf-extra-object-key-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jpobj_path, sel_jpobj_value"),
        "deployment-seccomp-profile-leaf-nested-type-unconfined-own-runtime-default-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jpobj_path"),
        "deployment-seccomp-profile-leaf-value-first-deep-op-key-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jpobj_path, sel_jpobj_value"),
        "deployment-seccomp-profile-leaf-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jpobj_path, sel_jpobj_value"),
        "deployment-seccomp-runtime-default-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jpobj_path"),
        "deployment-seccomp-type-leaf-extra-object-key-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_leaf"),
        "deployment-securitycontext-seccomp-extra-key-value-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_value"),
        "deployment-securitycontext-seccomp-unconfined-value-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_value"),
        "deployment-template-seccomp-unconfined-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jpobj_path, sel_jpobj_value"),
        "ephemeral-apparmor-profile-leaf-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jpobj_path, sel_jpobj_value"),
        "ephemeral-debug-seccomp-unconfined-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_value"),
        "jp-ephemeral-seccomp-unconfined-procE-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_value"),
        "profile-path-and-unrelated-type-unconfined-labels-two-ops-fires": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jpobj_path, sel_jpobj_value"),
        "remediation-test-op-asserts-unconfined-fires": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_conf_leaf"),
    },
    ("gke", "T1611/k8s_podspec_controller_host_access.yml"): {
        "patch-cronjob-hostipc-value-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_hostns_value, sel_jp_tmpl_path"),
        "patch-cronjob-syscap-jsonpatch-value": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_caps_value, sel_jp_tmpl_path"),
        "patch-daemonset-hostnetwork-false-value-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-daemonset-hostnetwork-value-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_hostns_value, sel_jp_tmpl_path"),
        "patch-daemonset-hostpid-jsonpatch-leaf": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_bool, sel_jp_tmpl_path"),
        "patch-deployment-add-securitycontext-privileged-jsonpatch-value": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_priv_value, sel_jp_tmpl_path"),
        "patch-deployment-caps-leaf-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_caps, sel_jp_tmpl_path"),
        "patch-deployment-caps-list-leaf-null-element-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_caps, sel_jp_tmpl_path"),
        "patch-deployment-caps-list-leaf-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_caps, sel_jp_tmpl_path"),
        "patch-deployment-caps-list-leaf-value-first-null-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_caps, sel_jp_tmpl_path"),
        "patch-deployment-caps-value-after-bracket-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_caps_value, sel_jp_tmpl_path"),
        "patch-deployment-copy-container-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-deployment-copy-into-caps-index-minus-zero-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_copy, sel_jp_tmpl_path"),
        "patch-deployment-copy-into-hostpid-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_copy, sel_jp_tmpl_path"),
        "patch-deployment-emptydir-leaf-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-deployment-emptydir-volume-value-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-deployment-hostipc-leaf-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_bool, sel_jp_tmpl_path"),
        "patch-deployment-hostpath-leaf-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_hostpath, sel_jp_tmpl_path"),
        "patch-deployment-hostpath-leaf-value-first-extra-brace-string-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_hostpath, sel_jp_tmpl_path"),
        "patch-deployment-hostpath-leaf-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_hostpath, sel_jp_tmpl_path"),
        "patch-deployment-hostpath-volume-jsonpatch-value": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_hostpath_value, sel_jp_tmpl_path"),
        "patch-deployment-hostpid-false-and-stdin-true-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-deployment-hostpid-leaf-deep-nested-key-not-graded": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-deployment-hostpid-leaf-extra-object-key-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_bool, sel_jp_tmpl_path"),
        "patch-deployment-hostpid-value-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_hostns_value, sel_jp_tmpl_path"),
        "patch-deployment-image-bump-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-deployment-move-into-privileged-path-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_copy, sel_jp_tmpl_path"),
        "patch-deployment-net-bind-service-cap-jsonpatch-value": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-deployment-net-bind-service-leaf-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-deployment-privileged-at-non-template-path-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_priv_value"),
        "patch-deployment-privileged-false-jsonpatch-leaf": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-deployment-privileged-jsonpatch-leaf": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_bool, sel_jp_tmpl_path"),
        "patch-deployment-privileged-leaf-extra-string-key-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_bool, sel_jp_tmpl_path"),
        "patch-deployment-root-replace-plain-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_tmpl_path"),
        "patch-deployment-root-replace-privileged-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_priv_value, sel_jp_tmpl_path"),
        "patch-deployment-sys-admin-leaf-index-plus-zero-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_caps, sel_jp_tmpl_path"),
        "patch-deployment-sys-admin-leaf-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_caps, sel_jp_tmpl_path"),
        "patch-deployment-sys-admin-leaf-negative-index-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_caps, sel_jp_tmpl_path"),
        "patch-statefulset-caps-list-leaf-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_caps, sel_jp_tmpl_path"),
        "remediation-test-op-asserts-host-network-fires": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_leaf_bool, sel_jp_tmpl_path"),
    },
    ("gke", "T1611/k8s_podspec_host_access.yml"): {
        "ephemeral-caps-leaf-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_caps"),
        "ephemeral-caps-list-leaf-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_caps"),
        "ephemeral-caps-list-leaf-null-element-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_caps"),
        "ephemeral-caps-list-leaf-value-first-bracket-null-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_caps"),
        "ephemeral-caps-list-leaf-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_caps"),
        "ephemeral-copy-image-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_eph_path"),
        "ephemeral-copy-into-privileged-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_copy"),
        "ephemeral-move-into-caps-index-plus-zero-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_copy"),
        "ephemeral-move-into-caps-path-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_copy"),
        "ephemeral-net-bind-service-cap-jsonpatch-value": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_eph_path"),
        "ephemeral-net-bind-service-leaf-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_eph_path"),
        "ephemeral-plain-container-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_eph_path"),
        "ephemeral-privileged-false-jsonpatch-leaf": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_eph_path"),
        "ephemeral-privileged-jsonpatch-leaf": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_bool"),
        "ephemeral-privileged-jsonpatch-value": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_priv_value"),
        "ephemeral-privileged-leaf-deep-nested-key-known-miss": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_eph_path"),
        "ephemeral-privileged-leaf-extra-key-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_bool"),
        "ephemeral-privileged-leaf-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_bool"),
        "ephemeral-root-replace-plain-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_eph_path"),
        "ephemeral-root-replace-privileged-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_priv_value"),
        "ephemeral-sys-admin-caps-value-after-bracket-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_caps_value, sel_jp_eph_path"),
        "ephemeral-sys-admin-caps-value-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_caps_value, sel_jp_eph_path"),
        "ephemeral-sys-admin-leaf-index-plus-zero-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_caps"),
        "ephemeral-sys-admin-leaf-negative-index-value-first-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_caps"),
        "ephemeral-sys-ptrace-jsonpatch-leaf": ExpectedLoss(
            GKE_JSON_PATCH, "all: native fires, gke quiet; blocks sel_jp_eph_path, sel_jp_leaf_caps"),
        "pod-container-privileged-off-ephemeral-path-jsonpatch": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jp_priv_value"),
    },
    ("gke", "T1685/k8s_admission_webhook_neutered.yml"): {
        "jsonpatch-add-matchcondition-false-index-plus-zero": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_matchconditions, sel_jsonpatch_neuter_value"),
        "jsonpatch-add-matchconditions-constant": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_matchconditions, sel_jsonpatch_neuter_value"),
        "jsonpatch-add-matchconditions-exclude-leases": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_matchconditions"),
        "jsonpatch-add-matchconditions-literal-false": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_matchconditions, sel_jsonpatch_neuter_value"),
        "jsonpatch-fail-open-dry-run-query-over-param-limit": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_fail_open"),
        "jsonpatch-fail-open-extra-object-key": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_fail_open"),
        "jsonpatch-fail-open-fieldmanager-mentions-dry-run": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_fail_open"),
        "jsonpatch-fail-open-index-minus-zero": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_fail_open"),
        "jsonpatch-fail-open-index-plus-zero": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_fail_open"),
        "jsonpatch-fail-open-negative-index": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_fail_open"),
        "jsonpatch-failurepolicy-ignore": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_fail_open"),
        "jsonpatch-remove-rules-extra-empty-object-key": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_rules_cleared"),
        "jsonpatch-remove-rules-index-plus-zero": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_rules_cleared"),
        "jsonpatch-remove-webhook-rules": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_rules_cleared"),
        "jsonpatch-remove-whole-webhook": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_whole_webhook"),
        "jsonpatch-replace-list-drops-rules-of-one-webhook": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_rules_kept, sel_jsonpatch_whole_webhook"),
        "jsonpatch-replace-webhooks-list-without-rules": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_whole_webhook"),
        "jsonpatch-replace-whole-webhook-fail-open": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_neuter_value, sel_jsonpatch_rules_kept, sel_jsonpatch_whole_webhook"),
        "jsonpatch-replace-whole-webhook-negative-index-fail-open": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_neuter_value, sel_jsonpatch_rules_kept, sel_jsonpatch_whole_webhook"),
        "jsonpatch-replace-whole-webhook-rules-kept": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_jsonpatch_rules_kept, sel_jsonpatch_whole_webhook"),
    },
    ("gke", "T1685/k8s_enforcer_workload_removed.yml"): {
        "deployment-jsonpatch-replace-spec-replicas-two": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "deployment-jsonpatch-replace-spec-replicas-zero": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body, sel_scale_zero_jsonpatch"),
        "deployment-jsonpatch-value-minus-zero-raw-text": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body, sel_scale_zero_jsonpatch"),
        "jsonpatch-scale-gatekeeper-to-one": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks filter_scale_jsonpatch_positive, sel_no_jsonpatch_body"),
        "jsonpatch-scale-zero-gatekeeper": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body, sel_scale_zero_jsonpatch"),
        "jsonpatch-scale-zero-gatekeeper-brace-string-in-nested-key-known-miss": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "jsonpatch-scale-zero-gatekeeper-deep-nested-key-known-miss": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "scale-jsonpatch-remove-replicas": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "scale-jsonpatch-replace-to-three": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks filter_scale_jsonpatch_positive, sel_no_jsonpatch_body"),
        "scale-jsonpatch-set-count-then-remove": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
    },
    ("gke", "T1685/k8s_security_tool_workload_removed.yml"): {
        "anchor-deployment-jsonpatch-replace-spec-replicas-two": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "anchor-deployment-jsonpatch-replace-spec-replicas-zero": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body, sel_scale_zero_jsonpatch"),
        "anchor-deployment-jsonpatch-value-minus-zero-raw-text": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body, sel_scale_zero_jsonpatch"),
        "anchor-jsonpatch-scale-zero-brace-string-in-nested-key-known-miss": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "anchor-jsonpatch-scale-zero-deep-nested-key-known-miss": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "anchor-scale-jsonpatch-remove-replicas": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "anchor-scale-jsonpatch-replace-to-three": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks filter_scale_jsonpatch_positive, sel_no_jsonpatch_body"),
        "anchor-scale-jsonpatch-set-count-then-remove": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "jsonpatch-copy-from-replicas": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "jsonpatch-copy-zero-into-replicas": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body, sel_scale_zero_jsonpatch"),
        "jsonpatch-replicas-three-other-zero": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body"),
        "jsonpatch-scale-down-to-one": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks filter_scale_jsonpatch_positive, sel_no_jsonpatch_body"),
        "jsonpatch-scale-zero": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body, sel_scale_zero_jsonpatch"),
        "jsonpatch-scale-zero-extra-object-key": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body, sel_scale_zero_jsonpatch"),
        "jsonpatch-scale-zero-two-level-object-key": ExpectedLoss(
            GKE_JSON_PATCH, "all: blocks sel_no_jsonpatch_body, sel_scale_zero_jsonpatch"),
    },
}

# A rule that the provider's pipeline cannot convert: (provider, rule) -> the items it
# refuses. The pipeline's own message is the reason (printed and in mapping_results.json).
# A human approval, like EXPECTED_LOSS.
NOT_PORTABLE = {
    ("gke", "T1070/k8s_namespace_deleted.yml"): (
        "filter_dry_run[0].requestURI",
        "filter_dry_run_query.requestURI",
        "filter_dry_run_read[0].requestURI",
        "filter_query_parsed.requestURI",
        "sel_accepted.responseStatus.code",
        "sel_no_request_uri.requestURI",
    ),
    ("aks", "T1134/k8s_impersonation.yml"): (
        "select_impersonation.impersonatedUser.username",
    ),
    ("gke", "T1134/k8s_impersonation.yml"): (
        "select_denied_impersonation.responseStatus.code",
        "select_denied_impersonation.responseStatus.message",
        "select_headers_without_user.responseStatus.code",
        "select_headers_without_user.responseStatus.message",
    ),
    ("aks", "T1134/k8s_impersonation_privileged.yml"): (
        "sel_priv_groups.impersonatedUser.groups",
        "sel_priv_sa.impersonatedUser.username",
        "sel_priv_users.impersonatedUser.username",
        "select_impersonation.impersonatedUser.username",
    ),
    ("gke", "T1134/k8s_impersonation_privileged.yml"): (
        "sel_priv_groups.impersonatedUser.groups",
    ),
    ("gke", "T1546/k8s_admission_webhook_created.yml"): (
        "select_adm_ssa_create.responseStatus.code",
    ),
    ("gke", "T1546/k8s_admission_webhook_repointed_to_url.yml"): (
        "filter_dry_run.requestURI",
        "sel_query_parsed.requestURI",
        "select_accepted.responseStatus.code",
    ),
    ("gke", "T1546/k8s_malicious_admission_webhook_created.yml"): (
        "select_webhook_ssa_create.responseStatus.code",
    ),
    ("gke", "T1572/k8s_node_proxy_portforward.yml"): (
        "select_portforward_endpoint.requestURI",
    ),
    ("gke", "T1609/k8s_node_proxy_exec.yml"): (
        "filter_other_kubelet_endpoint.requestURI",
        "select_exec_path.requestURI",
        "select_path_not_normalized.requestURI",
    ),
    ("gke", "T1609/k8s_node_proxy_kubelet_api.yml"): (
        "select_kubelet_endpoint.requestURI",
    ),
    ("gke", "T1685/k8s_admission_webhook_disabled.yml"): (
        "filter_dry_run_write.requestURI",
        "sel_query_parsed.requestURI",
    ),
    ("gke", "T1685/k8s_admission_webhook_neutered.yml"): (
        "filter_dry_run_write.requestURI",
        "filter_ssa_install.responseStatus.code",
        "sel_query_parsed.requestURI",
    ),
    ("gke", "T1685/k8s_enforcer_workload_removed.yml"): (
        "filter_dry_run_write.requestURI",
        "sel_accepted.responseStatus.code",
        "sel_query_parsed.requestURI",
        "sel_scale_patch_body.level",
    ),
    ("gke", "T1685/k8s_security_tool_workload_removed.yml"): (
        "filter_dry_run_write.requestURI",
        "sel_accepted.responseStatus.code",
        "sel_query_parsed.requestURI",
        "sel_scale_patch_body.level",
    ),
}


# ------------------------------------------------------------------ record transforms
AKS_COLUMNS = {
    "annotations": "Annotations", "auditID": "AuditId", "level": "Level",
    "objectRef": "ObjectRef", "requestObject": "RequestObject",
    "requestReceivedTimestamp": "RequestReceivedTime", "requestURI": "RequestUri",
    "responseObject": "ResponseObject", "responseStatus": "ResponseStatus",
    "sourceIPs": "SourceIps", "stage": "Stage", "stageTimestamp": "StageReceivedTime",
    "user": "User", "userAgent": "UserAgent", "verb": "Verb",
}


def convert_aks(ev):
    """audit.k8s.io/v1 Event -> one AKSAudit / AKSAuditAdmin row (no ImpersonatedUser column)."""
    return {AKS_COLUMNS[k]: copy.deepcopy(v) for k, v in ev.items() if k in AKS_COLUMNS}


# HTTP status -> google.rpc.Code: the reverse of the "HTTP Mapping" notes in
# googleapis google/rpc/code.proto. How GKE fills protoPayload.status is not documented;
# no rule reads it (responseStatus is NOT PORTABLE on GKE).
_RPC = {400: 3, 401: 16, 403: 7, 404: 5, 409: 6, 429: 8, 499: 1, 500: 13, 501: 12, 503: 14,
        504: 4}


def gke_created_name(ev):
    """The name that GKE's resourceName shows for a create without a subresource (see
    GKE_CREATE_NAME): none for a failed create; for a successful one, the created object's
    name from the response object, else objectRef.name (the request body's name)."""
    code = (ev.get("responseStatus") or {}).get("code")
    if isinstance(code, int) and code >= 400:
        return None
    response = ev.get("responseObject")
    if isinstance(response, dict):
        name = (response.get("metadata") or {}).get("name")
        if isinstance(name, str) and name:
            return name
    return (ev.get("objectRef") or {}).get("name")


def gke_method_and_resource(ev, ref_name_on_create=False):
    """(methodName, resourceName) for an Event, per the grammar in k8s_gke.py.

    ref_name_on_create=True takes a create's name from objectRef.name instead (the
    counterfactual that proves a GKE_CREATE_NAME difference)."""
    o = ev.get("objectRef") or {}
    verb = ev.get("verb") or ""
    res = o.get("resource")
    if not res:  # a non-resource request (unverified form)
        return f"io.k8s.{verb}", (ev.get("requestURI") or "").split("?", 1)[0].lstrip("/")
    group = o.get("apiGroup") or ""
    ver = o.get("apiVersion") or "v1"
    if "/" in ver:
        ver = ver.split("/", 1)[1]
    sub, ns, name = o.get("subresource"), o.get("namespace"), o.get("name")
    if verb == "create" and not sub and not ref_name_on_create:
        name = gke_created_name(ev)
    method = (f"io.k8s.{k8s_gke.gke_group(group)}.{ver}.{res}" + (f".{sub}" if sub else "")
              + f".{verb}")
    parts = [group or "core", ver]
    if ns and res != "namespaces":
        parts += ["namespaces", ns]
    parts.append(res)
    if name:
        parts.append(name)
        if sub:
            parts.append(sub)
    return method, "/".join(parts)


def convert_gke(ev, keep_bodies=False, ref_name_on_create=False):
    """audit.k8s.io/v1 Event -> one GKE Cloud Logging LogEntry (protoPayload AuditLog).

    The two options are counterfactuals that prove an EXPECTED_LOSS reason: keep_bodies
    keeps a body that is not an object (GKE_JSON_PATCH), ref_name_on_create takes a
    create's name from objectRef.name (GKE_CREATE_NAME)."""
    if ref_name_on_create:
        method, resource = gke_method_and_resource(ev, ref_name_on_create=True)
    else:
        method, resource = gke_method_and_resource(ev)
    o = ev.get("objectRef") or {}
    pp = {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": "k8s.io",
          "methodName": method, "resourceName": resource}
    user = ev.get("user") or {}
    auth = {}
    if "username" in user:
        auth["principalEmail"] = user["username"]
    imp = ev.get("impersonatedUser") or {}
    if "username" in imp:
        auth["authoritySelector"] = imp["username"]
    if auth:
        pp["authenticationInfo"] = auth
    meta = {}
    if ev.get("sourceIPs"):
        meta["callerIp"] = ev["sourceIPs"][0]
    if "userAgent" in ev:
        meta["callerSuppliedUserAgent"] = ev["userAgent"]
    if meta:
        pp["requestMetadata"] = meta
    for src, dst in (("requestObject", "request"), ("responseObject", "response")):
        body = ev.get(src)
        if isinstance(body, dict):
            body = copy.deepcopy(body)
            # '@type' as the khi records show it: k8s.io/Patch for a patch body,
            # core.k8s.io/<version>.<Kind> for a core object. Other groups: unverified.
            if src == "requestObject" and ev.get("verb") == "patch":
                body = {"@type": "k8s.io/Patch", **body}
            elif not o.get("apiGroup") and isinstance(body.get("kind"), str) \
                    and body["kind"] != "Status":
                body = {"@type": f"core.k8s.io/{o.get('apiVersion') or 'v1'}.{body['kind']}",
                        **body}
            pp[dst] = body
    code = (ev.get("responseStatus") or {}).get("code")
    if isinstance(code, int):
        pp["status"] = {"code": 0} if code < 400 else {
            "code": _RPC.get(code, 2), "message": (ev.get("responseStatus") or {}).get("message", "")}
    if keep_bodies:
        for src, dst in (("requestObject", "request"), ("responseObject", "response")):
            if src in ev and not isinstance(ev[src], dict):
                pp[dst] = copy.deepcopy(ev[src])
    entry = {"protoPayload": pp, "resource": {"type": "k8s_cluster"}}
    if ev.get("auditID"):
        entry["insertId"] = ev["auditID"]
    if ev.get("annotations"):
        entry["labels"] = dict(ev["annotations"])
    return entry


def _flatten_json(obj, prefix, sort, object_text=False):
    out = {}
    for key, val in obj.items():
        name = f"{prefix}{key}"
        if isinstance(val, dict):
            if object_text:  # KQL: an object is not null, and reads as its JSON text
                out[name] = json.dumps(val, separators=(",", ":"), sort_keys=sort)
            out.update(_flatten_json(val, f"{name}.", sort, object_text))
        elif isinstance(val, list):
            out[name] = json.dumps(val, separators=(",", ":"), sort_keys=sort)
        else:
            out[name] = val
    return out


def flatten_compact(obj):
    """sigma_eval.flatten, but a list is COMPACT JSON text (no blanks), key order kept."""
    return _flatten_json(obj, "", False)


def flatten_sorted(obj):
    """Compact JSON text with sorted keys, as Kusto's dynamic_to_json() writes it."""
    return _flatten_json(obj, "", True)


# The query-time columns that convert_k8s.py defines with an `extend` line for an AKS
# query (convert_k8s.NOT_BAG): the body, or null when the body is a property bag.
AKS_NOT_BAG = {"RequestObjectNotBag": "RequestObject", "ResponseObjectNotBag": "ResponseObject"}


def _aks_flatten(sort):
    def flat(row):
        out = _flatten_json(row, "", sort, object_text=True)
        for col, src in AKS_NOT_BAG.items():
            if src in row and not isinstance(row[src], dict):
                out[col] = out[src]
        return out
    flat.__doc__ = (f"An AKS row in the KQL model ({'sorted' if sort else 'original'} key "
                    "order): lists and objects as JSON text, plus the query-time columns.")
    return flat


aks_flatten_compact, aks_flatten_sorted = _aks_flatten(False), _aks_flatten(True)


def flatten_exploded(obj, prefix=""):
    """A list becomes indexed keys (a.0, a.1.b): no field holds the list's JSON text."""
    out = {}
    items = obj.items() if isinstance(obj, dict) else enumerate(obj)
    for key, val in items:
        name = f"{prefix}{key}"
        if isinstance(val, (dict, list)):
            if val:
                out.update(flatten_exploded(val, f"{name}."))
        else:
            out[name] = val
    return out


def aks_pipeline():
    with open(os.path.join(PIPELINES, "kubernetes_aks_auditlogs.yml"), encoding="utf-8") as fh:
        return ProcessingPipeline.from_yaml(fh.read())


def gke_pipeline():
    return k8s_gke.gke_cloud_audit()


def convert_gke_keeping_bodies(ev):
    """convert_gke, but a body that is not an object (a JSON patch: an array, or the raw text
    that a case models) is kept: the counterfactual that proves a GKE_JSON_PATCH difference
    comes from the dropped body alone."""
    return convert_gke(ev, keep_bodies=True)


def convert_gke_ref_name(ev):
    """convert_gke, but a create's resourceName takes objectRef.name: the counterfactual
    that proves a GKE_CREATE_NAME difference comes from the create name alone."""
    return convert_gke(ev, ref_name_on_create=True)


def gke_dropped(field, event):
    """The transform drops a body that is not an object: AuditLog.request is a Struct."""
    return field in ("requestObject", "responseObject") and field in event \
        and not isinstance(event[field], dict)


def aks_render(field):
    """The KQL path the AKS converter writes for a mapped field name; ValueError when
    convert_k8s.py cannot render it (CANNOT CONVERT there)."""
    return convert_k8s.kql_path(field)


# counterfactuals: {reason name: a transform without that one loss}. A difference
# approved with that reason must vanish under it. render: the provider's own field
# renderer (a mapped field name -> its query text; ValueError when it cannot), or None
# when any pySigma backend writes the query.
Provider = namedtuple("Provider",
                      "pipeline convert variants gate title dropped counterfactuals render")
PROVIDERS = {
    "aks": Provider(aks_pipeline, convert_aks,
                    {"compact": aks_flatten_compact, "sorted": aks_flatten_sorted}, True,
                    "AKS resource-specific table AKSAudit (KQL; AKSAuditAdmin holds the same "
                    "rows without get and list events: see loses_positive_without_reads)",
                    lambda field, event: False, {}, aks_render),
    "gke": Provider(gke_pipeline, convert_gke,
                    {"compact": flatten_compact, "sorted": flatten_sorted}, True,
                    "GKE Cloud Audit Logs (Cloud Logging LogEntry JSON; reads only with Data "
                    "Access logs on: see loses_positive_without_reads)", gke_dropped,
                    {"GKE_JSON_PATCH": convert_gke_keeping_bodies,
                     "GKE_CREATE_NAME": convert_gke_ref_name}, None),
    # No pipeline: the EKS CloudWatch message (and any raw-JSON store) IS the native Event.
    # This mode only shows which rules read a list as its JSON text, which a backend that
    # explodes JSON arrays into multi-valued fields cannot match. It never fails.
    "exploded": Provider(None, lambda ev: ev, {"exploded": flatten_exploded}, False,
                         "native Event on a backend that explodes JSON arrays (no pipeline)",
                         lambda field, event: False, {}, None),
}
# Stores that keep no reads: the verbs whose events they do not hold.
READS = {
    "aksauditadmin": ("AKSAuditAdmin: AKSAudit without get and list events (Microsoft Learn, "
                      "tables/aksauditadmin)", ("get", "list")),
    "gke_admin_activity": ("GKE with Data Access logs off: Admin Activity only, no get, list "
                           "or watch (gke-mcp k8s_audit_logs.md: Data Access logs hold reads, "
                           "'if enabled')", ("get", "list", "watch")),
}


# ------------------------------------------------------------------ rule structure
def load_rule(path):
    with open(path, encoding="utf-8") as fh:
        docs = [d for d in yaml.safe_load_all(fh) if d]
    if len(docs) != 1 or "correlation" in docs[0]:
        raise ValueError(f"{path}: one plain rule expected (a correlation rule is not "
                         "supported by this check yet)")
    return docs[0]


def _map_items(block, prefix, mapping):
    fields = [str(k).split("|")[0] for k in mapping]
    names = [str(k) if fields.count(f) > 1 else f for k, f in zip(mapping, fields)]
    return [(f"{prefix}.{name}", block, str(k).split("|")[0], {k: v})
            for name, (k, v) in zip(names, mapping.items())]


def detection_items(doc):
    """[(atom, block, field, detection)] for every item, named as rule_cases.py names atoms."""
    out = []
    for block, definition in doc["detection"].items():
        if block == "condition":
            continue
        if isinstance(definition, dict):
            out += _map_items(block, block, definition)
        elif isinstance(definition, list) and definition and all(isinstance(m, dict)
                                                                 for m in definition):
            if len(definition) == 1:
                out += _map_items(block, block, definition[0])
            else:
                for i, m in enumerate(definition):
                    out += _map_items(block, f"{block}[{i}]", m)
        else:
            out.append((block, block, None, definition))
    return out


def _doc_with(doc, detection):
    d = {k: copy.deepcopy(v) for k, v in doc.items() if k in ("title", "id", "logsource")}
    d["title"] = d.get("title") or "rule"
    d["detection"] = detection
    return d


def compile_doc(doc, pipeline):
    backend = sqliteBackend(processing_pipeline=pipeline) if pipeline else sqliteBackend()
    queries = backend.convert(SigmaCollection.from_dicts([doc]))
    if len(queries) != 1:
        raise ValueError(f"expected one query, got {len(queries)}")
    return queries[0]


def mapped_rule(doc, pipeline):
    rule = SigmaRule.from_dict(copy.deepcopy(doc))
    if pipeline is not None:
        pipeline.apply(rule)
    return rule


def rule_fields_and_regexes(rule):
    names, regexes = set(), set()

    def walk(det):
        for item in det.detection_items:
            if isinstance(item, SigmaDetection):
                walk(item)
            elif item.field:
                names.add(item.field)
                regexes.update(str(v.regexp) for v in item.value
                               if isinstance(v, SigmaRegularExpression))
    for det in rule.detection.detections.values():
        walk(det)
    return names, regexes


def list_paths(obj, prefix=""):
    """Dotted paths at which the event holds a JSON list (flatten() makes those text)."""
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            name = f"{prefix}{k}"
            if isinstance(v, list):
                out.add(name)
            elif isinstance(v, dict):
                out |= list_paths(v, f"{name}.")
    return out


# ------------------------------------------------------------------ evaluation
def _hits_per_case(sql_by_key, case_events):
    """{key: [set(event index) per case]} for every compiled query, one table per run."""
    flat = [(ci, ei, ev) for ci, events in enumerate(case_events) for ei, ev in enumerate(events)]
    out = {k: [set() for _ in case_events] for k in sql_by_key}
    if not flat:
        return out
    try:
        tables = [(sigma_eval.EventTable([ev for _, _, ev in flat]), flat)]
    except ValueError:  # keys that differ only by case across cases: one table per case
        tables = [(sigma_eval.EventTable(events), [(ci, ei, ev) for ei, ev in enumerate(events)])
                  for ci, events in enumerate(case_events) if events]
    for table, rows in tables:
        for key, sql in sql_by_key.items():
            for hit in table.hit_indices(sql):
                for row in hit:
                    ci, ei, _ = rows[row]
                    out[key][ci].add(ei)
    return out


def case_signature(diffs):
    """{variant: (verdict diff or None, [blocks])} -> one stable string."""
    parts = {}
    for variant, (verdict, blocks) in sorted(diffs.items()):
        bits = []
        if verdict:
            bits.append(verdict)
        if blocks:
            bits.append("blocks " + ", ".join(sorted(blocks)))
        if bits:
            parts[variant] = "; ".join(bits)
    if not parts:
        return ""
    if len(set(parts.values())) == 1 and len(parts) == len(diffs):
        return "all: " + next(iter(parts.values()))
    return " | ".join(f"{v}: {s}" for v, s in sorted(parts.items()))


def check_rule(path, provider_name, provider=None):
    """One rule on one provider. Returns a report dict (see main() for the fields)."""
    provider = provider or PROVIDERS[provider_name]
    rel = os.path.relpath(path, SIGMA_DIR)
    doc = load_rule(path)
    cases, errors = rule_cases.load_cases(rule_cases.cases_path(path))
    if errors:
        raise ValueError(f"{rel}: sidecar errors: {errors}")
    pipeline = provider.pipeline() if provider.pipeline else None
    items = detection_items(doc)
    blocks = [b for b in doc["detection"] if b != "condition"]
    report = {"rule": rel, "provider": provider_name, "cases": len(cases), "not_portable": {},
              "case_diffs": {}, "item_diffs": {}, "errors": []}

    native_sql, mapped_sql = {"<rule>": compile_doc(doc, None)}, {}
    for b in blocks:
        native_sql[b] = compile_doc(_doc_with(doc, {b: doc["detection"][b], "condition": b}), None)
    for atom, block, field, det in items:
        item_doc = _doc_with(doc, {"_item": det, "condition": "_item"})
        native_sql["item:" + atom] = compile_doc(item_doc, None)
        if pipeline is None:
            mapped_sql["item:" + atom] = native_sql["item:" + atom]
            continue
        try:
            mapped_sql["item:" + atom] = compile_doc(item_doc, provider.pipeline())
        except SigmaError as e:
            report["not_portable"][atom] = str(e).split("\n")[0]
            continue
        # The provider's own renderer (the AKS KQL converter) must write every mapped
        # field. A field it cannot write is NOT PORTABLE there, as the converter reports
        # it; it is also an error that no approval excuses: fix the converter.
        if provider.render is not None:
            names, _ = rule_fields_and_regexes(mapped_rule(item_doc, provider.pipeline()))
            for name in sorted(names):
                try:
                    provider.render(name)
                except ValueError as e:
                    why = f"CANNOT CONVERT: {str(e).splitlines()[0]}"
                    report["not_portable"][atom] = why
                    report["errors"].append(f"{atom}: {why} (the converter cannot write this "
                                            "mapped field: fix detections/pipelines/"
                                            "convert_k8s.py, for example MAP_PARENTS)")
                    mapped_sql.pop("item:" + atom, None)
                    break
    for b in blocks:
        if pipeline is None:
            mapped_sql[b] = native_sql[b]
        elif not any(blk == b and a in report["not_portable"] for a, blk, _, _ in items):
            try:
                mapped_sql[b] = compile_doc(_doc_with(doc, {b: doc["detection"][b],
                                                            "condition": b}), provider.pipeline())
            except SigmaError as e:  # every item converts, the block does not
                report["not_portable"][b] = str(e).split("\n")[0]
    if not report["not_portable"]:
        try:
            mapped_sql["<rule>"] = compile_doc(doc, pipeline) if pipeline else native_sql["<rule>"]
        except SigmaError as e:  # every block converts, the rule does not
            report["not_portable"]["<rule>"] = str(e).split("\n")[0]

    native_events = [[sigma_eval.flatten(e) for e in c["events"]] for c in cases]
    native_hits = _hits_per_case(native_sql, native_events)
    converted = [[provider.convert(e) for e in c["events"]] for c in cases]
    variant_hits, variant_keys = {}, {}
    for variant, flat in provider.variants.items():
        events = [[flat(e) for e in evs] for evs in converted]
        variant_hits[variant] = _hits_per_case(mapped_sql, events)
        variant_keys[variant] = {k for evs in events for e in evs for k in e}

    counter_hits = {}  # {reason: {variant: hits}}
    for reason, transform in sorted(provider.counterfactuals.items()):
        alt = [[transform(e) for e in c["events"]] for c in cases]
        counter_hits[reason] = {variant: _hits_per_case(mapped_sql, [[flat(e) for e in evs]
                                                                     for evs in alt])
                                for variant, flat in provider.variants.items()}
    report["counterfactual"] = {reason: {} for reason in counter_hits}

    def signature(ci, by_variant):
        diffs = {}
        for variant, hits in by_variant.items():
            verdict = None
            if "<rule>" in hits:
                a, b = bool(native_hits["<rule>"][ci]), bool(hits["<rule>"][ci])
                if a != b:
                    verdict = f"native {'fires' if a else 'quiet'}, {provider_name} " \
                              f"{'fires' if b else 'quiet'}"
            diffs[variant] = (verdict, [b for b in blocks
                                        if b in hits and native_hits[b][ci] != hits[b][ci]])
        return case_signature(diffs)

    for ci, case in enumerate(cases):
        item_diffs = {}
        for variant, hits in variant_hits.items():
            idiff = [a[5:] for a in hits if a.startswith("item:")
                     and native_hits[a][ci] != hits[a][ci]]
            if idiff:
                item_diffs[variant] = sorted(idiff)
        sig = signature(ci, variant_hits)
        if sig:
            report["case_diffs"][case["name"]] = {"kind": case["kind"], "diff": sig}
            for reason, hits in counter_hits.items():
                report["counterfactual"][reason][case["name"]] = signature(ci, hits)
        if item_diffs:
            report["item_diffs"][case["name"]] = item_diffs

    # Field names: case-sensitive, and carried whenever the native field is carried
    # (except where the transform documents that it drops the field).
    if pipeline is not None:
        raw_events = [e for c in cases for e in c["events"]]
        all_keys = set().union(*variant_keys.values())
        folded = {k.lower(): k for k in all_keys}
        native_regexes = rule_fields_and_regexes(mapped_rule(doc, None))[1]
        for atom, block, field, det in items:
            if atom in report["not_portable"] or field is None:
                continue
            item_rule = mapped_rule(_doc_with(doc, {"_item": det, "condition": "_item"}),
                                    provider.pipeline())
            names, regexes = rule_fields_and_regexes(item_rule)
            names.discard("protoPayload.serviceName")
            for name in sorted(names):
                if name not in all_keys and name.lower() in folded:
                    report["errors"].append(f"{atom}: mapped field {name!r} differs only in "
                                            f"letter case from the record key "
                                            f"{folded[name.lower()]!r}")
            carriers = [e for e in raw_events if field in sigma_eval.flatten(e)
                        and not provider.dropped(field, e)]
            if carriers and names and not any(
                    names & set(flat(provider.convert(e)))
                    for e in carriers for flat in provider.variants.values()):
                report["errors"].append(f"{atom}: {len(carriers)} native record(s) carry "
                                        f"{field!r}, but no transformed one carries "
                                        f"{sorted(names)}")
            for r in sorted(regexes - native_regexes):
                found = check_sigma_regex.check_value(r, [], _re2)
                if found:
                    report["errors"].append(f"{atom}: generated regex {r!r}: {'; '.join(found)}")
    # The static recount: items that read a field holding a JSON list in some case event.
    lists = set()
    for c in cases:
        for e in c["events"]:
            lists |= list_paths(e)
    report["list_text_items"] = sorted(a for a, _, f, _ in items if f in lists)
    # Stores that keep no reads: the positive cases that stop firing (natively).
    report["reads_lost"] = {}
    for key, (_, verbs) in READS.items():
        kept = [[sigma_eval.flatten(e) for e in c["events"] if e.get("verb") not in verbs]
                for c in cases]
        hits = _hits_per_case({"<rule>": native_sql["<rule>"]}, kept)["<rule>"]
        report["reads_lost"][key] = sorted(
            c["name"] for ci, c in enumerate(cases)
            if c["kind"] == "positive" and native_hits["<rule>"][ci] and not hits[ci])
    return report


# ------------------------------------------------------------------ anchors
def _get(obj, path):
    cur = obj
    for part in path:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _set(obj, path, value):
    cur = obj
    for part in path[:-1]:
        cur = cur.setdefault(part, {})
    cur[path[-1]] = value


def _mapped_names(field, provider):
    """The field names one native field becomes through the provider pipeline."""
    doc = {"title": "anchor", "logsource": {"product": "kubernetes", "service": "audit"},
           "detection": {"sel": {field: "x"}, "condition": "sel"}}
    names, _ = rule_fields_and_regexes(mapped_rule(doc, provider.pipeline()))
    names.discard("protoPayload.serviceName")
    return names


def _probe_doc(selection):
    return {"title": "anchor", "logsource": {"product": "kubernetes", "service": "audit"},
            "detection": {"sel": selection, "condition": "sel"}}


def pipeline_mappings(pipeline):
    """(exact field names, field prefixes) that a pipeline's field mappings rename."""
    from sigma.processing.transformations import (FieldMappingTransformation,
                                                  FieldPrefixMappingTransformation)
    exact, prefixes = set(), set()
    for item in pipeline.items:
        t = item.transformation
        if isinstance(t, FieldPrefixMappingTransformation):
            prefixes |= set(t.mapping)
        elif isinstance(t, FieldMappingTransformation):
            exact |= set(t.mapping)
    return exact, prefixes


def _verdict(doc, events, pipeline):
    return bool(sigma_eval.evaluate(compile_doc(doc, pipeline), events))


def check_anchor(path, provider_name, provider=None):
    """Problems (strings) for one anchor file; [] when it holds.

    An anchor may hold: "native" (an audit.k8s.io/v1 Event) and "record" (the real-shape
    provider record it encodes) with "compare" (paths at which the transform of "native"
    must equal "record"); "rules" (verdicts and block truths the named rules must give on
    both shapes) and "variants" (the same after setting native paths in both shapes);
    "pairs" (GKE methodName / resourceName pairs from a source, resourceName null when the
    source shows only the methodName; "lost": the native items that GKE does not record
    there, which must not hold on the record); "must_hold" / "must_not_hold" (probes
    {selection, native}: true / false on the native Event and on its transform);
    "known_differences" (probes {selection, native, holds_native, holds_provider}: a
    documented difference of the provider's encoding; each shape must give its stated
    truth, and the two must differ, so a change of the encoding shows here);
    "field_map" (native field -> the provider field the pipeline must write; with
    "field_map_complete", every mapping the pipeline writes must have an entry);
    "columns" (the only top-level keys a transformed record may have; "query_columns" are
    the query-time columns a field may also map to).
    """
    provider = provider or PROVIDERS[provider_name]
    with open(path, encoding="utf-8") as fh:
        anchor = json.load(fh)
    problems = []
    if not (anchor.get("provenance") or {}).get("source"):
        problems.append("no provenance.source")
    native, real = anchor.get("native"), anchor.get("record")
    if native is not None and real is not None:
        mine = provider.convert(native)
        for keys in anchor.get("compare", []):
            if _get(mine, keys) != _get(real, keys):
                problems.append(f"transform differs at {'/'.join(keys)}: "
                                f"{json.dumps(_get(mine, keys))[:200]} != recorded "
                                f"{json.dumps(_get(real, keys))[:200]}")
    if "columns" in anchor and native is not None:
        extra = sorted(set(provider.convert(native)) - set(anchor["columns"]))
        if extra:
            problems.append(f"the transform writes columns the source does not list: {extra}")
    field_map = anchor.get("field_map") or {}
    for field, want in sorted(field_map.items()):
        try:
            got = _mapped_names(field, provider)
        except SigmaError as e:
            got = {f"<refused: {str(e).splitlines()[0][:80]}>"}
        if got != {want}:
            problems.append(f"the pipeline maps {field} to {sorted(got)}, the source shows {want}")
        if "columns" in anchor and want.split(".")[0] not in \
                set(anchor["columns"]) | set(anchor.get("query_columns", [])):
            problems.append(f"field_map {field} -> {want}: {want.split('.')[0]!r} is not a column "
                            "the source lists")
        if field not in (anchor.get("field_map_sources") or {}):
            problems.append(f"field_map {field}: no field_map_sources entry")
    if anchor.get("field_map_complete"):
        exact, prefixes = pipeline_mappings(provider.pipeline())
        for key in sorted(exact):
            if key not in field_map:
                problems.append(f"the pipeline maps {key!r}, and field_map has no entry for it")
        for prefix in sorted(prefixes):
            if not any(f.startswith(prefix) for f in field_map):
                problems.append(f"the pipeline maps the prefix {prefix!r}, and field_map has no "
                                "field under it")
    for pair in anchor.get("pairs", []):
        method, resource = gke_method_and_resource(pair["native"])
        want_resource = pair["resourceName"]
        if method != pair["methodName"] or (want_resource is not None and resource != want_resource):
            problems.append(f"transform gives {method} {resource}, the source shows "
                            f"{pair['methodName']} {want_resource} ({pair['source']})")
        # The mapped objectRef/verb items of the native event must hold on the record.
        o = pair["native"].get("objectRef") or {}
        on_method = {"resource", "subresource"}
        lost = set(pair.get("lost", []))
        sel = {f"objectRef.{k}": v for k, v in o.items() if k != "apiVersion"
               and (want_resource is not None or k in on_method)}
        sel["verb"] = pair["native"]["verb"]
        rec = {"protoPayload": {"serviceName": "k8s.io", "methodName": pair["methodName"]}}
        if want_resource is not None:
            rec["protoPayload"]["resourceName"] = want_resource
        kept = {k: v for k, v in sel.items() if k not in lost}
        if not _verdict(_probe_doc(kept), [flatten_compact(rec)], provider.pipeline()):
            problems.append(f"the mapped objectRef/verb items {sorted(kept)} do not hold on "
                            f"{pair['methodName']} {want_resource} ({pair['source']})")
        for item in sorted(lost):
            if item not in sel:
                problems.append(f"pair 'lost' item {item} is not an item of the native event")
            elif _verdict(_probe_doc({item: sel[item]}), [flatten_compact(rec)],
                          provider.pipeline()):
                problems.append(f"the 'lost' item {item}: {sel[item]!r} holds on "
                                f"{pair['methodName']} {want_resource}, which the source shows "
                                f"without it ({pair['source']})")
    for want, key in ((True, "must_hold"), (False, "must_not_hold")):
        for probe in anchor.get(key, []):
            doc = _probe_doc(probe["selection"])
            shapes = (("native", [sigma_eval.flatten(probe["native"])], None),
                      (provider_name, [flatten_compact(provider.convert(probe["native"]))],
                       provider.pipeline()))
            for label, events, pipe in shapes:
                if _verdict(doc, events, pipe) != want:
                    problems.append(f"{key} probe ({probe['why']}): {probe['selection']} is "
                                    f"{not want} on the {label} shape")
    for probe in anchor.get("known_differences", []):
        doc = _probe_doc(probe["selection"])
        if probe["holds_native"] == probe["holds_provider"]:
            problems.append(f"known_differences probe ({probe['why']}): holds_native and "
                            "holds_provider must differ")
        shapes = (("native", [sigma_eval.flatten(probe["native"])], None, probe["holds_native"]),
                  (provider_name, [flatten_compact(provider.convert(probe["native"]))],
                   provider.pipeline(), probe["holds_provider"]))
        for label, events, pipe, want in shapes:
            if _verdict(doc, events, pipe) != want:
                problems.append(f"known_differences probe ({probe['why']}): "
                                f"{probe['selection']} is {not want} on the {label} shape, "
                                f"the anchor says {want}")
    for exp in anchor.get("rules", []):
        doc = load_rule(os.path.join(SIGMA_DIR, exp["rule"]))
        runs = [{"name": "as recorded", "set": {}, "fires": exp.get("fires"),
                 "blocks": exp.get("blocks") or {}}] + anchor.get("variants", [])
        for variant in runs:
            nat, rec = copy.deepcopy(native), copy.deepcopy(real)
            for p, v in variant.get("set", {}).items():
                _set(nat, p.split("/"), copy.deepcopy(v))
                _set(rec, _map_path(provider_name, p), copy.deepcopy(v))
            shapes = (("native", [sigma_eval.flatten(nat)], None),
                      (provider_name, [flatten_compact(rec)], provider.pipeline()))
            want = variant.get("fires", exp.get("fires"))
            for label, events, pipe in shapes:
                got = _verdict(doc, events, pipe)
                if got != want:
                    problems.append(f"{exp['rule']} [{variant['name']}]: {label} "
                                    f"{'fires' if got else 'quiet'}, the anchor says "
                                    f"{'fires' if want else 'quiet'}")
            for block, want_b in (variant.get("blocks") or {}).items():
                bdoc = _doc_with(doc, {block: doc["detection"][block], "condition": block})
                for label, events, pipe in shapes:
                    got = _verdict(bdoc, events, pipe)
                    if got != want_b:
                        problems.append(f"{exp['rule']} [{variant['name']}] block {block}: "
                                        f"{label} {got}, the anchor says {want_b}")
    return problems


def _map_path(provider_name, native_path):
    """A native Event path (a/b/c) -> the same value's path in the provider record."""
    parts = native_path.split("/")
    if provider_name == "gke":
        heads = {"requestObject": ["protoPayload", "request"],
                 "responseObject": ["protoPayload", "response"], "annotations": ["labels"]}
    else:
        heads = {k: [v] for k, v in AKS_COLUMNS.items()}
    if parts[0] not in heads:
        raise ValueError(f"anchor variant path {native_path!r}: no {provider_name} form")
    return heads[parts[0]] + parts[1:]


def anchor_files(provider_name):
    return sorted(glob.glob(os.path.join(ANCHORS, provider_name, "*.json")))


# ------------------------------------------------------------------ the check
def k8s_audit_rules():
    out = []
    for p in sorted(glob.glob(os.path.join(SIGMA_DIR, "T*", "*.yml"))):
        with open(p, encoding="utf-8") as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d]
        ls = (docs[0] if docs else {}).get("logsource", {})
        if ls.get("product") == "kubernetes" and ls.get("service") == "audit" \
                and os.path.exists(rule_cases.cases_path(p)):
            out.append(p)
    return out


def _loses_positive(report):
    return any(d["kind"] == "positive" and "native fires" in d["diff"]
               for d in report["case_diffs"].values())


def judge(report, provider_name, expected_loss, not_portable):
    """Compare one report with the approvals. Returns (status, problems, approved, unexpected)."""
    rule = report["rule"]
    problems = list(report["errors"])
    gate = PROVIDERS[provider_name].gate
    approved_np = set(not_portable.get((provider_name, rule), ()))
    actual_np = set(report["not_portable"])
    if gate and actual_np != approved_np:
        new, gone = sorted(actual_np - approved_np), sorted(approved_np - actual_np)
        if new:
            problems.append(f"NOT PORTABLE item(s) not approved in NOT_PORTABLE: {new}")
        if gone:
            problems.append(f"stale NOT_PORTABLE entry: item(s) now portable: {gone}")
    allowed = dict(expected_loss.get((provider_name, rule), {}))
    approved, unexpected = {}, {}
    for case, d in sorted(report["case_diffs"].items()):
        entry = allowed.get(case)
        if not gate:
            unexpected[case] = d["diff"]
        elif entry is not None and entry.diff == d["diff"]:
            approved[case] = d["diff"]
            # The reason must hold for this case.
            reason = next((k for k, v in REASONS.items() if v == entry.why), None)
            proofs = report["counterfactual"]
            if reason is None:
                problems.append(f"{case}: an EXPECTED_LOSS reason must be one of "
                                f"{sorted(REASONS)}")
            elif reason == "KEY_ORDER":
                if not d["diff"].startswith("sorted: "):
                    problems.append(f"{d['kind']} {case}: approved as KEY_ORDER, but the "
                                    f"difference is not in the sorted variant only: {d['diff']!r}")
            elif reason not in proofs:
                problems.append(f"{d['kind']} {case}: approved as {reason}, which "
                                f"{provider_name} cannot prove (no counterfactual)")
            elif proofs[reason].get(case, "?") != "":
                problems.append(f"{d['kind']} {case}: approved as {reason}, but the "
                                "difference does not vanish without that one loss (left: "
                                f"{proofs[reason].get(case)!r})")
        elif entry is not None:
            problems.append(f"{d['kind']} {case}: the difference changed: approved "
                            f"{entry.diff!r}, now {d['diff']!r}")
            unexpected[case] = d["diff"]
        else:
            problems.append(f"{d['kind']} {case}: unexpected difference: {d['diff']}")
            unexpected[case] = d["diff"]
    if gate:
        for case in sorted(set(allowed) - set(report["case_diffs"])):
            problems.append(f"stale EXPECTED_LOSS entry: case {case!r} no longer differs")
    if not gate:
        status = "not_portable" if actual_np else "diverges" if report["case_diffs"] else "same"
        problems = []
    elif actual_np:
        status = "not_portable"
    elif problems:
        status = "diverges"
    elif approved:
        status = "expected_loss"
    else:
        status = "same"
    return status, problems, approved, unexpected


def run(rules, providers, expected_loss=None, not_portable=None, check_anchors=True):
    """The whole check. Returns (results dict, [problem strings])."""
    expected_loss = EXPECTED_LOSS if expected_loss is None else expected_loss
    not_portable = NOT_PORTABLE if not_portable is None else not_portable
    results = {"schema": 2,
               "generated_by": "python3 detections/check_provider_mappings.py --write",
               "providers": {}, "rules": {}, "summary": {}, "anchors": {},
               "reads": {k: title for k, (title, _) in READS.items()}}
    problems = []
    # An approval keyed on a provider that does not gate (a typo, or a warning mode)
    # would never be checked: refuse it.
    for (prov, rel) in sorted(set(expected_loss) | set(not_portable)):
        if prov not in PROVIDERS or not PROVIDERS[prov].gate:
            problems.append(f"[{prov}] approval for an unknown or non-gating provider: {rel} "
                            f"(gating providers: {sorted(k for k, v in PROVIDERS.items() if v.gate)})")
    # The query-time columns the AKS model computes must be the ones the converter defines.
    if "aks" in providers and convert_k8s.NOT_BAG != AKS_NOT_BAG:
        problems.append(f"[aks] the harness models the query-time columns {AKS_NOT_BAG}, but "
                        f"convert_k8s.py defines {convert_k8s.NOT_BAG}")
    rels = set()
    reads_lost = {}
    for name in providers:
        p = PROVIDERS[name]
        results["providers"][name] = {
            "title": p.title, "gate": p.gate, "variants": sorted(p.variants),
            "pipeline": {"aks": "detections/pipelines/kubernetes_aks_auditlogs.yml",
                         "gke": "detections/pipelines/k8s_gke.py:gke_cloud_audit"}.get(name)}
        counts = {"same": 0, "expected_loss": 0, "not_portable": 0, "diverges": 0}
        for path in rules:
            report = check_rule(path, name)
            rel = report["rule"]
            REPORTS[(name, rel)] = report
            rels.add(rel)
            reads_lost[rel] = report["reads_lost"]
            status, probs, approved, unexpected = judge(report, name, expected_loss, not_portable)
            counts[status] += 1
            row = results["rules"].setdefault(rel, {
                "list_text_items": report["list_text_items"],
                "loses_positive_without_reads": {k: bool(v)
                                                 for k, v in report["reads_lost"].items()},
                "providers": {}})
            if p.gate:
                row["providers"][name] = {"status": status,
                                          "not_portable": report["not_portable"],
                                          "expected_loss": {c: {"diff": d, "why": _reason_name(
                                              expected_loss, name, rel, c)}
                                              for c, d in approved.items()},
                                          "unexpected": unexpected, "errors": probs}
            else:
                # A warning mode records no per-case text, so that a new case changes the
                # file only when it changes the rule's status.
                row["providers"][name] = {"status": status,
                                          "loses_positive": _loses_positive(report)}
            problems += [f"[{name}] {rel}: {x}" for x in probs]
            yield_line(name, rel, report, status, approved, unexpected, probs)
        results["summary"][name] = counts
        if check_anchors and p.gate:
            for path in anchor_files(name):
                rel = os.path.relpath(path, PIPELINES)
                found = check_anchor(path, name)
                results["anchors"][rel] = "ok" if not found else "failed"
                print(f"[{name}] ANCHOR {'ok    ' if not found else 'FAILED'} {rel}")
                for f in found:
                    print(f"      {f}")
                problems += [f"[{name}] anchor {rel}: {f}" for f in found]
            if not anchor_files(name):
                problems.append(f"[{name}] no anchors in detections/pipelines/anchors/{name}/")
    for key in READS:
        lost = {rel: v[key] for rel, v in sorted(reads_lost.items()) if v[key]}
        results["summary"][key] = {"rules_losing_a_positive": len(lost)}
        for rel, cases in lost.items():
            print(f"[{key}] (warning) {rel} loses positive case(s) without reads: "
                  f"{', '.join(cases)}")
    # Approvals for rules not checked here (a rule renamed or removed) are stale.
    if rules == k8s_audit_rules():
        for (prov, rel) in sorted(set(expected_loss) | set(not_portable)):
            if prov in providers and rel not in rels:
                problems.append(f"[{prov}] stale approval: no such rule with a sidecar: {rel}")
    return results, problems


def _reason_name(expected_loss, provider_name, rel, case):
    why = expected_loss[(provider_name, rel)][case].why
    return next((k for k, v in REASONS.items() if v == why), "?")


VERBOSE = False
REPORTS = {}  # (provider, rule) -> the last run's report (for --propose)


def yield_line(provider_name, rel, report, status, approved, unexpected, problems):
    label = {"same": "SAME", "expected_loss": "EXPECTED LOSS", "not_portable": "NOT PORTABLE",
             "diverges": "DIVERGES"}[status]
    if not PROVIDERS[provider_name].gate and status == "diverges":
        label = "DIVERGES (warning)"
    extra = f"; {len(approved)} approved difference(s)" if approved else ""
    print(f"[{provider_name}] {label:18} {rel} ({report['cases']} cases{extra})")
    reasons = {}
    for atom, why in report["not_portable"].items():
        reasons.setdefault(why, []).append(atom)
    for why, atoms in reasons.items():
        print(f"      not portable: {', '.join(atoms)}: {why}")
    for p in problems:
        print(f"      FAIL {p}")
    if VERBOSE or not PROVIDERS[provider_name].gate:
        shown = list(unexpected.items()) if not VERBOSE else \
            list(approved.items()) + list(unexpected.items())
        for case, diff in shown[: None if VERBOSE else 3]:
            print(f"      {case}: {diff}")
        if not VERBOSE and len(shown) > 3:
            print(f"      ... {len(shown) - 3} more")
        if VERBOSE:
            for case, items in sorted(report["item_diffs"].items()):
                print(f"      item truth differs (warning), {case}: {items}")


def results_text(results):
    return json.dumps(results, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def results_stale(text, path):
    """True when the file at path is not exactly the generated text."""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read() != text
    except FileNotFoundError:
        return True


def summary_line(results, problems):
    parts = []
    for name, c in results["summary"].items():
        if name in READS:
            parts.append(f"{name} (warning only) {c['rules_losing_a_positive']} rule(s) lose a "
                         "positive case")
        elif PROVIDERS[name].gate:
            parts.append(f"{name} {c['same']} same, {c['expected_loss']} with approved losses, "
                         f"{c['not_portable']} not portable, {c['diverges']} diverging")
        else:
            parts.append(f"{name} (warning only) {c['diverges']} of "
                         f"{c['diverges'] + c['same']} rules read a list as its JSON text")
    anchors = results["anchors"]
    if anchors:
        parts.append(f"anchors {sum(v == 'ok' for v in anchors.values())}/{len(anchors)} ok")
    return "; ".join(parts)


def propose(results, reports):
    """Python text for EXPECTED_LOSS / NOT_PORTABLE from this run's differences, with the
    reason this run can prove for each case (or <WHY?> when it proves none). Printing it
    approves nothing: a human reviews it and merges it."""
    lines = ["EXPECTED_LOSS = {"]
    for rel, row in sorted(results["rules"].items()):
        for name, r in sorted(row["providers"].items()):
            if not PROVIDERS[name].gate:
                continue
            diffs = {**{c: e["diff"] for c, e in r["expected_loss"].items()}, **r["unexpected"]}
            if not diffs:
                continue
            counter = reports[(name, rel)]["counterfactual"]
            lines.append(f'    ("{name}", "{rel}"): {{')
            for c, d in sorted(diffs.items()):
                proven = [reason for reason, cases in sorted(counter.items())
                          if cases.get(c) == ""]
                why = proven[0] if proven else "KEY_ORDER" if d.startswith("sorted: ") \
                    else "<WHY?>"
                lines.append(f'        "{c}": ExpectedLoss(\n            {why}, "{d}"),')
            lines.append("    },")
    lines += ["}", "", "NOT_PORTABLE = {"]
    for rel, row in sorted(results["rules"].items()):
        for name, r in sorted(row["providers"].items()):
            if PROVIDERS[name].gate and r["not_portable"]:
                atoms = "".join(f'\n        "{a}",' for a in sorted(r["not_portable"]))
                lines.append(f'    ("{name}", "{rel}"): ({atoms}\n    ),')
    lines.append("}")
    return "\n".join(lines)


def approvals_table(reports, expected_loss=None, not_portable=None):
    """Every approval as Markdown, for a pull request: one row per EXPECTED_LOSS case (its
    case kind, reason and difference; "drops a positive" when a positive case fires
    natively and not on the provider) and one row per NOT_PORTABLE rule."""
    expected_loss = EXPECTED_LOSS if expected_loss is None else expected_loss
    not_portable = NOT_PORTABLE if not_portable is None else not_portable
    lines = ["| Provider | Rule | Case | Kind | Reason | Difference | Drops a positive |",
             "|---|---|---|---|---|---|---|"]
    for (prov, rel), cases in sorted(expected_loss.items()):
        report = reports.get((prov, rel)) or {"case_diffs": {}}
        for case, entry in sorted(cases.items()):
            kind = report["case_diffs"].get(case, {}).get("kind", "?")
            reason = next((k for k, v in REASONS.items() if v == entry.why), "?")
            drops = "yes" if kind == "positive" and "native fires" in entry.diff else ""
            lines.append(f"| {prov} | `{rel}` | `{case}` | {kind} | {reason} | {entry.diff} | "
                         f"{drops} |")
    lines += ["", "| Provider | Rule | NOT PORTABLE items | Reason |", "|---|---|---|---|"]
    for (prov, rel), atoms in sorted(not_portable.items()):
        report = reports.get((prov, rel)) or {"not_portable": {}}
        whys = sorted({report["not_portable"].get(a, "?") for a in atoms})
        lines.append(f"| {prov} | `{rel}` | {', '.join(f'`{a}`' for a in atoms)} | "
                     f"{'; '.join(whys)} |")
    return "\n".join(lines)


def main(argv=None):
    global VERBOSE
    ap = argparse.ArgumentParser(description="Prove the managed-cluster field mappings.")
    ap.add_argument("rules", nargs="*", help="rule files (default: every Kubernetes audit rule "
                    "with a sidecar)")
    ap.add_argument("--provider", action="append", choices=sorted(PROVIDERS))
    ap.add_argument("--check", action="store_true",
                    help="also fail when detections/pipelines/mapping_results.json is stale")
    ap.add_argument("--write", action="store_true", help="rewrite mapping_results.json")
    ap.add_argument("--propose", action="store_true",
                    help="print EXPECTED_LOSS / NOT_PORTABLE text for this run (review it)")
    ap.add_argument("--approvals-table", action="store_true",
                    help="print every EXPECTED_LOSS / NOT_PORTABLE approval as Markdown")
    ap.add_argument("--self-test", action="store_true", help="planted errors must be caught")
    ap.add_argument("--require-re2", action="store_true",
                    help="fail unless google-re2 is installed (the regex lint then uses RE2)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    VERBOSE = args.verbose
    if args.require_re2 and _re2 is None:
        print("google-re2 is not installed (pip install google-re2==1.1.20251105)")
        return 2
    if args.self_test:
        return self_test()
    full = not args.rules and not args.provider
    if (args.check or args.write) and not full:
        ap.error("--check and --write need the full run (no rules, no --provider)")
    rules = [os.path.abspath(r) for r in args.rules] or k8s_audit_rules()
    providers = args.provider or list(PROVIDERS)
    results, problems = run(rules, providers)
    if args.propose:
        print(propose(results, REPORTS))
    if args.approvals_table:
        print(approvals_table(REPORTS))
    text = results_text(results)
    if args.write:
        with open(RESULTS, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {os.path.relpath(RESULTS, REPO)}")
    elif args.check and results_stale(text, RESULTS):
        problems.append(f"{os.path.relpath(RESULTS, REPO)} is stale: run "
                        "python3 detections/check_provider_mappings.py --write and commit it")
    print()
    print(summary_line(results, problems))
    if problems:
        print(f"FAILED: {len(problems)} problem(s).")
        for p in problems:
            print(f"  {p}")
        return 1
    print("OK: every mapped rule keeps its verdicts and block truth on every case, or the "
          "difference is approved.")
    return 0


# ------------------------------------------------------------------ self-test
class _Swap:
    """Temporarily replace attributes of modules / entries of dicts (restored on exit)."""

    def __init__(self, *swaps):
        self.swaps, self.saved = swaps, []

    def __enter__(self):
        for target, key, value in self.swaps:
            if isinstance(target, dict):
                self.saved.append((target, key, target[key]))
                target[key] = value
            else:
                self.saved.append((target, key, getattr(target, key)))
                setattr(target, key, value)

    def __exit__(self, *exc):
        for target, key, value in reversed(self.saved):
            if isinstance(target, dict):
                target[key] = value
            else:
                setattr(target, key, value)


def _aks_yaml_pipeline(*edits):
    with open(os.path.join(PIPELINES, "kubernetes_aks_auditlogs.yml"), encoding="utf-8") as fh:
        text = fh.read()
    for old, new in edits:
        if old not in text:
            raise AssertionError(f"self-test: {old!r} not in the AKS pipeline")
        text = text.replace(old, new)
    return lambda: ProcessingPipeline.from_yaml(text)


def self_test():
    import io
    from contextlib import redirect_stdout

    def rule(rel):
        return os.path.join(SIGMA_DIR, rel)

    subset = [rule(r) for r in ("T1609/k8s_pod_exec_attach.yml", "T1609/k8s_node_proxy_exec.yml",
                                "T1098.006/k8s_rbac_privileged_grant.yml",
                                "T1565.001/k8s_coredns_configmap_modified.yml",
                                "T1611/k8s_podspec_host_access.yml")]
    exec_rel = "T1609/k8s_pod_exec_attach.yml"
    first_exec_case = rule_cases.load_cases(rule_cases.cases_path(rule(exec_rel)))[0][0]["name"]
    grant_key = next(k for k in EXPECTED_LOSS if k[0] == "gke" and "rbac_privileged" in k[1])
    some_case = next(c for c, e in sorted(EXPECTED_LOSS[grant_key].items())
                     if e.why == GKE_JSON_PATCH)
    entry = EXPECTED_LOSS[grant_key][some_case]
    changed = dict(EXPECTED_LOSS)
    changed[grant_key] = {**EXPECTED_LOSS[grant_key],
                          some_case: ExpectedLoss(entry.why, entry.diff + ", sel_invented")}
    wrong_reason = dict(EXPECTED_LOSS)
    wrong_reason[grant_key] = {**EXPECTED_LOSS[grant_key],
                               some_case: ExpectedLoss(KEY_ORDER, entry.diff)}
    stale = dict(EXPECTED_LOSS)
    stale[("aks", exec_rel)] = {first_exec_case: ExpectedLoss(GKE_JSON_PATCH,
                                                              "all: native fires, aks quiet")}
    no_np = {k: v for k, v in NOT_PORTABLE.items()
             if k != ("gke", "T1609/k8s_node_proxy_exec.yml")}
    real_regexes = k8s_gke._regexes
    real_method = gke_method_and_resource
    real_created_name = gke_created_name

    def subresource_from_verb(field, v):
        return [r"\." + v + "$"] if field == "objectRef.subresource" else real_regexes(field, v)

    def drop_subresource(ev, **kw):
        e = copy.deepcopy(ev)
        (e.get("objectRef") or {}).pop("subresource", None)
        method, _ = real_method(e, **kw)
        return method, real_method(ev, **kw)[1]

    seg, label = k8s_gke.SEG, k8s_gke.LABEL

    def regex_mutant(field, make):
        def mutated(f, v):
            return make(v, real_regexes(f, v)) if f == field else real_regexes(f, v)
        return [(k8s_gke, "_regexes", mutated)]

    def name_cluster_any_third(v, out):
        out = list(out)
        out[1] = "^" + seg + "/" + seg + "/" + seg + "/" + v + "(/.*)?$"
        return out

    gke = PROVIDERS["gke"]

    def gke_with_typo():
        p = k8s_gke.gke_cloud_audit()
        for item in p.items:
            if item.identifier == "gke_fields":
                item.transformation.mapping["user.username"] = \
                    "protoPayload.authenticationInfo.principalMail"
        return p

    mutants = [
        ("M1 GKE subresource read from the verb position", ["gke"], {},
         [(k8s_gke, "_regexes", subresource_from_verb)], "unexpected difference"),
        ("M2a AKS maps to a column the table does not have (Objectref)", ["aks"], {},
         [(PROVIDERS, "aks", PROVIDERS["aks"]._replace(pipeline=_aks_yaml_pipeline(
             ("      objectRef.: ObjectRef.", "      objectRef.: Objectref."))))],
         "not approved in NOT_PORTABLE"),
        ("M2b ... and its column list says the same (only the letter case differs)", ["aks"],
         {}, [(PROVIDERS, "aks", PROVIDERS["aks"]._replace(pipeline=_aks_yaml_pipeline(
             ("      objectRef.: ObjectRef.", "      objectRef.: Objectref."),
             ("'^(ObjectRef|User|", "'^(Objectref|User|"))))],
         "differs only in letter case"),
        ("M3 GKE transform drops the subresource from methodName", ["gke"], {},
         [(sys.modules[__name__], "gke_method_and_resource", drop_subresource)],
         "unexpected difference"),
        ("M4 AKS requestURI mapped to the UserAgent column", ["aks"], {},
         [(PROVIDERS, "aks", PROVIDERS["aks"]._replace(pipeline=_aks_yaml_pipeline(
             ("      requestURI: RequestUri", "      requestURI: UserAgent"))))],
         "unexpected difference"),
        ("M5 GKE writes a non-portable regex (bare - in a class)", ["gke"], {},
         [(k8s_gke, "METHOD_PREFIX", k8s_gke.METHOD_PREFIX.replace(r"[a-z0-9\-]", "[a-z0-9-]"))],
         "generated regex"),
        ("M6 a stale EXPECTED_LOSS entry", ["aks"], {"expected_loss": stale}, [],
         "stale EXPECTED_LOSS"),
        ("M7 an approved difference that changed", ["gke"], {"expected_loss": changed}, [],
         "the difference changed"),
        ("M7b an approved difference with a reason that does not hold", ["gke"],
         {"expected_loss": wrong_reason}, [], "approved as KEY_ORDER"),
        ("M8 a NOT PORTABLE rule with no NOT_PORTABLE entry", ["gke"],
         {"not_portable": no_np}, [], "not approved in NOT_PORTABLE"),
        ("M9 GKE group labels not reversed (anchor transform)", ["gke"], {"check_anchors": True},
         [(k8s_gke, "gke_group", lambda g: "core" if not g else g.replace(".k8s.io", ""))],
         "transform"),
        ("M10 GKE user.username mapped to a misspelled field", ["gke"], {},
         [(PROVIDERS, "gke", gke._replace(pipeline=gke_with_typo))], "no transformed one carries"),
        # M12 holds the KQL model of a dynamic value: an object column is not null and
        # reads as its JSON text. Without that model this mutant is not caught.
        ("M12 AKS whole-body items read the RequestObject column (an object is not null "
         "there, and its text matches)", ["aks"], {},
         [(PROVIDERS, "aks", PROVIDERS["aks"]._replace(pipeline=_aks_yaml_pipeline(
             ("      requestObject: RequestObjectNotBag", "      requestObject: RequestObject"))))],
         "unexpected difference"),
        ("M13 AKS level and stage swapped in the pipeline AND in the transform's column list",
         ["aks"], {"check_anchors": True},
         [(PROVIDERS, "aks", PROVIDERS["aks"]._replace(pipeline=_aks_yaml_pipeline(
             ("      level: Level", "      level: Stage"),
             ("      stage: Stage", "      stage: Level")))),
          (AKS_COLUMNS, "level", "Stage"), (AKS_COLUMNS, "stage", "Level")],
         "the pipeline maps level"),
        ("M14 GKE namespace regex is a prefix match", ["gke"], {"check_anchors": True},
         regex_mutant("objectRef.namespace",
                      lambda v, out: ["^" + seg + "/" + seg + "/namespaces/" + v]),
         "must_not_hold probe"),
        ("M15 GKE name regex: the cluster-scoped branch accepts 'namespaces'", ["gke"],
         {"check_anchors": True}, regex_mutant("objectRef.name", name_cluster_any_third),
         "must_not_hold probe"),
        ("M16 GKE verb regex not anchored at the end", ["gke"], {"check_anchors": True},
         regex_mutant("verb", lambda v, out: [r"\." + v]), "must_not_hold probe"),
        ("M17 GKE resource regex accepts the subresource label", ["gke"], {"check_anchors": True},
         regex_mutant("objectRef.resource", lambda v, out: [
             k8s_gke.METHOD_PREFIX + "(" + label + r"\.)?" + v + r"(\." + label + r")?\.[a-z]+$"]),
         "must_not_hold probe"),
        ("M18 GKE subresource regex matches any inner label", ["gke"], {"check_anchors": True},
         regex_mutant("objectRef.subresource", lambda v, out: [r"\." + v + r"\."]),
         "must_not_hold probe"),
        ("M19 an approval keyed on an unknown provider", ["gke"],
         {"expected_loss": {**EXPECTED_LOSS, ("gek", exec_rel): {
             first_exec_case: ExpectedLoss(KEY_ORDER, "sorted: x")}}},
         [], "unknown or non-gating provider"),
        ("M20 GKE takes a create's name from objectRef.name (not the response)", ["gke"],
         {"check_anchors": True},
         [(sys.modules[__name__], "gke_created_name",
           lambda ev: (ev.get("objectRef") or {}).get("name"))], "anchor"),
        # The AKS KQL converter cannot write an annotation key with a '/' when it does not
        # know that `annotations` is a map: the rule is CANNOT CONVERT there, and the
        # harness must say so (it reads annotation keys of a pod template).
        ("M21 the AKS converter does not know the annotations map (MAP_PARENTS)", ["aks"],
         {"rules": [rule("T1611/k8s_podspec_confinement_disabled.yml")]},
         [(convert_k8s, "MAP_PARENTS", convert_k8s.MAP_PARENTS - {"annotations"})],
         "CANNOT CONVERT"),
        ("M22 GKE drops the name of a successful namespace create (the known difference "
         "of objectRef.namespace changes)", ["gke"], {"check_anchors": True},
         [(sys.modules[__name__], "gke_created_name",
           lambda ev: None if (ev.get("objectRef") or {}).get("resource") == "namespaces"
           else real_created_name(ev))], "known_differences probe"),
    ]
    failures = 0
    with redirect_stdout(io.StringIO()):
        _, base = run(subset, ["aks", "gke"])
    print(f"{'ok  ' if not base else 'FAIL'}  baseline: {len(base)} problem(s) on the "
          f"{len(subset)}-rule subset with the real pipelines and approvals")
    failures += bool(base)
    for name, providers, kwargs, swaps, pattern in mutants:
        kw = {"check_anchors": False, **kwargs}
        rules = kw.pop("rules", subset)
        with _Swap(*swaps), redirect_stdout(io.StringIO()):
            _, problems = run(rules, providers, **kw)
        hit = [p for p in problems if pattern in p]
        ok = bool(hit)
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {name}: "
              + (f"caught ({len(problems)} problem(s)), e.g. {hit[0][:160]}" if ok
                 else f"NOT caught (problems: {problems[:2]})"))
    # M11: --check fails on a results file that is not what the run generates.
    import tempfile
    with redirect_stdout(io.StringIO()):
        results, _ = run(subset[:1], ["aks"], check_anchors=False)
    text = results_text(results)
    edited = json.loads(text)
    edited["summary"]["aks"]["same"] += 1
    with tempfile.TemporaryDirectory() as tmp:
        good, bad = os.path.join(tmp, "good.json"), os.path.join(tmp, "bad.json")
        for path, body in ((good, text), (bad, results_text(edited))):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        ok = results_stale(text, bad) and not results_stale(text, good) \
            and results_stale(text, os.path.join(tmp, "missing.json"))
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  M11 --check: a hand-edited or missing results file is "
          "stale, the generated one is not")
    print()
    if failures:
        print(f"SELF-TEST FAILED: {failures} check(s)")
        return 1
    print("SELF-TEST OK: every planted error is caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
