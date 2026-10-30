#!/usr/bin/env python3
"""
Write the generated blocks of detections/k8s/PLATFORMS.md (offline, deterministic).

PLATFORMS.md says which Kubernetes audit rule works on which platform and log shape,
and why. Its hand-written parts (how to read it, the sourced platform summary, the
managed principals, the open questions) stay as they are. This script rewrites only
the text between these marker pairs:

  <!-- platform-coverage:begin --> ... <!-- platform-coverage:end -->
      one row per rule, one cell per platform log shape, and one row per policy
  <!-- platform-pairs:begin --> ... <!-- platform-pairs:end -->
      each grader's positive cases, replayed through its chokepoint rule under each
      policy and each replayed store (the replays below)
  <!-- platform-needs:begin --> ... <!-- platform-needs:end -->
      what each rule needs from the audit policy (rules[<rule>].needs)
  <!-- platform-fp:begin --> ... <!-- platform-fp:end -->
      the negative cases that start to fire on a platform (a false positive there)
  <!-- platform-recommended:begin --> ... <!-- platform-recommended:end -->
      the recommended policy, when policy_coverage.json has a policy with id
      'recommended'

Inputs (read only):
  detections/k8s/policy_coverage.json      schema "det-eng/k8s-policy-coverage/v1"
      (the docstring of detections/k8s_policy_coverage.py documents it); the policy
      simulator's result, per rule and policy. Optional keys that this script reads
      when they are there: rules[<rule>].needs and policies[<id>].opt_in_losses.
  detections/pipelines/mapping_results.json   schema 2 (documented in
      detections/pipelines/README.md, section mapping_results.json); the mapping
      harness's result, per rule and provider shape.
  detections/sigma/<rule>.cases.jsonl      the sidecar of each rule, for the case kinds
      and the verbs of the positive cases. Its SHA-256 must be the cases_sha256 that
      policy_coverage.json records, so the three inputs describe the same cases.
  The store replay (--write and --check; needs pySigma): a column whose store keeps no
      reads that its policy logs (store_columns(): GKE with Data Access logs off, on
      the gce-kube-up policy) is a replayed store. Every case of every rule goes
      through k8s_policy_coverage.run_rule(), the function that makes
      policy_coverage.json, under that policy with a log filter that drops the store's
      read verbs: the way the simulator models the AKS kube-audit-admin category. The
      result has the shape of rules[<rule>].results[<policy>], and the column reads it
      in place of the policy's result. A policy whose own log filter is the store's
      (aks-kube-audit-admin) is not replayed again.
  The chokepoint replay (--write and --check; needs pySigma): for each grader in
      GRADERS, the grader's positive cases go through k8s_policy_coverage.py's
      records_under() under every policy of policy_order (with its log filter) and
      every replayed store, and the chokepoint rule (sigma_eval, the validators'
      backend) runs on the records. The result is the list of grader positives that
      the chokepoint misses, per policy and replayed store.
  Both replays load each policy from the files that policy_coverage.json lists
      (policies[<id>].files); each file must have the SHA-256 recorded there.

A schema string that this script does not know, a rule that one input has and the
other does not, a stale sidecar or policy-file digest, a mapping that diverges or whose status
disagrees with its fields, an unknown status or reason, a rule with no positive case,
or a missing or malformed field stops the run with exit code 2: the generated text
would be wrong, so no text is written.

One cell combines the two results for one rule and one platform log shape (SHAPES):
  - the policy result: the positive cases that still fire under the platform's
    policy (results[<policy>].positives), with the reason of each lost case, the
    negative cases that fire and the not-modeled events;
  - a store that keeps no reads: on the AKSAuditAdmin shapes the policy column
    aks-kube-audit-admin already drops get and list; on GKE with Data Access logs off
    the store replay drops get, list and watch. Every count of the cell (positives,
    not-modeled, fp) is then the store's. A case that the store leaves without a
    record, and that the policy alone does not, is relabelled "reads-dropped" (the
    base is the sibling policy, the same files without the log filter, or the
    replayed store's policy). The script checks that every positive case whose
    every event is a read verb of the store is lost there, and that the set of such
    cases agrees with loses_positive_without_reads in mapping_results.json;
  - the mapping result for that shape (mapping_results.rules[<rule>].providers):
    "native" shapes keep the Event (no mapping); for AKSAudit and AKSAuditAdmin the
    "aks" result, for GKE the "gke" result. A NOT_PORTABLE rule cannot be converted
    for that shape. A positive case in an approved EXPECTED_LOSS entry whose diff
    says "native fires, <provider> quiet" is lost there.
The lost sets are joined: a positive case counts once. The two checks run apart (the
mapping harness reads the case records as recorded, not as the policy keeps them),
so a cell is the union of two losses, not one replay.

Support words (one per cell):
  full                every positive case fires on that shape (a remaining approved
                      difference that drops no positive case shows as a code);
  partial             some positive cases fire, some do not;
  chokepoint only     the rule is a grader (GRADERS) that fires no positive case, its
                      chokepoint rule's own cell on the same shape is "full", and the
                      replay shows the chokepoint firing on every positive case of the
                      grader under that policy and store;
  chokepoint partial  as "chokepoint only", but the chokepoint fires on some of the
                      grader's positive cases, not all;
  blind               no positive case fires (and no chokepoint covers them);
  not portable        the shape's pipeline cannot express the rule (NOT_PORTABLE), and
                      the policy and the store keep at least one positive case; the
                      bracket gives the positive cases that they keep. When they keep
                      none, the word is "blind" and the missing field is a code.

Reason codes (after the count; a number is a count of positive cases unless noted):
  no-record n #i   every record of the case is dropped; #i is the 0-based index of the
                   policy rule that decided it (level None, an omitted stage), "#-"
                   when no rule matched (level None by default);
  body-removed n   the record is kept at a lower level, so the body the rule reads is
                   gone;
  opt-in n         a loss that the policy names in opt_in_losses (it needs a line of
                   the policy that is commented out);
  reads-dropped n  the store keeps no reads (AKSAuditAdmin: get, list; GKE without Data
                   Access logs: get, list, watch);
  approved-loss n  an approved EXPECTED_LOSS entry drops the case on that shape (in
                   every variant of the JSON text);
  approved-loss-if-<variant> n   the same, but only in that variant of the JSON text
                   (KEY_ORDER: "sorted", a store that sorts object keys); the case
                   counts as lost;
  approved-diff n  approved EXPECTED_LOSS entries that change a block but no case
                   verdict (n cases of any kind);
  partial-record n, other n   as the simulator reports them;
  not-in-schema: f the field f is not in the provider's schema (NOT_PORTABLE);
  not-modeled n    n events (any case kind) that the policy and the store log with a
                   body the case record lacks, and the rule reads it: those cases are
                   not proven on that shape;
  fp n             n negative cases fire on that shape: under the policy and the store,
                   or by an approved mapping difference (see the false-positive block);
  chokepoint k/n   (graders) the chokepoint fires on k of the grader's n positive cases
                   on that shape;
  chokepoint not full (w)   (graders) the chokepoint's own cell on that shape is w, so
                   it does not cover the grader there.

Usage:
    python3 detections/k8s_platforms_md.py --write       # rewrite the blocks
    python3 detections/k8s_platforms_md.py --check       # exit 1 if a block is stale
    python3 detections/k8s_platforms_md.py --anchors     # exit 1 on a bad anchor
    python3 detections/k8s_platforms_md.py --self-test   # constructed inputs
    Options for constructed inputs: --policy-coverage PATH --mapping-results PATH
    --doc PATH --sigma DIR.

--write and --check need pySigma (detections/requirements.txt) for the replay;
--anchors and --self-test need only the standard library (the self-test also runs a
replay on constructed rules when pySigma is there). Exit codes: 0 OK, 1 a stale block
or a bad anchor, 2 bad inputs.

--anchors checks, in every Markdown file of the repository (as
.github/scripts/check_md_links.py walks them), each link to PLATFORMS.md that has an
anchor (#...): inline links (with or without a title), reference definitions, and
paths from the repository root ("/detections/..."), outside code. The anchor must be a
heading of PLATFORMS.md (GitHub's slugs, or an <a id>/<a name> tag). It also checks
the in-page links of PLATFORMS.md, and each link from PLATFORMS.md to another
Markdown file with an anchor. check_md_links.py checks the paths only. CI runs it in
the markdown-links job, which runs on every pull request.

Run --write after k8s_policy_coverage.py --update and check_provider_mappings.py
--write.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from urllib.parse import unquote

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DOC = os.path.join(HERE, "k8s", "PLATFORMS.md")
DOC_DIR_REL = "detections/k8s"
POLICY_COVERAGE = os.path.join(HERE, "k8s", "policy_coverage.json")
MAPPING_RESULTS = os.path.join(HERE, "pipelines", "mapping_results.json")
SIGMA = os.path.join(HERE, "sigma")

PC_SCHEMAS = ("det-eng/k8s-policy-coverage/v1",)
MR_SCHEMAS = (2,)
BLOCKS = ("platform-coverage", "platform-pairs", "platform-needs", "platform-fp",
          "platform-recommended")
LEVELS = ("None", "Metadata", "Request", "RequestResponse")
LOST_REASONS = ("no-record", "body-removed", "partial-record", "other")
FIRING_REASONS = ("no-record", "body-removed", "partial-record", "request-received",
                  "other")
MAPPING_STATUS = ("same", "expected_loss", "not_portable", "diverges")
CASE_KINDS = ("positive", "near-miss", "filtered", "confounder", "benign")
RECOMMENDED = "recommended"
WORDS = ("full", "partial", "chokepoint only", "chokepoint partial", "blind",
         "not portable")
# The order of the loss codes in a cell; "approved-loss-if-<variant>" follows
# "approved-loss".
CODE_ORDER = ("no-record", "body-removed", "opt-in", "reads-dropped", "approved-loss",
              "approved-loss-if-", "partial-record", "other")
SUMMARY_KEYS = ("rules", "rules_all_positives", "rules_some_positives", "rules_blind",
                "positives", "positives_firing", "negatives_firing", "not_modeled_reads")

# Stores that keep no reads: the verbs whose events they do not hold. The keys and
# verbs are the READS table of check_provider_mappings.py; the run checks that the
# "reads" text of mapping_results.json names each verb.
READ_VERBS = {"aksauditadmin": ("get", "list"),
              "gke_admin_activity": ("get", "list", "watch")}

# One column per platform log shape: (id, header, policy id or None for the rule's
# home lab policy, mapping provider or "native", store without reads or None).
SHAPES = [
    ("lab", "kind lab (home policy)", None, "native", None),
    ("eks", "EKS (CloudWatch)", "eks", "native", None),
    ("gke", "GKE, Data Access on", "gce-kube-up", "gke", None),
    ("gke-admin", "GKE, Admin Activity only", "gce-kube-up", "gke", "gke_admin_activity"),
    ("aks", "AKS AKSAudit", "aks-kube-audit", "aks", None),
    ("aks-admin", "AKS AKSAuditAdmin", "aks-kube-audit-admin", "aks", "aksauditadmin"),
    ("aks-raw", "AKS raw Event, kube-audit", "aks-kube-audit", "native", None),
    ("aks-raw-admin", "AKS raw Event, kube-audit-admin", "aks-kube-audit-admin", "native",
     "aksauditadmin"),
    ("os-default", "OpenShift 4.18+ Default", "openshift-default", "native", None),
    ("os-wrb", "OpenShift 4.18+ WriteRequestBodies", "openshift-wrb", "native", None),
    ("os-default-4.17", "OpenShift 4.17 Default", "openshift-default-4.17", "native", None),
    ("os-wrb-4.17", "OpenShift 4.17 WriteRequestBodies", "openshift-wrb-4.17", "native",
     None),
    ("k3s", "k3s starter policy", "k3s-starter", "native", None),
]
SHAPE_NOTES = {
    "lab": "The lab policy of the validator whose MANIFEST registers the rule (proven "
           "live in CI)",
    "eks": "The EKS Best Practices Guide policy; each CloudWatch message is the native "
           "Event, so no mapping",
    "gke": "The GCE kube-up policy (the GKE audit-policy page names its script; whether "
           "GKE runs it is unverified) and the GKE mapping",
    "gke-admin": "As the GKE column, without get, list and watch events (Data Access logs "
                 "off): the store replay runs every case under the gce-kube-up policy "
                 "with a filter that drops those verbs, so every count is the store's",
    "aks": "The AKS policy, kube-audit category, and the AKSAudit mapping",
    "aks-admin": "The AKS policy, kube-audit-admin category (no get and list), and the "
                 "AKSAudit mapping (AKSAuditAdmin has the same columns)",
    "aks-raw": "The AKS policy, kube-audit category, stored as the native Event "
               "(AzureDiagnostics log_s, or the Event Hub or storage export's "
               "properties.log), so no mapping",
    "aks-raw-admin": "As the raw kube-audit column, kube-audit-admin category (no get and "
                     "list)",
}

# Grader -> its Metadata-level chokepoint, as each TRR's Detection Strategy names them:
# TRR9004 Strategy 1 (k8s_rbac_write) under the graders; TRR9008 Strategies 1 and 2;
# TRR9025 Strategies 1 to 4 (the Procedure D grader rides on the TRR9008 chokepoint);
# TRR9027 Strategies 1 and 2. The replay runs each grader's positive cases through its
# chokepoint under every policy.
GRADERS = {
    "T1098.006/k8s_rbac_privileged_grant.yml": "T1098.006/k8s_rbac_write.yml",
    "T1098.006/k8s_rbac_sensitive_permission_grant.yml": "T1098.006/k8s_rbac_write.yml",
    "T1685/k8s_admission_webhook_neutered.yml": "T1685/k8s_admission_webhook_disabled.yml",
    "T1546/k8s_admission_webhook_repointed_to_url.yml":
        "T1685/k8s_admission_webhook_disabled.yml",
    "T1546/k8s_malicious_admission_webhook_created.yml":
        "T1546/k8s_admission_webhook_created.yml",
    "T1565.001/k8s_coredns_corefile_poisoned.yml":
        "T1565.001/k8s_coredns_configmap_modified.yml",
}

GENERATED = ("<!-- Generated by detections/k8s_platforms_md.py --write. Do not edit by "
             "hand. -->")
LOSS_RE = re.compile(r"native fires, \w+ quiet")
FP_RE = re.compile(r"native quiet, \w+ fires")
_TITLE = r"""(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\)))?"""
INLINE_LINK_RE = re.compile(r"\]\(\s*(<[^>\n]*>|[^)\s]+)" + _TITLE + r"\s*\)")
REF_DEF_RE = re.compile(r"^ {0,3}\[[^\]\n]+\]:[ \t]*(<[^>\n]*>|\S+)" + _TITLE + r"[ \t]*$",
                        re.M)
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
SCHEME_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)")
HTML_ANCHOR_RE = re.compile(r"""<a\s+[^>]*?\b(?:id|name)\s*=\s*["']([^"']+)["']""", re.I)


class InputError(ValueError):
    """The inputs are wrong or disagree; no text is written."""


# ------------------------------------------------------------------ inputs
def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def load_cases(sigma_dir, rules, pc):
    """{rule: [case dict]} from each sidecar; the digest must match policy_coverage."""
    out = {}
    for rule in rules:
        path = os.path.join(sigma_dir, rule[:-len(".yml")] + ".cases.jsonl")
        if not os.path.isfile(path):
            raise InputError(f"{rule}: no sidecar at {os.path.relpath(path, REPO)}")
        want = pc["rules"][rule].get("cases_sha256")
        got = sha256_file(path)
        if want != got:
            raise InputError(f"{rule}: the sidecar's SHA-256 is {got}, policy_coverage.json "
                             f"records {want}: run python3 detections/k8s_policy_coverage.py "
                             "--update first")
        cases = []
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if line.strip():
                    try:
                        cases.append(json.loads(line))
                    except ValueError as exc:
                        raise InputError(f"{path}:{n}: {exc}") from exc
        out[rule] = cases
    return out


def _need(cond, msg):
    if not cond:
        raise InputError(msg)


def _keys(obj, keys, where):
    _need(isinstance(obj, dict), f"{where} must be an object")
    missing = [k for k in keys if k not in obj]
    _need(not missing, f"{where} has no {', '.join(missing)}")


def validate_needs(rule, needs):
    _need(isinstance(needs, dict), f"{rule}: needs must be an object")
    _need(set(needs) == {"level", "requests", "note"},
          f"{rule}: needs keys must be level, requests, note (got {sorted(needs)})")
    _need(needs["level"] is None or needs["level"] in LEVELS,
          f"{rule}: needs.level {needs['level']!r} is not a level or null")
    _need(needs["note"] is None or isinstance(needs["note"], str),
          f"{rule}: needs.note must be a string or null")
    reqs = needs["requests"]
    _need(isinstance(reqs, list), f"{rule}: needs.requests must be a list")
    keys = []
    for r in reqs:
        _need(isinstance(r, dict) and set(r) == {"group", "resource", "subresource", "verbs"},
              f"{rule}: each needs.requests entry has group, resource, subresource, verbs")
        _need(isinstance(r["group"], str) and isinstance(r["resource"], str),
              f"{rule}: needs.requests group and resource must be strings")
        _need(r["subresource"] is None or isinstance(r["subresource"], str),
              f"{rule}: needs.requests subresource must be a string or null")
        v = r["verbs"]
        _need(isinstance(v, list) and all(isinstance(x, str) for x in v)
              and v == sorted(set(v)),
              f"{rule}: needs.requests verbs must be a sorted list of unique strings")
        keys.append(json.dumps(r, sort_keys=True))
    # Unique; the producer's sort order is not checked (this page sorts them itself).
    _need(len(keys) == len(set(keys)), f"{rule}: needs.requests must be unique")


def validate_mapping(rule, mrule, names):
    """The fields of mapping_results.rules[<rule>] that the cells read."""
    where = f"mapping_results.json rules[{rule!r}]"
    _keys(mrule, ("list_text_items", "loses_positive_without_reads", "providers"), where)
    _need(isinstance(mrule["list_text_items"], list), f"{where}.list_text_items must be a list")
    lpw = mrule["loses_positive_without_reads"]
    _keys(lpw, sorted(READ_VERBS), f"{where}.loses_positive_without_reads")
    _need(all(isinstance(lpw[k], bool) for k in READ_VERBS),
          f"{where}.loses_positive_without_reads values must be true or false")
    _keys(mrule["providers"], ("aks", "gke"), f"{where}.providers")
    for prov in ("aks", "gke"):
        m, w = mrule["providers"][prov], f"{where}.providers.{prov}"
        _keys(m, ("status", "not_portable", "expected_loss", "unexpected", "errors"), w)
        _need(m["status"] in MAPPING_STATUS, f"{rule} / {prov}: unknown status {m['status']!r}")
        _need(isinstance(m["not_portable"], dict) and isinstance(m["expected_loss"], dict)
              and isinstance(m["unexpected"], dict) and isinstance(m["errors"], list),
              f"{w}: not_portable, expected_loss and unexpected must be objects, errors a "
              "list")
        _need(m["status"] != "diverges" and not m["unexpected"] and not m["errors"],
              f"{rule} / {prov}: the mapping diverges or has errors; fix it first "
              "(python3 detections/check_provider_mappings.py --check)")
        # The harness's precedence (judge()): not_portable, diverges, expected_loss, same.
        _need((m["status"] == "not_portable") == bool(m["not_portable"]),
              f"{rule} / {prov}: status {m['status']!r} disagrees with not_portable "
              f"{sorted(m['not_portable'])} (run check_provider_mappings.py --check)")
        _need(m["status"] != "expected_loss" or m["expected_loss"],
              f"{rule} / {prov}: status 'expected_loss' with no expected_loss entry")
        _need(m["status"] != "same" or not m["expected_loss"],
              f"{rule} / {prov}: status 'same' with expected_loss entries "
              f"{sorted(m['expected_loss'])}")
        for case, e in m["expected_loss"].items():
            _need(case in names, f"{rule} / {prov}: EXPECTED_LOSS case {case!r} is not in "
                  "the sidecar")
            _need(isinstance(e, dict) and isinstance(e.get("diff"), str)
                  and isinstance(e.get("why"), str),
                  f"{rule} / {prov}: EXPECTED_LOSS {case!r} needs diff and why strings")


def validate_result(rule, pid, res, npos):
    """One rules[<rule>].results[<policy>] object (or a store replay's result)."""
    w = f"rules[{rule!r}].results[{pid!r}]"
    _keys(res, ("positives", "negatives_firing", "not_modeled_reads"), w)
    _keys(res["positives"], ("total", "firing", "lost"), w + ".positives")
    _need(res["positives"]["total"] == npos,
          f"{rule} / {pid}: positives.total {res['positives']['total']} is not the "
          f"sidecar's {npos}")
    _need(isinstance(res["not_modeled_reads"], int), f"{w}.not_modeled_reads must be a count")
    lost_names = [x.get("case") for x in res["positives"]["lost"]]
    _need(len(set(lost_names)) == len(lost_names)
          and res["positives"]["firing"] == res["positives"]["total"] - len(lost_names),
          f"{rule} / {pid}: positives.firing {res['positives']['firing']} is not total "
          f"{res['positives']['total']} minus the {len(lost_names)} lost case(s)")
    for lost in res["positives"]["lost"]:
        _keys(lost, ("case", "reason", "policy_rules"), w + ".positives.lost[]")
        _need(lost["reason"] in LOST_REASONS,
              f"{rule} / {pid}: unknown lost reason {lost['reason']!r}")
    for neg in res["negatives_firing"]:
        _keys(neg, ("case", "kind", "reason"), w + ".negatives_firing[]")
        _need(neg["reason"] in FIRING_REASONS,
              f"{rule} / {pid}: unknown firing reason {neg['reason']!r}")


def store_columns(pc):
    """{store key: (policy id, store)} for each column whose store keeps no reads that
    its policy logs. The store replay runs that policy with a log filter that drops
    the store's read verbs. A policy whose own log filter is the store's (the AKS
    kube-audit-admin category) needs no replay."""
    out = {}
    for _, _, pid, _, reads in SHAPES:
        if not reads:
            continue
        lf = pc["policies"][pid].get("log_filter")
        if lf and sorted(lf.get("drop_verbs") or ()) == sorted(READ_VERBS[reads]):
            continue
        _need(not lf, f"policy {pid!r} has a log filter {lf!r} that is not the store "
              f"{reads!r} (drop {list(READ_VERBS[reads])}): the script cannot join them")
        out[f"{pid}+{reads}"] = (pid, reads)
    return out


def validate(pc, mr, cases, graders=None, pairs=None, stores=None):
    """Raise InputError when the inputs cannot give a correct page."""
    pcs = pc.get("schema") if isinstance(pc, dict) else None
    mrs = mr.get("schema") if isinstance(mr, dict) else None
    _need(pcs in PC_SCHEMAS, f"policy_coverage.json: unknown schema {pcs!r} "
          f"(this script knows {list(PC_SCHEMAS)})")
    _need(mrs in MR_SCHEMAS, f"mapping_results.json: unknown schema {mrs!r} "
          f"(this script knows {list(MR_SCHEMAS)})")
    _keys(pc, ("policy_order", "policies", "rules", "summary"), "policy_coverage.json")
    _keys(mr, ("providers", "reads", "rules"), "mapping_results.json")
    order = pc["policy_order"]
    pols = pc["policies"]
    _need(isinstance(order, list) and isinstance(pols, dict) and sorted(order) == sorted(pols)
          and len(set(order)) == len(order),
          "policy_coverage.json: policy_order must list each policy once")
    for pid in order:
        p = pols[pid]
        _keys(p, ("kind", "platform", "label", "version", "status", "files", "warnings"),
              f"policy_coverage.json policies[{pid!r}]")
        _need(isinstance(p["files"], list) and p["files"]
              and all(isinstance(f, dict) and isinstance(f.get("path"), str)
                      for f in p["files"]),
              f"policy_coverage.json policies[{pid!r}].files must list paths")
        _need(isinstance(p["warnings"], list), f"policies[{pid!r}].warnings must be a list")
        _keys(pc["summary"].get(pid), SUMMARY_KEYS, f"policy_coverage.json summary[{pid!r}]")
    for _, _, pid, mapping, reads in SHAPES:
        _need(pid is None or pid in pols, f"policy_coverage.json has no policy {pid!r}, "
              "which a platform column of this script reads (update SHAPES)")
        _need(mapping == "native" or mapping in mr["providers"],
              f"mapping_results.json has no provider {mapping!r}")
        _need(reads is None or reads in mr["reads"],
              f"mapping_results.json has no store {reads!r} in reads")
    for store, verbs in READ_VERBS.items():
        text = mr["reads"].get(store)
        _need(isinstance(text, str), f"mapping_results.json: reads.{store} is missing")
        for v in verbs:
            _need(re.search(rf"\b{v}\b", text),
                  f"mapping_results.json: reads.{store} does not name the verb {v!r} that "
                  "this script drops (update READ_VERBS)")
    _need(set(mr["reads"]) == set(READ_VERBS),
          f"mapping_results.json: reads stores {sorted(mr['reads'])} != "
          f"{sorted(READ_VERBS)} (update READ_VERBS)")
    prules, mrules = set(pc["rules"]), set(mr["rules"])
    _need(prules == mrules, "the two inputs list different rules: only in "
          f"policy_coverage.json {sorted(prules - mrules)}, only in mapping_results.json "
          f"{sorted(mrules - prules)}")
    graders = GRADERS if graders is None else graders
    for g, c in graders.items():
        _need(g in prules and c in prules, f"GRADERS names {g} -> {c}, not both in the inputs")
    for rule in sorted(prules):
        info = pc["rules"][rule]
        _keys(info, ("home_policy", "results", "case_counts"),
              f"policy_coverage.json rules[{rule!r}]")
        _need(info["home_policy"] in pols,
              f"{rule}: home_policy {info['home_policy']!r} is not a policy (the "
              "simulator's home check fails)")
        _need(set(info["results"]) == set(pols), f"{rule}: results must hold every policy")
        npos = sum(1 for c in cases[rule] if c["kind"] == "positive")
        _need(npos > 0, f"{rule}: the sidecar has no positive case (check_sufficiency.py "
              "fails it)")
        _need(npos == info["case_counts"].get("positive"),
              f"{rule}: the sidecar's positive count differs from policy_coverage.json")
        for pid, res in info["results"].items():
            validate_result(rule, pid, res, npos)
        if "needs" in info:
            validate_needs(rule, info["needs"])
        names = {c["name"]: c for c in cases[rule]}
        _need(len(names) == len(cases[rule]), f"{rule}: duplicate case names in the sidecar")
        validate_mapping(rule, mr["rules"][rule], names)
    for pid in order:
        opt = pols[pid].get("opt_in_losses")
        if opt is None:
            continue
        _need(isinstance(opt, dict), f"policies[{pid!r}].opt_in_losses must be an object")
        for rule, named in opt.items():
            _need(rule in prules and isinstance(named, dict),
                  f"policies[{pid!r}].opt_in_losses: {rule!r} is not a rule of the inputs")
            lost = {x["case"] for x in pc["rules"][rule]["results"][pid]["positives"]["lost"]}
            for case, why in named.items():
                _need(case in lost and isinstance(why, str),
                      f"policies[{pid!r}].opt_in_losses: {rule} {case!r} is not a lost "
                      "positive case under that policy")
    skeys = store_columns(pc)
    if stores is not None:
        _need(isinstance(stores, dict) and set(stores) == set(skeys),
              f"the store replay has results for {sorted(stores)}; the columns need "
              f"{sorted(skeys)}")
        for key in sorted(skeys):
            _need(isinstance(stores[key], dict) and set(stores[key]) == prules,
                  f"the store replay {key} has no result for every rule")
            for rule in sorted(prules):
                npos = sum(1 for c in cases[rule] if c["kind"] == "positive")
                validate_result(rule, key, stores[key][rule], npos)
    if pairs is not None:
        for g in graders:
            _need(isinstance(pairs.get(g), dict) and set(pairs[g]) == set(order) | set(skeys),
                  f"the chokepoint replay has no result for {g} under every policy and "
                  "replayed store")
            pos = {c["name"] for c in cases[g] if c["kind"] == "positive"}
            for pid, missed in pairs[g].items():
                _need(isinstance(missed, list) and set(missed) <= pos,
                      f"the chokepoint replay of {g} / {pid} names cases that are not its "
                      "positives")


# ------------------------------------------------------------------ the replays
def _simulator():
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    try:
        import k8s_policy_coverage as kpc  # noqa: E402  (pySigma)
        import sigma_eval  # noqa: E402
    except ImportError as exc:
        raise InputError(f"the replays need pySigma ({exc}): pip install -r "
                         "detections/requirements.txt") from exc
    return kpc, sigma_eval


def policies_from_pc(pc, kpc):
    """{policy id: (policy, log filter)}: the policies that policy_coverage.json names,
    loaded from its file lists with k8s_policy_coverage.load_policy(). Each file must
    have the SHA-256 that the JSON records, so the replays use the policy texts that
    the JSON describes."""
    out = {}
    for pid in pc["policy_order"]:
        p = pc["policies"][pid]
        for f in p["files"]:
            full = os.path.join(REPO, f["path"])
            _need(os.path.isfile(full), f"policy {pid!r}: no file {f['path']}")
            got = sha256_file(full)
            _need(got == f.get("sha256"), f"policy {pid!r}: {f['path']} has SHA-256 {got}, "
                  f"policy_coverage.json records {f.get('sha256')}: run python3 "
                  "detections/k8s_policy_coverage.py --update first")
        try:
            out[pid] = (kpc.load_policy([f["path"] for f in p["files"]]), p.get("log_filter"))
        except kpc.PolicyError as exc:
            raise InputError(f"policy {pid!r}: {exc}") from exc
    return out


def _store_runs(policies, stores):
    """[(store key, policy, log filter)]: each replayed store's policy, with a filter
    that drops the store's read verbs."""
    runs = []
    for key, (pid, store) in sorted(stores.items()):
        _need(pid in policies, f"the simulator has no policy {pid!r} for the replay")
        policy, log_filter = policies[pid]
        _need(not log_filter, f"{key}: the simulator's policy {pid!r} has a log filter")
        runs.append((key, policy, {"drop_verbs": list(READ_VERBS[store])}))
    return runs


def replay_stores(pc, sigma_dir=SIGMA, policies=None, stores=None):
    """{store key: {rule: result}} for each replayed store (store_columns()).

    Each rule's sidecar cases go through k8s_policy_coverage.run_rule(), the function
    that makes policy_coverage.json, under the store's policy with a log filter that
    drops the store's read verbs. A result has the shape of
    rules[<rule>].results[<policy>]. Needs pySigma."""
    kpc, _ = _simulator()
    if policies is None:
        policies = policies_from_pc(pc, kpc)
    stores = store_columns(pc) if stores is None else stores
    out = {}
    for key, policy, log_filter in _store_runs(policies, stores):
        out[key] = {}
        for rule in sorted(pc["rules"]):
            # run_rule joins its argument to the simulator's sigma directory; an
            # absolute path stays as it is, so --sigma reaches the replay too.
            path = os.path.join(os.path.abspath(sigma_dir), rule)
            try:
                res, _ = kpc.run_rule(path, {key: (policy, log_filter)})
            except SystemExit as exc:
                raise InputError(f"{rule}: {exc}") from exc
            out[key][rule] = res[key]
    return out


def replay_pairs(pc, cases, graders=None, sigma_dir=SIGMA, policies=None, stores=None):
    """{grader: {policy id or store key: [grader positive cases the chokepoint misses]}}.

    Each grader positive goes through k8s_policy_coverage.records_under() under the
    policy (and its log filter), as the simulator does in run_rule(), and under each
    replayed store; the chokepoint rule runs on the records with sigma_eval. Needs
    pySigma."""
    graders = GRADERS if graders is None else graders
    kpc, sigma_eval = _simulator()
    if policies is None:
        policies = policies_from_pc(pc, kpc)
    stores = store_columns(pc) if stores is None else stores
    runs = []
    for pid in pc["policy_order"]:
        _need(pid in policies, f"the simulator has no policy {pid!r} for the replay")
        runs.append((pid,) + tuple(policies[pid]))
    runs += _store_runs(policies, stores)
    out = {}
    for grader, choke in sorted(graders.items()):
        sql = sigma_eval.compile_rule(os.path.join(sigma_dir, choke))
        pos = [c for c in cases[grader] if c["kind"] == "positive"]
        out[grader] = {}
        for key, policy, log_filter in runs:
            missed = []
            for case in pos:
                flat = [sigma_eval.flatten(r) for ev in case["events"]
                        for r in kpc.records_under(policy, ev, log_filter)[0]]
                if not (flat and sigma_eval.EventTable(flat).hit_indices(sql)):
                    missed.append(case["name"])
            out[grader][key] = sorted(missed)
    return out


# ------------------------------------------------------------------ cells
def _sibling(pc, pid):
    """The policy with the same files and no log filter (aks-kube-audit for -admin)."""
    me = pc["policies"][pid]
    if not me.get("log_filter"):
        return None
    files = [f["path"] for f in me["files"]]
    for other in pc["policy_order"]:
        p = pc["policies"][other]
        if other != pid and not p.get("log_filter") and [f["path"] for f in p["files"]] == files:
            return other
    return None


def _all_reads(case, verbs):
    evs = case.get("events") or []
    return bool(evs) and all(e.get("verb") in verbs for e in evs)


def _mixed(case, verbs):
    flags = {e.get("verb") in verbs for e in case.get("events") or []}
    return len(flags) > 1


def _field(atom):
    return atom.split(".", 1)[1] if "." in atom else atom


def _idx_key(v):
    return (isinstance(v, str), v if isinstance(v, int) else 0)


def _variants(diff, regex):
    """None when no variant of an EXPECTED_LOSS diff matches regex; "all" when the diff
    is the same in every variant; else the sorted variant names that match."""
    if diff.startswith("all: "):
        return "all" if regex.search(diff) else None
    hit = sorted(part.split(":", 1)[0].strip() for part in diff.split(" | ")
                 if ":" in part and regex.search(part))
    return tuple(hit) or None


def _code_rank(code):
    for i, prefix in enumerate(CODE_ORDER):
        if code == prefix or (prefix.endswith("-") and code.startswith(prefix)):
            return (i, code)
    return (len(CODE_ORDER), code)


def compute_cell(pc, mr, cases, rule, shape, graders, pairs, stores):
    sid, _, pid, mapping, reads = shape
    info = pc["rules"][rule]
    pid = pid or info["home_policy"]
    skey = f"{pid}+{reads}" if reads and f"{pid}+{reads}" in stores else None
    if skey:
        # A replayed store: the policy's cases with the store's reads dropped.
        res, base, drop = stores[skey][rule], pid, READ_VERBS[reads]
    else:
        res, base = info["results"][pid], _sibling(pc, pid)
        drop = tuple(pc["policies"][pid]["log_filter"].get("drop_verbs") or ()) if base else ()
    kinds = {c["name"]: c["kind"] for c in cases[rule]}
    positives = [c for c in cases[rule] if c["kind"] == "positive"]
    total = res["positives"]["total"]
    opt_in = (pc["policies"][pid].get("opt_in_losses") or {}).get(rule, {})
    lost = {}            # case -> (code, policy rule indexes or None)
    # The base result: the same policy without the log filter or the store.
    base_reason = ({x["case"]: x["reason"] for x in info["results"][base]["positives"]["lost"]}
                   if base else {})
    for x in res["positives"]["lost"]:
        idx = sorted({"-" if i is None else i for i in x["policy_rules"]}, key=_idx_key)
        if base and x["reason"] == "no-record" and base_reason.get(x["case"]) != "no-record":
            lost[x["case"]] = ("reads-dropped", None)
        elif x["case"] in opt_in:
            lost[x["case"]] = ("opt-in", None)
        else:
            lost[x["case"]] = (x["reason"], tuple(idx))
    if drop:
        # The log filter is the store's read filter: it must drop exactly the cases
        # whose every event is a read verb of that store.
        store = reads if skey else next((k for k, v in READ_VERBS.items()
                                         if sorted(v) == sorted(drop)), None)
        if store:
            by_filter = {c for c, (code, _) in lost.items() if code == "reads-dropped"}
            by_verbs = {c["name"] for c in positives if _all_reads(c, READ_VERBS[store])
                        and base_reason.get(c["name"]) != "no-record"}
            if not any(_mixed(c, READ_VERBS[store]) for c in positives):
                _need(by_filter == by_verbs, f"{rule} / {skey or pid}: the log filter drops "
                      f"{sorted(by_filter)}, the read verbs say {sorted(by_verbs)}")
    if reads:
        verbs = READ_VERBS[reads]
        mixed = [c["name"] for c in positives if _mixed(c, verbs)]
        allr = [c["name"] for c in positives if _all_reads(c, verbs)]
        harness = mr["rules"][rule]["loses_positive_without_reads"][reads]
        if not mixed:
            _need(bool(allr) == bool(harness),
                  f"{rule}: {reads}: the sidecar's read-only positives {allr} disagree with "
                  f"loses_positive_without_reads={harness} in mapping_results.json")
        kept_reads = sorted(set(allr) - set(lost))
        _need(not kept_reads, f"{rule} / {sid}: the result keeps the read-only positive "
              f"cases {kept_reads}, which the store {reads} drops")
    # What the policy and the store keep, before the provider's mapping.
    kept = total - len(lost)
    np_fields = []
    # The negative cases that fire, by name: a negative that fires under the policy and
    # also has an approved mapping false positive counts once ("fp n": n cases).
    fp_cases = {n["case"] for n in res["negatives_firing"]}
    by_name = {c["name"]: c for c in cases[rule]}
    approved_diff = 0
    if mapping != "native":
        m = mr["rules"][rule]["providers"][mapping]
        if m["status"] == "not_portable":
            np_fields = sorted({_field(a) for a in m["not_portable"]})
        # A loss in every variant of the provider is a plain approved-loss.
        every = tuple(sorted(((mr.get("providers") or {}).get(mapping) or {})
                             .get("variants") or ()))
        for case, e in sorted(m["expected_loss"].items()):
            loss = _variants(e["diff"], LOSS_RE)
            if kinds.get(case) == "positive" and loss:
                code = ("approved-loss" if loss == "all" or loss == every
                        else "approved-loss-if-" + "/".join(loss))
                lost.setdefault(case, (code, None))
            elif kinds.get(case) != "positive" and _variants(e["diff"], FP_RE):
                # A store without reads drops a read-only case, so it cannot fire there.
                if not (reads and _all_reads(by_name.get(case, {}), READ_VERBS[reads])):
                    fp_cases.add(case)
            else:
                approved_diff += 1
    firing = total - len(lost)
    _need(firing >= 0, f"{rule} / {sid}: more lost cases than positives")
    counts = {}
    for code, idx in lost.values():
        counts.setdefault(code, [0, set()])
        counts[code][0] += 1
        if idx:
            counts[code][1].update(idx)
    codes = []
    for key in sorted(counts, key=_code_rank):
        n, idx = counts[key]
        tag = (" " + " ".join(f"#{i}" for i in sorted(idx, key=_idx_key))
               if key == "no-record" and idx else "")
        codes.append(f"{key} {n}{tag}")
    if approved_diff:
        codes.append(f"approved-diff {approved_diff}")
    if res["not_modeled_reads"]:
        codes.append(f"not-modeled {res['not_modeled_reads']}")
    fp = len(fp_cases)
    if fp:
        codes.append(f"fp {fp}")
    if np_fields:
        word = "not portable" if kept else "blind"
    elif firing == total:
        word = "full"
    elif firing:
        word = "partial"
    else:
        word = "blind"
    choke = graders.get(rule)
    if word == "blind" and choke:
        cc = compute_cell(pc, mr, cases, choke, shape, graders, pairs, stores)
        if cc["word"] != "full":
            codes.append(f"chokepoint not full ({cc['word']})")
        else:
            missed = set(pairs[rule][skey or pid])
            k = total - len(missed)
            codes.append(f"chokepoint {k}/{total}")
            word = "chokepoint only" if k == total else "chokepoint partial" if k else "blind"
    return {"word": word, "firing": firing, "total": total, "codes": codes,
            "policy": pid, "np_fields": np_fields, "kept": kept}


def cell_text(c, shape_id):
    codes = c["codes"]
    if c["np_fields"]:
        # NOT_PORTABLE makes the mapping's approved differences moot.
        codes = (["not-in-schema: " + ", ".join(f"`{f}`" for f in c["np_fields"])]
                 + [x for x in codes if not x.startswith("approved-")])
    if c["word"] == "not portable":
        head = f"**not portable** ({c['kept']}/{c['total']} by policy and store)"
    else:
        head = f"**{c['word']}** {c['firing']}/{c['total']}"
    if shape_id == "lab":
        head += f" `{c['policy']}`"
    return head + ("; " + "; ".join(codes) if codes else "")


# ------------------------------------------------------------------ blocks
def _rel(repo_path):
    return os.path.relpath(repo_path, DOC_DIR_REL).replace(os.sep, "/")


def _rule_link(rule, mr):
    stem = rule[:-len(".yml")]
    mark = " L" if mr["rules"][rule]["list_text_items"] else ""
    return f"[`{stem}`]({_rel('detections/sigma/' + rule)}){mark}"


def extra_shapes(pc):
    """A column for each policy that no fixed column reads, except the lab policies
    (their column is the home one): a self-managed cluster that runs that policy."""
    used = {s[2] for s in SHAPES if s[2]}
    out = []
    for pid in pc["policy_order"]:
        p = pc["policies"][pid]
        if pid in used or (p.get("kind") == "lab" and pid != RECOMMENDED):
            continue
        out.append((f"x-{pid}", f"Self-managed, `{pid}`", pid, "native", None))
    return out


def _md(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def _sentence(text):
    text = _md(text)
    return text[:1].upper() + text[1:]


def block_coverage(pc, mr, cases, graders, pairs, stores):
    shapes = SHAPES + extra_shapes(pc)
    rules = sorted(pc["rules"])
    lines = ["<!-- Generated by detections/k8s_platforms_md.py --write from "
             "detections/k8s/policy_coverage.json and detections/pipelines/"
             "mapping_results.json. Do not edit by hand. -->", ""]
    lines.append("Columns (each is one policy and one record shape):")
    lines.append("")
    for sid, head, pid, mapping, reads in shapes:
        pol = f"policy `{pid}`" if pid else "policy: the rule's home lab policy"
        note = SHAPE_NOTES.get(sid) or (pc["policies"][pid]["label"] if pid else "")
        shape = "native Event" if mapping == "native" else f"mapping `{mapping}`"
        store = f", store without reads `{reads}`" if reads else ""
        lines.append(f"- **{head}**: {pol}, {shape}{store}. {_sentence(note)}.")
    lines.append("")
    lines.append("`L` after a rule: some item reads a JSON list as its text "
                 "(`list_text_items`); a store that explodes JSON arrays cannot match it "
                 "([pipelines/README.md](../pipelines/README.md"
                 "#rules-that-read-a-list-as-its-json-text)).")
    lines.append("")
    lines.append("| Rule | " + " | ".join(s[1] for s in shapes) + " |")
    lines.append("|---" * (len(shapes) + 1) + "|")
    tally = {s[0]: {} for s in shapes}
    for rule in rules:
        row = [_rule_link(rule, mr)]
        for s in shapes:
            c = compute_cell(pc, mr, cases, rule, s, graders, pairs, stores)
            tally[s[0]][c["word"]] = tally[s[0]].get(c["word"], 0) + 1
            row.append(cell_text(c, s[0]))
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append("Rules per support word (" + ", ".join(WORDS) + "):")
    lines.append("")
    lines.append("| Shape | " + " | ".join(WORDS) + " |")
    lines.append("|---" * (len(WORDS) + 1) + "|")
    for s in shapes:
        t = tally[s[0]]
        _need(set(t) <= set(WORDS), f"unknown support word in {sorted(t)}")
        lines.append(f"| {s[1]} | " + " | ".join(str(t.get(w, 0)) for w in WORDS) + " |")
    lines.append("")
    lines.append("Every policy, as the simulator reports it (no mapping): rules with every / "
                 "some / no positive case firing, positive cases firing, negative cases "
                 "that fire, and events whose missing body the rule reads (not proven):")
    lines.append("")
    lines.append("| Policy | Platform | What the column is | Rules every / some / none "
                 "| Positives firing | Negatives firing | Not proven | What is verified |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for pid in pc["policy_order"]:
        p, s = pc["policies"][pid], pc["summary"][pid]
        files = ", ".join(f"[`{os.path.basename(f['path'])}`]({_rel(f['path'])})"
                          for f in p["files"])
        lines.append(
            f"| `{pid}` | {_md(p['platform'])} | {_md(p['label'])} ({files}) | "
            f"{s['rules_all_positives']} / {s['rules_some_positives']} / {s['rules_blind']} | "
            f"{s['positives_firing']} of {s['positives']} | {s['negatives_firing']} | "
            f"{s['not_modeled_reads']} | {_md(p['status'])} |")
    warns = [(pid, w) for pid in pc["policy_order"] for w in pc["policies"][pid]["warnings"]]
    if warns:
        lines.append("")
        lines.append("Simulator warnings:")
        lines.append("")
        for pid, w in warns:
            lines.append(f"- `{pid}`: {_md(w)}")
    return "\n".join(lines)


def _run_label(key, stores):
    if key in stores:
        pid, store = stores[key]
        return f"`{pid}` + store `{store}`"
    return f"`{key}`"


def block_pairs(pc, cases, graders, pairs, stores):
    keys = list(pc["policy_order"]) + sorted(stores)
    lines = [GENERATED, "",
             "The replay runs each grader's positive cases through its chokepoint rule "
             "under each policy with its log filter, and under each replayed store (its "
             "policy, without the store's read verbs). It applies no mapping. A miss is a "
             "positive case of the grader on which the chokepoint does not fire.", "",
             "| Grader | Chokepoint | Positive cases | The chokepoint fires on every one of "
             "them under | Misses (policies and stores: fired / total, cases) |",
             "|---|---|---|---|---|"]
    for g in sorted(graders):
        n = sum(1 for c in cases[g] if c["kind"] == "positive")
        groups = {}
        for key in keys:
            missed = tuple(pairs[g][key])
            if missed:
                groups.setdefault(missed, []).append(key)
        clean = [key for key in keys if not pairs[g][key]]
        under = ("every policy and store" if not groups else
                 "no policy" if not clean else ", ".join(_run_label(k, stores) for k in clean))
        parts = []
        for missed, pids in groups.items():
            names = (", ".join(f"`{x}`" for x in missed) if len(missed) <= 6
                     else f"{len(missed)} cases")
            parts.append(f"{', '.join(_run_label(p, stores) for p in pids)}: "
                         f"{n - len(missed)}/{n}, {names}")
        lines.append(f"| `{g[:-4]}` | `{graders[g][:-4]}` | {n} | {under} | "
                     f"{'; '.join(parts) if parts else 'none'} |")
    return "\n".join(lines)


def block_needs(pc):
    rules = sorted(pc["rules"])
    have = [r for r in rules if "needs" in pc["rules"][r]]
    if not have:
        return (GENERATED + "\n\nThe needs data is not computed yet: no rule in "
                "`detections/k8s/policy_coverage.json` has a `needs` key. When the policy "
                "simulator writes it, this block lists, for each rule, the lowest audit "
                "level at which every positive case fires and the requests of those cases.")
    lines = [GENERATED, "",
             "Lowest level: the lowest level that, given to every request of the rule's "
             "positive cases, makes every one of them fire (no uniform level: no single level "
             "does). "
             "Requests: the group (`core` for the core group), resource, subresource and "
             "verbs of those cases: a sample of what the rule selects, not a complete "
             "list, so read the rule's detection (or start from the recommended policy) "
             "before you write a policy from them.", "",
             "| Rule | Lowest level | Requests | Note |", "|---|---|---|---|"]
    for r in rules:
        n = pc["rules"][r].get("needs")
        if n is None:
            lines.append(f"| `{r[:-4]}` | not computed | | |")
            continue
        reqs = "<br>".join(
            f"`{(q['group'] or 'core')}/{q['resource']}"
            f"{('/' + q['subresource']) if q['subresource'] else ''}`: {', '.join(q['verbs'])}"
            for q in sorted(n["requests"], key=lambda q: (q["group"], q["resource"],
                                                          q["subresource"] or "", q["verbs"]))
        ) or "no requests"
        level = n["level"] if n["level"] is not None else "no uniform level"
        lines.append(f"| `{r[:-4]}` | {level} | {reqs} | "
                     f"{_md(n['note']) if n['note'] else ''} |")
    return "\n".join(lines)


FP_WHY = {
    "body-removed": "the record has no body, so a filter that reads the body has no input",
    "request-received": "only the extra RequestReceived record fires",
    "no-record": "no record (not expected for a firing case)",
    "partial-record": "some events of the case are dropped",
    "other": "read the case",
}


def block_fp(pc, mr, cases, stores, cols):
    rows = []
    for pid in pc["policy_order"]:
        p = pc["policies"][pid]
        if p.get("kind") == "lab" and pid != RECOMMENDED:
            continue
        for rule in sorted(pc["rules"]):
            for n in pc["rules"][rule]["results"][pid]["negatives_firing"]:
                rows.append((f"`{pid}`", rule, n["case"], n["kind"], FP_WHY[n["reason"]]))
    for key in sorted(stores):
        for rule in sorted(pc["rules"]):
            for n in stores[key][rule]["negatives_firing"]:
                rows.append((_run_label(key, cols), rule, n["case"], n["kind"],
                             FP_WHY[n["reason"]]))
    for prov in ("aks", "gke"):
        for rule in sorted(mr["rules"]):
            kinds = {c["name"]: c["kind"] for c in cases[rule]}
            for case, e in sorted(mr["rules"][rule]["providers"][prov]["expected_loss"].items()):
                if kinds.get(case) != "positive" and _variants(e["diff"], FP_RE):
                    rows.append((f"`mapping {prov}`", rule, case, kinds.get(case),
                                 f"approved difference: {e['diff']} ({e['why']})"))
    lines = [GENERATED, ""]
    if not rows:
        lines.append("No negative case fires under a platform policy or mapping.")
        return "\n".join(lines)
    per = {}
    for r in rows:
        per[r[0]] = per.get(r[0], 0) + 1
    lines.append("Negative cases that fire, per platform policy and replayed store: " + ", ".join(
        f"{k} {v}" for k, v in per.items()) + ". Lab policies are left out: they are not "
        "platforms, and under its own home policy no negative case of a rule fires (the "
        "simulator's home check).")
    lines.append("")
    lines.append("| Policy | Rule | Case | Kind | Why it fires |")
    lines.append("|---|---|---|---|---|")
    for label, rule, case, kind, why in rows:
        lines.append(f"| {label} | `{rule[:-4]}` | `{case}` | {kind} | {_md(why)} |")
    return "\n".join(lines)


def block_recommended(pc, exists):
    if RECOMMENDED not in pc["policies"]:
        return (GENERATED + "\n\nA recommended policy is not available yet: "
                "`detections/k8s/policy_coverage.json` has no policy with id "
                f"`{RECOMMENDED}`. When it has one, this block names it, links its file "
                "and gives its simulator result.")
    p, s = pc["policies"][RECOMMENDED], pc["summary"][RECOMMENDED]
    first = p["files"][0]["path"]
    if not exists(first):
        raise InputError(f"policy {RECOMMENDED!r}: its file {first} does not exist")
    lines = [
        GENERATED,
        "",
        f"**{_sentence(p['label'])}**: [`{first}`]({_rel(first)}). "
        f"Version: {_md(p['version'])}.",
        "",
        f"Simulator result: {s['rules_all_positives']} of {s['rules']} rules fire on every "
        f"positive case, {s['rules_some_positives']} on some, {s['rules_blind']} on none; "
        f"{s['positives_firing']} of {s['positives']} positive cases fire; "
        f"{s['negatives_firing']} negative cases fire; {s['not_modeled_reads']} events are "
        "not proven (the policy logs a body that the case record lacks, and the rule "
        "reads it).",
        "",
        f"What is verified: {_md(p['status'])}."]
    opt = p.get("opt_in_losses") or {}
    if opt:
        lines += ["", "Named opt-in losses (each needs a line of the policy that is "
                  "commented out):", ""]
        for rule in sorted(opt):
            for case in sorted(opt[rule]):
                lines.append(f"- `{rule[:-4]}`, `{case}`: {_md(opt[rule][case])}")
    return "\n".join(lines)


def render_blocks(pc, mr, cases, exists=None, graders=None, pairs=None, stores=None):
    exists = exists or (lambda path: os.path.exists(os.path.join(REPO, path)))
    graders = GRADERS if graders is None else graders
    validate(pc, mr, cases, graders)
    if stores is None:
        stores = replay_stores(pc)
    if pairs is None:
        pairs = replay_pairs(pc, cases, graders)
    validate(pc, mr, cases, graders, pairs, stores)
    cols = store_columns(pc)
    return {"platform-coverage": block_coverage(pc, mr, cases, graders, pairs, stores),
            "platform-pairs": block_pairs(pc, cases, graders, pairs, cols),
            "platform-needs": block_needs(pc),
            "platform-fp": block_fp(pc, mr, cases, stores, cols),
            "platform-recommended": block_recommended(pc, exists)}


# ------------------------------------------------------------------ the document
def _markers(name):
    return f"<!-- {name}:begin -->", f"<!-- {name}:end -->"


def split_doc(text):
    """Check that each marker pair is there once, in order; return the spans."""
    spans = {}
    for name in BLOCKS:
        b, e = _markers(name)
        nb, ne = text.count(b), text.count(e)
        if nb != 1 or ne != 1:
            raise InputError(f"PLATFORMS.md must hold {b} and {e} once each "
                             f"(found {nb} and {ne})")
        i, j = text.index(b), text.index(e)
        if j < i:
            raise InputError(f"PLATFORMS.md: {e} comes before {b}")
        spans[name] = (i + len(b), j)
    last = -1
    for name in BLOCKS:
        if spans[name][0] < last:
            raise InputError("PLATFORMS.md: the marker blocks overlap or are out of order")
        last = spans[name][1]
    return spans


def apply_blocks(text, blocks):
    spans = split_doc(text)
    out, pos = [], 0
    for name in BLOCKS:
        i, j = spans[name]
        out.append(text[pos:i])
        out.append("\n" + blocks[name].rstrip("\n") + "\n")
        pos = j
    out.append(text[pos:])
    return "".join(out)


def stale_blocks(text, blocks):
    spans = split_doc(text)
    return [name for name in BLOCKS
            if text[spans[name][0]:spans[name][1]] != "\n" + blocks[name].rstrip("\n") + "\n"]


# ------------------------------------------------------------------ anchors
def _blank_code(text):
    """The text with fenced code blocks and inline code spans blanked (same lines)."""
    out, fence = [], None
    for line in text.split("\n"):
        m = FENCE_RE.match(line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
            out.append("")
            continue
        if m:
            fence = m.group(1)
            out.append("")
            continue
        out.append(re.sub(r"(`+)(?:(?!\1).)+?\1", lambda s: " " * len(s.group(0)), line))
    return "\n".join(out)


def slugs(text):
    """GitHub heading anchors of a Markdown text (outside fenced code), and the ids of
    <a id> / <a name> tags."""
    out, seen = set(), {}
    lines = _blank_code_keep_spans(text).split("\n")
    heads = []
    for n, line in enumerate(lines):
        m = re.match(r"^ {0,3}#{1,6}[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$", line)
        if m:
            heads.append(m.group(1))
        elif (n and re.match(r"^ {0,3}(=+|-+)[ \t]*$", line) and lines[n - 1].strip()
              and not re.match(r"^ {0,3}([-*+>|#]|\d+[.)])", lines[n - 1])):
            heads.append(lines[n - 1].strip())
        out.update(HTML_ANCHOR_RE.findall(line))
    for h in heads:
        h = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", h)     # links and images: their text
        h = re.sub(r"<[^>]+>", "", h)                          # HTML tags
        s = re.sub(r"[^\w\- ]", "", h.strip().lower()).replace(" ", "-")
        n = seen.get(s, 0)
        seen[s] = n + 1
        out.add(s if n == 0 else f"{s}-{n}")
    return out


def _blank_code_keep_spans(text):
    """Fenced code blanked; inline code kept (a heading's code text is in its slug)."""
    out, fence = [], None
    for line in text.split("\n"):
        m = FENCE_RE.match(line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
            out.append("")
            continue
        if m:
            fence = m.group(1)
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


def md_files(root):
    """Every .md file under root, hidden folders too, except .git and templates/ (as
    .github/scripts/check_md_links.py walks them)."""
    out = []
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in (".git", "templates"))
        out += [os.path.join(base, f) for f in sorted(files) if f.endswith(".md")]
    return sorted(out)


def links(text):
    """(line number, url) of each inline link and reference definition outside code."""
    clean = _blank_code(text)
    out = []
    for rx in (INLINE_LINK_RE, REF_DEF_RE):
        for m in rx.finditer(clean):
            url = m.group(1)
            if url.startswith("<") and url.endswith(">"):
                url = url[1:-1]
            out.append((clean.count("\n", 0, m.start()) + 1, url))
    return sorted(out)


def _resolve(url, src, root):
    """(target path or None for an in-page link, anchor or None); None for an
    external URL."""
    if SCHEME_RE.match(url):
        return None
    path, sep, frag = url.partition("#")
    path = unquote(path.split("?", 1)[0])
    frag = unquote(frag) if sep else None
    if not path:
        return (None, frag)
    base = root if path.startswith("/") else os.path.dirname(src)
    return (os.path.normpath(os.path.join(base, path.lstrip("/"))), frag)


def bad_anchors(doc_path, root):
    """Bad anchors: links to doc_path#x from any .md under root, in-page links of
    doc_path, and links from doc_path to another .md file with an anchor.
    Returns (bad strings, number of anchored links checked)."""
    doc_path = os.path.abspath(doc_path)
    try:
        with open(doc_path, encoding="utf-8") as fh:
            doc_text = fh.read()
    except OSError as exc:
        raise InputError(f"{doc_path}: {exc}") from exc
    anchors = slugs(doc_text)
    cache = {doc_path: anchors}
    bad, checked = [], 0
    for path in md_files(root):
        path = os.path.abspath(path)
        rel = os.path.relpath(path, root)
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        is_doc = path == doc_path
        for line, url in links(text):
            r = _resolve(url, path, root)
            if r is None or r[1] is None:
                continue
            target, frag = r
            if target is None:
                if not is_doc:
                    continue
                target = doc_path
            elif target != doc_path and not (is_doc and target.endswith(".md")):
                continue
            checked += 1
            if target not in cache:
                try:
                    with open(target, encoding="utf-8") as fh:
                        cache[target] = slugs(fh.read())
                except OSError:
                    bad.append(f"{rel}:{line}: {url} (no such file)")
                    continue
            if frag not in cache[target]:
                bad.append(f"{rel}:{line}: {url} (no heading of "
                           f"{os.path.relpath(target, root)} has the anchor #{frag})")
    return bad, checked


# ------------------------------------------------------------------ run
def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise InputError(f"{path}: {exc}") from exc


def run(args):
    pc = load_json(args.policy_coverage)
    mr = load_json(args.mapping_results)
    _need(isinstance(pc, dict) and isinstance(pc.get("rules"), dict),
          "policy_coverage.json: no rules")
    _need(isinstance(mr, dict), "mapping_results.json: not an object")
    if pc.get("schema") not in PC_SCHEMAS or mr.get("schema") not in MR_SCHEMAS:
        validate(pc, mr, {})       # raises with the schema message
    cases = load_cases(args.sigma, sorted(pc["rules"]), pc)
    validate(pc, mr, cases)
    kpc, _ = _simulator()
    policies = policies_from_pc(pc, kpc)
    stores = replay_stores(pc, sigma_dir=args.sigma, policies=policies)
    pairs = replay_pairs(pc, cases, sigma_dir=args.sigma, policies=policies)
    blocks = render_blocks(pc, mr, cases, pairs=pairs, stores=stores)
    try:
        with open(args.doc, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise InputError(f"{args.doc}: {exc}") from exc
    if args.write:
        new = apply_blocks(text, blocks)
        if new != text:
            with open(args.doc, "w", encoding="utf-8") as fh:
                fh.write(new)
            print(f"wrote {os.path.relpath(args.doc, REPO)}")
        else:
            print(f"{os.path.relpath(args.doc, REPO)} is current")
        return 0
    stale = stale_blocks(text, blocks)
    for name in stale:
        print(f"STALE: the {name} block of {os.path.relpath(args.doc, REPO)} differs from "
              "the inputs; run python3 detections/k8s_platforms_md.py --write")
    if stale:
        return 1
    print(f"OK: {os.path.relpath(args.doc, REPO)}: {len(BLOCKS)} generated blocks are current "
          f"({len(pc['rules'])} rules, {len(pc['policy_order'])} policies, "
          f"{len(SHAPES) + len(extra_shapes(pc))} platform columns, "
          f"{len(store_columns(pc))} replayed store(s), {len(GRADERS)} graders replayed "
          "through their chokepoints)")
    return 0


def run_anchors(args):
    bad, checked = bad_anchors(args.doc, REPO)
    for b in bad:
        print(f"BAD ANCHOR: {b}")
    if bad:
        return 1
    print(f"OK: {checked} anchored link(s) into, inside and out of "
          f"{os.path.relpath(args.doc, REPO)} resolve to a heading")
    return 0


# ------------------------------------------------------------------ self-test
GKE_STORE = "gce-kube-up+gke_admin_activity"


def _fixture():
    """A small, complete input: five rules, every SHAPES policy, a recommended policy,
    and the replays ({"pairs": ..., "stores": ...})."""
    pols = ["lab-apiserver", "eks", "gce-kube-up", "aks-kube-audit", "aks-kube-audit-admin",
            "openshift-default", "openshift-wrb", "openshift-default-4.17",
            "openshift-wrb-4.17", "k3s-starter", RECOMMENDED]
    rules = {
        "T1/grader.yml": ["p-create", "p-patch"],
        "T1/choke.yml": ["c-create"],
        "T2/exec.yml": ["e-ws-get", "e-spdy-create", "e-watch"],
        "T3/imp.yml": ["i-get"],
        "T4/np.yml": ["n-get", "n-create"],
    }
    verbs = {"p-create": "create", "p-patch": "patch", "c-create": "create",
             "e-ws-get": "get", "e-spdy-create": "create", "e-watch": "watch", "i-get": "get",
             "n-get": "get", "n-create": "create"}
    cases = {}
    for r, names in rules.items():
        cases[r] = [{"name": n, "kind": "positive", "events": [{"verb": verbs[n]}]}
                    for n in names]
        cases[r].append({"name": f"{r}-dry", "kind": "filtered",
                         "events": [{"verb": "delete"}]})
    # A near-miss read: the policy logs its body (not-modeled) and it fires (fp) under
    # gce-kube-up; a store without reads holds neither.
    cases["T1/choke.yml"].append({"name": "c-get-recon", "kind": "near-miss",
                                  "events": [{"verb": "get"}]})
    pc = {"schema": PC_SCHEMAS[0], "generator": "self-test", "semantics": "self-test",
          "policy_order": pols, "policies": {}, "rules": {}, "summary": {}}
    for pid in pols:
        files = [{"path": "detections/k8s/audit-policy-apiserver.yaml", "sha256": "0"}]
        if pid.startswith("aks"):
            files = [{"path": "detections/k8s/provider-policies/aks/aks-audit-policy.yaml",
                      "sha256": "0"}]
        if pid == RECOMMENDED:
            files = [{"path": "detections/k8s/audit-policy-recommended.yaml", "sha256": "0"}]
        pc["policies"][pid] = {
            "kind": "lab" if pid.startswith("lab") else "provider",
            "platform": pid, "label": f"label of {pid}", "version": "v",
            "status": f"status of {pid}", "files": files,
            "log_filter": ({"drop_verbs": ["get", "list"], "source": "x"}
                           if pid == "aks-kube-audit-admin" else None),
            "rule_count": 1, "warnings": ["w1"] if pid == "eks" else []}
        pc["summary"][pid] = {"rules": 5, "rules_all_positives": 2, "rules_some_positives": 1,
                              "rules_blind": 1, "positives": 9, "positives_firing": 5,
                              "negatives_firing": 0, "not_modeled": 0,
                              "not_modeled_reads": 0}

    def res(lost=(), fp=(), nmr=0, total=None, reason="body-removed", idx=3):
        return {"positives": {"total": total, "firing": total - len(lost),
                              "lost": [{"case": c, "reason": reason, "policy_rules": [idx]}
                                       for c in lost]},
                "near_misses": {"total": 0, "quiet": 0, "no_record": 0},
                "negatives_firing": [{"case": c, "kind": "filtered", "reason": "body-removed"}
                                     for c in fp],
                "not_modeled": nmr, "not_modeled_reads": nmr}
    for r, names in rules.items():
        results = {pid: res(total=len(names)) for pid in pols}
        pc["rules"][r] = {"title": r, "level": "high", "rule_digest": "0",
                          "cases_sha256": "0", "home_policy": "lab-apiserver",
                          "case_counts": {"positive": len(names), "near-miss": 0,
                                          "filtered": 1, "confounder": 0, "benign": 0},
                          "results": results}
    g = pc["rules"]["T1/grader.yml"]["results"]
    for pid in ("openshift-default", "k3s-starter", "openshift-default-4.17"):
        g[pid] = res(lost=["p-create", "p-patch"], total=2)          # blind -> chokepoint
    g["eks"] = res(lost=["p-patch"], total=2, nmr=4)                 # partial
    g[RECOMMENDED] = res(lost=["p-patch"], total=2)                  # an opt-in loss
    pc["policies"][RECOMMENDED]["opt_in_losses"] = {
        "T1/grader.yml": {"p-patch": "needs the opt-in line"}}
    e = pc["rules"]["T2/exec.yml"]["results"]
    e["aks-kube-audit-admin"] = res(lost=["e-ws-get"], total=3, reason="no-record", idx=22)
    e["openshift-default-4.17"] = res(lost=["e-ws-get"], total=3, reason="no-record", idx=0,
                                      fp=["T2/exec.yml-dry"])
    pc["rules"]["T1/choke.yml"]["results"]["eks"] = res(total=1, fp=["T1/choke.yml-dry"])
    pc["rules"]["T1/choke.yml"]["results"]["gce-kube-up"] = res(total=1, nmr=2,
                                                                fp=["c-get-recon"])
    pc["rules"]["T3/imp.yml"]["results"]["aks-kube-audit-admin"] = res(
        lost=["i-get"], total=1, reason="no-record", idx=17)
    pc["rules"]["T4/np.yml"]["results"]["aks-kube-audit-admin"] = res(
        lost=["n-get"], total=2, reason="no-record", idx=17)
    pc["rules"]["T2/exec.yml"]["needs"] = {
        "level": "Metadata", "note": None,
        "requests": [{"group": "", "resource": "pods", "subresource": "exec",
                      "verbs": ["create", "get"]},
                     {"group": "", "resource": "pods", "subresource": None,
                      "verbs": ["watch"]}]}
    pc["rules"]["T1/grader.yml"]["needs"] = {"level": None, "note": "no uniform level",
                                             "requests": []}
    np_reason = "pipeline cannot map this field"
    mr = {"schema": MR_SCHEMAS[0], "generated_by": "self-test",
          "providers": {"aks": {}, "gke": {}, "exploded": {}},
          "reads": {"aksauditadmin": "AKSAudit without get and list events",
                    "gke_admin_activity": "no get, list or watch"},
          "summary": {}, "anchors": {}, "rules": {}}
    for r in rules:
        reads_lost = r in ("T2/exec.yml", "T3/imp.yml", "T4/np.yml")
        mr["rules"][r] = {
            "list_text_items": ["sel.requestObject.rules"] if r == "T1/grader.yml" else [],
            "loses_positive_without_reads": {"aksauditadmin": reads_lost,
                                             "gke_admin_activity": reads_lost},
            "providers": {p: {"status": "same", "not_portable": {}, "expected_loss": {},
                              "unexpected": {}, "errors": []} for p in ("aks", "gke")}}
        mr["rules"][r]["providers"]["exploded"] = {"status": "same", "loses_positive": False}
    imp = mr["rules"]["T3/imp.yml"]["providers"]
    imp["aks"].update(status="not_portable",
                      not_portable={"sel.impersonatedUser.username": np_reason})
    imp["gke"].update(status="not_portable", not_portable={"sel.responseStatus.code": np_reason})
    mr["rules"]["T4/np.yml"]["providers"]["gke"].update(
        status="not_portable", not_portable={"sel.requestURI": np_reason})
    gp = mr["rules"]["T1/grader.yml"]["providers"]["gke"]
    gp.update(status="expected_loss", expected_loss={
        "p-patch": {"diff": "all: native fires, gke quiet; blocks sel", "why": "GKE_JSON_PATCH"},
        "T1/grader.yml-dry": {"diff": "all: blocks sel", "why": "GKE_JSON_PATCH"}})
    ap = mr["rules"]["T1/grader.yml"]["providers"]["aks"]
    ap.update(status="expected_loss", expected_loss={
        "p-create": {"diff": "sorted: native fires, aks quiet; blocks sel", "why": "KEY_ORDER"}})
    # The store replay (GKE Admin Activity): the gce-kube-up result, with every
    # read-only positive lost (no record), and without the read near-miss's not-modeled
    # event and false positive.
    stores = {GKE_STORE: {}}
    for r in rules:
        st = json.loads(json.dumps(pc["rules"][r]["results"]["gce-kube-up"]))
        for c in cases[r]:
            if c["kind"] == "positive" and _all_reads(c, READ_VERBS["gke_admin_activity"]):
                st["positives"]["lost"].append({"case": c["name"], "reason": "no-record",
                                                "policy_rules": [5]})
        st["positives"]["firing"] = st["positives"]["total"] - len(st["positives"]["lost"])
        stores[GKE_STORE][r] = st
    stores[GKE_STORE]["T1/choke.yml"] = res(total=1, nmr=1)
    # The chokepoint replay: the chokepoint misses p-patch under openshift-default-4.17.
    pairs = {"T1/grader.yml": {pid: [] for pid in pols + [GKE_STORE]}}
    pairs["T1/grader.yml"]["openshift-default-4.17"] = ["p-patch"]
    return pc, mr, cases, {"pairs": pairs, "stores": stores}


def _row(block, rule):
    for line in block.splitlines():
        if line.startswith(f"| [`{rule[:-4]}`]"):
            return [c.strip() for c in line.strip("|").split("|")]
    raise AssertionError(f"no row for {rule}")


def _col(shape_id, pc):
    ids = [s[0] for s in SHAPES + extra_shapes(pc)]
    return ids.index(shape_id) + 1


def _self_test_replay(check):
    """The replay on constructed rules and policies (needs pySigma; skipped without)."""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    try:
        import k8s_policy_coverage as kpc  # noqa: E402
    except ImportError as exc:
        print(f"SKIP replay on constructed rules (no pySigma: {exc})")
        return
    base = {"title": "t", "status": "experimental", "level": "low",
            "logsource": {"product": "kubernetes", "service": "audit"}}
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "T9"))
        rules = {
            "T9/choke.yml": ("id: 00000000-0000-4000-8000-000000000001\n"
                             "detection:\n  sel:\n    verb: update\n"
                             "    objectRef.resource: configmaps\n"
                             "  operator:\n    user.username: trusted-operator\n"
                             "  condition: sel and not operator\n"),
            "T9/grader.yml": ("id: 00000000-0000-4000-8000-000000000002\n"
                              "detection:\n  sel:\n    verb: update\n"
                              "    requestObject.data.Corefile|contains: evil\n"
                              "  condition: sel\n"),
        }
        for rel, det in rules.items():
            with open(os.path.join(tmp, rel), "w", encoding="utf-8") as fh:
                fh.write("".join(f"{k}: {json.dumps(v)}\n" for k, v in base.items()) + det)

        def ev(user):
            return {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Request",
                    "stage": "ResponseComplete", "auditID": "a", "verb": "update",
                    "user": {"username": user}, "requestURI": "/api/v1/namespaces/kube-"
                    "system/configmaps/coredns",
                    "objectRef": {"resource": "configmaps", "namespace": "kube-system",
                                  "name": "coredns", "apiVersion": "v1"},
                    "responseStatus": {"code": 200},
                    "requestObject": {"data": {"Corefile": "evil"}}}
        cases = {"T9/grader.yml": [
            {"name": "by-attacker", "kind": "positive", "events": [ev("mallory")]},
            {"name": "by-operator", "kind": "positive", "events": [ev("trusted-operator")]}]}
        pols = {"meta": (kpc.policy_from_rules([{"level": "Metadata"}]), None),
                "none": (kpc.policy_from_rules([{"level": "None"}]), None),
                "drop-update": (kpc.policy_from_rules([{"level": "Request"}]),
                                {"drop_verbs": ["update"]})}
        pc = {"policy_order": ["meta", "none", "drop-update"]}
        got = replay_pairs(pc, cases, {"T9/grader.yml": "T9/choke.yml"}, tmp, pols,
                           {"meta+gke_admin_activity": ("meta", "gke_admin_activity")})
        check("replay: the chokepoint misses only the case its filter drops (Metadata), "
              "every case without a record (None, a log filter); a store without reads "
              "keeps the update cases",
              got == {"T9/grader.yml": {"meta": ["by-operator"],
                                        "none": ["by-attacker", "by-operator"],
                                        "drop-update": ["by-attacker", "by-operator"],
                                        "meta+gke_admin_activity": ["by-operator"]}}, got)
        # The store replay: run_rule() under a policy with the store's reads dropped.
        with open(os.path.join(tmp, "T9/body.yml"), "w", encoding="utf-8") as fh:
            fh.write("".join(f"{k}: {json.dumps(v)}\n" for k, v in base.items())
                     + "id: 00000000-0000-4000-8000-000000000003\n"
                     "detection:\n  sel:\n    objectRef.resource: configmaps\n"
                     "  safe:\n    requestObject.data.safe: 'yes'\n"
                     "  condition: sel and not safe\n")

        def ev2(verb, resource, level, safe=None):
            e = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": level,
                 "stage": "ResponseComplete", "auditID": "b", "verb": verb,
                 "user": {"username": "mallory"},
                 "requestURI": f"/api/v1/namespaces/default/{resource}/x",
                 "objectRef": {"resource": resource, "namespace": "default", "name": "x",
                               "apiVersion": "v1"},
                 "responseStatus": {"code": 200}}
            if safe is not None:
                e["requestObject"] = {"data": {"safe": safe}}
            return e
        body_cases = [
            ("update-unsafe", "positive", ev2("update", "configmaps", "Request", "no")),
            ("get-unsafe", "positive", ev2("get", "configmaps", "Request", "no")),
            ("get-safe", "filtered", ev2("get", "configmaps", "Request", "yes")),
            ("update-secret-meta", "near-miss", ev2("update", "secrets", "Metadata")),
            ("get-secret-meta", "near-miss", ev2("get", "secrets", "Metadata"))]
        with open(os.path.join(tmp, "T9/body.cases.jsonl"), "w", encoding="utf-8") as fh:
            for name, kind, e in body_cases:
                fh.write(json.dumps({"name": name, "kind": kind, "why": "self-test",
                                     "breaks": "sel", "events": [e]}) + "\n")
        # get configmaps at Metadata (the body is gone); everything else at Request (a
        # Metadata case record lacks the body that the policy logs: not-modeled).
        pol = kpc.policy_from_rules(
            [{"level": "Metadata", "verbs": ["get"],
              "resources": [{"group": "", "resources": ["configmaps"]}]},
             {"level": "Request"}], omit_stages=("RequestReceived",))
        base_res, _ = kpc.run_rule(os.path.join(tmp, "T9/body.yml"), {"p": (pol, None)})
        st = replay_stores({"rules": {"T9/body.yml": {}}}, tmp, {"p": (pol, None)},
                           {"p+gke_admin_activity": ("p", "gke_admin_activity")})
        st = st.get("p+gke_admin_activity", {}).get("T9/body.yml", {})

        def brief(r):
            return ([(x["case"], x["reason"]) for x in r["positives"]["lost"]],
                    [(x["case"], x["reason"]) for x in r["negatives_firing"]],
                    r["not_modeled_reads"])
        check("store replay: the policy alone keeps the read cases (an fp, two not-modeled "
              "events)", brief(base_res["p"]) == ([], [("get-safe", "body-removed")], 2),
              brief(base_res["p"]))
        check("store replay: the store drops the read cases (a positive without a record, "
              "no fp, one not-modeled event)",
              bool(st) and brief(st) == ([("get-unsafe", "no-record")], [], 1),
              brief(st) if st else st)
    # The replays load the policies that policy_coverage.json names, with their digests.
    rel = "detections/k8s/audit-policy.yaml"
    one = {"policy_order": ["x"], "policies": {"x": {
        "files": [{"path": rel, "sha256": sha256_file(os.path.join(REPO, rel))}],
        "log_filter": {"drop_verbs": ["get"], "source": "x"}}}}
    got = policies_from_pc(one, kpc)
    check("policies_from_pc loads the listed file and keeps the log filter",
          set(got) == {"x"} and got["x"][0]["rules"] and got["x"][1]["drop_verbs"] == ["get"])
    one["policies"]["x"]["files"][0]["sha256"] = "0" * 64
    try:
        policies_from_pc(one, kpc)
        msg = ""
    except InputError as exc:
        msg = str(exc)
    check("policies_from_pc stops on a file whose digest differs from the JSON",
          "has SHA-256" in msg and "--update first" in msg, msg)


def self_test():
    fails = []

    def check(name, cond, detail=""):
        tail = f": {detail}" if detail and not cond else ""
        print(("ok   " if cond else "FAIL ") + name + tail)
        if not cond:
            fails.append(name)

    def raises(name, fn, needle):
        try:
            fn()
        except InputError as exc:
            check(name, needle in str(exc), f"message {exc!s}")
            return
        check(name, False, "no InputError")

    exists = lambda path: True  # noqa: E731
    test_graders = {"T1/grader.yml": "T1/choke.yml"}

    def render_blocks_t(pc, mr, cases, exists, q, graders=test_graders):
        return render_blocks(pc, mr, cases, exists, graders, q["pairs"], q["stores"])
    pc, mr, cases, pairs = _fixture()
    b = render_blocks_t(pc, mr, cases, exists, pairs)
    cov = b["platform-coverage"]
    g, c, e, i, n = (_row(cov, r) for r in ("T1/grader.yml", "T1/choke.yml", "T2/exec.yml",
                                            "T3/imp.yml", "T4/np.yml"))
    col = lambda sid: _col(sid, pc)  # noqa: E731
    check("full", c[col("aks")] == "**full** 1/1", c[col("aks")])
    check("partial with not-modeled", g[col("eks")] == "**partial** 1/2; body-removed 1; "
          "not-modeled 4", g[col("eks")])
    check("chokepoint only: grader blind, chokepoint full, replay has no miss",
          g[col("os-default")] == "**chokepoint only** 0/2; body-removed 2; chokepoint 2/2",
          g[col("os-default")])
    check("chokepoint partial: the replay shows a miss",
          g[col("os-default-4.17")] == "**chokepoint partial** 0/2; body-removed 2; "
          "chokepoint 1/2", g[col("os-default-4.17")])
    check("approved loss of a positive + approved block diff on GKE",
          g[col("gke")] == "**partial** 1/2; approved-loss 1; approved-diff 1", g[col("gke")])
    check("a loss in the sorted variant only has its own code",
          g[col("aks")] == "**partial** 1/2; approved-loss-if-sorted 1", g[col("aks")])
    check("lab column names the home policy", g[col("lab")] == "**full** 2/2 `lab-apiserver`",
          g[col("lab")])
    check("list-text mark", "grader`](../sigma/T1/grader.yml) L" in cov)
    check("AKSAuditAdmin: a filter drop is reads-dropped",
          e[col("aks-admin")] == "**partial** 2/3; reads-dropped 1", e[col("aks-admin")])
    check("raw kube-audit-admin: the same drop, no mapping",
          e[col("aks-raw-admin")] == "**partial** 2/3; reads-dropped 1", e[col("aks-raw-admin")])
    check("GKE Admin Activity: get and watch positives are lost",
          e[col("gke-admin")] == "**partial** 1/3; reads-dropped 2", e[col("gke-admin")])
    check("no-record shows the policy rule index and fp",
          e[col("os-default-4.17")] == "**partial** 2/3; no-record 1 #0; fp 1",
          e[col("os-default-4.17")])
    check("not portable: the bracket counts what the policy and the store keep",
          i[col("aks")] == "**not portable** (1/1 by policy and store); not-in-schema: "
          "`impersonatedUser.username`", i[col("aks")])
    check("not portable and the store keeps nothing (AKSAuditAdmin): blind, field as a code",
          i[col("aks-admin")] == "**blind** 0/1; not-in-schema: `impersonatedUser.username`; "
          "reads-dropped 1", i[col("aks-admin")])
    check("not portable and the store keeps nothing (GKE Admin Activity): blind",
          i[col("gke-admin")] == "**blind** 0/1; not-in-schema: `responseStatus.code`; "
          "reads-dropped 1", i[col("gke-admin")])
    check("not portable, the store keeps some: reads-dropped stays",
          n[col("gke-admin")] == "**not portable** (1/2 by policy and store); not-in-schema: "
          "`requestURI`; reads-dropped 1", n[col("gke-admin")])
    check("raw AKS shape keeps an AKSAudit-not-portable rule",
          i[col("aks-raw")] == "**full** 1/1", i[col("aks-raw")])
    check("fp on a chokepoint", c[col("eks")] == "**full** 1/1; fp 1", c[col("eks")])
    check("GKE Data Access on: the policy's not-modeled read event and fp count",
          c[col("gke")] == "**full** 1/1; not-modeled 2; fp 1", c[col("gke")])
    check("GKE Admin Activity: not-modeled and fp come from the store replay (no read)",
          c[col("gke-admin")] == "**full** 1/1; not-modeled 1", c[col("gke-admin")])
    check("opt-in loss under the recommended policy",
          g[col(f"x-{RECOMMENDED}")] == "**partial** 1/2; opt-in 1", g[col(f"x-{RECOMMENDED}")])
    check("every policy in policy_order is in the summary table",
          all(f"| `{p}` |" in cov for p in pc["policy_order"]))
    check("the recommended policy gets its own column",
          f"Self-managed, `{RECOMMENDED}`" in cov and len(g) == len(SHAPES) + 2)
    check("warnings rendered", "- `eks`: w1" in cov)
    check("column legend sentences start in upper case",
          "native Event. The lab policy of the validator" in cov
          and "native Event. Label of openshift-default." in cov, cov[:900])
    check("the word tally has every word",
          "| Shape | full | partial | chokepoint only | chokepoint partial | blind | "
          "not portable |" in cov)
    pr = b["platform-pairs"]
    check("pairs block: misses grouped by policy and store",
          "| `T1/grader` | `T1/choke` | 2 | `lab-apiserver`, `eks`, `gce-kube-up`, "
          "`aks-kube-audit`, `aks-kube-audit-admin`, `openshift-default`, `openshift-wrb`, "
          "`openshift-wrb-4.17`, `k3s-starter`, `recommended`, `gce-kube-up` + store "
          "`gke_admin_activity` | `openshift-default-4.17`: 1/2, `p-patch` |" in pr, pr)
    nd = b["platform-needs"]
    check("needs rows", "| `T2/exec` | Metadata | `core/pods`: watch<br>"
          "`core/pods/exec`: create, get |  |" in nd, nd)
    check("needs null level", "| `T1/grader` | no uniform level | no requests | "
          "no uniform level |" in nd, nd)
    check("needs absent for a rule", "| `T1/choke` | not computed | | |" in nd)
    rec = b["platform-recommended"]
    check("recommended block links its first file",
          "[`detections/k8s/audit-policy-recommended.yaml`](audit-policy-recommended.yaml)"
          in rec, rec)
    first = rec.split("\n")[2]
    check("recommended block starts with an upper-case sentence and names the version",
          first == "**Label of recommended**: [`detections/k8s/audit-policy-recommended."
          "yaml`](audit-policy-recommended.yaml). Version: v.", first)
    check("recommended summary line", "2 of 5 rules fire on every positive case" in rec, rec)
    check("recommended block names the opt-in losses",
          "- `T1/grader`, `p-patch`: needs the opt-in line" in rec, rec)
    fp = b["platform-fp"]
    check("fp block lists provider policies only",
          "| `openshift-default-4.17` | `T2/exec` | `T2/exec.yml-dry` |" in fp
          and "`lab-apiserver`" not in fp.split("\n", 3)[-1], fp)
    pc5, mr5, cases5, q5 = _fixture()
    pc5["rules"]["T1/choke.yml"]["results"]["lab-apiserver"]["negatives_firing"] = [
        {"case": "T1/choke.yml-dry", "kind": "filtered", "reason": "body-removed"}]
    fp5 = block_fp(pc5, mr5, cases5, q5["stores"], store_columns(pc5))
    check("fp block leaves out a lab policy's firing negative",
          "| `lab-apiserver` |" not in fp5 and "| `eks` | `T1/choke` |" in fp5, fp5)
    pc6, mr6, cases6, q6 = _fixture()
    mr6["rules"]["T1/choke.yml"]["providers"]["gke"].update(
        status="expected_loss", expected_loss={"c-get-recon": {
            "diff": "all: native quiet, gke fires; blocks filter_x", "why": "W"}})
    c6 = _row(render_blocks_t(pc6, mr6, cases6, exists, q6)["platform-coverage"],
              "T1/choke.yml")
    check("a mapping fp on a negative that already fires counts once; a store without "
          "reads drops a read-only one",
          (c6[col("gke")], c6[col("gke-admin")])
          == ("**full** 1/1; not-modeled 2; fp 1", "**full** 1/1; not-modeled 1"),
          (c6[col("gke")], c6[col("gke-admin")]))
    pc7v, mr7v, cases7v, q7v = _fixture()
    mr7v["providers"]["gke"]["variants"] = ["compact", "sorted"]
    mr7v["rules"]["T1/grader.yml"]["providers"]["gke"]["expected_loss"]["p-patch"][
        "diff"] = ("compact: native fires, gke quiet; blocks sel_a | "
                   "sorted: native fires, gke quiet; blocks sel_a, sel_b")
    g7v = _row(render_blocks_t(pc7v, mr7v, cases7v, exists, q7v)["platform-coverage"],
               "T1/grader.yml")
    check("a loss in every variant (different blocks) is a plain approved-loss",
          g7v[col("gke")] == "**partial** 1/2; approved-loss 1; approved-diff 1",
          g7v[col("gke")])
    check("fp block: a read fp is under the policy, not under the store without reads",
          "| `gce-kube-up` | `T1/choke` | `c-get-recon` |" in fp
          and "store `gke_admin_activity` | `T1/choke`" not in fp, fp)
    # deterministic: shuffled key order gives the same text
    pc2, mr2, cases2, pairs2 = _fixture()
    pc2["rules"] = dict(reversed(list(pc2["rules"].items())))
    pc2["policies"] = dict(reversed(list(pc2["policies"].items())))
    mr2["rules"] = dict(reversed(list(mr2["rules"].items())))
    pc2["rules"]["T2/exec.yml"]["needs"]["requests"].reverse()
    check("deterministic (key order, request order)",
          render_blocks_t(pc2, mr2, cases2, exists, pairs2) == b)
    pc4, mr4, cases4, pairs4 = _fixture()
    pc4["policies"][RECOMMENDED]["kind"] = "lab"
    check("a recommended policy of kind lab still gets its column",
          f"Self-managed, `{RECOMMENDED}`" in render_blocks_t(pc4, mr4, cases4, exists, pairs4)[
              "platform-coverage"])
    pc5, mr5, cases5, pairs5 = _fixture()
    for pid in pairs5["pairs"]["T1/grader.yml"]:
        pairs5["pairs"]["T1/grader.yml"][pid] = ["p-create", "p-patch"]
    g5 = _row(render_blocks_t(pc5, mr5, cases5, exists, pairs5)["platform-coverage"],
              "T1/grader.yml")
    check("blind when the chokepoint misses every grader positive",
          g5[col("os-default")] == "**blind** 0/2; body-removed 2; chokepoint 0/2",
          g5[col("os-default")])
    pc6, mr6, cases6, pairs6 = _fixture()
    pc6["rules"]["T1/choke.yml"]["results"]["openshift-default"] = {
        "positives": {"total": 1, "firing": 0, "lost": [{"case": "c-create",
                                                         "reason": "body-removed",
                                                         "policy_rules": [1]}]},
        "near_misses": {}, "negatives_firing": [], "not_modeled": 0, "not_modeled_reads": 0}
    g6 = _row(render_blocks_t(pc6, mr6, cases6, exists, pairs6)["platform-coverage"],
              "T1/grader.yml")
    check("blind when the chokepoint's own cell is not full",
          g6[col("os-default")] == "**blind** 0/2; body-removed 2; chokepoint not full "
          "(blind)", g6[col("os-default")])
    pc8, mr8, cases8, q8 = _fixture()
    for r8 in (pc8["rules"]["T1/grader.yml"]["results"]["gce-kube-up"],
               q8["stores"][GKE_STORE]["T1/grader.yml"]):
        r8["positives"].update(firing=0, lost=[
            {"case": x, "reason": "body-removed", "policy_rules": [2]}
            for x in ("p-create", "p-patch")])
    q8["pairs"]["T1/grader.yml"][GKE_STORE] = ["p-patch"]
    g8 = _row(render_blocks_t(pc8, mr8, cases8, exists, q8)["platform-coverage"],
              "T1/grader.yml")
    check("the chokepoint replay of a store without reads is the store's, not the policy's",
          (g8[col("gke")], g8[col("gke-admin")])
          == ("**chokepoint only** 0/2; body-removed 2; approved-diff 1; chokepoint 2/2",
              "**chokepoint partial** 0/2; body-removed 2; approved-diff 1; chokepoint 1/2"),
          (g8[col("gke")], g8[col("gke-admin")]))
    # absent needs and recommended
    pc3, mr3, cases3, pairs3 = _fixture()
    for r in pc3["rules"].values():
        r.pop("needs", None)
    pc3["policy_order"].remove(RECOMMENDED)
    del pc3["policies"][RECOMMENDED]
    del pc3["summary"][RECOMMENDED]
    for r in pc3["rules"].values():
        del r["results"][RECOMMENDED]
    del pairs3["pairs"]["T1/grader.yml"][RECOMMENDED]
    b3 = render_blocks_t(pc3, mr3, cases3, exists, pairs3)
    check("needs not computed yet", b3["platform-needs"].startswith(
        GENERATED + "\n\nThe needs data is not computed yet"))
    check("recommended not available yet", b3["platform-recommended"].startswith(
        GENERATED + "\n\nA recommended policy is not available yet"))
    check("no recommended column", f"`{RECOMMENDED}`" not in b3["platform-coverage"])
    # schema and consistency errors
    for name, mutate, needle in [
        ("unknown policy_coverage schema", lambda p, m, c, q: p.update(
            schema="det-eng/k8s-policy-coverage/v2"), "unknown schema"),
        ("unknown mapping_results schema", lambda p, m, c, q: m.update(schema=1),
         "mapping_results.json: unknown schema"),
        ("bad needs level", lambda p, m, c, q: p["rules"]["T2/exec.yml"]["needs"].update(
            level="Full"), "needs.level"),
        ("unsorted needs verbs", lambda p, m, c, q: p["rules"]["T2/exec.yml"]["needs"][
            "requests"][0].update(verbs=["get", "create"]), "sorted list"),
        ("duplicate needs request", lambda p, m, c, q: p["rules"]["T2/exec.yml"]["needs"][
            "requests"].append(dict(p["rules"]["T2/exec.yml"]["needs"]["requests"][1])),
         "unique"),
        ("a diverging mapping", lambda p, m, c, q: m["rules"]["T1/choke.yml"]["providers"][
            "gke"].update(status="diverges"), "diverges"),
        ("status same with not_portable fields", lambda p, m, c, q: m["rules"]["T4/np.yml"][
            "providers"]["gke"].update(status="same"), "disagrees with not_portable"),
        ("status expected_loss with no entry", lambda p, m, c, q: m["rules"]["T1/choke.yml"][
            "providers"]["aks"].update(status="expected_loss"), "no expected_loss entry"),
        ("status same with an expected_loss entry", lambda p, m, c, q: m["rules"][
            "T1/grader.yml"]["providers"]["gke"].update(status="same"), "status 'same' with"),
        ("a missing provider", lambda p, m, c, q: m["rules"]["T2/exec.yml"]["providers"].pop(
            "gke"), "providers has no gke"),
        ("missing loses_positive_without_reads", lambda p, m, c, q: m["rules"][
            "T2/exec.yml"].pop("loses_positive_without_reads"),
         "has no loses_positive_without_reads"),
        ("missing summary", lambda p, m, c, q: p["summary"].pop("eks"), "summary['eks']"),
        ("rule sets differ", lambda p, m, c, q: m["rules"].pop("T3/imp.yml"), "different rules"),
        ("missing platform policy", lambda p, m, c, q: (p["policy_order"].remove("eks"),
                                                        p["policies"].pop("eks")),
         "no policy 'eks'"),
        ("read verbs disagree with the harness", lambda p, m, c, q: m["rules"]["T2/exec.yml"][
            "loses_positive_without_reads"].update(gke_admin_activity=False), "disagree"),
        ("reads text drops a verb", lambda p, m, c, q: m["reads"].update(
            gke_admin_activity="no get or list"), "watch"),
        ("unknown lost reason", lambda p, m, c, q: p["rules"]["T1/grader.yml"]["results"][
            "eks"]["positives"]["lost"][0].update(reason="weird"), "unknown lost reason"),
        ("a rule with no positive case", lambda p, m, c, q: (
            c.__setitem__("T1/choke.yml", [x for x in c["T1/choke.yml"]
                                           if x["kind"] != "positive"])),
         "no positive case"),
        ("a stale opt-in loss", lambda p, m, c, q: p["policies"][RECOMMENDED][
            "opt_in_losses"]["T1/grader.yml"].update({"p-create": "x"}), "not a lost positive"),
        ("a replay without a policy", lambda p, m, c, q: q["pairs"]["T1/grader.yml"].pop(
            "eks"), "no result for T1/grader.yml"),
        ("a replay without the store", lambda p, m, c, q: q["pairs"]["T1/grader.yml"].pop(
            GKE_STORE), "every policy and replayed store"),
        ("a replay that names a non-positive", lambda p, m, c, q: q["pairs"][
            "T1/grader.yml"]["eks"].append("T1/grader.yml-dry"), "not its positives"),
        ("no store replay", lambda p, m, c, q: q["stores"].pop(GKE_STORE),
         "the store replay has results for []"),
        ("a store replay without a rule", lambda p, m, c, q: q["stores"][GKE_STORE].pop(
            "T4/np.yml"), "no result for every rule"),
        ("a store replay that keeps a read-only positive", lambda p, m, c, q: q["stores"][
            GKE_STORE]["T3/imp.yml"]["positives"].update(lost=[], firing=1),
         "the log filter drops [], the read verbs say ['i-get']"),
        ("a store without reads whose policy keeps a read-only positive (no sibling)",
         lambda p, m, c, q: (p["policies"]["aks-kube-audit"].update(files=[{"path": "x"}]),
                             p["rules"]["T3/imp.yml"]["results"]["aks-kube-audit-admin"][
                                 "positives"].update(lost=[], firing=1)),
         "keeps the read-only positive cases ['i-get'], which the store aksauditadmin"),
        ("a store replay with a wrong total", lambda p, m, c, q: q["stores"][GKE_STORE][
            "T1/choke.yml"]["positives"].update(total=2), "is not the sidecar's 1"),
        ("a firing count that is not total minus the lost cases", lambda p, m, c, q: p[
            "rules"]["T1/choke.yml"]["results"]["eks"]["positives"].update(firing=99),
         "minus the 0 lost case(s)"),
        ("a policy with a log filter that is not the store's", lambda p, m, c, q: p[
            "policies"]["gce-kube-up"].update(log_filter={"drop_verbs": ["get"]}),
         "the script cannot join them"),
    ]:
        p, m, cs, q = _fixture()
        mutate(p, m, cs, q)
        raises(name, lambda: render_blocks_t(p, m, cs, exists, q), needle)
    p7, m7, c7, q7 = _fixture()
    raises("recommended file must exist",
           lambda: render_blocks_t(p7, m7, c7, lambda path: False, q7), "does not exist")
    # document handling
    doc = "intro\n" + "".join(f"<!-- {n}:begin -->\nold\n<!-- {n}:end -->\n\n" for n in BLOCKS)
    new = apply_blocks(doc, b)
    check("write fills every block", not stale_blocks(new, b) and new.startswith("intro\n"))
    check("write is idempotent", apply_blocks(new, b) == new)
    check("stale block found", stale_blocks(new.replace("**full** 1/1", "**full** 9/9", 1), b)
          == ["platform-coverage"])
    raises("missing marker", lambda: split_doc(doc.replace("<!-- platform-fp:end -->", "")),
           "platform-fp:end")
    raises("duplicate marker", lambda: split_doc(doc + "<!-- platform-needs:begin -->"),
           "platform-needs:begin")
    # anchors
    with tempfile.TemporaryDirectory() as tmp:
        for d in ("detections/k8s", "detections/pipelines", "research/trr1/k8s", ".claude/x"):
            os.makedirs(os.path.join(tmp, d))
        dp = os.path.join(tmp, "detections", "k8s", "PLATFORMS.md")

        def write(rel, text):
            with open(os.path.join(tmp, rel), "w", encoding="utf-8") as fh:
                fh.write(text)
        write("detections/k8s/PLATFORMS.md",
              "# Title\n\n## Rules on each platform\n\n```\n## Not a heading\n```\n"
              "<a id=\"custom-id\"></a>\n"
              "[ok](#rules-on-each-platform) [bad](#no-such-section) [c](#custom-id)\n"
              "[out ok](../pipelines/README.md#gke) [setext](../pipelines/README.md#eks)\n"
              "[renamed](../pipelines/README.md#renamed) "
              "[code](../pipelines/README.md#not-a-heading)\n"
              "[out gone](../pipelines/GONE.md#x) [no anchor](../pipelines/README.md)\n")
        write("detections/pipelines/README.md", "# P\n\n## GKE\n\nEKS\n---\n\n"
              "`## not a heading`\n")
        write("research/trr1/k8s/README.md",
              "[a](../../../detections/k8s/PLATFORMS.md#rules-on-each-platform)\n"
              "[b](../../../detections/k8s/PLATFORMS.md#not-a-heading)\n"
              "[c](../../../detections/k8s/PLATFORMS.md)\n"
              "[t](../../../detections/k8s/PLATFORMS.md#titled-bad \"A title\")\n"
              "[r][p] [abs](/detections/k8s/PLATFORMS.md#abs-bad)\n"
              "[p]: ../../../detections/k8s/PLATFORMS.md#ref-bad\n"
              "`[code](../../../detections/k8s/PLATFORMS.md#in-code)`\n"
              "```\n[fenced](../../../detections/k8s/PLATFORMS.md#in-fence)\n```\n"
              "[ext](https://example.com/PLATFORMS.md#x) [other](../../other.md#x)\n")
        write(".claude/x/SKILL.md", "[s](../../detections/k8s/PLATFORMS.md#custom-id)\n"
              "[s2](<../../detections/k8s/PLATFORMS.md#angle-bad>)\n")
        bad, checked = bad_anchors(dp, tmp)
        got = sorted(x.split(" ")[0] for x in bad)
        want = sorted(["detections/k8s/PLATFORMS.md:9:", "detections/k8s/PLATFORMS.md:11:",
                       "detections/k8s/PLATFORMS.md:11:", "detections/k8s/PLATFORMS.md:12:",
                       "research/trr1/k8s/README.md:2:",
                       "research/trr1/k8s/README.md:4:", "research/trr1/k8s/README.md:5:",
                       "research/trr1/k8s/README.md:6:", ".claude/x/SKILL.md:2:"])
        check("anchors: inbound (inline, titled, reference, root-absolute, angle brackets, "
              "under .claude), in-page, outbound (setext heading, missing file); code, "
              "external links and links without an anchor are skipped",
              got == want and checked == 15, f"{bad} checked={checked}")
        check("anchors: the message names the anchor, the target file, or a missing file",
              any(x.endswith("README.md#renamed (no heading of detections/pipelines/"
                             "README.md has the anchor #renamed)") for x in bad)
              and any(x.endswith("#ref-bad (no heading of detections/k8s/PLATFORMS.md has "
                                 "the anchor #ref-bad)") for x in bad)
              and any(x.endswith("GONE.md#x (no such file)") for x in bad), bad)
    check("slugs follow GitHub", slugs("## 2. What it needs (MP8)!\n## Rules\n## Rules\n"
                                       "### K45. `k8s_x`: the [link](u) <b>b</b>\nSet\n===\n")
          == {"2-what-it-needs-mp8", "rules", "rules-1", "k45-k8s_x-the-link-b", "set"},
          slugs("## 2. What it needs (MP8)!\n## Rules\n## Rules\n"
                "### K45. `k8s_x`: the [link](u) <b>b</b>\nSet\n===\n"))
    _self_test_replay(check)
    print(f"\n{len(fails)} failure(s)" if fails else "\nself-test passed")
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="rewrite the generated blocks")
    mode.add_argument("--check", action="store_true", help="fail when a block is stale (default)")
    mode.add_argument("--anchors", action="store_true",
                      help="fail on a bad anchor into, inside or out of PLATFORMS.md "
                           "(standard library only)")
    mode.add_argument("--self-test", action="store_true", help="run on constructed inputs")
    ap.add_argument("--policy-coverage", default=POLICY_COVERAGE)
    ap.add_argument("--mapping-results", default=MAPPING_RESULTS)
    ap.add_argument("--doc", default=DOC)
    ap.add_argument("--sigma", default=SIGMA)
    args = ap.parse_args()
    args.doc = os.path.abspath(args.doc)
    if args.self_test:
        return self_test()
    try:
        if args.anchors:
            return run_anchors(args)
        return run(args)
    except InputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        print(f"ERROR: malformed input ({type(exc).__name__}: {exc}); no text written",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
