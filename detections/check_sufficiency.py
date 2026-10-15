#!/usr/bin/env python3
"""
The check-sufficiency gate: fail a detection whose checks are easy to satisfy.

The validators prove that a rule fires on its emulation and stays silent on its
controls, and rule_cases.py proves that each sidecar case holds. Neither asks
whether those checks would catch a plausible WRONG rule. A rule tested only
against a no-op, an unrelated event or a pre-emulation baseline passes every
validator while its argument constraints, filters and correlation halves stay
untested. This gate asks that question for every rule file
detections/sigma/<T>/<stem>.yml, offline, through the same pySigma SQLite
backend (sigma_eval) and the same item-by-item grading (sigma_explain):

  R0 loads       the rule compiles and sigma_explain can split it into items.
                 Repository hygiene is R0 too: detections/sigma/ may hold only
                 T<id>/<stem>.yml rules, their T<id>/<stem>.cases.jsonl sidecars
                 and *.md notes. Anything else (another extension, a nested
                 directory, a hidden file, a symlink) fails the run before
                 pySigma is imported: the directory shares the `sigma` package
                 namespace with pySigma, and a rule hidden one level down is
                 never checked.
  R1 positive    the rule is a positive in some validator MANIFEST (auditd,
                 cloud, API server, TRR9002, TRR9003), or it is listed in
                 COMPILE_ONLY below for a documented telemetry gap. A
                 COMPILE_ONLY rule still needs a passing sidecar positive.
  R2 negatives   at least one VERIFIED non-trivial negative that breaks a
                 DISCRIMINATING item (a selection item outside SURFACE_FIELDS:
                 an argument, a provenance field, a policy pattern) or a
                 filter. A verified negative is a sidecar case of kind
                 near-miss or filtered that passed (rule_cases.run_rule checks
                 it is one item flip from firing, on the item it declares), or,
                 for a cloud rule, a record of its hard benign fixture that
                 sigma_explain grades near-miss or filtered. Trivial and
                 distant negatives, no-op controls and pre-emulation baselines
                 do not count: they would also pass for a rule with a wrong
                 argument or a dead filter. Neither does a negative that breaks
                 only the surface (syscall, verb, eventName, ...): it passes
                 just as well for the rule with its argument deleted, the
                 commonest wrong rule (afxdp_socket without `a0: '2c'` fires on
                 every socket() and still rejects a bind()). When the only
                 negatives that count break filters, R2 passes and R5 warns: a
                 filtered case proves the allowlist suppresses, not that the
                 selection is specific, and a synthetic filtered case can verify
                 a filter on a field the log source never writes.
                 A PURE-SURFACE rule (every positive item is a SURFACE_FIELDS
                 field, so it matches every record of one kind) has no argument
                 a negative could break, and it is exactly the shape a rule takes
                 when it loses its argument. It fails R2 unless a human lists it
                 in CHOKEPOINT below, with the reason the record kind itself is
                 the technique; then any verified negative counts.
  R3 cases hold  every sidecar case passes, every sidecar parses, and no
                 sidecar exists without its rule.
  R4 not name-keyed
                 the rule keys on the technique, not on the names the repo's
                 emulations give their objects:
                 - its detection names no emulation literally (trr9NNN, deteng_);
                 - the RENAME TEST, every platform: each positive unit (every
                   passing sidecar positive case, and for a cloud rule every
                   attack fixture record it fires on that carries the
                   validator gate's marker) must still fire after every
                   emulation name (/trr9\\d{3}/i, `deteng_`) and every gate
                   marker in it is replaced by a neutral token of the same
                   length and character classes. A rule that stops firing keys
                   on the emulation's naming, however its regex spells the
                   name (`rr9026`, `tr?9026`, `ssrf-demo`). A rule with no
                   positive unit to rename fails: the test cannot run;
                 - (cloud) every MANIFEST gate of the rule is a marker(substr,
                   *fields): it carries `.substr` and `.fields` and answers as
                   marker() does on every attack, benign and renamed record.
                   Any other gate (a lambda, a wrapper) hides its marker, so
                   the rename test cannot know what to rename;
                 - its verified negatives must not ALL break only name-keyed
                   items: items whose truth on a positive unit flips under the
                   rename. Such negatives differ from the attack only in the
                   emulation's naming, so they do not show that the rule keys
                   on the technique. Renaming, rather than "the item reads a
                   gate field", is what decides: a gate field such as Glue's
                   requestParameters.policyInJson carries both the marker and
                   the technique (the public Principal), and a negative that
                   changes the Principal is a real negative.
  R5 thin        (warning only, never fails) items exercised by verified
                 negatives versus the rule's item count. Warns when that ratio
                 is below half the median of the rule's platform (linux /
                 kubernetes / cloud; the median is over rules that have any
                 verified negative), or when the negatives break no
                 discriminating selection item (only filters).

An atom (item) is what rule_cases.py calls one: `<block>.<field>`,
`<block>[i].<field>` inside a list of maps, `<block>` for a keyword list, and for
a correlation rule `base:<name>`, `group-by`, `timespan`, `threshold`.
"Exercised" counts the items a verified negative flips: the declared `breaks` of
a sidecar case, or every single flip sigma_explain finds for a fixture record.

Waivers: there are none beyond COMPILE_ONLY and CHOKEPOINT. A human edits those
dicts, with a reason, and a change to this file needs a human approval before
merge.

Usage:
    python3 detections/check_sufficiency.py                      # the gate
    python3 detections/check_sufficiency.py --rule detections/sigma/T1040/afinet_raw_socket.yml
    python3 detections/check_sufficiency.py -v                   # list each rule's negatives
    python3 detections/check_sufficiency.py --json out.json --markdown "$GITHUB_STEP_SUMMARY"
"""

import argparse
import glob
import json
import os
import re
import statistics
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA = os.path.join(REPO, "detections", "sigma")

# ---- repository hygiene (R0), before pySigma is imported --------------------

TECHNIQUE_DIR = re.compile(r"T\d{4}(\.\d{3})?")
RULE_MATERIAL = re.compile(r"[^./][^/]*\.(yml|cases\.jsonl|md)")


def unexpected_sigma_files():
    """Entries under detections/sigma/ that are not rule material (R0).

    Allowed: T<id>/<stem>.yml, T<id>/<stem>.cases.jsonl, T<id>/*.md and *.md at
    the top. A directory is reported once, with a trailing slash.
    """
    def name(entry, prefix=""):
        return prefix + entry.name + ("/" if entry.is_dir(follow_symlinks=False) else "")

    bad = []
    if not os.path.isdir(SIGMA):
        return ["(detections/sigma/ itself is missing)"]
    for entry in sorted(os.scandir(SIGMA), key=lambda e: e.name):
        if entry.is_dir(follow_symlinks=False) and TECHNIQUE_DIR.fullmatch(entry.name):
            for item in sorted(os.scandir(entry.path), key=lambda e: e.name):
                if not (item.is_file(follow_symlinks=False) and RULE_MATERIAL.fullmatch(item.name)):
                    bad.append(name(item, entry.name + "/"))
        elif not (entry.is_file(follow_symlinks=False) and entry.name.endswith(".md")
                  and not entry.name.startswith(".")):
            bad.append(name(entry))
    return bad


def hygiene_errors(unexpected):
    return [f"R0: unexpected `detections/sigma/{p}`: detections/sigma/ holds only "
            "T<id>/<stem>.yml rules, their <stem>.cases.jsonl sidecars and *.md notes (no "
            "other extension, nested directory, hidden file or symlink: a rule one level down "
            "is never checked, and the directory shares pySigma's `sigma` namespace); move "
            "or delete it" for p in unexpected]


def _arg_parser():
    ap = argparse.ArgumentParser(
        description="Fail a detection whose checks are easy to satisfy (R0-R4); warn on thin "
                    "checks (R5).")
    ap.add_argument("--rule", action="append", default=[], metavar="PATH",
                    help="check only this rule (repeatable); medians still use every rule")
    ap.add_argument("--json", metavar="PATH", help="write the full result as JSON")
    ap.add_argument("--markdown", metavar="PATH",
                    help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list every rule's verified negatives and rename analysis")
    return ap


def _hygiene_exit(unexpected):
    """Report unexpected files under detections/sigma/ without importing pySigma."""
    args = _arg_parser().parse_args()
    errors = hygiene_errors(unexpected)
    line = f"{len(errors)} unexpected file(s) under detections/sigma/ (R0); no rule was checked"
    print("Check sufficiency: repository hygiene (R0) fails, so pySigma was not imported:")
    for e in errors:
        print(f"  [ERROR] {e}")
    print(f"\nFAILED: {line}.")
    if args.markdown:
        with open(args.markdown, "a", encoding="utf-8") as fh:
            fh.write("\n".join(["## Check sufficiency", "", f"**FAIL**: {line}.", "",
                                "### Failures", ""] + [f"- **error**: {e}" for e in errors])
                     + "\n\n")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"summary": {"rules": 0, "ok": False, "errors": errors}, "rules": []},
                      fh, indent=2)
            fh.write("\n")
    return 1


if __name__ == "__main__":
    _UNEXPECTED = unexpected_sigma_files()
    if _UNEXPECTED:
        sys.exit(_hygiene_exit(_UNEXPECTED))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rule_cases  # noqa: E402
import sigma_eval  # noqa: E402
import sigma_explain  # noqa: E402

# Rules no validator can match-gate, because CI does not collect their telemetry.
# Each still needs a passing positive in its sidecar. Adding an entry is a waiver
# of R1: a human decides it, with the reason, and approves the change.
COMPILE_ONLY = {
    "T1552.007/linux_k8s_sa_token_read.yml":
        "node file-access telemetry (open of the projected service-account token) is not "
        "collected on the kind CI cluster; validate_apiserver_detections.py compiles the rule "
        "but cannot match-gate it",
    "T1543.005/linux_static_pod_manifest_write.yml":
        "node file-write telemetry (a manifest dropped in the kubelet's staticPodPath) is not "
        "collected on the kind CI cluster; validate_staticpod_detections.py compiles the rule "
        "but cannot match-gate it",
}

# Pure-surface rules: every positive item is a SURFACE_FIELDS field, so the rule
# matches every record of one kind (minus its filters). That is the shape a rule
# takes when it loses its argument, so R2 fails it unless a human states here why
# the record kind itself is the technique (a chokepoint). An entry waives the
# discriminating-negative part of R2 only: the rule still needs a verified negative.
# PRESENCE rules: one positive item, no filter. Such a rule fires on the mere
# presence of one field or value, so no negative can be one item flip from firing
# (a record without the field shares nothing with the rule: it grades trivial,
# exactly like an unrelated record). Its proof is the positive case plus the
# benign corpus: the rule must be scored there, under a budget. A human decides
# each entry, with the reason, and approves the change.
PRESENCE = {
    "T1134/k8s_impersonation.yml":
        "TRR9009: any request carrying impersonatedUser is the technique; the API server "
        "stamps it only for an impersonated request, so presence is the chokepoint",
    "T1053.007/k8s_cri_job_pod.yml":
        "TRR9005 node-runtime fallback: a pod sandbox carrying the job-name label is a Job's "
        "pod; a low-severity hunting rule bounded by its benign-corpus budget",
    "T1543.005/k8s_cri_static_pod_start.yml":
        "TRR9003 chokepoint: the kubelet stamps config.source file/http only on a pod it ran "
        "from a node-local or URL manifest (api otherwise)",
}

CHOKEPOINT = {
    "T1053.007/k8s_job_create.yml":
        "TRR9005 chokepoint: every Job/CronJob procedure is a batch/v1 write; the "
        "controllers' own writes are filtered",
    "T1068/keyring_add_key_burst.yml":
        "add_key(2) itself is the keyring-stuffing primitive; the keyring users are filtered",
    "T1068/perf_event_open_non_profiler.yml":
        "perf_event_open(2) itself is the escalation surface; profilers are filtered",
    "T1068/userfaultfd_syscall.yml":
        "userfaultfd(2) itself is the exploit timing primitive and is rare outside CRIU/QEMU",
    "T1070/k8s_events_deleted.yml":
        "TRR9010 chokepoint: deleting Events is the evidence removal",
    "T1070/k8s_workload_deleted_evidence.yml":
        "TRR9010 low-fidelity fallback by design: any pod/job delete",
    "T1098.001/azure_managed_identity_federated_credential_backdoor.yml":
        "the Activity Log carries no issuer/subject, so the FIC write operation is the "
        "whole signal (TRR9013 procedure C)",
    "T1098.006/k8s_rbac_write.yml":
        "TRR9004 chokepoint: every grant passes through an RBAC write",
    "T1546/k8s_admission_webhook_created.yml":
        "TRR9025 chokepoint: creating an admission controller object",
    "T1552.007/k8s_secret_access.yml":
        "TRR9006 chokepoint: every API read of a Secret",
    "T1552.007/k8s_secret_token_request.yml":
        "TRR9006 fallback: the TokenRequest create itself; system minters are filtered",
    "T1572/k8s_pod_portforward.yml":
        "TRR9026 chokepoint: the pods/portforward subresource is the tunnel",
    "T1609/k8s_pod_ephemeral_container.yml":
        "TRR9002 strategy 2: a write to pods/ephemeralcontainers is the injection",
    "T1609/k8s_pod_exec_attach.yml":
        "TRR9002 chokepoint: the pods/exec and pods/attach subresources",
    "T1611/setns_namespace_join.yml":
        "setns(2) itself is the namespace-join primitive; container runtimes are filtered",
    "T1685/io_uring_setup.yml":
        "creating or entering an io_uring ring is the sensor-evasion surface",
    "T1685/k8s_admission_webhook_disabled.yml":
        "TRR9008 chokepoint: any delete/update/patch of an admission control object",
}

# Validators whose MANIFEST registers positives: (label, module name).
VALIDATORS = (
    ("auditd", "validate_detections"),
    ("cloud", "validate_cloud_detections"),
    ("apiserver", "validate_apiserver_detections"),
    ("trr9002", "validate_k8s_detections"),
    ("trr9003", "validate_staticpod_detections"),
)

PLATFORM = {"linux": "linux", "kubernetes": "kubernetes",
            "aws": "cloud", "azure": "cloud", "gcp": "cloud"}

# Where a new positive for each platform is registered (for R1 messages).
REGISTER_HINT = {
    "linux": "validate_detections.py MANIFEST (rule, atomic source, args, kernel probes)",
    "kubernetes": "validate_apiserver_detections.py MANIFEST (folder, rule, source, label, "
                  "note, emulation gate)",
    "cloud": "validate_cloud_detections.py MANIFEST (trr, folder, rule, attack fixture, "
             "benign fixture, provider, note, marker(...))",
}

# Fields that name WHERE a technique happens (the log record's kind) or its
# generic outcome, not WHAT makes it the technique. A negative should keep these
# and break a discriminating item; breaking only these proves little.
SURFACE_FIELDS = {
    # auditd
    "type", "syscall", "success",
    # Kubernetes audit
    "verb", "objectRef.resource", "objectRef.subresource", "objectRef.apiGroup", "stage",
    # CloudTrail
    "eventSource", "eventName", "eventType", "userIdentity.type",
    "userIdentity.sessionContext.sessionIssuer.type",
    # GCP Cloud Audit Logs
    "protoPayload.serviceName", "protoPayload.methodName", "operation.first",
    # Azure / Entra
    "category", "operationName", "properties.category", "properties.loggedByService",
    "properties.activityDisplayName", "properties.operationName", "properties.result",
    "properties.resultType", "properties.status.errorCode",
}

# Names the repo's emulations give their objects. A rule that matches one keys
# on the emulation, not the technique (R4, every platform).
EMULATION_NAME = re.compile(r"trr9\d{3}|deteng_", re.IGNORECASE)

CHECKS = ("R0", "R1", "R2", "R3", "R4")


def rule_key(path):
    return os.path.relpath(path, SIGMA).replace(os.sep, "/")


def rel(path):
    return os.path.relpath(path, REPO).replace(os.sep, "/")


def platform_of(rule):
    return PLATFORM.get(str(rule.logsource.get("product") or "").lower(), "other")


# ---- validator manifests ---------------------------------------------------


def _entry_rule_path(module, entry):
    """The rule file a MANIFEST entry registers, whatever the tuple's shape.

    The validators' tuples differ: validate_detections names a repo-relative
    path, the cloud and API-server validators a technique folder plus a file
    name, and the TRR9002/TRR9003 validators a file name inside RULES_DIR.
    """
    ymls = [x for x in entry if isinstance(x, str) and x.endswith(".yml")]
    if len(ymls) != 1:
        raise ValueError(f"cannot find the rule file in MANIFEST entry {entry!r:.120}")
    name = ymls[0]
    if "/" in name:
        return os.path.normpath(os.path.join(REPO, name))
    folder = next((x for x in entry if isinstance(x, str)
                   and re.fullmatch(r"T\d{4}(\.\d{3})?", x)), None)
    base = os.path.join(SIGMA, folder) if folder else getattr(module, "RULES_DIR", None)
    if base is None:
        raise ValueError(f"MANIFEST entry {entry!r:.120} names no folder and "
                         f"{module.__name__} has no RULES_DIR")
    return os.path.normpath(os.path.join(base, name))


def _declared_marker(gate):
    """{"substr", "fields"} a marker() gate carries as attributes, or None.

    validate_cloud_detections.marker(substr, *fields) sets `.substr` and `.fields`
    on the gate it returns. Any other callable (a lambda, a wrapper) declares no
    marker, and check_rule fails it: the rename test must know what to rename.
    """
    substr, fields = getattr(gate, "substr", None), getattr(gate, "fields", None)
    if (callable(gate) and isinstance(substr, str) and substr
            and isinstance(fields, (tuple, list)) and fields
            and all(isinstance(f, str) and f for f in fields)):
        return {"substr": substr, "fields": list(fields)}
    return None


def _cloud_entry(module, entry):
    """Attack / benign fixtures and the marker of one cloud MANIFEST entry."""
    jsons = [x for x in entry if isinstance(x, str) and x.endswith(".json")]
    benign = next((j for j in jsons if "benign" in os.path.basename(j)), None)
    attack = next((j for j in jsons if j != benign), None)
    gate = next((x for x in entry if callable(x)), None)
    marker = _declared_marker(gate)
    fix = getattr(module, "FIX", os.path.join(REPO, "detections", "cloud", "fixtures"))
    return {"attack": os.path.join(fix, attack) if attack else None,
            "benign": os.path.join(fix, benign) if benign else None,
            "gate": gate, "marker": marker,
            "load": getattr(module, "load_fixture", None)}


def load_manifests():
    """({rule key: [validator label, ...]}, {rule key: [cloud entry, ...]}, errors)."""
    import importlib

    positives, cloud, errors = {}, {}, []
    for label, name in VALIDATORS:
        try:
            module = importlib.import_module(name)
            manifest = module.MANIFEST
        except Exception as e:  # noqa: BLE001 - a broken validator must not pass silently
            errors.append(f"could not import {name}.MANIFEST: {type(e).__name__}: {e}")
            continue
        for entry in manifest:
            try:
                key = rule_key(_entry_rule_path(module, entry))
            except ValueError as e:
                errors.append(f"{name}: {e}")
                continue
            if label not in positives.setdefault(key, []):
                positives[key].append(label)
            if label == "cloud":
                cloud.setdefault(key, []).append(_cloud_entry(module, entry))
    return positives, cloud, errors


# ---- rule items, for messages ----------------------------------------------


def _short(value, limit=60):
    text = json.dumps(value) if not isinstance(value, str) else f"'{value}'"
    return text if len(text) <= limit else text[:limit - 3] + "..."


def atom_spec(rule, atom):
    """`field|mods: value` as the rule writes the item, for a message."""
    if rule.is_correlation or atom not in getattr(rule, "block_of", {}):
        return f"`{atom}`"
    block = rule.block_of[atom]
    definition = rule.definitions.get(block)
    rest = atom[len(block):]
    m = re.match(r"\[(\d+)\]", rest)
    if m and isinstance(definition, list):
        definition = definition[int(m.group(1))]
        rest = rest[m.end():]
    if not rest:
        return f"`{atom}` (keywords `{_short(definition)}`)"
    field = rest.lstrip(".")
    if isinstance(definition, dict):
        for key, value in definition.items():
            if str(key).split("|")[0] == field:
                return f"`{atom}` (`{key}: {_short(value)}`)"
    return f"`{atom}`"


def surface_atoms(rule):
    if rule.is_correlation:
        return []
    return [a for a in rule.positive_atoms() if rule.item_field.get(a) in SURFACE_FIELDS]


def discriminating_atoms(rule):
    """Selection items that make the event the technique (not its surface)."""
    if rule.is_correlation:
        return list(rule.atoms)
    surface = set(surface_atoms(rule))
    return [a for a in rule.positive_atoms() if a not in surface]


def _surface_parts(rule):
    """"syscall: 'socket'; ..." from the rule's surface items ('' if none)."""
    parts = []
    for atom in surface_atoms(rule):
        spec = atom_spec(rule, atom)
        part = spec[spec.find("(") + 1:-1] if "(" in spec else atom
        if part not in parts:
            parts.append(part)
    return "; ".join(parts[:4]) + ("; ..." if len(parts) > 4 else "")


def _surface_text(rule):
    """'the surface (syscall: 'socket'; ...)' from the rule's surface items."""
    shown = _surface_parts(rule)
    return f"the surface ({shown})" if shown else None


def _cases_rel(path):
    return rel(rule_cases.cases_path(path))


def _negative_hint(rule, path, exclude=(), cloud_fixture=None, keep_extra=None):
    """'Add a near-miss case to X that keeps <surface> and breaks one of: <items>'."""
    target = f"`{_cases_rel(path)}`"
    if rule.is_correlation:
        bases = [a for a in rule.atoms if a.startswith("base:") and a not in exclude]
        other = [a for a in ("group-by", "timespan", "order", "threshold")
                 if a in rule.atoms and a not in exclude]
        text = f"Add a near-miss case to {target}: half a correlation, every event but one " \
               f"base's (breaks one of: {', '.join(bases) or '-'})"
        if other:
            text += f", or every base but in the wrong {'/'.join(other)} " \
                    f"(breaks one of: {', '.join(other)})"
        return text
    picks = [a for a in discriminating_atoms(rule) if a not in exclude]
    others = "every other item" if len(rule.positive_atoms()) > 1 else "the log source"
    if picks:
        keep = _surface_text(rule) or others
    else:
        # A pure chokepoint rule: its surface is the technique, so break part of it.
        picks = [a for a in rule.positive_atoms() if a not in exclude]
        keep = others
    if keep_extra:
        keep = f"{keep_extra} and {keep}"
    text = f"Add a near-miss case to {target} that keeps {keep} and breaks exactly one of: " \
           f"{', '.join(atom_spec(rule, a) for a in picks[:6])}"
    if len(picks) > 6:
        text += f" (+{len(picks) - 6} more; `rule_cases.py --atoms` lists them)"
    filters = [a for a in rule.negated_atoms() if a not in exclude]
    if filters:
        text += f"; or a filtered case (an allowlisted look-alike doing the positive's exact " \
                f"call) that trips one of: {', '.join(filters[:4])}"
    if cloud_fixture:
        text += f"; or add such a record to `{rel(cloud_fixture)}` (the fixture must stay " \
                "clean for every rule that reads it)"
    return text


# ---- marker analysis (R4) --------------------------------------------------


def _scramble(text):
    """Same length and character classes, different letters and digits."""
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        elif ch.isdigit():
            out.append(str((int(ch) + 5) % 10))
        else:
            out.append(ch)
    return "".join(out)


def rename_pattern(markers=()):
    """Every emulation name, and each gate marker (longest first, so a marker that
    contains an emulation name is renamed whole), case-insensitive."""
    alts = [re.escape(m) for m in sorted({m for m in markers if m}, key=len, reverse=True)]
    return re.compile("|".join(alts + [EMULATION_NAME.pattern]), re.IGNORECASE)


def rename_names(event, pattern):
    """The flat event with every match of `pattern` in a value replaced by a neutral
    token of the same length and character classes (see _scramble)."""
    return {k: pattern.sub(lambda m: _scramble(m.group(0)), v) if isinstance(v, str) else v
            for k, v in event.items()}


def _fires(rule, events):
    return bool(events) and bool(sigma_eval.EventTable(events).hit_indices(rule.sql))


def _flipped_atoms(rule, own, renamed):
    """Atoms whose truth on some event of the unit changes under the rename."""
    both = sigma_eval.EventTable(own + renamed)
    n = len(own)
    if rule.is_correlation:
        # A correlation's per-event unit is its base rules: a base is name-keyed
        # when the events it matches change under the rename.
        out = []
        for ref, base in rule.bases.items():
            hit = {i for h in both.hit_indices(base.sql) for i in h}
            if any((i in hit) != (n + i in hit) for i in range(n)):
                out.append(f"base:{ref}")
        return out
    rows, _ = rule.truth_table(both)
    return [a for a in rule.atoms if any(rows[i][a] != rows[n + i][a] for i in range(n))]


def rename_test(rule, units, pattern):
    """Rename the emulation's names in every positive unit; does each still fire?

    `units` is [(label, [flat events])], each a unit that fires the rule (a
    passing positive case, or one marker-carrying attack record / alert). Returns
    {"units", "renamed", "stopped": [{"unit", "names", "flipped"}], "name_keyed"}.
    """
    out = {"units": len(units), "renamed": 0, "stopped": [], "name_keyed": set()}
    for label, own in units:
        names = {}
        for e in own:
            for v in e.values():
                for m in pattern.finditer(v) if isinstance(v, str) else ():
                    names.setdefault(m.group(0).lower(), m.group(0))
        if not names:
            continue  # nothing to rename: the unit cannot show anything either way
        out["renamed"] += 1
        renamed = [rename_names(e, pattern) for e in own]
        flipped = _flipped_atoms(rule, own, renamed)
        out["name_keyed"] |= set(flipped)
        if not _fires(rule, renamed):
            out["stopped"].append({"unit": label, "flipped": flipped,
                                   "names": [names[k] for k in sorted(names)]})
    out["name_keyed"] = [a for a in rule.atoms if a in out["name_keyed"]]
    return out


def _gate_disagreement(gate, marker, records):
    """Where a gate that declares a marker does not answer as marker() would."""
    substr, fields = marker["substr"], marker["fields"]
    for label, record in records:
        want = any(substr in str(record.get(f) or "") for f in fields)
        try:
            got = bool(gate(record))
        except Exception as e:  # noqa: BLE001 - a crashing gate is no marker()
            return f"raises {type(e).__name__}: {e} on {label}"
        if got != want:
            return f"answers {got} on {label}, where marker() answers {want}"
    return None


def _attack_units(rule, entry):
    """Positive units from a cloud attack fixture: each record the rule fires on
    that carries the entry's marker (each marker-carrying alert, for a correlation).
    Returns (the fixture's records, [(label, [records])])."""
    marker = entry["marker"]
    attack = entry["load"](entry["attack"])

    def carries(record):
        return any(marker["substr"] in str(record.get(f) or "") for f in marker["fields"])

    hits = sigma_eval.EventTable(attack).hit_indices(rule.sql)
    if rule.is_correlation:
        return attack, [(f"{rel(entry['attack'])} alert on records #{', #'.join(map(str, hit))}",
                         [attack[j] for j in hit]) for hit in hits
                        if any(carries(attack[j]) for j in hit)]
    ours = sorted({i for hit in hits for i in hit if carries(attack[i])})
    return attack, [(_fixture_label(entry["attack"], attack, i), [attack[i]]) for i in ours]


# ---- one rule --------------------------------------------------------------


class Report:
    def __init__(self, path):
        self.path = path
        self.key = rule_key(path)
        self.rule = None
        self.platform = "other"
        self.positives = []
        self.compile_only = None
        self.cases_file = None
        self.case_total = self.case_passed = 0
        self.sidecar_positive = False
        self.negatives = []  # {"source", "kind", "atoms"}
        self.exercised = []
        self.positive_units = []  # (label, [flat events]) the rename test runs on
        self.rename = None
        self.failures = []  # (check, message)
        self.warnings = []

    def fail(self, check, message):
        self.failures.append((check, message))

    def warn(self, check, message):
        self.warnings.append((check, message))

    @property
    def status(self):
        return "FAIL" if self.failures else ("WARN" if self.warnings else "PASS")

    @property
    def atoms(self):
        return list(self.rule.atoms) if self.rule else []

    @property
    def ratio(self):
        return len(self.exercised) / len(self.atoms) if self.atoms else 0.0

    def to_json(self):
        return {
            "rule": self.key, "platform": self.platform, "status": self.status,
            "logsource": dict(self.rule.logsource) if self.rule else None,
            "positives": self.positives, "compile_only": self.compile_only,
            "chokepoint": CHOKEPOINT.get(self.key),
            "cases": {"file": rel(self.cases_file) if self.cases_file else None,
                      "total": self.case_total, "passed": self.case_passed,
                      "positive": self.sidecar_positive},
            "negatives": self.negatives,
            "atoms": {"total": len(self.atoms), "exercised": self.exercised,
                      "ratio": round(self.ratio, 3)},
            "rename": self.rename,
            "failures": [{"check": c, "message": m} for c, m in self.failures],
            "warnings": [{"check": c, "message": m} for c, m in self.warnings],
        }


def _fixture_label(path, events, i):
    e = events[i]
    what = e.get("eventName") or e.get("protoPayload.methodName") or e.get("operationName") \
        or e.get("properties.activityDisplayName") or e.get("category") or "record"
    return f"{rel(path)} record #{i} ({what})"


def check_rule(path, positives, cloud):
    r = Report(path)
    try:
        rule = sigma_explain.load(path)
    except Exception as e:  # noqa: BLE001
        r.fail("R0", f"the rule does not load: {type(e).__name__}: {e} (pySigma must compile "
                     "it and every detection item; fix the rule)")
        return r
    r.rule = rule
    r.platform = platform_of(rule)

    # R1: a registered positive.
    r.positives = list(positives.get(r.key, []))
    r.compile_only = COMPILE_ONLY.get(r.key)

    # R3: the sidecar cases.
    cases_path = rule_cases.cases_path(path)
    unverified = []
    if os.path.exists(cases_path):
        r.cases_file = cases_path
        try:
            _, results, errors = rule_cases.run_rule(path)
        except Exception as e:  # noqa: BLE001
            results, errors = [], [f"the cases file could not be run: {type(e).__name__}: {e}"]
        r.case_total = len(results) + len(errors)
        for err in errors:
            r.fail("R3", f"`{rel(cases_path)}` {err}")
        for res in results:
            case = res.case
            where = f"case '{case['name']}' ({case['kind']}, `{rel(cases_path)}` " \
                    f"line {case.get('_line', '?')})"
            if not res.ok:
                r.fail("R3", f"{where} fails: {res.detail}. Fix the event set or, if the case "
                             "is right, the rule; never relabel or weaken the case")
                continue
            r.case_passed += 1
            if case["kind"] == "positive":
                r.sidecar_positive = True
                r.positive_units.append((f"positive case '{case['name']}'",
                                         [sigma_eval.flatten(e) for e in case["events"]]))
            elif case["kind"] in ("near-miss", "filtered"):
                breaks = case["breaks"] if isinstance(case["breaks"], list) else [case["breaks"]]
                r.negatives.append({"source": f"case:{case['name']}", "kind": case["kind"],
                                    "atoms": list(breaks)})
            elif res.verdict.kind in sigma_explain.NON_TRIVIAL and res.verdict.atoms:
                unverified.append(f"case '{case['name']}' is declared {case['kind']} but "
                                  f"already grades {res.verdict.kind} on "
                                  f"{', '.join(res.verdict.atoms)}; declare it kind "
                                  f"{res.verdict.kind} with that `breaks` to count it")

    # Cloud: the hard benign fixture's records, graded the same way.
    fixture_grades = []
    for entry in cloud.get(r.key, []):
        benign = entry["benign"]
        if not benign or not os.path.exists(benign) or not entry["load"]:
            r.warn("R2", f"benign fixture {benign and rel(benign)} is missing; its records "
                         "cannot count as negatives")
            continue
        events = entry["load"](benign)
        verdicts = sigma_explain.judge_events(rule, events)
        for i, v in enumerate(verdicts):
            label = (_fixture_label(benign, events, i) if not rule.is_correlation
                     else f"{rel(benign)} (event set)")
            if v.mismatch:
                r.warn("R2", f"{label}: sigma_explain disagrees with the compiled rule, so "
                             "the record is not counted (report it)")
                continue
            if v.fired:
                continue  # the cloud validator fails on this; it is no negative
            fixture_grades.append(v.kind)
            if v.kind in sigma_explain.NON_TRIVIAL:
                r.negatives.append({"source": f"fixture:{label}", "kind": v.kind,
                                    "atoms": list(v.atoms)})

    r.exercised = [a for a in rule.atoms if any(a in n["atoms"] for n in r.negatives)]

    # R1 verdict.
    if r.positives:
        if r.compile_only:
            r.warn("R1", f"listed in COMPILE_ONLY but registered in {', '.join(r.positives)}; "
                         "remove the stale waiver from check_sufficiency.py")
    elif r.compile_only:
        if not r.sidecar_positive:
            r.fail("R1", "COMPILE_ONLY waives the missing CI telemetry, not the positive, and "
                         f"there is no passing positive case. Add a positive case to "
                         f"`{_cases_rel(path)}` with the event the emulation would produce, in "
                         f"the rule's log shape ({_logsource_text(rule)})")
    else:
        r.fail("R1", "no registered positive: register the rule and its emulation in "
                     f"{REGISTER_HINT.get(r.platform, 'a validator MANIFEST')}; for a "
                     "documented telemetry gap a human may add it to COMPILE_ONLY in "
                     "check_sufficiency.py with the reason (it then needs a sidecar positive)")

    # R2 verdict.
    disc = set(discriminating_atoms(rule))
    pure_surface = not disc
    if pure_surface and r.key not in CHOKEPOINT:
        r.fail("R2", f"every positive item is a surface field ("
                     f"{_surface_parts(rule) or 'it has no positive item'}), so "
                     "the rule matches every record of that kind and no negative can show "
                     "that an argument of the technique is load-bearing. This is the shape a "
                     "rule takes when it loses its argument (an `a0`, a provenance field, a "
                     "policy pattern): restore it. Only if the record kind itself is the "
                     "technique may a human list the rule in CHOKEPOINT in check_sufficiency.py, "
                     "with the reason")
    if r.key in CHOKEPOINT and not pure_surface:
        r.warn("R2", "listed in CHOKEPOINT but the rule has discriminating items ("
                     + ", ".join(a for a in rule.atoms if a in disc)
                     + "); remove the stale waiver from check_sufficiency.py")
    presence = (len([a for a in rule.positive_atoms() if a not in getattr(rule, "vacuous", ())])
                == 1 and not rule.negated_atoms()) if not rule.is_correlation else False
    if r.key in PRESENCE and not presence:
        r.warn("R2", "listed in PRESENCE but the rule has more than one positive item or a "
                     "filter, so a near-miss is possible; remove the stale waiver from "
                     "check_sufficiency.py and add one")
    if not r.negatives and r.key in PRESENCE and presence:
        r.warn("R2", "presence rule (PRESENCE waiver): no negative can be one item flip from "
                     f"firing; its proof is the positive case and its benign-corpus budget "
                     f"({PRESENCE[r.key]})")
    elif not r.negatives:
        why = []
        if r.cases_file is None:
            why.append(f"no `{os.path.basename(cases_path)}`")
        else:
            why.append(f"no passing near-miss/filtered case in `{rel(cases_path)}`")
        if fixture_grades:
            counts = {k: fixture_grades.count(k) for k in ("distant", "trivial")
                      if k in fixture_grades}
            why.append("benign fixture records grade "
                       + ", ".join(f"{n} {k}" for k, n in counts.items())
                       + " (none is one item flip from firing)")
        r.fail("R2", f"no verified near-miss or filtered negative ({'; '.join(why)}). "
                     + _negative_hint(rule, path, cloud_fixture=next(
                         (e["benign"] for e in cloud.get(r.key, []) if e["benign"]), None))
                     + ("" if not unverified else ". Note: " + "; ".join(unverified)))
    elif not pure_surface:
        # A surface-only negative passes as well for the rule with its argument
        # deleted; it needs company that breaks a discriminating item or a filter.
        decisive = disc | set(rule.negated_atoms())
        if not any(set(n["atoms"]) & decisive for n in r.negatives):
            r.fail("R2", "every verified negative breaks only the surface ("
                         + ", ".join(r.exercised) + "): it would pass just as well for the rule "
                         "with its discriminating items deleted ("
                         + ", ".join(a for a in rule.atoms if a in disc) + "). "
                         + _negative_hint(rule, path, exclude=r.exercised, cloud_fixture=next(
                             (e["benign"] for e in cloud.get(r.key, []) if e["benign"]), None)))

    check_names(r, rule, path, cloud.get(r.key, []))
    return r


def check_names(r, rule, path, entries):
    """R4: the rule keys on the technique, not on the emulation's naming."""
    named = _emulation_names(rule)
    if named:
        r.fail("R4", f"the detection matches emulation naming ({', '.join(named)}): a rule must "
                     "key on the technique, never on the names the emulation gives its objects; "
                     "remove it from the rule")

    # Cloud: every gate must be a marker(), so the rename test knows the marker.
    markers, attacks, attack_units, no_attack = [], [], [], []
    for entry in entries:
        if entry["marker"] is None:
            no_attack.append(f"the gate for `{entry['attack'] and rel(entry['attack'])}` is not "
                             "a marker()")
            r.fail("R4", "the cloud validator's gate for this rule is not a marker(substr, "
                         "*fields) (it carries no `.substr` / `.fields`), so the rename test "
                         "cannot know which emulation name to rename. Write the gate in the "
                         "validate_cloud_detections.py MANIFEST as marker('<a name only the "
                         "emulation uses>', '<field>', ...)")
            continue
        markers.append(entry["marker"]["substr"])
        if not entry["attack"] or not os.path.exists(entry["attack"]) or not entry["load"]:
            no_attack.append(f"attack fixture {entry['attack'] and rel(entry['attack'])} "
                             "is missing")
            continue
        records, units = _attack_units(rule, entry)
        attacks.append((entry, records))
        attack_units += units
        if not units:
            no_attack.append(f"no record of `{rel(entry['attack'])}` both fires the rule and "
                             f"carries the marker {entry['marker']['substr']!r} "
                             "(validate_cloud_detections.py fails on this too)")
    pattern = rename_pattern(markers)
    for entry, records in attacks:
        checked = [(_fixture_label(entry["attack"], records, i), e) for i, e in enumerate(records)]
        checked += [(f"renamed {label}", rename_names(e, pattern)) for label, e in checked]
        if entry["benign"] and os.path.exists(entry["benign"]):
            benign = entry["load"](entry["benign"])
            checked += [(_fixture_label(entry["benign"], benign, i), e)
                        for i, e in enumerate(benign)]
        problem = _gate_disagreement(entry["gate"], entry["marker"], checked)
        if problem:
            r.fail("R4", f"the cloud validator's gate declares marker("
                         f"{entry['marker']['substr']!r}, ...) but is not one: it {problem}. "
                         "Write it as marker(...) in the validate_cloud_detections.py MANIFEST")

    # The rename test (every platform).
    units = r.positive_units + attack_units
    r.rename = dict(rename_test(rule, units, pattern), markers=markers,
                    attack_units=len(attack_units))
    if not units:
        r.fail("R4", "no positive unit to run the rename test on: "
                     + ("; ".join(no_attack) + ", and " if no_attack else "")
                     + f"there is no passing positive case in `{_cases_rel(path)}`. Add the "
                     "emulation's own event as a positive case, so renaming its names can show "
                     "the rule keys on the technique")
    elif no_attack:
        r.warn("R4", "; ".join(no_attack) + "; the rename test ran on the sidecar positives only")
    stopped = r.rename["stopped"]
    if stopped:
        names = {}
        for s in stopped:
            for n in s["names"]:
                names.setdefault(n.lower(), n)
        flipped = [a for a in rule.atoms if any(a in s["flipped"] for s in stopped)] \
            if not rule.is_correlation else sorted({a for s in stopped for a in s["flipped"]})
        shown = "; ".join(s["unit"] for s in stopped[:3]) \
            + (f" (+{len(stopped) - 3} more)" if len(stopped) > 3 else "")
        renames = ", ".join(f"{n} -> {_scramble(n)}" for n in list(names.values())[:4])
        r.fail("R4", f"renaming the emulation's names ({renames}) stops the rule firing on "
                     f"{len(stopped)}/{len(units)} positive unit(s): {shown}. Items that flip: "
                     f"{', '.join(flipped) or 'no single item'}. The rule keys on the names the "
                     "emulation gives its objects (or on the validator gate's marker), however "
                     "it spells them; key it on the technique instead")

    # Negatives that differ from a positive only in the emulation's naming.
    keyed = set(r.rename["name_keyed"])
    if keyed and r.negatives and all(n["atoms"] and set(n["atoms"]) <= keyed
                                     for n in r.negatives):
        r.fail("R4", "every verified negative breaks only name-keyed items ("
                     + ", ".join(a for a in r.exercised if a in keyed)
                     + "): renaming the emulation's names in a positive flips them, so the "
                     "negatives differ from the attack only in naming and do not show the rule "
                     "keys on the technique. "
                     + _negative_hint(rule, path, exclude=keyed,
                                      keep_extra="the emulation's naming"))


def _logsource_text(rule):
    return "/".join(str(v) for v in rule.logsource.values()) or "?"


def _emulation_names(rule):
    docs = [rule.doc] if not rule.is_correlation else [b.doc for b in rule.bases.values()]
    found = []
    for doc in docs:
        text = json.dumps(doc.get("detection") or {})
        for m in EMULATION_NAME.findall(text):
            if m not in found:
                found.append(m)
    return found


def thin_checks(reports):
    """R5: compare each rule's exercised ratio with its platform's median."""
    medians = {}
    for plat in sorted({r.platform for r in reports if r.rule}):
        ratios = [r.ratio for r in reports if r.rule and r.platform == plat and r.negatives]
        medians[plat] = statistics.median(ratios) if ratios else None
    for r in reports:
        if not r.rule or not r.negatives:
            continue
        med = medians.get(r.platform)
        disc = discriminating_atoms(r.rule)
        reasons = []
        if med and r.ratio < med / 2:
            reasons.append(f"verified negatives exercise {len(r.exercised)}/{len(r.atoms)} "
                           f"items ({r.ratio:.0%}), under half the {r.platform} median "
                           f"({med:.0%})")
        if disc and not any(a in disc for a in r.exercised) \
                and not any(c == "R2" for c, _ in r.failures):  # R2 already says it
            only = "filters" if all(a in r.rule.negated_atoms() for a in r.exercised) \
                else "surface items and filters"
            subject = "they" if reasons else "the verified negatives"
            reasons.append(f"{subject} break only {only} ({', '.join(r.exercised)}) and no "
                           "discriminating selection item")
        if reasons:
            r.warn("R5", "thin: " + "; ".join(reasons) + ". "
                         + _negative_hint(r.rule, r.path, exclude=r.exercised))
    return medians


# ---- the run ---------------------------------------------------------------


def run(selected=None):
    """Check every rule. Returns (reports for the selection, medians, global errors)."""
    errors = hygiene_errors(unexpected_sigma_files())
    positives, cloud, manifest_errors = load_manifests()
    errors += manifest_errors
    paths = sorted(glob.glob(os.path.join(SIGMA, "*", "*.yml")))
    reports = [check_rule(p, positives, cloud) for p in paths]
    medians = thin_checks(reports)

    known = {r.key for r in reports}
    for key in sorted(set(positives) - known):
        errors.append(f"a validator MANIFEST registers {key}, which does not exist")
    for key in sorted(set(COMPILE_ONLY) - known):
        errors.append(f"COMPILE_ONLY lists {key}, which does not exist; remove the entry")
    for key in sorted(set(CHOKEPOINT) - known):
        errors.append(f"CHOKEPOINT lists {key}, which does not exist; remove the entry")
    for case_file in sorted(glob.glob(os.path.join(SIGMA, "*", "*.cases.jsonl"))):
        if not os.path.exists(case_file[:-len(".cases.jsonl")] + ".yml"):
            errors.append(f"`{rel(case_file)}` has no rule next to it (rename it with its rule "
                          "or delete it)")
    if selected is not None:
        reports = [r for r in reports if os.path.abspath(r.path) in selected]
    return reports, medians, errors


def _cell(r):
    pos = "+".join(r.positives) or ("compile-only" if r.compile_only else "-")
    cases = f"{r.case_passed}/{r.case_total}" if r.cases_file else "-"
    neg_cases = sum(1 for n in r.negatives if n["source"].startswith("case:"))
    neg_fix = len(r.negatives) - neg_cases
    neg = f"{neg_cases}c+{neg_fix}f" if neg_fix else str(neg_cases)
    atoms = f"{len(r.exercised)}/{len(r.atoms)}" if r.rule else "-"
    codes = sorted({c for c, _ in r.failures}) or sorted({c for c, _ in r.warnings})
    status = r.status + (" " + ",".join(codes) if codes else "")
    return [r.key, r.platform, pos, cases, neg, atoms, status]


HEADER = ["RULE", "PLATFORM", "POSITIVE", "CASES", "NEG", "ITEMS", "STATUS"]


def print_report(reports, medians, errors, verbose=False, subset=False):
    rows = [_cell(r) for r in reports]
    widths = [max(len(str(x[i])) for x in rows + [HEADER]) for i in range(len(HEADER))]
    print("Check sufficiency (NEG = verified near-miss/filtered negatives, c = sidecar "
          "cases, f = benign fixture records; ITEMS = items they exercise / all items):")
    print("  " + "  ".join(h.ljust(w) for h, w in zip(HEADER, widths)))
    for row in rows:
        print("  " + "  ".join(str(c).ljust(w) for c, w in zip(row, widths)))
    if verbose:
        print("\nVerified negatives:")
        for r in reports:
            print(f"  {r.key}")
            for n in r.negatives:
                print(f"      {n['kind']:<9} {n['source']}  breaks {', '.join(n['atoms'])}")
            if r.rename:
                n = r.rename
                print(f"      rename test: {n['renamed']}/{n['units']} positive unit(s) carry a "
                      f"name ({n['attack_units']} attack record(s)); markers "
                      f"{', '.join(repr(m) for m in n['markers']) or '-'}; stopped firing: "
                      f"{len(n['stopped'])}; name-keyed items: "
                      f"{', '.join(n['name_keyed']) or '-'}")
    failing = [r for r in reports if r.failures]
    if errors or failing:
        print("\nFailures (each fails the gate; the message says what to add):")
        for e in errors:
            print(f"  [ERROR] {e}")
        for r in failing:
            for check, message in r.failures:
                print(f"  [{check}] {r.key}: {message}")
    warned = [r for r in reports if r.warnings]
    if warned:
        print("\nWarnings (never fail; treat as a request for more negatives):")
        for r in warned:
            for check, message in r.warnings:
                print(f"  [{check}] {r.key}: {message}")
    print("\n" + summary_line(reports, medians, errors, subset=subset))


def summary(reports, medians, errors, subset=False):
    by_check = {c: sum(1 for r in reports if any(f[0] == c for f in r.failures)) for c in CHECKS}
    return {"rules": len(reports),
            "pass": sum(1 for r in reports if r.status == "PASS"),
            "warn": sum(1 for r in reports if r.status == "WARN"),
            "fail": sum(1 for r in reports if r.status == "FAIL"),
            "failing_by_check": by_check, "errors": list(errors),
            "platform_median_ratio": {k: (round(v, 3) if v is not None else None)
                                      for k, v in medians.items()},
            "subset": subset,
            # With --rule, repository-wide errors are shown but only the selected
            # rules decide the exit code; the full run (CI) fails on them.
            "ok": (subset or not errors) and not any(r.failures for r in reports)}


def summary_line(reports, medians, errors, head=True, subset=False):
    s = summary(reports, medians, errors, subset)
    counts = ", ".join(f"{c} {n}" for c, n in s["failing_by_check"].items() if n)
    meds = ", ".join(f"{k} {v:.0%}" for k, v in medians.items() if v is not None) or "-"
    head = ("OK: " if s["ok"] else "FAILED: ") if head else ""
    return (f"{head}{s['rules']} rule(s): {s['pass']} pass, {s['warn']} pass with warnings, "
            f"{s['fail']} fail" + (f" (rules failing {counts})" if counts else "")
            + (f"; {len(errors)} repository error(s)"
               + (" (not counted with --rule)" if subset else "") if errors else "")
            + f". Median items exercised per platform: {meds}.")


def write_markdown(path, reports, medians, errors, subset=False):
    s = summary(reports, medians, errors, subset)
    line = summary_line(reports, medians, errors, head=False, subset=subset)
    lines = ["## Check sufficiency", "",
             f"**{'PASS' if s['ok'] else 'FAIL'}**: {line}", "",
             "| Rule | Platform | Positive | Cases | Neg | Items | Status |",
             "|---|---|---|---|---|---|---|"]
    for r in reports:
        lines.append("| " + " | ".join(f"`{c}`" if i == 0 else str(c).replace("|", "\\|")
                                         for i, c in enumerate(_cell(r))) + " |")
    if errors or any(r.failures for r in reports):
        lines += ["", "### Failures", ""]
        lines += [f"- **error**: {e}" for e in errors]
        lines += [f"- `{r.key}` **{c}**: {m}" for r in reports for c, m in r.failures]
    warned = [(r, c, m) for r in reports for c, m in r.warnings]
    if warned:
        lines += ["", f"<details><summary>Warnings ({len(warned)})</summary>", ""]
        lines += [f"- `{r.key}` **{c}**: {m}" for r, c, m in warned]
        lines += ["", "</details>"]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n\n")


def _resolve(path):
    for candidate in (path, os.path.join(REPO, path), os.path.join(SIGMA, path)):
        if os.path.isfile(candidate) and candidate.endswith(".yml"):
            return os.path.abspath(candidate)
    return None


def main():
    ap = _arg_parser()
    args = ap.parse_args()

    selected = None
    if args.rule:
        selected = set()
        for p in args.rule:
            resolved = _resolve(p)
            if not resolved:
                ap.error(f"--rule {p}: no such rule file")
            selected.add(resolved)

    reports, medians, errors = run(selected)
    subset = selected is not None
    print_report(reports, medians, errors, verbose=args.verbose, subset=subset)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary(reports, medians, errors, subset),
                       "compile_only": COMPILE_ONLY, "chokepoint": CHOKEPOINT,
                       "rules": [r.to_json() for r in reports]}, fh, indent=2)
            fh.write("\n")
    if args.markdown:
        write_markdown(args.markdown, reports, medians, errors, subset)
    return 0 if summary(reports, medians, errors, subset)["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
