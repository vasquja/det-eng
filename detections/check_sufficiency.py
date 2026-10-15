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
  R1 positive    the rule is a positive in some validator MANIFEST (auditd,
                 cloud, API server, TRR9002, TRR9003), or it is listed in
                 COMPILE_ONLY below for a documented telemetry gap. A
                 COMPILE_ONLY rule still needs a passing sidecar positive.
  R2 negatives   at least one VERIFIED non-trivial negative: a sidecar case of
                 kind near-miss or filtered that passed (rule_cases.run_rule
                 checks it is one item flip from firing, on the item it
                 declares), or, for a cloud rule, a record of its hard benign
                 fixture that sigma_explain grades near-miss or filtered.
                 Trivial and distant negatives, no-op controls and
                 pre-emulation baselines do not count: they would also pass
                 for a rule with a wrong argument or a dead filter.
  R3 cases hold  every sidecar case passes, every sidecar parses, and no
                 sidecar exists without its rule.
  R4 not marker-keyed
                 no rule's detection names an emulation (trr9NNN, deteng_).
                 For a cloud rule, its verified negatives must not ALL break
                 only marker-keyed items: items whose truth on the attack's
                 own matched records changes when the emulation marker (the
                 validator gate's `substr`) is renamed. Such negatives differ
                 from the attack only in the emulation's naming, so they do not
                 show that the rule keys on the technique. Renaming, rather than
                 "the item reads a gate field", is what decides: a gate field
                 such as Glue's requestParameters.policyInJson carries both the
                 marker and the technique (the public Principal), and a negative
                 that changes the Principal is a real negative.
  R5 thin        (warning only, never fails) items exercised by verified
                 negatives versus the rule's item count. Warns when that ratio
                 is below half the median of the rule's platform (linux /
                 kubernetes / cloud; the median is over rules that have any
                 verified negative), or when the negatives break no
                 discriminating selection item (only filters, or only the
                 surface: syscall, verb, eventName, ...). Also warns when a
                 renamed attack no longer fires (the marker gate is then not
                 independent of the rule) and when a non-cloud rule has no
                 offline positive case to anchor its negatives.

An atom (item) is what rule_cases.py calls one: `<block>.<field>`,
`<block>[i].<field>` inside a list of maps, `<block>` for a keyword list, and for
a correlation rule `base:<name>`, `group-by`, `timespan`, `threshold`.
"Exercised" counts the items a verified negative flips: the declared `breaks` of
a sidecar case, or every single flip sigma_explain finds for a fixture record.

Waivers: there are none beyond COMPILE_ONLY. A human edits that dict, with a
reason, and a change to this file needs a human approval before merge.

Usage:
    python3 detections/check_sufficiency.py                      # the gate
    python3 detections/check_sufficiency.py --rule detections/sigma/T1040/afinet_raw_socket.yml
    python3 detections/check_sufficiency.py -v                   # list each rule's negatives
    python3 detections/check_sufficiency.py --json out.json --markdown "$GITHUB_STEP_SUMMARY"
"""

import argparse
import glob
import inspect
import json
import os
import re
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rule_cases  # noqa: E402
import sigma_eval  # noqa: E402
import sigma_explain  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA = os.path.join(REPO, "detections", "sigma")

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


def _cloud_entry(module, entry):
    """Attack / benign fixtures and the marker of one cloud MANIFEST entry."""
    jsons = [x for x in entry if isinstance(x, str) and x.endswith(".json")]
    benign = next((j for j in jsons if "benign" in os.path.basename(j)), None)
    attack = next((j for j in jsons if j != benign), None)
    gate = next((x for x in entry if callable(x)), None)
    marker = None
    if gate is not None:
        try:
            nonlocals = inspect.getclosurevars(gate).nonlocals
        except TypeError:
            nonlocals = {}
        if isinstance(nonlocals.get("substr"), str) and nonlocals.get("fields"):
            marker = {"substr": nonlocals["substr"], "fields": list(nonlocals["fields"])}
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


def _surface_text(rule):
    """'the surface (syscall: 'socket'; ...)' from the rule's surface items."""
    parts = []
    for atom in surface_atoms(rule):
        spec = atom_spec(rule, atom)
        part = spec[spec.find("(") + 1:-1] if "(" in spec else atom
        if part not in parts:
            parts.append(part)
    if not parts:
        return None
    shown = "; ".join(parts[:4]) + ("; ..." if len(parts) > 4 else "")
    return f"the surface ({shown})"


def _cases_rel(path):
    return rel(rule_cases.cases_path(path))


def _negative_hint(rule, path, exclude=(), cloud_fixture=None, keep_extra=None):
    """'Add a near-miss case to X that keeps <surface> and breaks one of: <items>'."""
    target = f"`{_cases_rel(path)}`"
    if rule.is_correlation:
        bases = [a for a in rule.atoms if a.startswith("base:") and a not in exclude]
        other = [a for a in ("group-by", "timespan", "threshold")
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


def rename_marker(event, substr):
    """The event with every occurrence of the marker renamed (case-insensitive)."""
    pattern = re.compile(re.escape(substr), re.IGNORECASE)
    return {k: pattern.sub(lambda m: _scramble(m.group(0)), v) if isinstance(v, str) else v
            for k, v in event.items()}


def marker_analysis(rule, entries):
    """Which items key on the emulation marker, by renaming it in the attack.

    Returns a dict, or None when no entry carries an introspectable marker.
    """
    out = None
    for entry in entries:
        marker = entry["marker"]
        if not marker or not entry["attack"] or not os.path.exists(entry["attack"]):
            continue
        out = out or {"substr": marker["substr"], "fields": marker["fields"],
                      "reads_marker_fields": [], "name_keyed": set(),
                      "attack_hits": 0, "renamed_fires": True, "method": "rename"}
        mfields = set(marker["fields"])
        out["reads_marker_fields"] = [a for a in rule.atoms if set(rule.fields(a)) & mfields]
        attack = entry["load"](entry["attack"]) if entry["load"] else []
        table = sigma_eval.EventTable(attack)
        ours = sorted({i for hit in table.hit_indices(rule.sql)
                       if any(entry["gate"](attack[j]) for j in hit) for i in hit})
        if not ours:
            continue
        out["attack_hits"] += len(ours)
        own = [attack[i] for i in ours]
        renamed = [rename_marker(e, marker["substr"]) for e in own]
        if rule.is_correlation:
            # No per-event truth for a correlation: fall back to "reads a gate field".
            out["renamed_fires"] = out["renamed_fires"] and bool(
                sigma_eval.EventTable(renamed).hit_indices(rule.sql))
            out["name_keyed"] |= set(out["reads_marker_fields"])
            out["method"] = "fields"
            continue
        both = sigma_eval.EventTable(own + renamed)
        rows, fired = rule.truth_table(both)
        n = len(own)
        out["name_keyed"] |= {a for a in rule.atoms
                              if any(rows[i][a] != rows[n + i][a] for i in range(n))}
        out["renamed_fires"] = out["renamed_fires"] and all(n + i in fired for i in range(n))
    if out is not None:
        out["name_keyed"] = [a for a in rule.atoms if a in out["name_keyed"]]
    return out


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
        self.marker = None
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
            "cases": {"file": rel(self.cases_file) if self.cases_file else None,
                      "total": self.case_total, "passed": self.case_passed,
                      "positive": self.sidecar_positive},
            "negatives": self.negatives,
            "atoms": {"total": len(self.atoms), "exercised": self.exercised,
                      "ratio": round(self.ratio, 3)},
            "marker": self.marker,
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
    if not r.negatives:
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

    # R4: the rule names an emulation (any platform).
    named = _emulation_names(rule)
    if named:
        r.fail("R4", f"the detection matches emulation naming ({', '.join(named)}): a rule must "
                     "key on the technique, never on the names the emulation gives its objects; "
                     "remove it from the rule")

    # R4: cloud negatives that differ from the attack only in the marker.
    if r.key in cloud:
        r.marker = marker_analysis(rule, cloud[r.key])
        if r.marker is None:
            r.warn("R4", "the cloud validator's gate is not a marker(substr, *fields) closure, "
                         "so the marker check could not run")
        else:
            keyed = set(r.marker["name_keyed"])
            if r.negatives and all(n["atoms"] and set(n["atoms"]) <= keyed
                                   for n in r.negatives):
                r.fail("R4", "every verified negative breaks only marker-keyed items ("
                             + ", ".join(a for a in r.exercised if a in keyed)
                             + f"): renaming the emulation marker {r.marker['substr']!r} in "
                             "the attack flips them, so the negatives differ from the attack "
                             "only in naming and do not show the rule keys on the technique. "
                             + _negative_hint(rule, path, exclude=keyed,
                                              keep_extra="the marker naming"))
            if r.marker["attack_hits"] and not r.marker["renamed_fires"]:
                flipped = ", ".join(r.marker["name_keyed"]) or "no single item flips"
                r.warn("R4", f"renaming the marker {r.marker['substr']!r} in the attack stops "
                             f"the rule firing (items that flip: {flipped}): the rule keys on "
                             "the same text the validator's gate uses, "
                             "so 'the match carries the emulation marker' proves nothing for it; "
                             "gate on a name only the emulation uses")
            if not r.marker["attack_hits"]:
                r.warn("R4", "no attack record both fires the rule and carries the marker, so "
                             "the rename check could not run (validate_cloud_detections.py "
                             "fails on this too)")

    # Non-cloud rules: an offline positive anchors the negatives.
    if r.platform != "cloud" and r.negatives and not r.sidecar_positive:
        r.warn("R5", f"no positive case in `{_cases_rel(path)}`: add the emulation's own "
                     "event so the near-misses are anchored to a known-firing event")
    return r


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
        if disc and not any(a in disc for a in r.exercised):
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
    positives, cloud, errors = load_manifests()
    paths = sorted(glob.glob(os.path.join(SIGMA, "*", "*.yml")))
    reports = [check_rule(p, positives, cloud) for p in paths]
    medians = thin_checks(reports)

    known = {r.key for r in reports}
    for key in sorted(set(positives) - known):
        errors.append(f"a validator MANIFEST registers {key}, which does not exist")
    for key in sorted(set(COMPILE_ONLY) - known):
        errors.append(f"COMPILE_ONLY lists {key}, which does not exist; remove the entry")
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
            if r.marker:
                print(f"      marker {r.marker['substr']!r} in {', '.join(r.marker['fields'])}; "
                      f"name-keyed items: {', '.join(r.marker['name_keyed']) or '-'}; "
                      f"renamed attack fires: {r.marker['renamed_fires']}")
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
    ap = argparse.ArgumentParser(
        description="Fail a detection whose checks are easy to satisfy (R1-R4); warn on thin "
                    "checks (R5).")
    ap.add_argument("--rule", action="append", default=[], metavar="PATH",
                    help="check only this rule (repeatable); medians still use every rule")
    ap.add_argument("--json", metavar="PATH", help="write the full result as JSON")
    ap.add_argument("--markdown", metavar="PATH",
                    help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list every rule's verified negatives and marker analysis")
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
                       "compile_only": COMPILE_ONLY,
                       "rules": [r.to_json() for r in reports]}, fh, indent=2)
            fh.write("\n")
    if args.markdown:
        write_markdown(args.markdown, reports, medians, errors, subset)
    return 0 if summary(reports, medians, errors, subset)["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
