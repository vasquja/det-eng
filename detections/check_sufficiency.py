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
                 never checked. So does anything in detections/ (or its
                 __pycache__/) named sigma.*, and any compiled module directly
                 in detections/ (a name ending in a bytecode or extension-module
                 suffix: a sourceless .pyc, a .so): detections/ is first on
                 sys.path, so such a file would replace pySigma, PyYAML or a
                 standard-library module in every gate, unreviewed. This script
                 imports the standard library before detections/ is on sys.path,
                 so R0 runs before any such file could be imported.
  R1 positive    the rule is a positive in some validator MANIFEST (auditd,
                 cloud, API server, TRR9002, TRR9003), or it is listed in
                 COMPILE_ONLY below for a documented telemetry gap. A
                 COMPILE_ONLY rule still needs a passing sidecar positive.
                 The rule's logsource (every base's, for a correlation) must
                 name the log its validator proves it on: auditd ->
                 linux/auditd; API server and TRR9003 -> kubernetes/<the
                 entry's source, audit or cri>; TRR9002 -> kubernetes/audit;
                 cloud -> product = the entry's provider. The validators run
                 the compiled SQL, which ignores logsource, but the benign
                 corpus scores a rule only on the slices of its logsource: a
                 rule moved to a sibling service would read 0 benign hits and
                 escape its budget. (The cloud MANIFEST names no service, so R1
                 lets a cloud rule move between services of its provider, e.g.
                 Azure activitylogs / auditlogs / signinlogs; the ratchet below
                 fails any logsource change of an existing rule instead.)
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
                 the technique; then any verified negative counts. A PRESENCE
                 rule (one positive item, no filter) can have no one-flip
                 negative; a human lists it in PRESENCE, and its proof is the
                 positive plus its benign-corpus budget.
                 A CORRELATION's own items (base presence, group-by, timespan,
                 order, threshold) say which events go together, not what makes
                 an event the technique: that lives in each base rule, so R2
                 runs on each base. A pure-surface base fails unless CHOKEPOINT
                 names it ("<rule> base:<name>"). Every other base needs a
                 verified negative that breaks one of ITS discriminating items
                 (or its filter): a set declared `breaks: [base:<name>]` in which
                 one event misses that base by exactly such an item and, marked
                 as the base's match, makes the compiled correlation fire (so the
                 event is in the right group and window, not just anywhere).
                 Dropping a base's event, or moving events out of the group or
                 the window, does not count for a base.
  R3 cases hold  every sidecar case passes, every sidecar parses, and no
                 sidecar exists without its rule.
  R4 not name-keyed
                 the rule keys on the technique, not on the names the repo's
                 emulations give their objects:
                 - its detection names no emulation literally (trr9NNN, deteng_);
                 - the RENAME TEST, every platform: each positive unit (every
                   passing sidecar positive case; for a rule the auditd
                   validator runs, a copy of each such case whose every event
                   carries the exe and comm that validator's run of each of the
                   rule's atomics writes, /tmp/deteng_val_<8 random>/deteng_<atomic
                   stem> and its first 15 characters, if that copy fires; and
                   for a cloud rule every attack fixture record it fires on that
                   carries the validator gate's marker) must still fire after
                   every emulation IDENTITY in it is renamed, by each of two
                   renames drawn at random for the run (SystemRandom), which the
                   failure message never prints: SAME-SHAPE (every letter and
                   digit becomes another of its class, through one random
                   substitution for the run; other characters are kept) and
                   NEUTRAL (each identity becomes random lowercase letters of a
                   different length). An identity is an emulation name
                   (/trr9\\d{3}/i, `deteng_`) or a gate marker plus the rest of
                   its token (letters, digits, `_`, `.`, `-` up to the next `/`,
                   `:`, `=`, quote, space): the whole of `deteng_val_x`,
                   `deteng_afxdp_socket_behavioral`, `trr9026-target`,
                   `oidc.trr9013-attacker.example.com`. So a rule that stops
                   firing keys on some part of the emulation's naming (the
                   atomic's `_behavioral` suffix, an object's `-target`),
                   however its regex spells it (`rr9026`, `tr?9026`,
                   `ssrf-demo`), or on the naming's shape (`_[a-z]{10}$`). What
                   precedes the name in its token is kept: the platform writes
                   it (the AWS unique-id type in `AKIATRR9012EXAMPLE01`, `ami-`,
                   `Cognito_`) and a rule may key on it. Where a platform's
                   naming template follows the name (Cognito_<pool>Unauth_Role),
                   a human lists the rule in PLATFORM_NAMING with the substrings
                   to keep. A rule with no positive unit fails: the test cannot
                   run. So does a rule none of whose units carries an identity
                   (the test renamed nothing), unless it is COMPILE_ONLY (no
                   emulation run names anything). RESIDUAL: only names are
                   renamed. A rule keyed on a token's prefix before the
                   emulation name, or on another constant of an emulation run
                   (an attack fixture's source IP, an instance, account or key
                   id, a timestamp), still passes here. Outside the auditd
                   validator the units come from the sidecar and the attack
                   fixtures as written, so a positive that carries an identity
                   only in a field the rule does not read, with the field the
                   rule keys on renamed by hand (`web-target` for
                   `trr9026-target`), passes too; the human review of the rule
                   and its sidecar must catch both;
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
The checks grade each rule without its null guards and null-safe copies
(sigma_explain's PlainRule.stripped(); check_null_safety.py): they only make a
`not` null-safe and change no two-valued verdict, so they are no item of the rule
(no discriminating item, no R5 count, no hint target), and rule_cases.py rejects a
case that names one in `breaks`.

Waivers: COMPILE_ONLY (R1), CHOKEPOINT and PRESENCE (R2), PLATFORM_NAMING (R4);
nothing else. A human edits those dicts, and a change to this file needs a human
approval before merge. Each entry is Waiver(why, digest): the reason, and the
digest of the rule content the human approved (detection_digest: sha256 of every
YAML document's name, id, logsource, detection and correlation blocks as canonical
JSON; comments, title, description and other metadata are not part of it). When
the rule changes, the digest no longer matches and the waiver stops excusing it:
R1, R2 or R4 fails and prints the new digest, so a human re-reviews the changed
rule and re-approves it by writing that digest here. A waiver is never keyed by
path alone.

RATCHET (--baseline FILE; the CI job sufficiency-ratchet runs it on a pull
request): FILE is the --json report of the base branch, made by the base tree's own
copy of this script. The report records, per rule, every sidecar case by name with
its kind and digest (sha256 of canonical JSON of its kind, `breaks` and events; not
its why or source text) and every verified negative with a digest (a case's, or the
canonical JSON of a fixture record). Every rule of the base must still exist on the
head (a deleted or renamed rule is a decrease). For every rule in both reports, the
head must keep every base sidecar case by name with the same kind and digest, keep
every base verified negative (same source, same digest), not have fewer verified
negatives, not lose an item those negatives exercised (a rule item, a correlation
item, or a correlation base's item), not have fewer passing positive cases, not
lose its sidecar, and keep its logsource (and each correlation base's: a rule
moved to a sibling service of its provider is scored on other slices and budgets).
New cases are fine. Each decrease is printed and fails the run, so deleting or
editing any sidecar case, or a verified negative's fixture record (content-only
edits), goes to a human instead of merging on its own. A base report from an older
copy of this script has no digests: the ratchet then says it compared those rules'
cases and negatives by count and name only.

Usage:
    python3 detections/check_sufficiency.py                      # the gate
    python3 detections/check_sufficiency.py --rule detections/sigma/T1040/afinet_raw_socket.yml
    python3 detections/check_sufficiency.py -v                   # list each rule's negatives
    python3 detections/check_sufficiency.py --json out.json --markdown "$GITHUB_STEP_SUMMARY"
    python3 detections/check_sufficiency.py --baseline base.json # the gate plus the ratchet
"""

import os
import sys

# Running this script puts detections/ first on sys.path, ahead of the standard
# library and site-packages. Import the standard library before it is there, so a
# stray compiled module in detections/ cannot replace one before R0 has looked
# (R0 refuses such files; detections/ goes back on sys.path after R0 passes).
_HERE = os.path.dirname(os.path.abspath(__file__))
if sys.path and os.path.abspath(sys.path[0] or os.curdir) == _HERE:
    del sys.path[0]

import argparse  # noqa: E402
import glob  # noqa: E402
import hashlib  # noqa: E402
import importlib.machinery  # noqa: E402
import itertools  # noqa: E402
import json  # noqa: E402
import random  # noqa: E402
import re  # noqa: E402
import statistics  # noqa: E402
import string  # noqa: E402
from collections import namedtuple  # noqa: E402

REPO = os.path.dirname(_HERE)
SIGMA = os.path.join(REPO, "detections", "sigma")

# ---- repository hygiene (R0), before pySigma is imported --------------------

TECHNIQUE_DIR = re.compile(r"T\d{4}(\.\d{3})?")
RULE_MATERIAL = re.compile(r"[^./][^/]*\.(yml|cases\.jsonl|md)")
# A sourceless compiled module (.pyc, .so, ...) directly in detections/ is imported
# ahead of site-packages and the standard library by every gate (detections/ is
# first on sys.path), and it cannot be reviewed. sigma_eval's import guard uses the
# same rule.
COMPILED_SUFFIXES = tuple(s.lower() for s in importlib.machinery.BYTECODE_SUFFIXES
                          + importlib.machinery.EXTENSION_SUFFIXES)


def unexpected_sigma_files():
    """Entries under detections/sigma/ that are not rule material, anything in
    detections/ (or detections/__pycache__/) named sigma.*, and any compiled module
    (COMPILED_SUFFIXES) directly in detections/ (R0), as repo paths.

    Allowed: T<id>/<stem>.yml, T<id>/<stem>.cases.jsonl, T<id>/*.md and *.md at
    the top. A directory is reported once, with a trailing slash. The detections/
    checks mirror sigma_eval's import guard, so R0 names the file itself.
    """
    def name(entry, prefix=""):
        return prefix + entry.name + ("/" if entry.is_dir(follow_symlinks=False) else "")

    bad = []
    detections = os.path.dirname(SIGMA)
    for sub in ("", "__pycache__"):
        try:
            names = sorted(os.listdir(os.path.join(detections, sub)))
        except (FileNotFoundError, NotADirectoryError):
            continue
        bad += [f"detections/{sub + '/' if sub else ''}{n}" for n in names
                if n.lower().startswith("sigma.") or (not sub and n.lower().endswith(COMPILED_SUFFIXES))]
    if not os.path.isdir(SIGMA):
        return bad + ["detections/sigma/ (the directory itself is missing)"]
    for entry in sorted(os.scandir(SIGMA), key=lambda e: e.name):
        if entry.is_dir(follow_symlinks=False) and TECHNIQUE_DIR.fullmatch(entry.name):
            for item in sorted(os.scandir(entry.path), key=lambda e: e.name):
                if not (item.is_file(follow_symlinks=False) and RULE_MATERIAL.fullmatch(item.name)):
                    bad.append("detections/sigma/" + name(item, entry.name + "/"))
        elif not (entry.is_file(follow_symlinks=False) and entry.name.endswith(".md")
                  and not entry.name.startswith(".")):
            bad.append("detections/sigma/" + name(entry))
    return bad


def hygiene_errors(unexpected):
    def error(p):
        if p.startswith("detections/sigma/"):
            return (f"R0: unexpected `{p}`: detections/sigma/ holds only "
                    "T<id>/<stem>.yml rules, their <stem>.cases.jsonl sidecars and *.md notes "
                    "(no other extension, nested directory, hidden file or symlink: a rule one "
                    "level down is never checked, and the directory shares pySigma's `sigma` "
                    "namespace); move or delete it")
        if os.path.basename(p.rstrip("/")).lower().startswith("sigma."):
            return (f"R0: unexpected `{p}`: nothing in detections/ (or its __pycache__/) may be "
                    "named sigma.*, because a `sigma` module beside the validators would "
                    "replace pySigma whole; move or delete it")
        return (f"R0: unexpected `{p}`: no compiled module ({', '.join(COMPILED_SUFFIXES)}) "
                "may sit directly in detections/: detections/ is first on sys.path, so every "
                "gate would import it instead of the standard-library or site-packages module "
                "of that name, and a binary cannot be reviewed; delete it")
    return [error(p) for p in unexpected]


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
    ap.add_argument("--baseline", metavar="FILE",
                    help="the base branch's --json report: also fail when a base rule is gone, "
                         "or a rule in both loses or changes a sidecar case or verified "
                         "negative, loses exercised items, passing positives or its sidecar, "
                         "or changes its logsource")
    return ap


def _hygiene_exit(unexpected):
    """Report unexpected files in detections/ without importing pySigma."""
    args = _arg_parser().parse_args()
    errors = hygiene_errors(unexpected)
    line = f"{len(errors)} unexpected file(s) in detections/ (R0); no rule was checked"
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

sys.path.insert(0, _HERE)
import rule_cases  # noqa: E402
import sigma_eval  # noqa: E402
import sigma_explain  # noqa: E402
import yaml  # noqa: E402

# A human-approved waiver: the reason, and detection_digest() of the rule content
# the human approved. A rule that changes no longer matches its digest, and the
# waiver stops excusing it until a human re-approves the new content. `keep` is
# used by PLATFORM_NAMING only.
Waiver = namedtuple("Waiver", "why digest keep", defaults=((),))

# Rules no validator can match-gate, because CI does not collect their telemetry.
# Each still needs a passing positive in its sidecar. Adding an entry is a waiver
# of R1: a human decides it, with the reason, and approves the change.
#
# The two node file-event rules (T1552.007/linux_k8s_sa_token_read and
# T1543.005/linux_static_pod_manifest_write) were waived here while CI collected no
# node file telemetry. The kind CI jobs now run an auditd node file-event sensor
# (C2-7): validate_apiserver_detections.py gates the token read on TRR9006 Procedure
# E, and validate_staticpod_detections.py gates the manifest write on TRR9003
# Procedure A, both with a 'file' log source. The gate the waiver excused is met, so
# the waivers are removed (a human decision, taken with that sensor in the same PR).
COMPILE_ONLY = {
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
    "T1543.005/k8s_cri_static_pod_start.yml": Waiver(
        "TRR9003 chokepoint: the kubelet stamps config.source file/http only on a pod it ran "
        "from a node-local or URL manifest (api otherwise)",
        "571f06abb83e7cf3acce50fde1266a80518d87c4758b8bd135534870b27b1ac3"),
}

# Keyed by rule, or "<rule> base:<name>" for one base of a correlation rule.
CHOKEPOINT = {
    "T1053.007/k8s_job_create.yml": Waiver(
        "TRR9005 chokepoint: every Job/CronJob procedure is a batch/v1 write; the "
        "controllers' own writes are filtered",
        "87d2ecca2eef5b4b616b01118fc70203930779e9b26b5232f1bee89d195d3382"),
    "T1068/copyfail_af_alg_authencesn.yml base:copyfail_splice": Waiver(
        "splice(2) is the CopyFail page-cache write itself; the AF_ALG base carries the "
        "argument (a0 = AF_ALG) and the same-pid 5s correlation narrows it",
        "d3f704de9aa8ca79e9fd20b94254d1ebf60f752bafee68a2c6beaf081a8bf075"),
    "T1068/dirtypipe_splice_readonly.yml base:dirtypipe_pipe_create": Waiver(
        "pipe(2)/pipe2(2) is the DirtyPipe setup step; auditd records no descriptor type, so "
        "the pipe-then-splice sequence on one pid within 5s is the whole signal",
        "a326cb4dee31ba4faf8865b404af703ccf3538e84f2af02905397d62c5215cf6"),
    "T1068/dirtypipe_splice_readonly.yml base:dirtypipe_splice": Waiver(
        "splice(2) is the DirtyPipe page-cache write itself; auditd records no descriptor "
        "type, so the pipe-then-splice sequence on one pid within 5s is the whole signal",
        "a326cb4dee31ba4faf8865b404af703ccf3538e84f2af02905397d62c5215cf6"),
    "T1068/keyring_add_key_burst.yml": Waiver(
        "add_key(2) itself is the keyring-stuffing primitive; the keyring users are filtered",
        "c1d0096671aea15afb5a06895b4bb399e006046a57b65cb478abdb6e996be76a"),
    "T1068/perf_event_open_non_profiler.yml": Waiver(
        "perf_event_open(2) itself is the escalation surface; profilers are filtered",
        "dd058958fc30b77e80437825eb503a9ff2a8b403c5ed99b19cd4af3d2410f985"),
    "T1068/userfaultfd_syscall.yml": Waiver(
        "userfaultfd(2) itself is the exploit timing primitive and is rare outside CRIU/QEMU",
        "ada55f947b8af992be5f43d7b7961bfd55b1432904c9918840a2b94fa2368c98"),
    "T1070/k8s_events_deleted.yml": Waiver(
        "TRR9010 chokepoint: deleting Events is the evidence removal",
        "b752f49bb3d0fb27dad9cd7a252e8a8b32a9dc5da3fabd8c9df747048faa6696"),
    "T1070/k8s_workload_deleted_evidence.yml": Waiver(
        "TRR9010 low-fidelity fallback by design: any pod/job delete",
        "9b206ed862e7b36a3b17ab82280c043d90e0f4800f54deb377b51db93c2d6d3e"),
    "T1098.001/azure_managed_identity_federated_credential_backdoor.yml": Waiver(
        "the Activity Log carries no issuer/subject, so the FIC write operation is the "
        "whole signal (TRR9013 procedure C)",
        "bc64702280f8f8d1b71ea1f889322e6456424efe71995da8d9cb1589931e2229"),
    "T1098.006/k8s_rbac_write.yml": Waiver(
        "TRR9004 chokepoint: every RBAC-object grant passes through an RBAC write",
        "2298ffb181b03dc759985927b5a45d711cde1417342620a9670780fd8eb1c7ce"),
    "T1546/k8s_admission_webhook_created.yml": Waiver(
        "TRR9025 chokepoint: creating an admission controller object (a create, or the "
        "server-side-apply create that is a patch answered 201; K21)",
        "00eb9aa313f7fb56185913ee8d658f2e6c09e233130e90b11559df560a8042e3"),
    "T1552.007/k8s_secret_access.yml": Waiver(
        "TRR9006 chokepoint: every API read of a Secret",
        "02c75f50efdcbadbde1687c623b0557c797fd190c8ccc2f0a1b4b8421100d596"),
    "T1552.007/k8s_secret_token_request.yml": Waiver(
        "TRR9006 fallback: the TokenRequest create itself; system minters are filtered",
        "9d42e65762b82781163a3f7d7c97d3413c450fa861ffa068b01a716898e54dcb"),
    "T1572/k8s_pod_portforward.yml": Waiver(
        "TRR9026 chokepoint: the pods/portforward subresource is the tunnel",
        "b3809fdd4a546ec9227d4ee21a639c67d110cf73ed7b965fbc63b6fa95150e2b"),
    "T1609/k8s_pod_ephemeral_container.yml": Waiver(
        "TRR9002 strategy 2: a write to pods/ephemeralcontainers is the injection",
        "d8c58a95b41b744af9e82b72eedd279aaee14a101c7423586bc7ce6f809be5c1"),
    "T1609/k8s_pod_exec_attach.yml": Waiver(
        "TRR9002 chokepoint: the pods/exec and pods/attach subresources",
        "efcf8dad25a63e1bbb805b035d9b8dc596b91679261b33cfc83a2c9f685a173b"),
    "T1611/setns_namespace_join.yml": Waiver(
        "setns(2) itself is the namespace-join primitive; container runtimes are filtered",
        "d52e76374c66d0abf7a0af32e0a7e61b4a0616128e0cf2ae673692c36903f68b"),
    "T1620/memfd_create_execveat.yml base:memfd_exec_execveat": Waiver(
        "execveat(2) of the anonymous file is the fileless execution itself; the "
        "memfd_create-then-execveat sequence on one pid within 10s is the whole signal",
        "655e1e5a6b78cfe16bb304363669fef0a4af4c23b937f0283f2161ebbe23da8a"),
    "T1620/memfd_create_execveat.yml base:memfd_exec_memfd_create": Waiver(
        "memfd_create(2) is the anonymous in-memory file of fileless execution; the "
        "memfd_create-then-execveat sequence on one pid within 10s is the whole signal",
        "655e1e5a6b78cfe16bb304363669fef0a4af4c23b937f0283f2161ebbe23da8a"),
    "T1685/io_uring_setup.yml": Waiver(
        "creating an io_uring ring is the sensor-evasion surface",
        "b50573eddab59ad45de592ca2f1fe47f1cdcb700f3440aaf8da792129da08357"),
    "T1685/k8s_admission_webhook_disabled.yml": Waiver(
        "TRR9008 chokepoint: any delete/update/patch of an admission control object",
        "b4763cb3de364ecf10d4c72b2406d9a2c55323b79f51bc8ec2eb223d173250b8"),
}


# R4: a rule that keys on a PLATFORM's naming convention, which the emulation's
# identity embeds after the emulation name (AWS's console names an identity pool's
# guest role Cognito_<pool>Unauth_Role). The rename test cannot tell that part of
# the token from the emulation's own naming, so a human names the convention's
# substrings (`keep`); the rename keeps them and renames every other character.
PLATFORM_NAMING = {
    "T1078.004/aws_cognito_unauthenticated_identity_use.yml": Waiver(
        "the Cognito console names an identity pool's guest role Cognito_<pool>Unauth_Role "
        "(Amplify: ...-unauthRole); the rule keys on that convention by design and documents "
        "a renamed guest role as a miss. The emulation's pool name is trr9016Pool, so its "
        "role is Cognito_trr9016PoolUnauth_Role",
        "665831c4b77beacc294c500847e49abd330e02ae27a9625a7766ae71e291042c",
        keep=("Unauth",)),
}

WAIVERS = (("COMPILE_ONLY", COMPILE_ONLY), ("CHOKEPOINT", CHOKEPOINT), ("PRESENCE", PRESENCE),
           ("PLATFORM_NAMING", PLATFORM_NAMING))


def detection_digest(path):
    """What a waiver approves: sha256 of the rule file's name, id, logsource,
    detection and correlation blocks (every YAML document, in order), as canonical
    JSON. Comments, description, tags and other metadata are not part of it."""
    with open(path, encoding="utf-8") as fh:
        docs = [d for d in yaml.safe_load_all(fh) if d]
    content = [{k: d[k] for k in ("name", "id", "logsource", "detection", "correlation")
                if k in d} for d in docs if isinstance(d, dict)]
    text = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def waiver_rule(key):
    """(rule key, base name or None) of a waiver key ("<rule> base:<name>" for a base)."""
    rule, _, base = key.partition(" base:")
    return rule, (base or None)


def _waiver_json(waiver):
    return dict(waiver._asdict()) if waiver else None


def check_waiver_digest(r, check, table, key, path):
    """Fail `check` when the waiver's approved digest no longer matches the rule."""
    waiver = table[key]
    now = detection_digest(path)
    if waiver.digest == now:
        return True
    name = next(n for n, t in WAIVERS if t is table)
    r.fail(check, f"the {name} waiver for `{key}` was approved for rule digest "
                  f"{waiver.digest[:16]}..., and the rule's name/id/logsource/detection/"
                  f"correlation now digest to {now}: the rule changed since a human approved "
                  f"the waiver ({waiver.why}), so the waiver no longer excuses it. A human "
                  "re-reviews the changed rule and, if the reason still holds, re-approves it "
                  f"by setting the entry's digest to \"{now}\" in check_sufficiency.py (a "
                  "protected path); otherwise revert the rule change")
    return False


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


CLOUD_PROVIDERS = ("aws", "azure", "gcp")


def _proven_on(label, entry):
    """The logsource fields of the log a MANIFEST entry proves its rule on.

    Each value is read where the validator itself reads it: the API-server
    validator unpacks (folder, rule, source, ...), the TRR9003 validator (rule,
    source, ...) and the cloud validator (trr, folder, rule, attack, benign,
    provider, ...). A value outside the known set raises (a fail-closed error).
    """
    if label == "auditd":
        return {"product": "linux", "service": "auditd"}
    if label == "trr9002":
        return {"product": "kubernetes", "service": "audit"}
    if label in ("apiserver", "trr9003"):
        source = entry[2] if label == "apiserver" else entry[1]
        # The node file-event sensor (C2-7): a 'file' source proves a rule on the
        # Linux file_event log (the node file-integrity / EDR / auditd open+write
        # telemetry the two node rules read), not the Kubernetes audit log.
        if source == "file":
            return {"product": "linux", "category": "file_event"}
        if source not in ("audit", "cri"):
            raise ValueError(f"MANIFEST entry {entry!r:.120} names log source {source!r}, "
                             "not 'audit', 'cri' or 'file'")
        return {"product": "kubernetes", "service": source}
    if label == "cloud":
        provider = str(entry[5]).lower()
        if provider not in CLOUD_PROVIDERS:
            raise ValueError(f"MANIFEST entry {entry!r:.120} names provider {entry[5]!r}, not "
                             f"one of {', '.join(CLOUD_PROVIDERS)}")
        return {"product": provider}
    raise ValueError(f"no log source is known for validator {label}")


def load_manifests():
    """({rule key: [validator label, ...]}, {rule key: [cloud entry, ...]},
    {rule key: [(validator label, logsource it is proven on), ...]},
    {rule key: [auditd atomic source, ...]}, errors)."""
    import importlib

    positives, cloud, proven, atomics, errors = {}, {}, {}, {}, []
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
                where = _proven_on(label, entry)
            except (ValueError, IndexError) as e:
                errors.append(f"{name}: {e}")
                continue
            if label not in positives.setdefault(key, []):
                positives[key].append(label)
            if (label, where) not in proven.setdefault(key, []):
                proven[key].append((label, where))
            if label == "cloud":
                cloud.setdefault(key, []).append(_cloud_entry(module, entry))
            if label == "auditd":
                for src in (x for x in entry if isinstance(x, str) and x.endswith(".c")):
                    if src not in atomics.setdefault(key, []):
                        atomics[key].append(src)
    return positives, cloud, proven, atomics, errors


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
    """Selection items that make the event the technique (not its surface).

    A correlation has none of its own: base presence, group-by, timespan, order
    and threshold say which events go together. What makes an event the
    technique lives in its bases (see base_items). Nor is the item of a null guard
    or a null-safe copy: it changes no two-valued verdict (the rule is graded
    stripped of them)."""
    if rule.is_correlation:
        return []
    rule = rule.stripped()
    surface = set(surface_atoms(rule))
    return [a for a in rule.positive_atoms() if a not in surface]


def base_items(rule):
    """{base ref: (discriminating items, filter items)} of a correlation's bases."""
    return {ref: (discriminating_atoms(base), base.negated_atoms())
            for ref, base in rule.bases.items()}


def base_negative_items(rule, events, refs):
    """Base-level items a correlation negative breaks, as "base:<ref>/<item>".

    For each base the negative misses (`refs`, from its verified `breaks` or the
    grader's repairs), every event of the set that no base matches and that misses
    that base by one item flip (near-miss) or by one filter (filtered) is marked as
    the base's match, and the compiled correlation (that base relaxed to "the
    marked event") runs on the set. If it fires, the event is the base's near-miss
    in the right group and window, and the items it flips are what the negative
    exercises in that base.
    """
    out = []
    table = sigma_eval.EventTable(events)
    matched = {i for base in rule.bases.values() for hit in table.hit_indices(base.sql)
               for i in hit}
    for ref in refs:
        base = rule.bases.get(ref)
        if base is None:
            continue
        rows, _ = base.truth_table(table)
        for i, event in enumerate(events):
            if i in matched:
                continue
            v = base.verdict(event, rows[i], False)
            if v.mismatch or v.kind not in sigma_explain.NON_TRIVIAL or not v.atoms:
                continue
            key = f"base:{ref}"
            marked = [dict(e, **{sigma_explain.REPAIR_FIELD: key}) if j == i else e
                      for j, e in enumerate(events)]
            if not rule._fires(marked, rule._variant(key)):
                continue
            for atom in v.atoms:
                item = f"{key}/{atom}"
                if item not in out:
                    out.append(item)
    return out


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


def _with_true(node, atom):
    """The condition tree with `atom` true: True, False or the subtree it still reads."""
    if node[0] == "id":
        return True if node[1] == atom else node
    if node[0] == "not":
        inner = _with_true(node[1], atom)
        return (not inner) if isinstance(inner, bool) else ("not", inner)
    done = node[0] == "or"  # one true child decides an OR, one false child an AND
    kids = [_with_true(c, atom) for c in node[1]]
    if any(k is done for k in kids):
        return done
    kids = [k for k in kids if not isinstance(k, bool)]
    return (not done) if not kids else kids[0] if len(kids) == 1 else (node[0], kids)


def _reads(node):
    """The items a condition (sub)tree reads."""
    if isinstance(node, bool):
        return set()
    return {node[1]} if node[0] == "id" else set().union(*(_reads(c) for c in (
        [node[1]] if node[0] == "not" else node[1])))


# _lone_atoms() searches every truth assignment of a rule's items, so it searches only
# a rule of at most this many items.
LONE_SEARCH_ITEMS = 12


def _lone_atoms(rule):
    """The items of a plain rule that no near-miss can break: each fires the rule alone.

    An item is lone when the condition never negates it and, with it true, the
    condition can still hold and reads no other selection item. (Filters, items that
    are also negated, and items that hold on an empty record are not selection items:
    the grader keeps them when it asks whether a flip shares a branch.) A record that
    one flip of the item makes fire then holds no selection item of that branch, so
    rule_cases.py grades it trivial or does not count that flip.

    The grader then confirms each such item: sigma_explain's own verdict runs on every
    truth assignment of the rule's items (_counted_flips), and an item that one of
    those verdicts counts as a negative's flip is not lone. A rule of more than
    LONE_SEARCH_ITEMS items is not searched, so none of its items is lone. The shape
    test does not clear every item that no case can break: it keeps `a` in
    `(a and not f) or b`, an item that is also negated (`m` in `(a and m) or not m`),
    and an item whose flip alone never fires the rule (`a` in `(a and b) or b`)."""
    if rule.is_correlation or len(rule.atoms) > LONE_SEARCH_ITEMS:
        return set()
    selection = {a for a in rule.atoms if rule.polarity[a] == {"+"} and a not in rule.vacuous}
    lone = set()
    for atom in rule.positive_atoms():
        if rule.polarity[atom] != {"+"}:
            continue  # also negated: kept (the shape test does not decide it)
        rest = _with_true(rule.tree, atom)
        if rest is not False and not _reads(rest) & selection:
            lone.add(atom)
    return lone - _counted_flips(rule) if lone else lone


def _counted_flips(rule):
    """The items that sigma_explain counts as a negative's flip (a near-miss or filtered
    verdict's atoms) in some truth assignment of the plain rule's items. A case or a
    fixture record can break only such an item (rule_cases.run_case)."""
    counted = set()
    for bits in itertools.product((False, True), repeat=len(rule.atoms)):
        truth = dict(zip(rule.atoms, bits))
        fired = rule.evaluate(truth)
        if not fired:
            verdict = rule.verdict({}, truth, fired)
            if verdict.kind in sigma_explain.NON_TRIVIAL:
                counted.update(verdict.atoms)
    return counted


def _merge_key(rule, items):
    """The `field|mods` key that each of `items` writes, when they all write the same one
    without `|all` (so one item with a list of their values matches the same records);
    else None."""
    keys = set()
    for atom in items:
        block = rule.block_of[atom]
        definition = rule.definitions.get(block)
        rest = atom[len(block):]
        m = re.match(r"\[(\d+)\]", rest)
        if m and isinstance(definition, list):
            definition, rest = definition[int(m.group(1))], rest[m.end():]
        elif isinstance(definition, list) and len(definition) == 1:
            definition = definition[0]
        name = rest.lstrip(".")
        found = [k for k in definition if str(k) == name or str(k).split("|")[0] == name] \
            if name and isinstance(definition, dict) else []
        if len(found) != 1:
            return None
        keys.add(str(found[0]))
    key = keys.pop() if len(keys) == 1 else None
    return key if key is not None and "all" not in key.split("|")[1:] else None


def _no_near_miss_hint(rule, key, target, dropped, filters, lone, cloud_fixture, exclude,
                       name_keyed=False):
    """_negative_hint() when every item it could offer is lone (`dropped`).

    `exclude` names the items that the caller sets aside: for R2 and R5 the items that
    the rule's verified negatives already break (so a non-empty `exclude` means the rule
    has a negative, and PRESENCE, which excuses only a rule with none, does not help it),
    for R4 (`name_keyed`) the name-keyed items, which a new negative must not break
    alone. `filters` are the rule's filters outside `exclude`. A pure-surface rule that
    CHOKEPOINT (`key`) does not list fails R2 whatever its negatives, so for it the hint
    says to restore its argument first."""
    shown = ", ".join(atom_spec(rule, a) for a in dropped[:6]) \
        + (f" (+{len(dropped) - 6} more)" if len(dropped) > 6 else "")
    text = f"No near-miss can break {shown}: " \
           + ("it is" if len(dropped) == 1 else "each is") + " the only selection item of " \
           "its branch (filters, items that are also negated, and items that hold on an empty " \
           "record do not count), so a record without it holds no selection item of that " \
           "branch (rule_cases.py grades such a record trivial, or does not count that flip " \
           "because the record holds no item of the branch)"
    trip = ""
    if filters:
        trip = f"a filtered case to {target} (an allowlisted look-alike doing the " \
               f"positive's exact call) that trips one of: {', '.join(filters[:4])}"
        if cloud_fixture:
            trip += f", or add such a record to `{rel(cloud_fixture)}` (the fixture must " \
                    "stay clean for every rule that reads it)"
    selected = [a for a in rule.positive_atoms() if a not in rule.vacuous]
    disc = discriminating_atoms(rule)
    if not disc and key not in CHOKEPOINT:
        # check_rule fails a pure-surface rule outside CHOKEPOINT, whatever its negatives.
        text += ". Every positive item of the rule is a surface field, and R2 fails such a " \
                "rule whatever its negatives: restore its argument. Only if the record kind " \
                "itself is the technique may a human list the rule in CHOKEPOINT" \
                + (" and in PRESENCE" if len(selected) == 1 and not rule.negated_atoms()
                   and not exclude else "") \
                + " in check_sufficiency.py, with the reason"
        return text + (f"; then add {trip}" if trip else "")
    keyed = [a for a in rule.atoms if a in exclude] if name_keyed else []
    if keyed and not filters:
        # Every item outside `exclude` that a negative could break is named above.
        return text + "; every other item and filter that a negative can break is " \
            "name-keyed (" + ", ".join(keyed) + "), so " \
            "every negative the rule can have breaks only name-keyed items: add a filter " \
            "or, where the technique has one, a second required item to the branch of each " \
            "item named above"
    if trip:
        text += f"; add {trip}"
    if rule.negated_atoms():
        if set(selected) <= lone:
            text += "; its proof is the positive and the filtered cases, and its " \
                    "benign-corpus budget if a benign slice reads its log source " \
                    "(score_benign.py says which)"
        return text
    text += "; the rule has no filter for a filtered case to trip"
    if not set(disc) <= lone:
        # Not reached from check_rule or thin_checks: R2 and R5 set aside no
        # discriminating item, and R4 returned above.
        return text  # a discriminating item left out by `exclude` may still be broken
    if len(selected) == 1 and not exclude:
        return text + ", and it has one positive item (items that hold on an empty record " \
            "aside), so a human may list it in PRESENCE in check_sufficiency.py, with the " \
            "reason; its proof is then the positive and its benign-corpus budget"
    # A pure-surface rule here is in CHOKEPOINT, so any negative counts for it.
    text += ", so no negative can break " + ("a discriminating item" if disc else "an item") \
        + " or a filter: "
    merge = _merge_key(rule, selected) \
        if len(selected) > 1 and set(selected) <= lone and not rule.vacuous else None
    if merge:
        text += f"its items all read `{merge}`, so merge them into one item with a list of " \
                "values (a human may then list the rule in PRESENCE, with the reason), or "
    text += "add a filter or, where the technique has one, a second required item to the " \
            "branch of each item named above"
    if len(selected) > 1:
        text += ", or move each such branch to a rule of its own (a human may then list a " \
                "rule of one item and no filter in " \
                + ("PRESENCE" if disc else "CHOKEPOINT and PRESENCE") + ", with the reason)"
    return text


def _negative_hint(rule, path, exclude=(), cloud_fixture=None, keep_extra=None):
    """'Add a near-miss case to X that keeps <surface> and breaks one of: <items>',
    or 'No near-miss can break <items>: ...' when no item is left to offer.

    The hint does not offer an item that _lone_atoms() clears (no near-miss can
    break it). For R4 (`keep_extra`), a flip of any item outside `exclude` (the
    name-keyed items) clears the failure, so when no discriminating item is left the
    hint offers the surface items that are not lone. When no item is left, the hint
    says so, names the filters that a filtered case can still trip (those not in
    `exclude`), and says what is left: the rule's proof when no selection item of it
    can be broken, or how to change the rule when no negative can be what the caller
    needs (_no_near_miss_hint)."""
    target = f"`{_cases_rel(path)}`"
    if rule.is_correlation:
        bases = [a for a in rule.atoms if a.startswith("base:") and a not in exclude]
        other = [a for a in ("group-by", "timespan", "order", "threshold")
                 if a in rule.atoms and a not in exclude]
        text = f"Add a near-miss case to {target}: the full correlation whose event for one " \
               "base misses that base by one discriminating item, or half a correlation, " \
               f"every event but one base's (breaks one of: {', '.join(bases) or '-'})"
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

    lone = _lone_atoms(rule)
    dropped = [a for a in picks if a in lone]
    picks = [a for a in picks if a not in lone]
    if dropped and not picks and keep_extra:
        # R4: a flip of any item outside `exclude` clears it, so offer the surface too.
        picks = [a for a in rule.positive_atoms() if a not in exclude and a not in lone]
        dropped = [a for a in rule.positive_atoms() if a not in exclude and a in lone]
        keep = others
    filters = [a for a in rule.negated_atoms() if a not in exclude]
    if dropped and not picks:
        return _no_near_miss_hint(rule, rule_key(path), target, dropped, filters, lone,
                                  cloud_fixture, exclude, name_keyed=bool(keep_extra))
    if keep_extra:
        keep = f"{keep_extra} and {keep}"
    text = f"Add a near-miss case to {target} that keeps {keep} and breaks exactly one of: " \
           f"{', '.join(atom_spec(rule, a) for a in picks[:6])}"
    if len(picks) > 6:
        text += f" (+{len(picks) - 6} more; `rule_cases.py --atoms` lists them)"
    if filters:
        text += f"; or a filtered case (an allowlisted look-alike doing the positive's exact " \
                f"call) that trips one of: {', '.join(filters[:4])}"
    if cloud_fixture:
        text += f"; or add such a record to `{rel(cloud_fixture)}` (the fixture must stay " \
                "clean for every rule that reads it)"
    return text


# ---- marker analysis (R4) --------------------------------------------------


_RANDOM = random.SystemRandom()
_CHAR_CLASSES = (string.ascii_lowercase, string.ascii_uppercase, string.digits)


def _derangement(chars):
    """A random permutation of `chars` that moves every character."""
    while True:
        out = list(chars)
        _RANDOM.shuffle(out)
        if all(a != b for a, b in zip(chars, out)):
            return dict(zip(chars, out))


# The two renames, drawn once per run (os.urandom through SystemRandom), so a rule
# cannot list the replacement:
# - SAME-SHAPE: every lowercase letter, uppercase letter and digit becomes another
#   of its class (one random substitution for the run, so a name that recurs in a
#   unit, e.g. across a correlation's events, stays one name); other characters
#   are kept. It catches a rule keyed on a part of the name, however spelled.
# - NEUTRAL: each renamed stretch becomes random lowercase letters of a different
#   length (one per distinct stretch for the run). It catches a rule keyed on the
#   name's shape (`_[a-z]{10}$`, `^[a-z]{3}\d{4}-`), which the first rename keeps.
_SAME_SHAPE = {}
for _chars in _CHAR_CLASSES:
    _SAME_SHAPE.update(_derangement(_chars))
_NEUTRAL = {}
RENAMES = ("same-shape", "neutral")


def _neutral(text):
    if text not in _NEUTRAL:
        taken = set(_NEUTRAL.values())
        while True:
            token = "".join(_RANDOM.choice(string.ascii_lowercase)
                            for _ in range(len(text) + _RANDOM.randint(3, 8)))
            if token not in taken:
                break
        _NEUTRAL[text] = token
    return _NEUTRAL[text]


# The rest of an identity token after an emulation name or a marker: letters,
# digits, `_`, `.` and `-` (a token ends at `/`, `:`, `=`, a quote, a space, ...).
TOKEN_REST = r"[\w.-]*"


def rename_pattern(markers=()):
    """Every emulation IDENTITY: an emulation name or a gate marker (longest
    marker first) and the rest of its token, case-insensitive. `deteng_val_x`,
    `deteng_afxdp_socket_behavioral` and `trr9026-target` are renamed whole.

    The token is renamed from the name onward, not from its first character: the
    platform writes what comes before it (the AWS unique-id type in
    `AKIATRR9012EXAMPLE01`, `ami-`, `fs-`, `Cognito_`), and a rule may key on
    that. A rule keyed on such a prefix is not caught here (residual)."""
    cores = [re.escape(m) for m in sorted({m for m in markers if m}, key=len, reverse=True)]
    cores.append(EMULATION_NAME.pattern)
    return re.compile(rf"(?:{'|'.join(cores)}){TOKEN_REST}", re.IGNORECASE)


def _rename_token(token, keep=(), how="same-shape"):
    """The token renamed (see RENAMES), except the substrings a PLATFORM_NAMING
    waiver keeps: those stay, and each stretch between them is renamed."""
    kept = set()
    for k in keep:
        for m in re.finditer(re.escape(k), token, re.IGNORECASE):
            kept.update(range(*m.span()))
    if how == "same-shape":
        return "".join(ch if i in kept else _SAME_SHAPE.get(ch, ch)
                       for i, ch in enumerate(token))
    out = []
    for is_kept, run in itertools.groupby(range(len(token)), key=lambda i: i in kept):
        run = list(run)
        text = token[run[0]:run[-1] + 1]
        out.append(text if is_kept else _neutral(text))
    return "".join(out)


def rename_names(event, pattern, keep=(), how="same-shape"):
    """The flat event with every match of `pattern` in a value renamed (`how`: one
    of RENAMES)."""
    return {k: pattern.sub(lambda m: _rename_token(m.group(0), keep, how), v)
            if isinstance(v, str) else v for k, v in event.items()}


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


def rename_test(rule, units, pattern, keep=()):
    """Rename the emulation's identities in every positive unit, once by each of
    RENAMES; does each still fire?

    `units` is [(label, [flat events])], each a unit that fires the rule (a
    passing positive case, its copy carrying the Linux emulation's identity, or
    one marker-carrying attack record / alert). Returns {"units", "renamed",
    "stopped": [{"unit", "names", "flipped", "renames"}], "name_keyed"}; "renames"
    lists the renames that stopped the unit firing.
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
        flipped, stopped_by = [], []
        for how in RENAMES:
            renamed = [rename_names(e, pattern, keep, how) for e in own]
            flipped += [a for a in _flipped_atoms(rule, own, renamed) if a not in flipped]
            if not _fires(rule, renamed):
                stopped_by.append(how)
        out["name_keyed"] |= set(flipped)
        if stopped_by:
            out["stopped"].append({"unit": label, "flipped": flipped, "renames": stopped_by,
                                   "names": [names[k] for k in sorted(names)]})
    out["name_keyed"] = [a for a in rule.atoms if a in out["name_keyed"]]
    return out


# How validate_detections.py names a Linux emulation: compile_atomic builds the
# atomic `<dir>/<stem>.c` as `deteng_<stem>` inside tempfile.mkdtemp(prefix=
# "deteng_val_"), so the kernel logs that path as exe and its first 15 characters
# as comm (TASK_COMM_LEN).
MKDTEMP_CHARS = string.ascii_lowercase + string.digits + "_"


def emulation_identity(src):
    """{"exe", "comm"} the auditd validator's run of atomic `src` carries; the
    mkdtemp directory is random, as it is in the validator's run."""
    binary = "deteng_" + os.path.basename(src)[:-len(".c")]
    workdir = "deteng_val_" + "".join(_RANDOM.choice(MKDTEMP_CHARS) for _ in range(8))
    return {"exe": f"/tmp/{workdir}/{binary}", "comm": binary[:15]}


def emulation_units(rule, units, atomics):
    """Each passing positive unit with every event's exe and comm set to the
    identity of each emulation (atomic) the auditd validator runs for the rule, if
    that copy fires: the rename test then renames the emulation's real names, not
    what the sidecar author wrote."""
    out = []
    for src in atomics:
        identity = emulation_identity(src)
        for label, own in units:
            copy = [dict(e, **identity) for e in own]
            if _fires(rule, copy):
                out.append((f"{label} as the emulation `{identity['exe']}`", copy))
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
        self.positive_cases = 0  # passing sidecar positive cases
        self.case_digests = {}  # every sidecar case: name -> {"kind", "digest"}
        self.negatives = []  # {"source", "kind", "atoms", "digest"[, "base_items"]}
        self.exercised = []
        self.base_exercised = []  # correlation: "base:<ref>/<item>" its negatives break
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
    def sidecar_positive(self):
        return self.positive_cases > 0

    @property
    def atoms(self):
        return list(self.rule.atoms) if self.rule else []

    @property
    def logsources(self):
        """The logsource of the rule, or of each base of a correlation ("base:<ref>")."""
        if not self.rule:
            return None
        if self.rule.is_correlation:
            return {f"base:{ref}": dict(b.logsource) for ref, b in sorted(self.rule.bases.items())}
        return {"rule": dict(self.rule.logsource)}

    @property
    def ratio(self):
        return len(self.exercised) / len(self.atoms) if self.atoms else 0.0

    def to_json(self):
        return {
            "rule": self.key, "platform": self.platform, "status": self.status,
            "logsource": dict(self.rule.logsource) if self.rule else None,
            "logsources": self.logsources,
            "positives": self.positives, "compile_only": _waiver_json(self.compile_only),
            "chokepoint": {k: _waiver_json(w) for k, w in CHOKEPOINT.items()
                           if waiver_rule(k)[0] == self.key} or None,
            "presence": _waiver_json(PRESENCE.get(self.key)),
            "cases": {"file": rel(self.cases_file) if self.cases_file else None,
                      "total": self.case_total, "passed": self.case_passed,
                      "positive": self.sidecar_positive, "positives": self.positive_cases,
                      "digests": self.case_digests},
            "negatives": self.negatives,
            "atoms": {"total": len(self.atoms), "exercised": self.exercised,
                      "base_exercised": self.base_exercised,
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


def _base_refs(atoms):
    return [a[len("base:"):] for a in atoms if a.startswith("base:")]


def check_logsource(r, rule, proven):
    """R1: the rule's logsource names the log each validator proves it on."""
    sources = [(f"base:{ref} ", b.logsource) for ref, b in rule.bases.items()] \
        if rule.is_correlation else [("", rule.logsource)]
    for label, want in proven:
        for where, logsource in sources:
            have = {k: str(logsource.get(k) or "").lower() for k in want}
            if have != want:
                shown = "/".join(f"{k}: {logsource.get(k)}" for k in want)
                r.fail("R1", f"{where}logsource ({shown}) disagrees with the log the {label} "
                             "validator proves the rule on ("
                             + ", ".join(f"{k}: {v}" for k, v in want.items()) + "). The "
                             "benign corpus scores a rule only on the slices of its logsource, "
                             "so the rule would be scored on a log it never reads (a noisy rule "
                             "escapes its budget that way). Set the logsource to the log the "
                             "validator reads, or register the rule with the validator of its "
                             "log")


def content_digest(value):
    """sha256 of `value` as canonical JSON (what the ratchet compares)."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def case_digest(case):
    """A sidecar case's content: its kind, `breaks` and events (not its why or
    source text, so rewording a case does not change it)."""
    return content_digest({"kind": case["kind"], "breaks": case.get("breaks"),
                           "events": case["events"]})


def check_rule(path, positives, cloud, proven=None, atomics=None):
    r = Report(path)
    try:
        # Graded without its null guards and null-safe copies (see the docstring).
        rule = sigma_explain.load(path).stripped()
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
            r.case_digests[case["name"]] = {"kind": case["kind"], "digest": case_digest(case)}
            where = f"case '{case['name']}' ({case['kind']}, `{rel(cases_path)}` " \
                    f"line {case.get('_line', '?')})"
            if not res.ok:
                r.fail("R3", f"{where} fails: {res.detail}. Fix the event set or, if the case "
                             "is right, the rule; never relabel or weaken the case")
                continue
            r.case_passed += 1
            if case["kind"] == "positive":
                r.positive_cases += 1
                r.positive_units.append((f"positive case '{case['name']}'",
                                         [sigma_eval.flatten(e) for e in case["events"]]))
            elif case["kind"] in ("near-miss", "filtered"):
                breaks = case["breaks"] if isinstance(case["breaks"], list) else [case["breaks"]]
                negative = {"source": f"case:{case['name']}", "kind": case["kind"],
                            "atoms": list(breaks),
                            "digest": r.case_digests[case["name"]]["digest"]}
                if rule.is_correlation:
                    negative["base_items"] = base_negative_items(
                        rule, [sigma_eval.flatten(e) for e in case["events"]], _base_refs(breaks))
                r.negatives.append(negative)
            elif res.verdict.kind in sigma_explain.NON_TRIVIAL and res.verdict.atoms:
                unverified.append(f"case '{case['name']}' is declared {case['kind']} but "
                                  f"already grades {res.verdict.kind} on "
                                  f"{', '.join(a for a in res.verdict.atoms if a in rule.atoms)}"
                                  f"; declare it kind {res.verdict.kind} with that `breaks` to "
                                  "count it")

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
                negative = {"source": f"fixture:{label}", "kind": v.kind, "atoms": list(v.atoms),
                            "digest": content_digest(events if rule.is_correlation
                                                     else events[i])}
                if rule.is_correlation:
                    negative["base_items"] = base_negative_items(rule, events,
                                                                 _base_refs(v.atoms))
                r.negatives.append(negative)

    r.exercised = [a for a in rule.atoms if any(a in n["atoms"] for n in r.negatives)]
    for n in r.negatives:
        r.base_exercised += [b for b in n.get("base_items", ()) if b not in r.base_exercised]

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
    if r.compile_only:
        check_waiver_digest(r, "R1", COMPILE_ONLY, r.key, path)
    check_logsource(r, rule, (proven or {}).get(r.key, []))

    # R2 verdict.
    for key in [k for k in CHOKEPOINT if waiver_rule(k)[0] == r.key]:
        check_waiver_digest(r, "R2", CHOKEPOINT, key, path)
    if r.key in PRESENCE:
        check_waiver_digest(r, "R2", PRESENCE, r.key, path)
    disc = set(discriminating_atoms(rule))
    pure_surface = not disc
    needs = check_bases(r, rule) if rule.is_correlation else {}
    if not rule.is_correlation and pure_surface and r.key not in CHOKEPOINT:
        r.fail("R2", f"every positive item is a surface field ("
                     f"{_surface_parts(rule) or 'it has no positive item'}), so "
                     "the rule matches every record of that kind and no negative can show "
                     "that an argument of the technique is load-bearing. This is the shape a "
                     "rule takes when it loses its argument (an `a0`, a provenance field, a "
                     "policy pattern): restore it. Only if the record kind itself is the "
                     "technique may a human list the rule in CHOKEPOINT in check_sufficiency.py, "
                     "with the reason")
    if r.key in CHOKEPOINT and rule.is_correlation:
        r.warn("R2", "CHOKEPOINT lists the correlation itself, but R2 runs on each base: name "
                     f"the base (\"{r.key} base:<name>\") or remove the stale waiver from "
                     "check_sufficiency.py")
    elif r.key in CHOKEPOINT and not pure_surface:
        r.warn("R2", "listed in CHOKEPOINT but the rule has discriminating items ("
                     + ", ".join(a for a in rule.atoms if a in disc)
                     + "); remove the stale waiver from check_sufficiency.py")
    presence = (len([a for a in rule.positive_atoms() if a not in getattr(rule, "vacuous", ())])
                == 1 and not rule.negated_atoms()) if not rule.is_correlation else False
    if r.key in PRESENCE and not presence:
        # The R2 hint (_negative_hint) says which negative, if any, the rule can have.
        r.warn("R2", "listed in PRESENCE but the rule has more than one positive item or a "
                     "filter, so PRESENCE does not cover it: remove the stale waiver from "
                     "check_sufficiency.py (an R2 failure, if the rule has one, says what "
                     "negative it needs)")
    if not r.negatives and r.key in PRESENCE and presence:
        r.warn("R2", "presence rule (PRESENCE waiver): no negative can be one item flip from "
                     f"firing; its proof is the positive case and its benign-corpus budget "
                     f"({PRESENCE[r.key].why})")
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
    elif rule.is_correlation:
        # Each base with an argument needs a negative that breaks it in place.
        for ref, decisive in needs.items():
            want = {f"base:{ref}/{a}" for a in decisive}
            if any(want & set(n.get("base_items", ())) for n in r.negatives):
                continue
            base = rule.bases[ref]
            disc_items = [a for a in decisive if a not in base.negated_atoms()]
            keep = _surface_text(base) or "the base's other items"
            r.fail("R2", f"no verified negative breaks a discriminating item of base:{ref} ("
                         + ", ".join(atom_spec(base, a) for a in disc_items[:6]) + "): every "
                         "negative only drops a base's event or moves events out of the group or "
                         "the window, which passes just as well for the rule with that base's "
                         "argument deleted. Add a near-miss case to "
                         f"`{_cases_rel(path)}`: the full correlation (one group, inside the "
                         f"window) whose base:{ref} event keeps {keep} and breaks exactly one of "
                         "those items, declared `breaks: [\"base:" + ref + "\"]`"
                         + (f"; or a filtered look-alike for its filter "
                            f"({', '.join(base.negated_atoms()[:4])})"
                            if base.negated_atoms() else ""))
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

    check_names(r, rule, path, cloud.get(r.key, []), (atomics or {}).get(r.key, []))
    return r


def check_bases(r, rule):
    """R2 on each base of a correlation: a pure-surface base fails unless CHOKEPOINT
    names it. Returns {base ref: decisive items} for every base with an argument
    (discriminating items, plus its filters), which a negative must break in place."""
    needs = {}
    for ref, (disc, filters) in base_items(rule).items():
        key = f"{r.key} base:{ref}"
        if not disc and key not in CHOKEPOINT:
            r.fail("R2", f"base:{ref}: every positive item of the base is a surface field ("
                         f"{_surface_parts(rule.bases[ref]) or 'it has no positive item'}), so "
                         "it matches every record of that kind and the correlation's group-by, "
                         "window and order are all that is left of the argument. This is the "
                         "shape a base takes when it loses its argument (an `a0`, a protocol, a "
                         "flag): restore it. Only if the record kind itself is that step of the "
                         f"technique may a human list \"{key}\" in CHOKEPOINT in "
                         "check_sufficiency.py, with the reason")
        elif disc and key in CHOKEPOINT:
            r.warn("R2", f"CHOKEPOINT lists `{key}` but the base has discriminating items ("
                         + ", ".join(disc) + "); remove the stale waiver from "
                         "check_sufficiency.py")
        if disc:
            needs[ref] = list(disc) + list(filters)
    return needs


def check_names(r, rule, path, entries, atomics=()):
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
        checked += [(f"renamed ({how}) {label}", rename_names(e, pattern, how=how))
                    for how in RENAMES for label, e in checked]
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
    keep = ()
    if r.key in PLATFORM_NAMING:
        check_waiver_digest(r, "R4", PLATFORM_NAMING, r.key, path)
        keep = tuple(PLATFORM_NAMING[r.key].keep)
    emulated = emulation_units(rule, r.positive_units, atomics)
    units = r.positive_units + emulated + attack_units
    r.rename = dict(rename_test(rule, units, pattern, keep), markers=markers, kept=list(keep),
                    attack_units=len(attack_units), emulation_units=len(emulated))
    if not units:
        r.fail("R4", "no positive unit to run the rename test on: "
                     + ("; ".join(no_attack) + ", and " if no_attack else "")
                     + f"there is no passing positive case in `{_cases_rel(path)}`. Add the "
                     "emulation's own event as a positive case, so renaming its names can show "
                     "the rule keys on the technique")
    elif not r.rename["renamed"] and not r.compile_only:
        r.fail("R4", f"no positive unit carries an emulation identity (0/{len(units)} carry "
                     "trr9NNN, deteng_ or a validator gate's marker), so the rename test renamed "
                     "nothing and cannot show the rule keys on the technique rather than on the "
                     f"emulation's naming. Add a positive case to `{_cases_rel(path)}` that is the "
                     "emulation's own record, with the names the emulation gives its objects as "
                     "the validator's run writes them")
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
        how = [h for h in RENAMES if any(h in s["renames"] for s in stopped)]
        r.fail("R4", f"renaming the emulation's identities ({', '.join(list(names.values())[:4])}"
                     + (f" +{len(names) - 4} more" if len(names) > 4 else "")
                     + f") to random tokens ({' and '.join(how)} rename) stops the rule firing on "
                     f"{len(stopped)}/{len(units)} positive unit(s): {shown}. Items that flip: "
                     f"{', '.join(flipped) or 'no single item'}. The rule keys on the names the "
                     "emulation gives its objects (or on the validator gate's marker), however "
                     "it spells them, or on their shape; key it on the technique instead")

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
    positives, cloud, proven, atomics, manifest_errors = load_manifests()
    errors += manifest_errors
    paths = sorted(glob.glob(os.path.join(SIGMA, "*", "*.yml")))
    reports = [check_rule(p, positives, cloud, proven, atomics) for p in paths]
    medians = thin_checks(reports)

    known = {r.key: r.rule for r in reports}
    for key in sorted(set(positives) - set(known)):
        errors.append(f"a validator MANIFEST registers {key}, which does not exist")
    for name, table in WAIVERS:
        for key in sorted(table):
            rule, base = waiver_rule(key)
            if rule not in known:
                errors.append(f"{name} lists {key}, which does not exist; remove the entry")
            elif base is not None and not (getattr(known[rule], "is_correlation", False)
                                           and base in known[rule].bases):
                errors.append(f"{name} lists {key}, but {rule} has no correlation base named "
                              f"{base!r}; remove or rename the entry")
            elif base is not None and name != "CHOKEPOINT":
                errors.append(f"{name} lists {key}: only CHOKEPOINT waives one base of a "
                              "correlation; remove the entry")
            elif not (isinstance(table[key], Waiver) and isinstance(table[key].digest, str)
                      and re.fullmatch(r"[0-9a-f]{64}", table[key].digest)):
                errors.append(f"{name}[{key!r}] is not Waiver(why, <sha256 detection_digest>)")
            elif (name == "PLATFORM_NAMING") != bool(table[key].keep):
                errors.append(f"{name}[{key!r}]: `keep` belongs to PLATFORM_NAMING entries, and "
                              "every PLATFORM_NAMING entry names the substrings it keeps")
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
                print(f"      {n['kind']:<9} {n['source']}  breaks {', '.join(n['atoms'])}"
                      + (f"  (in place: {', '.join(n['base_items'])})"
                         if n.get("base_items") else ""))
            if r.rename:
                n = r.rename
                print(f"      rename test: {n['renamed']}/{n['units']} positive unit(s) carry a "
                      f"name ({n['attack_units']} attack record(s), {n['emulation_units']} "
                      "positive(s) carrying the emulation's identity); markers "
                      f"{', '.join(repr(m) for m in n['markers']) or '-'}; stopped firing: "
                      f"{len(n['stopped'])}; name-keyed items: "
                      f"{', '.join(n['name_keyed']) or '-'}"
                      + (f"; kept (PLATFORM_NAMING): {', '.join(n['kept'])}" if n['kept'] else ""))
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


# ---- the ratchet (--baseline) -----------------------------------------------


def ratchet(reports, baseline_path):
    """Compare each rule with the base branch's --json report.

    Returns (decreases, errors, notes): one line per base rule that is not on the
    head, and per rule in both that has fewer verified negatives, lost one or
    changed its content (a sidecar case's kind/breaks/events, or a fixture
    record), lost or changed any sidecar case, lost an item its negatives
    exercised (rule, correlation or base item), has fewer passing positive cases,
    lost its sidecar, or changed its logsource (or a base's); the reasons the
    baseline cannot be used (each fails the run: the ratchet fails closed); and
    notes on what could not be compared (a base report without content digests).
    """
    try:
        with open(baseline_path, encoding="utf-8") as fh:
            rules = json.load(fh)["rules"]
        base = {b["rule"]: b for b in rules}
    except (OSError, ValueError, KeyError, TypeError) as e:
        return [], [f"--baseline {baseline_path}: not a check_sufficiency.py --json report "
                    f"({type(e).__name__}: {e})"], []
    if not base:
        return [], [f"--baseline {baseline_path} holds no rule (the base run failed before "
                    "checking any rule, e.g. on R0 hygiene), so nothing can be compared"], []
    decreases, undigested = [], []
    head = {r.key for r in reports}
    for key, b in sorted(base.items()):
        if key not in head and not os.path.exists(os.path.join(SIGMA, key)):
            decreases.append(f"{key}: on the base branch but not on the head: deleted or renamed; "
                             f"its {len(b.get('negatives') or [])} verified negative(s) are not "
                             "compared")
    for r in reports:
        b = base.get(r.key)
        if b is None:
            continue  # a new rule: nothing to ratchet against
        lost = []
        b_cases = (b.get("cases") or {}).get("digests")
        changed_cases = []
        if b_cases is None:
            undigested.append(r.key)
        else:
            gone = [n for n in b_cases if n not in r.case_digests]
            for n, was in b_cases.items():
                now = r.case_digests.get(n)
                if now and (now["kind"], now["digest"]) != (was.get("kind"), was.get("digest")):
                    changed_cases.append(n)
            if gone:
                lost.append(f"sidecar case(s) gone: {', '.join(gone)}")
            if changed_cases:
                lost.append("sidecar case(s) changed (kind, breaks or events): " + ", ".join(
                    n + (f" ({b_cases[n].get('kind')} -> {r.case_digests[n]['kind']})"
                         if b_cases[n].get("kind") != r.case_digests[n]["kind"] else "")
                    for n in changed_cases))
        b_neg = b.get("negatives") or []
        now = {n["source"]: n.get("digest") for n in r.negatives}
        gone = [n.get("source") for n in b_neg if n.get("source") not in now]
        changed = [n["source"] for n in b_neg if n.get("source") in now
                   and n.get("digest") is not None and now[n["source"]] != n["digest"]
                   and n["source"] not in {f"case:{c}" for c in changed_cases}]  # said above
        if any(n.get("digest") is None for n in b_neg) and r.key not in undigested:
            undigested.append(r.key)
        if gone or len(r.negatives) < len(b_neg):
            lost.append(f"verified negatives {len(b_neg)} -> {len(r.negatives)}"
                        + (f" (gone: {', '.join(gone)})" if gone else ""))
        if changed:
            lost.append(f"verified negative(s) changed: {', '.join(changed)}")
        atoms = b.get("atoms") or {}
        for field, label, have in (("exercised", "items", r.exercised),
                                   ("base_exercised", "base items", r.base_exercised)):
            gone = [a for a in atoms.get(field) or [] if a not in have]
            if gone:
                lost.append(f"{label} its negatives exercised, now untested: {', '.join(gone)}")
        cases = b.get("cases") or {}
        b_pos = cases.get("positives")
        if not isinstance(b_pos, int):
            b_pos = 1 if cases.get("positive") else 0
        if r.positive_cases < b_pos:
            lost.append(f"passing positive cases {b_pos} -> {r.positive_cases}")
        if cases.get("file") and not r.cases_file:
            lost.append(f"its sidecar `{cases['file']}` is gone")
        b_ls = b.get("logsources")
        if b_ls is None and b.get("logsource") is not None:
            b_ls = {"rule": b["logsource"]}  # a report from before "logsources"
        if b_ls is not None and r.logsources is not None and b_ls != r.logsources:
            lost.append(f"logsource changed ({_logsources_text(b_ls)} -> "
                        f"{_logsources_text(r.logsources)}): the benign corpus scores a rule "
                        "only on the slices of its logsource, so a move changes which budget "
                        "and which slices apply")
        if lost:
            decreases.append(f"{r.key}: " + "; ".join(lost))
    notes = [f"{len(undigested)} rule(s) of the base report carry no case or negative digests "
             "(a report from an older check_sufficiency.py), so the content of their sidecar "
             "cases and verified negatives was not compared, only their counts and names: "
             + ", ".join(undigested[:6])
             + (f" (+{len(undigested) - 6} more)" if len(undigested) > 6 else "")] \
        if undigested else []
    return decreases, [], notes


def _logsources_text(logsources):
    return "; ".join((f"{k} " if k != "rule" else "")
                     + "/".join(f"{f}: {v}" for f, v in sorted((ls or {}).items()))
                     for k, ls in sorted(logsources.items()))


def print_ratchet(baseline_path, decreases, errors, notes=()):
    print(f"\nRatchet against {baseline_path} (the base branch's report):")
    for e in errors:
        print(f"  [ERROR] {e}")
    for d in decreases:
        print(f"  [RATCHET] {d}")
    for n in notes:
        print(f"  [NOTE] {n}")
    if errors or decreases:
        print(f"FAILED: {len(decreases)} rule(s) lost or changed checks against the base branch"
              + (f"; {len(errors)} baseline error(s)" if errors else "")
              + ". A decrease is a human's decision: restore the checks, or a human approves "
                "the pull request as it is.")
    else:
        print("OK: every base rule is on the head, and none has fewer verified negatives, "
              "exercised items, passing positives or sidecars, a different logsource, or a "
              "sidecar case or verified negative that is gone or changed"
              + (" (content not compared for the rules noted)" if notes else "") + ".")


def write_ratchet_markdown(path, decreases, errors, notes=()):
    ok = not (decreases or errors)
    lines = ["## Sufficiency ratchet (vs the base branch)", "",
             "**PASS**: no rule lost or changed checks." if ok else
             f"**FAIL**: {len(decreases)} rule(s) lost or changed checks against the base "
             "branch.", ""]
    lines += [f"- **error**: {e}" for e in errors]
    lines += [f"- {d}" for d in decreases]
    lines += [f"- **note**: {n}" for n in notes]
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
                       **{name.lower(): {k: _waiver_json(w) for k, w in table.items()}
                          for name, table in WAIVERS},
                       "rules": [r.to_json() for r in reports]}, fh, indent=2)
            fh.write("\n")
    if args.markdown:
        write_markdown(args.markdown, reports, medians, errors, subset)
    ok = summary(reports, medians, errors, subset)["ok"]
    if args.baseline:
        decreases, ratchet_errors, notes = ratchet(reports, args.baseline)
        print_ratchet(args.baseline, decreases, ratchet_errors, notes)
        if args.markdown:
            write_ratchet_markdown(args.markdown, decreases, ratchet_errors, notes)
        ok = ok and not (decreases or ratchet_errors)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
