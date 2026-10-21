#!/usr/bin/env python3
"""
Offline smoke test of the live capture split (score_benign.py --extra-split-at).

Only validate-apiserver-detections splits a real capture, and it runs only when
its paths change, weekly, or by hand. The benign-corpus job of
detection-quality.yml runs this test on every change instead, on a constructed
Kubernetes audit capture of kubernetes-admin RoleBinding creates, which
T1098.006/k8s_rbac_write.yml matches:

  * bootstrap: the rule's corpus budget + 1 events, the last 1 microsecond
    before the split point T;
  * workload: events from T on (the first exactly at T), plus four events with
    no usable requestReceivedTimestamp (missing, null, a time with no zone, a
    time that is out of the datetime range in UTC).

It runs score_benign.py on the capture (with GITHUB_ACTIONS=true, so the
annotations are printed) and asserts:

  * unsplit, every rule with hits is annotated, as before the split existed, and
    no text row is flagged;
  * split at T, each event lands in its window and no hit is lost or added;
  * the rule is over its corpus budget on both windows, but only the workload
    row is flagged OVER and annotated: in the text log (the row and the summary
    line under the window), the --json and the markdown;
  * split 1 microsecond after T, the event at T moves to bootstrap, and the
    workload row (at its budget while the budget is 5 or more) is not flagged;
  * a split point after or before the whole capture leaves one window with no
    timed event, and the log, one annotation and that window's markdown section
    give the true cause;
  * an invalid split point (an offset minute over 59, no zone, out of range in
    UTC) exits 2.

The budget is read from detections/benign/budgets.json at run time, so a new
budget needs no edit here. Each run also scores the committed corpus, so it can
print the corpus annotation of a shadow-mode rule over its budget ("... on the
benign corpus (budget B, shadow mode)"). That annotation does not come from the
capture, and it is ignored on purpose; every other ::warning line is counted.
When score_benign.py exits with an unexpected code, its output is printed with
each leading "::" broken, so that it does not post annotations of its own. It
writes only to a temporary directory.

Exit 0 when every check holds; exit 1 with one ::error line per failed check.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RULE = "T1098.006/k8s_rbac_write.yml"  # any RoleBinding write; budget from budgets.json
budgets = json.load(open(os.path.join(REPO, "detections", "benign", "budgets.json"),
                         encoding="utf-8"))


def cap_of(key):  # the rule's corpus budget, as score_benign.py reads it
    b = dict(budgets["default"])
    b.update(budgets["rules"].get(key, {}))
    return b.get("max_hits", 0)


cap = cap_of(RULE)
T = datetime(2026, 10, 20, 18, 1, 25, 454000, tzinfo=timezone.utc)


def stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def event(n, received):  # a kubernetes-admin RoleBinding create (k8s_rbac_write)
    name = f"split-smoke-{n:03d}"
    e = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Request",
         "auditID": f"5b0c7a51-0000-4000-8000-{n:012d}", "stage": "ResponseComplete",
         "requestURI": "/apis/rbac.authorization.k8s.io/v1/namespaces/shop/rolebindings"
                       "?fieldManager=kubectl-create",
         "verb": "create", "sourceIPs": ["192.0.2.10"],
         "user": {"username": "kubernetes-admin",
                  "groups": ["kubeadm:cluster-admins", "system:authenticated"]},
         "objectRef": {"resource": "rolebindings", "namespace": "shop", "name": name,
                       "apiGroup": "rbac.authorization.k8s.io", "apiVersion": "v1"},
         "responseStatus": {"metadata": {}, "code": 201},
         "requestObject": {"kind": "RoleBinding", "apiVersion": "rbac.authorization.k8s.io/v1",
                           "metadata": {"name": name, "namespace": "shop"},
                           "subjects": [{"kind": "ServiceAccount", "name": "default",
                                         "namespace": "shop"}],
                           "roleRef": {"apiGroup": "rbac.authorization.k8s.io",
                                       "kind": "ClusterRole", "name": "view"}},
         "stageTimestamp": stamp(T + timedelta(seconds=30))}
    if received != "missing":
        e["requestReceivedTimestamp"] = received
    return e


# Bootstrap: cap + 1 events, the last 1 microsecond before T, so the bootstrap row is
# over the corpus budget and still must not be flagged or warned. Workload: n_timed
# events from T on (the first exactly at T), and 4 events with no usable time
# (missing, null, a zoneless time before T, a time before year 1 in UTC), so the
# workload row is over the budget: n_work is cap + 1 while the budget is 5 or more.
n_untimed = 4
n_boot, n_timed = cap + 1, max(cap + 1 - n_untimed, 2)
n_work = n_timed + n_untimed
received = ([stamp(T - timedelta(microseconds=n_boot - i)) for i in range(n_boot)]
            + [stamp(T + timedelta(milliseconds=i)) for i in range(n_timed)]
            + ["missing", None, "2026-10-20T18:01:24.000000", "0001-01-01T00:00:00+01:00"])
d = tempfile.mkdtemp(prefix="live-split-smoke-")
with open(f"{d}/capture.jsonl", "w", encoding="utf-8") as fh:
    for n, r in enumerate(received, 1):
        fh.write(json.dumps(event(n, r)) + "\n")
fails = []
# The one annotation that comes from the committed corpus, not from the capture: a
# shadow-mode rule over its budget. An enforce-mode one is an ::error, not counted.
CORPUS_WARNING = re.compile(r"::warning title=benign-corpus::\S+ fired \d+ time\(s\) on the "
                            r"benign corpus \(budget \d+, shadow mode\)")


def quiet(text):  # the child's output with each leading "::" broken: no annotation
    return "\n".join(": :" + ln[2:] if ln.startswith("::") else ln for ln in text.splitlines())


def run(name, *args, rc=0, markdown=False):
    """Score the capture; return (JSON report, ::warning lines, markdown, output).

    The ::warning lines leave out the corpus annotation (CORPUS_WARNING) only."""
    cmd = [sys.executable, os.path.join(REPO, "detections", "score_benign.py"),
           "--examples", "0", "--extra-slice", f"{d}/capture.jsonl", "--extra-label", "smoke",
           "--json", f"{d}/{name}.json", *args]
    if markdown:
        cmd += ["--markdown", f"{d}/{name}.md"]
    p = subprocess.run(cmd, capture_output=True, text=True,
                       env=dict(os.environ, GITHUB_ACTIONS="true"))
    if p.returncode != rc:
        print(quiet(p.stdout + p.stderr))
        fails.append(f"{name}: score_benign.py exited {p.returncode}, expected {rc}")
        return None, [], "", p.stdout + p.stderr
    if rc:
        return None, [], "", p.stdout + p.stderr
    doc = json.load(open(f"{d}/{name}.json", encoding="utf-8"))
    md = open(f"{d}/{name}.md", encoding="utf-8").read() if markdown else ""
    warns = [ln for ln in p.stdout.splitlines()
             if ln.startswith("::warning") and not CORPUS_WARNING.fullmatch(ln)]
    return doc, warns, md, p.stdout


def check(name, got, want):
    if got != want:
        fails.append(f"{name}: got {got!r}, expected {want!r}")


def section(md, part):  # the markdown section of one window
    head = f"### Live capture `{part}` (shadow)"
    if head not in md:
        fails.append(f"markdown has no section {head!r}")
        return ""
    return md.split(head, 1)[1].split("\n### ", 1)[0]


def row(text, key):
    return next((ln for ln in text.splitlines() if ln.startswith(f"| `{key}` |")), "")


def block(out, part):  # the text log of one window: from its heading to the next blank line
    head = f"\nLive capture {part} ("
    if head not in out:
        fails.append(f"log has no block {head.strip()!r}")
        return ""
    return out.split(head, 1)[1].split("\n\n", 1)[0]


def text_row(text, key):  # the text row of one rule in a window's log
    return next((ln for ln in text.splitlines() if ln.startswith(f"  {key} ")), "")


def summary(over, part):  # the log line under a compared window
    return f"\n  {over} rule(s) over their corpus budget on {part} (shadow: warned, never enforced)"


def finish():
    for f in fails:
        print(f"::error title=live-split-smoke::{f}")
    if fails:
        print(f"The capture and the reports are kept in {d}.")
        sys.exit(1)
    shutil.rmtree(d, ignore_errors=True)


# Unsplit: every hit warns, as before the split existed.
whole, warns, _, out = run("whole")
whole = (whole or {}).get("extra", {})
check("unsplit hits", whole.get(RULE, {}).get("hits"), n_boot + n_work)
check("unsplit ::warning lines", len(warns), sum(1 for sc in whole.values() if sc["hits"]))
check("unsplit ::warning text", all(ln.endswith(" on the live benign capture smoke (shadow)")
                                    for ln in warns), True)
text = block(out, "smoke")
check("unsplit text row", f"hits {n_boot + n_work:>5}" in text_row(text, RULE), True)
check("unsplit text flag or summary", ("OVER" in text, "over their corpus budget" in text),
      (False, False))
if fails:  # the checks below need the rule to match every event
    finish()

# Split at T: each event lands in its window, no hit is lost, and only the workload
# row over its corpus budget is flagged and warned, never the bootstrap row.
split, warns, md, out = run("split", "--extra-split-at", stamp(T), markdown=True)
if split:
    boot, work = split["extra"]["smoke-bootstrap"], split["extra"]["smoke-workload"]
    xs = split["extra_split"]
    check("split", {k: xs[k] for k in ("at", "untimed", "events", "timed", "empty")},
          {"at": stamp(T), "untimed": n_untimed, "empty": [],
           "events": {"smoke-bootstrap": n_boot, "smoke-workload": n_work},
           "timed": {"smoke-bootstrap": n_boot, "smoke-workload": n_timed}})
    check("rules scored per window", (set(boot), set(work)), (set(whole), set(whole)))
    check("hits lost or added by the split",
          sorted(k for k in whole if boot[k]["hits"] + work[k]["hits"] != whole[k]["hits"]), [])
    check("bootstrap hits over the budget", boot[RULE]["hits"] > cap, True)
    want_over = sorted(k for k in work if work[k]["hits"] > cap_of(k))
    check("rules over the budget on the workload (fixture)", want_over, [RULE])
    check("over_corpus_budget", sorted(xs["over_corpus_budget"]), want_over)
    check("split ::warning lines", warns,
          [f"::warning title=benign-corpus::{RULE} fired {n_work} time(s) on the live benign "
           f"capture smoke-workload, over its corpus budget of {cap} (shadow)"])
    b, w = section(md, "smoke-bootstrap"), section(md, "smoke-workload")
    check("markdown bootstrap row", row(b, RULE).startswith(f"| `{RULE}` | {n_boot} |")
          and "OVER" not in b, True)
    check("markdown workload row", row(w, RULE).startswith(f"| `{RULE}` | {n_work} |")
          and "**OVER corpus budget**" in row(w, RULE), True)
    check("markdown OVER cells", w.count("**OVER corpus budget**"), len(want_over))
    tb, tw = block(out, "smoke-bootstrap"), block(out, "smoke-workload")
    check("text bootstrap row", f"hits {n_boot:>5}" in text_row(tb, RULE)
          and f"budget {cap:>4}" in text_row(tb, RULE), True)
    check("text bootstrap flag or summary", ("OVER" in tb, "over their corpus budget" in tb),
          (False, False))
    check("text workload row", f"hits {n_work:>5}" in text_row(tw, RULE)
          and f"budget {cap:>4}  OVER corpus budget  " in text_row(tw, RULE), True)
    check("text OVER rows", sum(1 for ln in tw.splitlines()
                                if ln.startswith("  ") and "OVER corpus budget" in ln),
          len(want_over))
    check("text workload summary", summary(len(want_over), "smoke-workload") + "."
          in "\n" + tw, True)

# Split 1 microsecond after T: the event at T moves to bootstrap. A workload row at
# its budget is not over it.
edge, warns, _, out = run("edge", "--extra-split-at", stamp(T + timedelta(microseconds=1)))
if edge:
    hits = edge["extra"]["smoke-workload"][RULE]["hits"]
    check("edge events", edge["extra_split"]["events"],
          {"smoke-bootstrap": n_boot + 1, "smoke-workload": n_work - 1})
    check("edge over_corpus_budget", edge["extra_split"]["over_corpus_budget"],
          [RULE] if hits > cap else [])
    check("edge ::warning lines", len(warns), 1 if hits > cap else 0)
    tw = block(out, "smoke-workload")
    check("edge text workload row flagged", "OVER corpus budget" in text_row(tw, RULE),
          hits > cap)
    check("edge text workload summary", summary(int(hits > cap), "smoke-workload") + "."
          in "\n" + tw, True)
    check("edge text bootstrap flag", "OVER" in block(out, "smoke-bootstrap"), False)

# A split point after (late) or before (early, with an offset) the whole capture
# leaves one window with no timed event: the log, an annotation and the markdown
# section of that window say so, with the true cause.
for name, at, part, cut, side in (
        ("late", "2026-10-20T18:05:00Z", "smoke-workload", "2026-10-20T18:05:00.000000Z",
         "at or after"),
        ("early", "2000-01-01T00:00:00+02:00", "smoke-bootstrap",
         "1999-12-31T22:00:00.000000Z", "before")):
    doc, warns, md, out = run(name, "--extra-split-at", at, markdown=True)
    if not doc:
        continue
    check(f"{name} split point", doc["extra_split"]["at"], cut)
    check(f"{name} empty", doc["extra_split"]["empty"], [part])
    msg = (f"--extra-split-at {cut} left {part} with no timed event: no event in smoke "
           f"was received {side} it")
    check(f"{name} WARNING line", f"WARNING: {msg}" in out, True)
    check(f"{name} empty-window annotation", sum(1 for ln in warns if msg in ln), 1)
    over = doc["extra"]["smoke-workload"][RULE]["hits"] > cap
    check(f"{name} ::warning lines", len(warns), 1 + over)
    check(f"{name} over_corpus_budget", doc["extra_split"]["over_corpus_budget"],
          [RULE] if over else [])
    check(f"{name} markdown WARNING", f"**WARNING:** {msg}" in section(md, part), True)
    check(f"{name} text workload summary", summary(int(over), "smoke-workload")
          + ("; the window holds no timed event" if part == "smoke-workload" else ".")
          in "\n" + block(out, "smoke-workload"), True)

# An invalid split point is an argument error (exit 2): an offset minute over 59,
# a time with no zone, and a time that is out of the datetime range in UTC.
for bad in ("2026-10-20T18:01:25+05:99", "2026-10-20T18:01:25", "0001-01-01T00:00:00+01:00"):
    _, _, _, out = run("bad", "--extra-split-at", bad, rc=2)
    check(f"--extra-split-at {bad} message", "is not an RFC 3339 time" in out, True)

finish()
print(f"Live capture split smoke test OK: {n_boot} bootstrap and {n_work} workload event(s); "
      f"{RULE} over its corpus budget of {cap} on both windows, flagged and warned on the "
      "workload only; empty windows and invalid split points caught.")
