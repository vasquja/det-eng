#!/usr/bin/env python3
"""
Schedule freshness: does every weekly schedule still run, and pass?

Each workflow under .github/workflows/ with a `schedule:` trigger re-proves its
layer once a week, also when nothing in the repository changed. GitHub can start
a scheduled run hours late, drop it, or not start it at all (a workflow that a
human or GitHub disabled). This check finds those workflows in the workflow
files (not in a list kept here), and reads from the GitHub REST API, for each:

  GET /repos/{repo}/actions/workflows                    its id and state
  GET /repos/{repo}/actions/workflows/{id}/runs?event=schedule&status=success&per_page=1
  GET /repos/{repo}/actions/workflows/{id}/runs?event=schedule&per_page=10
      (the newest scheduled runs of any result: the red runs after the newest
      success, and the newest run, which the report names)
  GET /repos/{repo}/contents/<file>  and  GET /repos/{repo}/commits?path=<file>&per_page=1
      (only for a workflow with no scheduled run at all, or one that GitHub does
      not list: does the default branch have the file, does that version have a
      schedule trigger, and since when is it unchanged there; this tells a new
      schedule from one that never started)

The age of a run is now minus its created_at (when the schedule started it;
a re-run does not change it). A red run is a completed scheduled run whose
conclusion is not `success` (failure, cancelled, timed_out, skipped, ...); a
queued or running one is not counted yet. The grades:

  newest successful scheduled run <= --warn-days old   ok
  older than --warn-days (8)                            warning
  older than --fail-days (15)                           failure
  one red scheduled run after the newest success        warning
  two or more red scheduled runs in a row after it      failure
  the workflow state is not `active`                    failure (no schedule runs)
  no successful scheduled run yet                       warning only: a new schedule,
      also when its runs are red. It is new while its oldest scheduled run is
      --fail-days old or less. With no scheduled run at all, or when GitHub lists
      no workflow at the path, it is new while the default branch has no such
      file, or its version there has no schedule trigger, or has had it,
      unchanged, for --fail-days or less. After that, it is a failure: the
      schedule never started, or never passed.
  --self-workflow names this workflow                   the workflow that holds this
      check: its other jobs run again in this run, so its own red scheduled runs
      are not counted (two of them can come from this check), and its age is that
      of its newest scheduled run of any result
  --scheduled-run-of names this workflow                ok: this run is a scheduled
      run of it, so its schedule runs

Phase: every weekly cron in this repository is on Monday morning. The crons of
lint-trr.yml and the validate-*.yml workflows (06:11 to 06:43 UTC) come before the
cron of detection-quality.yml (06:53 UTC), whose scheduled run runs this check.
Their scheduled runs usually end in minutes, before it starts (on 2026-10-19,
all 7 hours late, they ended 6 to 55 minutes before it). So the scheduled run
sees ages of about 0, 7, 14 or 21 days. A red run counts as soon as
it has ended: one red week warns, two red weeks in a row fail. A run that GitHub
drops (no run at all) shows only by age: one dropped week is not seen (7 days is
ok), two in a row warn (14 days), three in a row fail (21 days). For a workflow
whose cron is after 06:53, add 7 days. A pull request or a manual run at another
time of the week sees other ages.

Every schedule must run at least once a week (a cron entry whose day-of-month
and month fields are `*`): the thresholds fit only such a schedule. Another
schedule is an error, so that a human picks thresholds for it.

--warn-only (pull requests) reports a failure as a warning. It also reports as a
warning an API error that a re-run can clear: a rate limit (403 or 429), or a
5xx, a 429, a network error or a truncated answer on all its attempts (up to 4;
see Time budget), or a request that the time budget stops. Every other API error
(for example a 403 or a 404: a fault in the token or its permissions) and an
answer of the wrong shape fail closed in every mode. An API error on one
workflow does not stop the check of the others. Every warning and failure is also
a GitHub annotation, written as soon as that workflow is graded; --markdown
appends a table.

Time budget: a slow API outage must end as API errors, not at the job's timeout
(which ends the step with no report, and a red pull request). So an attempt
waits at most 15 s (GitHub itself ends a request after 10 s). After one request
fails on all its attempts with an error that a re-run can clear, each later
request gets one attempt. No attempt or pause starts that would end more than
--api-budget seconds (default 240) after the first request; a request that the
budget stops is an API error that a re-run can clear. With 8 scheduled workflows
and no answer at all, the reads end after about 215 s, and each workflow gets its
own error row.

Exit 0: no failure (there can be warnings). Exit 1: a failure. Exit 2: the
check cannot decide: a workflow file that does not parse or has an unsupported
schedule, no workflow with a schedule trigger, a --self-workflow or
--scheduled-run-of that names no scheduled workflow here, an unexpected internal
error, or an API error or unexpected API answer (with --warn-only, one that a
re-run cannot clear).

  python3 .github/scripts/check_schedule_freshness.py --repo OWNER/REPO
  python3 .github/scripts/check_schedule_freshness.py --self-test
  python3 .github/scripts/check_schedule_freshness.py --fixtures responses.json ...

The token comes from GH_TOKEN or GITHUB_TOKEN (without one, a public repository
still answers, at a lower rate limit). --fixtures replays recorded answers: a
JSON object that maps "<path>?<query>" to {"status": N, "body": ..., "headers":
{...}}, or to a list of them (one per attempt).
"""

import argparse
import base64
import datetime as dt
import glob
import http.client
import io
import json
import math
import os
import re
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install -r detections/requirements.txt")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKFLOWS_DIR = os.path.join(REPO_ROOT, ".github", "workflows")
TITLE = "schedule-freshness"
ATTEMPTS = 4               # per request; only 5xx, 429 and network errors retry
BACKOFF = (5, 15, 30)      # seconds before attempt 2, 3 and 4
SOCKET_TIMEOUT = 15        # seconds an attempt waits; GitHub ends a request after 10 s
API_BUDGET = 240           # seconds for all API reads of one run (the job has 10 minutes)
PAGE_LIMIT = 1000          # the runs API returns at most 1000 results for a filter
RECENT = 10                # newest scheduled runs read to count the red runs
OK, WARN, FAIL, ERROR = "ok", "warn", "fail", "error"
RANK = {OK: 0, WARN: 1, FAIL: 2}


class ApiError(Exception):
    """The API did not answer, or its answer is not what the check expects.

    transient: a re-run can clear it (a 5xx, a 429 or a rate limit, a network
    error or a truncated answer). Every other error (a 4xx such as 403 or 404, an
    answer of the wrong shape) is a fault in the token, its permissions or this
    check, and a re-run does not clear it."""

    def __init__(self, message, transient=False):
        super().__init__(message)
        self.transient = transient


# ---------------------------------------------------------------------------
# API access
# ---------------------------------------------------------------------------

class Api:
    """GET with retries, inside a time budget for the whole run.

    A slow outage must end as API errors (a warning on a pull request) before the
    job's timeout ends the step with no report. So: an attempt waits at most
    SOCKET_TIMEOUT; after one request has failed on all its attempts with an
    error that a re-run can clear, each later request gets one attempt (the breaker);
    and no attempt or pause starts that would end after `budget` seconds from the
    first request. A request that the budget stops is a transient ApiError, so
    each later workflow still gets its own error row."""

    def __init__(self, base, token=None, sleep=time.sleep, clock=time.monotonic,
                 budget=API_BUDGET):
        self.base = base.rstrip("/")
        self.token = token
        self.sleep = sleep
        self.clock = clock
        self.budget = budget
        self.deadline = None   # clock() + budget, set at the first request
        self.down = None       # the error that tripped the breaker
        self.calls = []

    def _send(self, key, timeout):
        """One HTTP GET. Returns (status, body, headers); raises OSError or HTTPException."""
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "det-eng-schedule-freshness"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.base + key, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw, status, got = resp.read(), resp.status, dict(resp.headers.items())
        except urllib.error.HTTPError as err:
            raw, status, got = err.read(), err.code, dict((err.headers or {}).items())
        try:
            return status, json.loads(raw.decode("utf-8") or "null"), got
        except ValueError:
            return status, None, got

    def get(self, path, params, absent_ok=False):
        """The JSON body of a 200 answer; None for a 404 when absent_ok."""
        key = path + ("?" + urllib.parse.urlencode(params) if params else "")
        if self.deadline is None:
            self.deadline = self.clock() + self.budget
        budget = f"the API time budget ({self.budget:g} s)"
        tripped = self.down is not None
        last, transient = None, False
        for attempt in range(1 if tripped else ATTEMPTS):
            if attempt:
                pause = BACKOFF[min(attempt, len(BACKOFF)) - 1]
                if self.clock() + pause + 1 > self.deadline:
                    last += f"; no attempt {attempt + 1}: it would end after {budget}"
                    break
                self.sleep(pause)
            left = self.deadline - self.clock()
            if left < 1:
                last, transient = f"GET {key}: not sent: {budget} is spent", True
                break
            self.calls.append(key)
            try:
                status, body, headers = self._send(key, min(SOCKET_TIMEOUT, left))
            # OSError: URLError, timeouts, resets. HTTPException: a truncated body
            # (IncompleteRead) or a status line that is not HTTP (BadStatusLine).
            except (OSError, http.client.HTTPException) as err:
                last, transient = f"GET {key}: {type(err).__name__}: {err}", True
                if tripped:
                    last += " (one attempt only: an earlier request failed, and a re-run can clear it)"
                continue
            if status == 200:
                return body
            if status == 404 and absent_ok:
                return None
            message = body.get("message") if isinstance(body, dict) else None
            last = f"GET {key}: HTTP {status}" + (f" ({message})" if message else "")
            # GitHub answers a rate limit with 403 or 429: x-ratelimit-remaining 0
            # (primary) or a message that names it (secondary). A re-run clears it.
            remaining = {k.lower(): v for k, v in (headers or {}).items()}.get("x-ratelimit-remaining")
            limited = status in (403, 429) and ("rate limit" in (message or "").lower()
                                                or str(remaining) == "0")
            transient = status >= 500 or status == 429 or limited
            if tripped and transient:
                last += " (one attempt only: an earlier request failed, and a re-run can clear it)"
            if status < 500 and status != 429:
                break
        if transient and not tripped:
            self.down = last   # the API is down or slow: later requests get one attempt
        raise ApiError(last, transient=transient)


class FixtureApi(Api):
    """Replays recorded answers. A request with no recorded answer is an error."""

    def __init__(self, responses, sleep=lambda s: None, **kwargs):
        super().__init__("fixture://", sleep=sleep, **kwargs)
        self.queue = {k: list(v) if isinstance(v, list) else [v] for k, v in responses.items()}

    def _send(self, key, timeout):
        if key not in self.queue:
            raise ApiError(f"GET {key}: no recorded answer")
        answers = self.queue[key]
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        if answer.get("network_error"):
            raise OSError(answer["network_error"])
        if answer.get("truncated"):
            raise http.client.IncompleteRead(b"{", 499)
        if answer.get("internal_error"):
            raise RuntimeError(answer["internal_error"])
        return answer.get("status", 200), answer.get("body"), answer.get("headers") or {}


def _parse_time(value, what):
    if not isinstance(value, str):
        raise ApiError(f"{what}: no timestamp ({value!r})")
    text = re.sub(r"\.\d+", "", value.strip()).replace("Z", "+00:00")
    try:
        stamp = dt.datetime.fromisoformat(text)
    except ValueError:
        raise ApiError(f"{what}: timestamp {value!r} does not parse") from None
    if stamp.tzinfo is None:
        raise ApiError(f"{what}: timestamp {value!r} has no time zone")
    return stamp.astimezone(dt.timezone.utc)


def list_workflows(api, repo):
    """{path: {id, state, name}} for every workflow GitHub lists, all pages."""
    found, page, total = {}, 1, None
    while True:
        body = api.get(f"/repos/{repo}/actions/workflows", [("per_page", 100), ("page", page)])
        if not (isinstance(body, dict) and isinstance(body.get("total_count"), int)
                and isinstance(body.get("workflows"), list)):
            raise ApiError(f"the workflow list (page {page}) is not a workflows object")
        total = body["total_count"]
        for wf in body["workflows"]:
            if not (isinstance(wf, dict) and isinstance(wf.get("path"), str)
                    and isinstance(wf.get("id"), int) and isinstance(wf.get("state"), str)):
                raise ApiError(f"the workflow list holds an entry without path, id or state: {wf!r}")
            found[wf["path"]] = {"id": wf["id"], "state": wf["state"], "name": wf.get("name")}
        if len(found) >= total or not body["workflows"]:
            break
        page += 1
    if len(found) < total:
        raise ApiError(f"the workflow list holds {len(found)} of total_count {total}")
    return found


def scheduled_runs(api, repo, wf_id, success_only=False, page=1, per_page=1):
    """(total_count, [runs on that page, newest first]) of the workflow's scheduled runs."""
    params = [("event", "schedule")]
    if success_only:
        params.append(("status", "success"))
    params += [("exclude_pull_requests", "true"), ("per_page", per_page), ("page", page)]
    body = api.get(f"/repos/{repo}/actions/workflows/{wf_id}/runs", params)
    what = f"workflow {wf_id} runs (event=schedule{', status=success' if success_only else ''})"
    if not (isinstance(body, dict) and isinstance(body.get("total_count"), int)
            and isinstance(body.get("workflow_runs"), list)):
        raise ApiError(f"{what}: the answer is not a workflow_runs object")
    runs = body["workflow_runs"]
    if body["total_count"] and not runs:
        raise ApiError(f"{what}: total_count {body['total_count']} but no run on page {page}")
    if len(runs) > per_page:
        raise ApiError(f"{what}: {len(runs)} runs on a page of {per_page}")
    out = []
    for run in runs:
        if not isinstance(run, dict) or run.get("event") != "schedule" or run.get("workflow_id") != wf_id:
            raise ApiError(f"{what}: the API returned a run of another event or workflow: "
                           + (f"event={run.get('event')!r}, workflow_id={run.get('workflow_id')!r}"
                              if isinstance(run, dict) else repr(run)))
        if success_only and run.get("conclusion") != "success":
            raise ApiError(f"{what}: the API returned a run with conclusion {run.get('conclusion')!r}")
        out.append(dict(run, _created=_parse_time(run.get("created_at"),
                                                  f"{what}: run {run.get('id')}")))
    return body["total_count"], out


def file_commit(api, repo, path):
    """The newest commit of `path` on the default branch, or None when it has none."""
    body = api.get(f"/repos/{repo}/commits", [("path", path), ("per_page", 1)])
    what = f"the commits of {path} on the default branch"
    if not isinstance(body, list) or len(body) > 1:
        raise ApiError(f"{what}: the answer is not a list of at most one commit")
    if not body:
        return None
    commit = body[0]
    if not (isinstance(commit, dict) and isinstance(commit.get("sha"), str)
            and isinstance(commit.get("commit"), dict)
            and isinstance(commit["commit"].get("committer"), dict)):
        raise ApiError(f"{what}: the commit has no sha or committer: {commit!r}")
    date = commit["commit"]["committer"].get("date")
    return {"sha": commit["sha"], "_date": _parse_time(date, f"{what}: commit {commit['sha'][:7]}")}


def default_branch_crons(api, repo, path):
    """The cron entries of the default branch's version of `path`: None when the
    default branch has no such file, [] when that version has no schedule trigger
    (or does not parse, so GitHub cannot run its schedule either)."""
    body = api.get(f"/repos/{repo}/contents/{urllib.parse.quote(path)}", [], absent_ok=True)
    if body is None:
        return None
    what = f"the default branch's {path}"
    if not (isinstance(body, dict) and body.get("type") == "file"
            and body.get("encoding") == "base64" and isinstance(body.get("content"), str)):
        raise ApiError(f"{what}: the answer is not a file with base64 content")
    try:
        text = base64.b64decode(body["content"]).decode("utf-8")
    except ValueError:  # binascii.Error and UnicodeDecodeError are ValueErrors
        raise ApiError(f"{what}: the content does not decode") from None
    try:
        crons, _ = schedule_of(yaml.safe_load(text))
    except yaml.YAMLError:
        return []
    return crons or []


# ---------------------------------------------------------------------------
# Workflow files
# ---------------------------------------------------------------------------

def _weekly_or_faster(cron):
    """True for a 5-field cron whose day-of-month and month fields are `*`: whatever
    its minute, hour and day-of-week fields hold, it fires on a day of every week."""
    fields = cron.split()
    return len(fields) == 5 and fields[2] == "*" and fields[3] == "*"


def schedule_of(doc):
    """(crons, error) of a parsed workflow file; crons is None when it has no schedule."""
    if not isinstance(doc, dict):
        return None, "is not a workflow mapping"
    # YAML 1.1 reads a bare `on` key as the boolean true.
    on = doc["on"] if "on" in doc else doc.get(True)
    if isinstance(on, dict) and "schedule" in on:
        crons = [e.get("cron") for e in (on["schedule"] or []) if isinstance(e, dict)]
        if not crons or not all(isinstance(c, str) and c.strip() for c in crons):
            return None, "its schedule trigger has no valid cron entry"
        return crons, None
    if on == "schedule" or (isinstance(on, list) and "schedule" in on):
        return None, "names the schedule event without a cron entry"
    return None, None


def find_scheduled(workflows_dir):
    """([{path, file, crons}], [error]) for every workflow file with a schedule trigger."""
    found, errors = [], []
    files = sorted(glob.glob(os.path.join(workflows_dir, "*.yml"))
                   + glob.glob(os.path.join(workflows_dir, "*.yaml")))
    for full in files:
        name = os.path.basename(full)
        try:
            with open(full, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as err:
            errors.append(f"{name}: does not parse: {err}")
            continue
        crons, error = schedule_of(doc)
        if error:
            errors.append(f"{name}: {error}")
            continue
        if crons is None:
            continue
        bad = [c for c in crons if len(c.split()) != 5]
        if bad:
            errors.append(f"{name}: cron {bad[0]!r} does not have 5 fields")
            continue
        if not any(_weekly_or_faster(c) for c in crons):
            errors.append(f"{name}: no cron entry runs at least once a week ({', '.join(crons)}; "
                          f"day-of-month and month must be '*'): the warn and fail days of this "
                          f"check fit only a weekly or faster schedule, so a human must choose "
                          f"thresholds for this one first")
            continue
        found.append({"path": f".github/workflows/{name}", "file": name, "crons": crons})
    return found, errors


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------

def _stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _days(now, t):
    return max(0.0, (now - t).total_seconds() / 86400.0)


def _fmt_days(days):
    """Days with two decimals, rounded up: a shown age is more than a threshold
    (with at most two decimals) exactly when the age is (8 days and 1 minute
    shows 8.01, not 8.00). Ages are whole seconds, so round() only drops float noise."""
    return f"{math.ceil(round(days * 100, 6)) / 100:.2f}"


def _run_ref(run):
    sha = (run.get("head_sha") or "")[:7]
    attempt = run.get("run_attempt")
    extra = f", attempt {attempt}" if isinstance(attempt, int) and attempt > 1 else ""
    return f"run {run.get('id')}{', ' + sha if sha else ''}{extra}"


def _bump(res, level):
    res["level"] = max(res["level"], level, key=RANK.get)


def _by_age(res, notes, age, what, when, warn_days, fail_days):
    """Grade an age: the note for it goes first."""
    if age > fail_days:
        _bump(res, FAIL)
        notes.insert(0, f"{what} is more than {fail_days:g} days old: {when}")
    elif age > warn_days:
        _bump(res, WARN)
        notes.insert(0, f"{what} is more than {warn_days:g} days old: {when}")
    else:
        notes.insert(0, f"{what}: {when}")


def schedule_on_main(api, repo, wf, now, fail_days):
    """(level, note) for a workflow with no scheduled run at all, or one GitHub does
    not list: is its schedule new (warn), or has it been on the default branch,
    unchanged, for more than fail_days (fail: the schedule never started)?"""
    crons = default_branch_crons(api, repo, wf["path"])
    if crons is None:
        return WARN, "the default branch has no such file: a new file, so its schedule does not run yet"
    if not crons:
        return WARN, ("the default branch's version of the file has no schedule trigger: "
                      "a new schedule, not on the default branch yet")
    commit = file_commit(api, repo, wf["path"])
    if commit is None:
        raise ApiError(f"the default branch has {wf['path']}, but the commits API lists no commit of it")
    since = _days(now, commit["_date"])
    when = (f"with a schedule trigger, unchanged since {_stamp(commit['_date'])} "
            f"({_fmt_days(since)} days, commit {commit['sha'][:7]})")
    if since > fail_days:
        return FAIL, (f"the default branch has had the file {when}: more than {fail_days:g} days, "
                      f"so the schedule never started")
    return WARN, f"a new schedule: the default branch has the file {when}"


def grade(api, repo, wf, registered, now, warn_days, fail_days, self_path, scheduled_self):
    """One result dict per scheduled workflow: level, message and the run it read."""
    res = {"file": wf["file"], "crons": wf["crons"], "state": None, "run": None,
           "age": None, "self": wf["path"] == self_path, "level": OK, "message": ""}
    reg = registered.get(wf["path"])
    if reg is None:
        res["level"], note = schedule_on_main(api, repo, wf, now, fail_days)
        res["message"] = "GitHub lists no workflow at this path; " + note
        return res
    res["state"] = reg["state"]
    notes = []
    if reg["state"] != "active":
        res["level"] = FAIL
        notes.append(f"GitHub reports the state '{reg['state']}', so it does not start the "
                     f"schedule; enable the workflow (Actions tab, or gh workflow enable "
                     f"{wf['file']})")
    if res["self"] and scheduled_self:
        notes.insert(0, "this run is a scheduled run of this workflow, so its schedule runs")
        res["message"] = "; ".join(notes)
        return res
    if res["self"]:
        # The workflow that holds this check: its other jobs run again in this run,
        # and two of its red scheduled runs can come from this check. So any
        # scheduled run proves that its schedule runs, and red runs do not count.
        total, recent = scheduled_runs(api, repo, reg["id"], per_page=RECENT)
        if recent:
            newest = recent[0]
            res["run"], res["age"] = newest, _days(now, newest["_created"])
            result = newest.get("conclusion") or newest.get("status") or "unknown"
            _by_age(res, notes, res["age"], "the newest scheduled run (any result)",
                    f"{_stamp(newest['_created'])} ({_fmt_days(res['age'])} days ago, "
                    f"{_run_ref(newest)}, {result})", warn_days, fail_days)
            notes.append("this workflow holds this check, so its red scheduled runs are not "
                         "counted: its other jobs run again in this run")
        else:
            level, note = schedule_on_main(api, repo, wf, now, fail_days)
            _bump(res, level)
            notes.insert(0, "no scheduled run yet; " + note)
        res["message"] = "; ".join(notes)
        return res
    _, found = scheduled_runs(api, repo, reg["id"], success_only=True)
    success = found[0] if found else None
    total, recent = scheduled_runs(api, repo, reg["id"], per_page=RECENT)
    newest = recent[0] if recent else None
    # A run can turn green between the two reads: the newer success counts.
    for r in recent:
        if r.get("status") == "completed" and r.get("conclusion") == "success":
            if success is None or r["_created"] > success["_created"]:
                success = r
            break
    # The red runs in a row after the newest success (a queued or running one is not counted).
    red, reached = [], False
    for r in recent:
        if success is not None and r["_created"] <= success["_created"]:
            reached = True
            break
        if r.get("status") == "completed":
            red.append(r)
    more = "" if reached or len(recent) >= total else "at least "
    new = False   # a new schedule (no success yet): it only warns, also when its runs are red
    if success is not None:
        res["run"], res["age"] = success, _days(now, success["_created"])
        _by_age(res, notes, res["age"], "the newest successful scheduled run",
                f"{_stamp(success['_created'])} ({_fmt_days(res['age'])} days ago, "
                f"{_run_ref(success)})", warn_days, fail_days)
    elif total == 0:
        level, note = schedule_on_main(api, repo, wf, now, fail_days)
        _bump(res, level)
        notes.insert(0, "no scheduled run yet; " + note)
    else:
        if total <= len(recent):
            oldest = recent[-1]
        else:
            _, page = scheduled_runs(api, repo, reg["id"], page=min(total, PAGE_LIMIT))
            oldest = page[0]
        since = _days(now, oldest["_created"])
        new = since <= fail_days
        _bump(res, WARN if new else FAIL)
        notes.insert(0, f"no successful scheduled run in {total} scheduled run(s) since "
                        f"{_stamp(oldest['_created'])} ({_fmt_days(since)} days)"
                        + (": a new schedule" if new
                           else f", more than {fail_days:g} days, so it is not new"))
    if red:
        _bump(res, WARN if new or len(red) < 2 else FAIL)
        after = "after the newest success" if success is not None else "and none passed"
        if len(red) >= 2:
            notes.append(f"{more}{len(red)} red scheduled runs in a row {after} (newest: "
                         + ", ".join(f"{r.get('conclusion')} {_stamp(r['_created'])}"
                                     for r in red[:3])
                         + ("" if len(red) <= 3 else ", ...") + f"; {_run_ref(red[0])})")
        else:
            notes.append(f"the newest completed scheduled run is red: {red[0].get('conclusion')}, "
                         f"{_stamp(red[0]['_created'])} ({_run_ref(red[0])})")
    if newest is not None and newest.get("status") != "completed":
        notes.append(f"newest scheduled run: {newest.get('status') or 'unknown'}, "
                     f"{_stamp(newest['_created'])} ({_run_ref(newest)}), not counted yet")
    res["message"] = "; ".join(notes)
    return res


def _escape_data(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotate(level, text, out):
    kind = "error" if level in (FAIL, ERROR) else "warning"
    out.write(f"::{kind} title={TITLE}::{_escape_data(text)}\n")


def write_markdown(path, results, errors, soft, counts, warn_days, fail_days, warn_only):
    lines = ["## Schedule freshness", ""]
    hard = soft.count(False)
    verdict = ("ERROR" if hard else "FAIL" if counts[FAIL]
               else "WARN (API error)" if any(soft) else "WARN" if counts[WARN] else "PASS")
    lines.append(f"**{verdict}**: {len(results)} workflow(s) with a schedule trigger: "
                 f"{counts[OK]} ok, {counts[WARN]} warn, {counts[FAIL]} fail, "
                 f"{counts[ERROR]} error. Warn when the newest successful scheduled run is more "
                 f"than {warn_days:g} days old or one scheduled run after it is red, fail at more "
                 f"than {fail_days:g} days or two red runs in a row."
                 + (" On this pull request a failure only warns, and so does an API error that a "
                    "re-run can clear." if warn_only else ""))
    lines += ["", "| Workflow | Cron (UTC) | State | Graded scheduled run | Age (days) | Result |",
              "|---|---|---|---|---|---|"]
    for r in results:
        run = r["run"]
        cell = (f"[{_stamp(run['_created'])}]({run.get('html_url')})" if run and run.get("html_url")
                else _stamp(run["_created"]) if run else "this run" if r["self"] else "none")
        age = "" if r["age"] is None else _fmt_days(r["age"])
        crons = ", ".join(f"`{c}`" for c in r["crons"])
        # An ok row's message repeats the run and age cells; show it only when it adds a fact.
        detail = (r["message"] if r["level"] != OK or r["self"] or "newest scheduled run:" in r["message"]
                  else "")
        result = r["level"] + (": " + detail.replace("|", "/") if detail else "")
        lines.append(f"| `{r['file']}` | {crons} | {r['state'] or 'not listed'} | {cell} | {age} | "
                     f"{result} |")
    if errors:
        lines += ["", "### Errors (the check cannot decide)", ""]
        lines += [f"- {kind}{' (a re-run can clear it; this pull request only warns)' if s else ''}: "
                  f"{text}" for (kind, text, _), s in zip(errors, soft)]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _self_path(ref):
    """'.github/workflows/x.yml' from a GITHUB_WORKFLOW_REF 'owner/repo/.github/workflows/x.yml@ref'."""
    if not ref:
        return None
    path = ref.split("@", 1)[0]
    i = path.find(".github/workflows/")
    return path[i:] if i >= 0 else path


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0].strip())
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"),
                    help="OWNER/REPO (default: $GITHUB_REPOSITORY)")
    ap.add_argument("--workflows-dir", default=WORKFLOWS_DIR,
                    help="where the workflow files are (default: .github/workflows)")
    ap.add_argument("--warn-days", type=float, default=8.0,
                    help="warn when the newest successful scheduled run is older (default 8)")
    ap.add_argument("--fail-days", type=float, default=15.0,
                    help="fail when it is older (default 15)")
    ap.add_argument("--warn-only", action="store_true",
                    help="report a failure, and an API error that a re-run can clear, as a "
                         "warning (pull requests)")
    me = ap.add_mutually_exclusive_group()
    me.add_argument("--self-workflow", metavar="WORKFLOW_REF",
                    help="the workflow that holds this check ($GITHUB_WORKFLOW_REF): do not count "
                         "its red scheduled runs, grade the age of its newest scheduled run")
    me.add_argument("--scheduled-run-of", metavar="WORKFLOW_REF",
                    help="this run is a scheduled run of this workflow ($GITHUB_WORKFLOW_REF): "
                         "grade that workflow ok")
    ap.add_argument("--api-budget", type=float, default=API_BUDGET, metavar="SECONDS",
                    help=f"stop the API reads this long after the first one (default {API_BUDGET}; "
                         f"an attempt waits at most {SOCKET_TIMEOUT} s)")
    ap.add_argument("--now", help="the time to grade against, ISO 8601 (default: now)")
    ap.add_argument("--fixtures", metavar="FILE", help="replay recorded API answers (see above)")
    ap.add_argument("--markdown", metavar="PATH",
                    help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in cases on constructed API answers, then exit")
    return ap


def run(argv, api=None, out=None):
    """The check; any exception it does not expect is an error (exit 2), not a traceback."""
    out = out or sys.stdout
    try:
        return _check(argv, api, out)
    except Exception as err:  # noqa: BLE001 -- fail closed with an annotation
        traceback.print_exc(file=sys.stderr)
        text = f"unexpected error: {type(err).__name__}: {err}"
        out.write(f"::error title={TITLE}::{_escape_data(text)}\n")
        return 2


def _check(argv, api, out):
    args = build_parser().parse_args(argv)
    if args.self_test:
        return self_test(out)
    if not args.repo or "/" not in args.repo:
        out.write(f"::error title={TITLE}::no --repo OWNER/REPO and no $GITHUB_REPOSITORY\n")
        return 2
    if not 0 < args.warn_days <= args.fail_days:
        out.write(f"::error title={TITLE}::need 0 < --warn-days <= --fail-days\n")
        return 2
    if not args.api_budget > 0:
        out.write(f"::error title={TITLE}::need --api-budget > 0\n")
        return 2
    try:
        now = _parse_time(args.now, "--now") if args.now else dt.datetime.now(dt.timezone.utc)
    except ApiError as err:
        out.write(f"::error title={TITLE}::{err}\n")
        return 2
    now = now.replace(microsecond=0)   # whole seconds, like the API's timestamps
    if api is None:
        if args.fixtures:
            with open(args.fixtures, encoding="utf-8") as fh:
                api = FixtureApi(json.load(fh))
        else:
            api = Api(os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                      os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    api.budget = args.api_budget
    scheduled_self = bool(args.scheduled_run_of)
    flag = "--scheduled-run-of" if scheduled_self else "--self-workflow"
    self_path = _self_path(args.scheduled_run_of or args.self_workflow)

    workflows, file_errors = find_scheduled(args.workflows_dir)
    out.write(f"{TITLE}: {len(workflows)} workflow(s) with a schedule trigger"
              f" (warn > {args.warn_days:g} days, fail > {args.fail_days:g} days"
              f"{', warn only' if args.warn_only else ''}; repo {args.repo}, now {_stamp(now)})\n")
    errors, soft = [], []   # errors: (kind, text, transient); soft: it only warns

    def add_error(kind, text, transient):
        # With --warn-only, an API error that a re-run can clear only warns.
        s = args.warn_only and kind == "api" and transient
        errors.append((kind, text, transient))
        soft.append(s)
        if s:
            annotate(WARN, "API error that a re-run can clear (a scheduled run would fail "
                           "closed): " + text, out)
        else:
            annotate(ERROR, text, out)
        out.flush()

    results, counts = [], {OK: 0, WARN: 0, FAIL: 0, ERROR: 0}

    def add_result(r):
        # Each row goes out as soon as it is graded: a step that a timeout ends
        # still shows what the check found.
        if args.warn_only and r["level"] == FAIL:
            # A scheduled run grades its own workflow ok, so only a manual run would fail on it.
            who = "a manual run" if r["self"] else "a scheduled run"
            r["level"], r["message"] = WARN, f"({who} would fail) " + r["message"]
        results.append(r)
        counts[r["level"]] += 1
        out.write(f"  {r['level'].upper():<5}  {r['file']:<36} {', '.join(r['crons']):<14} "
                  f"{r['message']}\n")
        if r["level"] in (WARN, FAIL):   # an error row is annotated by add_error
            annotate(r["level"], f"{r['file']}: {r['message']}", out)
        out.flush()

    for e in file_errors:
        add_error("config", e, False)
    if not workflows and not errors:
        add_error("config", f"no workflow file in {args.workflows_dir} has a schedule trigger",
                  False)
    if self_path and not any(w["path"] == self_path for w in workflows):
        add_error("config", f"{flag} names {self_path}, which has no schedule trigger here", False)
    registered = None
    if workflows:
        try:
            registered = list_workflows(api, args.repo)
        except ApiError as err:
            add_error("api", str(err), err.transient)
    # An API error on one workflow does not stop the check of the others.
    for wf in workflows if registered is not None else []:
        try:
            r = grade(api, args.repo, wf, registered, now, args.warn_days, args.fail_days,
                      self_path, scheduled_self)
        except ApiError as err:
            add_result({"file": wf["file"], "crons": wf["crons"],
                        "state": (registered.get(wf["path"]) or {}).get("state"), "run": None,
                        "age": None, "self": wf["path"] == self_path, "level": ERROR,
                        "message": f"API error: {err}"})
            add_error("api", f"{wf['file']}: {err}", err.transient)
            continue
        add_result(r)
    out.write(f"{TITLE}: {len(results)} checked: {counts[OK]} ok, {counts[WARN]} warn, "
              f"{counts[FAIL]} fail, {len(errors)} error(s)"
              + (f" ({sum(soft)} only warn: a re-run can clear them)" if any(soft) else "") + "\n")
    if args.markdown:
        write_markdown(args.markdown, results, errors, soft, counts, args.warn_days,
                       args.fail_days, args.warn_only)
    return 2 if soft.count(False) else 1 if counts[FAIL] else 0


# ---------------------------------------------------------------------------
# Self-test: constructed API answers, in the shapes GitHub returns
# ---------------------------------------------------------------------------

REPO = "example/det-eng"
NOW = "2026-10-21T12:00:00Z"
FILES = {  # file name -> text; a.yml and b.yaml have a schedule, c.yml has none
    "a.yml": "name: a\non:\n  pull_request:\n  schedule:\n    - cron: '11 6 * * 1'\njobs: {}\n",
    "b.yaml": "name: b\n'on':\n  schedule:\n    - cron: '17 6 * * 1'\n    - cron: '0 0 1 * *'\n"
              "jobs: {}\n",
    "c.yml": "name: c\non: [push, pull_request]\njobs: {}\n",
}
IDS = {"a.yml": 101, "b.yaml": 102, "c.yml": 103}
LIST_KEY = f"/repos/{REPO}/actions/workflows?per_page=100&page=1"


def _wf_list(states=None, omit=()):
    states = states or {}
    wfs = [{"id": i, "name": f[:1], "path": f".github/workflows/{f}", "state": states.get(f, "active"),
            "created_at": "2026-10-04T23:17:35.000-04:00"} for f, i in IDS.items() if f not in omit]
    return {"total_count": len(wfs), "workflows": wfs}


def _run(wf_id, days_ago, conclusion="success", run_id=None, attempt=1, status="completed"):
    t = _parse_time(NOW, "NOW") - dt.timedelta(days=days_ago)
    return {"id": run_id or wf_id * 1000 + int(days_ago * 10), "workflow_id": wf_id,
            "event": "schedule", "status": status, "conclusion": conclusion,
            "head_sha": "dc92c159482bb1202694b756be3acb538e2d4a97", "run_attempt": attempt,
            "created_at": _stamp(t), "run_started_at": _stamp(t),
            "html_url": f"https://github.com/{REPO}/actions/runs/{run_id or wf_id}"}


def _runs_key(wf_id, success_only=False, page=1, per_page=None):
    per_page = per_page or (1 if success_only else RECENT)
    q = [("event", "schedule")] + ([("status", "success")] if success_only else []) + \
        [("exclude_pull_requests", "true"), ("per_page", per_page), ("page", page)]
    return f"/repos/{REPO}/actions/workflows/{wf_id}/runs?" + urllib.parse.urlencode(q)


def _commits_key(name):
    q = [("path", f".github/workflows/{name}"), ("per_page", 1)]
    return f"/repos/{REPO}/commits?" + urllib.parse.urlencode(q)


def _contents_key(name):
    return f"/repos/{REPO}/contents/.github/workflows/{name}"


def _commit(days_ago):
    t = _stamp(_parse_time(NOW, "NOW") - dt.timedelta(days=days_ago))
    return {"sha": "7d63696323dcfa1056489e1be3849835a1604ac2",
            "commit": {"author": {"name": "x", "date": t}, "committer": {"name": "GitHub", "date": t}}}


def _content(name, text):
    return {"type": "file", "encoding": "base64", "name": name, "path": f".github/workflows/{name}",
            "sha": "0f7788c4a61c3e5428297343131f264f1a05822b", "size": len(text),
            "content": base64.encodebytes(text.encode("utf-8")).decode("ascii")}


def _answers(success=None, recent=None, total=None, oldest=None, states=None, omit=(),
             commits=None, mains=None):
    """Fixture map. success: {file: run or None}; recent: {file: [runs, newest first]};
    commits: {file: days since the file's newest default-branch commit, or None for none};
    mains: {file: the default branch's text of the file, or None for no such file}
    (default: the same text as here). A file not given has a fresh success, which is
    also its newest scheduled run."""
    success, recent, total, oldest = success or {}, recent or {}, total or {}, oldest or {}
    commits, mains = commits or {}, mains or {}
    fx = {LIST_KEY: {"body": _wf_list(states, omit)}}
    for f, i in IDS.items():
        s = success[f] if f in success else _run(i, 2.0)
        runs = recent.get(f, [s] if s else [])
        fx[_runs_key(i, True)] = {"body": {"total_count": 1 if s else 0,
                                           "workflow_runs": [s] if s else []}}
        fx[_runs_key(i)] = {"body": {"total_count": total.get(f, len(runs)), "workflow_runs": runs}}
        if f in oldest:
            fx[_runs_key(i, page=total[f], per_page=1)] = {"body": {"total_count": total[f],
                                                        "workflow_runs": [oldest[f]]}}
        c = commits.get(f, 3.0)
        fx[_commits_key(f)] = {"body": [] if c is None else [_commit(c)]}
        text = mains.get(f, FILES[f])
        fx[_contents_key(f)] = ({"status": 404, "body": {"message": "Not Found", "status": "404"}}
                                if text is None else {"body": _content(f, text)})
    return fx


def self_test(out):
    a, b = IDS["a.yml"], IDS["b.yaml"]
    me_main = ["--self-workflow", "Example/Det-Eng/.github/workflows/a.yml@refs/heads/main"]
    me_pr = ["--self-workflow", f"{REPO}/.github/workflows/a.yml@refs/pull/7/merge"]
    old_fail = {"a.yml": _run(a, 3.0, "failure")}
    # Monday phase: the scheduled check runs after the other Monday runs have ended.
    green7 = _run(a, 7.0)
    red0 = _run(a, 0.01, "failure", 70)
    red7 = _run(a, 7.0, "failure", 77)
    green14 = _run(a, 14.0)
    no_sched_b = "name: b\non:\n  push:\njobs: {}\n"
    cases = [
        # (name, answers, extra args, expected exit, {file: level}, text that must appear,
        #  or a list of texts; a text that starts with '!' must not appear)
        ("fresh", _answers(), [], 0, {"a.yml": OK, "b.yaml": OK}, "2 checked: 2 ok"),
        ("8.0 days is not more than 8", _answers(success={"a.yml": _run(a, 8.0)}), [], 0,
         {"a.yml": OK}, "(8.00 days ago"),
        ("8 days and 1 minute warns, and shows more than 8", _answers(
            success={"a.yml": _run(a, 8 + 1 / 1440)}), [], 0, {"a.yml": WARN},
         ["::warning title=schedule-freshness::a.yml: the newest successful", "(8.01 days ago"]),
        ("15.0 days only warns", _answers(success={"a.yml": _run(a, 15.0)}), [], 0,
         {"a.yml": WARN}, "more than 8 days old"),
        ("16 days fails", _answers(success={"a.yml": _run(a, 16.0)}), [], 1,
         {"a.yml": FAIL}, "::error title=schedule-freshness::a.yml: the newest successful"),
        ("16 days on a pull request warns", _answers(success={"a.yml": _run(a, 16.0)}),
         ["--warn-only"], 0, {"a.yml": WARN}, "(a scheduled run would fail)"),
        ("Monday: a red run this morning after last week's success warns",
         _answers(success={"a.yml": green7}, recent={"a.yml": [red0, green7]}), [], 0,
         {"a.yml": WARN}, "the newest completed scheduled run is red: failure"),
        ("Monday: two red weeks in a row fail",
         _answers(success={"a.yml": green14}, recent={"a.yml": [red0, red7, green14]}), [], 1,
         {"a.yml": FAIL}, "2 red scheduled runs in a row after the newest success"),
        ("two red runs in a row on a pull request warn",
         _answers(success={"a.yml": green14}, recent={"a.yml": [red0, red7, green14]}),
         ["--warn-only"], 0, {"a.yml": WARN}, "(a scheduled run would fail) the newest"),
        ("Monday: one dropped run is not seen (7 days is ok)", _answers(success={"a.yml": green7}),
         [], 0, {"a.yml": OK}, "(7.00 days ago"),
        ("Monday: two dropped runs in a row warn (14 days)", _answers(success={"a.yml": green14}),
         [], 0, {"a.yml": WARN}, "(14.00 days ago"),
        ("Monday: three dropped runs in a row fail (21 days)",
         _answers(success={"a.yml": _run(a, 21.0)}), [], 1, {"a.yml": FAIL}, "(21.00 days ago"),
        ("a full page of red runs reads 'at least'",
         _answers(success={"a.yml": _run(a, 80.0)},
                  recent={"a.yml": [_run(a, 7.0 * k, "failure", 900 + k) for k in range(RECENT)]},
                  total={"a.yml": 40}), [], 1, {"a.yml": FAIL}, f"at least {RECENT} red scheduled runs"),
        ("a queued run is not counted as red",
         _answers(success={"a.yml": green7},
                  recent={"a.yml": [_run(a, 0.01, None, 71, status="queued"), green7]}), [], 0,
         {"a.yml": OK}, "newest scheduled run: queued"),
        ("a run that turned green between the two reads counts",
         _answers(success={"a.yml": _run(a, 9.0)}, recent={"a.yml": [_run(a, 0.5, run_id=72)]}),
         [], 0, {"a.yml": OK}, "0.50 days ago, run 72"),
        ("re-run attempt is named", _answers(success={"a.yml": _run(a, 1.0, attempt=2)}), [], 0,
         {"a.yml": OK}, "attempt 2"),
        ("disabled_inactivity fails", _answers(states={"b.yaml": "disabled_inactivity"}), [], 1,
         {"b.yaml": FAIL}, "state 'disabled_inactivity'"),
        ("disabled_manually on a pull request warns",
         _answers(states={"b.yaml": "disabled_manually"}), ["--warn-only"], 0, {"b.yaml": WARN},
         "gh workflow enable b.yaml"),
        ("an unknown state fails closed", _answers(states={"a.yml": "paused"}), [], 1,
         {"a.yml": FAIL}, "state 'paused'"),
        # A file that GitHub does not list.
        ("a file GitHub does not list and main does not have only warns",
         _answers(omit=("b.yaml",), mains={"b.yaml": None}), [], 0,
         {"b.yaml": WARN}, "the default branch has no such file: a new file"),
        ("a file on main for 3 days that GitHub does not list yet only warns (new)",
         _answers(omit=("b.yaml",)), [], 0, {"b.yaml": WARN},
         "GitHub lists no workflow at this path; a new schedule"),
        ("a file with a schedule on main for 20 days that GitHub does not list fails",
         _answers(omit=("b.yaml",), commits={"b.yaml": 20.0}), [], 1, {"b.yaml": FAIL},
         "so the schedule never started"),
        # No scheduled run at all: is the schedule on the default branch, and since when?
        ("no scheduled run, file changed 3 days ago on main, only warns",
         _answers(success={"b.yaml": None}), [], 0, {"b.yaml": WARN}, "a new schedule: the default"),
        ("no scheduled run, main has no such file (old commits of a deleted path), only warns",
         _answers(success={"b.yaml": None}, mains={"b.yaml": None}, commits={"b.yaml": 30.0}), [], 0,
         {"b.yaml": WARN}, "the default branch has no such file"),
        ("no scheduled run, a schedule added here to a file unchanged on main for 30 days, warns",
         _answers(success={"b.yaml": None}, mains={"b.yaml": no_sched_b}, commits={"b.yaml": 30.0}),
         [], 0, {"b.yaml": WARN}, ["has no schedule trigger: a new schedule", "!never started"]),
        ("the same on a pull request is a plain warning",
         _answers(success={"b.yaml": None}, mains={"b.yaml": no_sched_b}, commits={"b.yaml": 30.0}),
         ["--warn-only"], 0, {"b.yaml": WARN}, ["a new schedule", "!would fail"]),
        ("main's version that does not parse has no schedule: only warns",
         _answers(success={"b.yaml": None}, mains={"b.yaml": "on: {schedule: [\n"},
                  commits={"b.yaml": 30.0}), [], 0, {"b.yaml": WARN}, "has no schedule trigger"),
        ("no scheduled run in 20 days on main fails",
         _answers(success={"b.yaml": None}, commits={"b.yaml": 20.0}), [], 1, {"b.yaml": FAIL},
         "unchanged since 2026-10-01T12:00:00Z (20.00 days, commit 7d63696): more than 15 days, "
         "so the schedule never started"),
        ("no scheduled run in 20 days on a pull request warns",
         _answers(success={"b.yaml": None}, commits={"b.yaml": 20.0}), ["--warn-only"], 0,
         {"b.yaml": WARN}, "(a scheduled run would fail) no scheduled run yet"),
        # No successful scheduled run, but some runs.
        ("new schedule, one red run, warns",
         _answers(success={"a.yml": None}, recent={"a.yml": [old_fail["a.yml"]]}, total={"a.yml": 1},
                  oldest=old_fail),
         [], 0, {"a.yml": WARN}, "no successful scheduled run in 1 scheduled run(s)"),
        ("new schedule, two red runs, only warns",
         _answers(success={"a.yml": None}, recent={"a.yml": [red0, old_fail["a.yml"]]},
                  total={"a.yml": 2}, oldest=old_fail),
         [], 0, {"a.yml": WARN}, ["(3.00 days): a new schedule",
                                  "2 red scheduled runs in a row and none passed"]),
        ("one red run 20 days ago, none since, fails",
         _answers(success={"a.yml": None}, recent={"a.yml": [_run(a, 20.0, "failure")]}),
         [], 1, {"a.yml": FAIL}, "(20.00 days), more than 15 days, so it is not new"),
        ("a queued run and one red run 20 days ago fail: the oldest run decides",
         _answers(success={"a.yml": None},
                  recent={"a.yml": [_run(a, 0.01, None, 73, status="in_progress"),
                                    _run(a, 20.0, "failure", 74)]}),
         [], 1, {"a.yml": FAIL}, "since 2026-10-01T12:00:00Z (20.00 days), more than 15 days"),
        ("never green in 12 runs (oldest on page 12) fails",
         _answers(success={"a.yml": None},
                  recent={"a.yml": [_run(a, 7.0 * k, "failure", 800 + k) for k in range(RECENT)]},
                  total={"a.yml": 12}, oldest={"a.yml": _run(a, 77.0, "failure", 812)}),
         [], 1, {"a.yml": FAIL}, "no successful scheduled run in 12 scheduled run(s) since "
                                 "2026-08-05T12:00:00Z (77.00 days), more than 15 days"),
        # The workflow that holds this check.
        ("this scheduled run counts for its own workflow",
         _answers(success={"a.yml": _run(a, 30.0)},
                  recent={"a.yml": [red7, _run(a, 14.0, "failure", 78), _run(a, 30.0)]}),
         ["--scheduled-run-of", f"{REPO}/.github/workflows/a.yml@refs/heads/main"], 0,
         {"a.yml": OK}, "this run is a scheduled run of this workflow"),
        ("a manual run after a fix: the red runs of this workflow are not counted",
         _answers(success={"a.yml": green14},
                  recent={"a.yml": [_run(a, 0.2, "failure", 61), _run(a, 7.2, "failure", 62),
                                    green14]}),
         me_main, 0, {"a.yml": OK}, ["the newest scheduled run (any result): 2026-10-21T07:12:00Z "
                                     "(0.20 days ago, run 61, dc92c15, failure)",
                                     "its red scheduled runs are not counted"]),
        ("the same red runs of another workflow still fail",
         _answers(success={"a.yml": green14},
                  recent={"a.yml": [_run(a, 0.2, "failure", 61), _run(a, 7.2, "failure", 62),
                                    green14]}),
         [], 1, {"a.yml": FAIL}, "2 red scheduled runs in a row"),
        ("this workflow with no scheduled run in 20 days fails a manual run",
         _answers(success={"a.yml": _run(a, 20.0)}), me_main, 1, {"a.yml": FAIL},
         "the newest scheduled run (any result) is more than 15 days old"),
        ("the same on a pull request warns that a manual run would fail",
         _answers(success={"a.yml": _run(a, 20.0)}), ["--warn-only"] + me_pr, 0, {"a.yml": WARN},
         ["(a manual run would fail) the newest scheduled run", "!a scheduled run would fail"]),
        ("this workflow with no scheduled run at all uses the default branch",
         _answers(success={"a.yml": None}, commits={"a.yml": 20.0}), me_main, 1, {"a.yml": FAIL},
         "no scheduled run yet; the default branch has had the file"),
        ("--scheduled-run-of a workflow with no schedule is an error", _answers(),
         ["--scheduled-run-of", f"{REPO}/.github/workflows/c.yml@refs/heads/main"], 2, {},
         "--scheduled-run-of names .github/workflows/c.yml, which has no schedule trigger here"),
        ("--self-workflow of a workflow with no schedule is an error, also on a pull request",
         _answers(), ["--warn-only", "--self-workflow", f"{REPO}/.github/workflows/c.yml@refs/pull/7/merge"],
         2, {}, "--self-workflow names .github/workflows/c.yml, which has no schedule trigger here"),
    ]
    # API failures. An error that a re-run can clear (5xx, 429, a rate limit, a
    # network error, a truncated body) fails closed (exit 2) on the scheduled and
    # manual runs, and only warns with --warn-only. Every other error fails closed
    # in every mode. An error on one workflow does not stop the others.
    e502 = _answers()
    e502[_runs_key(b, True)] = [{"status": 502, "body": {"message": "Bad Gateway"}}] * ATTEMPTS
    retry_ok = _answers()
    retry_ok[_runs_key(b, True)] = [{"network_error": "connection reset"},
                                    {"truncated": True},
                                    {"status": 500, "body": None},
                                    {"body": {"total_count": 1, "workflow_runs": [_run(b, 1.0)]}}]
    truncated = _answers()
    truncated[LIST_KEY] = [{"truncated": True}]
    e403 = _answers()
    e403[LIST_KEY] = [{"status": 403, "body": {"message": "Resource not accessible by integration"}}]
    limit403 = _answers()
    limit403[LIST_KEY] = [{"status": 403, "body": {"message": "API rate limit exceeded for "
                                                              "installation ID 1."}}]
    limit_hdr = _answers()
    limit_hdr[LIST_KEY] = [{"status": 403, "body": {"message": "Forbidden"},
                            "headers": {"X-RateLimit-Remaining": "0"}}]
    e404_one = _answers(success={"b.yaml": _run(b, 30.0)})
    e404_one[_runs_key(a, True)] = {"status": 404, "body": {"message": "Not Found"}}
    e502_one = _answers(success={"b.yaml": _run(b, 30.0)})
    e502_one[_runs_key(a, True)] = {"status": 502, "body": {"message": "Bad Gateway"}}
    wrong = _answers(success={"a.yml": _run(a, 1.0, "failure")})
    short = _answers()
    short[LIST_KEY]["body"]["total_count"] = 9
    short[f"/repos/{REPO}/actions/workflows?per_page=100&page=2"] = {
        "body": {"total_count": 9, "workflows": []}}
    other_event = _answers()
    other_event[_runs_key(a, True)]["body"]["workflow_runs"][0]["event"] = "push"
    other_wf = _answers()
    other_wf[_runs_key(a)]["body"]["workflow_runs"][0] = dict(_run(a, 2.0), workflow_id=999)
    two_on_one = _answers()
    two_on_one[_runs_key(a, True)]["body"] = {"total_count": 2,
                                              "workflow_runs": [_run(a, 1.0), _run(a, 8.0)]}
    bad_commits = _answers(success={"b.yaml": None})
    bad_commits[_commits_key("b.yaml")] = {"body": {"message": "not a list"}}
    no_commit = _answers(success={"b.yaml": None}, commits={"b.yaml": None})
    bad_contents = _answers(success={"b.yaml": None})
    bad_contents[_contents_key("b.yaml")] = {"body": [{"type": "file", "name": "b.yaml"}]}
    internal = _answers()
    internal[_runs_key(a)] = {"internal_error": "boom"}
    # A 404 is not an outage: it does not trip the breaker, so a later 502 still retries.
    e404_then_retry = _answers()
    e404_then_retry[_runs_key(a, True)] = {"status": 404, "body": {"message": "Not Found"}}
    e404_then_retry[_runs_key(b, True)] = [{"status": 502, "body": {"message": "Bad Gateway"}},
                                           {"status": 502, "body": {"message": "Bad Gateway"}},
                                           {"body": {"total_count": 1,
                                                     "workflow_runs": [_run(b, 1.0)]}}]
    cases += [
        ("502 on every attempt fails closed", e502, [], 2, {"b.yaml": ERROR},
         "HTTP 502 (Bad Gateway)"),
        ("502 on every attempt on a pull request only warns", e502, ["--warn-only"], 0,
         {"a.yml": OK, "b.yaml": ERROR},
         "::warning title=schedule-freshness::API error that a re-run can clear (a scheduled run "
         "would fail closed): b.yaml: GET"),
        ("a reset, a truncated body and a 500, then 200, passes", retry_ok, [], 0,
         {"b.yaml": OK}, "2 checked: 2 ok"),
        ("a truncated body on every attempt fails closed", truncated, [], 2, {},
         "IncompleteRead"),
        ("a truncated body on every attempt on a pull request only warns", truncated,
         ["--warn-only"], 0, {}, "(1 only warn: a re-run can clear them)"),
        ("403 fails closed without retry", e403, [], 2, {},
         "::error title=schedule-freshness::GET /repos/example/det-eng/actions/workflows?per_page=100"
         "&page=1: HTTP 403 (Resource not accessible by integration)"),
        ("403 on a pull request fails closed too (a token or permission fault)", e403,
         ["--warn-only"], 2, {}, ["::error title=schedule-freshness::GET", "!only warn"]),
        ("403 rate limit on a pull request only warns", limit403, ["--warn-only"], 0, {},
         "API error that a re-run can clear"),
        ("403 rate limit (x-ratelimit-remaining 0) on a pull request only warns", limit_hdr,
         ["--warn-only"], 0, {}, "API error that a re-run can clear"),
        ("403 rate limit on a scheduled run fails closed", limit403, [], 2, {},
         "::error title=schedule-freshness::GET"),
        ("404 on one workflow: the others are still graded, and it fails closed", e404_one, [], 2,
         {"a.yml": ERROR, "b.yaml": FAIL}, "::error title=schedule-freshness::a.yml: GET"),
        ("the same 404 on a pull request fails closed too", e404_one, ["--warn-only"], 2,
         {"a.yml": ERROR, "b.yaml": WARN}, "(a scheduled run would fail) the newest successful"),
        ("a 502 on one workflow on a pull request warns, and the others are graded", e502_one,
         ["--warn-only"], 0, {"a.yml": ERROR, "b.yaml": WARN}, "1 error(s) (1 only warn"),
        ("a non-success run from the success filter fails closed", wrong, [], 2, {"a.yml": ERROR},
         "conclusion 'failure'"),
        ("a short workflow list fails closed", short, [], 2, {}, "holds 3 of total_count 9"),
        ("an answer of the wrong shape on a pull request fails closed", short, ["--warn-only"], 2,
         {}, "holds 3 of total_count 9"),
        ("a run of another event fails closed", other_event, [], 2, {}, "event='push'"),
        ("a run of another workflow fails closed", other_wf, [], 2, {}, "workflow_id=999"),
        ("two runs on a page of one fails closed", two_on_one, [], 2, {}, "2 runs on a page of 1"),
        ("a commits answer that is not a list fails closed", bad_commits, [], 2, {},
         "is not a list of at most one commit"),
        ("a file on main with no commit of it fails closed", no_commit, [], 2, {"b.yaml": ERROR},
         "but the commits API lists no commit of it"),
        ("a contents answer that is not a file fails closed", bad_contents, ["--warn-only"], 2, {},
         "is not a file with base64 content"),
        ("an unexpected internal error fails closed, also on a pull request", internal,
         ["--warn-only"], 2, {}, "unexpected error: RuntimeError: boom"),
        ("a 404 does not trip the breaker: a later 502 still retries", e404_then_retry, [], 2,
         {"a.yml": ERROR, "b.yaml": OK}, ["HTTP 404", "!one attempt only"]),
    ]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        wdir = os.path.join(tmp, "workflows")
        os.makedirs(wdir)
        for name, text in FILES.items():
            with open(os.path.join(wdir, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        extra_dirs = {
            "empty": {},
            "broken": {"x.yml": "on: {schedule: [\n"},
            "monthly": {"m.yml": "on:\n  schedule:\n    - cron: '7 5 1 * *'\njobs: {}\n"},
            "short_cron": {"s.yml": "on:\n  schedule:\n    - cron: '7 5 * *'\njobs: {}\n"},
        }
        dirs = {}
        for dname, files in extra_dirs.items():
            dirs[dname] = os.path.join(tmp, dname)
            os.makedirs(dirs[dname])
            for name, text in files.items():
                with open(os.path.join(dirs[dname], name), "w", encoding="utf-8") as fh:
                    fh.write(text)
        base = ["--repo", REPO, "--now", NOW, "--workflows-dir", wdir]
        runs = [(n, fx, base + x, rc, lv, txt) for n, fx, x, rc, lv, txt in cases]
        only = ["--repo", REPO, "--now", NOW, "--workflows-dir"]
        runs += [("no scheduled workflow fails closed", _answers(), only + [dirs["empty"]], 2, {},
                  "has a schedule trigger"),
                 ("a workflow file that does not parse fails closed", _answers(),
                  only + [dirs["broken"]], 2, {}, "does not parse"),
                 ("a monthly-only schedule is an error, also on a pull request", _answers(),
                  only + [dirs["monthly"], "--warn-only"], 2, {},
                  "m.yml: no cron entry runs at least once a week (7 5 1 * *"),
                 ("a cron without 5 fields is an error", _answers(), only + [dirs["short_cron"]], 2,
                  {}, "does not have 5 fields")]
        md = os.path.join(tmp, "summary.md")
        for name, fx, argv, want_rc, levels, texts in runs:
            buf, api = io.StringIO(), FixtureApi(fx)
            if name.startswith("an unexpected internal error"):
                err, sys.stderr = sys.stderr, io.StringIO()   # the traceback goes to stderr
            try:
                got_rc = run(argv + ["--markdown", md], api=api, out=buf)
            finally:
                if name.startswith("an unexpected internal error"):
                    sys.stderr = err
            log = buf.getvalue()
            got = {m.group(2): m.group(1).lower()
                   for m in re.finditer(r"^  (OK|WARN|FAIL|ERROR)\s+(\S+)", log, re.M)}
            bad = [f"exit {got_rc}, want {want_rc}"] if got_rc != want_rc else []
            bad += [f"{f}: {got.get(f)}, want {lv}" for f, lv in levels.items() if got.get(f) != lv]
            for text in [texts] if isinstance(texts, str) else texts:
                if text.startswith("!"):
                    bad += [f"text {text[1:]!r} must not appear"] if text[1:] in log else []
                else:
                    bad += [f"no text {text!r}"] if text not in log else []
            if name.startswith(("502 on every", "a truncated body")):
                key = _runs_key(b, True) if name.startswith("502") else LIST_KEY
                n = api.calls.count(key)
                bad += [] if n == ATTEMPTS else [f"{n} attempts, want {ATTEMPTS}"]
            if name.startswith("403"):
                n = len(api.calls)
                bad += [] if n == 1 else [f"{n} requests, want 1 (no retry on 403)"]
            failures += bool(bad)
            out.write(f"  {'PASS' if not bad else 'FAIL'}  {name}" + (f": {'; '.join(bad)}" if bad else "")
                      + "\n")
            if bad:
                out.write("".join("        | " + line + "\n" for line in log.splitlines()))
        # A slow outage, on a virtual clock: 8 scheduled workflows, the workflow list
        # answers, and every later read fails after `per` seconds (inf: no answer, so
        # the attempt ends at its timeout). The reads must end inside the budget (so
        # that the job's timeout does not end the step with no report), and each
        # workflow must still get its own error row.
        odir = os.path.join(tmp, "outage")
        os.makedirs(odir)
        names = [f"w{k}.yml" for k in range(1, 9)]
        for k, fname in enumerate(names):
            with open(os.path.join(odir, fname), "w", encoding="utf-8") as fh:
                fh.write(f"on:\n  schedule:\n    - cron: '{11 + k} 6 * * 1'\njobs: {{}}\n")
        olist = {"total_count": len(names), "workflows": [
            {"id": 201 + k, "name": n, "path": f".github/workflows/{n}", "state": "active"}
            for k, n in enumerate(names)]}

        class SlowApi(Api):
            def __init__(self, per):
                self.t, self.per = 0.0, per
                super().__init__("fixture://", sleep=self._pause, clock=lambda: self.t)

            def _pause(self, seconds):
                self.t += seconds

            def _send(self, key, timeout):
                if key == LIST_KEY:
                    return 200, olist, {}
                if self.per >= timeout:
                    self.t += timeout
                    raise TimeoutError("timed out")
                self.t += self.per
                return 502, {"message": "Server Error"}, {}

        hang = float("inf")
        outages = [  # (name, per, extra args, exit, most seconds, requests or None, texts)
            ("a slow outage (every read a 502 after 10 s) on a pull request only warns, inside "
             "the budget", 10.0, ["--warn-only"], 0, API_BUDGET, 1 + ATTEMPTS + 7,
             ["one attempt only: an earlier request failed", "8 error(s) (8 only warn"]),
            ("the same slow outage on a scheduled run fails closed, inside the budget", 10.0, [],
             2, API_BUDGET, 1 + ATTEMPTS + 7, ["8 error(s)", "!only warn"]),
            (f"no answer at all: an attempt waits {SOCKET_TIMEOUT} s, inside the budget", hang,
             ["--warn-only"], 0, API_BUDGET, 1 + ATTEMPTS + 7, ["TimeoutError", "8 error(s)"]),
            ("--api-budget 60 stops the reads, and each later workflow gets its own error row",
             hang, ["--warn-only", "--api-budget", "60"], 0, 60, 4,
             ["no attempt 4: it would end after the API time budget (60 s)",
              "w8.yml: GET", "not sent: the API time budget (60 s) is spent", "8 error(s)"]),
        ]
        obase = ["--repo", REPO, "--now", NOW, "--workflows-dir", odir]
        for name, per, extra, want_rc, most, want_n, texts in outages:
            buf, api = io.StringIO(), SlowApi(per)
            got_rc = run(obase + extra, api=api, out=buf)
            log = buf.getvalue()
            rows = re.findall(r"^  ERROR\s+(\S+)", log, re.M)
            bad = [f"exit {got_rc}, want {want_rc}"] if got_rc != want_rc else []
            bad += [] if rows == names else [f"error rows {rows}, want one for each of {names}"]
            bad += [] if api.t <= most else [f"{api.t:g} s of API time, want at most {most:g}"]
            bad += [] if want_n in (None, len(api.calls)) else [
                f"{len(api.calls)} requests, want {want_n}"]
            for text in texts:
                if text.startswith("!"):
                    bad += [f"text {text[1:]!r} must not appear"] if text[1:] in log else []
                else:
                    bad += [f"no text {text!r}"] if text not in log else []
            failures += bool(bad)
            out.write(f"  {'PASS' if not bad else 'FAIL'}  {name} ({api.t:g} s)"
                      + (f": {'; '.join(bad)}" if bad else "") + "\n")
            if bad:
                out.write("".join("        | " + line + "\n" for line in log.splitlines()))
        runs += outages
        with open(md, encoding="utf-8") as fh:
            table = fh.read()
        missing = [v for v in ("**FAIL**", "**ERROR**", "**WARN (API error)**", "**WARN**",
                               "**PASS**") if v not in table]
        if "| Workflow | Cron (UTC) |" not in table or missing:
            failures += 1
            out.write(f"  FAIL  the Markdown summary has no table, or no verdict {missing}\n")
    if _escape_data("50% done\nnext") != "50%25 done%0Anext":
        failures += 1
        out.write("  FAIL  annotation text escaping\n")
    # The default budget must fit in the job: in half of its timeout-minutes, so that
    # checkout, setup-python, pip and this self-test have the other half.
    try:
        with open(os.path.join(WORKFLOWS_DIR, "detection-quality.yml"), encoding="utf-8") as fh:
            limit = float(yaml.safe_load(fh)["jobs"][TITLE]["timeout-minutes"]) * 60 / 2
        fits = API_BUDGET + SOCKET_TIMEOUT <= limit
        why = (f"API_BUDGET {API_BUDGET} s + SOCKET_TIMEOUT {SOCKET_TIMEOUT} s, want at most "
               f"{limit:g} s (half the {TITLE} job's timeout-minutes)")
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError) as err:
        fits, why = False, f"cannot read the {TITLE} job's timeout-minutes: {type(err).__name__}: {err}"
    failures += not fits
    out.write(f"  {'PASS' if fits else 'FAIL'}  the API time budget fits in the job: {why}\n")
    out.write(f"{TITLE} self-test: {len(runs) + 3 - failures} of {len(runs) + 3} passed\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
