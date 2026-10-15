"""
Load the benign corpus: the noise floor every rule is scored against.

The positive/negative controls in each validator are a hard, binary gate: the
rule must catch its emulation and reject its broken variants. They say nothing
about how often a rule fires on ordinary operational activity. The benign corpus
is that second, softer layer: slices of normal admin, developer and service
activity, in the same event schema the validators use, that score_benign.py runs
every rule over and reports a false-positive count and rate for.

A slice is one JSON spec under detections/benign/slices/<family>/<id>.json:

  id           unique slice id (also the file's stem).
  version      integer; bump it whenever the slice's content changes.
  logsource    {"product": ..., "service": ...} (or "category"), matched against
               each rule's own logsource. Only rules with the same logsource are
               scored against the slice.
  fidelity     "recorded"  real telemetry, captured and sanitized; or
               "synthetic" generated from the templates below, modelled on
               documented real activity.
  represents   what activity the slice stands for (one or two sentences).
  provenance   where the shapes come from (docs, a CI capture, a lab run).
  adjacent_to  optional list of the rules / techniques the slice deliberately
               sits next to (near-miss operational activity).

  A recorded slice adds:
    data       a JSONL file next to the spec (one raw event per line).

  A synthetic slice adds:
    count      how many events to generate.
    vars       named value generators (below).
    templates  [{"weight": n, "event": {...}}]: raw events with "{{var}}" or
               "{{var.attr}}" placeholders. A string that is exactly one
               placeholder takes the value's own type (int, bool, object).

  Value generators (deterministic: seeded by "<id>:<version>"):
    [a, b, ...]                    pick one (objects allowed: use {{var.attr}})
    {"weighted": [[w, value], ...]} pick one by weight
    {"int": [lo, hi]}              integer in [lo, hi]
    {"hex": n}                     n lowercase hex digits
    {"ipv4": "cidr"}               a host address inside the CIDR
    {"uuid": true}                 a UUID-shaped string
    {"seq": "fmt {n}"}             a per-slice counter
    {"time": {"start": ISO, "step_seconds": [lo, hi], "format": strftime}}
                                   a per-slice clock that only moves forward
                                   (format defaults to ISO 8601 with Z)

    {"offset": {"var": "t", "seconds": n, "format": strftime}}
                                   another time variable of the same event (or
                                   sequence) shifted by n seconds, e.g. a
                                   credential's expiration after its issue time

  Each variable is drawn once per event, so the same placeholder used twice in
  one event (an ARN and its user name) stays consistent.

  A template may hold a SEQUENCE instead of one event:
    {"weight": n, "events": [{"event": {...}}, {"delay_ms": 40, "event": {...}}]}
  Every event of one draw shares the draw's variables (the same pid, the same
  session), and a time variable advances only by each step's delay_ms. Real
  multi-event behaviour -- runc's memfd re-exec, a pipe then a splice in one
  process, a namespace deletion and its controller's cleanup -- must be written
  as a sequence: events drawn independently almost never line up in one pid
  inside a correlation window. `count` is the number of template draws, so a
  sequence adds several events per draw.

Expansion is deterministic, so the corpus is versioned data: the same specs
always produce the same events, and corpus_digest() changes only when a spec
does.
"""

import glob
import hashlib
import ipaddress
import json
import os
import random
import re
from datetime import datetime, timedelta, timezone

import sigma_eval

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.join(REPO, "detections", "benign")
SLICES = os.path.join(ROOT, "slices")
_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][\w]*)((?:\.[\w]+)*)\s*\}\}")
REQUIRED = ("id", "version", "logsource", "fidelity", "represents", "provenance")


class Slice:
    def __init__(self, spec, path, raw_events):
        self.spec = spec
        self.path = path
        self.id = spec["id"]
        self.version = spec["version"]
        self.logsource = spec["logsource"]
        self.fidelity = spec["fidelity"]
        self.raw = raw_events
        self.events = [sigma_eval.flatten(e) for e in raw_events]
        canon = "\n".join(json.dumps(e, sort_keys=True, separators=(",", ":"))
                          for e in raw_events)
        self.digest = hashlib.sha256(canon.encode()).hexdigest()

    def matches(self, logsource):
        """True if a rule with this logsource reads this slice."""
        keys = ("product", "service", "category")
        mine = {k: self.logsource.get(k) for k in keys}
        theirs = {k: (logsource or {}).get(k) for k in keys}
        return mine == theirs


class _Gen:
    """Deterministic value generators for one slice."""

    def __init__(self, spec):
        self.rng = random.Random(f"{spec['id']}:{spec['version']}")
        self.vars = spec.get("vars") or {}
        self.counters = {}
        self.clocks = {}
        self.seq_base = None  # {time var: datetime} while expanding a sequence
        self.delay_ms = 0
        self.times = {}       # time var -> datetime of its value in this draw

    def _below(self, n):
        return int(self.rng.random() * n) if n > 0 else 0

    def draw(self, name):
        if name not in self.vars:
            raise KeyError(f"undefined variable {{{{{name}}}}}")
        g = self.vars[name]
        if isinstance(g, list):
            return g[self._below(len(g))]
        if not isinstance(g, dict):
            return g
        if "weighted" in g:
            total = sum(w for w, _ in g["weighted"])
            x = self.rng.random() * total
            for w, value in g["weighted"]:
                x -= w
                if x < 0:
                    return value
            return g["weighted"][-1][1]
        if "int" in g:
            lo, hi = g["int"]
            return lo + self._below(hi - lo + 1)
        if "hex" in g:
            return "".join("0123456789abcdef"[self._below(16)] for _ in range(g["hex"]))
        if "ipv4" in g:
            net = ipaddress.ip_network(g["ipv4"], strict=False)
            usable = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
            offset = 1 + self._below(usable) if net.num_addresses > 2 else self._below(usable)
            return str(net.network_address + offset)
        if "uuid" in g:
            h = "".join("0123456789abcdef"[self._below(16)] for _ in range(32))
            return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{'89ab'[self._below(4)]}{h[17:20]}-{h[20:32]}"
        if "seq" in g:
            n = self.counters.get(name, 0) + 1
            self.counters[name] = n
            return g["seq"].replace("{n}", str(n))
        if "time" in g:
            t = g["time"]
            if self.seq_base is not None and name in self.seq_base:
                # a later step of a sequence: same draw, moved on by the step delays
                now = self.seq_base[name] + timedelta(milliseconds=self.delay_ms)
            else:
                now = self.clocks.get(name)
                if now is None:
                    now = datetime.fromisoformat(t["start"].replace("Z", "+00:00"))
                else:
                    lo, hi = t.get("step_seconds", [1, 60])
                    now = now + timedelta(seconds=lo + self.rng.random() * (hi - lo))
                self.clocks[name] = now
                if self.seq_base is not None:
                    self.seq_base[name] = now
            self.times[name] = now
            return _fmt_time(now, t.get("format"))
        if "offset" in g:
            o = g["offset"]
            base = self.times.get(o["var"])
            if base is None:
                raise ValueError(f"{name}: offset of {o['var']!r}, which this event has not "
                                 "drawn yet (put the base time earlier in the template)")
            return _fmt_time(base + timedelta(seconds=o.get("seconds", 0)), o.get("format"))
        raise ValueError(f"unknown generator for {name}: {g}")


def _fmt_time(when, fmt):
    if fmt:
        text = when.astimezone(timezone.utc).strftime(fmt)
        return text[:-3] if fmt.endswith("%f") else text  # milliseconds
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fill(node, values, gen):
    if isinstance(node, dict):
        return {k: _fill(v, values, gen) for k, v in node.items()}
    if isinstance(node, list):
        return [_fill(v, values, gen) for v in node]
    if not isinstance(node, str) or "{{" not in node:
        return node

    def resolve(name, attrs):
        if name not in values:
            values[name] = gen.draw(name)
        value = values[name]
        for attr in filter(None, attrs.split(".")):
            value = value[attr]
        return value

    whole = _PLACEHOLDER.fullmatch(node.strip())
    if whole:
        return resolve(whole.group(1), whole.group(2))
    return _PLACEHOLDER.sub(lambda m: str(resolve(m.group(1), m.group(2))), node)


def expand(spec):
    """Generate a synthetic slice's raw events."""
    gen = _Gen(spec)
    templates = spec["templates"]
    weights = [t.get("weight", 1) for t in templates]
    total = sum(weights)
    events = []
    for _ in range(spec["count"]):
        x = gen.rng.random() * total
        for template, w in zip(templates, weights):
            x -= w
            if x < 0:
                break
        gen.times = {}
        if "events" not in template:
            events.append(_fill(template["event"], {}, gen))
            continue
        # A sequence: one draw of the shared variables; time moves only by delay_ms.
        values, gen.seq_base, gen.delay_ms = {}, {}, 0
        time_vars = {n for n, g in gen.vars.items() if isinstance(g, dict) and "time" in g}
        try:
            for step in template["events"]:
                gen.delay_ms += step.get("delay_ms", 0)
                for name in time_vars | {n for n, g in gen.vars.items()
                                         if isinstance(g, dict) and "offset" in g}:
                    values.pop(name, None)  # re-render the clock at this step's delay
                events.append(_fill(step["event"], values, gen))
        finally:
            gen.seq_base, gen.delay_ms = None, 0
    return events


def validate_spec(spec, path):
    problems = [f"missing {k}" for k in REQUIRED if k not in spec]
    stem = os.path.splitext(os.path.basename(path))[0]
    if spec.get("id") != stem:
        problems.append(f"id {spec.get('id')!r} does not match the file name {stem!r}")
    if spec.get("fidelity") not in ("recorded", "synthetic"):
        problems.append("fidelity must be 'recorded' or 'synthetic'")
    if spec.get("fidelity") == "recorded" and not spec.get("data"):
        problems.append("a recorded slice needs `data` (a JSONL file)")
    if spec.get("fidelity") == "synthetic":
        for k in ("count", "templates"):
            if k not in spec:
                problems.append(f"a synthetic slice needs `{k}`")
        for i, t in enumerate(spec.get("templates") or []):
            if ("event" in t) == ("events" in t):
                problems.append(f"template {i} needs exactly one of `event` or `events`")
    return problems


def load_slice(path):
    with open(path, encoding="utf-8") as fh:
        spec = json.load(fh)
    problems = validate_spec(spec, path)
    if problems:
        raise ValueError(f"{os.path.relpath(path, REPO)}: {'; '.join(problems)}")
    if spec["fidelity"] == "recorded":
        data = os.path.join(os.path.dirname(path), spec["data"])
        with open(data, encoding="utf-8") as fh:
            raw = [json.loads(line) for line in fh if line.strip()]
    else:
        raw = expand(spec)
    return Slice(spec, path, raw)


def load_corpus(root=SLICES):
    """Every slice under detections/benign/slices/, sorted by id."""
    slices = [load_slice(p) for p in sorted(glob.glob(os.path.join(root, "**", "*.json"),
                                                      recursive=True))]
    ids = [s.id for s in slices]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate slice id(s): {', '.join(dupes)}")
    return sorted(slices, key=lambda s: s.id)


def corpus_digest(slices):
    h = hashlib.sha256()
    for s in sorted(slices, key=lambda s: s.id):
        h.update(f"{s.id}:{s.version}:{s.digest}\n".encode())
    return h.hexdigest()
