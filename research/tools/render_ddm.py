#!/usr/bin/env python3
"""
Render a Detection Data Model (Arrows app JSON) to a PNG.

The tired-labs/techniques TRRs show each DDM as a PNG exported from the
Arrows app (https://arrows.app): circle nodes with a coloured border, the
operation name inside, telemetry sources as pill labels, and the details as
"Key: value" properties beside the node. This script draws the same picture
from the same JSON, so the JSON stays the source and the PNG is a build
output. You can still import the JSON into Arrows to edit it by hand.

    python3 research/tools/render_ddm.py research/trr9001/lin/ddms/*.json
    python3 research/tools/render_ddm.py --check research/trr*/*/ddms/*.json

The PNG is written beside the JSON (same base name). The renderer stores the
SHA-256 of the source JSON in a PNG tEXt chunk (key "ddm-source-sha256"), so
`--check` and the TRR linter can tell when a PNG is stale without a browser.

Rendering needs a headless Chromium (or Chrome). It looks for one at
$CHROME, then the Playwright cache, then on PATH. `--check` needs no browser.

Node style keys honoured (per node, falling back to the top-level "style"):
  border-color, border-width, node-color, radius, caption-font-size,
  label-font-size, property-font-size, outside-position
  (auto | top | bottom | left | right).
Relationship style keys honoured: arrow-color, arrow-width.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"
HASH_KEY = b"ddm-source-sha256"
SCALE = 2  # device pixel ratio of the output PNG


def source_hash(json_path):
    with open(json_path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def png_chunks(data):
    if not data.startswith(PNG_SIG):
        raise ValueError("not a PNG file")
    pos = len(PNG_SIG)
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        yield pos, ctype, body, 12 + length
        pos += 12 + length


def png_source_hash(png_path):
    """Return the stored source hash, or None if the PNG has none."""
    with open(png_path, "rb") as fh:
        data = fh.read()
    for _, ctype, body, _ in png_chunks(data):
        if ctype == b"tEXt" and body.startswith(HASH_KEY + b"\x00"):
            return body[len(HASH_KEY) + 1:].decode("latin-1")
    return None


def stamp_png(png_path, digest):
    """Insert (or replace) the tEXt source-hash chunk right after IHDR."""
    with open(png_path, "rb") as fh:
        data = fh.read()
    out = bytearray(PNG_SIG)
    payload = HASH_KEY + b"\x00" + digest.encode("latin-1")
    chunk = (struct.pack(">I", len(payload)) + b"tEXt" + payload
             + struct.pack(">I", zlib.crc32(b"tEXt" + payload) & 0xFFFFFFFF))
    for pos, ctype, body, size in png_chunks(data):
        if ctype == b"tEXt" and body.startswith(HASH_KEY + b"\x00"):
            continue
        out += data[pos:pos + size]
        if ctype == b"IHDR":
            out += chunk
    with open(png_path, "wb") as fh:
        fh.write(out)


def find_chrome():
    env = os.environ.get("CHROME")
    if env:
        return env
    # Prefer headless_shell: its viewport is exactly the window size.
    pw = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
    for pattern in ("chromium_headless_shell-*/chrome-linux/headless_shell",
                    "chromium-*/chrome-linux/chrome"):
        found = sorted(glob.glob(os.path.join(pw, pattern)), reverse=True)
        if found:
            return found[0]
    for name in ("chromium-headless-shell", "chromium", "chromium-browser",
                 "google-chrome", "chrome"):
        path = shutil.which(name)
        if path:
            return path
    sys.exit("render_ddm: no Chromium found; set $CHROME to a Chrome/Chromium binary")


# The drawing itself runs in the browser, so text is measured with the real
# font. Pass 1 lays out the graph and reports its size; pass 2 screenshots it.
PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8">
<style>html,body{margin:0;padding:0;background:#fff;overflow:hidden}
svg{display:block}</style></head>
<body><svg id="c" xmlns="http://www.w3.org/2000/svg"></svg>
<script>
const DATA = __DATA__;
const FONT = '"Liberation Sans", Arial, Helvetica, sans-serif';
const DEF = {"border-width": 4, "border-color": "#000000", "node-color": "#ffffff",
  "radius": 50, "caption-font-size": 16, "label-font-size": 14,
  "property-font-size": 14, "outside-position": "auto", "arrow-width": 5,
  "arrow-color": "#000000", "type-font-size": 16};
const G = Object.assign({}, DEF, DATA.style || {});
const sv = (o, k) => (o.style && o.style[k] !== undefined) ? o.style[k] : G[k];
const ctx = document.createElement("canvas").getContext("2d");
const tw = (t, s) => { ctx.font = s + "px " + FONT; return ctx.measureText(t).width; };
const svg = document.getElementById("c");
const NS = "http://www.w3.org/2000/svg";
function el(tag, attrs, parent, text) {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (text !== undefined) e.textContent = text;
  (parent || svg).appendChild(e);
  return e;
}
const edgeLayer = el("g", {}), nodeLayer = el("g", {}), textLayer = el("g", {});

// Wrap a caption to fit inside the circle; grow the radius if it must.
function wrap(text, size, maxW) {
  const lines = [];
  for (const para of String(text).split("\n")) {
    let cur = "";
    for (const w of para.split(/\s+/).filter(Boolean)) {
      const t = cur ? cur + " " + w : w;
      if (cur && tw(t, size) > maxW) { lines.push(cur); cur = w; } else cur = t;
    }
    lines.push(cur);
  }
  return lines;
}

const nodes = {};
for (const n of DATA.nodes) {
  const size = sv(n, "caption-font-size");
  let r = sv(n, "radius");
  const lines = wrap(n.caption || "", size, r * 1.4);
  const lh = size * 1.2;
  const w = Math.max(0, ...lines.map(l => tw(l, size)));
  const need = Math.sqrt((w / 2) ** 2 + (lines.length * lh / 2) ** 2) + 8;
  r = Math.max(r, need);
  nodes[n.id] = {n, x: n.position.x, y: n.position.y, r, lines, size, lh,
                 bw: sv(n, "border-width"), angles: []};
}

// Relationships: straight arrows border to border; parallel ones are offset.
const pairs = {};
for (const rel of DATA.relationships) {
  const key = [rel.fromId, rel.toId].sort().join("|");
  (pairs[key] = pairs[key] || []).push(rel);
}
for (const key in pairs) {
  const group = pairs[key];
  group.forEach((rel, i) => {
    const a = nodes[rel.fromId], b = nodes[rel.toId];
    const [lo] = key.split("|");
    const sgn = rel.fromId === lo ? 1 : -1;
    const off = (i - (group.length - 1) / 2) * 14 * sgn;
    const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
    const ux = dx / len, uy = dy / len, px = -uy, py = ux;
    a.angles.push(Math.atan2(dy, dx)); b.angles.push(Math.atan2(-dy, -dx));
    const w = sv(rel, "arrow-width"), color = sv(rel, "arrow-color");
    const sa = Math.sqrt(Math.max(0, a.r * a.r - off * off));
    const sb = Math.sqrt(Math.max(0, b.r * b.r - off * off));
    const x1 = a.x + ux * (sa + a.bw / 2 + 6) + px * off;
    const y1 = a.y + uy * (sa + a.bw / 2 + 6) + py * off;
    const x2 = b.x - ux * (sb + b.bw / 2 + 6) + px * off;
    const y2 = b.y - uy * (sb + b.bw / 2 + 6) + py * off;
    const hl = w * 4 + 4, hw = w * 2.2 + 2;
    const xs = x2 - ux * hl, ys = y2 - uy * hl;
    el("line", {x1, y1, x2: xs + ux, y2: ys + uy, stroke: color,
                "stroke-width": w}, edgeLayer);
    el("polygon", {fill: color, points: [[x2, y2], [xs + px * hw, ys + py * hw],
                   [xs - px * hw, ys - py * hw]].map(p => p.join(",")).join(" ")},
       edgeLayer);
    if (rel.type) {
      const s = sv(rel, "type-font-size");
      let ang = Math.atan2(uy, ux) * 180 / Math.PI;
      if (ang > 90) ang -= 180; else if (ang < -90) ang += 180;
      const mx = (x1 + xs) / 2, my = (y1 + ys) / 2;
      const g = el("g", {transform: `translate(${mx},${my}) rotate(${ang})`}, textLayer);
      const lw = tw(rel.type, s);
      el("rect", {x: -lw / 2 - 5, y: -s * 0.75, width: lw + 10, height: s * 1.5,
                  fill: "#ffffff"}, g);
      el("text", {x: 0, y: 0, "font-size": s, "font-family": FONT,
                  "text-anchor": "middle", "dominant-baseline": "central",
                  fill: color}, g, rel.type);
    }
  });
}

// Nodes: circle, caption inside, labels (pills) and properties outside.
const SIDES = {top: -Math.PI / 2, bottom: Math.PI / 2, right: 0, left: Math.PI};
const angDist = (a, b) => { let d = Math.abs(a - b) % (2 * Math.PI); return d > Math.PI ? 2 * Math.PI - d : d; };
for (const id in nodes) {
  const o = nodes[id], n = o.n;
  el("circle", {cx: o.x, cy: o.y, r: o.r, fill: sv(n, "node-color"),
                stroke: sv(n, "border-color"), "stroke-width": o.bw}, nodeLayer);
  const top0 = o.y - (o.lines.length * o.lh) / 2 + o.lh / 2;
  o.lines.forEach((l, i) => el("text", {x: o.x, y: top0 + i * o.lh,
    "font-size": o.size, "font-family": FONT, "text-anchor": "middle",
    "dominant-baseline": "central", fill: "#000"}, textLayer, l));

  const labels = n.labels || [], props = Object.entries(n.properties || {});
  if (!labels.length && !props.length) continue;
  let side = sv(n, "outside-position");
  if (!(side in SIDES)) {
    side = "top"; let best = -1;
    for (const s of ["top", "bottom", "right", "left"]) {
      const d = Math.min(Math.PI, ...o.angles.map(a => angDist(a, SIDES[s])));
      if (d > best + 1e-6) { best = d; side = s; }
    }
  }
  const ls = sv(n, "label-font-size"), ps = sv(n, "property-font-size");
  const pillH = ls + 10, plh = ps * 1.25;
  const kw = Math.max(0, ...props.map(([k]) => tw(k + ": ", ps)));
  const vw = Math.max(0, ...props.map(([, v]) => tw(String(v), ps)));
  const pillW = labels.map(l => tw(l, ls) + 22);
  const bw = Math.max(kw + vw, ...pillW, 0);
  const bh = labels.length * (pillH + 6) + props.length * plh;
  const gap = o.bw / 2 + 8;
  let bx, by;  // top-left of the block
  if (side === "top") { bx = o.x - bw / 2; by = o.y - o.r - gap - bh; }
  else if (side === "bottom") { bx = o.x - bw / 2; by = o.y + o.r + gap; }
  else if (side === "right") { bx = o.x + o.r + gap; by = o.y - bh / 2; }
  else { bx = o.x - o.r - gap - bw; by = o.y - bh / 2; }
  let cy = by;
  labels.forEach((l, i) => {
    const w = pillW[i];
    const px = side === "right" ? bx : side === "left" ? bx + bw - w : o.x - w / 2;
    el("rect", {x: px, y: cy + 1, width: w, height: pillH, rx: pillH / 2,
                fill: "#fff", stroke: "#000", "stroke-width": 2}, textLayer);
    el("text", {x: px + w / 2, y: cy + 1 + pillH / 2, "font-size": ls,
                "font-family": FONT, "text-anchor": "middle",
                "dominant-baseline": "central", fill: "#000"}, textLayer, l);
    cy += pillH + 6;
  });
  // Properties are colon-aligned: keys end at one column, values start there.
  const colX = side === "right" ? bx + kw
             : side === "left" ? bx + bw - vw
             : o.x - (kw + vw) / 2 + kw;
  props.forEach(([k, v]) => {
    el("text", {x: colX, y: cy + plh / 2, "font-size": ps, "font-family": FONT,
                "text-anchor": "end", "dominant-baseline": "central", fill: "#000"},
       textLayer, k + ": ");
    el("text", {x: colX, y: cy + plh / 2, "font-size": ps, "font-family": FONT,
                "dominant-baseline": "central", fill: "#000"}, textLayer, String(v));
    cy += plh;
  });
}

const bb = svg.getBBox(), pad = 24;
const W = Math.ceil(bb.width + 2 * pad), H = Math.ceil(bb.height + 2 * pad);
svg.setAttribute("viewBox", `${bb.x - pad} ${bb.y - pad} ${W} ${H}`);
svg.setAttribute("width", W); svg.setAttribute("height", H);
document.title = "SIZE " + W + "x" + H + " VH" + innerHeight;
</script></body></html>
"""


def chrome_run(chrome, args):
    cmd = [chrome, "--headless", "--no-sandbox", "--disable-gpu",
           "--hide-scrollbars", "--force-color-profile=srgb"] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def render(json_path, chrome):
    with open(json_path, encoding="utf-8") as fh:
        data = json.load(fh)
    page = PAGE.replace("__DATA__", json.dumps(data))
    png_path = os.path.splitext(json_path)[0] + ".png"
    with tempfile.TemporaryDirectory() as tmp:
        html = os.path.join(tmp, "ddm.html")
        with open(html, "w", encoding="utf-8") as fh:
            fh.write(page)
        url = "file://" + html
        dom = chrome_run(chrome, ["--window-size=1000,1000", "--dump-dom", url]).stdout
        m = re.search(r"<title>SIZE (\d+)x(\d+) VH(\d+)</title>", dom)
        if not m:
            sys.exit(f"render_ddm: layout failed for {json_path}")
        # Full Chrome's headless mode reserves part of the window for browser
        # UI, so grow the window by that much to keep the whole graph in view.
        w, h = int(m.group(1)), int(m.group(2)) + 1000 - int(m.group(3))
        res = chrome_run(chrome, [f"--window-size={w},{h}",
                                  f"--force-device-scale-factor={SCALE}",
                                  f"--screenshot={os.path.abspath(png_path)}", url])
        if not os.path.exists(png_path):
            sys.exit(f"render_ddm: screenshot failed for {json_path}\n{res.stderr}")
    stamp_png(png_path, source_hash(json_path))
    return png_path


def check(json_path):
    png_path = os.path.splitext(json_path)[0] + ".png"
    if not os.path.exists(png_path):
        return "no PNG beside the JSON"
    stored = png_source_hash(png_path)
    if stored is None:
        return "PNG has no source hash (not made by render_ddm.py)"
    if stored != source_hash(json_path):
        return "PNG is stale (JSON changed since it was rendered)"
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("json", nargs="+", help="DDM JSON file(s) (Arrows export)")
    ap.add_argument("--check", action="store_true",
                    help="verify each PNG matches its JSON; render nothing")
    args = ap.parse_args()
    if args.check:
        bad = 0
        for jp in args.json:
            problem = check(jp)
            print(f"{'FAIL' if problem else 'OK  '}  {jp}" + (f": {problem}" if problem else ""))
            bad += bool(problem)
        return 1 if bad else 0
    chrome = find_chrome()
    for jp in args.json:
        print(f"rendered {render(jp, chrome)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
