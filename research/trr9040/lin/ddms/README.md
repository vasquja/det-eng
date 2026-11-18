# Detection Data Models — TRR9040.LIN

One DDM per procedure. Each `*.json` file is the source: an
[Arrows app](https://arrows.app) graph in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.png` beside it is the picture the TRR shows, rendered from the JSON:

```sh
python3 research/tools/render_ddm.py research/trr9040/lin/ddms/*.json
```

To edit a model, change the JSON (by hand, or import it into Arrows and export
it back), then render again. The TRR linter fails when a PNG is missing or
older than its JSON.

Colours: black = the remote adversary (an abstract step), blue = the JVM (the
crashing process), green = the service supervisor. Shaded = the primary
detection node.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9040_lin_a` | TRR9040.LIN.A — JVM fatal error log | create of `hs_err_pid<pid>.log` — built + proven |
