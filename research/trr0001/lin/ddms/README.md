# Detection Data Models — TRR0001.LIN

Each `*.json` file is an [Arrows app](https://arrows.app) export of one
procedure's DDM. To edit a model, open Arrows, import the JSON, change the
graph, then export the JSON back here. Export a PNG beside the JSON (same base
name, `.png`) for the TRR and for the upstream pull request.

The TRR README also inlines each DDM as a Mermaid diagram, so the graphs
render on GitHub without a PNG. The JSON here is the canonical, editable
source.

| File | Procedure | Chokepoint node |
|------|-----------|-----------------|
| `trr0001_lin_a.json` | TRR0001.LIN.A — raw packet socket | `socket(AF_PACKET)` (shared with B) |
