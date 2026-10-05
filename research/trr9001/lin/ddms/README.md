# Detection Data Models — TRR9001.LIN

Each `*.json` file is an [Arrows app](https://arrows.app) export of one
procedure's DDM. To edit a model, open Arrows, import the JSON, change the
graph, then export the JSON back here. Export a PNG beside the JSON (same base
name, `.png`) for the TRR and for the upstream pull request.

The TRR README also inlines each DDM as a Mermaid diagram, so the graphs
render on GitHub without a PNG.

For this report the **inline Mermaid is the canonical DDM** for every
procedure. Procedure A also ships an Arrows JSON export below as the worked
exemplar of the format; add JSON exports for B, C, and D when a procedure's
graph grows past what the inline Mermaid shows, or before an upstream
contribution that asks for the JSON.

| File | Procedure | Chokepoint node |
|------|-----------|-----------------|
| `trr9001_lin_a.json` | TRR9001.LIN.A — raw packet socket | `socket(AF_PACKET)` (shared with B) |
