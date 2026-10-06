# Detection Data Models — TRR9002.K8S

Each `*.json` file is an [Arrows app](https://arrows.app) export of one
procedure's DDM. To edit a model, open Arrows, import the JSON, change the
graph, then export the JSON back here. Export a PNG beside the JSON (same base
name, `.png`) for the TRR and for the upstream pull request.

The TRR README also shows each DDM as an inline Mermaid diagram, so the graphs
show on GitHub without a PNG.

For this report the **inline Mermaid is the canonical DDM** for every
procedure. Procedure A also has an Arrows JSON export, because it holds the
chokepoint. Add JSON exports for B to E before an upstream contribution that
asks for them.

| File | Procedure | Chokepoint node |
|------|-----------|-----------------|
| `trr9002_k8s_a.json` | TRR9002.K8S.A — exec through the API server | `pods/exec` audit event (shared with B and the attach step of C) |
