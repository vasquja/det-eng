# Detection Data Models — TRR9006.K8S

One DDM per procedure. Each `*.json` file is the source: an
[Arrows app](https://arrows.app) graph in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.png` beside it is the picture the TRR shows, rendered from the JSON:

```sh
python3 research/tools/render_ddm.py research/trr9006/k8s/ddms/*.json
```

To edit a model, change the JSON (by hand, or import it into Arrows and export
it back), then render again. The TRR linter fails when a PNG is missing or older
than its JSON.

Colours: green = the client, blue = the API server, purple = the node (file
sensor), black = the abstract effect. Shaded = a primary detection node.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9006_k8s_a` | TRR9006.K8S.A — list Secrets | secret-read audit event (chokepoint, shared A–C) |
| `trr9006_k8s_b` | TRR9006.K8S.B — get a specific Secret | secret-read audit event (chokepoint, shared A–C) |
| `trr9006_k8s_c` | TRR9006.K8S.C — watch Secrets | secret-read audit event (chokepoint, shared A–C) |
| `trr9006_k8s_d` | TRR9006.K8S.D — mint a token (TokenRequest) | `serviceaccounts/token` create audit event (fallback) |
| `trr9006_k8s_e` | TRR9006.K8S.E — read a mounted token off disk | node file sensor; no audit event (the gap) |
