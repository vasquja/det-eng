# Detection Data Models — TRR9005.K8S

One DDM per procedure. Each `*.json` file is the source: an
[Arrows app](https://arrows.app) graph in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.png` beside it is the picture the TRR shows, rendered from the JSON:

```sh
python3 research/tools/render_ddm.py research/trr9005/k8s/ddms/*.json
```

To edit a model, change the JSON (by hand, or import it into Arrows and export
it back), then render again. The TRR linter fails when a PNG is missing or older
than its JSON.

Colours: green = the client, blue = the API server, purple = the node (container
runtime), black = the abstract effect. Shaded = a primary detection node. In
every procedure the shaded node is the same one: the API server's audit of the
batch write — the invariant chokepoint.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9005_k8s_a` | TRR9005.K8S.A — create a CronJob | batch-write audit event (chokepoint, shared A–D) |
| `trr9005_k8s_b` | TRR9005.K8S.B — create a one-shot Job | batch-write audit event; Pod sandbox label on the node |
| `trr9005_k8s_c` | TRR9005.K8S.C — privileged/host-mounting batch object | batch-write audit event; template at Request level |
| `trr9005_k8s_d` | TRR9005.K8S.D — modify an existing CronJob/Job | batch-write audit event (`verb: patch`) |
