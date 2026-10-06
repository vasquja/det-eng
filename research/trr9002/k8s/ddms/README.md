# Detection Data Models — TRR9002.K8S

One DDM per procedure. Each `*.json` file is the source: an
[Arrows app](https://arrows.app) graph in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.png` beside it is the picture the TRR shows, rendered from the JSON:

```sh
python3 research/tools/render_ddm.py research/trr9002/k8s/ddms/*.json
```

To edit a model, change the JSON (by hand, or import it into Arrows and export
it back), then render again. The TRR linter fails when a PNG is missing or
older than its JSON.

Colours: green = the client, blue = the API server, purple = the node (kubelet
and container runtime). Shaded = a primary detection node.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9002_k8s_a` | TRR9002.K8S.A — exec through the API server | `pods/exec` audit event (chokepoint, shared with B) |
| `trr9002_k8s_b` | TRR9002.K8S.B — attach through the API server | `pods/attach` audit event (chokepoint, shared with A) |
| `trr9002_k8s_c` | TRR9002.K8S.C — ephemeral debug container | `pods/ephemeralcontainers` audit event |
| `trr9002_k8s_d` | TRR9002.K8S.D — exec through `nodes/proxy` | `nodes/proxy` audit event with an exec path |
| `trr9002_k8s_e` | TRR9002.K8S.E — exec through the kubelet API | network flow to TCP 10250 and the new container process |
