# Detection Data Models — TRR9026.K8S

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9026/k8s/ddms/*.json
```

Colours: green = the client, blue = the API server, purple = a node component,
black = the abstract effect. Shaded = a primary detection node. Procedures A and B
share the API server's audit of the `pods/portforward` request (the chokepoint,
verb-agnostic); Procedure C is the direct-kubelet gap, seen only by a node sensor.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9026_k8s_a` | TRR9026.K8S.A — port-forward over SPDY | `pods/portforward` audit event (`verb=create`) |
| `trr9026_k8s_b` | TRR9026.K8S.B — port-forward over WebSocket | `pods/portforward` audit event (`verb=get`) |
| `trr9026_k8s_c` | TRR9026.K8S.C — direct-kubelet tunnel | node sensor (no `pods/portforward` event — the gap) |
