# Detection Data Models — TRR9003.K8S

One DDM per procedure. Each `*.json` file is the source: an
[Arrows app](https://arrows.app) graph in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.png` beside it is the picture the TRR shows, rendered from the JSON:

```sh
python3 research/tools/render_ddm.py research/trr9003/k8s/ddms/*.json
```

To edit a model, change the JSON (by hand, or import it into Arrows and export
it back), then render again. The TRR linter fails when a PNG is missing or
older than its JSON.

Colours: green = the attacker on the node, blue = the API server, purple = the
node (kubelet and container runtime). Shaded = a primary detection node.

Both procedures converge on the same shaded node — *Start Pod via CRI* — where
the kubelet runs a pod the API server never scheduled (`config.source` is
`file` or `http`, never `api`). That node is the invariant chokepoint. A node
runtime sensor sees it; the API server audit log cannot, because the control
plane is not in this path.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9003_k8s_a` | TRR9003.K8S.A — drop a manifest in the static-pod directory | `Start Pod via CRI` (chokepoint, shared with B) |
| `trr9003_k8s_b` | TRR9003.K8S.B — reconfigure the kubelet static source | `Start Pod via CRI` (chokepoint, shared with A) |

The *Create Mirror Pod* node (blue) is the one audit-log opportunity: the
kubelet registers a mirror pod as `system:node:<node>`. It is a fallback, not
the anchor — an attacker suppresses it by naming an invalid namespace, and the
control-plane components produce the same event at every kubelet start.
