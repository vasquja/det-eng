# Detection Data Models — TRR9007.K8S

One DDM per procedure. Each `*.json` file is the source: an
[Arrows app](https://arrows.app) graph in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.png` beside it is the picture the TRR shows, rendered from the JSON:

```sh
python3 research/tools/render_ddm.py research/trr9007/k8s/ddms/*.json
```

To edit a model, change the JSON (by hand, or import it into Arrows and export
it back), then render again. The TRR linter fails when a PNG is missing or older
than its JSON.

Colours: green = the client, blue = the API server, purple = the node (container
runtime), black = the abstract effect. Shaded = a primary detection node. In
every procedure the shaded node is the same one: the API server's admission audit
of the pod spec at Request level. Procedures A–D share the host-access chokepoint on
that event. Procedure E is read from the same audit event by its own medium rule
(the host-access rules do not fire on a profile of type `Unconfined`).

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9007_k8s_a` | TRR9007.K8S.A — privileged container | pod-spec admission audit event (chokepoint, shared A–D) |
| `trr9007_k8s_b` | TRR9007.K8S.B — hostPath mount | pod-spec admission audit event; `volumes` has `hostPath` |
| `trr9007_k8s_c` | TRR9007.K8S.C — host namespace | pod-spec admission audit event; `hostPID`/etc boolean |
| `trr9007_k8s_d` | TRR9007.K8S.D — dangerous capabilities | pod-spec admission audit event; capability in `containers` |
| `trr9007_k8s_e` | TRR9007.K8S.E — seccomp or AppArmor `Unconfined` | pod-spec admission audit event; a profile of type `Unconfined` (graded by the medium confinement rule) |
