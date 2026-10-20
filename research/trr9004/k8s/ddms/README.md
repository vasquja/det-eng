# Detection Data Models — TRR9004.K8S

One DDM per procedure. Each `*.json` file is the source: an
[Arrows app](https://arrows.app) graph in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.png` beside it is the picture the TRR shows, rendered from the JSON:

```sh
python3 research/tools/render_ddm.py research/trr9004/k8s/ddms/*.json
```

To edit a model, change the JSON (by hand, or import it into Arrows and export
it back), then render again. The TRR linter fails when a PNG is missing or older
than its JSON.

Colours: green = the client, blue = the API server, black = the abstract effect.
Shaded = a primary detection node. In the RBAC procedures (A–E, G) the shaded node
is the same one: the API server's audit of the RBAC write — the invariant
chokepoint. Procedure F is the exception: its shaded node is the API server's audit
of the `kube-system/aws-auth` ConfigMap write.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9004_k8s_a` | TRR9004.K8S.A — ClusterRoleBinding to a powerful ClusterRole | RBAC-write audit event (chokepoint, shared A–E, G) |
| `trr9004_k8s_b` | TRR9004.K8S.B — namespaced RoleBinding to a ClusterRole | RBAC-write audit event (chokepoint, shared A–E, G) |
| `trr9004_k8s_c` | TRR9004.K8S.C — write a wildcard or escalate/bind role | RBAC-write audit event; `rules` at Request level |
| `trr9004_k8s_d` | TRR9004.K8S.D — bind a built-in group (mass grant) | RBAC-write audit event; Group subject at Request level |
| `trr9004_k8s_e` | TRR9004.K8S.E — patch an existing binding or role | RBAC-write audit event (`verb: patch`) |
| `trr9004_k8s_f` | TRR9004.K8S.F — map an IAM principal through the EKS aws-auth ConfigMap | `configmaps` write to `kube-system/aws-auth` (chokepoint F) |
| `trr9004_k8s_g` | TRR9004.K8S.G — write a sensitive non-wildcard role | RBAC-write audit event; `rules` graded at Request level |
