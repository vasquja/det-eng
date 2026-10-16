# Detection Data Models — TRR9027.K8S

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9027/k8s/ddms/*.json
```

Colours: green = the client, blue = the API server, black = the abstract effect.
Shaded = a primary detection node. In every procedure the shaded node is the same
one: the API server's audit of the DNS-ConfigMap write in kube-system (the
chokepoint). The Corefiles of Procedures A and D are content-graded (Request level or
higher); B (kube-dns JSON) and C (coredns-custom import) are covered at the chokepoint
and triaged.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9027_k8s_a` | TRR9027.K8S.A — repoint the coredns Corefile | configmap-write audit event; poisoned `data.Corefile` grades it |
| `trr9027_k8s_b` | TRR9027.K8S.B — edit the kube-dns ConfigMap | configmap-write audit event (`name=kube-dns`; chokepoint) |
| `trr9027_k8s_c` | TRR9027.K8S.C — inject via coredns-custom | configmap-write audit event (`name=coredns-custom`; chokepoint) |
| `trr9027_k8s_d` | TRR9027.K8S.D — recreate the coredns ConfigMap | configmap-create audit event (`name=coredns`; Request by the kube-system create rule); created `data.Corefile` grades it |
