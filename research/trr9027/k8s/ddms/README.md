# Detection Data Models — TRR9027.K8S

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9027/k8s/ddms/*.json
```

Colours: green = a client of the API server (the adversary's client, or the OpenShift
DNS Operator), blue = the API server, black = the abstract effect. Shaded = a primary
detection node. In every procedure the shaded node is the API server's audit of the
write to the cluster DNS configuration (the chokepoint): a DNS ConfigMap in kube-system
(A to D), the OpenShift ConfigMap openshift-dns/dns-default (E), or the OpenShift DNS
Operator object (F). The Corefiles of Procedures A, D and E are content-graded (Request
level or higher); B (kube-dns JSON) and C (coredns-custom import) are covered at the
chokepoint and triaged, and F is graded when the operator renders it into dns-default.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9027_k8s_a` | TRR9027.K8S.A — repoint the coredns Corefile | configmap-write audit event; poisoned `data.Corefile` grades it |
| `trr9027_k8s_b` | TRR9027.K8S.B — edit the kube-dns ConfigMap | configmap-write audit event (`name=kube-dns`; chokepoint) |
| `trr9027_k8s_c` | TRR9027.K8S.C — inject via coredns-custom | configmap-write audit event (`name=coredns-custom`; chokepoint) |
| `trr9027_k8s_d` | TRR9027.K8S.D — recreate the coredns ConfigMap | configmap-create audit event (`name=coredns`; Request by the kube-system create rule); created `data.Corefile` grades it |
| `trr9027_k8s_e` | TRR9027.K8S.E — edit the OpenShift dns-default ConfigMap | configmap-write audit event (`namespace=openshift-dns`, `name=dns-default`; chokepoint); `data.Corefile` grades it. CoreDNS reloads the edit; while the DNS object is Managed the operator reverts it (its update is filtered at the chokepoint) |
| `trr9027_k8s_f` | TRR9027.K8S.F — edit the OpenShift DNS Operator object | dnses-write audit event (`apiGroup=operator.openshift.io`; chokepoint at `Metadata`); the operator renders it into `dns-default`, which the grader reads |
