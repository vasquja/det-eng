# Detection Data Models — TRR9008.K8S

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9008/k8s/ddms/*.json
```

Colours: green = the client, blue = the API server, purple = the node, black = the
abstract effect. Shaded = a primary detection node (the admission-write audit event
is shared by A–C).

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9008_k8s_a` | TRR9008.K8S.A — delete a ValidatingWebhookConfiguration | admission-write audit event (chokepoint, A–C) |
| `trr9008_k8s_b` | TRR9008.K8S.B — delete a MutatingWebhookConfiguration | admission-write audit event (chokepoint, A–C) |
| `trr9008_k8s_c` | TRR9008.K8S.C — neuter a webhook config | admission-write audit event; failurePolicy/rules at Request |
| `trr9008_k8s_d` | TRR9008.K8S.D — remove the enforcer workload | apps-write audit event (alert in the engines' default namespaces; anchor in any namespace) and the engine-namespace delete; node sensor |
