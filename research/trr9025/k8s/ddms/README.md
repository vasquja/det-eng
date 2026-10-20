# Detection Data Models — TRR9025.K8S

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9025/k8s/ddms/*.json
```

Colours: green = the client, blue = the API server, black = the abstract effect.
Shaded = a primary detection node. In every procedure the shaded node is the same
one: the API server's audit of the admissionregistration create (the chokepoint).
Procedures A and B are graded from the webhook body at Request level; C (a CEL
policy) is covered at the chokepoint only.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9025_k8s_a` | TRR9025.K8S.A — mutating webhook backdoor | create audit event; any `clientConfig.url` (URL mode, normally off-cluster) grades it |
| `trr9025_k8s_b` | TRR9025.K8S.B — validating webhook Secret exfiltration | create audit event; any `clientConfig.url` grades it; the `secrets` scope is not graded |
| `trr9025_k8s_c` | TRR9025.K8S.C — CEL admission policy | create audit event (chokepoint only; not graded) |
