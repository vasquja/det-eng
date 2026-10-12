# Detection Data Models — TRR9014.GCP

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9014/gcp/ddms/*.json
```

Colours: green = the attacker, blue = the GCP control plane (Cloud Audit Logs), black = the
abstract effect. Shaded = a primary detection node.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9014_gcp_a` | A — public grant via the delta path | Admin Activity policyDelta ADD of a public member (chokepoint) |
| `trr9014_gcp_b` | B — public grant via the request path | Admin Activity request.policy.bindings public member (chokepoint) |
| `trr9014_gcp_c` | C — exposure without an IAM binding | no setIamPolicy event; Data Access logs off (gap) |
