# Detection Data Models — TRR9038.GCP

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9038/gcp/ddms/*.json
```

Colours: green = the attacker, blue = the GCP control plane (Cloud Audit Logs,
Admin Activity), black = the abstract effect. Shaded = the primary detection node
(the ConfigServiceV2 write chokepoint).

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9038_gcp_a` | A — delete or disable the _Default sink | Admin Activity ConfigServiceV2 DeleteSink/UpdateSink on `.../sinks/_Default` (chokepoint) |
| `trr9038_gcp_b` | B — delete a log bucket | Admin Activity ConfigServiceV2 DeleteBucket/UpdateBucket on `.../buckets/_Default` (chokepoint) |
| `trr9038_gcp_c` | C — add an audit-dropping exclusion | Admin Activity ConfigServiceV2 CreateExclusion/UpdateExclusion (chokepoint; filter content is an approximation) |
