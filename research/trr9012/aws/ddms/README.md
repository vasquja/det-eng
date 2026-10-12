# Detection Data Models — TRR9012.AWS

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9012/aws/ddms/*.json
```

Colours: green = the attacker, blue = the AWS control plane (CloudTrail), black = the abstract
effect. Shaded = a primary detection node.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9012_aws_a` | A — direct API use + enumeration | IAMUser+AKIA-from-new-source CloudTrail event (chokepoint) |
| `trr9012_aws_b` | B — data-plane recon | data-event record (off by default; gap) |
| `trr9012_aws_c` | C — STS pivot | the pivot call (IAMUser+AKIA, caught); downstream ASIA evades |
