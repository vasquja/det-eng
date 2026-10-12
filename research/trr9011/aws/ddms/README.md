# Detection Data Models — TRR9011.AWS

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9011/aws/ddms/*.json
```

Colours: green = the client/attacker, blue = the AWS control plane (CloudTrail), purple = the
instance/host, black = the abstract effect. Shaded = a primary detection node (the
off-instance-use audit event is shared by A–D).

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9011_aws_a` | A — SSRF to IMDSv1, then off-instance use | off-instance-use CloudTrail event (chokepoint, A–D) |
| `trr9011_aws_b` | B — SSRF to IMDSv2, then off-instance use | same chokepoint; ec2RoleDelivery 2.0 |
| `trr9011_aws_c` | C — on-host IMDS read, then off-instance use | same chokepoint; host retrieval unlogged |
| `trr9011_aws_d` | D — retrieval via SSM, then off-instance use | same chokepoint; SendCommand also logged |
| `trr9011_aws_e` | E — off-instance use from another AWS account | AWS-owned source IP evades the public-IP rule (gap) |
