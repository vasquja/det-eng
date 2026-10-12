# Detection Data Models — TRR9015.AWS

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9015/aws/ddms/*.json
```

Colours: green = the client/attacker, blue = the AWS control plane (CloudTrail), black = the
abstract effect. Shaded = a primary detection node (the trust-policy write is shared by A–C).

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9015_aws_a` | A — over-broad sub grant (wildcard) | IAM trust-policy write (chokepoint, A–C) |
| `trr9015_aws_b` | B — missing-condition grant | same chokepoint; absent sub condition |
| `trr9015_aws_c` | C — create-time grant | same chokepoint; iam:CreateRole / assumeRolePolicyDocument |
| `trr9015_aws_d` | D — create the OIDC provider | iam:CreateOpenIDConnectProvider (precursor) |
| `trr9015_aws_e` | E — use of the federated trust | sts:AssumeRoleWithWebIdentity; needs a per-role sub allowlist |
