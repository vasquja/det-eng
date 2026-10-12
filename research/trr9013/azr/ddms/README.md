# Detection Data Models — TRR9013.AZR

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9013/azr/ddms/*.json
```

Colours: green = the client/attacker, blue = the control plane (Entra audit log, Azure Activity
Log, or sign-in logs), black = the abstract effect. Shaded = a primary detection node.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9013_azr_a` | A — add a FIC to an app | Entra audit FIC-write event (chokepoint, A–B) |
| `trr9013_azr_b` | B — repoint an existing FIC | same chokepoint; oldValue→newValue change |
| `trr9013_azr_c` | C — FIC on a managed identity | Azure Activity Log .../federatedIdentityCredentials/write |
| `trr9013_azr_d` | D — use the backdoor | SP sign-in (federated flow); minting off-platform (gap) |
