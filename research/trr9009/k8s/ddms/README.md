# Detection Data Models — TRR9009.K8S

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9009/k8s/ddms/*.json
```

Colours: green = the client, blue = the API server, black = the abstract effect.
Shaded = a primary detection node. In every procedure the shaded node is the same
one: the API server's audit of the impersonated request (`impersonatedUser`
present). There is no node sensor — impersonation is wholly API-server-internal.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9009_k8s_a` | TRR9009.K8S.A — impersonate a user | impersonated-request audit event (chokepoint, A–D) |
| `trr9009_k8s_b` | TRR9009.K8S.B — impersonate a group | impersonated-request audit event; groups at severity |
| `trr9009_k8s_c` | TRR9009.K8S.C — impersonate a service account | impersonated-request audit event; SA name |
| `trr9009_k8s_d` | TRR9009.K8S.D — impersonate a uid/extras | impersonated-request audit event; username always present |
