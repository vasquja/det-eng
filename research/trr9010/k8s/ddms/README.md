# Detection Data Models — TRR9010.K8S

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9010/k8s/ddms/*.json
```

Colours: green = the client, blue = the API server, purple = the node, black = the
abstract effect. Shaded = a primary detection node (the events-delete audit event is
shared by A–C).

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9010_k8s_a` | TRR9010.K8S.A — delete a single Event (core) | events-delete audit event (chokepoint, A–C) |
| `trr9010_k8s_b` | TRR9010.K8S.B — bulk-wipe Events | events-delete audit event (`deletecollection`, no name) |
| `trr9010_k8s_c` | TRR9010.K8S.C — delete an Event (events.k8s.io) | events-delete audit event (apiGroup-agnostic) |
| `trr9010_k8s_d` | TRR9010.K8S.D — delete a Pod or Job | pod/job-delete audit event (fallback) |
| `trr9010_k8s_e` | TRR9010.K8S.E — clear the audit log on the node | node file sensor; no audit event (the gap) |
| `trr9010_k8s_f` | TRR9010.K8S.F — delete a whole namespace | namespace-delete audit event (hunting) |
