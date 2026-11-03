# Detection Data Models — TRR9034.K8S

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9034/k8s/ddms/*.json
```

Colours: green = a client of the API server (the adversary's client, or the replicaset
controller), blue = the API server, black = the abstract effect. Shaded = a primary
detection node. In every procedure the shaded node is the API server's admission-and-audit
of the workload write, which carries the server-computed ValidatingAdmissionPolicy
verdict: the `validation.policy.admission.k8s.io/validation_failure` event annotation for
an Audit binding (A, C) or the `denied request` responseStatus message for a Deny binding
(B). The marker is the chokepoint; the rule keys on it, not on the attacker-chosen image
string.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| `trr9034_k8s_a` | TRR9034.K8S.A — pod the Audit binding flags | workload-create audit event with the `validation_failure` annotation (admitted) |
| `trr9034_k8s_b` | TRR9034.K8S.B — pod the Deny binding flags | workload-create audit event with the `ValidatingAdmissionPolicy '...' denied request` responseStatus (422 Invalid) |
| `trr9034_k8s_c` | TRR9034.K8S.C — Deployment whose controller pod the Audit binding flags | the replicaset controller's own pods-create audit event with the annotation (controllers not filtered) |
