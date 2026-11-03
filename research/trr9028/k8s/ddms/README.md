# Detection Data Models — TRR9028.K8S

One DDM per procedure, in the style of the
[tired-labs/techniques](https://github.com/tired-labs/techniques) DDMs. Each
`*.json` is the source; each `*.png` is rendered from it:

```sh
python3 research/tools/render_ddm.py research/trr9028/k8s/ddms/*.json
```

Colours: green = the adversary's client of the API server, blue = the API server
(authorize + audit), black = the abstract effect. Shaded = a primary detection node.
In Procedures A, B and C the shaded node is the API server's audit of the
delete/deletecollection of a PersistentVolumeClaim or PersistentVolume (the
chokepoint `k8s_storage_volume_deleted`). In Procedure D it is the audit of the PV
patch that sets the reclaim policy to Delete (the grader
`k8s_volume_reclaim_set_to_delete`), the step that makes a later delete destructive.

| File | Procedure | Primary detection node |
|------|-----------|------------------------|
| [`trr9028_k8s_a.json`](trr9028_k8s_a.json) | A | delete a bound PVC |
| [`trr9028_k8s_b.json`](trr9028_k8s_b.json) | B | delete a PV |
| [`trr9028_k8s_c.json`](trr9028_k8s_c.json) | C | deletecollection of a namespace's PVCs |
| [`trr9028_k8s_d.json`](trr9028_k8s_d.json) | D | patch a PV reclaim policy to Delete |
