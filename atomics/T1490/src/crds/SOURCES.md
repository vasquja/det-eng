# Vendored CRD sources (TRR9029)

The TRR9029 emulation installs these CustomResourceDefinitions on a throwaway kind
cluster so it can create and delete inert snapshot and Velero objects. They are vendored
verbatim (not edited) from the upstream releases below. Each is Apache License 2.0.
Retrieved 2026-11-01 via `raw.githubusercontent.com`.

The emulation installs a CRD only when it is absent and removes on cleanup only the CRDs
it installed, so a real snapshot or Velero install is never modified.

## external-snapshotter v8.7.0 (Apache-2.0)

Repository: https://github.com/kubernetes-csi/external-snapshotter
License: https://github.com/kubernetes-csi/external-snapshotter/blob/v8.7.0/LICENSE
Path: `client/config/crd/`

| File | group/resource (v1) | SHA-256 |
|------|---------------------|---------|
| `snapshot.storage.k8s.io_volumesnapshots.yaml` | snapshot.storage.k8s.io/volumesnapshots (namespaced) | `b032116e987fb1d7d93cec7d942833adeb9d95c9bdc7e00c10b280c2fe4a6c33` |
| `snapshot.storage.k8s.io_volumesnapshotcontents.yaml` | snapshot.storage.k8s.io/volumesnapshotcontents (cluster) | `895a3c1e73b60f06a0deb566dd123d01bdf1b2efc5d5ff5231ff8bbcf42dafc7` |

## Velero v1.18.4 (Apache-2.0)

Repository: https://github.com/vmware-tanzu/velero
License: https://github.com/vmware-tanzu/velero/blob/v1.18.4/LICENSE
Path: `config/crd/v1/bases/`

| File | group/resource (v1) | SHA-256 |
|------|---------------------|---------|
| `velero.io_schedules.yaml` | velero.io/schedules (namespaced) | `d2276c19d93b63ed848fb492a0f34a2ac1e162938bed499a824acf356b5860c9` |
| `velero.io_backupstoragelocations.yaml` | velero.io/backupstoragelocations (namespaced) | `bd6e8fb1169d6e9299f49090f86cb9aa263a9e67314013ba231e93ba74485eba` |
| `velero.io_deletebackuprequests.yaml` | velero.io/deletebackuprequests (namespaced) | `c3e027086585c15a3b05b5596bcf3b6fed2dad9fdc8dea8cbcfb0abd5fc2ab50` |

Both projects are Apache License 2.0; the NOTICE/LICENSE of each is linked above. No CRD
file was modified; the group, resource, scope and version facts the rule keys on are taken
directly from these files.
