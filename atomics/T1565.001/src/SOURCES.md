# Third-party sources — atomics/T1565.001/src

The TRR9027 Procedure F emulation installs the OpenShift DNS Operator CRD on a `kind`
cluster, which has no such CRD. The file is copied from its upstream source without a
change. Do not edit it here: copy a new version from the source and update this table.

| File | Source (pinned commit) | Retrieved | License | SHA-256 |
|------|------------------------|-----------|---------|---------|
| `openshift-dnses.crd.yaml` | [openshift/api `operator/v1/zz_generated.crd-manifests/0000_70_dns_00_dnses.crd.yaml`](https://raw.githubusercontent.com/openshift/api/b32f49f8a70985c6ad9abb2dc579abc18d143051/operator/v1/zz_generated.crd-manifests/0000_70_dns_00_dnses.crd.yaml) at `b32f49f8a70985c6ad9abb2dc579abc18d143051` (branch `release-4.20`) | 2026-10-23 | Apache License 2.0 | `01ff5f27892955d3269ed823f9ecb3fd15ccfde96b28fff0ff7cd062cb15e373` |
| `LICENSE.openshift-api` | [openshift/api `LICENSE`](https://raw.githubusercontent.com/openshift/api/b32f49f8a70985c6ad9abb2dc579abc18d143051/LICENSE) at the same commit | 2026-10-23 | Apache License 2.0 (the license text) | `ea81dcff98532f22802f03eb0ad532407b9122c4c76aae32cbd58442485f3885` |

The CRD file holds no copyright or notice header, and openshift/api has no `NOTICE`
file at that commit (HTTP 404), so `LICENSE.openshift-api` is the only notice to keep
(Apache License 2.0, section 4(a)).

## Derived text (not a copy)

`emulate.sh` holds `OCP_DEFAULT_COREFILE`, the Corefile that the OpenShift DNS
Operator renders for a DNS object with an empty spec. It is the output of the
`corefileTemplate` in
[openshift/cluster-dns-operator `pkg/operator/controller/controller_dns_configmap.go`](https://raw.githubusercontent.com/openshift/cluster-dns-operator/82578923164636746e0d74d594ab32d83a660c0b/pkg/operator/controller/controller_dns_configmap.go)
at `82578923164636746e0d74d594ab32d83a660c0b` (branch `release-4.20`, Apache License
2.0), rendered with Go `text/template` (cluster domain `cluster.local`, upstream
`/etc/resolv.conf` with policy sequential, log class `error`, lameduck `20s`, cache
900 and 30, the DNSNameResolver plugin off). It equals the root block and the
`hostname.bind` block of that commit's
`pkg/operator/controller/testdata/without_upstreamresolvers`. SHA-256 of the
rendered text (26 lines, with the final line break):
`ca1b5b5a82c21ab466f45b2dcea2528608a00979fd380f33574bee6be74a9adf`. The OpenShift
sidecar cases in `detections/sigma/T1565.001/` use the same rendering.
