# Provider audit policies: sources, licenses and digests

These files are copies of the Kubernetes audit policies that managed platforms
publish. [`detections/k8s_policy_coverage.py`](../../k8s_policy_coverage.py) reads
them, together with the lab policies in [`detections/k8s/`](..), to compute which
Kubernetes rule still fires on which platform. Its result is
[`detections/k8s/policy_coverage.json`](../policy_coverage.json).

Nine of the ten files are the policy text exactly as the source holds it, with no
header and no edit: the six OpenShift files are the whole upstream file, and the
EKS, AKS and k3s files are the YAML block of a documentation page, byte for byte.
The GCE kube-up file is the one changed extract: the policy that a shell function
writes, with one variable expanded, below a comment header that keeps the source's
copyright and license notice and states the change (Apache-2.0 sections 4(b) and
4(c)); its row gives the digest of the policy text after that header too. So you
can compare each copy with its source again (`--verify-sources` below). The
script's self-test (`--self-test`) recomputes every digest and fails if a file
changed or if this page does not list it.

All texts were retrieved on **2026-10-23**.

## Read this first

- A published policy is what the provider says it runs. It is **not** a capture.
  Whether a provider runs the text unchanged on every version is **unverified**
  for every provider here (no live capture; backlog issue #55). The `status`
  field of each policy in `policy_coverage.json` says what is known.
- The simulator models the audit policy only. It does not model the provider's
  log pipeline (field names, tables, size limits, a log category's own filter
  other than the one AKS documents). Those are in the provider pipelines and the
  mapping harness.
- Where a policy keeps the RequestReceived stage (no `omitStages:
  [RequestReceived]` on the matching rule or the policy), one request writes two
  records: RequestReceived and ResponseComplete. A rule that reads only request
  metadata fires on both, so it alerts twice for one request. The simulator writes
  both records. This is so under the k3s starter policy (every request), the AKS
  policy (its Events create, update, patch, delete and list rules) and the EKS
  policy (its `serviceaccounts/token` rule). Deduplicate by `auditID`, or filter on
  `stage`.
- The EKS text says `apiVersion: audit.k8s.io/v1beta1`. The v1.36 API server loads
  only `audit.k8s.io/v1`, so EKS cannot run this exact file on a current version.
  The simulator evaluates its rules as v1 and prints a warning.
- The OpenShift WriteRequestBodies rules (4.18 and later) hold a group entry with
  the key `resource` (not `resources`). The library-go loader (`yaml.Unmarshal`)
  and the API server's lenient decoding drop an unknown key, so that entry
  matches every resource of `machineconfiguration.openshift.io`. The simulator
  does the same and prints a warning. No rule here reads that group.

## Refresh

```bash
python3 detections/k8s_policy_coverage.py --verify-sources   # fetch and compare
python3 detections/k8s_policy_coverage.py --write-sources    # fetch and rewrite
```

`--verify-sources` needs the network and is not run in CI. When a source changes,
rewrite the copy, put the new digests in the `SOURCES` table of the script and on
this page (for the GCE kube-up file, also the digest of the policy text after its
header), then run `--self-test` and `--update`. A refresh is a human decision:
it changes what the platform columns say.

## Files

### Amazon EKS

| | |
|---|---|
| File | [`eks/eks-bpg-audit-policy.yaml`](eks/eks-bpg-audit-policy.yaml) |
| Source | <https://raw.githubusercontent.com/aws/aws-eks-best-practices/master/latest/bpg/security/detective.adoc> (the `[source,yaml]` block after "The audit policy for EKS is as follows:", lines 20-178). The guide is also published at <https://docs.aws.amazon.com/eks/latest/best-practices/auditing-and-logging.html>; the repository README says the repository is still its source. |
| Upstream file SHA-256 | `8c59ba4b9e847f04568d122eaddb673de50fa43327421d7cc57f7507c2880568` |
| Vendored file SHA-256 | `858a452342a050cf6e7539b60c9a371af665a177d1b0526f7c1c2bf797247319` |
| License | The repository README: "The documentation is made available under the Creative Commons Attribution-ShareAlike 4.0 International License" and "The sample code within this documentation is made available under the MIT-0 license." The policy is a code sample in the guide, so MIT-0 applies ([`LICENSES/MIT-0-aws-eks-best-practices.txt`](LICENSES/MIT-0-aws-eks-best-practices.txt), "Copyright 2019 Amazon.com, Inc. or its affiliates"). If it is read as documentation, CC BY-SA 4.0 (<https://creativecommons.org/licenses/by-sa/4.0/>) also permits this verbatim copy with this attribution: "Amazon EKS Best Practices Guide, Auditing and logging, by Amazon Web Services, CC BY-SA 4.0; copied without change." |
| EKS user guide | The EKS user guide page "Send control plane logs to CloudWatch Logs", <https://raw.githubusercontent.com/awsdocs/amazon-eks-user-guide/mainline/latest/ug/observability/control-plane-logs.adoc> (SHA-256 `df1d9a3aae813846dc859d00d79de842ef77e18a71fbba031d2f60fc3168449a`, retrieved 2026-10-24; the repository README says it is the open-source version of <https://docs.aws.amazon.com/eks/latest/userguide/>), line 29, under the API server log type: "For more information, see [kube-apiserver] and the [audit policy] in the Kubernetes documentation". Its "audit policy" link points to `cluster/gce/gci/configure-helper.sh#L1129-L1255` on kubernetes `master`, the policy of the `gce-kube-up` column. The user guide does not publish a policy of its own and does not say that EKS runs that text unchanged. The Best Practices Guide text above is a variant of it: it adds `aws-auth` writes at RequestResponse and `serviceaccounts/token` at Request, and leaves out a few kube-up identities. The simulator gives the same result for the two texts on every sidecar case of this repository (only `not_modeled` counts differ). This page is cited, not copied (CC BY-SA 4.0). |

### GCE kube-up (the policy the EKS user guide links and the GKE audit-policy page names)

| | |
|---|---|
| File | [`gce/gce-kube-up-audit-policy.yaml`](gce/gce-kube-up-audit-policy.yaml) |
| Source | <https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.4/cluster/gce/gci/configure-helper.sh>, function `create-master-audit-policy` (lines 1131-1291): the here-document written when no custom policy is given, with `${known_apis}` expanded as bash expands it. |
| Changes | This file is a changed extract, not a copy. Its first 21 lines are a YAML comment header: the source file's copyright and license notice (lines 3-15 of the script), then a change notice. The text after the header equals the output of the function, run with bash on the retrieved script. |
| Upstream file SHA-256 | `ffe7ab144be24f2490b050e3e23ba3f3bd3185796b0e0ec42a5aeb40f135d1ab` |
| Vendored file SHA-256 | `dbbba87c7a53483b5ce06310122c8008b5eb39d1e78507c95da27bd3b8932fb1` (with the header) |
| Policy text SHA-256 | `09063bc7e2fcd0f3065fe694cbb124b7998d53e0863ad67565c58227cd608121` (the file after the header: the bytes the function writes) |
| License | Apache License 2.0 ([`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt), the kubernetes/kubernetes `LICENSE` file, SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`). Notice of the source file, kept in the file's header: "Copyright 2016 The Kubernetes Authors. Licensed under the Apache License, Version 2.0." |
| GKE | The GKE page "Audit policy" (<https://cloud.google.com/kubernetes-engine/docs/concepts/audit-policy>) says that GKE supplies the API server with a policy file through `--audit-policy-file`, and that the `configure-helper.sh` script in the open-source repository generates that file. The page was not reachable from the build host (a search result quoted it), so whether GKE runs this exact text is **unverified**. GKE also routes entries to its Admin Activity or Data Access log by its own GKE audit policy; the simulator does not model that split. |

### Azure AKS

| | |
|---|---|
| File | [`aks/aks-audit-policy.yaml`](aks/aks-audit-policy.yaml) |
| Source | <https://raw.githubusercontent.com/MicrosoftDocs/azure-aks-docs/main/articles/aks/monitor-aks.md> (`ms.date: 08/18/2026`), the YAML block under "View the complete AKS audit policy" (lines 181-414). Published as <https://learn.microsoft.com/azure/aks/monitor-aks>. The page says: "The audit policy is managed by AKS and can't be customized." |
| Upstream file SHA-256 | `1bf68ed7418379f98f47f4c3c907323c403e8a0f0e8e5df018dfdacdf7eea3f6` |
| Vendored file SHA-256 | `0b243c3ad50ed4789a4b30bef8e2c361e58e310542bd819134ae58510b18763f` |
| License | The MicrosoftDocs/azure-aks-docs repository licenses code under MIT ([`LICENSES/MIT-azure-aks-docs.txt`](LICENSES/MIT-azure-aks-docs.txt), "Copyright (c) Microsoft Corporation", the repository's `LICENSE-CODE`) and documentation under CC BY 4.0 (<https://creativecommons.org/licenses/by/4.0/>, the repository's `LICENSE`). Attribution: "Monitor Azure Kubernetes Service (AKS), Microsoft Learn, by Microsoft; copied without change." |
| Log category | The same page: "Enable collection from `kube-audit-admin`, which excludes the `get` and `list` audit events." The `aks-kube-audit-admin` column drops those two verbs after the policy. Whether that category also drops `watch` is **unverified**. |

### Red Hat OpenShift

The OpenShift kube-apiserver operator builds the policy from library-go's base
policy, then the rules of the chosen profile (`GetAuditPolicy` in
<https://github.com/openshift/library-go/blob/master/pkg/operator/apiserver/audit/audit_policies.go>).
The cluster-kube-apiserver-operator branches `release-4.17` and `release-4.18`
vendor the same files as the library-go branches of the same name (compared on the
retrieval date). Default is the default profile; WriteRequestBodies is a choice of
the cluster admin.

| File | Source | SHA-256 (upstream file = vendored file) |
|---|---|---|
| [`openshift/base-policy-release-4.18.yaml`](openshift/base-policy-release-4.18.yaml) | <https://raw.githubusercontent.com/openshift/library-go/release-4.18/pkg/operator/apiserver/audit/manifests/base-policy.yaml> (`release-4.19`, `release-4.20`, `release-4.21` and `master` hold the same text) | `964c47ab88c0f23effad73a4dad5514aba7cf77575db0a23e8614c983cfd695b` |
| [`openshift/base-policy-release-4.17.yaml`](openshift/base-policy-release-4.17.yaml) | <https://raw.githubusercontent.com/openshift/library-go/release-4.17/pkg/operator/apiserver/audit/manifests/base-policy.yaml> (its first rule logs core-group Events at None; `release-4.14` to `release-4.16` hold the same rules without the `/livez` URL) | `94042b757e4730846c71e828622f67a75ad6d1bf94e0a88a36cdea2ea307180b` |
| [`openshift/default-rules-release-4.18.yaml`](openshift/default-rules-release-4.18.yaml) | <https://raw.githubusercontent.com/openshift/library-go/release-4.18/pkg/operator/apiserver/audit/manifests/default-rules.yaml> | `933d827a8d48bda129c7bae53436f6351dad63dc64699d64be7962bcae20c33c` |
| [`openshift/default-rules-release-4.17.yaml`](openshift/default-rules-release-4.17.yaml) | <https://raw.githubusercontent.com/openshift/library-go/release-4.17/pkg/operator/apiserver/audit/manifests/default-rules.yaml> | `933d827a8d48bda129c7bae53436f6351dad63dc64699d64be7962bcae20c33c` |
| [`openshift/writerequestbodies-rules-release-4.18.yaml`](openshift/writerequestbodies-rules-release-4.18.yaml) | <https://raw.githubusercontent.com/openshift/library-go/release-4.18/pkg/operator/apiserver/audit/manifests/writerequestbodies-rules.yaml> | `d3d6f45bc459bd1364286cc95619b96d648881d1af6d24b5544993ec798f6832` |
| [`openshift/writerequestbodies-rules-release-4.17.yaml`](openshift/writerequestbodies-rules-release-4.17.yaml) | <https://raw.githubusercontent.com/openshift/library-go/release-4.17/pkg/operator/apiserver/audit/manifests/writerequestbodies-rules.yaml> | `7dde3830fa3ac32d94fb700d61e3d6693d011b5fb3673e5fc4101a4de8a968f1` |

License: Apache License 2.0 ([`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt);
the openshift/library-go `LICENSE` file is the same text without its first blank
line, SHA-256 `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`).
The files carry no notice of their own; they are copied without change.

### k3s

| | |
|---|---|
| File | [`k3s/k3s-hardening-starter-audit-policy.yaml`](k3s/k3s-hardening-starter-audit-policy.yaml) |
| Source | <https://raw.githubusercontent.com/k3s-io/docs/main/docs/security/hardening-guide.md>, the YAML block after "A starter audit policy to log request metadata is provided below." The same guide says: "K3s doesn't enable auditing by default, so audit log configuration and audit policy must be created manually." |
| Upstream file SHA-256 | `a0818e611091201f5313d768ff3672b2f101435647ca7ca839bbc7afa2714fab` |
| Vendored file SHA-256 | `4c24658bceb8766ff68ad3fce45906665c140cdf35b0468c10123e2dcdaebd48` |
| License | The k3s-io/docs `LICENSE` says "K3s Docs is licensed under a Creative Commons Attribution 4.0 International License" (its link points to the BY-SA 4.0 page; both permit a verbatim copy with attribution). Attribution: "K3s CIS Hardening Guide, by the k3s-io contributors, CC BY 4.0 (<https://creativecommons.org/licenses/by/4.0/>); copied without change." The policy is four lines: one catch-all rule at Metadata. |

## Licence texts in this directory

| File | Source | SHA-256 |
|---|---|---|
| [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt) | <https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.4/LICENSE> | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| [`LICENSES/MIT-azure-aks-docs.txt`](LICENSES/MIT-azure-aks-docs.txt) | <https://raw.githubusercontent.com/MicrosoftDocs/azure-aks-docs/main/LICENSE-CODE> | `91f7258203fd43ba6d6f7f72b644eaedee9e3430f035c053beb6f34052f045e2` |
| [`LICENSES/MIT-0-aws-eks-best-practices.txt`](LICENSES/MIT-0-aws-eks-best-practices.txt) | <https://raw.githubusercontent.com/aws/aws-eks-best-practices/master/LICENSE-SAMPLECODE> | `ddf9b5d9dd2fded18653e0ca4c5934008d4faea1161d754493b54a23c25eac14` |

The decision to vendor these texts (rather than keep only a URL and a digest) is a
human decision recorded in the pull request.
