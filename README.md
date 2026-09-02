# kube-upgrade-check

Find what breaks before you upgrade Kubernetes.

Point it at a cluster and it tells you what an upgrade to a given version would break: removed
APIs still in use, control-plane and kubelet settings the new version refuses to start with,
in-tree volume plugins that stop mounting, node-level changes, and whether the add-ons you run
support the version you are moving to.

It reads your cluster and writes nothing. No account, no agent, no data leaves the machine.

```console
$ kube-upgrade-check --target 1.34

  prod-eu (v1.33.13-eks-a1b2c3, EKS, 6 nodes)
  upgrade to 1.34   risk 81/100 CRITICAL

  BREAKS (2)
    CRIT  kube-system/exempt — FlowSchema flowcontrol.apiserver.k8s.io/v1beta3 was removed in 1.32
          rtz-k8s-dep-flowcontrol-v1beta3-flowschema
          helm last wrote this at flowcontrol.apiserver.k8s.io/v1beta3 on 2024-03-02.
          Move these objects to flowcontrol.apiserver.k8s.io/v1 before upgrading.

    HIGH  Deployment/karpenter/karpenter — Karpenter 1.0.5 does not support Kubernetes 1.34
          rtz-addon-karpenter-support
          The vendor's table gives Karpenter 1.0.5 a ceiling of Kubernetes 1.31. Upgrade
          Karpenter to at least 1.0.6 before upgrading Kubernetes.

  ADD-ONS (3 detected)
    !! Karpenter 1.0.5       does not support the target (vendor ceiling: Kubernetes 1.31) —
                             upgrade to at least 1.0.6
    ok cert-manager v1.19.1  supported
    ?? CoreDNS 1.11.1        the vendor publishes no compatibility matrix, so this could not
                             be checked

  COULD NOT SEE (1)
    - control-plane flags — 276 rules not checked
      no static control-plane pods were found. This is normal on a managed control plane
      (EKS, GKE, AKS), and on distributions such as k3s that run the control plane as a
      single process rather than as pods. Either way its flags cannot be read through the API
      check: kubectl get pods -n kube-system -l tier=control-plane -o yaml

  Standard support for 1.33 ends 2026-11-23 (82 days). Staying past standard support costs
  about $5256 per cluster per year.
```

## Install

```bash
brew install runtimez-com/tap/kube-upgrade-check
```

```bash
curl -fsSL https://raw.githubusercontent.com/runtimez-com/kube-upgrade-check/main/install.sh | sh
```

Windows: `scoop bucket add runtimez https://github.com/runtimez-com/scoop-bucket && scoop install kube-upgrade-check`

Binaries cover macOS, Linux and Windows on amd64 and arm64. Debian, RPM and Alpine packages are
attached to each release, and the checksum file is signed. Building from source: `make build`.

## Use

```bash
kube-upgrade-check                     # current context, one minor up
kube-upgrade-check --target 1.35       # a specific target
kube-upgrade-check --context staging   # a specific kubeconfig context
kube-upgrade-check -o json | jq .      # machine-readable
```

In CI, gate on severity:

```bash
kube-upgrade-check --target 1.34 --fail-on high
```

Exit codes are a contract:

| Code | Meaning |
| --- | --- |
| 0 | The scan ran and nothing reached the threshold |
| 1 | The scan itself failed |
| 2 | The command line was wrong |
| 3 | The cluster refused the credentials |
| 4 | Findings reached `--fail-on`, or `--strict` was set and something could not be checked |

An unknown `--fail-on` value is rejected rather than ignored. A typo that quietly parsed as
"never fail" would turn a gate into a no-op that reports success forever.

## What it checks

| Family | What it finds | Rules |
| --- | --- | --- |
| Removed APIs | Objects still written at an API version the target removes | 97 |
| Config breakers | Control-plane flags and kubelet settings the target refuses to start with, including feature gates locked to their default | 382 |
| Volume plugins | In-tree volume plugins that stop mounting | 17 |
| Node runtime | Container runtime, cgroup version, kubelet and kube-proxy version skew | 8 |
| Add-on compatibility | Whether Karpenter, ingress-nginx, cert-manager, Argo CD, CoreDNS, Istio and kube-proxy support the target | 7 catalogs |
| Advisories | Behaviour changes on the path that no API call can settle | 34 |

## Why not Pluto or kubent

Those tools find removed APIs, and they do it well. This one covers removed APIs plus the other
five families above, and it looks for API usage differently.

The API server converts objects on read. Ask for a Deployment at `apps/v1` and you get
`apps/v1` back, whatever it was written as. So listing objects and reporting their `apiVersion`
tells you what you asked for, not what is there.

What survives is the record of who wrote what:

- **Managed fields.** Every object records which client last wrote each part of it, at which API
  version, and when. An entry at a removed version means those fields have not been rewritten
  since. This is per-object, names the writer, and carries a date.
- **Last-applied annotation.** What a client-side `kubectl apply` submitted. Narrow, since Helm
  and server-side apply leave nothing, but it names the manifest a person actually edited.
- **API server metrics.** The cluster's own count of deprecated requests served since it started.
  Cluster-wide rather than per-object, so it catches a controller that no stored object reveals.

Each finding says which of these found it.

## What it cannot see

Every check that could not run is printed, with the reason and a command to run yourself. The
tool never shows an unchecked rule as a passed one.

The usual gaps:

- **Managed control planes.** On EKS, GKE and AKS the provider runs the API server, scheduler and
  controller manager outside your cluster. Their flags cannot be read, so several hundred config
  rules cannot be evaluated. The report names the number.
- **`/metrics`.** Needs `nonResourceURLs: ["/metrics"]`, which is not in the built-in `view` role.
  Without it one evidence tier is missing.
- **Node configuration.** Reading each kubelet's live config needs `nodes/proxy`. Some managed
  providers block it.
- **Objects written before Kubernetes 1.18** carry no managed-field record. If nothing has
  touched an object since, there may be no evidence to find.

Run with `--strict` to make any gap a non-zero exit, for pipelines that would rather fail than
proceed on partial information.

## The catalog

Every rule is data, in [`catalog/`](catalog/). Adding an add-on is a JSON file and no Go code.

Each add-on entry carries the vendor's compatibility table, the source URL it was transcribed
from, and the date someone last checked it. Findings quote the vendor's own words and link to
where they were published, so you can check the claim rather than take our word for it. Past 180
days the report says the data may be stale; it never hides a finding because the source is old.

Verdicts are never collapsed into a tick. An add-on can be supported, too old, too new, or one of
three kinds of unknown: the vendor publishes no matrix, we could not read your installed version,
or your version is not in their table. The last three are reported, because an add-on nobody could
judge is not an add-on that passed.

```bash
kube-upgrade-check catalog list        # what the catalog covers
kube-upgrade-check catalog validate    # check your edit before opening a pull request
```

Validation fails if a rule names a check nobody implemented, if a finding has no vendor quote or
source URL, or if an add-on has no version anchor. The feature-gate and removed-API rules are
additionally checked in CI against ground truth generated from the Kubernetes source, not from
release notes.

## Running it from CI

Scanning with your own kubeconfig needs no setup. To run under a service account that can do
nothing else, apply [`rbac/clusterrole.yaml`](rbac/clusterrole.yaml). It grants reads and the two
extras above; nothing in it can write.

## Beyond one cluster

This checks one cluster, once, from your terminal. If you want the same checks running
continuously across a fleet, with history, with the CVEs that block an upgrade correlated against
it, that is [runtimez](https://runtimez.io/upgrade?utm_source=kube-upgrade-check-readme).

## Licence

Apache 2.0.
