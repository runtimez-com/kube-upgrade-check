# kube-upgrade-check

[![ci](https://github.com/runtimez-com/kube-upgrade-check/actions/workflows/ci.yml/badge.svg)](https://github.com/runtimez-com/kube-upgrade-check/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/runtimez-com/kube-upgrade-check)](https://github.com/runtimez-com/kube-upgrade-check/releases)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)
[![go report](https://goreportcard.com/badge/github.com/runtimez-com/kube-upgrade-check)](https://goreportcard.com/report/github.com/runtimez-com/kube-upgrade-check)

**Find what breaks before you upgrade Kubernetes.**

Point it at a cluster and it tells you what an upgrade to a given version would break: removed
APIs still in use, control-plane and kubelet settings the new version refuses to start with,
in-tree volume plugins that stop mounting, node-level changes, and whether the add-ons you run
support the version you are moving to.

It reads your cluster and writes nothing. No account, no agent, no data leaves the machine.

![kube-upgrade-check scanning a cluster](docs/demo.gif)

> That recording is a real scan, not a mock-up. Regenerate it any time with `vhs docs/demo.tape`.

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

## How this differs from Pluto and kubent

[Pluto](https://github.com/FairwindsOps/pluto) and
[kubent](https://github.com/doitintl/kube-no-trouble) are good tools and this one is not a
replacement for them. Both answer one question — *am I using an API version that is going away?* —
and both answer it well. If that is your question, either will serve you.

This tool answers a wider one: *what breaks when I upgrade?* Removed APIs are one of seven
families it checks.

| | Pluto | kubent | kube-upgrade-check |
| --- | :---: | :---: | :---: |
| Removed and deprecated APIs | yes | yes | yes |
| Scans manifests and Helm charts in a repo | **yes** | **yes** | no |
| Helm 2 releases | **yes** | no | no |
| Reads stored Helm 3 release manifests | **yes** | **yes** | no — see below |
| Managed-fields evidence | no | no | **yes** |
| Control-plane and kubelet settings the target rejects | no | no | **382 rules** |
| Feature gates locked to a new default | no | no | **yes** |
| In-tree volume plugins that stop mounting | no | no | **17 rules** |
| Node runtime and version skew | no | no | **yes** |
| Add-on compatibility (Karpenter, ingress-nginx, …) | no | no | **7 catalogs** |
| Vendor support dates and extended-support cost | no | no | **yes** |
| Reports what it could **not** check | no | no | **yes** |

Two of those rows deserve explaining, because they are the reasons this exists.

### Managed fields find what a stored manifest cannot

The API server converts objects on read. Ask for a Deployment at `apps/v1` and you get `apps/v1`
back whatever it was written as, so listing objects and reporting their `apiVersion` tells you
what you asked for rather than what is there. Pluto's README makes this point plainly, and it is
why both tools read the manifest a client stored: Helm's release secret, or the
`last-applied-configuration` annotation that client-side `kubectl apply` leaves behind.

That works, and it misses everything applied another way. Server-side apply writes no annotation.
Nor does `kubectl create`, `kubectl edit`, an operator, Flux, or Argo CD.

Kubernetes has recorded the answer on every object since 1.18 regardless of how it was written.
`metadata.managedFields` says which client last wrote each part of an object, **at which API
version, and when**. An entry at a removed version means those fields have not been rewritten
since. Neither Pluto nor kubent reads it — there is no reference to managed fields anywhere in
kubent's source, and Pluto documents repository manifests and Helm releases as its sources.

So a finding here can say *helm wrote this at `flowcontrol.apiserver.k8s.io/v1beta3` on
2024-03-02* — the writer and the date, per object, with no manifest stored anywhere.

Helm is worth being precise about. Because Helm appears as a field manager, objects it applied are
covered by this tier like any other. What this tool does **not** do is read Helm's stored release
manifest, and that is a real gap rather than a redundant one: the stored manifest is what
`helm upgrade` replays, so it can fail on a removed API even when nothing in the live cluster
still carries one. Pluto and kubent both read it. If you manage everything with Helm, run one of
them as well.

### It tells you what it could not check

Every check that could not run is printed, with the reason and a command to run yourself. On EKS,
GKE and AKS the provider runs the control plane out of reach, so a few hundred config rules
genuinely cannot be evaluated, and the report says so with a count rather than quietly returning
a shorter list of findings.

This matters more than it sounds. The failure mode of an upgrade checker is not a wrong finding,
which someone will notice. It is a clean report that was clean because half the checks never ran.
`--strict` turns any gap into a non-zero exit for pipelines that would rather fail than proceed on
partial information.

### Where the other tools are still the better choice

- **Checking a change before it is applied.** Pluto and kubent both scan static manifests and Helm
  charts in a repository. This tool reads a live cluster, so it cannot review a pull request. A
  `--manifests` mode is planned; until it lands, use Pluto in CI.
- **Stored Helm release manifests**, for the reason above.
- **Helm 2.** Pluto supports it. This does not.
- **Maturity.** Both have years of production use behind them. This was released in 2026.

## What it cannot see

The specific gaps, all of them printed at the end of a run with a command to check yourself:

- **Managed control planes.** On EKS, GKE and AKS the provider runs the API server, scheduler and
  controller manager outside your cluster. Their flags cannot be read, so several hundred config
  rules cannot be evaluated. The report names the number.
- **`/metrics`.** Needs `nonResourceURLs: ["/metrics"]`, which is not in the built-in `view` role.
  Without it one evidence tier is missing.
- **Node configuration.** Reading each kubelet's live config needs `nodes/proxy`. Some managed
  providers block it.
- **Objects written before Kubernetes 1.18** carry no managed-field record. If nothing has
  touched an object since, there may be no evidence to find.
- **Objects written by a client that reset `managedFields`.** Rare, but it erases the record.

A resource type the target no longer serves, or one the API server answers rather than stores
such as `SubjectAccessReview`, cannot hold objects at all. Those are reported as not applicable
rather than as gaps, so the list above stays short enough to act on.

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
it, that is [runtimez](https://runtimez.io?utm_source=kube-upgrade-check-readme).

## Licence

Apache 2.0.
