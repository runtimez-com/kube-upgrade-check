#!/usr/bin/env python3
"""Regenerate the krew plugin manifest from a published release.

The checksums come from the release's own checksums.txt rather than being computed locally, so
the manifest can only ever describe artifacts that are actually downloadable. Hand-editing this
file is how a manifest ends up claiming a digest nothing matches.

Usage: scripts/gen-krew-manifest.py v0.1.2
"""
import sys
import urllib.request
from pathlib import Path

REPO = "runtimez-com/kube-upgrade-check"
OUT = Path(__file__).resolve().parent.parent / "plugins" / "krew" / "upgrade-check.yaml"

PLATFORMS = [
    ("darwin", "amd64", "tar.gz"),
    ("darwin", "arm64", "tar.gz"),
    ("linux", "amd64", "tar.gz"),
    ("linux", "arm64", "tar.gz"),
    ("windows", "amd64", "zip"),
    ("windows", "arm64", "zip"),
]

DESCRIPTION = """    Reports what an upgrade to a target Kubernetes version would break in the
    cluster you are pointed at: objects still written at an API version the
    target removes, control-plane and kubelet settings it refuses to start
    with, in-tree volume plugins that stop mounting, node runtime and version
    skew, and whether add-ons such as Karpenter, ingress-nginx, cert-manager,
    Argo CD, CoreDNS and Istio support the version you are moving to.

    It reads the cluster and writes nothing. No account and no agent, and no
    data leaves the machine.

    Removed APIs are found through managed fields, so an object is caught
    whatever applied it, including server-side apply, operators and GitOps
    controllers that leave no last-applied annotation behind.

    Every check that could not run is printed with the reason and a command to
    run yourself, so a clean report cannot be one where half the checks were
    silently skipped.

    Examples:
      kubectl upgrade-check --target 1.34
      kubectl upgrade-check --target 1.34 -o json
      kubectl upgrade-check --fail-on high --strict
"""

CAVEATS = """    Some checks need permissions the built-in view role does not grant:

      * nodes/proxy, to read each node's live kubelet configuration
      * the /metrics endpoint, for one of the removed-API evidence sources

    Without them the affected checks are reported as unavailable rather than
    skipped silently. A read-only ClusterRole covering everything is in the
    repository under rbac/.
"""


def main(version: str) -> int:
    if not version.startswith("v"):
        print(f"version should look like v0.1.2, got {version}", file=sys.stderr)
        return 2

    base = f"https://github.com/{REPO}/releases/download/{version}"
    try:
        raw = urllib.request.urlopen(f"{base}/checksums.txt", timeout=30).read().decode()
    except Exception as err:  # noqa: BLE001 - the message matters more than the type
        print(f"could not read checksums for {version}: {err}", file=sys.stderr)
        print("has the release finished publishing?", file=sys.stderr)
        return 1

    digests = dict(line.split()[::-1] for line in raw.strip().splitlines())

    blocks = []
    for os_name, arch, ext in PLATFORMS:
        archive = f"kube-upgrade-check_{version[1:]}_{os_name}_{arch}.{ext}"
        if archive not in digests:
            print(f"{archive} is not in the release", file=sys.stderr)
            return 1
        binary = "kube-upgrade-check.exe" if os_name == "windows" else "kube-upgrade-check"
        blocks.append(
            f"""    - selector:
        matchLabels:
          os: {os_name}
          arch: {arch}
      uri: {base}/{archive}
      sha256: {digests[archive]}
      bin: {binary}
      files:
        - from: "{binary}"
          to: "."
        - from: LICENSE
          to: "."
"""
        )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        "apiVersion: krew.googlecontainertools.github.com/v1alpha2\n"
        "kind: Plugin\n"
        "metadata:\n"
        "  name: upgrade-check\n"
        "spec:\n"
        f"  version: {version}\n"
        f"  homepage: https://github.com/{REPO}\n"
        "  shortDescription: Find what breaks before you upgrade Kubernetes\n"
        "  description: |\n" + DESCRIPTION +
        "  caveats: |\n" + CAVEATS +
        "  platforms:\n" + "".join(blocks).rstrip() + "\n"
    )
    print(f"wrote {OUT.relative_to(Path.cwd())} for {version} ({len(blocks)} platforms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
