#!/usr/bin/env python3
"""Generate locked-to-default feature-gate config-breaker rules from the kubernetes source.

The 2026-08-31 changelog audit found the config-breaker catalog's systemic gap: it encodes
REMOVED gates only, but a gate that becomes LockToDefault while explicitly set to the non-default
value is the same fatal component-startup failure, 1-5 releases earlier (SidecarContainers=false
at 1.33; ExecProbeTimeout=false at 1.35). This script reads `LockToDefault: true` entries straight
from each tag's pkg/features/kube_features.go + the generic apiserver registry — never from the
changelog, which the audit caught mis-stating lock versions twice.

Usage:
  python3 scripts/gen-locked-gate-rules.py /path/to/kubernetes v1.32.0 v1.33.0 v1.34.0 v1.35.0 \
      > /tmp/locked-gate-rules.json
Then merge the emitted rows into src/main/resources/k8s-config-breakers/config-breakers.json
(rules array) and bump _meta.

For each gate we emit TWO rows (the removed-gate catalog convention):
  - componentFlag / featureGateListValueEquals on the 3 control-plane components
  - kubeletConfig / featureGateMapValueEquals on the kubelet featureGates map
value = "Gate=<non-default>", i.e. the explicit setting that now refuses to start.
"""
import json
import re
import subprocess
import sys

FEATURE_FILES = [
    "pkg/features/kube_features.go",
    "staging/src/k8s.io/apiserver/pkg/features/kube_features.go",
]

GATE_BLOCK = re.compile(r"^\t(\w+): \{")
VERSIONED_SPEC = re.compile(
    r'Version: version\.MustParse\("(\d+\.\d+)"\).*?Default: (true|false)(?P<lock>.*?LockToDefault: true)?',
)
# Pre-versioned map format (still used for many gates at 1.32):
#   GateName: {Default: true, PreRelease: featuregate.GA, LockToDefault: true},
FLAT_SPEC = re.compile(r"Default: (true|false)(?P<lock>.*?LockToDefault: true)?")


def locked_gates_at(repo: str, tag: str) -> dict:
    """gate -> its locked default, for every gate LOCKED as of this tag (either spec format)."""
    locked = {}
    for path in FEATURE_FILES:
        try:
            src = subprocess.run(["git", "-C", repo, "show", f"{tag}:{path}"],
                                 capture_output=True, text=True, check=True).stdout
        except subprocess.CalledProcessError:
            continue
        current = None
        for line in src.splitlines():
            m = GATE_BLOCK.match(line)
            if m:
                current = m.group(1)
            if current is None:
                continue
            s = VERSIONED_SPEC.search(line) or FLAT_SPEC.search(line)
            if s and s.group("lock"):
                locked[current] = s.group(1) == "true" if s.re is FLAT_SPEC \
                    else s.group(2) == "true"
            if line.startswith("\t},") or line.rstrip().endswith("},"):
                if GATE_BLOCK.match(line) is None:
                    current = current if line.startswith("\t\t") else None
    return locked


def main() -> None:
    repo, *tags = sys.argv[1:]
    minors = [t.removeprefix("v").rsplit(".", 1)[0] for t in tags]

    # A gate is NEWLY locked at minor M when it is locked at M's tag but not at the PREVIOUS
    # tag — a pure set diff, immune to both spec formats and to mis-recorded lock versions.
    # The minor before the first requested tag is the baseline (e.g. v1.31.0 for v1.32.0).
    first_major, first_minor = minors[0].split(".")
    baseline_tag = f"v{first_major}.{int(first_minor) - 1}.0"
    per_tag = {t: locked_gates_at(repo, t) for t in [baseline_tag, *tags]}

    rules = []
    for i, tag in enumerate(tags):
        minor = minors[i]
        prev = per_tag[baseline_tag if i == 0 else tags[i - 1]]
        for gate, default in sorted(per_tag[tag].items()):
            if gate in prev:
                continue   # already locked before this window
            fatal = f"{gate}={'false' if default else 'true'}"
            base = {
                "deprecatedInVersion": None,
                "appliesFromVersion": minor,
                "severity": "CRITICAL",
                "deprecatedSeverity": None,
                "provisional": False,
                "detectable": True,
                "value": fatal,
                "provenance": [{
                    "name": f"kubernetes/kubernetes {tag} pkg/features/kube_features.go",
                    "url": "https://github.com/kubernetes/kubernetes/blob/"
                           f"{tag}/pkg/features/kube_features.go",
                    "matchedText": f"{gate}: LockToDefault: true at {minor} "
                                   f"(Default: {str(default).lower()})",
                }],
                "note": "Locked-to-default gate (source-derived, 2026-08-31 audit): setting it to "
                        "the non-default value is a fatal 'cannot set feature gate' error at "
                        "startup. Presence at the DEFAULT value is harmless — hence the "
                        "ValueEquals condition, unlike the removed-gate rows.",
            }
            rules.append({**base,
                "ruleId": f"rtz-k8s-gate-locked-{slug(gate)}",
                "source": "componentFlag",
                "component": "kube-apiserver,kube-scheduler,kube-controller-manager",
                "selectors": ["--feature-gates"],
                "condition": "featureGateListValueEquals",
                "title": f"Feature gate `{gate}` is locked to {str(default).lower()} from "
                         f"Kubernetes {minor} — a component started with `{fatal}` fails",
                "remediation": f"Remove `{gate}` from `--feature-gates` (or stop setting it to "
                               f"{str(not default).lower()}) before upgrading to {minor}+; the "
                               "gate can no longer be changed.",
            })
            rules.append({**base,
                "ruleId": f"rtz-k8s-gate-locked-{slug(gate)}-kubelet",
                "source": "kubeletConfig",
                "component": "kubelet",
                "selectors": ["featureGates"],
                "condition": "featureGateMapValueEquals",
                "title": f"Feature gate `{gate}` is locked to {str(default).lower()} from "
                         f"Kubernetes {minor} — kubelet fails to start with `{fatal}` in its "
                         "featureGates map",
                "remediation": f"Remove `{gate}: {str(not default).lower()}` from the kubelet's "
                               f"`featureGates` config before upgrading to {minor}+.",
            })
    json.dump({"lockedGateRules": rules, "count": len(rules)}, sys.stdout, indent=1)
    print(file=sys.stderr)
    print(f"emitted {len(rules)} rules ({len(rules)//2} gates) for {minors}", file=sys.stderr)


def slug(gate: str) -> str:
    # Acronym-aware: StrictCostEnforcementForVAP -> strict-cost-enforcement-for-vap (never v-a-p).
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", gate)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", s)
    return s.lower()


if __name__ == "__main__":
    main()
