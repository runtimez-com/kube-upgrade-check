#!/usr/bin/env python3
"""Generate locked-to-default feature-gate config-breaker rules from the kubernetes source.

The 2026-08-31 changelog audit found the config-breaker catalog's systemic gap: it encodes
REMOVED gates only, but a gate that becomes LockToDefault while explicitly set to the non-default
value is the same fatal component-startup failure, 1-5 releases earlier (SidecarContainers=false
at 1.33; ExecProbeTimeout=false at 1.35). This script reads lock state straight from the
kubernetes source at each tag — never from the changelog, which the audit caught mis-stating lock
versions twice, and which (2026-09-07) missed 12 of the 13 gates locked in 1.37 because the
release notes phrase a lock a dozen different ways.

Source, in order of preference at each tag:
  1. test/compatibility_lifecycle/reference/versioned_feature_list.yaml — the canonical,
     machine-checked lifecycle table (exists from v1.32.0). It is the union across every
     component's registry, so it also carries gates that never appear in kube_features.go.
  2. pkg/features/kube_features.go + the generic apiserver registry — the pre-1.32 fallback.
Verified 2026-09-07: at v1.35.0 both sources yield the identical 12 newly-locked gates.

Usage:
  python3 scripts/gen-locked-gate-rules.py /path/to/kubernetes v1.36.0 v1.37.0 \
      [--merge src/main/resources/k8s-config-breakers/config-breakers.json] [--dry-run]

Without --merge the emitted rows are printed to stdout as JSON. With --merge, rows whose ruleId is
not already in the catalog are appended in place (existing rows are never rewritten) and the run
is recorded under _meta.lockedGateRuns. --dry-run prints what --merge would add and writes nothing.

For each gate we emit TWO rows (the removed-gate catalog convention):
  - componentFlag / featureGateListValueEquals on the 3 control-plane components
  - kubeletConfig / featureGateMapValueEquals on the kubelet featureGates map
value = "Gate=<non-default>", i.e. the explicit setting that now refuses to start.
"""
from __future__ import annotations

import datetime
import json
import re
import subprocess
import sys

LIFECYCLE_FILE = "test/compatibility_lifecycle/reference/versioned_feature_list.yaml"
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

# One versionedSpecs entry in the lifecycle yaml. Field order is fixed by the generator upstream
# (test/compatibility_lifecycle), so a positional match is safe and needs no yaml library.
LIFECYCLE_SPEC = re.compile(
    r"-\s*default:\s*(true|false)\s*\n\s*lockToDefault:\s*(true|false)\s*\n"
    r"\s*preRelease:\s*(\w+)\s*\n\s*version:\s*\"(\d+\.\d+)\""
)


def git_show(repo: str, tag: str, path: str) -> str | None:
    try:
        return subprocess.run(["git", "-C", repo, "show", f"{tag}:{path}"],
                              capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError:
        return None


class Locked:
    """What a source says about every gate LOCKED as of one tag."""

    def __init__(self, source_path: str, gates: dict):
        self.source_path = source_path
        self.gates = gates          # gate -> {"default": bool, "preRelease": str|None, "since": str|None}


def locked_from_lifecycle(repo: str, tag: str) -> Locked | None:
    src = git_show(repo, tag, LIFECYCLE_FILE)
    if src is None:
        return None
    gates = {}
    for entry in re.split(r"^- name: ", src, flags=re.M)[1:]:
        name = entry.split("\n", 1)[0].strip()
        specs = LIFECYCLE_SPEC.findall(entry)
        if not specs:
            continue
        default, lock, pre, ver = specs[-1]       # the last spec is the state at this tag
        if lock == "true":
            # `since` is the first spec of the unbroken locked run ending at the tag.
            since = ver
            for d, l, p, v in reversed(specs):
                if l != "true":
                    break
                since = v
            gates[name] = {"default": default == "true", "preRelease": pre, "since": since}
    return Locked(LIFECYCLE_FILE, gates)


def locked_from_go(repo: str, tag: str) -> Locked:
    gates = {}
    for path in FEATURE_FILES:
        src = git_show(repo, tag, path)
        if src is None:
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
                default = s.group(1) == "true" if s.re is FLAT_SPEC else s.group(2) == "true"
                gates[current] = {"default": default, "preRelease": None, "since": None}
            if line.startswith("\t},") or line.rstrip().endswith("},"):
                if GATE_BLOCK.match(line) is None:
                    current = current if line.startswith("\t\t") else None
    return Locked(FEATURE_FILES[0], gates)


def locked_gates_at(repo: str, tag: str) -> Locked:
    return locked_from_lifecycle(repo, tag) or locked_from_go(repo, tag)


def rules_for(gate: str, info: dict, minor: str, tag: str, source_path: str) -> list:
    default = info["default"]
    fatal = f"{gate}={'false' if default else 'true'}"
    if info["preRelease"] is not None:
        matched = (f"{gate}: lockToDefault: true at {minor} "
                   f"(default: {str(default).lower()}, preRelease: {info['preRelease']})")
        if info["since"] and info["since"] != minor:
            # Upstream sometimes locks a gate by amending an OLDER spec entry (TopologyManagerPolicyOptions
            # was locked in the v1.36.0 tag by annotating its 1.32 GA entry). The tag diff is what a
            # running cluster experiences, so the rule is bound to the tag; the quote says both.
            matched = (f"{gate}: lockToDefault: true first shipped in {tag} "
                       f"(spec entry annotated at {info['since']}; default: {str(default).lower()}, "
                       f"preRelease: {info['preRelease']})")
    else:
        matched = f"{gate}: LockToDefault: true at {minor} (Default: {str(default).lower()})"
    base = {
        "deprecatedInVersion": None,
        "appliesFromVersion": minor,
        "severity": "CRITICAL",
        "deprecatedSeverity": None,
        "provisional": False,
        "detectable": True,
        "value": fatal,
        "provenance": [{
            "name": f"kubernetes/kubernetes {tag} {source_path}",
            "url": f"https://github.com/kubernetes/kubernetes/blob/{tag}/{source_path}",
            "matchedText": matched,
        }],
        "note": "Locked-to-default gate (source-derived by scripts/gen-locked-gate-rules.py): "
                "setting it to the non-default value is a fatal 'cannot set feature gate' error "
                "at startup. Presence at the DEFAULT value is harmless — hence the ValueEquals "
                "condition, unlike the removed-gate rows.",
    }
    return [
        {**base,
         "ruleId": f"rtz-k8s-gate-locked-{slug(gate)}",
         "source": "componentFlag",
         "component": "kube-apiserver,kube-scheduler,kube-controller-manager",
         "selectors": ["--feature-gates"],
         "condition": "featureGateListValueEquals",
         "title": f"Feature gate `{gate}` is locked to {str(default).lower()} from "
                  f"Kubernetes {minor} — a component started with `{fatal}` fails",
         "remediation": f"Remove `{gate}` from `--feature-gates` (or stop setting it to "
                        f"{str(not default).lower()}) before upgrading to {minor}+; the "
                        "gate can no longer be changed."},
        {**base,
         "ruleId": f"rtz-k8s-gate-locked-{slug(gate)}-kubelet",
         "source": "kubeletConfig",
         "component": "kubelet",
         "selectors": ["featureGates"],
         "condition": "featureGateMapValueEquals",
         "title": f"Feature gate `{gate}` is locked to {str(default).lower()} from "
                  f"Kubernetes {minor} — kubelet fails to start with `{fatal}` in its "
                  "featureGates map",
         "remediation": f"Remove `{gate}: {str(not default).lower()}` from the kubelet's "
                        f"`featureGates` config before upgrading to {minor}+."},
    ]


def generate(repo: str, tags: list) -> tuple[list, dict]:
    minors = [t.removeprefix("v").rsplit(".", 1)[0] for t in tags]
    # A gate is NEWLY locked at minor M when it is locked at M's tag but not at the PREVIOUS
    # tag — a pure set diff, immune to spec formats and to mis-recorded lock versions.
    first_major, first_minor = minors[0].split(".")
    baseline_tag = f"v{first_major}.{int(first_minor) - 1}.0"
    per_tag = {t: locked_gates_at(repo, t) for t in [baseline_tag, *tags]}

    rules, summary = [], {}
    for i, tag in enumerate(tags):
        minor = minors[i]
        prev = per_tag[baseline_tag if i == 0 else tags[i - 1]].gates
        cur = per_tag[tag]
        new_gates = sorted(g for g in cur.gates if g not in prev)
        summary[minor] = new_gates
        for gate in new_gates:
            rules.extend(rules_for(gate, cur.gates[gate], minor, tag, cur.source_path))
    return rules, summary


def merge(catalog_path: str, rules: list, tags: list, summary: dict, dry_run: bool) -> None:
    raw = open(catalog_path, encoding="utf-8").read()
    doc = json.loads(raw)
    existing = {r["ruleId"] for r in doc["rules"]}
    added = [r for r in rules if r["ruleId"] not in existing]
    skipped = len(rules) - len(added)
    print(f"merge: {len(added)} new rules, {skipped} already present, "
          f"catalog {len(doc['rules'])} -> {len(doc['rules']) + len(added)}", file=sys.stderr)
    if dry_run:
        for r in added:
            print(f"  + {r['ruleId']}", file=sys.stderr)
        return
    doc["rules"].extend(added)
    doc["_meta"].setdefault("lockedGateRuns", []).append({
        "date": datetime.date.today().isoformat(),
        "tags": tags,
        "gatesPerMinor": {m: len(g) for m, g in summary.items()},
        "rulesAdded": len(added),
        "source": "scripts/gen-locked-gate-rules.py (versioned_feature_list.yaml at each tag, "
                  "kube_features.go fallback)",
    })
    # Preserve the file's own formatting conventions rather than imposing new ones.
    indent = len(raw.split("\n", 2)[1]) - len(raw.split("\n", 2)[1].lstrip(" ")) or 1
    ensure_ascii = "\\u2014" in raw
    out = json.dumps(doc, indent=indent, ensure_ascii=ensure_ascii)
    if raw.endswith("\n"):
        out += "\n"
    open(catalog_path, "w", encoding="utf-8").write(out)


def slug(gate: str) -> str:
    # Acronym-aware: StrictCostEnforcementForVAP -> strict-cost-enforcement-for-vap (never v-a-p).
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", gate)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", s)
    return s.lower()


def main() -> None:
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]
    catalog = None
    if "--merge" in args:
        i = args.index("--merge")
        catalog = args[i + 1]
        del args[i:i + 2]
    repo, *tags = args
    if not tags:
        sys.exit("usage: gen-locked-gate-rules.py REPO TAG... [--merge CATALOG] [--dry-run]")

    rules, summary = generate(repo, tags)
    for minor, gates in summary.items():
        print(f"{minor}: {len(gates)} newly locked gates: {', '.join(gates)}", file=sys.stderr)
    print(f"emitted {len(rules)} rules ({len(rules)//2} gates) for {list(summary)}", file=sys.stderr)
    if catalog:
        merge(catalog, rules, tags, summary, dry_run)
    else:
        json.dump({"lockedGateRules": rules, "count": len(rules)}, sys.stdout, indent=1)
        print()


if __name__ == "__main__":
    main()
