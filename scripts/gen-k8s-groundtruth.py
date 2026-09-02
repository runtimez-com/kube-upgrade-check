#!/usr/bin/env python3
"""Regenerate the Kubernetes ground-truth fixtures consumed by CatalogGroundTruthTest.

The upgrade catalogs under src/main/resources/k8s-* used to be transcribed from CHANGELOG prose,
which is incomplete and sometimes announces removals upstream never ships (see the
resource.k8s.io/v1beta1 1.36-vs-1.38 correction). The kubernetes/kubernetes source tree carries
machine-readable ground truth for both facts we care about, so we read that instead:

  API removals       APILifecycleRemoved() in staging/src/k8s.io/api/<group>/<ver>/
                     zz_generated.prerelease-lifecycle.go. Authoritative because
                     apiserver/pkg/server/deleted_kinds.go (ResourceExpirationEvaluator) stops
                     serving a GVK at exactly that value.
  Feature gates      Set difference of gate NAMES declared in */features/kube_features.go between
                     consecutive release tags. A gate name that disappears is a hard startup
                     failure for any component still passing it in --feature-gates.

Usage:  python3 scripts/gen-k8s-groundtruth.py /path/to/kubernetes [--out src/test/resources/k8s-groundtruth]
"""
import argparse, collections, glob, json, os, re, subprocess, sys

# The Go identifier is NOT always capitalised — v1.16.0 declares
# `deprecatedGCERegionalPersistentDisk featuregate.Feature = "GCERegionalPersistentDisk"`. Match any
# identifier and capture the STRING literal, which is what --feature-gates actually accepts.
GATE_DECL = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\s+featuregate\.Feature\s*=\s*"([A-Za-z0-9]+)"')
LIFECYCLE = re.compile(
    r'func \(in \*(\w+)\) APILifecycle(Deprecated|Removed)\(\) \(major, minor int\) \{\s*return (\d+), (\d+)')
GROUP_NAME = re.compile(r'GroupName\s*=\s*"([^"]*)"')


def git(repo, *args):
    return subprocess.check_output(['git', '-C', repo, *args], stderr=subprocess.DEVNULL).decode()


def release_tags(repo):
    tags = [t for t in git(repo, 'tag', '-l', 'v1.*.0').split()
            if re.fullmatch(r'v1\.\d+\.0', t)]
    return sorted(tags, key=lambda t: int(t.split('.')[1]))


def gates_at(repo, tag):
    files = [f for f in git(repo, 'ls-tree', '-r', '--name-only', tag).split('\n')
             if f.endswith('features/kube_features.go') or f.endswith('/features/features.go')]
    found = set()
    for f in files:
        try:
            found |= set(GATE_DECL.findall(git(repo, 'show', f'{tag}:{f}')))
        except subprocess.CalledProcessError:
            pass
    return found


def gate_removals(repo):
    """version -> sorted gate names that existed in the previous release and not in this one."""
    out, prev = {}, None
    for tag in release_tags(repo):
        g = gates_at(repo, tag)
        if not g:
            continue                      # tag predates the featuregate.Feature declaration style
        if prev:
            gone = sorted(prev[1] - g)
            if gone:
                out['.'.join(tag.lstrip('v').split('.')[:2])] = gone
        prev = (tag, g)
    return out


def api_removals(repo):
    """Read the CURRENT working tree — generated lifecycle tags carry the whole schedule, including
    releases that have not shipped yet, so no tag walk is needed."""
    rows = []
    for path in glob.glob(os.path.join(repo, 'staging/src/k8s.io/api/*/*/zz_generated.prerelease-lifecycle.go')):
        group_dir, version = path.split(os.sep)[-3], path.split(os.sep)[-2]
        register = os.path.join(repo, 'staging/src/k8s.io/api', group_dir, version, 'register.go')
        group = ''
        if os.path.exists(register):
            m = GROUP_NAME.search(open(register).read())
            group = m.group(1) if m else ''
        per_kind = collections.defaultdict(dict)
        for kind, which, major, minor in LIFECYCLE.findall(open(path).read()):
            if kind.endswith('List'):
                continue                  # List types mirror their item type
            per_kind[kind][which] = f'{major}.{minor}'
        for kind, life in per_kind.items():
            if 'Removed' in life:
                rows.append({
                    'apiVersion': f'{group}/{version}' if group else version,
                    'kind': kind,
                    'deprecatedIn': life.get('Deprecated'),
                    'removedIn': life['Removed'],
                })
    return sorted(rows, key=lambda r: (tuple(map(int, r['removedIn'].split('.'))), r['apiVersion'], r['kind']))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('repo', help='path to a kubernetes/kubernetes checkout')
    ap.add_argument('--out', default='src/test/resources/k8s-groundtruth')
    args = ap.parse_args()
    if not os.path.isdir(os.path.join(args.repo, '.git')):
        sys.exit(f'not a git checkout: {args.repo}')
    os.makedirs(args.out, exist_ok=True)
    described = git(args.repo, 'describe', '--tags').strip()

    apis = api_removals(args.repo)
    gates = gate_removals(args.repo)
    for name, payload, note in [
        ('api-removals.json', apis,
         'Every built-in API GVK with an APILifecycleRemoved() tag, from '
         'staging/src/k8s.io/api/*/*/zz_generated.prerelease-lifecycle.go. removedIn is the release '
         'the apiserver stops SERVING the GVK (enforced by ResourceExpirationEvaluator in '
         'apiserver/pkg/server/deleted_kinds.go), which is why it can name a release that has not '
         'shipped yet.'),
        ('gate-removals.json', gates,
         'version -> feature gates whose NAME disappeared from */features/kube_features.go between '
         'the previous release tag and this one. Any component still passing a removed name in '
         '--feature-gates exits at startup with "unrecognized feature-gate".'),
    ]:
        with open(os.path.join(args.out, name), 'w') as fh:
            json.dump({'_generatedFrom': described, '_generator': 'scripts/gen-k8s-groundtruth.py',
                       '_note': note, 'data': payload}, fh, indent=1, sort_keys=False)
            fh.write('\n')
    print(f'wrote {args.out}/api-removals.json ({len(apis)} rows)')
    print(f'wrote {args.out}/gate-removals.json ({sum(len(v) for v in gates.values())} gates '
          f'across {len(gates)} releases)')
    print(f'source: {args.repo} @ {described}')


if __name__ == '__main__':
    main()
