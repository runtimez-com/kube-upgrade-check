#!/usr/bin/env bash
# Copy the catalog into a consuming checkout and record what was copied.
#
# The catalog lives here. Anything that vendors it evaluates the same rules and produces the same
# rule IDs, so a finding reproduces identically in both. Drift between copies means a finding that
# appears in one and not the other, which is the hardest kind of bug to be told about.
#
# Usage: scripts/sync-catalog-to-backend.sh <path-to-consuming-checkout> [--force]
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
backend="${1:-}"
if [ -z "$backend" ]; then
  echo "usage: $0 <path-to-consuming-checkout>" >&2
  exit 2
fi
target="$backend/src/main/resources"

if [ ! -d "$target" ]; then
  echo "no resources directory at $target" >&2
  exit 2
fi

echo "Syncing catalog from $here/catalog to $target"
# Refuse to delete anything the consumer has that this catalog does not. The consumer is also
# where rules are authored, so a file only it has is usually work in progress that belongs
# here next, not something to wipe. Pass --force to overwrite regardless.
force=0
[ "${2:-}" = "--force" ] && force=1
for dir in "$here"/catalog/k8s-*; do
  name="$(basename "$dir")"
  if [ -d "$target/$name" ] && [ "$force" = 0 ]; then
    only_there="$(cd "$target/$name" && find . -type f | sort | comm -23 - <(cd "$dir" && find . -type f | sort))"
    if [ -n "$only_there" ]; then
      echo "refusing to sync $name: $target/$name has files this catalog lacks:" >&2
      echo "$only_there" | sed 's|^\./|    |' >&2
      echo "Copy them into $here/catalog/$name first, or re-run with --force to delete them." >&2
      exit 3
    fi
  fi
done
for dir in "$here"/catalog/k8s-*; do
  name="$(basename "$dir")"
  if [ "$name" = k8s-rules ]; then
    # Rule sets are per source directory. Only the sources vendored here are replaced; a
    # source the consumer has and this catalog does not is left alone.
    for src in "$dir"/*/; do
      sname="$(basename "$src")"
      rm -rf "${target:?}/k8s-rules/$sname"
      mkdir -p "$target/k8s-rules"
      cp -R "$src" "$target/k8s-rules/$sname"
      echo "  k8s-rules/$sname"
    done
    continue
  fi
  rm -rf "${target:?}/$name"
  cp -R "$dir" "$target/$name"
  echo "  $name"
done

cp "$here/catalog/CHECKSUMS" "$target/k8s-catalog-CHECKSUMS"
echo
echo "Copied. A consumer's parity test compares against k8s-catalog-CHECKSUMS."
echo "Commit both repositories together, or the next parity run will fail."
