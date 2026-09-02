#!/usr/bin/env bash
# Copy the catalog into a consuming checkout and record what was copied.
#
# The catalog lives here. Anything that vendors it evaluates the same rules and produces the same
# rule IDs, so a finding reproduces identically in both. Drift between copies means a finding that
# appears in one and not the other, which is the hardest kind of bug to be told about.
#
# Usage: scripts/sync-catalog-to-backend.sh <path-to-consuming-checkout>
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
for dir in "$here"/catalog/k8s-*; do
  name="$(basename "$dir")"
  rm -rf "${target:?}/$name"
  cp -R "$dir" "$target/$name"
  echo "  $name"
done

cp "$here/catalog/CHECKSUMS" "$target/k8s-catalog-CHECKSUMS"
echo
echo "Copied. A consumer's parity test compares against k8s-catalog-CHECKSUMS."
echo "Commit both repositories together, or the next parity run will fail."
