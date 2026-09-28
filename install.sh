#!/bin/sh
# Install kube-upgrade-check.
#
#   curl -fsSL https://runtimez.io/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/runtimez-com/kube-upgrade-check/main/install.sh | sh
#
# Verifies the checksum before installing. Set KUC_VERSION to pin a release, and INSTALL_DIR
# to choose where the binary lands.
#
# After a successful install the script sends ONE anonymous ping (release version, OS, CPU
# architecture — nothing about you or your clusters) so we can count installs. Set
# KUC_NO_PING=1 to skip it. The ping is a plain GET; the endpoint is a static empty object,
# counted from the CDN's access log.
set -eu

REPO="runtimez-com/kube-upgrade-check"
BINARY="kube-upgrade-check"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
PING_URL="${KUC_PING_URL:-https://runtimez.io/i}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux|darwin) ;;
  *) echo "unsupported OS: $os — on Windows use: scoop install $BINARY" >&2; exit 1 ;;
esac

version="${KUC_VERSION:-}"
if [ -z "$version" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
fi
if [ -z "$version" ]; then
  echo "could not determine the latest release; set KUC_VERSION to pin one" >&2
  exit 1
fi

plain="${version#v}"
archive="${BINARY}_${plain}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$version"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $BINARY $version ($os/$arch)…"
curl -fsSL "$base/$archive" -o "$tmp/$archive"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"

# An unverified download is how a compromised mirror becomes a compromised laptop. No
# checksum, no install.
echo "Verifying checksum…"
( cd "$tmp" && grep " $archive\$" checksums.txt | {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum -c -
    elif command -v shasum   >/dev/null 2>&1; then shasum -a 256 -c -
    else echo "no sha256sum or shasum available to verify the download" >&2; exit 1
    fi
  } )

tar -xzf "$tmp/$archive" -C "$tmp"

if [ -w "$INSTALL_DIR" ]; then
  mv "$tmp/$BINARY" "$INSTALL_DIR/$BINARY"
else
  echo "Installing to $INSTALL_DIR (needs sudo)…"
  sudo mv "$tmp/$BINARY" "$INSTALL_DIR/$BINARY"
fi
chmod +x "$INSTALL_DIR/$BINARY" 2>/dev/null || sudo chmod +x "$INSTALL_DIR/$BINARY"

echo
"$INSTALL_DIR/$BINARY" version

# Install counter. Only reached after the binary is verified and in place, so the access log
# counts completed installs rather than curls of this script. Never fails the install.
if [ -z "${KUC_NO_PING:-}" ]; then
  echo "Counting this install (v=$plain os=$os arch=$arch only). KUC_NO_PING=1 skips it."
  curl -fsS -m 3 -o /dev/null "$PING_URL?v=$plain&os=$os&arch=$arch" 2>/dev/null || true
fi

echo
echo "Next: $BINARY --target 1.34     (reads your current kubeconfig context, read-only)"
