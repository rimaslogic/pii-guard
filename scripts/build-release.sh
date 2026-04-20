#!/usr/bin/env bash
# Build the two release artifacts: standalone zip + plugin zip.
# Outputs into dist/.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

VERSION="$(cat VERSION | tr -d '[:space:]')"
NAME="pii-guard"
DIST="$HERE/dist"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$DIST"
rm -f "$DIST"/${NAME}-*.zip "$DIST"/*.sha256

# --- Standalone zip: skill/ contents at the root of the zip ---
STANDALONE="$STAGE/standalone/${NAME}"
mkdir -p "$STANDALONE"
cp -R skill/. "$STANDALONE/"
cp README.md LICENSE CHANGELOG.md VERSION "$STANDALONE/"
(cd "$STAGE/standalone" && zip -qr "$DIST/${NAME}-${VERSION}.zip" "${NAME}")

# --- Plugin zip: plugin.json + .claude-plugin/ + skill/ ---
PLUGIN="$STAGE/plugin/${NAME}"
mkdir -p "$PLUGIN/.claude-plugin"
cp plugin.json "$PLUGIN/"
cp .claude-plugin/marketplace.json "$PLUGIN/.claude-plugin/"
cp -R skill "$PLUGIN/skill"
cp README.md LICENSE CHANGELOG.md VERSION "$PLUGIN/"
(cd "$STAGE/plugin" && zip -qr "$DIST/${NAME}-${VERSION}-plugin.zip" "${NAME}")

# --- Checksums ---
cd "$DIST"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${NAME}-${VERSION}.zip" "${NAME}-${VERSION}-plugin.zip" > "${NAME}-${VERSION}.sha256"
else
  shasum -a 256 "${NAME}-${VERSION}.zip" "${NAME}-${VERSION}-plugin.zip" > "${NAME}-${VERSION}.sha256"
fi

echo "Built:"
ls -lh "$DIST"
