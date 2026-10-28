#!/usr/bin/env bash
# Package the binary and matching deployment templates from this checkout.
# @author lyt
# @date 2026-10-29
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 BINARY {amd64|amd64v3|arm64} OUTPUT_DIRECTORY" >&2
  exit 1
fi

BINARY="$1"
ARCH="$2"
OUTPUT_DIR="$3"
case "$ARCH" in amd64|amd64v3|arm64) ;; *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;; esac
[ -f "$BINARY" ] || { echo "binary not found: $BINARY" >&2; exit 1; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p -- "$OUTPUT_DIR"
OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd)"
STAGE="$(mktemp -d "$OUTPUT_DIR/.package.XXXXXXXX")"
trap 'rm -rf -- "$STAGE"' EXIT

install -m 0755 -- "$BINARY" "$STAGE/sing-box"
for name in config.anytls-native.json server.anytls-native.yml; do
  install -m 0644 -- "$ROOT/$name" "$STAGE/$name"
done
for name in install.sh sb-auto.sh; do
  install -m 0755 -- "$ROOT/$name" "$STAGE/$name"
done
install -m 0644 -- "$ROOT/docs/xboard-config.md" "$STAGE/USAGE.md"
install -m 0644 -- "$ROOT/docs/anytls-native.md" "$STAGE/anytls-native.md"
install -m 0644 -- "$ROOT/LICENSE" "$STAGE/LICENSE"
install -m 0644 -- "$ROOT/third_party/sing-anytls/LICENSE" "$STAGE/ANYTLS-LICENSE"

ASSET="sing-box-xboard-${ARCH}.tar.gz"
tar -czf "$OUTPUT_DIR/$ASSET" -C "$STAGE" \
  sing-box config.anytls-native.json server.anytls-native.yml install.sh sb-auto.sh \
  USAGE.md anytls-native.md LICENSE ANYTLS-LICENSE
(cd -- "$OUTPUT_DIR" && sha256sum "$ASSET" > "SHA256SUMS-${ARCH}.txt")
printf 'packaged %s\n' "$OUTPUT_DIR/$ASSET"
