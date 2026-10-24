#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${REPOSITORY:-ballardmandy69/sing-box-xboard}"
VERSION="${1:-latest}"
OUTPUT_DIR="${2:-.}"

if [ "$VERSION" = latest ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPOSITORY}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported CPU architecture" >&2; exit 1 ;;
esac

mkdir -p "$OUTPUT_DIR"
curl -fL "https://github.com/${REPOSITORY}/releases/download/${VERSION}/sing-box-xboard-${ARCH}.tar.gz" \
  | tar -xz -C "$OUTPUT_DIR"
