#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${REPOSITORY:-ballardmandy69/sing-box-xboard}"
VERSION="${VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/opt/sing-box-xboard}"
SERVICE_PREFIX="${SERVICE_PREFIX:-xboard-}"

info() { printf '\033[32m%s\033[0m\n' "$*"; }
error() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || error "curl is required"
command -v tar >/dev/null 2>&1 || error "tar is required"
command -v sha256sum >/dev/null 2>&1 || error "sha256sum is required"

case "$(uname -m)" in
  x86_64|amd64)
    if grep -qw avx2 /proc/cpuinfo 2>/dev/null; then ARCH=amd64v3; else ARCH=amd64; fi
    ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) error "unsupported CPU architecture: $(uname -m)" ;;
esac

if [ "$ARCH" = amd64v3 ] && ! grep -qw avx2 /proc/cpuinfo 2>/dev/null; then
  ARCH=amd64
fi

if [ "$VERSION" = latest ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPOSITORY}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$VERSION" ] || error "no GitHub release found"
fi

ASSET="sing-box-xboard-${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fLSo "$TMP_DIR/$ASSET" "$BASE_URL/$ASSET"
curl -fLSo "$TMP_DIR/SHA256SUMS.txt" "$BASE_URL/SHA256SUMS.txt"
(cd "$TMP_DIR" && grep "  $ASSET$" SHA256SUMS.txt | sha256sum -c -)

mkdir -p "$INSTALL_DIR"
tar -xzf "$TMP_DIR/$ASSET" -C "$TMP_DIR"
install -m 0755 "$TMP_DIR/sing-box" "$INSTALL_DIR/sing-box"
mkdir -p "$INSTALL_DIR/configs"

cat > "/etc/systemd/system/${SERVICE_PREFIX}sb@.service" <<UNIT
[Unit]
Description=sing-box XBoard shared service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
LimitNOFILE=999999
ExecStart=$INSTALL_DIR/sing-box run -c $INSTALL_DIR/config.json -c $INSTALL_DIR/%i.yml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

cat > "/etc/systemd/system/${SERVICE_PREFIX}sbc@.service" <<UNIT
[Unit]
Description=sing-box XBoard independent config service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
LimitNOFILE=999999
ExecStart=$INSTALL_DIR/sing-box run -c $INSTALL_DIR/%i.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
info "installed sing-box XBoard ${VERSION} (${ARCH}) to ${INSTALL_DIR}"
info "shared service: ${SERVICE_PREFIX}sb@.service"
info "independent service: ${SERVICE_PREFIX}sbc@.service"
info "no local identity or activation verification is used"
