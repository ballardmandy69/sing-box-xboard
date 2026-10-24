#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash <(curl -fsSL https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/main/sb-auto.sh) config.json server.yml

JSON_NAME="${1:?please input the JSON file name}"
YAML_NAME="${2:?please input the server YAML file name}"
SHARE="${SHARE:?set SHARE to the HTTPS directory containing the configuration files}"
INSTANCE="${INSTANCE:-a}"
INSTALL_DIR="${INSTALL_DIR:-/opt/sing-box-xboard}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run this script as root" >&2
  exit 1
fi

if [ ! -x "$INSTALL_DIR/sing-box" ]; then
  curl -fsSL https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/main/install.sh | bash
fi

mkdir -p "$INSTALL_DIR"
curl -fsSLo "$INSTALL_DIR/${INSTANCE}.json" "${SHARE%/}/$JSON_NAME"
curl -fsSLo "$INSTALL_DIR/${INSTANCE}.yml" "${SHARE%/}/$YAML_NAME"

systemctl enable --now "xboard-sbc@${INSTANCE}.service"
echo "started xboard-sbc@${INSTANCE}.service"
