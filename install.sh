#!/usr/bin/env bash
# Install the backend and nyafw-style shared/independent service templates.
# @author lyt
# @date 2026-10-29
set -euo pipefail
umask 077

REPOSITORY="${REPOSITORY:-ballardmandy69/sing-box-xboard}"
VERSION="${VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/opt/sing-box-xboard}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_PREFIX="${SERVICE_PREFIX-xboard-}"
INSTANCE="${INSTANCE:-server}"
RELEASE_DIR="${RELEASE_DIR:-}"

info() { printf '%s\n' "$*"; }
error() { printf 'install: %s\n' "$*" >&2; exit 1; }
valid_directory() {
  [[ "$1" =~ ^/[A-Za-z0-9_./-]+$ ]] && [[ "$1" != / ]] &&
    [[ "/${1#/}/" != *'/../'* && "/${1#/}/" != *'/./'* ]]
}
download() {
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -o "$2" "$1"
}

[ "$#" -eq 0 ] || error "no positional arguments are accepted; PRODUCT and identity UUID are not required"
[ "$(uname -s)" = Linux ] || error "Linux with systemd is required"
[ "$(id -u)" -eq 0 ] || error "run this script as root"
valid_directory "$INSTALL_DIR" || error "INSTALL_DIR must be a non-root absolute path without spaces or dot components"
valid_directory "$SYSTEMD_DIR" || error "SYSTEMD_DIR must be a non-root absolute path without spaces or dot components"
[[ "$SERVICE_PREFIX" =~ ^[A-Za-z0-9_-]*$ ]] || error "invalid SERVICE_PREFIX"
[[ "$INSTANCE" =~ ^[A-Za-z0-9_-]+$ ]] || error "invalid INSTANCE"
[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || error "invalid REPOSITORY"
[[ "$VERSION" =~ ^[A-Za-z0-9_.-]+$ ]] || error "invalid VERSION"
[ "${PROTOCOL+x}" != x ] ||
  error "PROTOCOL selection was removed; configure the protocols to start in server.yml Nodes instead"
for command_name in curl tar sha256sum install mktemp sed grep cp mv systemctl; do
  command -v "$command_name" >/dev/null 2>&1 || error "$command_name is required"
done

if [ -z "${ARCH:-}" ]; then
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) error "unsupported CPU architecture: $(uname -m)" ;;
  esac
fi
case "$ARCH" in amd64|amd64v3|arm64) ;; *) error "ARCH must be amd64, amd64v3 or arm64" ;; esac

TMP_DIR="$(mktemp -d)"
install_started=false
install_targets=()
cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && [ "$install_started" = true ]; then
    set +e
    printf 'install: restoring previous installation\n' >&2
    for index in "${!install_targets[@]}"; do
      target="${install_targets[$index]}"
      if [ -f "$TMP_DIR/previous/$index" ]; then
        cp -p -- "$TMP_DIR/previous/$index" "$target.rollback.$$" && mv -f -- "$target.rollback.$$" "$target"
      else
        rm -f -- "$target"
      fi
      rm -f -- "$target.new.$$"
    done
    systemctl daemon-reload || printf 'install: files restored; systemd reload still needs inspection\n' >&2
  fi
  rm -rf -- "$TMP_DIR"
  exit "$status"
}
atomic_install() {
  install -m "$1" "$2" "$3.new.$$"
  mv -f -- "$3.new.$$" "$3"
}
trap cleanup EXIT
ASSET="sing-box-xboard-${ARCH}.tar.gz"
if [ -n "$RELEASE_DIR" ]; then
  [[ "$RELEASE_DIR" = /* ]] || error "RELEASE_DIR must be an absolute directory path"
  [ -d "$RELEASE_DIR" ] || error "RELEASE_DIR does not exist"
  cp -- "$RELEASE_DIR/$ASSET" "$TMP_DIR/$ASSET"
  cp -- "$RELEASE_DIR/SHA256SUMS.txt" "$TMP_DIR/SHA256SUMS.txt"
  VERSION="local ($RELEASE_DIR)"
else
  if [ "$VERSION" = latest ]; then
    download "https://api.github.com/repos/${REPOSITORY}/releases/latest" "$TMP_DIR/release.json"
    VERSION="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMP_DIR/release.json")"
    [[ "$VERSION" =~ ^[A-Za-z0-9_.-]+$ ]] || error "GitHub did not return a valid release tag"
  fi
  BASE_URL="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
  download "$BASE_URL/$ASSET" "$TMP_DIR/$ASSET"
  download "$BASE_URL/SHA256SUMS.txt" "$TMP_DIR/SHA256SUMS.txt"
fi

checksum_pattern="^[0-9a-fA-F]{64}  sing-box-xboard-${ARCH}\\.tar\\.gz$"
[ "$(grep -Ec "$checksum_pattern" "$TMP_DIR/SHA256SUMS.txt")" -eq 1 ] || error "missing or ambiguous asset checksum"
(cd "$TMP_DIR" && grep -E "$checksum_pattern" SHA256SUMS.txt | sha256sum -c -) || error "checksum verification failed"
tar -tzf "$TMP_DIR/$ASSET" > "$TMP_DIR/members"
declare -A seen_members=()
while IFS= read -r member; do
  case "$member" in
    sing-box|install.sh|sb-auto.sh|USAGE.md|anytls-native.md|LICENSE|ANYTLS-LICENSE) ;;
    config.xboard.json|server.xboard.yml) ;;
    config.anytls-native.json|server.anytls-native.yml|config.anytls.json|server.anytls.yml) ;;
    config.trojan.json|server.trojan.yml) ;;
    *) error "unexpected package member: $member" ;;
  esac
  [ -z "${seen_members[$member]+set}" ] || error "duplicate package member: $member"
  seen_members[$member]=1
done < "$TMP_DIR/members"
tar -tvzf "$TMP_DIR/$ASSET" > "$TMP_DIR/member-types"
while IFS= read -r member_type; do
  [[ "$member_type" = -* ]] || error "package contains a link or non-regular entry"
done < "$TMP_DIR/member-types"
mkdir "$TMP_DIR/package" "$TMP_DIR/config"
tar -xzf "$TMP_DIR/$ASSET" --no-same-owner --no-same-permissions -C "$TMP_DIR/package"
package_files=(sing-box install.sh sb-auto.sh USAGE.md anytls-native.md LICENSE ANYTLS-LICENSE)
for protocol_name in xboard anytls-native anytls trojan; do
  package_files+=("config.$protocol_name.json" "server.$protocol_name.yml")
done
for name in "${package_files[@]}"; do
  [ -s "$TMP_DIR/package/$name" ] && [ ! -L "$TMP_DIR/package/$name" ] ||
    error "package lacks regular file $name; a release containing Nodes-driven configuration is required"
done
chmod 0755 "$TMP_DIR/package/sing-box"

new_config=false
if [ -e "$INSTALL_DIR/config.json" ]; then
  [ -f "$INSTALL_DIR/config.json" ] && [ ! -L "$INSTALL_DIR/config.json" ] || error "config.json must be a regular file"
  [ -e "$INSTALL_DIR/$INSTANCE.yml" ] ||
    error "existing config.json has no matching $INSTANCE.yml; supply its matching panel YAML before upgrading"
  cp -- "$INSTALL_DIR/config.json" "$TMP_DIR/config/config.json"
else
  [ ! -e "$INSTALL_DIR/$INSTANCE.yml" ] ||
    error "existing $INSTANCE.yml has no matching config.json; supply its matching JSON before installing"
  cp -- "$TMP_DIR/package/config.xboard.json" "$TMP_DIR/config/config.json"
  new_config=true
fi
if [ -e "$INSTALL_DIR/$INSTANCE.yml" ]; then
  [ -f "$INSTALL_DIR/$INSTANCE.yml" ] && [ ! -L "$INSTALL_DIR/$INSTANCE.yml" ] ||
    error "instance YAML must be a regular file"
  cp -- "$INSTALL_DIR/$INSTANCE.yml" "$TMP_DIR/config/$INSTANCE.yml"
else
  cp -- "$TMP_DIR/package/server.xboard.yml" "$TMP_DIR/config/$INSTANCE.yml"
fi
check_directory="$TMP_DIR/config"
[ ! -d "$INSTALL_DIR" ] || check_directory="$INSTALL_DIR"
(cd "$check_directory" && "$TMP_DIR/package/sing-box" check \
  -c "$TMP_DIR/config/config.json" -s "$TMP_DIR/config/$INSTANCE.yml") ||
  error "configuration check failed; installation was not changed"

for kind in sb sbc; do
  json_name=config.json
  [ "$kind" != sbc ] || json_name='%i.json'
  cat > "$TMP_DIR/${SERVICE_PREFIX}${kind}@.service" <<UNIT
[Unit]
Description=sing-box XBoard ${kind} service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
LimitNOFILE=999999
ExecStart=$INSTALL_DIR/sing-box run -c $INSTALL_DIR/$json_name -s $INSTALL_DIR/%i.yml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
done

install_targets=("$INSTALL_DIR/sing-box" "$INSTALL_DIR/install.sh" "$INSTALL_DIR/sb-auto.sh"
  "$INSTALL_DIR/USAGE.md" "$INSTALL_DIR/anytls-native.md" "$INSTALL_DIR/LICENSE" "$INSTALL_DIR/ANYTLS-LICENSE"
  "$SYSTEMD_DIR/${SERVICE_PREFIX}sb@.service" "$SYSTEMD_DIR/${SERVICE_PREFIX}sbc@.service")
if [ "$new_config" = true ]; then
  install_targets+=("$INSTALL_DIR/config.json")
fi
if [ ! -e "$INSTALL_DIR/$INSTANCE.yml" ]; then
  install_targets+=("$INSTALL_DIR/$INSTANCE.yml")
fi
for protocol_name in xboard anytls-native anytls trojan; do
  install_targets+=("$INSTALL_DIR/examples/config.$protocol_name.json"
    "$INSTALL_DIR/examples/server.$protocol_name.yml")
done
mkdir "$TMP_DIR/previous"
for index in "${!install_targets[@]}"; do
  target="${install_targets[$index]}"
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ -f "$target" ] && [ ! -L "$target" ] || error "installation target must be a regular file: $target"
    cp -p -- "$target" "$TMP_DIR/previous/$index"
  fi
done
install_started=true
mkdir -p -- "$INSTALL_DIR/examples" "$SYSTEMD_DIR"
if [ "$new_config" = true ]; then
  atomic_install 0600 "$TMP_DIR/config/config.json" "$INSTALL_DIR/config.json"
fi
[ -e "$INSTALL_DIR/$INSTANCE.yml" ] || atomic_install 0600 "$TMP_DIR/config/$INSTANCE.yml" "$INSTALL_DIR/$INSTANCE.yml"
for name in install.sh sb-auto.sh; do
  atomic_install 0755 "$TMP_DIR/package/$name" "$INSTALL_DIR/$name"
done
for name in USAGE.md anytls-native.md LICENSE ANYTLS-LICENSE; do
  atomic_install 0644 "$TMP_DIR/package/$name" "$INSTALL_DIR/$name"
done
for protocol_name in xboard anytls-native anytls trojan; do
  for name in "config.$protocol_name.json" "server.$protocol_name.yml"; do
    atomic_install 0644 "$TMP_DIR/package/$name" "$INSTALL_DIR/examples/$name"
  done
done
for kind in sb sbc; do
  atomic_install 0644 "$TMP_DIR/${SERVICE_PREFIX}${kind}@.service" "$SYSTEMD_DIR/${SERVICE_PREFIX}${kind}@.service"
done
atomic_install 0755 "$TMP_DIR/package/sing-box" "$INSTALL_DIR/sing-box"
systemctl daemon-reload || error "systemd reload failed; restoring previous installation"
install_started=false
info "installed sing-box XBoard $VERSION ($ARCH) in $INSTALL_DIR"
info "existing configuration and keys were preserved; services were not started or restarted"
info "add Nodes to $INSTALL_DIR/$INSTANCE.yml with panel URL, API key, node ID and any required certificate paths"
info "review $INSTALL_DIR/config.json, then run: systemctl enable --now ${SERVICE_PREFIX}sb@${INSTANCE}.service"
info "no PRODUCT, identity UUID or activation verification is required"
