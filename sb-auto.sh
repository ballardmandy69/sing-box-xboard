#!/usr/bin/env bash
# Fetch and validate an independent JSON/YAML configuration before activating it.
# @author lyt
# @date 2026-10-29
set -euo pipefail
umask 077

error() { printf 'sb-auto: %s\n' "$*" >&2; exit 1; }
valid_directory() {
  [[ "$1" =~ ^/[A-Za-z0-9_./-]+$ ]] && [[ "$1" != / ]] &&
    [[ "/${1#/}/" != *'/../'* && "/${1#/}/" != *'/./'* ]]
}
download() {
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -o "$2" "$1"
}

[ "$#" -eq 2 ] || error "usage: SHARE=https://host/path bash sb-auto.sh config.json server.yml"
JSON_NAME="$1"
YAML_NAME="$2"
SHARE="${SHARE:-}"
INSTANCE="${INSTANCE:-a}"
INSTALL_DIR="${INSTALL_DIR:-/opt/sing-box-xboard}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_PREFIX="${SERVICE_PREFIX-xboard-}"
[ "$(uname -s)" = Linux ] || error "Linux with systemd is required"
[ "$(id -u)" -eq 0 ] || error "run this script as root"
valid_directory "$INSTALL_DIR" || error "invalid INSTALL_DIR"
valid_directory "$SYSTEMD_DIR" || error "invalid SYSTEMD_DIR"
[[ "$INSTANCE" =~ ^[A-Za-z0-9_-]+$ ]] || error "invalid INSTANCE"
[[ "$SERVICE_PREFIX" =~ ^[A-Za-z0-9_-]*$ ]] || error "invalid SERVICE_PREFIX"
[[ "$JSON_NAME" =~ ^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.json$ ]] || error "JSON file name must be a simple .json basename"
[[ "$YAML_NAME" =~ ^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.ya?ml$ ]] || error "YAML file name must be a simple .yml or .yaml basename"
[[ "$SHARE" =~ ^https://[A-Za-z0-9] ]] && [[ "$SHARE" != *[$'\r\n\t ']* ]] &&
  [[ "$SHARE" != *'?'* && "$SHARE" != *'#'* && "$SHARE" != *'@'* ]] || error "SHARE must be an HTTPS directory URL without credentials, query or fragment"
for command_name in curl systemctl mktemp install cp mv date; do
  command -v "$command_name" >/dev/null 2>&1 || error "$command_name is required"
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT
if [ ! -x "$INSTALL_DIR/sing-box" ]; then
  download "https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/main/install.sh" "$TMP_DIR/install.sh"
  INSTALL_DIR="$INSTALL_DIR" SYSTEMD_DIR="$SYSTEMD_DIR" SERVICE_PREFIX="$SERVICE_PREFIX" bash "$TMP_DIR/install.sh"
fi
for extension in json yml; do
  target="$INSTALL_DIR/$INSTANCE.$extension"
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ -f "$target" ] && [ ! -L "$target" ] || error "existing instance configuration must be a regular file"
  fi
done
download "${SHARE%/}/$JSON_NAME" "$TMP_DIR/$INSTANCE.json"
download "${SHARE%/}/$YAML_NAME" "$TMP_DIR/$INSTANCE.yml"
(cd "$INSTALL_DIR" && ./sing-box check -c "$TMP_DIR/$INSTANCE.json" -c "$TMP_DIR/$INSTANCE.yml") ||
  error "downloaded configuration check failed; existing files were preserved"

unit="${SERVICE_PREFIX}sbc@${INSTANCE}.service"
was_active=false
systemctl is-active --quiet "$unit" && was_active=true
was_enabled=false
systemctl is-enabled --quiet "$unit" && was_enabled=true
BACKUP_DIR="$INSTALL_DIR/backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p -- "$BACKUP_DIR"
chmod 0700 "$INSTALL_DIR/backups" "$BACKUP_DIR"
for extension in json yml; do
  if [ -f "$INSTALL_DIR/$INSTANCE.$extension" ]; then
    install -m 0600 "$INSTALL_DIR/$INSTANCE.$extension" "$BACKUP_DIR/$INSTANCE.$extension"
  fi
  install -m 0600 "$TMP_DIR/$INSTANCE.$extension" "$INSTALL_DIR/.$INSTANCE.$extension.new"
done

rollback() {
  for extension in json yml; do
    if [ -f "$BACKUP_DIR/$INSTANCE.$extension" ]; then
      install -m 0600 "$BACKUP_DIR/$INSTANCE.$extension" "$INSTALL_DIR/$INSTANCE.$extension"
    else
      rm -f -- "$INSTALL_DIR/$INSTANCE.$extension"
    fi
    rm -f -- "$INSTALL_DIR/.$INSTANCE.$extension.new"
  done
  if [ "$was_active" = true ]; then
    systemctl restart "$unit" || printf 'sb-auto: previous configuration restored; service recovery needs inspection\n' >&2
  else
    systemctl stop "$unit" || true
    if [ "$was_enabled" = false ]; then
      systemctl disable "$unit" || printf 'sb-auto: could not restore disabled service state\n' >&2
    fi
  fi
}
if ! mv -f -- "$INSTALL_DIR/.$INSTANCE.json.new" "$INSTALL_DIR/$INSTANCE.json" ||
  ! mv -f -- "$INSTALL_DIR/.$INSTANCE.yml.new" "$INSTALL_DIR/$INSTANCE.yml"; then
  rollback
  error "could not replace configuration; previous files restored"
fi
if [ "$was_active" = true ]; then
  if ! systemctl restart "$unit"; then
    rollback
    error "service restart failed; previous configuration restored"
  fi
elif ! systemctl enable --now "$unit"; then
  rollback
  error "service start failed; previous configuration restored"
fi
printf 'activated %s; previous configuration backup: %s\n' "$unit" "$BACKUP_DIR"
