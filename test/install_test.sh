#!/usr/bin/env bash
# Isolated installation smoke tests; the core remains a real built Linux binary.
# @author lyt
# @date 2026-10-29
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SING_BOX_BINARY:?set SING_BOX_BINARY to an absolute path to the built Linux core}"
[[ "$SING_BOX_BINARY" = /* ]] && [ -x "$SING_BOX_BINARY" ] || {
  printf 'SING_BOX_BINARY must be an executable absolute path\n' >&2
  exit 1
}
TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT
mkdir "$TMP_DIR/shims" "$TMP_DIR/package" "$TMP_DIR/release" "$TMP_DIR/share"
export SMOKE_LOG="$TMP_DIR/systemctl.log"
export SMOKE_SHARE="$TMP_DIR/share"
touch "$SMOKE_LOG"
cat > "$TMP_DIR/shims/id" <<'SHIM'
#!/usr/bin/env bash
[ "$1" = -u ] || exit 1
printf '%s\n' "${SMOKE_UID:-0}"
SHIM
cat > "$TMP_DIR/shims/systemctl" <<'SHIM'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$SMOKE_LOG"
case "$1" in
  is-active) [ "${SMOKE_ACTIVE:-false}" = true ] ;;
  is-enabled) [ "${SMOKE_ENABLED:-false}" = true ] ;;
  enable|restart) [ "${SMOKE_FAIL_SERVICE:-false}" != true ] ;;
  daemon-reload) [ "${SMOKE_FAIL_RELOAD:-false}" != true ] ;;
  disable|stop) exit 0 ;;
  *) exit 1 ;;
esac
SHIM
cat > "$TMP_DIR/shims/curl" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
output=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --proto|--proto-redir) [ "$2" = '=https' ]; shift 2 ;;
    -o) output="$2"; shift 2 ;;
    --tlsv1.2|-fsSL) shift ;;
    https://*) url="$1"; shift ;;
    *) printf 'unexpected curl argument\n' >&2; exit 1 ;;
  esac
done
[ -n "$url" ] && [ -n "$output" ]
[ "${SMOKE_FAIL_DOWNLOAD:-}" != "${url##*/}" ] || exit 22
cp -- "$SMOKE_SHARE/${url##*/}" "$output"
SHIM
chmod 0755 "$TMP_DIR/shims/"*
export PATH="$TMP_DIR/shims:$PATH"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }
expect_failure() {
  if "$@" > "$TMP_DIR/expected-failure.log" 2>&1; then
    fail "command unexpectedly succeeded"
  fi
}
run_installer() {
  env INSTALL_DIR="$TMP_DIR/install" SYSTEMD_DIR="$TMP_DIR/units" ARCH=amd64 \
    INSTANCE=server SERVICE_PREFIX=xboard- PROTOCOL=anytls-native RELEASE_DIR="$TMP_DIR/release" \
    bash "$ROOT/install.sh" > "$TMP_DIR/install.log" 2>&1
}
run_auto() {
  env INSTALL_DIR="$TMP_DIR/install" SYSTEMD_DIR="$TMP_DIR/units" INSTANCE=demo \
    SERVICE_PREFIX=xboard- SHARE=https://configs.example.test/backend \
    bash "$ROOT/sb-auto.sh" backend.json backend.yml > "$TMP_DIR/auto.log" 2>&1
}

bash -n "$ROOT/install.sh" "$ROOT/sb-auto.sh" "$ROOT/test/install_test.sh" "$ROOT/release/package-xboard.sh"
bash "$ROOT/release/package-xboard.sh" "$SING_BOX_BINARY" amd64 "$TMP_DIR/release" > "$TMP_DIR/package.log"
cp "$TMP_DIR/release/SHA256SUMS-amd64.txt" "$TMP_DIR/release/SHA256SUMS.txt"
tar -xzf "$TMP_DIR/release/sing-box-xboard-amd64.tar.gz" -C "$TMP_DIR/package"

run_installer || { cat "$TMP_DIR/install.log" >&2; fail "fresh install"; }
[ -x "$TMP_DIR/install/sing-box" ] || fail "missing installed core"
[ -s "$TMP_DIR/install/server-public-key.txt" ] || fail "missing public key"
! grep -q '__SERVER_PRIVATE_KEY__' "$TMP_DIR/install/config.json" || fail "unreplaced private key"
[ "$(stat -c %a "$TMP_DIR/install/config.json")" = 600 ] || fail "config permissions"
[ "$(stat -c %a "$TMP_DIR/install/server.yml")" = 600 ] || fail "YAML permissions"
[ -s "$TMP_DIR/units/xboard-sb@.service" ] && [ -s "$TMP_DIR/units/xboard-sbc@.service" ] || fail "missing units"
for protocol in anytls-native anytls trojan; do
  for name in "config.$protocol.json" "server.$protocol.yml"; do
    [ "$(stat -c %a "$TMP_DIR/install/examples/$name")" = 644 ] || fail "missing protected example $name"
  done
done
grep -q '__SERVER_PRIVATE_KEY__' "$TMP_DIR/install/examples/config.anytls-native.json" ||
  fail "example contains generated private key"
! grep -Eq '^(enable|restart|start) ' "$SMOKE_LOG" || fail "installer started a service"
pass 'fresh install generates protected native config and both service templates'

printf '\n# operator setting retained\n' >> "$TMP_DIR/install/server.yml"
cp "$TMP_DIR/install/config.json" "$TMP_DIR/original.json"
cp "$TMP_DIR/install/server.yml" "$TMP_DIR/original.yml"
cp "$TMP_DIR/install/server-public-key.txt" "$TMP_DIR/original.public"
run_installer || { cat "$TMP_DIR/install.log" >&2; fail "upgrade"; }
cmp "$TMP_DIR/original.json" "$TMP_DIR/install/config.json" || fail "upgrade changed private key or config"
cmp "$TMP_DIR/original.yml" "$TMP_DIR/install/server.yml" || fail "upgrade changed YAML"
cmp "$TMP_DIR/original.public" "$TMP_DIR/install/server-public-key.txt" || fail "upgrade changed public key"
pass 'upgrade preserves configuration and existing key pair'

command -v openssl >/dev/null 2>&1 || fail "openssl is required for real TLS configuration tests"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$TMP_DIR/tls.key" -out "$TMP_DIR/tls.crt" -days 1 -subj /CN=localhost \
  > "$TMP_DIR/certificate.log" 2>&1
sha256sum "$TMP_DIR/tls.crt" "$TMP_DIR/tls.key" > "$TMP_DIR/certificate-before.sha256"
for protocol in anytls trojan; do
  expect_failure env -u TLS_CERT_FILE -u TLS_KEY_FILE \
    INSTALL_DIR="$TMP_DIR/no-cert-$protocol" SYSTEMD_DIR="$TMP_DIR/no-cert-units-$protocol" \
    ARCH=amd64 INSTANCE=server PROTOCOL="$protocol" RELEASE_DIR="$TMP_DIR/release" bash "$ROOT/install.sh"
  grep -q 'TLS_CERT_FILE' "$TMP_DIR/expected-failure.log" || fail "$protocol did not require TLS certificate"
  [ ! -e "$TMP_DIR/no-cert-$protocol" ] || fail "missing TLS certificate modified target"
  env INSTALL_DIR="$TMP_DIR/$protocol" SYSTEMD_DIR="$TMP_DIR/units-$protocol" \
    ARCH=amd64 INSTANCE=server PROTOCOL="$protocol" RELEASE_DIR="$TMP_DIR/release" \
    TLS_CERT_FILE="$TMP_DIR/tls.crt" TLS_KEY_FILE="$TMP_DIR/tls.key" \
    bash "$ROOT/install.sh" > "$TMP_DIR/$protocol.log" 2>&1 || {
      cat "$TMP_DIR/$protocol.log" >&2
      fail "$protocol fresh install"
    }
  grep -Eq '"type"[[:space:]]*:[[:space:]]*"'"$protocol"'"' "$TMP_DIR/$protocol/config.json" ||
    fail "$protocol template selection"
  grep -Fq "$TMP_DIR/tls.crt" "$TMP_DIR/$protocol/config.json" || fail "$protocol certificate path not substituted"
  grep -Fq "$TMP_DIR/tls.key" "$TMP_DIR/$protocol/config.json" || fail "$protocol key path not substituted"
  [ ! -e "$TMP_DIR/$protocol/server-public-key.txt" ] || fail "$protocol generated an unrelated native public key"
  ! grep -q 'server_public_key' "$TMP_DIR/$protocol.log" || fail "$protocol displayed native key instructions"
  "$TMP_DIR/$protocol/sing-box" check -c "$TMP_DIR/$protocol/config.json" -c "$TMP_DIR/$protocol/server.yml"
  cp "$TMP_DIR/$protocol/config.json" "$TMP_DIR/$protocol-before.json"
  cp "$TMP_DIR/$protocol/server.yml" "$TMP_DIR/$protocol-before.yml"
  env -u TLS_CERT_FILE -u TLS_KEY_FILE \
    INSTALL_DIR="$TMP_DIR/$protocol" SYSTEMD_DIR="$TMP_DIR/units-$protocol" \
    ARCH=amd64 INSTANCE=server PROTOCOL=anytls-native RELEASE_DIR="$TMP_DIR/release" \
    bash "$ROOT/install.sh" > "$TMP_DIR/$protocol-upgrade.log" 2>&1 ||
    fail "$protocol upgrade without new TLS variables"
  cmp "$TMP_DIR/$protocol-before.json" "$TMP_DIR/$protocol/config.json" || fail "$protocol upgrade changed JSON"
  cmp "$TMP_DIR/$protocol-before.yml" "$TMP_DIR/$protocol/server.yml" || fail "$protocol upgrade changed YAML"
  [ ! -e "$TMP_DIR/$protocol/server-public-key.txt" ] || fail "$protocol upgrade generated native public key"
  pass "$protocol requires TLS, installs a real checked configuration and preserves it on upgrade"
done
sha256sum -c "$TMP_DIR/certificate-before.sha256" > "$TMP_DIR/certificate-check.log" ||
  fail "installer altered TLS certificate or key"

mkdir "$TMP_DIR/partial-config"
cp "$TMP_DIR/install/config.json" "$TMP_DIR/partial-config/config.json"
expect_failure env INSTALL_DIR="$TMP_DIR/partial-config" SYSTEMD_DIR="$TMP_DIR/partial-units" \
  ARCH=amd64 INSTANCE=server PROTOCOL=trojan RELEASE_DIR="$TMP_DIR/release" bash "$ROOT/install.sh"
grep -q 'matching server.yml' "$TMP_DIR/expected-failure.log" || fail "missing paired YAML was not explained"
cmp "$TMP_DIR/install/config.json" "$TMP_DIR/partial-config/config.json" || fail "partial pair changed JSON"
[ ! -e "$TMP_DIR/partial-config/server.yml" ] && [ ! -e "$TMP_DIR/partial-config/sing-box" ] ||
  fail "partial pair received unmatched files"
pass 'existing JSON without matching YAML is rejected without guessing its protocol tag'

mkdir "$TMP_DIR/发布 包"
cp "$TMP_DIR/release/"* "$TMP_DIR/发布 包/"
env INSTALL_DIR="$TMP_DIR/install" SYSTEMD_DIR="$TMP_DIR/units" ARCH=amd64 INSTANCE=server \
  RELEASE_DIR="$TMP_DIR/发布 包" bash "$ROOT/install.sh" > "$TMP_DIR/install.log" 2>&1 || fail "Unicode release source"
pass 'local release directory supports spaces and Unicode names'

cp "$TMP_DIR/install/sing-box" "$TMP_DIR/original-core"
printf '\n# existing unit override\n' >> "$TMP_DIR/units/xboard-sb@.service"
cp "$TMP_DIR/units/xboard-sb@.service" "$TMP_DIR/original-unit"
export SMOKE_FAIL_RELOAD=true
expect_failure run_installer
unset SMOKE_FAIL_RELOAD
cmp "$TMP_DIR/original-core" "$TMP_DIR/install/sing-box" || fail "reload failure changed binary"
cmp "$TMP_DIR/original-unit" "$TMP_DIR/units/xboard-sb@.service" || fail "reload failure changed unit"
cmp "$TMP_DIR/original.json" "$TMP_DIR/install/config.json" || fail "reload failure changed config"
pass 'failed daemon reload restores the previous binary and systemd units'

mkdir "$TMP_DIR/legacy"
tar -czf "$TMP_DIR/legacy/sing-box-xboard-amd64.tar.gz" -C "$TMP_DIR/package" sing-box
(cd "$TMP_DIR/legacy" && sha256sum sing-box-xboard-amd64.tar.gz > SHA256SUMS.txt)
expect_failure env INSTALL_DIR="$TMP_DIR/reject-legacy" SYSTEMD_DIR="$TMP_DIR/reject-units" \
  RELEASE_DIR="$TMP_DIR/legacy" ARCH=amd64 bash "$ROOT/install.sh"
[ ! -e "$TMP_DIR/reject-legacy" ] && [ ! -e "$TMP_DIR/reject-units" ] || fail "legacy package modified target"
pass 'legacy release without native templates is rejected before installation'

mkdir "$TMP_DIR/links" "$TMP_DIR/unsafe-release"
ln -s "$TMP_DIR/original.json" "$TMP_DIR/links/LICENSE"
tar -czf "$TMP_DIR/unsafe-release/sing-box-xboard-amd64.tar.gz" -C "$TMP_DIR/links" LICENSE
(cd "$TMP_DIR/unsafe-release" && sha256sum sing-box-xboard-amd64.tar.gz > SHA256SUMS.txt)
expect_failure env INSTALL_DIR="$TMP_DIR/reject-link" SYSTEMD_DIR="$TMP_DIR/reject-units" \
  RELEASE_DIR="$TMP_DIR/unsafe-release" ARCH=amd64 bash "$ROOT/install.sh"
grep -q 'link or non-regular entry' "$TMP_DIR/expected-failure.log" ||
  fail "archive link not rejected before extraction"
tar -czf "$TMP_DIR/unsafe-release/sing-box-xboard-amd64.tar.gz" -C "$TMP_DIR/package" LICENSE LICENSE
(cd "$TMP_DIR/unsafe-release" && sha256sum sing-box-xboard-amd64.tar.gz > SHA256SUMS.txt)
expect_failure env INSTALL_DIR="$TMP_DIR/reject-duplicate" SYSTEMD_DIR="$TMP_DIR/reject-units" \
  RELEASE_DIR="$TMP_DIR/unsafe-release" ARCH=amd64 bash "$ROOT/install.sh"
grep -q 'duplicate package member' "$TMP_DIR/expected-failure.log" || fail "duplicate archive member not rejected"
[ ! -e "$TMP_DIR/reject-link" ] && [ ! -e "$TMP_DIR/reject-duplicate" ] || fail "invalid archive modified target"
pass 'archive links and duplicate members are rejected before extraction'

cp "$TMP_DIR/release/SHA256SUMS.txt" "$TMP_DIR/good-checksums"
printf '%064d  sing-box-xboard-amd64.tar.gz\n' 0 > "$TMP_DIR/release/SHA256SUMS.txt"
expect_failure env INSTALL_DIR="$TMP_DIR/reject-checksum" SYSTEMD_DIR="$TMP_DIR/reject-units" \
  RELEASE_DIR="$TMP_DIR/release" ARCH=amd64 bash "$ROOT/install.sh"
[ ! -e "$TMP_DIR/reject-checksum" ] || fail "bad checksum modified target"
cp "$TMP_DIR/good-checksums" "$TMP_DIR/release/SHA256SUMS.txt"
pass 'checksum mismatch is rejected before installation'

expect_failure bash "$ROOT/install.sh" legacy-product legacy-identity
expect_failure env SMOKE_UID=1000 bash "$ROOT/install.sh"
expect_failure env INSTANCE='../escape' bash "$ROOT/install.sh"
expect_failure env SERVICE_PREFIX='bad prefix' bash "$ROOT/install.sh"
expect_failure env PROTOCOL=unsupported bash "$ROOT/install.sh"
expect_failure env INSTALL_DIR='/tmp/../escape' bash "$ROOT/install.sh"
expect_failure env SHARE=http://configs.example.test bash "$ROOT/sb-auto.sh" backend.json backend.yml
expect_failure env SHARE=https://configs.example.test bash "$ROOT/sb-auto.sh" ../backend.json backend.yml
pass 'legacy identity arguments and unsafe paths or URLs are rejected'

cp "$TMP_DIR/install/config.json" "$SMOKE_SHARE/backend.json"
cp "$TMP_DIR/install/server.yml" "$SMOKE_SHARE/backend.yml"
run_auto || { cat "$TMP_DIR/auto.log" >&2; fail "initial configuration fetch"; }
grep -q '^enable --now xboard-sbc@demo.service$' "$SMOKE_LOG" || fail "new instance not enabled"
[ "$(stat -c %a "$TMP_DIR/install/demo.json")" = 600 ] || fail "downloaded JSON permissions"
[ "$(stat -c %a "$TMP_DIR/install/demo.yml")" = 600 ] || fail "downloaded YAML permissions"
pass 'configuration fetch checks real core configuration before enabling the independent service'

export SMOKE_ACTIVE=true
printf '\n# update from configuration host\n' >> "$SMOKE_SHARE/backend.yml"
run_auto || { cat "$TMP_DIR/auto.log" >&2; fail "active instance update"; }
grep -q '^restart xboard-sbc@demo.service$' "$SMOKE_LOG" || fail "active instance was not restarted"
cmp "$SMOKE_SHARE/backend.yml" "$TMP_DIR/install/demo.yml" || fail "updated YAML not installed"
cp "$TMP_DIR/install/demo.json" "$TMP_DIR/before-auto.json"
cp "$TMP_DIR/install/demo.yml" "$TMP_DIR/before-auto.yml"
pass 'active instance update restarts the service and creates private backups'

export SMOKE_FAIL_DOWNLOAD=backend.yml
expect_failure run_auto
unset SMOKE_FAIL_DOWNLOAD
cmp "$TMP_DIR/before-auto.json" "$TMP_DIR/install/demo.json" || fail "partial download changed JSON"
cmp "$TMP_DIR/before-auto.yml" "$TMP_DIR/install/demo.yml" || fail "partial download changed YAML"
cp "$SMOKE_SHARE/backend.json" "$TMP_DIR/good-auto.json"
printf '{invalid json\n' > "$SMOKE_SHARE/backend.json"
expect_failure run_auto
cmp "$TMP_DIR/before-auto.json" "$TMP_DIR/install/demo.json" || fail "invalid download changed JSON"
cmp "$TMP_DIR/before-auto.yml" "$TMP_DIR/install/demo.yml" || fail "invalid download changed YAML"
cp "$TMP_DIR/good-auto.json" "$SMOKE_SHARE/backend.json"
pass 'failed download or invalid configuration leaves both previous files intact'

printf '\n# should be rolled back\n' >> "$SMOKE_SHARE/backend.yml"
export SMOKE_FAIL_SERVICE=true
expect_failure run_auto
unset SMOKE_FAIL_SERVICE
cmp "$TMP_DIR/before-auto.json" "$TMP_DIR/install/demo.json" || fail "failed restart did not restore JSON"
cmp "$TMP_DIR/before-auto.yml" "$TMP_DIR/install/demo.yml" || fail "failed restart did not restore YAML"
pass 'failed service restart restores the previous configuration'

export SMOKE_ACTIVE=false SMOKE_ENABLED=false SMOKE_FAIL_SERVICE=true
expect_failure run_auto
unset SMOKE_FAIL_SERVICE
cmp "$TMP_DIR/before-auto.json" "$TMP_DIR/install/demo.json" || fail "failed initial start changed JSON"
cmp "$TMP_DIR/before-auto.yml" "$TMP_DIR/install/demo.yml" || fail "failed initial start changed YAML"
grep -q '^disable xboard-sbc@demo.service$' "$SMOKE_LOG" || fail "failed enable did not restore disabled state"
pass 'failed initial enable restores files and the previously disabled service state'

printf 'All installer smoke tests passed; no real service or network operation was performed.\n'
