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
panel_pid=''
core_pid=''
cleanup() {
  if [ -n "$core_pid" ]; then
    kill "$core_pid" 2>/dev/null || true
    wait "$core_pid" 2>/dev/null || true
  fi
  if [ -n "$panel_pid" ]; then
    kill "$panel_pid" 2>/dev/null || true
    wait "$panel_pid" 2>/dev/null || true
  fi
  rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT
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
    INSTANCE=server SERVICE_PREFIX=xboard- RELEASE_DIR="$TMP_DIR/release" \
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

command -v openssl >/dev/null 2>&1 || fail "openssl is required for real TLS configuration tests"
run_installer || { cat "$TMP_DIR/install.log" >&2; fail "fresh install"; }
[ -x "$TMP_DIR/install/sing-box" ] || fail "missing installed core"
[ ! -e "$TMP_DIR/install/server-public-key.txt" ] || fail "installer generated an unsolicited native key pair"
for name in zq.key zq.crt zq.pem; do
  [ -s "$TMP_DIR/install/$name" ] || fail "missing initial TLS file $name"
  [ "$(stat -c %a "$TMP_DIR/install/$name")" = 600 ] || fail "TLS file permissions: $name"
done
openssl pkey -in "$TMP_DIR/install/zq.key" -pubout > "$TMP_DIR/default-key.pub"
openssl x509 -in "$TMP_DIR/install/zq.crt" -pubkey -noout > "$TMP_DIR/default-cert.pub"
cmp "$TMP_DIR/default-key.pub" "$TMP_DIR/default-cert.pub" || fail "initial TLS key and certificate differ"
openssl pkey -in "$TMP_DIR/install/zq.key" -text -noout > "$TMP_DIR/default-key-info"
grep -q 'prime256v1' "$TMP_DIR/default-key-info" || fail "initial TLS key is not P-256"
[ "$(openssl x509 -in "$TMP_DIR/install/zq.crt" -subject -noout -nameopt RFC2253)" = 'subject=' ] ||
  fail "initial TLS certificate subject differs from the sample"
openssl x509 -in "$TMP_DIR/install/zq.crt" -checkend 31449600 -noout > /dev/null ||
  fail "initial TLS validity is shorter than 364 days"
if openssl x509 -in "$TMP_DIR/install/zq.crt" -checkend 31622400 -noout > /dev/null; then
  fail "initial TLS validity exceeds 366 days"
fi
cat "$TMP_DIR/install/zq.crt" "$TMP_DIR/install/zq.key" > "$TMP_DIR/default-bundle.pem"
cmp "$TMP_DIR/default-bundle.pem" "$TMP_DIR/install/zq.pem" || fail "TLS bundle order differs"
sha256sum "$TMP_DIR/install/zq.key" "$TMP_DIR/install/zq.crt" "$TMP_DIR/install/zq.pem" \
  > "$TMP_DIR/default-certificate-before.sha256"
cmp "$ROOT/config.xboard.json" "$TMP_DIR/install/config.json" || fail "generic JSON template changed"
cmp "$ROOT/server.xboard.yml" "$TMP_DIR/install/server.yml" || fail "generic YAML template changed"
grep -Eq '"inbounds"[[:space:]]*:[[:space:]]*\[\]' "$TMP_DIR/install/config.json" || fail "unexpected default listener"
grep -Eq '^Nodes:[[:space:]]*\[\]' "$TMP_DIR/install/server.yml" || fail "default Nodes must be empty"
[ "$(stat -c %a "$TMP_DIR/install/config.json")" = 600 ] || fail "config permissions"
[ "$(stat -c %a "$TMP_DIR/install/server.yml")" = 600 ] || fail "YAML permissions"
[ -s "$TMP_DIR/units/xboard-sb@.service" ] && [ -s "$TMP_DIR/units/xboard-sbc@.service" ] || fail "missing units"
grep -Fq -- "-s $TMP_DIR/install/%i.yml" "$TMP_DIR/units/xboard-sb@.service" || fail "shared unit lacks YAML alias"
grep -Fq -- "-s $TMP_DIR/install/%i.yml" "$TMP_DIR/units/xboard-sbc@.service" || fail "independent unit lacks YAML alias"
for protocol in xboard anytls-native anytls trojan; do
  for name in "config.$protocol.json" "server.$protocol.yml"; do
    [ "$(stat -c %a "$TMP_DIR/install/examples/$name")" = 644 ] || fail "missing protected example $name"
  done
done
grep -q '__SERVER_PRIVATE_KEY__' "$TMP_DIR/install/examples/config.anytls-native.json" ||
  fail "example contains generated private key"
! grep -Eq '^(enable|restart|start) ' "$SMOKE_LOG" || fail "installer started a service"
pass 'fresh install creates default P-256 TLS files with empty Nodes, without starting services or contacting a panel'

printf 'log:\n  level: warn\n' > "$TMP_DIR/extra.yml"
"$TMP_DIR/install/sing-box" check -c "$TMP_DIR/install/config.json" \
  -s "$TMP_DIR/install/server.yml" -s "$TMP_DIR/extra.yml" || fail "repeated -s CLI validation"
"$TMP_DIR/install/sing-box" check -c "$TMP_DIR/install/config.json" \
  --server-config "$TMP_DIR/install/server.yml" || fail "long server-config CLI alias"
pass 'real CLI accepts repeated -s and --server-config panel configuration flags'

printf '\n# operator setting retained\n' >> "$TMP_DIR/install/server.yml"
cp "$TMP_DIR/install/config.json" "$TMP_DIR/original.json"
cp "$TMP_DIR/install/server.yml" "$TMP_DIR/original.yml"
run_installer || { cat "$TMP_DIR/install.log" >&2; fail "upgrade"; }
cmp "$TMP_DIR/original.json" "$TMP_DIR/install/config.json" || fail "upgrade changed config"
cmp "$TMP_DIR/original.yml" "$TMP_DIR/install/server.yml" || fail "upgrade changed YAML"
sha256sum -c "$TMP_DIR/default-certificate-before.sha256" > "$TMP_DIR/default-certificate-check.log" ||
  fail "upgrade replaced the initial TLS identity"
pass 'upgrade preserves generic configuration and operator edits'

rm -f -- "$TMP_DIR/install/zq.pem"
run_installer || { cat "$TMP_DIR/install.log" >&2; fail "missing TLS bundle repair"; }
sha256sum -c "$TMP_DIR/default-certificate-before.sha256" > "$TMP_DIR/default-certificate-check.log" ||
  fail "missing bundle repair changed the certificate or private key"
pass 'missing TLS bundle is rebuilt from the existing unchanged certificate and key'

mkdir "$TMP_DIR/partial-tls"
cp "$TMP_DIR/install/zq.key" "$TMP_DIR/partial-tls/zq.key"
expect_failure env INSTALL_DIR="$TMP_DIR/partial-tls" SYSTEMD_DIR="$TMP_DIR/partial-tls-units" \
  ARCH=amd64 RELEASE_DIR="$TMP_DIR/release" bash "$ROOT/install.sh"
cmp "$TMP_DIR/install/zq.key" "$TMP_DIR/partial-tls/zq.key" || fail "incomplete TLS identity was overwritten"
[ ! -e "$TMP_DIR/partial-tls/sing-box" ] || fail "incomplete TLS files allowed partial installation"
pass 'incomplete existing TLS pair is rejected without replacing its private key'

mkdir "$TMP_DIR/invalid-tls-config"
printf '{invalid-json}\n' > "$TMP_DIR/invalid-tls-config/config.json"
cp "$ROOT/server.xboard.yml" "$TMP_DIR/invalid-tls-config/server.yml"
expect_failure env INSTALL_DIR="$TMP_DIR/invalid-tls-config" SYSTEMD_DIR="$TMP_DIR/invalid-tls-units" \
  ARCH=amd64 RELEASE_DIR="$TMP_DIR/release" bash "$ROOT/install.sh"
for name in zq.key zq.crt zq.pem sing-box; do
  [ ! -e "$TMP_DIR/invalid-tls-config/$name" ] || fail "failed check left generated file $name"
done
grep -Fxq '{invalid-json}' "$TMP_DIR/invalid-tls-config/config.json" || fail "failed check changed old JSON"
cmp "$ROOT/server.xboard.yml" "$TMP_DIR/invalid-tls-config/server.yml" || fail "failed check changed old YAML"
pass 'configuration validation failure removes newly generated TLS files and preserves original configuration'

mkdir "$TMP_DIR/default-tls-static"
default_tls_config="$(< "$ROOT/config.trojan.json")"
default_tls_config="${default_tls_config//__TLS_CERT_FILE__/.\/zq.crt}"
default_tls_config="${default_tls_config//__TLS_KEY_FILE__/.\/zq.key}"
printf '%s\n' "$default_tls_config" > "$TMP_DIR/default-tls-static/config.json"
unset default_tls_config
cp "$ROOT/server.xboard.yml" "$TMP_DIR/default-tls-static/server.yml"
env INSTALL_DIR="$TMP_DIR/default-tls-static" SYSTEMD_DIR="$TMP_DIR/default-tls-static-units" \
  ARCH=amd64 RELEASE_DIR="$TMP_DIR/release" bash "$ROOT/install.sh" > "$TMP_DIR/default-tls-static.log" 2>&1 ||
  { cat "$TMP_DIR/default-tls-static.log" >&2; fail "relative default TLS paths"; }
(cd "$TMP_DIR/default-tls-static" && ./sing-box check -c config.json -s server.yml) ||
  fail "generated default TLS files are unusable from the service working directory"
pass 'existing static configuration resolves newly generated relative zq certificate paths during validation'

mkdir "$TMP_DIR/fail-openssl"
printf '#!/usr/bin/env bash\nexit 19\n' > "$TMP_DIR/fail-openssl/openssl"
chmod 0755 "$TMP_DIR/fail-openssl/openssl"
expect_failure env PATH="$TMP_DIR/fail-openssl:$PATH" INSTALL_DIR="$TMP_DIR/failed-certificate" \
  SYSTEMD_DIR="$TMP_DIR/failed-certificate-units" ARCH=amd64 RELEASE_DIR="$TMP_DIR/release" \
  bash "$ROOT/install.sh"
[ ! -e "$TMP_DIR/failed-certificate" ] || fail "certificate generation failure changed the installation"
pass 'certificate generation failure stops before changing the installation'

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$TMP_DIR/tls.key" -out "$TMP_DIR/tls.crt" -days 1 -subj /CN=localhost \
  > "$TMP_DIR/certificate.log" 2>&1
sha256sum "$TMP_DIR/tls.crt" "$TMP_DIR/tls.key" > "$TMP_DIR/certificate-before.sha256"
for protocol in anytls trojan; do
  mkdir "$TMP_DIR/$protocol"
  legacy_config="$(< "$ROOT/config.$protocol.json")"
  legacy_config="${legacy_config//__TLS_CERT_FILE__/$TMP_DIR/tls.crt}"
  legacy_config="${legacy_config//__TLS_KEY_FILE__/$TMP_DIR/tls.key}"
  printf '%s\n' "$legacy_config" > "$TMP_DIR/$protocol/config.json"
  unset legacy_config
  cp "$ROOT/server.xboard.yml" "$TMP_DIR/$protocol/server.yml"
  cp "$TMP_DIR/$protocol/config.json" "$TMP_DIR/$protocol-before.json"
  cp "$TMP_DIR/$protocol/server.yml" "$TMP_DIR/$protocol-before.yml"
  env INSTALL_DIR="$TMP_DIR/$protocol" SYSTEMD_DIR="$TMP_DIR/units-$protocol" \
    ARCH=amd64 INSTANCE=server RELEASE_DIR="$TMP_DIR/release" \
    bash "$ROOT/install.sh" > "$TMP_DIR/$protocol-upgrade.log" 2>&1 ||
    { cat "$TMP_DIR/$protocol-upgrade.log" >&2; fail "$protocol manual configuration upgrade"; }
  cmp "$TMP_DIR/$protocol-before.json" "$TMP_DIR/$protocol/config.json" || fail "$protocol upgrade changed JSON"
  cmp "$TMP_DIR/$protocol-before.yml" "$TMP_DIR/$protocol/server.yml" || fail "$protocol upgrade changed YAML"
  [ ! -e "$TMP_DIR/$protocol/server-public-key.txt" ] || fail "$protocol upgrade generated native public key"
  "$TMP_DIR/$protocol/sing-box" check -c "$TMP_DIR/$protocol/config.json" -s "$TMP_DIR/$protocol/server.yml"
  pass "upgrade preserves manually configured $protocol listeners and existing TLS material"
done
sha256sum -c "$TMP_DIR/certificate-before.sha256" > "$TMP_DIR/certificate-check.log" ||
  fail "installer altered TLS certificate or key"

command -v python3 >/dev/null 2>&1 || fail "python3 is required for the local panel fixture"
cat > "$TMP_DIR/panel.py" <<'PYTHON'
import http.server
import json
import sys
import urllib.parse


class Panel(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path not in ("/api/v1/server/UniProxy/config", "/api/v1/server/UniProxy/user"):
            self.send_error(404)
            return
        if query.get("token") != ["installer-test-token"]:
            self.send_error(401)
            return
        node_id = int(query["node_id"][0])
        protocol = query["node_type"][0]
        if parsed.path.endswith("/user"):
            payload = {"users": [{"id": 1, "uuid": "00000000-0000-4000-8000-000000000001"}]}
        else:
            payload = {"protocol": protocol, "server_port": 24000 + node_id}
        body = json.dumps(payload).encode()
        with open(sys.argv[1], "a", encoding="utf-8") as log:
            log.write(f"{node_id} {protocol}\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Panel)
print(server.server_address[1], flush=True)
server.serve_forever()
PYTHON
coproc PANEL_PROCESS { exec python3 -u "$TMP_DIR/panel.py" "$TMP_DIR/panel-requests.log"; }
panel_pid="$PANEL_PROCESS_PID"
read -r -t 10 panel_port <&"${PANEL_PROCESS[0]}" || fail "local panel fixture did not start"
touch "$TMP_DIR/panel-requests.log"
key_pair="$("$SING_BOX_BINARY" generate anytls-native-keypair)"
native_private_key="$(printf '%s\n' "$key_pair" | sed -n 's/^PrivateKey: //p')"
unset key_pair
combination_index=0
for combination in anytls trojan native anytls,trojan anytls,native trojan,native \
  anytls,trojan,native anytls,anytls,trojan,native; do
  combination_index=$((combination_index + 1))
  combination_dir="$TMP_DIR/combination-$combination_index"
  mkdir "$combination_dir"
  cp "$ROOT/config.xboard.json" "$combination_dir/config.json"
  cp "$TMP_DIR/tls.crt" "$combination_dir/tls.crt"
  cp "$TMP_DIR/tls.key" "$combination_dir/tls.key"
  printf 'DisableAccessLog: false\nNodes:\n' > "$combination_dir/server.yml"
  IFS=, read -r -a protocols <<< "$combination"
  listen_ports=()
  node_index=0
  for protocol in "${protocols[@]}"; do
    node_index=$((node_index + 1))
    node_type="$protocol"
    [ "$protocol" != native ] || node_type=anytls
    listen_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
    listen_ports+=("$listen_port")
    cat >> "$combination_dir/server.yml" <<YAML
  - Type: UniProxy
    ListenIP: "127.0.0.1"
    ListenPort: $listen_port
    ApiConfig:
      PanelTag: "$protocol-$node_index"
      ApiHost: "http://127.0.0.1:$panel_port"
      ApiKey: "installer-test-token"
      NodeType: "$node_type"
      NodeID: $node_index
YAML
    if [ "$protocol" = native ]; then
      printf '%s\n' "$native_private_key" > "$combination_dir/native.key"
      cat >> "$combination_dir/server.yml" <<'YAML'
    Protocol: anytls-native
    PrivateKeyPath: "./native.key"
YAML
    else
      cat >> "$combination_dir/server.yml" <<'YAML'
    CertConfig:
      CertFile: "./tls.crt"
      KeyFile: "./tls.key"
YAML
    fi
  done
  (cd "$combination_dir" && sha256sum config.json server.yml tls.crt tls.key > before.sha256)
  if [ -f "$combination_dir/native.key" ]; then
    (cd "$combination_dir" && sha256sum native.key >> before.sha256)
  fi
  requests_before="$(wc -l < "$TMP_DIR/panel-requests.log")"
  env INSTALL_DIR="$combination_dir" SYSTEMD_DIR="$TMP_DIR/combination-units-$combination_index" \
    ARCH=amd64 INSTANCE=server RELEASE_DIR="$TMP_DIR/release" \
    bash "$ROOT/install.sh" > "$TMP_DIR/combination-$combination_index.log" 2>&1 || {
      cat "$TMP_DIR/combination-$combination_index.log" >&2
      fail "Nodes-driven protocol combination $combination"
    }
  (cd "$combination_dir" && sha256sum -c before.sha256) > "$TMP_DIR/combination-hashes.log" ||
    fail "installation changed existing Nodes or key material for $combination"
  [ "$(wc -l < "$TMP_DIR/panel-requests.log")" = "$requests_before" ] ||
    fail "configuration checking contacted a panel before runtime startup"
  (cd "$combination_dir" && exec ./sing-box run -c config.json -s server.yml) \
    > "$TMP_DIR/combination-runtime-$combination_index.log" 2>&1 &
  core_pid=$!
  if ! python3 - "${listen_ports[@]}" <<'PYTHON'
import socket
import sys
import time

deadline = time.monotonic() + 8
pending = {int(port) for port in sys.argv[1:]}
while pending and time.monotonic() < deadline:
    for port in list(pending):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                pending.remove(port)
        except OSError:
            pass
    if pending:
        time.sleep(0.02)
if pending:
    sys.exit("configured listeners did not start: " + str(sorted(pending)))
PYTHON
  then
    cat "$TMP_DIR/combination-runtime-$combination_index.log" >&2
    fail "runtime failed to activate Nodes for $combination"
  fi
  kill "$core_pid"
  wait "$core_pid" || true
  core_pid=''
done
unset native_private_key
[ "$(wc -l < "$TMP_DIR/panel-requests.log")" -ge 16 ] || fail "node combinations did not query the local panel"
pass 'all protocol combinations preserve files, check offline, and activate real configured listeners at runtime'

mkdir "$TMP_DIR/partial-config"
cp "$TMP_DIR/install/config.json" "$TMP_DIR/partial-config/config.json"
expect_failure env INSTALL_DIR="$TMP_DIR/partial-config" SYSTEMD_DIR="$TMP_DIR/partial-units" \
  ARCH=amd64 INSTANCE=server RELEASE_DIR="$TMP_DIR/release" bash "$ROOT/install.sh"
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
pass 'legacy release without Nodes-driven templates is rejected before installation'

mkdir "$TMP_DIR/legacy-v1"
mapfile -t legacy_members < <(tar -tzf "$TMP_DIR/release/sing-box-xboard-amd64.tar.gz" |
  grep -vE '^(config.xboard.json|server.xboard.yml)$')
tar -czf "$TMP_DIR/legacy-v1/sing-box-xboard-amd64.tar.gz" -C "$TMP_DIR/package" "${legacy_members[@]}"
(cd "$TMP_DIR/legacy-v1" && sha256sum sing-box-xboard-amd64.tar.gz > SHA256SUMS.txt)
expect_failure env INSTALL_DIR="$TMP_DIR/reject-v1" SYSTEMD_DIR="$TMP_DIR/reject-v1-units" \
  RELEASE_DIR="$TMP_DIR/legacy-v1" ARCH=amd64 bash "$ROOT/install.sh"
grep -q 'config.xboard.json' "$TMP_DIR/expected-failure.log" || fail "missing generic template not diagnosed"
[ ! -e "$TMP_DIR/reject-v1" ] && [ ! -e "$TMP_DIR/reject-v1-units" ] || fail "old v1 package changed target"
pass 'complete old thirteen-file package without generic templates is rejected'

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
expect_failure env PROTOCOL=anytls bash "$ROOT/install.sh"
grep -q 'server.yml Nodes' "$TMP_DIR/expected-failure.log" || fail "removed PROTOCOL option lacks migration guidance"
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

printf 'All installer smoke tests passed; no real system service or external network operation was performed.\n'
