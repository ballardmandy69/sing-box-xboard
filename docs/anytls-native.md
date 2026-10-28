# AnyTLS Native

`anytls-native` 是本项目自有的 TCP 代理协议：复用 AnyTLS 会话及空闲连接池，在会话下面使用 X25519、HKDF-SHA256 和 XChaCha20-Poly1305 安全传输，也可再由 TLS 包装。

它参考 Eclipse 的密钥交换与记录加密分层思路，采用本项目自己的协议域和格式，**不兼容 Eclipse、TitanNative 或公版 AnyTLS 的线格式**。服务端与客户端均需使用本项目支持 `anytls-native` 的版本。

## 功能边界

- 首版只承载 TCP 业务，不提供 UDP 或 UoT。
- 保留 AnyTLS 现有的串行会话复用和连接池；不新增支持同一会话同时承载多个活跃业务流的 Mux。
- 新建底层连接需要完成握手；不提供冷连接 0-RTT。
- 密钥交换与业务记录都由安全传输保护。原生模式不依赖 TLS 才获得加密；TLS 模式增加外层 TLS。
- 用户索引认证与目标地址处理保留在 AnyTLS 会话内部；安全传输不复制用户列表、路由地址或面板逻辑。
- 加密、TLS 指纹和 padding 分别影响不同层面；不承诺无法被识别或解决 IP/链路被过滤的问题。

## 生成服务器密钥

在本地执行：

```sh
sing-box generate anytls-native-keypair
```

输出 `PrivateKey` 和 `PublicKey` 两行，均为 32 字节 X25519 密钥的无填充 URL-safe Base64 编码。命令不访问网络。

服务器保存私钥，客户端配置对应公钥。每个用户另有自己的 AnyTLS 认证口令；服务器私钥不作为用户口令分发。服务器公钥应通过可信渠道提供给客户端。

## 生成完整原生模式配置

下面脚本需要 Bash 和 `jq`。它生成一组新的服务器密钥、随机用户口令及两份完整 JSON；输入实际服务器地址，不需要手工替换密钥占位符。`server.json` 留在服务器，`client.json` 放在客户端。

```bash
set -euo pipefail
read -r -p '服务器 IP 或域名: ' server_address
test -n "$server_address"
key_pair="$(sing-box generate anytls-native-keypair)"
private_key="$(printf '%s\n' "$key_pair" | awk '/^PrivateKey: / {print $2}')"
public_key="$(printf '%s\n' "$key_pair" | awk '/^PublicKey: / {print $2}')"
password="$(sing-box generate rand 32 --base64)"
umask 077
jq -n --arg private_key "$private_key" --arg password "$password" '{
  log: {level: "info"},
  dns: {servers: [{type: "local", tag: "system"}]},
  inbounds: [{type: "anytls-native", tag: "native-in", listen: "0.0.0.0",
    listen_port: 443, private_key: $private_key,
    users: [{name: "user-1", password: $password}]}],
  outbounds: [{type: "direct", tag: "direct", domain_resolver: "system"}], route: {final: "direct"}
}' > server.json
jq -n --arg server "$server_address" --arg public_key "$public_key" --arg password "$password" '{
  log: {level: "info"},
  dns: {servers: [{type: "local", tag: "system"}]},
  inbounds: [{type: "mixed", tag: "local-in", listen: "127.0.0.1", listen_port: 1080}],
  outbounds: [{type: "anytls-native", tag: "native", server: $server, server_port: 443,
    server_public_key: $public_key, password: $password,
    domain_resolver: "system"}], route: {final: "native"}
}' > client.json
unset key_pair private_key password
sing-box check -c server.json
sing-box check -c client.json
```

客户端在 `127.0.0.1:1080` 提供 HTTP/SOCKS 入口，只支持 TCP 代理请求。分别在两端使用 `sing-box run -c server.json` 和 `sing-box run -c client.json` 启动；监听 443 需具备相应端口权限。

## 配置字段

入站的 `type` 为 `anytls-native`，使用标准 `listen`、`listen_port`；`private_key` 必填，`users` 中每项使用 `name`、`password`。出站同样使用 `type: anytls-native`，`server`、`server_port`、`server_public_key`、`password` 必填。密钥也接受标准 Base64 编码。

| 字段 | 使用位置 | 默认值及作用 |
| --- | --- | --- |
| `handshake_timeout` | 入站、出站 | `10s`；入站共同限制 TLS、原生握手及完整 AnyTLS 用户认证；出站安全建连和认证写入分别使用该上限，并非统一总时限 |
| `max_pending_handshakes` | 入站 | `128`，直到用户认证完成才释放槽位；占满时拒绝新连接 |
| `padding` | 入站、出站 | 省略使用下述默认预算；`{}` 关闭随机 padding |
| `idle_session_check_interval` | 出站 | 复用 AnyTLS 连接池的空闲检查设置 |
| `idle_session_timeout` | 出站 | 复用 AnyTLS 连接池的空闲淘汰设置 |
| `min_idle_session` | 出站 | 复用 AnyTLS 连接池的最小空闲保留设置 |
| `session_health` | 出站 | 复用现有按需空闲会话健康检查设置 |

### 外层 TLS

两端省略 `tls`，或设置 `tls.enabled: false`，使用原生加密传输。两端均设置 `tls.enabled: true` 时，先建立 TLS，再进行原生安全传输握手。

TLS 入站使用标准 `certificate_path`、`key_path`，出站使用匹配证书的 `server_name`，默认校验证书；自签证书需显式配置受信任的 `certificate` 或 `certificate_path`。不允许 `insecure: true`。两端模式必须一致。TCP Fast Open 不受支持。

以下命令在上面生成的两份配置基础上构造完整 TLS 配置，需要 `openssl`。证书名独立于实际拨号地址；客户端显式信任这张新生成的自签证书。

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server-tls.key -out server-tls.crt -days 30 \
  -subj '/CN=anytls-native.local' -addext 'subjectAltName=DNS:anytls-native.local'
jq '.inbounds[0].tls = {enabled: true, certificate_path: "server-tls.crt",
  key_path: "server-tls.key"}' server.json > server-tls.json
jq '.outbounds[0].tls = {enabled: true, server_name: "anytls-native.local",
  certificate_path: "server-tls.crt"}' client.json > client-tls.json
sing-box check -c server-tls.json
sing-box check -c client-tls.json
```

把 `client-tls.json` 和 `server-tls.crt` 放在客户端同一工作目录，服务器使用 `server-tls.json`、证书及私钥；也可配置绝对证书路径。已有受信任域名证书时，替换成真实证书路径及对应域名，客户端无需额外信任自签证书。

## Padding

安全传输只设置一层有预算的随机 padding，避免再叠加 AnyTLS 旧 padding。

`padding` 的默认值为 `{"max_padding":256,"max_percent":5,"max_total":65536}`：单条记录最多 256 字节随机 padding、累计随机 padding 不超过传输明文字节的 5%、每个发送方向累计随机 padding 最多 65,536 字节。实际设置须同时满足这三个上限；任一值为零表示关闭随机 padding，负值无效。

这里的传输明文包括 AnyTLS 的认证、控制帧及业务数据，并非终端业务净流量。5% 预算只统计随机 padding；固定记录头及认证标签另有开销。记录的最大明文负载为 16,382 字节。随机 padding 会增加带宽和加密工作量，其边界及实际网络表现应分别验证。

## 用户与连接池

服务端预先计算用户口令的 SHA-256 索引，并将完整索引表原子替换；新连接对收到的 32 字节索引进行一次平均 O(1) 查表。该索引在安全传输建立后发送，目标地址随后由 AnyTLS 会话处理，不进入初始密钥交换。

每个出站客户端实例固定自己的服务器和用户口令，独立持有会话池；不同用户不能共用同一客户端池。用户名称用于路由、统计和日志归属，不作为公开握手标识发送。对接面板时，用户更新应通过入站管理接口完成。

入站提供 `ManagedSSMServer` 用户更新和统计包装接口：删除或改密会取消该用户已有会话并关闭底层连接，撤销后尚未分派的缓冲新流也会被拒绝；未改动用户保留连接。完整用户更新校验失败时保留原有效用户表。本轮复用 `SetTracker` 的流量归属/计数接入点，不新增每用户限速实现。

## 安全传输边界

初始客户端请求只包含临时 X25519 公钥、随机盐和加密的版本/随机数，不发送用户口令、口令索引或目标地址。服务器先验证该请求，再生成独立的 32 字节响应随机盐；`response` 派生域绑定客户端请求摘要和服务器随机盐，以免重放同一个客户端请求时重复使用服务器响应的密钥/nonce。

客户端固定服务器静态公钥，服务器再提供经过响应密钥认证的临时公钥。业务密钥结合两次 X25519 共享秘密及握手摘要，通过独立的 `traffic` 域派生；记录长度和内容分别由不同的 XChaCha20-Poly1305 密钥保护，并使用单调序号。错误记录使整条底层连接失效。

用户认证在安全传输建立后继续使用 AnyTLS 认证格式，没有新增 `AUTH_OK` 响应，也没有在密钥交换中重复处理用户。首版不接受冷连接业务数据，捕获初始握手不能直接重放已认证业务。这里描述实现边界，不代表已完成独立密码学审计；随机密文也不具有标准 HTTPS 的语义。

## 验证范围

协议集成测试使用真实注册 JSON 和 localhost TCP，已覆盖原生无 padding、原生默认 padding、TLS 默认 padding 三种模式、冷连接和空闲会话复用、连续及并发请求完整内容校验、错误服务器密钥和未知用户拒绝、UDP/UoT 拒绝、不同用户之间的池和统计归属隔离。

管理与边界测试覆盖统计包装的实际读写字节、改密/删除后撤销旧连接及同一加密记录内的缓冲新流、错误用户更新保留原表、并发更新期间未改用户保持业务、握手槽位占满拒绝、超时释放槽位及关闭服务时回收未认证连接。

```sh
go test ./protocol/anytlsnative ./transport/anytlsnative ./cmd/sing-box -count=1 -timeout=120s
```

这些检查用于验证协议和实现的一致性；本机回环测试不代表跨境吞吐或可识别性。
