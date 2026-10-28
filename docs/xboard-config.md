# XBoard / XiaoV2Board 安装与配置

安装包提供 **原版 Trojan、原版 AnyTLS、AnyTLS Native** 三套配置，使用与原后端相似的双文件布局：`config.json` 配置内核，`server.yml` 配置面板节点。安装命令不带产品名、用户名、授权码或身份 UUID；面板的 `ApiKey` 仍是调用 UniProxy API 必需的凭据。

## 版本状态与安装

首个包含新协议和配套配置的安装版本为 `v1.14.3-xboard-native.1`。Linux 服务器需提供 systemd，以下安装、服务命令均以 root 执行。

```bash
VERSION=v1.14.3-xboard-native.1 bash <(curl -fLSs https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/v1.14.3-xboard-native.1/install.sh)
```

上面的命令固定脚本与内核版本。下载入口为本项目 GitHub，不需要原 nyafw 的身份参数；旧的 `v1.14.3-xboard-anytls.1` 不包含新协议。

首次安装通过 `PROTOCOL` 选择默认入口，省略时使用 `anytls-native`：

| `PROTOCOL` | 本地协议 / 默认标签 | TLS 与客户端 |
| --- | --- | --- |
| `trojan` | 原版 Trojan / `trojan-1` | 必须提供 TLS 证书；标准 Trojan 客户端 |
| `anytls` | 原版 AnyTLS / `anytls-1` | 必须提供 TLS 证书；标准 AnyTLS 客户端，保持原版 padding |
| `anytls-native` | 自有 Native / `native-1` | 自动生成原生密钥；自有客户端，可选外层 TLS |

安装原版 Trojan，例如：

```bash
PROTOCOL=trojan TLS_CERT_FILE=/etc/ssl/my-node/fullchain.pem TLS_KEY_FILE=/etc/ssl/my-node/privkey.pem \
  VERSION=v1.14.3-xboard-native.1 bash <(curl -fLSs https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/v1.14.3-xboard-native.1/install.sh)
```

安装原版 AnyTLS，把 `PROTOCOL=trojan` 改为 `PROTOCOL=anytls`。证书文件必须已存在，路径使用不含空格的绝对路径；证书需覆盖客户端的 `server_name`。安装器引用这些文件，不申请证书，也不会覆盖已有证书。客户端应正常验证证书；自签证书须另行导入客户端信任。

三套模板都会安装到 `/opt/sing-box-xboard/examples/`。一次初始安装只创建一个入口，默认 TCP 443，避免端口冲突。需要并行运行时按下文建立独立实例，分别设置端口或监听 IP。三套默认配置均不转发 UDP。

也可将交付目录上传至服务器，目录中需有 `install.sh`、对应架构的 `sing-box-xboard-amd64.tar.gz` 或 `sing-box-xboard-arm64.tar.gz`，以及 `SHA256SUMS.txt`，在该目录执行：

```bash
RELEASE_DIR="$PWD" bash ./install.sh
```

安装器会校验压缩包哈希，将程序装到 `/opt/sing-box-xboard`。首次安装生成所选协议的双文件配置，权限为 `600`；Native 另外生成服务器密钥，私钥写入 `config.json`，公钥保存到 `server-public-key.txt`。再次安装保留已有配置、密钥和证书；`PROTOCOL` 不会替换已有入口。默认不启动服务，先填写面板参数。已有旧协议实例不会自动改成新协议；迁移时按新模板另建独立实例，并配置所需密钥或证书。

升级后，检查配置并重启正在使用的实例，让它加载新内核。安装器保留原有运行状态；`enable --now` 不会替已经运行的实例完成重启。

默认文件与服务：

| 位置或名称 | 用途 |
| --- | --- |
| `/opt/sing-box-xboard/sing-box` | 客户端与服务端共用内核 |
| `/opt/sing-box-xboard/config.json` | 入站、私钥、监听端口、DNS、路由与出站 |
| `/opt/sing-box-xboard/server.yml` | 面板 URL、API token、节点 ID 与同步间隔 |
| `/opt/sing-box-xboard/server-public-key.txt` | 仅 Native：分发给自有客户端的服务器公钥 |
| `/opt/sing-box-xboard/examples/` | 三种协议的 JSON/YAML 模板，均无真实凭据 |
| `xboard-sb@server.service` | 合并 `config.json` 与 `server.yml` 的默认实例 |
| `xboard-sbc@实例.service` | 合并 `实例.json` 与 `实例.yml` 的独立实例 |

可在安装时设置 `INSTALL_DIR`、`SERVICE_PREFIX`、`INSTANCE`。下文命令使用默认值；改名后同步调整路径和服务名。

## 填写面板配置

修改 `/opt/sing-box-xboard/server.yml`。以下以 Native 为例；标准协议安装器会生成对应 `PanelTag` 和 `NodeType`：

```yaml
DisableAccessLog: false

Nodes:
  - Type: UniProxy
    UpdateInterval: "60s"
    ApiConfig:
      PanelTag: "native-1"
      ApiHost: "https://panel.example.com"
      ApiKey: "replace-with-server-token"
      NodeType: anytls
      NodeID: 1
      Timeout: 15
```

- `ApiHost`、`ApiKey`、`NodeID` 填面板实际值，不能保留示例占位内容。
- `PanelTag` 必须与 `config.json` 中入站的 `tag` 一致：Native 默认 `native-1`，原版 AnyTLS 为 `anytls-1`，Trojan 为 `trojan-1`。
- **`NodeType` 是该节点在面板 API 中的实际类型。** 示例使用 `anytls`；若现有面板节点是其他受支持类型，按其实际类型填写。它不决定本地协议，不能因为本地用了 `anytls-native` 就随意把面板类型也改成这个名称。
- `UpdateInterval` 是默认拉取用户、上报流量间隔，面板返回的间隔可以覆盖它。
- 日志默认保留，便于定位同步失败。`DisableAccessLog: true` 在兼容转换中会禁用整个日志输出，并非只屏蔽访问日志。

服务端从面板取得用户 UUID，并将其用作客户端的 `password`。用户新增、删除或凭据变更由同步接口处理，`config.json` 的 `users: []` 无需人工维护。流量统计绑定到对应面板用户；没有额外实现原后端的用户限速或 IP 数量限制。

`config.json` 默认监听 TCP 443，使用本地 DNS 和直连出站。Native 的 `private_key` 由安装器生成，不能直接使用源码模板中的 `__SERVER_PRIVATE_KEY__`；标准协议模板的证书占位符也须替换为实际路径。入站端口以本地配置为准，不会自动随面板端口变更。Native 未填写 `padding` 时使用协议默认预算；原版 AnyTLS 使用原版 padding，不自动启用私有增强。

## 检查与运行

```bash
cd /opt/sing-box-xboard
./sing-box check -c config.json -c server.yml
systemctl enable --now xboard-sb@server.service
systemctl status xboard-sb@server.service --no-pager
journalctl -u xboard-sb@server.service -f
```

`check` 校验配置与本地构造，不验证面板 token 是否有效。启动后应在日志中看到用户同步成功；同步失败时先检查面板 URL、节点类型、节点 ID 和 token。云防火墙及主机防火墙需允许监听的 TCP 端口。

服务使用 `Type=simple`，启动命令返回成功后仍需通过 `status` 和日志确认运行情况，例如端口是否被其他程序占用。

修改配置后先重新执行 `check`，再重启：

```bash
systemctl restart xboard-sb@server.service
```

停止服务使用 `systemctl stop xboard-sb@server.service`；取消开机启动并停止使用 `systemctl disable --now xboard-sb@server.service`。

## 自有客户端

原版 Trojan 和 AnyTLS 使用各自的标准客户端：服务器地址、监听端口、匹配证书的 `server_name`，密码为面板用户 UUID。它们不使用 Native 的 `server_public_key`。面板订阅中下发的地址、端口、TLS 参数须与本地配置一致。

客户端需使用本项目包含 `anytls-native` 的内核。读取服务器的 `server-public-key.txt`，通过可信渠道交给客户端；`password` 填对应面板用户的 UUID。客户端出站的核心字段如下，需并入完整客户端配置：

```json
{
  "type": "anytls-native",
  "tag": "proxy",
  "server": "your-server.example.com",
  "server_port": 443,
  "server_public_key": "填写生成的服务器公钥",
  "password": "填写面板用户UUID",
  "domain_resolver": "local-dns"
}
```

示例中的域名、公钥和 UUID 均需替换；完整客户端还需配置 `local-dns`、本地入口及路由，见 [AnyTLS Native 使用说明](anytls-native.md)。如果直接填写服务器 IP，可省略 `domain_resolver`。

**旧面板的 AnyTLS/VLESS 等订阅不会自动变成新协议配置。** 面板在这里提供用户及流量接口；自有客户端或订阅转换层仍须显式生成 `type: anytls-native` 并下发正确公钥。公版 AnyTLS 客户端不能连接这个入口。

## 可选外层 TLS

本节仅针对 Native；原版 Trojan 和 AnyTLS 的安装模板已要求 TLS。Native 默认不启用外层 TLS，启用时，在 `config.json` 的 `anytls-native` 入站中增加：

```json
"tls": {
  "enabled": true,
  "certificate_path": "/opt/sing-box-xboard/server.crt",
  "key_path": "/opt/sing-box-xboard/server.key"
}
```

证书和私钥需提前放到对应路径。在客户端相应出站中增加：

```json
"tls": {
  "enabled": true,
  "server_name": "your-server.example.com"
}
```

证书需覆盖 `server_name`。自签证书须在客户端 TLS 配置中增加客户端本地受信任证书的 `certificate_path`；本协议不接受 `insecure: true`。两端的外层 TLS 开关必须一致，服务器的原生 `private_key` 与用户认证配置仍需保留。

## 多实例与远程配置

共享配置实例 `xboard-sb@a` 读取 `/opt/sing-box-xboard/config.json` 与 `/opt/sing-box-xboard/a.yml`；独立实例 `xboard-sbc@a` 读取同目录下的 `a.json` 与 `a.yml`。不要同时启动监听同一 IP、同一端口的实例；每个独立实例需配置自己的监听端口或 IP，面板标签也要与该实例入站匹配。按需为独立实例生成自己的密钥。

独立实例启动前检查：

```bash
cd /opt/sing-box-xboard
./sing-box check -c a.json -c a.yml
systemctl enable --now xboard-sbc@a.service
```

`sb-auto.sh` 保留原来的从配置服务器下载双文件并启动独立实例的用法：

```bash
export SHARE=https://config.example.com/airport
export INSTANCE=a
bash <(curl -fLSs https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/main/sb-auto.sh) config.json server.yml
```

也可以直接执行交付包中的 `sb-auto.sh`。下载后在本机分别保存为 `a.json` 和 `a.yml`，并通过 `xboard-sbc@a.service` 运行。配置服务器应限制访问权限，因为真实配置包含面板 token 和服务器私钥。自动部署前填写真实面板值；不能上传未替换私钥的源码模板当成可运行配置。

## 与原配置的边界

兼容转换实际映射 `Nodes`、`ApiConfig`、`UpdateInterval`、`DisableAccessLog`、`TrafficFactor` 和 `DisableUploadTraffic`。`Nodes` 负责绑定面板服务，不会自动创建入站。

`IPLimit`、`RateLimit`、`ConnectionLimit` 等旧字段目前只接受格式，不会启用对应控制功能。`CertConfig`、`DisableTLS`、`ProxyProtocol`、`AcceptAnyTLS`、`ForceMux` 也不会自动改变本地入站；请按真实支持的内核字段配置，勿照抄后认为已经生效。示例移除了这些无效限制项。

安装过程移除了产品身份验证，面板 API 认证和协议用户认证仍正常执行。Trojan 和 AnyTLS 保持各自原版线格式；Native 仅提供 TCP，复用现有 AnyTLS 串行会话及空闲连接池，不与 Eclipse 或公版 AnyTLS 入口混用。
