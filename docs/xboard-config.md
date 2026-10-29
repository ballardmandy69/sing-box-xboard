# XBoard / XiaoV2Board 安装与配置

本项目用官方 sing-box 源码独立实现后端，参考 nyafw 二进制中确认的节点管理流程；没有修改或分发 nyafw 原二进制。支持原版 **Trojan、AnyTLS** 和自有 **anytls-native**。安装不需要产品账号、授权码或身份 UUID；面板 API token 和协议用户认证仍正常执行。

## 安装

本文对应 `v1.14.3-xboard-native.2`。在 Linux systemd 服务器上以 root 执行：

```bash
VERSION=v1.14.3-xboard-native.2 bash <(curl -fLSs https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/v1.14.3-xboard-native.2/install.sh)
```

安装目录默认 `/opt/sing-box-xboard`。首次安装生成 `config.json` 和 `server.yml`，后者初始为 `Nodes: []`。安装时不选择协议，也不自动启动服务；在 YAML 中添加什么节点，就启动什么节点。同一协议可以添加多个节点。

安装器校验发布包 SHA-256；再次安装保留已有配置、密钥和证书。默认 amd64 使用通用指令集，另有 amd64v3 和 arm64 包。`PROTOCOL` 安装参数已移除。可设置 `INSTALL_DIR`、`SERVICE_PREFIX`、`INSTANCE`；以下命令使用默认值。

离线安装时，将发布包、`SHA256SUMS.txt` 和 `install.sh` 放在同一目录，执行 `RELEASE_DIR="$PWD" bash ./install.sh`。

## 添加节点

`config.json` 保留 DNS、路由和出站设置，默认直连并拒绝 UDP。无需在里面重复声明自动节点。编辑 `/opt/sing-box-xboard/server.yml`：

```yaml
DisableAccessLog: false

Nodes:
  - Type: UniProxy
    ListenIP: "192.0.2.10"
    AutoOutIP: true
    ProxyProtocol: false
    ApiConfig:
      PanelTag: "anytls-1"
      ApiHost: "https://panel.example.com"
      ApiKey: "replace-with-server-token"
      NodeType: Anytls
      NodeID: 171
    CertConfig:
      CertFile: "./z.crt"
      KeyFile: "./z.key"

  - Type: UniProxy
    ListenIP: "192.0.2.11"
    AutoOutIP: true
    ApiConfig:
      PanelTag: "trojan-1"
      ApiHost: "https://panel.example.com"
      ApiKey: "replace-with-server-token"
      NodeType: Trojan
      NodeID: 10
    CertConfig:
      CertFile: "./zq.crt"
      KeyFile: "./zq.key"

  - Type: UniProxy
    Protocol: anytls-native
    ListenIP: "192.0.2.12"
    AutoOutIP: true
    PrivateKeyPath: "./native.key"
    ApiConfig:
      PanelTag: "native-1"
      ApiHost: "https://panel.example.com"
      ApiKey: "replace-with-server-token"
      NodeType: Anytls
      NodeID: 172
```

这些 IP、节点 ID、面板地址和凭据都是占位内容，必须换成实际值。每个 `PanelTag` 唯一。相对证书和密钥路径以服务工作目录 `/opt/sing-box-xboard` 为基准。

| 字段 | 行为 |
| --- | --- |
| `ApiConfig.NodeType` | 面板 API 中的实际节点类型，不区分大小写；不随意填自定义协议名 |
| `Protocol` | 本地协议覆盖；Native 使用 `anytls-native`，标准节点可省略 |
| `ListenIP` | 优先使用此本机 IP；省略则使用面板 `listen_ip`，再省略为 `0.0.0.0` |
| `ListenPort` | 1–65535 覆盖面板端口；省略或 0 使用面板 `server_port` |
| `AutoOutIP` | TCP 直连出站绑定连接实际到达的本机 IP |
| `ProxyProtocol` | 兼容 nyafw YAML 语义：为 true 时接受 PROXY v1/v2，也接受无头部直连 |
| `CertConfig` | 标准 Trojan、AnyTLS 必填证书和私钥；Native 填写后增加外层 TLS |
| `PrivateKey` / `PrivateKeyPath` | Native 原生服务器私钥，二选一；后者读取只含私钥字符串的文件 |
| `StaticInbound` | true 时必须已有同标签 JSON 入站，面板仅管理用户和流量 |
| `UpdateInterval` | 默认拉取和上报间隔，如 `"60s"`；面板的同步间隔可覆盖 |

普通直连节点可省略 `ProxyProtocol`。启用后，PROXY 声明的客户端地址会被信任，应在可信转发链路或防火墙限制的入口使用。原生 JSON 的 `proxy_protocol` 仍要求头部，只有同时设置 `proxy_protocol_accept_no_header` 才允许无头部直连。PROXY 中的目标地址不能替换 AutoOutIP 使用的真实本机地址。

多 IP 同端口需要各节点绑定不同的本机 IP。例如两节点均使用 443，分别监听 `.10`、`.11`，出站也分别绑定 `.10`、`.11`。IP 必须实际配置在服务器上；云平台若通过 NAT 映射公网 IP，最终公网出口还取决于平台 NAT。IPv4 入站不能静默改用 IPv6 出站；绑定失败会报错，不回退到另一节点 IP。此保证适用于默认直连出站，额外代理链的最终公网出口由下一跳决定。

## Native 密钥与客户端

只在添加 Native 节点时生成密钥：

```bash
cd /opt/sing-box-xboard
./sing-box generate anytls-native-keypair
```

将输出的 `PrivateKey` 值填入该节点的 `PrivateKey`，或写入 `native.key` 并设置权限 `600`；将 `PublicKey` 通过可信渠道交给自有客户端。不要将私钥发给客户端。`check` 不会自动创建或覆盖密钥。

客户端出站核心字段：

```json
{
  "type": "anytls-native",
  "server": "your-server.example.com",
  "server_port": 443,
  "server_public_key": "填写服务器公钥",
  "password": "填写面板用户UUID",
  "domain_resolver": "local-dns"
}
```

完整客户端仍需本地入口、DNS 和路由，见 [Native 使用说明](anytls-native.md)。Native 默认无外层 TLS；服务端配置 `CertConfig` 后，客户端也必须启用 TLS 并验证证书。标准 Trojan、AnyTLS 使用对应公版客户端及正常证书验证，不使用 Native 公钥。

用户 UUID 来自面板并作为协议密码，用户列表、删除和流量上报由后端同步。面板的 AnyTLS 订阅不会自动变成 Native 配置，自有客户端或订阅转换层必须下发 `anytls-native` 类型和公钥。

## 检查、启动与更新

```bash
cd /opt/sing-box-xboard
./sing-box check -c config.json -s server.yml
systemctl enable --now xboard-sb@server.service
systemctl status xboard-sb@server.service --no-pager
journalctl -u xboard-sb@server.service -f
```

自动节点的 `check` 会访问面板获取节点配置，并检查证书、密钥和参数；不绑定监听端口，不能代替运行时检查。空 `Nodes` 不访问面板。启动后仍应确认服务状态和用户同步日志。主机及云防火墙需放行相应 TCP 端口。

面板配置变化时后端重新核对自动节点设置。切换到不同端口时先启动候选入口，成功后关闭旧入口；同端口重建会短暂中断连接，失败时尝试恢复旧配置，回滚失败会明确报错。配置更新失败期间仍继续同步用户撤销。已有手工 JSON 入站保持手工管理。修改本地 YAML、增删节点或替换密钥后，先执行 `check`，再重启：

```bash
systemctl restart xboard-sb@server.service
```

升级内核后也需重启运行中的实例；安装器不擅自中断现有服务。

`xboard-sb@a.service` 读取共享 `config.json` 与 `a.yml`；`xboard-sbc@a.service` 读取独立 `a.json` 与 `a.yml`。不要让两个实例绑定同一 IP 和端口。`examples/` 保留通用模板与三种协议的手工 JSON/YAML 模板；手工模式的 `PanelTag` 必须与入站 `tag` 相同。

先按上文安装本版本内核，再使用 `sb-auto.sh` 部署远程配置：

```bash
export SHARE=https://config.example.com/airport
export INSTANCE=a
bash <(curl -fLSs https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/v1.14.3-xboard-native.2/sb-auto.sh) config.json server.yml
```

下载后校验配置，保存为 `a.json` / `a.yml`，启动独立实例；失败恢复旧配置并尝试恢复原服务状态，恢复操作失败会明确提示。证书、私钥文件应提前存在，配置下载服务需保护其中的 API token。

## 已发布 v1.14.3-xboard-native.2 的兼容边界

已对齐此处三种协议的节点布局、面板用户与流量同步、监听覆盖、证书、PROXY protocol 和 AutoOutIP；不是 nyafw 全功能复刻。自动节点暂限普通 TCP、标准 TLS，未实现 WebSocket、gRPC、Reality 或 `MultiApiConfig`。

旧全局 `IPLimit`、`RateLimit`、`ConnectionLimit`、`HotUserCacheSec`、`ConnectionCleanupIntervalSec` 等兼容字段不会启用原后端对应限制；面板 `speed_limit`、`device_limit` 也尚未执行。不要将它们当作已经生效的限速或限设备保障。`DisableAccessLog: true` 目前会禁用整个日志输出，建议保留 false。`AcceptAnyTLS`、`ForceMux`、`TLSJson` 等原后端专有扩展未接入。

Native 仅支持 TCP，复用 AnyTLS 串行会话和空闲连接池；没有新增并发多流 mux 或冷连接 0-RTT。不宣称私有协议无法被识别，也不保证解决公网 IP 的 TCP 阻断。

## 完整复现开发分支

`codex/nyafw-full-parity` 中的当前源码已进一步接入下列能力，尚未发布对应版本；
上文固定版本的安装命令仍安装 v2，不能把开发分支选项当作 v2 已有功能。

- TCP VMess、VLESS、Shadowsocks 和 SS2022 的自动面板节点；支持的 WS、HTTPUpgrade、gRPC 组合有真实客户端测试。
- UniProxy `MultiApiConfig` 聚合、全局与用户限速、IP/连接数/请求配额、ReportAlive。
- 热用户认证候选缓存、空闲连接清理、原版 AccessLog/SbApi；访问日志开关不会关闭运行错误日志。
- MemoryGuard 按系统可用内存关闭选中来源 IP 的连接，并按配置时长拒绝其新 TCP 连接。
- 旧 DNS/FakeIP、GeoIP/Geosite、ip_on_demand、旧入站嗅探与域名策略。
- `ShadowsocksObfsMu` HTTP 前导机制。它不等于 WebSocket：101 后直接传输 SS 密文，没有 WS 帧。

当前源码的 `check` 不访问面板；运行后先同步用户、再同步节点配置，成功后才开放监听。
首次同步失败会退避重试。安装烟测覆盖配置离线检查与真实节点进程启动两部分。

开发分支可在 `server.yml` 根级配置内存保护；省略时不启用：

```yaml
MemoryGuard:
  Enabled: true
  CheckInterval: 5s
  BlockDuration: 60s
  Steps:
    - AvailableMemoryPercent: 10
      BlockPercentPerCheck: 2
      MaxBlockedPercent: 10
```

这里统计 Linux `/proc/meminfo` 的系统内存，不是进程堆或容器的内存配额。
比例按同一次内存压力事件首次出现连接时的来源 IP 数计算；连接关闭后基数保持不变。
内存恢复只重置压力事件，尚未到期的 IP 封禁继续有效。

所有代理 UDP 协议和 UDP 转发均排除，内部 DNS 保留配置语义。
仍有其他面板、私有扩展组合、规则和资源管理功能未完成；详细进度及证据限制见
[完整复现清单](nyafw-parity.md)。完成原版运行对照前，不称为完整兼容版。
