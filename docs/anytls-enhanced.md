# AnyTLS TCP 双模式兼容

服务端与出站客户端的 `type` 均保持 `anytls`。新增布尔配置 `enhanced_padding`，默认 `false`。
服务端可以设为 `true` 同时接受公版客户端和启用增强的自编译客户端；公版客户端无需修改。

服务端示例（放在 `inbounds`）：

```json
{
  "type": "anytls",
  "tag": "anytls-in",
  "listen": "::",
  "listen_port": 443,
  "users": [{"name": "example", "password": "replace-with-your-password"}],
  "enhanced_padding": true,
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/sing-box/server.crt",
    "key_path": "/etc/sing-box/server.key"
  }
}
```

自编译客户端示例（放在 `outbounds`）：

```json
{
  "type": "anytls",
  "tag": "anytls-out",
  "server": "node.example.com",
  "server_port": 443,
  "password": "replace-with-your-password",
  "enhanced_padding": true,
  "session_health": {
    "enabled": true,
    "idle_threshold": "15s",
    "timeout": "3s",
    "max_idle_sessions": 32
  },
  "tls": {"enabled": true, "server_name": "node.example.com"}
}
```

## 协商与第三方兼容

传输保持原生 TCP + TLS，不新增 UDP、QUIC 或 HTTP 外层。认证布局、命令号、基础协议版本 `v=2` 均保留。
新客户端在加密后的 Settings 中声明 `x-padding=2`，只有服务端启用并确认后才开始会话增强。
新服务端仍接受旧自有客户端的 `x-padding=1`；新客户端可以接受旧扩展确认，或在没有确认时使用标准会话行为。
公版客户端不声明扩展，因此继续走标准分支。旧自有服务端若只接受 `1`，收到新客户端的 `2` 时会回到标准分支。

客户端启用增强且当前使用上游默认 padding scheme 时，认证 padding 从固定 30 字节改为每连接随机 32–256 字节。
这仍是标准 AnyTLS 认证格式，无须服务端先确认；即使服务器没有启用增强，也会出现这一变化。
收到服务器下发的自定义 padding scheme 后，后续新连接尊重该方案；首次连接不能预先知道服务器的自定义方案。
认证读取支持任意 TCP/TLS 分片，padding 长度上限是协议规定的 65535 字节；调用者设置的连接 deadline 保持有效。

## 分块与开销

原版客户端早期 padding scheme 完整保留，修复旧增强版本协商后跳过它的问题。
客户端早期方案结束后，以及协商完成的服务端业务发送，才启用额外会话策略。
`x-padding=2` 为每个发送方向选择 8、12 或 16 KiB 的分块上限，并在大块写入时改变实际分块大小；
完整 AnyTLS 帧内的字节保持连续，控制帧可以在完整帧之间优先发送。
策略不加入人为等待、不发送空闲填充、不改 TLS ClientHello，也不声称模拟浏览器。

开销分开计算，不能将下面的 5% 当作链路总开销保证：

- 认证：默认方案下每条新连接比原版多 2–226 字节。
- 原版早期 padding：由原有 `padding_scheme` 决定，不计入增强预算。
- 后续额外 padding：使用标准 `cmdWaste`，连同其 7 字节帧头累计不超过参与增强的业务字节的 5%，
  每个方向、每个会话累计最多 64 KiB，单次上限由会话策略决定（最多 256 字节）。
- 预算耗尽后停止额外填充，分块策略继续有效。认证、TLS record、TCP/IP 头和重传另计。
- PSH 保持原版 65535 字节载荷上限，不因增强额外缩小；超长应用写入按协议长度安全分帧。

## 空闲连接健康检查

`session_health` 仅是客户端参数。省略时，`enhanced_padding=true` 自动启用默认健康检查；
`enhanced_padding=false` 保持原版池策略。显式 `{"enabled": false}` 可以关闭健康检查。
启用后的默认值为：空闲阈值 `15s`、探测超时 `3s`、最多保留 `32` 个空闲会话。

只在准备复用且空闲超过阈值时，向已确认支持 v2 的对端发送标准 HeartRequest；不做周期心跳。
最近使用的会话不增加探测 RTT，v1 或版本未知的对端不会收到探测。
探测失败关闭旧连接并重新拨号，遵守调用方取消；每次拨号最多等待一次旧连接探测。
`max_idle_sessions` 限制空闲会话，不限制正在使用的连接；`min_idle_session` 不得大于此上限。
负数时长或容量会报配置错误。不会自动重放业务数据，也不会无损迁移已建立连接。

## 验证和隐私边界

独立上游 `sing-anytls v0.0.11` 双向互通、真实 TLS 四种开关组合、分片认证、短写、超长载荷、
填充预算、控制优先和连接池并发都有自动化测试。测试命令：

```sh
cd third_party/sing-anytls
go test -race ./... -count=1 -timeout=180s
go test -run TestTLSRecordObservations -v -count=3
```

后一个测试在本机 TCP/TLS 下记录双向 TLS record 长度、字节开销、echo 延迟和吞吐；
它验证整形实际进入 TLS 记录层，不是网卡抓包，也不代表广域网吞吐或真实识别率。
应用 Write、TLS record、TCP 数据包的边界不同，不能混用统计。

数据内容保密仍依赖 TLS；服务器 IP、业务时序、账户和日志关联不会因此隐藏。
目前没有独立分类数据集或真实网络识别率实验，不能宣称更难识别、匿名性提高或无法封锁。
新增策略默认关闭。原版客户端保持可用，不会自动获得新客户端行为。

本地依赖基于 `github.com/anytls/sing-anytls v0.0.11`，位于 `third_party/sing-anytls`，保留其许可证。
构建时需携带该目录。第三方 AnyTLS 的具体客户端版本仍需单独进行互通测试。
