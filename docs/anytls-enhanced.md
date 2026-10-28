# AnyTLS 双模式兼容

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
  "tls": {"enabled": true, "server_name": "node.example.com"}
}
```

认证和 TLS 格式不变，协议版本继续声明 `v=2`。增强能力通过 Settings 中的 `x-padding=1` 声明，
服务器只有同时启用时才确认。客户端收到确认前维持标准行为；公版服务器未确认则继续标准模式。
新增协商字段处于 TLS 加密内容内。数据填充使用标准 `cmdWaste`，不引入新的帧命令。

增强填充仅由业务数据触发，不发送定时空闲填充、不加入人为随机等待。额外填充受每连接预算限制；
TLS/TCP 自身开销与已有公版初始 padding 不计入这份增强预算。

此功能改变部分加密后的长度分布，不改变 TLS ClientHello、证书和真实业务的全部统计行为。
目前没有识别率实验数据，不能据此宣称无法识别。抓包分析需区分 TLS record、TCP 分段及应用写入。

本地依赖基于 `github.com/anytls/sing-anytls v0.0.11`，位于 `third_party/sing-anytls`，保留其许可证。
构建时需携带该目录。第三方 AnyTLS 的具体客户端版本仍需单独进行互通测试。
