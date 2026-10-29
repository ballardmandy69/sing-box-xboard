# nyafw 完整非 UDP 功能复现

## 验收目标

用户最终要求：复现 nyafw 完整非 UDP 功能，在此基础上加入自有 `anytls-native` TCP 协议。
排除产品身份/激活授权；保留面板 API 和用户认证。所有 UDP 代理协议及 UDP 转发排除，
因此 Hysteria、TUIC 不作为待补协议；DNS 解析器保留原配置语义。以同一配置和请求下的行为对照作为最终验收，
不能用配置可以解析、源码存在某协议或单元测试通过代替原版互通验证。

已发布的 `v1.14.3-xboard-native.2` 是阶段版本，不满足本文件的完整验收目标。
新增复现工作在 `codex/nyafw-full-parity` 分支进行。

## 证据基线

- 原件：`shabi-elsaqaq-amd64.final`，Linux x86_64 Go ELF。
- SHA-256：`794b7e59588537934e0f19c11294fd8b7d4493d410a969b82d03a4430ac0e1ed`。
- 已恢复 41,737 个函数表条目、3,984 个 Go 结构体的名称/字段类型/配置标签/偏移。
- 新结构体提取结果与此前 19 个 YAML 结构逐字段一致；元数据仍不能单独证明执行语义。
- 使用已有 Ghidra 12.1.4 的 Go ABI 离线反编译，并与机器码数据流核对。
  REA 6.4.0 的当前 Windows provider 不支持本 ELF，这些伪代码不是 REA provider 输出，
  也不是还原的原始源码。静态基线未在本机执行；用户现有运行实例另行核验。
- 本机研究材料在 `E:/singbox后端分析/nyafw-core-integration-study/full-parity/`，
  包含字段矩阵、机器码证据、伪代码和可重跑的提取脚本。

## 功能与验证清单

| 功能组 | 已知状态 | 完成条件 |
| --- | --- | --- |
| 安装、双文件配置、多实例 | 默认 zq 自签证书、双配置和共享/独立实例已接入 | 原版所有非 UDP 配置组合可用，升级/回滚/重启行为对照 |
| 旧版 JSON 配置 | GeoIP/Geosite、旧 DNS/FakeIP、ip_on_demand 与旧入站嗅探已接入 | 数据库、解析、嗅探和路由组合的原实例对照 |
| 面板适配 | UniProxy、OldV2Board、PPanel、SSPanel 已接入 | 每类请求认证、节点/用户/流量/规则与错误处理对照 |
| 多面板聚合 | 四种 provider 已接入首项主面板、按源缓存和流量分账 | 混合来源同 ID 与部分上报失败已测；重复凭据归属、缓存回收及主面板规则仍需原版对照 |
| 用户及统计 | 独立 ID@PanelTag@provider 身份与凭据；按成功快照扣费 | 上报失败保留、并发流量不丢失已测；用户删除时遗留统计仍需对照 |
| 限速与配额 | 双向用户共享限速、活动 IP/连接及请求频率已接线 | 正常与边界单测、race 已过；原版运行性能与极端限速值待对照 |
| 在线上报 | UniProxy ReportAlive 已实现；multi 按原版不报告在线 | 空对象清空在线、独立于流量开关已测；真实面板与 PROXY 来源对照 |
| 协议范围 | Trojan/AnyTLS/Native/VMess/VLESS/SS/SS2022 已有真实 TCP 集成测试 | 其余传输、TLS 与私有扩展组合对照；并非所有组合都已支持 |
| 私有协议扩展 | 同端口组合、ForceMux、ServerPadding、TLS/SNI、MasterPassword、认证失败 IP 封禁已接入 | 原实例组合行为与失败边界仍需对照 |
| 安全/资源管理 | 空闲连接清理、热认证缓存、MemoryGuard、BlockScanner 已接入 | 算法、触发条件、默认值与原实例资源行为对照 |
| 访问日志 | 正常与规则拒绝记录、SbApi gzip 上传、周期违规队列已接入 | 真实接收端及失败重试时序对照 |
| 调试接口 | 已恢复内存、连接榜、pprof、GC 与热用户过期表 | 单元及 race 已过；原版响应与运行资源指标待对照 |
| UDP 排除 | 统一路由、托管流、代理 UDP 监听、QUIC 传输及 UDP 协议配置已加拒绝 | UDP 与 UDP-over-TCP 已有测试；继续审计绕过路径 |

## 已确认并修正的统计差异

`DisableUploadTraffic` 为 true 时，原控制器跳过整个流量报告，在线上报另行控制。
上下行上报字节数分别按 `ceil(rawBytes * TrafficFactor)` 计算。
原控制器先读取不清零的快照，普通面板报告成功后才减去该批原始字节数；
多面板模式只扣除报告成功的用户，失败用户保留。

本分支单面板实现按上述规则修正，新增快照确认机制。确认绑定原计数器，
不会减掉请求期间新增的流量，也不会误减同名用户删除重加后的新计数器。
UniProxy 多面板按来源独立确认，失败来源保留待重试；已有部分失败与重试测试。
不同 provider 使用各自请求和载荷；OldV2Board、PPanel、SSPanel 均有独立转换。

## 本分支已验证的新增行为

- 安装时缺省生成原脚本的 P-256、365 天、空 subject `zq.key` / `zq.crt`，
  `zq.pem` 保持证书后接私钥的顺序。保留已有密钥/证书，部分缺失时拒绝覆盖；
  仅缺合并文件时重建，失败事务回滚新增文件。这修正了原脚本每次删除重建证书的行为。
- 用户身份由 ID、面板标签、provider 组成；更换 UUID 不重建计费身份。
- `MasterPassword` 非空时，自动 Trojan/AnyTLS 使用原始 UUID 与 MasterPassword 直接拼接后的
  MD5 小写十六进制作为协议凭据；组合 AnyTLS 入口的三个子协议统一使用该派生值。
  派生发生在用户表更新或监听配置替换时，原 UUID、统计身份与 SS-obfs Host 保持原值。
  空值保持原凭据，其他协议不使用该设置；实际认证、重复更新、轮换及启动失败回滚已测。
- OldV2Board 使用其原 API 命名空间与嵌套用户字段。SS 的原密码与派生 UUID 分开保存，
  解密使用原密码，obfs Host 使用 UUID；密码轮换与自动监听替换已有真实流量测试。
  `trojantidalab` 请求别名保留，但原用户转换不识别该别名，不能替代 `trojan` 提供有效用户。
- PPanel 使用 `protocol/server_id/secret_key` 查询参数及 `/v1/server/*` 端点。
  保留静态证据确认的流量数组前半零记录、在线上报导出字段名以及状态固定三个 `100` 的格式；
  状态只在后续刷新发送，multi 不发送，失败不阻止配置或用户刷新。
  原配置解析不传递普通 SS2022 server key、SNI、Reality 或 VLESS flow，未擅自扩展这些字段。
  这些异常格式仍须通过原实例验证，不能视为推荐的面板 API 设计。
- OldV2Board/PPanel/SSPanel 网络和响应体读取失败最多重试三次，复用原 POST body，等待支持取消；
  HTTP 状态或 JSON 解析错误不重试。保留原重试语义，也保留响应丢失时 POST 可能重复送达的边界。
- SSPanel 同时发送 `key`、`muKey`，用户、节点、规则各自缓存 ETag。
  两代节点格式、`aliveip` 单数路径、浮点 Mbps 转精确字节速率、在线设备扣减已接入。
  SS 使用面板 passwd，Trojan/AnyTLS 使用规范化 UUID，真实认证和计费链已有测试。
  provider ETag 仍按原顺序更新；本地应用失败的有效配置和用户批次另行保留，
  后续 304 时继续应用，避免证书/端口修复后仍无法恢复。新的不可解析响应不会重放旧候选。
  SSPanel 面板节点 `node_speedlimit` 的最终消费仍未证实，不将其擅自当作节点总限速；
  用户速度与本地 MaxSpeedLimit 的限制则实际生效。
- UniProxy、OldV2Board、PPanel、SSPanel 混合节点保留各自相同数字 ID 的独立身份与请求格式。
  SSPanel 报告失败时只保留该来源的流量，成功来源不重复上报，重试合并新增字节；真实 HTTP 已测。
- 面板规则违规按原样累积重复记录；首次同步不上报，后续在流量/在线报告后、拉用户前发送。
  上传期间持队列锁，失败保留整批，成功清空；multi 报告为空操作并确认清空。
  它不受 `DisableUploadTraffic` 控制，CEL 扫描拒绝不会产生面板违规事件。
- `MaxSpeedLimit` 与面板 `speed_limit` 保持不同单位语义，前者按原版 1024 倍率解析，后者按 Mbps。
  IP/连接数用户非零值覆盖全局；速度受节点或全局上限约束。
- `ReportAlive` 发送去重后的活动 IP，最后连接关闭后发送 `{}` 清除在线信息；
  `DisableUploadTraffic` 不影响它。multi adapter 的在线报告按原版保持无操作。
- 旧 YAML `UpdateInterval < 10s` 回退为 `60s`，每轮结束后再等待；
  面板返回的 `base_config` 两个周期不覆盖旧 YAML 的统一调度。
- multi 仅由生效的 `ApiConfig.Type` 或继承的节点 `Type: multi` 激活；
  `MultiApiConfig` 不自动追加单独的 `ApiConfig`，首项提供节点配置，同名面板标签的后项替换用户来源。
- 大整数限制在服务配置的读取和格式化中保留原始精度，避免通用 JSON 对象中转成浮点数。
- VMess/VLESS 用户表使用同代认证快照，用户热更新不与握手并发读写 map；
  防重放状态不会随用户更新重置，静态同名/空名用户保留兼容处理。
- GeoIP/Geosite 路由读取真实数据库，并恢复缺省文件名、下载地址、出站与重试路径；
  错误文件或缺失条目使加载失败，重载失败保留旧快照。
- 首次用户与配置同步失败按 1/2/4 秒递增、最大 30 秒重试；没有成功配置前不开放监听。
  SS2022 凭据在获知 cipher 后才发现无效时，会重新获取用户并恢复启动。
- 旧 DNS 的共享缓存命中先于规则；每服务器查询策略与 bootstrap 策略分开处理。
  FakeIP 共享地址池、首次 `.3`、回绕 `.2`、范围端点和持久化均有边界测试。
- `ForceVision` 在托管 VLESS 中控制严格 Vision 或兼容普通 flow，并保留原 mux 例外。
  普通真实 TLS/Vision 组合已测；上游 Vision unsafe.Pointer 在 Go checkptr 下不兼容，
  该真实 Vision 测试明确排除 `-race`，不能声称它通过了 race。
- AnyTLS 入站在同一 TCP 连接上按有效认证前缀区分 AnyTLS、VLESS、Trojan，5 秒完成分类。
  `FallbackService` 优先于 `AcceptAnyTLS`；组合只接纳空或精确 `tcp` 传输。
  保留完整协议解析，使用内部认证回调传递快照，不信任外部 metadata 中的用户字段。
  原协议认证表依次发布，本实现共享不可变快照原子发布，避免混合代身份，这是并发改进。
- 全局 SingMux 按特殊 FQDN 接管、不依赖端口；保留 detour 优先和 5 秒握手期限。
  smux/yamux/h2mux、padding、多个逻辑流、子流身份检查及 UDP 拒绝已有真实 Box 测试。
  `ForceMux` 按原边界只拒绝普通 IPv4 Trojan 目标；IPv6 与特殊复用目标不受此门禁限制。
  `ServerPadding` 仅拆分前 19 次 Trojan 下行 Write，不增加随机数据或延迟。
- `TLSJson` 解码为全新的原版 TLS 字段集合，优先于 DisableTLS、CertConfig 与面板 TLS。
  默认 TLS 只使用原 provider 的开关及本地证书/SniPolicy，不补入面板 ServerName 或 ALPN。
  SniPolicy 最后一行是正则，前导精确 `skip-ipv6` 允许真实 IPv6 来源跳过检查；
  IPv4-mapped 地址不会跳过。静态证书握手含空 SNI 的匹配已测，错误正则返回配置错误而非原 panic。
- 自动节点默认开启嗅探及目标覆盖，`DisableSniffing` 同时关闭两者。
  仅原 `v2ray` 类型受本地 `VLESS` 或面板 VLESS 标记影响，显式 `vmess` 不因此改为 VLESS。
  顶层 NodeType 只选择本地入站，ApiConfig.NodeType 仍用于 API；嵌套 PanelTag 优先于顶层缺省值。
- `StaticInbound` 首次也不创建自动监听；没有同名手工入站时仍同步用户、配置、规则和报告。
  静态认证表保持原配置，`users[].name` 匹配面板原 UUID，密码可独立设置。
  `use_panel_tag` 关联目标面板，保留原路由入站名，别名查找按原顺序最多回退两层。
  未设置该开关的既有手工托管模式继续管理认证表。
- Box 中 XBoard 的限额和计费在最终路由逻辑流统一处理；detour 和全局 SingMux 先分发。
  请求频次在旧嗅探前检查；CEL/面板规则后执行连接/IP/速度及统计，再匹配普通路由动作。
  计费包装正确回放嗅探缓存；同一个 Mux 载体的子流分别受限，载体不重复计入。
  跨嗅探阶段固定原请求身份，UUID 轮换导致映射改变时拒绝；已准入日志使用同一 UID 快照。
  双面板不同 ID、独立静态密码、detour、Mux、拒绝释放与轮换均有真实连接及 race 验证。
  普通 SSM 服务与无注册器的嵌入场景保留原 tracker 路径。
- WS 接受 `ws` / `websocket`，默认 2048 字节 Early Data，头名为 `Sec-WebSocket-Protocol`。
  路径按原 URL 规则仅在非空 `ed` 参数时移除它；保留其余查询与解析失败的原串。
  HTTPUpgrade 接受三种原别名；WS/Upgrade 不透传原 builder 未消费的 Headers / Host。
  raw TCP 忽略 networkSettings，UniProxy 忽略未复制的 neko；不额外新增 HTTP/h2 面板传输。
  真实握手覆盖 Early Data、普通 WS、Upgrade 及原路径拒绝边界。
- 空闲连接每 120 秒（或 `ConnectionCleanupIntervalSec`）采样；连续两轮无字节变化才关闭。
  一个 Box 共用注册器，包装连接按底层连接去重，关闭外层释放连接/IP 配额。
- MemoryGuard 读取 `/proc/meminfo` 的系统可用内存，按来源 IP 的登记连接数、流量排序，
  每轮选择一个适用阈值，按压力事件首次非空快照的 IP 基数计算每轮及累计封禁比例。
  关闭已有连接并按 TTL 拒绝新 TCP 连接；内存恢复不会提前解除仍在 TTL 内的封禁。
  默认检查间隔 5 秒、封禁 60 秒、步骤为可用内存 10% / 每轮封禁 2% / 累计最多 10%。
  检查间隔带 ±10% 抖动；回收内存的信号合并，距前次回收完成至少 5 秒。
  TCP 接受后、PROXY 头解析前登记和检查对端；认证路由后更新来源及用户标签。
  同一底层连接替换为外层计数/关闭器，不同底层键的逻辑流仍登记。
  确定性压力模拟、真实 PROXY 头及 Linux race 已通过；未制造真实系统内存耗尽。
  禁用时不校验策略；启用时拒绝可能导致抖动时长溢出的极端间隔，这是本实现的容错边界。
- 用户移除后不立即断开已有流，已有速率桶改为双向 1 B/s；再次加入恢复同一桶。
- `BlockScanner` 按原字段提供 CEL 字符串表达式：返回非空字符串拒绝，求值失败放行。
  按嗅探/显式 DNS → CEL → 面板正则规则 → 普通路由顺序执行；TLS 嗅探时才提取 JA3，
  不因配置扫描器而额外读取流量。拒绝记录分别使用 `gfw:<原因>`、`audit:<规则 ID>`。
  用户身份表先于新认证凭据发布，凭据更新失败回滚；已准入流等待期间用户被删除后拒绝路由，
  关闭原未知身份旁路可能造成的规则竞态，这是有意保留的安全差异。
- VMess/传统 SS 认证先尝试热子集，失败继续完整表，不重复试热项；更新凭据时重建热子集。
  热身份默认 600 秒，流量维护时清理过期并在报告确认前刷新；关闭流量报告也跳过热维护。
  传统 SS 冷匹配可异步回填。SS2022 原始热方法无操作，继续使用身份头定位。
- `ShadowsocksBanIP` 在根级或节点级为 true 即启用，节点 false 不覆盖根级 true。
  VMess 与传统 SS 多用户入口共用进程级来源 IP 计数，第三次候选读取/认证流程全部失败后封禁；
  失败计数与封禁按 Unix 整数秒加 60 过期，读取和封禁期间的探测不续期。
  初始短读、SS hint 失败、VMess 已识别身份后的时间窗/重放/协议错误不计入；
  传统 SS 长度头已解密、后续 payload 短读仍可能进入原候选全部失败分支。
  PROXY protocol 启用时使用解析后的来源 IP；SS2022 与共享密码 obfs 路径不安装此功能。
  本实现以一个互斥事务处理计数，修正原两缓存间可能丢失并发递增的窗口；未添加任意容量上限。
- `ShadowsocksObfsMu` 的 Host 为 UUID 原文 MD5 小写十六进制加固定后缀，101 后直接是 SS 密文。
  原版单次读取前导的限制保留。传统 SS 的 Host 提示仍须解密认证，错误不会回退其他用户；
  SS2022 不消费该提示，按自己的加密身份头归属用户，Host A 与合法 B 密文的边界已测。
- 综合 race 发现并修复上游 SS2022 首次响应与 Close 的竞争：写操作串行使用已有锁，
  Close 直接关闭底层连接以打断阻塞写。真实共享密码组合重复测试与协议整包 race 已通过。
- `AccessLog` 模式 0 采集、1 打印并采集、2 关闭。它独立于运行错误日志和流量报告开关。
  `SbApi` 使用 POST `/accesslog/upload`，gzip JSON 数组、大小写精确字段，只有 HTTP 200 成功；
  四次失败间隔 1/2/4 秒，失败批不重入队，上传期间新增记录保留到下一批。
  未配置 SbApi 时仍按周期清空队列。真实自有协议连接至本地接收端的集成及 race 已通过。
  `DisableAccessLog: true` 作为本实现保留的兼容别名映射模式 2，显式 AccessLog 优先；
  原二进制是否认此别名尚未证明，不能将别名扩展声称为原版行为。
- `experimental.debug.listen` 的 `/debug/memory` 返回原字段与单位，`/debug/connections` 复用统一登记表，
  按连接数及分组键排序，`top=0` 返回空分组但保留登记总数；恢复原 pprof 路径与异步 GC 接口。
  `/sb/debug/users?tag=` 返回热用户过期时间；查询键保留原 `Node.ApiConfig.PanelTag`，
  不用 multi 首面板标签替换。未知标签返回 `wrong tag`，没有 provider 时返回空响应。
  监听绑定失败会明确使启动失败，保留上游 sing-box 的错误处理，这是与原异步绑定的已知差异。

这些测试证明本实现的相应行为，尚不能证明所有行为与原版一致。
已知配置项的实现与组合仍须按原运行实例逐项验收；尚未发布完整兼容版本。

完整 Linux 回归曾受 WSL 网络命名空间权限和外部 TLS 分片测试超时影响；不将这些失败隐藏或记为通过。
本机 Windows 10 build 19045 上，三项上游 Schannel TLS 1.3 测试失败；该系统不在微软正式支持范围，
见 [Schannel 协议支持表](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-)。
新增 Go TLS 握手测试和 Linux TLS 包 race 通过；不将 Windows 系统 TLS 用例改名为通过。
新增限额模块的 100% statement coverage 仅指该模块，不代表仓库整体达到 100% 覆盖。
全仓回归还暴露原基线 OOM profile 对 Go 私有链接符号的依赖；已按 Go 1.26.5 BSD 许可保留
必要本地 maps/ELF 解析逻辑，六类 profile 经 pprof 解析，相关实验包普通测试通过，未关闭链接检查。

## 运行对照

已通过用户现有 FinalShell 连接的代理和私钥建立 SSH 通道，并复用已保存主机指纹校验。
只读确认 `sbc@a.service` 正在运行，配置为 `a.json` 与 `a.yml`；
当前是一个 AnyTLS、两个 Trojan 节点，其中一个 Trojan 禁用 TLS。
运行二进制已另存供离线核对，SHA-256 为
`6be01a84ca7cd52f9780ee045a5b88b013102b70381a7a0623fc2418e821f93f`，
大小 35,000,446 字节，与上面的静态基线不同。两者 `go version -m` 均返回 unknown，
不能仅凭哈希差异断定版本号，也不能直接把旧样本静态结论当作运行对照结果。
现有服务保持运行；受控对照需保存脱敏请求/响应、日志、必要抓包及性能数据。
没有运行证据的项目继续标为静态确认或待验证，凭据不进入仓库或对外输出。

运行原件提取出 41,634 个函数、3,981 个结构；与静态基线共有 3,977 个完全同布局结构。
应用 YAML 的 7 个结构、65 个字段一致，497 个关键入口中 479 个指令形态一致。
运行样本缺少旧基线的 HTTPUpgrade 对应选项字段与构造分支，两个 RawConn 读取结构也有变化；
旧基线的 HTTPUpgrade 能力仍保留在重建中，不能把运行样本视为覆盖全部旧基线功能的参考。

现有两个 TLS 入口已通过已保存 SSH 主机指纹的隧道完成 TLS 1.3 握手，证书分别匹配配置文件；
禁用 TLS 的入口对 TLS 握手返回 EOF。另以隔离网络及挂载命名空间、模拟面板和测试账号
启动运行原件，确认纯 TCP Trojan 正确凭据可回显、错误凭据拒绝、上下行各 23 字节上报。
原件启动输出版本为 `20260920`；其面板域名授权限制会拒绝普通 localhost 模拟 API，
隔离测试使用已有授权域名的私有主机名映射，真实面板和运行服务不参与该测试。

进一步的 7 场景原版/重建版对照中，6 场景的行为和流量结果一致：静态 Trojan 自定义密码、
AnyTLS raw、Trojan 接受 AnyTLS、AnyTLS 的 Trojan/VLESS 双 fallback、IPLimit=1 和 ConnectionLimit=1。
比较所用重建内核 SHA-256 为
`f52d205766caf6c2dab57072141e498adcaccb2975dadbd75c54ea95a6c8b9a1`；
它是本次同源开发构建，最终 CGO=0 测试包另有独立校验值与安装烟测记录。

唯一不一致是 MasterPassword。原版 debug 记录先确认派生身份的入站连接，随后报
`sbCheckUser: ... user not found`；原 UUID 密码则在认证阶段被拒绝。
这支持“派生认证成功、后续 gateway 用户索引不一致”的原版故障，而不是派生公式错误。
重建保留原 UUID 与稳定计费身份，派生凭据可回显并按用户 7 上报 23/23 字节，未复制该故障。
此项明确记为行为差异，不能把全批次记为完全一致。测试临时目录已清理，
运行服务的状态、PID 和原件哈希均保持一致。

另已使用用户指定的测试账号完成真实 UniProxy 面板验收：约 5.6 万用户表同步成功，
AnyTLS 的正确/错误凭据、PROXY 头有无两种连接、IP=1 与同 IP 连接数=1 均按预期运行。
在回环多 IP 上确认 AutoOutIP 绑定入站本机 IP；面板 API 接受上传、下载各 86,016 字节，
在线报告包含 PROXY 声明的测试来源，均返回 HTTP 200。这证明接口上报被接受，
不代表已读取面板数据库核对最终扣费。测试后另发送空在线快照并获 HTTP 200。
该轮使用最终 CGO=0 开发构建（SHA-256
`6fec9358d317fb96acd7f37a9b0577f5ae6ee7ad2d79a5c9ecb6659283c0c3a1`），
无 SAN 自签证书通过证书指纹、链与有效期共同校验；轻负载启动后 RSS 约 139 MiB。
未进行面板所设 4000 Mbps 的吞吐压测，未将轻负载数据当作峰值容量。
该轮仅使用临时回环监听，进程、私钥副本及目录已清理；公网测试服务尚未部署。
