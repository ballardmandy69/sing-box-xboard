# XBoard 配置布局

配置布局与原后端示例保持一致：

- `config.json`：DNS、路由、出站和本地入站模板。
- `server.yml`：`Nodes`、`ApiConfig`、`UpdateInterval` 等面板节点配置。
- `sb-auto.sh`：从配置文件服务器下载 `${INSTANCE}.json` 和 `${INSTANCE}.yml`，然后启动 systemd 实例。

```bash
export SHARE=https://config.example.com/airport
bash <(curl -fsSL https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/main/sb-auto.sh) config.json server.yml
```

`PanelTag` 需要与 `config.json` 中的入站 `tag` 对应。示例中都是 `vless-1`。如果增加多个节点，需要在 `config.json` 中增加对应协议入站，并在 `server.yml` 的每个 `ApiConfig.PanelTag` 中使用唯一 tag。

XBoard 面板 token 放在 `ApiConfig.ApiKey`，它只用于调用面板的 UniProxy API。安装过程和运行过程不读取产品名、授权码或本地身份信息。
