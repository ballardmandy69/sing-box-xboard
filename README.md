# sing-box

## XBoard / XiaoV2Board

This tree includes the XBoard UniProxy service, YAML configuration support, and the custom TCP-only `anytls-native` protocol. It synchronizes panel users and reports traffic through managed inbounds.

The nyafw-style installer includes standard Trojan, standard AnyTLS, and `anytls-native` templates using `config.json` + `server.yml`, without product identity or activation arguments. The panel API token is still required. Installation preserves existing configurations.

The first matching native release is `v1.14.3-xboard-native.1`. As root on a Linux systemd server:

```bash
VERSION=v1.14.3-xboard-native.1 bash <(curl -fLSs https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/v1.14.3-xboard-native.1/install.sh)
```

Then edit `/opt/sing-box-xboard/server.yml` and start `xboard-sb@server.service`. This is an experimental custom protocol; existing public AnyTLS clients and panel subscriptions do not automatically become native clients.

For a standard protocol, set `PROTOCOL=trojan` or `PROTOCOL=anytls` and provide existing certificate paths in `TLS_CERT_FILE` and `TLS_KEY_FILE`. Standard entries keep their original wire formats; the default remains `anytls-native`. All three template pairs are installed under `examples/`.

- [Installation, panel configuration, and systemd commands](docs/xboard-config.md)
- [Native protocol and client configuration](docs/anytls-native.md)
- Native templates: [config.anytls-native.json](config.anytls-native.json), [server.anytls-native.yml](server.anytls-native.yml)
- Standard templates: [Trojan](config.trojan.json), [AnyTLS](config.anytls.json)

The upstream-style [xboard.example.yaml](xboard.example.yaml) and existing protocol examples remain available.

The universal proxy platform.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
