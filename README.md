# sing-box

## XBoard / XiaoV2Board

This tree includes the XBoard UniProxy service and YAML configuration support. It synchronizes users and reports traffic for VLESS, VMess, Trojan, Shadowsocks, Hysteria2 and TUIC inbounds.

Install the latest Linux release with:

```bash
curl -fsSL https://raw.githubusercontent.com/ballardmandy69/sing-box-xboard/main/install.sh | sudo bash
```

The installer uses `/opt/sing-box-xboard`, creates `xboard-sb@.service` for shared configurations and `xboard-sbc@.service` for independent configurations, and performs no local identity or activation verification. The XBoard `api_key` remains required as the panel API credential.

Example configuration: [xboard.example.yaml](xboard.example.yaml).

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
