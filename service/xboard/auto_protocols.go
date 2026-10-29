package xboard

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
)

// panelTransportSettings contains transport fields emitted by the UniProxy panel API.
// @author lyt
// @date 2026-10-29
type panelTransportSettings struct {
	Path        string                     `json:"path"`
	Host        string                     `json:"host"`
	Headers     map[string]json.RawMessage `json:"headers"`
	ServiceName string                     `json:"serviceName"`
	Neko        string                     `json:"neko"`
}

func normalizedProtocol(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "v2ray" {
		return C.TypeVMess
	}
	return value
}

func (r autoConfigResponse) transportOptions(protocol string) (*option.V2RayTransportOptions, error) {
	network := strings.ToLower(strings.TrimSpace(r.Network))
	var fields map[string]json.RawMessage
	if !emptyPanelValue(r.NetworkSettings) {
		if err := json.Unmarshal(r.NetworkSettings, &fields); err != nil {
			return nil, fmt.Errorf("xboard networkSettings must be an object")
		}
	}
	if network == "" || network == "tcp" {
		if len(fields) > 0 {
			return nil, fmt.Errorf("automatic raw TCP inbounds do not support networkSettings")
		}
		return nil, nil
	}
	if protocol != C.TypeVMess && protocol != C.TypeVLESS && protocol != C.TypeTrojan {
		return nil, fmt.Errorf("this automatic xboard inbound requires raw TCP")
	}
	var settings panelTransportSettings
	if len(fields) > 0 {
		if err := json.Unmarshal(r.NetworkSettings, &settings); err != nil {
			return nil, fmt.Errorf("invalid xboard TCP transport settings")
		}
	}
	if settings.Neko != "" {
		return nil, fmt.Errorf("automatic xboard transport does not yet support neko settings")
	}
	headers := make(badoption.HTTPHeader, len(settings.Headers))
	for name, raw := range settings.Headers {
		var values []string
		var value string
		if json.Unmarshal(raw, &value) == nil {
			values = []string{value}
		} else if json.Unmarshal(raw, &values) != nil {
			return nil, fmt.Errorf("xboard transport header must be a string or array of strings")
		}
		headers[name] = values
	}
	switch network {
	case "ws":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path: settings.Path, Headers: headers,
			},
		}, nil
	case "httpupgrade":
		host := settings.Host
		if host == "" {
			for name, values := range headers {
				if http.CanonicalHeaderKey(name) == "Host" && len(values) > 0 {
					host = values[0]
					break
				}
			}
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
				Path: settings.Path, Host: host, Headers: headers,
			},
		}, nil
	case "grpc":
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{ServiceName: settings.ServiceName},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported automatic xboard TCP transport")
	}
}

func (r autoConfigResponse) shadowsocksOptions(listen option.ListenOptions, obfsMu string) (*option.ShadowsocksInboundOptions, error) {
	// The original UniProxy adapter fixes SS to TCP and does not propagate panel obfs/plugin fields.
	if !emptyPanelValue(r.TLS) {
		mode, err := panelInteger(r.TLS)
		if err != nil || mode != 0 {
			return nil, fmt.Errorf("automatic Shadowsocks inbound does not support TLS wrapping")
		}
	}
	method := strings.ToLower(strings.TrimSpace(r.Cipher))
	password := r.ServerKey
	sharedPassword := false
	if obfsMu != "" {
		parts := strings.Split(obfsMu, ":")
		if len(parts) > 2 || parts[0] == "" {
			return nil, fmt.Errorf("invalid Shadowsocks obfs_mu configuration")
		}
		method = parts[0]
		if len(parts) == 2 {
			password = parts[1]
			sharedPassword = true
		}
	}
	keySize := shadowsocksUserKeySize(method)
	if sharedPassword && method == "2022-blake3-chacha20-poly1305" {
		keySize = 32
	}
	if keySize == 0 && !common.Contains(shadowaead.List, method) && !(sharedPassword && method == "none") {
		return nil, fmt.Errorf("unsupported automatic Shadowsocks multi-user cipher")
	}
	if keySize != 0 {
		key, err := base64.StdEncoding.DecodeString(password)
		if err != nil || len(key) != keySize {
			return nil, fmt.Errorf("invalid xboard Shadowsocks 2022 server_key")
		}
	}
	return &option.ShadowsocksInboundOptions{
		ListenOptions: listen, Network: option.NetworkList("tcp"),
		Method: method, Password: password, Managed: true, ObfsMu: obfsMu,
	}, nil
}

func nonemptyPanelOptions(value json.RawMessage) bool {
	if emptyPanelValue(value) {
		return false
	}
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text != ""
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(value, &fields) != nil {
		return true
	}
	for _, field := range fields {
		if nonemptyPanelOptions(field) {
			return true
		}
	}
	return false
}

func shadowsocksUserKeySize(method string) int {
	switch method {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm":
		return 32
	default:
		return 0
	}
}

func (c autoInboundConfig) userCredentials(credentials []string) ([]string, error) {
	if c.protocol != C.TypeShadowsocks {
		return credentials, nil
	}
	options, ok := c.options.(*option.ShadowsocksInboundOptions)
	if !ok {
		return nil, fmt.Errorf("invalid automatic Shadowsocks configuration")
	}
	if strings.Contains(options.ObfsMu, ":") {
		return credentials, nil
	}
	keySize := shadowsocksUserKeySize(options.Method)
	if keySize == 0 {
		return credentials, nil
	}
	converted := make([]string, len(credentials))
	for index, credential := range credentials {
		if len(credential) < keySize {
			return nil, fmt.Errorf("xboard Shadowsocks 2022 user credential is too short")
		}
		// XBoard Helper::uuidToBase64 encodes the UUID text prefix, not parsed UUID bytes.
		converted[index] = base64.StdEncoding.EncodeToString([]byte(credential[:keySize]))
	}
	return converted, nil
}
