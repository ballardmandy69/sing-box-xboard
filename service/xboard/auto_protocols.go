package xboard

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
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
	if network == "" || network == "tcp" {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if !emptyPanelValue(r.NetworkSettings) {
		if err := json.Unmarshal(r.NetworkSettings, &fields); err != nil {
			return nil, fmt.Errorf("xboard networkSettings must be an object")
		}
	}
	if protocol != C.TypeVMess && protocol != C.TypeVLESS && protocol != C.TypeTrojan {
		return nil, fmt.Errorf("this automatic xboard inbound requires raw TCP")
	}
	// UniProxy decodes neko but never passes it to the original shared transport builder.
	if r.providerNormalized {
		neko, err := panelTransportString(fields, "neko")
		if err != nil {
			return nil, err
		}
		if neko != "" {
			return nil, fmt.Errorf("automatic xboard transport does not yet support neko settings")
		}
	}
	switch network {
	case "ws", "websocket":
		// The sample strips a non-empty ed query but fixes the early-data default at 2048.
		path, err := panelTransportString(fields, "path")
		if err != nil {
			return nil, err
		}
		if parsed, err := url.Parse(path); err == nil {
			query := parsed.Query()
			if query.Get("ed") != "" {
				query.Del("ed")
				parsed.RawQuery = query.Encode()
				path = parsed.String()
			}
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path: path, Headers: make(badoption.HTTPHeader),
				MaxEarlyData: 2048, EarlyDataHeaderName: "Sec-WebSocket-Protocol",
			},
		}, nil
	case "httpupgrade", "http-upgrade", "http_upgrade":
		// Panel Host/headers are not forwarded by the original shared transport builder.
		path, err := panelTransportString(fields, "path")
		if err != nil {
			return nil, err
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
				Path: path, Headers: make(badoption.HTTPHeader),
			},
		}, nil
	case "grpc":
		serviceName, err := panelTransportString(fields, "serviceName")
		if err != nil {
			return nil, err
		}
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{ServiceName: serviceName},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported automatic xboard TCP transport")
	}
}

func panelTransportString(fields map[string]json.RawMessage, key string) (string, error) {
	field := fields[key]
	if len(field) == 0 {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(field, &value); err != nil {
		return "", fmt.Errorf("invalid xboard TCP transport settings")
	}
	return value, nil
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
	return c.panelCredentials(credentials, make([]string, len(credentials)))
}

func (c autoInboundConfig) panelCredentials(uuids, passwords []string) ([]string, error) {
	credentials, err := panelProtocolCredentials(c.protocol, uuids, passwords)
	if err != nil {
		return nil, err
	}
	if c.masterPassword != "" && (c.protocol == C.TypeTrojan || c.protocol == C.TypeAnyTLS) {
		// Legacy callbacks derive from the original UUID without replacing the panel identity or UUID cache.
		for index, uuid := range uuids {
			digest := md5.Sum([]byte(uuid + c.masterPassword))
			credentials[index] = hex.EncodeToString(digest[:])
		}
	}
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
		if passwords[index] != "" {
			converted[index] = credential
			continue
		}
		if len(credential) < keySize {
			return nil, fmt.Errorf("xboard Shadowsocks 2022 user credential is too short")
		}
		// XBoard Helper::uuidToBase64 encodes the UUID text prefix, not parsed UUID bytes.
		converted[index] = base64.StdEncoding.EncodeToString([]byte(credential[:keySize]))
	}
	return converted, nil
}
