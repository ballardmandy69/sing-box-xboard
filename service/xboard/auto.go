package xboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

// autoConfigResponse follows XBoard ServerService::buildNodeConfig's node response.
// Source: https://github.com/cedar2025/Xboard/blob/master/app/Services/ServerService.php
// @author lyt
// @date 2026-10-29
type autoConfigResponse struct {
	configResponse
	Protocol        string          `json:"protocol"`
	ListenIP        string          `json:"listen_ip"`
	ServerPort      json.RawMessage `json:"server_port"`
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"networkSettings"`
	TLS             json.RawMessage `json:"tls"`
	TLSSettings     json.RawMessage `json:"tls_settings"`
	ServerName      string          `json:"server_name"`
	PaddingScheme   json.RawMessage `json:"padding_scheme"`
	Cipher          string          `json:"cipher"`
	ServerKey       string          `json:"server_key"`
	Obfs            string          `json:"obfs"`
	ObfsSettings    json.RawMessage `json:"obfs_settings"`
	Plugin          string          `json:"plugin"`
	PluginOptions   json.RawMessage `json:"plugin_opts"`
	Decryption      json.RawMessage `json:"decryption"`
}

func (n *node) createInbound(ctx context.Context, manager adapter.InboundManager, tag string,
	auto option.XBoardAutoInboundOptions,
) (adapter.Inbound, error) {
	router := service.FromContext[adapter.Router](ctx)
	if router == nil {
		return nil, fmt.Errorf("missing router for automatic xboard inbound")
	}
	protocol, err := automaticProtocol(n.nodeType, auto)
	if err != nil {
		return nil, err
	}
	registry := service.FromContext[adapter.InboundRegistry](ctx)
	if registry == nil {
		return nil, fmt.Errorf("missing inbound registry for automatic xboard inbound")
	}
	created := newEmptyAutoInbound(ctx, registry, router, n.service.logger, tag, protocol)
	if err = manager.Register(created); err != nil {
		created.close()
		return nil, err
	}
	n.auto = created
	n.autoOptions = auto
	n.service.logger.Info("xboard automatic inbound awaiting initial synchronization: ", tag,
		" type=", protocol, " node=", n.nodeID)
	return created, nil
}

func (r autoConfigResponse) buildInboundConfig(nodeType string,
	auto option.XBoardAutoInboundOptions,
) (autoInboundConfig, error) {
	protocol, inboundOptions, err := r.inboundOptions(nodeType, auto)
	if err != nil {
		return autoInboundConfig{}, err
	}
	listen := inboundOptions.(option.ListenOptionsWrapper).TakeListenOptions()
	return autoInboundConfig{
		protocol: protocol, options: inboundOptions,
		endpoint: netip.AddrPortFrom(listen.Listen.Build(netip.IPv4Unspecified()), listen.ListenPort),
	}, nil
}

func (r autoConfigResponse) inboundOptions(nodeType string,
	auto option.XBoardAutoInboundOptions,
) (string, any, error) {
	protocol, err := automaticProtocol(nodeType, auto)
	if err != nil {
		return "", nil, err
	}
	if r.Protocol != "" && normalizedProtocol(r.Protocol) != normalizedProtocol(nodeType) {
		return "", nil, fmt.Errorf("xboard config protocol differs from the requested panel node type")
	}
	if protocol == C.TypeVLESS && nonemptyPanelOptions(r.Decryption) {
		return "", nil, fmt.Errorf("automatic VLESS inbound does not support panel decryption settings")
	}
	transport, err := r.transportOptions(protocol)
	if err != nil {
		return "", nil, err
	}
	port := auto.ListenPort
	if port == 0 {
		port, err = panelInteger(r.ServerPort)
	}
	if err != nil || port < 1 || port > 65535 {
		return "", nil, fmt.Errorf("xboard server_port must be an integer between 1 and 65535")
	}
	listenIP := strings.TrimSpace(auto.Listen)
	if listenIP == "" {
		listenIP = strings.TrimSpace(r.ListenIP)
	}
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	address, err := netip.ParseAddr(listenIP)
	if err != nil {
		return "", nil, fmt.Errorf("xboard listen address must be an IP address")
	}
	listenAddress := badoption.Addr(address)
	listen := option.ListenOptions{
		Listen: &listenAddress, ListenPort: uint16(port),
		ProxyProtocol: auto.ProxyProtocol, ProxyProtocolAcceptNoHeader: auto.ProxyProtocol,
		AutoOutIP: auto.AutoOutIP,
	}
	if protocol == C.TypeShadowsocks {
		options, err := r.shadowsocksOptions(listen, auto.ShadowsocksObfsMu)
		return protocol, options, err
	}
	tlsOptions, err := r.tlsOptions(protocol, auto)
	if err != nil {
		return "", nil, err
	}
	switch protocol {
	case C.TypeAnyTLS:
		padding, err := panelPadding(r.PaddingScheme)
		if err != nil {
			return "", nil, err
		}
		return protocol, &option.AnyTLSInboundOptions{
			ListenOptions: listen, InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: tlsOptions},
			PaddingScheme: padding,
		}, nil
	case C.TypeTrojan:
		return protocol, &option.TrojanInboundOptions{
			ListenOptions: listen, InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: tlsOptions},
			Transport: transport,
		}, nil
	case C.TypeVMess:
		return protocol, &option.VMessInboundOptions{
			ListenOptions: listen, InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: tlsOptions},
			Transport: transport,
		}, nil
	case C.TypeVLESS:
		return protocol, &option.VLESSInboundOptions{
			ListenOptions: listen, InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: tlsOptions},
			Transport: transport, ForceVision: &auto.ForceVision,
		}, nil
	default:
		key, err := readNativePrivateKey(auto)
		if err != nil {
			return "", nil, err
		}
		return protocol, &option.AnyTLSNativeInboundOptions{
			ListenOptions: listen, InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: tlsOptions},
			PrivateKey: key,
		}, nil
	}
}

func automaticProtocol(nodeType string, auto option.XBoardAutoInboundOptions) (string, error) {
	protocol := normalizedProtocol(auto.Protocol)
	if protocol == "" {
		protocol = normalizedProtocol(nodeType)
	}
	switch protocol {
	case C.TypeAnyTLS, C.TypeTrojan, C.TypeAnyTLSNative, C.TypeVMess, C.TypeVLESS, C.TypeShadowsocks:
		return protocol, nil
	default:
		return "", fmt.Errorf("unsupported automatic xboard inbound protocol")
	}
}

func (r autoConfigResponse) tlsOptions(protocol string,
	auto option.XBoardAutoInboundOptions,
) (*option.InboundTLSOptions, error) {
	enabled := protocol == C.TypeAnyTLS || protocol == C.TypeTrojan ||
		protocol == C.TypeAnyTLSNative && (auto.CertificatePath != "" || auto.KeyPath != "")
	if !emptyPanelValue(r.TLS) {
		mode, err := panelInteger(r.TLS)
		if err != nil || mode < 0 || mode > 1 {
			return nil, fmt.Errorf("automatic xboard inbounds do not support Reality or unknown TLS modes")
		}
		if mode == 0 && (protocol == C.TypeAnyTLS || protocol == C.TypeTrojan) {
			return nil, fmt.Errorf("automatic public anytls and trojan inbounds require TLS")
		}
		enabled = mode == 1
	}
	var settings map[string]json.RawMessage
	if !emptyPanelValue(r.TLSSettings) {
		if err := json.Unmarshal(r.TLSSettings, &settings); err != nil {
			return nil, fmt.Errorf("xboard tls_settings must be an object")
		}
		for key, value := range settings {
			switch strings.ToLower(key) {
			case "reality", "reality_settings", "private_key", "public_key", "short_id", "short_ids":
				if !emptyPanelValue(value) {
					return nil, fmt.Errorf("automatic xboard inbounds do not support Reality settings")
				}
			case "security":
				var security string
				if json.Unmarshal(value, &security) != nil || security != "" && !strings.EqualFold(security, "tls") {
					return nil, fmt.Errorf("automatic xboard inbounds require standard TLS settings")
				}
			}
		}
	}
	if !enabled {
		return nil, nil
	}
	if auto.CertificatePath == "" || auto.KeyPath == "" {
		return nil, fmt.Errorf("automatic TLS inbound requires both certificate_path and key_path")
	}
	serverName := r.ServerName
	if value := settings["server_name"]; !emptyPanelValue(value) {
		if err := json.Unmarshal(value, &serverName); err != nil {
			return nil, fmt.Errorf("xboard TLS server_name must be a string")
		}
	}
	var alpn []string
	if value := settings["alpn"]; !emptyPanelValue(value) {
		if err := json.Unmarshal(value, &alpn); err != nil {
			return nil, fmt.Errorf("xboard TLS alpn must be an array of strings")
		}
	}
	return &option.InboundTLSOptions{
		Enabled: true, CertificatePath: auto.CertificatePath, KeyPath: auto.KeyPath,
		ServerName: serverName, ALPN: alpn,
	}, nil
}

func emptyPanelValue(value json.RawMessage) bool {
	value = bytes.TrimSpace(value)
	return len(value) == 0 || bytes.Equal(value, []byte("null"))
}

func panelInteger(value json.RawMessage) (int, error) {
	value = bytes.TrimSpace(value)
	var text string
	if len(value) > 0 && value[0] == '"' {
		if err := json.Unmarshal(value, &text); err != nil {
			return 0, err
		}
	} else {
		text = string(value)
	}
	return strconv.Atoi(strings.TrimSpace(text))
}

func panelPadding(value json.RawMessage) ([]string, error) {
	if emptyPanelValue(value) {
		return nil, nil
	}
	var lines []string
	if json.Unmarshal(value, &lines) == nil {
		return lines, nil
	}
	var text string
	if json.Unmarshal(value, &text) != nil {
		return nil, fmt.Errorf("xboard padding_scheme must be a string or an array of strings")
	}
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	return strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n"), nil
}

func readNativePrivateKey(auto option.XBoardAutoInboundOptions) (string, error) {
	if auto.PrivateKey != "" && auto.PrivateKeyPath != "" {
		return "", fmt.Errorf("native private_key and private_key_path are mutually exclusive")
	}
	if auto.PrivateKey != "" {
		key := strings.TrimSpace(auto.PrivateKey)
		if key == "" {
			return "", fmt.Errorf("native private_key is empty")
		}
		return key, nil
	}
	if auto.PrivateKeyPath == "" {
		return "", fmt.Errorf("automatic native inbound requires private_key or private_key_path")
	}
	file, err := os.Open(auto.PrivateKeyPath)
	if err != nil {
		return "", fmt.Errorf("cannot open native private_key_path")
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil || len(content) > 1024 {
		return "", fmt.Errorf("cannot read native private_key_path or file exceeds size limit")
	}
	key := strings.TrimSpace(string(content))
	if key == "" {
		return "", fmt.Errorf("native private_key_path is empty")
	}
	return key, nil
}
