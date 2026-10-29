package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/anytlsnative"
)

func TestNormalizeLegacyServerConfig(t *testing.T) {
	value := map[string]any{
		"DisableAccessLog": true,
		"Nodes": []any{map[string]any{
			"UpdateInterval": "60s",
			"ApiConfig": map[string]any{
				"PanelTag": "vless-1",
				"ApiHost":  "https://panel.example",
				"ApiKey":   "secret",
				"NodeType": "VLESS",
				"NodeID":   float64(12),
				"Timeout":  float64(10),
			},
		}},
	}
	result := normalizeLegacyServerConfig(value).(map[string]any)
	services := result["services"].([]any)
	service := services[0].(map[string]any)
	if service["type"] != "xboard" || service["inbound"] != "vless-1" {
		t.Fatalf("unexpected service mapping: %#v", service)
	}
	if service["node_type"] != "vless" || service["node_id"] != 12 || service["timeout"] != "10s" {
		t.Fatalf("unexpected API mapping: %#v", service)
	}
	if result["log"].(map[string]any)["disabled"] != true {
		t.Fatal("DisableAccessLog was not mapped")
	}
}

// TestLegacyAutomaticNodes exercises the nyafw-shaped YAML without exposing real panel credentials.
// @author lyt
// @date 2026-10-29
func TestLegacyAutomaticNodes(t *testing.T) {
	previousContext := globalCtx
	globalCtx = include.Context(context.Background())
	t.Cleanup(func() { globalCtx = previousContext })
	content := []byte(`DisableAccessLog: false
Nodes:
  - Type: UniProxy
    ListenIP: 192.0.2.10
    ListenPort: 443
    AutoOutIP: true
    ProxyProtocol: true
    ApiConfig:
      PanelTag: anytls-a
      ApiHost: https://panel.example.com
      ApiKey: test-token
      NodeType: Anytls
      NodeID: 171
    CertConfig:
      CertFile: ./z.crt
      KeyFile: ./z.key
  - Type: UniProxy
    ListenIP: 192.0.2.11
    AutoOutIP: true
    ApiConfig:
      PanelTag: trojan-b
      ApiHost: https://panel.example.com
      ApiKey: test-token
      NodeType: Trojan
      NodeID: 10
    CertConfig:
      CertFile: ./zq.crt
      KeyFile: ./zq.key
  - Type: UniProxy
    Protocol: anytls-native
    PrivateKeyPath: ./native.key
    ApiConfig:
      PanelTag: native-c
      ApiHost: https://panel.example.com
      ApiKey: test-token
      NodeType: Anytls
      NodeID: 172
`)
	path := filepath.Join(t.TempDir(), "server.yml")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := readConfigAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.options.Inbounds) != 0 || len(entry.options.Services) != 3 {
		t.Fatal("legacy Nodes must create panel services with automatic inbound settings")
	}
	a := entry.options.Services[0].Options.(*option.XBoardServiceOptions)
	b := entry.options.Services[1].Options.(*option.XBoardServiceOptions)
	c := entry.options.Services[2].Options.(*option.XBoardServiceOptions)
	if a.NodeType != "anytls" || a.NodeID != 171 || a.AutoInbound.Listen != "192.0.2.10" ||
		a.AutoInbound.ListenPort != 443 || !a.AutoInbound.AutoOutIP || !a.AutoInbound.ProxyProtocol ||
		a.AutoInbound.CertificatePath != "./z.crt" || a.AutoInbound.KeyPath != "./z.key" {
		t.Fatal("AnyTLS listener, proxy, egress or certificate settings were lost")
	}
	if b.NodeType != "trojan" || b.AutoInbound.Listen != "192.0.2.11" ||
		b.AutoInbound.ListenPort != 0 || !b.AutoInbound.AutoOutIP || b.AutoInbound.ProxyProtocol {
		t.Fatal("Trojan node must retain independent settings and default to the panel port")
	}
	if c.NodeType != "anytls" || c.AutoInbound.Protocol != "anytls-native" ||
		c.AutoInbound.PrivateKeyPath != "./native.key" {
		t.Fatal("native protocol selection must preserve the panel's API node type")
	}
}

func TestLegacyStaticInbound(t *testing.T) {
	value := map[string]any{"Nodes": []any{map[string]any{
		"StaticInbound": true,
		"ApiConfig":     map[string]any{"PanelTag": "manual", "NodeType": "AnyTLS"},
	}}}
	result := normalizeLegacyServerConfig(value).(map[string]any)
	service := result["services"].([]any)[0].(map[string]any)
	if _, exists := service["auto_inbound"]; exists {
		t.Fatal("StaticInbound must require an existing manually configured inbound")
	}
}

func TestLegacyNodeValidation(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
	}{
		{"not-array", "Nodes: {}", "Nodes must be an array"},
		{"not-object", "Nodes: [invalid]", "Nodes[0] must be an object"},
		{"missing-api", "Nodes: [{}]", "ApiConfig must be an object"},
		{"unknown-type", "Nodes: [{Type: Unknown, ApiConfig: {}}]", "Type must be UniProxy"},
		{"invalid-port", "Nodes: [{ListenPort: 65536, ApiConfig: {}}]", "ListenPort must be"},
		{"fractional-port", "Nodes: [{ListenPort: 443.5, ApiConfig: {}}]", "ListenPort must be"},
		{"invalid-proxy", "Nodes: [{ProxyProtocol: 'true', ApiConfig: {}}]", "ProxyProtocol must be a boolean"},
		{"invalid-egress", "Nodes: [{AutoOutIP: yes, ApiConfig: {}}]", "AutoOutIP must be a boolean"},
		{"duplicate-tag", "Nodes: [{ApiConfig: {PanelTag: a}}, {ApiConfig: {PanelTag: a}}]", "PanelTag must be unique"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeConfigContent("server.yml", []byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want %s", err, test.want)
			}
		})
	}
	if _, err := decodeConfigContent("server.yml", []byte("Nodes: []")); err != nil {
		t.Fatalf("empty generic installation config must be valid: %v", err)
	}
}

// TestNativePanelTemplates verifies the shipped two-file layout through the CLI loader and merger.
// @author lyt
// @date 2026-10-29
func TestNativePanelTemplates(t *testing.T) {
	coreTemplate, err := os.ReadFile(filepath.Join("..", "..", "config.anytls-native.json"))
	if err != nil {
		t.Fatal(err)
	}
	panelTemplate, err := os.ReadFile(filepath.Join("..", "..", "server.anytls-native.yml"))
	if err != nil {
		t.Fatal(err)
	}
	privateKey, _, err := anytlsnative.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	coreContent := bytes.ReplaceAll(coreTemplate, []byte("__SERVER_PRIVATE_KEY__"),
		[]byte(base64.RawURLEncoding.EncodeToString(privateKey)))
	previousContext := globalCtx
	globalCtx = include.Context(context.Background())
	t.Cleanup(func() { globalCtx = previousContext })

	for _, panelType := range []string{"anytls", "vless"} {
		t.Run(panelType, func(t *testing.T) {
			directory := t.TempDir()
			corePath := filepath.Join(directory, "config.json")
			panelPath := filepath.Join(directory, "server.yml")
			panelContent := bytes.ReplaceAll(panelTemplate, []byte("NodeType: anytls"),
				[]byte("NodeType: "+panelType))
			if err := os.WriteFile(corePath, coreContent, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(panelPath, panelContent, 0o600); err != nil {
				t.Fatal(err)
			}
			core, err := readConfigAt(corePath)
			if err != nil {
				t.Fatal(err)
			}
			panel, err := readConfigAt(panelPath)
			if err != nil {
				t.Fatal(err)
			}
			merged, err := mergeOptionsList([]*OptionsEntry{core, panel})
			if err != nil {
				t.Fatal(err)
			}
			if len(merged.Inbounds) != 1 || len(merged.Services) != 1 {
				t.Fatal("the two-file layout must produce one inbound and one panel service")
			}
			inbound := merged.Inbounds[0]
			if inbound.Type != "anytls-native" || inbound.Tag != "native-1" {
				t.Fatal("the panel node type must not replace the native inbound type or tag")
			}
			native, ok := inbound.Options.(*option.AnyTLSNativeInboundOptions)
			if !ok || native.ListenPort != 443 || len(native.Users) != 0 {
				t.Fatal("the native inlet must listen on TCP 443 and await managed users")
			}
			service, ok := merged.Services[0].Options.(*option.XBoardServiceOptions)
			if !ok || service.Inbound != inbound.Tag || service.NodeType != panelType {
				t.Fatal("the panel service must retain its API node type and bind the native inbound")
			}
			if service.NodeID != 1 || service.APIHost != "https://panel.example.com" {
				t.Fatal("the panel connection settings did not survive the YAML conversion")
			}
			if merged.Log == nil || merged.Log.Disabled {
				t.Fatal("the shipped template must retain logs for panel synchronization failures")
			}
		})
	}
}
