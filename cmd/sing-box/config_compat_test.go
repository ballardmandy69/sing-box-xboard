package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
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
