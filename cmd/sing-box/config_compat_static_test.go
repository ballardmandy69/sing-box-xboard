package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/include"
)

func TestLegacyStaticInboundSelectsIndependentAuthentication(t *testing.T) {
	root := normalizeLegacyServerConfig(map[string]any{"Nodes": []any{map[string]any{
		"StaticInbound": true, "MasterPassword": "must-not-rewrite-static-users",
		"ApiConfig": map[string]any{"PanelType": "XBoard", "PanelTag": "panel",
			"ApiHost": "https://panel.example.invalid", "ApiKey": "fixture", "NodeID": 1, "NodeType": "vmess"},
	}}}).(map[string]any)
	config := root["services"].([]any)[0].(map[string]any)
	if config["static_inbound"] != true || config["auto_inbound"] != nil || config["inbound"] != "panel" {
		t.Fatalf("legacy static mode was not preserved: %#v", config)
	}
}

func TestLegacyStaticInboundAndAliasRequireExactFieldTypes(t *testing.T) {
	previous := globalCtx
	globalCtx = include.Context(context.Background())
	t.Cleanup(func() { globalCtx = previous })
	for _, content := range []string{
		`{"services":[{"type":"xboard","static_inbound":"true"}]}`,
		`{"inbounds":[{"type":"trojan","use_panel_tag":123}]}`,
		`{"Nodes":[{"StaticInbound":"true","ApiConfig":{"PanelType":"XBoard","PanelTag":"p",` +
			`"ApiHost":"https://panel.example.invalid","ApiKey":"fixture","NodeID":1,"NodeType":"vmess"}}]}`,
	} {
		path := filepath.Join(t.TempDir(), "server.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readConfigAt(path); err == nil {
			t.Fatalf("invalid field type was silently accepted: %s", content)
		}
	}
}
