package main

import "testing"

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
