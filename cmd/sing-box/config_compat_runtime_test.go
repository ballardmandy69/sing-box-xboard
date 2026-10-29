package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func TestLegacyRuntimeConfiguration(t *testing.T) {
	previous := globalCtx
	globalCtx = include.Context(context.Background())
	t.Cleanup(func() { globalCtx = previous })
	path := filepath.Join(t.TempDir(), "server.yml")
	if err := os.WriteFile(path, []byte(`AccessLog: 1
ConnectionCleanupIntervalSec: 30
HotUserCacheSec: 45
DisableAccessLog: true
BlockScanner: 'network == "tcp" ? "rule match" : ""'
MemoryGuard:
  Enabled: true
  CheckInterval: 7s
  BlockDuration: 2m
  Steps:
    - AvailableMemoryPercent: 12.5
      BlockPercentPerCheck: 2
      MaxBlockedPercent: 8
SbApi:
  BaseURL: https://logs.example.test
  Tag: server-a
  Token: local-test-token
  SendTokenInQuery: true
Nodes: []
`), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := readConfigAt(path)
	if err != nil {
		t.Fatal(err)
	}
	settings := entry.options.NYAFW
	if settings == nil || settings.ConnectionCleanupIntervalSec != 30 || settings.HotUserCacheSec != 45 || settings.AccessLog != 1 ||
		settings.SbAPI == nil || settings.SbAPI.BaseURL != "https://logs.example.test" ||
		settings.SbAPI.Tag != "server-a" || settings.SbAPI.Token != "local-test-token" || !settings.SbAPI.SendTokenInQuery {
		t.Fatal("legacy process options were discarded or explicit AccessLog lost precedence")
	}
	if entry.options.Log != nil && entry.options.Log.Disabled {
		t.Fatal("access-log setting muted operational error logs")
	}
	if settings.BlockScanner != `network == "tcp" ? "rule match" : ""` {
		t.Fatal("legacy scanner expression was dropped or altered")
	}
	guard := settings.MemoryGuard
	if !guard.Enabled || time.Duration(guard.CheckInterval) != 7*time.Second ||
		time.Duration(guard.BlockDuration) != 2*time.Minute || len(guard.Steps) != 1 ||
		guard.Steps[0].AvailableMemoryPercent != 12.5 || guard.Steps[0].BlockPercentPerCheck != 2 ||
		guard.Steps[0].MaxBlockedPercent != 8 {
		t.Fatal("legacy MemoryGuard policy was dropped or changed")
	}
	if err = os.WriteFile(path, []byte("ConnectionCleanupIntervalSec: -1\nNodes: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = readConfigAt(path); err == nil {
		t.Fatal("negative uint64 cleanup interval accepted")
	}
}

func TestLegacyMemoryGuardRejectsMalformedValues(t *testing.T) {
	previous := globalCtx
	globalCtx = include.Context(context.Background())
	t.Cleanup(func() { globalCtx = previous })
	for _, content := range []string{
		"MemoryGuard: 123\nNodes: []\n",
		"MemoryGuard: {Enabled: true, CheckInterval: invalid}\nNodes: []\n",
		"MemoryGuard: {Enabled: true, Steps: invalid}\nNodes: []\n",
		"MemoryGuard: {Enabled: true, Steps: [123]}\nNodes: []\n",
		"MemoryGuard: {Enabled: true, Steps: [{AvailableMemoryPercent: invalid}]}\nNodes: []\n",
		"MemoryGuard: {Enabled: true, UnknownField: 1}\nNodes: []\n",
	} {
		path := filepath.Join(t.TempDir(), "server.yml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readConfigAt(path); err == nil {
			t.Fatalf("malformed guard policy silently discarded: %s", content)
		}
	}
}

func TestLegacyPanelProvidersKeepRawNodeType(t *testing.T) {
	previous := globalCtx
	globalCtx = include.Context(context.Background())
	t.Cleanup(func() { globalCtx = previous })
	for panelType, nodeTypes := range map[string][]string{
		"oldv2board": {"v2ray", "trojan", "trojantidalab", "shadowsocks", "shadowsockstidalab"},
		"ppanel":     {"v2ray", "vmess", "vless", "trojan", "anytls", "shadowsocks"},
	} {
		for _, nodeType := range nodeTypes {
			content := fmt.Sprintf(`Nodes:
  - Type: %s
    ApiConfig:
      PanelTag: legacy-panel
      ApiHost: https://old.example.test
      ApiKey: local-test-token
      NodeType: %s
      NodeID: 4
`, panelType, nodeType)
			path := filepath.Join(t.TempDir(), "server.yml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			entry, err := readConfigAt(path)
			if err != nil {
				t.Fatal(err)
			}
			settings := entry.options.Services[0].Options.(*option.XBoardServiceOptions)
			if settings.PanelType != panelType || settings.NodeType != nodeType || settings.LegacyPanelTag == nil ||
				*settings.LegacyPanelTag != "legacy-panel" {
				t.Fatal("legacy protocol alias was lost before provider-specific HTTP dispatch")
			}
		}
	}
}
