package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/include"
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
	if err = os.WriteFile(path, []byte("ConnectionCleanupIntervalSec: -1\nNodes: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = readConfigAt(path); err == nil {
		t.Fatal("negative uint64 cleanup interval accepted")
	}
}
