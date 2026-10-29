package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func TestLegacyBanIPInheritanceAndTypeValidation(t *testing.T) {
	previous := globalCtx
	globalCtx = include.Context(context.Background())
	t.Cleanup(func() { globalCtx = previous })
	for _, test := range []struct {
		root, node string
		want, fail bool
	}{
		{"", "", false, false},
		{"false", "false", false, false},
		{"true", "", true, false},
		{"true", "false", true, false},
		{"false", "true", true, false},
		{"", "true", true, false},
		{`"true"`, "", false, true},
		{"true", `"false"`, false, true},
		{"0", "false", false, true},
		{"false", "1", false, true},
	} {
		t.Run(fmt.Sprintf("root=%s/node=%s", test.root, test.node), func(t *testing.T) {
			var rootField, nodeField string
			if test.root != "" {
				rootField = "ShadowsocksBanIP: " + test.root + "\n"
			}
			if test.node != "" {
				nodeField = "    ShadowsocksBanIP: " + test.node + "\n"
			}
			content := rootField + "Nodes:\n  - Type: UniProxy\n" + nodeField + `    ApiConfig:
      PanelTag: ban-fixture
      ApiHost: https://panel.example.test
      ApiKey: fixture-token
      NodeType: vmess
      NodeID: 1
`
			path := filepath.Join(t.TempDir(), "server.yml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			entry, err := readConfigAt(path)
			if test.fail {
				if err == nil {
					t.Fatal("invalid BanIP field type was silently coerced or ignored")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			settings := entry.options.Services[0].Options.(*option.XBoardServiceOptions)
			if settings.AutoInbound == nil || settings.AutoInbound.ShadowsocksBanIP != test.want {
				t.Fatal("node=false incorrectly disabled the root BanIP setting")
			}
		})
	}
}
