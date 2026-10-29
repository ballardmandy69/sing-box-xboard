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

func TestMasterPasswordConfigurationCompatibility(t *testing.T) {
	previous := globalCtx
	globalCtx = include.Context(context.Background())
	t.Cleanup(func() { globalCtx = previous })
	for _, legacy := range []bool{false, true} {
		for _, test := range []struct {
			name, raw, want string
			invalid         bool
		}{
			{"string", `" master-A "`, " master-A ", false},
			{"empty", `""`, "", false},
			{"number", `123`, "", true},
			{"boolean", `true`, "", true},
			{"array", `["secret"]`, "", true},
			{"object", `{"value":"secret"}`, "", true},
		} {
			t.Run(fmt.Sprintf("legacy=%t/%s", legacy, test.name), func(t *testing.T) {
				var content, extension string
				if legacy {
					extension = "yml"
					content = fmt.Sprintf(`Nodes:
  - Type: UniProxy
    MasterPassword: %s
    ApiConfig:
      ApiHost: https://panel.example.test
      ApiKey: local-test-key
      NodeID: 4
      NodeType: anytls
      PanelTag: master-test
`, test.raw)
				} else {
					extension = "json"
					content = fmt.Sprintf(`{"services":[{"type":"xboard","tag":"master-test",
"api_host":"https://panel.example.test","api_key":"local-test-key","node_id":4,
"node_type":"anytls","inbound":"master-test","auto_inbound":{"master_password":%s}}]}`, test.raw)
				}
				path := filepath.Join(t.TempDir(), "server."+extension)
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				entry, err := readConfigAt(path)
				if test.invalid {
					if err == nil {
						t.Fatal("non-string master password was silently accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				settings := entry.options.Services[0].Options.(*option.XBoardServiceOptions)
				if settings.AutoInbound == nil || settings.AutoInbound.MasterPassword != test.want {
					t.Fatal("master password was dropped or normalized")
				}
			})
		}
	}
}
