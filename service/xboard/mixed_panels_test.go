package xboard

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestMixedProvidersKeepIdentityAndTrafficSources(t *testing.T) {
	tests := []struct {
		provider, namespace, userPath, pushPath, users, report string
		down                                                   int
	}{
		{"uniproxy", "uniproxy", "/api/v1/server/UniProxy/user", "/api/v1/server/UniProxy/push",
			`{"users":[{"id":7,"uuid":"credential-a"}]}`, `{"7":[0,3]}`, 3},
		{"oldv2board", "oldv2b", "/api/v1/server/TrojanTidalab/user", "/api/v1/server/TrojanTidalab/submit",
			`{"data":[{"id":7,"trojan_user":{"password":"credential-b"}}]}`,
			`[{"user_id":7,"u":0,"d":5}]`, 5},
		{"ppanel", "ppanel", "/v1/server/user", "/v1/server/push",
			`{"users":[{"id":7,"uuid":"credential-c"}]}`,
			`{"traffic":[{"uid":0,"upload":0,"download":0},{"uid":7,"upload":0,"download":7}]}`, 7},
		{"sspanel", "sspanel", "/mod_mu/users", "/mod_mu/users/traffic",
			`{"ret":1,"data":[{"id":7,"uuid":"credential-d"}]}`,
			`{"data":[{"user_id":7,"u":0,"d":11}]}`, 11},
	}
	var access sync.Mutex
	reports := make([][]string, len(tests))
	options := option.XBoardServiceOptions{}
	identities := make([]string, len(tests))
	var first *httptest.Server
	for index, test := range tests {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case test.userPath:
				if r.Method != http.MethodGet {
					t.Error("user synchronization did not use GET")
				}
				io.WriteString(w, test.users)
			case test.pushPath:
				if r.Method != http.MethodPost {
					t.Error("traffic synchronization did not use POST")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				access.Lock()
				reports[index] = append(reports[index], string(body))
				attempt := len(reports[index])
				access.Unlock()
				if test.provider == "sspanel" && attempt == 1 {
					io.WriteString(w, `{"ret":0}`)
					return
				}
				io.WriteString(w, `{"ret":1,"data":true}`)
			default:
				t.Errorf("unexpected mixed-provider request: %s", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(server.Close)
		if first == nil {
			first = server
		}
		tag := fmt.Sprintf("source-%d", index)
		options.Panels = append(options.Panels, option.XBoardPanelOptions{
			PanelTag: tag, PanelType: test.provider, APIHost: server.URL,
			APIKey: "fixture-token", NodeID: 1, NodeType: "trojan",
		})
		identities[index] = "7@" + tag + "@" + test.namespace
	}
	inbound := &userSyncInbound{}
	n := userSyncNode(first, "mixed", inbound)
	var err error
	n.primary, n.panels, err = createNodePanels(options, "mixed", "trojan")
	if err != nil {
		t.Fatal(err)
	}
	if err = n.syncUserList(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inbound.names, identities) || !reflect.DeepEqual(inbound.credentials,
		[]string{"credential-a", "credential-b", "credential-c", "credential-d"}) {
		t.Fatal("same numeric user IDs from distinct providers lost their identity or credential")
	}
	for index, test := range tests {
		addPanelDownload(n, identities[index], test.down)
	}
	if err = n.pushTraffic(context.Background()); err == nil {
		t.Fatal("SSPanel ret=0 was acknowledged in a mixed-provider report")
	}
	for index, snapshot := range n.traffic.SnapshotTraffic(identities) {
		want := int64(0)
		if index == 3 {
			want = 11
		}
		if snapshot.DownlinkBytes != want {
			t.Fatal("failed provider's bytes were lost or successful provider's bytes remained")
		}
	}
	addPanelDownload(n, identities[3], 2)
	if err = n.pushTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	access.Lock()
	defer access.Unlock()
	for index, test := range tests {
		want := []string{test.report}
		if index == 3 {
			want = append(want, `{"data":[{"user_id":7,"u":0,"d":13}]}`)
		}
		if !reflect.DeepEqual(reports[index], want) {
			t.Fatalf("provider %s reports = %v, want %v", test.provider, reports[index], want)
		}
	}
}
