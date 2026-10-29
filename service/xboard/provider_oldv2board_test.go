package xboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/nodepolicy"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing/service"
)

func TestOldV2BoardProtocolAliasesStayProviderLocal(t *testing.T) {
	for _, test := range []struct{ raw, protocol string }{
		{"v2ray", C.TypeVMess}, {"trojan", C.TypeTrojan}, {"trojantidalab", C.TypeTrojan},
		{"shadowsocks", C.TypeShadowsocks}, {"shadowsockstidalab", C.TypeShadowsocks},
	} {
		t.Run(test.raw, func(t *testing.T) {
			manager := inbound.NewManager(nil, endpoint.NewManager(nil))
			ctx := service.ContextWith[adapter.InboundManager](context.Background(), manager)
			ctx = service.ContextWith[adapter.InboundRegistry](ctx, inbound.NewRegistry())
			ctx = service.ContextWith[adapter.Router](ctx, struct{ adapter.Router }{})
			created, err := NewService(ctx, log.NewNOPFactory().Logger(), "legacy", option.XBoardServiceOptions{
				PanelType: "oldv2board", APIHost: "http://127.0.0.1:1", APIKey: "test", NodeID: 1,
				NodeType: test.raw, Inbound: "automatic", AutoInbound: &option.XBoardAutoInboundOptions{},
			})
			if err != nil {
				t.Fatal(err)
			}
			n := created.(*Service).nodes[0]
			defer n.auto.close()
			if n.nodeType != test.protocol || n.auto.Type() != test.protocol ||
				n.primary.client.options.NodeType != test.raw {
				t.Fatal("provider's raw HTTP type was conflated with its internal protocol")
			}
			response := autoConfigResponse{Protocol: test.protocol, ServerPort: json.RawMessage(`443`),
				Network: "tcp", Cipher: "aes-128-gcm"}
			if _, err = response.buildInboundConfig(n.nodeType, option.XBoardAutoInboundOptions{
				CertificatePath: "certificate.pem", KeyPath: "key.pem",
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, raw := range []string{"trojantidalab", "shadowsockstidalab"} {
		if _, err := automaticProtocol(raw, option.XBoardAutoInboundOptions{}); err == nil {
			t.Fatal("legacy alias was incorrectly enabled for every provider")
		}
	}
}

func TestOldV2BoardRulesAndNotModifiedRetainSnapshot(t *testing.T) {
	var response atomic.Value
	response.Store(`{"inbound":{"port":443,"streamSettings":{"network":"tcp"}},` +
		`"routing":{"rules":[{}, {"domain":["regexp:^blocked$", "other"]}]}}`)
	var status atomic.Int32
	status.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		io.WriteString(w, response.Load().(string))
	}))
	defer server.Close()
	client := oldPanelClient(t, server, "v2ray")
	provider := client.provider.(*oldV2BoardProvider)
	request := func() (int, error) {
		_, code, _, err := client.request(context.Background(), http.MethodGet, "config", "", nil)
		return code, err
	}
	if _, err := request(); err != nil {
		t.Fatal(err)
	}
	want := []nodepolicy.Rule{{ID: 0, Pattern: "^blocked$"}, {ID: 1, Pattern: "other"}}
	copy := provider.NodeRules()
	copy[0].Pattern = "changed"
	if !reflect.DeepEqual(provider.NodeRules(), want) {
		t.Fatal("caller mutated provider rules")
	}
	status.Store(http.StatusNotModified)
	response.Store("")
	if code, err := request(); err != nil || code != http.StatusNotModified {
		t.Fatalf("304 was incorrectly parsed as JSON: %d %v", code, err)
	}
	status.Store(http.StatusOK)
	for _, body := range []string{"private invalid JSON", `{"inbounds":[]}`,
		`{"inbound":{},"routing":{"rules":[{}, {"domain":["["]}]}}`} {
		response.Store(body)
		if _, err := request(); err == nil {
			t.Fatal("invalid config accepted")
		}
		if !reflect.DeepEqual(provider.NodeRules(), want) {
			t.Fatal("failed node update replaced the last rules")
		}
	}
	var done sync.WaitGroup
	for i := 0; i < 2; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			for j := 0; j < 100; j++ {
				provider.NodeRules()
			}
		}()
	}
	root, _ := decodeOldV2BoardJSON([]byte(`{"inbound":{}}`))
	for i := 0; i < 100; i++ {
		if _, err := provider.nodeConfig(root); err != nil {
			t.Fatal(err)
		}
	}
	done.Wait()
	if len(provider.NodeRules()) != 0 {
		t.Fatal("successful empty rules did not clear the prior snapshot")
	}
}

func oldPanelClient(t *testing.T, server *httptest.Server, nodeType string) *panelClient {
	t.Helper()
	client, err := newPanelClient(option.XBoardPanelOptions{
		PanelType: "OldV2Board", PanelTag: "legacy", APIHost: server.URL,
		APIKey: "private-panel-key", NodeID: 17, NodeType: nodeType,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestOldV2BoardWireContract(t *testing.T) {
	for _, test := range []struct {
		nodeType, namespace string
	}{
		{"v2ray", "Deepbwork"}, {"trojan", "TrojanTidalab"},
		{"trojantidalab", "TrojanTidalab"}, {"shadowsocks", "ShadowsocksObfsMu"},
		{"shadowsockstidalab", "ShadowsocksTidalab"},
	} {
		t.Run(test.nodeType, func(t *testing.T) {
			var count atomic.Int32
			var pushed []map[string]json.RawMessage
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				query := r.URL.Query()
				if query.Get("token") != "private-panel-key" || query.Get("node_id") != "17" || len(query) != 2 {
					t.Error("legacy query differs from token + node_id")
				}
				if r.Header.Get("If-None-Match") != "" {
					t.Error("legacy request unexpectedly used ETag")
				}
				prefix := "/api/v1/server/" + test.namespace + "/"
				if !strings.HasPrefix(r.URL.Path, prefix) {
					t.Errorf("wrong legacy endpoint: %s", r.URL.Path)
				}
				switch strings.TrimPrefix(r.URL.Path, prefix) {
				case "user":
					if r.Method != http.MethodGet {
						t.Error("user request was not GET")
					}
					io.WriteString(w, `{"data":[{"id":18446744073709551615,"secret":"legacy-secret",`+
						`"cipher":"aes-128-gcm","port":443,"v2ray_user":{"uuid":"raw-uuid"},`+
						`"trojan_user":{"password":"raw-trojan-password"}}]}`)
				case "config":
					if r.Method != http.MethodGet {
						t.Error("config request was not GET")
					}
					io.WriteString(w, `{"local_port":443,"ssl":{"sni":"legacy.example"},`+
						`"inbound":{"port":443,"streamSettings":{"network":"tcp","security":"none"}}}`)
				case "submit":
					if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
						t.Error("submit was not a JSON POST")
					}
					if err := json.NewDecoder(r.Body).Decode(&pushed); err != nil {
						t.Error(err)
					}
					io.WriteString(w, `{"data":true}`)
				default:
					t.Errorf("unexpected endpoint: %s", r.URL.Path)
				}
			}))
			defer server.Close()
			client := oldPanelClient(t, server, test.nodeType)
			body, _, etag, err := client.request(context.Background(), http.MethodGet, "user", "ignored", nil)
			if err != nil || etag != "" {
				t.Fatal(err)
			}
			users, err := client.decodeUsers(body)
			if err != nil {
				t.Fatal(err)
			}
			if test.nodeType == "trojantidalab" {
				if len(users.Users) != 0 {
					t.Fatal("URL alias incorrectly canonicalized before original user conversion")
				}
			} else if len(users.Users) != 1 || users.Users[0].ID != ^uint64(0) {
				t.Fatal("legacy uint64 user ID changed")
			}
			if client.userName(8) != "8@legacy@oldv2b" {
				t.Fatal("legacy provider identity namespace changed")
			}
			body, _, _, err = client.request(context.Background(), http.MethodGet, "config", "ignored", nil)
			if err != nil {
				t.Fatal(err)
			}
			var config autoConfigResponse
			if json.Unmarshal(body, &config) != nil || string(config.ServerPort) != "443" {
				t.Fatal("legacy config normalization failed")
			}
			_, _, _, err = client.request(context.Background(), http.MethodPost, "push", "",
				[]byte(`{"18446744073709551615":[31,47]}`))
			if err != nil || len(pushed) != 1 || string(pushed[0]["user_id"]) != "18446744073709551615" ||
				string(pushed[0]["u"]) != "31" || string(pushed[0]["d"]) != "47" || len(pushed[0]) != 3 {
				t.Fatalf("legacy submit format changed: %v", err)
			}
			before := count.Load()
			for _, endpoint := range []string{"alive", "status", "illegal"} {
				if _, _, _, err = client.request(context.Background(), http.MethodPost, endpoint, "", nil); err != nil {
					t.Fatal(err)
				}
			}
			if count.Load() != before {
				t.Fatal("legacy no-op report sent an HTTP request")
			}
		})
	}
}

func TestOldV2BoardConfigurationAndUserQuirks(t *testing.T) {
	provider, _ := newOldV2BoardProvider("v2ray")
	for _, rootKey := range []string{"inbound", "inbounds"} {
		for _, network := range []string{"ws", "grpc"} {
			node := `{"port":65537,"streamSettings":{"network":"` + network + `","security":"tls",` +
				`"wsSettings":{"path":"/old","headers":{"Host":"legacy.example","Ignored":"unused"}},` +
				`"grpcSettings":{"serviceName":"old-service"}}}`
			if rootKey == "inbounds" {
				node = "[" + node + "]"
			}
			root, _ := decodeOldV2BoardJSON([]byte(`{"` + rootKey + `":` + node + `,` +
				`"routing":{"rules":[{"domain":["ignored"]},{"domain":["regexp:^blocked$","second"]},` +
				`{"domain":["also-ignored"]}]}}`))
			config, err := provider.nodeConfig(root)
			if err != nil || string(config.ServerPort) != "1" || string(config.TLS) != "1" || config.Network != network {
				t.Fatalf("legacy config conversion failed: %v", err)
			}
			if len(provider.rules) != 2 || provider.rules[0].String() != "^blocked$" ||
				provider.rules[1].String() != "second" {
				t.Fatal("legacy fixed second routing rule semantics changed")
			}
			var settings map[string]any
			json.Unmarshal(config.NetworkSettings, &settings)
			if network == "ws" && (settings["path"] != "/old" ||
				!reflect.DeepEqual(settings["headers"], map[string]any{"Host": "legacy.example"})) {
				t.Fatal("legacy websocket fields changed")
			}
			if network == "grpc" && settings["serviceName"] != "old-service" {
				t.Fatal("legacy gRPC field changed")
			}
		}
	}
	ss, _ := newOldV2BoardProvider("shadowsocks")
	for _, secret := range []string{"old-secret", "4A18C093-3CDF-4ED6-963F-F1C49A000129", uuid.Nil.String()} {
		body, _ := json.Marshal(map[string]any{"data": []any{map[string]any{"id": 7, "secret": secret}}})
		users, err := ss.decodeUsers(body)
		want := uuid.FromStringOrNil(secret)
		if want.IsNil() {
			want = uuid.NewV5(uuid.Nil, secret)
		}
		if err != nil || len(users.Users) != 1 || users.Users[0].UUID != want.String() ||
			users.Users[0].ProtocolPassword != secret {
			t.Fatalf("independent legacy password/UUID normalization failed: %v", err)
		}
	}
	for _, body := range []string{`{}`, `{"data":[]}`, `{"data":[{"secret":""}]}`} {
		root, _ := decodeOldV2BoardJSON([]byte(body))
		if _, err := ss.nodeConfig(root); err == nil {
			t.Fatal("legacy SS config accepted zero normalized users")
		}
	}
	root, _ := decodeOldV2BoardJSON([]byte(`{"routing":{"rules":[{}, {"domain":["["]}]}}`))
	if _, err := oldV2BoardRules(root); err == nil {
		t.Fatal("invalid legacy regex silently ignored")
	}
}

func TestOldV2BoardPanelToActualObfsCredentials(t *testing.T) {
	var response atomic.Value
	response.Store(`{"data":[]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/ShadowsocksObfsMu/user" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		io.WriteString(w, response.Load().(string))
	}))
	defer server.Close()
	n := userSyncNode(server, "legacy", &userSyncInbound{})
	n.primary.client = oldPanelClient(t, server, "shadowsocks")
	n.nodeType = C.TypeShadowsocks
	registry := inbound.NewRegistry()
	shadowsocks.RegisterInbound(registry)
	router := &credentialRouter{users: make(chan string, 8)}
	holder := newEmptyAutoInbound(context.Background(), registry, router, log.NewNOPFactory().Logger(),
		"old", C.TypeShadowsocks)
	defer holder.close()
	n.auto, n.inbound = holder, holder
	n.autoOptions = option.XBoardAutoInboundOptions{ShadowsocksObfsMu: "aes-128-gcm"}
	holder.SetTracker(n.control)
	if err := n.syncUsers(context.Background()); err == nil || holder.hasCurrent() {
		t.Fatal("empty legacy SS initial response must remain retryable without a listener")
	}
	for index, secret := range []string{"old-panel-secret", "rotated-panel-secret"} {
		response.Store(fmt.Sprintf(`{"data":[{"id":9,"secret":%q,"cipher":"aes-128-gcm","port":%d}]}`,
			secret, 18000+index))
		if err := n.syncUsers(context.Background()); err != nil {
			t.Fatal(err)
		}
		identity := uuid.NewV5(uuid.Nil, secret).String()
		if err := exchangeSeparatePassword(holder.current.inbound.(adapter.TCPInjectableInbound), identity, secret); err != nil {
			t.Fatal(err)
		}
		if got := <-router.users; got != "9@legacy@oldv2b" {
			t.Fatalf("panel identity lost: %s", got)
		}
		if n.traffic.SnapshotTraffic([]string{"9@legacy@oldv2b"})[0].UplinkBytes == 0 {
			t.Fatal("actual SS data did not reach accounting")
		}
	}
	previous := holder.current
	response.Store(`not JSON private-panel-key`)
	if err := n.syncUsers(context.Background()); err == nil || strings.Contains(err.Error(), "private-panel-key") ||
		holder.current != previous || holder.passwords[0] != "rotated-panel-secret" {
		t.Fatal("malformed provider response lost credentials or exposed panel response")
	}
}
