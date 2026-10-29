package xboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	anytlsclient "github.com/anytls/sing-anytls"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/trojan"
	T "github.com/sagernet/sing-box/transport/trojan"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func sspanelTestClient(t *testing.T, protocol string, handler http.HandlerFunc) (*sspanelProvider, *panelClient) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	provider, err := newSSPanelProvider(protocol)
	if err != nil {
		t.Fatal(err)
	}
	p := provider.(*sspanelProvider)
	return p, &panelClient{provider: p, client: server.Client(), options: option.XBoardPanelOptions{
		PanelType: "sspanel", APIHost: server.URL, APIKey: "fixture-key", NodeID: 17, NodeType: protocol,
	}}
}

func TestSSPanelWire(t *testing.T) {
	tests := []struct {
		endpoint string
		method   string
		path     string
		input    string
		wantBody string
		data     string
		nodeID   bool
	}{
		{"config", "GET", "/mod_mu/nodes/17/info", "", "",
			`{"version":"2023.1","custom_config":{"offset_port_node":"443"}}`, false},
		{"user", "GET", "/mod_mu/users", "", "", `[]`, true},
		{"rules", "GET", "/mod_mu/func/detect_rules", "", "", `[]`, true},
		{"push", "POST", "/mod_mu/users/traffic", `{"18446744073709551615":[3,-5]}`,
			`{"data":[{"user_id":18446744073709551615,"u":3,"d":-5}]}`, `{}`, true},
		{"alive", "POST", "/mod_mu/users/aliveip", `{"1":["192.0.2.1","192.0.2.1"]}`,
			`{"data":[{"user_id":1,"ip":"192.0.2.1"},{"user_id":1,"ip":"192.0.2.1"}]}`, `{}`, true},
		{"illegal", "POST", "/mod_mu/users/detectlog", `[{"user_id":7,"list_id":42}]`,
			`{"data":[{"user_id":7,"list_id":42}]}`, `{}`, true},
		{"status", "POST", "/mod_mu/nodes/17/info", `{"uptime":"100","load":"1.00 1.00 1.00"}`,
			`{"uptime":"100","load":"1.00 1.00 1.00"}`, `{}`, false},
	}
	for _, test := range tests {
		t.Run(test.endpoint, func(t *testing.T) {
			p, client := sspanelTestClient(t, "vmess", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != test.method || r.URL.Path != test.path {
					t.Errorf("request = %s %s", r.Method, r.URL.Path)
				}
				query := r.URL.Query()
				if query.Get("key") != "fixture-key" || query.Get("muKey") != "fixture-key" {
					t.Error("missing SSPanel authentication query")
				}
				wantKeys := 2
				if test.nodeID {
					wantKeys++
					if query.Get("node_id") != "17" {
						t.Error("missing node ID query")
					}
				}
				if len(query) != wantKeys {
					t.Errorf("unexpected query keys: %d", len(query))
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if string(body) != test.wantBody {
					t.Errorf("body = %s, want %s", body, test.wantBody)
				}
				fmt.Fprintf(w, `{"ret":1,"data":%s}`, test.data)
			})
			var body []byte
			if test.input != "" {
				body = []byte(test.input)
			}
			_, status, _, err := p.request(context.Background(), client, "ignored", test.endpoint, "ignored", body)
			if err != nil || status != http.StatusOK {
				t.Fatalf("status = %d, error = %v", status, err)
			}
		})
	}
}

func TestSSPanelUsersAndLimits(t *testing.T) {
	provider, _ := newSSPanelProvider("shadowsocks")
	p := provider.(*sspanelProvider)
	p.online[4] = 2
	body := []byte(`[
		{"id":1,"uuid":"literal-uuid","passwd":"secret","node_speedlimit":1.25,"node_connector":5},
		{"id":2,"passwd":"secret","node_connector":1,"alive_ip":2},
		{"id":3,"uuid":"dropped","node_connector":1,"alive_ip":1},
		{"id":4,"uuid":"fallback-local","node_connector":1,"alive_ip":3},
		{"id":5,"uuid":"unlimited","node_connector":0,"alive_ip":99,"node_speedlimit":0.000008},
		{"id":6,"passwd":"00000000-0000-0000-0000-000000000001"},
		{"id":7}
	]`)
	response, err := p.decodeUsers(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Users) != 5 {
		t.Fatalf("users = %+v", response.Users)
	}
	users := make(map[uint64]panelUser)
	for _, user := range response.Users {
		users[user.ID] = user
	}
	if *users[1].SpeedLimitBytes != 156250 || users[1].ProtocolPassword != "secret" || users[1].UUID != "literal-uuid" {
		t.Fatalf("fractional speed or independent credentials lost: %+v", users[1])
	}
	if users[2].UUID != uuid.NewV5(uuid.Nil, "secret").String() || uint16(users[2].DeviceLimit) != 65535 {
		t.Fatalf("UUID derivation or uint16 wrap lost: %+v", users[2])
	}
	if users[4].DeviceLimit != 2 || users[5].DeviceLimit != 0 || *users[5].SpeedLimitBytes != 1 {
		t.Fatalf("device calculation or small speed incorrect: %+v", users)
	}
	if users[6].UUID != "00000000-0000-0000-0000-000000000001" {
		t.Fatal("valid password UUID was not retained")
	}
	for _, protocol := range []string{"vmess", "vless", "trojan", "anytls"} {
		provider, _ := newSSPanelProvider(protocol)
		response, err := provider.decodeUsers([]byte(`[{"id":1,"uuid":"uuid-password","passwd":"ss-secret"}]`))
		if err != nil || len(response.Users) != 1 || response.Users[0].ProtocolPassword != "" {
			t.Fatalf("%s must use UUID, not SS password: %+v %v", protocol, response, err)
		}
	}
	for _, bad := range []string{
		`[{"id":-1}]`, `[{"node_connector":65536}]`, `[{"alive_ip":-1}]`, `[{"node_speedlimit":"1"}]`,
	} {
		if _, err := p.decodeUsers([]byte(bad)); err == nil {
			t.Fatalf("accepted invalid numeric width/type: %s", bad)
		}
	}
}

func TestSSPanelOnlineFailureStillUpdatesLimits(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	p, client := sspanelTestClient(t, "trojan", func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		fmt.Fprint(w, `{"ret":0,"data":{}}`)
	})
	done := make(chan error, 1)
	go func() {
		_, _, _, err := p.request(context.Background(), client, "POST", "alive", "", []byte(`{"1":["a","b"]}`))
		done <- err
	}()
	<-entered
	if p.onlineAccess.TryLock() {
		p.onlineAccess.Unlock()
		close(release)
		t.Fatal("online mutex was released before HTTP completed")
	}
	decoded := make(chan usersResponse, 1)
	go func() {
		response, _ := p.decodeUsers([]byte(`[{"id":1,"uuid":"u","node_connector":1,"alive_ip":3}]`))
		decoded <- response
	}()
	close(release)
	if err := <-done; err == nil {
		t.Fatal("ret=0 must fail")
	}
	response := <-decoded
	if len(response.Users) != 1 || response.Users[0].DeviceLimit != 2 {
		t.Fatalf("failed HTTP must retain new local online count: %+v", response)
	}
	p.onlineAccess.Lock()
	_, err := p.onlineBody([]byte(`{}`))
	p.onlineAccess.Unlock()
	if err != nil || len(p.online) != 0 {
		t.Fatalf("empty online report did not reset counts: %v", err)
	}
}

func TestSSPanelETagAndRuleTransactions(t *testing.T) {
	var phase int
	p, client := sspanelTestClient(t, "trojan", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mod_mu/users" {
			if phase != 0 && r.Header.Get("If-None-Match") != "users-v1" {
				t.Error("users ETag not retained after payload parse failure")
			}
			w.Header().Set("ETag", "users-v1")
			fmt.Fprint(w, `{"ret":1,"data":{"invalid":"users"}}`)
			return
		}
		if r.URL.Path != "/mod_mu/func/detect_rules" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		switch phase {
		case 0:
			if r.Header.Get("If-None-Match") != "" {
				t.Error("rules inherited user ETag")
			}
			w.Header().Set("ETag", "rules-v1")
			fmt.Fprint(w, `{"ret":1,"data":[{"id":42,"regex":"example\\.com"}]}`)
		case 1:
			if r.Header.Get("If-None-Match") != "rules-v1" {
				t.Error("rules ETag not supplied")
			}
			w.WriteHeader(http.StatusNotModified)
		case 2:
			w.Header().Set("ETag", "rules-invalid")
			fmt.Fprint(w, `{"ret":1,"data":[{"id":7,"regex":"["}]}`)
		case 3:
			if r.Header.Get("If-None-Match") != "rules-invalid" {
				t.Error("original ETag update must precede regex parsing")
			}
			fmt.Fprint(w, `{"ret":0,"data":"private-payload"}`)
		}
	})
	body, _, _, err := p.request(context.Background(), client, "GET", "user", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.decodeUsers(body); err == nil {
		t.Fatal("invalid user payload accepted")
	}
	if err := p.RefreshNodeRules(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	want := p.NodeRules()
	if len(want) != 1 || want[0].ID != 42 {
		t.Fatalf("rule ID changed: %+v", want)
	}
	for phase = 1; phase <= 3; phase++ {
		err := p.RefreshNodeRules(context.Background(), client)
		if (err != nil) != (phase >= 2) {
			t.Fatalf("phase %d: %v", phase, err)
		}
		if err != nil && strings.Contains(err.Error(), "private-payload") {
			t.Fatal("response data leaked into error")
		}
		if !reflect.DeepEqual(p.NodeRules(), want) {
			t.Fatal("failed/unchanged rules replaced the previous snapshot")
		}
	}
	_, _, _, _ = p.request(context.Background(), client, "GET", "user", "", nil)
	copy := p.NodeRules()
	copy[0].Pattern = "changed"
	if p.NodeRules()[0].Pattern == "changed" {
		t.Fatal("NodeRules exposed mutable state")
	}
}

func TestSSPanelNodeFormats(t *testing.T) {
	tests := []struct {
		name, protocol, data, network, tls, port, host, path, service, cipher string
		vless                                                                 bool
	}{
		{"custom-vmess", "v2ray", `{"version":"2023.2","custom_config":{"offset_port_node":"65537",` +
			`"network":"ws","security":"xtls","enable_vless":"1","host":"h","path":"/p",` +
			`"servicename":"s","mu_encryption":"m"}}`, "ws", "1", "1", "h", "/p", "s", "m", true},
		{"custom-ss", "shadowsocks", `{"version":"v","custom_config":{"offset_port_node":"443",` +
			`"network":"grpc","security":"tls","mu_encryption":"aes-128-gcm","server_key":"base64"}}`,
			"tcp", "0", "443", "", "", "", "aes-128-gcm", false},
		{"custom-trojan", "trojan", `{"version":"v","custom_config":{"offset_port_node":"443","grpc":"1"}}`,
			"grpc", "1", "443", "", "", "", "", false},
		{"custom-anytls", "anytls", `{"version":"v","custom_config":{"offset_port_node":"443",` +
			`"security":"tls","network":"ws"}}`, "", "0", "443", "", "", "", "", false},
		{"legacy-vmess", "vmess", `{"server":"example;443;ignored;tls;ws;` +
			`host=h=ignored|path=/p?a=b|servicename=s|headerType=http"}`, "ws", "1", "443", "h", "/p?a=b", "s", "", false},
		{"legacy-trojan", "trojan", `{"server":"example;port=443#8443|host=example.com|grpc=0|servicename=s"}`,
			"grpc", "1", "8443", "example.com", "", "s", "", false},
		{"legacy-trojan-outer-port", "trojan", `{"server":"example;port=443|host=ab-c.example"}`,
			"tcp", "1", "443", "", "", "", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, _ := newSSPanelProvider(test.protocol)
			p := provider.(*sspanelProvider)
			var info sspanelNodeInfo
			if err := json.Unmarshal([]byte(test.data), &info); err != nil {
				t.Fatal(err)
			}
			result, err := p.nodeConfig(context.Background(), nil, info)
			if err != nil {
				t.Fatal(err)
			}
			var transport panelTransportSettings
			if len(result.NetworkSettings) > 0 {
				if err := json.Unmarshal(result.NetworkSettings, &transport); err != nil {
					t.Fatal(err)
				}
			}
			if result.Network != test.network || string(result.TLS) != test.tls || string(result.ServerPort) != test.port ||
				transport.Host != test.host || transport.Path != test.path || transport.ServiceName != test.service ||
				result.Cipher != test.cipher || result.PanelVLESS != test.vless {
				t.Fatalf("node = %+v, transport = %+v", result, transport)
			}
		})
	}
	for _, protocol := range []string{"vmess", "trojan", "anytls"} {
		provider, _ := newSSPanelProvider(protocol)
		p := provider.(*sspanelProvider)
		for _, server := range []string{"", "missing-fields", "x;443;x;tls;ws;missing-equals"} {
			if _, err := p.nodeConfig(context.Background(), nil, sspanelNodeInfo{Server: server}); err == nil {
				t.Errorf("%s accepted malformed legacy server %q", protocol, server)
			}
		}
	}
}

func TestSSPanelLegacyShadowsocksUsesUnfilteredSharedUser(t *testing.T) {
	requests := 0
	p, client := sspanelTestClient(t, "shadowsocks", func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/mod_mu/nodes/17/info" {
			fmt.Fprint(w, `{"ret":1,"data":{"server":"not-used"}}`)
			return
		}
		if r.URL.Path != "/mod_mu/users" || r.Header.Get("If-None-Match") != "" {
			t.Error("shared-user lookup must use an independent non-ETag request")
		}
		fmt.Fprint(w, `{"ret":1,"data":[{"port":123,"method":"ignored"},`+
			`{"is_multi_user":1,"port":8388,"method":"aes-128-gcm"},`+
			`{"is_multi_user":1,"port":9999,"method":"ignored"}]}`)
	})
	p.etags["users"] = "must-not-be-used"
	body, _, _, err := p.request(context.Background(), client, "GET", "config", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result autoConfigResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || string(result.ServerPort) != "8388" || result.Cipher != "aes-128-gcm" {
		t.Fatalf("unexpected shared-user node: requests=%d config=%+v", requests, result)
	}
}

func TestSSPanelStatusAndIllegal(t *testing.T) {
	var bodies []string
	p, client := sspanelTestClient(t, "trojan", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		fmt.Fprint(w, `{"ret":1,"data":null}`)
	})
	for _, version := range []string{"", "2022.12", "2023.1", "2023.2", "2023.2.0", "2023.10"} {
		p.version = version
		if err := p.reportStatus(context.Background(), client); err != nil {
			t.Fatal(err)
		}
	}
	if len(bodies) != 3 {
		t.Fatalf("status version gate sent %d reports", len(bodies))
	}
	for _, body := range bodies {
		if body != `{"uptime":"100","load":"1.00 1.00 1.00"}` {
			t.Fatalf("wrong compatibility status: %s", body)
		}
	}
	if err := p.reportIllegal(context.Background(), client, nil); err != nil {
		t.Fatal(err)
	}
	if bodies[len(bodies)-1] != `{"data":[]}` {
		t.Fatal("empty illegal batch must be an array")
	}
}

func TestSSPanelReportDoesNotAcknowledgeNotModified(t *testing.T) {
	p, client := sspanelTestClient(t, "trojan", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})
	if err := p.reportIllegal(context.Background(), client, []panelIllegalRecord{{UserID: 1, RuleID: 2}}); err == nil {
		t.Fatal("304 must not acknowledge an illegal report")
	}
	if err := p.reportStatus(context.Background(), client); err == nil {
		t.Fatal("304 must not acknowledge a status report")
	}
}

func TestSSPanelConcurrentState(t *testing.T) {
	p, client := sspanelTestClient(t, "vmess", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "v1")
		fmt.Fprint(w, `{"ret":1,"data":[]}`)
	})
	var workers sync.WaitGroup
	for worker := range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 20 {
				switch worker {
				case 0:
					_, _, _, _ = p.request(context.Background(), client, "POST", "alive", "", []byte(`{"1":["ip"]}`))
				case 1:
					_, _ = p.decodeUsers([]byte(`[{"id":1,"uuid":"u","node_connector":1,"alive_ip":1}]`))
				case 2:
					_ = p.RefreshNodeRules(context.Background(), client)
				case 3:
					_ = p.NodeRules()
				}
			}
		}()
	}
	workers.Wait()
	if _, err := newSSPanelProvider(C.TypeTUIC); err != C.ErrUDPDisabled {
		t.Fatal("UDP-only protocol was accepted")
	}
}

type sspanelCredentialRouter struct{ credentialRouter }

func (r *sspanelCredentialRouter) RouteConnectionEx(_ context.Context, conn net.Conn,
	metadata adapter.InboundContext, onClose N.CloseHandlerFunc,
) {
	r.users <- metadata.User
	go func() {
		_, err := io.Copy(conn, conn)
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func TestSSPanelToActualProtocolCredentials(t *testing.T) {
	const credential = "00000000-0000-0000-0000-000000000007"
	for _, protocol := range []string{"shadowsocks", "trojan", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			var response atomic.Value
			response.Store(`{"ret":0,"data":"fixture-private-error"}`)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/mod_mu/func/detect_rules" {
					fmt.Fprint(w, `{"ret":1,"data":[]}`)
					return
				}
				if r.URL.Path == "/mod_mu/nodes/17/info" {
					fmt.Fprint(w, `{"ret":1,"data":{"version":"2023.2","custom_config":`+
						`{"offset_port_node":"18017","mu_encryption":"aes-128-gcm"}}}`)
					return
				}
				if r.URL.Path != "/mod_mu/users" {
					t.Errorf("unexpected request %s", r.URL.Path)
				}
				fmt.Fprint(w, response.Load().(string))
			}))
			defer server.Close()
			n := userSyncNode(server, "sspanel-test", &userSyncInbound{})
			client, err := newPanelClient(option.XBoardPanelOptions{
				PanelType: "sspanel", APIHost: server.URL, APIKey: "fixture-key", NodeID: 17,
				NodeType: protocol, PanelTag: "sspanel-test",
			})
			if err != nil {
				t.Fatal(err)
			}
			n.primary.client, n.nodeType = client, protocol
			router := &sspanelCredentialRouter{credentialRouter{users: make(chan string, 8)}}
			logger := log.NewNOPFactory().Logger()
			var managed adapter.ManagedSSMServer
			var current func() adapter.TCPInjectableInbound
			switch protocol {
			case "shadowsocks":
				registry := inbound.NewRegistry()
				shadowsocks.RegisterInbound(registry)
				holder := newEmptyAutoInbound(context.Background(), registry, router, logger, "ss", C.TypeShadowsocks)
				defer holder.close()
				n.auto, n.inbound = holder, holder
				n.autoOptions = option.XBoardAutoInboundOptions{ShadowsocksObfsMu: "aes-128-gcm"}
				managed = holder
				current = func() adapter.TCPInjectableInbound { return holder.current.inbound.(adapter.TCPInjectableInbound) }
			case "trojan":
				created, err := trojan.NewInbound(context.Background(), router, logger, "trojan",
					option.TrojanInboundOptions{})
				if err != nil {
					t.Fatal(err)
				}
				managed = created.(adapter.ManagedSSMServer)
				n.inbound = managed
				current = func() adapter.TCPInjectableInbound { return created.(adapter.TCPInjectableInbound) }
			case "anytls":
				created, err := anytls.NewInbound(context.Background(), router, logger, "anytls", option.AnyTLSInboundOptions{})
				if err != nil {
					t.Fatal(err)
				}
				managed = created.(adapter.ManagedSSMServer)
				n.inbound = managed
				current = func() adapter.TCPInjectableInbound { return created.(adapter.TCPInjectableInbound) }
			}
			managed.SetTracker(n.control)
			if err := n.syncUsers(context.Background()); err == nil || strings.Contains(err.Error(), "fixture-private-error") {
				t.Fatal("initial panel failure was accepted or exposed its payload")
			}
			if len(n.users) != 0 {
				t.Fatal("failed first user fetch published identities")
			}
			for _, password := range []string{"ss-panel-password", "rotated-password"} {
				response.Store(fmt.Sprintf(`{"ret":1,"data":[{"id":7,"uuid":%q,"passwd":%q,"node_speedlimit":0}]}`,
					credential, password))
				if err := n.syncUsers(context.Background()); err != nil {
					t.Fatal(err)
				}
				if protocol == "shadowsocks" {
					err = exchangeSeparatePassword(current(), credential, password)
				} else {
					err = sspanelExchange(current(), protocol, credential)
				}
				if err != nil {
					t.Fatal(err)
				}
				select {
				case identity := <-router.users:
					if identity != "7@sspanel-test@sspanel" {
						t.Fatalf("authentication attributed to %q", identity)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("authenticated stream did not reach routing")
				}
				if protocol == "shadowsocks" {
					err = exchangeSeparatePassword(current(), credential, credential)
				} else {
					err = sspanelExchange(current(), protocol, password)
				}
				if err == nil {
					t.Fatal("wrong provider credential was accepted")
				}
			}
			if n.traffic.SnapshotTraffic([]string{"7@sspanel-test@sspanel"})[0].UplinkBytes == 0 {
				t.Fatal("authenticated bytes did not reach accounting")
			}
			if protocol == "shadowsocks" {
				if err := exchangeSeparatePassword(current(), credential, "ss-panel-password"); err == nil {
					t.Fatal("previous SSPanel password survived rotation")
				}
			}
			select {
			case identity := <-router.users:
				t.Fatalf("rejected authentication reached routing: %s", identity)
			default:
			}
		})
	}
}

func TestSSPanelAutomaticProtocolAndTransportMapping(t *testing.T) {
	provider, _ := newSSPanelProvider("v2ray")
	p := provider.(*sspanelProvider)
	result, err := p.customNodeConfig(autoConfigResponse{Protocol: "vmess", TLS: json.RawMessage("0")},
		[]byte(`{"offset_port_node":"443","enable_vless":"1","network":"ws","host":"cover.example","path":"/socket"}`))
	if err != nil {
		t.Fatal(err)
	}
	result.providerNormalized = true
	config, err := result.buildInboundConfig("v2ray", option.XBoardAutoInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	options, ok := config.options.(*option.VLESSInboundOptions)
	if !ok || config.protocol != C.TypeVLESS {
		t.Fatalf("panel enable_vless did not select VLESS: %s", config.protocol)
	}
	if options.TLS != nil && options.TLS.Enabled {
		t.Fatal("SSPanel security omission unexpectedly enabled TLS")
	}
	if options.Transport.WebsocketOptions.Path != "/socket" ||
		!reflect.DeepEqual([]string(options.Transport.WebsocketOptions.Headers["Host"]), []string{"cover.example"}) {
		t.Fatalf("WebSocket host/path not mapped: %+v", options.Transport.WebsocketOptions)
	}
	provider, _ = newSSPanelProvider("anytls")
	p = provider.(*sspanelProvider)
	result, err = p.customNodeConfig(autoConfigResponse{Protocol: "anytls", TLS: json.RawMessage("0")},
		[]byte(`{"offset_port_node":"443"}`))
	if err != nil {
		t.Fatal(err)
	}
	result.providerNormalized = true
	config, err = result.buildInboundConfig("anytls", option.XBoardAutoInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	anyOptions := config.options.(*option.AnyTLSInboundOptions)
	if anyOptions.TLS != nil && anyOptions.TLS.Enabled {
		t.Fatal("SSPanel AnyTLS incorrectly inherited UniProxy's mandatory TLS")
	}
}

func sspanelExchange(inbound adapter.TCPInjectableInbound, protocol, password string) error {
	var handlers sync.WaitGroup
	dial := func(context.Context) (net.Conn, error) {
		server, client := net.Pipe()
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			inbound.NewConnection(context.Background(), server,
				adapter.InboundContext{Source: M.ParseSocksaddr("127.0.0.1:12345")}, nil)
		}()
		return client, nil
	}
	defer handlers.Wait()
	var conn net.Conn
	if protocol == "anytls" {
		client, err := anytlsclient.NewClient(context.Background(), anytlsclient.ClientConfig{
			Password: password, Logger: log.NewNOPFactory().Logger(),
			AuthenticationTimeout: time.Second, DialOut: dial,
		})
		if err != nil {
			return err
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err = client.CreateProxy(ctx, M.ParseSocksaddr("example.com:443"))
		if err != nil {
			return err
		}
	} else {
		raw, err := dial(context.Background())
		if err != nil {
			return err
		}
		conn = T.NewClientConn(raw, T.Key(password), M.ParseSocksaddr("example.com:443"))
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("SSPanel credential round trip")
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if string(response) != string(payload) {
		return fmt.Errorf("echo payload differs")
	}
	return nil
}
