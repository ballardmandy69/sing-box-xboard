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
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func ppanelTestConfig(protocol, config string) string {
	return fmt.Sprintf(`{"basic":{"push_interval":"60","pull_interval":30.9},"protocol":%q,"config":%s}`,
		protocol, config)
}

func TestPPanelConfigMapping(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol string
		config   string
		tls      string
		network  string
		cipher   string
	}{
		{"vmess clear", "vmess", `{"port":443,"transport":"tcp","transport_config":{},"security":"tls"}`, "0", "tcp", ""},
		{"vmess object", "vmess",
			`{"port":443,"transport":"ws","transport_config":{},"security":"none","security_config":{}}`, "1", "ws", ""},
		{"vless", "vless",
			`{"port":443,"transport":"grpc","transport_config":{},"flow":"ignored","security":"none"}`, "1", "grpc", ""},
		{"trojan", "trojan", `{"port":443,"transport":"httpupgrade","transport_config":{}}`, "1", "httpupgrade", ""},
		{"anytls", "anytls", `{"port":443}`, "1", "", ""},
		{"shadowsocks", "shadowsocks",
			`{"port":443,"method":"aes-128-gcm","server_key":"ignored"}`, "null", "", "aes-128-gcm"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, err := normalizePPanelConfig([]byte(ppanelTestConfig(test.protocol, test.config)))
			if err != nil {
				t.Fatal(err)
			}
			var got autoConfigResponse
			if err = json.Unmarshal(body, &got); err != nil {
				t.Fatal(err)
			}
			if got.Protocol != test.protocol || string(got.ServerPort) != "443" ||
				string(got.TLS) != test.tls || got.Network != test.network || got.Cipher != test.cipher {
				t.Fatalf("normalized config: %s", body)
			}
			if got.BaseConfig.PushInterval != 60 || got.BaseConfig.PullInterval != 30 {
				t.Fatalf("interval conversion: %+v", got.BaseConfig)
			}
			if got.ServerKey != "" || got.ServerName != "" || string(got.TLSSettings) != "null" {
				t.Fatalf("ignored fields were unexpectedly applied: %s", body)
			}
		})
	}
	body, err := normalizePPanelConfig([]byte(ppanelTestConfig("vless", `{
		"port":65979,"transport":"ws","transport_config":{"path":"/t","host":"example.test","service_name":"grpc-test"},
		"security_config":{"sni":"ignored.test","reality_private_key":"ignored"}}`)))
	if err != nil {
		t.Fatal(err)
	}
	var result autoConfigResponse
	if err = json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	var transport panelTransportSettings
	if err = json.Unmarshal(result.NetworkSettings, &transport); err != nil {
		t.Fatal(err)
	}
	if string(result.ServerPort) != "443" || transport.Path != "/t" || transport.Host != "example.test" ||
		transport.ServiceName != "grpc-test" {
		t.Fatalf("port cast or transport mapping: %s", body)
	}
}

func TestPPanelConfigRejectsUnsupportedAndInvalid(t *testing.T) {
	for _, body := range []string{
		`{`, `{"protocol":"anytls","config":{}}`,
		ppanelTestConfig("vmess", `{"port":443}`),
		ppanelTestConfig("hysteria2", `{"port":443}`),
		ppanelTestConfig("tuic", `{"port":443}`),
		ppanelTestConfig("Unknown", `{"port":443}`),
		`{"basic":{"push_interval":true,"pull_interval":1},"protocol":"anytls","config":{"port":443}}`,
	} {
		if _, err := normalizePPanelConfig([]byte(body)); err == nil {
			t.Fatalf("accepted invalid config: %s", body)
		}
	}
	if got, err := ppanelInterval("invalid"); err != nil || got != 0 {
		t.Fatalf("original invalid-string interval: %d %v", got, err)
	}
	for _, nodeType := range []string{"vmess", "V2RAY", "vless", "trojan", "anytls", "shadowsocks"} {
		provider, err := newPPanelProvider(nodeType)
		if err != nil || provider.identityTag() != "ppanel" {
			t.Fatalf("node=%s: %v", nodeType, err)
		}
	}
	for _, nodeType := range []string{"", "ss", " vmess ", "hysteria2", "tuic"} {
		if _, err := newPPanelProvider(nodeType); err == nil {
			t.Fatalf("accepted node=%q", nodeType)
		}
	}
}

func TestPPanelSS2022DoesNotApplyIgnoredPanelServerKey(t *testing.T) {
	const key = "MDEyMzQ1Njc4OWFiY2RlZg=="
	body, err := normalizePPanelConfig([]byte(ppanelTestConfig("shadowsocks", fmt.Sprintf(
		`{"port":443,"method":"2022-blake3-aes-128-gcm","server_key":%q}`, key))))
	if err != nil {
		t.Fatal(err)
	}
	var response autoConfigResponse
	if err = json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if _, err = response.shadowsocksOptions(option.ListenOptions{}, ""); err == nil {
		t.Fatal("ordinary SS2022 unexpectedly obtained the ignored PPanel server_key")
	}
	options, err := response.shadowsocksOptions(option.ListenOptions{}, "2022-blake3-aes-128-gcm:"+key)
	if err != nil {
		t.Fatal(err)
	}
	if options.Password != key || !strings.Contains(options.ObfsMu, ":") {
		t.Fatal("explicit local shared ObfsMu credentials were lost")
	}
}

func TestPPanelUsersFieldWidths(t *testing.T) {
	provider := ppanelProvider{}
	result, err := provider.decodeUsers([]byte(`{"users":[
		{"id":18446744073709551615,"uuid":"first","speed_limit":-1,"device_limit":65537,"connection_limit":99},
		{"id":2,"uuid":"second","speed_limit":12,"device_limit":65535},
		{"id":3,"uuid":"third","device_limit":-2}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Users) != 3 || result.Users[0].SpeedLimit != -1 || result.Users[0].DeviceLimit != 1 ||
		result.Users[1].DeviceLimit != -1 || result.Users[2].DeviceLimit != -2 {
		t.Fatalf("limits normalization: %+v", result)
	}
	for _, user := range result.Users {
		if user.ConnectionLimit != 0 || user.ProtocolPassword != "" {
			t.Fatalf("unsupported fields leaked into the user model: %+v", user)
		}
	}
	for _, body := range []string{`{"users":[{"device_limit":9223372036854775808}]}`, `{"users":[{"id":-1}]}`} {
		if _, err := provider.decodeUsers([]byte(body)); err == nil {
			t.Fatal("accepted integer overflow")
		}
	}
}

func TestPPanelReportBodiesPreserveSampleQuirks(t *testing.T) {
	traffic, err := ppanelTrafficBody([]byte(`{"7":[123,456],"9":[1,2]}`))
	if err != nil {
		t.Fatal(err)
	}
	wantTraffic := `{"traffic":[{"uid":0,"upload":0,"download":0},{"uid":0,"upload":0,"download":0},` +
		`{"uid":7,"upload":123,"download":456},{"uid":9,"upload":1,"download":2}]}`
	if string(traffic) != wantTraffic {
		t.Fatalf("sample's 2N traffic slice changed: %s", traffic)
	}
	online, err := ppanelOnlineBody([]byte(`{"7":["192.0.2.1","2001:db8::1"]}`))
	if err != nil {
		t.Fatal(err)
	}
	wantOnline := `{"users":[{"W5Ab6dV":7,"GO1AXXe":"192.0.2.1"},{"W5Ab6dV":7,"GO1AXXe":"2001:db8::1"}]}`
	if string(online) != wantOnline {
		t.Fatalf("untagged exported names changed: %s", online)
	}
	for _, test := range []struct {
		build func([]byte) ([]byte, error)
		want  string
	}{{ppanelTrafficBody, `{"traffic":[]}`}, {ppanelOnlineBody, `{"users":[]}`}} {
		body, err := test.build([]byte(`{}`))
		if err != nil || string(body) != test.want {
			t.Fatalf("empty report: %s %v", body, err)
		}
		if _, err = test.build([]byte(`{"invalid":[]}`)); err == nil {
			t.Fatal("accepted non-numeric user ID")
		}
	}
	now := time.Date(2026, 10, 29, 0, 0, 1, 123000000, time.UTC)
	status, err := ppanelStatusBody([]byte(`{"cpu":0.1,"mem":0.2,"disk":0.3,"updated_at":1}`), now)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]float64
	json.Unmarshal(status, &decoded)
	if decoded["cpu"] != .1 || decoded["mem"] != .2 || decoded["disk"] != .3 ||
		decoded["updated_at"] != float64(now.UnixMilli()) {
		t.Fatalf("status values or millisecond timestamp: %s", status)
	}
}

func TestPPanelHTTPAuthenticationPathsAndETag(t *testing.T) {
	provider := ppanelProvider{}
	responses := map[string]string{
		"/v1/server/config": ppanelTestConfig("vmess", `{"port":443,"transport":"tcp","transport_config":{}}`),
		"/v1/server/user":   `{"users":[]}`,
		"/v1/server/push":   `{}`,
		"/v1/server/online": `{}`,
		"/v1/server/status": `{}`,
	}
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		query := r.URL.Query()
		if len(query) != 3 || query.Get("protocol") != "vmess" || query.Get("server_id") != "17" ||
			query.Get("secret_key") != "test & secret" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected authentication layout")
		}
		if r.Method == http.MethodGet {
			if r.Header.Get("If-None-Match") != `"previous"` {
				t.Error("missing conditional request")
			}
		} else {
			body, err := io.ReadAll(r.Body)
			if err != nil || !json.Valid(body) || r.Header.Get("Content-Type") != "application/json" {
				t.Error("invalid report encoding")
			}
		}
		response, ok := responses[r.URL.Path]
		if !ok {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("ETag", `"next"`)
		io.WriteString(w, response)
	}))
	defer server.Close()
	client := &panelClient{options: option.XBoardPanelOptions{
		APIHost: server.URL, APIKey: "test & secret", NodeID: 17, NodeType: "V2RAY",
	}, client: server.Client()}
	for _, endpoint := range []string{"config", "user", "push", "alive", "status"} {
		method, etag, body := http.MethodGet, `"previous"`, []byte(nil)
		if endpoint != "config" && endpoint != "user" {
			method, etag, body = http.MethodPost, "", []byte(`{}`)
		}
		_, status, nextETag, err := provider.request(context.Background(), client, method, endpoint, etag, body)
		if err != nil || status != http.StatusOK || nextETag != `"next"` {
			t.Fatalf("%s: status=%d etag=%s err=%v", endpoint, status, nextETag, err)
		}
	}
	if !reflect.DeepEqual(paths, []string{
		"/v1/server/config", "/v1/server/user", "/v1/server/push", "/v1/server/online", "/v1/server/status",
	}) {
		t.Fatalf("paths=%v", paths)
	}
}

func TestPPanelHTTPNotModifiedAndSafeErrors(t *testing.T) {
	status := http.StatusNotModified
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	defer server.Close()
	client := &panelClient{options: option.XBoardPanelOptions{
		APIHost: server.URL, APIKey: "private-token", NodeID: 1, NodeType: "anytls",
	}, client: server.Client()}
	provider := ppanelProvider{}
	body, gotStatus, _, err := provider.request(context.Background(), client, http.MethodGet, "config", "", nil)
	if err != nil || gotStatus != http.StatusNotModified || len(body) != 0 {
		t.Fatalf("304 unexpectedly parsed: %s %d %v", body, gotStatus, err)
	}
	status = http.StatusUnauthorized
	_, _, _, err = provider.request(context.Background(), client, http.MethodGet, "user", "", nil)
	if err == nil || strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("unsafe error: %v", err)
	}
	if _, _, _, err = provider.request(context.Background(), client, http.MethodGet, "unknown", "", nil); err == nil {
		t.Fatal("accepted an unknown operation")
	}
}
