package xboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/ssmapi"
	"github.com/sagernet/sing/service"
)

func TestAutoInboundPanelOptions(t *testing.T) {
	base := autoConfigResponse{Protocol: "anytls", ServerPort: json.RawMessage(`"8443"`), ListenIP: "127.0.0.1"}
	auto := option.XBoardAutoInboundOptions{CertificatePath: "cert.pem", KeyPath: "key.pem"}
	config, err := base.buildInboundConfig("anytls", auto)
	if err != nil || config.endpoint.String() != "127.0.0.1:8443" {
		t.Fatalf("panel port/listen were not mapped: %v, %v", config.endpoint, err)
	}
	options := config.options.(*option.AnyTLSInboundOptions)
	if len(options.PaddingScheme) != 0 || !options.TLS.Enabled {
		t.Fatal("automatic AnyTLS changed default padding or TLS")
	}
	auto.Listen, auto.ListenPort, auto.ProxyProtocol, auto.AutoOutIP = "::1", 9443, true, true
	config, err = base.buildInboundConfig("anytls", auto)
	if err != nil || config.endpoint.String() != "[::1]:9443" {
		t.Fatalf("local overrides were not applied: %v, %v", config.endpoint, err)
	}
	options = config.options.(*option.AnyTLSInboundOptions)
	if !options.ProxyProtocol || !options.ProxyProtocolAcceptNoHeader || !options.AutoOutIP {
		t.Fatal("legacy PROXY optional-header and AutoOutIP flags were not preserved")
	}
	base.ListenIP = ""
	auto.Listen, auto.ListenPort = "", 0
	config, err = base.buildInboundConfig("anytls", auto)
	if err != nil || config.endpoint.Addr() != netip.IPv4Unspecified() {
		t.Fatal("missing panel listen_ip did not use 0.0.0.0")
	}
	for _, protocol := range []string{"anytls", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			base.Protocol = protocol
			if config, err := base.buildInboundConfig(protocol, auto); err != nil || config.protocol != protocol {
				t.Fatalf("supported protocol rejected: %v", err)
			}
		})
	}
}

func TestAutoInboundRejectsInvalidPanelSettings(t *testing.T) {
	tests := []struct {
		name string
		body string
		auto option.XBoardAutoInboundOptions
	}{
		{name: "missing port", body: `{}`},
		{name: "zero port", body: `{"server_port":0}`},
		{name: "large port", body: `{"server_port":65536}`},
		{name: "fraction port", body: `{"server_port":443.5}`},
		{name: "bad string port", body: `{"server_port":"secret-value"}`},
		{name: "negative override", body: `{"server_port":443}`, auto: option.XBoardAutoInboundOptions{ListenPort: -1}},
		{name: "host listen", body: `{"server_port":443,"listen_ip":"example.com"}`},
		{name: "mismatched protocol", body: `{"server_port":443,"protocol":"trojan"}`},
		{name: "websocket", body: `{"server_port":443,"network":"ws"}`},
		{name: "grpc", body: `{"server_port":443,"network":"grpc"}`},
		{name: "transport settings", body: `{"server_port":443,"networkSettings":{"path":"/"}}`},
		{name: "reality mode", body: `{"server_port":443,"tls":2}`},
		{name: "disabled tls", body: `{"server_port":443,"tls":0}`},
		{name: "reality settings", body: `{"server_port":443,"tls_settings":{"reality":{}}}`},
		{name: "invalid tls settings", body: `{"server_port":443,"tls_settings":[]}`},
		{name: "invalid alpn", body: `{"server_port":443,"tls_settings":{"alpn":true}}`},
		{name: "invalid padding", body: `{"server_port":443,"padding_scheme":42}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var response autoConfigResponse
			if err := json.Unmarshal([]byte(test.body), &response); err != nil {
				t.Fatal(err)
			}
			test.auto.CertificatePath, test.auto.KeyPath = "cert.pem", "key.pem"
			_, err := response.buildInboundConfig("anytls", test.auto)
			if err == nil {
				t.Fatal("invalid panel configuration accepted")
			}
			if strings.Contains(err.Error(), "secret-value") {
				t.Fatal("panel response value leaked into validation error")
			}
		})
	}
	response := autoConfigResponse{ServerPort: json.RawMessage(`443`)}
	if _, err := response.buildInboundConfig("anytls", option.XBoardAutoInboundOptions{}); err == nil {
		t.Fatal("standard AnyTLS accepted missing certificate paths")
	}
}

func TestAutoInboundNativeOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-private-key.txt")
	const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	response := autoConfigResponse{Protocol: "anytls", ServerPort: json.RawMessage(`443`)}
	auto := option.XBoardAutoInboundOptions{Protocol: "anytls-native", PrivateKeyPath: path}
	config, err := response.buildInboundConfig("anytls", auto)
	if err != nil {
		t.Fatal(err)
	}
	options := config.options.(*option.AnyTLSNativeInboundOptions)
	if config.protocol != "anytls-native" || options.PrivateKey != key || options.TLS != nil {
		t.Fatal("native override changed panel identity or required unintended outer TLS")
	}
	auto.PrivateKey = key
	if _, err = response.buildInboundConfig("anytls", auto); err == nil {
		t.Fatal("ambiguous native private key source accepted")
	}
	auto.PrivateKey, auto.PrivateKeyPath = "", filepath.Join(t.TempDir(), "missing")
	if _, err = response.buildInboundConfig("anytls", auto); err == nil {
		t.Fatal("missing native key file accepted")
	}
	if _, err = os.Stat(auto.PrivateKeyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("configuration validation generated a private key")
	}
}

type lifecycleOptions struct {
	Revision  int
	FailMake  bool
	FailStart bool
	FailUsers bool
}

// lifecycleInbound injects deterministic replacement failures and records ownership cleanup.
// @author lyt
// @date 2026-10-29
type lifecycleInbound struct {
	inbound.Adapter
	options lifecycleOptions
	stages  []adapter.StartStage
	closed  bool
	tracker adapter.SSMTracker
	users   []string
}

func (i *lifecycleInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	i.stages = append(i.stages, stage)
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error { i.closed = true; return nil })
	}
	if stage == adapter.StartStateStart && i.options.FailStart {
		return errors.New("injected listener bind failure")
	}
	return nil
}

func (i *lifecycleInbound) SetTracker(tracker adapter.SSMTracker) { i.tracker = tracker }
func (i *lifecycleInbound) UpdateUsers(users, credentials []string) error {
	if i.options.FailUsers {
		return errors.New("injected user update failure")
	}
	i.users = append([]string(nil), users...)
	return nil
}

func lifecycleWrapper(t *testing.T) *autoInbound {
	t.Helper()
	registry := inbound.NewRegistry()
	inbound.Register[lifecycleOptions](registry, "test", func(_ context.Context, _ adapter.Router,
		_ log.ContextLogger, tag string, options lifecycleOptions,
	) (adapter.Inbound, error) {
		if options.FailMake {
			return nil, errors.New("injected constructor failure")
		}
		return &lifecycleInbound{Adapter: inbound.NewAdapter("test", tag), options: options}, nil
	})
	logger := log.NewNOPFactory().Logger()
	h, err := newAutoInbound(context.Background(), registry, nil, logger, "auto-test", autoInboundConfig{
		protocol: "test", options: &lifecycleOptions{Revision: 1}, endpoint: netip.MustParseAddrPort("127.0.0.1:8443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.close() })
	h.SetTracker(ssmapi.NewTrafficManager())
	if err = h.UpdateUsers([]string{"user"}, []string{"credential"}); err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(context.Background(), logger)
	t.Cleanup(func() { scope.Close() })
	for _, stage := range adapter.ListStartStages {
		if err = h.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func TestAutoInboundReplacementLifecycle(t *testing.T) {
	for _, samePort := range []bool{false, true} {
		t.Run(map[bool]string{false: "different-port", true: "same-port"}[samePort], func(t *testing.T) {
			h := lifecycleWrapper(t)
			original := h.current.inbound.(*lifecycleInbound)
			config := h.current.config
			if !samePort {
				config.endpoint = netip.MustParseAddrPort("127.0.0.1:9443")
			}
			for _, rejected := range []lifecycleOptions{
				{Revision: 2, FailMake: true}, {Revision: 2, FailUsers: true}, {Revision: 2, FailStart: true},
			} {
				config.options = &rejected
				if err := h.replace(config); err == nil {
					t.Fatal("injected replacement failure was ignored")
				}
				current := h.current.inbound.(*lifecycleInbound)
				if current.closed || current.options.Revision != 1 || h.current.stage != int(adapter.StartStateStarted) {
					t.Fatal("rejected candidate left old service unavailable")
				}
			}
			config.options = &lifecycleOptions{Revision: 3}
			if err := h.replace(config); err != nil {
				t.Fatal(err)
			}
			current := h.current.inbound.(*lifecycleInbound)
			if !original.closed || current.tracker != h.tracker || !reflect.DeepEqual(current.users, []string{"user"}) {
				t.Fatal("replacement leaked old lifecycle or lost managed state")
			}
			if !reflect.DeepEqual(current.stages, adapter.ListStartStages) {
				t.Fatal("replacement did not receive each lifecycle stage exactly once")
			}
			if err := h.replace(config); err != nil || len(current.stages) != 4 {
				t.Fatal("identical config restarted a live listener")
			}
		})
	}
}

func TestXBoardHTTPErrorRedactionAndStaticConfig(t *testing.T) {
	status := http.StatusForbidden
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "next")
		w.WriteHeader(status)
		w.Write([]byte(`{"server_port":false,"base_config":{"pull_interval":7},"error":"response-secret"}`))
	}))
	defer panel.Close()
	n := &node{service: &Service{client: panel.Client()}, apiHost: panel.URL, apiKey: "query-secret"}
	if err := n.syncConfig(context.Background()); err == nil || strings.Contains(err.Error(), "secret") ||
		strings.Contains(err.Error(), panel.URL) {
		t.Fatalf("HTTP failure was not redacted: %v", err)
	}
	if n.configETag != "" {
		t.Fatal("failed request advanced ETag")
	}
	status = http.StatusOK
	if err := n.syncConfig(context.Background()); err != nil || n.configETag != "next" || n.pullInterval != 7*time.Second {
		t.Fatalf("static inbound incorrectly validated panel listener settings: %v", err)
	}
	status = http.StatusNotModified
	if err := n.syncConfig(context.Background()); err != nil || n.configETag != "next" {
		t.Fatalf("304 changed configuration state: %v", err)
	}
}

func TestXBoardDuplicateAutomaticOwnership(t *testing.T) {
	h := lifecycleWrapper(t)
	manager := inbound.NewManager(nil, nil)
	if err := manager.Register(h); err != nil {
		t.Fatal(err)
	}
	ctx := service.ContextWith[adapter.InboundManager](context.Background(), manager)
	_, err := NewService(ctx, log.NewNOPFactory().Logger(), "second-panel", option.XBoardServiceOptions{
		APIHost: "https://panel.example.invalid", APIKey: "test-token", NodeID: 1, Inbound: h.Tag(),
	})
	if err == nil || !strings.Contains(err.Error(), "already belongs") {
		t.Fatalf("second node took an existing automatic inbound: %v", err)
	}
}

func TestAutoInboundCloseWaitsForRetiredCleanup(t *testing.T) {
	h := lifecycleWrapper(t)
	entered, release := make(chan struct{}), make(chan struct{})
	h.current.scope.Add(func() error {
		close(entered)
		<-release
		return nil
	})
	config := h.current.config
	config.endpoint = netip.MustParseAddrPort("127.0.0.1:9443")
	config.options = &lifecycleOptions{Revision: 2}
	replaced := make(chan error, 1)
	go func() { replaced <- h.replace(config) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("replacement did not begin retired scope cleanup")
	}
	closed := make(chan error, 2)
	for range 2 {
		go func() { closed <- h.close() }()
	}
	select {
	case err := <-closed:
		close(release)
		t.Fatalf("Close returned before the retired scope finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-replaced; err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not finish after retired scope cleanup")
		}
	}
	if !h.current.inbound.(*lifecycleInbound).closed {
		t.Fatal("Close omitted the replacement scope")
	}
}
