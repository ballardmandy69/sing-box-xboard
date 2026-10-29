package xboard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/nodepolicy"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	ssinbound "github.com/sagernet/sing-box/protocol/shadowsocks"
	trojaninbound "github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/service/ssmapi"
	T "github.com/sagernet/sing-box/transport/trojan"
	shadowsocks "github.com/sagernet/sing-shadowsocks2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// pendingPanelFixture models an HTTP panel that advances its validator before local application.
// @author lyt
// @date 2026-10-29
type pendingPanelFixture struct {
	access            sync.Mutex
	config            any
	users             any
	configTag         string
	usersTag          string
	rules             any
	rulesStatus       int
	rulesRequests     int
	configNotModified int
	usersNotModified  int
}

func (p *pendingPanelFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.access.Lock()
	defer p.access.Unlock()
	var value any
	var tag string
	switch r.URL.Path {
	case "/mod_mu/nodes/1/info":
		value, tag = p.config, p.configTag
	case "/mod_mu/users":
		value, tag = p.users, p.usersTag
	case "/mod_mu/func/detect_rules":
		p.rulesRequests++
		if p.rulesStatus != 0 {
			w.WriteHeader(p.rulesStatus)
			return
		}
		value = p.rules
		if value == nil {
			value = []any{}
		}
	default:
		http.NotFound(w, r)
		return
	}
	if tag != "" {
		w.Header().Set("ETag", tag)
		if r.Header.Get("If-None-Match") == tag {
			if r.URL.Path == "/mod_mu/users" {
				p.usersNotModified++
			} else {
				p.configNotModified++
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ret": 1, "data": value})
}

func pendingPanelConfig(port uint16, cipher, serverKey string) any {
	return map[string]any{
		"version": "2023.2",
		"custom_config": map[string]any{
			"offset_port_node": strconv.Itoa(int(port)), "network": "tcp",
			"mu_encryption": cipher, "server_key": serverKey,
		},
	}
}

func pendingPanelUsers(password string) any {
	return []any{map[string]any{
		"id": 42, "uuid": "01234567-89ab-cdef-0123-456789abcdef", "passwd": password,
	}}
}

type pendingEchoRouter struct{ adapter.Router }

func (pendingEchoRouter) RouteConnection(_ context.Context, conn net.Conn, _ adapter.InboundContext) error {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err := io.Copy(conn, conn)
	_ = conn.Close()
	return err
}

func (pendingEchoRouter) RouteConnectionEx(_ context.Context, conn net.Conn,
	_ adapter.InboundContext, onClose N.CloseHandlerFunc,
) {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err := io.Copy(conn, conn)
	_ = conn.Close()
	if onClose != nil {
		onClose(err)
	}
}

func pendingAutoNode(t *testing.T, panel *httptest.Server, protocol string,
	auto option.XBoardAutoInboundOptions,
) *node {
	t.Helper()
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()
	registry := inbound.NewRegistry()
	trojaninbound.RegisterInbound(registry)
	ssinbound.RegisterInbound(registry)
	holder := newEmptyAutoInbound(ctx, registry, pendingEchoRouter{}, logger, "pending-node", protocol)
	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { _ = scope.Close() })
	for _, stage := range adapter.ListStartStages {
		if err := holder.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	client, err := newPanelClient(option.XBoardPanelOptions{
		PanelType: "sspanel", APIHost: panel.URL, APIKey: "test-token",
		PanelTag: "pending", NodeID: 1, NodeType: protocol,
	})
	if err != nil {
		t.Fatal(err)
	}
	traffic := ssmapi.NewTrafficManager()
	control := usercontrol.NewManager(traffic)
	holder.SetTracker(control)
	return &node{
		service: &Service{logger: logger}, inbound: holder, auto: holder, autoOptions: auto,
		primary: &nodePanel{client: client}, nodeID: 1, nodeType: client.protocolType(),
		traffic: traffic, control: control, trafficFactor: 1,
		users: make(map[string]uint64), limits: make(map[string]usercontrol.Limits),
	}
}

func pendingPort(t *testing.T) (uint16, net.Listener) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return uint16(listener.Addr().(*net.TCPAddr).Port), listener
}

func pendingCertificate(t *testing.T, certPath, keyPath string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pendingExchange(port uint16, protocol, cipher, password string) error {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	dialer := &net.Dialer{Timeout: time.Second}
	var conn net.Conn
	var err error
	if protocol == "trojan" {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	destination := M.ParseSocksaddr("example.test:443")
	if protocol == "trojan" {
		conn = T.NewClientConn(conn, T.Key(password), destination)
	} else {
		method, createErr := shadowsocks.CreateMethod(context.Background(), cipher,
			shadowsocks.MethodOptions{Password: password})
		if createErr != nil {
			return createErr
		}
		conn = method.DialEarlyConn(conn, destination)
	}
	payload := bytes.Repeat([]byte("pending recovery "), 32)
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		return err
	}
	if !bytes.Equal(payload, response) {
		return fmt.Errorf("echo payload changed")
	}
	return nil
}

func TestPendingConfigSSPanelLocalRecovery(t *testing.T) {
	for _, failure := range []string{"certificate", "listen"} {
		t.Run(failure, func(t *testing.T) {
			port, occupied := pendingPort(t)
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			if failure == "certificate" {
				_ = occupied.Close()
			} else {
				pendingCertificate(t, certPath, keyPath)
			}
			fixture := &pendingPanelFixture{
				config: pendingPanelConfig(port, "", ""), users: pendingPanelUsers("unused"),
				configTag: `"config-1"`, usersTag: `"users-1"`,
			}
			server := httptest.NewServer(fixture)
			defer server.Close()
			n := pendingAutoNode(t, server, "trojan", option.XBoardAutoInboundOptions{
				Listen: "127.0.0.1", CertificatePath: certPath, KeyPath: keyPath,
			})
			if err := n.syncUserList(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := n.syncConfig(context.Background()); err == nil {
				t.Fatal("local activation unexpectedly succeeded")
			}
			if n.pendingConfig == nil || n.auto.hasCurrent() || n.configETag != "" {
				t.Fatal("failed activation did not retain only the decoded candidate")
			}
			if failure == "certificate" {
				pendingCertificate(t, certPath, keyPath)
			} else {
				_ = occupied.Close()
			}
			if err := n.syncConfig(context.Background()); err != nil {
				t.Fatal(err)
			}
			if n.pendingConfig != nil || !n.auto.hasCurrent() || n.configETag != `"config-1"` {
				t.Fatal("304 did not commit the recovered candidate")
			}
			if err := pendingExchange(port, "trojan", "", "01234567-89ab-cdef-0123-456789abcdef"); err != nil {
				t.Fatal(err)
			}
			fixture.access.Lock()
			defer fixture.access.Unlock()
			if fixture.configNotModified != 1 {
				t.Fatalf("expected actual HTTP 304, got %d", fixture.configNotModified)
			}
		})
	}
}

func TestPendingUsersSSPanelCipherRepair(t *testing.T) {
	port, occupied := pendingPort(t)
	_ = occupied.Close()
	serverKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	oldPassword := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
	newPassword := "valid-legacy-but-not-base64"
	fixture := &pendingPanelFixture{
		config: pendingPanelConfig(port, "2022-blake3-aes-128-gcm", serverKey),
		users:  pendingPanelUsers(oldPassword), configTag: `"config-1"`, usersTag: `"users-1"`,
	}
	server := httptest.NewServer(fixture)
	defer server.Close()
	n := pendingAutoNode(t, server, "shadowsocks", option.XBoardAutoInboundOptions{Listen: "127.0.0.1"})
	ctx := context.Background()
	if err := n.syncUserList(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n.syncConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pendingExchange(port, "shadowsocks", "2022-blake3-aes-128-gcm", serverKey+":"+oldPassword); err != nil {
		t.Fatal(err)
	}
	fixture.access.Lock()
	fixture.users, fixture.usersTag = pendingPanelUsers(newPassword), `"users-2"`
	fixture.access.Unlock()
	if err := n.syncUserList(ctx); err == nil {
		t.Fatal("invalid 2022 key unexpectedly applied")
	}
	if n.pendingUsers == nil || n.userETag != `"users-1"` {
		t.Fatal("failed user update did not remain pending")
	}
	if err := pendingExchange(port, "shadowsocks", "2022-blake3-aes-128-gcm", serverKey+":"+oldPassword); err != nil {
		t.Fatalf("failed user update broke previous authentication: %v", err)
	}
	fixture.access.Lock()
	fixture.config, fixture.configTag = pendingPanelConfig(port, "aes-128-gcm", ""), `"config-2"`
	fixture.access.Unlock()
	if err := n.syncConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n.syncUserList(ctx); err != nil {
		t.Fatal(err)
	}
	if n.pendingUsers != nil || n.userETag != `"users-2"` {
		t.Fatal("304 did not publish pending users after cipher repair")
	}
	if err := pendingExchange(port, "shadowsocks", "aes-128-gcm", newPassword); err != nil {
		t.Fatal(err)
	}
	if err := pendingExchange(port, "shadowsocks", "aes-128-gcm", oldPassword); err == nil {
		t.Fatal("removed credential still authenticated")
	}
	fixture.access.Lock()
	defer fixture.access.Unlock()
	if fixture.usersNotModified != 1 {
		t.Fatalf("expected actual user HTTP 304, got %d", fixture.usersNotModified)
	}
}

func TestPendingConfigSSPanelKeepsPreviousListener(t *testing.T) {
	oldPort, oldReservation := pendingPort(t)
	_ = oldReservation.Close()
	newPort, occupied := pendingPort(t)
	fixture := &pendingPanelFixture{
		config: pendingPanelConfig(oldPort, "aes-128-gcm", ""), users: pendingPanelUsers("old-password"),
		configTag: `"config-1"`, usersTag: `"users-1"`,
	}
	server := httptest.NewServer(fixture)
	defer server.Close()
	n := pendingAutoNode(t, server, "shadowsocks", option.XBoardAutoInboundOptions{Listen: "127.0.0.1"})
	ctx := context.Background()
	if err := n.syncUserList(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n.syncConfig(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.access.Lock()
	fixture.config, fixture.configTag = pendingPanelConfig(newPort, "aes-128-gcm", ""), `"config-2"`
	fixture.access.Unlock()
	if err := n.syncConfig(ctx); err == nil {
		t.Fatal("replacement unexpectedly acquired the occupied port")
	}
	if n.pendingConfig == nil || n.configETag != `"config-1"` {
		t.Fatal("failed replacement published its validator")
	}
	if err := pendingExchange(oldPort, "shadowsocks", "aes-128-gcm", "old-password"); err != nil {
		t.Fatalf("previous listener did not survive rollback: %v", err)
	}
	_ = occupied.Close()
	if err := n.syncConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pendingExchange(newPort, "shadowsocks", "aes-128-gcm", "old-password"); err != nil {
		t.Fatal(err)
	}
	if n.pendingConfig != nil || n.configETag != `"config-2"` {
		t.Fatal("recovered replacement was not committed")
	}
	oldAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(oldPort)))
	if conn, err := net.DialTimeout("tcp", oldAddress, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("previous listening socket remained active after successful replacement")
	}
}

func TestPendingConfigIndependentRuleRefresh(t *testing.T) {
	port, reservation := pendingPort(t)
	_ = reservation.Close()
	fixture := &pendingPanelFixture{
		config: pendingPanelConfig(port, "aes-128-gcm", ""), users: pendingPanelUsers("rule-password"),
		configTag: `"config-1"`, usersTag: `"users-1"`, rulesStatus: http.StatusServiceUnavailable,
	}
	server := httptest.NewServer(fixture)
	defer server.Close()
	n := pendingAutoNode(t, server, "shadowsocks", option.XBoardAutoInboundOptions{Listen: "127.0.0.1"})
	registry, err := nodepolicy.NewRegistry("", nil)
	if err != nil {
		t.Fatal(err)
	}
	n.service.policy = registry
	ctx := context.Background()
	if err = n.syncUserList(ctx); err != nil {
		t.Fatal(err)
	}
	if err = n.syncConfig(ctx); err != nil {
		t.Fatalf("independent rule failure discarded the valid node configuration: %v", err)
	}
	if !n.auto.hasCurrent() || n.pendingConfig != nil || n.configETag != `"config-1"` {
		t.Fatal("valid configuration was not committed after rule HTTP failure")
	}
	if err = pendingExchange(port, "shadowsocks", "aes-128-gcm", "rule-password"); err != nil {
		t.Fatal(err)
	}
	metadata := adapter.InboundContext{
		Inbound: "pending-node", User: n.primary.client.userName(42), Network: "tcp",
		Source: M.ParseSocksaddr("192.0.2.1:3000"), Destination: M.ParseSocksaddr("blocked.test:443"),
	}
	if err = registry.Check(ctx, &metadata, nil); err != nil {
		t.Fatal(err)
	}
	fixture.access.Lock()
	fixture.rulesStatus, fixture.rules = 0, []any{map[string]any{"id": 42, "regex": `blocked\.test`}}
	fixture.access.Unlock()
	if err = n.syncConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if err = registry.Check(ctx, &metadata, nil); !errors.Is(err, adapter.ErrManagedNodePolicyRejected) {
		t.Fatalf("node 304 failed to refresh independent rules: %v", err)
	}
	fixture.access.Lock()
	fixture.rulesStatus = http.StatusServiceUnavailable
	fixture.access.Unlock()
	if err = n.syncConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if err = registry.Check(ctx, &metadata, nil); !errors.Is(err, adapter.ErrManagedNodePolicyRejected) {
		t.Fatalf("failed rule refresh lost the previous policy: %v", err)
	}
	fixture.access.Lock()
	defer fixture.access.Unlock()
	if fixture.configNotModified != 2 || fixture.rulesRequests != 3 {
		t.Fatalf("unexpected independent request counts: config 304=%d rules=%d",
			fixture.configNotModified, fixture.rulesRequests)
	}
}

func TestPendingUsersUndecodableResponseInvalidatesOlderCandidate(t *testing.T) {
	fixture := &pendingPanelFixture{users: pendingPanelUsers("first"), usersTag: `"users-1"`}
	server := httptest.NewServer(fixture)
	defer server.Close()
	inbound := &userSyncInbound{updateError: errors.New("temporarily invalid local state")}
	n := userSyncNode(server, "pending", inbound)
	client, err := newPanelClient(option.XBoardPanelOptions{
		PanelType: "sspanel", APIHost: server.URL, APIKey: "test-token",
		PanelTag: "pending", NodeID: 1, NodeType: "trojan",
	})
	if err != nil {
		t.Fatal(err)
	}
	n.primary, n.nodeType = &nodePanel{client: client}, "trojan"
	ctx := context.Background()
	if err = n.syncUserList(ctx); err == nil || n.pendingUsers == nil {
		t.Fatal("expected successfully decoded users to await local recovery")
	}
	fixture.access.Lock()
	fixture.users, fixture.usersTag = map[string]any{"not": "a user list"}, `"users-2"`
	fixture.access.Unlock()
	if err = n.syncUserList(ctx); err == nil {
		t.Fatal("malformed fresh user response was accepted")
	}
	inbound.updateError = nil
	if err = n.syncUserList(ctx); err != nil {
		t.Fatal(err)
	}
	if n.pendingUsers != nil || n.userETag != "" || len(inbound.names) != 0 {
		t.Fatal("304 replayed an older candidate after newer users failed decoding")
	}
}

func TestPendingConfigUndecodableResponseInvalidatesOlderCandidate(t *testing.T) {
	port, reservation := pendingPort(t)
	_ = reservation.Close()
	fixture := &pendingPanelFixture{
		config: pendingPanelConfig(port, "aes-128-gcm", ""), users: pendingPanelUsers("password"),
		configTag: `"config-1"`, usersTag: `"users-1"`,
	}
	server := httptest.NewServer(fixture)
	defer server.Close()
	// An invalid listen address is local state: the panel payload itself is valid.
	n := pendingAutoNode(t, server, "shadowsocks", option.XBoardAutoInboundOptions{Listen: "invalid IP"})
	ctx := context.Background()
	if err := n.syncUserList(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n.syncConfig(ctx); err == nil || n.pendingConfig == nil {
		t.Fatal("expected a decoded candidate waiting for local activation")
	}
	fixture.access.Lock()
	fixture.config, fixture.configTag = []any{"invalid config"}, `"config-2"`
	fixture.access.Unlock()
	if err := n.syncConfig(ctx); err == nil {
		t.Fatal("fresh malformed node response was accepted")
	}
	n.autoOptions.Listen = "127.0.0.1"
	if err := n.syncConfig(ctx); err == nil {
		t.Fatal("304 without a decoded candidate incorrectly initialized the listener")
	}
	if n.pendingConfig != nil || n.configETag != "" || n.auto.hasCurrent() {
		t.Fatal("malformed node payload was treated as an applied configuration")
	}
}
