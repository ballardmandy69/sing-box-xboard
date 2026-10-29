package xboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	anytlsprotocol "github.com/sagernet/sing-box/protocol/anytls"
	trojanprotocol "github.com/sagernet/sing-box/protocol/trojan"
	vlessprotocol "github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/service/ssmapi"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	masterTestUUID     = "de0975cb-d941-57a4-b452-ef638e39d962"
	masterTestNextUUID = "8ef0a1bb-1567-4ff0-a313-316bf78a9184"
	masterTestUser     = "42@legacy@oldv2b"
	masterTestDerived  = "a0cec2d73e4d7d7b3fdbeef8d7942235"
)

func TestMasterPasswordCredentialCompatibility(t *testing.T) {
	for _, protocol := range []string{
		C.TypeTrojan, C.TypeAnyTLS, C.TypeVLESS, C.TypeVMess, C.TypeAnyTLSNative, C.TypeShadowsocks,
	} {
		for _, master := range []string{"", "master-A", " 主密码\n"} {
			t.Run(protocol+"/"+master, func(t *testing.T) {
				uuids, passwords := []string{masterTestUUID}, []string{"separate-secret"}
				config := autoInboundConfig{protocol: protocol, masterPassword: master,
					options: &option.ShadowsocksInboundOptions{Method: "aes-128-gcm"}}
				got, err := config.panelCredentials(uuids, passwords)
				want := "separate-secret"
				if protocol == C.TypeVMess || protocol == C.TypeVLESS {
					want = masterTestUUID
				} else if (protocol == C.TypeTrojan || protocol == C.TypeAnyTLS) && master != "" {
					want = masterTestDerived
					if master != "master-A" {
						want = "24aec3639587f130ee224510f2613aa6"
					}
				}
				if err != nil || len(got) != 1 || got[0] != want {
					t.Fatalf("unexpected credentials: %v %v", got, err)
				}
				if uuids[0] != masterTestUUID || passwords[0] != "separate-secret" {
					t.Fatal("derivation mutated the source credentials")
				}
				if _, err = config.panelCredentials(uuids, nil); err == nil {
					t.Fatal("mismatched input lengths were accepted")
				}
			})
		}
	}
	for _, protocol := range []string{C.TypeTrojan, C.TypeAnyTLS} {
		got, err := (autoInboundConfig{protocol: protocol}).userCredentials([]string{masterTestUUID})
		if err != nil || !reflect.DeepEqual(got, []string{masterTestUUID}) {
			t.Fatalf("empty master changed UUID credentials: %v %v", got, err)
		}
	}
}

func TestMasterPasswordUsesFinalAutomaticProtocol(t *testing.T) {
	for _, test := range []struct {
		protocol string
		accept   bool
		want     bool
	}{
		{C.TypeTrojan, false, true}, {C.TypeAnyTLS, false, true},
		{C.TypeVLESS, true, true}, {C.TypeTrojan, true, true},
		{C.TypeVLESS, false, false}, {C.TypeVMess, false, false},
	} {
		t.Run(fmt.Sprintf("%s/accept=%t", test.protocol, test.accept), func(t *testing.T) {
			response := autoConfigResponse{Protocol: test.protocol, ServerPort: json.RawMessage(`443`)}
			auto := option.XBoardAutoInboundOptions{DisableTLS: true, AcceptAnyTLS: test.accept}
			without, err := response.buildInboundConfig(test.protocol, auto)
			if err != nil {
				t.Fatal(err)
			}
			auto.MasterPassword = "master-A"
			with, err := response.buildInboundConfig(test.protocol, auto)
			if err != nil || (with.masterPassword == "master-A") != test.want {
				t.Fatalf("master did not follow final protocol: %q %v", with.protocol, err)
			}
			if !test.want && !reflect.DeepEqual(with, without) {
				t.Fatal("unused master would replace an unrelated protocol listener")
			}
		})
	}
}

// masterPasswordUUIDCapture observes the separate immutable UUID channel used by managed protocols.
// @author lyt
// @date 2026-10-29
type masterPasswordUUIDCapture struct {
	*lifecycleInbound
	uuids       []string
	credentials []string
}

func (s *masterPasswordUUIDCapture) UpdateUsersWithUUIDs(names, credentials, uuids []string) error {
	s.uuids = append([]string(nil), uuids...)
	s.credentials = append([]string(nil), credentials...)
	return s.UpdateUsers(names, credentials)
}

func TestMasterPasswordPreservesOriginalUUIDChannel(t *testing.T) {
	capture := &masterPasswordUUIDCapture{lifecycleInbound: &lifecycleInbound{}}
	instance := autoInboundInstance{inbound: capture,
		config: autoInboundConfig{protocol: C.TypeTrojan, masterPassword: "master-A"}}
	if err := instance.updatePanelUsers([]string{masterTestUser}, []string{masterTestUUID},
		[]string{"separate-secret"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(capture.uuids, []string{masterTestUUID}) ||
		!reflect.DeepEqual(capture.users, []string{masterTestUser}) ||
		!reflect.DeepEqual(capture.credentials, []string{masterTestDerived}) {
		t.Fatal("original UUID, statistics identity, and protocol credential were not kept separate")
	}
}

// masterPasswordRouter preserves real protocol authentication while echoing payloads asynchronously.
// @author lyt
// @date 2026-10-29
type masterPasswordRouter struct {
	adapter.Router
	metadata chan adapter.InboundContext
}

func (r *masterPasswordRouter) RouteConnectionEx(_ context.Context, conn net.Conn,
	metadata adapter.InboundContext, onClose N.CloseHandlerFunc,
) {
	r.metadata <- metadata
	go func() {
		_, err := io.Copy(conn, conn)
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

// masterPasswordRegistry can fail one candidate at Start while the real previous listener is restored.
// @author lyt
// @date 2026-10-29
type masterPasswordRegistry struct {
	adapter.InboundRegistry
	failNext atomic.Bool
}

func (r *masterPasswordRegistry) Create(ctx context.Context, router adapter.Router,
	logger log.ContextLogger, tag, protocol string, options any,
) (adapter.Inbound, error) {
	created, err := r.InboundRegistry.Create(ctx, router, logger, tag, protocol, options)
	if err == nil && r.failNext.Swap(false) {
		return &masterPasswordStartFailure{created.(adapter.ManagedSSMServer)}, nil
	}
	return created, err
}

// masterPasswordStartFailure injects failure after construction and user application.
// @author lyt
// @date 2026-10-29
type masterPasswordStartFailure struct{ adapter.ManagedSSMServer }

func (s *masterPasswordStartFailure) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		return errors.New("injected candidate start failure")
	}
	return s.ManagedSSMServer.Start(stage, scope)
}

func startMasterPasswordInbound(t *testing.T, protocol string, accept bool,
	fallback string,
) (*autoInbound, *masterPasswordRouter, *ssmapi.TrafficManager, *masterPasswordRegistry) {
	t.Helper()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	_ = reserved.Close()
	response := autoConfigResponse{Protocol: protocol, ServerPort: json.RawMessage(fmt.Sprint(port))}
	config, err := response.buildInboundConfig(protocol, option.XBoardAutoInboundOptions{
		Listen: "127.0.0.1", DisableTLS: true, DisableSniffing: true, MasterPassword: "master-A",
		AcceptAnyTLS: accept, FallbackService: fallback,
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := inbound.NewRegistry()
	trojanprotocol.RegisterInbound(registry)
	anytlsprotocol.RegisterInbound(registry)
	vlessprotocol.RegisterInbound(registry)
	controlled := &masterPasswordRegistry{InboundRegistry: registry}
	router := &masterPasswordRouter{metadata: make(chan adapter.InboundContext, 64)}
	logger := log.NewNOPFactory().Logger()
	holder, err := newAutoInbound(context.Background(), controlled, router, logger, "master", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.close() })
	traffic := ssmapi.NewTrafficManager()
	holder.SetTracker(traffic)
	if err = holder.updatePanelUsers([]string{masterTestUser}, []string{masterTestUUID},
		[]string{"separate-secret"}); err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(context.Background(), logger)
	t.Cleanup(func() { _ = scope.Close() })
	for _, stage := range adapter.ListStartStages {
		if err = holder.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	return holder, router, traffic, controlled
}

func exchangeMasterPassword(address, protocol, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	destination := M.ParseSocksaddr("example.com:443")
	var conn net.Conn
	var err error
	if protocol == C.TypeAnyTLS {
		client, createErr := anytls.NewClient(ctx, anytls.ClientConfig{
			Password: password, Logger: log.NewNOPFactory().Logger(), AuthenticationTimeout: time.Second,
			DialOut: func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", address)
			},
		})
		if createErr != nil {
			return createErr
		}
		defer client.Close()
		conn, err = client.CreateProxy(ctx, destination)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err == nil {
			if protocol == C.TypeTrojan {
				digest := sha256.Sum224([]byte(password))
				var key [56]byte
				hex.Encode(key[:], digest[:])
				conn = trojan.NewClientConn(conn, key, destination)
			} else {
				key := uuid.FromStringOrNil(password)
				if key == uuid.Nil {
					key = uuid.NewV5(uuid.Nil, password)
				}
				conn = vless.NewConn(conn, key, vmess.CommandTCP, destination, "")
			}
		}
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	const payload = "master-password-authenticated-echo-payload"
	if _, err = conn.Write([]byte(payload)); err != nil {
		return err
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		return err
	}
	if string(response) != payload {
		return errors.New("echo differs")
	}
	return nil
}

func assertMasterPasswordExchange(t *testing.T, h *autoInbound, router *masterPasswordRouter,
	protocol, credential string,
) {
	t.Helper()
	if err := exchangeMasterPassword(h.current.config.endpoint.String(), protocol, credential); err != nil {
		t.Fatalf("%s derived authentication failed: %v", protocol, err)
	}
	select {
	case metadata := <-router.metadata:
		if metadata.User != masterTestUser || metadata.InboundType != protocol || metadata.Inbound != "master" {
			t.Fatalf("derived authentication changed identity: %+v", metadata)
		}
	case <-time.After(time.Second):
		t.Fatal("authenticated request did not route")
	}
}

func TestMasterPasswordActualTCPAndRotation(t *testing.T) {
	for _, test := range []struct {
		name, protocol, fallback string
		accept                   bool
		clients                  []string
	}{
		{"trojan", C.TypeTrojan, "", false, []string{C.TypeTrojan}},
		{"anytls", C.TypeAnyTLS, "", false, []string{C.TypeAnyTLS}},
		{"combined", C.TypeAnyTLS, "trojan-vless", false, []string{C.TypeTrojan, C.TypeVLESS, C.TypeAnyTLS}},
		{"accept-vless", C.TypeVLESS, "", true, []string{C.TypeVLESS, C.TypeAnyTLS}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, router, traffic, _ := startMasterPasswordInbound(t, test.protocol, test.accept, test.fallback)
			for index, step := range []struct{ uuid, master, derived string }{
				{masterTestUUID, "master-A", masterTestDerived},
				{masterTestUUID, "master-A", masterTestDerived},
				{masterTestUUID, "master-B", "ec93bb6eb65d042d63540235931a5b24"},
				{masterTestNextUUID, "master-B", "44f8f2f68c67f579cba30bab039a75f6"},
			} {
				if err := h.updatePanelUsers([]string{masterTestUser}, []string{step.uuid},
					[]string{"separate-secret"}); err != nil {
					t.Fatal(err)
				}
				config := h.current.config
				config.masterPassword = step.master
				if err := h.replace(config); err != nil {
					t.Fatal(err)
				}
				for _, protocol := range test.clients {
					assertMasterPasswordExchange(t, h, router, protocol, step.derived)
					if index >= 2 {
						if err := exchangeMasterPassword(config.endpoint.String(), protocol, masterTestDerived); err == nil {
							t.Fatal("old derived credential survived replacement or rotation")
						}
					}
				}
				if h.credentials[0] != step.uuid || h.passwords[0] != "separate-secret" || h.users[0] != masterTestUser {
					t.Fatal("derived credentials replaced original identity or cached UUID")
				}
			}
			for _, protocol := range test.clients {
				for _, wrong := range []string{masterTestNextUUID, "separate-secret"} {
					if err := exchangeMasterPassword(h.current.config.endpoint.String(), protocol, wrong); err == nil {
						t.Fatal("original UUID or separate password bypassed master derivation")
					}
				}
			}
			for _, snapshot := range traffic.SnapshotTraffic([]string{masterTestUser, masterTestUUID, masterTestDerived}) {
				if snapshot.UserName == masterTestUser {
					if snapshot.UplinkBytes == 0 || snapshot.DownlinkBytes == 0 {
						t.Fatalf("identity lost traffic: %+v", snapshot)
					}
				} else if snapshot.UplinkBytes != 0 || snapshot.DownlinkBytes != 0 {
					t.Fatal("traffic was attributed to a credential instead of the user")
				}
			}
			select {
			case metadata := <-router.metadata:
				t.Fatalf("rejected credential reached routing: %+v", metadata)
			default:
			}
		})
	}
}

func TestMasterPasswordFailedReplacementRestoresOriginalDerivation(t *testing.T) {
	h, router, _, registry := startMasterPasswordInbound(t, C.TypeTrojan, false, "")
	config := h.current.config
	config.masterPassword = "master-B"
	registry.failNext.Store(true)
	if err := h.replace(config); err == nil {
		t.Fatal("injected start failure was ignored")
	}
	if h.current.config.masterPassword != "master-A" || h.credentials[0] != masterTestUUID {
		t.Fatal("rollback retained candidate derivation or lost original UUID")
	}
	assertMasterPasswordExchange(t, h, router, C.TypeTrojan, masterTestDerived)
	if err := exchangeMasterPassword(config.endpoint.String(), C.TypeTrojan,
		"ec93bb6eb65d042d63540235931a5b24"); err == nil {
		t.Fatal("failed candidate credential remained active")
	}
	if err := h.replace(config); err != nil {
		t.Fatal(err)
	}
	assertMasterPasswordExchange(t, h, router, C.TypeTrojan, "ec93bb6eb65d042d63540235931a5b24")
	config.masterPassword = ""
	if err := h.replace(config); err != nil {
		t.Fatal(err)
	}
	assertMasterPasswordExchange(t, h, router, C.TypeTrojan, "separate-secret")
}
