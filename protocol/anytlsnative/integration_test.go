package anytlsnative_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	stdjson "encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/anytlsnative"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type nativeRouteEvent struct {
	user   string
	source M.Socksaddr
}

type nativeRouteTracker struct {
	events   chan nativeRouteEvent
	progress chan struct{}
	read     atomic.Int64
	written  atomic.Int64
}

func (r *nativeRouteTracker) TrackConnection(conn net.Conn, metadata adapter.InboundContext) net.Conn {
	r.events <- nativeRouteEvent{user: metadata.User, source: metadata.Source}
	return &nativeCountedConn{Conn: conn, tracker: r}
}

func (r *nativeRouteTracker) TrackPacketConnection(conn N.PacketConn, _ adapter.InboundContext) N.PacketConn {
	return conn
}

type nativeCountedConn struct {
	net.Conn
	tracker *nativeRouteTracker
}

func (c *nativeCountedConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	c.tracker.read.Add(int64(n))
	c.notify()
	return n, err
}

func (c *nativeCountedConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.tracker.written.Add(int64(n))
	c.notify()
	return n, err
}

func (c *nativeCountedConn) notify() {
	select {
	case c.tracker.progress <- struct{}{}:
	default:
	}
}

func (r *nativeRouteTracker) RoutedConnection(_ context.Context, conn net.Conn,
	metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound,
) net.Conn {
	r.events <- nativeRouteEvent{user: metadata.User, source: metadata.Source}
	return conn
}

func (r *nativeRouteTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn,
	_ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound,
) N.PacketConn {
	return conn
}

func (r *nativeRouteTracker) RoutedFlow(context.Context, adapter.InboundContext,
	adapter.Rule, adapter.Outbound,
) tun.FlowTracker {
	return nil
}

func TestNativeRegisteredRoundTrip(t *testing.T) {
	for _, mode := range []struct {
		name       string
		tls        bool
		paddingOff bool
	}{
		{name: "native_without_padding", paddingOff: true},
		{name: "native_default_padding"},
		{name: "tls_default_padding", tls: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			privateKey, publicKey := nativeTestKeys(t)
			tracker := &nativeRouteTracker{events: make(chan nativeRouteEvent, 64)}
			serverInbound := nativeServerConfig(nativeFreePort(t), privateKey)
			clientOutbounds := []map[string]any{
				nativeClientConfig(serverInbound["listen_port"].(uint16), publicKey, "alpha", "alpha-secret"),
				nativeClientConfig(serverInbound["listen_port"].(uint16), publicKey, "bravo", "bravo-secret"),
			}
			if mode.paddingOff {
				serverInbound["padding"] = map[string]any{}
				for _, outbound := range clientOutbounds {
					outbound["padding"] = map[string]any{}
				}
			}
			if mode.tls {
				certificate, key := nativeTestCertificate(t)
				serverInbound["tls"] = map[string]any{
					"enabled": true, "certificate": []string{certificate}, "key": []string{key},
				}
				for _, outbound := range clientOutbounds {
					outbound["tls"] = map[string]any{
						"enabled": true, "server_name": "native.test", "certificate": []string{certificate},
					}
				}
			}
			nativeStartBox(t, map[string]any{
				"inbounds": []any{serverInbound}, "outbounds": []any{map[string]any{"type": "direct"}},
			}, tracker)
			client := nativeStartBox(t, map[string]any{"outbounds": clientOutbounds}, nil)
			destination := nativeEchoServer(t)
			var previousSource M.Socksaddr
			for _, user := range []string{"alpha", "bravo"} {
				outbound := nativeGetOutbound(t, client, user)
				var firstSource M.Socksaddr
				for request, size := range []int{1024, 32 * 1024, 1024} {
					if err := nativeExchange(outbound, destination, size); err != nil {
						t.Fatalf("%s request %d: %v", user, request, err)
					}
					event := nativeNextRoute(t, tracker)
					if event.user != user {
						t.Fatalf("request authenticated as %q, want %q", event.user, user)
					}
					if request == 0 {
						firstSource = event.source
					} else if event.source != firstSource {
						t.Fatalf("warm request opened another transport: %s != %s", event.source, firstSource)
					}
				}
				if firstSource == previousSource {
					t.Fatal("different users shared the same authenticated transport")
				}
				previousSource = firstSource
			}
			outbound := nativeGetOutbound(t, client, "alpha")
			errors := make(chan error, 8)
			for range 8 {
				go func() { errors <- nativeExchange(outbound, destination, 32*1024) }()
			}
			for range 8 {
				if err := <-errors; err != nil {
					t.Error(err)
				}
				event := nativeNextRoute(t, tracker)
				if event.user != "alpha" {
					t.Errorf("concurrent request authenticated as %q", event.user)
				}
			}
		})
	}
}

func TestNativeRejectsWrongKeyAndUser(t *testing.T) {
	privateKey, publicKey := nativeTestKeys(t)
	_, wrongPublicKey := nativeTestKeys(t)
	serverInbound := nativeServerConfig(nativeFreePort(t), privateKey)
	tracker := &nativeRouteTracker{events: make(chan nativeRouteEvent, 8)}
	nativeStartBox(t, map[string]any{
		"inbounds": []any{serverInbound}, "outbounds": []any{map[string]any{"type": "direct"}},
	}, tracker)
	destination := nativeEchoServer(t)
	for _, invalid := range []struct {
		name     string
		key      string
		password string
	}{
		{name: "wrong_server_key", key: wrongPublicKey, password: "alpha-secret"},
		{name: "unknown_user", key: publicKey, password: "unknown-secret"},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			outbound := nativeClientConfig(serverInbound["listen_port"].(uint16),
				invalid.key, "invalid", invalid.password)
			outbound["handshake_timeout"] = "1s"
			client := nativeStartBox(t, map[string]any{"outbounds": []any{outbound}}, nil)
			if err := nativeExchange(nativeGetOutbound(t, client, "invalid"), destination, 1024); err == nil {
				t.Fatal("invalid peer unexpectedly completed a business request")
			}
			select {
			case event := <-tracker.events:
				t.Fatalf("invalid peer reached routing as user %q", event.user)
			default:
			}
		})
	}
}

func TestNativeRejectsUDP(t *testing.T) {
	_, publicKey := nativeTestKeys(t)
	client := nativeStartBox(t, map[string]any{
		"outbounds": []any{nativeClientConfig(1, publicKey, "native", "alpha-secret")},
	}, nil)
	outbound := nativeGetOutbound(t, client, "native")
	destination := M.ParseSocksaddr("127.0.0.1:53")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := outbound.DialContext(ctx, "udp", destination); err == nil {
		conn.Close()
		t.Fatal("UDP DialContext was accepted")
	}
	if conn, err := outbound.ListenPacket(ctx, destination); err == nil {
		conn.Close()
		t.Fatal("UDP ListenPacket was accepted")
	}
	for _, network := range outbound.Network() {
		if network != N.NetworkTCP {
			t.Fatalf("outbound advertises unsupported network %q", network)
		}
	}
}

func TestNativeRejectsUoTTargets(t *testing.T) {
	privateKey, publicKey := nativeTestKeys(t)
	serverInbound := nativeServerConfig(nativeFreePort(t), privateKey)
	tracker := &nativeRouteTracker{events: make(chan nativeRouteEvent, 8)}
	nativeStartBox(t, map[string]any{
		"inbounds": []any{serverInbound}, "outbounds": []any{map[string]any{"type": "direct"}},
	}, tracker)
	client := nativeStartBox(t, map[string]any{
		"outbounds": []any{nativeClientConfig(serverInbound["listen_port"].(uint16),
			publicKey, "native", "alpha-secret")},
	}, nil)
	for _, domain := range []string{uot.MagicAddress, uot.LegacyMagicAddress} {
		t.Run(domain, func(t *testing.T) {
			destination := M.ParseSocksaddrHostPort(domain, 0)
			if err := nativeExchange(nativeGetOutbound(t, client, "native"), destination, 32); err == nil {
				t.Fatal("UoT magic target was accepted")
			}
			select {
			case <-tracker.events:
				t.Fatal("UoT magic target reached the business router")
			default:
			}
		})
	}
}

func TestNativeRejectsInvalidConfiguration(t *testing.T) {
	privateKey, publicKey := nativeTestKeys(t)
	for _, invalid := range []struct {
		name    string
		inbound bool
		field   string
		value   any
		want    string
	}{
		{name: "private_key", inbound: true, field: "private_key", value: "bad", want: "private_key"},
		{name: "public_key", field: "server_public_key", value: "bad", want: "server_public_key"},
		{name: "low_order_public_key", field: "server_public_key",
			value: base64.StdEncoding.EncodeToString(make([]byte, 32)), want: "low-order"},
		{name: "duplicate_names", inbound: true, field: "users", value: []any{
			map[string]any{"name": "alpha", "password": "first"},
			map[string]any{"name": "alpha", "password": "second"},
		}, want: "duplicate"},
		{name: "duplicate_credentials", inbound: true, field: "users", value: []any{
			map[string]any{"name": "alpha", "password": "same"},
			map[string]any{"name": "bravo", "password": "same"},
		}, want: "duplicate"},
		{name: "empty_password", field: "password", value: "", want: "password"},
		{name: "negative_padding", field: "padding",
			value: map[string]any{"max_padding": -1}, want: "padding"},
		{name: "excessive_padding", inbound: true, field: "padding",
			value: map[string]any{"max_padding": 257}, want: "padding"},
		{name: "negative_timeout", field: "handshake_timeout", value: "-1s", want: "handshake_timeout"},
		{name: "negative_handshake_limit", inbound: true,
			field: "max_pending_handshakes", value: -1, want: "max_pending_handshakes"},
		{name: "insecure_tls", field: "tls",
			value: map[string]any{"enabled": true, "insecure": true}, want: "certificate verification"},
		{name: "tcp_fast_open", field: "tcp_fast_open", value: true, want: "tcp_fast_open"},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			config := map[string]any{"log": map[string]any{"disabled": true}}
			var endpoint map[string]any
			if invalid.inbound {
				endpoint = nativeServerConfig(0, privateKey)
				config["inbounds"] = []any{endpoint}
				config["outbounds"] = []any{map[string]any{"type": "direct"}}
			} else {
				endpoint = nativeClientConfig(1, publicKey, "native", "alpha-secret")
				config["outbounds"] = []any{endpoint}
			}
			endpoint[invalid.field] = invalid.value
			encoded, err := stdjson.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(include.Context(context.Background()))
			defer cancel()
			options, err := json.UnmarshalExtendedContext[option.Options](ctx, encoded)
			if err == nil {
				var instance *box.Box
				instance, err = box.New(box.Options{Context: ctx, Options: options})
				if instance != nil {
					defer instance.Close()
				}
			}
			if err == nil || !strings.Contains(err.Error(), invalid.want) {
				t.Fatalf("configuration error = %v, want %q", err, invalid.want)
			}
		})
	}
}

func TestNativeManagedUserRevocation(t *testing.T) {
	privateKey, publicKey := nativeTestKeys(t)
	serverInbound := nativeServerConfig(nativeFreePort(t), privateKey)
	server := nativeStartBox(t, map[string]any{
		"inbounds": []any{serverInbound}, "outbounds": []any{map[string]any{"type": "direct"}},
	}, nil)
	inbound, loaded := server.Inbound().Get("native-in")
	if !loaded {
		t.Fatal("registered native inbound is missing")
	}
	managed, ok := inbound.(adapter.ManagedSSMServer)
	if !ok {
		t.Fatal("native inbound does not support managed users")
	}
	tracker := &nativeRouteTracker{events: make(chan nativeRouteEvent, 64), progress: make(chan struct{}, 1)}
	managed.SetTracker(tracker)
	port := serverInbound["listen_port"].(uint16)
	client := nativeStartBox(t, map[string]any{"outbounds": []any{
		nativeClientConfig(port, publicKey, "alpha", "alpha-secret"),
		nativeClientConfig(port, publicKey, "bravo", "bravo-secret"),
	}}, nil)
	destination := nativeEchoServer(t)
	alpha := nativeGetOutbound(t, client, "alpha")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := alpha.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	var response [1]byte
	if _, err = io.ReadFull(conn, response[:]); err != nil || response[0] != 1 {
		t.Fatalf("initial managed stream: payload=%v error=%v", response, err)
	}
	if event := nativeNextRoute(t, tracker); event.user != "alpha" {
		t.Fatalf("managed tracker attributed stream to %q", event.user)
	}
	byteDeadline := time.NewTimer(time.Second)
	defer byteDeadline.Stop()
	for tracker.read.Load() < 1 || tracker.written.Load() < 1 {
		select {
		case <-tracker.progress:
		case <-byteDeadline.C:
			t.Fatal("managed tracker did not observe both business read and write bytes")
		}
	}
	if err = managed.UpdateUsers([]string{"alpha", "bravo"},
		[]string{"rotated-secret", "bravo-secret"}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = conn.Read(response[:]); err == nil {
		t.Fatal("password rotation left an authenticated old stream open")
	} else if timeout, isTimeout := err.(net.Error); isTimeout && timeout.Timeout() {
		t.Fatal("password rotation did not promptly close the old stream")
	}
	if err = nativeExchange(alpha, destination, 1024); err == nil {
		t.Fatal("old password still authenticated after rotation")
	}
	if err = nativeExchange(nativeGetOutbound(t, client, "bravo"), destination, 1024); err != nil {
		t.Fatalf("unchanged user stopped working after another user rotated: %v", err)
	}
	if event := nativeNextRoute(t, tracker); event.user != "bravo" {
		t.Fatalf("managed tracker attributed unchanged user to %q", event.user)
	}
	rotated := nativeStartBox(t, map[string]any{"outbounds": []any{
		nativeClientConfig(port, publicKey, "rotated", "rotated-secret"),
	}}, nil)
	rotatedOutbound := nativeGetOutbound(t, rotated, "rotated")
	if err = nativeExchange(rotatedOutbound, destination, 1024); err != nil {
		t.Fatalf("new password failed after rotation: %v", err)
	}
	if event := nativeNextRoute(t, tracker); event.user != "alpha" {
		t.Fatalf("rotated password lost its user identity: %q", event.user)
	}
	if err = managed.UpdateUsers([]string{"bravo"}, []string{"bravo-secret"}); err != nil {
		t.Fatal(err)
	}
	if err = nativeExchange(rotatedOutbound, destination, 1024); err == nil {
		t.Fatal("deleted user retained an authenticated idle session")
	}
	if err = managed.UpdateUsers([]string{"bravo"}, []string{}); err == nil {
		t.Fatal("mismatched user and credential counts were accepted")
	}
	if err = managed.UpdateUsers([]string{"bravo", "bravo"}, []string{"first", "second"}); err == nil {
		t.Fatal("duplicate user update was accepted")
	}
	if err = managed.UpdateUsers([]string{"alpha", "bravo"}, []string{"same", "same"}); err == nil {
		t.Fatal("duplicate credential update was accepted")
	}
	if err = nativeExchange(nativeGetOutbound(t, client, "bravo"), destination, 1024); err != nil {
		t.Fatalf("rejected user update changed the active credential table: %v", err)
	}
	bravo := nativeGetOutbound(t, client, "bravo")
	bravoConn, err := bravo.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer bravoConn.Close()
	bravoConn.SetDeadline(time.Now().Add(3 * time.Second))
	if err = nativeExchangeOnConn(bravoConn, 1024); err != nil {
		t.Fatal(err)
	}
	updated := make(chan error, 1)
	go func() {
		for index := range 32 {
			if updateErr := managed.UpdateUsers([]string{"alpha", "bravo"},
				[]string{fmt.Sprintf("changing-%d", index), "bravo-secret"}); updateErr != nil {
				updated <- updateErr
				return
			}
		}
		updated <- nil
	}()
	for range 32 {
		if err = nativeExchangeOnConn(bravoConn, 1024); err != nil {
			t.Fatalf("unchanged active user failed during concurrent updates: %v", err)
		}
	}
	if err = <-updated; err != nil {
		t.Fatal(err)
	}
}

type nativeReadStartedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *nativeReadStartedConn) Read(data []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(data)
}

func TestNativePendingHandshakeLimitAndTimeout(t *testing.T) {
	privateKey, publicKey := nativeTestKeys(t)
	serverInbound := nativeServerConfig(nativeFreePort(t), privateKey)
	serverInbound["max_pending_handshakes"] = 1
	serverInbound["handshake_timeout"] = "500ms"
	server := nativeStartBox(t, map[string]any{
		"inbounds": []any{serverInbound}, "outbounds": []any{map[string]any{"type": "direct"}},
	}, nil)
	inbound, _ := server.Inbound().Get("native-in")
	injectable, ok := inbound.(adapter.TCPInjectableInbound)
	if !ok {
		t.Fatal("registered inbound cannot accept TCP connections")
	}
	slow, accepted := nativeTCPPair(t)
	reading := &nativeReadStartedConn{Conn: accepted, started: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		injectable.NewConnection(context.Background(), reading,
			adapter.InboundContext{Source: M.SocksaddrFromNet(accepted.RemoteAddr())}, nil)
	}()
	nativeWaitSignal(t, reading.started, "first connection entering the secure handshake")
	extra, extraAccepted := nativeTCPPair(t)
	extraDone := make(chan struct{})
	go func() {
		defer close(extraDone)
		injectable.NewConnection(context.Background(), extraAccepted,
			adapter.InboundContext{Source: M.SocksaddrFromNet(extraAccepted.RemoteAddr())}, nil)
	}()
	nativeAssertPeerClosed(t, extra, 250*time.Millisecond, "full handshake gate")
	nativeWaitSignal(t, extraDone, "rejected excess handshake")
	nativeAssertPeerClosed(t, slow, 2*time.Second, "handshake timeout")
	nativeWaitSignal(t, done, "timed out handshake releasing its slot")
	client := nativeStartBox(t, map[string]any{"outbounds": []any{
		nativeClientConfig(serverInbound["listen_port"].(uint16), publicKey, "native", "alpha-secret"),
	}}, nil)
	if err := nativeExchange(nativeGetOutbound(t, client, "native"), nativeEchoServer(t), 1024); err != nil {
		t.Fatalf("authentication slot was not reusable after timeout: %v", err)
	}
}

func TestNativeCloseTerminatesUnauthenticatedConnection(t *testing.T) {
	privateKey, _ := nativeTestKeys(t)
	serverInbound := nativeServerConfig(nativeFreePort(t), privateKey)
	serverInbound["handshake_timeout"] = "1m"
	server := nativeStartBox(t, map[string]any{
		"inbounds": []any{serverInbound}, "outbounds": []any{map[string]any{"type": "direct"}},
	}, nil)
	inbound, _ := server.Inbound().Get("native-in")
	client, accepted := nativeTCPPair(t)
	reading := &nativeReadStartedConn{Conn: accepted, started: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		inbound.(adapter.TCPInjectableInbound).NewConnection(context.Background(), reading,
			adapter.InboundContext{Source: M.SocksaddrFromNet(accepted.RemoteAddr())}, nil)
	}()
	nativeWaitSignal(t, reading.started, "unauthenticated connection registered for shutdown")
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	nativeAssertPeerClosed(t, client, time.Second, "server shutdown")
	nativeWaitSignal(t, done, "unauthenticated handler exiting after shutdown")
}

func nativeAssertPeerClosed(t *testing.T, conn net.Conn, timeout time.Duration, reason string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(timeout))
	var data [1]byte
	if _, err := conn.Read(data[:]); err == nil {
		t.Fatalf("%s did not close the connection", reason)
	} else if timed, ok := err.(net.Error); ok && timed.Timeout() {
		t.Fatalf("%s left the connection blocked until the test deadline", reason)
	}
}

func nativeWaitSignal(t *testing.T, signal <-chan struct{}, reason string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", reason)
	}
}

func nativeTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	connected := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		conn, dialErr := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if dialErr != nil {
			failed <- dialErr
			return
		}
		connected <- conn
	}()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	select {
	case client := <-connected:
		t.Cleanup(func() { client.Close() })
		return client, server
	case err = <-failed:
		t.Fatal(err)
		return nil, nil
	}
}

func nativeServerConfig(port uint16, privateKey string) map[string]any {
	return map[string]any{
		"type": "anytls-native", "tag": "native-in", "listen": "127.0.0.1", "listen_port": port,
		"private_key": privateKey,
		"users": []any{
			map[string]any{"name": "alpha", "password": "alpha-secret"},
			map[string]any{"name": "bravo", "password": "bravo-secret"},
		},
	}
}

func nativeClientConfig(port uint16, publicKey, tag, password string) map[string]any {
	return map[string]any{
		"type": "anytls-native", "tag": tag, "server": "127.0.0.1", "server_port": port,
		"server_public_key": publicKey, "password": password,
	}
}

func nativeStartBox(t *testing.T, config map[string]any, tracker *nativeRouteTracker) *box.Box {
	t.Helper()
	config["log"] = map[string]any{"disabled": true}
	encoded, err := stdjson.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	t.Cleanup(cancel)
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, encoded)
	if err != nil {
		t.Fatalf("decode registered configuration: %v", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatalf("create configured instance: %v", err)
	}
	t.Cleanup(func() { instance.Close() })
	if tracker != nil {
		instance.Router().AppendTracker(tracker)
	}
	if err = instance.Start(); err != nil {
		t.Fatalf("start configured instance: %v", err)
	}
	return instance
}

func nativeGetOutbound(t *testing.T, instance *box.Box, tag string) adapter.Outbound {
	t.Helper()
	outbound, loaded := instance.Outbound().Outbound(tag)
	if !loaded {
		t.Fatalf("outbound %q was not registered", tag)
	}
	return outbound
}

func nativeTestKeys(t *testing.T) (string, string) {
	t.Helper()
	privateKey, publicKey, err := anytlsnative.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(privateKey), base64.RawURLEncoding.EncodeToString(publicKey)
}

func nativeFreePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()
	return port
}

func nativeEchoServer(t *testing.T) M.Socksaddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.Map
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			connections.Store(conn, struct{}{})
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connections.Delete(conn)
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
		connections.Range(func(key, _ any) bool {
			key.(net.Conn).Close()
			return true
		})
		workers.Wait()
	})
	return M.SocksaddrFromNet(listener.Addr())
}

func nativeExchange(outbound adapter.Outbound, destination M.Socksaddr, size int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	return nativeExchangeOnConn(conn, size)
}

func nativeExchangeOnConn(conn net.Conn, size int) error {
	payload := make([]byte, size)
	var err error
	if _, err = rand.Read(payload); err != nil {
		return err
	}
	if _, err = io.Copy(conn, bytes.NewReader(payload)); err != nil {
		return err
	}
	response := make([]byte, size)
	if _, err = io.ReadFull(conn, response); err != nil {
		return err
	}
	if !bytes.Equal(payload, response) {
		return fmt.Errorf("echo payload differs (%d bytes)", size)
	}
	return nil
}

func nativeNextRoute(t *testing.T, tracker *nativeRouteTracker) nativeRouteEvent {
	t.Helper()
	select {
	case event := <-tracker.events:
		return event
	case <-time.After(3 * time.Second):
		t.Fatal("business request did not reach the server router")
		return nativeRouteEvent{}
	}
}

func nativeTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "native.test"},
		DNSNames: []string{"native.test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}
