package anytlsnative_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/usercontrol"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestNativeUserLimitRejectsBeforeOutboundDial verifies admission at the real native protocol entry.
// @author lyt
// @date 2026-10-29
func TestNativeUserLimitRejectsBeforeOutboundDial(t *testing.T) {
	privateKey, publicKey := nativeTestKeys(t)
	serverInbound := nativeServerConfig(nativeFreePort(t), privateKey)
	server := nativeStartBox(t, map[string]any{
		"inbounds": []any{serverInbound}, "outbounds": []any{map[string]any{"type": "direct"}},
	}, nil)
	manager := usercontrol.NewManager(nil)
	if err := manager.UpdateUsers(map[string]usercontrol.Limits{"alpha": {ConnectionLimit: 1}}); err != nil {
		t.Fatal(err)
	}
	inbound, _ := server.Inbound().Get("native-in")
	inbound.(adapter.ManagedSSMServer).SetTracker(manager)
	client := nativeStartBox(t, map[string]any{"outbounds": []any{
		nativeClientConfig(serverInbound["listen_port"].(uint16), publicKey, "alpha", "alpha-secret"),
	}}, nil)
	outbound := nativeGetOutbound(t, client, "alpha")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := outbound.DialContext(ctx, N.NetworkTCP, nativeEchoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err = first.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = nativeExchangeOnConn(first, 64); err != nil {
		t.Fatal(err)
	}
	if manager.ActiveConnections("alpha") != 1 {
		t.Fatal("first native stream did not acquire the user's sole connection slot")
	}
	target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err = nativeExchange(outbound, M.SocksaddrFromNet(target.Addr()), 1); err == nil {
		t.Fatal("second native stream bypassed the active connection limit")
	}
	if err = target.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	unexpected, err := target.Accept()
	if err == nil {
		unexpected.Close()
		t.Fatal("rejected native stream dialed the target before enforcing the limit")
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("unexpected target listener error: %v", err)
	}
	if err = nativeExchangeOnConn(first, 64); err != nil {
		t.Fatalf("rejecting a later logical stream damaged the admitted stream: %v", err)
	}
	first.Close()
	deadline := time.Now().Add(time.Second)
	for manager.ActiveConnections("alpha") != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if manager.ActiveConnections("alpha") != 0 || len(manager.OnlineIPs()) != 0 {
		t.Fatal("closing the real native stream retained admission or online state")
	}
	if err = nativeExchange(outbound, nativeEchoServer(t), 64); err != nil {
		t.Fatalf("a new stream could not reuse the released connection slot: %v", err)
	}
}
