package listener

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/memoryguard"
	"github.com/sagernet/sing-box/common/usercontrol"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestMaintenanceAcceptRegistersBeforeHandshakeAndCountsWireBytes(t *testing.T) {
	cleaner, err := usercontrol.NewConnectionCleaner(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleaner.Close()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegisterPtr(ctx, cleaner)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := wrapMaintenanceListener(ctx, raw)
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if snapshot := cleaner.SourceSnapshot(); len(snapshot) != 1 || snapshot[0].Count != 1 || snapshot[0].Traffic != 0 {
		t.Fatalf("unauthed TCP socket not registered: %+v", snapshot)
	}
	client.Write([]byte("handshake"))
	if _, err := io.ReadFull(server, make([]byte, 9)); err != nil {
		t.Fatal(err)
	}
	if snapshot := cleaner.SourceSnapshot(); snapshot[0].Traffic != 9 {
		t.Fatalf("handshake bytes were not counted: %+v", snapshot)
	}
	cleaner.CloseSources([]string{"127.0.0.1"})
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("closing source did not close unauthenticated socket: %v", err)
	}
}

func TestMaintenanceDisabledAndGuardRegistration(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if wrapMaintenanceListener(context.Background(), raw) != raw {
		t.Fatal("unconfigured maintenance changed the listener")
	}
	cleaner, err := usercontrol.NewConnectionCleaner(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleaner.Close()
	guard, err := memoryguard.New(memoryguard.Options{Enabled: true}, cleaner, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegisterPtr(ctx, cleaner)
	service.MustRegisterPtr(ctx, guard)
	listener := wrapMaintenanceListener(ctx, raw)
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if snapshot := cleaner.SourceSnapshot(); len(snapshot) != 1 || snapshot[0].Count != 1 {
		t.Fatalf("guard and listener registered the socket twice: %+v", snapshot)
	}
}

type rejectFirstAdmission struct {
	cleaner *usercontrol.ConnectionCleaner
	count   int
}

func (g *rejectFirstAdmission) Accept(conn net.Conn, source netip.Addr) (net.Conn, bool) {
	g.count++
	if g.count == 1 {
		conn.Close()
		return nil, false
	}
	return g.cleaner.TrackAcceptedConnection(conn, source), true
}

func TestMaintenanceAcceptSkipsRejectedConnection(t *testing.T) {
	cleaner, err := usercontrol.NewConnectionCleaner(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleaner.Close()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	listener := &maintenanceListener{Listener: raw, guard: &rejectFirstAdmission{cleaner: cleaner}}
	first, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	first.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := first.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("rejected connection was returned to handler: %v", err)
	}
	if server.RemoteAddr().String() != second.LocalAddr().String() || cleaner.SourceSnapshot()[0].Count != 1 {
		t.Fatal("accept did not continue to the next eligible connection")
	}
}

func TestMaintenancePrecedesProxyHeaderAndRoutedMetadataUpdate(t *testing.T) {
	cleaner, err := usercontrol.NewConnectionCleaner(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleaner.Close()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegisterPtr(ctx, cleaner)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := newProxyProtocolListener(wrapMaintenanceListener(ctx, raw), false, time.Second)
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	header := "PROXY TCP4 198.51.100.7 192.0.2.1 1234 443\r\n"
	if _, err := client.Write([]byte(header + "data")); err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := cleaner.SourceSnapshot()
	if len(snapshot) != 1 || snapshot[0].SourceIP != "127.0.0.1" || snapshot[0].Traffic < int64(len(header)) {
		t.Fatalf("registration moved after PROXY parsing or excluded handshake bytes: %+v", snapshot)
	}
	metadata := adapter.InboundContext{User: "user-a", Source: M.SocksaddrFromNet(server.RemoteAddr()).Unwrap()}
	cleaner.UpdateMetadata(server, "tcp-routed", metadata.Source.Addr.Unmap().String(), "panel-label")
	routed := cleaner.RoutedConnection(ctx, server, metadata, nil, nil)
	defer routed.Close()
	if _, err := io.ReadFull(routed, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	snapshot = cleaner.SourceSnapshot()
	if len(snapshot) != 1 || snapshot[0].SourceIP != "198.51.100.7" || snapshot[0].Count != 1 || snapshot[0].Traffic != 4 {
		t.Fatalf("routed PROXY wrapper lost deduplication/source/counter replacement: %+v", snapshot)
	}
}
