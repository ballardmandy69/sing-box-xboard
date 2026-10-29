package route

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	mDNS "github.com/miekg/dns"
)

func TestConnectionManagerRejectsPacketBypass(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	for _, connected := range []bool{false, true} {
		metadata := tcpOnlyMetadata()
		metadata.UDPConnect = connected
		// Marking a proxy stream as DNS does not turn it into an internal resolver query.
		metadata.Protocol = C.ProtocolDNS
		conn := new(tcpOnlyPacketConn)
		var callbackErr error
		var callbacks int
		// A nil dialer proves both the connected and unconnected paths reject before dialing.
		manager.NewPacketConnection(context.Background(), nil, conn, metadata, func(err error) {
			callbackErr = err
			callbacks++
		})
		if !errors.Is(callbackErr, C.ErrUDPDisabled) || callbacks != 1 || conn.closed.Load() != 1 {
			t.Fatalf("packet bypass was not closed: err=%v callbacks=%d closes=%d",
				callbackErr, callbacks, conn.closed.Load())
		}
		if manager.Count() != 0 {
			t.Fatal("rejected packet connection was tracked")
		}
	}
}

func TestConnectionManagerRejectsUoTBypass(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	for _, domain := range []string{uot.MagicAddress, uot.LegacyMagicAddress, "SP.UDP-OVER-TCP.ARPA."} {
		t.Run(domain, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			client.SetWriteDeadline(time.Now().Add(time.Second))
			metadata := tcpOnlyMetadata()
			metadata.Destination.Fqdn = domain
			var callbackErr error
			var callbacks int
			manager.NewConnection(context.Background(), nil, server, metadata, func(err error) {
				callbackErr = err
				callbacks++
			})
			if !errors.Is(callbackErr, C.ErrUDPDisabled) || callbacks != 1 {
				t.Fatalf("UoT bypass was not rejected: err=%v callbacks=%d", callbackErr, callbacks)
			}
			if _, err := client.Write([]byte("payload")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("rejected UoT connection remained open: %v", err)
			}
		})
	}
}

func TestTCPOnlyAllowsInternalUDPResolver(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	server.SetDeadline(time.Now().Add(5 * time.Second))
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1500)
		n, source, readErr := server.ReadFrom(buffer)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		query := new(mDNS.Msg)
		if unpackErr := query.Unpack(buffer[:n]); unpackErr != nil {
			serverDone <- unpackErr
			return
		}
		response := new(mDNS.Msg)
		response.SetReply(query)
		payload, packErr := response.Pack()
		if packErr != nil {
			serverDone <- packErr
			return
		}
		_, writeErr := server.WriteTo(payload, source)
		serverDone <- writeErr
	}()
	resolverDialer, err := dialer.NewDefault(context.Background(), option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	logger := log.NewNOPFactory().Logger()
	resolver := transport.NewUDPRaw(logger, boxDNS.NewTransportAdapter(C.DNSTypeUDP, "test", nil),
		resolverDialer, M.SocksaddrFromNet(server.LocalAddr()))
	scope := adapter.NewScope(context.Background(), logger)
	t.Cleanup(func() { scope.Close() })
	if err = resolver.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	query := new(mDNS.Msg)
	query.SetQuestion("internal-resolver.test.", mDNS.TypeA)
	response, err := resolver.Exchange(ctx, query)
	if err != nil {
		t.Fatalf("internal DNS failed under the TCP-only policy: %v", err)
	}
	if !response.Response || len(response.Question) != 1 || response.Question[0] != query.Question[0] {
		t.Fatal("unexpected internal DNS response")
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}
