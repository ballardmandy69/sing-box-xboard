package transport

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type legacyNetworkTestOutbound struct {
	adapter.Outbound
	udpDials atomic.Int32
}

func (o *legacyNetworkTestOutbound) DialContext(ctx context.Context, network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	if network == "udp" {
		o.udpDials.Add(1)
	}
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

type legacyNetworkTestManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *legacyNetworkTestManager) Default() adapter.Outbound { return m.outbound }

func TestLegacyBareDNSAddressKeepsUDPWithRealExchange(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &mDNS.Server{PacketConn: listener, Handler: mDNS.HandlerFunc(func(w mDNS.ResponseWriter, request *mDNS.Msg) {
		response := new(mDNS.Msg).SetReply(request)
		response.Answer = []mDNS.RR{&mDNS.A{
			Hdr: mDNS.RR_Header{Name: request.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.10"),
		}}
		_ = w.WriteMsg(response)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) })
	manager := &legacyNetworkTestManager{}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	registry := dns.NewTransportRegistry()
	RegisterUDP(registry)
	transport, err := registry.CreateDNSTransport(ctx, log.NewNOPFactory().Logger(), "legacy", "",
		&option.LegacyDNSServerOptions{Address: listener.LocalAddr().String()})
	require.NoError(t, err)
	selected := &legacyNetworkTestOutbound{}
	manager.outbound = selected
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, transport.Start(adapter.StartStateStart, scope))
	queryContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	response, err := transport.Exchange(queryContext, new(mDNS.Msg).SetQuestion("real.example.", mDNS.TypeA))
	require.NoError(t, err)
	require.Equal(t, "192.0.2.10", response.Answer[0].(*mDNS.A).A.String())
	require.Equal(t, int32(1), selected.udpDials.Load())
}
