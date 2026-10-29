package route

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	mDNS "github.com/miekg/dns"
)

type tcpOnlyRule struct {
	adapter.Rule
	action adapter.RuleAction
}

func (r tcpOnlyRule) Match(*adapter.InboundContext) bool { return true }
func (r tcpOnlyRule) String() string                     { return "test" }
func (r tcpOnlyRule) Action() adapter.RuleAction         { return r.action }

type tcpOnlyPacketConn struct {
	closed   atomic.Int32
	response []byte
}

func (c *tcpOnlyPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, net.ErrClosed
}
func (c *tcpOnlyPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	c.response = append([]byte(nil), buffer.Bytes()...)
	buffer.Release()
	return nil
}
func (c *tcpOnlyPacketConn) Close() error                   { c.closed.Add(1); return nil }
func (*tcpOnlyPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*tcpOnlyPacketConn) SetDeadline(time.Time) error      { return nil }
func (*tcpOnlyPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*tcpOnlyPacketConn) SetWriteDeadline(time.Time) error { return nil }

func tcpOnlyRouter() *Router {
	return &Router{ctx: context.Background(), logger: log.NewNOPFactory().Logger()}
}

func tcpOnlyMetadata() adapter.InboundContext {
	return adapter.InboundContext{
		Network: N.NetworkUDP, Domain: "example.test",
		Destination: M.Socksaddr{Fqdn: "example.test", Port: 443},
	}
}

func TestPacketForwardingRejectedWithoutManagedTracker(t *testing.T) {
	for _, inboundType := range []string{C.TypeTrojan, C.TypeVMess, C.TypeVLESS, C.TypeShadowsocks, C.TypeSOCKS} {
		t.Run(inboundType, func(t *testing.T) {
			r := tcpOnlyRouter()
			metadata := tcpOnlyMetadata()
			metadata.InboundType = inboundType
			conn := &tcpOnlyPacketConn{}
			// No outbound manager is present: any attempt to select an outbound would panic.
			if err := r.RoutePacketConnection(context.Background(), conn, metadata); !errors.Is(err, C.ErrUDPDisabled) {
				t.Fatalf("legacy packet API returned %v", err)
			}
			if conn.closed.Load() != 1 {
				t.Fatal("rejected packet connection was not closed")
			}
			var callbackError error
			conn = &tcpOnlyPacketConn{}
			r.RoutePacketConnectionEx(context.Background(), conn, metadata, func(err error) { callbackError = err })
			if !errors.Is(callbackError, C.ErrUDPDisabled) || conn.closed.Load() != 1 {
				t.Fatal("packet rejection did not propagate through the asynchronous API")
			}
		})
	}
}

func TestUDPOverTCPAndPacketDetoursCannotBypassPolicy(t *testing.T) {
	r := tcpOnlyRouter()
	for _, domain := range []string{uot.MagicAddress, uot.LegacyMagicAddress, "SP.UDP-OVER-TCP.ARPA."} {
		metadata := tcpOnlyMetadata()
		metadata.Destination.Fqdn = domain
		metadata.InboundDetour = "would-bypass"
		if err := r.routeConnection(context.Background(), nil, metadata, nil); !errors.Is(err, C.ErrUDPDisabled) {
			t.Fatalf("UoT TCP destination %q was not rejected before detouring", domain)
		}
		metadata.Domain = domain
		metadata.InboundDetour = ""
		r.rules = []adapter.Rule{tcpOnlyRule{action: &R.RuleActionHijackDNS{}}}
		if err := r.routePacketConnection(context.Background(), nil, metadata, nil); !errors.Is(err, C.ErrUDPDisabled) {
			t.Fatal("decoded UoT packets bypassed policy through a DNS rule")
		}
	}
	metadata := tcpOnlyMetadata()
	metadata.InboundDetour = "would-bypass"
	if err := r.routePacketConnection(context.Background(), nil, metadata, nil); !errors.Is(err, C.ErrUDPDisabled) {
		t.Fatal("packet detour bypassed TCP-only forwarding")
	}
}

func TestUDPFastPathsRejectButDNSInterceptionRemainsAvailable(t *testing.T) {
	for _, action := range []adapter.RuleAction{
		&R.RuleActionRoute{Outbound: "direct"}, &R.RuleActionBypass{}, &R.RuleActionBypass{Outbound: "direct"},
	} {
		r := tcpOnlyRouter()
		r.rules = []adapter.Rule{tcpOnlyRule{action: action}}
		if result := r.PreMatch(tcpOnlyMetadata(), nil); result.Action != adapter.PreMatchReject {
			t.Fatalf("UDP action %T escaped via pre-match: %v", action, result.Action)
		}
	}
	r := tcpOnlyRouter()
	if result := r.PreMatch(tcpOnlyMetadata(), nil); result.Action != adapter.PreMatchReject {
		t.Fatal("default UDP flow escaped via pre-match")
	}
	r.rules = []adapter.Rule{tcpOnlyRule{action: &R.RuleActionHijackDNS{}}}
	if result := r.PreMatch(tcpOnlyMetadata(), nil); result.Action != adapter.PreMatchHijackDNS {
		t.Fatal("local DNS interception was blocked")
	}
}

type tcpOnlyDNSRouter struct {
	adapter.DNSRouter
	queries int
}

func (r *tcpOnlyDNSRouter) ExchangeAsync(_ context.Context, request *mDNS.Msg, _ adapter.DNSQueryOptions,
	callback func(*mDNS.Msg, error),
) {
	r.queries++
	response := new(mDNS.Msg)
	response.SetReply(request)
	callback(response, nil)
}

func TestInternalDNSExchangeStillProducesAResponse(t *testing.T) {
	r := tcpOnlyRouter()
	dns := &tcpOnlyDNSRouter{}
	r.dns = dns
	request := new(mDNS.Msg)
	request.SetQuestion("example.test.", mDNS.TypeA)
	payload, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	writer := &tcpOnlyPacketConn{}
	r.HijackDNSPacket(context.Background(), payload, writer, tcpOnlyMetadata())
	var response mDNS.Msg
	if err = response.Unpack(writer.response); err != nil {
		t.Fatal(err)
	}
	if dns.queries != 1 || !response.Response || response.Id != request.Id {
		t.Fatal("TCP-only forwarding interfered with the internal DNS exchange")
	}
}
