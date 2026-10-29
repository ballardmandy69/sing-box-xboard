package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	D "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type onDemandTestTransport struct {
	adapter.DNSTransport
	address string
}

func (*onDemandTestTransport) Type() string { return C.DNSTypeUDP }
func (*onDemandTestTransport) Tag() string  { return "test" }
func (t *onDemandTestTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	client := &mDNS.Client{Net: N.NetworkUDP, Timeout: time.Second}
	response, _, err := client.ExchangeContext(ctx, message, t.address)
	return response, err
}

type onDemandTestTransportManager struct {
	adapter.DNSTransportManager
	transport adapter.DNSTransport
}

func (*onDemandTestTransportManager) FakeIP() adapter.FakeIPTransport { return nil }
func (m *onDemandTestTransportManager) Default() adapter.DNSTransport { return m.transport }

func onDemandNetworkRouter(t *testing.T, enabled bool, address string, rcode int) (*Router, *atomic.Int32) {
	t.Helper()
	queries := new(atomic.Int32)
	listener, err := net.ListenPacket(N.NetworkUDP, "127.0.0.1:0")
	require.NoError(t, err)
	server := &mDNS.Server{PacketConn: listener, Handler: mDNS.HandlerFunc(func(w mDNS.ResponseWriter, request *mDNS.Msg) {
		queries.Add(1)
		response := new(mDNS.Msg).SetReply(request)
		response.Rcode = rcode
		if address != "" {
			header := mDNS.RR_Header{Name: request.Question[0].Name, Class: mDNS.ClassINET, Ttl: 60}
			ip := netip.MustParseAddr(address)
			if ip.Is4() && request.Question[0].Qtype == mDNS.TypeA {
				header.Rrtype = mDNS.TypeA
				response.Answer = []mDNS.RR{&mDNS.A{Hdr: header, A: ip.AsSlice()}}
			} else if ip.Is6() && request.Question[0].Qtype == mDNS.TypeAAAA {
				header.Rrtype = mDNS.TypeAAAA
				response.Answer = []mDNS.RR{&mDNS.AAAA{Hdr: header, AAAA: ip.AsSlice()}}
			}
		}
		_ = w.WriteMsg(response)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) })
	manager := &onDemandTestTransportManager{transport: &onDemandTestTransport{address: listener.LocalAddr().String()}}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	strategy := C.DomainStrategyIPv4Only
	if address != "" && netip.MustParseAddr(address).Is6() {
		strategy = C.DomainStrategyIPv6Only
	}
	dnsRouter, err := D.NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			DNSClientOptions: option.DNSClientOptions{Strategy: option.DomainStrategy(strategy), DisableCache: true},
		},
	})
	require.NoError(t, err)
	return &Router{ctx: ctx, logger: log.NewNOPFactory().Logger(), ipOnDemand: enabled,
		dns: dnsRouter, dnsTransport: manager}, queries
}

func onDemandRules(t *testing.T, r *Router, content string) {
	t.Helper()
	var options []option.Rule
	require.NoError(t, json.Unmarshal([]byte(content), &options))
	for _, ruleOptions := range options {
		rule, err := R.NewRule(r.ctx, r.logger, ruleOptions, false)
		require.NoError(t, err)
		r.rules = append(r.rules, rule)
	}
}

func onDemandMetadata() adapter.InboundContext {
	return adapter.InboundContext{Network: N.NetworkTCP, Destination: M.Socksaddr{Fqdn: "lookup.example", Port: 443}}
}

func TestIPOnDemandNetworkLookupAndTerminalRules(t *testing.T) {
	for _, test := range []struct {
		name, address, rules string
		enabled              bool
		queries              int32
		selected             int
		initialIP, resolved  bool
	}{
		{"ipv4", "192.0.2.10", `[{"ip_cidr":"192.0.2.0/24","outbound":"ip"}]`, true, 1, 0, false, false},
		{"ipv6", "2001:db8::10", `[{"ip_cidr":"2001:db8::/32","outbound":"ip"}]`, true, 1, 0, false, false},
		{"domain-before-lookup", "192.0.2.10", `[{"ip_cidr":"192.0.2.0/24","outbound":"ip"},
			{"domain":"lookup.example","outbound":"domain"}]`, true, 0, 1, false, false},
		{"catch-all", "192.0.2.10", `[{"outbound":"default"}]`, true, 0, 0, false, false},
		{"reject", "192.0.2.10", `[{"action":"reject"}]`, true, 0, 0, false, false},
		{"disabled", "192.0.2.10", `[{"ip_cidr":"192.0.2.0/24","outbound":"ip"}]`, false, 0, -1, false, false},
		{"initial-ip", "192.0.2.10", `[{"ip_cidr":"192.0.2.0/24","outbound":"ip"}]`, true, 0, 0, true, false},
		{"already-resolved", "192.0.2.10", `[{"ip_cidr":"192.0.2.0/24","outbound":"ip"}]`, true, 0, 0, false, true},
		{"no-rule-after-lookup", "192.0.2.10", `[{"ip_cidr":"198.51.100.0/24","outbound":"ip"}]`, true, 1, -1, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, queries := onDemandNetworkRouter(t, test.enabled, test.address, mDNS.RcodeSuccess)
			onDemandRules(t, r, test.rules)
			metadata := onDemandMetadata()
			if test.initialIP {
				metadata.Destination = M.Socksaddr{Addr: netip.MustParseAddr(test.address), Port: 443}
			} else if test.resolved {
				metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr(test.address)}
			}
			rule, index, buffers, _, _, err := r.matchRule(r.ctx, &metadata, nil, nil, nil)
			defer buf.ReleaseMulti(buffers)
			require.NoError(t, err)
			require.Equal(t, test.queries, queries.Load())
			if test.selected < 0 {
				require.Nil(t, rule)
			} else {
				require.Same(t, r.rules[test.selected], rule)
				require.Equal(t, test.selected, index)
			}
		})
	}
}

func TestIPOnDemandLookupFailure(t *testing.T) {
	for _, rcode := range []int{mDNS.RcodeSuccess, mDNS.RcodeNameError, mDNS.RcodeServerFailure} {
		t.Run(mDNS.RcodeToString[rcode], func(t *testing.T) {
			r, queries := onDemandNetworkRouter(t, true, "", rcode)
			metadata := onDemandMetadata()
			_, _, _, _, _, err := r.matchRule(r.ctx, &metadata, nil, nil, nil)
			require.ErrorContains(t, err, "ip_on_demand: resolve lookup.example")
			require.Equal(t, int32(1), queries.Load())
		})
	}
}

func TestIPOnDemandSniffRestoresOriginalIP(t *testing.T) {
	for _, address := range []string{"192.0.2.10", "2001:db8::10"} {
		t.Run(address, func(t *testing.T) {
			r, queries := onDemandNetworkRouter(t, true, "", mDNS.RcodeNameError)
			onDemandRules(t, r, `[{"action":"sniff","sniffer":"http"},
				{"ip_cidr":["192.0.2.0/24","2001:db8::/32"],"outbound":"original"}]`)
			// This internal flag is used by legacy inbound sniff configuration, not the modern JSON action.
			r.rules[0].Action().(*R.RuleActionSniff).OverrideDestination = true
			metadata := onDemandMetadata()
			metadata.Destination = M.Socksaddr{Addr: netip.MustParseAddr(address), Port: 8443}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: sniff.example\r\n\r\n")) }()
			rule, _, buffers, _, _, err := r.matchRule(r.ctx, &metadata, server, nil, nil)
			defer buf.ReleaseMulti(buffers)
			require.NoError(t, err)
			require.Same(t, r.rules[1], rule)
			require.Equal(t, M.Socksaddr{Addr: netip.MustParseAddr(address), Port: 8443}, metadata.Destination)
			require.Equal(t, "sniff.example", metadata.Domain)
			require.Len(t, buffers, 1)
			require.Equal(t, int32(1), queries.Load())
		})
	}
}

func TestIPOnDemandSniffFallbackBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, address, extraRules string
		originalDomain, fakeIP    bool
		wantError                 bool
		port                      uint16
	}{
		{"resolved", "192.0.2.10", "", false, false, false, 8443},
		{"empty-answer-restores", "", "", false, false, false, 8443},
		{"port-override", "", `{"action":"route-options","override_port":9443},`, false, false, false, 9443},
		{"domain-input-no-fallback", "", "", true, false, true, 8443},
		{"fakeip-no-fallback", "", "", false, true, true, 8443},
		{"address-override-clears-fallback", "", `{"action":"route-options","override_address":"other.example"},`,
			false, false, true, 8443},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, queries := onDemandNetworkRouter(t, true, test.address, mDNS.RcodeSuccess)
			onDemandRules(t, r, `[{"action":"sniff","sniffer":"http"},`+test.extraRules+
				`{"ip_cidr":"192.0.2.0/24","outbound":"resolved"},
				{"ip_cidr":"198.51.100.0/24","outbound":"original"}]`)
			r.rules[0].Action().(*R.RuleActionSniff).OverrideDestination = true
			sniffRule := &onDemandCountingRule{Rule: r.rules[0]}
			r.rules[0] = sniffRule
			metadata := onDemandMetadata()
			metadata.FakeIP = test.fakeIP
			metadata.Destination.Port = 8443
			if !test.originalDomain {
				metadata.Destination = M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 8443}
			}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: sniff.example\r\n\r\n")) }()
			rule, _, buffers, _, _, err := r.matchRule(r.ctx, &metadata, server, nil, nil)
			defer buf.ReleaseMulti(buffers)
			require.Equal(t, int32(1), queries.Load())
			require.Equal(t, 1, sniffRule.matches)
			if test.wantError {
				require.Error(t, err)
				require.Empty(t, buffers, "fatal supplemental lookup must release sniff buffers")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, rule)
			require.Equal(t, test.port, metadata.Destination.Port)
			if test.address != "" {
				require.Equal(t, "resolved", rule.Action().(*R.RuleActionRoute).Outbound)
				require.Equal(t, "sniff.example", metadata.Destination.Fqdn)
			} else {
				require.Equal(t, "original", rule.Action().(*R.RuleActionRoute).Outbound)
				require.Equal(t, netip.MustParseAddr("198.51.100.10"), metadata.Destination.Addr)
			}
		})
	}
}

func TestIPOnDemandDoesNotResolveProxyUDP(t *testing.T) {
	r, queries := onDemandNetworkRouter(t, true, "192.0.2.10", mDNS.RcodeSuccess)
	metadata := onDemandMetadata()
	metadata.Network = N.NetworkUDP
	_, _, _, _, _, err := r.matchRule(r.ctx, &metadata, nil, nil, nil)
	require.NoError(t, err)
	require.Zero(t, queries.Load())
}

type onDemandLookupSequence struct {
	adapter.DNSRouter
	calls int
}

func (*onDemandLookupSequence) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (d *onDemandLookupSequence) Lookup(_ context.Context, _ string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	d.calls++
	if d.calls == 1 {
		return nil, nil
	}
	if d.calls > 2 {
		return nil, errors.New("resolve action was replayed")
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
}

type onDemandCountingRule struct {
	adapter.Rule
	matches int
}

func (r *onDemandCountingRule) Match(metadata *adapter.InboundContext) bool {
	r.matches++
	return r.Rule.Match(metadata)
}

func TestIPOnDemandDoesNotReplayActions(t *testing.T) {
	r, _ := onDemandNetworkRouter(t, true, "192.0.2.10", mDNS.RcodeSuccess)
	dnsRouter := new(onDemandLookupSequence)
	r.dns = dnsRouter
	onDemandRules(t, r, `[{"action":"route-options","override_port":8443},{"action":"resolve"},
		{"ip_cidr":"192.0.2.0/24","outbound":"ip"}]`)
	first := &onDemandCountingRule{Rule: r.rules[0]}
	second := &onDemandCountingRule{Rule: r.rules[1]}
	r.rules[0], r.rules[1] = first, second
	metadata := onDemandMetadata()
	rule, _, _, _, _, err := r.matchRule(r.ctx, &metadata, nil, nil, nil)
	require.NoError(t, err)
	require.Same(t, r.rules[2], rule)
	require.Equal(t, uint16(8443), metadata.Destination.Port)
	require.Equal(t, 2, dnsRouter.calls)
	require.Equal(t, 1, first.matches)
	require.Equal(t, 1, second.matches)
}

func TestIPOnDemandPreMatchDefersUnmatchedDomain(t *testing.T) {
	r := &Router{ipOnDemand: true}
	metadata := onDemandMetadata()
	result := r.preMatchFlow(context.Background(), &metadata, metadata.Destination, nil, "")
	require.Equal(t, adapter.PreMatchContinue, result.Action)
	metadata.Network = N.NetworkUDP
	result = r.preMatchFlow(context.Background(), &metadata, metadata.Destination, nil, "")
	require.Equal(t, adapter.PreMatchReject, result.Action)
}

func TestIPOnDemandOptionDefaultsAndRouterCopy(t *testing.T) {
	for _, test := range []struct {
		content string
		enabled bool
	}{{`{}`, false}, {`{"ip_on_demand":false}`, false}, {`{"ip_on_demand":true}`, true}} {
		var options option.RouteOptions
		require.NoError(t, json.UnmarshalDisallowUnknownFields([]byte(test.content), &options))
		r := NewRouter(service.ContextWithDefaultRegistry(context.Background()), log.NewNOPFactory(), options, option.DNSOptions{})
		require.Equal(t, test.enabled, r.ipOnDemand)
	}
}
