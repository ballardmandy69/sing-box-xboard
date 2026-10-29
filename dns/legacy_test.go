package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestLegacyDNSServerConversion(t *testing.T) {
	for _, test := range []struct {
		address, kind, host string
		port                uint16
	}{
		{"1.1.1.1", C.DNSTypeUDP, "1.1.1.1", 53},
		{"2001:4860::8888", C.DNSTypeUDP, "2001:4860::8888", 53},
		{"udp://[2001:4860::8888]:5353", C.DNSTypeUDP, "2001:4860::8888", 5353},
		{"tcp://1.1.1.1:5353", C.DNSTypeTCP, "1.1.1.1", 5353},
		{"tls://dns.example:853", C.DNSTypeTLS, "dns.example", 853},
		{"https://dns.example:8443/custom?key=value", C.DNSTypeHTTPS, "dns.example", 8443},
	} {
		t.Run(test.address, func(t *testing.T) {
			kind, converted, err := convertLegacyDNSServer(option.LegacyDNSServerOptions{
				Address: test.address, AddressResolver: "bootstrap",
				AddressStrategy:      option.DomainStrategy(C.DomainStrategyPreferIPv6),
				AddressFallbackDelay: badoption.Duration(123 * time.Millisecond),
				Strategy:             option.DomainStrategy(C.DomainStrategyIPv4Only), Detour: "proxy",
			})
			require.NoError(t, err)
			require.Equal(t, test.kind, kind)
			var remote option.RemoteDNSServerOptions
			switch typed := converted.(type) {
			case *option.RemoteDNSServerOptions:
				remote = *typed
			case *option.RemoteTLSDNSServerOptions:
				remote = typed.RemoteDNSServerOptions
			case *option.RemoteHTTPSDNSServerOptions:
				remote = typed.RemoteDNSServerOptions
				require.Equal(t, "/custom?key=value", typed.Path)
			default:
				t.Fatalf("unexpected converted type %T", converted)
			}
			require.Equal(t, test.host, remote.Server)
			require.Equal(t, test.port, remote.ServerPort)
			require.Equal(t, "proxy", remote.Detour)
			require.Equal(t, "bootstrap", remote.DomainResolver.Server)
			require.Equal(t, option.DomainStrategy(C.DomainStrategyPreferIPv6), remote.DomainResolver.Strategy)
			require.Equal(t, badoption.Duration(123*time.Millisecond), remote.FallbackDelay)
		})
	}
	for _, address := range []string{"", "tls://dns.example", "udp://1.1.1.1:0", "tcp://1.1.1.1/path", "bad://1.1.1.1"} {
		_, _, err := convertLegacyDNSServer(option.LegacyDNSServerOptions{Address: address})
		require.Error(t, err, address)
	}
	for address, kind := range map[string]string{"local": C.DNSTypeLocal, "dhcp://auto": C.DNSTypeDHCP} {
		actual, _, err := convertLegacyDNSServer(option.LegacyDNSServerOptions{Address: address})
		require.NoError(t, err)
		require.Equal(t, kind, actual)
	}
}

type legacyTestOutbound struct {
	adapter.Outbound
	network     string
	destination M.Socksaddr
	calls       int
}

func (o *legacyTestOutbound) IsEmpty() bool { return true }

func (o *legacyTestOutbound) DialContext(_ context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.network, o.destination = network, destination
	o.calls++
	return nil, errors.New("test outbound reached")
}

type legacyTestOutboundManager struct {
	adapter.OutboundManager
	defaultOutbound adapter.Outbound
	explicit        adapter.Outbound
}

func (m *legacyTestOutboundManager) Default() adapter.Outbound { return m.defaultOutbound }

func (m *legacyTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.explicit, tag == "chosen" && m.explicit != nil
}

func TestLegacyDNSDialerUsesLateDefaultAndExplicitOutbound(t *testing.T) {
	for _, detour := range []string{"", "chosen", "missing"} {
		t.Run(detour, func(t *testing.T) {
			manager := &legacyTestOutboundManager{}
			ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
			ctx = context.WithValue(ctx, legacyDNSContextKey{}, true)
			_, raw, err := convertLegacyDNSServer(option.LegacyDNSServerOptions{Address: "1.1.1.1", Detour: detour})
			require.NoError(t, err)
			dialer, err := NewRemoteDialer(ctx, *raw.(*option.RemoteDNSServerOptions))
			require.NoError(t, err, "outbounds are not yet created")
			defaultOutbound, explicit := &legacyTestOutbound{}, &legacyTestOutbound{}
			manager.defaultOutbound, manager.explicit = defaultOutbound, explicit
			_, err = dialer.DialContext(ctx, "udp", M.ParseSocksaddr("1.1.1.1:53"))
			if detour == "missing" {
				require.ErrorContains(t, err, "outbound detour not found")
				require.Zero(t, defaultOutbound.calls)
				return
			}
			require.ErrorContains(t, err, "test outbound reached")
			selected := defaultOutbound
			if detour != "" {
				selected = explicit
				require.Zero(t, defaultOutbound.calls)
			}
			require.Equal(t, "udp", selected.network)
			require.Equal(t, M.ParseSocksaddr("1.1.1.1:53"), selected.destination)
			require.Equal(t, 1, selected.calls)
		})
	}
}

func newLegacyTestRouter(t *testing.T, options option.DNSOptions, transports ...*fakeDNSTransport) *Router {
	t.Helper()
	manager := &fakeDNSTransportManager{transports: make(map[string]adapter.DNSTransport), defaultTransport: transports[0]}
	for _, transport := range transports {
		manager.transports[transport.Tag()] = transport
	}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	router, err := NewRouter(ctx, log.NewNOPFactory(), options)
	require.NoError(t, err)
	require.NoError(t, router.Initialize(options.Rules))
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, router.Start(adapter.StartStateStart, scope))
	return router
}

func TestLegacyDNSSharedAndIndependentCache(t *testing.T) {
	for _, test := range []struct {
		name                string
		legacy, independent bool
		expectedCalls       int32
	}{
		{"legacy-shared", true, false, 0}, {"legacy-independent", true, true, 1}, {"modern-independent", false, false, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := &fakeDNSTransport{tag: "first", address: netip.MustParseAddr("1.1.1.1")}
			second := &fakeDNSTransport{tag: "second", address: netip.MustParseAddr("8.8.8.8")}
			options := option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
				DNSClientOptions: option.DNSClientOptions{IndependentCache: test.independent},
			}}
			if test.legacy {
				options.Servers = []option.DNSServerOptions{{
					Tag: "first", Options: &option.LegacyDNSServerOptions{Address: "local"},
				}}
			}
			router := newLegacyTestRouter(t, options, first, second)
			message := new(mDNS.Msg).SetQuestion("cache.example.", mDNS.TypeA)
			_, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: first})
			require.NoError(t, err)
			response, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: second})
			require.NoError(t, err)
			require.Equal(t, test.expectedCalls, second.queryCount.Load())
			address := "8.8.8.8"
			if test.expectedCalls == 0 {
				address = "1.1.1.1"
			}
			require.Equal(t, address, response.Answer[0].(*mDNS.A).A.String())
		})
	}
}

func TestLegacyDNSServerStrategyAndQueryRules(t *testing.T) {
	first := &fakeDNSTransport{tag: "first", address: netip.MustParseAddr("1.1.1.1")}
	options := option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
		Servers: []option.DNSServerOptions{{Tag: "first", Options: &option.LegacyDNSServerOptions{
			Address: "local", Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only),
		}}},
		DNSClientOptions: option.DNSClientOptions{
			Strategy: option.DomainStrategy(C.DomainStrategyIPv6Only), DisableCache: true,
		},
	}}
	var rule option.DNSRule
	require.NoError(t, json.Unmarshal([]byte(`{"query_type":"AAAA","server":"first"}`), &rule))
	options.Rules = []option.DNSRule{rule}
	router := newLegacyTestRouter(t, options, first)
	require.True(t, router.legacyDNSMode)
	addresses, err := router.Lookup(context.Background(), "strategy.example", adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, addresses)
	require.Equal(t, int32(1), first.queryCount.Load(), "server strategy overrides root and sends only A")
	message := new(mDNS.Msg).SetQuestion("strategy.example.", mDNS.TypeAAAA)
	response, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Empty(t, response.Answer)
	require.Equal(t, int32(1), first.queryCount.Load(), "ipv4_only suppresses AAAA on selected server")
	optionsWithOverride := router.finalizeExchangeOptions(first, adapter.DNSQueryOptions{
		Strategy: C.DomainStrategyIPv6Only,
	})
	require.Equal(t, C.DomainStrategyIPv6Only, optionsWithOverride.Strategy)
}

func TestLegacyDNSRcodeRegistry(t *testing.T) {
	registry := NewTransportRegistry()
	transport, err := registry.CreateDNSTransport(context.Background(), log.NewNOPFactory().Logger(), "refuse", "",
		&option.LegacyDNSServerOptions{Address: "rcode://refused"})
	require.NoError(t, err)
	response, err := transport.Exchange(context.Background(), new(mDNS.Msg).SetQuestion("block.example.", mDNS.TypeA))
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeRefused, response.Rcode)
	_, err = registry.CreateDNSTransport(context.Background(), log.NewNOPFactory().Logger(), "bad", "legacy",
		&option.LegacyDNSServerOptions{Address: "rcode://not-a-code"})
	require.ErrorContains(t, err, "unknown legacy DNS rcode")
}

func TestLegacyDNSSharedCachePrecedesRules(t *testing.T) {
	for _, independent := range []bool{false, true} {
		t.Run(fmt.Sprint(independent), func(t *testing.T) {
			transport := &fakeDNSTransport{tag: "first", address: netip.MustParseAddr("1.1.1.1")}
			var reject option.DNSRule
			require.NoError(t, json.Unmarshal([]byte(`{"domain":"cache.example","action":"reject"}`), &reject))
			options := option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{{
					Tag: "first", Options: &option.LegacyDNSServerOptions{Address: "local"},
				}},
				Rules:            []option.DNSRule{reject},
				DNSClientOptions: option.DNSClientOptions{IndependentCache: independent},
			}}
			router := newLegacyTestRouter(t, options, transport)
			message := new(mDNS.Msg).SetQuestion("cache.example.", mDNS.TypeA)
			_, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{Transport: transport})
			require.NoError(t, err)
			response, err := router.Exchange(context.Background(), message, adapter.DNSQueryOptions{})
			require.NoError(t, err)
			if independent {
				require.Equal(t, mDNS.RcodeRefused, response.Rcode, "independent cache cannot bypass server selection")
			} else {
				require.Len(t, response.Answer, 1, "original shared-cache hit precedes reject rule evaluation")
			}
			completed := make(chan *mDNS.Msg, 1)
			router.ExchangeAsync(context.Background(), message, adapter.DNSQueryOptions{}, func(response *mDNS.Msg, err error) {
				if err != nil {
					t.Error(err)
				}
				completed <- response
			})
			if independent {
				require.Equal(t, mDNS.RcodeRefused, (<-completed).Rcode)
			} else {
				require.Len(t, (<-completed).Answer, 1)
			}
			response, err = router.Exchange(context.Background(), message, adapter.DNSQueryOptions{DisableCache: true})
			require.NoError(t, err)
			require.Equal(t, mDNS.RcodeRefused, response.Rcode, "an explicit cache bypass must still evaluate rules")
		})
	}
}

func TestLegacyDNSBootstrapDoesNotInheritQueryStrategy(t *testing.T) {
	transport := &fakeDNSTransport{tag: "bootstrap", address: netip.MustParseAddr("1.1.1.1")}
	router := newLegacyTestRouter(t, option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
		Servers: []option.DNSServerOptions{{Tag: "bootstrap", Options: &option.LegacyDNSServerOptions{
			Address: "local", Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only),
		}}},
		DNSClientOptions: option.DNSClientOptions{
			Strategy: option.DomainStrategy(C.DomainStrategyIPv6Only), DisableCache: true,
		},
	}}, transport)
	ctx := service.ContextWith[adapter.DNSRouter](router.ctx, router)
	outbound := &legacyTestOutbound{}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &legacyTestOutboundManager{defaultOutbound: outbound})
	ctx = context.WithValue(ctx, legacyDNSContextKey{}, true)
	_, converted, err := convertLegacyDNSServer(option.LegacyDNSServerOptions{
		Address: "tcp://resolver.example", AddressResolver: "bootstrap",
	})
	require.NoError(t, err)
	dialer, err := NewRemoteDialer(ctx, *converted.(*option.RemoteDNSServerOptions))
	require.NoError(t, err)
	require.Same(t, router, service.FromContext[adapter.DNSRouter](ctx), "private resolver must not replace global router")
	_, err = dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("resolver.example:53"))
	require.ErrorContains(t, err, "test outbound reached")
	require.Equal(t, int32(2), transport.queryCount.Load(), "raw as-is strategy queries A and AAAA")
	require.Equal(t, M.ParseSocksaddr("1.1.1.1:53"), outbound.destination)
}
