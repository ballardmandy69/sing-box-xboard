package route

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func legacySniffInput(t *testing.T, useTLS bool) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	t.Cleanup(func() { _ = client.Close(); _ = server.Close(); <-done })
	go func() {
		defer close(done)
		if useTLS {
			connection := tls.Client(client, &tls.Config{ServerName: "sniff.example", InsecureSkipVerify: true})
			_ = connection.Handshake()
		} else {
			_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: sniff.example\r\n\r\n"))
		}
	}()
	return server
}

func TestLegacyInboundSniffBeforeRules(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		for _, override := range []bool{false, true} {
			r, queries := onDemandNetworkRouter(t, false, "192.0.2.10", mDNS.RcodeSuccess)
			onDemandRules(t, r, `[{"domain":"sniff.example","outbound":"sniffed"}]`)
			metadata := onDemandMetadata()
			metadata.Destination = M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 8443}
			metadata.LegacyInboundOptions = option.InboundOptions{SniffEnabled: true, SniffOverrideDestination: override}
			rule, _, buffers, _, err := r.matchRule(r.ctx, &metadata, legacySniffInput(t, useTLS), nil)
			buf.ReleaseMulti(buffers)
			require.NoError(t, err)
			require.Same(t, r.rules[0], rule)
			require.Equal(t, "sniff.example", metadata.Domain)
			require.Equal(t, uint16(8443), metadata.Destination.Port)
			require.Equal(t, override, metadata.Destination.IsDomain())
			require.Zero(t, queries.Load())
			if useTLS {
				require.Equal(t, C.ProtocolTLS, metadata.Protocol)
			} else {
				require.Equal(t, C.ProtocolHTTP, metadata.Protocol)
			}
		}
	}
}

func TestLegacyInboundSniffDoesNotOverrideClientDomain(t *testing.T) {
	r, queries := onDemandNetworkRouter(t, false, "192.0.2.10", mDNS.RcodeSuccess)
	metadata := onDemandMetadata()
	metadata.LegacyInboundOptions = option.InboundOptions{SniffEnabled: true, SniffOverrideDestination: true}
	_, _, buffers, _, err := r.matchRule(r.ctx, &metadata, legacySniffInput(t, true), nil)
	defer buf.ReleaseMulti(buffers)
	require.NoError(t, err)
	require.Equal(t, "lookup.example", metadata.Destination.Fqdn)
	require.Equal(t, "sniff.example", metadata.Domain)
	require.Zero(t, queries.Load())
}

func TestLegacyInboundSniffIPOnDemandRecovery(t *testing.T) {
	r, queries := onDemandNetworkRouter(t, true, "", mDNS.RcodeNameError)
	onDemandRules(t, r, `[{"ip_cidr":"198.51.100.0/24","outbound":"original"}]`)
	metadata := onDemandMetadata()
	metadata.Destination = M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 443}
	metadata.LegacyInboundOptions = option.InboundOptions{SniffEnabled: true, SniffOverrideDestination: true}
	rule, _, buffers, _, err := r.matchRule(r.ctx, &metadata, legacySniffInput(t, false), nil)
	defer buf.ReleaseMulti(buffers)
	require.NoError(t, err)
	require.Same(t, r.rules[0], rule)
	require.Equal(t, netip.MustParseAddr("198.51.100.10"), metadata.Destination.Addr)
	require.Equal(t, int32(1), queries.Load())
}

type legacyLookupRecorder struct {
	adapter.DNSRouter
	strategy C.DomainStrategy
	domain   string
	address  []netip.Addr
	err      error
	reverse  string
	calls    int
}

func (r *legacyLookupRecorder) LookupReverseMapping(netip.Addr) (string, bool) {
	return r.reverse, r.reverse != ""
}
func (r *legacyLookupRecorder) Lookup(_ context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.calls++
	r.strategy, r.domain = options.Strategy, domain
	return r.address, r.err
}

func TestLegacyInboundDomainStrategyPrecedesRules(t *testing.T) {
	for _, strategy := range []C.DomainStrategy{C.DomainStrategyPreferIPv4, C.DomainStrategyPreferIPv6,
		C.DomainStrategyIPv4Only, C.DomainStrategyIPv6Only} {
		r, _ := onDemandNetworkRouter(t, true, "192.0.2.10", mDNS.RcodeSuccess)
		onDemandRules(t, r, `[{"ip_cidr":"192.0.2.0/24","outbound":"ip"},
			{"domain":"lookup.example","outbound":"domain"}]`)
		recorder := &legacyLookupRecorder{address: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
		r.dns = recorder
		metadata := onDemandMetadata()
		metadata.LegacyInboundOptions.DomainStrategy = option.DomainStrategy(strategy)
		rule, _, _, _, err := r.matchRule(r.ctx, &metadata, nil, nil)
		require.NoError(t, err)
		require.Same(t, r.rules[0], rule)
		require.Equal(t, strategy, recorder.strategy)
		require.Equal(t, 1, recorder.calls)
	}
}

func TestLegacyInboundDomainStrategyFailureAndExistingAddresses(t *testing.T) {
	for _, existing := range []bool{false, true} {
		r, _ := onDemandNetworkRouter(t, true, "", mDNS.RcodeNameError)
		recorder := &legacyLookupRecorder{err: errors.New("lookup failed")}
		r.dns = recorder
		metadata := onDemandMetadata()
		metadata.LegacyInboundOptions.DomainStrategy = option.DomainStrategy(C.DomainStrategyIPv4Only)
		if existing {
			metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("192.0.2.10")}
		}
		_, _, _, _, err := r.matchRule(r.ctx, &metadata, nil, nil)
		if existing {
			require.NoError(t, err)
			require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, metadata.DestinationAddresses)
		} else {
			require.ErrorContains(t, err, "legacy inbound domain_strategy")
		}
		require.Equal(t, 1, recorder.calls, "ip_on_demand must not retry failed explicit domain_strategy")
	}
}

func TestLegacyInboundSniffBuffersReleasedWhenLaterActionFails(t *testing.T) {
	r, _ := onDemandNetworkRouter(t, false, "", mDNS.RcodeNameError)
	onDemandRules(t, r, `[{"action":"resolve"}]`)
	metadata := onDemandMetadata()
	metadata.LegacyInboundOptions = option.InboundOptions{SniffEnabled: true}
	_, _, buffers, packetBuffers, err := r.matchRule(r.ctx, &metadata, legacySniffInput(t, false), nil)
	require.Error(t, err)
	require.Empty(t, buffers)
	require.Empty(t, packetBuffers)
}

type legacyDeadlineConn struct {
	net.Conn
	firstDeadline time.Time
}

func (c *legacyDeadlineConn) SetReadDeadline(deadline time.Time) error {
	if c.firstDeadline.IsZero() {
		c.firstDeadline = deadline
	}
	return c.Conn.SetReadDeadline(deadline)
}

func TestLegacyInboundSniffTimeoutAndReverseMapping(t *testing.T) {
	for _, timeout := range []time.Duration{0, 75 * time.Millisecond} {
		r, _ := onDemandNetworkRouter(t, false, "", mDNS.RcodeSuccess)
		recorder := &legacyLookupRecorder{reverse: "reverse.example"}
		r.dns = recorder
		metadata := onDemandMetadata()
		metadata.Destination = M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 443}
		metadata.LegacyInboundOptions = option.InboundOptions{SniffEnabled: true, SniffTimeout: badoption.Duration(timeout)}
		conn := &legacyDeadlineConn{Conn: legacySniffInput(t, false)}
		before := time.Now()
		_, _, buffers, _, err := r.matchRule(r.ctx, &metadata, conn, nil)
		defer buf.ReleaseMulti(buffers)
		require.NoError(t, err)
		expected := timeout
		if expected == 0 {
			expected = 500 * time.Millisecond
		}
		require.WithinDuration(t, before.Add(expected), conn.firstDeadline, 100*time.Millisecond)
		require.Equal(t, "sniff.example", metadata.Domain, "sniff result takes priority over reverse mapping")
	}
}

func TestLegacyJSONRPCOriginalPredicate(t *testing.T) {
	for _, test := range []struct {
		payload string
		matches bool
	}{
		{`{"jsonrpc":"2.0","method":"call","params":[]}`, true},
		{`{"method":"call","id":1}`, true},
		{`not-json { : "method" "id"`, true},
		{`{"method":"call","params":[]}`, false},
		{`{"jsonrpc":"2.0","id":1}`, false},
		{`{"method":"x","id":`, false},
	} {
		var metadata adapter.InboundContext
		err := legacyJSONRPC(context.Background(), &metadata, bytes.NewBufferString(test.payload))
		require.Equal(t, test.matches, err == nil, test.payload)
		if test.matches {
			require.Equal(t, "jsonrpc", metadata.Protocol)
		}
	}
}

type legacyMappedFakeIPStore struct{ adapter.FakeIPStore }

func (*legacyMappedFakeIPStore) Contains(address netip.Addr) bool {
	return address == netip.MustParseAddr("198.18.0.3")
}
func (*legacyMappedFakeIPStore) Lookup(netip.Addr) (string, bool) { return "mapped.example", true }

type legacyMappedFakeIPTransport struct{ adapter.FakeIPTransport }

func (*legacyMappedFakeIPTransport) Store() adapter.FakeIPStore { return new(legacyMappedFakeIPStore) }

type legacyMappedFakeIPManager struct{ adapter.DNSTransportManager }

func (*legacyMappedFakeIPManager) FakeIP() adapter.FakeIPTransport {
	return new(legacyMappedFakeIPTransport)
}

func TestLegacyInboundFakeIPMappingPrecedesSniffAndLookup(t *testing.T) {
	r, _ := onDemandNetworkRouter(t, true, "192.0.2.10", mDNS.RcodeSuccess)
	r.dnsTransport = new(legacyMappedFakeIPManager)
	recorder := &legacyLookupRecorder{address: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
	r.dns = recorder
	metadata := onDemandMetadata()
	metadata.Destination = M.Socksaddr{Addr: netip.MustParseAddr("198.18.0.3"), Port: 443}
	original := metadata.Destination
	metadata.LegacyInboundOptions = option.InboundOptions{
		SniffEnabled: true, SniffOverrideDestination: true,
		DomainStrategy: option.DomainStrategy(C.DomainStrategyIPv4Only),
	}
	_, _, buffers, _, err := r.matchRule(r.ctx, &metadata, legacySniffInput(t, true), nil)
	defer buf.ReleaseMulti(buffers)
	require.NoError(t, err)
	require.True(t, metadata.FakeIP)
	require.Equal(t, original, metadata.OriginDestination)
	require.Equal(t, "mapped.example", metadata.Destination.Fqdn)
	require.Equal(t, "sniff.example", metadata.Domain)
	require.Equal(t, "mapped.example", recorder.domain)
	require.Equal(t, 1, recorder.calls)
}

func TestLegacyInboundPreMatchDefersTCPOnly(t *testing.T) {
	r, _ := onDemandNetworkRouter(t, false, "", mDNS.RcodeSuccess)
	for _, options := range []option.InboundOptions{
		{SniffEnabled: true}, {DomainStrategy: option.DomainStrategy(C.DomainStrategyIPv4Only)},
	} {
		metadata := onDemandMetadata()
		metadata.LegacyInboundOptions = options
		require.Equal(t, adapter.PreMatchContinue, r.PreMatch(metadata, nil).Action)
		metadata.Network = N.NetworkUDP
		require.Equal(t, adapter.PreMatchReject, r.PreMatch(metadata, nil).Action)
	}
}
