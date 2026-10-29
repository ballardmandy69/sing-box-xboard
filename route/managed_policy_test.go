package route

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func managedPolicyRouter(t *testing.T, r *Router, expression string, node nodepolicy.Node) *nodepolicy.Registry {
	t.Helper()
	policy, err := nodepolicy.NewRegistry(expression, nil)
	require.NoError(t, err)
	require.NoError(t, policy.Register("panel-node", node))
	r.ctx = service.ContextWith[adapter.ManagedNodePolicy](r.ctx, policy)
	return policy
}

func managedPolicyUser(identity string) (nodepolicy.User, bool) {
	return nodepolicy.User{ID: 42, Label: "user-label"}, identity == "panel-identity"
}

func TestManagedPolicyAfterLegacySniffBeforeRulesAndOnDemand(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "tls"}[useTLS], func(t *testing.T) {
			r, queries := onDemandNetworkRouter(t, true, "192.0.2.10", mDNS.RcodeSuccess)
			onDemandRules(t, r, `[{"action":"route-options","override_address":"rewritten.example"}]`)
			var observed adapter.InboundContext
			var reason string
			managedPolicyRouter(t, r, `domain == 'sniff.example' ? protocol : ''`, nodepolicy.Node{
				LookupUser: managedPolicyUser,
				OnBlocked: func(_ context.Context, metadata adapter.InboundContext, uid uint64, value string) {
					require.Equal(t, uint64(42), uid)
					observed, reason = metadata, value
				},
			})
			metadata := onDemandMetadata()
			metadata.Inbound, metadata.User = "panel-node", "panel-identity"
			metadata.Destination = M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.10"), Port: 8443}
			metadata.LegacyInboundOptions = option.InboundOptions{SniffEnabled: true, SniffOverrideDestination: true}
			_, _, buffers, packets, err := r.matchRule(r.ctx, &metadata, legacySniffInput(t, useTLS), nil)
			require.ErrorIs(t, err, adapter.ErrManagedNodePolicyRejected)
			require.True(t, R.IsRejected(err))
			require.Empty(t, buffers, "rejected sniff buffers must be released")
			require.Empty(t, packets)
			require.Equal(t, "sniff.example:8443", observed.Destination.String())
			require.Equal(t, "gfw:"+observed.Protocol, reason)
			require.Zero(t, queries.Load(), "policy must precede ip_on_demand")
			if useTLS {
				require.Equal(t, C.ProtocolTLS, observed.Protocol)
				require.Len(t, observed.TLSFingerprint, 32)
			} else {
				require.Equal(t, C.ProtocolHTTP, observed.Protocol)
				require.Empty(t, observed.TLSFingerprint)
			}
		})
	}
}

func TestManagedPolicyAfterExplicitDomainStrategy(t *testing.T) {
	r, queries := onDemandNetworkRouter(t, true, "192.0.2.10", mDNS.RcodeSuccess)
	var observed adapter.InboundContext
	managedPolicyRouter(t, r, `'deny'`, nodepolicy.Node{LookupUser: managedPolicyUser,
		OnBlocked: func(_ context.Context, metadata adapter.InboundContext, _ uint64, _ string) {
			observed = metadata
		},
	})
	metadata := onDemandMetadata()
	metadata.Inbound, metadata.User = "panel-node", "panel-identity"
	metadata.LegacyInboundOptions.DomainStrategy = option.DomainStrategy(C.DomainStrategyIPv4Only)
	_, _, _, _, err := r.matchRule(r.ctx, &metadata, nil, nil)
	require.ErrorIs(t, err, adapter.ErrManagedNodePolicyRejected)
	require.Equal(t, int32(1), queries.Load())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, observed.DestinationAddresses)
	require.Equal(t, "lookup.example:443", observed.Destination.String())
}

func TestManagedPolicyRunsOnceAcrossOnDemandRetry(t *testing.T) {
	r, queries := onDemandNetworkRouter(t, true, "192.0.2.10", mDNS.RcodeSuccess)
	onDemandRules(t, r, `[{"ip_cidr":"192.0.2.0/24","outbound":"resolved"}]`)
	lookups := 0
	managedPolicyRouter(t, r, "", nodepolicy.Node{LookupUser: func(identity string) (nodepolicy.User, bool) {
		lookups++
		return managedPolicyUser(identity)
	}})
	metadata := onDemandMetadata()
	metadata.Inbound, metadata.User = "panel-node", "panel-identity"
	rule, _, buffers, _, err := r.matchRule(r.ctx, &metadata, nil, nil)
	defer buf.ReleaseMulti(buffers)
	require.NoError(t, err)
	require.Same(t, r.rules[0], rule)
	require.Equal(t, 1, lookups)
	require.Equal(t, int32(1), queries.Load())
}

func TestManagedPreMatchDefersTerminalRulesWithoutEvaluatingPolicy(t *testing.T) {
	r, queries := onDemandNetworkRouter(t, true, "192.0.2.10", mDNS.RcodeSuccess)
	onDemandRules(t, r, `[{"action":"reject"}]`)
	managedPolicyRouter(t, r, "", nodepolicy.Node{LookupUser: func(string) (nodepolicy.User, bool) {
		t.Fatal("PreMatch evaluated managed policy before stream sniffing")
		return nodepolicy.User{}, false
	}})
	metadata := onDemandMetadata()
	metadata.Inbound, metadata.User = "panel-node", "panel-identity"
	require.Equal(t, adapter.PreMatchContinue, r.PreMatch(metadata, nil).Action)
	require.Zero(t, queries.Load())
	metadata.Inbound = "unmanaged"
	require.Equal(t, adapter.PreMatchReject, r.PreMatch(metadata, nil).Action)
}

type managedUnreadableConn struct {
	net.Conn
	t *testing.T
}

func (c *managedUnreadableConn) Read([]byte) (int, error) {
	c.t.Fatal("BlockScanner forced a stream read while legacy sniff was disabled")
	return 0, nil
}

func TestManagedScannerDoesNotForceSniff(t *testing.T) {
	r, queries := onDemandNetworkRouter(t, true, "192.0.2.10", mDNS.RcodeSuccess)
	managedPolicyRouter(t, r, `fingerprint == '' && protocol == '' ? 'no-sniff' : ''`, nodepolicy.Node{
		LookupUser: managedPolicyUser,
	})
	metadata := onDemandMetadata()
	metadata.Inbound, metadata.User = "panel-node", "panel-identity"
	_, _, _, _, err := r.matchRule(r.ctx, &metadata, &managedUnreadableConn{t: t}, nil)
	require.ErrorIs(t, err, adapter.ErrManagedNodePolicyRejected)
	require.Zero(t, queries.Load())
	require.Empty(t, metadata.TLSFingerprint)
}
