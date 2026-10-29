package nodepolicy

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/usercontrol"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func policyMetadata() adapter.InboundContext {
	return adapter.InboundContext{Inbound: "node", User: "internal-id", Network: "tcp", Protocol: "tls",
		Source: M.ParseSocksaddr("[2001:db8::1]:1234"), Destination: M.ParseSocksaddr("dest.example:443"),
		Domain: "sni.example", TLSFingerprint: "test-ja3"}
}

func policyUser(name string) (User, bool) {
	return User{ID: 18446744073709551615, Label: "traffic-label"}, name == "internal-id"
}

func TestScannerTypesAndVariables(t *testing.T) {
	metadata := policyMetadata()
	scanner, err := NewScanner(`source == '[2001:db8::1]:1234' && dest == 'dest.example:443' &&
		fingerprint == 'test-ja3' && protocol == 'tls' && network == 'tcp' && inbound == 'node' &&
		domain == 'sni.example' && uid == 18446744073709551615u ? 'matched' : ''`)
	require.NoError(t, err)
	result, err := scanner.Check(&metadata, metadata.TLSFingerprint, ^uint64(0))
	require.NoError(t, err)
	require.Equal(t, "matched", result)
	for _, expression := range []string{`true`, `uid`, `unknown`, `'unterminated`, `dyn('value')`} {
		_, err = NewScanner(expression)
		require.Error(t, err, expression)
	}
	empty, err := NewScanner(" \t\n")
	require.NoError(t, err)
	require.Nil(t, empty)
	require.Empty(t, empty.MustCheck(nil, "", 0))
}

func TestScannerErrorContinuesNodeRulesAndReportsInOrder(t *testing.T) {
	r, err := NewRegistry(`{'known':'value'}[domain]`, nil)
	require.NoError(t, err)
	metadata := policyMetadata()
	_, err = r.scanner.Check(&metadata, "", 0)
	require.Error(t, err)
	var calls []string
	require.NoError(t, r.Register("node", Node{LookupUser: policyUser,
		Rules: []Rule{{ID: 7, Pattern: `^dest\.example:443$`}, {ID: 8, Pattern: `.*`}},
		OnIllegal: func(uid uint64, id int) {
			require.Equal(t, ^uint64(0), uid)
			require.Equal(t, 7, id)
			calls = append(calls, "illegal")
		},
		OnBlocked: func(_ context.Context, actual adapter.InboundContext, uid uint64, reason string) {
			require.Equal(t, metadata, actual)
			require.Equal(t, ^uint64(0), uid)
			calls = append(calls, reason)
		},
	}))
	require.ErrorIs(t, r.Check(context.Background(), &metadata, nil), adapter.ErrManagedNodePolicyRejected)
	require.Equal(t, []string{"illegal", "audit:7"}, calls)
}

func TestScannerPrecedesAuditAndUnknownManagedUserIsRejected(t *testing.T) {
	r, err := NewRegistry(`'reason'`, nil)
	require.NoError(t, err)
	require.True(t, r.FingerprintEnabled())
	var reasons []string
	require.NoError(t, r.Register("node", Node{LookupUser: policyUser, Rules: []Rule{{Pattern: ".*"}},
		OnIllegal: func(uint64, int) { t.Fatal("CEL block reached node audit") },
		OnBlocked: func(_ context.Context, _ adapter.InboundContext, _ uint64, reason string) {
			reasons = append(reasons, reason)
		},
	}))
	metadata := policyMetadata()
	require.ErrorIs(t, r.Check(context.Background(), &metadata, nil), adapter.ErrManagedNodePolicyRejected)
	require.Equal(t, []string{"gfw:reason"}, reasons)
	metadata.User = "unknown"
	require.ErrorIs(t, r.Check(context.Background(), &metadata, nil), adapter.ErrManagedNodePolicyRejected)
	metadata.User, metadata.Inbound = "internal-id", "other"
	require.NoError(t, r.Check(context.Background(), &metadata, nil))
	require.Len(t, reasons, 1)
	r.Remove("node")
	require.False(t, r.HasNode("node"))
}

func TestAdmittedStreamIsRejectedWhenUserIsRemovedBeforeRouting(t *testing.T) {
	ctx := context.Background()
	metadata := policyMetadata()
	users := map[string]uint64{metadata.User: 7}
	manager := usercontrol.NewManagerWithRequestLimit(nil, 0)
	require.NoError(t, manager.UpdateUsers(map[string]usercontrol.Limits{metadata.User: {}}))
	registry, err := NewRegistry(`'blocked'`, nil)
	require.NoError(t, err)
	require.NoError(t, registry.Register(metadata.Inbound, Node{
		LookupUser: func(name string) (User, bool) {
			id, exists := users[name]
			return User{ID: id, Label: name}, exists
		},
	}))
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	tracked, err := manager.TrackConnectionContext(ctx, server, metadata)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tracked.Close() })

	// Sniffing or DNS can delay routing after admission while a panel refresh
	// revokes this identity. The manager retains the existing connection.
	require.NoError(t, manager.UpdateUsers(map[string]usercontrol.Limits{}))
	delete(users, metadata.User)
	require.ErrorIs(t, registry.Check(ctx, &metadata, tracked), adapter.ErrManagedNodePolicyRejected)

	// Revocation also rejects a fresh admission, but that does not protect the
	// already admitted stream above; the routing gate must check it independently.
	_, err = manager.TrackConnectionContext(ctx, server, metadata)
	require.ErrorIs(t, err, usercontrol.ErrUnknownUser)
	metadata.Inbound = "unmanaged"
	require.NoError(t, registry.Check(ctx, &metadata, tracked))
}

func TestPolicyPublicationIsAtomicAndRetainsOldRulesOnError(t *testing.T) {
	r, err := NewRegistry("", nil)
	require.NoError(t, err)
	require.False(t, r.FingerprintEnabled())
	allowed := Node{LookupUser: policyUser}
	blocked := Node{LookupUser: policyUser, Rules: []Rule{{ID: 3, Pattern: ".*"}}}
	require.NoError(t, r.Register("node", blocked))
	require.Error(t, r.Register("node", Node{LookupUser: policyUser, Rules: []Rule{{Pattern: "["}}}))
	metadata := policyMetadata()
	require.ErrorIs(t, r.Check(context.Background(), &metadata, nil), adapter.ErrManagedNodePolicyRejected)
	require.Error(t, r.Register("", allowed))
	require.Error(t, r.Register("node", Node{}))
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 30 {
				require.NoError(t, r.Register("node", allowed))
				_ = r.Check(context.Background(), &metadata, nil)
				require.NoError(t, r.Register("node", blocked))
				r.HasNode("node")
			}
		})
	}
	workers.Wait()
}

func TestAllowedPolicyUpdatesExistingRegistrationOnly(t *testing.T) {
	cleaner, err := usercontrol.NewConnectionCleaner(time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cleaner.Close() })
	r, err := NewRegistry("", cleaner)
	require.NoError(t, err)
	require.NoError(t, r.Register("node", Node{LookupUser: policyUser}))
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	tracked := cleaner.TrackAcceptedConnection(server, netip.MustParseAddr("192.0.2.1"))
	t.Cleanup(func() { _ = tracked.Close() })
	metadata := policyMetadata()
	require.NoError(t, r.Check(context.Background(), &metadata, tracked))
	entries := cleaner.SnapshotRegistrations()
	require.Len(t, entries, 1)
	require.Equal(t, "tcp-routed", entries[0].Type)
	require.Equal(t, "2001:db8::1", entries[0].SourceIP)
	require.Equal(t, "traffic-label", entries[0].UserLabel)
	unknownClient, unknownServer := net.Pipe()
	defer unknownClient.Close()
	defer unknownServer.Close()
	require.NoError(t, r.Check(context.Background(), &metadata, unknownServer))
	require.Len(t, cleaner.SnapshotRegistrations(), 1)
	require.NoError(t, r.Register("node", Node{LookupUser: policyUser, Rules: []Rule{{Pattern: ".*"}}}))
	metadata.Source = M.ParseSocksaddr("198.51.100.1:42")
	require.ErrorIs(t, r.Check(context.Background(), &metadata, tracked), adapter.ErrManagedNodePolicyRejected)
	require.Equal(t, "2001:db8::1", cleaner.SnapshotRegistrations()[0].SourceIP)
}
