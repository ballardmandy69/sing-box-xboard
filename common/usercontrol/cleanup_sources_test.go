package usercontrol

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type sourcedFixture struct {
	fixtureConn
	source string
}

func (c *sourcedFixture) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(c.source), 1234))
}

func TestSourceSnapshotDeduplicatesKeysAndKeepsOriginalSource(t *testing.T) {
	cleaner := newCleaner(t)
	raw := &sourcedFixture{source: "::ffff:192.0.2.1"}
	inner := cleaner.TrackAcceptedConnection(raw, netip.MustParseAddr(raw.source))
	outer := cleaner.TrackConnection(inner)
	outer.Write([]byte("abc"))
	outer.Read(make([]byte, 2))
	snapshot := cleaner.SourceSnapshot()
	if len(snapshot) != 1 || snapshot[0].Count != 1 || snapshot[0].Traffic != 5 ||
		snapshot[0].SourceIP != "192.0.2.1" {
		t.Fatalf("nested replacement double counted or lost source/counter: %+v", snapshot)
	}
	// Distinct logical closer keys are registered too; the source alone never deduplicates them.
	logical := cleaner.TrackConnection(&sourcedFixture{source: "192.0.2.1"})
	defer logical.Close()
	if snapshot = cleaner.SourceSnapshot(); snapshot[0].Count != 2 {
		t.Fatalf("distinct logical key was filtered out: %+v", snapshot)
	}
	// A stale inner removal cannot unregister its current outer replacement.
	cleaner.remove(inner.(*cleanupConn))
	if len(cleaner.entries) != 2 {
		t.Fatal("stale removal deleted the outer registration")
	}
	if n := cleaner.CloseSources([]string{"192.0.2.1"}); n != 2 {
		t.Fatalf("closed %d registrations, want 2", n)
	}
	if len(cleaner.SourceSnapshot()) != 0 || raw.closed.Load() != 1 {
		t.Fatal("source close failed to remove/close the outer chain exactly once")
	}
}

func TestSourceSnapshotOrderingAndUnknownSource(t *testing.T) {
	cleaner := newCleaner(t)
	for _, source := range []string{"2001:db8::1", "192.0.2.2", "192.0.2.10", "192.0.2.3", "192.0.2.3"} {
		conn := cleaner.TrackConnection(&sourcedFixture{source: source})
		defer conn.Close()
		if source == "2001:db8::1" {
			conn.Write([]byte("more"))
		}
	}
	unknown := cleaner.trackConnection(&fixtureConn{}, "")
	defer unknown.Close()
	snapshot := cleaner.SourceSnapshot()
	want := []string{"192.0.2.3", "2001:db8::1", "192.0.2.10", "192.0.2.2"}
	if len(snapshot) != len(want) {
		t.Fatalf("unknown source entered pressure candidates: %+v", snapshot)
	}
	for index, source := range want {
		if snapshot[index].SourceIP != source {
			t.Fatalf("count/traffic/text ordering differs: %+v", snapshot)
		}
	}
	cleaner.CloseSources([]string{"2001:db8::1"})
	if len(cleaner.SourceSnapshot()) != 3 {
		t.Fatal("source close affected unrelated connections")
	}
}

func TestSourceRegistryConcurrentSnapshotAndClose(t *testing.T) {
	cleaner := newCleaner(t)
	var workers sync.WaitGroup
	for range 10 {
		workers.Go(func() {
			for range 50 {
				conn := cleaner.TrackConnection(&sourcedFixture{source: "192.0.2.1"})
				conn.Write([]byte("x"))
				cleaner.SourceSnapshot()
				cleaner.CloseSources([]string{"192.0.2.1"})
				conn.Close()
			}
		})
	}
	workers.Wait()
	if len(cleaner.SourceSnapshot()) != 0 {
		t.Fatal("concurrent registration leaked entries")
	}
}

func TestRoutedRegistrationIncludesUnmanagedAuthenticatedStreams(t *testing.T) {
	cleaner := newCleaner(t)
	metadata := adapter.InboundContext{User: "user-a", Source: M.ParseSocksaddr("198.51.100.1:1234")}
	raw := &sourcedFixture{source: "192.0.2.1"}
	accepted := cleaner.TrackAcceptedConnection(raw, netip.MustParseAddr("192.0.2.1"))
	routed := cleaner.RoutedConnection(context.Background(), accepted, metadata, nil, nil)
	defer routed.Close()
	routed.Write([]byte("data"))
	entries := cleaner.SnapshotRegistrations()
	if len(entries) != 1 || entries[0].UserLabel != "user-a" || entries[0].Traffic != 4 ||
		entries[0].SourceIP != "198.51.100.1" {
		t.Fatalf("routed wrapper lost key deduplication/metadata/counter: %+v", entries)
	}
	logical := cleaner.RoutedConnection(context.Background(), &fixtureConn{}, metadata, nil, nil)
	defer logical.Close()
	if entries = cleaner.SnapshotRegistrations(); len(entries) != 2 {
		t.Fatal("unmanaged authenticated logical stream was omitted")
	}
	anonymous := &fixtureConn{}
	if got := cleaner.RoutedConnection(context.Background(), anonymous, adapter.InboundContext{}, nil, nil); got != anonymous || len(cleaner.SnapshotRegistrations()) != 2 {
		t.Fatal("anonymous unregistered stream was wrapped without original user-label predicate")
	}
	value := cleanupValueConn{fixtureConn: &fixtureConn{}}
	nonComparable := cleaner.RoutedConnection(context.Background(), value, metadata, nil, nil)
	defer nonComparable.Close()
}

func TestRoutedInvalidSourceReplacesOldAddressWithAddrString(t *testing.T) {
	cleaner := newCleaner(t)
	conn := cleaner.TrackAcceptedConnection(&fixtureConn{}, netip.MustParseAddr("192.0.2.1"))
	defer conn.Close()
	cleaner.RoutedConnection(context.Background(), conn, adapter.InboundContext{}, nil, nil)
	snapshot := cleaner.SourceSnapshot()
	if len(snapshot) != 1 || snapshot[0].SourceIP != "invalid IP" {
		t.Fatalf("invalid metadata was retained or dropped instead of Addr.String: %+v", snapshot)
	}
}
