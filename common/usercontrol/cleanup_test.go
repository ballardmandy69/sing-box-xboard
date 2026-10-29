package usercontrol

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

func newCleaner(t *testing.T) *ConnectionCleaner {
	t.Helper()
	cleaner, err := NewConnectionCleaner(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleaner.Close() })
	return cleaner
}

func TestCleanupSnapshotsCountBothDirections(t *testing.T) {
	c := newCleaner(t)
	c.SetLogger(log.NewNOPFactory().NewLogger("test"))
	raw := &fixtureConn{}
	conn := c.TrackConnection(raw).(*cleanupConn)
	if conn.Upstream() != raw || conn.ReaderReplaceable() || conn.WriterReplaceable() {
		t.Fatal("optimized copies could bypass activity accounting")
	}
	// Each explicit sweep is one clock tick; no wall-clock sleeps determine these assertions.
	c.sweep()
	if raw.closed.Load() != 0 {
		t.Fatal("the first snapshot closed a newly registered stream")
	}
	conn.Read(make([]byte, 2))
	c.sweep()
	conn.Write([]byte("abc"))
	c.sweep()
	if conn.activity.Load() != 5 || raw.closed.Load() != 0 {
		t.Fatal("either upload or download failed to keep the stream active")
	}
	c.sweep()
	conn.Close()
	if raw.closed.Load() != 1 || len(c.entries) != 0 || len(c.previous) != 0 {
		t.Fatal("idle close did not unregister exactly once")
	}
}

func TestCleanupUsesOuterCloserAndReleasesAdmission(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "cancelled"}[cancelled], func(t *testing.T) {
			c := newCleaner(t)
			manager := NewManager(nil)
			manager.SetConnectionCleaner(c)
			update(t, manager, map[string]Limits{"a": {ConnectionLimit: 1, IPLimit: 1}})
			server, client := net.Pipe()
			t.Cleanup(func() { client.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tracked, err := adapter.TrackConnection(ctx, manager, server, testMetadata("a", "192.0.2.1"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { tracked.Close() })
			c.sweep()
			written := make(chan error, 1)
			go func() { _, err := client.Write([]byte("ping")); written <- err }()
			if _, err := io.ReadFull(tracked, make([]byte, 4)); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			c.sweep()
			if manager.ActiveConnections("a") != 1 {
				t.Fatal("active traffic lost admission")
			}
			if cancelled {
				cancel()
			} else {
				c.sweep()
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("real stream was not closed: %v", err)
			}
			// Close waits for an in-progress cancellation callback's once-protected cleanup.
			tracked.Close()
			if manager.ActiveConnections("a") != 0 || len(manager.OnlineIPs()) != 0 || len(c.entries) != 0 {
				t.Fatal("cleanup bypassed the admission wrapper")
			}
		})
	}
}

func TestCleanupNestedRegistrationAndOldUnregister(t *testing.T) {
	c := newCleaner(t)
	raw := &fixtureConn{}
	inner := c.TrackConnection(raw).(*cleanupConn)
	outer := c.TrackConnection(inner).(*cleanupConn)
	if len(c.entries) != 1 || c.entries[raw] != outer {
		t.Fatal("nested wrappers registered the underlying stream twice")
	}
	c.sweep()
	outer.Write([]byte("x"))
	c.sweep()
	if raw.closed.Load() != 0 {
		t.Fatal("nested wrapper activity was lost")
	}
	// A stale wrapper may not unregister a more recent registration for the same key.
	c.remove(inner)
	if c.entries[raw] != outer {
		t.Fatal("stale removal deleted the newest record")
	}
	c.sweep()
	if raw.closed.Load() != 1 || len(c.entries) != 0 {
		t.Fatal("cleanup did not close the outer wrapper chain once")
	}
	removed := c.TrackConnection(&fixtureConn{})
	c.sweep()
	removed.Close()
	c.sweep()
	if len(c.previous) != 0 {
		t.Fatal("a normally closed stream remained in the next snapshot")
	}
}

type cleanupForceConn struct {
	fixtureConn
	forced atomic.Bool
}

func (c *cleanupForceConn) ForceClose() { c.forced.Store(true) }
func (c *cleanupForceConn) Close() error {
	if !c.forced.Load() {
		return errors.New("ForceClose must precede Close")
	}
	return c.fixtureConn.Close()
}

type cleanupNetConn struct{ net.Conn }

func (c *cleanupNetConn) NetConn() net.Conn { return c.Conn }

type cleanupUpstreamConn struct {
	net.Conn
	value any
}

func (c *cleanupUpstreamConn) Upstream() any { return c.value }

type cleanupCyclicConn struct{ fixtureConn }

func (c *cleanupCyclicConn) Upstream() any { return c }

type cleanupValueConn struct {
	*fixtureConn
	uncomparable []byte
}

func TestCleanupUnwrapAndForceClose(t *testing.T) {
	c := newCleaner(t)
	raw := &cleanupForceConn{}
	wrapped := &cleanupUpstreamConn{Conn: raw, value: &cleanupNetConn{Conn: raw}}
	conn := c.TrackConnection(wrapped)
	if c.entries[raw] == nil {
		t.Fatal("Upstream and NetConn unwrapping did not reach the shared key")
	}
	c.sweep()
	c.sweep()
	if !raw.forced.Load() || raw.closed.Load() != 1 {
		t.Fatal("ForceClose was not dispatched before closing the outer wrapper")
	}
	conn.Close()
	for _, input := range []io.Closer{
		&cleanupUpstreamConn{Conn: raw, value: "invalid"}, &cleanupNetConn{},
	} {
		if next, ok := unwrapCloser(input); ok || next != nil {
			t.Fatal("invalid upstream was treated as a closer")
		}
	}
	cyclic := &cleanupCyclicConn{}
	if connectionKey(cyclic) != cyclic {
		t.Fatal("cyclic upstream traversal did not terminate at its depth limit")
	}
	forceClose(cyclic)
	value := cleanupValueConn{fixtureConn: &fixtureConn{}}
	tracked := c.TrackConnection(value).(*cleanupConn)
	if c.entries[tracked] != tracked {
		t.Fatal("non-comparable upstream did not receive a stable registration key")
	}
	tracked.Close()
}

type cleanupPartialConn struct{ fixtureConn }

func (c *cleanupPartialConn) Read(p []byte) (int, error) { return copy(p, "x"), io.EOF }
func (c *cleanupPartialConn) Write(p []byte) (int, error) {
	return min(1, len(p)), io.ErrUnexpectedEOF
}

func TestCleanupCountsPartialIOAndIgnoresZero(t *testing.T) {
	c := newCleaner(t)
	conn := c.TrackConnection(&cleanupPartialConn{}).(*cleanupConn)
	conn.Read(make([]byte, 3))
	conn.Write([]byte("abc"))
	conn.Read(nil)
	conn.Write(nil)
	if conn.activity.Load() != 2 {
		t.Fatal("partial I/O with an error was not counted exactly")
	}
	conn.Close()
}

func TestCleanupLifecycleAndConcurrentRegistration(t *testing.T) {
	if _, err := NewConnectionCleaner(-1); err == nil {
		t.Fatal("negative duration must not create a busy cleanup loop")
	}
	c := newCleaner(t)
	if c.interval != DefaultConnectionCleanupInterval {
		t.Fatal("zero interval did not select the original default")
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			conn := c.TrackConnection(&fixtureConn{})
			conn.Write([]byte("a"))
			c.sweep()
			conn.Close()
		})
	}
	workers.Wait()
	c.Close()
	c.Close()
	if !errors.Is(c.Start(), net.ErrClosed) {
		t.Fatal("a closed cleaner restarted")
	}
	c.sweep()
	conn := c.TrackConnection(&fixtureConn{})
	if len(c.entries) != 0 {
		t.Fatal("closed cleaner retained a newly tracked connection")
	}
	conn.Close()
}

type cleanupNotifyConn struct {
	fixtureConn
	notify chan struct{}
}

func (c *cleanupNotifyConn) Close() error {
	close(c.notify)
	return c.fixtureConn.Close()
}

func TestCleanupWorkerTicksAndStops(t *testing.T) {
	c, err := NewConnectionCleaner(time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	raw := &cleanupNotifyConn{notify: make(chan struct{})}
	tracked := c.TrackConnection(raw)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-raw.notify:
	case <-time.After(time.Second):
		t.Fatal("background snapshot worker never closed an idle connection")
	}
	tracked.Close()
	c.Close()
}

func TestRemovedUserRetainsStreamButUsesOneByteBuckets(t *testing.T) {
	manager := NewManager(nil)
	limits := map[string]Limits{"a": {ConnectionLimit: 2}}
	update(t, manager, limits)
	server, client := net.Pipe()
	t.Cleanup(func() { client.Close() })
	tracked, err := adapter.TrackConnection(context.Background(), manager, server, testMetadata("a", "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tracked.Close() })
	state := manager.cache["a"]
	upload, download := state.upload, state.download
	update(t, manager, nil)
	if state.upload != upload || state.download != download || manager.ActiveConnections("a") != 1 {
		t.Fatal("removing a user replaced its buckets or tore down a live stream")
	}
	if upload.chunk(100) != 1 || download.chunk(100) != 1 ||
		upload.limiter.Limit() != 1 || download.limiter.Limit() != 1 {
		t.Fatal("removed users were not limited to one byte per second in each direction")
	}
	finished := make(chan error, 1)
	go func() { _, err := tracked.Write([]byte("ab")); finished <- err }()
	client.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := io.ReadFull(client, buffer); err != nil || string(buffer) != "a" {
		t.Fatalf("removed user's existing stream could not deliver its one-byte burst: %v", err)
	}
	// Re-adding restores the same objects and wakes a pending reservation without a clock sleep.
	update(t, manager, limits)
	if manager.cache["a"] != state || upload.chunk(100) != 100 || download.chunk(100) != 100 {
		t.Fatal("re-adding did not restore the same cached state")
	}
	if _, err := io.ReadFull(client, buffer); err != nil || string(buffer) != "b" {
		t.Fatalf("restored stream did not resume: %v", err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	tracked.Close()
	if manager.ActiveConnections("a") != 0 {
		t.Fatal("restored stream did not release its preserved reference")
	}
}
