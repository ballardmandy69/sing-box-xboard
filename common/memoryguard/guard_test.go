package memoryguard

import (
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/usercontrol"
)

type manualClock struct {
	access  sync.Mutex
	now     time.Time
	timers  []*manualTimer
	created chan time.Duration
}

type manualTimer struct {
	clock  *manualClock
	at     time.Time
	active bool
	ch     chan time.Time
}

func newManualClock() *manualClock {
	return &manualClock{now: time.Unix(1000, 0), created: make(chan time.Duration, 256)}
}

func (c *manualClock) Now() time.Time {
	c.access.Lock()
	defer c.access.Unlock()
	return c.now
}

func (c *manualClock) NewTimer(duration time.Duration) timer {
	c.access.Lock()
	t := &manualTimer{clock: c, at: c.now.Add(duration), active: true, ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	c.access.Unlock()
	c.created <- duration
	return t
}

func (c *manualClock) advance(duration time.Duration) {
	c.access.Lock()
	defer c.access.Unlock()
	c.now = c.now.Add(duration)
	for _, t := range c.timers {
		if t.active && !c.now.Before(t.at) {
			t.active = false
			t.ch <- c.now
		}
	}
}

func (t *manualTimer) C() <-chan time.Time { return t.ch }
func (t *manualTimer) Stop() bool {
	t.clock.access.Lock()
	defer t.clock.access.Unlock()
	wasActive := t.active
	t.active = false
	return wasActive
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("worker failed to reach its synchronization point")
		var zero T
		return zero
	}
}

type testConn struct{ closed atomic.Int32 }

func (c *testConn) Read(p []byte) (int, error)       { return len(p), nil }
func (c *testConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *testConn) Close() error                     { c.closed.Add(1); return nil }
func (c *testConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *testConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }

func testGuard(t *testing.T, options Options) (*Guard, *manualClock) {
	t.Helper()
	registry, err := usercontrol.NewConnectionCleaner(0)
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(options, registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	clock := newManualClock()
	g.clock, g.reclaim.clock = clock, clock
	g.reclaim.release = func() {}
	g.jitter = func(interval time.Duration) time.Duration { return interval }
	g.sample = func() (float64, error) { return 10, nil }
	t.Cleanup(func() { g.Close(); registry.Close() })
	return g, clock
}

func addSources(t *testing.T, g *Guard, count int) {
	t.Helper()
	for index := 1; index <= count; index++ {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(index)})
		conn, allowed := g.Accept(&testConn{}, ip)
		if !allowed {
			t.Fatalf("initial source %s rejected", ip)
		}
		t.Cleanup(func() { conn.Close() })
	}
}

func TestOptionsDefaultsDisabledAndValidation(t *testing.T) {
	if guard, err := New(Options{CheckInterval: -1, Steps: []Step{{math.NaN(), -1, -1}}}, nil, nil); err != nil || guard != nil {
		t.Fatalf("disabled guard created service or validated ignored values: %v", err)
	}
	defaults, err := normalize(Options{Enabled: true})
	if err != nil || defaults.CheckInterval != 5*time.Second || defaults.BlockDuration != time.Minute ||
		len(defaults.Steps) != 1 || defaults.Steps[0] != (Step{10, 2, 10}) {
		t.Fatalf("original defaults differ: %+v %v", defaults, err)
	}
	for _, options := range []Options{
		{Enabled: true, CheckInterval: -1}, {Enabled: true, BlockDuration: -1},
		{Enabled: true, CheckInterval: time.Duration(math.MaxInt64)},
		{Enabled: true, Steps: []Step{{0, 1, 1}}}, {Enabled: true, Steps: []Step{{101, 1, 1}}},
		{Enabled: true, Steps: []Step{{10, 2, 1}}}, {Enabled: true, Steps: []Step{{10, 1, 1}, {10, 2, 2}}},
		{Enabled: true, Steps: []Step{{math.NaN(), 1, 1}}},
		{Enabled: true, Steps: []Step{{10, math.Inf(1), 100}}},
	} {
		if _, err := normalize(options); err == nil {
			t.Fatalf("invalid options accepted: %+v", options)
		}
	}
	steps := []Step{{10, 1, 100}, {20, 2, 100}}
	normalized, err := normalize(Options{Enabled: true, Steps: steps})
	if err != nil || normalized.Steps[0].AvailableMemoryPercent != 20 || steps[0].AvailableMemoryPercent != 10 {
		t.Fatal("normalization sorted incorrectly or mutated caller-owned options")
	}
	if _, err := New(Options{Enabled: true}, nil, nil); err == nil {
		t.Fatal("enabled guard accepted a missing registry")
	}
}

func TestMeminfoRealFormatAndErrors(t *testing.T) {
	for _, text := range []string{
		"MemTotal: 1000 kB\nMemAvailable: 100 kB\nCached: nonsense\n",
		"MemAvailable:\t100\nMemTotal: 1000\n",
	} {
		percent, err := availablePercent(strings.NewReader(text))
		if err != nil || percent != 10 {
			t.Fatalf("valid meminfo rejected: %f %v", percent, err)
		}
	}
	for _, text := range []string{
		"", "MemTotal: 100 kB", "MemAvailable: 10 kB", "MemTotal: 0\nMemAvailable: 0",
		"MemTotal: 100\nMemAvailable: 101", "MemTotal: -1\nMemAvailable: 0",
		"MemTotal: 100 MB\nMemAvailable: 10 kB", "MemTotal: 100\nMemAvailable: wrong",
		"MemTotal: 18446744073709551616\nMemAvailable: 1", strings.Repeat("x", 70000),
	} {
		if _, err := availablePercent(strings.NewReader(text)); err == nil {
			t.Fatalf("invalid meminfo accepted: %.80s", text)
		}
	}
	if percent, err := availablePercent(strings.NewReader("MemTotal: 100\nMemAvailable: 0")); err != nil || percent != 0 {
		t.Fatal("zero available memory must trigger pressure rather than a parse error")
	}
}

func TestEpisodeBaseCapsExpiryAndRecovery(t *testing.T) {
	g, clock := testGuard(t, Options{Enabled: true, Steps: []Step{{10, 10, 30}}})
	addSources(t, g, 10)
	if err := g.check(); err != nil || g.base != 10 || len(g.selected) != 1 {
		t.Fatalf("threshold equality/base/ceil failed: base=%d selected=%d err=%v", g.base, len(g.selected), err)
	}
	first := netip.MustParseAddr("192.0.2.1")
	raw := &testConn{}
	if _, allowed := g.Accept(raw, first); allowed || raw.closed.Load() != 1 {
		t.Fatal("blocked source reached a protocol handler")
	}
	clock.advance(time.Minute)
	if g.Blocked(first) {
		t.Fatal("TTL remained active at exact expiry")
	}
	conn, allowed := g.Accept(&testConn{}, first)
	if !allowed {
		t.Fatal("expired source could not reconnect")
	}
	defer conn.Close()
	for range 6 {
		if err := g.check(); err != nil {
			t.Fatal(err)
		}
	}
	if g.base != 10 || len(g.selected) != 3 || g.Blocked(first) {
		t.Fatal("episode base/cap drifted or an expired episode member was selected again")
	}
	g.sample = func() (float64, error) { return 0, errors.New("read failure") }
	if err := g.check(); err == nil || g.base != 10 || len(g.selected) != 3 {
		t.Fatal("sampling failure reset the episode")
	}
	g.sample = func() (float64, error) { return 11, nil }
	if err := g.check(); err != nil || g.base != 0 || len(g.selected) != 0 ||
		!g.Blocked(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("recovery failed to reset episode or prematurely cleared TTL bans")
	}
}

func TestSmallestApplicableStepAndEmptyBase(t *testing.T) {
	g, _ := testGuard(t, Options{Enabled: true, Steps: []Step{{20, 10, 100}, {10, 50, 100}}})
	if err := g.check(); err != nil || g.base != 0 {
		t.Fatal("an empty first snapshot fixed a nonzero episode base")
	}
	addSources(t, g, 10)
	if err := g.check(); err != nil || len(g.selected) != 5 {
		t.Fatalf("did not select only smallest applicable threshold: %d %v", len(g.selected), err)
	}
}

func TestDefaultPercentagesRoundUpAndSkipExistingBans(t *testing.T) {
	g, clock := testGuard(t, Options{Enabled: true})
	addSources(t, g, 3)
	g.blocked["192.0.2.1"] = clock.Now().Add(time.Minute)
	g.blocked["198.51.100.1"] = clock.Now().Add(-time.Second)
	if err := g.check(); err != nil || len(g.selected) != 1 {
		t.Fatal("fractional default quota failed to round upward")
	}
	if _, selected := g.selected["192.0.2.1"]; selected {
		t.Fatal("preexisting global ban consumed the episode quota")
	}
	if _, expired := g.blocked["198.51.100.1"]; expired {
		t.Fatal("post-selection blocked count retained an expired unrelated TTL")
	}
	g.check()
	if len(g.selected) != 1 {
		t.Fatal("rounded maximum cap allowed another episode selection")
	}
}

func TestPressureClosesRealConnectionAndConcurrentAdmission(t *testing.T) {
	g, _ := testGuard(t, Options{Enabled: true, Steps: []Step{{100, 100, 100}}})
	server, client := net.Pipe()
	defer client.Close()
	tracked, allowed := g.Accept(server, netip.MustParseAddr("2001:db8::1"))
	if !allowed {
		t.Fatal("initial connection rejected")
	}
	defer tracked.Close()
	if err := g.check(); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("pressure did not close existing transport: %v", err)
	}
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			for range 20 {
				conn, allowed := g.Accept(&testConn{}, netip.MustParseAddr("2001:db8::1"))
				if allowed {
					conn.Close()
					t.Error("active ban admitted a concurrent connection")
				}
				g.check()
			}
		})
	}
	workers.Wait()
	if len(g.registry.SourceSnapshot()) != 0 {
		t.Fatal("blocked admission left a registered connection")
	}
}

func TestGuardWaitsBeforeFirstCheckAndStops(t *testing.T) {
	g, clock := testGuard(t, Options{Enabled: true})
	checks := make(chan struct{}, 2)
	g.sample = func() (float64, error) { checks <- struct{}{}; return 100, nil }
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	g.Start()
	if duration := receive(t, clock.created); duration != 5*time.Second {
		t.Fatalf("first interval = %s", duration)
	}
	select {
	case <-checks:
		t.Fatal("guard sampled immediately at startup")
	default:
	}
	clock.advance(5 * time.Second)
	receive(t, checks)
	receive(t, clock.created)
	g.Close()
	g.Close()
	if err := g.Start(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed guard restarted")
	}
	other, _ := testGuard(t, Options{Enabled: true})
	other.Close()
	if err := other.Start(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("close-before-start did not terminate the service")
	}
	for range 100 {
		value := jitterInterval(5 * time.Second)
		if value < 4500*time.Millisecond || value > 5500*time.Millisecond {
			t.Fatalf("jitter outside original bounds: %s", value)
		}
	}
	if jitterInterval(time.Nanosecond) != time.Nanosecond {
		t.Fatal("sub-10ns interval gained jitter")
	}
}

func TestAdmissionAndBanRaceLeavesNoLiveBlockedRegistration(t *testing.T) {
	g, _ := testGuard(t, Options{Enabled: true, Steps: []Step{{100, 100, 100}}})
	source := netip.MustParseAddr("192.0.2.1")
	var workers sync.WaitGroup
	connections := make([]*testConn, 100)
	for index := range connections {
		raw := &testConn{}
		connections[index] = raw
		workers.Go(func() {
			g.Accept(raw, source)
			g.check()
		})
	}
	workers.Wait()
	g.check()
	if !g.Blocked(source) || len(g.registry.SourceSnapshot()) != 0 {
		t.Fatal("ban raced with registration and left a live blocked source")
	}
	for _, conn := range connections {
		if conn.closed.Load() != 1 {
			t.Fatal("accepted or rejected socket was not closed exactly once")
		}
	}
}
