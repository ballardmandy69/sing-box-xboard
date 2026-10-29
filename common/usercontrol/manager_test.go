package usercontrol

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

// fixtureConn provides immediate I/O so tests isolate admission and token waiting from network delays.
// @author lyt
// @date 2026-10-29
type fixtureConn struct {
	closed atomic.Int32
	wrote  atomic.Int64
}

func (c *fixtureConn) Read(buffer []byte) (int, error) {
	if c.closed.Load() > 0 {
		return 0, net.ErrClosed
	}
	clear(buffer)
	return len(buffer), nil
}
func (c *fixtureConn) Write(buffer []byte) (int, error) {
	if c.closed.Load() > 0 {
		return 0, net.ErrClosed
	}
	c.wrote.Add(int64(len(buffer)))
	return len(buffer), nil
}
func (c *fixtureConn) Close() error                     { c.closed.Add(1); return nil }
func (c *fixtureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fixtureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *fixtureConn) SetDeadline(time.Time) error      { return nil }
func (c *fixtureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fixtureConn) SetWriteDeadline(time.Time) error { return nil }

func testMetadata(user, ip string) adapter.InboundContext {
	return adapter.InboundContext{User: user, Source: M.Socksaddr{Addr: netip.MustParseAddr(ip), Port: 12345}}
}

func track(t *testing.T, manager *Manager, ctx context.Context, user, ip string) net.Conn {
	t.Helper()
	conn, err := adapter.TrackConnection(ctx, manager, &fixtureConn{}, testMetadata(user, ip))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func update(t *testing.T, manager *Manager, users map[string]Limits) {
	t.Helper()
	if err := manager.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionCountsActiveIPsAndLogicalStreams(t *testing.T) {
	m := NewManager(nil)
	update(t, m, map[string]Limits{"a": {IPLimit: 1, ConnectionLimit: 2}, "b": {IPLimit: 1}})
	first := track(t, m, context.Background(), "a", "192.0.2.1")
	second := track(t, m, context.Background(), "a", "::ffff:192.0.2.1")
	raw := &fixtureConn{}
	returned, err := adapter.TrackConnection(context.Background(), m, raw, testMetadata("a", "192.0.2.1"))
	if !errors.Is(err, ErrConnectionLimit) || returned != raw || m.ActiveConnections("a") != 2 {
		t.Fatal("connection limit must precede IP checks and preserve the caller's connection on rejection")
	}
	second.Close()
	if _, err := adapter.TrackConnection(context.Background(), m, raw, testMetadata("a", "192.0.2.2")); !errors.Is(err, ErrIPLimit) {
		t.Fatal("another source IP was accepted while the first remains active")
	}
	track(t, m, context.Background(), "b", "192.0.2.2")
	first.Close()
	first.Close()
	if m.ActiveConnections("a") != 0 {
		t.Fatal("closing an admitted stream twice changed its reference count")
	}
	track(t, m, context.Background(), "a", "192.0.2.2")
	if got := m.OnlineIPs()["a"]; len(got) != 1 || got[0].String() != "192.0.2.2" {
		t.Fatal("online IPs did not follow active source references")
	}
}

func TestAdmissionHotUpdatesAndUserLifecycle(t *testing.T) {
	m := NewManager(nil)
	update(t, m, map[string]Limits{"a": {}})
	first := track(t, m, context.Background(), "a", "192.0.2.1")
	second := track(t, m, context.Background(), "a", "192.0.2.2")
	update(t, m, map[string]Limits{"a": {IPLimit: 1, ConnectionLimit: 1}})
	if _, err := first.Write([]byte("kept")); err != nil || m.ActiveConnections("a") != 2 {
		t.Fatal("lowering thresholds terminated a preexisting stream")
	}
	update(t, m, map[string]Limits{})
	if _, err := adapter.TrackConnection(context.Background(), m, &fixtureConn{}, testMetadata("a", "192.0.2.1")); !errors.Is(err, ErrUnknownUser) {
		t.Fatal("removed user could open a new stream")
	}
	if len(m.OnlineIPs()) != 0 {
		t.Fatal("removed users should not be included in online reports")
	}
	update(t, m, map[string]Limits{"a": {ConnectionLimit: 1}})
	if m.ActiveConnections("a") != 2 {
		t.Fatal("readding a user lost the still-active cached admission state")
	}
	first.Close()
	second.Close()
	track(t, m, context.Background(), "a", "192.0.2.3")
}

func TestAdmissionConcurrentLimitIsShared(t *testing.T) {
	m := NewManager(nil)
	update(t, m, map[string]Limits{"a": {IPLimit: 1, ConnectionLimit: 4}})
	var wait sync.WaitGroup
	admitted := make(chan net.Conn, 32)
	for range 32 {
		wait.Go(func() {
			conn, err := adapter.TrackConnection(context.Background(), m, &fixtureConn{}, testMetadata("a", "192.0.2.1"))
			if err == nil {
				admitted <- conn
			} else if !errors.Is(err, ErrConnectionLimit) {
				t.Errorf("unexpected admission failure: %v", err)
			}
		})
	}
	wait.Wait()
	close(admitted)
	if len(admitted) != 4 || m.ActiveConnections("a") != 4 {
		t.Fatal("parallel streams did not share the same connection budget")
	}
	for conn := range admitted {
		conn.Close()
	}
	if m.ActiveConnections("a") != 0 || len(m.OnlineIPs()) != 0 {
		t.Fatal("parallel cleanup left active IP references")
	}
}

func TestBandwidthSharedPerUserAndIndependentPerDirection(t *testing.T) {
	m := NewManager(nil)
	update(t, m, map[string]Limits{"a": {UploadBytesPerSecond: 1, DownloadBytesPerSecond: 1}})
	first := track(t, m, context.Background(), "a", "192.0.2.1")
	second := track(t, m, context.Background(), "a", "192.0.2.1")
	if _, err := first.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := second.Write([]byte{2}); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("another stream bypassed the user's exhausted download bucket: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := second.Read(make([]byte, 1)); err != nil {
		t.Fatal("upload incorrectly shared the download token budget")
	}
	update(t, m, map[string]Limits{"a": {}})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("disabling the limit did not wake an existing waiter")
	}
	if first.(interface{ ReaderReplaceable() bool }).ReaderReplaceable() ||
		first.(interface{ WriterReplaceable() bool }).WriterReplaceable() {
		t.Fatal("optimized copies may not bypass the stream limiter")
	}
}

func TestBandwidthShrinkDoesNotKillWaitingStream(t *testing.T) {
	m := NewManager(nil)
	update(t, m, map[string]Limits{"a": {DownloadBytesPerSecond: 8}})
	conn := track(t, m, context.Background(), "a", "192.0.2.1")
	if _, err := conn.Write(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Write(make([]byte, 8)); done <- err }()
	time.Sleep(10 * time.Millisecond)
	update(t, m, map[string]Limits{"a": {DownloadBytesPerSecond: 1}})
	select {
	case err := <-done:
		t.Fatalf("changing burst size interrupted or bypassed the old stream: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	update(t, m, map[string]Limits{"a": {}})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting stream did not resume")
	}
}

func TestCancellationReleasesTokensAndAdmission(t *testing.T) {
	for _, closeOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "context", true: "close"}[closeOnly], func(t *testing.T) {
			m := NewManager(nil)
			update(t, m, map[string]Limits{"a": {DownloadBytesPerSecond: 1, ConnectionLimit: 1}})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn := track(t, m, ctx, "a", "192.0.2.1")
			if _, err := conn.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := conn.Write([]byte{2}); done <- err }()
			select {
			case err := <-done:
				t.Fatalf("exhausted bandwidth bucket did not block the second write: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			if closeOnly {
				conn.Close()
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled stream reported success")
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt token waiting")
			}
			deadline := time.Now().Add(time.Second)
			for m.ActiveConnections("a") != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if m.ActiveConnections("a") != 0 {
				t.Fatal("cancelled stream retained admission")
			}
			if _, err := conn.Write([]byte{3}); !errors.Is(err, context.Canceled) {
				t.Fatal("a cancelled stream started another token reservation")
			}
		})
	}
}

func TestInvalidLimitUpdateIsAtomic(t *testing.T) {
	m := NewManager(nil)
	update(t, m, map[string]Limits{"a": {IPLimit: 1}})
	if err := m.UpdateUsers(map[string]Limits{"a": {}, "": {}}); err == nil {
		t.Fatal("empty user accepted")
	}
	if _, err := m.TrackConnectionContext(context.Background(), &fixtureConn{}, adapter.InboundContext{User: "a"}); !errors.Is(err, ErrInvalidSource) {
		t.Fatal("invalid update modified previously valid limits")
	}
	if err := m.UpdateUsers(map[string]Limits{"a": {UploadBytesPerSecond: ^uint64(0)}}); err == nil {
		t.Fatal("overflowing rate accepted")
	}
}

type fixturePacketConn struct{ fixtureConn }

func (c *fixturePacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, net.ErrClosed
}

func (c *fixturePacketConn) WritePacket(*buf.Buffer, M.Socksaddr) error {
	c.wrote.Add(1)
	return nil
}

func TestUDPAndUDPOverTCPRejectedBeforeAdmission(t *testing.T) {
	m := NewManager(nil)
	update(t, m, map[string]Limits{"a": {ConnectionLimit: 1}})
	metadata := testMetadata("a", "192.0.2.1")
	packet := &fixturePacketConn{}
	returned, err := adapter.TrackPacketConnection(context.Background(), m, packet, metadata)
	if !errors.Is(err, ErrUDPDisabled) || returned != packet || packet.wrote.Load() != 0 {
		t.Fatal("packet forwarding did not return the original socket with a rejection")
	}
	for _, domain := range []string{uot.MagicAddress, uot.LegacyMagicAddress, "SP.UDP-OVER-TCP.ARPA."} {
		metadata.Destination = M.Socksaddr{Fqdn: domain, Port: 443}
		raw := &fixtureConn{}
		returned, err := adapter.TrackConnection(context.Background(), m, raw, metadata)
		if !errors.Is(err, ErrUDPDisabled) || returned != raw || m.ActiveConnections("a") != 0 {
			t.Fatalf("UDP-over-TCP destination %q was admitted", domain)
		}
	}
	if len(m.OnlineIPs()) != 0 {
		t.Fatal("rejected UDP streams left online references")
	}
	if m.TrackPacketConnection(packet, metadata) != packet || packet.closed.Load() != 1 {
		t.Fatal("legacy packet tracking did not close the rejected socket")
	}
}

func TestAdmissionCancellationDuringConstruction(t *testing.T) {
	m := NewManager(nil)
	update(t, m, map[string]Limits{"a": {}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.TrackConnection(ctx, m, &fixtureConn{}, testMetadata("a", "192.0.2.1")); !errors.Is(err, context.Canceled) || m.ActiveConnections("a") != 0 {
		t.Fatal("an already cancelled stream acquired admission")
	}
	ctx, cancel = context.WithCancel(context.Background())
	m.now = func() time.Time {
		cancel()
		return time.Now()
	}
	if _, err := adapter.TrackConnection(ctx, m, &fixtureConn{}, testMetadata("a", "192.0.2.1")); !errors.Is(err, context.Canceled) || m.ActiveConnections("a") != 0 {
		t.Fatal("cancellation during admission was not rolled back before returning the stream")
	}
	m.now = time.Now
	var wait sync.WaitGroup
	for range 100 {
		wait.Go(func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go cancel()
			conn, err := adapter.TrackConnection(ctx, m, &fixtureConn{}, testMetadata("a", "192.0.2.1"))
			if err == nil {
				conn.Close()
			} else if !errors.Is(err, context.Canceled) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wait.Wait()
	if m.ActiveConnections("a") != 0 || len(m.OnlineIPs()) != 0 {
		t.Fatal("cancellation while wrapping a stream leaked admission")
	}
}

type accountingTracker struct{ bytes atomic.Int64 }

type accountingConn struct {
	net.Conn
	tracker *accountingTracker
}

func (c *accountingConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.tracker.bytes.Add(int64(n))
	return n, err
}

func (t *accountingTracker) TrackConnection(conn net.Conn, _ adapter.InboundContext) net.Conn {
	return &accountingConn{Conn: conn, tracker: t}
}

func (t *accountingTracker) TrackPacketConnection(conn N.PacketConn, _ adapter.InboundContext) N.PacketConn {
	return conn
}

func TestLegacyTrackingPreservesAccountingAndReleasesAdmission(t *testing.T) {
	base := &accountingTracker{}
	m := NewManager(base)
	update(t, m, map[string]Limits{"a": {}})
	raw := &fixtureConn{}
	conn := m.TrackConnection(raw, testMetadata("a", "192.0.2.1"))
	if _, err := conn.Write(make([]byte, 17)); err != nil || base.bytes.Load() != 17 {
		t.Fatal("user admission wrapper bypassed legacy traffic accounting")
	}
	conn.Close()
	if m.ActiveConnections("a") != 0 || raw.closed.Load() != 1 {
		t.Fatal("accounting wrapper did not propagate close to admission")
	}
	invalid := &fixtureConn{}
	if m.TrackConnection(invalid, testMetadata("missing", "192.0.2.1")) != invalid ||
		invalid.closed.Load() != 1 || m.ActiveConnections("missing") != 0 {
		t.Fatal("legacy rejection did not close the original stream")
	}
}

type partialWriteConn struct {
	fixtureConn
	err error
}

func (c *partialWriteConn) Write(data []byte) (int, error) { return len(data) - 1, c.err }

func TestBandwidthPreservesPartialWriteErrors(t *testing.T) {
	for _, failure := range []error{nil, io.ErrClosedPipe} {
		m := NewManager(nil)
		update(t, m, map[string]Limits{"a": {DownloadBytesPerSecond: 4}})
		raw := &partialWriteConn{err: failure}
		conn, err := adapter.TrackConnection(context.Background(), m, raw, testMetadata("a", "192.0.2.1"))
		if err != nil {
			t.Fatal(err)
		}
		n, err := conn.Write(make([]byte, 8))
		conn.Close()
		wantError := failure
		if wantError == nil {
			wantError = io.ErrShortWrite
		}
		if n != 3 || !errors.Is(err, wantError) {
			t.Fatalf("partial write returned (%d, %v), want (3, %v)", n, err, wantError)
		}
	}
}

func TestBandwidthTokensRefillWhileWaiting(t *testing.T) {
	m := NewManager(nil)
	update(t, m, map[string]Limits{"a": {DownloadBytesPerSecond: 100}})
	conn := track(t, m, context.Background(), "a", "192.0.2.1")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := conn.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Write(make([]byte, 5)); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("bandwidth tokens never refilled")
	}
}

func TestBandwidthBurstShrinkBetweenSizingAndReservation(t *testing.T) {
	gate := newRateGate()
	gate.set(2000)
	readSize := gate.chunk(1005)
	gate.set(1000)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gate.wait(ctx, readSize); err != nil {
		t.Fatalf("an in-flight read larger than the new burst could not be reserved in parts: %v", err)
	}
}
