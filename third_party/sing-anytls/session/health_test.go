package session

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func healthFixture(t *testing.T, version byte) (*Session, net.Conn) {
	t.Helper()
	local, remote := net.Pipe()
	s := NewClientSession(local, fixturePadding(t), logger.NOP())
	s.sendPadding = false
	s.markHealthPeerVersion(version)
	t.Cleanup(func() { s.Close(); remote.Close() })
	return s, remote
}

func serveHealthFrames(conn net.Conn, reply bool, wrongID bool) {
	defer conn.Close()
	for {
		var header [7]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(header[5:]))); err != nil {
			return
		}
		if reply && header[0] == cmdHeartRequest {
			header[0] = cmdHeartResponse
			if wrongID {
				binary.BigEndian.PutUint32(header[1:5], binary.BigEndian.Uint32(header[1:5])+1000)
			}
			if _, err := conn.Write(header[:]); err != nil {
				return
			}
		}
	}
}

func TestHealthV2EchoConcurrent(t *testing.T) {
	s, remote := healthFixture(t, 2)
	go s.recvLoop()
	go serveHealthFrames(remote, true, false)
	var wait sync.WaitGroup
	for i := 0; i < 24; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := s.checkHealth(ctx); err != nil {
				t.Errorf("healthy peer: %v", err)
			}
		}()
	}
	wait.Wait()
	s.health.access.Lock()
	defer s.health.access.Unlock()
	if len(s.health.pending) != 0 {
		t.Fatal("probe waiters leaked")
	}
}

func TestHealthUnknownAndV1SendNothing(t *testing.T) {
	for _, version := range []byte{0, 1} {
		s, remote := healthFixture(t, version)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := s.checkHealth(ctx); err != nil {
			t.Fatal(err)
		}
		cancel()
		remote.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		var data [1]byte
		if n, err := remote.Read(data[:]); n != 0 || err == nil {
			t.Fatal("heartbeat sent before v2 support confirmed")
		}
	}
}

func TestHealthTimeoutAndWrongResponse(t *testing.T) {
	for _, mode := range []string{"silent", "wrong-response", "blocked-write"} {
		t.Run(mode, func(t *testing.T) {
			s, remote := healthFixture(t, 2)
			go s.recvLoop()
			if mode != "blocked-write" {
				go serveHealthFrames(remote, mode == "wrong-response", true)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			started := time.Now()
			err := s.checkHealth(ctx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected probe timeout, got %v", err)
			}
			if !s.IsClosed() || time.Since(started) > time.Second {
				t.Fatal("timed out connection not closed promptly")
			}
		})
	}
}

func TestHealthCanceledContext(t *testing.T) {
	s, _ := healthFixture(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.checkHealth(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected caller cancellation, got %v", err)
	}
}

func TestClientIdleBoundConcurrent(t *testing.T) {
	c, err := NewClientWithHealth(context.Background(), logger.NOP(), nil, fixturePadding(t),
		time.Minute, time.Minute, 0, HealthOptions{Enabled: true, MaxIdleSessions: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	var sessions []*Session
	for i := 0; i < 50; i++ {
		s, _ := healthFixture(t, 2)
		s.seq = uint64(i + 1)
		sessions = append(sessions, s)
	}
	var wait sync.WaitGroup
	for _, s := range sessions {
		wait.Add(1)
		go func(s *Session) { defer wait.Done(); c.returnIdleSession(s) }(s)
	}
	wait.Wait()
	c.idleSessionLock.Lock()
	count := c.idleSession.Len()
	c.idleSessionLock.Unlock()
	if count != 4 {
		t.Fatalf("idle pool length %d, want 4", count)
	}
	closed := 0
	for _, s := range sessions {
		if s.IsClosed() {
			closed++
		}
	}
	if closed != 46 {
		t.Fatalf("overflow closed %d sessions, want 46", closed)
	}
}

func TestClientEvictsSilentIdleBeforeFreshDial(t *testing.T) {
	var dials atomic.Int32
	c, err := NewClientWithHealth(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		local, remote := net.Pipe()
		go func() { defer remote.Close(); io.Copy(io.Discard, remote) }()
		return local, nil
	}, fixturePadding(t), time.Minute, time.Minute, 0,
		HealthOptions{Enabled: true, IdleThreshold: time.Nanosecond, Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	stale, remote := healthFixture(t, 2)
	stale.seq = 99
	go stale.recvLoop()
	go serveHealthFrames(remote, false, false)
	c.returnIdleSession(stale)
	c.idleSessionLock.Lock()
	stale.idleSince = time.Now().Add(-time.Minute)
	c.idleSessionLock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := c.CreateStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if !stale.IsClosed() || dials.Load() != 1 {
		t.Fatalf("stale closed=%v fresh dials=%d", stale.IsClosed(), dials.Load())
	}
}

func TestHealthOptionsValidation(t *testing.T) {
	for _, options := range []HealthOptions{
		{Enabled: true, MaxIdleSessions: -1},
		{Enabled: true, Timeout: -time.Second},
		{Enabled: true, IdleThreshold: -time.Second},
		{Enabled: true, MaxIdleSessions: 1},
	} {
		c, err := NewClientWithHealth(context.Background(), logger.NOP(), nil, fixturePadding(t),
			time.Minute, time.Minute, 2, options)
		if err == nil {
			c.Close()
			t.Fatal("invalid options accepted")
		}
	}
}

func TestClientParentDeadlinePreventsFreshDial(t *testing.T) {
	var dials atomic.Int32
	c, err := NewClientWithHealth(context.Background(), logger.NOP(), func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected fresh dial")
	}, fixturePadding(t), time.Minute, time.Minute, 0,
		HealthOptions{Enabled: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	stale, remote := healthFixture(t, 2)
	stale.seq = 99
	go stale.recvLoop()
	go serveHealthFrames(remote, false, false)
	c.returnIdleSession(stale)
	c.idleSessionLock.Lock()
	stale.idleSince = time.Now().Add(-time.Minute)
	c.idleSessionLock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = c.CreateStream(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || dials.Load() != 0 {
		t.Fatalf("caller deadline err=%v fresh dials=%d", err, dials.Load())
	}
}

func TestClientFreshIdleReuseDoesNotProbe(t *testing.T) {
	c, err := NewClientWithHealth(context.Background(), logger.NOP(), nil, fixturePadding(t),
		time.Minute, time.Minute, 0, HealthOptions{Enabled: true, IdleThreshold: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s, remote := healthFixture(t, 2)
	s.seq = 1
	var heartbeats atomic.Int32
	go func() {
		defer remote.Close()
		for {
			var header [7]byte
			if _, err := io.ReadFull(remote, header[:]); err != nil {
				return
			}
			if header[0] == cmdHeartRequest {
				heartbeats.Add(1)
			}
			if _, err := io.CopyN(io.Discard, remote, int64(binary.BigEndian.Uint16(header[5:]))); err != nil {
				return
			}
		}
	}()
	c.returnIdleSession(s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := c.CreateStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	if heartbeats.Load() != 0 {
		t.Fatal("recently active session unnecessarily probed")
	}
}

func TestClientParentDeadlineInterruptsBlockedStreamOpen(t *testing.T) {
	c, err := NewClientWithHealth(context.Background(), logger.NOP(), nil, fixturePadding(t),
		time.Minute, time.Minute, 0, HealthOptions{Enabled: true, IdleThreshold: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s, _ := healthFixture(t, 2)
	s.seq = 1
	c.returnIdleSession(s)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = c.CreateStream(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("blocked OpenStream did not honor caller deadline: %v", err)
	}
}

func TestMinimumIdleRetentionDoesNotResetHealthAge(t *testing.T) {
	c, err := NewClientWithHealth(context.Background(), logger.NOP(), nil, fixturePadding(t),
		time.Hour, time.Minute, 1, HealthOptions{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s, _ := healthFixture(t, 2)
	s.seq = 1
	c.returnIdleSession(s)
	old := time.Now().Add(-2 * time.Minute)
	c.idleSessionLock.Lock()
	s.idleSince = old
	c.idleSessionLock.Unlock()
	c.idleCleanup()
	if got := c.getIdleSession(); got != s || !s.idleSince.Equal(old) || s.IsClosed() {
		t.Fatal("retaining minimum idle sessions reset activity or discarded the session")
	}
}
