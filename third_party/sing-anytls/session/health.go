package session

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// HealthOptions bounds idle resources and optionally validates stale pooled sessions.
// @author lyt
// @date 2026-10-28
type HealthOptions struct {
	Enabled         bool
	IdleThreshold   time.Duration
	Timeout         time.Duration
	MaxIdleSessions int
}

func (o HealthOptions) normalized() HealthOptions {
	if !o.Enabled {
		return HealthOptions{}
	}
	if o.IdleThreshold <= 0 {
		o.IdleThreshold = 15 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.MaxIdleSessions <= 0 {
		o.MaxIdleSessions = 32
	}
	return o
}

type sessionHealth struct {
	peerVersion atomic.Uint32
	nextID      atomic.Uint32
	access      sync.Mutex
	pending     map[uint32]chan struct{}
}

func (s *Session) markHealthPeerVersion(version byte) {
	s.health.peerVersion.Store(uint32(version))
}

func (s *Session) healthPeerVersion() byte {
	return byte(s.health.peerVersion.Load())
}

func (s *Session) handleHealthResponse(id uint32) {
	s.health.access.Lock()
	if response, ok := s.health.pending[id]; ok {
		delete(s.health.pending, id)
		close(response)
	}
	s.health.access.Unlock()
}

// checkHealth uses existing v2 heartbeat frames, never probing unknown or v1 peers.
func (s *Session) checkHealth(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	if s.health.peerVersion.Load() < 2 {
		return nil
	}
	id := s.health.nextID.Add(1)
	response := make(chan struct{})
	s.health.access.Lock()
	if s.health.pending == nil {
		s.health.pending = make(map[uint32]chan struct{})
	}
	s.health.pending[id] = response
	s.health.access.Unlock()
	defer func() {
		s.health.access.Lock()
		delete(s.health.pending, id)
		s.health.access.Unlock()
	}()

	// A blocked write must also respect the caller's timeout. Closing the session
	// on cancellation releases the network write without leaving a probe goroutine.
	written := make(chan error, 1)
	go func() {
		_, err := s.writeControlFrame(newFrame(cmdHeartRequest, id))
		written <- err
	}()
	for written != nil {
		select {
		case err := <-written:
			if err != nil {
				return err
			}
			written = nil
		case <-ctx.Done():
			s.Close()
			return ctx.Err()
		case <-s.die:
			return io.ErrClosedPipe
		}
	}
	select {
	case <-response:
		return nil
	case <-ctx.Done():
		s.Close()
		return ctx.Err()
	case <-s.die:
		return io.ErrClosedPipe
	}
}
