package session

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/skiplist"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

type Client struct {
	die       context.Context
	dieCancel context.CancelFunc

	dialOut util.DialOutFunc

	sessionCounter atomic.Uint64

	idleSession     *skiplist.SkipList[uint64, *Session]
	idleSessionLock sync.Mutex

	sessions     map[uint64]*Session
	sessionsLock sync.Mutex

	padding *atomic.TypedValue[*padding.PaddingFactory]

	idleSessionTimeout time.Duration
	minIdleSession     int

	logger          logger.Logger
	enhancedPadding bool
	health          HealthOptions
	disablePadding  bool
}

func NewClient(ctx context.Context, logger logger.Logger, dialOut util.DialOutFunc,
	_padding *atomic.TypedValue[*padding.PaddingFactory], idleSessionCheckInterval, idleSessionTimeout time.Duration, minIdleSession int, enhancedPadding ...bool,
) *Client {
	return newClient(ctx, logger, dialOut, _padding, idleSessionCheckInterval,
		idleSessionTimeout, minIdleSession, HealthOptions{}, enhancedPadding...)
}

func NewClientWithHealth(ctx context.Context, logger logger.Logger, dialOut util.DialOutFunc,
	_padding *atomic.TypedValue[*padding.PaddingFactory], idleSessionCheckInterval, idleSessionTimeout time.Duration,
	minIdleSession int, health HealthOptions, enhancedPadding ...bool,
) (*Client, error) {
	if minIdleSession < 0 || health.MaxIdleSessions < 0 || health.IdleThreshold < 0 || health.Timeout < 0 {
		return nil, fmt.Errorf("session health limits and durations must not be negative")
	}
	health = health.normalized()
	if health.Enabled && minIdleSession > health.MaxIdleSessions {
		return nil, fmt.Errorf("min idle sessions must not exceed max idle sessions")
	}
	return newClient(ctx, logger, dialOut, _padding, idleSessionCheckInterval,
		idleSessionTimeout, minIdleSession, health, enhancedPadding...), nil
}

func newClient(ctx context.Context, logger logger.Logger, dialOut util.DialOutFunc,
	_padding *atomic.TypedValue[*padding.PaddingFactory], idleSessionCheckInterval, idleSessionTimeout time.Duration,
	minIdleSession int, health HealthOptions, enhancedPadding ...bool,
) *Client {
	c := &Client{
		sessions:           make(map[uint64]*Session),
		dialOut:            dialOut,
		padding:            _padding,
		idleSessionTimeout: idleSessionTimeout,
		minIdleSession:     minIdleSession,
		logger:             logger,
		enhancedPadding:    len(enhancedPadding) > 0 && enhancedPadding[0],
		health:             health,
		disablePadding:     len(enhancedPadding) > 1 && enhancedPadding[1],
	}
	if idleSessionCheckInterval <= time.Second*5 {
		idleSessionCheckInterval = time.Second * 30
	}
	if c.idleSessionTimeout <= time.Second*5 {
		c.idleSessionTimeout = time.Second * 30
	}
	c.die, c.dieCancel = context.WithCancel(ctx)
	c.idleSession = skiplist.NewSkipList[uint64, *Session]()
	go func() {
		ticker := time.NewTicker(idleSessionCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.die.Done():
				return
			case <-ticker.C:
				c.idleCleanup()
			}
		}
	}()
	return c
}

func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	ctx, cancelDial := context.WithCancel(ctx)
	stop := context.AfterFunc(c.die, cancelDial)
	defer stop()
	defer cancelDial()
	select {
	case <-c.die.Done():
		return nil, io.ErrClosedPipe
	default:
	}

	var session *Session
	var stream *Stream
	var err error

	session = c.getIdleSession()
	for session != nil && session.IsClosed() {
		session = c.getIdleSession()
	}
	if session != nil && c.health.Enabled && time.Since(session.idleSince) >= c.health.IdleThreshold {
		probeCtx, cancel := context.WithTimeout(ctx, c.health.Timeout)
		err = session.checkHealth(probeCtx)
		cancel()
		if err != nil {
			c.logger.Debug("AnyTLS idle session health check failed; replacing connection: ", err)
			session.Close()
			session = nil
		}
	}
	if err = ctx.Err(); err != nil {
		if session != nil {
			session.Close()
		}
		return nil, err
	}
	if session == nil {
		session, err = c.createSession(ctx)
	}
	if session == nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	closeDone := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() {
		session.Close()
		close(closeDone)
	})
	stream, err = session.OpenStream()
	if !stopClose() {
		<-closeDone
	}
	if ctx.Err() != nil {
		session.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to create stream: %w", err)
	}

	stream.setDieHook(func() {
		// If Session is not closed, put this Stream to pool
		if !session.IsClosed() {
			c.returnIdleSession(session)
		}
	})

	return stream, nil
}

func (c *Client) returnIdleSession(session *Session) {
	c.idleSessionLock.Lock()
	select {
	case <-c.die.Done():
		c.idleSessionLock.Unlock()
		session.Close()
		return
	default:
	}
	if session.IsClosed() || (c.health.Enabled && c.idleSession.Len() >= c.health.MaxIdleSessions) {
		c.idleSessionLock.Unlock()
		session.Close()
		return
	}
	session.idleSince = time.Now()
	c.idleSession.Insert(math.MaxUint64-session.seq, session)
	c.idleSessionLock.Unlock()
}

func (c *Client) getIdleSession() (idle *Session) {
	c.idleSessionLock.Lock()
	if !c.idleSession.IsEmpty() {
		it := c.idleSession.Iterate()
		idle = it.Value()
		c.idleSession.Remove(it.Key())
	}
	c.idleSessionLock.Unlock()
	return
}

func (c *Client) createSession(ctx context.Context) (*Session, error) {
	underlying, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		underlying.Close()
		return nil, err
	}

	session := NewClientSession(underlying, c.padding, c.logger, c.enhancedPadding, c.disablePadding)
	session.seq = c.sessionCounter.Add(1)
	session.dieHook = func() {
		c.idleSessionLock.Lock()
		c.idleSession.Remove(math.MaxUint64 - session.seq)
		c.idleSessionLock.Unlock()

		c.sessionsLock.Lock()
		delete(c.sessions, session.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
	select {
	case <-c.die.Done():
		c.sessionsLock.Unlock()
		underlying.Close()
		return nil, io.ErrClosedPipe
	default:
	}
	c.sessions[session.seq] = session
	c.sessionsLock.Unlock()

	session.Run()
	return session, nil
}

func (c *Client) Close() error {
	c.dieCancel()

	c.sessionsLock.Lock()
	sessionToClose := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessionToClose = append(sessionToClose, session)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}

	return nil
}

func (c *Client) idleCleanup() {
	c.idleCleanupExpTime(time.Now().Add(-c.idleSessionTimeout))
}

func (c *Client) idleCleanupExpTime(expTime time.Time) {
	activeCount := 0
	var sessionToClose []*Session

	c.idleSessionLock.Lock()
	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		session := it.Value()
		key := it.Key()
		it.MoveToNext()

		if !session.idleSince.Before(expTime) {
			activeCount++
			continue
		}

		if activeCount < c.minIdleSession {
			// Retention is not activity: health probes must see the real idle age.
			if !c.health.Enabled {
				session.idleSince = time.Now()
			}
			activeCount++
			continue
		}

		sessionToClose = append(sessionToClose, session)
		c.idleSession.Remove(key)
	}
	c.idleSessionLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}
}
