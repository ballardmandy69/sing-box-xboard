package usercontrol

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const DefaultConnectionCleanupInterval = 120 * time.Second

// ConnectionCleaner closes streams whose byte counter is unchanged across two periodic snapshots.
// One instance is shared by accepted TCP sockets and managed streams in a Box.
// Nested registrations share an underlying closer key and retain the most recent outer wrapper.
// @author lyt
// @date 2026-10-29
type ConnectionCleaner struct {
	access   sync.Mutex
	entries  map[io.Closer]*cleanupConn
	interval time.Duration
	logger   logger.Logger
	started  bool
	closed   bool
	stop     chan struct{}
	done     chan struct{}

	sweepAccess sync.Mutex
	previous    map[*cleanupConn]int64
}

func NewConnectionCleaner(interval time.Duration) (*ConnectionCleaner, error) {
	if interval < 0 {
		return nil, fmt.Errorf("connection cleanup interval must not be negative")
	}
	if interval == 0 {
		interval = DefaultConnectionCleanupInterval
	}
	return &ConnectionCleaner{
		entries: make(map[io.Closer]*cleanupConn), interval: interval,
		stop: make(chan struct{}), done: make(chan struct{}),
	}, nil
}

func (c *ConnectionCleaner) SetLogger(logger logger.Logger) {
	c.access.Lock()
	c.logger = logger
	c.access.Unlock()
}

func (c *ConnectionCleaner) Start() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.started {
		return nil
	}
	c.started = true
	go c.run()
	return nil
}

func (c *ConnectionCleaner) run() {
	defer close(c.done)
	timer := time.NewTimer(c.interval)
	defer timer.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-timer.C:
			c.sweep()
			timer.Reset(c.interval)
		}
	}
}

// Close stops collection without forcing live streams closed; their owner manages shutdown.
func (c *ConnectionCleaner) Close() error {
	c.access.Lock()
	if !c.closed {
		c.closed = true
		close(c.stop)
		clear(c.entries)
	}
	started := c.started
	c.access.Unlock()
	if started {
		<-c.done
	}
	c.sweepAccess.Lock()
	c.previous = nil
	c.sweepAccess.Unlock()
	return nil
}

// TrackConnection deduplicates nested wrappers by their underlying closer, retaining the outer one.
func (c *ConnectionCleaner) TrackConnection(conn net.Conn) net.Conn {
	var source string
	if remote := conn.RemoteAddr(); remote != nil {
		source = M.SocksaddrFromNet(remote).Unwrap().Addr.String()
	}
	return c.trackConnection(conn, source)
}

func (c *ConnectionCleaner) trackConnection(conn net.Conn, source string) net.Conn {
	tracked := &cleanupConn{Conn: conn, cleaner: c}
	key := connectionKey(conn)
	if !reflect.TypeOf(key).Comparable() {
		// A non-comparable user supplied connection cannot be a Go map key.
		key = tracked
	}
	tracked.key = key
	tracked.source = source
	c.access.Lock()
	if !c.closed {
		// The original registry replaces the closer/counter while retaining source metadata.
		if previous := c.entries[key]; previous != nil {
			tracked.source = previous.source
			tracked.kind = previous.kind
			tracked.userLabel = previous.userLabel
		}
		c.entries[key] = tracked
	}
	c.access.Unlock()
	return tracked
}

func (c *ConnectionCleaner) remove(conn *cleanupConn) {
	c.access.Lock()
	if c.entries[conn.key] == conn {
		delete(c.entries, conn.key)
	}
	c.access.Unlock()
}

func (c *ConnectionCleaner) sweep() {
	c.sweepAccess.Lock()
	defer c.sweepAccess.Unlock()
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return
	}
	current := make(map[*cleanupConn]int64, len(c.entries))
	for _, conn := range c.entries {
		current[conn] = conn.activity.Load()
	}
	log := c.logger
	c.access.Unlock()
	for conn, before := range c.previous {
		after, exists := current[conn]
		if !exists || after != before {
			continue
		}
		if log != nil {
			log.Debug("close idle proxy connection after unchanged activity snapshots")
		}
		forceClose(conn.Conn)
		conn.Close()
		delete(current, conn)
	}
	c.previous = current
}

func connectionKey(conn io.Closer) io.Closer {
	for range 64 {
		next, exists := unwrapCloser(conn)
		if !exists {
			break
		}
		conn = next
	}
	return conn
}

func unwrapCloser(conn io.Closer) (io.Closer, bool) {
	if upstream, exists := conn.(interface{ Upstream() any }); exists {
		next, valid := upstream.Upstream().(io.Closer)
		return next, valid && next != nil
	}
	if upstream, exists := conn.(interface{ NetConn() net.Conn }); exists {
		next := upstream.NetConn()
		return next, next != nil
	}
	return nil, false
}

func forceClose(conn io.Closer) {
	for range 64 {
		if force, exists := conn.(interface{ ForceClose() }); exists {
			force.ForceClose()
			return
		}
		next, exists := unwrapCloser(conn)
		if !exists {
			return
		}
		conn = next
	}
}

// cleanupConn counts successful bytes even when an I/O operation also returns an error.
// @author lyt
// @date 2026-10-29
type cleanupConn struct {
	net.Conn
	cleaner   *ConnectionCleaner
	key       io.Closer
	source    string
	kind      string
	userLabel string
	activity  atomic.Int64
	closeOnce sync.Once
	closeErr  error
}

func (c *cleanupConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if n > 0 {
		c.activity.Add(int64(n))
	}
	return n, err
}

func (c *cleanupConn) Write(buffer []byte) (int, error) {
	n, err := c.Conn.Write(buffer)
	if n > 0 {
		c.activity.Add(int64(n))
	}
	return n, err
}

func (c *cleanupConn) Close() error {
	c.closeOnce.Do(func() {
		c.cleaner.remove(c)
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *cleanupConn) Upstream() any           { return c.Conn }
func (c *cleanupConn) ReaderReplaceable() bool { return false }
func (c *cleanupConn) WriterReplaceable() bool { return false }
