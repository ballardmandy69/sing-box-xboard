package route

import (
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
)

// cachedConn owns replay bytes while allowing cancellation to close a concurrent network read.
// @author lyt
// @date 2026-10-30
type cachedConn struct {
	net.Conn
	access    sync.Mutex
	buffer    *buf.Buffer
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

func newCachedConn(conn net.Conn, buffer *buf.Buffer) *cachedConn {
	buffer.IncRef()
	return &cachedConn{Conn: conn, buffer: buffer}
}

func (c *cachedConn) Read(p []byte) (int, error) {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return 0, net.ErrClosed
	}
	if c.buffer != nil {
		n, err := c.buffer.Read(p)
		if c.buffer.IsEmpty() {
			c.releaseBuffer()
		}
		if err == nil {
			c.access.Unlock()
			return n, nil
		}
	}
	c.access.Unlock()
	// A blocking network read must not prevent Close from releasing the stream.
	return c.Conn.Read(p)
}

func (c *cachedConn) ReadCached() *buf.Buffer {
	c.access.Lock()
	defer c.access.Unlock()
	buffer := c.buffer
	c.buffer = nil
	if buffer != nil {
		// Ownership moves to the caller; Close must no longer release these bytes.
		buffer.DecRef()
	}
	return buffer
}

func (c *cachedConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		c.access.Lock()
		c.closed = true
		c.releaseBuffer()
		c.access.Unlock()
	})
	return c.closeErr
}

// releaseBuffer requires access to be held and releases only locally owned replay bytes.
func (c *cachedConn) releaseBuffer() {
	if c.buffer != nil {
		c.buffer.DecRef()
		c.buffer.Release()
		c.buffer = nil
	}
}

func (c *cachedConn) ReaderReplaceable() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.buffer == nil
}

func (*cachedConn) WriterReplaceable() bool { return true }
func (c *cachedConn) Upstream() any         { return c.Conn }
