package usercontrol

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// controlledConn releases admission exactly once and prevents optimized copies bypassing limits.
// @author lyt
// @date 2026-10-29
type controlledConn struct {
	net.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	stop      atomic.Pointer[func() bool]
	state     *userState
	ip        netip.Addr
	closeOnce sync.Once
	closeErr  error
}

func (c *controlledConn) Read(buffer []byte) (int, error) {
	buffer = buffer[:c.state.upload.chunk(len(buffer))]
	n, err := c.Conn.Read(buffer)
	if err == nil && n > 0 {
		err = c.state.upload.wait(c.ctx, n)
	}
	return n, err
}

func (c *controlledConn) Write(buffer []byte) (int, error) {
	written := 0
	for len(buffer) > 0 {
		length := c.state.download.chunk(len(buffer))
		if err := c.state.download.wait(c.ctx, length); err != nil {
			return written, err
		}
		n, err := c.Conn.Write(buffer[:length])
		written += n
		if err != nil {
			return written, err
		}
		if n != length {
			return written, io.ErrShortWrite
		}
		buffer = buffer[length:]
	}
	return written, nil
}

func (c *controlledConn) Close() error {
	c.closeOnce.Do(func() {
		if stop := c.stop.Load(); stop != nil {
			(*stop)()
		}
		c.cancel()
		c.closeErr = c.Conn.Close()
		c.state.release(c.ip)
	})
	return c.closeErr
}

func (c *controlledConn) ReaderReplaceable() bool { return false }
func (c *controlledConn) WriterReplaceable() bool { return false }
func (c *controlledConn) Upstream() any           { return c.Conn }
