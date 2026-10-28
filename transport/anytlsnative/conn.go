// Author: lyt. Date: 2026-10-29.
package anytlsnative

import (
	"net"
	"sync"
	"time"
)

// Conn serializes each direction independently; a record or I/O failure closes
// the underlying stream and permanently terminates both directions.
type Conn struct {
	underlying net.Conn
	readMu     sync.Mutex
	writeMu    sync.Mutex
	stateMu    sync.Mutex
	terminal   error
	closeOnce  sync.Once
	closeErr   error
	reader     recordState
	writer     recordState
	padding    paddingBudget
	buffer     []byte
}

func newConn(raw net.Conn, reader, writer recordState, padding PaddingOptions) *Conn {
	return &Conn{underlying: raw, reader: reader, writer: writer,
		padding: paddingBudget{options: padding}}
}

func (c *Conn) failure() error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.terminal
}

func (c *Conn) fail(err error) error {
	c.stateMu.Lock()
	if c.terminal == nil {
		c.terminal = err
	}
	result := c.terminal
	c.stateMu.Unlock()
	c.closeOnce.Do(func() { c.closeErr = c.underlying.Close() })
	return result
}

func (c *Conn) Read(data []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := c.failure(); err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	for len(c.buffer) == 0 {
		payload, _, err := c.reader.read(c.underlying, nil)
		if err != nil {
			return 0, c.fail(err)
		}
		c.buffer = payload
	}
	n := copy(data, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}

func (c *Conn) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.failure(); err != nil {
		return 0, err
	}
	total := 0
	for len(data) > 0 {
		size := min(len(data), MaxPayload)
		padding, err := c.padding.next(size)
		if err != nil {
			return total, c.fail(err)
		}
		wire, err := c.writer.seal(data[:size], nil, padding)
		if err == nil {
			err = writeAll(c.underlying, wire)
		}
		if err != nil {
			return total, c.fail(err)
		}
		total += size
		data = data[size:]
	}
	return total, nil
}

func (c *Conn) Close() error {
	c.fail(net.ErrClosed)
	return c.closeErr
}

func (c *Conn) LocalAddr() net.Addr                { return c.underlying.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.underlying.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.underlying.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.underlying.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.underlying.SetWriteDeadline(t) }

var _ net.Conn = (*Conn)(nil)
