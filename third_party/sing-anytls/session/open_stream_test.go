package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// openReplyConn delivers a peer reply before the SYN Write can return, ensuring
// the stream-registration race is exercised without scheduler sleeps.
// @author lyt
// @date 2026-10-28
type openReplyConn struct {
	input    chan []byte
	buffer   bytes.Reader
	done     chan struct{}
	once     sync.Once
	onSYN    func(uint32) error
	writeErr error
}

func (c *openReplyConn) Read(data []byte) (int, error) {
	if c.buffer.Len() > 0 {
		return c.buffer.Read(data)
	}
	select {
	case frame := <-c.input:
		c.buffer.Reset(frame)
		return c.buffer.Read(data)
	case <-c.done:
		return 0, net.ErrClosed
	}
}
func (c *openReplyConn) Write(data []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(data) >= 7 && data[0] == cmdSYN {
		if err := c.onSYN(binary.BigEndian.Uint32(data[1:5])); err != nil {
			return 0, err
		}
	}
	return len(data), nil
}
func (c *openReplyConn) Close() error                   { c.once.Do(func() { close(c.done) }); return nil }
func (*openReplyConn) LocalAddr() net.Addr              { return nil }
func (*openReplyConn) RemoteAddr() net.Addr             { return nil }
func (*openReplyConn) SetDeadline(time.Time) error      { return nil }
func (*openReplyConn) SetReadDeadline(time.Time) error  { return nil }
func (*openReplyConn) SetWriteDeadline(time.Time) error { return nil }

func TestOpenStreamRegistersBeforeImmediatePeerClose(t *testing.T) {
	for _, command := range []byte{cmdFIN, cmdSYNACK} {
		t.Run(map[byte]string{cmdFIN: "FIN", cmdSYNACK: "refused-SYNACK"}[command], func(t *testing.T) {
			conn := &openReplyConn{input: make(chan []byte, 1), done: make(chan struct{})}
			session := NewClientSession(conn, fixturePadding(t), logger.NOP())
			conn.onSYN = func(id uint32) error {
				session.streamLock.RLock()
				stream := session.streams[id]
				session.streamLock.RUnlock()
				if stream == nil {
					return errors.New("SYN was sent before stream registration")
				}
				processed := make(chan struct{})
				stream.setDieHook(func() { close(processed) })
				var data []byte
				if command == cmdSYNACK {
					data = []byte("upstream refused")
				}
				frame := fixtureFrame(command, data)
				binary.BigEndian.PutUint32(frame[1:5], id)
				conn.input <- frame
				select {
				case <-processed:
					return nil
				case <-time.After(2 * time.Second):
					return errors.New("peer close was not processed during SYN Write")
				}
			}
			received := make(chan struct{})
			go func() { _ = session.recvLoop(); close(received) }()
			stream, err := session.OpenStream()
			if err == nil || stream != nil {
				t.Fatalf("stream=%v err=%v", stream, err)
			}
			if command == cmdSYNACK && !strings.Contains(err.Error(), "upstream refused") {
				t.Fatalf("peer rejection lost: %v", err)
			}
			session.streamLock.RLock()
			remaining := len(session.streams)
			session.streamLock.RUnlock()
			if remaining != 0 {
				t.Fatalf("leaked streams=%d", remaining)
			}
			_ = session.Close()
			select {
			case <-received:
			case <-time.After(2 * time.Second):
				t.Fatal("receive loop did not exit")
			}
		})
	}
}

func TestOpenStreamFailedSYNRemovesRegisteredStream(t *testing.T) {
	conn := &openReplyConn{done: make(chan struct{}), writeErr: io.ErrUnexpectedEOF}
	session := NewClientSession(conn, fixturePadding(t), logger.NOP())
	stream, err := session.OpenStream()
	if stream != nil || !errors.Is(err, io.ErrUnexpectedEOF) || !session.IsClosed() {
		t.Fatalf("stream=%v err=%v closed=%v", stream, err, session.IsClosed())
	}
	if len(session.streams) != 0 {
		t.Fatalf("leaked streams=%d", len(session.streams))
	}
}
