package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

// fixtureConn is a finite protocol fixture, not evidence of a third-party endpoint.
type fixtureConn struct {
	input   bytes.Reader
	written bytes.Buffer
	short   bool
}

func (c *fixtureConn) Read(data []byte) (int, error) { return c.input.Read(data) }
func (c *fixtureConn) Write(data []byte) (int, error) {
	if c.short {
		return c.written.Write(data[:len(data)-1])
	}
	return c.written.Write(data)
}
func (*fixtureConn) Close() error                     { return nil }
func (*fixtureConn) LocalAddr() net.Addr              { return nil }
func (*fixtureConn) RemoteAddr() net.Addr             { return nil }
func (*fixtureConn) SetDeadline(time.Time) error      { return nil }
func (*fixtureConn) SetReadDeadline(time.Time) error  { return nil }
func (*fixtureConn) SetWriteDeadline(time.Time) error { return nil }

func fixturePadding(t *testing.T) *atomic.TypedValue[*padding.PaddingFactory] {
	t.Helper()
	value := new(atomic.TypedValue[*padding.PaddingFactory])
	if !padding.UpdatePaddingScheme([]byte("stop=0"), value) {
		t.Fatal("invalid test padding")
	}
	return value
}

func fixtureFrame(command byte, data []byte) []byte {
	frame := make([]byte, 7+len(data))
	frame[0] = command
	binary.BigEndian.PutUint16(frame[5:7], uint16(len(data)))
	copy(frame[7:], data)
	return frame
}

func TestEnhancedNegotiationFixtures(t *testing.T) {
	for _, endpoint := range []string{"server", "client"} {
		for _, test := range []struct {
			name, version, extension string
			enabled, want            bool
		}{
			{"both-v2", "2", "1", true, true},
			{"v1", "1", "1", true, false},
			{"bad-version", "invalid", "1", true, false},
			{"missing-capability", "2", "", true, false},
			{"future-capability", "2", "2", true, false},
			{"malicious-capability", "2", "1,unexpected", true, false},
			{"local-disabled", "2", "1", false, false},
		} {
			t.Run(endpoint+"/"+test.name, func(t *testing.T) {
				paddingValue := fixturePadding(t)
				settings := util.StringMap{"v": test.version, "padding-md5": paddingValue.Load().Md5}
				if test.extension != "" {
					settings[enhancedPaddingSetting] = test.extension
				}
				command := byte(cmdSettings)
				if endpoint == "client" {
					command = cmdServerSettings
				}
				conn := &fixtureConn{}
				conn.input.Reset(fixtureFrame(command, settings.ToBytes()))
				var session *Session
				if endpoint == "server" {
					session = NewServerSession(conn, nil, paddingValue, logger.NOP(), test.enabled)
				} else {
					session = NewClientSession(conn, paddingValue, logger.NOP(), test.enabled)
				}
				_ = session.recvLoop()
				if got := session.enhancedReady.Load(); got != test.want {
					t.Fatalf("negotiated=%v want=%v", got, test.want)
				}
			})
		}
	}
}

func TestEnhancedBudgetFixtures(t *testing.T) {
	session := &Session{}
	var payloadBytes uint64
	for index := 0; index < 12000; index++ {
		payloadSize := int(65535)
		if index%3 == 0 {
			payloadSize = 1
		}
		payloadBytes += uint64(payloadSize)
		paddingFrame := session.appendEnhancedPadding(nil, payloadSize)
		if len(paddingFrame) > 256 {
			t.Fatalf("per-write wire budget exceeded: %d", len(paddingFrame))
		}
		if len(paddingFrame) > 0 {
			if paddingFrame[0] != cmdWaste || binary.BigEndian.Uint32(paddingFrame[1:5]) != 0 {
				t.Fatal("nonstandard waste frame")
			}
			if int(binary.BigEndian.Uint16(paddingFrame[5:7])) != len(paddingFrame)-7 {
				t.Fatal("wrong frame length")
			}
		}
		if session.enhancedPaddingBytes > payloadBytes/20 || session.enhancedPaddingBytes > 64*1024 {
			t.Fatal("cumulative wire budget exceeded")
		}
	}
	if session.enhancedPaddingBytes == 0 {
		t.Fatal("no padding generated")
	}
	if session.enhancedDataBytes != 64*1024*20 {
		t.Fatal("business-byte saturation missing")
	}
}

func TestEnhancedDataAndWriteSemanticsFixtures(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-negotiation", true: "negotiated"}[enabled], func(t *testing.T) {
			conn := &fixtureConn{}
			session := NewClientSession(conn, fixturePadding(t), logger.NOP(), true)
			session.enhancedReady.Store(enabled)
			payload := bytes.Repeat([]byte("exact-data"), 1024)
			n, err := session.writeDataFrame(19, payload)
			if err != nil || n != len(payload) {
				t.Fatalf("write returned payload n=%d err=%v", n, err)
			}
			wire := conn.written.Bytes()
			if wire[0] != cmdPSH || binary.BigEndian.Uint32(wire[1:5]) != 19 || int(binary.BigEndian.Uint16(wire[5:7])) != len(payload) {
				t.Fatal("PSH framing changed")
			}
			if !bytes.Equal(wire[7:7+len(payload)], payload) {
				t.Fatal("application payload changed")
			}
			trailer := wire[7+len(payload):]
			if !enabled && len(trailer) != 0 {
				t.Fatal("extension emitted without agreement")
			}
			if enabled && (len(trailer) == 0 || trailer[0] != cmdWaste) {
				t.Fatal("standard waste trailer absent")
			}
		})
	}
	t.Run("short-write", func(t *testing.T) {
		conn := &fixtureConn{short: true}
		session := NewClientSession(conn, fixturePadding(t), logger.NOP(), true)
		session.enhancedReady.Store(true)
		_, err := session.writeDataFrame(1, bytes.Repeat([]byte("data"), 1024))
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write was not surfaced: %v", err)
		}
	})
}
