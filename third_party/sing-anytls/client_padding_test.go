package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
)

func TestAuthenticationPaddingSelection(t *testing.T) {
	standard := padding.NewPaddingFactory(padding.DefaultPaddingScheme)
	for _, test := range []struct {
		name   string
		random byte
		want   int
	}{
		{"minimum", 0, privateAuthPaddingMin},
		{"maximum", 224, privateAuthPaddingMax},
	} {
		t.Run(test.name, func(t *testing.T) {
			size, err := selectAuthenticationPadding(standard, true, bytes.NewReader([]byte{test.random}))
			if err != nil || size != test.want {
				t.Fatalf("size=%d err=%v, want %d", size, err, test.want)
			}
		})
	}
	if _, err := selectAuthenticationPadding(standard, true, bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("entropy failure was not preserved: %v", err)
	}
	for _, test := range []struct {
		name     string
		scheme   []byte
		enhanced bool
		want     int
		invalid  bool
	}{
		{"standard unchanged", padding.DefaultPaddingScheme, false, 30, false},
		{"server scheme respected", []byte("stop=1\n0=42-42"), true, 42, false},
		{"empty scheme record", []byte("stop=0"), true, 0, false},
		{"maximum encoded length", []byte("stop=1\n0=65535-65535"), true, 65535, false},
		{"overflow rejected", []byte("stop=1\n0=65536-65536"), true, 0, true},
		{"check marker rejected", []byte("stop=1\n0=c"), true, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			size, err := selectAuthenticationPadding(padding.NewPaddingFactory(test.scheme), test.enhanced, nil)
			if (err != nil) != test.invalid || !test.invalid && size != test.want {
				t.Fatalf("size=%d err=%v, want size=%d invalid=%v", size, err, test.want, test.invalid)
			}
		})
	}
}

// authenticationWriteConn records authentication writes without running a peer session.
// @author lyt
// @date 2026-10-28
type authenticationWriteConn struct {
	net.Conn
	written []byte
	short   bool
	closed  bool
}

func (c *authenticationWriteConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	if c.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func (c *authenticationWriteConn) Close() error {
	c.closed = true
	return nil
}

func TestClientAuthenticationLengthAndShortWrite(t *testing.T) {
	for _, short := range []bool{false, true} {
		transport := &authenticationWriteConn{short: short}
		hash := sha256.Sum256([]byte("test"))
		client := &Client{
			passwordSha256: hash[:],
			dialOut:        func(context.Context) (net.Conn, error) { return transport, nil },
		}
		padding.UpdatePaddingScheme([]byte("stop=1\n0=65535-65535"), &client.padding)
		conn, err := client.createOutboundConnection(context.Background())
		if short {
			if !errors.Is(err, io.ErrShortWrite) || !transport.closed || conn != nil {
				t.Fatalf("short write: conn=%v err=%v closed=%v", conn, err, transport.closed)
			}
		} else if err != nil || conn != transport || transport.closed {
			t.Fatalf("normal write: conn=%v err=%v closed=%v", conn, err, transport.closed)
		}
		if len(transport.written) != sha256.Size+2+65535 {
			t.Fatalf("authentication length=%d", len(transport.written))
		}
		if !bytes.Equal(transport.written[:sha256.Size], hash[:]) ||
			binary.BigEndian.Uint16(transport.written[sha256.Size:]) != 65535 {
			t.Fatal("standard authentication fields changed")
		}
	}
}

func TestClientRejectsInvalidHealthConfiguration(t *testing.T) {
	for _, health := range []SessionHealthOptions{
		{Enabled: true, Timeout: -time.Second},
		{Enabled: true, IdleThreshold: -time.Second},
		{Enabled: true, MaxIdleSessions: -1},
		{Enabled: true, MaxIdleSessions: 1},
	} {
		client, err := NewClient(context.Background(), ClientConfig{
			Logger: logger.NOP(), MinIdleSession: 2, SessionHealth: &health,
		})
		if err == nil {
			client.Close()
			t.Fatalf("accepted invalid health configuration: %+v", health)
		}
	}
}
