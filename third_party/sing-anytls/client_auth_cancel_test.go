package anytls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type authenticationWriteObserver struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *authenticationWriteObserver) Write(data []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(data)
}

func TestBlockedAuthenticationWriteCancellation(t *testing.T) {
	for _, mode := range []string{"context", "client-close", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			observed := &authenticationWriteObserver{Conn: a, entered: make(chan struct{})}
			config := ClientConfig{Password: "test-password", Logger: logger.NOP(), DisablePadding: true,
				DialOut: func(context.Context) (net.Conn, error) { return observed, nil }}
			if mode == "timeout" {
				config.AuthenticationTimeout = 20 * time.Millisecond
			}
			client, err := NewClient(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := client.CreateProxy(ctx, M.ParseSocksaddr("example.com:443")); result <- err }()
			select {
			case <-observed.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("authentication not started")
			}
			switch mode {
			case "context":
				cancel()
			case "client-close":
				client.Close()
			}
			select {
			case err = <-result:
				want := context.Canceled
				if mode == "timeout" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Fatalf("authentication cancellation: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("authentication write stayed blocked")
			}
		})
	}
}

func TestSuccessfulAuthenticationDetachesCancellation(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	client, err := NewClient(context.Background(), ClientConfig{Password: "test-password", Logger: logger.NOP(), DisablePadding: true,
		AuthenticationTimeout: time.Second, DialOut: func(context.Context) (net.Conn, error) { return a, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer := make(chan error, 1)
	go func() { header := make([]byte, 34); _, err := io.ReadFull(b, header); peer <- err }()
	conn, err := client.createOutboundConnection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-peer; err != nil {
		t.Fatal(err)
	}
	cancel()
	go func() { _, err := b.Write([]byte("alive")); peer <- err }()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var received [5]byte
	if _, err = io.ReadFull(conn, received[:]); err != nil || string(received[:]) != "alive" {
		t.Fatalf("successful conn closed by old context: %v", err)
	}
	if err = <-peer; err != nil {
		t.Fatal(err)
	}
}

func TestNegativeAuthenticationTimeoutRejected(t *testing.T) {
	if _, err := NewClient(context.Background(), ClientConfig{AuthenticationTimeout: -time.Second}); err == nil {
		t.Fatal("negative auth timeout accepted")
	}
}
