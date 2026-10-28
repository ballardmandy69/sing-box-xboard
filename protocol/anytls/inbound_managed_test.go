package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// managedEchoRouter observes actual streams after authentication and tracker processing.
// @author lyt
// @date 2026-10-29
type managedEchoRouter struct {
	adapter.Router
	calls atomic.Int32
}

func (r *managedEchoRouter) RouteConnectionEx(ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext, onClose N.CloseHandlerFunc,
) {
	r.calls.Add(1)
	_, err := io.Copy(conn, conn)
	conn.Close()
	if onClose != nil {
		onClose(err)
	}
}

type managedUserTraffic struct {
	read  atomic.Int64
	wrote atomic.Int64
	write chan struct{}
}

type managedCountingConn struct {
	net.Conn
	traffic *managedUserTraffic
}

func (c *managedCountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.traffic.read.Add(int64(n))
	return n, err
}

func (c *managedCountingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.traffic.wrote.Add(int64(n))
	select {
	case c.traffic.write <- struct{}{}:
	default:
	}
	return n, err
}

type managedTracker struct {
	users sync.Map
}

func (r *managedTracker) TrackConnection(conn net.Conn, metadata adapter.InboundContext) net.Conn {
	traffic, _ := r.users.LoadOrStore(metadata.User, &managedUserTraffic{write: make(chan struct{}, 1)})
	return &managedCountingConn{Conn: conn, traffic: traffic.(*managedUserTraffic)}
}

func (r *managedTracker) TrackPacketConnection(conn N.PacketConn, _ adapter.InboundContext) N.PacketConn {
	return conn
}

func managedInbound(t *testing.T, users []option.AnyTLSUser) (*Inbound, *managedEchoRouter) {
	t.Helper()
	router := new(managedEchoRouter)
	result, err := NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "public-anytls",
		option.AnyTLSInboundOptions{Users: users})
	if err != nil {
		t.Fatal(err)
	}
	inbound := result.(*Inbound)
	t.Cleanup(func() { inbound.closeConnections() })
	return inbound, router
}

func managedListen(t *testing.T, inbound *Inbound) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				inbound.NewConnection(context.Background(), conn,
					adapter.InboundContext{Source: M.SocksaddrFromNet(conn.RemoteAddr())}, nil)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		managedWait(t, accepted, "accept loop")
		inbound.closeConnections()
		done := make(chan struct{})
		go func() { connections.Wait(); close(done) }()
		managedWait(t, done, "server sessions")
	})
	return listener.Addr().String()
}

func managedClient(t *testing.T, address, password string) (*anytls.Client, *atomic.Int32) {
	t.Helper()
	dials := new(atomic.Int32)
	client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: password, Logger: log.NewNOPFactory().Logger(), AuthenticationTimeout: 2 * time.Second,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, dials
}

func managedExchange(client *anytls.Client, payload string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.CreateProxy(ctx, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write([]byte(payload)); err != nil {
		return err
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		return err
	}
	if string(response) != payload {
		return errors.New("echo payload differs")
	}
	return nil
}

func managedWait(t *testing.T, done <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func TestManagedAnyTLSUsersAndSessionRevocation(t *testing.T) {
	for _, changePassword := range []bool{false, true} {
		name := "delete"
		if changePassword {
			name = "password-change"
		}
		t.Run(name, func(t *testing.T) {
			inbound, _ := managedInbound(t, nil)
			if err := inbound.UpdateUsers([]string{"alpha", "bravo"}, []string{"alpha-secret", "bravo-secret"}); err != nil {
				t.Fatal(err)
			}
			tracker := new(managedTracker)
			inbound.SetTracker(tracker)
			address := managedListen(t, inbound)
			alpha, _ := managedClient(t, address, "alpha-secret")
			bravo, bravoDials := managedClient(t, address, "bravo-secret")
			for _, client := range []*anytls.Client{alpha, bravo} {
				if err := managedExchange(client, "first"); err != nil {
					t.Fatal(err)
				}
			}
			if err := inbound.UpdateUsers([]string{"bravo", "alpha"}, []string{"bravo-secret", "alpha-secret"}); err != nil {
				t.Fatal(err)
			}
			if err := managedExchange(bravo, "second"); err != nil {
				t.Fatal(err)
			}
			users, passwords := []string{"bravo"}, []string{"bravo-secret"}
			if changePassword {
				users, passwords = append(users, "alpha"), append(passwords, "new-alpha-secret")
			}
			if err := inbound.UpdateUsers(users, passwords); err != nil {
				t.Fatal(err)
			}
			if err := managedExchange(alpha, "revoked"); err == nil {
				t.Fatal("a revoked user's pooled session still carried a new stream")
			}
			oldPassword, _ := managedClient(t, address, "alpha-secret")
			if err := managedExchange(oldPassword, "old-password"); err == nil {
				t.Fatal("revoked credentials still authenticate on a fresh connection")
			}
			if err := managedExchange(bravo, "third"); err != nil {
				t.Fatal(err)
			}
			if bravoDials.Load() != 1 {
				t.Fatal("unchanged users lost their reusable AnyTLS session")
			}
			trafficValue, exists := tracker.users.Load("bravo")
			if !exists {
				t.Fatal("tracker did not receive the authenticated user identity")
			}
			traffic := trafficValue.(*managedUserTraffic)
			deadline := time.NewTimer(2 * time.Second)
			defer deadline.Stop()
			for traffic.wrote.Load() < 16 {
				select {
				case <-traffic.write:
				case <-deadline.C:
					t.Fatal("server response accounting did not finish")
				}
			}
			if traffic.read.Load() != 16 || traffic.wrote.Load() != 16 {
				t.Fatalf("bravo traffic was misattributed: read=%d wrote=%d", traffic.read.Load(), traffic.wrote.Load())
			}
			if changePassword {
				newPassword, _ := managedClient(t, address, "new-alpha-secret")
				if err := managedExchange(newPassword, "new-password"); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestManagedAnyTLSValidationIsAtomic(t *testing.T) {
	inbound, _ := managedInbound(t, nil)
	if err := inbound.UpdateUsers([]string{"alpha"}, []string{"secret"}); err != nil {
		t.Fatal(err)
	}
	client, _ := managedClient(t, managedListen(t, inbound), "secret")
	for _, invalid := range []struct{ names, passwords []string }{
		{[]string{"alpha"}, nil},
		{[]string{""}, []string{"secret"}},
		{[]string{"alpha"}, []string{""}},
		{[]string{"alpha", "alpha"}, []string{"first", "second"}},
		{[]string{"alpha", "bravo"}, []string{"shared", "shared"}},
	} {
		if err := inbound.UpdateUsers(invalid.names, invalid.passwords); err == nil {
			t.Fatal("invalid update succeeded")
		}
		if err := managedExchange(client, "original"); err != nil {
			t.Fatalf("invalid update replaced the previous authentication snapshot: %v", err)
		}
	}
	if err := inbound.UpdateUsers(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := managedExchange(client, "removed"); err == nil {
		t.Fatal("empty snapshot did not revoke all users")
	}
	inbound.closeConnections()
	if !errors.Is(inbound.UpdateUsers([]string{"alpha"}, []string{"secret"}), net.ErrClosed) {
		t.Fatal("closed inbound accepted a user update")
	}
}

func TestManagedAnyTLSConcurrentSnapshots(t *testing.T) {
	inbound, _ := managedInbound(t, nil)
	if err := inbound.UpdateUsers([]string{"bravo"}, []string{"bravo-secret"}); err != nil {
		t.Fatal(err)
	}
	tracker := new(managedTracker)
	inbound.SetTracker(tracker)
	client, dials := managedClient(t, managedListen(t, inbound), "bravo-secret")
	if err := managedExchange(client, "ready"); err != nil {
		t.Fatal(err)
	}
	updated := make(chan error, 1)
	go func() {
		for index := 0; index < 50; index++ {
			if err := inbound.UpdateUsers([]string{"alpha", "bravo"}, []string{"alpha-secret", "bravo-secret"}); err != nil {
				updated <- err
				return
			}
			inbound.SetTracker(tracker)
			if err := inbound.UpdateUsers([]string{"bravo"}, []string{"bravo-secret"}); err != nil {
				updated <- err
				return
			}
		}
		updated <- nil
	}()
	for index := 0; index < 50; index++ {
		if err := managedExchange(client, "stable"); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 1 {
		t.Fatal("unrelated user updates replaced the unchanged user's connection")
	}
}

func TestManagedAnyTLSPreservesUnnamedStaticUsers(t *testing.T) {
	inbound, _ := managedInbound(t, []option.AnyTLSUser{{Password: "first"}, {Password: "second"}})
	address := managedListen(t, inbound)
	for _, password := range []string{"first", "second"} {
		client, _ := managedClient(t, address, password)
		if err := managedExchange(client, "unnamed"); err != nil {
			t.Fatalf("public AnyTLS static-user behavior changed: %v", err)
		}
	}
}

func TestManagedAnyTLSRevokesActiveStream(t *testing.T) {
	inbound, _ := managedInbound(t, nil)
	if err := inbound.UpdateUsers([]string{"alpha"}, []string{"secret"}); err != nil {
		t.Fatal(err)
	}
	client, _ := managedClient(t, managedListen(t, inbound), "secret")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.CreateProxy(ctx, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	var echo [4]byte
	if _, err = io.ReadFull(conn, echo[:]); err != nil {
		t.Fatal(err)
	}
	if err = inbound.UpdateUsers(nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Read(echo[:]); err == nil {
		t.Fatal("removed user's active stream remained open")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("revocation relied on the client deadline instead of closing the session")
	}
}

type managedReadSignal struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *managedReadSignal) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Read(p)
}

func TestManagedAnyTLSShutdownClosesPendingAuthentication(t *testing.T) {
	inbound, _ := managedInbound(t, nil)
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	signaled := &managedReadSignal{Conn: server, entered: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		inbound.NewConnection(context.Background(), signaled, adapter.InboundContext{}, nil)
	}()
	managedWait(t, signaled.entered, "pending authentication read")
	if err := inbound.closeConnections(); err != nil {
		t.Fatal(err)
	}
	managedWait(t, done, "pending authentication shutdown")
}

type managedAuthenticationBarrier struct {
	net.Conn
	readDigest chan struct{}
	resume     chan struct{}
	once       sync.Once
}

func (c *managedAuthenticationBarrier) Read(p []byte) (int, error) {
	if len(p) == 2 {
		c.once.Do(func() { close(c.readDigest); <-c.resume })
	}
	return c.Conn.Read(p)
}

func TestManagedAnyTLSRejectsAuthenticationRacingUpdate(t *testing.T) {
	inbound, _ := managedInbound(t, nil)
	if err := inbound.UpdateUsers([]string{"alpha"}, []string{"old-secret"}); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	barrier := &managedAuthenticationBarrier{Conn: server, readDigest: make(chan struct{}), resume: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		inbound.NewConnection(context.Background(), barrier, adapter.InboundContext{}, nil)
	}()
	digest := sha256.Sum256([]byte("old-secret"))
	client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write(digest[:]); err != nil {
		t.Fatal(err)
	}
	managedWait(t, barrier.readDigest, "old digest lookup")
	if err := inbound.UpdateUsers([]string{"alpha"}, []string{"new-secret"}); err != nil {
		t.Fatal(err)
	}
	close(barrier.resume)
	if _, err := client.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	managedWait(t, done, "authentication rejection after snapshot change")
}

type managedBufferedConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c *managedBufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type managedRevokingTracker struct {
	inbound *Inbound
	count   atomic.Int32
	once    sync.Once
	updated chan error
}

func (r *managedRevokingTracker) TrackConnection(conn net.Conn, _ adapter.InboundContext) net.Conn {
	r.count.Add(1)
	r.once.Do(func() { r.updated <- r.inbound.UpdateUsers(nil, nil) })
	return conn
}

func (r *managedRevokingTracker) TrackPacketConnection(conn N.PacketConn, _ adapter.InboundContext) N.PacketConn {
	return conn
}

func TestManagedAnyTLSRevocationRejectsBufferedStreams(t *testing.T) {
	inbound, router := managedInbound(t, nil)
	if err := inbound.UpdateUsers([]string{"alpha"}, []string{"secret"}); err != nil {
		t.Fatal(err)
	}
	tracker := &managedRevokingTracker{inbound: inbound, updated: make(chan error, 1)}
	inbound.SetTracker(tracker)
	digest := sha256.Sum256([]byte("secret"))
	batch := append([]byte{}, digest[:]...)
	batch = append(batch, 0, 1, 7) // Public AnyTLS authentication padding remains accepted.
	appendFrame := func(command byte, streamID uint32, payload []byte) {
		var header [7]byte
		header[0] = command
		binary.BigEndian.PutUint32(header[1:], streamID)
		binary.BigEndian.PutUint16(header[5:], uint16(len(payload)))
		batch = append(batch, header[:]...)
		batch = append(batch, payload...)
	}
	appendFrame(4, 0, []byte("v=1"))
	var address bytes.Buffer
	if err := M.SocksaddrSerializer.WriteAddrPort(&address, M.ParseSocksaddr("example.com:443")); err != nil {
		t.Fatal(err)
	}
	for _, streamID := range []uint32{1, 3} {
		appendFrame(1, streamID, nil)
		appendFrame(2, streamID, append(append([]byte{}, address.Bytes()...), 1))
	}
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go io.Copy(io.Discard, client)
	done := make(chan struct{})
	go func() {
		defer close(done)
		inbound.NewConnection(context.Background(), &managedBufferedConn{Conn: server, reader: bytes.NewReader(batch)},
			adapter.InboundContext{}, nil)
	}()
	select {
	case err := <-tracker.updated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first buffered stream did not reach the revocation barrier")
	}
	managedWait(t, done, "revoked buffered session")
	if tracker.count.Load() != 1 || router.calls.Load() != 0 {
		t.Fatal("a revoked buffered stream reached a tracker or router after cancellation")
	}
}
