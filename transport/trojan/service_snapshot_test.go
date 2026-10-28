package trojan

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// snapshotIdentityHandler records the identity delivered after parsing a complete TCP request.
// @author lyt
// @date 2026-10-29
type snapshotIdentityHandler struct{}

type snapshotResultKey struct{}

type snapshotIdentityResult struct {
	name   string
	loaded bool
}

func (snapshotIdentityHandler) NewConnectionEx(ctx context.Context, _ net.Conn, _ M.Socksaddr,
	_ M.Socksaddr, _ N.CloseHandlerFunc,
) {
	result := ctx.Value(snapshotResultKey{}).(*snapshotIdentityResult)
	result.name, result.loaded = auth.UserFromContext[string](ctx)
}

func (snapshotIdentityHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn,
	_ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc,
) {
	conn.Close()
}

func snapshotAuthenticate(service *Service[string], password string) (string, error) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline := time.Now().Add(3 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	key := Key(password)
	var request bytes.Buffer
	request.Write(key[:])
	request.Write(CRLF)
	request.WriteByte(CommandTCP)
	if err := M.SocksaddrSerializer.WriteAddrPort(&request, M.ParseSocksaddr("127.0.0.1:80")); err != nil {
		return "", err
	}
	request.Write(CRLF)
	written := make(chan error, 1)
	go func() {
		_, err := client.Write(request.Bytes())
		written <- err
	}()
	var result snapshotIdentityResult
	err := service.NewConnection(context.WithValue(context.Background(), snapshotResultKey{}, &result),
		server, M.Socksaddr{}, nil)
	server.Close()
	writeErr := <-written
	if err != nil {
		return "", err
	}
	if writeErr != nil {
		return "", writeErr
	}
	if !result.loaded {
		return "", fmt.Errorf("authenticated request did not reach the handler")
	}
	return result.name, nil
}

func TestRejectedUserUpdatePreservesAuthentication(t *testing.T) {
	service := NewService[string](snapshotIdentityHandler{}, nil, nil)
	if err := service.UpdateUsers([]string{"alpha", "bravo"}, []string{"alpha-secret", "bravo-secret"}); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		name      string
		users     []string
		passwords []string
	}{
		{name: "short_passwords", users: []string{"replacement"}},
		{name: "excess_passwords", passwords: []string{"replacement"}},
		{name: "duplicate_user", users: []string{"replacement", "replacement"}, passwords: []string{"one", "two"}},
		{name: "duplicate_password", users: []string{"one", "two"}, passwords: []string{"same", "same"}},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			if err := service.UpdateUsers(invalid.users, invalid.passwords); err == nil {
				t.Fatal("invalid user update was accepted")
			}
			if user, err := snapshotAuthenticate(service, "alpha-secret"); err != nil || user != "alpha" {
				t.Fatalf("rejected update changed the previous credential map: user=%q, err=%v", user, err)
			}
		})
	}
}

func TestConcurrentUserSnapshotAuthentication(t *testing.T) {
	service := NewService[string](snapshotIdentityHandler{}, nil, nil)
	if err := service.UpdateUsers([]string{"alpha", "bravo"}, []string{"alpha-secret", "bravo-secret"}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for range 200 {
			if err := service.UpdateUsers([]string{"bravo", "alpha"}, []string{"bravo-secret", "alpha-secret"}); err != nil {
				t.Errorf("update reordered users: %v", err)
				return
			}
			if err := service.UpdateUsers([]string{"alpha", "bravo"}, []string{"alpha-secret", "bravo-secret"}); err != nil {
				t.Errorf("restore original user order: %v", err)
				return
			}
		}
	}()
	for worker := range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			name := "alpha"
			if worker%2 != 0 {
				name = "bravo"
			}
			for range 50 {
				if user, err := snapshotAuthenticate(service, name+"-secret"); err != nil || user != name {
					t.Errorf("concurrent authentication changed identity: got %q, want %q, err=%v", user, name, err)
					return
				}
			}
		}()
	}
	close(start)
	workers.Wait()
}
