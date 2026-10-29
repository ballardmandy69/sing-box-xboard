package shadowsocks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
)

// hotIdentityRouter captures the identity produced by the actual Shadowsocks inbound handler.
// @author lyt
// @date 2026-10-29
type hotIdentityRouter struct {
	adapter.Router
	users chan string
}

func (r *hotIdentityRouter) RouteConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.users <- metadata.User
	_, _ = io.Copy(conn, conn)
	return nil
}

func TestManagedHotAuthenticationKeepsRoutingIdentity(t *testing.T) {
	router := &hotIdentityRouter{users: make(chan string, 64)}
	inbound, err := newMultiInbound(context.Background(), router, log.NewNOPFactory().Logger(), "managed",
		option.ShadowsocksInboundOptions{Method: "aes-128-gcm", Managed: true, Network: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"42@panel@uniproxy", "43@panel@uniproxy"}
	passwords := []string{"first-secret", "second-secret"}
	if err = inbound.UpdateUsers(names, passwords); err != nil {
		t.Fatal(err)
	}
	hot := adapter.HotUserManager(inbound)
	hot.UpdateHotUsers([]string{names[0], "unknown"})
	callbacks := make(chan string, 64)
	hot.SetHotUserCallback(func(name string) { callbacks <- name })
	if err = exchangeHotInbound(inbound, passwords[0]); err != nil {
		t.Fatal(err)
	}
	if got := <-router.users; got != names[0] {
		t.Fatalf("hot authentication routed as %q", got)
	}
	if err = exchangeHotInbound(inbound, passwords[1]); err != nil {
		t.Fatal(err)
	}
	if got := <-router.users; got != names[1] {
		t.Fatalf("cold authentication routed as %q", got)
	}
	select {
	case got := <-callbacks:
		if got != names[1] {
			t.Fatalf("hot callback attributed to %q, want cold identity %q", got, names[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cold authentication did not notify the managed hot-user callback")
	}
	hot.SetHotUserCallback(nil)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for index := 0; index < 60; index++ {
			orderedNames, orderedPasswords := names, passwords
			if index%2 != 0 {
				orderedNames = []string{names[1], names[0]}
				orderedPasswords = []string{passwords[1], passwords[0]}
			}
			if err := inbound.UpdateUsers(orderedNames, orderedPasswords); err != nil {
				t.Error(err)
				return
			}
			hot.UpdateHotUsers(names)
		}
	}()
	for index := 0; index < 16; index++ {
		if err := exchangeHotInbound(inbound, passwords[index%2]); err != nil {
			t.Error(err)
			break
		}
		if got := <-router.users; got != names[index%2] {
			t.Errorf("reordered credentials routed as %q, want %q", got, names[index%2])
		}
	}
	workers.Wait()
	if err := inbound.UpdateUsers(names, []string{passwords[0], "rotated-secret"}); err != nil {
		t.Fatal(err)
	}
	hot.UpdateHotUsers(names)
	if err := exchangeHotInbound(inbound, passwords[1]); err == nil {
		t.Fatal("old password authenticated after rotation")
	}
	if err := exchangeHotInbound(inbound, "rotated-secret"); err != nil {
		t.Fatal(err)
	}
	if got := <-router.users; got != names[1] {
		t.Fatalf("rotated password routed as %q", got)
	}
	select {
	case got := <-router.users:
		t.Fatalf("rejected credentials reached routing as %q", got)
	default:
	}
}

func exchangeHotInbound(inbound *MultiInbound, password string) error {
	server, client := net.Pipe()
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		done <- inbound.service.NewConnection(context.Background(), server, M.Metadata{})
	}()
	method, err := shadowaead.New("aes-128-gcm", nil, password)
	if err != nil {
		return err
	}
	conn := method.DialEarlyConn(client, M.ParseSocksaddr("example.org:443"))
	payload := []byte("managed hot-user identity")
	if _, err = conn.Write(payload); err == nil {
		response := make([]byte, len(payload))
		_, err = io.ReadFull(conn, response)
		if err == nil && !bytes.Equal(response, payload) {
			err = errors.New("Shadowsocks payload changed")
		}
	}
	_ = conn.Close()
	if serverErr := <-done; serverErr != nil {
		return serverErr
	}
	return err
}
