package shadowaead

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type hotTestHandler struct{ users chan string }

func (h *hotTestHandler) NewConnection(ctx context.Context, conn net.Conn, _ M.Metadata) error {
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		return errors.New("missing authenticated identity")
	}
	h.users <- user
	io.Copy(conn, conn)
	return nil
}

func (*hotTestHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return errors.New("unexpected packet connection")
}

func (*hotTestHandler) NewError(context.Context, error) {}

func hotTestService(t *testing.T) (*MultiService[string], *hotTestHandler) {
	t.Helper()
	handler := &hotTestHandler{users: make(chan string, 100)}
	service, err := NewMultiService[string]("aes-128-gcm", 60, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateUsersWithPasswords([]string{"hot", "cold"}, []string{"hot-secret", "cold-secret"}); err != nil {
		t.Fatal(err)
	}
	return service, handler
}

func hotExchange(service *MultiService[string], ctx context.Context, password string) error {
	server, client := net.Pipe()
	defer client.Close()
	server.SetDeadline(time.Now().Add(2 * time.Second))
	client.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		done <- service.NewConnection(ctx, server, M.Metadata{})
	}()
	method, err := New("aes-128-gcm", nil, password)
	if err != nil {
		return err
	}
	conn := method.DialEarlyConn(client, M.ParseSocksaddr("example.org:443"))
	payload := []byte("hot candidate test")
	_, writeErr := conn.Write(payload)
	if writeErr == nil {
		response := make([]byte, len(payload))
		_, err = io.ReadFull(conn, response)
		if err == nil && !bytes.Equal(response, payload) {
			err = errors.New("payload changed")
		}
	} else {
		err = writeErr
	}
	conn.Close()
	serverErr := <-done
	if serverErr != nil {
		return serverErr
	}
	return err
}

func countCandidate(service *MultiService[string], user string, counter *atomic.Int64) {
	method := service.methodMap[user]
	original := method.constructor
	method.constructor = func(key []byte) (cipher.AEAD, error) {
		counter.Add(1)
		return original(key)
	}
}

func TestHotFirstAndColdFallbackWithAuthenticatedIdentity(t *testing.T) {
	service, handler := hotTestService(t)
	var hotCalls, coldCalls atomic.Int64
	countCandidate(service, "hot", &hotCalls)
	countCandidate(service, "cold", &coldCalls)
	service.UpdateHotUsersMatching(func(user string) bool { return user == "hot" })
	callback := make(chan string, 10)
	service.SetHotUserCallback(func(user string) { callback <- user })
	if err := hotExchange(service, context.Background(), "hot-secret"); err != nil {
		t.Fatal(err)
	}
	if user := <-handler.users; user != "hot" || coldCalls.Load() != 0 {
		t.Fatal("hot authentication attempted a cold key or changed identity")
	}
	select {
	case <-callback:
		t.Fatal("a hot match emitted a cold-user callback")
	default:
	}
	hotCalls.Store(0)
	if err := hotExchange(service, context.Background(), "cold-secret"); err != nil {
		t.Fatal(err)
	}
	if user := <-handler.users; user != "cold" || hotCalls.Load() != 1 {
		t.Fatal("cold fallback repeated the hot key or changed identity")
	}
	select {
	case user := <-callback:
		if user != "cold" {
			t.Fatalf("callback identity=%q", user)
		}
	case <-time.After(time.Second):
		t.Fatal("cold success did not emit the asynchronous callback")
	}
}

func TestUserHintIsOneCandidateAndStillAuthenticates(t *testing.T) {
	service, handler := hotTestService(t)
	service.UpdateHotUsersMatching(func(string) bool { return true })
	ctx := shadowsocks.ContextWithUserHint(context.Background(), "cold")
	if err := hotExchange(service, ctx, "cold-secret"); err != nil {
		t.Fatal(err)
	}
	if user := <-handler.users; user != "cold" {
		t.Fatal("hint changed authenticated identity")
	}
	if err := hotExchange(service, ctx, "hot-secret"); err == nil {
		t.Fatal("wrong hinted password fell back to a valid user's key")
	}
	ctx = shadowsocks.ContextWithUserHint(context.Background(), "missing")
	if err := hotExchange(service, ctx, "hot-secret"); !errors.Is(err, shadowsocks.ErrNoUsers) {
		t.Fatalf("unknown hint did not fail before scanning: %v", err)
	}
	if len(handler.users) != 0 {
		t.Fatal("rejected hint reached the handler")
	}
}

func TestHotCredentialRotationAndConcurrentPublication(t *testing.T) {
	service, handler := hotTestService(t)
	service.UpdateHotUsersMatching(func(string) bool { return true })
	previous := service.hotMethodMap
	if err := service.UpdateUsersWithPasswords([]string{"hot"}, []string{"new-secret"}); err != nil {
		t.Fatal(err)
	}
	if service.hotMethodMap["hot"] != service.methodMap["hot"] ||
		service.hotMethodMap["hot"] == previous["hot"] || len(service.hotMethodMap) != 1 {
		t.Fatal("updated hot subset retained stale credentials")
	}
	if err := hotExchange(service, context.Background(), "hot-secret"); err == nil {
		t.Fatal("retired credential authenticated through the hot subset")
	}
	if err := hotExchange(service, context.Background(), "new-secret"); err != nil {
		t.Fatal(err)
	}
	<-handler.users
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for index := 0; index < 60; index++ {
			service.UpdateUsersWithPasswords([]string{"hot"}, []string{"new-secret"})
			service.UpdateHotUsersMatching(func(string) bool { return true })
			service.SetHotUserCallback(nil)
		}
	}()
	for index := 0; index < 20; index++ {
		if err := hotExchange(service, context.Background(), "new-secret"); err != nil {
			t.Fatal(err)
		}
		if user := <-handler.users; user != "hot" {
			t.Fatal("concurrent publication changed identity")
		}
	}
	workers.Wait()
	service.UpdateUsersWithPasswords(nil, nil)
	if len(service.hotMethodMap) != 0 || len(previous) != 2 {
		t.Fatal("removal retained hot credentials or mutated a previous generation")
	}
}
