package vless

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

const policyTestCredential = "61552c7d-d297-4593-86dd-62c57d01afbb"

type policyTestHandler struct {
	mu    sync.Mutex
	users []string
}

func (h *policyTestHandler) NewConnectionEx(ctx context.Context, conn net.Conn,
	_, _ M.Socksaddr, _ N.CloseHandlerFunc,
) {
	user, _ := auth.UserFromContext[string](ctx)
	h.mu.Lock()
	h.users = append(h.users, user)
	h.mu.Unlock()
	conn.Close()
}

func (*policyTestHandler) NewPacketConnectionEx(context.Context, N.PacketConn,
	M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc,
) {
	panic("unexpected UDP request")
}

func TestClientFlowSingMuxException(t *testing.T) {
	for _, item := range []struct {
		destination string
		flow        string
		force       bool
		accepted    bool
	}{
		{"example.test", "", false, true},
		{"example.test", "", true, false},
		{"sp.mux.sing-box.arpa", "", true, true},
		{"SP.MUX.SING-BOX.ARPA", "", true, false},
		{"sp.mux.sing-box.arpa.", "", true, false},
		{"sp.mux.sing-box.arpa", "unsupported", true, false},
	} {
		handler := new(policyTestHandler)
		service := NewService[string](logger.NOP(), handler)
		service.UpdateUsersWithClientFlow([]string{"managed"}, []string{policyTestCredential}, item.force)
		err := policyHandshake(service, item.destination, item.flow)
		if (err == nil) != item.accepted {
			t.Fatalf("destination=%q force=%v flow=%q: %v",
				item.destination, item.force, item.flow, err)
		}
		if item.accepted && (len(handler.users) != 1 || handler.users[0] != "managed") {
			t.Fatal("accepted carrier lost its authenticated identity")
		}
		if !item.accepted && len(handler.users) != 0 {
			t.Fatal("rejected flow reached the handler")
		}
	}
}

func TestClientFlowPolicyUpdatesKeepHandshakeGeneration(t *testing.T) {
	handler := new(policyTestHandler)
	service := NewService[string](logger.NOP(), handler)
	service.UpdateUsers([]string{"strict"}, []string{policyTestCredential}, []string{FlowVision})
	previous := service.users.Load()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			service.UpdateUsersWithClientFlow([]string{"compatible"}, []string{policyTestCredential}, false)
			service.UpdateUsers([]string{"strict"}, []string{policyTestCredential}, []string{FlowVision})
			runtime.Gosched()
		}
	}()
	defer func() { cancel(); <-done }()
	for index := 0; index < 80; index++ {
		err := policyHandshake(service, "example.test", "")
		if err != nil && !strings.Contains(err.Error(), "flow mismatch") {
			t.Fatal(err)
		}
	}
	if previous.allowClientFlow || previous.userFlow["strict"] != FlowVision {
		t.Fatal("published user snapshot was mutated")
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	for _, user := range handler.users {
		if user != "compatible" {
			t.Fatalf("handshake combined compatible policy with strict identity %q", user)
		}
	}
}

func policyHandshake(service *Service[string], destination string, flow string) error {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	server.SetDeadline(time.Now().Add(3 * time.Second))
	client.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	go func() {
		done <- service.NewConnection(context.Background(), server, M.Socksaddr{}, nil)
	}()
	userUUID, _ := uuid.FromString(policyTestCredential)
	if err := WriteRequest(client, Request{
		UUID: userUUID, Command: vmess.CommandTCP, Flow: flow,
		Destination: M.Socksaddr{Fqdn: destination, Port: 443},
	}, nil); err != nil {
		return err
	}
	return <-done
}
