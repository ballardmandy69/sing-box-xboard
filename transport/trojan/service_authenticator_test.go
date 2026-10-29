package trojan

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// authenticatorConn supplies a real Trojan request to the common wire parser.
// @author lyt
// @date 2026-10-29
type authenticatorConn struct {
	net.Conn
	*bytes.Reader
	beforeRead func()
}

func (c *authenticatorConn) Read(data []byte) (int, error) {
	if c.beforeRead != nil {
		callback := c.beforeRead
		c.beforeRead = nil
		callback()
	}
	return c.Reader.Read(data)
}

func TestServiceOwnAuthenticatorLoadsUsersAfterHeaderRead(t *testing.T) {
	handler := new(paddingTCPHandler)
	service := NewService[string](handler, nil, nil)
	if err := service.UpdateUsers([]string{"user"}, []string{"old-secret"}); err != nil {
		t.Fatal(err)
	}
	conn := &authenticatorConn{Reader: bytes.NewReader(authenticatorRequest(t, "old-secret")), beforeRead: func() {
		if err := service.UpdateUsers(nil, nil); err != nil {
			t.Fatal(err)
		}
	}}
	if err := service.NewConnection(context.Background(), conn, M.Socksaddr{}, nil); err == nil || handler.called {
		t.Fatal("ordinary authentication retained a user removed while reading the header")
	}
}

func authenticatorRequest(t *testing.T, password string) []byte {
	t.Helper()
	var request bytes.Buffer
	key := Key(password)
	request.Write(key[:])
	request.Write(CRLF)
	request.WriteByte(CommandTCP)
	if err := M.SocksaddrSerializer.WriteAddrPort(&request, M.ParseSocksaddr("example.test:443")); err != nil {
		t.Fatal(err)
	}
	request.Write(CRLF)
	return request.Bytes()
}

func TestServiceAuthenticatorAlwaysChecksWireHeader(t *testing.T) {
	for _, test := range []struct {
		name         string
		wirePassword string
		custom       bool
		accept       bool
	}{
		{"external snapshot", "external-secret", true, true},
		{"nil uses own snapshot", "own-secret", false, true},
		{"external lookup excludes own table", "own-secret", true, false},
		{"context user cannot bypass own table", "wrong-secret", false, false},
		{"context user cannot bypass external table", "wrong-secret", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := new(paddingTCPHandler)
			service := NewService[string](handler, nil, nil)
			if err := service.UpdateUsers([]string{"user"}, []string{"own-secret"}); err != nil {
				t.Fatal(err)
			}
			key := Key(test.wirePassword)
			var lookup func([56]byte) (string, bool)
			calls := 0
			if test.custom {
				lookup = func(actual [56]byte) (string, bool) {
					calls++
					if actual != key {
						t.Fatal("authenticator did not receive the wire header")
					}
					return "user", actual == Key("external-secret")
				}
			}
			ctx := auth.ContextWithUser(context.Background(), "untrusted-context-user")
			conn := &authenticatorConn{Reader: bytes.NewReader(authenticatorRequest(t, test.wirePassword))}
			err := service.NewConnectionWithAuthenticator(ctx, conn, M.Socksaddr{}, nil, lookup)
			if test.accept {
				if err != nil || handler.err != nil || !handler.called {
					t.Fatalf("authentication failed: error=%v handler=%v called=%v", err, handler.err, handler.called)
				}
			} else if err == nil || handler.called {
				t.Fatalf("bad wire credentials accepted: error=%v called=%v", err, handler.called)
			}
			if test.custom && calls != 1 {
				t.Fatalf("lookup calls=%d, want 1", calls)
			}
		})
	}
}

// authenticatorFallback verifies rejected headers remain available to the configured fallback.
// @author lyt
// @date 2026-10-29
type authenticatorFallback struct {
	key    [56]byte
	called bool
	err    error
}

func (h *authenticatorFallback) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr,
	_ N.CloseHandlerFunc,
) {
	h.called = true
	_, h.err = conn.Read(h.key[:])
}

func TestServiceAuthenticatorPreservesFallbackHeader(t *testing.T) {
	fallback := new(authenticatorFallback)
	service := NewService[string](new(paddingTCPHandler), fallback, nil)
	key := Key("unknown-secret")
	conn := &authenticatorConn{Reader: bytes.NewReader(key[:])}
	err := service.NewConnectionWithAuthenticator(context.Background(), conn, M.Socksaddr{}, nil,
		func([56]byte) (string, bool) { return "", false })
	if err != nil || fallback.err != nil || !fallback.called || fallback.key != key {
		t.Fatalf("fallback lost the rejected header: error=%v fallback=%v called=%v", err, fallback.err, fallback.called)
	}
}
