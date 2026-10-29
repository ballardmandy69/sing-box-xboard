package shadowaead

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type authBanMemoryConn struct {
	net.Conn
	reader *bytes.Reader
	reads  int
}

func (c *authBanMemoryConn) Read(p []byte) (int, error) {
	c.reads++
	return c.reader.Read(p)
}

type authBanRejectHandler struct{ shadowsocks.Handler }

func (authBanRejectHandler) NewConnection(context.Context, net.Conn, M.Metadata) error {
	return errors.New("business route rejected")
}

func authBanFrame(t *testing.T, password string, payload []byte) []byte {
	t.Helper()
	method, err := New("aes-128-gcm", nil, password)
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{7}, method.keySaltLength)
	key := buf.NewSize(method.keySaltLength)
	defer key.Release()
	Kdf(method.key, salt, key)
	cipher, err := method.constructor(key.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, cipher.NonceSize())
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	result := append([]byte(nil), salt...)
	result = cipher.Seal(result, nonce, length, nil)
	nonce[0]++
	return cipher.Seal(result, nonce, payload, nil)
}

func TestAuthenticationFailureHookBoundaries(t *testing.T) {
	var address bytes.Buffer
	if err := M.SocksaddrSerializer.WriteAddrPort(&address, M.ParseSocksaddr("example.test:443")); err != nil {
		t.Fatal(err)
	}
	valid := authBanFrame(t, "cold-secret", address.Bytes())
	wrong := authBanFrame(t, "wrong-secret", address.Bytes())
	for _, test := range []struct {
		name    string
		data    []byte
		hint    string
		blocked bool
		reports int64
	}{
		{name: "initial short read", data: []byte{1}},
		{name: "unknown credential", data: wrong, reports: 1},
		{name: "hint wrong credential", data: wrong, hint: "cold"},
		{name: "hint unknown user", data: wrong, hint: "missing"},
		{name: "authenticated destination error", data: authBanFrame(t, "cold-secret", []byte{0xff})},
		{name: "business route rejected", data: valid},
		{name: "candidate payload short read", data: valid[:16+2+Overhead], reports: 1},
		{name: "blocked before reading", data: valid, blocked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, _ := hotTestService(t)
			service.handler = authBanRejectHandler{}
			var reports atomic.Int64
			source := M.ParseSocksaddr("192.0.2.7:1234")
			service.SetAuthenticationFailureHooks(func(got M.Socksaddr) {
				if got != source {
					t.Errorf("source changed: %v", got)
				}
				reports.Add(1)
			}, func(got M.Socksaddr) bool {
				if got != source {
					t.Errorf("source changed before authentication: %v", got)
				}
				return test.blocked
			})
			ctx := context.Background()
			if test.hint != "" {
				ctx = shadowsocks.ContextWithUserHint(ctx, test.hint)
			}
			conn := &authBanMemoryConn{reader: bytes.NewReader(test.data)}
			if err := service.NewConnection(ctx, conn, M.Metadata{Source: source}); err == nil {
				t.Fatal("rejected handshake unexpectedly succeeded")
			}
			if reports.Load() != test.reports || test.blocked && conn.reads != 0 {
				t.Fatalf("reports=%d expected=%d reads=%d", reports.Load(), test.reports, conn.reads)
			}
		})
	}
}

func TestAuthenticationFailureHookConcurrentPublication(t *testing.T) {
	service, _ := hotTestService(t)
	var reports atomic.Int64
	report := func(M.Socksaddr) { reports.Add(1) }
	blocked := func(M.Socksaddr) bool { return false }
	service.SetAuthenticationFailureHooks(report, blocked)
	data := authBanFrame(t, "wrong-secret", []byte{1})
	var wait sync.WaitGroup
	for index := 0; index < 50; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			service.SetAuthenticationFailureHooks(report, blocked)
			_ = service.NewConnection(context.Background(), &authBanMemoryConn{reader: bytes.NewReader(data)}, M.Metadata{})
		}()
	}
	wait.Wait()
	if reports.Load() != 50 {
		t.Fatalf("lost callbacks: %d", reports.Load())
	}
}
