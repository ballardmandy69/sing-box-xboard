package vmess

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func TestAuthenticationFailureHookBoundaries(t *testing.T) {
	for _, test := range []struct {
		name    string
		known   bool
		stale   bool
		short   bool
		blocked bool
		replay  bool
		reports int64
	}{
		{name: "unknown identity", reports: 1},
		{name: "initial short read", short: true},
		{name: "recognized identity invalid header", known: true},
		{name: "recognized identity expired timestamp", known: true, stale: true},
		{name: "replayed identity", known: true, replay: true},
		{name: "blocked before reading", blocked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := NewService[string](nil, ServiceWithDisableHeaderProtection())
			if err := service.UpdateUsers([]string{"known"}, []string{"known-credential"}, []int{0}); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 128)
			if test.known {
				timestamp := time.Now().Unix()
				if test.stale {
					timestamp -= 1000
				}
				copy(data, encryptedAuthID(service.users.Load().userIdCipher["known"], 1, timestamp))
			}
			if test.short {
				data = data[:1]
			}
			var reports atomic.Int64
			source := M.ParseSocksaddr("192.0.2.8:1234")
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
			if test.replay {
				_, _, _ = service.findAEADUser(service.users.Load(), data[:16])
			}
			conn := &authBanMemoryConn{reader: bytes.NewReader(data)}
			if err := service.NewConnection(context.Background(), conn, source, nil); err == nil {
				t.Fatal("rejected handshake unexpectedly succeeded")
			}
			if reports.Load() != test.reports || test.blocked && conn.reads != 0 {
				t.Fatalf("reports=%d expected=%d reads=%d", reports.Load(), test.reports, conn.reads)
			}
		})
	}
}

func TestAuthenticationFailureHookConcurrentPublication(t *testing.T) {
	service := NewService[string](nil, ServiceWithDisableHeaderProtection())
	var reports atomic.Int64
	report := func(M.Socksaddr) { reports.Add(1) }
	blocked := func(M.Socksaddr) bool { return false }
	service.SetAuthenticationFailureHooks(report, blocked)
	var wait sync.WaitGroup
	for index := 0; index < 50; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			service.SetAuthenticationFailureHooks(report, blocked)
			_ = service.NewConnection(context.Background(),
				&authBanMemoryConn{reader: bytes.NewReader(make([]byte, 128))}, M.Socksaddr{}, nil)
		}()
	}
	wait.Wait()
	if reports.Load() != 50 {
		t.Fatalf("lost callbacks: %d", reports.Load())
	}
}
