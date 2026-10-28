package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func snapshotService(t *testing.T, disable bool) *Service {
	t.Helper()
	s, err := NewService(ServiceConfig{
		Users:         []User{{Name: "auth-user", Password: "auth-password"}},
		PaddingScheme: padding.DefaultPaddingScheme, Logger: logger.NOP(), DisablePadding: disable,
		Handler: authHandler(func(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
			t.Error("unexpected route")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConcurrentUserSnapshotsAuthenticate(t *testing.T) {
	s := snapshotService(t, false)
	stopped := errors.New("authenticated; do not create session")
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := 0; index < 200; index++ {
				conn := &authenticationFixtureConn{bytes.NewReader(authenticationBytes(0))}
				err := s.NewConnectionWithAuth(context.Background(), conn, M.Socksaddr{}, nil, func(ctx context.Context) error {
					if name, _ := auth.UserFromContext[string](ctx); name != "auth-user" {
						t.Errorf("snapshot user=%q", name)
					}
					return stopped
				})
				if !errors.Is(err, stopped) {
					t.Errorf("auth failed during update: %v", err)
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for index := 0; index < 200; index++ {
			s.UpdateUsers([]User{{Name: "auth-user", Password: "auth-password"}, {Name: "changing-user", Password: fmt.Sprint(index)}})
		}
	}()
	workers.Wait()
	old := s.users.Load()
	s.UpdateUsers(nil)
	digest := sha256.Sum256([]byte("auth-password"))
	if _, ok := s.lookupUser(digest); ok {
		t.Fatal("removed user still in current snapshot")
	}
	if old.byDigest[digest] != "auth-user" {
		t.Fatal("published snapshot was mutated")
	}
}

func TestAuthCallbackConsumesOnlyCompleteAuth(t *testing.T) {
	for _, pad := range []int{0, 31} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("padding-%d/reject-%v", pad, fail), func(t *testing.T) {
				s := snapshotService(t, false)
				settings := authFrame(4, 0, []byte("v=1\npadding-md5="+s.padding.Load().Md5+"\n"))
				input := append(authenticationBytes(pad), settings...)
				conn := &authenticationFixtureConn{bytes.NewReader(input)}
				called := false
				refusal := errors.New("gate rejected")
				err := s.NewConnectionWithAuth(context.Background(), conn, M.Socksaddr{}, nil, func(ctx context.Context) error {
					called = true
					if conn.Reader.Len() != len(settings) {
						t.Error("callback consumed session data or ran before full auth")
					}
					if name, _ := auth.UserFromContext[string](ctx); name != "auth-user" {
						t.Error("callback lacks authenticated context")
					}
					if fail {
						return refusal
					}
					return nil
				})
				if !called {
					t.Fatal("callback not called")
				}
				if fail {
					if !errors.Is(err, refusal) || conn.Reader.Len() != len(settings) {
						t.Fatalf("rejected auth processed session: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	for _, input := range [][]byte{authenticationBytes(31)[:40], authenticationBytes(0)[:33], []byte("bad")} {
		s := snapshotService(t, false)
		called := false
		_ = s.NewConnectionWithAuth(context.Background(), &authenticationFixtureConn{bytes.NewReader(input)}, M.Socksaddr{}, nil, func(context.Context) error { called = true; return nil })
		if called {
			t.Fatal("callback invoked on incomplete auth")
		}
	}
}

func TestDisableAuthenticationPadding(t *testing.T) {
	var written bytes.Buffer
	client, err := NewClient(context.Background(), ClientConfig{
		Password: "auth-password", Logger: logger.NOP(), EnhancedPadding: true, DisablePadding: true,
		DialOut: func(context.Context) (net.Conn, error) {
			return &authenticationCaptureConn{authenticationFixtureConn: authenticationFixtureConn{bytes.NewReader(nil)}, written: &written}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.createOutboundConnection(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if written.Len() != 34 || binary.BigEndian.Uint16(written.Bytes()[32:]) != 0 {
		t.Fatalf("padding emitted: %d bytes", written.Len())
	}
	if client.enhancedPadding {
		t.Fatal("enhanced enabled despite DisablePadding")
	}
	s := snapshotService(t, true)
	called := false
	err = s.NewConnectionWithAuth(context.Background(), &authenticationFixtureConn{bytes.NewReader(authenticationBytes(1))}, M.Socksaddr{}, nil, func(context.Context) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("nonzero padding accepted in disabled mode")
	}
}

type authenticationCaptureConn struct {
	authenticationFixtureConn
	written *bytes.Buffer
}

func (c *authenticationCaptureConn) Write(p []byte) (int, error) { return c.written.Write(p) }

func BenchmarkUserSnapshotLookup(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			users := make([]User, count)
			digests := make([][32]byte, count)
			for index := range users {
				users[index] = User{Name: fmt.Sprint(index), Password: fmt.Sprint("bench-password-", index)}
				digests[index] = sha256.Sum256([]byte(users[index].Password))
			}
			s := new(Service)
			s.UpdateUsers(users)
			b.Run("hot", func(b *testing.B) {
				digest := digests[len(digests)-1]
				b.ReportAllocs()
				b.ResetTimer()
				for index := 0; index < b.N; index++ {
					if _, ok := s.lookupUser(digest); !ok {
						b.Fatal("missing user")
					}
				}
			})
			b.Run("round_robin", func(b *testing.B) {
				userIndex := 0
				b.ReportAllocs()
				b.ResetTimer()
				for index := 0; index < b.N; index++ {
					if _, ok := s.lookupUser(digests[userIndex]); !ok {
						b.Fatal("missing user")
					}
					userIndex++
					if userIndex == len(digests) {
						userIndex = 0
					}
				}
			})
			b.Run("parallel_round_robin", func(b *testing.B) {
				var workerNumber atomic.Uint64
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					// Stagger workers once; the measured lookup loop has no RNG or shared counter.
					userIndex := int((workerNumber.Add(1) - 1) * 97 % uint64(len(digests)))
					for pb.Next() {
						if _, ok := s.lookupUser(digests[userIndex]); !ok {
							b.Error("missing user")
							return
						}
						userIndex++
						if userIndex == len(digests) {
							userIndex = 0
						}
					}
				})
			})
		})
	}
}
