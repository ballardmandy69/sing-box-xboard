package anytls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type authHandler func(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc)

func (h authHandler) NewConnectionEx(ctx context.Context, c net.Conn, s, d M.Socksaddr, f N.CloseHandlerFunc) {
	h(ctx, c, s, d, f)
}

func authenticationBytes(paddingLength int) []byte {
	password := sha256.Sum256([]byte("auth-password"))
	b := make([]byte, 34+paddingLength)
	copy(b, password[:])
	binary.BigEndian.PutUint16(b[32:34], uint16(paddingLength))
	return b
}

func authFrame(cmd byte, id uint32, payload []byte) []byte {
	b := make([]byte, 7+len(payload))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], id)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(payload)))
	copy(b[7:], payload)
	return b
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestAuthenticationFragmentationTCPAndTLS(t *testing.T) {
	for _, transport := range []string{"TCP", "TLS"} {
		for _, test := range []struct {
			name    string
			padding int
			split   bool
		}{
			{"zero-fragmented", 0, true}, {"padding-fragmented", 4096, true}, {"maximum-padding-fragmented", 65535, true}, {"coalesced-session", 23, false},
		} {
			t.Run(transport+"/"+test.name, func(t *testing.T) {
				result := make(chan error, 1)
				var authorized atomic.Bool
				payload := []byte("business frame after authentication")
				handler := authHandler(func(ctx context.Context, conn net.Conn, _ M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
					user, _ := auth.UserFromContext[string](ctx)
					if !authorized.Load() || user != "auth-user" || destination.String() != "example.com:443" {
						result <- io.ErrUnexpectedEOF
						return
					}
					got := make([]byte, len(payload))
					_, err := io.ReadFull(conn, got)
					if err == nil && !bytes.Equal(got, payload) {
						err = io.ErrUnexpectedEOF
					}
					result <- err
				})
				s, err := NewService(ServiceConfig{Users: []User{{Name: "auth-user", Password: "auth-password"}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: handler, Logger: logger.NOP()})
				if err != nil {
					t.Fatal(err)
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				var serverTLS *tls.Config
				if transport == "TLS" {
					serverTLS = &tls.Config{Certificates: []tls.Certificate{testCertificate(t)}, MinVersion: tls.VersionTLS13}
				}
				serverDone := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						serverDone <- err
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					if serverTLS != nil {
						conn = tls.Server(conn, serverTLS)
					}
					serverDone <- s.NewConnectionWithAuth(context.Background(), conn, M.Socksaddr{}, nil, func(context.Context) error {
						authorized.Store(true)
						return nil
					})
				}()
				client, err := net.Dial("tcp", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				client.SetDeadline(time.Now().Add(10 * time.Second))
				if serverTLS != nil {
					client = tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
				}
				authBytes := authenticationBytes(test.padding)
				settings := []byte("v=1\npadding-md5=" + s.padding.Load().Md5 + "\n")
				var application bytes.Buffer
				if err = M.SocksaddrSerializer.WriteAddrPort(&application, M.ParseSocksaddr("example.com:443")); err != nil {
					t.Fatal(err)
				}
				application.Write(payload)
				frames := append(authFrame(4, 0, settings), authFrame(1, 1, nil)...)
				frames = append(frames, authFrame(2, 1, application.Bytes())...)
				if !test.split {
					_, err = client.Write(append(authBytes, frames...))
				} else {
					for _, b := range authBytes[:34] {
						if _, err = client.Write([]byte{b}); err != nil {
							break
						}
					}
					for rest := authBytes[34:]; err == nil && len(rest) > 0; {
						n := len(rest)
						if n > 257 {
							n = 257
						}
						_, err = client.Write(rest[:n])
						rest = rest[n:]
					}
					if err == nil {
						_, err = client.Write(frames)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				select {
				case err = <-result:
					if err != nil {
						t.Fatal(err)
					}
				case err = <-serverDone:
					t.Fatalf("session ended before payload: %v", err)
				case <-time.After(10 * time.Second):
					t.Fatal("payload not delivered")
				}
				client.Close()
				select {
				case <-serverDone:
				case <-time.After(10 * time.Second):
					t.Fatal("server did not exit")
				}
			})
		}
	}
}

type authenticationFixtureConn struct{ *bytes.Reader }

func (*authenticationFixtureConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*authenticationFixtureConn) Close() error                     { return nil }
func (*authenticationFixtureConn) LocalAddr() net.Addr              { return nil }
func (*authenticationFixtureConn) RemoteAddr() net.Addr             { return nil }
func (*authenticationFixtureConn) SetDeadline(time.Time) error      { return nil }
func (*authenticationFixtureConn) SetReadDeadline(time.Time) error  { return nil }
func (*authenticationFixtureConn) SetWriteDeadline(time.Time) error { return nil }

func TestAuthenticationFallbackReplaysConsumedPrefix(t *testing.T) {
	unknown := authenticationBytes(0)
	unknown[0] ^= 255
	unknown = append(unknown, []byte("unread tail")...)
	for _, test := range []struct {
		name  string
		input []byte
	}{
		{"short-password", []byte("truncated")}, {"short-padding-length", authenticationBytes(0)[:33]},
		{"short-padding", authenticationBytes(8)[:37]}, {"unknown-password", unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			var replay []byte
			handler := authHandler(func(_ context.Context, c net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
				replay, _ = io.ReadAll(c)
				c.Close()
			})
			s, err := NewService(ServiceConfig{Users: []User{{Name: "auth-user", Password: "auth-password"}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: handler, FallbackHandler: handler, Logger: logger.NOP()})
			if err != nil {
				t.Fatal(err)
			}
			err = s.NewConnection(context.Background(), &authenticationFixtureConn{bytes.NewReader(test.input)}, M.Socksaddr{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(replay, test.input) {
				t.Fatalf("fallback replay %x, expected %x", replay, test.input)
			}
			s.fallbackHandler = nil
			err = s.NewConnection(context.Background(), &authenticationFixtureConn{bytes.NewReader(test.input)}, M.Socksaddr{}, nil)
			if err == nil || !strings.Contains(err.Error(), "fallback disabled") {
				t.Fatalf("missing contextual error: %v", err)
			}
		})
	}
}

type authenticationErrorConn struct {
	authenticationFixtureConn
	err error
}

func (c *authenticationErrorConn) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	if c.Reader.Len() == 0 {
		return n, c.err
	}
	return n, err
}

func TestAuthenticationReadErrorPreserved(t *testing.T) {
	fault := errors.New("injected transport read error")
	for _, length := range []int{0, 11, 33, 35} {
		input := authenticationBytes(8)[:length]
		s, err := NewService(ServiceConfig{
			Users:         []User{{Name: "auth-user", Password: "auth-password"}},
			PaddingScheme: padding.DefaultPaddingScheme,
			Handler:       authHandler(func(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {}),
			Logger:        logger.NOP(),
		})
		if err != nil {
			t.Fatal(err)
		}
		conn := &authenticationErrorConn{authenticationFixtureConn{bytes.NewReader(input)}, fault}
		err = s.NewConnection(context.Background(), conn, M.Socksaddr{}, nil)
		if !errors.Is(err, fault) {
			t.Fatalf("length %d lost read error: %v", length, err)
		}
	}
}
