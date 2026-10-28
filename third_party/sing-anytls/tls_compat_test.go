package anytls_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// TestTLSModeMatrix covers real TLS and simultaneous streams in all local modes.
// The separate TestUnmodifiedUpstreamInterop supplies actual upstream evidence.
// @author lyt
// @date 2026-10-28
func TestTLSModeMatrix(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}))
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	trust.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for _, mode := range []struct {
		name           string
		client, server bool
	}{
		{"standard", false, false}, {"server-only", false, true},
		{"client-only", true, false}, {"both-enhanced", true, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			server, err := anytls.NewService(anytls.ServiceConfig{
				Users:         []anytls.User{{Name: "test", Password: "tls-test-password"}},
				PaddingScheme: padding.DefaultPaddingScheme, Handler: compatibilityEcho{},
				Logger: logger.NOP(), EnhancedPadding: mode.server,
			})
			if err != nil {
				t.Fatal(err)
			}
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var accepted sync.WaitGroup
			acceptDone := make(chan struct{})
			go func() {
				defer close(acceptDone)
				for {
					conn, acceptErr := listener.Accept()
					if acceptErr != nil {
						return
					}
					accepted.Add(1)
					go func() {
						defer accepted.Done()
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
						_ = server.NewConnection(ctx, conn, M.Socksaddr{}, nil)
					}()
				}
			}()
			client, err := anytls.NewClient(ctx, anytls.ClientConfig{
				Password: "tls-test-password", Logger: logger.NOP(), EnhancedPadding: mode.client,
				DialOut: func(ctx context.Context) (net.Conn, error) {
					return (&tls.Dialer{Config: &tls.Config{
						RootCAs: trust, ServerName: "localhost", MinVersion: tls.VersionTLS12,
					}}).DialContext(ctx, "tcp", listener.Addr().String())
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = client.Close()
				_ = listener.Close()
				<-acceptDone
				accepted.Wait()
			}()
			var streams sync.WaitGroup
			for index := 0; index < 3; index++ {
				streams.Add(1)
				go func(index int) {
					defer streams.Done()
					conn, createErr := client.CreateProxy(ctx, M.ParseSocksaddr("example.com:443"))
					if createErr != nil {
						t.Error(createErr)
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					payload := bytes.Repeat([]byte{byte(index + 1)}, 8192)
					for round := 0; round < 16; round++ {
						n, writeErr := conn.Write(payload)
						if writeErr != nil || n != len(payload) {
							t.Errorf("write count %d error %v", n, writeErr)
							return
						}
						response := make([]byte, len(payload))
						if _, readErr := io.ReadFull(conn, response); readErr != nil {
							t.Error(readErr)
							return
						}
						if !bytes.Equal(payload, response) {
							t.Error("TLS payload mismatch")
							return
						}
					}
				}(index)
			}
			streams.Wait()
		})
	}
}
