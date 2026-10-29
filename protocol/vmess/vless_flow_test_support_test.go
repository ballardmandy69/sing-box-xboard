package vmess_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// runVLESSFlowMatrix uses real TLS/VLESS clients to verify the legacy node-level policy.
// @author lyt
// @date 2026-10-29
func runVLESSFlowMatrix(t *testing.T, flows []string) {
	certificate, key := flowCertificate(t)
	for _, mode := range []struct {
		name       string
		managed    bool
		force      any
		staticFlow string
		acceptNone bool
		acceptXTLS bool
	}{
		{"managed-default", true, nil, "", true, true},
		{"managed-required", true, true, "", false, true},
		{"static-default", false, nil, "", true, false},
		{"static-explicit-vision", false, nil, "xtls-rprx-vision", false, true},
		{"static-compatible", false, false, "", true, true},
		{"static-required", false, true, "", false, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			const credential = "61552c7d-d297-4593-86dd-62c57d01afbb"
			port := identityFreePort(t)
			inboundOptions := map[string]any{
				"type": "vless", "tag": "managed", "listen": "127.0.0.1", "listen_port": port,
				"tls": map[string]any{"enabled": true, "certificate": []string{certificate}, "key": []string{key}},
			}
			if mode.force != nil {
				inboundOptions["force_vision"] = mode.force
			}
			if !mode.managed {
				inboundOptions["users"] = []any{map[string]any{
					"name": "static", "uuid": credential, "flow": mode.staticFlow,
				}}
			}
			server := identityBox(t, map[string]any{
				"inbounds": []any{inboundOptions}, "outbounds": []any{map[string]any{"type": "direct"}},
			})
			if mode.managed {
				inbound, _ := server.Inbound().Get("managed")
				managed := inbound.(adapter.ManagedSSMServer)
				for range 2 {
					if err := managed.UpdateUsers([]string{"42@panel@uniproxy"}, []string{credential}); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, flow := range flows {
				t.Run("flow="+flow, func(t *testing.T) {
					client := identityBox(t, map[string]any{"outbounds": []any{map[string]any{
						"type": "vless", "tag": "client", "server": "127.0.0.1", "server_port": port,
						"uuid": credential, "flow": flow,
						"tls": map[string]any{
							"enabled": true, "server_name": "flow.test", "certificate": []string{certificate},
						},
					}}})
					outbound, _ := client.Outbound().Outbound("client")
					wantSuccess := mode.acceptNone
					if flow != "" {
						wantSuccess = mode.acceptXTLS
					}
					err, dialed := flowExchange(t, outbound)
					if (err == nil) != wantSuccess {
						t.Fatalf("accepted=%v want=%v: %v", err == nil, wantSuccess, err)
					}
					if !wantSuccess && dialed {
						t.Fatal("rejected flow reached its destination")
					}
				})
			}
		})
	}
}

func flowCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"flow.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func flowExchange(t *testing.T, outbound adapter.Outbound) (error, bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- struct{}{}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			io.Copy(conn, conn)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, M.SocksaddrFromNet(listener.Addr()))
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload := []byte("client-selected VLESS flow")
		_, err = conn.Write(payload)
		if err == nil {
			response := make([]byte, len(payload))
			_, err = io.ReadFull(conn, response)
			if err == nil && !bytes.Equal(response, payload) {
				err = fmt.Errorf("VLESS flow payload mismatch")
			}
		}
	}
	select {
	case <-accepted:
		return err, true
	default:
		return err, false
	}
}
