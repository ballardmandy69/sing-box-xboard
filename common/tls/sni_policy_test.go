package tls

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// sniPeerConn supplies a deterministic peer address while retaining a real TLS byte stream.
// @author lyt
// @date 2026-10-29
type sniPeerConn struct {
	net.Conn
	peer net.Addr
}

func (c sniPeerConn) RemoteAddr() net.Addr { return c.peer }

func TestSNIPolicyHandshake(t *testing.T) {
	certificate, err := GenerateKeyPair(nil, nil, time.Now, "allowed.test")
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	options := option.InboundTLSOptions{
		Enabled: true,
		Certificate: []string{string(pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: certificate.Certificate[0],
		}))},
		Key: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))},
	}
	for _, test := range []struct {
		name, policy, serverName, peer string
		allowed                        bool
	}{
		{"match", `^allowed\.test$`, "allowed.test", "192.0.2.1", true},
		{"mismatch", `^allowed\.test$`, "denied.test", "192.0.2.1", false},
		{"empty SNI", `^allowed\.test$`, "", "192.0.2.1", false},
		{"IPv6 default", `^allowed\.test$`, "denied.test", "2001:db8::1", false},
		{"IPv6 bypass", "skip-ipv6\n^allowed\\.test$", "denied.test", "2001:db8::1", true},
		{"mapped IPv4", "skip-ipv6\n^allowed\\.test$", "denied.test", "::ffff:192.0.2.1", false},
		{"exact directive", "skip-ipv6 \n^allowed\\.test$", "denied.test", "2001:db8::1", false},
		{"only final line regex", "ignored\n^allowed\\.test$", "allowed.test", "192.0.2.1", true},
		{"trailing newline is empty regex", "^allowed\\.test$\n", "denied.test", "192.0.2.1", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			options.SNIRegex = test.policy
			server, err := NewSTDServer(context.Background(), log.NewNOPFactory().Logger(), options)
			if err != nil {
				t.Fatal(err)
			}
			// Config cloning must retain the gate as it does during certificate reload.
			server.SetServerName("configuration.test")
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			peer := &net.TCPAddr{IP: net.ParseIP(test.peer), Port: 12345}
			serverConn, err := server.Server(sniPeerConn{Conn: left, peer: peer})
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- serverConn.HandshakeContext(ctx) }()
			client := stdtls.Client(right, &stdtls.Config{ServerName: test.serverName, InsecureSkipVerify: true})
			clientErr := client.HandshakeContext(ctx)
			serverErr := <-result
			if (clientErr == nil && serverErr == nil) != test.allowed {
				t.Fatalf("allowed=%v client=%v server=%v", test.allowed, clientErr, serverErr)
			}
		})
	}
	options.SNIRegex = "["
	if _, err := NewSTDServer(context.Background(), log.NewNOPFactory().Logger(), options); err == nil {
		t.Fatal("invalid regex must fail construction without a panic")
	}
}

func TestSNIPolicyDoesNotApplyToGeneratedCertificates(t *testing.T) {
	_, err := NewSTDServer(context.Background(), log.NewNOPFactory().Logger(), option.InboundTLSOptions{
		Enabled: true, Insecure: true, SNIRegex: "[",
	})
	if err != nil {
		t.Fatalf("original generated-certificate path should ignore SNI policy: %v", err)
	}
}
