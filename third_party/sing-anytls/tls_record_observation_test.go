package anytls_test

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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// recordCapture parses TLS record headers below crypto/tls, not application
// writes or TCP packet boundaries. It retains sizes only, never credentials.
// @author lyt
// @date 2026-10-28
type recordCapture struct {
	sync.Mutex
	buffer  []byte
	bytes   int64
	lengths []int
}

func (o *recordCapture) observeLocked(data []byte) {
	o.bytes += int64(len(data))
	o.buffer = append(o.buffer, data...)
	for len(o.buffer) >= 5 {
		length := int(binary.BigEndian.Uint16(o.buffer[3:5]))
		if len(o.buffer) < length+5 {
			break
		}
		if o.buffer[0] == 23 {
			o.lengths = append(o.lengths, length)
		}
		o.buffer = o.buffer[length+5:]
	}
}

func (o *recordCapture) summary() recordSummary {
	o.Lock()
	defer o.Unlock()
	lengths := append([]int(nil), o.lengths...)
	sort.Ints(lengths)
	s := recordSummary{WireBytes: o.bytes, Records: len(lengths)}
	if len(lengths) > 0 {
		s.Min = lengths[0]
		s.P50 = lengths[(len(lengths)-1)/2]
		s.P95 = lengths[((len(lengths)*95+99)/100)-1]
		s.Max = lengths[len(lengths)-1]
	}
	for _, length := range lengths {
		switch {
		case length <= 255:
			s.Buckets[0]++
		case length <= 1023:
			s.Buckets[1]++
		case length <= 4095:
			s.Buckets[2]++
		default:
			s.Buckets[3]++
		}
	}
	return s
}

type recordSummary struct {
	WireBytes int64  `json:"wire_bytes"`
	Records   int    `json:"encrypted_records"`
	Min       int    `json:"min"`
	P50       int    `json:"p50"`
	P95       int    `json:"p95"`
	Max       int    `json:"max"`
	Buckets   [4]int `json:"buckets_le255_le1023_le4095_gt4095"`
}

type capturedTLSConn struct {
	net.Conn
	observer *recordCapture
}

func (c *capturedTLSConn) Write(data []byte) (int, error) {
	c.observer.Lock()
	defer c.observer.Unlock()
	n, err := c.Conn.Write(data)
	if n > 0 {
		c.observer.observeLocked(data[:n])
	}
	return n, err
}

type verifiedEcho struct {
	result chan [sha256.Size]byte
}

func (e verifiedEcho) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr,
	destination M.Socksaddr, onClose N.CloseHandlerFunc,
) {
	defer conn.Close()
	hash := sha256.New()
	_, _ = io.Copy(conn, io.TeeReader(conn, hash))
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	e.result <- digest
}

func recordTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, err := tls.X509KeyPair(certPEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}))
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM(certPEM) {
		t.Fatal("certificate import failed")
	}
	return pair, trust
}

// TestTLSRecordObservations is an opt-in verbose observation report and a payload
// integrity test. Local loopback rates are not WAN or anti-classification claims.
// Run: go test github.com/anytls/sing-anytls -run TestTLSRecordObservations -v -count=1
func TestTLSRecordObservations(t *testing.T) {
	pair, trust := recordTestCertificate(t)
	for _, mode := range []struct {
		name           string
		client, server bool
	}{
		{"standard", false, false}, {"server-only", false, true},
		{"client-only", true, false}, {"both-enhanced", true, true},
	} {
		for _, size := range []int{1024, 32768} {
			t.Run(fmt.Sprintf("%s/%d", mode.name, size), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				clientCapture, serverCapture := new(recordCapture), new(recordCapture)
				results := make(chan [sha256.Size]byte, 1)
				server, err := anytls.NewService(anytls.ServiceConfig{
					Users:         []anytls.User{{Name: "record-test", Password: "record-test-password"}},
					PaddingScheme: padding.DefaultPaddingScheme, Logger: logger.NOP(),
					Handler: verifiedEcho{results}, EnhancedPadding: mode.server,
				})
				if err != nil {
					t.Fatal(err)
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				accepted := make(chan struct{})
				go func() {
					defer close(accepted)
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(15 * time.Second))
					tlsConn := tls.Server(&capturedTLSConn{conn, serverCapture}, &tls.Config{
						Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13,
					})
					_ = server.NewConnection(ctx, tlsConn, M.Socksaddr{}, nil)
				}()
				client, err := anytls.NewClient(ctx, anytls.ClientConfig{
					Password: "record-test-password", Logger: logger.NOP(), EnhancedPadding: mode.client,
					DialOut: func(ctx context.Context) (net.Conn, error) {
						raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
						if err != nil {
							return nil, err
						}
						tlsConn := tls.Client(&capturedTLSConn{raw, clientCapture}, &tls.Config{
							RootCAs: trust, ServerName: "localhost", MinVersion: tls.VersionTLS13,
						})
						if err := tlsConn.HandshakeContext(ctx); err != nil {
							raw.Close()
							return nil, err
						}
						return tlsConn, nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { client.Close(); listener.Close(); <-accepted }()
				started := time.Now()
				conn, err := client.CreateProxy(ctx, M.ParseSocksaddr("record-test.invalid:443"))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				payload := make([]byte, size)
				if _, err := rand.Read(payload); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, size)
				sent, received := sha256.New(), sha256.New()
				var latencies []time.Duration
				const rounds = 32
				var first time.Duration
				var steadyStarted time.Time
				for i := 0; i < rounds; i++ {
					if i == 1 {
						steadyStarted = time.Now()
					}
					roundStarted := time.Now()
					n, err := conn.Write(payload)
					if err != nil || n != size {
						t.Fatalf("write n=%d err=%v", n, err)
					}
					sent.Write(payload)
					if _, err := io.ReadFull(conn, response); err != nil {
						t.Fatal(err)
					}
					received.Write(response)
					if !bytes.Equal(payload, response) {
						t.Fatal("echo payload corrupted")
					}
					if i == 0 {
						first = time.Since(started)
					} else {
						latencies = append(latencies, time.Since(roundStarted))
					}
				}
				elapsed := time.Since(steadyStarted)
				up, down := clientCapture.summary(), serverCapture.summary()
				conn.Close()
				select {
				case digest := <-results:
					if !bytes.Equal(digest[:], sent.Sum(nil)) || !bytes.Equal(sent.Sum(nil), received.Sum(nil)) {
						t.Fatal("bidirectional payload hash mismatch")
					}
				case <-ctx.Done():
					t.Fatal("server hash result timed out")
				}
				sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
				business := int64(size * rounds * 2)
				report := struct {
					Scope    string  `json:"scope"`
					Mode     string  `json:"mode"`
					Payload  int     `json:"payload_bytes"`
					Rounds   int     `json:"rounds"`
					FirstMS  float64 `json:"first_request_ms_including_tls_auth"`
					P95MS    float64 `json:"steady_echo_p95_ms"`
					MiBPS    float64 `json:"steady_duplex_mib_per_s"`
					Business int64   `json:"duplex_business_bytes"`
					Ratio    float64 `json:"wire_to_business_including_tls_auth"`
					Up, Down recordSummary
				}{"localhost_tls13_not_pcap", mode.name, size, rounds,
					float64(first) / float64(time.Millisecond),
					float64(latencies[(len(latencies)*95+99)/100-1]) / float64(time.Millisecond),
					float64(size*(rounds-1)*2) / (1024 * 1024) / elapsed.Seconds(), business,
					float64(up.WireBytes+down.WireBytes) / float64(business), up, down}
				encoded, err := json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				t.Log(string(encoded))
			})
		}
	}
}
