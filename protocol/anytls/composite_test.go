package anytls

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// compositeEchoRouter deliberately takes ownership asynchronously to catch premature physical Close.
// @author lyt
// @date 2026-10-29
type compositeEchoRouter struct {
	adapter.Router
	metadata chan adapter.InboundContext
}

func (r *compositeEchoRouter) RouteConnectionEx(ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext, onClose N.CloseHandlerFunc,
) {
	r.metadata <- metadata
	go func() {
		_, err := io.Copy(conn, conn)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func compositeInboundForTest(t *testing.T, fallback string, encrypted bool) (*Inbound, *compositeEchoRouter, string) {
	t.Helper()
	router := &compositeEchoRouter{metadata: make(chan adapter.InboundContext, 32)}
	opts := option.AnyTLSInboundOptions{
		Users:           []option.AnyTLSUser{{Name: "panel-user", Password: "composite-password"}},
		FallbackService: fallback,
	}
	if encrypted {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		certificate := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
			DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute),
			NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		opts.TLS = &option.InboundTLSOptions{
			Enabled:     true,
			Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))},
			Key:         []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))},
		}
	}
	result, err := NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "composite", opts)
	if err != nil {
		t.Fatal(err)
	}
	inbound := result.(*Inbound)
	if inbound.tlsConfig != nil {
		if err = inbound.tlsConfig.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { inbound.tlsConfig.Close() })
	}
	return inbound, router, managedListen(t, inbound)
}

func compositeDial(t *testing.T, address string, encrypted bool) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted {
		secured := stdtls.Client(conn, &stdtls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
		secured.SetDeadline(time.Now().Add(2 * time.Second))
		if err = secured.Handshake(); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		conn = secured
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return conn
}

type compositeFragmentConn struct{ net.Conn }

func (c compositeFragmentConn) Write(p []byte) (int, error) {
	var total int
	for len(p) > 0 {
		n, err := c.Conn.Write(p[:1])
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func compositeProxy(t *testing.T, conn net.Conn, protocol, password string) net.Conn {
	t.Helper()
	destination := M.ParseSocksaddr("example.com:443")
	if protocol == "trojan" {
		digest := sha256.Sum224([]byte(password))
		var key [56]byte
		hex.Encode(key[:], digest[:])
		return trojan.NewClientConn(conn, key, destination)
	}
	key := uuid.FromStringOrNil(password)
	if key == uuid.Nil {
		key = uuid.NewV5(uuid.Nil, password)
	}
	return vless.NewConn(conn, key, vmess.CommandTCP, destination, "")
}

func compositeExchange(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	result := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, result); err != nil {
		t.Fatal(err)
	}
	if string(result) != payload {
		t.Fatalf("response %q, want %q", result, payload)
	}
}

func TestCompositeProtocolsShareOneTCPListener(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plain"
		if encrypted {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			_, router, address := compositeInboundForTest(t, "trojan-vless", encrypted)
			for _, protocol := range []string{"trojan", "vless", "anytls"} {
				if protocol == "anytls" {
					client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
						Password: "composite-password", Logger: log.NewNOPFactory().Logger(),
						DialOut: func(context.Context) (net.Conn, error) {
							return compositeFragmentConn{compositeDial(t, address, encrypted)}, nil
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { client.Close() })
					if err = managedExchange(client, "anytls-coalesced-frame"); err != nil {
						t.Fatal(err)
					}
				} else {
					conn := compositeProxy(t, compositeFragmentConn{compositeDial(t, address, encrypted)},
						protocol, "composite-password")
					compositeExchange(t, conn, "first application payload")
					compositeExchange(t, conn, "second application payload after parser returned")
					conn.Close()
				}
				select {
				case metadata := <-router.metadata:
					if metadata.InboundType != protocol || metadata.User != "panel-user" || metadata.Inbound != "composite" {
						t.Fatalf("wrong routed identity/type: %+v", metadata)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("missing routed metadata")
				}
			}
		})
	}
}

func TestCompositeSharedHotUpdateRevokesFallbackSessions(t *testing.T) {
	h, _, address := compositeInboundForTest(t, "trojan-vless", false)
	if err := h.UpdateUsers([]string{"managed"}, []string{"old-password"}); err != nil {
		t.Fatal(err)
	}
	var previous []net.Conn
	for _, protocol := range []string{"trojan", "vless"} {
		conn := compositeProxy(t, compositeDial(t, address, false), protocol, "old-password")
		compositeExchange(t, conn, "before-update")
		previous = append(previous, conn)
	}
	if err := h.UpdateUsers([]string{"managed"}, []string{"new-password"}); err != nil {
		t.Fatal(err)
	}
	for _, conn := range previous {
		var data [1]byte
		if _, err := conn.Read(data[:]); err == nil {
			t.Fatal("revoked fallback connection remains open")
		}
	}
	for _, protocol := range []string{"trojan", "vless"} {
		conn := compositeProxy(t, compositeDial(t, address, false), protocol, "new-password")
		compositeExchange(t, conn, "after-update")
		conn.Close()
	}
	client, _ := managedClient(t, address, "new-password")
	if err := managedExchange(client, "updated-anytls"); err != nil {
		t.Fatal(err)
	}
}

// compositePrefixConn makes read boundaries and deadline operations observable without clock sleeps.
// @author lyt
// @date 2026-10-29
type compositePrefixConn struct {
	net.Conn
	input     []byte
	chunk     int
	dataEOF   bool
	deadlines []time.Time
}

func (c *compositePrefixConn) SetReadDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return nil
}

func (c *compositePrefixConn) Read(p []byte) (int, error) {
	if len(c.input) == 0 {
		return 0, io.EOF
	}
	if c.chunk > 0 && len(p) > c.chunk {
		p = p[:c.chunk]
	}
	n := copy(p, c.input)
	c.input = c.input[n:]
	if c.dataEOF && len(c.input) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestCompositePrefixClassificationPreservesBytesAndDeadline(t *testing.T) {
	s := &compositeService{trojan: new(trojan.Service[string]), vless: new(vless.Service[string])}
	s.updateUsers([]option.AnyTLSUser{{Name: "user", Password: "password"}})
	sha := sha256.Sum256([]byte("password"))
	key := uuid.NewV5(uuid.Nil, "password")
	trojanDigest := sha256.Sum224([]byte("password"))
	var trojanHeader [58]byte
	hex.Encode(trojanHeader[:56], trojanDigest[:])
	copy(trojanHeader[56:], "\r\n")
	headers := map[string][]byte{
		"anytls": sha[:], "trojan": trojanHeader[:],
		"vless": append(append([]byte{0}, key[:]...), 0),
	}
	for protocol, header := range headers {
		for _, chunk := range []int{1, 17, 18, 31, 32, 56, 57, 58, 256} {
			original := append(bytes.Clone(header), []byte("coalesced-payload")...)
			raw := &compositePrefixConn{input: bytes.Clone(original), chunk: chunk, dataEOF: true}
			start := time.Now()
			conn, got, err := s.users.selectConnection(raw)
			if err != nil || got != protocol {
				t.Fatalf("%s chunk %d: %s %v", protocol, chunk, got, err)
			}
			data, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(data, original) {
				t.Fatalf("%s lost bytes: %x %v", protocol, data, err)
			}
			if len(raw.deadlines) != 2 || !raw.deadlines[1].IsZero() ||
				raw.deadlines[0].Before(start.Add(5*time.Second)) || raw.deadlines[0].After(time.Now().Add(5*time.Second)) {
				t.Fatalf("deadline was extended or not cleared: %v", raw.deadlines)
			}
		}
	}
	for _, length := range []int{17, 31, 57, 58} {
		raw := &compositePrefixConn{input: bytes.Repeat([]byte{'!'}, length), chunk: 1}
		_, _, err := s.users.selectConnection(raw)
		want := io.EOF
		if length == 58 {
			want = os.ErrInvalid
		}
		if !errors.Is(err, want) || len(raw.deadlines) != 1 {
			t.Fatalf("length %d: %v deadlines=%v", length, err, raw.deadlines)
		}
	}
}

func TestCompositeVLESSCredentialConversionAndSelectionPriority(t *testing.T) {
	s := &compositeService{trojan: new(trojan.Service[string]), vless: new(vless.Service[string])}
	zero := "00000000-0000-0000-0000-000000000000"
	s.updateUsers([]option.AnyTLSUser{{Name: "first", Password: zero}, {Name: "last", Password: zero}})
	if s.users.vless[uuid.NewV5(uuid.Nil, zero)] != "last" {
		t.Fatal("nil UUID fallback or last credential precedence differs")
	}
	var prefix [58]byte
	copy(prefix[56:], "\r\n")
	s.users.anytls[[32]byte(prefix[:32])] = "anytls"
	s.users.vless[[16]byte(prefix[1:17])] = "vless"
	s.users.trojan[[56]byte(prefix[:56])] = "trojan"
	protocol, _, _ := s.users.classify(prefix[:])
	if protocol != "anytls" {
		t.Fatalf("first classifier = %s", protocol)
	}
	delete(s.users.anytls, [32]byte(prefix[:32]))
	protocol, _, _ = s.users.classify(prefix[:])
	if protocol != "vless" {
		t.Fatalf("second classifier = %s", protocol)
	}
}

func TestCompositeAuthenticatorNeverTrustsContextIdentity(t *testing.T) {
	h, _, _ := compositeInboundForTest(t, "trojan-vless", false)
	ctx := auth.ContextWithUser(context.Background(), "panel-user")
	var anytlsHeader [34]byte
	copy(anytlsHeader[:32], bytes.Repeat([]byte{1}, 32))
	if err := h.service.NewConnection(ctx, &compositePrefixConn{input: anytlsHeader[:]}, M.Socksaddr{}, nil); err == nil {
		t.Fatal("ordinary AnyTLS entry trusted a context identity")
	}
	var request bytes.Buffer
	if err := vless.WriteRequest(&request, vless.Request{
		UUID: uuid.NewV5(uuid.Nil, "unknown-password"), Command: vmess.CommandTCP,
		Destination: M.ParseSocksaddr("example.com:443"),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.composite.vless.NewConnection(ctx, &compositePrefixConn{input: request.Bytes()},
		M.Socksaddr{}, nil); err == nil {
		t.Fatal("ordinary VLESS entry trusted a context identity")
	}
	stop := errors.New("stop after authentication")
	called := false
	err := h.service.NewConnectionWithAuthenticator(ctx, &compositePrefixConn{input: anytlsHeader[:]},
		M.Socksaddr{}, nil, func(key [32]byte) (string, bool) {
			called = key[0] == 1
			return "snapshot-user", true
		}, func(ctx context.Context) error {
			user, _ := auth.UserFromContext[string](ctx)
			if user != "snapshot-user" {
				t.Fatalf("wrong authenticated identity: %q", user)
			}
			return stop
		})
	if !called || !errors.Is(err, stop) {
		t.Fatalf("wire lookup was not applied: called=%v error=%v", called, err)
	}
}

func TestCompositeRejectsUDPWithoutRouting(t *testing.T) {
	_, router, address := compositeInboundForTest(t, "vless", false)
	conn := compositeDial(t, address, false)
	if err := vless.WritePacketRequest(conn, vless.Request{
		UUID: uuid.NewV5(uuid.Nil, "composite-password"), Command: vmess.CommandUDP,
		Destination: M.ParseSocksaddr("example.com:53"),
	}, nil); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := conn.Read(data[:]); err == nil {
		t.Fatal("UDP command was accepted")
	}
	select {
	case metadata := <-router.metadata:
		t.Fatalf("UDP reached TCP router: %+v", metadata)
	default:
	}
}

func TestCompositeConfiguredFallbacksAndForceMuxScope(t *testing.T) {
	for _, fallback := range []string{"", "trojan", "vless", "trojan-vless"} {
		t.Run(fallback, func(t *testing.T) {
			h, _, address := compositeInboundForTest(t, fallback, false)
			if (h.composite.trojan != nil) != (fallback == "trojan" || fallback == "trojan-vless") ||
				(h.composite.vless != nil) != (fallback == "vless" || fallback == "trojan-vless") {
				t.Fatal("unexpected fallback service combination")
			}
			for _, protocol := range []string{"trojan", "vless"} {
				if (protocol == "trojan" && h.composite.trojan == nil) ||
					(protocol == "vless" && h.composite.vless == nil) {
					continue
				}
				conn := compositeProxy(t, compositeDial(t, address, false), protocol, "composite-password")
				compositeExchange(t, conn, "configured fallback")
				conn.Close()
			}
		})
	}
	if _, err := NewInbound(context.Background(), &compositeEchoRouter{}, log.NewNOPFactory().Logger(), "bad",
		option.AnyTLSInboundOptions{FallbackService: "Trojan"}); err == nil {
		t.Fatal("unknown fallback was accepted")
	}
	h, _, address := compositeInboundForTest(t, "trojan-vless", false)
	h.composite.forceMux = true
	trojanConn := compositeProxy(t, compositeDial(t, address, false), "trojan", "composite-password")
	if _, err := trojanConn.Write([]byte("reject non-mux")); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := trojanConn.Read(data[:]); err == nil {
		t.Fatal("non-Mux IPv4 Trojan was accepted")
	}
	vlessConn := compositeProxy(t, compositeDial(t, address, false), "vless", "composite-password")
	compositeExchange(t, vlessConn, "VLESS is not affected by ForceMuxForTrojan")
	vlessConn.Close()
	client, _ := managedClient(t, address, "composite-password")
	if err := managedExchange(client, "AnyTLS is not affected by ForceMuxForTrojan"); err != nil {
		t.Fatal(err)
	}
}
