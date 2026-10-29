package listener

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"github.com/pires/go-proxyproto"
)

type proxyTestEvent struct {
	metadata adapter.InboundContext
	bindAddr netip.Addr
	payload  string
	err      error
}

// proxyTestHandler observes application bytes only after a complete accepted PROXY header.
// @author lyt
// @date 2026-10-29
type proxyTestHandler struct {
	events chan proxyTestEvent
}

func (h *proxyTestHandler) NewConnection(ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext, _ N.CloseHandlerFunc,
) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var payload [4]byte
	_, err := io.ReadFull(conn, payload[:])
	h.events <- proxyTestEvent{
		metadata: metadata, bindAddr: adapter.OutboundBindAddressFrom(ctx), payload: string(payload[:]), err: err,
	}
}

func proxyTestListener(t *testing.T, options option.ListenOptions) (*Listener, *proxyTestHandler) {
	t.Helper()
	handler := &proxyTestHandler{events: make(chan proxyTestEvent, 8)}
	l := New(Options{
		Context: context.Background(), Logger: log.NewNOPFactory().Logger(),
		Network: []string{N.NetworkTCP}, Listen: options, ConnectionHandler: handler,
	})
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, handler
}

func proxyTestDial(t *testing.T, address net.Addr) *net.TCPConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.(*net.TCPConn)
}

func proxyTestHeader(t *testing.T, version byte, source, destination string) []byte {
	t.Helper()
	sourceAddr, err := net.ResolveTCPAddr("tcp", source)
	if err != nil {
		t.Fatal(err)
	}
	destinationAddr, err := net.ResolveTCPAddr("tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	header, err := proxyproto.HeaderProxyFromAddrs(version, sourceAddr, destinationAddr).Format()
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func proxyTestEventNext(t *testing.T, handler *proxyTestHandler) proxyTestEvent {
	t.Helper()
	select {
	case event := <-handler.events:
		if event.err != nil {
			t.Fatalf("application read failed: %v", event.err)
		}
		return event
	case <-time.After(time.Second):
		t.Fatal("connection did not reach the application handler")
		return proxyTestEvent{}
	}
}

func TestProxyProtocolAddressAndBufferedPayload(t *testing.T) {
	for _, test := range []struct {
		name    string
		version byte
		source  string
		target  string
	}{
		{name: "v1_ipv4", version: 1, source: "198.51.100.7:23456", target: "203.0.113.22:443"},
		{name: "v2_ipv4", version: 2, source: "198.51.100.8:23457", target: "203.0.113.23:443"},
		{name: "v1_ipv6", version: 1, source: "[2001:db8::7]:23456", target: "[2001:db8::22]:443"},
		{name: "v2_ipv6", version: 2, source: "[2001:db8::8]:23457", target: "[2001:db8::23]:443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			l, handler := proxyTestListener(t, option.ListenOptions{ProxyProtocol: true, AutoOutIP: true})
			if l.TCPListener().(*proxyProtocolListener).headerTimeout != 3*time.Second {
				t.Fatal("PROXY header deadline differs from the node compatibility timeout")
			}
			client := proxyTestDial(t, l.TCPListener().Addr())
			request := append(proxyTestHeader(t, test.version, test.source, test.target), []byte("ping")...)
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			event := proxyTestEventNext(t, handler)
			if event.metadata.Source.String() != test.source || event.payload != "ping" {
				t.Fatalf("source or buffered payload changed: source=%s payload=%q", event.metadata.Source, event.payload)
			}
			if event.metadata.OriginDestination.String() != client.RemoteAddr().String() {
				t.Fatalf("PROXY destination replaced the actual local socket: %s", event.metadata.OriginDestination)
			}
			if event.bindAddr != event.metadata.OriginDestination.Addr.Unmap() {
				t.Fatalf("AutoOutIP selected a PROXY address instead of the real local address: %s", event.bindAddr)
			}
		})
	}
}

func TestProxyProtocolOptionalAndDisabled(t *testing.T) {
	localHeader, err := (&proxyproto.Header{Version: 2, Command: proxyproto.LOCAL}).Format()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		options option.ListenOptions
		request []byte
		payload string
	}{
		{name: "optional_plain", options: option.ListenOptions{ProxyProtocolAcceptNoHeader: true},
			request: []byte("ping"), payload: "ping"},
		{name: "both_flags_plain", options: option.ListenOptions{ProxyProtocol: true, ProxyProtocolAcceptNoHeader: true},
			request: []byte("ping"), payload: "ping"},
		{name: "optional_tls_prefix", options: option.ListenOptions{ProxyProtocolAcceptNoHeader: true},
			request: []byte{0x16, 0x03, 0x01, 0x00}, payload: string([]byte{0x16, 0x03, 0x01, 0x00})},
		{name: "disabled_does_not_parse", request: []byte("PROX"), payload: "PROX"},
		{name: "v1_unknown", options: option.ListenOptions{ProxyProtocol: true},
			request: []byte("PROXY UNKNOWN\r\nping"), payload: "ping"},
		{name: "v2_local", options: option.ListenOptions{ProxyProtocol: true},
			request: append(localHeader, []byte("ping")...), payload: "ping"},
	} {
		t.Run(test.name, func(t *testing.T) {
			l, handler := proxyTestListener(t, test.options)
			client := proxyTestDial(t, l.TCPListener().Addr())
			if _, err := client.Write(test.request); err != nil {
				t.Fatal(err)
			}
			event := proxyTestEventNext(t, handler)
			if event.payload != test.payload || event.metadata.Source.String() != client.LocalAddr().String() {
				t.Fatalf("ordinary TCP data or address changed: source=%s payload=%q", event.metadata.Source, event.payload)
			}
			if event.bindAddr.IsValid() {
				t.Fatal("disabled AutoOutIP unexpectedly changed the connection context")
			}
		})
	}
}

func TestProxyProtocolFragmentedHeader(t *testing.T) {
	for _, version := range []byte{1, 2} {
		client, server := net.Pipe()
		client.SetDeadline(time.Now().Add(time.Second))
		prepared := make(chan net.Conn, 1)
		failed := make(chan error, 1)
		go func() {
			conn, err := readProxyProtocolHeader(server, false, time.Second)
			if err != nil {
				server.Close()
				failed <- err
				return
			}
			prepared <- conn
		}()
		header := proxyTestHeader(t, version, "198.51.100.7:1234", "203.0.113.8:443")
		if _, err := client.Write(header[:10]); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(append(header[10:], []byte("ping")...)); err != nil {
			t.Fatal(err)
		}
		select {
		case conn := <-prepared:
			var payload [4]byte
			if _, err := io.ReadFull(conn, payload[:]); err != nil || string(payload[:]) != "ping" {
				t.Fatalf("fragmented v%d header changed the first application bytes: %q, %v", version, payload, err)
			}
			conn.Close()
		case err := <-failed:
			t.Fatalf("fragmented v%d header: %v", version, err)
		case <-time.After(time.Second):
			t.Fatalf("fragmented v%d header did not complete", version)
		}
		client.Close()
	}
}

func TestProxyProtocolRejectsMalformedAndMissingHeaders(t *testing.T) {
	badVersion := proxyTestHeader(t, 2, "198.51.100.7:1234", "203.0.113.8:443")
	badVersion[12] = 0x11
	udpHeader, err := proxyproto.HeaderProxyFromAddrs(2,
		&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 1234},
		&net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 443}).Format()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		request  []byte
		optional bool
	}{
		{name: "missing_required", request: []byte("ping")},
		{name: "invalid_address", request: []byte("PROXY TCP4 not-an-ip 203.0.113.8 1234 443\r\n")},
		{name: "overlong_v1", request: append([]byte("PROXY "), bytes.Repeat([]byte{'A'}, 110)...)},
		{name: "bad_v2_version", request: badVersion},
		{name: "udp_on_tcp_listener", request: udpHeader},
		{name: "partial_v1_optional", request: []byte("PRO"), optional: true},
		{name: "partial_v2_optional", request: proxyproto.SIGV2[:5], optional: true},
		{name: "incomplete_body_optional", request: []byte("PROXY TCP4 198.51.100.7"), optional: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			l, handler := proxyTestListener(t, option.ListenOptions{
				ProxyProtocol: true, ProxyProtocolAcceptNoHeader: test.optional,
			})
			client := proxyTestDial(t, l.TCPListener().Addr())
			client.SetDeadline(time.Now().Add(time.Second))
			client.Write(test.request)
			client.CloseWrite()
			var data [1]byte
			if _, readErr := client.Read(data[:]); readErr == nil {
				t.Fatal("invalid PROXY request was not closed")
			} else if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
				t.Fatal("invalid PROXY request remained open")
			}
			select {
			case <-handler.events:
				t.Fatal("invalid PROXY bytes reached the application handler")
			default:
			}
		})
	}
}

// proxyObservedConn exposes header read progress without timing-based sleeps.
// @author lyt
// @date 2026-10-29
type proxyObservedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *proxyObservedConn) Read(data []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(data)
}

type proxyObservedListener struct {
	net.Listener
	started chan struct{}
	once    sync.Once
}

func (l *proxyObservedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.once.Do(func() { conn = &proxyObservedConn{Conn: conn, started: l.started} })
	return conn, nil
}

func TestProxyProtocolSlowHeaderAndShutdown(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	l := newProxyProtocolListener(&proxyObservedListener{Listener: raw, started: started}, true, 10*time.Second)
	t.Cleanup(func() { l.Close() })
	slow := proxyTestDial(t, raw.Addr())
	if _, err = slow.Write([]byte("PROXY TCP4 ")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("slow connection was not being parsed")
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := l.Accept()
		accepted <- conn
	}()
	fast := proxyTestDial(t, raw.Addr())
	request := append(proxyTestHeader(t, 1, "198.51.100.7:1234", "203.0.113.8:443"), []byte("ping")...)
	if _, err = fast.Write(request); err != nil {
		t.Fatal(err)
	}
	var active net.Conn
	select {
	case active = <-accepted:
		if active == nil {
			t.Fatal("ready connection was rejected")
		}
		t.Cleanup(func() { active.Close() })
	case <-time.After(time.Second):
		t.Fatal("slow PROXY header blocked a later complete connection")
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	slow.SetReadDeadline(time.Now().Add(time.Second))
	var data [4]byte
	if _, err = slow.Read(data[:]); err == nil {
		t.Fatal("listener shutdown did not close a pending header")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("shutdown waited for the pending header timeout")
	}
	active.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = io.ReadFull(active, data[:]); err != nil || string(data[:]) != "ping" {
		t.Fatalf("listener close changed an already accepted connection: data=%q err=%v", data, err)
	}
	if _, err = l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after shutdown returned %v", err)
	}
}

func TestProxyProtocolPartialHeaderTimesOut(t *testing.T) {
	for _, optional := range []bool{false, true} {
		t.Run(fmtProxyMode(optional), func(t *testing.T) {
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			l := newProxyProtocolListener(raw, optional, 50*time.Millisecond)
			t.Cleanup(func() { l.Close() })
			client := proxyTestDial(t, raw.Addr())
			client.SetDeadline(time.Now().Add(time.Second))
			client.Write([]byte("PRO"))
			var data [1]byte
			if _, err = client.Read(data[:]); err == nil {
				t.Fatal("partial header did not time out")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("header deadline did not close the peer")
			}
			select {
			case <-l.ready:
				t.Fatal("partial header reached application accept")
			default:
			}
		})
	}
}

func fmtProxyMode(optional bool) string {
	if optional {
		return "optional"
	}
	return "required"
}
