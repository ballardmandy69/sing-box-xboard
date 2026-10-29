package trojan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/trojan"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// privateTrojanRouter preserves a complete authenticated TCP payload at the routing boundary.
// @author lyt
// @date 2026-10-29
type privateTrojanRouter struct {
	adapter.Router
	called   bool
	metadata adapter.InboundContext
	err      error
}

func (r *privateTrojanRouter) RouteConnectionEx(_ context.Context, conn net.Conn,
	metadata adapter.InboundContext, _ N.CloseHandlerFunc,
) {
	r.called, r.metadata = true, metadata
	data := make([]byte, 64)
	if _, r.err = io.ReadFull(conn, data); r.err == nil {
		_, r.err = conn.Write(data)
	}
}

// privateTrojanWriteRecorder records transport writes without replacing their TCP behavior.
// @author lyt
// @date 2026-10-29
type privateTrojanWriteRecorder struct {
	net.Conn
	sizes []int
}

func (c *privateTrojanWriteRecorder) Write(data []byte) (int, error) {
	c.sizes = append(c.sizes, len(data))
	return c.Conn.Write(data)
}

func TestPrivateTrojanOptionsActualTCP(t *testing.T) {
	for _, test := range []struct {
		name        string
		listen      string
		forceMux    bool
		padding     bool
		destination string
		reject      bool
		segments    []int
	}{
		{"default IPv4", "127.0.0.1:0", false, false, "example.test:443", false, []int{64}},
		{"padding IPv4", "127.0.0.1:0", false, true, "example.test:443", false, []int{40, 9, 15}},
		{"force IPv4", "127.0.0.1:0", true, true, "example.test:443", true, nil},
		{"force IPv6", "[::1]:0", true, true, "example.test:443", false, []int{40, 9, 15}},
		{"mux bypasses both", "127.0.0.1:0", true, true, "sp.mux.sing-box.arpa:443", false, []int{64}},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", test.listen)
			if err != nil {
				if test.listen == "[::1]:0" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer listener.Close()
			router := new(privateTrojanRouter)
			inbound, err := NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "private-trojan",
				option.TrojanInboundOptions{
					Users:    []option.TrojanUser{{Name: "panel-user", Password: "test-secret"}},
					ForceMux: test.forceMux, ServerPadding: test.padding,
				})
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			var sizes []int
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					finished <- acceptErr
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				recording := &privateTrojanWriteRecorder{Conn: conn}
				var closeErr error
				inbound.(*Inbound).NewConnection(context.Background(), recording,
					adapter.InboundContext{Source: M.SocksaddrFromNet(conn.RemoteAddr())},
					func(err error) { closeErr = err })
				sizes = recording.sizes
				finished <- errors.Join(closeErr, router.err)
			}()
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			client := T.NewClientConn(conn, T.Key("test-secret"), M.ParseSocksaddr(test.destination))
			payload := bytes.Repeat([]byte("abcd"), 16)
			_, writeErr := client.Write(payload)
			response := make([]byte, len(payload))
			_, readErr := io.ReadFull(client, response)
			serverErr := <-finished
			if test.reject {
				if !errors.Is(serverErr, T.ErrForceMux) || router.called || readErr == nil {
					t.Fatalf("IPv4 gate failed: server=%v routed=%v read=%v", serverErr, router.called, readErr)
				}
				return
			}
			if writeErr != nil || readErr != nil || serverErr != nil || !router.called ||
				router.metadata.User != "panel-user" || router.metadata.Inbound != "private-trojan" ||
				!bytes.Equal(response, payload) || !reflect.DeepEqual(sizes, test.segments) {
				t.Fatalf("TCP behavior changed: write=%v read=%v server=%v routed=%v sizes=%v",
					writeErr, readErr, serverErr, router.called, sizes)
			}
		})
	}
}
