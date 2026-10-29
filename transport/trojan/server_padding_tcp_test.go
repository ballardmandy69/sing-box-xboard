package trojan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// paddingTCPHandler exercises authenticated TCP payloads over the actual Trojan service.
// @author lyt
// @date 2026-10-29
type paddingTCPHandler struct {
	writeCount int
	length     int
	err        error
	called     bool
}

func (h *paddingTCPHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _, _ M.Socksaddr,
	_ N.CloseHandlerFunc,
) {
	h.called = true
	if name, ok := auth.UserFromContext[string](ctx); !ok || name != "user" {
		h.err = errors.New("lost authenticated identity")
		return
	}
	payload := make([]byte, h.length)
	if _, h.err = io.ReadFull(conn, payload); h.err != nil {
		return
	}
	for range h.writeCount {
		var n int
		n, h.err = conn.Write(payload)
		if h.err != nil {
			return
		}
		if n != len(payload) {
			h.err = io.ErrShortWrite
			return
		}
	}
}

func (h *paddingTCPHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr,
	M.Socksaddr, N.CloseHandlerFunc,
) {
	h.called = true
	h.err = errors.New("UDP reached the application handler")
}

func TestServerPaddingActualTCPRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name        string
		padding     bool
		destination string
		segmented   bool
	}{
		{"disabled", false, "example.test:443", false},
		{"enabled", true, "example.test:443", true},
		{"special mux hostname", true, "sp.mux.sing-box.arpa:443", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			handler := &paddingTCPHandler{writeCount: 20, length: 64}
			service := NewService[string](handler, nil, nil)
			service.SetServerPadding(test.padding)
			if err = service.UpdateUsers([]string{"user"}, []string{"test-secret"}); err != nil {
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
				recording := &paddingRecordingConn{Conn: conn, write: func(_ int, data []byte) (int, error) {
					return conn.Write(data)
				}}
				serviceErr := service.NewConnection(context.Background(), recording,
					M.SocksaddrFromNet(conn.RemoteAddr()), nil)
				sizes = recording.sizes
				finished <- errors.Join(serviceErr, handler.err)
			}()
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			client := NewClientConn(conn, Key("test-secret"), M.ParseSocksaddr(test.destination))
			payload := bytes.Repeat([]byte("abcd"), 16)
			if _, err = client.Write(payload); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 20*len(payload))
			if _, err = io.ReadFull(client, response); err != nil {
				t.Fatal(err)
			}
			if err = <-finished; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(response, bytes.Repeat(payload, 20)) {
				t.Fatal("segmentation added, removed or reordered business payload bytes")
			}
			var expected []int
			for ordinal := 1; ordinal <= 20; ordinal++ {
				switch {
				case !test.segmented || ordinal == 20:
					expected = append(expected, 64)
				case ordinal == 1:
					expected = append(expected, 40, 9, 15)
				default:
					expected = append(expected, 9, 17, 38)
				}
			}
			if !reflect.DeepEqual(sizes, expected) {
				t.Fatalf("actual downstream writes=%v want=%v", sizes, expected)
			}
		})
	}
}

func TestServiceAndTrojanGoMuxRejectUDP(t *testing.T) {
	for _, muxStream := range []bool{false, true} {
		t.Run(fmt.Sprintf("mux=%v", muxStream), func(t *testing.T) {
			var request bytes.Buffer
			if !muxStream {
				key := Key("secret")
				request.Write(key[:])
				request.Write(CRLF)
			}
			request.WriteByte(CommandUDP)
			if err := M.SocksaddrSerializer.WriteAddrPort(&request, M.ParseSocksaddr("example.test:53")); err != nil {
				t.Fatal(err)
			}
			if !muxStream {
				request.Write(CRLF)
			}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			server.SetDeadline(time.Now().Add(3 * time.Second))
			written := make(chan error, 1)
			go func() {
				_, err := client.Write(request.Bytes())
				written <- err
			}()
			handler := new(paddingTCPHandler)
			var err error
			if muxStream {
				err = newMuxConnection0(context.Background(), server, M.Socksaddr{}, handler)
			} else {
				service := NewService[string](handler, nil, nil)
				service.SetServerPadding(true)
				if err = service.UpdateUsers([]string{"user"}, []string{"secret"}); err != nil {
					t.Fatal(err)
				}
				err = service.NewConnection(context.Background(), server, M.Socksaddr{}, nil)
			}
			if !errors.Is(err, ErrUDPDisabled) || handler.called {
				t.Fatalf("UDP rejection failed: error=%v called=%v", err, handler.called)
			}
			server.Close()
			if err = <-written; err != nil {
				t.Fatal(err)
			}
		})
	}
}
