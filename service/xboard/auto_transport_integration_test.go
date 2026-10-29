package xboard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttpupgrade"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"
)

// autoTransportTestDialer connects transport clients to the local test server.
// @author lyt
// @date 2026-10-29
type autoTransportTestDialer struct{ N.Dialer }

func (autoTransportTestDialer) DialContext(
	ctx context.Context, network string, destination M.Socksaddr,
) (net.Conn, error) {
	return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, destination.String())
}

// autoTransportRequest captures the HTTP handshake before the transport consumes it.
// @author lyt
// @date 2026-10-29
type autoTransportRequest struct {
	path      string
	earlyData []byte
	err       error
}

func autoTransportEcho(conn net.Conn, size int) error {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte{0x63}, size)
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if !bytes.Equal(payload, response) {
		return fmt.Errorf("transport changed payload bytes")
	}
	return nil
}

func newAutoWebSocketTransportTestServer(t *testing.T, ctx context.Context, network, path string) (
	option.V2RayWebsocketOptions, <-chan autoTransportRequest, *httptest.Server,
) {
	t.Helper()
	settings, err := json.Marshal(panelTransportSettings{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	transport, err := (autoConfigResponse{Network: network, NetworkSettings: settings}).transportOptions(C.TypeVMess)
	if err != nil {
		t.Fatal(err)
	}
	handler := adapter.NewUpstreamContextHandler(pendingEchoRouter{}.RouteConnectionEx, nil)
	wsServer, err := v2raywebsocket.NewServer(ctx, log.NewNOPFactory().Logger(),
		transport.WebsocketOptions, nil, handler)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan autoTransportRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, decodeErr := base64.RawURLEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Protocol"))
		requests <- autoTransportRequest{path: r.URL.RequestURI(), earlyData: data, err: decodeErr}
		wsServer.ServeHTTP(w, r)
	}))
	t.Cleanup(func() {
		server.Close()
		_ = wsServer.Close()
	})
	return transport.WebsocketOptions, requests, server
}

func TestAutoLegacyTransportWebSocketActualEarlyData(t *testing.T) {
	for _, network := range []string{"ws", "websocket"} {
		for _, path := range []string{"/socket", "/socket?ed=1", "/socket?ed=4096"} {
			for _, size := range []int{2047, 2048, 2049, 4096} {
				t.Run(fmt.Sprintf("%s/%s/%d", network, path, size), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					options, requests, server := newAutoWebSocketTransportTestServer(t, ctx, network, path)
					client, err := v2raywebsocket.NewClient(ctx, autoTransportTestDialer{},
						M.ParseSocksaddr(strings.TrimPrefix(server.URL, "http://")), options, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					conn, err := client.DialContext(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					if err = autoTransportEcho(conn, size); err != nil {
						t.Fatal(err)
					}
					select {
					case request := <-requests:
						wantEarly := min(size, 2048)
						if request.err != nil || request.path != "/socket" || len(request.earlyData) != wantEarly ||
							!bytes.Equal(request.earlyData, bytes.Repeat([]byte{0x63}, wantEarly)) {
							t.Fatalf("unexpected wire request: path=%q earlyBytes=%d err=%v",
								request.path, len(request.earlyData), request.err)
						}
					case <-ctx.Done():
						t.Fatal("websocket handshake did not reach the server")
					}
				})
			}
		}
	}
}

func TestAutoLegacyTransportWebSocketPlainAndPath(t *testing.T) {
	for _, network := range []string{"ws", "websocket"} {
		for _, test := range []struct {
			name       string
			path       string
			clientPath string
			wantOK     bool
		}{
			{"plain", "/socket", "/socket", true},
			{"early query stripped", "/socket?ed=4096", "/socket", true},
			{"client query accepted", "/socket", "/socket?client=value", true},
			{"wrong path rejected", "/socket", "/other", false},
			{"empty early query retained", "/socket?ed=", "/socket?ed=", false},
			{"empty early query literal path", "/socket?ed=", "/socket%3Fed=", true},
			{"other query retained", "/socket?z=2&ed=2048&a=1", "/socket?a=1&z=2", false},
			{"other query literal path", "/socket?z=2&ed=2048&a=1", "/socket%3Fa=1&z=2", true},
			{"invalid configured path retained", "/%zz?ed=2048", "/socket", false},
			{"invalid configured literal path", "/%zz?ed=2048", "/%25zz%3Fed=2048", true},
		} {
			t.Run(network+"/"+test.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, requests, server := newAutoWebSocketTransportTestServer(t, ctx, network, test.path)
				requestURL, err := url.Parse(server.URL + test.clientPath)
				if err != nil {
					t.Fatal(err)
				}
				requestURL.Scheme = "ws"
				rawConn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", requestURL.Host)
				if err != nil {
					t.Fatal(err)
				}
				defer rawConn.Close()
				_ = rawConn.SetDeadline(time.Now().Add(3 * time.Second))
				reader, _, err := (ws.Dialer{}).Upgrade(rawConn, requestURL)
				if !test.wantOK {
					if err == nil {
						t.Fatal("legacy configured path unexpectedly accepted a WebSocket handshake")
					}
					if !strings.Contains(err.Error(), "404") {
						t.Fatalf("path rejection did not come from the HTTP server: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if reader != nil && reader.Buffered() != 0 {
					t.Fatal("server sent unexpected data before the test payload")
				}
				conn := v2raywebsocket.NewConn(rawConn, nil, ws.StateClientSide)
				defer conn.Close()
				if err = autoTransportEcho(conn, 640); err != nil {
					t.Fatal(err)
				}
				select {
				case request := <-requests:
					if request.err != nil || request.path != test.clientPath || len(request.earlyData) != 0 {
						t.Fatalf("ordinary WebSocket handshake changed: path=%q earlyBytes=%d",
							request.path, len(request.earlyData))
					}
				case <-ctx.Done():
					t.Fatal("ordinary WebSocket handshake did not reach the server")
				}
			})
		}
	}
}

func TestAutoLegacyTransportHTTPUpgradeAliasesIgnorePanelHost(t *testing.T) {
	for _, network := range []string{"httpupgrade", "http-upgrade", "http_upgrade"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			transport, err := (autoConfigResponse{Network: network,
				NetworkSettings: json.RawMessage(`{"path":"/upgrade","host":"panel.invalid","headers":{"Host":"other.invalid"}}`),
			}).transportOptions(C.TypeVMess)
			if err != nil {
				t.Fatal(err)
			}
			handler := adapter.NewUpstreamContextHandler(pendingEchoRouter{}.RouteConnectionEx, nil)
			upgradeServer, err := v2rayhttpupgrade.NewServer(ctx, log.NewNOPFactory().Logger(),
				transport.HTTPUpgradeOptions, nil, handler)
			if err != nil {
				t.Fatal(err)
			}
			defer upgradeServer.Close()
			server := httptest.NewServer(upgradeServer)
			defer server.Close()
			clientOptions := transport.HTTPUpgradeOptions
			clientOptions.Host = "actual-client.invalid"
			client, err := v2rayhttpupgrade.NewClient(ctx, autoTransportTestDialer{},
				M.ParseSocksaddr(strings.TrimPrefix(server.URL, "http://")), clientOptions, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			conn, err := client.DialContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err = autoTransportEcho(conn, 640); err != nil {
				t.Fatal(err)
			}
		})
	}
}
