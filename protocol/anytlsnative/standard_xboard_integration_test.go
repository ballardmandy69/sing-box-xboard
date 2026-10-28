package anytlsnative_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/trojan"
	M "github.com/sagernet/sing/common/metadata"
)

// TestStandardTLSXBoardUserUpdates verifies the original TLS protocols with panel-managed users.
// @author lyt
// @date 2026-10-29
func TestStandardTLSXBoardUserUpdates(t *testing.T) {
	for _, protocol := range []string{"trojan", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			const (
				alphaUUID = "6cc1962e-765b-44eb-9c07-b0bddc13ee51"
				bravoUUID = "995ba419-d4eb-49bf-97c5-f5c3a2a74015"
				apiKey    = "local-standard-panel-token"
			)
			var desired, served atomic.Int64
			desired.Store(1)
			var appliedOnce [4]sync.Once
			applied := [4]chan struct{}{nil, make(chan struct{}), make(chan struct{}), make(chan struct{})}
			pushes := make(chan map[string][2]int64, 32)
			panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query()
				if query.Get("token") != apiKey || query.Get("node_id") != "10" ||
					query.Get("node_type") != protocol {
					t.Error("standard protocol request changed the configured panel API identity")
					http.Error(w, "invalid panel query", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /api/v1/server/UniProxy/config":
					if revision := served.Load(); revision > 0 {
						// A subsequent poll observes completion of the preceding UpdateUsers call.
						appliedOnce[revision].Do(func() { close(applied[revision]) })
					}
					json.NewEncoder(w).Encode(map[string]any{"base_config": map[string]any{}})
				case "GET /api/v1/server/UniProxy/user":
					revision := desired.Load()
					etag := fmt.Sprintf(`"users-%d"`, revision)
					if r.Header.Get("If-None-Match") == etag {
						w.WriteHeader(http.StatusNotModified)
						return
					}
					alpha := map[string]any{"id": 101, "uuid": alphaUUID}
					bravo := map[string]any{"id": 202, "uuid": bravoUUID}
					users := []any{alpha, bravo}
					if revision == 2 {
						users = []any{bravo, alpha}
					} else if revision == 3 {
						users = []any{bravo}
					}
					w.Header().Set("ETag", etag)
					served.Store(revision)
					json.NewEncoder(w).Encode(map[string]any{"users": users})
				case "POST /api/v1/server/UniProxy/push":
					var payload map[string][2]int64
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Errorf("decode standard protocol traffic: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					for id, traffic := range payload {
						if (id != "101" && id != "202") || traffic[0] < 0 || traffic[1] < 0 {
							t.Error("standard protocol traffic did not retain the panel numeric user ID")
							w.WriteHeader(http.StatusBadRequest)
							return
						}
					}
					select {
					case pushes <- payload:
					case <-r.Context().Done():
						return
					}
					w.Write([]byte(`{}`))
				default:
					t.Error("unexpected standard protocol panel request")
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(panel.Close)

			certificate, key := nativeTestCertificate(t)
			port := nativeFreePort(t)
			tracker := &nativeRouteTracker{events: make(chan nativeRouteEvent, 16)}
			nativeStartBox(t, map[string]any{
				"inbounds": []any{map[string]any{
					"type": protocol, "tag": "standard-in", "listen": "127.0.0.1", "listen_port": port,
					"users": []any{}, "tls": map[string]any{
						"enabled": true, "certificate": []string{certificate}, "key": []string{key},
					},
				}},
				"outbounds": []any{map[string]any{"type": "direct"}},
				"services": []any{map[string]any{
					"type": "xboard", "tag": "panel", "inbound": "standard-in",
					"api_host": panel.URL, "api_key": apiKey, "node_id": 10, "node_type": protocol,
					"pull_interval": "20ms", "push_interval": "20ms", "timeout": "1s",
				}},
			}, tracker)
			nativeWaitSignal(t, applied[1], "initial standard protocol panel users")

			clientConfig := func(tag, password string) map[string]any {
				return map[string]any{
					"type": protocol, "tag": tag, "server": "127.0.0.1", "server_port": port,
					"password": password, "tls": map[string]any{
						"enabled": true, "server_name": "native.test", "certificate": []string{certificate},
					},
				}
			}
			client := nativeStartBox(t, map[string]any{"outbounds": []any{
				clientConfig("alpha", alphaUUID), clientConfig("bravo", bravoUUID),
			}}, nil)
			destination := nativeEchoServer(t)
			alphaOutbound := nativeGetOutbound(t, client, "alpha")
			bravoOutbound := nativeGetOutbound(t, client, "bravo")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			alphaConn, err := alphaOutbound.DialContext(ctx, "tcp", destination)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { alphaConn.Close() })
			if err = alphaConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err = nativeExchangeOnConn(alphaConn, 1024); err != nil {
				t.Fatalf("initial alpha TCP exchange: %v", err)
			}
			standardAssertRouteUser(t, tracker, alphaUUID)
			if err = nativeExchange(bravoOutbound, destination, 2048); err != nil {
				t.Fatalf("initial bravo TCP exchange: %v", err)
			}
			standardAssertRouteUser(t, tracker, bravoUUID)
			totals := make(map[string][2]int64)
			standardAwaitTraffic(t, pushes, totals, 1024, 2048)

			desired.Store(2)
			nativeWaitSignal(t, applied[2], "reordered standard protocol users")
			if err = nativeExchangeOnConn(alphaConn, 3072); err != nil {
				t.Fatalf("existing alpha stream after user reorder: %v", err)
			}
			if err = nativeExchange(bravoOutbound, destination, 4096); err != nil {
				t.Fatalf("new bravo stream after user reorder: %v", err)
			}
			standardAssertRouteUser(t, tracker, bravoUUID)
			standardAwaitTraffic(t, pushes, totals, 4096, 6144)
			alphaConn.Close()

			desired.Store(3)
			nativeWaitSignal(t, applied[3], "deleted standard protocol user")
			freshClient := nativeStartBox(t, map[string]any{"outbounds": []any{
				clientConfig("deleted", alphaUUID),
			}}, nil)
			if err = nativeExchange(nativeGetOutbound(t, freshClient, "deleted"), destination, 1024); err == nil {
				t.Fatal("a new TLS connection authenticated a deleted panel user")
			}
			if err = nativeExchange(bravoOutbound, destination, 8192); err != nil {
				t.Fatalf("retained bravo user after deletion: %v", err)
			}
			standardAssertRouteUser(t, tracker, bravoUUID)
			standardAwaitTraffic(t, pushes, totals, 4096, 14336)
			select {
			case <-tracker.events:
				t.Fatal("an extra or deleted user reached routing")
			default:
			}
		})
	}
}

func standardAssertRouteUser(t *testing.T, tracker *nativeRouteTracker, user string) {
	t.Helper()
	if event := nativeNextRoute(t, tracker); event.user != user {
		t.Fatal("routed connection was assigned to a different panel user")
	}
}

func standardAwaitTraffic(t *testing.T, pushes <-chan map[string][2]int64, totals map[string][2]int64,
	alpha, bravo int64,
) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	wanted := map[string][2]int64{"101": {alpha, alpha}, "202": {bravo, bravo}}
	for totals["101"] != wanted["101"] || totals["202"] != wanted["202"] {
		select {
		case payload := <-pushes:
			for id, traffic := range payload {
				previous := totals[id]
				updated := [2]int64{previous[0] + traffic[0], previous[1] + traffic[1]}
				totals[id] = updated
				if updated[0] > wanted[id][0] || updated[1] > wanted[id][1] {
					t.Fatalf("traffic crossed user identities: got %v, want %v", totals, wanted)
				}
			}
		case <-deadline.C:
			t.Fatalf("timed out waiting for traffic: got %v, want %v", totals, wanted)
		}
	}
}

// standardAuthenticatedConn exposes the point after Trojan password authentication.
// @author lyt
// @date 2026-10-29
type standardAuthenticatedConn struct {
	net.Conn
	reads         int
	authenticated chan struct{}
}

func (c *standardAuthenticatedConn) Read(data []byte) (int, error) {
	c.reads++
	if c.reads == 1 {
		return io.ReadFull(c.Conn, data)
	}
	if c.reads == 2 {
		close(c.authenticated)
	}
	return c.Conn.Read(data)
}

// TestTrojanAuthenticatedIdentitySurvivesReorder holds a request between auth and routing.
// @author lyt
// @date 2026-10-29
func TestTrojanAuthenticatedIdentitySurvivesReorder(t *testing.T) {
	tracker := &nativeRouteTracker{events: make(chan nativeRouteEvent, 8)}
	server := nativeStartBox(t, map[string]any{
		"inbounds": []any{map[string]any{
			"type": "trojan", "tag": "trojan-in", "listen": "127.0.0.1", "listen_port": nativeFreePort(t),
			"users": []any{
				map[string]any{"name": "alpha", "password": "alpha-secret"},
				map[string]any{"name": "bravo", "password": "bravo-secret"},
			},
		}},
		"outbounds": []any{map[string]any{"type": "direct"}},
	}, tracker)
	inbound, _ := server.Inbound().Get("trojan-in")
	client, accepted := nativeTCPPair(t)
	observed := &standardAuthenticatedConn{Conn: accepted, authenticated: make(chan struct{})}
	go inbound.(adapter.TCPInjectableInbound).NewConnection(context.Background(), observed,
		adapter.InboundContext{Source: M.SocksaddrFromNet(accepted.RemoteAddr())}, nil)
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	key := trojan.Key("alpha-secret")
	if _, err := client.Write(key[:]); err != nil {
		t.Fatal(err)
	}
	nativeWaitSignal(t, observed.authenticated, "Trojan password authentication before destination parsing")
	if err := inbound.(adapter.ManagedSSMServer).UpdateUsers(
		[]string{"bravo", "alpha"}, []string{"bravo-secret", "alpha-secret"},
	); err != nil {
		t.Fatal(err)
	}
	var remainder bytes.Buffer
	remainder.Write(trojan.CRLF)
	remainder.WriteByte(trojan.CommandTCP)
	if err := M.SocksaddrSerializer.WriteAddrPort(&remainder, nativeEchoServer(t)); err != nil {
		t.Fatal(err)
	}
	remainder.Write(trojan.CRLF)
	payload := []byte("identity must follow the authenticated password")
	remainder.Write(payload)
	if _, err := client.Write(remainder.Bytes()); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(client, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, received) {
		t.Fatal("Trojan payload changed after user reorder")
	}
	standardAssertRouteUser(t, tracker, "alpha")
}
