package anytlsnative_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestNativeXBoardUserAndTraffic exercises the panel API and real encrypted TCP transport.
// @author lyt
// @date 2026-10-29
func TestNativeXBoardUserAndTraffic(t *testing.T) {
	for _, panelType := range []string{"anytls", "vless"} {
		t.Run(panelType, func(t *testing.T) {
			const (
				userID   = "101"
				userUUID = "ec682053-9beb-49fb-8b58-a755e37b51e2"
				apiKey   = "local-test-panel-token"
				dataSize = 4096
			)
			ready := make(chan struct{})
			pushes := make(chan [2]int64, 8)
			var configRequests atomic.Int32
			panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query()
				if query.Get("token") != apiKey || query.Get("node_id") != "9" ||
					query.Get("node_type") != panelType {
					t.Error("panel request did not preserve the configured panel identity and node type")
					http.Error(w, "invalid panel query", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /api/v1/server/UniProxy/config":
					if configRequests.Add(1) == 2 {
						// The second poll starts only after the first user's update has completed.
						close(ready)
					}
					json.NewEncoder(w).Encode(map[string]any{"base_config": map[string]any{}})
				case "GET /api/v1/server/UniProxy/user":
					if r.Header.Get("If-None-Match") == `"users-1"` {
						w.WriteHeader(http.StatusNotModified)
						return
					}
					w.Header().Set("ETag", `"users-1"`)
					json.NewEncoder(w).Encode(map[string]any{"users": []any{
						map[string]any{"id": 101, "uuid": userUUID},
					}})
				case "POST /api/v1/server/UniProxy/push":
					var payload map[string][2]int64
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Errorf("decode panel traffic: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					traffic, exists := payload[userID]
					if !exists || len(payload) != 1 || traffic[0] < 0 || traffic[1] < 0 {
						t.Error("traffic was not mapped to the panel numeric user ID")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					select {
					case pushes <- traffic:
					case <-r.Context().Done():
						return
					}
					w.Write([]byte(`{}`))
				default:
					t.Error("unexpected panel API method or endpoint")
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(panel.Close)

			privateKey, publicKey := nativeTestKeys(t)
			inbound := nativeServerConfig(nativeFreePort(t), privateKey)
			inbound["users"] = []any{}
			tracker := &nativeRouteTracker{events: make(chan nativeRouteEvent, 8)}
			nativeStartBox(t, map[string]any{
				"inbounds":  []any{inbound},
				"outbounds": []any{map[string]any{"type": "direct"}},
				"services": []any{map[string]any{
					"type": "xboard", "tag": "panel", "inbound": "native-in",
					"api_host": panel.URL, "api_key": apiKey, "node_id": 9, "node_type": panelType,
					"pull_interval": "20ms", "push_interval": "20ms", "timeout": "1s",
				}},
			}, tracker)
			nativeWaitSignal(t, ready, "XBoard completing the initial user synchronization")

			client := nativeStartBox(t, map[string]any{"outbounds": []any{
				nativeClientConfig(inbound["listen_port"].(uint16), publicKey, "native", userUUID),
			}}, nil)
			if err := nativeExchange(nativeGetOutbound(t, client, "native"), nativeEchoServer(t), dataSize); err != nil {
				t.Fatalf("panel-provided UUID did not authenticate an encrypted TCP exchange: %v", err)
			}
			if event := nativeNextRoute(t, tracker); event.user != userUUID {
				t.Fatal("native transport was not bound to the panel user")
			}

			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			var total [2]int64
			for total[0] < dataSize || total[1] < dataSize {
				select {
				case traffic := <-pushes:
					total[0] += traffic[0]
					total[1] += traffic[1]
				case <-deadline.C:
					t.Fatalf("timed out waiting for panel traffic: got %v, want [%d %d]", total, dataSize, dataSize)
				}
			}
			if total != [2]int64{dataSize, dataSize} {
				t.Fatalf("panel traffic included incorrect byte counts: %v", total)
			}
		})
	}
}
