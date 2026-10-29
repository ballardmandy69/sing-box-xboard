package anytlsnative_test

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestNativeAccessLog exercises capture after authentication and the real gzip receiver.
// @author lyt
// @date 2026-10-29
func TestNativeAccessLog(t *testing.T) {
	const userUUID = "ec682053-9beb-49fb-8b58-a755e37b51e2"
	type record struct {
		Time                    int64
		Inbound, Outbound       string
		Uid                     uint64
		Net, Protocol, Src, Dst string
	}
	records := make(chan record, 8)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/accesslog/upload" ||
			r.Header.Get("X-Api-Token") != "local-log-token" || r.URL.Query().Get("tag") != "node-log" {
			t.Error("incorrect access-log endpoint or authentication")
		}
		compressed, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		defer compressed.Close()
		var batch []record
		if err = json.NewDecoder(compressed).Decode(&batch); err != nil {
			t.Error(err)
			return
		}
		for _, entry := range batch {
			records <- entry
		}
	}))
	t.Cleanup(receiver.Close)
	ready := make(chan struct{})
	var configs atomic.Int32
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/user":
			json.NewEncoder(w).Encode(map[string]any{"users": []any{map[string]any{"id": 101, "uuid": userUUID}}})
		case "/api/v1/server/UniProxy/config":
			if configs.Add(1) == 2 {
				close(ready)
			}
			w.Write([]byte(`{}`))
		default:
			t.Error("DisableUploadTraffic did not suppress traffic reporting")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(panel.Close)
	privateKey, publicKey := nativeTestKeys(t)
	inbound := nativeServerConfig(nativeFreePort(t), privateKey)
	inbound["users"] = []any{}
	nativeStartBox(t, map[string]any{
		"nyafw": map[string]any{"access_log": 0, "sb_api": map[string]any{
			"base_url": receiver.URL, "tag": "node-log", "token": "local-log-token",
		}},
		"inbounds":  []any{inbound},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "exit"}},
		"services": []any{map[string]any{
			"type": "xboard", "tag": "panel", "inbound": "native-in", "api_host": panel.URL,
			"api_key": "local-panel-token", "node_id": 9, "node_type": "anytls",
			"pull_interval": "20ms", "push_interval": "20ms", "disable_upload_traffic": true,
		}},
	}, nil)
	nativeWaitSignal(t, ready, "initial panel synchronization")
	client := nativeStartBox(t, map[string]any{"outbounds": []any{
		nativeClientConfig(inbound["listen_port"].(uint16), publicKey, "native", userUUID),
	}}, nil)
	destination := nativeEchoServer(t)
	if err := nativeExchange(nativeGetOutbound(t, client, "native"), destination, 1024); err != nil {
		t.Fatal(err)
	}
	select {
	case entry := <-records:
		if entry.Inbound != "native-in" || entry.Outbound != "exit" || entry.Uid != 101 ||
			entry.Net != "tcp" || entry.Dst != destination.String() || !strings.HasPrefix(entry.Src, "127.0.0.1:") ||
			entry.Time < time.Now().Add(-time.Minute).Unix() {
			t.Fatalf("wrong captured routed metadata: %+v", entry)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("an authenticated stream was not delivered to the access-log receiver")
	}
}
