package anytlsnative_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
)

type autoPanelConfig struct {
	revision   int64
	port       uint16
	serverName string
}

// autoPanelNode models independently changing node configuration, users and accounting.
// @author lyt
// @date 2026-10-29
type autoPanelNode struct {
	protocol      string
	panelType     string
	config        atomic.Pointer[autoPanelConfig]
	requests      atomic.Int64
	acknowledged  atomic.Int64
	users         atomic.Int64
	servedUsers   atomic.Int64
	appliedUsers  atomic.Int64
	trafficAccess sync.Mutex
	traffic       [2]int64
}

func TestAutoXBoardMultipleProtocolsAndHotConfiguration(t *testing.T) {
	const alpha = "7e9537fa-91f0-44a6-a5d8-736e183f08d8"
	const bravo = "bdc18401-4fa0-4686-b1b9-4138ef876704"
	nodes := make(map[string]*autoPanelNode)
	for index, protocol := range []string{"anytls", "trojan", "anytls-native"} {
		n := &autoPanelNode{protocol: protocol, panelType: protocol}
		if protocol == "anytls-native" {
			n.panelType = "anytls"
		}
		n.config.Store(&autoPanelConfig{revision: 1, port: nativeFreePort(t), serverName: "native.test"})
		n.users.Store(1)
		nodes[strconv.Itoa(index+1)] = n
	}
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := nodes[r.URL.Query().Get("node_id")]
		if n == nil || r.URL.Query().Get("node_type") != n.panelType || r.URL.Query().Get("token") != "local-token" {
			http.Error(w, "invalid panel identity", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/server/UniProxy/config":
			n.requests.Add(1)
			n.appliedUsers.Store(n.servedUsers.Load())
			current := n.config.Load()
			etag := fmt.Sprintf(`"config-%d"`, current.revision)
			if r.Header.Get("If-None-Match") == etag {
				n.acknowledged.Store(current.revision)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			json.NewEncoder(w).Encode(map[string]any{
				"protocol": n.panelType, "listen_ip": "127.0.0.1", "server_port": current.port,
				"network": "tcp", "server_name": current.serverName, "base_config": map[string]any{},
			})
		case "GET /api/v1/server/UniProxy/user":
			revision := n.users.Load()
			etag := fmt.Sprintf(`"users-%d"`, revision)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			password := alpha
			if revision > 1 {
				password = bravo
			}
			w.Header().Set("ETag", etag)
			n.servedUsers.Store(revision)
			json.NewEncoder(w).Encode(map[string]any{"users": []any{map[string]any{"id": 101, "uuid": password}}})
		case "POST /api/v1/server/UniProxy/push":
			var payload map[string][2]int64
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			n.trafficAccess.Lock()
			for id, count := range payload {
				if id != "101" {
					t.Error("automatic inbound traffic lost the panel user ID")
				}
				n.traffic[0] += count[0]
				n.traffic[1] += count[1]
			}
			n.trafficAccess.Unlock()
			w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(panel.Close)
	certificate, key := nativeTestCertificate(t)
	private, public := nativeTestKeys(t)
	directory := t.TempDir()
	certificatePath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	nativeKeyPath := filepath.Join(directory, "native-key.txt")
	for path, data := range map[string]string{certificatePath: certificate, keyPath: key, nativeKeyPath: private} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	services := make([]any, 0, len(nodes))
	for id, n := range nodes {
		auto := map[string]any{"protocol": n.protocol}
		if n.protocol == "anytls-native" {
			auto["private_key_path"] = nativeKeyPath
		} else {
			auto["certificate_path"], auto["key_path"] = certificatePath, keyPath
		}
		nodeID, _ := strconv.Atoi(id)
		services = append(services, map[string]any{
			"type": "xboard", "tag": "panel-" + id, "inbound": "auto-" + id,
			"api_host": panel.URL, "api_key": "local-token", "node_id": nodeID, "node_type": n.panelType,
			"auto_inbound": auto, "pull_interval": "15ms", "push_interval": "60ms", "timeout": "1s",
		})
	}
	server := nativeStartBox(t, map[string]any{
		"services": services, "outbounds": []any{map[string]any{"type": "direct"}},
	}, nil)
	if len(server.Inbound().Inbounds()) != 3 {
		t.Fatal("Nodes did not create all three requested inbounds")
	}
	destination := nativeEchoServer(t)
	exchange := func(n *autoPanelNode, port uint16, password string, wantSuccess bool) {
		t.Helper()
		outbound := nativeClientConfig(port, public, "test", password)
		if n.protocol != "anytls-native" {
			outbound = map[string]any{
				"type": n.protocol, "tag": "test", "server": "127.0.0.1", "server_port": port,
				"password": password, "tls": map[string]any{
					"enabled": true, "server_name": "native.test", "certificate": []string{certificate},
				},
			}
		}
		client := nativeStartBox(t, map[string]any{"outbounds": []any{outbound}}, nil)
		defer client.Close()
		err := nativeExchange(nativeGetOutbound(t, client, "test"), destination, 512)
		if (err == nil) != wantSuccess {
			t.Fatalf("%s exchange success=%t, expected=%t: %v", n.protocol, err == nil, wantSuccess, err)
		}
	}
	for _, id := range []string{"1", "2", "3"} {
		n := nodes[id]
		t.Run(n.protocol, func(t *testing.T) {
			autoAwait(t, func() bool { return n.appliedUsers.Load() == 1 }, "initial automatic users")
			oldPort := n.config.Load().port
			exchange(n, oldPort, alpha, true)
			occupied, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { occupied.Close() })
			badPort := uint16(occupied.Addr().(*net.TCPAddr).Port)
			previousRequests := n.requests.Load()
			n.config.Store(&autoPanelConfig{revision: 2, port: badPort, serverName: "native.test"})
			autoAwait(t, func() bool { return n.requests.Load() >= previousRequests+3 }, "retry failed listener config")
			if n.acknowledged.Load() == 2 {
				t.Fatal("failed listener bind advanced config ETag")
			}
			exchange(n, oldPort, alpha, true)
			autoAwait(t, func() bool {
				n.trafficAccess.Lock()
				defer n.trafficAccess.Unlock()
				return n.traffic[0] >= 1024 && n.traffic[1] >= 1024
			}, "original user's traffic before account rotation")
			n.users.Store(2)
			autoAwait(t, func() bool { return n.appliedUsers.Load() == 2 }, "user update despite failed listener config")
			exchange(n, oldPort, alpha, false)
			exchange(n, oldPort, bravo, true)
			newPort := nativeFreePort(t)
			n.config.Store(&autoPanelConfig{revision: 3, port: newPort, serverName: "native.test"})
			autoAwait(t, func() bool { return n.acknowledged.Load() == 3 }, "hot port replacement")
			exchange(n, newPort, bravo, true)
			oldSocket, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(oldPort))), time.Second)
			if err == nil {
				oldSocket.Close()
				t.Fatal("previous listener remained open after hot replacement")
			}
			if n.protocol != "anytls-native" {
				n.config.Store(&autoPanelConfig{revision: 4, port: newPort, serverName: "updated.native.test"})
				autoAwait(t, func() bool { return n.acknowledged.Load() == 4 }, "same-port TLS configuration replacement")
				exchange(n, newPort, bravo, true)
			}
			autoAwait(t, func() bool {
				n.trafficAccess.Lock()
				defer n.trafficAccess.Unlock()
				return n.traffic[0] >= 2048 && n.traffic[1] >= 2048
			}, "traffic after hot configuration with pull interval shorter than push interval")
		})
	}
}

func autoAwait(t *testing.T, ready func() bool, reason string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", reason)
}

func TestAutoXBoardInitialFailureRejectsConfiguration(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		auto   map[string]any
	}{
		{name: "HTTP error", status: http.StatusForbidden, body: `response-private-token`},
		{name: "initial 304", status: http.StatusNotModified},
		{name: "invalid JSON", status: http.StatusOK, body: `response-private-token`},
		{name: "missing certificate", status: http.StatusOK, body: `{"server_port":443}`},
		{name: "missing certificate file", status: http.StatusOK, body: `{"server_port":443}`,
			auto: map[string]any{"certificate_path": "missing-cert.pem", "key_path": "missing-key.pem"}},
		{name: "invalid native key", status: http.StatusOK, body: `{"server_port":443}`,
			auto: map[string]any{"protocol": "anytls-native", "private_key": "invalid-key-material"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				w.Write([]byte(test.body))
			}))
			defer panel.Close()
			if test.auto == nil {
				test.auto = map[string]any{}
			}
			encoded, err := json.Marshal(map[string]any{
				"log":       map[string]any{"disabled": true},
				"outbounds": []any{map[string]any{"type": "direct"}},
				"services": []any{map[string]any{
					"type": "xboard", "tag": "panel", "inbound": "auto-in", "node_id": 1,
					"api_host": panel.URL, "api_key": "request-private-token", "node_type": "anytls",
					"auto_inbound": test.auto,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(include.Context(context.Background()))
			defer cancel()
			options, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, encoded)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			if err == nil {
				instance.Close()
				t.Fatal("invalid initial automatic node was accepted")
			}
			if strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), panel.URL) {
				t.Fatal("initial panel failure exposed request or response secrets")
			}
		})
	}
}
