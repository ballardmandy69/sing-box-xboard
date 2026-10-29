package anytlsnative_test

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-shadowsocks2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// standardAutoPanelSnapshot publishes immutable panel revisions for protocol integration tests.
// @author lyt
// @date 2026-10-29
type standardAutoPanelSnapshot struct {
	configRevision int64
	userRevision   int64
	config         map[string]any
	users          []map[string]any
}

func TestAutoStandardXBoardTCPProtocols(t *testing.T) {
	const alpha = "7e9537fa-91f0-44a6-a5d8-736e183f08d8"
	const bravo = "bdc18401-4fa0-4686-b1b9-4138ef876704"
	tests := []struct {
		protocol     string
		network      string
		cipher       string
		tls          bool
		shortInitial bool
		obfsMode     string
	}{
		{protocol: "vmess", network: "tcp"},
		{protocol: "vmess", network: "ws", tls: true},
		{protocol: "vmess", network: "grpc"},
		{protocol: "vless", network: "tcp"},
		{protocol: "vless", network: "httpupgrade"},
		{protocol: "shadowsocks", network: "tcp", cipher: "aes-128-gcm"},
		{protocol: "shadowsocks", network: "tcp", cipher: "2022-blake3-aes-128-gcm"},
		{protocol: "shadowsocks", network: "tcp", cipher: "2022-blake3-aes-128-gcm", shortInitial: true},
		{protocol: "shadowsocks", network: "tcp", cipher: "aes-128-gcm", obfsMode: "per-user"},
		{protocol: "shadowsocks", network: "tcp", cipher: "aes-128-gcm", obfsMode: "shared"},
		{protocol: "shadowsocks", network: "tcp", cipher: "2022-blake3-aes-128-gcm", obfsMode: "per-user"},
		{protocol: "shadowsocks", network: "tcp", cipher: "2022-blake3-aes-128-gcm", obfsMode: "shared"},
		{protocol: "shadowsocks", network: "tcp", cipher: "2022-blake3-chacha20-poly1305", obfsMode: "shared"},
	}
	for _, test := range tests {
		name := test.protocol + "/" + test.network + "/" + test.cipher
		if test.shortInitial {
			name += "/recover-invalid-cached-user"
		}
		if test.obfsMode != "" {
			name += "/obfs-" + test.obfsMode
		}
		t.Run(name, func(t *testing.T) {
			port := nativeFreePort(t)
			var configAck, usersAck, configRequests atomic.Int64
			var state atomic.Pointer[standardAutoPanelSnapshot]
			keyLength := 16
			if test.cipher == "2022-blake3-chacha20-poly1305" {
				keyLength = 32
			}
			serverKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("K", keyLength)))
			config := map[string]any{
				"protocol": test.protocol, "listen_ip": "127.0.0.1", "server_port": port,
				"network": test.network, "tls": 0,
			}
			var transport map[string]any
			switch test.network {
			case "ws":
				config["networkSettings"] = map[string]any{"path": "/socket", "headers": map[string]any{"Host": "native.test"}}
				transport = map[string]any{"type": "ws", "path": "/socket", "headers": map[string]any{"Host": "native.test"}}
			case "grpc":
				config["networkSettings"] = map[string]any{"serviceName": "proxy-service"}
				transport = map[string]any{"type": "grpc", "service_name": "proxy-service"}
			case "httpupgrade":
				config["networkSettings"] = map[string]any{"path": "/upgrade", "host": "native.test"}
				transport = map[string]any{"type": "httpupgrade", "path": "/upgrade", "host": "native.test"}
			}
			if test.cipher != "" {
				config["cipher"], config["server_key"] = test.cipher, serverKey
			}
			auto := map[string]any{}
			if test.obfsMode != "" {
				obfs := test.cipher
				if test.obfsMode == "shared" {
					obfs += ":" + serverKey
				}
				auto["shadowsocks_obfs_mu"] = obfs
			}
			var certificate string
			if test.tls {
				var key string
				certificate, key = nativeTestCertificate(t)
				directory := t.TempDir()
				certPath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
				for path, data := range map[string]string{certPath: certificate, keyPath: key} {
					if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				auto["certificate_path"], auto["key_path"] = certPath, keyPath
				config["tls"] = 1
				config["tls_settings"] = map[string]any{"server_name": "native.test"}
			}
			initialCredential := alpha
			if test.shortInitial {
				initialCredential = "short"
			}
			state.Store(&standardAutoPanelSnapshot{configRevision: 1, userRevision: 1,
				config: config, users: []map[string]any{{"id": 101, "uuid": initialCredential}}})
			var trafficAccess sync.Mutex
			totals := make(map[string][2]int64)
			panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				current := state.Load()
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /api/v1/server/UniProxy/config":
					configRequests.Add(1)
					etag := fmt.Sprintf(`"config-%d"`, current.configRevision)
					if r.Header.Get("If-None-Match") == etag {
						configAck.Store(current.configRevision)
						w.WriteHeader(http.StatusNotModified)
						return
					}
					w.Header().Set("ETag", etag)
					json.NewEncoder(w).Encode(current.config)
				case "GET /api/v1/server/UniProxy/user":
					etag := fmt.Sprintf(`"users-%d"`, current.userRevision)
					if r.Header.Get("If-None-Match") == etag {
						usersAck.Store(current.userRevision)
						w.WriteHeader(http.StatusNotModified)
						return
					}
					w.Header().Set("ETag", etag)
					json.NewEncoder(w).Encode(map[string]any{"users": current.users})
				case "POST /api/v1/server/UniProxy/push":
					var payload map[string][2]int64
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					trafficAccess.Lock()
					for id, usage := range payload {
						previous := totals[id]
						totals[id] = [2]int64{previous[0] + usage[0], previous[1] + usage[1]}
					}
					trafficAccess.Unlock()
					w.Write([]byte(`{}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(panel.Close)
			server := nativeStartBox(t, map[string]any{
				"services": []any{map[string]any{
					"type": "xboard", "tag": "standard-panel", "inbound": "auto-standard",
					"api_host": panel.URL, "api_key": "local-token", "node_id": 1, "node_type": test.protocol,
					"auto_inbound": auto, "pull_interval": "15ms", "push_interval": "30ms", "timeout": "1s",
				}},
				"outbounds": []any{map[string]any{"type": "direct"}},
			}, nil)
			defer server.Close()
			destination := nativeEchoServer(t)
			exchange := func(credential, method, key string, success bool) {
				t.Helper()
				outbound := map[string]any{
					"type": test.protocol, "tag": "test", "server": "127.0.0.1", "server_port": port,
				}
				if test.protocol == "shadowsocks" {
					password := credential
					if strings.HasPrefix(method, "2022-") {
						length := 16
						if method != "2022-blake3-aes-128-gcm" {
							length = 32
						}
						password = key + ":" + base64.StdEncoding.EncodeToString([]byte(credential[:length]))
					}
					if test.obfsMode != "" {
						if test.obfsMode == "shared" {
							password = key
						}
						err := standardObfsExchange(port, destination, method, password, credential)
						if (err == nil) != success {
							t.Fatalf("SS-obfs exchange success=%t, expected=%t: %v", err == nil, success, err)
						}
						return
					}
					outbound["method"], outbound["password"] = method, password
				} else {
					outbound["uuid"] = credential
					if test.protocol == "vmess" {
						outbound["security"] = "auto"
					}
				}
				if transport != nil {
					outbound["transport"] = transport
				}
				if test.tls {
					outbound["tls"] = map[string]any{
						"enabled": true, "server_name": "native.test", "certificate": []string{certificate},
					}
				}
				client := nativeStartBox(t, map[string]any{"outbounds": []any{outbound}}, nil)
				defer client.Close()
				if err := standardAutoExchange(nativeGetOutbound(t, client, "test"), destination); (err == nil) != success {
					t.Fatalf("protocol exchange success=%t, expected=%t: %v", err == nil, success, err)
				}
			}
			initialUserRevision := int64(1)
			if test.shortInitial {
				autoAwait(t, func() bool { return configRequests.Load() > 0 }, "invalid initial cached user")
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
				if err == nil {
					conn.Close()
					t.Fatal("initial invalid user enabled the listener")
				}
				initialUserRevision = 2
				state.Store(&standardAutoPanelSnapshot{configRevision: 1, userRevision: 2,
					config: config, users: []map[string]any{{"id": 101, "uuid": alpha}}})
			}
			autoAwait(t, func() bool {
				return configAck.Load() == 1 && usersAck.Load() == initialUserRevision
			}, "standard panel startup")
			exchange(alpha, test.cipher, serverKey, true)
			autoAwait(t, func() bool {
				trafficAccess.Lock()
				defer trafficAccess.Unlock()
				return totals["101"][0] >= 640 && totals["101"][1] >= 640
			}, "standard protocol traffic accounting")
			if test.obfsMode != "" {
				wrongPassword := "wrong-password"
				if strings.HasPrefix(test.cipher, "2022-") {
					wrongKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("W", keyLength)))
					wrongPassword = wrongKey
					if test.obfsMode == "per-user" {
						wrongPassword = serverKey + ":" + wrongKey
					}
				}
				reachedServer := false
				err := standardObfsExchange(port, destination, test.cipher, wrongPassword, alpha,
					func() { reachedServer = true })
				if !reachedServer {
					t.Fatalf("wrong-key test did not reach server authentication: %v", err)
				}
				if err == nil {
					t.Fatal("known Host bypassed Shadowsocks password verification")
				}
				state.Store(&standardAutoPanelSnapshot{configRevision: 1, userRevision: 2, config: config,
					users: []map[string]any{{"id": 202, "uuid": bravo}, {"id": 101, "uuid": alpha}}})
				autoAwait(t, func() bool { return usersAck.Load() == 2 }, "SS-obfs user addition and reorder")
				exchange(alpha, test.cipher, serverKey, true)
				exchange(bravo, test.cipher, serverKey, true)
				if test.obfsMode == "per-user" {
					password := bravo
					acceptDifferentIdentity := strings.HasPrefix(test.cipher, "2022-")
					if acceptDifferentIdentity {
						password = serverKey + ":" + base64.StdEncoding.EncodeToString([]byte(bravo[:16]))
					}
					err := standardObfsExchange(port, destination, test.cipher, password, alpha)
					if (err == nil) != acceptDifferentIdentity {
						t.Fatalf("legacy hint/2022 identity-header behavior differs, err=%v", err)
					}
				}
				autoAwait(t, func() bool {
					trafficAccess.Lock()
					defer trafficAccess.Unlock()
					return totals["202"][0] >= 640 && totals["202"][1] >= 640
				}, "SS-obfs second user accounting")
				state.Store(&standardAutoPanelSnapshot{configRevision: 1, userRevision: 3, config: config,
					users: []map[string]any{{"id": 202, "uuid": bravo}}})
				autoAwait(t, func() bool { return usersAck.Load() == 3 }, "SS-obfs user revocation")
				exchange(bravo, test.cipher, serverKey, true)
				exchange(alpha, test.cipher, serverKey, false)
				return
			}
			if test.cipher != "2022-blake3-aes-128-gcm" || test.shortInitial {
				return
			}
			updated := make(map[string]any, len(config))
			for name, value := range config {
				updated[name] = value
			}
			method := "2022-blake3-aes-256-gcm"
			serverKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("N", 32)))
			updated["cipher"], updated["server_key"] = method, serverKey
			state.Store(&standardAutoPanelSnapshot{configRevision: 2, userRevision: 1,
				config: updated, users: []map[string]any{{"id": 101, "uuid": alpha}}})
			autoAwait(t, func() bool { return configAck.Load() == 2 }, "2022 cipher replacement")
			exchange(alpha, method, serverKey, true)
			state.Store(&standardAutoPanelSnapshot{configRevision: 2, userRevision: 2, config: updated,
				users: []map[string]any{{"id": 101, "uuid": alpha}, {"id": 202, "uuid": bravo}}})
			autoAwait(t, func() bool { return usersAck.Load() == 2 }, "2022 user addition")
			exchange(bravo, method, serverKey, true)
			state.Store(&standardAutoPanelSnapshot{configRevision: 2, userRevision: 3,
				config: updated, users: []map[string]any{{"id": 202, "uuid": bravo}}})
			autoAwait(t, func() bool { return usersAck.Load() == 3 }, "2022 user revocation")
			exchange(bravo, method, serverKey, true)
			exchange(alpha, method, serverKey, false)
		})
	}
}

func standardObfsExchange(port uint16, destination M.Socksaddr, methodName, password, uuid string,
	onPreambleAccepted ...func(),
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	method, err := shadowsocks.CreateMethod(ctx, methodName, shadowsocks.MethodOptions{Password: password})
	if err != nil {
		return err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	host := fmt.Sprintf("%x.microsoft.com", md5.Sum([]byte(uuid)))
	if _, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host); err != nil {
		return err
	}
	const response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	header := make([]byte, len(response))
	if _, err = io.ReadFull(conn, header); err != nil {
		return err
	}
	if string(header) != response {
		return fmt.Errorf("unexpected SS-obfs response")
	}
	for _, callback := range onPreambleAccepted {
		callback()
	}
	return nativeExchangeOnConn(method.DialEarlyConn(conn, destination), 640)
}

func standardAutoExchange(outbound adapter.Outbound, destination M.Socksaddr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return err
	}
	defer conn.Close()
	// HTTP-backed streams need cancellation because they do not implement socket deadlines.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	return nativeExchangeOnConn(conn, 640)
}
