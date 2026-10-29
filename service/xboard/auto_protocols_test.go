package xboard

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestAutoStandardProtocolOptions(t *testing.T) {
	for _, protocol := range []string{"vmess", "v2ray", "vless"} {
		t.Run(protocol, func(t *testing.T) {
			var response autoConfigResponse
			if err := json.Unmarshal([]byte(`{"protocol":"`+normalizedProtocol(protocol)+`",`+
				`"server_port":443,"network":"tcp","tls":0}`), &response); err != nil {
				t.Fatal(err)
			}
			config, err := response.buildInboundConfig(protocol, option.XBoardAutoInboundOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if config.protocol != normalizedProtocol(protocol) ||
				config.options.(option.InboundTLSOptionsWrapper).TakeInboundTLSOptions() != nil {
				t.Fatal("plaintext protocol did not preserve its TLS mode")
			}
			response.TLS = json.RawMessage(`1`)
			if _, err := response.buildInboundConfig(protocol, option.XBoardAutoInboundOptions{}); err == nil {
				t.Fatal("TLS-enabled panel configuration accepted missing certificate files")
			}
			config, err = response.buildInboundConfig(protocol, option.XBoardAutoInboundOptions{
				CertificatePath: "cert.pem", KeyPath: "key.pem",
			})
			if err != nil || !config.options.(option.InboundTLSOptionsWrapper).TakeInboundTLSOptions().Enabled {
				t.Fatalf("standard TLS configuration was not enabled: %v", err)
			}
		})
	}
	response := autoConfigResponse{ServerPort: json.RawMessage(`443`), Decryption: json.RawMessage(`"private-secret"`)}
	if _, err := response.buildInboundConfig(C.TypeVLESS, option.XBoardAutoInboundOptions{}); err == nil ||
		strings.Contains(err.Error(), "private-secret") {
		t.Fatal("unsupported VLESS encryption was silently accepted or exposed its key")
	}
}

func TestAutoStandardTCPTransports(t *testing.T) {
	tests := []struct {
		network  string
		settings string
		want     string
	}{
		{"ws", `{"path":"/socket","headers":{"Host":"node.example","X-Test":["a","b"]}}`, "ws"},
		{"httpupgrade", `{"path":"/upgrade","host":"node.example"}`, "httpupgrade"},
		{"httpupgrade", `{"path":"/upgrade","headers":{"Host":"node.example"}}`, "httpupgrade"},
		{"grpc", `{"serviceName":"proxy-service"}`, "grpc"},
	}
	for _, test := range tests {
		t.Run(test.network+test.settings, func(t *testing.T) {
			response := autoConfigResponse{Network: test.network, NetworkSettings: json.RawMessage(test.settings)}
			transport, err := response.transportOptions(C.TypeVMess)
			if err != nil || transport.Type != test.want {
				t.Fatalf("invalid transport mapping: %#v %v", transport, err)
			}
			switch test.network {
			case "ws":
				if transport.WebsocketOptions.Path != "/socket" ||
					transport.WebsocketOptions.Headers["Host"][0] != "node.example" ||
					len(transport.WebsocketOptions.Headers["X-Test"]) != 2 {
					t.Fatal("websocket settings changed")
				}
			case "httpupgrade":
				if transport.HTTPUpgradeOptions.Host != "node.example" ||
					transport.HTTPUpgradeOptions.Path != "/upgrade" {
					t.Fatal("HTTP upgrade host or path changed")
				}
			case "grpc":
				if transport.GRPCOptions.ServiceName != "proxy-service" {
					t.Fatal("gRPC serviceName was not mapped to service_name")
				}
			}
		})
	}
	for _, network := range []string{"quic", "kcp", "xhttp", "unknown"} {
		if _, err := (autoConfigResponse{Network: network}).transportOptions(C.TypeVLESS); err == nil {
			t.Fatalf("unsupported transport %s was accepted", network)
		}
	}
}

func TestAutoShadowsocksOptionsAndCredentialDerivation(t *testing.T) {
	const credential = "7e9537fa-91f0-44a6-a5d8-736e183f08d8"
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			response := autoConfigResponse{Cipher: method, ServerPort: json.RawMessage(`8443`),
				ObfsSettings: json.RawMessage(`{"host":"","path":""}`)}
			keySize := shadowsocksUserKeySize(method)
			if keySize != 0 {
				response.ServerKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("K", keySize)))
			}
			config, err := response.buildInboundConfig(C.TypeShadowsocks, option.XBoardAutoInboundOptions{})
			if err != nil {
				t.Fatal(err)
			}
			options := config.options.(*option.ShadowsocksInboundOptions)
			if !options.Managed || options.Network != "tcp" || options.Method != method ||
				options.Password != response.ServerKey {
				t.Fatal("Shadowsocks managed TCP options were not preserved")
			}
			raw := []string{credential}
			got, err := config.userCredentials(raw)
			if err != nil || raw[0] != credential {
				t.Fatalf("credential conversion modified the cached UUID: %v", err)
			}
			want := credential
			if keySize != 0 {
				want = base64.StdEncoding.EncodeToString([]byte(credential[:keySize]))
			}
			if !reflect.DeepEqual(got, []string{want}) {
				t.Fatal("password does not match the XBoard UUID text prefix derivation")
			}
			if keySize != 0 {
				if _, err := config.userCredentials([]string{"short"}); err == nil {
					t.Fatal("short 2022 user key was accepted")
				}
			}
		})
	}
}

func TestAutoShadowsocksRejectsUnsupportedConfiguration(t *testing.T) {
	for _, response := range []autoConfigResponse{
		{Cipher: "none"},
		{Cipher: "2022-blake3-chacha20-poly1305"},
		{Cipher: "2022-blake3-aes-128-gcm", ServerKey: "invalid-secret"},
		{Cipher: "aes-128-gcm", TLS: json.RawMessage(`1`)},
	} {
		if _, err := response.shadowsocksOptions(option.ListenOptions{}, ""); err == nil {
			t.Fatal("unsupported Shadowsocks configuration was accepted")
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("private panel response data leaked into validation error")
		}
	}
}

func TestAutoShadowsocksIgnoresUniProxyObfsFields(t *testing.T) {
	response := autoConfigResponse{Cipher: "aes-128-gcm", Plugin: "obfs-local", Obfs: "http",
		PluginOptions: json.RawMessage(`"obfs=http;obfs-host=panel.example"`),
		ObfsSettings:  json.RawMessage(`{"host":"panel.example","path":"/legacy"}`)}
	options, err := response.shadowsocksOptions(option.ListenOptions{}, "")
	if err != nil || options.Method != "aes-128-gcm" || options.Network != "tcp" || !options.Managed {
		t.Fatalf("UniProxy obfs fields changed the original plain TCP SS mapping: %v", err)
	}
}

func TestAutoShadowsocksLocalObfsOverride(t *testing.T) {
	response := autoConfigResponse{Cipher: "panel-cipher-is-overridden"}
	for _, mode := range []string{"aes-128-gcm", "aes-256-gcm:shared-password", "none:shared-password"} {
		options, err := response.shadowsocksOptions(option.ListenOptions{}, mode)
		if err != nil {
			t.Fatalf("local obfs mode rejected: %v", err)
		}
		if options.Method != strings.Split(mode, ":")[0] || options.ObfsMu != mode || options.Network != "tcp" {
			t.Fatalf("local obfs override lost: %+v", options)
		}
	}
	for _, mode := range []string{":password", "aes-128-gcm:password:extra", "unsupported", "none"} {
		if _, err := response.shadowsocksOptions(option.ListenOptions{}, mode); err == nil {
			t.Fatal("invalid local obfs mode accepted")
		}
	}
}

func TestAutoShadowsocks2022ChaChaOnlySharedObfs(t *testing.T) {
	const method = "2022-blake3-chacha20-poly1305"
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("K", 32)))
	response := autoConfigResponse{Cipher: method, ServerKey: key}
	for _, mode := range []string{"", method} {
		if _, err := response.shadowsocksOptions(option.ListenOptions{}, mode); err == nil {
			t.Fatal("unsupported multi-user ChaCha2022 configuration was accepted")
		}
	}
	options, err := response.shadowsocksOptions(option.ListenOptions{}, method+":"+key)
	if err != nil || options.Method != method || options.Password != key {
		t.Fatalf("supported shared-password ChaCha2022 configuration was rejected: %v", err)
	}
	if _, err := response.shadowsocksOptions(option.ListenOptions{}, method+":invalid"); err == nil {
		t.Fatal("invalid shared ChaCha2022 key was accepted")
	}
}
