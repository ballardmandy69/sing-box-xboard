package xboard

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestAutomaticPrivateProtocolMatrix(t *testing.T) {
	for _, test := range []struct {
		protocol, fallback string
		accept, valid      bool
		wantFallback       string
	}{
		{"anytls", "", false, true, ""},
		{"anytls", "", true, false, ""},
		{"trojan", "", true, true, "trojan"},
		{"vless", "", true, true, "vless"},
		{"anytls", "trojan", false, true, "trojan"},
		{"anytls", "vless", true, true, "vless"},
		{"anytls", "trojan-vless", true, true, "trojan-vless"},
		{"trojan", "trojan", true, false, ""},
		{"vmess", "", true, false, ""},
		{"anytls", "Trojan", false, false, ""},
	} {
		auto := option.XBoardAutoInboundOptions{
			AcceptAnyTLS: test.accept, FallbackService: test.fallback,
			CertificatePath: "cert.pem", KeyPath: "key.pem", ForceMux: true, ServerPadding: true,
			PaddingScheme: "stop=2\n0=100-200\r\n1=200-300\n",
		}
		response := autoConfigResponse{ServerPort: json.RawMessage(`443`), TLS: json.RawMessage(`0`)}
		config, err := response.buildInboundConfig(test.protocol, auto)
		if (err == nil) != test.valid {
			t.Fatalf("protocol=%s fallback=%s accept=%v: %v", test.protocol, test.fallback, test.accept, err)
		}
		if !test.valid {
			continue
		}
		options := config.options.(*option.AnyTLSInboundOptions)
		if config.protocol != "anytls" || options.FallbackService != test.wantFallback ||
			!options.ForceMuxForTrojan || !options.ServerPaddingForTrojan {
			t.Fatal("combined inbound lost protocol-specific settings")
		}
		if test.protocol == "vless" && options.TLS != nil {
			t.Fatal("AcceptAnyTLS incorrectly changed the original VLESS TLS decision")
		}
		if !reflect.DeepEqual([]string(options.PaddingScheme), []string{"stop=2", "0=100-200\r", "1=200-300", ""}) {
			t.Fatal("local padding scheme was trimmed or newline-normalized")
		}
		if test.wantFallback == "" {
			continue
		}
		for _, network := range []string{"", "tcp", "TCP", " tcp", "ws", "grpc", "httpupgrade"} {
			response.Network = network
			_, err := response.buildInboundConfig(test.protocol, auto)
			if (err == nil) != (network == "" || network == "tcp") {
				t.Fatalf("combined transport %q: %v", network, err)
			}
		}
	}
}

func TestAutomaticProviderVLESSFlagAndTLS(t *testing.T) {
	response := autoConfigResponse{
		providerNormalized: true, Protocol: "vmess", PanelVLESS: true,
		ServerPort: json.RawMessage(`443`), TLS: json.RawMessage(`0`),
	}
	config, err := response.buildInboundConfig("v2ray", option.XBoardAutoInboundOptions{})
	if err != nil || config.protocol != "vless" {
		t.Fatalf("provider VLESS flag ignored: %v", err)
	}
	config, err = response.buildInboundConfig("v2ray", option.XBoardAutoInboundOptions{AcceptAnyTLS: true})
	if err != nil || config.protocol != "anytls" ||
		config.options.(*option.AnyTLSInboundOptions).FallbackService != "vless" {
		t.Fatalf("provider VLESS decision did not precede AcceptAnyTLS: %v", err)
	}
	response.Protocol = "anytls"
	response.PanelVLESS = false
	config, err = response.buildInboundConfig("anytls", option.XBoardAutoInboundOptions{})
	if err != nil || config.options.(*option.AnyTLSInboundOptions).TLS != nil {
		t.Fatalf("normalized provider TLS=false was overridden by UniProxy defaults: %v", err)
	}
}

func TestPanelByteSpeedLimits(t *testing.T) {
	for _, test := range []struct{ bytes, cap, want uint64 }{
		{156250, 0, 156250}, {156250, 100000, 100000}, {0, 100000, 100000}, {0, 0, 0},
	} {
		n := node{maxSpeed: test.cap}
		limits := n.userLimits(panelUser{SpeedLimit: 999, SpeedLimitBytes: &test.bytes})
		if limits.UploadBytesPerSecond != test.want || limits.DownloadBytesPerSecond != test.want {
			t.Fatal("exact provider byte speed was truncated to integer Mbps or escaped its node cap")
		}
	}
}

func TestAutomaticVLESSDecisionUsesEffectiveRawNodeType(t *testing.T) {
	for _, test := range []struct {
		name, apiType, rawType, localProtocol, want string
		localVLESS, panelVLESS, normalized          bool
	}{
		{"v2ray-default", "vmess", "v2ray", "", "vmess", false, false, true},
		{"local-v2ray", "vmess", "v2ray", "", "vless", true, false, true},
		{"panel-v2ray", "vmess", "V2RaY", "", "vless", false, true, true},
		{"both-v2ray", "vmess", "v2ray", "", "vless", true, true, true},
		{"explicit-vmess-local", "vmess", "vmess", "", "vmess", true, false, true},
		{"explicit-vmess-panel", "vmess", "vmess", "", "vmess", false, true, true},
		{"local-vmess-overrides-panel-v2ray", "vmess", "v2ray", "vmess", "vmess", true, true, true},
		{"local-v2ray-overrides-API-vmess", "vmess", "vmess", "V2Ray", "vless", true, false, true},
		{"local-trojan-is-independent", "vmess", "v2ray", "trojan", "trojan", true, true, true},
		{"explicit-vless-remains-vless", "vless", "vless", "", "vless", false, false, true},
		{"untrusted-panel-flag", "vmess", "v2ray", "", "vmess", false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := autoConfigResponse{
				providerNormalized: test.normalized, Protocol: test.apiType, rawNodeType: test.rawType,
				PanelVLESS: test.panelVLESS, ServerPort: json.RawMessage(`443`), TLS: json.RawMessage(`0`),
			}
			auto := option.XBoardAutoInboundOptions{
				Protocol: test.localProtocol, VLESS: test.localVLESS, DisableTLS: true,
			}
			config, err := response.buildInboundConfig(test.apiType, auto)
			if err != nil || config.protocol != test.want {
				t.Fatalf("effective local protocol=%q, want=%q, error=%v", config.protocol, test.want, err)
			}
			if response.Protocol != test.apiType || response.rawNodeType != test.rawType {
				t.Fatal("local protocol decision mutated the provider protocol")
			}
			if test.want != "vless" {
				return
			}
			auto.AcceptAnyTLS = true
			combined, err := response.buildInboundConfig(test.apiType, auto)
			if err != nil || combined.protocol != "anytls" ||
				combined.options.(*option.AnyTLSInboundOptions).FallbackService != "vless" {
				t.Fatalf("VLESS decision did not precede AnyTLS combination: protocol=%q error=%v", combined.protocol, err)
			}
		})
	}
}
