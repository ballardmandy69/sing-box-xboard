package xboard

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestAutoTLSOriginalProviderSemantics(t *testing.T) {
	auto := option.XBoardAutoInboundOptions{
		CertificatePath: "cert.pem", KeyPath: "key.pem", SNIPolicy: `^allowed\.test$`,
	}
	for _, protocol := range []string{"anytls", "trojan", "vmess", "vless"} {
		for _, mode := range []string{"0", "1", "2"} {
			r := autoConfigResponse{
				TLS: json.RawMessage(mode), ServerName: "ignored.test",
				TLSSettings: json.RawMessage(`{"server_name":"ignored.test","alpn":["h2"],"reality":{}}`),
			}
			options, err := r.tlsOptions(protocol, auto)
			if err != nil {
				t.Fatal(err)
			}
			enabled := protocol == "anytls" || protocol == "trojan" || mode == "1"
			if (options != nil && options.Enabled) != enabled {
				t.Fatalf("%s tls=%s was not mapped through provider semantics", protocol, mode)
			}
			if options != nil && (options.ServerName != "" || len(options.ALPN) != 0 || options.SNIRegex != auto.SNIPolicy) {
				t.Fatal("default TLS merged fields absent from the original central builder")
			}
			disabled := auto
			disabled.DisableTLS = true
			options, err = r.tlsOptions(protocol, disabled)
			if err != nil || options != nil {
				t.Fatal("DisableTLS did not override provider TLS")
			}
		}
	}
}

func TestAutoTLSJSONReplacesLocalAndPanelTLS(t *testing.T) {
	r := autoConfigResponse{TLS: json.RawMessage(`1`), ServerName: "panel.test"}
	for _, content := range []string{"{}", "null", `{"enabled":false,"unknown_field":true}`} {
		options, err := r.tlsOptions("anytls", option.XBoardAutoInboundOptions{
			TLSJSON: content, CertificatePath: "ignored.pem", KeyPath: "ignored.key", SNIPolicy: "ignored",
		})
		if err != nil || options == nil || options.Enabled || options.CertificatePath != "" || options.SNIRegex != "" {
			t.Fatalf("TLSJson must decode to a fresh zero value: %s: %v", content, err)
		}
	}
	options, err := r.tlsOptions("trojan", option.XBoardAutoInboundOptions{
		DisableTLS: true,
		TLSJSON: `{"enabled":true,"server_name":"json.test","sni_regex":"^json\\.test$",` +
			`"alpn":"h2","certificate_path":"json.pem","key_path":"json.key"}`,
	})
	if err != nil || !options.Enabled || options.ServerName != "json.test" || options.SNIRegex != `^json\.test$` ||
		len(options.ALPN) != 1 || options.ALPN[0] != "h2" || options.CertificatePath != "json.pem" {
		t.Fatalf("TLSJson lost precedence or original fields: %v", err)
	}
	for _, content := range []string{`{`, `{"enabled":"secret-value"}`, `{"enabled":true,"ktls_tx":true}`} {
		if _, err := r.tlsOptions("anytls", option.XBoardAutoInboundOptions{TLSJSON: content}); err == nil {
			t.Fatal("malformed or unsupported original TLSJson accepted")
		}
	}
}
