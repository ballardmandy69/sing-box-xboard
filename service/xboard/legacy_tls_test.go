package xboard

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestDecodeLegacyTLSJSONMapsOnlyOriginalFields(t *testing.T) {
	decoded, err := decodeLegacyTLSJSON(`{
		"enabled":true,"insecure":true,"ktls_tx":false,
		"server_name":"legacy.example","sni_regex":"^legacy\\.example$",
		"alpn":"h2","min_version":"1.2","max_version":"1.3",
		"cipher_suites":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"certificate":"certificate-pem","certificate_path":"cert.pem",
		"key":["key-pem"],"key_path":"key.pem",
		"acme":{"domain":"legacy.example","email":"operator@example.invalid"},
		"ech":{"enabled":true,"key":"ech-key","key_path":"ech.pem"},
		"reality":{"enabled":true},"kernel_tx":true,"kernel_rx":true,
		"curve_preferences":["invalid-curve"],"client_authentication":"invalid-client-auth",
		"client_certificate":"client-pem","client_certificate_path":"client.pem",
		"client_certificate_public_key_sha256":"invalid-base64",
		"handshake_timeout":"invalid-duration","certificate_provider":{"enabled":true}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	want := &option.InboundTLSOptions{
		Enabled: true, Insecure: true, ServerName: "legacy.example", SNIRegex: `^legacy\.example$`,
		ALPN: []string{"h2"}, MinVersion: "1.2", MaxVersion: "1.3",
		CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		Certificate:  []string{"certificate-pem"}, CertificatePath: "cert.pem",
		Key: []string{"key-pem"}, KeyPath: "key.pem",
		ACME: &option.InboundACMEOptions{Domain: []string{"legacy.example"}, Email: "operator@example.invalid"},
		ECH:  &option.InboundECHOptions{Enabled: true, Key: []string{"ech-key"}, KeyPath: "ech.pem"},
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("legacy field conversion differs:\n got %#v\nwant %#v", decoded, want)
	}
}

func TestDecodeLegacyTLSJSONPreservesCaseAndDuplicateFields(t *testing.T) {
	decoded, err := decodeLegacyTLSJSON(`{
		"enabled":false,"ENABLED":true,"SERVER_NAME":"first.example","server_name":"last.example",
		"sni_regex":"first","SNI_REGEX":"last","alpn":["h2","http/1.1"],"ALPN":"last-alpn",
		"certificate":["first"],"CERTIFICATE":["second","third"],
		"acme":{"email":"first@example.invalid"},"ACME":{"data_directory":"cache"},
		"ech":{"enabled":true},"ECH":{"key_path":"ech.pem"}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Enabled || decoded.ServerName != "last.example" || decoded.SNIRegex != "last" ||
		!reflect.DeepEqual([]string(decoded.ALPN), []string{"last-alpn"}) ||
		!reflect.DeepEqual([]string(decoded.Certificate), []string{"second", "third"}) {
		t.Fatalf("case-insensitive duplicate field order differs: %#v", decoded)
	}
	if decoded.ACME == nil || decoded.ACME.Email != "first@example.invalid" ||
		decoded.ACME.DataDirectory != "cache" || decoded.ECH == nil || !decoded.ECH.Enabled ||
		decoded.ECH.KeyPath != "ech.pem" {
		t.Fatalf("duplicate nested objects were not merged: ACME=%#v ECH=%#v", decoded.ACME, decoded.ECH)
	}
	decoded, err = decodeLegacyTLSJSON(`{"enabled":true,"enabled":null,"server_name":"kept","server_name":null}`)
	if err != nil || !decoded.Enabled || decoded.ServerName != "kept" {
		t.Fatalf("null scalar differs from v1 decoding: %#v %v", decoded, err)
	}
}

func TestDecodeLegacyTLSJSONEmptyNullAndUnknownFields(t *testing.T) {
	for _, raw := range []string{
		`{}`, `null`, " \n null \t ",
		`{"reality":true,"kernel_tx":"ignored","kernel_rx":{},"enabled_by_new_version":true}`,
		`{"ServerName":"ignored","sniRegex":"ignored","ktls_tx":true}`,
	} {
		decoded, err := decodeLegacyTLSJSON(raw)
		if err != nil || decoded == nil || !reflect.DeepEqual(decoded, &option.InboundTLSOptions{}) {
			t.Fatalf("zero legacy options for %s: %#v %v", raw, decoded, err)
		}
	}
}

func TestDecodeLegacyTLSJSONRejectsInvalidGrammarAndKnownTypes(t *testing.T) {
	for _, raw := range []string{
		``, `{"enabled":true,}`, `{"enabled":/* comment */true}`, "{\n# comment\n}",
		`{"enabled":true}//comment`, `{} {}`, `[]`, `true`, `"tls"`, `1`,
		`{"enabled":"yes"}`, `{"server_name":[]}`, `{"alpn":1}`, `{"certificate":[false]}`,
		`{"key":{}}`, `{"acme":true}`, `{"ech":[]}`, `{"ktls_tx":"true"}`,
	} {
		decoded, err := decodeLegacyTLSJSON(raw)
		if err == nil || decoded != nil || err.Error() != "invalid TLSJson configuration" {
			t.Fatalf("invalid legacy JSON accepted or leaked detail for %s: %#v %v", raw, decoded, err)
		}
	}
}

func TestDecodeLegacyTLSJSONKernelTXGateUsesFinalLegacyValues(t *testing.T) {
	for _, raw := range []string{
		`{"enabled":true,"ktls_tx":true}`,
		`{"ENABLED":true,"KTLS_TX":true,"kernel_tx":false}`,
		`{"enabled":false,"ktls_tx":true,"enabled":true}`,
	} {
		decoded, err := decodeLegacyTLSJSON(raw)
		if decoded != nil || err == nil || !strings.Contains(err.Error(), "ktls_tx is unsupported") {
			t.Fatalf("unsupported legacy kTLS was accepted: %#v %v", decoded, err)
		}
	}
	for _, raw := range []string{
		`{"enabled":false,"ktls_tx":true}`,
		`{"enabled":true,"ktls_tx":true,"KTLS_TX":false}`,
		`{"enabled":true,"ktls_tx":true,"ENABLED":false}`,
		`{"enabled":true,"kernel_tx":true}`,
	} {
		decoded, err := decodeLegacyTLSJSON(raw)
		if err != nil || decoded == nil || decoded.KernelTx || decoded.KernelRx {
			t.Fatalf("legacy kTLS condition differs: %#v %v", decoded, err)
		}
	}
}
