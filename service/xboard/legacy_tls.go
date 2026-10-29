package xboard

import (
	"context"
	stdjson "encoding/json"
	"errors"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// legacyTLSOptions limits TLSJson to the fields accepted by the original TLS option type.
// Keeping this wire shape separate prevents modern TLS additions from changing legacy configuration.
// @author lyt
// @date 2026-10-29
type legacyTLSOptions struct {
	Enabled         bool                       `json:"enabled"`
	Insecure        bool                       `json:"insecure"`
	KernelTX        bool                       `json:"ktls_tx"`
	ServerName      string                     `json:"server_name"`
	SNIRegex        string                     `json:"sni_regex"`
	ALPN            badoption.Listable[string] `json:"alpn"`
	MinVersion      string                     `json:"min_version"`
	MaxVersion      string                     `json:"max_version"`
	CipherSuites    badoption.Listable[string] `json:"cipher_suites"`
	Certificate     badoption.Listable[string] `json:"certificate"`
	CertificatePath string                     `json:"certificate_path"`
	Key             badoption.Listable[string] `json:"key"`
	KeyPath         string                     `json:"key_path"`
	ACME            *option.InboundACMEOptions `json:"acme"`
	ECH             *option.InboundECHOptions  `json:"ech"`
}

func decodeLegacyTLSJSON(raw string) (*option.InboundTLSOptions, error) {
	data := []byte(raw)
	// The context decoder supports Listable fields but also accepts JSON extensions.
	// Validate the original JSON grammar before using its v1-compatible field decoding.
	if !stdjson.Valid(data) {
		return nil, errors.New("invalid TLSJson configuration")
	}
	var decoded legacyTLSOptions
	if err := json.UnmarshalContext(context.Background(), data, &decoded); err != nil {
		return nil, errors.New("invalid TLSJson configuration")
	}
	if decoded.Enabled && decoded.KernelTX {
		return nil, errors.New("legacy TLSJson ktls_tx is unsupported")
	}
	return &option.InboundTLSOptions{
		Enabled: decoded.Enabled, Insecure: decoded.Insecure,
		ServerName: decoded.ServerName, SNIRegex: decoded.SNIRegex, ALPN: decoded.ALPN,
		MinVersion: decoded.MinVersion, MaxVersion: decoded.MaxVersion, CipherSuites: decoded.CipherSuites,
		Certificate: decoded.Certificate, CertificatePath: decoded.CertificatePath,
		Key: decoded.Key, KeyPath: decoded.KeyPath, ACME: decoded.ACME, ECH: decoded.ECH,
	}, nil
}
