// Package anytlsnative adapts AnyTLS sessions to the independent native transport.
// @author lyt
// @date 2026-10-29
package anytlsnative

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/anytlsnative"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

func decodeKey(value, field string, public bool) ([]byte, error) {
	var key []byte
	var err error
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		key, err = encoding.DecodeString(value)
		if err == nil {
			break
		}
	}
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s must be a base64-encoded 32-byte X25519 key", field)
	}
	if public {
		peer, keyErr := ecdh.X25519().NewPublicKey(key)
		if keyErr != nil {
			return nil, fmt.Errorf("invalid %s", field)
		}
		// A fixed non-secret scalar suffices to reject low-order public points.
		probeBytes := make([]byte, 32)
		probeBytes[0] = 9
		probe, _ := ecdh.X25519().NewPrivateKey(probeBytes)
		if _, keyErr = probe.ECDH(peer); keyErr != nil {
			return nil, fmt.Errorf("invalid %s: low-order X25519 point", field)
		}
	}
	return key, nil
}

func transportPadding(options *option.AnyTLSNativePaddingOptions) (T.PaddingOptions, error) {
	padding := T.DefaultPaddingOptions()
	if options != nil {
		padding = T.PaddingOptions{
			MaxPadding: options.MaxPadding, MaxPercent: options.MaxPercent, MaxTotal: options.MaxTotal,
		}
	}
	return padding, padding.Validate()
}

func handshakeTimeout(value time.Duration) (time.Duration, error) {
	if value < 0 {
		return 0, fmt.Errorf("handshake_timeout must be positive")
	}
	if value == 0 {
		value = 10 * time.Second
	}
	return value, nil
}

func userCredentials(users []option.AnyTLSUser) (map[string][32]byte, error) {
	credentials := make(map[string][32]byte, len(users))
	passwords := make(map[[32]byte]struct{}, len(users))
	for _, user := range users {
		if strings.TrimSpace(user.Name) == "" || user.Password == "" {
			return nil, fmt.Errorf("anytls-native users require a nonempty name and password")
		}
		if _, exists := credentials[user.Name]; exists {
			return nil, fmt.Errorf("duplicate anytls-native user name")
		}
		digest := sha256.Sum256([]byte(user.Password))
		if _, exists := passwords[digest]; exists {
			return nil, fmt.Errorf("duplicate anytls-native user credential")
		}
		credentials[user.Name] = digest
		passwords[digest] = struct{}{}
	}
	return credentials, nil
}

func isUDPOverTCP(destination M.Socksaddr) bool {
	domain := strings.TrimSuffix(strings.ToLower(destination.Fqdn), ".")
	return domain == uot.MagicAddress || domain == uot.LegacyMagicAddress
}
