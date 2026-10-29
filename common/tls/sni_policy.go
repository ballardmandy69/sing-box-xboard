package tls

import (
	"crypto/tls"
	"fmt"
	"regexp"
	"slices"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
)

// applySNIPolicy restores nyafw's last-line regex and optional IPv6 exception for static certificates.
// @author lyt
// @date 2026-10-29
func applySNIPolicy(config *tls.Config, policy string) error {
	if policy == "" {
		return nil
	}
	lines := strings.Split(policy, "\n")
	pattern, err := regexp.Compile(lines[len(lines)-1])
	if err != nil {
		// Return a configuration error instead of reproducing the original MustCompile panic.
		return fmt.Errorf("invalid SNI policy regex")
	}
	skipIPv6 := slices.Contains(lines[:len(lines)-1], "skip-ipv6")
	previous := config.GetConfigForClient
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		bypass := skipIPv6 && hello.Conn != nil && M.SocksaddrFromNet(hello.Conn.RemoteAddr()).Unwrap().Addr.Is6()
		if !bypass && !pattern.MatchString(hello.ServerName) {
			return nil, fmt.Errorf("TLS server name rejected by SNI policy")
		}
		if previous != nil {
			return previous(hello)
		}
		return nil, nil
	}
	return nil
}
