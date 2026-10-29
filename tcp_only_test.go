package box

import (
	"errors"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestUDPProtocolsFailBeforeInitialization(t *testing.T) {
	for _, protocol := range []string{C.TypeHysteria, C.TypeHysteria2, C.TypeTUIC} {
		t.Run(protocol, func(t *testing.T) {
			for _, options := range []option.Options{
				{Inbounds: []option.Inbound{{Type: protocol}}},
				{Outbounds: []option.Outbound{{Type: protocol}}},
			} {
				if _, err := New(Options{Options: options}); !errors.Is(err, C.ErrUDPDisabled) {
					t.Fatalf("UDP protocol did not fail before registry lookup: %v", err)
				}
			}
		})
	}
	for _, protocol := range []string{C.TypeWireGuard, C.TypeTailscale} {
		_, err := New(Options{Options: option.Options{Endpoints: []option.Endpoint{{Type: protocol}}}})
		if !errors.Is(err, C.ErrUDPDisabled) {
			t.Fatalf("UDP endpoint did not fail before registry lookup: %v", err)
		}
	}
	_, err := New(Options{Options: option.Options{Services: []option.Service{{Type: C.TypeHysteriaRealm}}}})
	if !errors.Is(err, C.ErrUDPDisabled) {
		t.Fatalf("UDP realm did not fail before registry lookup: %v", err)
	}
}

func TestTCPPolicyLeavesResolverOptionsIntact(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	options.DNS.Servers = []option.DNSServerOptions{{Type: C.DNSTypeUDP}}
	if err := validateTCPOnlyProxies(options); err != nil || options.DNS.Servers[0].Type != C.DNSTypeUDP {
		t.Fatal("proxy transport policy changed internal DNS resolution")
	}
}

func TestOptionalTransportsCannotCarryTCPOverUDP(t *testing.T) {
	for _, options := range []any{
		&option.NaiveOutboundOptions{QUIC: true},
		&option.CloudflaredInboundOptions{},
		&option.CloudflaredInboundOptions{Protocol: "quic"},
		&option.OpenConnectEndpointOptions{},
		&option.OpenConnectEndpointOptions{NoUDP: true, System: true},
		&option.OpenVPNClientEndpointOptions{},
		&option.OpenVPNClientEndpointOptions{Network: "tcp", Servers: []option.OpenVPNRemoteOptions{{Network: "udp"}}},
		&option.OpenVPNClientEndpointOptions{Network: "tcp",
			OpenVPNEndpointOptions: option.OpenVPNEndpointOptions{System: true}},
		&option.OpenVPNServerEndpointOptions{},
	} {
		if err := validateTCPOnlyTransport(options); !errors.Is(err, C.ErrUDPDisabled) {
			t.Fatalf("UDP or system-route transport %T bypassed policy: %v", options, err)
		}
	}
	for _, options := range []any{
		&option.NaiveOutboundOptions{},
		&option.CloudflaredInboundOptions{Protocol: "http2"},
		&option.OpenConnectEndpointOptions{NoUDP: true},
		&option.OpenVPNClientEndpointOptions{Network: "tcp"},
		&option.OpenVPNClientEndpointOptions{Servers: []option.OpenVPNRemoteOptions{{Network: "tcp6"}}},
		&option.OpenVPNServerEndpointOptions{Network: "tcp"},
	} {
		if err := validateTCPOnlyTransport(options); err != nil {
			t.Fatalf("TCP transport %T was incorrectly rejected: %v", options, err)
		}
	}
}
