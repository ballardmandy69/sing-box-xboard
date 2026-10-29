package box

import (
	"fmt"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// validateTCPOnlyProxies rejects UDP protocol transports before creating their resources.
// DNS resolver transports are independent of proxy forwarding and retain their configured behavior.
// @author lyt
// @date 2026-10-29
func validateTCPOnlyProxies(options option.Options) error {
	check := func(kind, protocol string) error {
		switch protocol {
		case C.TypeHysteria, C.TypeHysteria2, C.TypeTUIC, C.TypeWireGuard, C.TypeTailscale, C.TypeHysteriaRealm:
			return fmt.Errorf("%s/%s: %w", kind, protocol, C.ErrUDPDisabled)
		}
		return nil
	}
	for _, inbound := range options.Inbounds {
		if err := check("inbound", inbound.Type); err != nil {
			return err
		}
		if err := validateTCPOnlyTransport(inbound.Options); err != nil {
			return err
		}
	}
	for _, outbound := range options.Outbounds {
		if err := check("outbound", outbound.Type); err != nil {
			return err
		}
		if err := validateTCPOnlyTransport(outbound.Options); err != nil {
			return err
		}
	}
	for _, endpoint := range options.Endpoints {
		if err := check("endpoint", endpoint.Type); err != nil {
			return err
		}
		if err := validateTCPOnlyTransport(endpoint.Options); err != nil {
			return err
		}
	}
	for _, service := range options.Services {
		if err := check("service", service.Type); err != nil {
			return err
		}
	}
	return nil
}

func validateTCPOnlyTransport(options any) error {
	switch options := options.(type) {
	case *option.NaiveOutboundOptions:
		if options.QUIC {
			return fmt.Errorf("naive quic transport: %w", C.ErrUDPDisabled)
		}
	case *option.CloudflaredInboundOptions:
		if options.Protocol != "http2" && options.Protocol != "h2mux" {
			return fmt.Errorf("cloudflared requires an explicit HTTP/2 transport: %w", C.ErrUDPDisabled)
		}
	case *option.OpenConnectEndpointOptions:
		if !options.NoUDP || options.System {
			return fmt.Errorf("openconnect requires no_udp and userspace routing: %w", C.ErrUDPDisabled)
		}
	case *option.OpenVPNClientEndpointOptions:
		if options.System {
			return fmt.Errorf("openvpn requires userspace routing: %w", C.ErrUDPDisabled)
		}
		servers := options.Servers
		if len(servers) == 0 {
			servers = []option.OpenVPNRemoteOptions{{Network: options.Network}}
		}
		for _, server := range servers {
			network := server.Network
			if network == "" {
				network = options.Network
			}
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return fmt.Errorf("openvpn remotes require an explicit TCP transport: %w", C.ErrUDPDisabled)
			}
		}
	case *option.OpenVPNServerEndpointOptions:
		if options.Network != "tcp" || options.System {
			return fmt.Errorf("openvpn server requires TCP and userspace routing: %w", C.ErrUDPDisabled)
		}
	}
	return nil
}
