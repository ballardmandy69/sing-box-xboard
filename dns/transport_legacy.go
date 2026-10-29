package dns

import (
	"context"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

type legacyDNSContextKey struct{}

func legacyDefaultOutbound(ctx context.Context) bool {
	legacy, _ := ctx.Value(legacyDNSContextKey{}).(bool)
	return legacy
}

func (r *TransportRegistry) createLegacyTransport(ctx context.Context, logger log.ContextLogger,
	tag string, rawOptions any,
) (adapter.DNSTransport, error) {
	options, ok := rawOptions.(*option.LegacyDNSServerOptions)
	if !ok || options == nil {
		return nil, E.New("invalid legacy DNS server options")
	}
	if strings.HasPrefix(options.Address, "rcode://") {
		return newLegacyRcodeTransport(tag, strings.TrimPrefix(options.Address, "rcode://"))
	}
	if options.Address == "fakeip" {
		manager, ok := service.FromContext[adapter.DNSTransportManager](ctx).(*TransportManager)
		if !ok || manager.legacyFakeIPTransport == nil {
			return nil, E.New("legacy fakeip server requires dns.fakeip.enabled")
		}
		return &legacyFakeIPAlias{FakeIPTransport: manager.legacyFakeIPTransport, tag: tag}, nil
	}
	transportType, typedOptions, err := convertLegacyDNSServer(*options)
	if err != nil {
		return nil, err
	}
	// The default outbound is selected when dialing, after outbounds have been created.
	ctx = context.WithValue(ctx, legacyDNSContextKey{}, true)
	return r.CreateDNSTransport(ctx, logger, tag, transportType, typedOptions)
}

func convertLegacyDNSServer(options option.LegacyDNSServerOptions) (string, any, error) {
	dialOptions := option.DialerOptions{
		Detour: options.Detour,
		AbstractDialerOptions: option.AbstractDialerOptions{
			FallbackDelay: options.AddressFallbackDelay,
		},
	}
	if options.AddressResolver != "" {
		dialOptions.DomainResolver = &option.DomainResolveOptions{
			Server: options.AddressResolver, Strategy: options.AddressStrategy,
		}
	}
	localOptions := option.LocalDNSServerOptions{
		RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: dialOptions},
	}
	if options.Address == "local" {
		return C.DNSTypeLocal, &localOptions, nil
	}
	address := options.Address
	if address == "" {
		return "", nil, E.New("missing legacy DNS server address")
	}
	if ip, err := netip.ParseAddr(address); err == nil {
		address = "udp://" + netip.AddrPortFrom(ip, 53).String()
	} else if !strings.Contains(address, "://") {
		address = "udp://" + address
	}
	serverURL, err := url.Parse(address)
	if err != nil {
		return "", nil, E.Cause(err, "parse legacy DNS server address")
	}
	if serverURL.User != nil || serverURL.Fragment != "" {
		return "", nil, E.New("invalid legacy DNS server address")
	}
	if serverURL.Scheme == C.DNSTypeDHCP {
		return C.DNSTypeDHCP, &option.DHCPDNSServerOptions{
			LocalDNSServerOptions: localOptions, Interface: serverURL.Host,
		}, nil
	}
	server := serverURL.Hostname()
	if server == "" {
		return "", nil, E.New("missing legacy DNS server host")
	}
	if _, err = netip.ParseAddr(server); err != nil && options.AddressResolver == "" {
		return "", nil, E.New("missing address_resolver for legacy DNS server: ", server)
	}
	var port uint64
	if portText := serverURL.Port(); portText != "" {
		port, err = strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return "", nil, E.New("invalid legacy DNS server port: ", portText)
		}
	}
	remoteOptions := option.RemoteDNSServerOptions{
		RawLocalDNSServerOptions: localOptions.RawLocalDNSServerOptions,
		DNSServerAddressOptions:  option.DNSServerAddressOptions{Server: server, ServerPort: uint16(port)},
	}
	tlsOptions := option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: remoteOptions}
	switch serverURL.Scheme {
	case C.DNSTypeUDP, C.DNSTypeTCP:
		if serverURL.Path != "" || serverURL.RawQuery != "" {
			return "", nil, E.New("unexpected path or query in legacy DNS server address")
		}
		return serverURL.Scheme, &remoteOptions, nil
	case C.DNSTypeTLS, C.DNSTypeQUIC:
		return serverURL.Scheme, &tlsOptions, nil
	case C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		path := serverURL.EscapedPath()
		if path == "" {
			path = "/dns-query"
		}
		if serverURL.RawQuery != "" {
			path += "?" + serverURL.RawQuery
		}
		return serverURL.Scheme, &option.RemoteHTTPSDNSServerOptions{
			RemoteTLSDNSServerOptions: tlsOptions, Path: path,
		}, nil
	default:
		return "", nil, E.New("unsupported legacy DNS address scheme: ", serverURL.Scheme)
	}
}

// legacyRcodeTransport implements the original local DNS status response server.
// @author lyt
// @date 2026-10-29
type legacyRcodeTransport struct {
	TransportAdapter
	rcode int
}

func newLegacyRcodeTransport(tag string, name string) (*legacyRcodeTransport, error) {
	codes := map[string]int{
		"success": mDNS.RcodeSuccess, "format_error": mDNS.RcodeFormatError,
		"server_failure": mDNS.RcodeServerFailure, "name_error": mDNS.RcodeNameError,
		"not_implemented": mDNS.RcodeNotImplemented, "refused": mDNS.RcodeRefused,
	}
	rcode, loaded := codes[name]
	if !loaded {
		return nil, E.New("unknown legacy DNS rcode: ", name)
	}
	return &legacyRcodeTransport{TransportAdapter: NewTransportAdapter("rcode", tag, nil), rcode: rcode}, nil
}

func (t *legacyRcodeTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (t *legacyRcodeTransport) Reset() {}

func (t *legacyRcodeTransport) Exchange(_ context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	return FixedResponseStatus(message, t.rcode), nil
}

func (t *legacyRcodeTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg,
	callback func(*mDNS.Msg, error),
) {
	callback(t.Exchange(ctx, message))
}
