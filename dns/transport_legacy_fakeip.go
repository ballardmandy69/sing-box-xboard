package dns

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func (m *TransportManager) configureLegacyFakeIP(ctx context.Context, logger log.ContextLogger,
	options option.LegacyDNSFakeIPOptions,
) error {
	transport, err := m.registry.CreateDNSTransport(ctx, logger, "legacy-fakeip-store", C.DNSTypeFakeIP,
		&option.FakeIPDNSServerOptions{Inet4Range: options.Inet4Range, Inet6Range: options.Inet6Range, Legacy: true})
	if err != nil {
		return E.Cause(err, "initialize legacy fakeip store")
	}
	fakeIP, ok := transport.(adapter.FakeIPTransport)
	if !ok {
		return E.New("fakeip transport does not expose its store")
	}
	m.legacyFakeIPTransport = fakeIP
	m.fakeIPTransport = fakeIP
	return nil
}

// legacyFakeIPAlias exposes a server tag backed by the single root-configured store.
// @author lyt
// @date 2026-10-29
type legacyFakeIPAlias struct {
	adapter.FakeIPTransport
	tag string
}

func (t *legacyFakeIPAlias) Tag() string { return t.tag }

// The manager owns the shared transport lifecycle; aliases must not start or close it again.
func (t *legacyFakeIPAlias) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (t *legacyFakeIPAlias) lookupLegacy(domain string, strategy C.DomainStrategy) ([]netip.Addr, error) {
	var addresses []netip.Addr
	if strategy != C.DomainStrategyIPv6Only {
		address, err := t.Store().Create(domain, false)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	if strategy != C.DomainStrategyIPv4Only {
		address, err := t.Store().Create(domain, true)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}
