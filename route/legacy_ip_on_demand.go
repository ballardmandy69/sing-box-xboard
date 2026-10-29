package route

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// resolveIPOnDemand supplies destination addresses only after the first rule pass has no terminal match.
func (r *Router) resolveIPOnDemand(ctx context.Context, metadata *adapter.InboundContext, sniffOriginalIP netip.Addr) error {
	domain := metadata.Destination.Fqdn
	addresses, err := r.dns.Lookup(adapter.WithContext(ctx, metadata), domain, adapter.DNSQueryOptions{})
	if err == nil && len(addresses) > 0 {
		metadata.DestinationAddresses = addresses
		r.logger.DebugContext(ctx, "ip_on_demand: resolved ", domain, " to ", addresses)
		return nil
	}
	if err == nil {
		err = E.New("empty DNS response")
	}
	if !sniffOriginalIP.IsValid() {
		return E.Cause(err, "ip_on_demand: resolve ", domain)
	}
	metadata.Destination = M.Socksaddr{Addr: sniffOriginalIP, Port: metadata.Destination.Port}
	metadata.DestinationAddresses = nil
	r.logger.DebugContext(ctx, "ip_on_demand: restore sniffed destination ", metadata.Destination, ": ", err)
	return nil
}
