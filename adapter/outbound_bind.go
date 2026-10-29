package adapter

import (
	"context"
	"net/netip"
)

// outboundBindAddressKey carries the actual accepting socket IP through protocol session contexts.
// @author lyt
// @date 2026-10-29
type outboundBindAddressKey struct{}

// WithOutboundBindAddress binds outbound TCP sockets to a trusted local address selected by the listener.
func WithOutboundBindAddress(ctx context.Context, address netip.Addr) context.Context {
	return context.WithValue(ctx, outboundBindAddressKey{}, address.Unmap())
}

// OutboundBindAddressFrom returns the listener-selected source address, never the client or PROXY address.
func OutboundBindAddressFrom(ctx context.Context) netip.Addr {
	address, _ := ctx.Value(outboundBindAddressKey{}).(netip.Addr)
	return address
}
