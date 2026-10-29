package dialer

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/common/listener"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/database64128/tfo-go/v2"
)

// dialBoundContext uses a per-call dialer copy so concurrent nodes cannot change each other's source IP.
// @author lyt
// @date 2026-10-29
func (d *DefaultDialer) dialBoundContext(
	ctx context.Context, network string, destination M.Socksaddr, source netip.Addr,
) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.New("AutoOutIP only supports TCP")
	}
	if source.IsUnspecified() || source.IsMulticast() || source.Is4() != destination.IsIPv4() {
		return nil, E.New("AutoOutIP source and destination address families do not match")
	}
	base := &d.dialer4
	if source.Is6() {
		base = &d.dialer6
	}
	bound := tfo.Dialer{Dialer: base.Dialer, DisableTFO: base.DisableTFO}
	bound.LocalAddr = &net.TCPAddr{IP: source.AsSlice(), Zone: source.Zone()}
	conn, err := listener.ListenNetworkNamespace[net.Conn](ctx, d.netns, func() (net.Conn, error) {
		return DialSlowContext(&bound, ctx, network, destination)
	})
	return d.trackConn(ctx, destination, conn, err)
}
