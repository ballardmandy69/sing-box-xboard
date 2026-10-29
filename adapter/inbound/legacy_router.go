package inbound

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// legacyInboundRouter attaches configuration after protocol handlers construct stream metadata.
// @author lyt
// @date 2026-10-29
type legacyInboundRouter struct {
	adapter.Router
	options option.InboundOptions
}

func withLegacyInboundOptions(router adapter.Router, rawOptions any) adapter.Router {
	var options option.InboundOptions
	provider, loaded := rawOptions.(interface{ TakeLegacyInboundOptions() option.InboundOptions })
	if loaded {
		options = provider.TakeLegacyInboundOptions()
	}
	// Even zero options replace the source inbound's configuration after an inbound detour.
	return &legacyInboundRouter{Router: router, options: options}
}

func (r *legacyInboundRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	metadata.LegacyInboundOptions = r.options
	return r.Router.RouteConnection(ctx, conn, metadata)
}

func (r *legacyInboundRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.LegacyInboundOptions = r.options
	r.Router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (r *legacyInboundRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	metadata.LegacyInboundOptions = r.options
	return r.Router.RoutePacketConnection(ctx, conn, metadata)
}

func (r *legacyInboundRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.LegacyInboundOptions = r.options
	r.Router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (r *legacyInboundRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	metadata.LegacyInboundOptions = r.options
	return r.Router.PreMatch(metadata, firstPacket)
}
