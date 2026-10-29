package inbound

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type legacyCaptureRouter struct {
	adapter.Router
	metadata adapter.InboundContext
	calls    int
}

func (r *legacyCaptureRouter) RouteConnection(_ context.Context, _ net.Conn, metadata adapter.InboundContext) error {
	r.metadata, r.calls = metadata, r.calls+1
	return nil
}

func (r *legacyCaptureRouter) RouteConnectionEx(_ context.Context, _ net.Conn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.metadata, r.calls = metadata, r.calls+1
}

func (r *legacyCaptureRouter) RoutePacketConnection(_ context.Context, _ N.PacketConn, metadata adapter.InboundContext) error {
	r.metadata, r.calls = metadata, r.calls+1
	return nil
}

func (r *legacyCaptureRouter) RoutePacketConnectionEx(_ context.Context, _ N.PacketConn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.metadata, r.calls = metadata, r.calls+1
}

func (r *legacyCaptureRouter) PreMatch(metadata adapter.InboundContext, _ []byte) adapter.PreMatchResult {
	r.metadata, r.calls = metadata, r.calls+1
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

func TestLegacyInboundJSONAndRegistryMetadata(t *testing.T) {
	registry := NewRegistry()
	var constructedRouter adapter.Router
	Register(registry, C.TypeSOCKS, func(_ context.Context, router adapter.Router, _ log.ContextLogger,
		_ string, _ option.SocksInboundOptions,
	) (adapter.Inbound, error) {
		constructedRouter = router
		return nil, nil
	})
	ctx := service.ContextWith[option.InboundOptionsRegistry](context.Background(), registry)
	var inbound option.Inbound
	require.NoError(t, json.UnmarshalContext(ctx, []byte(`{"type":"socks","sniff":true,
		"sniff_override_destination":true,"sniff_timeout":"40ms","domain_strategy":"ipv4_only"}`), &inbound))
	options := inbound.Options.(*option.SocksInboundOptions)
	require.True(t, options.SniffEnabled)
	require.Equal(t, option.DomainStrategy(C.DomainStrategyIPv4Only), options.DomainStrategy)
	capture := new(legacyCaptureRouter)
	_, err := registry.Create(ctx, capture, log.NewNOPFactory().Logger(), "test", inbound.Type, inbound.Options)
	require.NoError(t, err)
	metadata := adapter.InboundContext{Inbound: "test", User: "user"}
	require.NoError(t, constructedRouter.RouteConnection(ctx, nil, metadata))
	constructedRouter.RouteConnectionEx(ctx, nil, metadata, nil)
	require.NoError(t, constructedRouter.RoutePacketConnection(ctx, nil, metadata))
	constructedRouter.RoutePacketConnectionEx(ctx, nil, metadata, nil)
	constructedRouter.PreMatch(metadata, nil)
	require.Equal(t, 5, capture.calls)
	require.Equal(t, options.InboundOptions, capture.metadata.LegacyInboundOptions)
	require.Equal(t, "user", capture.metadata.User)

	// A detour target must replace the source settings even when its own options are empty.
	metadata = capture.metadata
	_, err = registry.Create(ctx, capture, log.NewNOPFactory().Logger(), "target", C.TypeSOCKS, nil)
	require.NoError(t, err)
	constructedRouter.RouteConnectionEx(ctx, nil, metadata, nil)
	require.Equal(t, option.InboundOptions{}, capture.metadata.LegacyInboundOptions)
}

func TestLegacyInboundTunOptionsPromotedGetter(t *testing.T) {
	options := &option.TunInboundOptions{InboundOptions: option.InboundOptions{SniffEnabled: true}}
	capture := new(legacyCaptureRouter)
	router := withLegacyInboundOptions(capture, options)
	router.PreMatch(adapter.InboundContext{}, nil)
	require.True(t, capture.metadata.LegacyInboundOptions.SniffEnabled)
}
