package anytlsnative

import (
	"context"
	"fmt"
	"net"
	"os"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/anytlsnative"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AnyTLSNativeOutboundOptions](registry, C.TypeAnyTLSNative, NewOutbound)
}

var _ adapter.OutboundWithMultiplex = (*Outbound)(nil)

// Outbound owns one user's AnyTLS pool over native encryption and optional TLS.
// @author lyt
// @date 2026-10-29
type Outbound struct {
	outbound.Adapter
	ctx           context.Context
	dialer        N.Dialer
	server        M.Socksaddr
	transport     T.ClientConfig
	clientOptions anytls.ClientConfig
	client        *anytls.Client
	logger        log.ContextLogger
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger,
	tag string, options option.AnyTLSNativeOutboundOptions,
) (adapter.Outbound, error) {
	if options.Password == "" {
		return nil, fmt.Errorf("anytls-native password is required")
	}
	if options.TCPFastOpen {
		return nil, fmt.Errorf("anytls-native does not support tcp_fast_open")
	}
	key, err := decodeKey(options.ServerPublicKey, "server_public_key", true)
	if err != nil {
		return nil, err
	}
	padding, err := transportPadding(options.Padding)
	if err != nil {
		return nil, err
	}
	timeout, err := handshakeTimeout(options.HandshakeTimeout.Build())
	if err != nil {
		return nil, err
	}
	d, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx, Options: options.DialerOptions, RemoteIsDomain: options.ServerIsDomain(),
	})
	if err != nil {
		return nil, err
	}
	if options.TLS != nil && options.TLS.Enabled {
		if options.TLS.Insecure {
			return nil, fmt.Errorf("anytls-native TLS wrapping requires certificate verification")
		}
		tlsConfig, tlsErr := tls.NewClient(ctx, logger, options.Server, *options.TLS)
		if tlsErr != nil {
			return nil, tlsErr
		}
		d = tls.NewDialer(d, tlsConfig)
	}
	h := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(
			C.TypeAnyTLSNative, tag, []string{N.NetworkTCP}, options.DialerOptions,
		),
		ctx: ctx, dialer: d, server: options.ServerOptions.Build(), logger: logger,
		transport: T.ClientConfig{ServerPublicKey: key, HandshakeTimeout: timeout, Padding: padding},
	}
	health := &anytls.SessionHealthOptions{Enabled: true}
	if options.SessionHealth != nil {
		health = &anytls.SessionHealthOptions{
			Enabled:         options.SessionHealth.Enabled,
			IdleThreshold:   options.SessionHealth.IdleThreshold.Build(),
			Timeout:         options.SessionHealth.Timeout.Build(),
			MaxIdleSessions: options.SessionHealth.MaxIdleSessions,
		}
	}
	h.clientOptions = anytls.ClientConfig{
		Password: options.Password, DialOut: h.dialOut, Logger: logger,
		AuthenticationTimeout: timeout,
		DisablePadding:        true, SessionHealth: health,
		IdleSessionCheckInterval: options.IdleSessionCheckInterval.Build(),
		IdleSessionTimeout:       options.IdleSessionTimeout.Build(), MinIdleSession: options.MinIdleSession,
	}
	return h, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	client, err := anytls.NewClient(h.ctx, h.clientOptions)
	if err != nil {
		return err
	}
	h.client = client
	scope.Add(client.Close)
	h.logger.Debug("anytls-native connection pool initialized")
	return nil
}

func (h *Outbound) dialOut(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(adapter.ContextForMultiplexSession(ctx), h.transport.HandshakeTimeout)
	defer cancel()
	conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.server)
	if err != nil {
		return nil, err
	}
	secured, err := T.ClientHandshake(ctx, conn, h.transport)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return secured, nil
}

func (h *Outbound) MultiplexEnabled() bool { return true }

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP || isUDPOverTCP(destination) {
		return nil, fmt.Errorf("anytls-native supports TCP only: %w", os.ErrInvalid)
	}
	if h.client == nil {
		return nil, fmt.Errorf("anytls-native outbound is not started")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	return h.client.CreateProxy(ctx, destination)
}

func (h *Outbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("anytls-native supports TCP only: %w", os.ErrInvalid)
}
