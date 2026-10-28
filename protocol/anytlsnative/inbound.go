package anytlsnative

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/anytlsnative"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.AnyTLSNativeInboundOptions](registry, C.TypeAnyTLSNative, NewInbound)
}

var _ adapter.ManagedSSMServer = (*Inbound)(nil)

type trackerState struct{ tracker adapter.SSMTracker }

type connectionState struct {
	user    string
	cancel  context.CancelFunc
	secured net.Conn
}

// Inbound performs bounded authentication once and binds all session streams to that user.
// User changes are serialized only against authentication, never against record I/O.
// @author lyt
// @date 2026-10-29
type Inbound struct {
	inbound.Adapter
	router      adapter.ConnectionRouterEx
	logger      log.ContextLogger
	listener    *listener.Listener
	tlsConfig   tls.ServerConfig
	transport   T.ServerConfig
	service     *anytls.Service
	pending     chan struct{}
	tracker     atomic.Pointer[trackerState]
	access      sync.Mutex
	credentials map[string][32]byte
	connections map[net.Conn]*connectionState
	revision    uint64
	closed      bool
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger,
	tag string, options option.AnyTLSNativeInboundOptions,
) (adapter.Inbound, error) {
	key, err := decodeKey(options.PrivateKey, "private_key", false)
	if err != nil {
		return nil, err
	}
	pad, err := transportPadding(options.Padding)
	if err != nil {
		return nil, err
	}
	timeout, err := handshakeTimeout(options.HandshakeTimeout.Build())
	if err != nil {
		return nil, err
	}
	limit := options.MaxPendingHandshakes
	if limit == 0 {
		limit = 128
	}
	if limit < 1 || limit > 65536 {
		return nil, fmt.Errorf("max_pending_handshakes must be between 1 and 65536")
	}
	credentials, err := userCredentials(options.Users)
	if err != nil {
		return nil, err
	}
	h := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeAnyTLSNative, tag), router: router, logger: logger,
		transport: T.ServerConfig{PrivateKey: key, HandshakeTimeout: timeout, Padding: pad},
		pending:   make(chan struct{}, limit), credentials: credentials,
		connections: make(map[net.Conn]*connectionState),
	}
	if options.TLS != nil && options.TLS.Enabled {
		h.tlsConfig, err = tls.NewServer(ctx, logger, *options.TLS)
		if err != nil {
			return nil, err
		}
	}
	users := make([]anytls.User, len(options.Users))
	for index, user := range options.Users {
		users[index] = anytls.User(user)
	}
	h.service, err = anytls.NewService(anytls.ServiceConfig{
		Users: users, PaddingScheme: padding.DefaultPaddingScheme, DisablePadding: true,
		Handler: (*inboundHandler)(h), Logger: logger,
	})
	if err != nil {
		return nil, err
	}
	h.listener = listener.New(listener.Options{
		Context: ctx, Logger: logger, Network: []string{N.NetworkTCP}, Listen: options.ListenOptions,
		ConnectionHandler: h,
	})
	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return err
		}
		scope.Add(h.tlsConfig.Close)
	}
	if err := h.listener.Start(); err != nil {
		return err
	}
	scope.Add(h.closeConnections)
	scope.Add(h.listener.Close)
	h.logger.Info("anytls-native TCP listener started")
	return nil
}

func (h *Inbound) NewConnection(ctx context.Context, raw net.Conn,
	metadata adapter.InboundContext, onClose N.CloseHandlerFunc,
) {
	select {
	case h.pending <- struct{}{}:
	default:
		N.CloseOnHandshakeFailure(raw, onClose, fmt.Errorf("native authentication capacity reached"))
		return
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { <-h.pending }) }
	defer release()
	ctx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	state := &connectionState{cancel: cancelSession, secured: raw}
	h.access.Lock()
	if h.closed {
		h.access.Unlock()
		N.CloseOnHandshakeFailure(raw, onClose, net.ErrClosed)
		return
	}
	h.connections[raw] = state
	h.access.Unlock()
	defer func() {
		raw.Close()
		h.access.Lock()
		delete(h.connections, raw)
		h.access.Unlock()
	}()
	authContext, cancel := context.WithTimeout(ctx, h.transport.HandshakeTimeout)
	defer cancel()
	stopTimeout := context.AfterFunc(authContext, func() { raw.Close() })
	defer stopTimeout()
	conn := raw
	var err error
	if h.tlsConfig != nil {
		conn, err = tls.ServerHandshake(authContext, conn, h.tlsConfig)
	}
	if err == nil {
		conn, err = T.ServerHandshake(authContext, conn, h.transport)
	}
	if err != nil {
		h.logger.DebugContext(ctx, "native secure handshake failed: ", err)
		N.CloseOnHandshakeFailure(raw, onClose, err)
		return
	}
	h.access.Lock()
	state.secured = conn
	h.access.Unlock()
	deadline, _ := authContext.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		N.CloseOnHandshakeFailure(raw, onClose, err)
		return
	}
	h.access.Lock()
	revision := h.revision
	h.access.Unlock()
	err = h.service.NewConnectionWithAuth(adapter.WithContext(ctx, &metadata), conn,
		metadata.Source, onClose, func(userContext context.Context) error {
			if authErr := authContext.Err(); authErr != nil {
				return authErr
			}
			if !stopTimeout() {
				return context.DeadlineExceeded
			}
			cancel()
			if clearErr := conn.SetDeadline(time.Time{}); clearErr != nil {
				return clearErr
			}
			user, ok := auth.UserFromContext[string](userContext)
			h.access.Lock()
			defer h.access.Unlock()
			if _, found := h.credentials[user]; !ok || !found || h.closed || revision != h.revision {
				return fmt.Errorf("native user changed during authentication")
			}
			state.user = user
			release()
			return nil
		})
	if err != nil {
		h.logger.DebugContext(ctx, "native session rejected: ", err)
		N.CloseOnHandshakeFailure(raw, onClose, err)
	}
}

func (h *Inbound) SetTracker(tracker adapter.SSMTracker) {
	h.tracker.Store(&trackerState{tracker: tracker})
}

func (h *Inbound) UpdateUsers(names, passwords []string) error {
	if len(names) != len(passwords) {
		return fmt.Errorf("native user and credential counts differ")
	}
	users := make([]option.AnyTLSUser, len(names))
	serviceUsers := make([]anytls.User, len(names))
	for index := range names {
		users[index] = option.AnyTLSUser{Name: names[index], Password: passwords[index]}
		serviceUsers[index] = anytls.User(users[index])
	}
	credentials, err := userCredentials(users)
	if err != nil {
		return err
	}
	var revoked []connectionState
	h.access.Lock()
	if h.closed {
		h.access.Unlock()
		return net.ErrClosed
	}
	h.service.UpdateUsers(serviceUsers)
	h.revision++
	for _, state := range h.connections {
		if state.user == "" {
			continue
		}
		if digest, exists := credentials[state.user]; !exists || digest != h.credentials[state.user] {
			revoked = append(revoked, *state)
		}
	}
	h.credentials = credentials
	h.access.Unlock()
	for _, state := range revoked {
		state.cancel()
		state.secured.Close()
	}
	h.logger.Info("anytls-native users updated: ", len(users), "; revoked sessions: ", len(revoked))
	return nil
}

func (h *Inbound) closeConnections() error {
	h.access.Lock()
	h.closed = true
	connections := make([]connectionState, 0, len(h.connections))
	for _, state := range h.connections {
		connections = append(connections, *state)
	}
	h.access.Unlock()
	for _, state := range connections {
		state.cancel()
		state.secured.Close()
	}
	return nil
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn,
	source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc,
) {
	if err := ctx.Err(); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	if isUDPOverTCP(destination) {
		N.CloseOnHandshakeFailure(conn, onClose, fmt.Errorf("anytls-native supports TCP only"))
		return
	}
	user, ok := auth.UserFromContext[string](ctx)
	if !ok {
		N.CloseOnHandshakeFailure(conn, onClose, fmt.Errorf("missing native user context"))
		return
	}
	metadata := adapter.InboundContext{
		Inbound: h.Tag(), InboundType: h.Type(), Source: source, Destination: destination.Unwrap(), User: user,
	}
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	if state := h.tracker.Load(); state != nil && state.tracker != nil {
		conn = state.tracker.TrackConnection(conn, metadata)
	}
	if err := ctx.Err(); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	h.logger.DebugContext(ctx, "authenticated native stream to ", destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
