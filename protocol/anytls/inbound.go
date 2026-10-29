package anytls

import (
	"context"
	"crypto/sha256"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.AnyTLSInboundOptions](registry, C.TypeAnyTLS, NewInbound)
}

var _ adapter.ManagedSSMServer = (*Inbound)(nil)

type trackerState struct{ tracker adapter.SSMTracker }

type connectionState struct {
	connection    net.Conn
	cancel        context.CancelFunc
	user          string
	authenticated bool
}

// Inbound retains the public AnyTLS transport and optionally binds sessions to managed panel users.
// @author lyt
// @date 2026-10-29
type Inbound struct {
	inbound.Adapter
	tlsConfig   tls.ServerConfig
	router      adapter.ConnectionRouterEx
	logger      logger.ContextLogger
	listener    *listener.Listener
	service     *anytls.Service
	tracker     atomic.Pointer[trackerState]
	access      sync.Mutex
	credentials map[string][32]byte
	connections map[net.Conn]*connectionState
	revision    uint64
	managed     bool
	closed      bool
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter:     inbound.NewAdapter(C.TypeAnyTLS, tag),
		router:      uot.NewRouter(router, logger),
		logger:      logger,
		connections: make(map[net.Conn]*connectionState),
	}

	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}

	paddingScheme := padding.DefaultPaddingScheme
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	}

	service, err := anytls.NewService(anytls.ServiceConfig{
		Users: common.Map(options.Users, func(it option.AnyTLSUser) anytls.User {
			return anytls.User(it)
		}),
		PaddingScheme:   paddingScheme,
		EnhancedPadding: options.EnhancedPadding,
		Handler:         (*inboundHandler)(inbound),
		Logger:          logger,
	})
	if err != nil {
		return nil, err
	}
	inbound.service = service
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
		scope.Add(h.tlsConfig.Close)
	}
	err := h.listener.Start()
	if err != nil {
		return err
	}
	scope.Add(h.closeConnections)
	scope.Add(h.listener.Close)
	return nil
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx, cancel := context.WithCancel(ctx)
	raw := conn
	state := &connectionState{connection: raw, cancel: cancel}
	h.access.Lock()
	if h.closed {
		h.access.Unlock()
		cancel()
		N.CloseOnHandshakeFailure(raw, onClose, net.ErrClosed)
		return
	}
	h.connections[raw] = state
	h.access.Unlock()
	defer func() {
		cancel()
		raw.Close()
		h.access.Lock()
		delete(h.connections, raw)
		h.access.Unlock()
	}()
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	h.access.Lock()
	revision := h.revision
	h.access.Unlock()
	err := h.service.NewConnectionWithAuth(adapter.WithContext(ctx, &metadata), conn,
		metadata.Source, onClose, func(userContext context.Context) error {
			user, found := auth.UserFromContext[string](userContext)
			h.access.Lock()
			defer h.access.Unlock()
			if !found || h.closed || revision != h.revision || ctx.Err() != nil {
				return E.New("anytls user changed during authentication")
			}
			if h.managed {
				if _, exists := h.credentials[user]; !exists {
					return E.New("anytls managed user no longer exists")
				}
			}
			state.user = user
			state.authenticated = true
			return nil
		})
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func (h *Inbound) SetTracker(tracker adapter.SSMTracker) {
	h.tracker.Store(&trackerState{tracker: tracker})
}

func (h *Inbound) UpdateUsers(names, passwords []string) error {
	if len(names) != len(passwords) {
		return E.New("anytls user and credential counts differ")
	}
	users := make([]anytls.User, len(names))
	credentials := make(map[string][32]byte, len(names))
	digests := make(map[[32]byte]struct{}, len(names))
	for index, name := range names {
		if strings.TrimSpace(name) == "" || passwords[index] == "" {
			return E.New("anytls managed user name and credential must not be empty")
		}
		if _, exists := credentials[name]; exists {
			return E.New("duplicate anytls managed user name")
		}
		digest := sha256.Sum256([]byte(passwords[index]))
		if _, exists := digests[digest]; exists {
			return E.New("duplicate anytls managed credential")
		}
		credentials[name] = digest
		digests[digest] = struct{}{}
		users[index] = anytls.User{Name: name, Password: passwords[index]}
	}
	var revoked []connectionState
	h.access.Lock()
	if h.closed {
		h.access.Unlock()
		return net.ErrClosed
	}
	h.service.UpdateUsers(users)
	h.revision++
	for _, state := range h.connections {
		if !state.authenticated {
			continue
		}
		digest, exists := credentials[state.user]
		// Static configuration permits unnamed or repeated names. The first panel
		// update therefore retires those sessions before establishing unique identities.
		if !h.managed || !exists || digest != h.credentials[state.user] {
			revoked = append(revoked, *state)
		}
	}
	h.credentials = credentials
	h.managed = true
	h.access.Unlock()
	for _, state := range revoked {
		state.cancel()
		state.connection.Close()
	}
	h.logger.Info("anytls users updated: ", len(users), "; revoked sessions: ", len(revoked))
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
		state.connection.Close()
	}
	return nil
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if err := ctx.Err(); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	if state := h.tracker.Load(); state != nil && state.tracker != nil {
		var err error
		conn, err = adapter.TrackConnection(ctx, state.tracker, conn, metadata)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			return
		}
	}
	if err := ctx.Err(); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
