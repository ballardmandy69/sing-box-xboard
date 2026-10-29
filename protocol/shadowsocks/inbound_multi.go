package shadowsocks

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/authban"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

var (
	_ adapter.TCPInjectableInbound = (*MultiInbound)(nil)
	_ adapter.ManagedSSMServer     = (*MultiInbound)(nil)
)

type MultiInbound struct {
	inbound.Adapter
	ctx           context.Context
	router        adapter.ConnectionRouterEx
	logger        logger.ContextLogger
	listener      *listener.Listener
	service       shadowsocks.MultiService[multiUserIdentity]
	sharedService shadowsocks.Service
	obfs          *obfsProcessor
	usersAccess   sync.Mutex
	tracker       adapter.SSMTracker
}

func newMultiInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksInboundOptions) (*MultiInbound, error) {
	inbound := &MultiInbound{
		Adapter: inbound.NewAdapter(C.TypeShadowsocks, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
	}
	var err error
	sharedPassword := false
	if options.ObfsMu != "" {
		parts := strings.Split(options.ObfsMu, ":")
		if len(parts) > 2 || parts[0] == "" {
			return nil, E.New("invalid Shadowsocks obfs_mu configuration")
		}
		options.Method = parts[0]
		if len(parts) == 2 {
			options.Password = parts[1]
			sharedPassword = true
		}
		options.Network = option.NetworkList("tcp")
		inbound.obfs = &obfsProcessor{}
	}
	inbound.router, err = mux.NewRouterWithOptions(inbound.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	var service shadowsocks.MultiService[multiUserIdentity]
	if sharedPassword {
		inbound.sharedService, err = newSingleService(ctx, options, udpTimeout,
			adapter.NewLegacyUpstreamHandler(adapter.InboundContext{}, inbound.newConnection, inbound.newPacketConnection, inbound))
	} else if common.Contains(shadowaead_2022.List, options.Method) {
		service, err = shadowaead_2022.NewMultiServiceWithPassword[multiUserIdentity](
			options.Method,
			options.Password,
			int64(udpTimeout.Seconds()),
			adapter.NewLegacyUpstreamHandler(adapter.InboundContext{}, inbound.newConnection, inbound.newPacketConnection, inbound),
			ntp.TimeFuncFromContext(ctx),
		)
	} else if common.Contains(shadowaead.List, options.Method) {
		service, err = shadowaead.NewMultiService[multiUserIdentity](
			options.Method,
			int64(udpTimeout.Seconds()),
			adapter.NewLegacyUpstreamHandler(adapter.InboundContext{}, inbound.newConnection, inbound.newPacketConnection, inbound),
		)
	} else {
		return nil, E.New("unsupported method: " + options.Method)
	}
	if err != nil {
		return nil, err
	}
	inbound.service = service
	if options.ShadowsocksBanIP {
		if legacy, ok := service.(*shadowaead.MultiService[multiUserIdentity]); ok {
			policy := authban.Shared()
			legacy.SetAuthenticationFailureHooks(policy.ReportFailure, policy.IsBlocked)
		}
	}
	if len(options.Users) > 0 {
		err = inbound.UpdateUsers(common.Map(options.Users, func(user option.ShadowsocksUser) string {
			return user.Name
		}), common.Map(options.Users, func(user option.ShadowsocksUser) string { return user.Password }))
		if err != nil {
			return nil, err
		}
	}
	inbound.listener = listener.New(listener.Options{
		Context:                  ctx,
		Logger:                   logger,
		Network:                  options.Network.Build(),
		Listen:                   options.ListenOptions,
		ConnectionHandler:        inbound,
		PacketHandler:            inbound,
		ThreadUnsafePacketWriter: true,
	})
	return inbound, err
}

func (h *MultiInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := h.listener.Start()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	return nil
}

func (h *MultiInbound) SetTracker(tracker adapter.SSMTracker) {
	h.tracker = tracker
}

func (h *MultiInbound) UpdateUsers(users []string, uPSKs []string) error {
	return h.UpdateUsersWithUUIDs(users, uPSKs, uPSKs)
}

func (h *MultiInbound) UpdateUsersWithUUIDs(users, uPSKs, uuids []string) error {
	h.usersAccess.Lock()
	defer h.usersAccess.Unlock()
	if len(users) != len(uPSKs) || len(users) != len(uuids) {
		return E.New("Shadowsocks user credentials have different lengths")
	}
	identities := common.MapIndexed(users, func(index int, user string) multiUserIdentity {
		return multiUserIdentity{Name: user, Index: index}
	})
	if h.service != nil {
		if err := h.service.UpdateUsersWithPasswords(identities, uPSKs); err != nil {
			return err
		}
	}
	if h.obfs != nil {
		h.obfs.update(identities, uuids)
	}
	return nil
}

//nolint:staticcheck
func (h *MultiInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	var err error
	if h.obfs != nil {
		var user obfsUser
		conn, user, err = h.obfs.process(conn)
		if err == nil {
			if h.sharedService != nil {
				ctx = auth.ContextWithUser(ctx, user.identity)
			} else {
				ctx = shadowsocks.ContextWithUserHint(ctx, user.identity)
			}
		}
	}
	if err == nil {
		if h.sharedService != nil {
			err = h.sharedService.NewConnection(ctx, conn, adapter.UpstreamMetadata(metadata))
		} else {
			err = h.service.NewConnection(ctx, conn, adapter.UpstreamMetadata(metadata))
		}
	}
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

//nolint:staticcheck
func (h *MultiInbound) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	if h.obfs != nil {
		buffer.Release()
		return
	}
	err := h.service.NewPacket(h.ctx, &stubPacketConn{h.listener.PacketWriter()}, buffer, M.Metadata{Source: source})
	if err != nil {
		h.logger.Error(E.Cause(err, "process packet from ", source))
	}
}

func (h *MultiInbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	identity, loaded := auth.UserFromContext[multiUserIdentity](ctx)
	if !loaded {
		return os.ErrInvalid
	}
	user := identity.Name
	if user == "" {
		user = F.ToString(identity.Index)
	} else {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	if h.tracker != nil {
		var err error
		conn, err = adapter.TrackConnection(ctx, h.tracker, conn, metadata)
		if err != nil {
			return err
		}
	}
	return h.router.RouteConnection(ctx, conn, metadata)
}

func (h *MultiInbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	identity, loaded := auth.UserFromContext[multiUserIdentity](ctx)
	if !loaded {
		return os.ErrInvalid
	}
	user := identity.Name
	if user == "" {
		user = F.ToString(identity.Index)
	} else {
		metadata.User = user
	}
	ctx = log.ContextWithNewID(ctx)
	h.logger.InfoContext(ctx, "[", user, "] inbound packet connection from ", metadata.Source)
	h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	if h.tracker != nil {
		var err error
		conn, err = adapter.TrackPacketConnection(ctx, h.tracker, conn, metadata)
		if err != nil {
			return err
		}
	}
	return h.router.RoutePacketConnection(ctx, conn, metadata)
}

//nolint:staticcheck
func (h *MultiInbound) NewError(ctx context.Context, err error) {
	NewError(h.logger, ctx, err)
}
