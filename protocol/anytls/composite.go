package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"sync"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const compositeAuthenticationTimeout = 5 * time.Second

type compositeProtocolKey struct{}

// compositeService shares one listener and immutable authentication snapshot across the legacy TCP parsers.
// @author lyt
// @date 2026-10-29
type compositeService struct {
	trojan   *trojan.Service[string]
	vless    *vless.Service[string]
	users    *compositeUsers // Published and captured while Inbound.access is held.
	forceMux bool
}

type compositeUsers struct {
	anytls map[[32]byte]string
	trojan map[[56]byte]string
	vless  map[[16]byte]string
}

func newCompositeService(h *Inbound, options option.AnyTLSInboundOptions) (*compositeService, error) {
	service := &compositeService{forceMux: options.ForceMuxForTrojan}
	switch options.FallbackService {
	case "", "trojan", "vless", "trojan-vless":
	default:
		return nil, E.New("unknown anytls fallback_service: ", options.FallbackService)
	}
	if options.FallbackService == "trojan" || options.FallbackService == "trojan-vless" {
		service.trojan = trojan.NewService[string]((*inboundHandler)(h), nil, h.logger)
		service.trojan.SetServerPadding(options.ServerPaddingForTrojan)
	}
	if options.FallbackService == "vless" || options.FallbackService == "trojan-vless" {
		service.vless = vless.NewService[string](h.logger, (*inboundHandler)(h))
		service.vless.UpdateUsersWithClientFlow(nil, nil, options.ForceVision)
	}
	service.updateUsers(options.Users)
	return service, nil
}

func (s *compositeService) updateUsers(users []option.AnyTLSUser) {
	next := &compositeUsers{anytls: make(map[[32]byte]string, len(users))}
	if s.trojan != nil {
		next.trojan = make(map[[56]byte]string, len(users))
	}
	if s.vless != nil {
		next.vless = make(map[[16]byte]string, len(users))
	}
	for _, user := range users {
		next.anytls[sha256.Sum256([]byte(user.Password))] = user.Name
		if next.trojan != nil {
			digest := sha256.Sum224([]byte(user.Password))
			var key [56]byte
			hex.Encode(key[:], digest[:])
			next.trojan[key] = user.Name
		}
		if next.vless != nil {
			key := uuid.FromStringOrNil(user.Password)
			if key == uuid.Nil {
				key = uuid.NewV5(uuid.Nil, user.Password)
			}
			next.vless[key] = user.Name
		}
	}
	s.users = next
}

func (u *compositeUsers) classify(prefix []byte) (string, bool, error) {
	if len(prefix) >= 32 {
		if _, found := u.anytls[[32]byte(prefix[:32])]; found {
			return "anytls", true, nil
		}
	}
	if len(prefix) >= 18 && prefix[0] == 0 {
		if _, found := u.vless[[16]byte(prefix[1:17])]; found {
			return "vless", true, nil
		}
	}
	if len(prefix) >= 58 && prefix[56] == '\r' && prefix[57] == '\n' {
		if _, found := u.trojan[[56]byte(prefix[:56])]; found {
			return "trojan", true, nil
		}
	}
	if len(prefix) >= 58 {
		return "", false, os.ErrInvalid
	}
	return "", false, nil
}

func (u *compositeUsers) selectConnection(conn net.Conn) (net.Conn, string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(compositeAuthenticationTimeout)); err != nil {
		return nil, "", err
	}
	var prefix [256]byte
	length, emptyReads := 0, 0
	for {
		n, readErr := conn.Read(prefix[length:])
		length += n
		protocol, matched, err := u.classify(prefix[:length])
		if err != nil {
			return nil, "", err
		}
		if matched {
			if err = conn.SetReadDeadline(time.Time{}); err != nil {
				return nil, "", err
			}
			return bufio.NewCachedConn(conn, buf.As(prefix[:length]).ToOwned()), protocol, nil
		}
		if readErr != nil {
			return nil, "", readErr
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return nil, "", io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
	}
}

func (s *compositeService) newConnection(ctx context.Context, conn net.Conn, source M.Socksaddr,
	onClose N.CloseHandlerFunc, users *compositeUsers, service *anytls.Service,
	onAuthenticated func(context.Context) error,
) (string, error) {
	conn, protocol, err := users.selectConnection(conn)
	if err != nil {
		return "", err
	}
	ctx = context.WithValue(ctx, compositeProtocolKey{}, protocol)
	checkUser := func(user string, found bool) (string, bool) {
		if found && onAuthenticated(auth.ContextWithUser(ctx, user)) != nil {
			return "", false
		}
		return user, found
	}
	switch protocol {
	case "anytls":
		err = service.NewConnectionWithAuthenticator(ctx, conn, source, onClose,
			func(key [32]byte) (string, bool) {
				user, found := users.anytls[key]
				return user, found
			}, onAuthenticated)
	case "trojan":
		err = s.trojan.NewConnectionWithAuthenticator(ctx, conn, source, onClose,
			func(key [56]byte) (string, bool) {
				user, found := users.trojan[key]
				return checkUser(user, found)
			})
	case "vless":
		err = s.vless.NewConnectionWithAuthenticator(ctx, conn, source, onClose,
			func(key [16]byte) (string, bool) {
				user, found := users.vless[key]
				return checkUser(user, found)
			})
	}
	return protocol, err
}

// compositeLifetimeConn observes physical Close without treating the end of a logical Mux stream as session end.
// @author lyt
// @date 2026-10-29
type compositeLifetimeConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *compositeLifetimeConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func (c *compositeLifetimeConn) Upstream() any { return c.Conn }

func (h *inboundHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn,
	source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc,
) {
	N.CloseOnHandshakeFailure(conn, onClose, E.New("anytls composite inbound supports TCP only"))
}
