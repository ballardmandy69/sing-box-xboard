package trojan

import (
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[K comparable] struct {
	users           atomic.Pointer[userSnapshot[K]]
	serverPadding   atomic.Bool
	handler         Handler
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger
}

// userSnapshot is immutable after publication, so authentication reads never race with panel updates.
// @author lyt
// @date 2026-10-29
type userSnapshot[K comparable] struct {
	keys map[[56]byte]K
}

func NewService[K comparable](handler Handler, fallbackHandler N.TCPConnectionHandlerEx, logger logger.ContextLogger) *Service[K] {
	service := &Service[K]{
		handler:         handler,
		fallbackHandler: fallbackHandler,
		logger:          logger,
	}
	service.users.Store(&userSnapshot[K]{keys: make(map[[56]byte]K)})
	return service
}

var ErrUserExists = E.New("user already exists")
var ErrUDPDisabled = C.ErrUDPDisabled

// SetServerPadding controls wrapping of subsequently authenticated connections.
func (s *Service[K]) SetServerPadding(enabled bool) {
	s.serverPadding.Store(enabled)
}

func (s *Service[K]) UpdateUsers(userList []K, passwordList []string) error {
	if len(userList) != len(passwordList) {
		return E.New("user and password counts differ")
	}
	users := make(map[K][56]byte)
	keys := make(map[[56]byte]K)
	for i, user := range userList {
		if _, loaded := users[user]; loaded {
			return ErrUserExists
		}
		key := Key(passwordList[i])
		if oldUser, loaded := keys[key]; loaded {
			return E.Extend(ErrUserExists, "password used by ", oldUser)
		}
		users[user] = key
		keys[key] = user
	}
	s.users.Store(&userSnapshot[K]{keys: keys})
	return nil
}

func (s *Service[K]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	return s.NewConnectionWithAuthenticator(ctx, conn, source, onClose, nil)
}

// NewConnectionWithAuthenticator authenticates the wire header against a caller-owned immutable snapshot.
// A nil authenticator uses this service's user table. Context users never bypass header authentication.
func (s *Service[K]) NewConnectionWithAuthenticator(
	ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc,
	authenticate func([56]byte) (K, bool),
) error {
	if authenticate == nil {
		authenticate = func(key [56]byte) (K, bool) {
			user, loaded := s.users.Load().keys[key]
			return user, loaded
		}
	}
	return s.newConnection(ctx, conn, source, onClose, authenticate)
}

func (s *Service[K]) newConnection(
	ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc,
	authenticate func([56]byte) (K, bool),
) error {
	var key [KeyLength]byte
	n, err := conn.Read(key[:])
	if err != nil {
		return err
	} else if n != KeyLength {
		return s.fallback(ctx, conn, source, key[:n], E.New("bad request size"), onClose)
	}

	if user, loaded := authenticate(key); loaded {
		ctx = auth.ContextWithUser(ctx, user)
	} else {
		return s.fallback(ctx, conn, source, key[:], E.New("bad request"), onClose)
	}

	err = rw.SkipN(conn, 2)
	if err != nil {
		return E.Cause(err, "skip crlf")
	}

	var command byte
	err = binary.Read(conn, binary.BigEndian, &command)
	if err != nil {
		return E.Cause(err, "read command")
	}

	switch command {
	case CommandTCP, CommandUDP, CommandMux:
	default:
		return E.New("unknown command ", command)
	}

	// var destination M.Socksaddr
	destination, err := M.SocksaddrSerializer.ReadAddrPort(conn)
	if err != nil {
		return E.Cause(err, "read destination")
	}

	err = rw.SkipN(conn, 2)
	if err != nil {
		return E.Cause(err, "skip crlf")
	}

	if command != CommandUDP && s.serverPadding.Load() && destination.Fqdn != mux.Destination.Fqdn {
		conn = &serverPaddingConn{Conn: conn}
	}
	switch command {
	case CommandTCP:
		s.handler.NewConnectionEx(ctx, conn, source, destination, onClose)
	case CommandUDP:
		return ErrUDPDisabled
	// case CommandMux:
	default:
		return HandleMuxConnection(ctx, conn, source, s.handler, s.logger, onClose)
	}
	return nil
}

func (s *Service[K]) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, header []byte, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	conn = bufio.NewCachedConn(conn, buf.As(header).ToOwned())
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}

type PacketConn struct {
	net.Conn
	readWaitOptions N.ReadWaitOptions
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return ReadPacket(c.Conn, buffer)
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return WritePacket(c.Conn, buffer, destination)
}

func (c *PacketConn) FrontHeadroom() int {
	return M.MaxSocksaddrLength + 4
}

func (c *PacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *PacketConn) Upstream() any {
	return c.Conn
}
