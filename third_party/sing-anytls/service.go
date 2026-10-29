package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	stdatomic "sync/atomic"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Service struct {
	users           stdatomic.Pointer[userSnapshot]
	padding         atomic.TypedValue[*padding.PaddingFactory]
	handler         N.TCPConnectionHandlerEx
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger
	enhancedPadding bool
	disablePadding  bool
}

// userSnapshot is immutable after publication; readers never lock or scan users.
type userSnapshot struct {
	byDigest map[[32]byte]string
}

type ServiceConfig struct {
	PaddingScheme   []byte
	Users           []User
	Handler         N.TCPConnectionHandlerEx
	FallbackHandler N.TCPConnectionHandlerEx
	Logger          logger.ContextLogger
	EnhancedPadding bool
	DisablePadding  bool
}

type User struct {
	Name     string
	Password string
}

func NewService(config ServiceConfig) (*Service, error) {
	service := &Service{
		handler:         config.Handler,
		fallbackHandler: config.FallbackHandler,
		logger:          config.Logger,
		enhancedPadding: config.EnhancedPadding && !config.DisablePadding,
		disablePadding:  config.DisablePadding,
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}

	service.UpdateUsers(config.Users)

	scheme := config.PaddingScheme
	if config.DisablePadding {
		scheme = []byte("stop=0")
	}
	if !padding.UpdatePaddingScheme(scheme, &service.padding) {
		return nil, errors.New("incorrect padding scheme format")
	}

	return service, nil
}

func (s *Service) UpdateUsers(users []User) {
	u := make(map[[32]byte]string)
	for _, user := range users {
		u[sha256.Sum256([]byte(user.Password))] = user.Name
	}
	s.users.Store(&userSnapshot{byDigest: u})
}

func (s *Service) lookupUser(digest [32]byte) (string, bool) {
	snapshot := s.users.Load()
	if snapshot == nil {
		return "", false
	}
	user, ok := snapshot.byDigest[digest]
	return user, ok
}

// NewConnection `conn` should be plaintext
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	return s.NewConnectionWithAuth(ctx, conn, source, onClose, nil)
}

// NewConnectionWithAuth calls onAuthenticated after the complete authentication
// header and padding, before session construction or destination processing.
func (s *Service) NewConnectionWithAuth(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc, onAuthenticated func(context.Context) error) error {
	return s.NewConnectionWithAuthenticator(ctx, conn, source, onClose, nil, onAuthenticated)
}

// NewConnectionWithAuthenticator validates the wire credential against a caller-owned snapshot.
// A nil authenticator retains the service's ordinary authentication table; context users are never trusted.
// @author lyt
// @date 2026-10-29
func (s *Service) NewConnectionWithAuthenticator(ctx context.Context, conn net.Conn, source M.Socksaddr,
	onClose N.CloseHandlerFunc, authenticate func([32]byte) (string, bool), onAuthenticated func(context.Context) error,
) error {
	if authenticate == nil {
		authenticate = s.lookupUser
	}
	// Authentication is a byte stream and can span TCP reads or TLS records.
	// Read exactly each bounded field, leaving coalesced session frames on conn.
	var header [34]byte
	n, err := io.ReadFull(conn, header[:32])
	if err != nil {
		if n == 0 {
			return err
		}
		return s.fallbackPrefix(ctx, conn, source, header[:n], err, onClose)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], header[:32])
	if user, ok := authenticate(passwordSha256); ok {
		ctx = auth.ContextWithUser(ctx, user)
	} else {
		return s.fallbackPrefix(ctx, conn, source, header[:32], E.New("unknown user password"), onClose)
	}
	n, err = io.ReadFull(conn, header[32:])
	if err != nil {
		return s.fallbackPrefix(ctx, conn, source, header[:32+n], E.Extend(err, "read padding length"), onClose)
	}
	paddingLen := binary.BigEndian.Uint16(header[32:])
	if s.disablePadding && paddingLen != 0 {
		return E.New("authentication padding is disabled")
	}
	if paddingLen > 0 {
		// uint16 bounds this allocation to 65535 bytes after user authentication.
		authPadding := make([]byte, int(paddingLen))
		n, err = io.ReadFull(conn, authPadding)
		if err != nil {
			prefix := append(header[:], authPadding[:n]...)
			return s.fallbackPrefix(ctx, conn, source, prefix, E.Extend(err, "read padding"), onClose)
		}
	}
	if onAuthenticated != nil {
		if err = onAuthenticated(ctx); err != nil {
			return err
		}
	}

	session := session.NewServerSession(conn, func(stream *session.Stream) {
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			s.logger.ErrorContext(ctx, "ReadAddrPort:", err)
			return
		}

		s.handler.NewConnectionEx(ctx, stream, source, destination, onClose)
	}, &s.padding, s.logger, s.enhancedPadding, s.disablePadding)
	session.Run()
	session.Close()
	return nil
}

// fallbackPrefix restores every consumed authentication byte for the fallback.
func (s *Service) fallbackPrefix(ctx context.Context, conn net.Conn, source M.Socksaddr, prefix []byte, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return s.fallback(ctx, conn, source, err, onClose)
	}
	buffer := buf.NewSize(len(prefix))
	buffer.Write(prefix)
	defer buffer.Release()
	return s.fallback(ctx, bufio.NewCachedConn(conn, buffer), source, err, onClose)
}

func (s *Service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}
