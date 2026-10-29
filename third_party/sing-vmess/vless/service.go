package vless

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type Service[T comparable] struct {
	users   atomic.Pointer[serviceUsers[T]]
	logger  logger.Logger
	handler Handler
}

type serviceUsers[T comparable] struct {
	userMap         map[[16]byte]T
	userFlow        map[T]string
	allowClientFlow bool
	forceVision     bool
}

// The legacy node policy exempts the SingMux carrier; inner streams retain their own admission checks.
const clientFlowMuxDestination = "sp.mux.sing-box.arpa"

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

func NewService[T comparable](logger logger.Logger, handler Handler) *Service[T] {
	service := &Service[T]{
		logger:  logger,
		handler: handler,
	}
	service.users.Store(&serviceUsers[T]{})
	return service
}

func (s *Service[T]) UpdateUsers(userList []T, userUUIDList []string, userFlowList []string) {
	s.updateUsers(userList, userUUIDList, userFlowList, false, false)
}

// UpdateUsersWithClientFlow publishes credentials and the legacy node-level flow policy together.
// Unlike UpdateUsers, clients choose between an empty flow and Vision for the authenticated user.
func (s *Service[T]) UpdateUsersWithClientFlow(userList []T, userUUIDList []string, forceVision bool) {
	s.updateUsers(userList, userUUIDList, nil, true, forceVision)
}

func (s *Service[T]) updateUsers(userList []T, userUUIDList []string, userFlowList []string,
	allowClientFlow bool, forceVision bool,
) {
	userMap := make(map[[16]byte]T)
	userFlowMap := make(map[T]string)
	for i, userName := range userList {
		userID, err := uuid.FromString(userUUIDList[i])
		if err != nil {
			userID = uuid.NewV5(uuid.Nil, userUUIDList[i])
		}
		userMap[userID] = userName
		if !allowClientFlow {
			userFlowMap[userName] = userFlowList[i]
		}
	}
	s.users.Store(&serviceUsers[T]{
		userMap: userMap, userFlow: userFlowMap,
		allowClientFlow: allowClientFlow, forceVision: forceVision,
	})
}

func (s *Service[T]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	return s.NewConnectionWithAuthenticator(ctx, conn, source, onClose, nil)
}

// NewConnectionWithAuthenticator validates the UUID using a shared inbound credential snapshot.
// A nil authenticator preserves ordinary service authentication and never trusts context identity.
// @author lyt
// @date 2026-10-29
func (s *Service[T]) NewConnectionWithAuthenticator(ctx context.Context, conn net.Conn, source M.Socksaddr,
	onClose N.CloseHandlerFunc, authenticate func([16]byte) (T, bool),
) error {
	request, err := ReadRequest(conn)
	if err != nil {
		return err
	}
	users := s.users.Load()
	user, loaded := users.userMap[request.UUID]
	if authenticate != nil {
		user, loaded = authenticate(request.UUID)
	}
	if !loaded {
		return E.New("unknown UUID: ", uuid.FromBytesOrNil(request.UUID[:]))
	}
	ctx = auth.ContextWithUser(ctx, user)
	userFlow := users.userFlow[user]
	if request.Flow == FlowVision && request.Command == vmess.NetworkUDP {
		return E.New(FlowVision, " flow does not support UDP")
	} else if !users.allowClientFlow && request.Flow != userFlow {
		return E.New("flow mismatch: expected ", flowName(userFlow), ", but got ", flowName(request.Flow))
	}
	if users.allowClientFlow {
		userFlow = request.Flow
	}

	if request.Command == vmess.CommandUDP {
		s.handler.NewPacketConnectionEx(ctx, &serverPacketConn{ExtendedConn: bufio.NewExtendedConn(conn), destination: request.Destination}, source, request.Destination, onClose)
		return nil
	}
	responseConn := &serverConn{ExtendedConn: bufio.NewExtendedConn(conn)}
	switch userFlow {
	case FlowVision:
		conn, err = NewVisionConn(responseConn, conn, request.UUID, s.logger)
		if err != nil {
			return E.Cause(err, "initialize vision")
		}
	case "":
		if users.allowClientFlow && users.forceVision && request.Destination.Fqdn != clientFlowMuxDestination {
			return E.New("vision flow is required")
		}
		conn = responseConn
	default:
		return E.New("unknown flow: ", userFlow)
	}
	switch request.Command {
	case vmess.CommandTCP:
		s.handler.NewConnectionEx(ctx, conn, source, request.Destination, onClose)
		return nil
	case vmess.CommandMux:
		return vmess.HandleMuxConnection(ctx, conn, source, s.handler)
	default:
		return E.New("unknown command: ", request.Command)
	}
}

func flowName(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

type serverConn struct {
	N.ExtendedConn
	responseWritten bool
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	return c.ExtendedConn.Read(b)
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if !c.responseWritten {
		buffer := buf.NewSize(2 + len(b))
		buffer.WriteByte(Version)
		buffer.WriteByte(0)
		buffer.Write(b)
		_, err = c.ExtendedConn.Write(buffer.Bytes())
		buffer.Release()
		if err == nil {
			n = len(b)
		}
		c.responseWritten = true
		return
	}
	return c.ExtendedConn.Write(b)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if !c.responseWritten {
		header := buffer.ExtendHeader(2)
		header[0] = Version
		header[1] = 0
		c.responseWritten = true
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverConn) FrontHeadroom() int {
	if c.responseWritten {
		return 0
	}
	return 2
}

func (c *serverConn) ReaderReplaceable() bool {
	return true
}

func (c *serverConn) WriterReplaceable() bool {
	return c.responseWritten
}

func (c *serverConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverConn) Upstream() any {
	return c.ExtendedConn
}

type serverPacketConn struct {
	N.ExtendedConn
	responseWritten bool
	destination     M.Socksaddr
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}
	if len(p) < int(packetLen) {
		err = io.ErrShortBuffer
		return
	}
	n, err = io.ReadFull(c.ExtendedConn, p[:packetLen])
	if err != nil {
		return
	}
	if c.destination.IsFqdn() {
		addr = c.destination
	} else {
		addr = c.destination.UDPAddr()
	}
	return
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if !c.responseWritten {
		_, err = c.ExtendedConn.Write([]byte{Version, 0})
		if err != nil {
			return
		}
		c.responseWritten = true
	}
	err = binary.Write(c.ExtendedConn, binary.BigEndian, uint16(len(p)))
	if err != nil {
		return
	}
	return c.ExtendedConn.Write(p)
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}

	_, err = buffer.ReadFullFrom(c.ExtendedConn, int(packetLen))
	if err != nil {
		return
	}

	destination = c.destination
	return
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !c.responseWritten {
		_, err := c.ExtendedConn.Write([]byte{Version, 0})
		if err != nil {
			return err
		}
		c.responseWritten = true
	}
	packetLen := buffer.Len()
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(packetLen))
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverPacketConn) FrontHeadroom() int {
	return 2
}

func (c *serverPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverPacketConn) Upstream() any {
	return c.ExtendedConn
}
