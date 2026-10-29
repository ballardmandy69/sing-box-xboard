// Package usercontrol applies panel user limits to authenticated logical TCP streams.
package usercontrol

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

var (
	ErrUnknownUser     = errors.New("managed user is not active")
	ErrIPLimit         = errors.New("managed user IP limit reached")
	ErrConnectionLimit = errors.New("managed user connection limit reached")
	ErrInvalidSource   = errors.New("managed IP limit requires a valid source IP")
	ErrUDPDisabled     = C.ErrUDPDisabled
	ErrRequestLimit    = errors.New("managed user request limit reached")
)

// Limits uses bytes per second; zero disables the corresponding limit.
// @author lyt
// @date 2026-10-29
type Limits struct {
	UploadBytesPerSecond   uint64
	DownloadBytesPerSecond uint64
	IPLimit                uint32
	ConnectionLimit        uint32
}

type userState struct {
	access      sync.Mutex
	limits      Limits
	ips         map[netip.Addr]uint32
	connections uint32
	upload      *rateGate
	download    *rateGate
	requests    requestWindow
}

// Manager shares counters and bandwidth budgets across each user's logical streams.
// Cached state survives user-list updates; removed users' streams are slowed to one byte per second.
// @author lyt
// @date 2026-10-29
type Manager struct {
	access       sync.RWMutex
	users        map[string]*userState
	cache        map[string]*userState
	base         adapter.SSMTracker
	requestLimit uint64
	cleaner      *ConnectionCleaner
	now          func() time.Time
}

var (
	_ adapter.SSMTracker              = (*Manager)(nil)
	_ adapter.ContextSSMTracker       = (*Manager)(nil)
	_ adapter.ContextPacketSSMTracker = (*Manager)(nil)
)

func NewManager(base adapter.SSMTracker) *Manager {
	return NewManagerWithRequestLimit(base, 0)
}

// NewManagerWithRequestLimit configures a per-user request quota independently for this node.
// The quota is immutable; zero disables request admission limits.
func NewManagerWithRequestLimit(base adapter.SSMTracker, requestLimit uint64) *Manager {
	return &Manager{
		users: make(map[string]*userState), cache: make(map[string]*userState), base: base,
		requestLimit: requestLimit, now: time.Now,
	}
}

// SetConnectionCleaner attaches a shared cleaner to subsequently admitted streams.
func (m *Manager) SetConnectionCleaner(cleaner *ConnectionCleaner) {
	m.access.Lock()
	m.cleaner = cleaner
	m.access.Unlock()
}

func (m *Manager) UpdateUsers(users map[string]Limits) error {
	for name, limits := range users {
		if name == "" {
			return fmt.Errorf("managed limit user name is empty")
		}
		if limits.UploadBytesPerSecond > uint64(math.MaxInt) ||
			limits.DownloadBytesPerSecond > uint64(math.MaxInt) {
			return fmt.Errorf("managed bandwidth limit exceeds the platform integer range")
		}
	}
	m.access.Lock()
	defer m.access.Unlock()
	next := make(map[string]*userState, len(users))
	for name, limits := range users {
		state := m.cache[name]
		if state == nil {
			state = &userState{ips: make(map[netip.Addr]uint32), upload: newRateGate(), download: newRateGate()}
			m.cache[name] = state
		}
		state.access.Lock()
		state.limits = limits
		state.upload.set(limits.UploadBytesPerSecond)
		state.download.set(limits.DownloadBytesPerSecond)
		state.access.Unlock()
		next[name] = state
	}
	for name, state := range m.users {
		if _, exists := next[name]; exists {
			continue
		}
		state.access.Lock()
		state.limits.UploadBytesPerSecond = 1
		state.limits.DownloadBytesPerSecond = 1
		state.upload.set(1)
		state.download.set(1)
		state.access.Unlock()
	}
	m.users = next
	return nil
}

func (m *Manager) TrackConnectionContext(ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext,
) (net.Conn, error) {
	return m.trackConnection(ctx, conn, metadata, m.requestLimit)
}

// CheckRequest consumes the request quota before sniffing and node policy evaluation.
func (m *Manager) CheckRequest(ctx context.Context, user string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.access.RLock()
	defer m.access.RUnlock()
	state := m.users[user]
	if state == nil {
		return ErrUnknownUser
	}
	state.access.Lock()
	defer state.access.Unlock()
	if !state.requests.accept(m.now().Unix(), m.requestLimit) {
		return ErrRequestLimit
	}
	return nil
}

// TrackRoutedConnection admits a request already checked by CheckRequest.
// Node policy rejection therefore consumes requests, but never active connection or IP slots.
func (m *Manager) TrackRoutedConnection(ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext,
) (net.Conn, error) {
	return m.trackConnection(ctx, conn, metadata, 0)
}

func (m *Manager) trackConnection(ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext, requestLimit uint64,
) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	domain := strings.TrimSuffix(strings.ToLower(metadata.Destination.Fqdn), ".")
	if domain == uot.MagicAddress || domain == uot.LegacyMagicAddress {
		return nil, ErrUDPDisabled
	}
	m.access.RLock()
	state := m.users[metadata.User]
	if state == nil {
		m.access.RUnlock()
		return nil, ErrUnknownUser
	}
	ip := metadata.Source.Addr.Unmap()
	err := state.acquire(ip, requestLimit, m.now().Unix())
	cleaner := m.cleaner
	m.access.RUnlock()
	if err != nil {
		return nil, err
	}
	streamCtx, cancel := context.WithCancel(ctx)
	controlled := &controlledConn{Conn: conn, ctx: streamCtx, cancel: cancel, state: state, ip: ip}
	var tracked net.Conn = controlled
	if cleaner != nil {
		tracked = cleaner.TrackConnection(controlled)
	}
	// Cancellation closes the socket as well as any outstanding token reservation.
	stop := context.AfterFunc(streamCtx, func() { tracked.Close() })
	controlled.stop.Store(&stop)
	if err := ctx.Err(); err != nil {
		tracked.Close()
		return nil, err
	}
	if m.base != nil {
		return m.base.TrackConnection(tracked, metadata), nil
	}
	return tracked, nil
}

// TrackConnection is the legacy fallback. Managed inbounds use adapter.TrackConnection
// so admission errors propagate before routing, rather than discovering a closed socket later.
func (m *Manager) TrackConnection(conn net.Conn, metadata adapter.InboundContext) net.Conn {
	tracked, err := m.TrackConnectionContext(context.Background(), conn, metadata)
	if err == nil {
		return tracked
	}
	conn.Close()
	return conn
}

func (m *Manager) TrackPacketConnection(conn N.PacketConn, metadata adapter.InboundContext) N.PacketConn {
	conn.Close()
	return conn
}

func (m *Manager) TrackPacketConnectionContext(context.Context, N.PacketConn,
	adapter.InboundContext,
) (N.PacketConn, error) {
	return nil, ErrUDPDisabled
}

func (s *userState) acquire(ip netip.Addr, requestLimit uint64, now int64) error {
	s.access.Lock()
	defer s.access.Unlock()
	if !s.requests.accept(now, requestLimit) {
		return ErrRequestLimit
	}
	if s.connections == math.MaxUint32 ||
		s.limits.ConnectionLimit != 0 && s.connections >= s.limits.ConnectionLimit {
		return ErrConnectionLimit
	}
	if s.limits.IPLimit != 0 && !ip.IsValid() {
		return ErrInvalidSource
	}
	if ip.IsValid() {
		if _, exists := s.ips[ip]; !exists && s.limits.IPLimit != 0 && uint32(len(s.ips)) >= s.limits.IPLimit {
			return ErrIPLimit
		}
		s.ips[ip]++
	}
	s.connections++
	return nil
}

func (s *userState) release(ip netip.Addr) {
	s.access.Lock()
	defer s.access.Unlock()
	if count := s.ips[ip]; count <= 1 {
		delete(s.ips, ip)
	} else {
		s.ips[ip] = count - 1
	}
	if s.connections > 0 {
		s.connections--
	}
}

func (m *Manager) OnlineIPs() map[string][]netip.Addr {
	m.access.RLock()
	defer m.access.RUnlock()
	result := make(map[string][]netip.Addr)
	for name, state := range m.users {
		state.access.Lock()
		if len(state.ips) > 0 {
			ips := make([]netip.Addr, 0, len(state.ips))
			for ip := range state.ips {
				ips = append(ips, ip)
			}
			slices.SortFunc(ips, netip.Addr.Compare)
			result[name] = ips
		}
		state.access.Unlock()
	}
	return result
}

func (m *Manager) ActiveConnections(user string) uint32 {
	m.access.RLock()
	defer m.access.RUnlock()
	state := m.cache[user]
	if state == nil {
		return 0
	}
	state.access.Lock()
	defer state.access.Unlock()
	return state.connections
}
