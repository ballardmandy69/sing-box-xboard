package usercontrol

import (
	"context"
	"net"
	"reflect"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionTracker = (*ConnectionCleaner)(nil)

// Registration is a detached view of one deduplicated connection and its current byte counter.
// Type is reserved for confirmed original registration labels; unknown labels stay empty.
// @author lyt
// @date 2026-10-29
type Registration struct {
	Type      string
	SourceIP  string
	UserLabel string
	Traffic   int64
}

func (c *ConnectionCleaner) SnapshotRegistrations() []Registration {
	c.access.Lock()
	defer c.access.Unlock()
	result := make([]Registration, 0, len(c.entries))
	for _, conn := range c.entries {
		result = append(result, Registration{conn.kind, conn.source, conn.userLabel, conn.activity.Load()})
	}
	return result
}

func (c *ConnectionCleaner) RoutedConnection(
	_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound,
) net.Conn {
	if metadata.User != "" {
		conn = c.TrackConnection(conn)
	}
	key := connectionKey(conn)
	if wrapper, ok := conn.(*cleanupConn); ok {
		key = wrapper.key
	} else if !reflect.TypeOf(key).Comparable() {
		return conn
	}
	c.access.Lock()
	if tracked := c.entries[key]; tracked != nil {
		tracked.source = metadata.Source.Addr.Unmap().String()
		tracked.userLabel = metadata.User
	}
	c.access.Unlock()
	return conn
}

func (c *ConnectionCleaner) RoutedPacketConnection(
	_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound,
) N.PacketConn {
	return conn
}

func (c *ConnectionCleaner) RoutedFlow(
	_ context.Context, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound,
) tun.FlowTracker {
	return nil
}
