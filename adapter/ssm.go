package adapter

import (
	"context"
	"net"

	N "github.com/sagernet/sing/common/network"
)

type ManagedSSMServer interface {
	Inbound
	SetTracker(tracker SSMTracker)
	UpdateUsers(users []string, uPSKs []string) error
}

type SSMTracker interface {
	TrackConnection(conn net.Conn, metadata InboundContext) net.Conn
	TrackPacketConnection(conn N.PacketConn, metadata InboundContext) N.PacketConn
}

// HotUserManager prioritizes recently active identities without changing their credentials or access.
// @author lyt
// @date 2026-10-29
type HotUserManager interface {
	UpdateHotUsers(names []string)
	SetHotUserCallback(callback func(string))
}

// ContextSSMTracker can reject a managed stream before the router dials its destination.
// @author lyt
// @date 2026-10-29
type ContextSSMTracker interface {
	TrackConnectionContext(ctx context.Context, conn net.Conn, metadata InboundContext) (net.Conn, error)
}

// ContextPacketSSMTracker can reject packet forwarding before creating an outbound socket.
type ContextPacketSSMTracker interface {
	TrackPacketConnectionContext(ctx context.Context, conn N.PacketConn, metadata InboundContext) (N.PacketConn, error)
}

// TrackConnection preserves legacy accounting while supporting contextual admission controls.
func TrackConnection(ctx context.Context, tracker SSMTracker, conn net.Conn,
	metadata InboundContext,
) (net.Conn, error) {
	if contextual, ok := tracker.(ContextSSMTracker); ok {
		tracked, err := contextual.TrackConnectionContext(ctx, conn, metadata)
		if err != nil {
			return conn, err
		}
		return tracked, nil
	}
	if tracker == nil {
		return conn, nil
	}
	return tracker.TrackConnection(conn, metadata), nil
}

func TrackPacketConnection(ctx context.Context, tracker SSMTracker, conn N.PacketConn,
	metadata InboundContext,
) (N.PacketConn, error) {
	if contextual, ok := tracker.(ContextPacketSSMTracker); ok {
		tracked, err := contextual.TrackPacketConnectionContext(ctx, conn, metadata)
		if err != nil {
			return conn, err
		}
		return tracked, nil
	}
	if tracker == nil {
		return conn, nil
	}
	return tracker.TrackPacketConnection(conn, metadata), nil
}
