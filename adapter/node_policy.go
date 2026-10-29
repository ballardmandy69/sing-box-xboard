package adapter

import (
	"context"
	"errors"
	"net"
)

var ErrManagedNodePolicyRejected = errors.New("blocked by managed node policy")

// ManagedNodePolicy runs after legacy sniff/resolution and before routing selects an outbound.
// @author lyt
// @date 2026-10-29
type ManagedNodePolicy interface {
	HasNode(tag string) bool
	FingerprintEnabled() bool
	Check(ctx context.Context, metadata *InboundContext, conn net.Conn) error
}

// ManagedNodeTracker separates request admission from connection admission and accounting.
// @author lyt
// @date 2026-10-29
type ManagedNodeTracker interface {
	CheckNodeRequest(context.Context, *InboundContext) (ManagedNodeRequest, error)
	TrackNodeConnection(context.Context, net.Conn, *InboundContext) (net.Conn, error)
}

// ManagedNodeRequest keeps one logical stream's identity across sniffing and user-table refreshes.
// @author lyt
// @date 2026-10-29
type ManagedNodeRequest interface {
	CheckPolicy(context.Context, *InboundContext, net.Conn) error
	TrackConnection(context.Context, net.Conn, *InboundContext) (net.Conn, error)
}

// SetManagedNodeIdentity records the accounting admission without changing authentication or routing.
func (c *InboundContext) SetManagedNodeIdentity(panel string, userID uint64) {
	c.managedNodePanel = panel
	c.managedNodeUserID = userID
}

// ManagedNodeIdentity returns the admitted identity even if the panel's current UUID mapping changes.
func (c *InboundContext) ManagedNodeIdentity() (panel string, userID uint64, loaded bool) {
	return c.managedNodePanel, c.managedNodeUserID, c.managedNodePanel != ""
}
