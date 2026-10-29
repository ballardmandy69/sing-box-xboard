package xboard

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
)

func (n *node) policyTag() string {
	if n.panelTag != "" {
		return n.panelTag
	}
	if n.inbound != nil {
		return n.inbound.Tag()
	}
	return ""
}

// lookupStaticPolicyUser resolves the configured authentication name as a panel UUID.
// @author lyt
// @date 2026-10-29
func (n *node) lookupStaticPolicyUser(uuid string) (nodepolicy.User, bool) {
	n.access.RLock()
	name, exists := n.staticUsers[uuid]
	id, loaded := n.users[name]
	n.access.RUnlock()
	return nodepolicy.User{ID: id, Label: name}, exists && loaded
}

func (n *node) checkNodeRequest(ctx context.Context, user string) error {
	return n.control.CheckRequest(ctx, user)
}

func (n *node) trackNodeConnection(ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext,
) (net.Conn, error) {
	return n.control.TrackRoutedConnection(ctx, conn, metadata)
}

func (n *node) lookupAuthUUID(name string) (string, bool) {
	n.access.RLock()
	uuid, exists := n.authUUIDs[name]
	n.access.RUnlock()
	return uuid, exists
}
