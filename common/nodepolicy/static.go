package nodepolicy

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
)

// SetPanelTag associates a static inbound with a panel without changing its authentication table.
// @author lyt
// @date 2026-10-29
func (r *Registry) SetPanelTag(inbound, panel string) {
	r.access.Lock()
	r.aliases[inbound] = panel
	r.access.Unlock()
}

func (r *Registry) PanelTag(inbound string) string {
	r.access.RLock()
	panel, _ := r.panelTagLocked(inbound)
	r.access.RUnlock()
	return panel
}

func (r *Registry) HasPanelAlias(inbound string) bool {
	r.access.RLock()
	_, exists := r.aliases[inbound]
	r.access.RUnlock()
	return exists
}

func (r *Registry) panelTagLocked(inbound string) (string, bool) {
	panel, aliased := r.aliases[inbound]
	if !aliased {
		panel = inbound
	}
	// Route lookup substitutes one alias before GetUserGateway, which has one fallback of its own.
	if r.nodes[panel] == nil {
		if fallback := r.aliases[panel]; fallback != "" {
			return fallback, true
		}
	}
	return panel, aliased
}

func (r *Registry) lookupNode(inbound string) (*nodeSnapshot, bool) {
	r.access.RLock()
	panel, aliased := r.panelTagLocked(inbound)
	node := r.nodes[panel]
	r.access.RUnlock()
	return node, aliased || node != nil && node.Static
}

func (r *Registry) lookupUser(node *nodeSnapshot, static bool, inbound, name string) (User, bool) {
	if static {
		if node.LookupStaticUser == nil {
			return User{}, false
		}
		// Managed source inbounds use stable identities internally. Recover the UUID before
		// looking up the aliased panel, without moving or replacing source credentials.
		r.access.RLock()
		source := r.nodes[inbound]
		r.access.RUnlock()
		if source != nil && !source.Static {
			if source.LookupAuthUUID == nil {
				return User{}, false
			}
			uuid, exists := source.LookupAuthUUID(name)
			if !exists {
				return User{}, false
			}
			name = uuid
		}
		return node.LookupStaticUser(name)
	}
	return node.LookupUser(name)
}

func (r *Registry) LookupUser(inbound, name string) (User, bool) {
	node, static := r.lookupNode(inbound)
	if node == nil {
		return User{}, false
	}
	return r.lookupUser(node, static, inbound, name)
}

// CheckNodeRequest applies the final node's request quota before sniffing and rule checks.
func (r *Registry) CheckNodeRequest(ctx context.Context,
	metadata *adapter.InboundContext,
) (adapter.ManagedNodeRequest, error) {
	node, static := r.lookupNode(metadata.Inbound)
	if node == nil || node.CheckRequest == nil && node.TrackConnection == nil {
		return nil, nil
	}
	user, exists := r.lookupUser(node, static, metadata.Inbound, metadata.User)
	if !exists {
		return nil, adapter.ErrManagedNodePolicyRejected
	}
	uuid, exists := r.sourceUUID(metadata.Inbound, metadata.User)
	if !exists {
		return nil, adapter.ErrManagedNodePolicyRejected
	}
	request := &nodeRequest{registry: r, inbound: metadata.Inbound, authenticationName: metadata.User,
		panel: r.PanelTag(metadata.Inbound), sourceUUID: uuid, user: user}
	if _, err := request.validate(metadata); err != nil {
		return nil, err
	}
	if node.CheckRequest != nil {
		if err := node.CheckRequest(ctx, user.Label); err != nil {
			return nil, err
		}
	}
	return request, nil
}

// TrackNodeConnection counts admitted logical streams after legacy sniff bytes are restored.
// @author lyt
// @date 2026-10-29
func (r *Registry) TrackNodeConnection(ctx context.Context, conn net.Conn,
	metadata *adapter.InboundContext,
) (net.Conn, error) {
	node, static := r.lookupNode(metadata.Inbound)
	if node == nil || node.TrackConnection == nil {
		return conn, nil
	}
	user, exists := r.lookupUser(node, static, metadata.Inbound, metadata.User)
	if !exists {
		return conn, adapter.ErrManagedNodePolicyRejected
	}
	return r.trackNodeUser(ctx, conn, metadata, node, user)
}

func (r *Registry) trackNodeUser(ctx context.Context, conn net.Conn, metadata *adapter.InboundContext,
	node *nodeSnapshot, user User,
) (net.Conn, error) {
	if node.TrackConnection == nil {
		return conn, nil
	}
	trackedMetadata := *metadata
	trackedMetadata.User = user.Label
	tracked, err := node.TrackConnection(ctx, conn, trackedMetadata)
	if err != nil {
		return conn, err
	}
	metadata.SetManagedNodeIdentity(node.tag, user.ID)
	if r.cleaner != nil {
		r.cleaner.UpdateMetadata(tracked, "tcp-routed", metadata.Source.Addr.Unmap().String(), user.Label)
	}
	// Keep the original authentication name and inbound for later route checks and logs.
	return tracked, nil
}

// nodeRequest pins accounting identity without changing the original authentication metadata.
// @author lyt
// @date 2026-10-29
type nodeRequest struct {
	registry           *Registry
	inbound            string
	authenticationName string
	panel              string
	sourceUUID         string
	user               User
}

func (r *Registry) sourceUUID(inbound, name string) (string, bool) {
	r.access.RLock()
	source := r.nodes[inbound]
	r.access.RUnlock()
	if source != nil && !source.Static && source.LookupAuthUUID != nil {
		return source.LookupAuthUUID(name)
	}
	return name, true
}

func (q *nodeRequest) validate(metadata *adapter.InboundContext) (*nodeSnapshot, error) {
	if metadata.Inbound != q.inbound || metadata.User != q.authenticationName ||
		q.registry.PanelTag(metadata.Inbound) != q.panel {
		return nil, adapter.ErrManagedNodePolicyRejected
	}
	uuid, exists := q.registry.sourceUUID(q.inbound, q.authenticationName)
	if !exists || uuid != q.sourceUUID {
		return nil, adapter.ErrManagedNodePolicyRejected
	}
	node, static := q.registry.lookupNode(q.inbound)
	if node == nil {
		return nil, adapter.ErrManagedNodePolicyRejected
	}
	user, exists := q.registry.lookupUser(node, static, q.inbound, q.authenticationName)
	if !exists || user != q.user {
		return nil, adapter.ErrManagedNodePolicyRejected
	}
	return node, nil
}

func (q *nodeRequest) CheckPolicy(ctx context.Context, metadata *adapter.InboundContext, conn net.Conn) error {
	node, err := q.validate(metadata)
	if err != nil {
		return err
	}
	return q.registry.checkUserPolicy(ctx, metadata, conn, node, q.user)
}

func (q *nodeRequest) TrackConnection(ctx context.Context, conn net.Conn,
	metadata *adapter.InboundContext,
) (net.Conn, error) {
	node, err := q.validate(metadata)
	if err != nil {
		return conn, err
	}
	return q.registry.trackNodeUser(ctx, conn, metadata, node, q.user)
}
