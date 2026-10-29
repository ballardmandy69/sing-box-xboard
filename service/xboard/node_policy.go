package xboard

import (
	"context"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
)

// syncNodePolicy publishes the primary panel's rules with current user lookup and access reporting.
// @author lyt
// @date 2026-10-29
func (n *node) syncNodePolicy(ctx context.Context) error {
	if n.service == nil || n.service.policy == nil {
		return nil
	}
	n.service.policyAccess.Lock()
	defer n.service.policyAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if n.service.policyClosed {
		return net.ErrClosed
	}
	var rules []nodepolicy.Rule
	if n.primary != nil && n.primary.client != nil {
		if provider, ok := n.primary.client.provider.(interface{ NodeRules() []nodepolicy.Rule }); ok {
			rules = provider.NodeRules()
		}
	}
	err := n.service.policy.Register(n.inbound.Tag(), nodepolicy.Node{
		LookupUser: n.lookupPolicyUser,
		Rules:      rules,
		OnBlocked:  n.recordPolicyRejection,
		// OldV2Board's illegal-report method is a no-op. Other providers add their
		// confirmed reporting callback when their rule/report protocol is implemented.
	})
	if err != nil {
		return fmt.Errorf("update panel node policy: %w", err)
	}
	return nil
}

func (n *node) lookupPolicyUser(name string) (nodepolicy.User, bool) {
	n.access.RLock()
	id, exists := n.users[name]
	n.access.RUnlock()
	return nodepolicy.User{ID: id, Label: name}, exists
}

func (n *node) recordPolicyRejection(_ context.Context, metadata adapter.InboundContext,
	uid uint64, outbound string,
) {
	if n.accessLog == nil {
		return
	}
	n.accessLog.put(accessRecord{
		Inbound: metadata.Inbound, Outbound: outbound, Uid: uid, Net: metadata.Network,
		Protocol: metadata.Protocol, Src: metadata.Source.String(), Dst: metadata.Destination.String(),
	})
}

func (s *Service) closeNodePolicies() error {
	s.policyAccess.Lock()
	defer s.policyAccess.Unlock()
	s.policyClosed = true
	if s.policy != nil {
		for _, node := range s.nodes {
			s.policy.Remove(node.inbound.Tag())
		}
	}
	return nil
}
