package nodepolicy

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/usercontrol"
)

// User carries the panel's numeric identity and its existing traffic-statistics label.
// @author lyt
// @date 2026-10-29
type User struct {
	ID    uint64
	Label string
}

// Rule preserves the provider's rule identifier and regular expression.
// @author lyt
// @date 2026-10-29
type Rule struct {
	ID      int
	Pattern string
}

// Node supplies current identity lookup and reporting without coupling routing to HTTP providers.
// @author lyt
// @date 2026-10-29
type Node struct {
	LookupUser func(string) (User, bool)
	Rules      []Rule
	OnBlocked  func(context.Context, adapter.InboundContext, uint64, string)
	OnIllegal  func(uint64, int)
}

type compiledRule struct {
	id      int
	pattern *regexp.Regexp
}

type nodeSnapshot struct {
	Node
	rules []compiledRule
}

// Registry publishes validated immutable node policies and shares one compiled scanner.
// @author lyt
// @date 2026-10-29
type Registry struct {
	access  sync.RWMutex
	nodes   map[string]*nodeSnapshot
	scanner *Scanner
	cleaner *usercontrol.ConnectionCleaner
}

var _ adapter.ManagedNodePolicy = (*Registry)(nil)

func NewRegistry(expression string, cleaner *usercontrol.ConnectionCleaner) (*Registry, error) {
	scanner, err := NewScanner(expression)
	if err != nil {
		return nil, err
	}
	return &Registry{nodes: make(map[string]*nodeSnapshot), scanner: scanner, cleaner: cleaner}, nil
}

func (r *Registry) Register(tag string, node Node) error {
	if tag == "" || node.LookupUser == nil {
		return fmt.Errorf("managed node policy requires an inbound tag and user lookup")
	}
	snapshot := &nodeSnapshot{Node: node, rules: make([]compiledRule, 0, len(node.Rules))}
	snapshot.Node.Rules = nil
	for _, rule := range node.Rules {
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("managed node %s rule %d: %w", tag, rule.ID, err)
		}
		snapshot.rules = append(snapshot.rules, compiledRule{rule.ID, pattern})
	}
	r.access.Lock()
	r.nodes[tag] = snapshot
	r.access.Unlock()
	return nil
}

func (r *Registry) Remove(tag string) {
	r.access.Lock()
	delete(r.nodes, tag)
	r.access.Unlock()
}

func (r *Registry) HasNode(tag string) bool {
	r.access.RLock()
	_, exists := r.nodes[tag]
	r.access.RUnlock()
	return exists
}

func (r *Registry) FingerprintEnabled() bool { return r.scanner != nil }

func (r *Registry) Check(ctx context.Context, metadata *adapter.InboundContext, conn net.Conn) error {
	r.access.RLock()
	node := r.nodes[metadata.Inbound]
	r.access.RUnlock()
	if node == nil {
		return nil
	}
	user, exists := node.LookupUser(metadata.User)
	if !exists {
		// A stream admitted before a user refresh may reach routing after removal.
		// Deliberately fail closed here instead of preserving the sample's bypass.
		return adapter.ErrManagedNodePolicyRejected
	}
	if reason := r.scanner.MustCheck(metadata, metadata.TLSFingerprint, user.ID); reason != "" {
		if node.OnBlocked != nil {
			node.OnBlocked(ctx, *metadata, user.ID, "gfw:"+reason)
		}
		return adapter.ErrManagedNodePolicyRejected
	}
	destination := metadata.Destination.String()
	for _, rule := range node.rules {
		if !rule.pattern.MatchString(destination) {
			continue
		}
		if node.OnIllegal != nil {
			node.OnIllegal(user.ID, rule.id)
		}
		if node.OnBlocked != nil {
			node.OnBlocked(ctx, *metadata, user.ID, fmt.Sprintf("audit:%d", rule.id))
		}
		return adapter.ErrManagedNodePolicyRejected
	}
	if r.cleaner != nil && conn != nil {
		r.cleaner.UpdateMetadata(conn, "tcp-routed", metadata.Source.Addr.Unmap().String(), user.Label)
	}
	return nil
}
