package xboard

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
	M "github.com/sagernet/sing/common/metadata"
)

type policyFixtureInbound struct{ adapter.ManagedSSMServer }

func (policyFixtureInbound) Tag() string { return "policy-in" }

type policyFixtureProvider struct {
	panelProvider
	rules []nodepolicy.Rule
}

func (p *policyFixtureProvider) NodeRules() []nodepolicy.Rule { return p.rules }

func TestNodePolicyPublishesPrimaryRulesAndRejectLogs(t *testing.T) {
	registry, err := nodepolicy.NewRegistry(`uid == 8u ? "scanner" : ""`, nil)
	if err != nil {
		t.Fatal(err)
	}
	provider := &policyFixtureProvider{rules: []nodepolicy.Rule{{ID: 3, Pattern: `blocked\.test`}}}
	s := &Service{policy: registry}
	n := &node{
		service: s, inbound: policyFixtureInbound{},
		primary: &nodePanel{client: &panelClient{provider: provider}},
		users:   map[string]uint64{"seven": 7, "eight": 8}, accessLog: newAccessLogQueue(0, nil),
	}
	s.nodes = []*node{n}
	if err = n.syncNodePolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	metadata := adapter.InboundContext{
		Inbound: "policy-in", User: "seven", Network: "tcp", Protocol: "http",
		Source: M.ParseSocksaddr("192.0.2.1:3000"), Destination: M.ParseSocksaddr("blocked.test:443"),
	}
	if err = registry.Check(context.Background(), &metadata, nil); !errors.Is(err, adapter.ErrManagedNodePolicyRejected) {
		t.Fatalf("panel rule was not applied: %v", err)
	}
	metadata.User = "eight"
	if err = registry.Check(context.Background(), &metadata, nil); !errors.Is(err, adapter.ErrManagedNodePolicyRejected) {
		t.Fatalf("scanner did not reject the managed identity: %v", err)
	}
	if len(n.accessLog.records) != 2 || n.accessLog.records[0].Outbound != "audit:3" ||
		n.accessLog.records[0].Uid != 7 || n.accessLog.records[1].Outbound != "gfw:scanner" ||
		n.accessLog.records[1].Uid != 8 || n.accessLog.records[1].Dst != "blocked.test:443" {
		t.Fatalf("rejected-connection records lost their identity/reason: %+v", n.accessLog.records)
	}
	provider.rules = []nodepolicy.Rule{{ID: 4, Pattern: "["}}
	if err = n.syncNodePolicy(context.Background()); err == nil {
		t.Fatal("invalid new policy accepted")
	}
	metadata.User = "seven"
	if err = registry.Check(context.Background(), &metadata, nil); !errors.Is(err, adapter.ErrManagedNodePolicyRejected) {
		t.Fatal("failed policy update discarded the previous active rule")
	}
	provider.rules = nil
	if err = n.syncNodePolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = registry.Check(context.Background(), &metadata, nil); err != nil {
		t.Fatal("removing panel rules did not take effect")
	}
	if err = s.closeNodePolicies(); err != nil || registry.HasNode("policy-in") {
		t.Fatal("service shutdown left its policy registered")
	}
	if err = n.syncNodePolicy(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("a late panel response resurrected a closed service policy")
	}
}
