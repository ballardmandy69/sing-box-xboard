package inbound

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

// registeredInbound records lifecycle ownership for preconstructed managed inbounds.
// @author lyt
// @date 2026-10-29
type registeredInbound struct {
	tag    string
	stages []adapter.StartStage
	closed int
}

func (i *registeredInbound) Type() string { return "test" }
func (i *registeredInbound) Tag() string  { return i.tag }
func (i *registeredInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	i.stages = append(i.stages, stage)
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error { i.closed++; return nil })
	}
	return nil
}

func TestRegisterInboundLifecycle(t *testing.T) {
	manager := NewManager(nil, nil)
	inbound := &registeredInbound{tag: "panel-node"}
	if err := manager.Register(inbound); err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(&registeredInbound{tag: "panel-node"}); err == nil {
		t.Fatal("duplicate tag was accepted")
	}
	if err := manager.Register(nil); err == nil {
		t.Fatal("nil inbound was accepted")
	}
	snapshot := manager.Inbounds()
	snapshot[0] = nil
	if found, ok := manager.Get("panel-node"); !ok || found != inbound || manager.Inbounds()[0] != inbound {
		t.Fatal("caller changed manager ownership through its snapshot")
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	for _, stage := range adapter.ListStartStages {
		if err := manager.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.Register(&registeredInbound{tag: "late"}); err == nil {
		t.Fatal("late registration escaped lifecycle initialization")
	}
	if len(inbound.stages) != len(adapter.ListStartStages) {
		t.Fatal("registered inbound did not receive each lifecycle stage exactly once")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if inbound.closed != 1 {
		t.Fatal("registered inbound cleanup must run exactly once")
	}
}
