package inbound

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.InboundManager = (*Manager)(nil)

type Manager struct {
	registry     adapter.InboundRegistry
	endpoint     adapter.EndpointManager
	access       sync.Mutex
	inbounds     []adapter.Inbound
	inboundByTag map[string]adapter.Inbound
	started      bool
}

func NewManager(registry adapter.InboundRegistry, endpoint adapter.EndpointManager) *Manager {
	return &Manager{
		registry:     registry,
		endpoint:     endpoint,
		inboundByTag: make(map[string]adapter.Inbound),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	m.started = true
	inbounds := append([]adapter.Inbound(nil), m.inbounds...)
	m.access.Unlock()
	for _, inbound := range inbounds {
		name := "inbound/" + inbound.Type() + "[" + inbound.Tag() + "]"
		err := scope.Start(name, inbound, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Inbounds() []adapter.Inbound {
	m.access.Lock()
	defer m.access.Unlock()
	return append([]adapter.Inbound(nil), m.inbounds...)
}

func (m *Manager) Get(tag string) (adapter.Inbound, bool) {
	m.access.Lock()
	inbound, found := m.inboundByTag[tag]
	m.access.Unlock()
	if found {
		return inbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	inbound, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	return m.Register(inbound)
}

// Register attaches a preconstructed inbound before the manager's lifecycle starts.
// @author lyt
// @date 2026-10-29
func (m *Manager) Register(inbound adapter.Inbound) error {
	if inbound == nil {
		return E.New("cannot register a nil inbound")
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.started {
		return E.New("cannot register an inbound after the manager starts")
	}
	tag := inbound.Tag()
	_, loaded := m.inboundByTag[tag]
	if loaded {
		return E.New("duplicate inbound tag: ", tag)
	}
	m.inbounds = append(m.inbounds, inbound)
	m.inboundByTag[tag] = inbound
	return nil
}
