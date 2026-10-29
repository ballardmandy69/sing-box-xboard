package xboard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
)

type autoInboundConfig struct {
	protocol string
	options  any
	endpoint netip.AddrPort
}

type autoInboundInstance struct {
	inbound adapter.ManagedSSMServer
	scope   *adapter.Scope
	config  autoInboundConfig
	stage   int
}

// autoInbound retains one manager registration while owning replaceable protocol lifecycles.
// Credentials and traffic accounting survive successful listener replacement.
// @author lyt
// @date 2026-10-29
type autoInbound struct {
	inbound.Adapter
	ctx         context.Context
	registry    adapter.InboundRegistry
	router      adapter.Router
	logger      log.ContextLogger
	access      sync.Mutex
	current     *autoInboundInstance
	stage       int
	cleanupSet  bool
	closed      bool
	tracker     adapter.SSMTracker
	users       []string
	credentials []string
}

var _ adapter.ManagedSSMServer = (*autoInbound)(nil)

func newAutoInbound(ctx context.Context, registry adapter.InboundRegistry, router adapter.Router,
	logger log.ContextLogger, tag string, config autoInboundConfig,
) (*autoInbound, error) {
	h := &autoInbound{
		Adapter: inbound.NewAdapter(config.protocol, tag), ctx: ctx,
		registry: registry, router: router, logger: logger, stage: -1,
	}
	instance, err := h.construct(config)
	if err != nil {
		return nil, err
	}
	h.current = instance
	return h, nil
}

func (h *autoInbound) construct(config autoInboundConfig) (*autoInboundInstance, error) {
	scope := adapter.NewScope(h.ctx, h.logger)
	created, err := h.registry.Create(scope.Context(), h.router, h.logger, h.Tag(), config.protocol, config.options)
	if err != nil {
		scope.Close()
		return nil, err
	}
	managed, ok := created.(adapter.ManagedSSMServer)
	if !ok {
		scope.Close()
		return nil, fmt.Errorf("automatic xboard inbound does not support managed users")
	}
	return &autoInboundInstance{inbound: managed, scope: scope, config: config, stage: -1}, nil
}

func (h *autoInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	h.access.Lock()
	defer h.access.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	if !h.cleanupSet {
		scope.Add(h.close)
		h.cleanupSet = true
	}
	for next := h.stage + 1; next <= int(stage); next++ {
		if err := h.startInstance(h.current, adapter.StartStage(next)); err != nil {
			return err
		}
		h.stage = next
	}
	return nil
}

func (h *autoInbound) startInstance(instance *autoInboundInstance, stage adapter.StartStage) error {
	if err := instance.scope.Start("xboard inbound/"+h.Tag(), instance.inbound, stage); err != nil {
		return err
	}
	instance.stage = int(stage)
	return nil
}

func (h *autoInbound) SetTracker(tracker adapter.SSMTracker) {
	h.access.Lock()
	defer h.access.Unlock()
	h.tracker = tracker
	if !h.closed {
		h.current.inbound.SetTracker(tracker)
	}
}

func (h *autoInbound) UpdateUsers(users, credentials []string) error {
	h.access.Lock()
	defer h.access.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	if err := h.current.inbound.UpdateUsers(users, credentials); err != nil {
		return err
	}
	h.users = slices.Clone(users)
	h.credentials = slices.Clone(credentials)
	return nil
}

func (h *autoInbound) replace(config autoInboundConfig) error {
	h.access.Lock()
	if h.closed {
		h.access.Unlock()
		return net.ErrClosed
	}
	if reflect.DeepEqual(h.current.config, config) && h.current.stage == h.stage {
		h.access.Unlock()
		return nil
	}
	candidate, err := h.prepare(config)
	if err != nil {
		h.access.Unlock()
		return err
	}
	previous := h.current
	conflicts := h.stage >= int(adapter.StartStateStart) &&
		conflictingEndpoint(previous.config.endpoint, config.endpoint)
	var rollback *autoInboundInstance
	if conflicts {
		// Validate the fallback before closing the live socket, including certificate files.
		rollback, err = h.prepare(previous.config)
		if err != nil {
			candidate.scope.Close()
			h.access.Unlock()
			return fmt.Errorf("prepare previous xboard configuration for rollback: %w", err)
		}
		h.logger.Info("xboard inbound restarting on the same endpoint: ", h.Tag())
		h.closeInstance(previous)
	}
	if err = h.startPrepared(candidate); err != nil {
		candidate.scope.Close()
		if rollback != nil {
			h.current = rollback
			if rollbackErr := h.startPrepared(rollback); rollbackErr != nil {
				rollback.scope.Close()
				h.access.Unlock()
				return fmt.Errorf("new xboard listener failed: %v; previous listener rollback failed: %w", err, rollbackErr)
			}
			h.logger.Error("xboard configuration rejected; previous listener restored: ", h.Tag())
		}
		h.access.Unlock()
		return err
	}
	h.current = candidate
	if rollback != nil {
		rollback.scope.Close()
	} else {
		h.closeInstance(previous)
	}
	h.access.Unlock()
	h.logger.Info("xboard inbound configuration replaced: ", h.Tag())
	return nil
}

func (h *autoInbound) prepare(config autoInboundConfig) (*autoInboundInstance, error) {
	instance, err := h.construct(config)
	if err != nil {
		return nil, err
	}
	instance.inbound.SetTracker(h.tracker)
	if err = instance.inbound.UpdateUsers(h.users, h.credentials); err != nil {
		instance.scope.Close()
		return nil, err
	}
	return instance, nil
}

func (h *autoInbound) startPrepared(instance *autoInboundInstance) error {
	for stage := 0; stage <= h.stage; stage++ {
		if err := h.startInstance(instance, adapter.StartStage(stage)); err != nil {
			return err
		}
	}
	return nil
}

func (h *autoInbound) closeInstance(instance *autoInboundInstance) {
	if err := instance.scope.Close(); err != nil {
		h.logger.Error("xboard previous inbound cleanup failed: ", h.Tag(), ": ", err)
	}
}

func conflictingEndpoint(previous, next netip.AddrPort) bool {
	return previous.Port() == next.Port() && (previous.Addr() == next.Addr() ||
		previous.Addr().IsUnspecified() || next.Addr().IsUnspecified())
}

func (h *autoInbound) close() error {
	h.access.Lock()
	defer h.access.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	return h.current.scope.Close()
}
