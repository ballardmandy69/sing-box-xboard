package box

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/memoryguard"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// nyafwRuntime owns shared maintenance so nodes in one Box use the same sampling cycle.
// @author lyt
// @date 2026-10-29
type nyafwRuntime struct {
	cleaner *usercontrol.ConnectionCleaner
	guard   *memoryguard.Guard
}

func newNYAFWRuntime(ctx context.Context, logger log.ContextLogger, options option.NYAFWOptions) (*nyafwRuntime, error) {
	if options.AccessLog > 2 {
		return nil, fmt.Errorf("AccessLog must be 0 (collect), 1 (print and collect), or 2 (disabled)")
	}
	if options.ConnectionCleanupIntervalSec > uint64(math.MaxInt64/int64(time.Second)) {
		return nil, fmt.Errorf("ConnectionCleanupIntervalSec exceeds the supported timer range")
	}
	interval := time.Duration(options.ConnectionCleanupIntervalSec) * time.Second
	cleaner, err := usercontrol.NewConnectionCleaner(interval)
	if err != nil {
		return nil, err
	}
	cleaner.SetLogger(logger)
	guardOptions := memoryguard.Options{
		Enabled:       options.MemoryGuard.Enabled,
		CheckInterval: time.Duration(options.MemoryGuard.CheckInterval),
		BlockDuration: time.Duration(options.MemoryGuard.BlockDuration),
	}
	for _, step := range options.MemoryGuard.Steps {
		guardOptions.Steps = append(guardOptions.Steps, memoryguard.Step{
			AvailableMemoryPercent: step.AvailableMemoryPercent,
			BlockPercentPerCheck:   step.BlockPercentPerCheck,
			MaxBlockedPercent:      step.MaxBlockedPercent,
		})
	}
	guard, err := memoryguard.New(guardOptions, cleaner, logger)
	if err != nil {
		return nil, err
	}
	service.MustRegisterPtr(ctx, cleaner)
	if guard != nil {
		service.MustRegisterPtr(ctx, guard)
	}
	service.MustRegisterPtr(ctx, &options)
	return &nyafwRuntime{cleaner: cleaner, guard: guard}, nil
}

func (r *nyafwRuntime) Name() string {
	return "nyafw maintenance"
}

func (r *nyafwRuntime) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := r.cleaner.Start(); err != nil {
		return err
	}
	scope.Add(r.cleaner.Close)
	if r.guard != nil {
		if err := r.guard.Start(); err != nil {
			return err
		}
		scope.Add(r.guard.Close)
	}
	return nil
}
