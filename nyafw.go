package box

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/sagernet/sing-box/adapter"
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
	service.MustRegisterPtr(ctx, cleaner)
	service.MustRegisterPtr(ctx, &options)
	return &nyafwRuntime{cleaner: cleaner}, nil
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
	return nil
}
