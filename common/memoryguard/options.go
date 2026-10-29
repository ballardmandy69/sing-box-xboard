package memoryguard

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// Step selects source IPs when system available memory reaches its threshold.
// @author lyt
// @date 2026-10-29
type Step struct {
	AvailableMemoryPercent float64
	BlockPercentPerCheck   float64
	MaxBlockedPercent      float64
}

// Options preserves the original memory-pressure thresholds and durations.
// @author lyt
// @date 2026-10-29
type Options struct {
	Enabled       bool
	CheckInterval time.Duration
	BlockDuration time.Duration
	Steps         []Step
}

func normalize(options Options) (Options, error) {
	if !options.Enabled {
		return options, nil
	}
	if options.CheckInterval < 0 || options.BlockDuration < 0 {
		return options, fmt.Errorf("memory guard durations must not be negative")
	}
	if options.CheckInterval == 0 {
		options.CheckInterval = 5 * time.Second
	}
	// Reject an interval whose positive jitter endpoint would overflow time.Duration.
	// This is an explicit robustness bound; the original extreme-input behavior is unverified.
	if options.CheckInterval > time.Duration(math.MaxInt64)-options.CheckInterval/10 {
		return options, fmt.Errorf("memory guard check interval overflows its 10%% jitter range")
	}
	if options.BlockDuration == 0 {
		options.BlockDuration = time.Minute
	}
	options.Steps = slices.Clone(options.Steps)
	if len(options.Steps) == 0 {
		options.Steps = []Step{{10, 2, 10}}
	}
	thresholds := make(map[float64]bool, len(options.Steps))
	for index, step := range options.Steps {
		for _, value := range []float64{
			step.AvailableMemoryPercent, step.BlockPercentPerCheck, step.MaxBlockedPercent,
		} {
			if math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value > 100 {
				return options, fmt.Errorf("memory guard step %d: percentages must be finite and in (0,100]", index)
			}
		}
		if step.MaxBlockedPercent < step.BlockPercentPerCheck {
			return options, fmt.Errorf("memory guard step %d: maximum is below per-check percentage", index)
		}
		if thresholds[step.AvailableMemoryPercent] {
			return options, fmt.Errorf("memory guard step %d: duplicate available-memory threshold", index)
		}
		thresholds[step.AvailableMemoryPercent] = true
	}
	slices.SortFunc(options.Steps, func(left, right Step) int {
		if left.AvailableMemoryPercent > right.AvailableMemoryPercent {
			return -1
		}
		return 1
	})
	return options, nil
}
