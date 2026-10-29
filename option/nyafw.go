package option

import "github.com/sagernet/sing/common/json/badoption"

// NYAFWOptions holds process-wide settings normalized from a nyafw-shaped configuration.
// @author lyt
// @date 2026-10-29
type NYAFWOptions struct {
	BlockScanner                 string             `json:"block_scanner,omitempty"`
	ConnectionCleanupIntervalSec uint64             `json:"connection_cleanup_interval_sec,omitempty"`
	HotUserCacheSec              int64              `json:"hot_user_cache_sec,omitempty"`
	AccessLog                    uint8              `json:"access_log,omitempty"`
	SbAPI                        *SbAPIOptions      `json:"sb_api,omitempty"`
	MemoryGuard                  MemoryGuardOptions `json:"memory_guard,omitempty"`
}

// MemoryGuardOptions controls source-IP admission while system memory is under pressure.
// @author lyt
// @date 2026-10-29
type MemoryGuardOptions struct {
	Enabled       bool                     `json:"enabled,omitempty"`
	CheckInterval badoption.Duration       `json:"check_interval,omitempty"`
	BlockDuration badoption.Duration       `json:"block_duration,omitempty"`
	Steps         []MemoryGuardStepOptions `json:"steps,omitempty"`
}

// MemoryGuardStepOptions defines one available-memory threshold and its blocking budget.
// @author lyt
// @date 2026-10-29
type MemoryGuardStepOptions struct {
	AvailableMemoryPercent float64 `json:"available_memory_percent"`
	BlockPercentPerCheck   float64 `json:"block_percent_per_check"`
	MaxBlockedPercent      float64 `json:"max_blocked_percent"`
}

// SbAPIOptions describes the optional original access-log receiver.
// @author lyt
// @date 2026-10-29
type SbAPIOptions struct {
	BaseURL          string `json:"base_url,omitempty"`
	Tag              string `json:"tag,omitempty"`
	Token            string `json:"token,omitempty"`
	SendTokenInQuery bool   `json:"send_token_in_query,omitempty"`
}
