package option

// NYAFWOptions holds process-wide settings normalized from a nyafw-shaped configuration.
// @author lyt
// @date 2026-10-29
type NYAFWOptions struct {
	ConnectionCleanupIntervalSec uint64        `json:"connection_cleanup_interval_sec,omitempty"`
	HotUserCacheSec              int64         `json:"hot_user_cache_sec,omitempty"`
	AccessLog                    uint8         `json:"access_log,omitempty"`
	SbAPI                        *SbAPIOptions `json:"sb_api,omitempty"`
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
