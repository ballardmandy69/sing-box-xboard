package adapter

import "time"

// DebugHotUserProvider exposes a detached expiration snapshot for one primary panel tag.
// @author lyt
// @date 2026-10-29
type DebugHotUserProvider interface {
	DebugHotUsers(panelTag string) (map[string]time.Time, bool)
}
