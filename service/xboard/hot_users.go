package xboard

import (
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/service/ssmapi"
)

// hotUsers publishes authentication candidates without expiring users or their rate limiters.
// @author lyt
// @date 2026-10-29
type hotUsers struct {
	access  sync.Mutex
	expires map[string]time.Time
	ttl     time.Duration
	manager adapter.HotUserManager
	now     func() time.Time
}

func hotUserTTL(seconds int64) (time.Duration, error) {
	if seconds <= 0 {
		return 600 * time.Second, nil
	}
	if seconds > math.MaxInt64/int64(time.Second) {
		return 0, fmt.Errorf("HotUserCacheSec exceeds the supported timer range")
	}
	return time.Duration(seconds) * time.Second, nil
}

func newHotUsers(manager adapter.HotUserManager, ttl time.Duration) *hotUsers {
	users := &hotUsers{expires: make(map[string]time.Time), ttl: ttl, manager: manager, now: time.Now}
	manager.SetHotUserCallback(users.add)
	return users
}

func (h *hotUsers) add(name string) {
	h.access.Lock()
	defer h.access.Unlock()
	h.expires[name] = h.now().Add(h.ttl)
	// A callback refresh does not prune other entries; the traffic cycle owns pruning.
	h.publishLocked()
}

func (h *hotUsers) refresh(snapshots []*ssmapi.UserTrafficSnapshot) {
	if h == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	now := h.now()
	for name, expires := range h.expires {
		if expires.Before(now) {
			delete(h.expires, name)
		}
	}
	for _, snapshot := range snapshots {
		if snapshot.UplinkBytes+snapshot.DownlinkBytes > 0 {
			h.expires[snapshot.UserName] = now.Add(h.ttl)
		}
	}
	h.publishLocked()
}

func (h *hotUsers) publishLocked() {
	names := make([]string, 0, len(h.expires))
	for name := range h.expires {
		names = append(names, name)
	}
	slices.Sort(names)
	h.manager.UpdateHotUsers(names)
}
