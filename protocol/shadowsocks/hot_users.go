package shadowsocks

import "github.com/sagernet/sing-box/adapter"

// multiUserIdentity retains its authenticated generation through user-list reorder and callbacks.
// @author lyt
// @date 2026-10-29
type multiUserIdentity struct {
	Name  string
	Index int
}

type hotUserService interface {
	UpdateHotUsersMatching(func(multiUserIdentity) bool)
	SetHotUserCallback(func(multiUserIdentity))
}

var _ adapter.HotUserManager = (*MultiInbound)(nil)

func (h *MultiInbound) UpdateHotUsers(names []string) {
	service, supported := h.service.(hotUserService)
	if !supported {
		return
	}
	selected := make(map[string]struct{}, len(names))
	for _, name := range names {
		selected[name] = struct{}{}
	}
	service.UpdateHotUsersMatching(func(user multiUserIdentity) bool {
		_, exists := selected[user.Name]
		return exists
	})
}

func (h *MultiInbound) SetHotUserCallback(callback func(string)) {
	service, supported := h.service.(hotUserService)
	if !supported {
		return
	}
	if callback == nil {
		service.SetHotUserCallback(nil)
		return
	}
	service.SetHotUserCallback(func(user multiUserIdentity) { callback(user.Name) })
}
