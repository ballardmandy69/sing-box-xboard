package vmess

import "github.com/sagernet/sing-box/adapter"

var _ adapter.HotUserManager = (*Inbound)(nil)

func (h *Inbound) UpdateHotUsers(names []string) {
	selected := make(map[string]struct{}, len(names))
	for _, name := range names {
		selected[name] = struct{}{}
	}
	h.service.UpdateHotUsersMatching(func(user inboundUserIdentity) bool {
		_, exists := selected[user.Name]
		return exists
	})
}

// VMess learns hot users from traffic reports; the original TCP authentication has no success callback.
func (h *Inbound) SetHotUserCallback(func(string)) {}
