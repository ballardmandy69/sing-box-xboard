package usercontrol

// requestWindow preserves nyafw's integer-second quota, keyed by the authenticated user.
// Callers hold userState.access; a rejected request does not extend the window.
// @author lyt
// @date 2026-10-29
type requestWindow struct {
	initialized  bool
	lastAccepted int64
	remaining    uint64
}

func (w *requestWindow) accept(now int64, limit uint64) bool {
	if limit == 0 {
		return true
	}
	if !w.initialized || now >= w.lastAccepted+1 {
		w.remaining = limit
		w.initialized = true
	}
	if w.remaining == 0 {
		return false
	}
	w.lastAccepted = now
	w.remaining--
	return true
}
