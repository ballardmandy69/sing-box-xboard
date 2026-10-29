package memoryguard

import "time"

// clock keeps pressure episodes and reclamation tests independent of wall-clock sleeps.
type clock interface {
	Now() time.Time
	NewTimer(time.Duration) timer
}

type timer interface {
	C() <-chan time.Time
	Stop() bool
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }
func (systemClock) NewTimer(duration time.Duration) timer {
	return systemTimer{time.NewTimer(duration)}
}

type systemTimer struct{ *time.Timer }

func (t systemTimer) C() <-chan time.Time { return t.Timer.C }
