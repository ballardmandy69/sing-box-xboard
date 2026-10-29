package usercontrol

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateGate shares a one-second token bucket and wakes reservations when limits change.
// @author lyt
// @date 2026-10-29
type rateGate struct {
	access  sync.RWMutex
	value   uint64
	limiter *rate.Limiter
	changed chan struct{}
}

func newRateGate() *rateGate {
	return &rateGate{changed: make(chan struct{})}
}

func (g *rateGate) set(value uint64) {
	g.access.Lock()
	defer g.access.Unlock()
	if value == g.value {
		return
	}
	if value != 0 {
		if g.limiter == nil {
			g.limiter = rate.NewLimiter(rate.Limit(value), int(value))
		} else {
			g.limiter.SetLimit(rate.Limit(value))
			g.limiter.SetBurst(int(value))
		}
	}
	g.value = value
	close(g.changed)
	g.changed = make(chan struct{})
}

func (g *rateGate) chunk(length int) int {
	g.access.RLock()
	defer g.access.RUnlock()
	if g.value != 0 && uint64(length) > g.value {
		return int(g.value)
	}
	return length
}

func (g *rateGate) wait(ctx context.Context, length int) error {
	for length > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		g.access.RLock()
		if g.value == 0 {
			g.access.RUnlock()
			return nil
		}
		chunk := min(length, int(g.value))
		now := time.Now()
		reservation := g.limiter.ReserveN(now, chunk)
		changed := g.changed
		g.access.RUnlock()
		delay := reservation.DelayFrom(now)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				reservation.Cancel()
				return ctx.Err()
			case <-changed:
				timer.Stop()
				reservation.Cancel()
				continue
			case <-timer.C:
			}
		}
		length -= chunk
	}
	return nil
}
