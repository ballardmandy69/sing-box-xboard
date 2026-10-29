package memoryguard

import "time"

const reclaimInterval = 5 * time.Second

// reclaimer coalesces pressure notifications and spaces releases from the prior completion time.
// @author lyt
// @date 2026-10-29
type reclaimer struct {
	clock   clock
	release func()
	notice  chan struct{}
}

func newReclaimer(clock clock, release func()) *reclaimer {
	return &reclaimer{clock: clock, release: release, notice: make(chan struct{}, 1)}
}

func (r *reclaimer) notify() {
	select {
	case r.notice <- struct{}{}:
	default:
	}
}

func (r *reclaimer) run(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	var last time.Time
	var pending bool
	var waiting timer
	var timerChannel <-chan time.Time
	defer func() {
		if waiting != nil {
			waiting.Stop()
		}
	}()
	for {
		select {
		case <-stop:
			return
		case <-r.notice:
			pending = true
		case <-timerChannel:
			waiting, timerChannel = nil, nil
		}
		if !pending {
			continue
		}
		if !last.IsZero() {
			remaining := reclaimInterval - r.clock.Now().Sub(last)
			if remaining > 0 {
				if timerChannel == nil {
					waiting = r.clock.NewTimer(remaining)
					timerChannel = waiting.C()
				}
				continue
			}
		}
		pending = false
		for {
			select {
			case <-r.notice:
				continue
			default:
			}
			break
		}
		r.release()
		last = r.clock.Now()
	}
}
