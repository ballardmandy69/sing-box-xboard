// Package memoryguard applies the original system-memory policy to registered TCP source IPs.
package memoryguard

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing/common/logger"
)

// Guard owns one pressure episode and a source-IP TTL table shared by a Box's listeners.
// @author lyt
// @date 2026-10-29
type Guard struct {
	options  Options
	registry *usercontrol.ConnectionCleaner
	logger   logger.Logger
	clock    clock
	sample   func() (float64, error)
	jitter   func(time.Duration) time.Duration
	reclaim  *reclaimer

	access      sync.Mutex
	checkAccess sync.Mutex
	blocked     map[string]time.Time
	selected    map[string]struct{}
	base        int
	started     bool
	closed      bool
	stop        chan struct{}
	done        chan struct{}
	reclaimDone chan struct{}
}

// New returns nil when disabled and leaves other disabled options unvalidated.
func New(options Options, registry *usercontrol.ConnectionCleaner, logger logger.Logger) (*Guard, error) {
	options, err := normalize(options)
	if err != nil || !options.Enabled {
		return nil, err
	}
	if registry == nil {
		return nil, fmt.Errorf("memory guard requires the shared connection registry")
	}
	clock := systemClock{}
	return &Guard{
		options: options, registry: registry, logger: logger, clock: clock,
		sample: systemAvailablePercent, jitter: jitterInterval,
		reclaim: newReclaimer(clock, debug.FreeOSMemory),
		blocked: make(map[string]time.Time), selected: make(map[string]struct{}),
		stop: make(chan struct{}), done: make(chan struct{}), reclaimDone: make(chan struct{}),
	}, nil
}

func jitterInterval(interval time.Duration) time.Duration {
	delta := interval / 10
	if delta < 1 {
		return interval
	}
	return interval - delta + time.Duration(rand.Int64N(int64(2*delta+1)))
}

func (g *Guard) Start() error {
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed {
		return net.ErrClosed
	}
	if g.started {
		return nil
	}
	g.started = true
	go g.reclaim.run(g.stop, g.reclaimDone)
	go g.run()
	return nil
}

func (g *Guard) run() {
	defer close(g.done)
	for {
		waiting := g.clock.NewTimer(g.jitter(g.options.CheckInterval))
		select {
		case <-g.stop:
			waiting.Stop()
			return
		case <-waiting.C():
		}
		if err := g.check(); err != nil && g.logger != nil {
			g.logger.Error("memory guard: sample failed: ", err)
		}
	}
}

func (g *Guard) Close() error {
	g.access.Lock()
	if !g.closed {
		g.closed = true
		close(g.stop)
	}
	started := g.started
	g.access.Unlock()
	if started {
		<-g.done
		<-g.reclaimDone
	}
	return nil
}

// Accept atomically checks the source ban and registers the physical connection.
// A concurrent pressure check either sees and closes it, or rejects its registration.
func (g *Guard) Accept(conn net.Conn, source netip.Addr) (net.Conn, bool) {
	source = source.Unmap()
	g.access.Lock()
	blocked := g.blockedLocked(source.String(), g.clock.Now())
	if blocked {
		g.access.Unlock()
		conn.Close()
		return nil, false
	}
	tracked := g.registry.TrackAcceptedConnection(conn, source)
	g.access.Unlock()
	return tracked, true
}

func (g *Guard) Blocked(source netip.Addr) bool {
	g.access.Lock()
	defer g.access.Unlock()
	return g.blockedLocked(source.Unmap().String(), g.clock.Now())
}

func (g *Guard) blockedLocked(source string, now time.Time) bool {
	expires, exists := g.blocked[source]
	if !exists {
		return false
	}
	if now.Before(expires) {
		return true
	}
	delete(g.blocked, source)
	return false
}

func (g *Guard) check() error {
	g.checkAccess.Lock()
	defer g.checkAccess.Unlock()
	available, err := g.sample()
	if err != nil {
		return err
	}
	var applicable *Step
	for index := range g.options.Steps {
		step := &g.options.Steps[index]
		if available <= step.AvailableMemoryPercent {
			applicable = step
		}
	}
	g.access.Lock()
	if g.closed {
		g.access.Unlock()
		return nil
	}
	if applicable == nil {
		g.base = 0
		clear(g.selected)
		g.access.Unlock()
		return nil
	}
	candidates := g.registry.SourceSnapshot()
	if g.base == 0 {
		g.base = len(candidates)
	}
	count := int(math.Ceil(float64(g.base) * applicable.BlockPercentPerCheck / 100))
	limit := int(math.Ceil(float64(g.base) * applicable.MaxBlockedPercent / 100))
	count = min(count, limit-len(g.selected))
	now := g.clock.Now()
	var selected []string
	for _, candidate := range candidates {
		if count <= 0 {
			break
		}
		if _, exists := g.selected[candidate.SourceIP]; exists || g.blockedLocked(candidate.SourceIP, now) {
			continue
		}
		g.blocked[candidate.SourceIP] = now.Add(g.options.BlockDuration)
		g.selected[candidate.SourceIP] = struct{}{}
		selected = append(selected, candidate.SourceIP)
		count--
	}
	// The original post-selection count also purges expired global TTL entries.
	if len(selected) > 0 {
		for source, expires := range g.blocked {
			if !now.Before(expires) {
				delete(g.blocked, source)
			}
		}
	}
	g.access.Unlock()
	if len(selected) > 0 {
		closed := g.registry.CloseSources(selected)
		if g.logger != nil {
			g.logger.Warn("memory guard: available ", available, "%, blocked ", len(selected),
				" source IPs, closed ", closed, " TCP connections for ", g.options.BlockDuration)
		}
		g.reclaim.notify()
	}
	return nil
}
