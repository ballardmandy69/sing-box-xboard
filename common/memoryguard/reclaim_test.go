package memoryguard

import (
	"testing"
	"time"
)

func TestReclaimerCoalescesAndMeasuresFromCompletion(t *testing.T) {
	clock := newManualClock()
	started := make(chan time.Time, 4)
	permit := make(chan struct{}, 4)
	r := newReclaimer(clock, func() {
		started <- clock.Now()
		<-permit
	})
	stop, done := make(chan struct{}), make(chan struct{})
	defer func() { close(stop); permit <- struct{}{}; receive(t, done) }()
	for range 10 {
		r.notify()
	}
	go r.run(stop, done)
	first := receive(t, started)
	if !first.Equal(clock.Now()) {
		t.Fatal("first signal was delayed")
	}
	// Signals during release survive the drain before that release and request another round.
	r.notify()
	clock.advance(2 * time.Second)
	permit <- struct{}{}
	if duration := receive(t, clock.created); duration != 5*time.Second {
		t.Fatalf("throttle measured from notification/start instead of completion: %s", duration)
	}
	for range 100 {
		r.notify()
	}
	clock.advance(5*time.Second - time.Nanosecond)
	select {
	case <-started:
		t.Fatal("release ran before the five-second boundary")
	default:
	}
	clock.advance(time.Nanosecond)
	second := receive(t, started)
	if !second.Equal(first.Add(7 * time.Second)) {
		t.Fatalf("new notifications postponed the timer: %s", second.Sub(first))
	}
	select {
	case duration := <-clock.created:
		t.Fatalf("duplicate signals created another cooling timer: %s", duration)
	default:
	}
}

func TestReclaimerStopsWithoutSignals(t *testing.T) {
	clock := newManualClock()
	r := newReclaimer(clock, func() { t.Error("release without a notification") })
	stop, done := make(chan struct{}), make(chan struct{})
	go r.run(stop, done)
	close(stop)
	receive(t, done)
	if len(clock.created) != 0 {
		t.Fatal("reclaimer created a periodic timer without a notification")
	}
}
