package usercontrol

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func TestRequestWindowIntegerSecondsAndClockRollback(t *testing.T) {
	var window requestWindow
	for _, step := range []struct {
		second   int64
		accepted bool
	}{
		{100, true}, {100, true}, {100, false}, {99, false},
		{101, true}, {100, true}, {100, false}, {101, true},
	} {
		if actual := window.accept(step.second, 2); actual != step.accepted {
			t.Fatalf("second %d: accepted=%v, want %v", step.second, actual, step.accepted)
		}
	}
	if !window.accept(101, 0) || !window.accept(101, 0) {
		t.Fatal("zero request quota must be unlimited")
	}
}

func TestRequestQuotaSharedAndConsumedBeforeConnectionCheck(t *testing.T) {
	m := NewManagerWithRequestLimit(nil, 2)
	second := int64(100)
	m.now = func() time.Time { return time.Unix(second, 0) }
	update(t, m, map[string]Limits{"a": {ConnectionLimit: 1}, "b": {}})
	first := track(t, m, context.Background(), "a", "192.0.2.1")
	if _, err := adapter.TrackConnection(context.Background(), m, &fixtureConn{},
		testMetadata("a", "192.0.2.2")); !errors.Is(err, ErrConnectionLimit) {
		t.Fatal("request within quota should reach the connection check")
	}
	first.Close()
	if _, err := adapter.TrackConnection(context.Background(), m, &fixtureConn{},
		testMetadata("a", "192.0.2.3")); !errors.Is(err, ErrRequestLimit) {
		t.Fatal("connection rejection refunded request quota or source IP created a separate quota")
	}
	track(t, m, context.Background(), "b", "192.0.2.1").Close()
	second++
	track(t, m, context.Background(), "a", "192.0.2.1").Close()
	otherNode := NewManagerWithRequestLimit(nil, 2)
	otherNode.now = m.now
	update(t, otherNode, map[string]Limits{"a": {}})
	track(t, otherNode, context.Background(), "a", "192.0.2.1").Close()
}

func TestRequestQuotaConcurrentAdmission(t *testing.T) {
	m := NewManagerWithRequestLimit(nil, 4)
	m.now = func() time.Time { return time.Unix(100, 0) }
	update(t, m, map[string]Limits{"a": {}})
	var accepted atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Go(func() {
			conn, err := adapter.TrackConnection(context.Background(), m, &fixtureConn{},
				testMetadata("a", "192.0.2.1"))
			if err == nil {
				accepted.Add(1)
				conn.Close()
			} else if !errors.Is(err, ErrRequestLimit) {
				t.Errorf("unexpected rejection: %v", err)
			}
		})
	}
	wait.Wait()
	if accepted.Load() != 4 || m.ActiveConnections("a") != 0 {
		t.Fatal("concurrent streams exceeded or leaked the per-user request quota")
	}
}
