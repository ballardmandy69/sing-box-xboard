package xboard

import (
	"sync"
	"testing"
	"time"
)

func TestDebugHotUsersSnapshot(t *testing.T) {
	expires := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	hot := newHotUsers(&hotUserFixture{}, time.Minute)
	hot.expires["7@primary@uniproxy"] = expires
	s := &Service{nodes: []*node{{debugTag: "legacy", hotUsers: hot}, {debugTag: "empty"}}}
	users, found := s.DebugHotUsers("legacy")
	if !found || !users["7@primary@uniproxy"].Equal(expires) {
		t.Fatalf("snapshot: %v, %v", users, found)
	}
	delete(users, "7@primary@uniproxy")
	users, found = s.DebugHotUsers("legacy")
	if !found || len(users) != 1 {
		t.Fatal("caller changed the live map")
	}
	if users, found = s.DebugHotUsers("empty"); !found || users == nil || len(users) != 0 {
		t.Fatal("known empty node must return a non-nil empty map")
	}
	if users, found = s.DebugHotUsers("primary"); found || users != nil {
		t.Fatal("lookup must use the configured legacy tag, not a username panel tag")
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for range 100 {
			hot.add("new")
		}
	}()
	go func() {
		defer workers.Done()
		for range 100 {
			users, found := s.DebugHotUsers("legacy")
			if !found || len(users) < 1 {
				t.Error("concurrent snapshot lost entries")
			}
		}
	}()
	workers.Wait()
}
