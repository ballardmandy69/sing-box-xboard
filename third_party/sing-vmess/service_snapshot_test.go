package vmess

import (
	"sync"
	"testing"
)

func TestUserSnapshotsAndLegacyRefreshStayConsistent(t *testing.T) {
	service := NewService[string](nil)
	update := func(name, uuid string) {
		t.Helper()
		if err := service.UpdateUsers([]string{name}, []string{uuid}, []int{1}); err != nil {
			t.Fatal(err)
		}
	}
	update("alpha", "61552c7d-d297-4593-86dd-62c57d01afbb")
	previous := service.users.Load()
	marker := []byte("replay-marker-across-refresh")
	if !service.replayFilter.Check(marker) {
		t.Fatal("fresh replay marker rejected")
	}
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for index := 0; index < 30; index++ {
			service.generateLegacyKeys()
		}
	}()
	for index := 0; index < 30; index++ {
		update("bravo", "ed09f8db-0d7b-4850-aa9c-a75b33eab148")
		current := service.users.Load()
		if len(current.userKey) != 1 || len(current.userIdCipher) != 1 || len(current.alterIds) != 1 {
			t.Fatal("published an incomplete authentication snapshot")
		}
		for _, entry := range current.alterIdMap {
			if entry.User != "bravo" {
				t.Fatal("legacy refresh published keys from a replaced user generation")
			}
		}
	}
	wait.Wait()
	if _, exists := previous.userKey["alpha"]; !exists || len(previous.userKey) != 1 {
		t.Fatal("refresh mutated a snapshot retained by an existing handshake")
	}
	if service.replayFilter.Check(marker) {
		t.Fatal("user updates reset the instance's replay protection")
	}
	if _, exists := service.users.Load().userKey["bravo"]; !exists {
		t.Fatal("legacy refresh overwrote the final user update")
	}
}
