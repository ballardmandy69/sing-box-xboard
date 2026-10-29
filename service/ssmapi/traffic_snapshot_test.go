package ssmapi

import "testing"

func TestTrafficSnapshotAcknowledgesOnlyCapturedBytes(t *testing.T) {
	manager := NewTrafficManager()
	up, down, _, _, _, _ := manager.userCounter("alice")
	up.Add(11)
	down.Add(21)
	snapshot := manager.SnapshotTraffic([]string{"alice"})[0]
	up.Add(7)
	down.Add(3)
	if up.Load() != 18 || down.Load() != 24 {
		t.Fatal("taking a snapshot changed live counters")
	}
	snapshot.Acknowledge()
	snapshot.Acknowledge()
	if up.Load() != 7 || down.Load() != 3 {
		t.Fatal("acknowledgment lost concurrent traffic or was applied twice")
	}
}

func TestTrafficSnapshotDoesNotDebitReplacementUser(t *testing.T) {
	manager := NewTrafficManager()
	oldUp, oldDown, _, _, _, _ := manager.userCounter("alice")
	oldUp.Add(13)
	oldDown.Add(17)
	snapshot := manager.SnapshotTraffic([]string{"alice"})[0]
	manager.UpdateUsers(nil)
	newUp, newDown, _, _, _, _ := manager.userCounter("alice")
	newUp.Add(23)
	newDown.Add(29)
	snapshot.Acknowledge()
	if newUp.Load() != 23 || newDown.Load() != 29 || oldUp.Load() != 0 || oldDown.Load() != 0 {
		t.Fatal("old report acknowledgment modified the replacement user's counters")
	}
}
