package ssmapi

import "sync/atomic"

// UserTrafficSnapshot acknowledges only the original counters captured for a user.
// This preserves traffic arriving during a report and cannot debit a replacement user generation.
// @author lyt
// @date 2026-10-29
type UserTrafficSnapshot struct {
	UserName      string
	UplinkBytes   int64
	DownlinkBytes int64
	uplink        *atomic.Int64
	downlink      *atomic.Int64
	acknowledged  atomic.Bool
}

// Acknowledge removes the unscaled byte counts exactly once after a successful report.
func (s *UserTrafficSnapshot) Acknowledge() {
	if !s.acknowledged.CompareAndSwap(false, true) {
		return
	}
	if s.uplink != nil {
		s.uplink.Add(-s.UplinkBytes)
	}
	if s.downlink != nil {
		s.downlink.Add(-s.DownlinkBytes)
	}
}

// SnapshotTraffic reads without resetting counters; callers serialize report transactions.
func (s *TrafficManager) SnapshotTraffic(users []string) []*UserTrafficSnapshot {
	s.userAccess.Lock()
	defer s.userAccess.Unlock()
	snapshots := make([]*UserTrafficSnapshot, 0, len(users))
	for _, name := range users {
		snapshot := &UserTrafficSnapshot{
			UserName: name, uplink: s.userUplink[name], downlink: s.userDownlink[name],
		}
		if snapshot.uplink != nil {
			snapshot.UplinkBytes = snapshot.uplink.Load()
		}
		if snapshot.downlink != nil {
			snapshot.DownlinkBytes = snapshot.downlink.Load()
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}
