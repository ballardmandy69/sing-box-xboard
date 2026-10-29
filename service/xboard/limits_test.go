package xboard

import (
	"math"
	"testing"
)

func TestUserLimitsPreserveOriginalUnitsAndOverrides(t *testing.T) {
	n := &node{ipLimit: 5, connectionLimit: 20}
	for _, test := range []struct {
		name       string
		user       panelUser
		speed      uint64
		ips, conns uint32
	}{
		{name: "inherit defaults", user: panelUser{}, ips: 5, conns: 20},
		{name: "decimal Mbps", user: panelUser{SpeedLimit: 8}, speed: 1_000_000, ips: 5, conns: 20},
		{name: "user overrides without minimum", user: panelUser{DeviceLimit: 10, ConnectionLimit: 40},
			ips: 10, conns: 40},
		{name: "signed wire values preserve bit conversion",
			user:  panelUser{SpeedLimit: -1, DeviceLimit: -1, ConnectionLimit: -1},
			speed: (math.MaxUint64 - 999999) >> 3, ips: math.MaxUint16, conns: math.MaxUint32},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits := n.userLimits(test.user)
			if limits.UploadBytesPerSecond != test.speed || limits.DownloadBytesPerSecond != test.speed ||
				limits.IPLimit != test.ips || limits.ConnectionLimit != test.conns {
				t.Fatalf("unexpected original-compatible limit conversion: %+v", limits)
			}
		})
	}
}

func TestMaximumSpeedOriginalGrammar(t *testing.T) {
	for _, test := range []struct {
		input string
		want  uint64
		valid bool
	}{
		{"", 0, true}, {"100", 100, true}, {"+100", 100, true},
		{"100 Bps", 100, true}, {"100Mbps", 13_107_200, true}, {"100 MBps", 104_857_600, true},
		{"8Kbps", 1024, true}, {"1 GBps", 1 << 30, true}, {"1 TBps", 1 << 40, true},
		{"0 Bps", 0, true}, {"18446744073709551616 Bps", math.MaxUint64, true},
		{"1.5 Mbps", 0, false}, {"1 mbps", 0, false}, {"1 MBPS", 0, false},
		{" 100", 0, false}, {"100 Bps ", 0, false}, {"-1", 0, false},
	} {
		t.Run(test.input, func(t *testing.T) {
			got, valid := parseMaximumSpeed(test.input)
			if got != test.want || valid != test.valid {
				t.Fatalf("parseMaximumSpeed(%q) = %d, %t", test.input, got, valid)
			}
		})
	}
}

func TestNodeMaximumBoundsPanelSpeed(t *testing.T) {
	n := &node{maxSpeed: 200_000}
	for _, speed := range []int64{0, 1, 8} {
		want := uint64(200_000)
		if speed == 1 {
			want = 125_000
		}
		got := n.userLimits(panelUser{SpeedLimit: speed})
		if got.UploadBytesPerSecond != want || got.DownloadBytesPerSecond != want {
			t.Fatalf("speed=%d: node cap mismatch: %+v", speed, got)
		}
	}
}
