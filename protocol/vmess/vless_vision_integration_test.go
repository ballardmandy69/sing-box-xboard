//go:build !race

package vmess_test

import "testing"

// Upstream Vision converts uintptr back to TLS field pointers and fails race's automatic checkptr.
// Keep real Vision handshakes in normal builds; policy/snapshot/none-flow tests still run with race.
// See third_party/sing-vmess/LOCAL_CHANGES.md for the unchanged upstream source and validation limits.
func TestVLESSClientSelectedFlowVision(t *testing.T) {
	runVLESSFlowMatrix(t, []string{"xtls-rprx-vision"})
}
