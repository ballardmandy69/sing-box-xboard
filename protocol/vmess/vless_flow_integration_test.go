package vmess_test

import "testing"

func TestVLESSClientSelectedFlowNone(t *testing.T) {
	runVLESSFlowMatrix(t, []string{""})
}
