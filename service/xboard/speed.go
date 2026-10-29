package xboard

import (
	"regexp"
	"strconv"
)

// maximumSpeedPattern reproduces the original MaxSpeedLimit parser, distinct from panel Mbps.
// @author lyt
// @date 2026-10-29
var maximumSpeedPattern = regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`)

func parseMaximumSpeed(value string) (uint64, bool) {
	if value == "" {
		return 0, true
	}
	if number, err := strconv.Atoi(value); err == nil {
		value = strconv.Itoa(number) + " Bps"
	}
	parts := maximumSpeedPattern.FindStringSubmatch(value)
	if parts == nil {
		return 0, false
	}
	// The original ignores ParseUint's range error and multiplies in uint64 arithmetic.
	amount, _ := strconv.ParseUint(parts[1], 10, 64)
	switch parts[2] {
	case "K":
		amount *= 1 << 10
	case "M":
		amount *= 1 << 20
	case "G":
		amount *= 1 << 30
	case "T":
		amount *= 1 << 40
	}
	if parts[3] == "b" {
		amount >>= 3
	}
	return amount, true
}
