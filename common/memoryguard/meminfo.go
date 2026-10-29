package memoryguard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func systemAvailablePercent() (float64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return availablePercent(file)
}

func availablePercent(reader io.Reader) (float64, error) {
	var total, available uint64
	var totalFound, availableFound bool
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || (fields[0] != "MemTotal:" && fields[0] != "MemAvailable:") {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse %s: %w", fields[0], err)
		}
		if len(fields) > 2 && fields[2] != "kB" {
			return 0, fmt.Errorf("unexpected unit for %s: %s", fields[0], fields[2])
		}
		value <<= 10
		if fields[0] == "MemTotal:" {
			total, totalFound = value, true
		} else {
			available, availableFound = value, true
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if !totalFound || total == 0 || !availableFound || available > total {
		return 0, fmt.Errorf("invalid or missing MemTotal/MemAvailable")
	}
	return float64(available) * 100 / float64(total), nil
}
