package session

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"slices"
)

const (
	enhancedPaddingSetting = "x-padding"
	enhancedPaddingVersion = "1"
	enhancedShapingVersion = "2"
	enhancedPaddingLimit   = uint64(64 * 1024)
	enhancedPaddingMax     = uint64(256)
	enhancedPaddingRatio   = uint64(20)
)

// shapingState stores a bounded, session-local write policy after legacy padding.
// Application writes, TLS records, and network packets have different boundaries.
// @author lyt
// @date 2026-10-28
type shapingState struct {
	initialized bool
	chunkUpper  int
	paddingMax  uint64
}

func (s *Session) acceptPaddingVersion(version string) string {
	if !s.disablePadding && s.enhancedPadding && (version == enhancedPaddingVersion || version == enhancedShapingVersion) {
		return version
	}
	return ""
}

func (s *Session) enableEnhancedPadding(versions ...string) {
	if s.disablePadding {
		return
	}
	version := enhancedPaddingVersion
	if len(versions) > 0 {
		version = versions[0]
	}
	var mode uint32
	switch version {
	case enhancedPaddingVersion:
		mode = 1
	case enhancedShapingVersion:
		mode = 2
	default:
		return
	}
	// A session cannot switch policy after its first successful negotiation.
	if s.enhancedMode.CompareAndSwap(0, mode) {
		s.enhancedReady.Store(true)
		if s.logger != nil {
			s.logger.Debug("AnyTLS padding negotiated: ", version)
		}
	}
}

func (s *shapingState) initialize() bool {
	if s.initialized {
		return true
	}
	var selection [2]byte
	if _, err := rand.Read(selection[:]); err != nil {
		return false
	}
	s.chunkUpper = [...]int{8 * 1024, 12 * 1024, 16 * 1024}[int(selection[0])%3]
	s.paddingMax = uint64(64 * (1 + int(selection[1])%4))
	s.initialized = true
	return true
}

// writeShaped holds connLock through each complete frame and never sleeps or
// emits idle traffic. Control frames bypass additional padding and splitting.
func (s *Session) writeShaped(data []byte, payloadSize ...int) (int, error) {
	if s.disablePadding || !s.enhancedReady.Load() || len(payloadSize) == 0 || payloadSize[0] <= 0 {
		return s.writeWire(data)
	}
	inputSize := len(data)
	if s.enhancedMode.Load() != 2 {
		data = s.appendEnhancedPadding(data, payloadSize[0])
		n, err := s.writeWire(data)
		return min(n, inputSize), err
	}
	if !s.shaper.initialize() {
		return s.writeWire(data)
	}
	data = s.appendEnhancedPadding(data, payloadSize[0], s.shaper.paddingMax)
	var written int
	for len(data) > 0 {
		chunk := len(data)
		if chunk > s.shaper.chunkUpper {
			lower := s.shaper.chunkUpper * 3 / 4
			size, err := rand.Int(rand.Reader, big.NewInt(int64(s.shaper.chunkUpper-lower+1)))
			if err != nil {
				// Failure to randomize must not discard or alter application bytes.
				chunk = s.shaper.chunkUpper
			} else {
				chunk = lower + int(size.Int64())
			}
		}
		n, err := s.writeWire(data[:chunk])
		written += n
		if err != nil {
			return min(written, inputSize), err
		}
		data = data[chunk:]
	}
	return inputSize, nil
}

func (s *Session) writeWire(data []byte) (int, error) {
	n, err := s.conn.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

// appendEnhancedPadding counts the full waste frame against a cumulative budget:
// at most 5% of post-prefix application bytes and 64 KiB in each direction/session.
// The original explicitly configured padding scheme is accounted separately.
// This method is called only while connLock is held (or in single-threaded tests).
func (s *Session) appendEnhancedPadding(data []byte, payloadSize int, limits ...uint64) []byte {
	if payloadSize <= 0 {
		return data
	}
	dataLimit := enhancedPaddingLimit * enhancedPaddingRatio
	if uint64(payloadSize) >= dataLimit-s.enhancedDataBytes {
		s.enhancedDataBytes = dataLimit
	} else {
		s.enhancedDataBytes += uint64(payloadSize)
	}
	budget := s.enhancedDataBytes/enhancedPaddingRatio - s.enhancedPaddingBytes
	maximum := enhancedPaddingMax
	if len(limits) > 0 {
		maximum = min(maximum, limits[0])
	}
	budget = min(budget, maximum)
	if budget <= headerOverHeadSize {
		return data
	}
	size, err := rand.Int(rand.Reader, big.NewInt(int64(budget-headerOverHeadSize)))
	if err != nil {
		return data
	}
	frameSize := int(size.Int64()) + headerOverHeadSize + 1
	waste := make([]byte, frameSize)
	waste[0] = cmdWaste
	binary.BigEndian.PutUint16(waste[5:7], uint16(frameSize-headerOverHeadSize))
	if _, err = rand.Read(waste[headerOverHeadSize:]); err != nil {
		return data
	}
	s.enhancedPaddingBytes += uint64(frameSize)
	return slices.Concat(data, waste)
}
