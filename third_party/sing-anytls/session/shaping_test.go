package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

// shapingConn records application writes, not TLS records or TCP segments.
// @author lyt
// @date 2026-10-28
type shapingConn struct {
	mu      sync.Mutex
	writes  [][]byte
	short   bool
	closed  bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *shapingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *shapingConn) Write(data []byte) (int, error) {
	if c.entered != nil {
		c.once.Do(func() { close(c.entered); <-c.release })
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	size := len(data)
	if c.short && size > 0 {
		size--
	}
	c.writes = append(c.writes, append([]byte(nil), data[:size]...))
	return size, nil
}
func (c *shapingConn) Close() error                   { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (*shapingConn) LocalAddr() net.Addr              { return nil }
func (*shapingConn) RemoteAddr() net.Addr             { return nil }
func (*shapingConn) SetDeadline(time.Time) error      { return nil }
func (*shapingConn) SetReadDeadline(time.Time) error  { return nil }
func (*shapingConn) SetWriteDeadline(time.Time) error { return nil }

func shapingSession(t *testing.T, scheme string, conn net.Conn, enhanced bool) *Session {
	t.Helper()
	value := new(atomic.TypedValue[*padding.PaddingFactory])
	if !padding.UpdatePaddingScheme([]byte(scheme), value) {
		t.Fatal("invalid padding fixture")
	}
	s := NewClientSession(conn, value, logger.NOP(), enhanced)
	if enhanced {
		s.enableEnhancedPadding(enhancedShapingVersion)
	}
	return s
}

func readShapingFrames(t *testing.T, wire []byte) (payload []byte, commands []byte) {
	t.Helper()
	for len(wire) > 0 {
		if len(wire) < headerOverHeadSize {
			t.Fatal("truncated header")
		}
		command := wire[0]
		size := int(binary.BigEndian.Uint16(wire[5:7]))
		if len(wire) < headerOverHeadSize+size {
			t.Fatal("truncated payload")
		}
		commands = append(commands, command)
		if command == cmdPSH {
			payload = append(payload, wire[7:7+size]...)
		} else if command != cmdWaste && command != cmdHeartRequest {
			t.Fatalf("unexpected frame %d", command)
		}
		wire = wire[7+size:]
	}
	return
}

func TestShapingPreservesExplicitEarlyPadding(t *testing.T) {
	conn := new(shapingConn)
	s := shapingSession(t, "stop=3\n1=500-500\n2=600-600", conn, true)
	payload := bytes.Repeat([]byte{9}, 64)
	for _, want := range []int{500, 600} {
		before := len(conn.writes)
		if n, err := s.writeDataFrame(1, payload); n != len(payload) || err != nil {
			t.Fatalf("write n=%d err=%v", n, err)
		}
		if len(conn.writes) != before+1 || len(conn.writes[before]) != want {
			t.Fatalf("explicit early padding changed: want=%d", want)
		}
		if s.shaper.initialized || s.enhancedDataBytes != 0 || s.enhancedPaddingBytes != 0 {
			t.Fatal("early padding was bypassed or counted against enhancement")
		}
	}
	if _, err := s.writeDataFrame(1, bytes.Repeat([]byte{8}, 32768)); err != nil {
		t.Fatal(err)
	}
	if !s.shaper.initialized || s.enhancedDataBytes == 0 {
		t.Fatal("post-prefix shaping did not activate")
	}
}

func TestShapingWritesPreserveFramesAndBudgets(t *testing.T) {
	for _, size := range []int{0, 1, 159, 160, 1024, 16384, 65535, 65536, 131073} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			conn := new(shapingConn)
			s := shapingSession(t, "stop=0", conn, true)
			payload := bytes.Repeat([]byte{73}, size)
			if n, err := s.writeDataFrame(8, payload); n != size || err != nil {
				t.Fatalf("write n=%d err=%v", n, err)
			}
			wire := bytes.Join(conn.writes, nil)
			actual, commands := readShapingFrames(t, wire)
			if !bytes.Equal(actual, payload) {
				t.Fatal("application payload changed")
			}
			var dataFrames int
			for _, command := range commands {
				if command == cmdPSH {
					dataFrames++
				}
			}
			if dataFrames != max(1, (size+65534)/65535) {
				t.Fatal("shaping added nonstandard PSH fragmentation")
			}
			if len(wire) != size+dataFrames*7+int(s.enhancedPaddingBytes) {
				t.Fatal("enhancement overhead escaped the wire budget")
			}
			for _, write := range conn.writes {
				if s.shaper.initialized && len(write) > s.shaper.chunkUpper {
					t.Fatalf("unbounded shaped write: %d", len(write))
				}
			}
			if s.enhancedPaddingBytes > uint64(size)/20 || s.enhancedPaddingBytes > enhancedPaddingLimit {
				t.Fatal("wire budget exceeded")
			}
		})
	}
}

func TestShapingDoesNotRunWithoutNegotiation(t *testing.T) {
	conn := new(shapingConn)
	s := shapingSession(t, "stop=0", conn, false)
	payload := bytes.Repeat([]byte{1}, 32768)
	if n, err := s.writeDataFrame(2, payload); n != len(payload) || err != nil {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	if len(conn.writes) != 1 || len(conn.writes[0]) != len(payload)+7 || s.shaper.initialized {
		t.Fatal("standard path was shaped")
	}
}

func TestShapingShortWriteClosesSession(t *testing.T) {
	conn := &shapingConn{short: true}
	s := shapingSession(t, "stop=0", conn, true)
	_, err := s.writeDataFrame(1, bytes.Repeat([]byte{1}, 32768))
	if !errors.Is(err, io.ErrShortWrite) || !s.IsClosed() {
		t.Fatalf("short write err=%v closed=%v", err, s.IsClosed())
	}
}

func TestShapingConcurrentFrames(t *testing.T) {
	conn := new(shapingConn)
	s := shapingSession(t, "stop=0", conn, true)
	var workers sync.WaitGroup
	for index := 0; index < 12; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			for round := 0; round < 20; round++ {
				if _, err := s.writeDataFrame(uint32(index+1), bytes.Repeat([]byte{7}, 32768)); err != nil {
					t.Error(err)
					return
				}
			}
		}(index)
	}
	workers.Wait()
	actual, _ := readShapingFrames(t, bytes.Join(conn.writes, nil))
	if len(actual) != 12*20*32768 || s.enhancedPaddingBytes > enhancedPaddingLimit {
		t.Fatal("concurrent writes corrupted framing or budget")
	}
}

func TestShapingQueuedControlPrecedesNextDataFrame(t *testing.T) {
	conn := &shapingConn{entered: make(chan struct{}), release: make(chan struct{})}
	s := shapingSession(t, "stop=0", conn, true)
	dataDone := make(chan error, 1)
	controlDone := make(chan error, 1)
	go func() { _, err := s.writeDataFrame(1, bytes.Repeat([]byte{5}, 131070)); dataDone <- err }()
	<-conn.entered
	go func() { _, err := s.writeControlFrame(newFrame(cmdHeartRequest, 123)); controlDone <- err }()
	deadline := time.Now().Add(time.Second)
	for s.controlPending.Load() == 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if s.controlPending.Load() == 0 {
		close(conn.release)
		t.Fatal("control was not queued")
	}
	close(conn.release)
	if err := <-dataDone; err != nil {
		t.Fatal(err)
	}
	if err := <-controlDone; err != nil {
		t.Fatal(err)
	}
	_, commands := readShapingFrames(t, bytes.Join(conn.writes, nil))
	var before int
	for _, command := range commands {
		if command == cmdHeartRequest {
			break
		}
		if command == cmdPSH {
			before++
		}
	}
	if before != 1 {
		t.Fatalf("control waited for %d data frames", before)
	}
}
