package trojan

import (
	"bytes"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// paddingRecordingConn captures individual underlying writes and can inject short/error responses.
// @author lyt
// @date 2026-10-29
type paddingRecordingConn struct {
	net.Conn
	access sync.Mutex
	sizes  []int
	data   bytes.Buffer
	write  func(int, []byte) (int, error)
}

func (c *paddingRecordingConn) Write(data []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	c.sizes = append(c.sizes, len(data))
	n, err := len(data), error(nil)
	if c.write != nil {
		n, err = c.write(len(c.sizes), data)
	}
	c.data.Write(data[:n])
	return n, err
}

func TestServerPaddingWriteBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		prior  uint32
		length int
		sizes  []int
	}{
		{"empty first", 0, 0, []int{0}},
		{"small first", 0, 9, []int{9}},
		{"first ten", 0, 10, []int{9, 1}},
		{"first twenty seven", 0, 27, []int{9, 18}},
		{"first forty nine", 0, 49, []int{9, 40}},
		{"first fifty", 0, 50, []int{40, 9, 1}},
		{"large first", 0, 65536, []int{40, 9, 65487}},
		{"small second", 1, 9, []int{9}},
		{"second ten", 1, 10, []int{9, 1}},
		{"second twenty six", 1, 26, []int{9, 17}},
		{"second twenty seven", 1, 27, []int{9, 17, 1}},
		{"nineteenth", 18, 50, []int{9, 17, 24}},
		{"twentieth", 19, 50, []int{50}},
		{"after twentieth", 20, 50, []int{50}},
	} {
		t.Run(test.name, func(t *testing.T) {
			underlying := new(paddingRecordingConn)
			conn := &serverPaddingConn{Conn: underlying}
			conn.writes.Store(test.prior)
			payload := bytes.Repeat([]byte("x"), test.length)
			n, err := conn.Write(payload)
			if err != nil || n != len(payload) || !bytes.Equal(underlying.data.Bytes(), payload) {
				t.Fatalf("payload changed: n=%d error=%v", n, err)
			}
			if !reflect.DeepEqual(underlying.sizes, test.sizes) {
				t.Fatalf("write boundaries=%v want=%v", underlying.sizes, test.sizes)
			}
			if conn.writes.Load() != test.prior+1 || conn.Upstream() != underlying || !conn.ReaderReplaceable() {
				t.Fatal("counter or reader/underlying contract changed")
			}
			if _, replaceable := any(conn).(interface{ WriterReplaceable() bool }); replaceable {
				t.Fatal("sample padding writer must not expose a replaceable write path")
			}
		})
	}
}

func TestServerPaddingShortWritesAndErrors(t *testing.T) {
	writeError := errors.New("injected write failure")
	for _, test := range []struct {
		name      string
		call      int
		short     int
		err       error
		wantN     int
		wantSizes []int
	}{
		{"first prefix error", 1, 3, writeError, 3, []int{40}},
		{"second prefix error", 2, 4, writeError, 44, []int{40, 9}},
		{"remainder error", 3, 3, writeError, 52, []int{40, 9, 15}},
		{"first prefix short", 1, 20, nil, 64, []int{40, 9, 35}},
		{"second prefix short", 2, 4, nil, 64, []int{40, 9, 20}},
		{"zero prefix", 1, 0, nil, 64, []int{40, 9, 55}},
		{"remainder short", 3, 2, nil, 51, []int{40, 9, 15}},
	} {
		t.Run(test.name, func(t *testing.T) {
			underlying := &paddingRecordingConn{write: func(call int, data []byte) (int, error) {
				if call == test.call {
					return test.short, test.err
				}
				return len(data), nil
			}}
			conn := &serverPaddingConn{Conn: underlying}
			payload := make([]byte, 64)
			for index := range payload {
				payload[index] = byte(index)
			}
			n, err := conn.Write(payload)
			if n != test.wantN || err != test.err || !reflect.DeepEqual(underlying.sizes, test.wantSizes) ||
				!bytes.Equal(underlying.data.Bytes(), payload[:n]) {
				t.Fatalf("n=%d error=%v sizes=%v bytes=%v", n, err, underlying.sizes, underlying.data.Bytes())
			}
			if conn.writes.Load() != 1 {
				t.Fatal("failed write did not consume an ordinal")
			}
		})
	}
}

func TestServerPaddingCountsEveryWriteAndConcurrentCalls(t *testing.T) {
	underlying := new(paddingRecordingConn)
	conn := &serverPaddingConn{Conn: underlying}
	if _, err := conn.Write(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(make([]byte, 50)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(underlying.sizes, []int{0, 9, 17, 24}) {
		t.Fatalf("empty write must consume the first ordinal: %v", underlying.sizes)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 25 {
				if n, err := conn.Write([]byte("small")); err != nil || n != 5 {
					t.Errorf("concurrent write: n=%d error=%v", n, err)
				}
			}
		})
	}
	workers.Wait()
	if conn.writes.Load() != 202 {
		t.Fatalf("concurrent counter=%d", conn.writes.Load())
	}
}

func TestServerPaddingReadPassesThrough(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &serverPaddingConn{Conn: server}
	go func() { _, _ = client.Write([]byte("unchanged")) }()
	data := make([]byte, 9)
	if _, err := io.ReadFull(conn, data); err != nil || string(data) != "unchanged" {
		t.Fatalf("read=%q error=%v", data, err)
	}
	if conn.writes.Load() != 0 {
		t.Fatal("upstream reads must not consume downstream write ordinals")
	}
}

func TestForceMuxOriginalSourceAndDestinationBoundary(t *testing.T) {
	for _, test := range []struct {
		name        string
		source      string
		destination string
		reject      bool
	}{
		{"IPv4 direct", "192.0.2.1:1", "example.test:443", true},
		{"mapped IPv4 direct", "[::ffff:192.0.2.1]:1", "example.test:443", true},
		{"IPv6 direct", "[2001:db8::1]:1", "example.test:443", false},
		{"invalid source", "", "example.test:443", false},
		{"mux port zero", "192.0.2.1:1", "sp.mux.sing-box.arpa:0", false},
		{"mux other port", "192.0.2.1:1", "sp.mux.sing-box.arpa:443", false},
		{"case sensitive", "192.0.2.1:1", "SP.MUX.SING-BOX.ARPA:0", true},
		{"trailing dot", "192.0.2.1:1", "sp.mux.sing-box.arpa.:0", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := CheckForceMux(M.ParseSocksaddr(test.source), M.ParseSocksaddr(test.destination))
			if errors.Is(err, ErrForceMux) != test.reject {
				t.Fatalf("reject=%v error=%v", test.reject, err)
			}
		})
	}
}
