package trojan

import (
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-mux"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

var ErrForceMux = E.New("trojan IPv4 connection requires the multiplex destination")

// CheckForceMux preserves the original IPv4-only gate and exact multiplex hostname exception.
// Callers enable this check through their own ForceMux configuration.
func CheckForceMux(source, destination M.Socksaddr) error {
	if destination.Fqdn != mux.Destination.Fqdn && source.Unwrap().Addr.Is4() {
		return ErrForceMux
	}
	return nil
}

// serverPaddingConn splits the first nineteen downstream writes without adding bytes or delays.
// @author lyt
// @date 2026-10-29
type serverPaddingConn struct {
	net.Conn
	writes atomic.Uint32
}

func (c *serverPaddingConn) Write(data []byte) (int, error) {
	count := c.writes.Add(1)
	if count >= 20 || len(data) < 10 {
		return c.Conn.Write(data)
	}
	segments := [2]int{9, 0}
	segmentCount := 1
	if count == 1 {
		if len(data) >= 50 {
			segments, segmentCount = [2]int{40, 9}, 2
		}
	} else if len(data) >= 27 {
		segments, segmentCount = [2]int{9, 17}, 2
	}
	written := 0
	for _, size := range segments[:segmentCount] {
		n, err := c.Conn.Write(data[written : written+size])
		written += n
		if err != nil {
			return written, err
		}
	}
	// The sample advances by actual byte counts even after a nil-error short write.
	n, err := c.Conn.Write(data[written:])
	return written + n, err
}

func (c *serverPaddingConn) Upstream() any           { return c.Conn }
func (c *serverPaddingConn) ReaderReplaceable() bool { return true }
