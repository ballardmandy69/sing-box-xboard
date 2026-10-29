package route

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-mux"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// legacyMuxHeaderConn observes the handshake deadline without waiting for a wall-clock timeout.
// @author lyt
// @date 2026-10-29
type legacyMuxHeaderConn struct {
	net.Conn
	reader    *bytes.Reader
	deadlines []time.Time
	reads     int
}

func (c *legacyMuxHeaderConn) Read(data []byte) (int, error) {
	c.reads++
	return c.reader.Read(data)
}

func (c *legacyMuxHeaderConn) SetReadDeadline(value time.Time) error {
	c.deadlines = append(c.deadlines, value)
	return nil
}

func (c *legacyMuxHeaderConn) Close() error { return nil }

func TestLegacyMuxHandshakeDeadline(t *testing.T) {
	for _, validHeader := range []bool{false, true} {
		request := []byte{255}
		if validHeader {
			request = []byte{mux.Version0, 255} // Valid request, deliberately unsupported session protocol.
		}
		conn := &legacyMuxHeaderConn{reader: bytes.NewReader(request)}
		router := &Router{ctx: context.Background(), logger: log.NewNOPFactory().Logger()}
		var closeErr error
		before := time.Now()
		err := router.routeConnection(context.Background(), conn,
			adapter.InboundContext{Destination: M.Socksaddr{Fqdn: mux.Destination.Fqdn, Port: 443}},
			func(err error) { closeErr = err })
		if len(conn.deadlines) == 0 || conn.deadlines[0].Before(before.Add(5*time.Second)) ||
			conn.deadlines[0].After(time.Now().Add(5*time.Second)) {
			t.Fatalf("missing five-second request deadline: %v", conn.deadlines)
		}
		if validHeader {
			if err != nil || closeErr == nil || len(conn.deadlines) != 2 || !conn.deadlines[1].IsZero() {
				t.Fatalf("request deadline leaked into the session: error=%v close=%v deadlines=%v",
					err, closeErr, conn.deadlines)
			}
		} else if err == nil || len(conn.deadlines) != 1 {
			t.Fatalf("invalid request changed failure behavior: error=%v deadlines=%v", err, conn.deadlines)
		}
	}
}

// legacyMuxDetourManager exposes one injectable inbound to check dispatch ordering.
// @author lyt
// @date 2026-10-29
type legacyMuxDetourManager struct {
	adapter.InboundManager
	target adapter.Inbound
}

func (m *legacyMuxDetourManager) Get(tag string) (adapter.Inbound, bool) {
	return m.target, tag == "next-inbound"
}

// legacyMuxDetour records metadata without consuming a multiplex request.
// @author lyt
// @date 2026-10-29
type legacyMuxDetour struct {
	adapter.Inbound
	called   bool
	metadata adapter.InboundContext
}

func (d *legacyMuxDetour) NewConnection(_ context.Context, _ net.Conn,
	metadata adapter.InboundContext, _ N.CloseHandlerFunc,
) {
	d.called, d.metadata = true, metadata
}

func TestLegacyMuxDoesNotPreemptInboundDetour(t *testing.T) {
	detour := new(legacyMuxDetour)
	router := &Router{inbound: &legacyMuxDetourManager{target: detour}}
	conn := &legacyMuxHeaderConn{reader: bytes.NewReader(nil)}
	err := router.routeConnection(context.Background(), conn, adapter.InboundContext{
		Inbound: "first", InboundDetour: "next-inbound", Destination: mux.Destination,
	}, nil)
	if err != nil || !detour.called || conn.reads != 0 || len(conn.deadlines) != 0 ||
		detour.metadata.Inbound != "next-inbound" || detour.metadata.LastInbound != "first" {
		t.Fatalf("multiplex consumed a detoured connection: error=%v called=%v reads=%d", err, detour.called, conn.reads)
	}
}
