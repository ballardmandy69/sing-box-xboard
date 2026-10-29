package xboard

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/service/ssmapi"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestAccessLogKeepsAccountingIdentityAcrossRouteSniffRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(service.ContextWithDefaultRegistry(context.Background()))
	defer cancel()
	registry, err := nodepolicy.NewRegistry("", nil)
	require.NoError(t, err)
	service.MustRegister[adapter.ManagedNodePolicy](ctx, registry)
	var sourceUUID atomic.Value
	sourceUUID.Store("uuid-one")
	require.NoError(t, registry.Register("source", nodepolicy.Node{
		LookupUser: func(name string) (nodepolicy.User, bool) {
			return nodepolicy.User{ID: 11, Label: "source-name"}, name == "source-name"
		},
		LookupAuthUUID: func(name string) (string, bool) {
			return sourceUUID.Load().(string), name == "source-name"
		},
	}))
	traffic := ssmapi.NewTrafficManager()
	traffic.UpdateUsers([]string{"target-one", "target-two"})
	control := usercontrol.NewManagerWithRequestLimit(traffic, 1)
	require.NoError(t, control.UpdateUsers(map[string]usercontrol.Limits{
		"target-one": {ConnectionLimit: 1}, "target-two": {ConnectionLimit: 1},
	}))
	require.NoError(t, registry.Register("target", nodepolicy.Node{
		Static:     true,
		LookupUser: func(string) (nodepolicy.User, bool) { return nodepolicy.User{}, false },
		LookupStaticUser: func(uuid string) (nodepolicy.User, bool) {
			switch uuid {
			case "uuid-one":
				return nodepolicy.User{ID: 21, Label: "target-one"}, true
			case "uuid-two":
				return nodepolicy.User{ID: 22, Label: "target-two"}, true
			default:
				return nodepolicy.User{}, false
			}
		},
		CheckRequest: control.CheckRequest, TrackConnection: control.TrackRoutedConnection,
	}))
	registry.SetPanelTag("source", "target")
	const payload = "GET / HTTP/1.1\r\nHost: sniff.example\r\n\r\n"
	outbound := &identityRefreshOutbound{payload: []byte(payload)}
	service.MustRegister[adapter.OutboundManager](ctx, &identityRefreshOutboundManager{outbound: outbound})
	service.MustRegister[adapter.DNSRouter](ctx, identityRefreshDNSRouter{})
	router := route.NewRouter(ctx, log.NewNOPFactory(), option.RouteOptions{}, option.DNSOptions{})
	var rules []option.Rule
	require.NoError(t, json.Unmarshal([]byte(`[
		{"action":"sniff","sniffer":"http","timeout":"5s"},
		{"inbound":"source","auth_user":"source-name","outbound":"exit"},
		{"action":"reject"}
	]`), &rules))
	require.NoError(t, router.Initialize(rules, nil))
	queue := newAccessLogQueue(0, nil)
	router.AppendTracker(&accessLogTracker{queues: map[string]*accessLogQueue{"target": queue}, policy: registry})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	reading := make(chan struct{})
	done := make(chan struct{})
	metadata := adapter.InboundContext{Inbound: "source", User: "source-name",
		Source: M.ParseSocksaddr("192.0.2.1:1234"), Destination: M.ParseSocksaddr("example.com:443")}
	go func() {
		router.RouteConnectionEx(ctx, &identityRefreshReadConn{Conn: server, reading: reading}, metadata, nil)
		close(done)
	}()
	select {
	case <-reading:
	case <-time.After(5 * time.Second):
		t.Fatal("route sniff did not wait for client bytes")
	}
	require.Equal(t, uint32(1), control.ActiveConnections("target-one"))
	require.Zero(t, control.ActiveConnections("target-two"))
	// The route action is reading the admitted stream when the source's UUID changes.
	sourceUUID.Store("uuid-two")
	current, found := registry.LookupUser("source", "source-name")
	require.True(t, found)
	require.Equal(t, uint64(22), current.ID)
	_, err = client.Write([]byte(payload))
	require.NoError(t, err)
	actual := make([]byte, len(payload))
	_, err = io.ReadFull(client, actual)
	require.NoError(t, err)
	require.Equal(t, payload, string(actual))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("routed stream did not finish")
	}
	require.NoError(t, outbound.err)
	require.Equal(t, "source-name", outbound.metadata.User)
	require.Equal(t, "source", outbound.metadata.Inbound)
	snapshot := traffic.SnapshotTraffic([]string{"target-one", "target-two"})
	require.Equal(t, int64(len(payload)), snapshot[0].UplinkBytes)
	require.Equal(t, int64(len(payload)), snapshot[0].DownlinkBytes)
	require.Zero(t, snapshot[1].UplinkBytes+snapshot[1].DownlinkBytes)
	require.Zero(t, control.ActiveConnections("target-one"))
	require.Len(t, queue.records, 1)
	require.Equal(t, uint64(21), queue.records[0].Uid,
		"access log followed the refreshed UUID instead of the admitted accounting identity")
	require.Equal(t, "source", queue.records[0].Inbound)
}

// identityRefreshReadConn signals the actual first sniff read before waiting for client bytes.
// @author lyt
// @date 2026-10-30
type identityRefreshReadConn struct {
	net.Conn
	reading chan struct{}
	once    sync.Once
}

func (c *identityRefreshReadConn) Read(buffer []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(buffer)
}

// identityRefreshOutbound consumes the routed logical stream through its accounting wrapper.
// @author lyt
// @date 2026-10-30
type identityRefreshOutbound struct {
	adapter.Outbound
	payload  []byte
	metadata adapter.InboundContext
	err      error
}

func (*identityRefreshOutbound) Tag() string       { return "exit" }
func (*identityRefreshOutbound) Network() []string { return []string{N.NetworkTCP} }

func (o *identityRefreshOutbound) NewConnection(_ context.Context, conn net.Conn,
	metadata adapter.InboundContext, _ N.CloseHandlerFunc,
) {
	defer conn.Close()
	o.metadata = metadata
	payload := make([]byte, len(o.payload))
	if _, o.err = io.ReadFull(conn, payload); o.err == nil {
		_, o.err = conn.Write(payload)
	}
}

// identityRefreshOutboundManager exposes the one outbound selected by the original auth name.
// @author lyt
// @date 2026-10-30
type identityRefreshOutboundManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *identityRefreshOutboundManager) Default() adapter.Outbound { return m.outbound }
func (m *identityRefreshOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.outbound, tag == "exit"
}

// identityRefreshDNSRouter disables unrelated reverse lookup in the focused stream test.
// @author lyt
// @date 2026-10-30
type identityRefreshDNSRouter struct{ adapter.DNSRouter }

func (identityRefreshDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
