package route

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/ssmapi"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestManagedTrackingOrderAndEarlyActionRelease(t *testing.T) {
	for _, test := range []struct {
		name, expression, pattern, route string
		admitted                         bool
	}{
		{"scanner", "'deny'", "", `[{"action":"reject"}]`, false},
		{"panel-rule", "", ".*", `[{"action":"reject"}]`, false},
		{"route-reject", "", "", `[{"action":"reject"}]`, true},
		{"route-resolution-error", "", "", `[{"action":"resolve"}]`, true},
		{"dns-hijack-close", "", "", `[{"action":"hijack-dns"}]`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, _ := onDemandNetworkRouter(t, false, "", mDNS.RcodeNameError)
			onDemandRules(t, r, test.route)
			control := usercontrol.NewManager(nil)
			require.NoError(t, control.UpdateUsers(map[string]usercontrol.Limits{
				"user-label": {ConnectionLimit: 1, IPLimit: 1},
			}))
			requests, admissions := 0, 0
			node := nodepolicy.Node{LookupUser: managedPolicyUser,
				CheckRequest: func(ctx context.Context, name string) error {
					requests++
					if requests > 1 {
						return usercontrol.ErrRequestLimit
					}
					return control.CheckRequest(ctx, name)
				},
				TrackConnection: func(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) (net.Conn, error) {
					admissions++
					require.Equal(t, 1, requests, "request check must precede connection admission")
					tracked, err := control.TrackRoutedConnection(ctx, conn, metadata)
					require.NoError(t, err)
					require.Equal(t, uint32(1), control.ActiveConnections("user-label"))
					return tracked, nil
				},
			}
			if test.pattern != "" {
				node.Rules = []nodepolicy.Rule{{ID: 3, Pattern: test.pattern}}
			}
			managedPolicyRouter(t, r, test.expression, node)
			metadata := onDemandMetadata()
			metadata.Inbound, metadata.User = "panel-node", "panel-identity"
			metadata.Source = M.ParseSocksaddr("192.0.2.10:12345")
			client, server := net.Pipe()
			defer server.Close()
			client.Close()
			err := r.routeConnection(r.ctx, server, metadata, nil)
			if test.name != "dns-hijack-close" {
				require.Error(t, err)
			}
			require.Equal(t, 1, requests)
			require.Equal(t, test.admitted, admissions == 1)
			require.Zero(t, control.ActiveConnections("user-label"), "early route action leaked quota")
			require.Empty(t, control.OnlineIPs())
			err = r.routeConnection(r.ctx, server, metadata, nil)
			require.ErrorIs(t, err, usercontrol.ErrRequestLimit)
		})
	}
}

func TestManagedTrackingSniffReplayCountsOnce(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "route-action-sniff", true: "legacy-sniff"}[legacy], func(t *testing.T) {
			r, _ := onDemandNetworkRouter(t, false, "", mDNS.RcodeSuccess)
			onDemandRules(t, r, `[{"action":"sniff"},{"action":"reject"}]`)
			traffic := ssmapi.NewTrafficManager()
			traffic.UpdateUsers([]string{"user-label"})
			control := usercontrol.NewManager(traffic)
			require.NoError(t, control.UpdateUsers(map[string]usercontrol.Limits{"user-label": {}}))
			managedPolicyRouter(t, r, "", nodepolicy.Node{LookupUser: managedPolicyUser,
				CheckRequest: control.CheckRequest, TrackConnection: control.TrackRoutedConnection})
			metadata := onDemandMetadata()
			metadata.Inbound, metadata.User = "panel-node", "panel-identity"
			metadata.LegacyInboundOptions = option.InboundOptions{SniffEnabled: legacy}
			_, _, buffers, _, conn, err := r.matchRule(r.ctx, &metadata, legacySniffInput(t, false), nil, nil)
			require.NoError(t, err)
			defer conn.Close()
			defer func() { buf.ReleaseMulti(buffers) }()
			for _, buffer := range buffers {
				conn = bufio.NewCachedConn(conn, buffer)
			}
			buffers = nil
			const payload = "GET / HTTP/1.1\r\nHost: sniff.example\r\n\r\n"
			actual := make([]byte, len(payload))
			_, err = io.ReadFull(conn, actual)
			require.NoError(t, err)
			require.Equal(t, payload, string(actual))
			snapshot := traffic.SnapshotTraffic([]string{"user-label"})[0]
			require.Equal(t, int64(len(payload)), snapshot.UplinkBytes,
				"sniffed bytes were omitted or replay counted twice")
		})
	}
}
