package route_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/ssmapi"
	T "github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-mux"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestStaticPanelActualTCPAndMultiplex(t *testing.T) {
	for _, multiplex := range []bool{false, true} {
		name := "independent-listeners"
		if multiplex {
			name = "multiplex-logical-streams"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(service.ContextWithDefaultRegistry(include.Context(context.Background())))
			defer cancel()
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			var targets atomic.Int32
			go func() {
				for {
					conn, acceptErr := echo.Accept()
					if acceptErr != nil {
						return
					}
					targets.Add(1)
					go func() {
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(5 * time.Second))
						io.Copy(conn, conn)
					}()
				}
			}()
			var addresses []string
			var inbounds []any
			for _, tag := range []string{"static-a", "static-b"} {
				listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
				if listenErr != nil {
					t.Fatal(listenErr)
				}
				addresses = append(addresses, listener.Addr().String())
				port := listener.Addr().(*net.TCPAddr).Port
				listener.Close()
				inbounds = append(inbounds, map[string]any{
					"type": "trojan", "tag": tag, "use_panel_tag": "shared-panel",
					"listen": "127.0.0.1", "listen_port": port,
					"users": []any{
						map[string]any{"name": "raw-panel-uuid", "password": "mux-test-secret"},
						map[string]any{"name": "not-a-panel-user", "password": "unknown-static-password"},
					},
				})
			}
			config, err := json.Marshal(map[string]any{
				"log": map[string]any{"disabled": true}, "inbounds": inbounds,
				"nyafw":     map[string]any{"connection_cleanup_interval_sec": 3600},
				"outbounds": []any{map[string]any{"type": "direct"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			options, err := SJSON.UnmarshalExtendedContext[option.Options](ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			const identity = "42@shared-panel@uniproxy"
			traffic := ssmapi.NewTrafficManager()
			traffic.UpdateUsers([]string{identity})
			control := usercontrol.NewManager(traffic)
			cleaner := service.PtrFromContext[usercontrol.ConnectionCleaner](ctx)
			control.SetConnectionCleaner(cleaner)
			if err = control.UpdateUsers(map[string]usercontrol.Limits{identity: {ConnectionLimit: 2}}); err != nil {
				t.Fatal(err)
			}
			var admissions, rejected atomic.Int32
			registry := service.FromContext[adapter.ManagedNodePolicy](ctx).(*nodepolicy.Registry)
			if err = registry.Register("shared-panel", nodepolicy.Node{
				Static:     true,
				LookupUser: func(string) (nodepolicy.User, bool) { return nodepolicy.User{}, false },
				LookupStaticUser: func(name string) (nodepolicy.User, bool) {
					return nodepolicy.User{ID: 42, Label: identity}, name == "raw-panel-uuid"
				},
				Rules: []nodepolicy.Rule{{ID: 1, Pattern: `blocked\.invalid`}},
				OnBlocked: func(_ context.Context, metadata adapter.InboundContext, _ uint64, _ string) {
					if metadata.Inbound == "static-a" {
						rejected.Add(1)
					}
				},
				TrackConnection: func(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) (net.Conn, error) {
					admissions.Add(1)
					return control.TrackConnectionContext(ctx, conn, metadata)
				},
			}); err != nil {
				t.Fatal(err)
			}
			if err = instance.Start(); err != nil {
				t.Fatal(err)
			}
			destination := M.SocksaddrFromNet(echo.Addr())
			dial := func(index int, password string, target M.Socksaddr) net.Conn {
				conn, dialErr := net.Dial("tcp", addresses[index])
				if dialErr != nil {
					t.Fatal(dialErr)
				}
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				return T.NewClientConn(conn, T.Key(password), target)
			}
			dialStream := func(index int) net.Conn { return dial(index, "mux-test-secret", destination) }
			if multiplex {
				client, clientErr := mux.NewClient(mux.Options{
					Dialer: &legacyMuxDialer{address: addresses[0], port: 443},
					Logger: log.NewNOPFactory().Logger(), Protocol: "smux", MaxConnections: 1,
				})
				if clientErr != nil {
					t.Fatal(clientErr)
				}
				defer client.Close()
				dialStream = func(int) net.Conn { return legacyMuxStream(t, ctx, client, "tcp", destination) }
				udp := legacyMuxStream(t, ctx, client, "udp", destination)
				udp.Write([]byte("UDP must remain disabled"))
				if _, err = udp.Read(make([]byte, 64)); err == nil {
					t.Fatal("static alias allowed UDP forwarding")
				}
				udp.Close()
			}
			first, second := dialStream(0), dialStream(1)
			defer first.Close()
			defer second.Close()
			legacyMuxEcho(t, first, []byte("first"))
			legacyMuxEcho(t, second, []byte("second"))
			if control.ActiveConnections(identity) != 2 || admissions.Load() != 2 {
				t.Fatalf("carrier or child was counted twice: active=%d admissions=%d",
					control.ActiveConnections(identity), admissions.Load())
			}
			routed := 0
			for _, registration := range cleaner.SnapshotRegistrations() {
				if registration.Type == "tcp-routed" && registration.UserLabel == identity &&
					registration.SourceIP == "127.0.0.1" {
					routed++
				}
			}
			if routed != 2 {
				t.Fatalf("static child registrations lost their routed identity: %+v", cleaner.SnapshotRegistrations())
			}
			third := dialStream(0)
			third.Write([]byte("over limit"))
			if _, err = third.Read(make([]byte, 64)); err == nil {
				t.Fatal("over-limit static stream was accepted")
			}
			third.Close()
			if targets.Load() != 2 || control.ActiveConnections(identity) != 2 {
				t.Fatal("over-limit static stream dialed a target or leaked quota")
			}
			snapshot := traffic.SnapshotTraffic([]string{identity})[0]
			if snapshot.UplinkBytes != 11 || snapshot.DownlinkBytes != 11 {
				t.Fatalf("static traffic did not count payload exactly once: %+v", snapshot)
			}
			unknown := dial(0, "unknown-static-password", destination)
			unknown.Write([]byte("unknown panel identity"))
			if _, err = unknown.Read(make([]byte, 64)); err == nil {
				t.Fatal("unknown static user bypassed panel lookup")
			}
			unknown.Close()
			blocked := dial(0, "mux-test-secret", M.ParseSocksaddr("blocked.invalid:443"))
			blocked.Write([]byte("blocked by rule"))
			if _, err = blocked.Read(make([]byte, 64)); err == nil {
				t.Fatal("static panel rule was ignored")
			}
			blocked.Close()
			if rejected.Load() != 1 || admissions.Load() != 3 || targets.Load() != 2 {
				t.Fatal("route rejection changed the inbound label, admitted, or dialed a target")
			}
			first.Close()
			staticWaitActive(t, control, identity, 1)
			replacement := dialStream(1)
			legacyMuxEcho(t, replacement, []byte("replacement"))
			replacement.Close()
			second.Close()
			staticWaitActive(t, control, identity, 0)
		})
	}
}

func staticWaitActive(t *testing.T, manager *usercontrol.Manager, identity string, want uint32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for manager.ActiveConnections(identity) != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if manager.ActiveConnections(identity) != want {
		t.Fatalf("static connections did not release: got %d want %d", manager.ActiveConnections(identity), want)
	}
}
