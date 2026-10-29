package vmess_test

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type managedIdentityTracker struct{ identities chan string }

func (t *managedIdentityTracker) TrackConnection(conn net.Conn, metadata adapter.InboundContext) net.Conn {
	t.identities <- metadata.User
	return conn
}

func (*managedIdentityTracker) TrackPacketConnection(conn N.PacketConn, _ adapter.InboundContext) N.PacketConn {
	return conn
}

// TestManagedUUIDProtocolsSeparateIdentityFromCredentials authenticates actual VMess/VLESS clients.
// @author lyt
// @date 2026-10-29
func TestManagedUUIDProtocolsSeparateIdentityFromCredentials(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless"} {
		t.Run(protocol, func(t *testing.T) {
			const credential = "61552c7d-d297-4593-86dd-62c57d01afbb"
			const identity = "42@panel@uniproxy"
			port := identityFreePort(t)
			server := identityBox(t, map[string]any{
				"inbounds": []any{map[string]any{
					"type": protocol, "tag": "managed", "listen": "127.0.0.1", "listen_port": port,
				}},
				"outbounds": []any{map[string]any{"type": "direct"}},
			})
			inbound, _ := server.Inbound().Get("managed")
			managed := inbound.(adapter.ManagedSSMServer)
			tracker := &managedIdentityTracker{identities: make(chan string, 64)}
			control := usercontrol.NewManager(tracker)
			if err := control.UpdateUsers(map[string]usercontrol.Limits{identity: {}}); err != nil {
				t.Fatal(err)
			}
			managed.SetTracker(control)
			if err := managed.UpdateUsers([]string{identity}, []string{credential}); err != nil {
				t.Fatal(err)
			}
			if hot, supported := inbound.(adapter.HotUserManager); supported {
				hot.UpdateHotUsers([]string{identity})
				hot.SetHotUserCallback(func(string) { t.Error("VMess unexpectedly emitted an auth hot callback") })
			}
			clientOptions := map[string]any{
				"type": protocol, "tag": "client", "server": "127.0.0.1", "server_port": port,
				"uuid": credential,
			}
			if protocol == "vmess" {
				clientOptions["security"] = "auto"
			}
			client := identityBox(t, map[string]any{"outbounds": []any{clientOptions}})
			outbound, _ := client.Outbound().Outbound("client")
			identityExchange(t, outbound)
			if got := <-tracker.identities; got != identity {
				t.Fatalf("credential authenticated under identity %q, want %q", got, identity)
			}
			const otherIdentity = "43@panel@uniproxy"
			const otherCredential = "ed09f8db-0d7b-4850-aa9c-a75b33eab148"
			if err := control.UpdateUsers(map[string]usercontrol.Limits{identity: {}, otherIdentity: {}}); err != nil {
				t.Fatal(err)
			}
			updateContext, stopUpdates := context.WithCancel(context.Background())
			updated := make(chan error, 1)
			updateDone := make(chan struct{})
			go func() {
				defer close(updateDone)
				for index := 0; updateContext.Err() == nil; index++ {
					names := []string{identity, otherIdentity}
					credentials := []string{credential, otherCredential}
					if index%2 != 0 {
						names[0], names[1] = names[1], names[0]
						credentials[0], credentials[1] = credentials[1], credentials[0]
					}
					if err := managed.UpdateUsers(names, credentials); err != nil {
						updated <- err
						return
					}
					if hot, supported := inbound.(adapter.HotUserManager); supported {
						hot.UpdateHotUsers([]string{names[index%2]})
					}
					runtime.Gosched()
				}
			}()
			t.Cleanup(func() { stopUpdates(); <-updateDone })
			for range 16 {
				identityExchange(t, outbound)
				if got := <-tracker.identities; got != identity {
					t.Fatalf("concurrent reordering attributed an authenticated stream to %q", got)
				}
			}
			stopUpdates()
			<-updateDone
			select {
			case err := <-updated:
				t.Fatal(err)
			default:
			}
			// Existing SSM callers may omit a separate credential list; retain their UUID-as-name behavior.
			if err := control.UpdateUsers(map[string]usercontrol.Limits{credential: {}}); err != nil {
				t.Fatal(err)
			}
			if err := managed.UpdateUsers([]string{credential}, nil); err != nil {
				t.Fatal(err)
			}
			identityExchange(t, outbound)
			if got := <-tracker.identities; got != credential {
				t.Fatalf("legacy identity=%q, want UUID-as-name", got)
			}
		})
	}
}

func identityBox(t *testing.T, config map[string]any) *box.Box {
	t.Helper()
	config["log"] = map[string]any{"disabled": true}
	encoded, err := stdjson.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	t.Cleanup(cancel)
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, encoded)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance
}

func identityFreePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func identityExchange(t *testing.T, outbound adapter.Outbound) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, err = io.Copy(conn, conn)
		}
		accepted <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, M.SocksaddrFromNet(listener.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("managed identity survives separate UUID authentication")
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("authenticated stream payload mismatch")
	}
	conn.Close()
	select {
	case err = <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("authenticated stream did not close its destination")
	}
}
