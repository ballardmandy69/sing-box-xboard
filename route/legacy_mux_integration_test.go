package route_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-mux"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// legacyMuxDialer opens an authenticated Trojan tunnel without explicit inbound multiplex options.
// @author lyt
// @date 2026-10-29
type legacyMuxDialer struct {
	address string
	port    uint16
	dials   atomic.Int32
}

func (d *legacyMuxDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, d.address)
	if err != nil {
		return nil, err
	}
	d.dials.Add(1)
	destination.Port = d.port
	return T.NewClientConn(conn, T.Key("mux-test-secret"), destination), nil
}

func (d *legacyMuxDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("test dialer accepts TCP only")
}

func TestLegacyMuxActualTrojanBox(t *testing.T) {
	for _, protocol := range []string{"smux", "yamux", "h2mux"} {
		for _, padding := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/padding=%v", protocol, padding), func(t *testing.T) {
				echo, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { echo.Close() })
				go func() {
					for {
						conn, acceptErr := echo.Accept()
						if acceptErr != nil {
							return
						}
						go func() {
							defer conn.Close()
							conn.SetDeadline(time.Now().Add(10 * time.Second))
							io.Copy(conn, conn)
						}()
					}
				}()
				reservation, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address := reservation.Addr().String()
				port := reservation.Addr().(*net.TCPAddr).Port
				reservation.Close()
				ctx, cancel := context.WithCancel(service.ContextWithDefaultRegistry(include.Context(context.Background())))
				t.Cleanup(cancel)
				config, err := json.Marshal(map[string]any{
					"log": map[string]any{"disabled": true},
					"inbounds": []any{map[string]any{
						"type": "trojan", "tag": "mux-node", "listen": "127.0.0.1", "listen_port": port,
						"force_mux": true, "server_padding": true,
						"users": []any{map[string]any{"name": "panel-user", "password": "mux-test-secret"}},
					}},
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
				t.Cleanup(func() { instance.Close() })
				var available atomic.Bool
				available.Store(true)
				var policyCalls atomic.Int32
				policies := service.FromContext[adapter.ManagedNodePolicy](ctx).(*nodepolicy.Registry)
				if err = policies.Register("mux-node", nodepolicy.Node{
					LookupUser: func(identity string) (nodepolicy.User, bool) {
						policyCalls.Add(1)
						return nodepolicy.User{ID: 42}, available.Load() && identity == "panel-user"
					},
				}); err != nil {
					t.Fatal(err)
				}
				if err = instance.Start(); err != nil {
					t.Fatal(err)
				}
				dialer := &legacyMuxDialer{address: address, port: 443}
				client, err := mux.NewClient(mux.Options{
					Dialer: dialer, Logger: log.NewNOPFactory().Logger(), Protocol: protocol,
					MaxConnections: 1, Padding: padding,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { client.Close() })
				destination := M.SocksaddrFromNet(echo.Addr())
				first := legacyMuxStream(t, ctx, client, "tcp", destination)
				defer first.Close()
				legacyMuxEcho(t, first, []byte("first concurrent stream"))
				second := legacyMuxStream(t, ctx, client, "tcp", destination)
				legacyMuxEcho(t, second, []byte("second concurrent stream"))
				second.Close()
				if dialer.dials.Load() != 1 || policyCalls.Load() != 2 {
					t.Fatalf("streams lost reuse or policy: dials=%d checks=%d", dialer.dials.Load(), policyCalls.Load())
				}
				udp := legacyMuxStream(t, ctx, client, "udp", destination)
				udp.Write([]byte("must not forward UDP"))
				if _, err = udp.Read(make([]byte, 64)); err == nil {
					t.Fatal("UDP child stream was accepted")
				}
				udp.Close()
				available.Store(false)
				removed := legacyMuxStream(t, ctx, client, "tcp", destination)
				removed.Write([]byte("removed user"))
				if _, err = removed.Read(make([]byte, 64)); err == nil {
					t.Fatal("deleted user bypassed policy through an existing multiplex tunnel")
				}
				removed.Close()
				if policyCalls.Load() != 3 {
					t.Fatalf("new multiplex stream skipped user lookup: checks=%d", policyCalls.Load())
				}
				legacyMuxEcho(t, first, []byte("existing stream remains independent"))
			})
		}
	}
}

func legacyMuxStream(t *testing.T, ctx context.Context, client *mux.Client,
	network string, destination M.Socksaddr,
) net.Conn {
	t.Helper()
	stream, err := client.DialContext(ctx, network, destination)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	return stream
}

func legacyMuxEcho(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("multiplex stream changed payload bytes")
	}
}
