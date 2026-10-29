package anytls_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	stdjson "encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/gofrs/uuid/v5"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

// compositeMuxDialer uses the production wire clients and a nondefault carrier port to test FQDN-only routing.
// @author lyt
// @date 2026-10-29
type compositeMuxDialer struct {
	address  string
	protocol string
	anytls   *anytls.Client
	dials    atomic.Int32
}

const compositeMuxPassword = "composite-mux-password"

func (d *compositeMuxDialer) DialContext(ctx context.Context, network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	d.dials.Add(1)
	destination.Port = 8443
	if d.protocol == "anytls" {
		return d.anytls.CreateProxy(ctx, destination)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, d.address)
	if err != nil {
		return nil, err
	}
	if d.protocol == "trojan" {
		digest := sha256.Sum224([]byte(compositeMuxPassword))
		var key [56]byte
		hex.Encode(key[:], digest[:])
		return trojan.NewClientConn(conn, key, destination), nil
	}
	return vless.NewConn(conn, uuid.NewV5(uuid.Nil, compositeMuxPassword), vmess.CommandTCP, destination, ""), nil
}

func (*compositeMuxDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("UDP is outside the composite TCP test")
}

func compositeMuxServer(t *testing.T) string {
	t.Helper()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	encoded, err := stdjson.Marshal(map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{
			"type": "anytls", "tag": "composite", "listen": "127.0.0.1", "listen_port": port,
			"fallback_service": "trojan-vless", "force_mux_for_trojan": true,
			"server_padding_for_trojan": true, "force_vision": true,
			"users": []any{map[string]any{"name": "mux-user", "password": compositeMuxPassword}},
		}},
		"outbounds": []any{map[string]any{"type": "direct"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	t.Cleanup(cancel)
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, encoded)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func compositeMuxEcho(t *testing.T) M.Socksaddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()
	return M.SocksaddrFromNet(listener.Addr())
}

func TestCompositeGlobalSingMuxKeepsOtherStreamsAlive(t *testing.T) {
	for _, protocol := range []string{"trojan", "vless", "anytls"} {
		for _, padding := range []bool{false, true} {
			name := protocol + "/padding=" + strconv.FormatBool(padding)
			t.Run(name, func(t *testing.T) {
				address := compositeMuxServer(t)
				destination := compositeMuxEcho(t)
				dialer := &compositeMuxDialer{address: address, protocol: protocol}
				if protocol == "anytls" {
					client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
						Password: compositeMuxPassword, Logger: log.NewNOPFactory().Logger(),
						DialOut: func(ctx context.Context) (net.Conn, error) {
							return (&net.Dialer{}).DialContext(ctx, "tcp", address)
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					dialer.anytls = client
					t.Cleanup(func() { client.Close() })
				}
				client, err := mux.NewClient(mux.Options{
					Dialer: dialer, Logger: log.NewNOPFactory().Logger(), Protocol: "yamux",
					MaxConnections: 1, MaxStreams: 8, Padding: padding,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { client.Close() })
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				var streams []net.Conn
				for index := 0; index < 2; index++ {
					conn, err := client.DialContext(ctx, "tcp", destination)
					if err != nil {
						t.Fatal(err)
					}
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					t.Cleanup(func() { conn.Close() })
					streams = append(streams, conn)
				}
				exchange := func(conn net.Conn) {
					payload := []byte("a complete independent multiplexed stream")
					if _, err := conn.Write(payload); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(payload))
					if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("multiplexed response %q: %v", got, err)
					}
				}
				exchange(streams[0])
				exchange(streams[1])
				streams[0].Close()
				exchange(streams[1])
				if dialer.dials.Load() != 1 {
					t.Fatalf("opened %d carriers; expected one shared carrier", dialer.dials.Load())
				}
			})
		}
	}
}
