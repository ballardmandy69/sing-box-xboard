package anytlsnative_test

import (
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/pires/go-proxyproto"
)

// TestProxyProtocolAutoOutIP verifies client identity and real socket binding across protocol sessions.
// @author lyt
// @date 2026-10-29
func TestProxyProtocolAutoOutIP(t *testing.T) {
	const listenIP = "127.0.0.2"
	probe, err := net.Listen("tcp4", listenIP+":0")
	if err != nil {
		if runtime.GOOS != "linux" {
			t.Skip("this host cannot bind multiple loopback IPs")
		}
		t.Fatal(err)
	}
	probe.Close()
	for _, protocol := range []string{"trojan", "anytls", "anytls-native"} {
		t.Run(protocol, func(t *testing.T) {
			for _, mode := range []struct {
				name    string
				version byte
			}{
				{name: "v1", version: 1},
				{name: "v2", version: 2},
				{name: "direct_optional"},
			} {
				t.Run(mode.name, func(t *testing.T) {
					port := nativeFreePort(t)
					inbound := map[string]any{
						"type": protocol, "tag": "node", "listen": listenIP, "listen_port": port,
						"auto_out_ip": true, "proxy_protocol": true,
						"proxy_protocol_accept_no_header": mode.version == 0,
						"users":                           []any{map[string]any{"name": "alpha", "password": "alpha-secret"}},
					}
					outbound := map[string]any{
						"type": protocol, "tag": "client", "password": "alpha-secret",
					}
					if protocol == "anytls-native" {
						privateKey, publicKey := nativeTestKeys(t)
						inbound["private_key"] = privateKey
						outbound["server_public_key"] = publicKey
					} else {
						certificate, key := nativeTestCertificate(t)
						inbound["tls"] = map[string]any{
							"enabled": true, "certificate": []string{certificate}, "key": []string{key},
						}
						outbound["tls"] = map[string]any{
							"enabled": true, "server_name": "native.test", "certificate": []string{certificate},
						}
					}
					tracker := &nativeRouteTracker{events: make(chan nativeRouteEvent, 8)}
					nativeStartBox(t, map[string]any{
						"inbounds": []any{inbound}, "outbounds": []any{map[string]any{"type": "direct"}},
					}, tracker)
					claimedSource := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 23456}
					claimedDestination := &net.TCPAddr{IP: net.ParseIP("203.0.113.22"), Port: 443}
					var header []byte
					if mode.version != 0 {
						header, err = proxyproto.HeaderProxyFromAddrs(
							mode.version, claimedSource, claimedDestination,
						).Format()
						if err != nil {
							t.Fatal(err)
						}
					}
					backend := M.ParseSocksaddrHostPort(listenIP, port)
					front := proxyAutoOutRelay(t, backend, header)
					outbound["server"], outbound["server_port"] = front.Addr.String(), front.Port
					client := nativeStartBox(t, map[string]any{"outbounds": []any{outbound}}, nil)
					destination, observed := proxyAutoOutEcho(t)
					for range 2 {
						if err = nativeExchange(nativeGetOutbound(t, client, "client"), destination, 1024); err != nil {
							t.Fatal(err)
						}
						event := nativeNextRoute(t, tracker)
						if event.user != "alpha" {
							t.Fatalf("PROXY connection lost authenticated user: %q", event.user)
						}
						if mode.version != 0 && event.source.String() != claimedSource.String() {
							t.Fatalf("reported client = %s, want %s", event.source, claimedSource)
						}
						select {
						case address := <-observed:
							if address.Addr.String() != listenIP {
								t.Fatalf("target observed source %s, want real local IP %s", address, listenIP)
							}
						case <-time.After(time.Second):
							t.Fatal("target did not observe the outbound socket")
						}
					}
				})
			}
		})
	}
}

func proxyAutoOutRelay(t *testing.T, backend M.Socksaddr, header []byte) M.Socksaddr {
	t.Helper()
	return proxyAutoOutListener(t, func(client net.Conn) {
		upstream, err := net.DialTimeout("tcp4", backend.String(), 3*time.Second)
		if err != nil {
			return
		}
		defer upstream.Close()
		upstream.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = upstream.Write(header); err != nil {
			return
		}
		copied := make(chan struct{})
		go func() {
			defer close(copied)
			io.Copy(upstream, client)
			upstream.Close()
		}()
		io.Copy(client, upstream)
		client.Close()
		<-copied
	})
}

func proxyAutoOutEcho(t *testing.T) (M.Socksaddr, <-chan M.Socksaddr) {
	t.Helper()
	observed := make(chan M.Socksaddr, 8)
	address := proxyAutoOutListener(t, func(conn net.Conn) {
		observed <- M.SocksaddrFromNet(conn.RemoteAddr())
		io.Copy(conn, conn)
	})
	return address, observed
}

func proxyAutoOutListener(t *testing.T, handle func(net.Conn)) M.Socksaddr {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.Map
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			connections.Store(conn, struct{}{})
			workers.Go(func() {
				defer connections.Delete(conn)
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				handle(conn)
			})
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
		connections.Range(func(key, _ any) bool {
			key.(net.Conn).Close()
			return true
		})
		workers.Wait()
	})
	return M.SocksaddrFromNet(listener.Addr())
}
