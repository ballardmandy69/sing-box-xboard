package anytlsnative_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// TestNodeAutoOutIP checks what an external TCP server actually observes for concurrent node users.
// @author lyt
// @date 2026-10-29
func TestNodeAutoOutIP(t *testing.T) {
	addresses := []string{"127.0.0.2", "127.0.0.3"}
	for _, address := range addresses {
		probe, err := net.Listen("tcp4", address+":0")
		if err != nil {
			if runtime.GOOS != "linux" {
				t.Skip("this host cannot bind multiple loopback IPs")
			}
			t.Fatal(err)
		}
		probe.Close()
	}
	for _, protocol := range []string{"trojan", "anytls", "anytls-native"} {
		t.Run(protocol, func(t *testing.T) {
			certificate, key := nativeTestCertificate(t)
			privateKey, publicKey := nativeTestKeys(t)
			port := nativeFreePort(t)
			var inbounds, outbounds []any
			for index, address := range addresses {
				tag := fmt.Sprintf("node-%d", index)
				inbound := map[string]any{
					"type": protocol, "tag": tag, "listen": address, "listen_port": port, "auto_out_ip": true,
					"users": []any{map[string]any{"name": "user", "password": "local-test-password"}},
				}
				outbound := map[string]any{
					"type": protocol, "tag": tag, "server": address, "server_port": port,
					"password": "local-test-password",
				}
				if protocol == "anytls-native" {
					inbound["private_key"] = privateKey
					outbound["server_public_key"] = publicKey
				} else {
					inbound["tls"] = map[string]any{
						"enabled": true, "certificate": []string{certificate}, "key": []string{key},
					}
					outbound["tls"] = map[string]any{
						"enabled": true, "server_name": "native.test", "certificate": []string{certificate},
					}
				}
				inbounds = append(inbounds, inbound)
				outbounds = append(outbounds, outbound)
			}
			nativeStartBox(t, map[string]any{
				"inbounds": inbounds, "outbounds": []any{map[string]any{"type": "direct"}},
			}, nil)
			client := nativeStartBox(t, map[string]any{"outbounds": outbounds}, nil)
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			go func() {
				for {
					conn, acceptErr := listener.Accept()
					if acceptErr != nil {
						return
					}
					go func() {
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						var request [1]byte
						if _, readErr := io.ReadFull(conn, request[:]); readErr != nil {
							return
						}
						host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
						fmt.Fprintln(conn, host)
					}()
				}
			}()
			destination := M.SocksaddrFromNet(listener.Addr())
			results := make(chan error, 16)
			var workers sync.WaitGroup
			for index, address := range addresses {
				outbound := nativeGetOutbound(t, client, fmt.Sprintf("node-%d", index))
				for range 8 {
					workers.Go(func() {
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						conn, err := outbound.DialContext(ctx, "tcp", destination)
						if err != nil {
							results <- err
							return
						}
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						if _, err = conn.Write([]byte{1}); err == nil {
							var observed string
							observed, err = bufio.NewReader(conn).ReadString('\n')
							if err == nil && strings.TrimSpace(observed) != address {
								err = fmt.Errorf("node %s exposed source %q", address, observed)
							}
						}
						results <- err
					})
				}
			}
			workers.Wait()
			close(results)
			for err := range results {
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
