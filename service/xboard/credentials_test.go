package xboard

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
)

type credentialRouter struct {
	adapter.Router
	users chan string
}

func (r *credentialRouter) RouteConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.users <- metadata.User
	_, err := io.Copy(conn, conn)
	return err
}

func TestSeparatePanelPasswordActualShadowsocksObfs(t *testing.T) {
	const uuid = "de0975cb-d941-57a4-b452-ef638e39d962"
	const identity = "42@legacy@oldv2b"
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()
	options := option.ShadowsocksInboundOptions{Method: "aes-128-gcm", ObfsMu: "aes-128-gcm",
		Managed: true, Network: "tcp"}
	for _, automatic := range []bool{false, true} {
		t.Run(fmt.Sprintf("automatic=%t", automatic), func(t *testing.T) {
			router := &credentialRouter{users: make(chan string, 8)}
			var managed adapter.ManagedSSMServer
			var holder *autoInbound
			if automatic {
				registry := inbound.NewRegistry()
				shadowsocks.RegisterInbound(registry)
				var err error
				holder, err = newAutoInbound(ctx, registry, router, logger, "test", autoInboundConfig{
					protocol: C.TypeShadowsocks, options: &options,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = holder.close() })
				managed = holder
			} else {
				created, err := shadowsocks.NewInbound(ctx, router, logger, "test", options)
				if err != nil {
					t.Fatal(err)
				}
				managed = created.(adapter.ManagedSSMServer)
			}
			current := func() adapter.TCPInjectableInbound {
				if holder != nil {
					return holder.current.inbound.(adapter.TCPInjectableInbound)
				}
				return managed.(adapter.TCPInjectableInbound)
			}
			for _, password := range []string{"separate-legacy-secret", "rotated-legacy-secret"} {
				if err := updateManagedPanelUsers(managed, []string{identity}, []string{uuid}, []string{password}); err != nil {
					t.Fatal(err)
				}
				if holder != nil {
					config := holder.current.config
					config.endpoint = netip.MustParseAddrPort("127.0.0.1:18443")
					if err := holder.replace(config); err != nil {
						t.Fatal(err)
					}
				}
				if err := exchangeSeparatePassword(current(), uuid, password); err != nil {
					t.Fatal(err)
				}
				if got := <-router.users; got != identity {
					t.Fatalf("credential was attributed to %q", got)
				}
				if err := exchangeSeparatePassword(current(), password, password); err == nil {
					t.Fatal("password incorrectly became the obfs Host identity")
				}
				if err := exchangeSeparatePassword(current(), uuid, uuid); err == nil {
					t.Fatal("UUID incorrectly became the decryption password")
				}
			}
			if err := exchangeSeparatePassword(current(), uuid, "separate-legacy-secret"); err == nil {
				t.Fatal("old password survived rotation")
			}
			select {
			case identity := <-router.users:
				t.Fatalf("rejected authentication reached routing: %s", identity)
			default:
			}
		})
	}
}

func exchangeSeparatePassword(inbound adapter.TCPInjectableInbound, uuid, password string) error {
	server, client := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		inbound.NewConnection(context.Background(), server, adapter.InboundContext{}, nil)
	}()
	defer func() {
		_ = client.Close()
		<-done
	}()
	digest := md5.Sum([]byte(uuid))
	host := hex.EncodeToString(digest[:]) + ".microsoft.com"
	if _, err := fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host); err != nil {
		return err
	}
	response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	buffer := make([]byte, len(response))
	if _, err := io.ReadFull(client, buffer); err != nil {
		return err
	}
	if string(buffer) != response {
		return fmt.Errorf("unexpected obfs response")
	}
	method, err := shadowaead.New("aes-128-gcm", nil, password)
	if err != nil {
		return err
	}
	conn := method.DialEarlyConn(client, M.ParseSocksaddr("example.org:443"))
	payload := []byte("separate panel password round trip")
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	buffer = make([]byte, len(payload))
	if _, err = io.ReadFull(conn, buffer); err != nil {
		return err
	}
	if !bytes.Equal(buffer, payload) {
		return fmt.Errorf("payload changed")
	}
	return nil
}

func TestSeparatePanelPasswordConversionAndRetry(t *testing.T) {
	uuids := []string{"8ef0a1bb-1567-4ff0-a313-316bf78a9184"}
	passwords := []string{"explicit-secret"}
	for _, protocol := range []string{C.TypeVMess, C.TypeVLESS, C.TypeTrojan, C.TypeShadowsocks} {
		got, err := panelProtocolCredentials(protocol, uuids, passwords)
		want := passwords
		if protocol == C.TypeVMess || protocol == C.TypeVLESS {
			want = uuids
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("protocol=%s credentials=%v err=%v", protocol, got, err)
		}
	}
	if _, err := panelProtocolCredentials("unknown", uuids, passwords); err == nil {
		t.Fatal("unsupported protocol accepted a separate password")
	}
	if _, err := panelProtocolCredentials(C.TypeTrojan, uuids, nil); err == nil {
		t.Fatal("mismatched credentials were accepted")
	}
	encoded, err := json.Marshal(panelUser{ID: 1, UUID: uuids[0], ProtocolPassword: passwords[0]})
	if err != nil || strings.Contains(string(encoded), passwords[0]) {
		t.Fatal("internal password was serialized into panel JSON")
	}
	registry := inbound.NewRegistry()
	shadowsocks.RegisterInbound(registry)
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("K", 16)))
	config := autoInboundConfig{protocol: C.TypeShadowsocks, options: &option.ShadowsocksInboundOptions{
		Method: "2022-blake3-aes-128-gcm", Password: key, Managed: true, Network: "tcp",
	}}
	holder, err := newAutoInbound(context.Background(), registry, nil, log.NewNOPFactory().Logger(), "test", config)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.close()
	if err = holder.updatePanelUsers([]string{"user"}, uuids, passwords); err == nil || len(holder.users) != 0 {
		t.Fatal("failed first user update poisoned the credential cache")
	}
	if err = holder.updatePanelUsers([]string{"user"}, uuids, []string{key}); err != nil {
		t.Fatalf("valid raw SS2022 key could not retry: %v", err)
	}
	if holder.credentials[0] != uuids[0] || holder.passwords[0] != key {
		t.Fatal("successful retry lost UUID or raw password")
	}
	if err = holder.updatePanelUsers([]string{"user"}, uuids, passwords); err == nil || holder.passwords[0] != key {
		t.Fatal("failed password rotation changed the last successful cache")
	}
}
