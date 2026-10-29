package authban_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/authban"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	ssinbound "github.com/sagernet/sing-box/protocol/shadowsocks"
	vmessinbound "github.com/sagernet/sing-box/protocol/vmess"
	shadowsocks "github.com/sagernet/sing-shadowsocks2"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var sourceSequence atomic.Uint32

type banEchoRouter struct {
	adapter.Router
	sources chan M.Socksaddr
}

func (r *banEchoRouter) RouteConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.sources <- metadata.Source
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err := io.Copy(conn, conn)
	_ = conn.Close()
	return err
}

func (r *banEchoRouter) RouteConnectionEx(ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext, onClose N.CloseHandlerFunc,
) {
	err := r.RouteConnection(ctx, conn, metadata)
	if onClose != nil {
		onClose(err)
	}
}

func newBanInbound(t *testing.T, protocol, cipher, password string, enabled bool,
	obfsMu ...string,
) (uint16, *banEchoRouter) {
	t.Helper()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(reservation.Addr().(*net.TCPAddr).Port)
	_ = reservation.Close()
	address := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	listen := option.ListenOptions{Listen: &address, ListenPort: port, ProxyProtocol: true}
	var options any
	if protocol == "vmess" {
		options = &option.VMessInboundOptions{
			ListenOptions: listen, ShadowsocksBanIP: enabled,
			Users: []option.VMessUser{{Name: "test-user", UUID: password}},
		}
	} else {
		serverKey := ""
		if cipher == "2022-blake3-aes-128-gcm" {
			serverKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
		}
		ssOptions := &option.ShadowsocksInboundOptions{
			ListenOptions: listen, ShadowsocksBanIP: enabled, Method: cipher,
			Password: serverKey, Users: []option.ShadowsocksUser{{Name: "test-user", Password: password}},
		}
		if len(obfsMu) != 0 {
			ssOptions.ObfsMu = obfsMu[0]
		}
		options = ssOptions
	}
	registry := inbound.NewRegistry()
	ssinbound.RegisterInbound(registry)
	vmessinbound.RegisterInbound(registry)
	logger := log.NewNOPFactory().Logger()
	router := &banEchoRouter{sources: make(chan M.Socksaddr, 16)}
	instance, err := registry.Create(context.Background(), router, logger, protocol, protocol, options)
	if err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(context.Background(), logger)
	t.Cleanup(func() { _ = scope.Close() })
	for _, stage := range adapter.ListStartStages {
		if err = instance.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	return port, router
}

func banExchange(port uint16, source, protocol, cipher, credential string, obfsUUID ...string) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 3456 %d\r\n", source, port); err != nil {
		return err
	}
	if len(obfsUUID) != 0 {
		digest := md5.Sum([]byte(obfsUUID[0]))
		if _, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %x.microsoft.com\r\n\r\n", digest); err != nil {
			return err
		}
		const response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		buffer := make([]byte, len(response))
		if _, err = io.ReadFull(conn, buffer); err != nil {
			return err
		}
		if string(buffer) != response {
			return fmt.Errorf("unexpected shared obfs response")
		}
	}
	destination := M.ParseSocksaddr("example.test:443")
	if protocol == "vmess" {
		client, createErr := vmess.NewClient(credential, "aes-128-gcm", 0)
		if createErr != nil {
			return createErr
		}
		conn = client.DialEarlyConn(conn, destination)
	} else {
		method, createErr := shadowsocks.CreateMethod(context.Background(), cipher,
			shadowsocks.MethodOptions{Password: credential})
		if createErr != nil {
			return createErr
		}
		conn = method.DialEarlyConn(conn, destination)
	}
	payload := bytes.Repeat([]byte("authenticated TCP payload "), 24)
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, response); err != nil {
		return err
	}
	if !bytes.Equal(payload, response) {
		return fmt.Errorf("authenticated echo changed payload")
	}
	return nil
}

func TestSharedBanAcrossProtocolsUsesProxySource(t *testing.T) {
	sequence := sourceSequence.Add(1)
	badSource := fmt.Sprintf("198.18.%d.%d", sequence/250, sequence%250+1)
	goodSource := fmt.Sprintf("198.19.%d.%d", sequence/250, sequence%250+1)
	policySource := M.ParseSocksaddr(net.JoinHostPort(badSource, "9999"))
	ssPort, ssRouter := newBanInbound(t, "shadowsocks", "aes-128-gcm", "correct-password", true)
	vmessPort, vmessRouter := newBanInbound(t, "vmess", "", "correct-vmess-credential", true)
	for index, protocol := range []string{"shadowsocks", "vmess", "shadowsocks"} {
		port := ssPort
		if protocol == "vmess" {
			port = vmessPort
		}
		if err := banExchange(port, badSource, protocol, "aes-128-gcm", "wrong-credential"); err == nil {
			t.Fatal("unknown credential authenticated")
		}
		if authban.Shared().IsBlocked(policySource) != (index == 2) {
			t.Fatalf("cross-protocol attempt %d did not preserve the shared threshold", index+1)
		}
	}
	for _, test := range []struct {
		protocol   string
		port       uint16
		credential string
		router     *banEchoRouter
	}{
		{"shadowsocks", ssPort, "correct-password", ssRouter},
		{"vmess", vmessPort, "correct-vmess-credential", vmessRouter},
	} {
		if err := banExchange(test.port, badSource, test.protocol, "aes-128-gcm", test.credential); err == nil {
			t.Fatalf("%s accepted the blocked source with a correct credential", test.protocol)
		}
		if err := banExchange(test.port, goodSource, test.protocol, "aes-128-gcm", test.credential); err != nil {
			t.Fatalf("%s rejected a different source: %v", test.protocol, err)
		}
		select {
		case source := <-test.router.sources:
			if source.Addr.String() != goodSource {
				t.Fatalf("router saw proxy hop instead of actual source: %v", source)
			}
		case <-time.After(time.Second):
			t.Fatal("authenticated connection did not reach the router")
		}
	}
	if authban.Shared().IsBlocked(M.ParseSocksaddr("127.0.0.1:1234")) {
		t.Fatal("the common proxy hop was blocked instead of its declared source")
	}
	for _, protocol := range []string{"shadowsocks", "vmess"} {
		port, _ := newBanInbound(t, protocol, "aes-128-gcm", "unrestricted-credential", false)
		if err := banExchange(port, badSource, protocol, "aes-128-gcm", "unrestricted-credential"); err != nil {
			t.Fatalf("disabled %s policy inherited a process-wide ban: %v", protocol, err)
		}
	}
	userKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
	serverKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	ss2022Port, _ := newBanInbound(t, "shadowsocks", "2022-blake3-aes-128-gcm", userKey, true)
	if err := banExchange(ss2022Port, badSource, "shadowsocks", "2022-blake3-aes-128-gcm",
		serverKey+":"+userKey); err != nil {
		t.Fatalf("SS2022 incorrectly installed the legacy policy: %v", err)
	}
	sharedPort, _ := newBanInbound(t, "shadowsocks", "aes-128-gcm", "obfs-uuid", true,
		"aes-128-gcm:shared-password")
	if err := banExchange(sharedPort, badSource, "shadowsocks", "aes-128-gcm",
		"shared-password", "obfs-uuid"); err != nil {
		t.Fatalf("shared-password obfs incorrectly installed the multi-user policy: %v", err)
	}
}
