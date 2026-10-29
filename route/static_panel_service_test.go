package route_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestStaticPanelAliasFromManagedSourceCountsOnlyTarget(t *testing.T) {
	for _, mode := range []string{"alias", "detour", "managed-multiplex"} {
		t.Run(mode, func(t *testing.T) { testManagedPanelOwnership(t, mode) })
	}
}

func testManagedPanelOwnership(t *testing.T, mode string) {
	const uuid = "455fa71d-7bf2-429a-89d9-f45e30e35c21"
	var sourceBytes, targetBytes atomic.Int64
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uint64(11)
		if r.URL.Query().Get("node_id") == "2" {
			id = 22
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/user"):
			json.NewEncoder(w).Encode(map[string]any{"users": []any{map[string]any{"id": id, "uuid": uuid}}})
		case strings.HasSuffix(r.URL.Path, "/config"):
			io.WriteString(w, `{"protocol":"trojan","server_port":443}`)
		case strings.HasSuffix(r.URL.Path, "/push"):
			var records map[string][2]int64
			if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
				t.Error(err)
			}
			for user, value := range records {
				if id == 11 && user == "11" {
					sourceBytes.Add(value[0] + value[1])
				} else if id == 22 && user == "22" {
					targetBytes.Add(value[0] + value[1])
				} else {
					t.Errorf("traffic attributed to the wrong panel user: node=%d user=%s", id, user)
				}
			}
			io.WriteString(w, `{}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	defer panel.Close()
	var targets atomic.Int32
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
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
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, port := reservation.Addr().String(), reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	reservation, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	staticAddress, staticPort := reservation.Addr().String(), reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	ctx, cancel := context.WithCancel(service.ContextWithDefaultRegistry(include.Context(context.Background())))
	defer cancel()
	sourceInbound := map[string]any{
		"type": "trojan", "tag": "source-listener", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"name": "before-sync", "password": "before-sync"}},
	}
	switch mode {
	case "alias":
		sourceInbound["use_panel_tag"] = "target-panel"
	case "detour":
		sourceInbound["detour"] = "independent-listener"
	}
	config, err := json.Marshal(map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{sourceInbound, map[string]any{
			"type": "trojan", "tag": "independent-listener", "use_panel_tag": "target-panel",
			"listen": "127.0.0.1", "listen_port": staticPort,
			"users": []any{map[string]any{"name": uuid, "password": "independent-static-password"}},
		}},
		"outbounds": []any{map[string]any{"type": "direct"}},
		"services": []any{
			map[string]any{"type": "xboard", "tag": "source-panel", "inbound": "source-listener",
				"api_host": panel.URL, "api_key": "source", "node_id": 1, "node_type": "trojan",
				"connection_limit": 2, "pull_interval": "1m", "push_interval": "10ms"},
			map[string]any{"type": "xboard", "tag": "target-panel", "static_inbound": true,
				"api_host": panel.URL, "api_key": "target", "node_id": 2, "node_type": "trojan",
				"pull_interval": "1m", "push_interval": "10ms"},
		},
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
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	registry := service.FromContext[adapter.ManagedNodePolicy](ctx).(*nodepolicy.Registry)
	staticAwait(t, func() bool {
		user, exists := registry.LookupUser("source-listener", "11@source-panel@uniproxy")
		return exists && (mode == "alias" && user.ID == 22 || mode != "alias" && user.ID == 11)
	})
	if _, exists := registry.LookupUser("source-listener", uuid); exists {
		t.Fatal("unknown source identity was accepted by matching the target UUID text")
	}
	var conn net.Conn
	destination := M.SocksaddrFromNet(echo.Addr())
	if mode == "managed-multiplex" {
		dialer := &managedPanelMuxDialer{address: address, password: uuid}
		client, clientErr := mux.NewClient(mux.Options{Dialer: dialer, Logger: log.NewNOPFactory().Logger(),
			Protocol: "smux", MaxConnections: 1})
		if clientErr != nil {
			t.Fatal(clientErr)
		}
		defer client.Close()
		conn = legacyMuxStream(t, ctx, client, "tcp", destination)
		legacyMuxEcho(t, conn, []byte("first-child"))
		second := legacyMuxStream(t, ctx, client, "tcp", destination)
		legacyMuxEcho(t, second, []byte("second-child"))
		third := legacyMuxStream(t, ctx, client, "tcp", destination)
		third.Write([]byte("over-limit-child"))
		if _, err = third.Read(make([]byte, 32)); err == nil {
			t.Fatal("managed mux counted its carrier instead of limiting logical streams")
		}
		third.Close()
		if targets.Load() != 2 || dialer.dials.Load() != 1 {
			t.Fatalf("mux target/carrier counts: targets=%d carriers=%d", targets.Load(), dialer.dials.Load())
		}
		second.Close()
		staticAwait(t, func() bool { return sourceBytes.Load() == int64(2*(len("first-child")+len("second-child"))) })
	} else {
		raw, dialErr := net.Dial("tcp", address)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		conn = T.NewClientConn(raw, T.Key(uuid), destination)
		if mode == "detour" {
			conn = T.NewClientConn(conn, T.Key("independent-static-password"), destination)
		}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("only-target-panel")
	legacyMuxEcho(t, conn, payload)
	if mode == "managed-multiplex" {
		staticAwait(t, func() bool {
			return sourceBytes.Load() == int64(2*(len(payload)+len("first-child")+len("second-child")))
		})
		if targetBytes.Load() != 0 {
			t.Fatal("direct managed mux used another node's accounting")
		}
	} else {
		staticAwait(t, func() bool { return targetBytes.Load() == int64(2*len(payload)) })
	}
	if mode != "managed-multiplex" && sourceBytes.Load() != 0 {
		t.Fatal("source protocol tracker duplicated the target panel's traffic accounting")
	}
	rawStatic, err := net.Dial("tcp", staticAddress)
	if err != nil {
		t.Fatal(err)
	}
	staticConn := T.NewClientConn(rawStatic, T.Key("independent-static-password"), M.SocksaddrFromNet(echo.Addr()))
	defer staticConn.Close()
	staticConn.SetDeadline(time.Now().Add(3 * time.Second))
	staticPayload := []byte("independent-static-credentials")
	legacyMuxEcho(t, staticConn, staticPayload)
	expectedTarget := len(staticPayload)
	if mode != "managed-multiplex" {
		expectedTarget += len(payload)
	}
	staticAwait(t, func() bool { return targetBytes.Load() == int64(2*expectedTarget) })
	if mode != "managed-multiplex" && sourceBytes.Load() != 0 {
		t.Fatal("independent static authentication changed the source panel's counters")
	}
}

// managedPanelMuxDialer uses the panel's real credential while exposing physical carrier count.
// @author lyt
// @date 2026-10-29
type managedPanelMuxDialer struct {
	address, password string
	dials             atomic.Int32
}

func (d *managedPanelMuxDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	d.dials.Add(1)
	return T.NewClientConn(conn, T.Key(d.password), destination), nil
}

func (*managedPanelMuxDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("test client only supports TCP")
}

func staticAwait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal("static panel synchronization did not complete")
	}
}
