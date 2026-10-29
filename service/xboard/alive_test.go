package xboard

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/usercontrol"
	M "github.com/sagernet/sing/common/metadata"
)

func TestAliveReportsActiveIPsAndClearsOfflineUsers(t *testing.T) {
	var received map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/server/UniProxy/alive" ||
			r.URL.Query().Get("token") != "test-token" || r.URL.Query().Get("node_type") != "anytls" {
			t.Errorf("unexpected alive request: %s %s", r.Method, r.URL.Path)
		}
		received = nil
		json.NewDecoder(r.Body).Decode(&received)
	}))
	defer server.Close()
	n := userSyncNode(server, "online", &userSyncInbound{})
	n.reportAlive, n.disableUpload = true, true
	identity := n.userName(7)
	n.users[identity] = 7
	if err := n.control.UpdateUsers(map[string]usercontrol.Limits{identity: {}}); err != nil {
		t.Fatal(err)
	}
	var connections []net.Conn
	for _, ip := range []string{"192.0.2.10", "192.0.2.10", "2001:db8::2"} {
		conn, err := n.control.TrackConnectionContext(context.Background(), &trafficFixtureConn{},
			adapter.InboundContext{User: identity, Source: M.ParseSocksaddrHostPort(ip, 1000)})
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		defer conn.Close()
	}
	if err := n.pushReports(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(received["7"], []string{"192.0.2.10", "2001:db8::2"}) {
		t.Fatalf("active IPs were duplicated, missing or included source ports: %v", received)
	}
	connections[0].Close()
	if err := n.pushAlive(context.Background()); err != nil || len(received["7"]) != 2 {
		t.Fatal("closing one stream removed another active stream on the same IP")
	}
	connections[1].Close()
	connections[2].Close()
	if err := n.pushReports(context.Background()); err != nil || received == nil || len(received) != 0 {
		t.Fatal("empty alive report must be {} even when traffic reporting is disabled")
	}
}

func TestAliveDisabledDoesNotRequestPanel(t *testing.T) {
	n := &node{}
	if err := n.pushAlive(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyCycleReportsBeforeUserRemoval(t *testing.T) {
	var mutex sync.Mutex
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint := strings.TrimPrefix(r.URL.Path, "/api/v1/server/UniProxy/")
		mutex.Lock()
		calls = append(calls, endpoint)
		mutex.Unlock()
		if endpoint == "user" {
			w.Write([]byte(`{"users":[]}`))
		} else if endpoint == "config" {
			w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	n := userSyncNode(server, "cycle", &userSyncInbound{})
	n.reportAlive, n.syncInterval = true, time.Minute
	identity := n.userName(7)
	n.users[identity] = 7
	conn := n.traffic.TrackConnection(&trafficFixtureConn{}, adapter.InboundContext{User: identity})
	conn.Write([]byte("last bytes before user removal"))
	conn.Close()
	if err := n.syncCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if !reflect.DeepEqual(calls, []string{"push", "alive", "user", "config"}) {
		t.Fatalf("unexpected legacy synchronization order: %v", calls)
	}
	if len(n.users) != 0 {
		t.Fatal("panel user removal did not apply after reporting")
	}
}

func TestLegacyInitialSyncDoesNotReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			w.Write([]byte(`{}`))
		case strings.HasSuffix(r.URL.Path, "/user"):
			w.Write([]byte(`{"users":[]}`))
			cancel()
		default:
			t.Errorf("initial synchronization unexpectedly reported: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	n := userSyncNode(server, "initial", &userSyncInbound{})
	n.syncInterval, n.reportAlive = time.Minute, true
	done := make(chan struct{})
	go func() { n.legacyLoop(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("legacy sleep did not respond to cancellation")
	}
}

func TestLegacyIntervalFloorAndPanelIntervalIsolation(t *testing.T) {
	for _, input := range []time.Duration{-time.Second, 0, time.Second, 10*time.Second - 1} {
		if got := legacySyncInterval(input); got != time.Minute {
			t.Fatalf("interval %s: got %s instead of the original one-minute fallback", input, got)
		}
	}
	if legacySyncInterval(10*time.Second) != 10*time.Second {
		t.Fatal("the ten-second boundary must be retained")
	}
	n := &node{syncInterval: time.Minute, pullInterval: time.Minute, pushInterval: time.Minute}
	var response configResponse
	response.BaseConfig.PullInterval, response.BaseConfig.PushInterval = 3, 4
	n.applyConfigIntervals(response)
	if n.pullInterval != time.Minute || n.pushInterval != time.Minute || n.syncInterval != time.Minute {
		t.Fatal("panel intervals overwrote the legacy unified scheduler")
	}
}
