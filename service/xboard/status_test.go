package xboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/ssmapi"
)

func statusTestPanel(t *testing.T, host, panelType string) *nodePanel {
	t.Helper()
	client, err := newPanelClient(option.XBoardPanelOptions{
		APIHost: host, APIKey: "status-test-secret", PanelType: panelType,
		PanelTag: "status", NodeID: 7, NodeType: "shadowsocks",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &nodePanel{client: client}
}

func TestStatusPPanelUsesSampleConstantsAndCurrentMilliseconds(t *testing.T) {
	var calls atomic.Int32
	before := time.Now().UnixMilli()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/v1/server/status" ||
			request.URL.Query().Get("secret_key") != "status-test-secret" ||
			request.URL.Query().Get("server_id") != "7" {
			t.Error("unexpected status request")
		}
		var report map[string]float64
		if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
			t.Error(err)
		}
		if len(report) != 4 || report["cpu"] != 100 || report["mem"] != 100 || report["disk"] != 100 {
			t.Errorf("sample status constants changed: %v", report)
		}
		if timestamp := int64(report["updated_at"]); timestamp < before || timestamp > time.Now().UnixMilli() {
			t.Errorf("status is not using current Unix milliseconds: %d", timestamp)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	n := &node{primary: statusTestPanel(t, server.URL, "ppanel"), disableUpload: true, reportAlive: false}
	if err := n.pushStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("traffic and alive switches must not disable node status")
	}
}

func TestStatusMultiAndProvidersWithoutStatusDoNotRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	ppanel := statusTestPanel(t, server.URL, "ppanel")
	for _, n := range []*node{
		{primary: ppanel, panels: []*nodePanel{ppanel}},
		{primary: ppanel, panels: []*nodePanel{}},
		{primary: statusTestPanel(t, server.URL, "uniproxy")},
		{primary: statusTestPanel(t, server.URL, "oldv2board")},
	} {
		if err := n.pushStatus(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("no-op status provider made %d requests", calls.Load())
	}
}

func TestStatusRejectsNonSuccessWithoutLeakingCredentials(t *testing.T) {
	for _, status := range []int{http.StatusNotModified, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()
			n := &node{primary: statusTestPanel(t, server.URL, "ppanel")}
			err := n.pushStatus(context.Background())
			if err == nil || strings.Contains(err.Error(), "status-test-secret") ||
				strings.Contains(err.Error(), server.URL) {
				t.Fatalf("missing or unsafe status error: %v", err)
			}
		})
	}
}

func TestStatusOnlyRunsOnRefreshAndFailureDoesNotBlockConfig(t *testing.T) {
	var access sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		access.Lock()
		paths = append(paths, request.URL.Path)
		access.Unlock()
		switch request.URL.Path {
		case "/v1/server/user":
			w.Write([]byte(`{"users":[]}`))
		case "/v1/server/config":
			w.Write([]byte(ppanelTestConfig("shadowsocks", `{"port":443,"method":"aes-128-gcm"}`)))
		case "/v1/server/status":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected request %s", request.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	n := &node{
		service: &Service{logger: log.NewNOPFactory().Logger()},
		primary: statusTestPanel(t, server.URL, "ppanel"), inbound: &userSyncInbound{},
		traffic: ssmapi.NewTrafficManager(), nodeType: "shadowsocks", disableUpload: true,
	}
	assertPaths := func(expected ...string) {
		t.Helper()
		access.Lock()
		defer access.Unlock()
		if !reflect.DeepEqual(paths, expected) {
			t.Fatalf("request order %v, want %v", paths, expected)
		}
		paths = nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if !n.initialSync(ctx) {
		t.Fatal("initial panel synchronization failed")
	}
	assertPaths("/v1/server/user", "/v1/server/config")
	if err := n.syncUsers(ctx); err == nil {
		t.Fatal("status report failure was not made available to operational logging")
	}
	assertPaths("/v1/server/status", "/v1/server/config", "/v1/server/user")
	if err := n.syncCycle(ctx); err == nil {
		t.Fatal("legacy status failure was not returned for logging")
	}
	assertPaths("/v1/server/user", "/v1/server/status", "/v1/server/config")
}
