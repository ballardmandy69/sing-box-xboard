package xboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

// panelFixture exercises independent remote failures without a live panel or credentials.
// @author lyt
// @date 2026-10-29
type panelFixture struct {
	mu         sync.Mutex
	server     *httptest.Server
	users      []panelUser
	userStatus int
	pushStatus int
	etag       string
	requests   map[string]int
	reports    []map[string][2]int64
}

func newPanelFixture(t *testing.T, credential string) *panelFixture {
	t.Helper()
	f := &panelFixture{users: []panelUser{{ID: 1, UUID: credential}},
		userStatus: http.StatusOK, pushStatus: http.StatusOK, etag: "first", requests: make(map[string]int)}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		endpoint := strings.TrimPrefix(r.URL.Path, "/api/v1/server/UniProxy/")
		f.requests[endpoint]++
		switch endpoint {
		case "user":
			w.Header().Set("ETag", f.etag)
			w.WriteHeader(f.userStatus)
			if f.userStatus == http.StatusOK {
				json.NewEncoder(w).Encode(usersResponse{Users: f.users})
			}
		case "push":
			var report map[string][2]int64
			json.NewDecoder(r.Body).Decode(&report)
			f.reports = append(f.reports, report)
			w.WriteHeader(f.pushStatus)
		case "config":
			w.Write([]byte(`{}`))
		case "alive":
		default:
			t.Errorf("unexpected panel endpoint %s", endpoint)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *panelFixture) options(tag string) option.XBoardPanelOptions {
	return option.XBoardPanelOptions{PanelTag: tag, APIHost: f.server.URL,
		APIKey: "test-token", NodeID: 1, NodeType: "anytls"}
}

func multiTestNode(t *testing.T, fixtures ...*panelFixture) (*node, *userSyncInbound) {
	t.Helper()
	inbound := &userSyncInbound{}
	n := userSyncNode(fixtures[0].server, "aggregate", inbound)
	options := option.XBoardServiceOptions{Panels: make([]option.XBoardPanelOptions, len(fixtures))}
	for index, fixture := range fixtures {
		options.Panels[index] = fixture.options(string(rune('a' + index)))
	}
	var err error
	n.primary, n.panels, err = createNodePanels(options, "aggregate", "anytls")
	if err != nil {
		t.Fatal(err)
	}
	return n, inbound
}

func TestMultiPanelPartialPollRetainsFailedSource(t *testing.T) {
	a, b := newPanelFixture(t, "credential-a"), newPanelFixture(t, "credential-b")
	n, inbound := multiTestNode(t, a, b)
	if err := n.syncUserList(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inbound.names, []string{"1@a@uniproxy", "1@b@uniproxy"}) {
		t.Fatalf("panel-local IDs were merged: %v", inbound.names)
	}
	a.mu.Lock()
	a.userStatus = http.StatusInternalServerError
	a.mu.Unlock()
	b.mu.Lock()
	b.users[0].UUID, b.etag = "rotated-b", "second"
	b.mu.Unlock()
	if err := n.syncUserList(context.Background()); err != nil {
		t.Fatalf("one unavailable source rejected the successful merged update: %v", err)
	}
	if !reflect.DeepEqual(inbound.credentials, []string{"credential-a", "rotated-b"}) {
		t.Fatal("failed panel cache was dropped or successful panel update was lost")
	}
	if n.panels[0].etag != "first" || n.panels[1].etag != "second" {
		t.Fatal("ETags leaked between panel sources")
	}
	b.mu.Lock()
	b.users = nil
	b.mu.Unlock()
	n.syncUserList(context.Background())
	if !reflect.DeepEqual(inbound.names, []string{"1@a@uniproxy"}) {
		t.Fatal("successful empty source must revoke only that source's users")
	}
}

func TestMultiPanelRetriesLocalApplyAfterRemoteNotModified(t *testing.T) {
	a, b := newPanelFixture(t, "credential-a"), newPanelFixture(t, "credential-b")
	n, inbound := multiTestNode(t, a, b)
	if err := n.syncUserList(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.users[0].UUID, a.etag = "rotated-a", "second"
	a.mu.Unlock()
	inbound.updateError = errors.New("injected user update failure")
	if err := n.syncUserList(context.Background()); err == nil || !n.usersDirty {
		t.Fatal("failed local apply must preserve the pending panel cache")
	}
	a.mu.Lock()
	a.userStatus = http.StatusNotModified
	a.mu.Unlock()
	b.mu.Lock()
	b.userStatus = http.StatusNotModified
	b.mu.Unlock()
	inbound.updateError = nil
	if err := n.syncUserList(context.Background()); err != nil || n.usersDirty {
		t.Fatalf("304 responses prevented retrying a failed local update: %v", err)
	}
	if !reflect.DeepEqual(inbound.credentials, []string{"rotated-a", "credential-b"}) {
		t.Fatal("pending cached users were not committed")
	}
}

func addPanelDownload(n *node, user string, count int) {
	conn := n.traffic.TrackConnection(&trafficFixtureConn{}, adapter.InboundContext{User: user})
	conn.Write(make([]byte, count))
	conn.Close()
}

func TestMultiPanelTrafficAcknowledgesOnlySuccessfulSource(t *testing.T) {
	a, b := newPanelFixture(t, "credential-a"), newPanelFixture(t, "credential-b")
	n, _ := multiTestNode(t, a, b)
	if err := n.syncUserList(context.Background()); err != nil {
		t.Fatal(err)
	}
	const userA, userB = "1@a@uniproxy", "1@b@uniproxy"
	addPanelDownload(n, userA, 3)
	addPanelDownload(n, userB, 5)
	b.mu.Lock()
	b.pushStatus = http.StatusInternalServerError
	b.mu.Unlock()
	if err := n.pushTraffic(context.Background()); err == nil {
		t.Fatal("partial traffic failure was accepted")
	}
	snapshots := n.traffic.SnapshotTraffic([]string{userA, userB})
	if snapshots[0].DownlinkBytes != 0 || snapshots[1].DownlinkBytes != 5 {
		t.Fatal("failed panel's bytes were acknowledged or successful bytes were retained")
	}
	addPanelDownload(n, userB, 2)
	b.mu.Lock()
	b.pushStatus = http.StatusOK
	b.mu.Unlock()
	if err := n.pushTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(a.reports) != 1 || a.reports[0]["1"] != [2]int64{0, 3} ||
		len(b.reports) != 2 || b.reports[1]["1"] != [2]int64{0, 7} {
		t.Fatal("traffic crossed panel accounts, was duplicated, or was lost after retry")
	}
}

func TestMultiPanelUsesPrimaryConfigAndSuppressesAlive(t *testing.T) {
	a, b := newPanelFixture(t, "credential-a"), newPanelFixture(t, "credential-b")
	n, _ := multiTestNode(t, a, b)
	n.reportAlive = true
	if err := n.syncConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := n.pushAlive(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if a.requests["config"] != 1 || b.requests["config"] != 0 ||
		a.requests["alive"] != 0 || b.requests["alive"] != 0 {
		t.Fatal("multi node did not preserve the original primary/no-op reporting behavior")
	}
}

func TestDuplicatePanelTagReplacesUserSourceButRetainsPrimary(t *testing.T) {
	a, b := newPanelFixture(t, "credential-a"), newPanelFixture(t, "credential-b")
	primary, panels, err := createNodePanels(option.XBoardServiceOptions{
		Panels: []option.XBoardPanelOptions{a.options("same"), b.options("same")},
	}, "aggregate", "anytls")
	if err != nil || len(panels) != 1 || primary.client.options.APIHost != a.server.URL ||
		panels[0].client.options.APIHost != b.server.URL {
		t.Fatal("duplicate PanelTag did not preserve first-primary/last-user-source behavior")
	}
}
