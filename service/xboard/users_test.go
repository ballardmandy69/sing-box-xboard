package xboard

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/service/ssmapi"
)

// userSyncInbound records the separate identities and credentials supplied to a managed protocol.
// @author lyt
// @date 2026-10-29
type userSyncInbound struct {
	adapter.ManagedSSMServer
	names       []string
	credentials []string
	updateError error
}

func (i *userSyncInbound) UpdateUsers(names, credentials []string) error {
	if i.updateError != nil {
		return i.updateError
	}
	i.names = append([]string(nil), names...)
	i.credentials = append([]string(nil), credentials...)
	return nil
}

func userSyncNode(server *httptest.Server, tag string, inbound *userSyncInbound) *node {
	traffic := ssmapi.NewTrafficManager()
	return &node{
		service: &Service{logger: log.NewNOPFactory().Logger()},
		inbound: inbound, primary: fixturePanel(server, tag, "test-token"), nodeID: 1, nodeType: "anytls",
		traffic: traffic, control: usercontrol.NewManager(traffic),
		users: make(map[string]uint64), limits: make(map[string]usercontrol.Limits), trafficFactor: 1,
	}
}

func TestUserIdentitySurvivesCredentialRotation(t *testing.T) {
	credential := "credential-before"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/user" {
			t.Errorf("unexpected API path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(usersResponse{Users: []panelUser{{ID: 7, UUID: credential}}})
	}))
	defer server.Close()
	inbound := &userSyncInbound{}
	n := userSyncNode(server, "panel-a", inbound)
	if err := n.syncUserList(context.Background()); err != nil {
		t.Fatal(err)
	}
	const identity = "7@panel-a@uniproxy"
	if !reflect.DeepEqual(inbound.names, []string{identity}) || inbound.credentials[0] != credential {
		t.Fatal("accounting identity and authentication credential were conflated")
	}
	conn := n.traffic.TrackConnection(&trafficFixtureConn{reader: strings.NewReader("")},
		adapter.InboundContext{User: identity})
	conn.Write([]byte("before"))
	credential = "credential-after"
	if err := n.syncUserList(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("after"))
	conn.Close()
	if inbound.names[0] != identity || inbound.credentials[0] != credential || n.users[identity] != 7 {
		t.Fatal("rotating the credential changed the user's stable identity")
	}
	if got := n.traffic.SnapshotTraffic([]string{identity})[0].DownlinkBytes; got != 11 {
		t.Fatalf("credential rotation lost accounted bytes: %d", got)
	}
	otherInbound := &userSyncInbound{}
	other := userSyncNode(server, "panel-b", otherInbound)
	if err := other.syncUserList(context.Background()); err != nil {
		t.Fatal(err)
	}
	if otherInbound.names[0] == identity || otherInbound.credentials[0] != credential {
		t.Fatal("different panels must have independent identities without rewriting credentials")
	}
}

func TestUserSyncFailureRetainsPriorLimitsAndETag(t *testing.T) {
	response := usersResponse{Users: []panelUser{{ID: 9, UUID: "test-user", DeviceLimit: 2}}}
	etag := "first"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	inbound := &userSyncInbound{}
	n := userSyncNode(server, "test", inbound)
	if err := n.syncUserList(context.Background()); err != nil {
		t.Fatal(err)
	}
	identity := n.userName(9)
	inbound.updateError = errors.New("injected authentication update failure")
	response.Users[0].DeviceLimit, etag = 4, "second"
	if err := n.syncUserList(context.Background()); err == nil {
		t.Fatal("failed authentication update was accepted")
	}
	if n.userETag != "first" || n.limits[identity].IPLimit != 2 || n.users[identity] != 9 {
		t.Fatal("failed update changed the acknowledged user state")
	}
	inbound.updateError = nil
	response.Users = nil
	if err := n.syncUserList(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(inbound.names) != 0 || len(n.users) != 0 || len(n.limits) != 0 || n.userETag != "second" {
		t.Fatal("empty panel user list failed to revoke users")
	}
}

func TestUserIDPreservesUnsignedWidth(t *testing.T) {
	var report map[string][2]int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(usersResponse{Users: []panelUser{{ID: math.MaxUint64, UUID: "test-user"}}})
		} else {
			json.NewDecoder(r.Body).Decode(&report)
		}
	}))
	defer server.Close()
	inbound := &userSyncInbound{}
	n := userSyncNode(server, "max-id", inbound)
	if err := n.syncUserList(context.Background()); err != nil {
		t.Fatal(err)
	}
	const id = "18446744073709551615"
	if inbound.names[0] != id+"@max-id@uniproxy" {
		t.Fatal("uint64 panel user ID was truncated")
	}
	conn := n.traffic.TrackConnection(&trafficFixtureConn{}, adapter.InboundContext{User: inbound.names[0]})
	conn.Write([]byte("hello"))
	conn.Close()
	if err := n.pushTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	if report[id] != [2]int64{0, 5} {
		t.Fatal("traffic report lost the unsigned user ID")
	}
}
