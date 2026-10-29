package xboard

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/service/ssmapi"
)

type hotUserFixture struct {
	callback func(string)
	names    []string
}

func (f *hotUserFixture) UpdateHotUsers(names []string)            { f.names = slices.Clone(names) }
func (f *hotUserFixture) SetHotUserCallback(callback func(string)) { f.callback = callback }

func TestHotUserExpirationBoundaryAndCallback(t *testing.T) {
	manager := &hotUserFixture{}
	hot := newHotUsers(manager, 600*time.Second)
	now := time.Unix(1000, 0)
	hot.now = func() time.Time { return now }
	manager.callback("alice")
	now = now.Add(600 * time.Second)
	hot.refresh(nil)
	if !reflect.DeepEqual(manager.names, []string{"alice"}) {
		t.Fatal("expiry equal to now must remain hot")
	}
	now = now.Add(time.Nanosecond)
	manager.callback("bob")
	if !reflect.DeepEqual(manager.names, []string{"alice", "bob"}) {
		t.Fatal("authentication callback unexpectedly pruned expired candidates")
	}
	hot.refresh([]*ssmapi.UserTrafficSnapshot{{UserName: "zero"}, {UserName: "active", DownlinkBytes: 1}})
	if !reflect.DeepEqual(manager.names, []string{"active", "bob"}) {
		t.Fatal("traffic maintenance did not prune then refresh only active identities")
	}
}

func TestHotUserTrafficMaintenanceBeforeReportAndDisable(t *testing.T) {
	manager := &hotUserFixture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !reflect.DeepEqual(manager.names, []string{"alice"}) {
			t.Error("traffic was reported before hot candidates were published")
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	n := trafficTestNode(server)
	n.hotUsers = newHotUsers(manager, time.Minute)
	now := time.Unix(1000, 0)
	n.hotUsers.now = func() time.Time { return now }
	addFixtureTraffic(t, n, 1, 0)
	if err := n.pushTraffic(context.Background()); err == nil || len(n.hotUsers.expires) != 1 {
		t.Fatal("failed traffic upload must still refresh the active authentication candidate")
	}
	now = now.Add(time.Hour)
	n.disableUpload = true
	if err := n.pushTraffic(context.Background()); err != nil || len(n.hotUsers.expires) != 1 {
		t.Fatal("DisableUploadTraffic must skip hot-user maintenance too")
	}
	n.disableUpload = false
	n.users = nil
	if err := n.pushTraffic(context.Background()); err != nil || len(n.hotUsers.expires) != 0 {
		t.Fatal("an empty user list must still prune expired candidates")
	}
}

func TestHotUserConcurrentCallbacksAndRefresh(t *testing.T) {
	manager := &hotUserFixture{}
	hot := newHotUsers(manager, time.Minute)
	var workers sync.WaitGroup
	for i := range 32 {
		workers.Go(func() { manager.callback(fmt.Sprint(i)); hot.refresh(nil) })
	}
	workers.Wait()
	if len(manager.names) != 32 {
		t.Fatal("concurrent callback publication lost candidates")
	}
}

func TestHotUserTTLDefaultsAndOverflow(t *testing.T) {
	for _, value := range []int64{-1, 0} {
		if ttl, err := hotUserTTL(value); err != nil || ttl != 600*time.Second {
			t.Fatal("non-positive HotUserCacheSec must retain the original 600-second default")
		}
	}
	if ttl, err := hotUserTTL(42); err != nil || ttl != 42*time.Second {
		t.Fatal("explicit hot-user lifetime changed")
	}
	if _, err := hotUserTTL(math.MaxInt64); err == nil {
		t.Fatal("overflow must not silently expire every hot user")
	}
}
