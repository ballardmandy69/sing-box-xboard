package xboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInitialSyncRetriesEachPhaseWithoutReporting(t *testing.T) {
	for _, failingEndpoint := range []string{"user", "config"} {
		t.Run(failingEndpoint, func(t *testing.T) {
			var mutex sync.Mutex
			var calls []string
			failed := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mutex.Lock()
				defer mutex.Unlock()
				endpoint := strings.TrimPrefix(r.URL.Path, "/api/v1/server/UniProxy/")
				calls = append(calls, endpoint)
				if endpoint == failingEndpoint && !failed {
					failed = true
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if endpoint == "user" {
					w.Write([]byte(`{"users":[]}`))
				} else if endpoint == "config" {
					w.Write([]byte(`{}`))
				} else {
					t.Errorf("startup unexpectedly reported %s", endpoint)
				}
			}))
			defer server.Close()
			n := userSyncNode(server, "startup", &userSyncInbound{})
			n.reportAlive = true
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			started := time.Now()
			if !n.initialSync(ctx) {
				t.Fatal("a transient startup panel error prevented recovery")
			}
			if time.Since(started) < time.Second {
				t.Fatal("startup retried without the original initial backoff")
			}
			want := []string{"user", "user", "config"}
			if failingEndpoint == "config" {
				want = []string{"user", "config", "config"}
			}
			mutex.Lock()
			defer mutex.Unlock()
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("startup repeated successful phases or opened config before users: %v", calls)
			}
		})
	}
}

func TestInitialSyncRetryStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	n := userSyncNode(server, "cancel", &userSyncInbound{})
	calls := 0
	if n.retryInitial(ctx, "test", func(context.Context) error {
		calls++
		cancel()
		return errors.New("injected failure")
	}) || calls != 1 {
		t.Fatal("cancelled startup retried or reported success")
	}
}

func TestInitialConfigRejectsNotModifiedWithoutListener(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	n := userSyncNode(server, "cold", &userSyncInbound{})
	n.auto = &autoInbound{}
	if err := n.syncConfig(context.Background()); err == nil {
		t.Fatal("304 was accepted before any listener configuration had been applied")
	}
}
