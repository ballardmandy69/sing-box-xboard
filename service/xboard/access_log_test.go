package xboard

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestAccessLogWireContract(t *testing.T) {
	for _, queryToken := range []bool{false, true} {
		t.Run(fmt.Sprint(queryToken), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/prefix/accesslog/upload" || r.URL.Query().Get("tag") != "a&b" {
					t.Errorf("wrong endpoint or tag: %s %s", r.Method, r.URL.Path)
				}
				if (r.URL.Query().Get("token") == "test-token") != queryToken ||
					(r.Header.Get("X-Api-Token") == "test-token") == queryToken {
					t.Error("token must use exactly the selected location")
				}
				if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "gzip" {
					t.Error("wrong access-log encoding")
				}
				reader, err := gzip.NewReader(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				defer reader.Close()
				var records []map[string]json.RawMessage
				if err = json.NewDecoder(reader).Decode(&records); err != nil || len(records) != 1 {
					t.Errorf("invalid records: %v", err)
					return
				}
				if len(records[0]) != 8 || string(records[0]["Uid"]) != "18446744073709551615" ||
					string(records[0]["Dst"]) != `"example.com:443"` || records[0]["Time"] == nil {
					t.Error("JSON casing, field count or uint64 identity changed")
				}
			}))
			defer server.Close()
			client, err := newAccessLogClient(&option.SbAPIOptions{
				BaseURL: server.URL + "/prefix/", Tag: "a&b", Token: "test-token", SendTokenInQuery: queryToken,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = client.upload(context.Background(), []accessRecord{{Uid: math.MaxUint64, Dst: "example.com:443"}}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAccessLogModesAndPrintShape(t *testing.T) {
	for mode := uint8(0); mode <= 2; mode++ {
		queue := newAccessLogQueue(mode, nil)
		printed := ""
		queue.print = func(values ...any) { printed = fmt.Sprintln(values...) }
		queue.put(accessRecord{Inbound: "in", Outbound: "out", Uid: 7, Net: "tcp", Protocol: "tls", Src: "src", Dst: "dst"})
		if (len(queue.records) == 1) != (mode != 2) {
			t.Fatalf("mode %d incorrectly captured access records", mode)
		}
		if mode == 1 && printed != "[Access] {in out 7 tcp tls src dst}\n" || mode != 1 && printed != "" {
			t.Fatalf("mode %d changed the print-only shape: %q", mode, printed)
		}
		if mode != 2 && queue.records[0].Time < time.Now().Add(-time.Minute).Unix() {
			t.Fatal("missing capture timestamp")
		}
		if err := queue.upload(context.Background()); err != nil || len(queue.records) != 0 {
			t.Fatal("a missing SbApi must still drain the queue")
		}
	}
}

func TestAccessLogRetriesSnapshotAndDiscardsFailedBatch(t *testing.T) {
	var requests atomic.Int32
	started, resume := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if requests.Add(1) == 1 {
			close(started)
			<-resume
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	client, _ := newAccessLogClient(&option.SbAPIOptions{BaseURL: server.URL})
	queue := newAccessLogQueue(0, client)
	var waits []time.Duration
	queue.wait = func(_ context.Context, delay time.Duration) error { waits = append(waits, delay); return nil }
	queue.put(accessRecord{Uid: 1})
	result := make(chan error, 1)
	go func() { result <- queue.upload(context.Background()) }()
	<-started
	queue.put(accessRecord{Uid: 2})
	close(resume)
	if err := <-result; err == nil || requests.Load() != 4 {
		t.Fatalf("201 must fail all four attempts: %v, %d", err, requests.Load())
	}
	if !reflect.DeepEqual(waits, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Fatalf("wrong backoff: %v", waits)
	}
	if len(queue.records) != 1 || queue.records[0].Uid != 2 {
		t.Fatal("inflight snapshot lost concurrent records or requeued the failed batch")
	}
}

type accessTestOutbound struct{ adapter.Outbound }

func (accessTestOutbound) Tag() string { return "exit" }

func TestAccessLogTrackerKeepsMetadataAndRequiresManagedIdentity(t *testing.T) {
	queue := newAccessLogQueue(0, nil)
	tracker := &accessLogTracker{queues: map[string]*accessLogQueue{"node": queue}}
	metadata := adapter.InboundContext{
		Inbound: "node", User: "18446744073709551615@panel@uniproxy", Network: "tcp", Protocol: "tls",
		Source: M.ParseSocksaddr("[2001:db8::1]:54321"), Destination: M.ParseSocksaddr("example.com:443"),
	}
	tracker.RoutedConnection(context.Background(), nil, metadata, nil, accessTestOutbound{})
	if len(queue.records) != 1 || queue.records[0].Uid != math.MaxUint64 ||
		queue.records[0].Src != "[2001:db8::1]:54321" || queue.records[0].Dst != "example.com:443" ||
		queue.records[0].Protocol != "tls" || queue.records[0].Outbound != "exit" {
		t.Fatal("routed metadata was changed")
	}
	metadata.User = "opaque-password"
	tracker.record(metadata, accessTestOutbound{})
	metadata.User = "invalid@panel@uniproxy"
	tracker.record(metadata, accessTestOutbound{})
	if len(queue.records) != 1 {
		t.Fatal("unauthenticated or malformed identities must not produce records")
	}
}

func TestAccessLogConcurrentCollection(t *testing.T) {
	queue := newAccessLogQueue(0, nil)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 50 {
				queue.put(accessRecord{Uid: 1})
			}
		})
	}
	workers.Wait()
	if len(queue.records) != 800 {
		t.Fatal("concurrent capture lost records")
	}
}

func TestAccessLogLoopIndependentOfTrafficUpload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		called <- struct{}{}
	}))
	defer server.Close()
	client, _ := newAccessLogClient(&option.SbAPIOptions{BaseURL: server.URL})
	queue := newAccessLogQueue(0, client)
	queue.put(accessRecord{Uid: 1})
	n := &node{service: &Service{logger: log.NewNOPFactory().Logger()}, disableUpload: true,
		accessLog: queue, syncInterval: 10 * time.Millisecond}
	done := make(chan struct{})
	go func() { n.accessLogLoop(ctx, n.syncInterval); close(done) }()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("DisableUploadTraffic suppressed the independent access-log timer")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("access-log worker ignored cancellation")
	}
}

func TestAccessLogErrorsDoNotExposeToken(t *testing.T) {
	client, _ := newAccessLogClient(&option.SbAPIOptions{
		BaseURL: "http://127.0.0.1:1", Token: "private-test-token", SendTokenInQuery: true,
	})
	err := client.upload(context.Background(), []accessRecord{{Uid: 1}})
	if err == nil || strings.Contains(err.Error(), "private-test-token") {
		t.Fatal("transport error exposed credentials or unexpectedly succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = waitAccessLogRetry(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal("retry did not stop promptly")
	}
	for _, base := range []string{"ftp://example.com", "http://u:p@example.com", "http://example.com?q=token", "http://example.com/#token"} {
		if _, err = newAccessLogClient(&option.SbAPIOptions{BaseURL: base}); err == nil {
			t.Fatalf("invalid base URL accepted: %s", base)
		}
	}
}
