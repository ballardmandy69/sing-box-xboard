package box

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestDebugConnectionGrouping(t *testing.T) {
	entries := []usercontrol.Registration{
		{Type: "b", SourceIP: "two", UserLabel: "same", Traffic: 5},
		{Type: "a", SourceIP: "two", UserLabel: "same", Traffic: 999},
		{Type: "a", SourceIP: "one", UserLabel: "same", Traffic: -1},
		{Type: "a", SourceIP: "z", UserLabel: "first", Traffic: 7},
		{Type: "b", SourceIP: "two", UserLabel: "same", Traffic: 3},
		{},
	}
	result := groupDebugConnections(entries, 100)
	if result.Registrations != 6 || len(result.Groups) != 5 {
		t.Fatalf("unexpected totals: %+v", result)
	}
	want := []debugConnectionGroup{
		{debugConnectionKey{"b", "two", "same"}, 2, 8},
		{debugConnectionKey{}, 1, 0},
		{debugConnectionKey{"a", "z", "first"}, 1, 7},
		{debugConnectionKey{"a", "one", "same"}, 1, -1},
		{debugConnectionKey{"a", "two", "same"}, 1, 999},
	}
	if !reflect.DeepEqual(result.Groups, want) {
		t.Fatalf("groups=%+v, want %+v", result.Groups, want)
	}
	for _, top := range []int{0, 1, 3, 99, -1} {
		limited := groupDebugConnections(entries, top)
		count := 5
		if top >= 0 && top < count {
			count = top
		}
		if len(limited.Groups) != count || limited.Registrations != len(entries) {
			t.Fatalf("top=%d: %+v", top, limited)
		}
	}
	encoded, err := json.Marshal(groupDebugConnections(nil, 0))
	if err != nil || string(encoded) != `{"registrations":0,"groups":[]}` {
		t.Fatalf("empty result: %s, %v", encoded, err)
	}
}

func TestDebugHTTPMemoryAndRoutes(t *testing.T) {
	handler := newDebugHTTPHandler(context.Background())
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/debug/gc", http.StatusNoContent},
		{http.MethodPost, "/debug/gc", http.StatusMethodNotAllowed},
		{http.MethodGet, "/debug/memory", http.StatusOK},
		{http.MethodPost, "/debug/memory", http.StatusMethodNotAllowed},
		{http.MethodGet, "/debug/connections?top=0", http.StatusOK},
		{http.MethodGet, "/debug/pprof", http.StatusOK},
		{http.MethodGet, "/debug/pprof/", http.StatusOK},
		{http.MethodGet, "/debug/pprof/cmdline", http.StatusOK},
		{http.MethodGet, "/debug/pprof/symbol", http.StatusOK},
		{http.MethodPost, "/debug/pprof/symbol", http.StatusOK},
		{http.MethodGet, "/debug/pprof/absent-profile", http.StatusNotFound},
		{http.MethodGet, "/sb/debug/users?tag=missing", http.StatusOK},
		{http.MethodPost, "/sb/debug/users", http.StatusMethodNotAllowed},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			if response.Code != test.status {
				t.Fatalf("status=%d, want %d", response.Code, test.status)
			}
			if test.path == "/debug/memory" && test.method == http.MethodGet {
				var result map[string]any
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if len(result) != 6 {
					t.Fatalf("unexpected memory fields: %v", result)
				}
				previous := -1
				for _, key := range []string{"heap", "stack", "idle", "goroutines", "rss", "maxRss"} {
					position := strings.Index(response.Body.String(), `"`+key+`"`)
					if position <= previous {
						t.Fatalf("field order: %s", response.Body.String())
					}
					previous = position
				}
				for _, key := range []string{"heap", "stack", "idle"} {
					value, ok := result[key].(string)
					if !ok || !strings.Contains(value, "B") {
						t.Fatalf("%s must be an IEC byte string: %v", key, result[key])
					}
				}
				for _, key := range []string{"goroutines", "rss", "maxRss"} {
					if _, ok := result[key].(float64); !ok {
						t.Fatalf("%s must be numeric", key)
					}
				}
			}
			if strings.HasPrefix(test.path, "/debug/connections") {
				if response.Header().Get("Content-Type") != "application/json" ||
					response.Body.String() != "{\n  \"registrations\": 0,\n  \"groups\": []\n}\n" {
					t.Fatalf("connection wire response: %v %q", response.Header(), response.Body.String())
				}
			}
		})
	}
}

func TestDebugCurrentRSSParser(t *testing.T) {
	for _, test := range []struct {
		input string
		want  float64
	}{
		{"1000 256 0 0 0 0 0\n", 1},
		{"1000\t128\n", .5},
		{"", 0},
		{"1000", 0},
		{"1000 -1", 0},
		{"1000 invalid", 0},
		{"1000 18446744073709551616", 0},
	} {
		if got := parseCurrentRSS([]byte(test.input), 4096); got != test.want {
			t.Fatalf("%q: %v, want %v", test.input, got, test.want)
		}
	}
}

func TestDebugHTTPTopUsesSharedRegistrations(t *testing.T) {
	cleaner, err := usercontrol.NewConnectionCleaner(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleaner.Close() })
	for index := range 102 {
		server, client := net.Pipe()
		tracked := cleaner.RoutedConnection(context.Background(), server, adapter.InboundContext{
			User: fmt.Sprintf("user-%03d", index), Source: M.ParseSocksaddr("192.0.2.1:1234"),
		}, nil, nil)
		cleaner.UpdateMetadata(tracked, "tcp-routed", "192.0.2.1", fmt.Sprintf("user-%03d", index))
		t.Cleanup(func() { tracked.Close(); client.Close() })
	}
	ctx := service.ContextWithPtr(context.Background(), cleaner)
	handler := newDebugHTTPHandler(ctx)
	for _, test := range []struct {
		query string
		count int
	}{
		{"", 100}, {"top=", 100}, {"top=wrong", 100}, {"top=-1", 100},
		{"top=18446744073709551616", 100}, {"top=0", 0}, {"top=1", 1},
		{"top=101", 101}, {"top=999", 102}, {"top=1&top=99", 1},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/debug/connections?"+test.query, nil))
		var result debugConnections
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Registrations != 102 || len(result.Groups) != test.count {
			t.Fatalf("query=%q: total=%d groups=%d", test.query, result.Registrations, len(result.Groups))
		}
		if test.count > 0 && (result.Groups[0].UserLabel != "user-000" || result.Groups[0].SourceIP != "192.0.2.1") {
			t.Fatalf("metadata from shared registry missing: %+v", result.Groups[0])
		}
	}
}

type debugTestServices struct {
	adapter.ServiceManager
	items []adapter.Service
}

func (s debugTestServices) Services() []adapter.Service { return s.items }

type debugTestProvider struct {
	adapter.Service
	tag   string
	users map[string]time.Time
}

func (p debugTestProvider) DebugHotUsers(tag string) (map[string]time.Time, bool) {
	return p.users, tag == p.tag
}

func TestDebugHTTPUsers(t *testing.T) {
	expires := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	provider := debugTestProvider{tag: "primary", users: map[string]time.Time{"7@test@uniproxy": expires}}
	for _, test := range []struct {
		name  string
		items []adapter.Service
		query string
		want  string
	}{
		{"no provider", nil, "tag=primary", ""},
		{"unknown", []adapter.Service{provider}, "tag=missing", "wrong tag"},
		{"missing", []adapter.Service{provider}, "", "wrong tag"},
		{"first query", []adapter.Service{provider}, "tag=primary&tag=missing",
			`{"7@test@uniproxy":"2026-10-29T12:00:00Z"}`},
		{"empty map", []adapter.Service{debugTestProvider{tag: "", users: map[string]time.Time{}}}, "", `{}`},
		{"later provider", []adapter.Service{debugTestProvider{tag: "another"}, provider}, "tag=primary",
			`{"7@test@uniproxy":"2026-10-29T12:00:00Z"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := service.ContextWith[adapter.ServiceManager](context.Background(), debugTestServices{items: test.items})
			response := httptest.NewRecorder()
			newDebugHTTPHandler(ctx).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/sb/debug/users?"+test.query, nil))
			if response.Code != http.StatusOK || response.Body.String() != test.want {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func TestDebugHTTPListenFailure(t *testing.T) {
	server, err := startDebugHTTPServer(context.Background(), option.DebugOptions{})
	if err != nil || server != nil {
		t.Fatalf("disabled listener: %v, %v", server, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, err = startDebugHTTPServer(context.Background(), option.DebugOptions{Listen: listener.Addr().String()})
	if err == nil || server != nil {
		t.Fatalf("occupied address must fail: %v, %v", server, err)
	}
}
