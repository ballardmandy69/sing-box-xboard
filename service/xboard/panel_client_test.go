package xboard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// panelTransportFunc provides deterministic panel responses without external requests.
// @author lyt
// @date 2026-10-29
type panelTransportFunc func(*http.Request) (*http.Response, error)

func (f panelTransportFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func panelTestOptions() option.XBoardPanelOptions {
	return option.XBoardPanelOptions{
		PanelTag: "source-a",
		APIHost:  "https://panel.example.invalid",
		APIKey:   "test-key&with=special",
		NodeID:   7,
		NodeType: "AnyTLS",
	}
}

func TestPanelClientConfiguration(t *testing.T) {
	for _, timeout := range []time.Duration{-time.Second, 0, time.Second - 1, time.Second, 15 * time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			options := panelTestOptions()
			options.PanelType = "UniProxy"
			options.Timeout = badoption.Duration(timeout)
			options.APIHost += "///"
			client, err := newPanelClient(options)
			if err != nil {
				t.Fatal(err)
			}
			expectedTimeout := timeout
			if timeout < time.Second {
				expectedTimeout = 10 * time.Second
			}
			if client.client.Timeout != expectedTimeout || client.options.NodeType != "anytls" ||
				client.options.PanelType != "uniproxy" || strings.HasSuffix(client.options.APIHost, "/") {
				t.Fatal("panel configuration was not normalized")
			}
			if name := client.userName(18446744073709551615); name != "18446744073709551615@source-a@uniproxy" {
				t.Fatalf("unexpected identity: %s", name)
			}
		})
	}
}

func TestPanelClientRejectsUnsupportedConfiguration(t *testing.T) {
	for _, panelType := range []string{"sspanel", "multi", "unknown"} {
		t.Run(panelType, func(t *testing.T) {
			options := panelTestOptions()
			options.PanelType = panelType
			if _, err := newPanelClient(options); err == nil {
				t.Fatal("unsupported provider accepted")
			}
		})
	}
	for _, host := range []string{"", "://invalid", "file:///tmp/panel", "https://user:secret@example.invalid",
		"https://example.invalid?token=secret", "https://example.invalid#secret"} {
		options := panelTestOptions()
		options.APIHost = host
		_, err := newPanelClient(options)
		if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), host) && host != "" {
			t.Fatal("invalid api_host was accepted or exposed in an error")
		}
	}
	options := panelTestOptions()
	options.APIKey = " "
	if _, err := newPanelClient(options); err == nil {
		t.Fatal("missing API key accepted")
	}
	options = panelTestOptions()
	options.NodeID = 0
	if _, err := newPanelClient(options); err == nil {
		t.Fatal("invalid node ID accepted")
	}
}

func TestPanelClientUniProxyWireContract(t *testing.T) {
	options := panelTestOptions()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/prefix/api/v1/server/UniProxy/alive" || request.Method != http.MethodPost {
			t.Errorf("unexpected method/path: %s %s", request.Method, request.URL.Path)
		}
		query := request.URL.Query()
		if len(query) != 3 || query.Get("token") != options.APIKey || query.Get("node_id") != "7" ||
			query.Get("node_type") != "anytls" {
			t.Error("query authentication or node selector differs")
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("If-None-Match") != `"revision-1"` ||
			request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
			t.Error("unexpected panel headers")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || string(body) != "{}" {
			t.Error("empty online map was changed")
		}
		w.Header().Set("ETag", `"revision-2"`)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	options.APIHost = server.URL + "/prefix/"
	client, err := newPanelClient(options)
	if err != nil {
		t.Fatal(err)
	}
	body, status, etag, err := client.request(context.Background(), http.MethodPost, "alive", `"revision-1"`, []byte("{}"))
	if err != nil || status != http.StatusNoContent || len(body) != 0 || etag != `"revision-2"` {
		t.Fatalf("unexpected panel response: status=%d, etag=%s, error=%v", status, etag, err)
	}
}

func TestPanelClientHTTPStatusAndEmptyNodeType(t *testing.T) {
	for _, status := range []int{200, 201, 204, 299, 304, 400, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			options := panelTestOptions()
			options.NodeType = ""
			client, err := newPanelClient(options)
			if err != nil {
				t.Fatal(err)
			}
			client.client.Transport = panelTransportFunc(func(request *http.Request) (*http.Response, error) {
				if !request.URL.Query().Has("node_type") || request.Header.Get("Content-Type") != "" {
					t.Error("GET query/headers differ from the panel contract")
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
			})
			_, actualStatus, _, err := client.request(context.Background(), http.MethodGet, "user", "", nil)
			accepted := status >= 200 && status < 300 || status == 304
			if actualStatus != status || (err == nil) != accepted {
				t.Fatalf("status=%d, accepted=%v, error=%v", actualStatus, accepted, err)
			}
		})
	}
}

func TestPanelClientResponseSizeLimit(t *testing.T) {
	for _, size := range []int{16 << 20, (16 << 20) + 1} {
		client, err := newPanelClient(panelTestOptions())
		if err != nil {
			t.Fatal(err)
		}
		client.client.Transport = panelTransportFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", size))),
				Header:     http.Header{},
			}, nil
		})
		body, _, _, err := client.request(context.Background(), http.MethodGet, "user", "", nil)
		if size == 16<<20 && (err != nil || len(body) != size) {
			t.Fatalf("valid response rejected: %v", err)
		}
		if size > 16<<20 && (err == nil || body != nil) {
			t.Fatal("oversized response accepted")
		}
	}
}

func TestPanelClientErrorsDoNotExposeCredentials(t *testing.T) {
	client, err := newPanelClient(panelTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	client.client.Transport = panelTransportFunc(func(request *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("network failed at %s", request.URL)
	})
	_, _, _, err = client.request(context.Background(), http.MethodGet, "config", "", nil)
	if err == nil || strings.Contains(err.Error(), "example.invalid") || strings.Contains(err.Error(), "test-key") {
		t.Fatal("network error exposed the URL or token")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = client.request(ctx, http.MethodGet, "user", "", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not preserved: %v", err)
	}
}
