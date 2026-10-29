package xboard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// failingPanelBody reproduces a truncated response after successful HTTP headers.
// @author lyt
// @date 2026-10-29
type failingPanelBody struct{ closed bool }

func (*failingPanelBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (b *failingPanelBody) Close() error           { b.closed = true; return nil }

func TestLegacyPanelRetriesTransportAndBodyFailures(t *testing.T) {
	for _, provider := range []string{"oldv2board", "ppanel"} {
		for _, mode := range []string{"transport", "exhausted", "body", "status", "invalid-json"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				options := panelTestOptions()
				options.PanelType, options.NodeType = provider, "v2ray"
				client, err := newPanelClient(options)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				var expectedBody string
				failedBody := new(failingPanelBody)
				client.client.Transport = panelTransportFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					body, _ := io.ReadAll(r.Body)
					r.Body.Close()
					if calls == 1 {
						expectedBody = string(body)
					}
					if len(body) == 0 || string(body) != expectedBody || r.Method != http.MethodPost {
						t.Error("retry lost the original JSON POST body")
					}
					if mode == "exhausted" || mode == "transport" && calls < 3 {
						return nil, errors.New("private panel URL/token")
					}
					response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{},
						Body: io.NopCloser(strings.NewReader(`{}`))}
					switch {
					case mode == "body" && calls == 1:
						response.Body = failedBody
					case mode == "status":
						response.StatusCode = http.StatusInternalServerError
					case mode == "invalid-json":
						response.Body = io.NopCloser(strings.NewReader("private invalid JSON"))
					}
					return response, nil
				})
				body, _, _, err := client.request(context.Background(), http.MethodPost, "push", "",
					[]byte(`{"1":[2,3]}`))
				if mode == "invalid-json" && err == nil {
					_, err = client.decodeUsers(body)
				}
				wantCalls := map[string]int{"transport": 3, "exhausted": 4, "body": 2,
					"status": 1, "invalid-json": 1}[mode]
				wantError := mode == "exhausted" || mode == "status" || mode == "invalid-json"
				if calls != wantCalls || (err != nil) != wantError {
					t.Fatalf("retry boundary differs: calls=%d error=%v", calls, err)
				}
				if mode == "body" && !failedBody.closed {
					t.Fatal("failed response body leaked across retry")
				}
				if err != nil && strings.Contains(err.Error(), "private") {
					t.Fatal("retry exposed private response or transport details")
				}
			})
		}
	}
}

func TestLegacyPanelRetryDelayAndCancellation(t *testing.T) {
	for attempt, bounds := range [][2]time.Duration{
		{100 * time.Millisecond, 100 * time.Millisecond},
		{100 * time.Millisecond, 200*time.Millisecond - 1},
		{200 * time.Millisecond, 400*time.Millisecond - 1},
	} {
		for sample := 0; sample < 100; sample++ {
			if got := panelRetryDelay(attempt); got < bounds[0] || got > bounds[1] {
				t.Fatalf("attempt %d delay outside original bounds: %v", attempt, got)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitPanelRetry(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation did not interrupt the retry wait")
	}
}
