package xboard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSSPanelRetriesTransportAndBodyFailures(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, mode := range []string{"transport", "exhausted", "body", "status", "ret", "invalid-json"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				t.Parallel()
				options := panelTestOptions()
				options.PanelType = "sspanel"
				client, err := newPanelClient(options)
				if err != nil {
					t.Fatal(err)
				}
				provider := client.provider.(*sspanelProvider)
				provider.etags["users"] = "cached-users"
				endpoint, expectedBody := "user", ""
				var input []byte
				if method == http.MethodPost {
					endpoint = "push"
					input = []byte(`{"1":[2,3]}`)
					expectedBody = `{"data":[{"user_id":1,"u":2,"d":3}]}`
				}
				calls := 0
				failedBody := new(failingPanelBody)
				client.client.Transport = panelTransportFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					var body []byte
					if request.Body != nil {
						body, err = io.ReadAll(request.Body)
						request.Body.Close()
						if err != nil {
							t.Fatal(err)
						}
					}
					if request.Method != method || string(body) != expectedBody {
						t.Error("SSPanel retry changed the method or encoded request body")
					}
					if method == http.MethodGet && request.Header.Get("If-None-Match") != "cached-users" {
						t.Error("SSPanel retry lost the provider's cached validator")
					}
					if mode == "exhausted" || mode == "transport" && calls < 4 {
						return nil, errors.New("private fixture transport error")
					}
					response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
						Body: io.NopCloser(strings.NewReader(`{"ret":1,"data":[]}`))}
					switch {
					case mode == "body" && calls == 1:
						response.Body = failedBody
						response.Header.Set("ETag", "incomplete-response")
					case mode == "status":
						response.StatusCode = http.StatusInternalServerError
					case mode == "ret":
						response.Body = io.NopCloser(strings.NewReader(`{"ret":0,"data":"private fixture"}`))
					case mode == "invalid-json":
						response.Body = io.NopCloser(strings.NewReader("private fixture invalid JSON"))
					}
					return response, nil
				})
				_, _, _, err = client.request(context.Background(), method, endpoint, "", input)
				wantCalls := map[string]int{"transport": 4, "exhausted": 4, "body": 2,
					"status": 1, "ret": 1, "invalid-json": 1}[mode]
				wantError := mode == "exhausted" || mode == "status" || mode == "ret" || mode == "invalid-json"
				if calls != wantCalls || (err != nil) != wantError {
					t.Fatalf("SSPanel retry boundary differs: calls=%d, error=%v", calls, err)
				}
				if mode == "body" && !failedBody.closed {
					t.Fatal("failed response body was not closed before retry")
				}
				if provider.etags["users"] != "cached-users" {
					t.Fatal("failed or empty-validator response changed the cached ETag")
				}
				if err != nil && strings.Contains(err.Error(), "private") {
					t.Fatal("SSPanel retry exposed private transport or response details")
				}
			})
		}
	}
}

func TestSSPanelRetryStopsOnCancellation(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			options := panelTestOptions()
			options.PanelType = "sspanel"
			client, err := newPanelClient(options)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			client.client.Transport = panelTransportFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Body != nil {
					request.Body.Close()
				}
				cancel()
				return nil, errors.New("fixture transport failure after cancellation")
			})
			endpoint := "user"
			var body []byte
			if method == http.MethodPost {
				endpoint, body = "push", []byte(`{"1":[2,3]}`)
			}
			_, _, _, err = client.request(ctx, method, endpoint, "", body)
			if calls != 1 || !errors.Is(err, context.Canceled) {
				t.Fatalf("SSPanel retried a canceled request: calls=%d, error=%v", calls, err)
			}
		})
	}
}
