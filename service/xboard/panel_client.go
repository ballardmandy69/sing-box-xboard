package xboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
)

// panelClient owns the HTTP configuration and identity namespace of one panel.
// @author lyt
// @date 2026-10-29
type panelClient struct {
	options  option.XBoardPanelOptions
	client   *http.Client
	provider panelProvider
}

type panelProvider interface {
	request(context.Context, *panelClient, string, string, string, []byte) ([]byte, int, string, error)
	decodeUsers([]byte) (usersResponse, error)
	identityTag() string
}

func newPanelClient(options option.XBoardPanelOptions) (*panelClient, error) {
	options.PanelType = strings.ToLower(options.PanelType)
	switch options.PanelType {
	case "", "uniproxy", "oldv2board", "ppanel":
	default:
		return nil, errors.New("unsupported panel_type")
	}
	if options.PanelType == "" {
		options.PanelType = "uniproxy"
	}
	options.APIHost = strings.TrimRight(strings.TrimSpace(options.APIHost), "/")
	baseURL, err := url.Parse(options.APIHost)
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "http" && baseURL.Scheme != "https") {
		return nil, errors.New("invalid panel api_host")
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("panel api_host must not contain credentials, query parameters, or a fragment")
	}
	if strings.TrimSpace(options.APIKey) == "" {
		return nil, errors.New("missing panel api_key")
	}
	if options.NodeID <= 0 {
		return nil, errors.New("invalid panel node_id")
	}
	options.NodeType = strings.ToLower(options.NodeType)
	timeout := time.Duration(options.Timeout)
	if timeout < time.Second {
		timeout = 10 * time.Second
	}
	result := &panelClient{
		options: options,
		client:  &http.Client{Timeout: timeout},
	}
	switch options.PanelType {
	case "oldv2board":
		result.provider, err = newOldV2BoardProvider(options.NodeType)
	case "ppanel":
		result.provider, err = newPPanelProvider(options.NodeType)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *panelClient) userName(id uint64) string {
	tag := "uniproxy"
	if p.provider != nil {
		tag = p.provider.identityTag()
	}
	return strconv.FormatUint(id, 10) + "@" + p.options.PanelTag + "@" + tag
}

func (p *panelClient) protocolType() string {
	if provider, ok := p.provider.(interface{ protocolType() string }); ok {
		return provider.protocolType()
	}
	return p.options.NodeType
}

func (p *panelClient) decodeUsers(body []byte) (usersResponse, error) {
	if p.provider != nil {
		return p.provider.decodeUsers(body)
	}
	var response usersResponse
	err := json.Unmarshal(body, &response)
	return response, err
}

func (p *panelClient) request(
	ctx context.Context, method string, endpoint string, etag string, body []byte,
) ([]byte, int, string, error) {
	if p.provider != nil {
		return p.provider.request(ctx, p, method, endpoint, etag, body)
	}
	requestURL, err := url.Parse(p.options.APIHost + "/api/v1/server/UniProxy/" + endpoint)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid xboard %s request URL", endpoint)
	}
	query := requestURL.Query()
	query.Set("token", p.options.APIKey)
	query.Set("node_id", strconv.Itoa(p.options.NodeID))
	query.Set("node_type", p.options.NodeType)
	requestURL.RawQuery = query.Encode()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), reader)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid xboard %s request", endpoint)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	return p.doRequest(request, endpoint)
}

func (p *panelClient) doRequest(request *http.Request, endpoint string) ([]byte, int, string, error) {
	retries := 0
	if p.options.PanelType == "oldv2board" || p.options.PanelType == "ppanel" {
		// Both original constructors set Resty's RetryCount to three. HTTP status
		// and panel JSON validation happen after Backoff and do not trigger retries.
		retries = 3
	}
	for attempt := 0; ; attempt++ {
		body, status, etag, retry, err := p.doRequestOnce(request, endpoint)
		if err == nil || !retry || attempt >= retries || request.Context().Err() != nil {
			return body, status, etag, err
		}
		if request.Body != nil {
			if request.GetBody == nil {
				return body, status, etag, err
			}
			request = request.Clone(request.Context())
			request.Body, err = request.GetBody()
			if err != nil {
				return nil, status, "", fmt.Errorf("rebuild xboard %s request failed", endpoint)
			}
		}
		if err = waitPanelRetry(request.Context(), panelRetryDelay(attempt)); err != nil {
			if request.Body != nil {
				request.Body.Close()
			}
			return nil, status, "", fmt.Errorf("xboard %s request: %w", endpoint, err)
		}
	}
}

func panelRetryDelay(attempt int) time.Duration {
	// Callers use only attempts 0..2; the original exponential backoff is capped at 2 s.
	half := min(2*time.Second, 100*time.Millisecond<<attempt) / 2
	return max(100*time.Millisecond, half+time.Duration(rand.Int64N(int64(half))))
}

func waitPanelRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *panelClient) doRequestOnce(request *http.Request, endpoint string) ([]byte, int, string, bool, error) {
	ctx := request.Context()
	response, err := p.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, "", false, fmt.Errorf("xboard %s request: %w", endpoint, ctx.Err())
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return nil, 0, "", true, fmt.Errorf("xboard %s request timed out", endpoint)
		}
		return nil, 0, "", true, fmt.Errorf("xboard %s request failed", endpoint)
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if readErr != nil {
		return nil, response.StatusCode, "", true, fmt.Errorf("read xboard %s response failed", endpoint)
	}
	if len(responseBody) > 16<<20 {
		return nil, response.StatusCode, "", false, fmt.Errorf("xboard %s response exceeds size limit", endpoint)
	}
	if !successfulStatus(response.StatusCode) && response.StatusCode != http.StatusNotModified {
		return nil, response.StatusCode, "", false, fmt.Errorf("xboard %s HTTP status: %d", endpoint, response.StatusCode)
	}
	return responseBody, response.StatusCode, response.Header.Get("ETag"), false, nil
}
