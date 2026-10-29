package xboard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	options option.XBoardPanelOptions
	client  *http.Client
}

func newPanelClient(options option.XBoardPanelOptions) (*panelClient, error) {
	options.PanelType = strings.ToLower(options.PanelType)
	if options.PanelType != "" && options.PanelType != "uniproxy" {
		return nil, errors.New("unsupported panel_type: only uniproxy is implemented")
	}
	options.PanelType = "uniproxy"
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
	return &panelClient{
		options: options,
		client:  &http.Client{Timeout: timeout},
	}, nil
}

func (p *panelClient) userName(id uint64) string {
	return strconv.FormatUint(id, 10) + "@" + p.options.PanelTag + "@uniproxy"
}

func (p *panelClient) request(
	ctx context.Context, method string, endpoint string, etag string, body []byte,
) ([]byte, int, string, error) {
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
	response, err := p.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, "", fmt.Errorf("xboard %s request: %w", endpoint, ctx.Err())
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return nil, 0, "", fmt.Errorf("xboard %s request timed out", endpoint)
		}
		return nil, 0, "", fmt.Errorf("xboard %s request failed", endpoint)
	}
	defer response.Body.Close()
	if !successfulStatus(response.StatusCode) && response.StatusCode != http.StatusNotModified {
		return nil, response.StatusCode, "", fmt.Errorf("xboard %s HTTP status: %d", endpoint, response.StatusCode)
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if readErr != nil {
		return nil, response.StatusCode, "", fmt.Errorf("read xboard %s response failed", endpoint)
	}
	if len(responseBody) > 16<<20 {
		return nil, response.StatusCode, "", fmt.Errorf("xboard %s response exceeds size limit", endpoint)
	}
	return responseBody, response.StatusCode, response.Header.Get("ETag"), nil
}
