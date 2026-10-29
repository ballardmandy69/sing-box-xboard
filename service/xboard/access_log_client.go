package xboard

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
)

// accessRecord preserves the case-sensitive JSON contract of the original SbApi.
// @author lyt
// @date 2026-10-29
type accessRecord struct {
	Time     int64
	Inbound  string
	Outbound string
	Uid      uint64
	Net      string
	Protocol string
	Src      string
	Dst      string
}

// accessLogClient sends only to the receiver explicitly configured by the operator.
// @author lyt
// @date 2026-10-29
type accessLogClient struct {
	endpoint   string
	token      string
	queryToken bool
	client     *http.Client
}

func newAccessLogClient(options *option.SbAPIOptions) (*accessLogClient, error) {
	if options == nil {
		return nil, nil
	}
	base, err := url.Parse(options.BaseURL)
	if err != nil || base.Host == "" || base.Scheme != "http" && base.Scheme != "https" ||
		base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("SbApi.BaseURL must be an HTTP(S) URL without credentials, query or fragment")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/accesslog/upload"
	base.RawPath = ""
	query := base.Query()
	query.Set("tag", options.Tag)
	if options.SendTokenInQuery {
		query.Set("token", options.Token)
	}
	base.RawQuery = query.Encode()
	return &accessLogClient{
		endpoint: base.String(), token: options.Token, queryToken: options.SendTokenInQuery,
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (c *accessLogClient) upload(ctx context.Context, records []accessRecord) error {
	if len(records) == 0 {
		return nil
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, reader)
	if err != nil {
		return errors.New("invalid SbApi access-log request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "gzip")
	if !c.queryToken {
		request.Header.Set("X-Api-Token", c.token)
	}
	go func() {
		compressor := gzip.NewWriter(writer)
		encodeErr := json.NewEncoder(compressor).Encode(records)
		closeErr := compressor.Close()
		_ = writer.CloseWithError(errors.Join(encodeErr, closeErr))
	}()
	response, err := c.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// net/http errors may contain the token-bearing query URL.
		return errors.New("SbApi access-log request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("SbApi access-log receiver returned HTTP %d", response.StatusCode)
	}
	return nil
}
