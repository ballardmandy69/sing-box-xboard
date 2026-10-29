package rule

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

const (
	legacyGeoIPDownloadURL   = "https://github.com/soffchen/sing-geoip/releases/latest/download/geoip.db"
	legacyGeositeDownloadURL = "https://github.com/soffchen/sing-geosite/releases/latest/download/geosite.db"
)

func (s *LegacyGeoStore) prepareDatabase(kind string, path string, downloadURL string, detour string) (string, error) {
	if path == "" {
		path, _ = C.FindPath(kind + ".db")
	}
	if _, err := os.Stat(path); err != nil {
		path = filemanager.BasePath(s.ctx, path)
	}
	info, err := os.Stat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return "", E.New(kind, " database path is not a regular file: ", path)
		}
		if info.Size() > 0 {
			return path, nil
		}
		if err = os.Remove(path); err != nil {
			return "", E.Cause(err, "remove empty ", kind, " database")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", E.Cause(err, "stat ", kind, " database")
	}
	if downloadURL == "" {
		if kind == "geoip" {
			downloadURL = legacyGeoIPDownloadURL
		} else {
			downloadURL = legacyGeositeDownloadURL
		}
	}
	manager := service.FromContext[adapter.OutboundManager](s.ctx)
	if manager == nil {
		return "", E.New(kind, " database is missing and its download outbound manager is unavailable: ", path)
	}
	outbound := manager.Default()
	if detour != "" {
		var found bool
		outbound, found = manager.Outbound(detour)
		if !found {
			return "", E.New(kind, " database download outbound not found: ", detour)
		}
	}
	if outbound == nil {
		return "", E.New(kind, " database download has no default outbound")
	}
	for attempt := 1; attempt <= 3; attempt++ {
		s.logger.Info("download legacy ", kind, " database, attempt ", attempt)
		err = s.downloadDatabase(path, downloadURL, outbound)
		if err == nil {
			return path, nil
		}
		if s.ctx.Err() != nil {
			return "", s.ctx.Err()
		}
		s.logger.Warn(E.Cause(err, "download legacy ", kind, " database, attempt ", attempt))
	}
	return "", E.Cause(err, "download legacy ", kind, " database after 3 attempts")
}

func (s *LegacyGeoStore) downloadDatabase(path string, downloadURL string, outbound adapter.Outbound) error {
	transport := &http.Transport{
		TLSHandshakeTimeout: 5 * time.Second,
		ForceAttemptHTTP2:   true,
		DialContext: func(ctx context.Context, _ string, address string) (net.Conn, error) {
			return outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
		},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(s.ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return E.New("unexpected HTTP status: ", response.Status)
	}
	if err = filemanager.MkdirAll(s.ctx, filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	_, copyErr := io.Copy(temporary, response.Body)
	closeErr := temporary.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err = filemanager.Chown(s.ctx, temporary.Name()); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
