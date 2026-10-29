package rule

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type legacyGeoTestOutbound struct {
	adapter.Outbound
	calls atomic.Int32
}

func (o *legacyGeoTestOutbound) DialContext(
	ctx context.Context, network string, destination M.Socksaddr,
) (net.Conn, error) {
	o.calls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

type legacyGeoTestOutboundManager struct {
	adapter.OutboundManager
	defaultOutbound adapter.Outbound
	download        adapter.Outbound
}

func (m *legacyGeoTestOutboundManager) Default() adapter.Outbound {
	return m.defaultOutbound
}

func (m *legacyGeoTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.download, tag == "download" && m.download != nil
}

func TestLegacyGeoDownload(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "legacy-geo", "geoip-a.db"))
	require.NoError(t, err)
	for _, emptyFile := range []bool{false, true} {
		name := "missing"
		if emptyFile {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) < 3 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_, _ = w.Write(fixture)
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "nested", "geoip.db")
			if emptyFile {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.WriteFile(path, nil, 0o600))
			}
			ctx, store := legacyGeoTestStore(t, option.RouteOptions{GeoIP: &option.GeoIPOptions{
				Path: path, DownloadURL: server.URL, DownloadDetour: "download",
			}})
			defaultOutbound, downloadOutbound := &legacyGeoTestOutbound{}, &legacyGeoTestOutbound{}
			service.MustRegister[adapter.OutboundManager](ctx, &legacyGeoTestOutboundManager{
				defaultOutbound: defaultOutbound, download: downloadOutbound,
			})
			rule := legacyGeoTestRule(t, ctx, `{"geoip":["aa"]}`)
			require.NoError(t, store.Reload())
			require.EqualValues(t, 3, requests.Load())
			require.EqualValues(t, 3, downloadOutbound.calls.Load())
			require.Zero(t, defaultOutbound.calls.Load(), "explicit detour must override the default outbound")
			metadata := adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("1.1.1.1", 443)}
			require.True(t, rule.Match(&metadata), "downloaded content is parsed as a real GeoIP database")
			require.NoError(t, store.Reload())
			require.EqualValues(t, 3, requests.Load(), "existing nonempty file must not be downloaded again")
			files, globErr := filepath.Glob(filepath.Join(filepath.Dir(path), ".geoip.db-*"))
			require.NoError(t, globErr)
			require.Empty(t, files, "temporary download files are removed")
			require.NoError(t, store.Close())
			require.NoError(t, os.Remove(path), "closing releases the memory-mapped database")
		})
	}
}

func TestLegacyGeoDownloadFailure(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "geoip.db")
	ctx, store := legacyGeoTestStore(t, option.RouteOptions{GeoIP: &option.GeoIPOptions{
		Path: path, DownloadURL: server.URL,
	}})
	outbound := &legacyGeoTestOutbound{}
	service.MustRegister[adapter.OutboundManager](ctx, &legacyGeoTestOutboundManager{defaultOutbound: outbound})
	legacyGeoTestRule(t, ctx, `{"geoip":["aa"]}`)
	require.ErrorContains(t, store.Reload(), "after 3 attempts")
	require.EqualValues(t, 3, requests.Load())
	require.EqualValues(t, 3, outbound.calls.Load(), "omitted detour uses the configured default outbound")
	_, err := os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	store.geoIPOptions.DownloadDetour = "missing"
	require.ErrorContains(t, store.Reload(), "outbound not found")
	require.EqualValues(t, 3, requests.Load(), "an unknown detour must not silently use direct")
}

func TestLegacyGeoDownloadInvalidDatabase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not a database"))
	}))
	defer server.Close()
	for _, kind := range []string{"geoip", "geosite"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), kind+".db")
			var options option.RouteOptions
			if kind == "geoip" {
				options.GeoIP = &option.GeoIPOptions{Path: path, DownloadURL: server.URL}
			} else {
				options.Geosite = &option.GeositeOptions{Path: path, DownloadURL: server.URL}
			}
			ctx, store := legacyGeoTestStore(t, options)
			service.MustRegister[adapter.OutboundManager](ctx, &legacyGeoTestOutboundManager{
				defaultOutbound: &legacyGeoTestOutbound{},
			})
			legacyGeoTestRule(t, ctx, `{"`+kind+`":["aa"]}`)
			require.Error(t, store.Reload(), "HTTP 200 is not sufficient to accept invalid database content")
		})
	}
}
