package rule

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func legacyGeoTestStore(t *testing.T, options option.RouteOptions) (context.Context, *LegacyGeoStore) {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	store := NewLegacyGeoStore(ctx, log.NewNOPFactory().NewLogger("geo-test"), options)
	service.MustRegisterPtr(ctx, store)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return ctx, store
}

func legacyGeoTestRule(t *testing.T, ctx context.Context, config string) *DefaultRule {
	t.Helper()
	var options option.DefaultRule
	require.NoError(t, json.Unmarshal([]byte(config), &options))
	rule, err := NewDefaultRule(ctx, log.NewNOPFactory().NewLogger("rule-test"), options)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, rule.Close()) })
	return rule
}

func writeLegacyGeositeFixture(t *testing.T, path string, entries map[string][]geosite.Item) {
	t.Helper()
	var content bytes.Buffer
	require.NoError(t, geosite.Write(&content, entries))
	require.NoError(t, os.WriteFile(path, content.Bytes(), 0o600))
}

func TestLegacyGeoIPRules(t *testing.T) {
	ctx, store := legacyGeoTestStore(t, option.RouteOptions{
		GeoIP: &option.GeoIPOptions{Path: filepath.Join("testdata", "legacy-geo", "geoip-a.db")},
	})
	destinationRule := legacyGeoTestRule(t, ctx, `{"geoip":["aa"]}`)
	sourceRule := legacyGeoTestRule(t, ctx, `{"source_geoip":["bb"]}`)
	privateRule := legacyGeoTestRule(t, ctx, `{"geoip":["private"]}`)
	unknownRule := legacyGeoTestRule(t, ctx, `{"geoip":["unknown"]}`)
	combinedRule := legacyGeoTestRule(t, ctx, `{"geoip":["aa"],"domain":["exact.example"],"port":443}`)
	invertedRule := legacyGeoTestRule(t, ctx, `{"geoip":["aa"],"invert":true}`)
	require.NoError(t, store.Reload())
	for _, address := range []string{"1.1.1.1", "2001:4860::1"} {
		metadata := adapter.InboundContext{Destination: M.ParseSocksaddrHostPort(address, 443)}
		require.True(t, destinationRule.Match(&metadata), address)
		require.True(t, combinedRule.Match(&metadata), address)
		require.False(t, invertedRule.Match(&metadata), address)
		metadata.Destination.Port = 80
		require.False(t, combinedRule.Match(&metadata), "port condition must remain AND")
	}
	for _, address := range []string{"8.8.8.8", "2606:4700::1"} {
		metadata := adapter.InboundContext{
			Source: M.ParseSocksaddrHostPort(address, 1234), Destination: M.ParseSocksaddrHostPort(address, 443),
		}
		require.True(t, sourceRule.Match(&metadata), address)
		require.False(t, destinationRule.Match(&metadata), address)
		require.True(t, invertedRule.Match(&metadata), address)
	}
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("resolved.example", 443)}
	metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}
	require.True(t, destinationRule.Match(&metadata), "any resolved address may match")
	metadata = adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("exact.example", 443)}
	require.True(t, combinedRule.Match(&metadata), "domain and destination address conditions remain OR")
	for _, address := range []string{"10.0.0.1", "fd00::1", "127.0.0.1"} {
		metadata = adapter.InboundContext{Destination: M.ParseSocksaddrHostPort(address, 443)}
		require.True(t, privateRule.Match(&metadata), address)
		require.False(t, unknownRule.Match(&metadata), address)
	}
	metadata = adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("9.9.9.9", 443)}
	require.True(t, unknownRule.Match(&metadata))
	require.False(t, privateRule.Match(&metadata))
}

func TestLegacyGeositeRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite.db")
	writeLegacyGeositeFixture(t, path, map[string][]geosite.Item{
		"test": {
			{Type: geosite.RuleTypeDomain, Value: "exact.example"},
			{Type: geosite.RuleTypeDomainSuffix, Value: "suffix.example"},
			{Type: geosite.RuleTypeDomainKeyword, Value: "needle"},
			{Type: geosite.RuleTypeDomainRegex, Value: `^r[0-9]+\.example$`},
		},
	})
	ctx, store := legacyGeoTestStore(t, option.RouteOptions{Geosite: &option.GeositeOptions{Path: path}})
	rule := legacyGeoTestRule(t, ctx, `{"geosite":["test"]}`)
	require.NoError(t, store.Reload())
	for _, domain := range []string{
		"exact.example", "EXACT.EXAMPLE", "suffix.example", "a.suffix.example", "a-needle.test", "r12.example",
	} {
		metadata := adapter.InboundContext{Destination: M.ParseSocksaddrHostPort(domain, 443)}
		require.True(t, rule.Match(&metadata), domain)
	}
	for _, domain := range []string{"a.exact.example", "suffix.example.invalid", "outside.example", "rxx.example"} {
		metadata := adapter.InboundContext{Destination: M.ParseSocksaddrHostPort(domain, 443)}
		require.False(t, rule.Match(&metadata), domain)
	}
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("1.1.1.1", 443), Domain: "exact.example"}
	require.True(t, rule.Match(&metadata), "sniffed domain is preserved")
	require.NoError(t, os.Remove(path), "compiled geosite does not keep the database file open")
	require.True(t, rule.Match(&metadata), "compiled rules do not reread the file for every request")
}

func TestLegacyGeoPrivateDoesNotRequireDatabase(t *testing.T) {
	ctx, store := legacyGeoTestStore(t, option.RouteOptions{})
	rule := legacyGeoTestRule(t, ctx, `{"source_geoip":["private"]}`)
	require.NoError(t, store.Reload())
	metadata := adapter.InboundContext{Source: M.ParseSocksaddrHostPort("10.0.0.1", 1234)}
	require.True(t, rule.Match(&metadata))
	require.NoError(t, store.Close())
	require.False(t, rule.Match(&metadata), "closed store cannot match stale rules")
}

func TestLegacyGeoStartupErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.db")
	require.NoError(t, os.WriteFile(path, []byte{1, 2, 3}, 0o600))
	for _, testCase := range []struct {
		name, path, config string
		isGeosite          bool
	}{
		{"geoip_corrupt", path, `{"geoip":["aa"]}`, false},
		{"geosite_corrupt", path, `{"geosite":["test"]}`, true},
		{"geoip_missing", path + ".missing", `{"geoip":["aa"]}`, false},
		{"geosite_missing", path + ".missing", `{"geosite":["test"]}`, true},
		{"geoip_missing_code", filepath.Join("testdata", "legacy-geo", "geoip-a.db"), `{"geoip":["missing"]}`, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var options option.RouteOptions
			if testCase.isGeosite {
				options.Geosite = &option.GeositeOptions{Path: testCase.path}
			} else {
				options.GeoIP = &option.GeoIPOptions{Path: testCase.path}
			}
			ctx, store := legacyGeoTestStore(t, options)
			legacyGeoTestRule(t, ctx, testCase.config)
			require.Error(t, store.Reload(), "bad database must prevent startup")
		})
	}
	sitePath := filepath.Join(t.TempDir(), "geosite.db")
	writeLegacyGeositeFixture(t, sitePath, map[string][]geosite.Item{"present": {}})
	ctx, store := legacyGeoTestStore(t, option.RouteOptions{Geosite: &option.GeositeOptions{Path: sitePath}})
	legacyGeoTestRule(t, ctx, `{"geosite":["missing"]}`)
	require.ErrorContains(t, store.Reload(), "missing")
}

func TestLegacyGeoReloadAndClose(t *testing.T) {
	ctx, store := legacyGeoTestStore(t, option.RouteOptions{
		GeoIP: &option.GeoIPOptions{Path: filepath.Join("testdata", "legacy-geo", "geoip-a.db")},
	})
	rule := legacyGeoTestRule(t, ctx, `{"geoip":["aa"]}`)
	require.NoError(t, store.Reload())
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("1.1.1.1", 443)}
	require.True(t, rule.Match(&metadata))
	store.geoIPOptions.Path = filepath.Join("testdata", "legacy-geo", "geoip-b.db")
	require.NoError(t, store.Reload())
	require.False(t, rule.Match(&metadata), "successful reload publishes the new database")
	store.geoIPOptions.Path = filepath.Join(t.TempDir(), "missing.db")
	require.Error(t, store.Reload())
	require.False(t, rule.Match(&metadata), "failed reload preserves the previous database")
	metadata.Destination = M.ParseSocksaddrHostPort("8.8.8.8", 443)
	require.True(t, rule.Match(&metadata), "previous database still works after failed reload")
	store.geoIPOptions.Path = filepath.Join("testdata", "legacy-geo", "geoip-a.db")
	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Go(func() {
			for j := 0; j < 100; j++ {
				localMetadata := metadata
				rule.Match(&localMetadata)
			}
		})
	}
	require.NoError(t, store.Reload())
	require.NoError(t, store.Close())
	readers.Wait()
	require.False(t, rule.Match(&metadata))
	require.ErrorIs(t, store.Reload(), os.ErrClosed)
	require.NoError(t, store.Close(), "close is idempotent")
}

func TestLegacyGeoReloadAllOrNothing(t *testing.T) {
	directory := t.TempDir()
	sitePath := filepath.Join(directory, "geosite.db")
	writeLegacyGeositeFixture(t, sitePath, map[string][]geosite.Item{
		"test": {{Type: geosite.RuleTypeDomain, Value: "exact.example"}},
	})
	ctx, store := legacyGeoTestStore(t, option.RouteOptions{
		GeoIP:   &option.GeoIPOptions{Path: filepath.Join("testdata", "legacy-geo", "geoip-a.db")},
		Geosite: &option.GeositeOptions{Path: sitePath},
	})
	ipRule := legacyGeoTestRule(t, ctx, `{"geoip":["aa"]}`)
	siteRule := legacyGeoTestRule(t, ctx, `{"geosite":["test"]}`)
	require.NoError(t, store.Reload())
	newIPPath := filepath.Join(directory, "geoip-new.db")
	content, err := os.ReadFile(filepath.Join("testdata", "legacy-geo", "geoip-b.db"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(newIPPath, content, 0o600))
	store.geoIPOptions.Path = newIPPath
	require.NoError(t, os.WriteFile(sitePath, []byte("corrupt"), 0o600))
	require.Error(t, store.Reload())
	metadata := adapter.InboundContext{Destination: M.ParseSocksaddrHostPort("1.1.1.1", 443)}
	require.True(t, ipRule.Match(&metadata), "failed geosite reload must not replace the GeoIP snapshot")
	metadata.Destination = M.ParseSocksaddrHostPort("exact.example", 443)
	require.True(t, siteRule.Match(&metadata), "failed reload retains compiled geosite rules")
	require.NoError(t, os.Remove(newIPPath), "unpublished GeoIP reader must be closed on failure")
}
