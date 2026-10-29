package rule

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestLegacyDNSGeographicRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite.db")
	writeLegacyGeositeFixture(t, path, map[string][]geosite.Item{
		"test": {{Type: geosite.RuleTypeDomainSuffix, Value: "match.example"}},
	})
	ctx, store := legacyGeoTestStore(t, option.RouteOptions{
		GeoIP:   &option.GeoIPOptions{Path: filepath.Join("testdata", "legacy-geo", "geoip-a.db")},
		Geosite: &option.GeositeOptions{Path: path},
	})
	createRule := func(content string) *DefaultDNSRule {
		var options option.DefaultDNSRule
		require.NoError(t, json.Unmarshal([]byte(content), &options))
		rule, err := NewDefaultDNSRule(ctx, log.NewNOPFactory().Logger(), options, true)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, rule.Close()) })
		return rule
	}
	geoIPRule := createRule(`{"geoip":["aa"]}`)
	sourceRule := createRule(`{"source_geoip":["bb"]}`)
	geositeRule := createRule(`{"geosite":["test"]}`)
	require.NoError(t, store.Reload())
	metadata := adapter.InboundContext{Domain: "sub.match.example", Source: M.ParseSocksaddr("8.8.8.8:1234")}
	require.True(t, geoIPRule.WithAddressLimit())
	require.True(t, geoIPRule.LegacyPreMatch(&metadata), "address filtering happens after the answer")
	metadata.ResetRuleCache()
	require.True(t, sourceRule.LegacyPreMatch(&metadata))
	metadata.ResetRuleCache()
	require.True(t, geositeRule.LegacyPreMatch(&metadata))
	metadata.Domain = "other.example"
	metadata.ResetRuleCache()
	require.False(t, geositeRule.LegacyPreMatch(&metadata))
	for _, test := range []struct {
		address string
		match   bool
	}{
		{"1.1.1.1", true}, {"2001:4860::1", true}, {"8.8.8.8", false}, {"2606:4700::1", false},
	} {
		ip := net.ParseIP(test.address)
		var answer mDNS.RR
		if ip.To4() != nil {
			answer = &mDNS.A{
				Hdr: mDNS.RR_Header{Name: "geo.example.", Rrtype: mDNS.TypeA, Class: mDNS.ClassINET}, A: ip,
			}
		} else {
			answer = &mDNS.AAAA{
				Hdr: mDNS.RR_Header{Name: "geo.example.", Rrtype: mDNS.TypeAAAA, Class: mDNS.ClassINET}, AAAA: ip,
			}
		}
		response := &mDNS.Msg{Answer: []mDNS.RR{answer}}
		require.Equal(t, test.match, geoIPRule.MatchAddressLimit(&metadata, response), test.address)
	}
	require.False(t, geoIPRule.MatchAddressLimit(&metadata, &mDNS.Msg{}))
}
