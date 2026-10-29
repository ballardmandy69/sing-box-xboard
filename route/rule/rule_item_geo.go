package rule

import (
	"context"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

// LegacyGeoIPItem matches source or destination addresses against a shared database.
// @author lyt
// @date 2026-10-29
type LegacyGeoIPItem struct {
	store    *LegacyGeoStore
	codes    []string
	isSource bool
}

func NewLegacyGeoIPItem(ctx context.Context, codes []string, isSource bool) (*LegacyGeoIPItem, error) {
	store := service.PtrFromContext[LegacyGeoStore](ctx)
	if store == nil {
		return nil, E.New("legacy geographic database service is unavailable")
	}
	if err := store.requireCodes(codes, false); err != nil {
		return nil, err
	}
	return &LegacyGeoIPItem{store: store, codes: slices.Clone(codes), isSource: isSource}, nil
}

func (r *LegacyGeoIPItem) Match(metadata *adapter.InboundContext) bool {
	if r.isSource || metadata.IPCIDRMatchSource {
		return r.store.matchGeoIP(metadata.Source.Addr, r.codes)
	}
	if metadata.DestinationAddressMatchFromResponse {
		for _, address := range metadata.DNSResponseAddressesForMatch() {
			if r.store.matchGeoIP(address, r.codes) {
				return true
			}
		}
		return false
	}
	if metadata.Destination.IsIP() {
		return r.store.matchGeoIP(metadata.Destination.Addr, r.codes)
	}
	for _, address := range metadata.DestinationAddresses {
		if r.store.matchGeoIP(address, r.codes) {
			return true
		}
	}
	return false
}

func (r *LegacyGeoIPItem) String() string {
	if r.isSource {
		return "source_geoip=" + strings.Join(r.codes, ",")
	}
	return "geoip=" + strings.Join(r.codes, ",")
}

// LegacyGeositeItem matches domains against compiled categories in a shared database.
// @author lyt
// @date 2026-10-29
type LegacyGeositeItem struct {
	store *LegacyGeoStore
	codes []string
}

func NewLegacyGeositeItem(ctx context.Context, codes []string) (*LegacyGeositeItem, error) {
	store := service.PtrFromContext[LegacyGeoStore](ctx)
	if store == nil {
		return nil, E.New("legacy geographic database service is unavailable")
	}
	if err := store.requireCodes(codes, true); err != nil {
		return nil, err
	}
	return &LegacyGeositeItem{store: store, codes: slices.Clone(codes)}, nil
}

func (r *LegacyGeositeItem) Match(metadata *adapter.InboundContext) bool {
	return r.store.matchGeosite(metadata, r.codes)
}

func (r *LegacyGeositeItem) String() string {
	return "geosite=" + strings.Join(r.codes, ",")
}
