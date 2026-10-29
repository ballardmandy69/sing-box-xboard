package rule

import (
	"context"
	"net/netip"
	"os"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/geoip"
	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// LegacyGeoStore owns the databases shared by legacy geographic routing rules.
// @author lyt
// @date 2026-10-29
type LegacyGeoStore struct {
	ctx            context.Context
	logger         log.ContextLogger
	geoIPOptions   option.GeoIPOptions
	geositeOptions option.GeositeOptions
	geoIPCodes     map[string]struct{}
	geositeCodes   map[string]struct{}
	lifecycle      sync.Mutex
	access         sync.RWMutex
	geoIP          *geoip.Reader
	geosite        map[string][]RuleItem
	closed         bool
}

func NewLegacyGeoStore(ctx context.Context, logger log.ContextLogger, options option.RouteOptions) *LegacyGeoStore {
	return &LegacyGeoStore{
		ctx:            ctx,
		logger:         logger,
		geoIPOptions:   common.PtrValueOrDefault(options.GeoIP),
		geositeOptions: common.PtrValueOrDefault(options.Geosite),
		geoIPCodes:     make(map[string]struct{}),
		geositeCodes:   make(map[string]struct{}),
	}
}

func (s *LegacyGeoStore) requireCodes(codes []string, isGeosite bool) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	for _, code := range codes {
		if code == "" {
			return E.New("empty geographic database code")
		}
		if isGeosite {
			s.geositeCodes[code] = struct{}{}
		} else if code != "private" {
			s.geoIPCodes[code] = struct{}{}
		}
	}
	return nil
}

// Reload validates both databases before publishing a new snapshot. A failed
// reload leaves the previous snapshot usable by concurrent routing requests.
func (s *LegacyGeoStore) Reload() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	var newGeoIP *geoip.Reader
	if len(s.geoIPCodes) > 0 {
		path, err := s.prepareDatabase("geoip", s.geoIPOptions.Path,
			s.geoIPOptions.DownloadURL, s.geoIPOptions.DownloadDetour)
		if err != nil {
			return err
		}
		reader, availableCodes, err := geoip.Open(path)
		if err != nil {
			return E.Cause(err, "open legacy geoip database ", path)
		}
		for code := range s.geoIPCodes {
			if code != "unknown" && !slices.Contains(availableCodes, code) {
				reader.Close()
				return E.New("geoip code not found: ", code)
			}
		}
		newGeoIP = reader
	}
	newGeosite, err := s.loadGeosite()
	if err != nil {
		if newGeoIP != nil {
			newGeoIP.Close()
		}
		return err
	}
	s.access.Lock()
	oldGeoIP := s.geoIP
	s.geoIP = newGeoIP
	s.geosite = newGeosite
	var closeErr error
	if oldGeoIP != nil {
		closeErr = oldGeoIP.Close()
	}
	s.access.Unlock()
	if closeErr != nil {
		s.logger.Warn(E.Cause(closeErr, "close previous geoip database"))
	}
	if len(s.geoIPCodes)+len(s.geositeCodes) > 0 {
		s.logger.Info("loaded legacy geographic rules: geoip=", len(s.geoIPCodes), ", geosite=", len(s.geositeCodes))
	}
	return nil
}

func (s *LegacyGeoStore) loadGeosite() (map[string][]RuleItem, error) {
	if len(s.geositeCodes) == 0 {
		return nil, nil
	}
	path, err := s.prepareDatabase("geosite", s.geositeOptions.Path,
		s.geositeOptions.DownloadURL, s.geositeOptions.DownloadDetour)
	if err != nil {
		return nil, err
	}
	reader, _, err := geosite.Open(path)
	if err != nil {
		return nil, E.Cause(err, "open legacy geosite database ", path)
	}
	defer common.Close(reader.Upstream())
	compiled := make(map[string][]RuleItem, len(s.geositeCodes))
	for code := range s.geositeCodes {
		entries, readErr := reader.Read(code)
		if readErr != nil {
			return nil, E.Cause(readErr, "read geosite code ", code)
		}
		for _, entry := range entries {
			if entry.Type > geosite.RuleTypeDomainRegex {
				return nil, E.New("unsupported geosite item type ", entry.Type, " in code ", code)
			}
		}
		items, compileErr := compileLegacyGeosite(geosite.Compile(entries))
		if compileErr != nil {
			return nil, E.Cause(compileErr, "compile geosite code ", code)
		}
		compiled[code] = items
	}
	return compiled, nil
}

func compileLegacyGeosite(options option.DefaultRule) ([]RuleItem, error) {
	var items []RuleItem
	if len(options.Domain)+len(options.DomainSuffix) > 0 {
		item, err := NewDomainItem(options.Domain, options.DomainSuffix)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if len(options.DomainKeyword) > 0 {
		items = append(items, NewDomainKeywordItem(options.DomainKeyword))
	}
	if len(options.DomainRegex) > 0 {
		item, err := NewDomainRegexItem(options.DomainRegex)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *LegacyGeoStore) matchGeoIP(address netip.Addr, codes []string) bool {
	if !address.IsValid() {
		return false
	}
	s.access.RLock()
	defer s.access.RUnlock()
	if s.closed {
		return false
	}
	if !N.IsPublicAddr(address) {
		return slices.Contains(codes, "private")
	}
	return s.geoIP != nil && slices.Contains(codes, s.geoIP.Lookup(address))
}

func (s *LegacyGeoStore) matchGeosite(metadata *adapter.InboundContext, codes []string) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	for _, code := range codes {
		for _, item := range s.geosite[code] {
			if item.Match(metadata) {
				return true
			}
		}
	}
	return false
}

func (s *LegacyGeoStore) Close() error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.geoIP != nil {
		err = s.geoIP.Close()
	}
	s.geoIP = nil
	s.geosite = nil
	return err
}
