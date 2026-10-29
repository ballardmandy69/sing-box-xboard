package fakeip

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func legacyPrefix(value string) *badoption.Prefix {
	prefix := badoption.Prefix(netip.MustParsePrefix(value))
	return &prefix
}

func legacyFakeIPManager(t *testing.T, options option.LegacyDNSFakeIPOptions,
	tags ...string,
) (context.Context, *dns.TransportManager) {
	t.Helper()
	registry := dns.NewTransportRegistry()
	RegisterTransport(registry)
	manager := dns.NewTransportManager(registry, nil, "")
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	_, err := dns.NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
		FakeIP: &options,
	}})
	require.NoError(t, err)
	logger := log.NewNOPFactory().Logger()
	require.NoError(t, manager.Create(ctx, logger, "normal", "legacy",
		&option.LegacyDNSServerOptions{Address: "rcode://success"}))
	for _, tag := range tags {
		require.NoError(t, manager.Create(ctx, logger, tag, "legacy",
			&option.LegacyDNSServerOptions{Address: "fakeip"}))
	}
	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, manager.Start(stage, scope))
	}
	return ctx, manager
}

func TestLegacyFakeIPSharedAliasesAndRootOnlyStore(t *testing.T) {
	for _, tags := range [][]string{nil, {"fake-a", "fake-b"}} {
		t.Run(fmt.Sprint(tags), func(t *testing.T) {
			ctx, manager := legacyFakeIPManager(t, option.LegacyDNSFakeIPOptions{
				Enabled: true, Inet4Range: legacyPrefix("198.18.0.0/29"), Inet6Range: legacyPrefix("fc00::/125"),
			}, tags...)
			require.Equal(t, "normal", manager.Default().Tag())
			require.Len(t, manager.Transports(), 1+len(tags), "hidden store must not become a default candidate")
			sharedStore := manager.FakeIP().Store()
			for _, test := range []struct {
				domain, address string
				ipv6            bool
			}{
				{"first.example", "198.18.0.3", false}, {"first.example", "fc00::3", true},
			} {
				address, err := sharedStore.Create(test.domain, test.ipv6)
				require.NoError(t, err)
				require.Equal(t, test.address, address.String())
				domain, loaded := sharedStore.Lookup(address)
				require.True(t, loaded)
				require.Equal(t, test.domain, domain)
			}
			for _, tag := range tags {
				transport, loaded := manager.Transport(tag)
				require.True(t, loaded)
				require.Same(t, sharedStore, transport.(adapter.FakeIPTransport).Store())
				response, err := transport.Exchange(ctx, new(mDNS.Msg).SetQuestion("first.example.", mDNS.TypeA))
				require.NoError(t, err)
				require.Equal(t, "198.18.0.3", response.Answer[0].(*mDNS.A).A.String())
			}
		})
	}
}

func TestLegacyFakeIPRangeWrapAndConcurrency(t *testing.T) {
	_, manager := legacyFakeIPManager(t, option.LegacyDNSFakeIPOptions{
		Enabled: true, Inet4Range: legacyPrefix("198.18.0.0/29"), Inet6Range: legacyPrefix("fc00::/125"),
	})
	store := manager.FakeIP().Store()
	for index, suffix := range []int{3, 4, 5, 6, 7, 2, 3} {
		for _, ipv6 := range []bool{false, true} {
			address, err := store.Create(fmt.Sprintf("host-%d.example", index), ipv6)
			require.NoError(t, err)
			expected := fmt.Sprintf("198.18.0.%d", suffix)
			if ipv6 {
				expected = fmt.Sprintf("fc00::%d", suffix)
			}
			require.Equal(t, expected, address.String())
		}
	}
	var workers sync.WaitGroup
	addresses := make(chan netip.Addr, 20)
	for range 20 {
		workers.Go(func() {
			address, err := store.Create("same.example", false)
			if err != nil {
				t.Error(err)
				return
			}
			addresses <- address
		})
	}
	workers.Wait()
	close(addresses)
	var expected netip.Addr
	for address := range addresses {
		if !expected.IsValid() {
			expected = address
		}
		require.Equal(t, expected, address)
	}
	require.NoError(t, store.Reset())
	_, loaded := store.Lookup(expected)
	require.False(t, loaded)
}

func TestLegacyFakeIPMissingFamilyAndModernAllocation(t *testing.T) {
	ctx, manager := legacyFakeIPManager(t, option.LegacyDNSFakeIPOptions{
		Enabled: true, Inet4Range: legacyPrefix("198.18.0.0/29"),
	}, "fake")
	transport, _ := manager.Transport("fake")
	_, err := transport.Exchange(ctx, new(mDNS.Msg).SetQuestion("missing.example.", mDNS.TypeAAAA))
	require.ErrorContains(t, err, "missing IPv6 fakeip address range")
	client := dns.NewClient(dns.ClientOptions{Context: ctx, DisableCache: true})
	addresses, err := client.Lookup(ctx, transport, "both.example", adapter.DNSQueryOptions{}, nil)
	require.ErrorContains(t, err, "missing IPv6 fakeip address range")
	require.Empty(t, addresses, "legacy dual-family lookup returns no partial success")
	_, emptyManager := legacyFakeIPManager(t, option.LegacyDNSFakeIPOptions{Enabled: true})
	_, err = emptyManager.FakeIP().Store().Create("empty.example", false)
	require.ErrorContains(t, err, "missing IPv4 fakeip address range")

	modern, err := NewTransport(context.Background(), log.NewNOPFactory().Logger(), "modern",
		option.FakeIPDNSServerOptions{Inet4Range: legacyPrefix("198.18.0.0/29")})
	require.NoError(t, err)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, modern.Start(adapter.StartStateStart, scope))
	for index, suffix := range []int{2, 3, 4, 5, 6, 2} {
		address, err := modern.(adapter.FakeIPTransport).Store().Create(fmt.Sprintf("modern-%d.example", index), false)
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("198.18.0.%d", suffix), address.String())
	}
	response, err := modern.Exchange(context.Background(), new(mDNS.Msg).SetQuestion("modern.example.", mDNS.TypeAAAA))
	require.NoError(t, err)
	require.Empty(t, response.Answer)
	_, err = NewTransport(context.Background(), log.NewNOPFactory().Logger(), "invalid", option.FakeIPDNSServerOptions{})
	require.Error(t, err)
}

func TestLegacyFakeIPRequiresEnabledRoot(t *testing.T) {
	registry := dns.NewTransportRegistry()
	RegisterTransport(registry)
	manager := dns.NewTransportManager(registry, nil, "")
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	for _, options := range []*option.LegacyDNSFakeIPOptions{nil, {Enabled: false}} {
		_, err := dns.NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{FakeIP: options},
		})
		require.NoError(t, err)
		err = manager.Create(ctx, log.NewNOPFactory().Logger(), "fake", C.DNSTypeLegacy,
			&option.LegacyDNSServerOptions{Address: "fakeip"})
		require.ErrorContains(t, err, "requires dns.fakeip.enabled")
	}
}

func TestLegacyFakeIPDefaultDoesNotChangeModernRestriction(t *testing.T) {
	registry := dns.NewTransportRegistry()
	RegisterTransport(registry)
	manager := dns.NewTransportManager(registry, nil, "")
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	_, err := dns.NewRouter(ctx, log.NewNOPFactory(), option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
		FakeIP: &option.LegacyDNSFakeIPOptions{Enabled: true, Inet4Range: legacyPrefix("198.18.0.0/29")},
	}})
	require.NoError(t, err)
	require.NoError(t, manager.Create(ctx, log.NewNOPFactory().Logger(), "fake", C.DNSTypeLegacy,
		&option.LegacyDNSServerOptions{Address: "fakeip"}))
	require.Equal(t, "fake", manager.Default().Tag())
	modernManager := dns.NewTransportManager(registry, nil, "")
	err = modernManager.Create(ctx, log.NewNOPFactory().Logger(), "modern", C.DNSTypeFakeIP,
		&option.FakeIPDNSServerOptions{Inet4Range: legacyPrefix("198.18.0.0/29")})
	require.ErrorContains(t, err, "default server cannot be fakeip")
}

type legacyFakeIPPersistence struct {
	adapter.CacheFile
	memory   *MemoryStorage
	metadata *adapter.FakeIPMetadata
}

func (s *legacyFakeIPPersistence) StoreFakeIP() bool                       { return true }
func (s *legacyFakeIPPersistence) FakeIPMetadata() *adapter.FakeIPMetadata { return s.metadata }
func (s *legacyFakeIPPersistence) FakeIPSaveMetadata(metadata *adapter.FakeIPMetadata) error {
	copy := *metadata
	s.metadata = &copy
	return nil
}
func (s *legacyFakeIPPersistence) FakeIPSaveMetadataAsync(metadata *adapter.FakeIPMetadata) {
	_ = s.FakeIPSaveMetadata(metadata)
}
func (s *legacyFakeIPPersistence) FakeIPStore(address netip.Addr, domain string) error {
	return s.memory.FakeIPStore(address, domain)
}
func (s *legacyFakeIPPersistence) FakeIPStoreAsync(address netip.Addr, domain string, logger logger.Logger) {
	s.memory.FakeIPStoreAsync(address, domain, logger)
}
func (s *legacyFakeIPPersistence) FakeIPLoad(address netip.Addr) (string, bool) {
	return s.memory.FakeIPLoad(address)
}
func (s *legacyFakeIPPersistence) FakeIPLoadDomain(domain string, ipv6 bool) (netip.Addr, bool) {
	return s.memory.FakeIPLoadDomain(domain, ipv6)
}
func (s *legacyFakeIPPersistence) FakeIPReset() error { return s.memory.FakeIPReset() }

func TestLegacyFakeIPMetadataResumeAndChangedRange(t *testing.T) {
	cache := &legacyFakeIPPersistence{memory: NewMemoryStorage()}
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cache)
	newStore := func(prefix string) *Store {
		store := NewStore(ctx, log.NewNOPFactory().Logger(), netip.MustParsePrefix(prefix), netip.Prefix{})
		store.legacy = true
		require.NoError(t, store.Start())
		return store
	}
	first := newStore("198.18.0.0/29")
	address, err := first.Create("persist.example", false)
	require.NoError(t, err)
	require.Equal(t, "198.18.0.3", address.String())
	require.NoError(t, first.Close())
	resumed := newStore("198.18.0.0/29")
	restored, err := resumed.Create("persist.example", false)
	require.NoError(t, err)
	require.Equal(t, address, restored)
	next, err := resumed.Create("next.example", false)
	require.NoError(t, err)
	require.Equal(t, "198.18.0.4", next.String())
	require.NoError(t, resumed.Close())
	changed := newStore("198.19.0.0/29")
	_, loaded := changed.Lookup(address)
	require.False(t, loaded, "a changed range must reset incompatible mappings")
	address, err = changed.Create("fresh.example", false)
	require.NoError(t, err)
	require.Equal(t, "198.19.0.3", address.String())
	require.NoError(t, changed.Close())
}
