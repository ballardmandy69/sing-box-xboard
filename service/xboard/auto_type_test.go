package xboard

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
)

// registerLifecycleProtocol reuses the existing failure-injection fixture under another advertised protocol.
// @author lyt
// @date 2026-10-29
func registerLifecycleProtocol(registry *inbound.Registry, protocol string) {
	// Registry.Create holds its mutex while calling constructors. Delegate to a
	// separate fixture registry rather than recursively acquiring the same lock.
	fixture := lifecycleRegistry()
	inbound.Register[lifecycleOptions](registry, protocol, func(ctx context.Context, router adapter.Router,
		logger log.ContextLogger, tag string, options lifecycleOptions,
	) (adapter.Inbound, error) {
		created, err := fixture.Create(ctx, router, logger, tag, "test", &options)
		if err != nil {
			return nil, err
		}
		created.(*lifecycleInbound).Adapter = inbound.NewAdapter(protocol, tag)
		return created, nil
	})
}

func TestAutoInboundTypeTracksSuccessfulProtocolReplacement(t *testing.T) {
	h := lifecycleWrapper(t)
	registerLifecycleProtocol(h.registry.(*inbound.Registry), "next")
	if h.Type() != "test" {
		t.Fatalf("initial type=%q", h.Type())
	}
	stop := make(chan struct{})
	started := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		close(started)
		for {
			select {
			case <-stop:
				return
			default:
				if current := h.Type(); current != "test" && current != "next" {
					t.Errorf("concurrent Type returned unpublished protocol %q", current)
					return
				}
			}
		}
	}()
	<-started
	t.Cleanup(func() { close(stop); readers.Wait() })
	for _, protocol := range []string{"next", "test", "next"} {
		previous := h.current.inbound.(*lifecycleInbound)
		config := autoInboundConfig{
			protocol: protocol, options: &lifecycleOptions{Revision: 2},
			endpoint: netip.MustParseAddrPort("127.0.0.1:9443"),
		}
		if err := h.replace(config); err != nil {
			t.Fatal(err)
		}
		if h.Type() != protocol || h.current.inbound.Type() != protocol || h.Tag() != "auto-test" || !previous.closed {
			t.Fatalf("published type or stable identity differs after replacement: type=%q actual=%q tag=%q oldClosed=%v",
				h.Type(), h.current.inbound.Type(), h.Tag(), previous.closed)
		}
		if err := h.replace(config); err != nil || h.Type() != protocol {
			t.Fatalf("unchanged config lost its advertised protocol: %q %v", h.Type(), err)
		}
	}
}

func TestAutoInboundTypeRemainsOnRejectedReplacement(t *testing.T) {
	for _, test := range []struct {
		name         string
		options      lifecycleOptions
		sameEndpoint bool
	}{
		{"constructor", lifecycleOptions{Revision: 2, FailMake: true}, false},
		{"users", lifecycleOptions{Revision: 2, FailUsers: true}, false},
		{"new-listener", lifecycleOptions{Revision: 2, FailStart: true}, false},
		{"same-listener-rollback", lifecycleOptions{Revision: 2, FailStart: true}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := lifecycleWrapper(t)
			registerLifecycleProtocol(h.registry.(*inbound.Registry), "next")
			endpoint := netip.MustParseAddrPort("127.0.0.1:9443")
			if test.sameEndpoint {
				endpoint = h.current.config.endpoint
			}
			if err := h.replace(autoInboundConfig{protocol: "next", options: &test.options, endpoint: endpoint}); err == nil {
				t.Fatal("injected replacement failure was ignored")
			}
			if h.Type() != "test" || h.current == nil || h.current.inbound.Type() != "test" ||
				h.current.inbound.(*lifecycleInbound).closed {
				t.Fatalf("failed candidate changed advertised/live protocol: advertised=%q current=%#v", h.Type(), h.current)
			}
		})
	}
}

func TestAutoInboundTypeChangesOnlyAfterDeferredActivation(t *testing.T) {
	registry := lifecycleRegistry()
	registerLifecycleProtocol(registry, "next")
	h := newEmptyAutoInbound(context.Background(), registry, nil, log.NewNOPFactory().Logger(), "deferred", "test")
	t.Cleanup(func() { h.close() })
	config := autoInboundConfig{protocol: "next", options: &lifecycleOptions{FailMake: true},
		endpoint: netip.MustParseAddrPort("127.0.0.1:8443")}
	if err := h.replace(config); err == nil || h.Type() != "test" || h.hasCurrent() {
		t.Fatal("failed initial activation published the candidate type")
	}
	config.options = &lifecycleOptions{}
	if err := h.replace(config); err != nil {
		t.Fatal(err)
	}
	if h.Type() != "next" || !h.hasCurrent() || h.Tag() != "deferred" {
		t.Fatalf("successful deferred activation did not publish new type: %q", h.Type())
	}
}
