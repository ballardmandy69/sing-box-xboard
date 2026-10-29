package box

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/memoryguard"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

func TestNYAFWRuntimeSharedCleanerLifecycle(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	runtime, err := newNYAFWRuntime(ctx, log.NewNOPFactory().Logger(), option.NYAFWOptions{})
	if err != nil {
		t.Fatal(err)
	}
	first := service.PtrFromContext[usercontrol.ConnectionCleaner](ctx)
	second := service.PtrFromContext[usercontrol.ConnectionCleaner](ctx)
	if first == nil || first != second || first != runtime.cleaner {
		t.Fatal("nodes must share the same cleaner in one Box")
	}
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	for _, stage := range adapter.ListStartStages {
		if err = runtime.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	if err = scope.Close(); err != nil {
		t.Fatal(err)
	}
	if err = first.Start(); err == nil {
		t.Fatal("Box shutdown did not close the shared maintenance worker")
	}
}

func TestNYAFWRuntimeRejectsTimerOverflow(t *testing.T) {
	_, err := newNYAFWRuntime(service.ContextWithDefaultRegistry(context.Background()),
		log.NewNOPFactory().Logger(), option.NYAFWOptions{ConnectionCleanupIntervalSec: math.MaxUint64})
	if err == nil {
		t.Fatal("overflow must not become a negative duration or busy loop")
	}
}

func TestNYAFWMemoryGuardSharesRegistryAndLifecycle(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	runtime, err := newNYAFWRuntime(ctx, log.NewNOPFactory().Logger(), option.NYAFWOptions{
		MemoryGuard: option.MemoryGuardOptions{Enabled: true, CheckInterval: badoption.Duration(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	guard := service.PtrFromContext[memoryguard.Guard](ctx)
	if guard == nil || guard != runtime.guard {
		t.Fatal("listeners must share the Box memory guard")
	}
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	for _, stage := range adapter.ListStartStages {
		if err = runtime.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	if err = scope.Close(); err != nil {
		t.Fatal(err)
	}
	if err = guard.Start(); err == nil {
		t.Fatal("Box shutdown did not stop memory sampling and reclamation")
	}
}

func TestNYAFWMemoryGuardDisabledSkipsPolicyValidation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		ctx := service.ContextWithDefaultRegistry(context.Background())
		runtime, err := newNYAFWRuntime(ctx, log.NewNOPFactory().Logger(), option.NYAFWOptions{
			MemoryGuard: option.MemoryGuardOptions{
				Enabled: enabled, CheckInterval: -1, Steps: []option.MemoryGuardStepOptions{{}},
			},
		})
		if enabled {
			if err == nil {
				t.Fatal("enabled invalid guard policy was accepted")
			}
			if service.PtrFromContext[usercontrol.ConnectionCleaner](ctx) != nil {
				t.Fatal("invalid construction registered partial maintenance state")
			}
			continue
		}
		if err != nil || runtime.guard != nil || service.PtrFromContext[memoryguard.Guard](ctx) != nil {
			t.Fatalf("disabled guard must remain absent: %v", err)
		}
		_ = runtime.cleaner.Close()
	}
}
