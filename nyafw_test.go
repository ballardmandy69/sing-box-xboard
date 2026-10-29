package box

import (
	"context"
	"math"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
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
