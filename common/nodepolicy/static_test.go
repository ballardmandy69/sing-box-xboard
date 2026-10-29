package nodepolicy

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestStaticPanelAliasPrecedenceAndBoundedFallback(t *testing.T) {
	registry, err := NewRegistry("", nil)
	if err != nil {
		t.Fatal(err)
	}
	register := func(tag string, id uint64) {
		t.Helper()
		if err := registry.Register(tag, Node{
			Static:     true,
			LookupUser: func(string) (User, bool) { return User{}, false },
			LookupStaticUser: func(name string) (User, bool) {
				return User{ID: id, Label: tag}, name == "uuid"
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	register("A", 1)
	register("B", 2)
	register("C", 3)
	registry.SetPanelTag("A", "B")
	registry.SetPanelTag("B", "C")
	check := func(id uint64, tag string) {
		t.Helper()
		user, found := registry.LookupUser("A", "uuid")
		if !found || user.ID != id || registry.PanelTag("A") != tag {
			t.Fatalf("rule/log binding differs from route lookup: user=%+v found=%v panel=%s", user, found,
				registry.PanelTag("A"))
		}
	}
	check(2, "B")
	registry.Remove("B")
	check(3, "C")
	registry.Remove("C")
	registry.SetPanelTag("C", "D")
	register("D", 4)
	if registry.HasNode("A") {
		t.Fatal("alias lookup recursively followed more than the original two substitutions")
	}
	metadata := adapter.InboundContext{Inbound: "A", User: "uuid"}
	if err = registry.Check(context.Background(), &metadata, nil); err != nil {
		t.Fatal("missing gateway changed the original unbound route behavior")
	}
	tracked, trackErr := registry.TrackNodeConnection(context.Background(), nil, &metadata)
	if trackErr != nil || tracked != nil {
		t.Fatal("unbound connection unexpectedly installed a tracker")
	}
	if registry.PanelTag("unaliased") != "unaliased" || registry.HasPanelAlias("unaliased") {
		t.Fatal("unaliased route acquired a panel association")
	}
}
