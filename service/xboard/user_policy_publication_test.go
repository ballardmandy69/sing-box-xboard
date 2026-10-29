package xboard

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

// blockingUserUpdate exposes the interval in which a protocol has published new credentials.
// @author lyt
// @date 2026-10-29
type blockingUserUpdate struct {
	adapter.ManagedSSMServer
	entered chan struct{}
	release chan error
}

func (b *blockingUserUpdate) UpdateUsers(_, _ []string) error {
	close(b.entered)
	return <-b.release
}

func TestUserPolicyIdentityPublishedBeforeAuthentication(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[rollback], func(t *testing.T) {
			fixture := newPanelFixture(t, "unused")
			n := userSyncNode(fixture.server, "policy", &userSyncInbound{})
			oldName, newName := "1@policy@uniproxy", "2@policy@uniproxy"
			if err := n.applyUsers([]identifiedPanelUser{{name: oldName,
				user: panelUser{ID: 1, UUID: "old"}, panel: n.primary}}); err != nil {
				t.Fatal(err)
			}
			blocking := &blockingUserUpdate{entered: make(chan struct{}), release: make(chan error)}
			n.inbound = blocking
			done := make(chan error, 1)
			go func() {
				done <- n.applyUsers([]identifiedPanelUser{{name: newName,
					user: panelUser{ID: 2, UUID: "new"}, panel: n.primary}})
			}()
			<-blocking.entered
			if user, exists := n.lookupPolicyUser(newName); !exists || user.ID != 2 {
				t.Error("newly authenticated user can bypass policy before publication")
			}
			if _, exists := n.lookupPolicyUser(oldName); exists {
				t.Error("old policy identity survived the user replacement")
			}
			if rollback {
				blocking.release <- errors.New("authentication table rejected update")
			} else {
				blocking.release <- nil
			}
			err := <-done
			if (err != nil) != rollback {
				t.Fatalf("unexpected update outcome: %v", err)
			}
			wantName, wantID := newName, uint64(2)
			if rollback {
				wantName, wantID = oldName, 1
			}
			if user, exists := n.lookupPolicyUser(wantName); !exists || user.ID != wantID {
				t.Fatal("committed or rolled back identity is missing")
			}
			if len(n.limits) != 1 || len(n.users) != 1 || n.userPanels[wantName] != n.primary {
				t.Fatal("user policies and panel ownership were not committed together")
			}
			if _, exists := n.limits[wantName]; !exists {
				t.Fatal("limit policy was not retained on rollback")
			}
		})
	}
}
