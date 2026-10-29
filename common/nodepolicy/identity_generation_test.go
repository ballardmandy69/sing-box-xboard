package nodepolicy

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func TestManagedAliasIdentityRefreshDoesNotTransferRequestAdmission(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		name := "unchanged"
		if refresh {
			name = "source-UUID-rotated-during-sniff"
		}
		t.Run(name, func(t *testing.T) {
			registry, err := NewRegistry("", nil)
			if err != nil {
				t.Fatal(err)
			}
			authUUID := "uuid-one"
			if err = registry.Register("managed-A", Node{
				LookupUser: func(name string) (User, bool) {
					return User{ID: 11, Label: "stable-source-name"}, name == "stable-source-name"
				},
				LookupAuthUUID: func(name string) (string, bool) {
					return authUUID, name == "stable-source-name"
				},
			}); err != nil {
				t.Fatal(err)
			}
			var requests, connections []string
			users := map[string]User{
				"uuid-one": {ID: 21, Label: "target-user-one"},
				"uuid-two": {ID: 22, Label: "target-user-two"},
			}
			if err = registry.Register("static-B", Node{
				Static:     true,
				LookupUser: func(string) (User, bool) { return User{}, false },
				LookupStaticUser: func(uuid string) (User, bool) {
					user, exists := users[uuid]
					return user, exists
				},
				CheckRequest: func(_ context.Context, name string) error {
					requests = append(requests, name)
					return nil
				},
				TrackConnection: func(_ context.Context, conn net.Conn, metadata adapter.InboundContext) (net.Conn, error) {
					connections = append(connections, metadata.User)
					return conn, nil
				},
			}); err != nil {
				t.Fatal(err)
			}
			registry.SetPanelTag("managed-A", "static-B")
			ctx := context.Background()
			metadata := adapter.InboundContext{
				Inbound: "managed-A", User: "stable-source-name", Network: "tcp",
				Source: M.ParseSocksaddr("192.0.2.1:1234"), Destination: M.ParseSocksaddr("example.com:443"),
			}
			request, err := registry.CheckNodeRequest(ctx, &metadata)
			if err != nil {
				t.Fatal(err)
			}
			if request == nil {
				t.Fatal("managed admission did not retain an identity binding")
			}
			if !reflect.DeepEqual(requests, []string{"target-user-one"}) {
				t.Fatalf("initial request was charged to %v", requests)
			}
			// A panel refresh can run while legacy sniffing waits for client bytes.
			if refresh {
				authUUID = "uuid-two"
			}
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			checkErr := request.CheckPolicy(ctx, &metadata, server)
			_, trackErr := request.TrackConnection(ctx, server, &metadata)
			if !refresh {
				if checkErr != nil || trackErr != nil ||
					!reflect.DeepEqual(connections, []string{"target-user-one"}) {
					t.Fatalf("unchanged binding failed: check=%v track=%v connections=%v", checkErr, trackErr, connections)
				}
				return
			}
			if !errors.Is(checkErr, adapter.ErrManagedNodePolicyRejected) ||
				!errors.Is(trackErr, adapter.ErrManagedNodePolicyRejected) || len(connections) != 0 {
				t.Fatalf("identity changed after admission: requests=%v connections=%v check=%v track=%v",
					requests, connections, checkErr, trackErr)
			}
		})
	}
}
