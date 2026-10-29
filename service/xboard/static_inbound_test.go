package xboard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodepolicy"
	"github.com/sagernet/sing-box/common/usercontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestStaticInboundSynchronizesWithoutListener(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	registry, err := nodepolicy.NewRegistry("", nil)
	if err != nil {
		t.Fatal(err)
	}
	service.MustRegister[adapter.ManagedNodePolicy](ctx, registry)
	options := option.XBoardServiceOptions{
		StaticInbound: true, NodeType: "vmess", NodeID: 7, ReportAlive: true,
		APIHost: "https://panel.example.invalid", APIKey: "fixture",
	}
	created, err := NewService(ctx, log.NewNOPFactory().Logger(), "static-panel", options)
	if err != nil {
		t.Fatal(err)
	}
	n := created.(*Service).nodes[0]
	if n.inbound != nil || n.auto != nil || n.policyTag() != "static-panel" {
		t.Fatal("static panel constructed or required an inbound")
	}
	var userRequests, configRequests, reports int
	n.primary.client.client.Transport = panelTransportFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"data":[]}`
		switch {
		case strings.HasSuffix(request.URL.Path, "/user"):
			userRequests++
			body = `{"users":[{"id":42,"uuid":"static-user-uuid","connection_limit":1}]}`
		case strings.HasSuffix(request.URL.Path, "/config"):
			configRequests++
			body = `{"protocol":"vmess","server_port":0,"network":"tcp","tls":0}`
		default:
			reports++
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	if err = n.syncUsers(ctx); err != nil {
		t.Fatal(err)
	}
	if err = n.syncConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if err = n.pushReports(ctx); err != nil {
		t.Fatal(err)
	}
	if userRequests != 1 || configRequests != 2 || reports == 0 {
		t.Fatalf("static panel tasks were skipped: users=%d config=%d reports=%d", userRequests, configRequests, reports)
	}
	user, found := n.lookupStaticPolicyUser("static-user-uuid")
	if !found || user.ID != 42 || !strings.HasPrefix(user.Label, "42@") {
		t.Fatal("static name did not resolve to the panel UUID and stable identity")
	}
	registry.SetPanelTag("first-listener", "static-panel")
	registry.SetPanelTag("second-listener", "static-panel")
	metadata := adapter.InboundContext{Inbound: "first-listener", User: "static-user-uuid", Network: "tcp",
		Source: M.ParseSocksaddr("192.0.2.1:1000"), Destination: M.ParseSocksaddr("example.com:443")}
	server, client := net.Pipe()
	defer client.Close()
	tracked, err := registry.TrackNodeConnection(ctx, server, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer tracked.Close()
	if metadata.User != "static-user-uuid" || metadata.Inbound != "first-listener" {
		t.Fatal("static accounting changed the original authentication name or inbound")
	}
	if err = registry.Check(ctx, &metadata, tracked); err != nil {
		t.Fatalf("repeated policy check lost the original UUID: %v", err)
	}
	second, peer := net.Pipe()
	defer second.Close()
	defer peer.Close()
	metadata.Inbound, metadata.User = "second-listener", "static-user-uuid"
	if _, err = registry.TrackNodeConnection(ctx, second, &metadata); !errors.Is(err, usercontrol.ErrConnectionLimit) {
		t.Fatalf("two listeners did not share the panel connection limit: %v", err)
	}
	tracked.Close()
	if n.control.ActiveConnections(user.Label) != 0 {
		t.Fatal("closing the static stream did not release its connection quota")
	}
	n.primary.users = nil
	if err = n.applyUsers(nil); err != nil {
		t.Fatal(err)
	}
	if _, exists := n.lookupStaticPolicyUser("static-user-uuid"); exists {
		t.Fatal("removed panel user retained a static UUID binding")
	}
	if err = registry.Check(ctx, &metadata, nil); !errors.Is(err, adapter.ErrManagedNodePolicyRejected) {
		t.Fatal("removed static identity bypassed route policy")
	}
	created.(*Service).closeNodePolicies()
	if registry.HasNode("first-listener") {
		t.Fatal("closed static panel retained its route binding")
	}
}

func TestStaticInboundRejectsAutomaticModeConflict(t *testing.T) {
	_, err := NewService(context.Background(), log.NewNOPFactory().Logger(), "panel", option.XBoardServiceOptions{
		StaticInbound: true, AutoInbound: &option.XBoardAutoInboundOptions{},
	})
	if err == nil {
		t.Fatal("static authentication and automatic credential replacement enabled together")
	}
}
