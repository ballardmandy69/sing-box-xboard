package usercontrol

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRoutedRequestSeparatesRequestQuotaFromConnectionAdmission(t *testing.T) {
	m := NewManagerWithRequestLimit(nil, 1)
	second := int64(100)
	m.now = func() time.Time { return time.Unix(second, 0) }
	update(t, m, map[string]Limits{"a": {ConnectionLimit: 1, IPLimit: 1}})
	ctx := context.Background()
	if err := m.CheckRequest(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	// A node policy rejection stops here. It consumes a request, never an IP/connection slot.
	if m.ActiveConnections("a") != 0 || len(m.OnlineIPs()) != 0 {
		t.Fatal("request check acquired connection resources")
	}
	if err := m.CheckRequest(ctx, "a"); !errors.Is(err, ErrRequestLimit) {
		t.Fatalf("rejected node request refunded its quota: %v", err)
	}
	second++
	if err := m.CheckRequest(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	conn, err := m.TrackRoutedConnection(ctx, &fixtureConn{}, testMetadata("a", "192.0.2.1"))
	if err != nil {
		t.Fatalf("connection admission consumed request quota a second time: %v", err)
	}
	if m.ActiveConnections("a") != 1 || len(m.OnlineIPs()["a"]) != 1 {
		t.Fatal("routed stream did not acquire its resources")
	}
	conn.Close()
	if m.ActiveConnections("a") != 0 || len(m.OnlineIPs()) != 0 {
		t.Fatal("routed rejection did not release connection resources")
	}
	if err = m.CheckRequest(ctx, "unknown"); !errors.Is(err, ErrUnknownUser) {
		t.Fatal("unknown user bypassed request validation")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err = m.CheckRequest(canceled, "a"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request consumed quota")
	}
}
