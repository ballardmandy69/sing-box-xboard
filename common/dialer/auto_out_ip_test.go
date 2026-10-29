package dialer

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// TestAutoOutIPRejectsFamilyFallback prevents silently switching to an unrelated egress address.
// @author lyt
// @date 2026-10-29
func TestAutoOutIPRejectsFamilyFallback(t *testing.T) {
	dialer, err := NewDefault(context.Background(), option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := adapter.WithOutboundBindAddress(context.Background(), netip.MustParseAddr("127.0.0.2"))
	if conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("[::1]:443")); err == nil {
		conn.Close()
		t.Fatal("IPv4 source silently fell back to an IPv6 source")
	}
	if conn, err := dialer.DialContext(ctx, "udp", M.ParseSocksaddr("127.0.0.1:53")); err == nil {
		conn.Close()
		t.Fatal("AutoOutIP accepted UDP")
	}
	if conn, err := dialer.ListenPacket(ctx, M.ParseSocksaddr("127.0.0.1:53")); err == nil {
		conn.Close()
		t.Fatal("AutoOutIP created an unbound packet listener")
	}
}
