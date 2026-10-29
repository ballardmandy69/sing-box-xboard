package v2ray

import (
	"context"
	"errors"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestQUICProxyTransportIsDisabled(t *testing.T) {
	options := option.V2RayTransportOptions{Type: C.V2RayTransportTypeQUIC}
	if _, err := NewServerTransport(context.Background(), nil, options, nil, nil); !errors.Is(err, C.ErrUDPDisabled) {
		t.Fatalf("QUIC server reached its constructor: %v", err)
	}
	if _, err := NewClientTransport(context.Background(), nil, M.Socksaddr{}, options, nil); !errors.Is(err, C.ErrUDPDisabled) {
		t.Fatalf("QUIC client reached its constructor: %v", err)
	}
}
