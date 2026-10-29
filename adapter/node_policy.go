package adapter

import (
	"context"
	"errors"
	"net"
)

var ErrManagedNodePolicyRejected = errors.New("blocked by managed node policy")

// ManagedNodePolicy runs after legacy sniff/resolution and before routing selects an outbound.
// @author lyt
// @date 2026-10-29
type ManagedNodePolicy interface {
	HasNode(tag string) bool
	FingerprintEnabled() bool
	Check(ctx context.Context, metadata *InboundContext, conn net.Conn) error
}
