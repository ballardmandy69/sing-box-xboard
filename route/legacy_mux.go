package route

import (
	"bytes"
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// routeLegacyMultiplex accepts the sample's default SingMux destination after inbound detours.
// Each decoded stream re-enters routing with its authenticated parent identity and own destination.
// @author lyt
// @date 2026-10-29
func (r *Router) routeLegacyMultiplex(ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext, onClose N.CloseHandlerFunc,
) error {
	// The pinned mux service no longer bounds its initial request read. Replay the exact
	// bounded header so its parser and framing remain authoritative after the legacy deadline.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var header bytes.Buffer
	if _, err := mux.ReadRequest(io.TeeReader(conn, &header)); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Time{})
	conn = newCachedConn(conn, buf.As(header.Bytes()).ToOwned())
	service, err := mux.NewService(mux.ServiceOptions{
		NewStreamContext: func(ctx context.Context, _ net.Conn) context.Context {
			return log.ContextWithNewID(ctx)
		},
		Logger:    r.logger,
		HandlerEx: adapter.NewRouteContextHandler(r),
	})
	if err != nil {
		return err
	}
	r.logger.DebugContext(ctx, "accept legacy multiplex connection")
	service.NewConnectionEx(adapter.WithContext(ctx, &metadata), conn,
		metadata.Source, metadata.Destination, onClose)
	return nil
}
