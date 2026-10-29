package listener

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/common/memoryguard"
	"github.com/sagernet/sing-box/common/usercontrol"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// maintenanceListener applies shared admission and registration before protocol handshakes.
// It also covers callers that pass ListenTCP directly to an HTTP or gRPC server.
// @author lyt
// @date 2026-10-29
type maintenanceListener struct {
	net.Listener
	cleaner *usercontrol.ConnectionCleaner
	guard   maintenanceAdmission
}

type maintenanceAdmission interface {
	Accept(net.Conn, netip.Addr) (net.Conn, bool)
}

func wrapMaintenanceListener(ctx context.Context, listener net.Listener) net.Listener {
	cleaner := service.PtrFromContext[usercontrol.ConnectionCleaner](ctx)
	guard := service.PtrFromContext[memoryguard.Guard](ctx)
	if cleaner == nil && guard == nil {
		return listener
	}
	wrapped := &maintenanceListener{Listener: listener, cleaner: cleaner}
	if guard != nil {
		wrapped.guard = guard
	}
	return wrapped
}

func (l *maintenanceListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap().Addr
		if l.guard != nil {
			tracked, allowed := l.guard.Accept(conn, source)
			if !allowed {
				continue
			}
			return tracked, nil
		}
		return l.cleaner.TrackAcceptedConnection(conn, source), nil
	}
}
