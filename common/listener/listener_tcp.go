package listener

import (
	"bufio"
	"bytes"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/redir"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/database64128/tfo-go/v2"
	"github.com/pires/go-proxyproto"
)

func (l *Listener) ListenTCP() (net.Listener, error) {
	var err error
	bindAddr := M.SocksaddrFrom(l.listenOptions.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1})), l.listenOptions.ListenPort)
	var listenConfig net.ListenConfig
	if l.listenOptions.BindInterface != "" {
		listenConfig.Control = control.Append(listenConfig.Control, control.BindToInterface(service.FromContext[adapter.NetworkManager](l.ctx).InterfaceFinder(), l.listenOptions.BindInterface, -1))
	}
	if l.listenOptions.RoutingMark != 0 {
		listenConfig.Control = control.Append(listenConfig.Control, control.RoutingMark(uint32(l.listenOptions.RoutingMark)))
	}
	if l.listenOptions.ReuseAddr {
		listenConfig.Control = control.Append(listenConfig.Control, control.ReuseAddr())
	}
	if l.listenOptions.DisableTCPKeepAlive {
		listenConfig.KeepAlive = -1
		listenConfig.KeepAliveConfig.Enable = false
	} else {
		keepIdle := time.Duration(l.listenOptions.TCPKeepAlive)
		if keepIdle == 0 {
			keepIdle = C.TCPKeepAliveInitial
		}
		keepInterval := time.Duration(l.listenOptions.TCPKeepAliveInterval)
		if keepInterval == 0 {
			keepInterval = C.TCPKeepAliveInterval
		}
		listenConfig.KeepAliveConfig = net.KeepAliveConfig{
			Enable:   true,
			Idle:     keepIdle,
			Interval: keepInterval,
		}
	}
	if l.listenOptions.TCPMultiPath {
		listenConfig.SetMultipathTCP(true)
	}
	if l.tproxy {
		listenConfig.Control = control.Append(listenConfig.Control, func(network, address string, conn syscall.RawConn) error {
			return control.Raw(conn, func(fd uintptr) error {
				return redir.TProxy(fd, !strings.HasSuffix(network, "4"), false)
			})
		})
	}
	tcpListener, err := ListenNetworkNamespace[net.Listener](l.ctx, l.listenOptions.NetNs, func() (net.Listener, error) {
		if l.listenOptions.TCPFastOpen {
			var tfoConfig tfo.ListenConfig
			tfoConfig.ListenConfig = listenConfig
			return tfoConfig.Listen(l.ctx, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
		} else {
			return listenConfig.Listen(l.ctx, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
		}
	})
	if err != nil {
		return nil, err
	}
	// Original admission and registration precede PROXY header injection.
	tcpListener = wrapMaintenanceListener(l.ctx, tcpListener)
	if l.listenOptions.ProxyProtocol || l.listenOptions.ProxyProtocolAcceptNoHeader {
		tcpListener = newProxyProtocolListener(
			tcpListener, l.listenOptions.ProxyProtocolAcceptNoHeader, proxyProtocolHeaderTimeout,
		)
	}
	l.logger.Info("tcp server started at ", tcpListener.Addr())
	l.tcpListener = tcpListener
	return tcpListener, err
}

const (
	maxPendingProxyHeaders     = 128
	proxyProtocolHeaderTimeout = 3 * time.Second
)

// proxyProtocolListener parses bounded PROXY headers outside callers' accept loops.
// @author lyt
// @date 2026-10-29
type proxyProtocolListener struct {
	net.Listener
	acceptNoHeader bool
	headerTimeout  time.Duration
	ready          chan proxyPreparedConnection
	temporaryError chan error
	done           chan struct{}
	access         sync.Mutex
	pending        map[net.Conn]struct{}
	closed         bool
	acceptError    error
	closeError     error
	closeOnce      sync.Once
	workers        sync.WaitGroup
}

type proxyPreparedConnection struct {
	raw  net.Conn
	conn net.Conn
}

// proxyProtocolConn preserves the socket's local address and any buffered application bytes.
// @author lyt
// @date 2026-10-29
type proxyProtocolConn struct {
	net.Conn
	reader *bufio.Reader
	source net.Addr
}

func (c *proxyProtocolConn) Read(data []byte) (int, error) {
	return c.reader.Read(data)
}

func (c *proxyProtocolConn) RemoteAddr() net.Addr {
	return c.source
}

func (c *proxyProtocolConn) Upstream() any { return c.Conn }

func newProxyProtocolListener(
	listener net.Listener, acceptNoHeader bool, timeout time.Duration,
) *proxyProtocolListener {
	p := &proxyProtocolListener{
		Listener: listener, acceptNoHeader: acceptNoHeader, headerTimeout: timeout,
		ready: make(chan proxyPreparedConnection), temporaryError: make(chan error), done: make(chan struct{}),
		pending: make(map[net.Conn]struct{}),
	}
	go p.acceptLoop()
	return p
}

func (p *proxyProtocolListener) Accept() (net.Conn, error) {
	select {
	case prepared := <-p.ready:
		p.access.Lock()
		if p.closed {
			err := p.acceptError
			p.access.Unlock()
			prepared.raw.Close()
			return nil, err
		}
		delete(p.pending, prepared.raw)
		p.access.Unlock()
		return prepared.conn, nil
	case err := <-p.temporaryError:
		return nil, err
	case <-p.done:
		p.access.Lock()
		err := p.acceptError
		p.access.Unlock()
		return nil, err
	}
}

func (p *proxyProtocolListener) acceptLoop() {
	for {
		conn, err := p.Listener.Accept()
		if err != nil {
			//nolint:staticcheck
			if netError, ok := err.(net.Error); ok && netError.Temporary() {
				select {
				case p.temporaryError <- err:
					continue
				case <-p.done:
					return
				}
			}
			p.close(err)
			return
		}
		p.access.Lock()
		if p.closed || len(p.pending) >= maxPendingProxyHeaders {
			p.access.Unlock()
			conn.Close()
			continue
		}
		p.pending[conn] = struct{}{}
		p.workers.Add(1)
		p.access.Unlock()
		go p.prepare(conn)
	}
}

func (p *proxyProtocolListener) prepare(conn net.Conn) {
	defer p.workers.Done()
	prepared, err := readProxyProtocolHeader(conn, p.acceptNoHeader, p.headerTimeout)
	if err == nil {
		select {
		case p.ready <- proxyPreparedConnection{raw: conn, conn: prepared}:
			return
		case <-p.done:
		}
	}
	conn.Close()
	p.access.Lock()
	delete(p.pending, conn)
	p.access.Unlock()
}

func (p *proxyProtocolListener) Close() error {
	return p.close(net.ErrClosed)
}

func (p *proxyProtocolListener) close(acceptError error) error {
	p.closeOnce.Do(func() {
		p.access.Lock()
		p.closed = true
		p.acceptError = acceptError
		pending := p.pending
		p.pending = nil
		close(p.done)
		p.access.Unlock()
		p.closeError = p.Listener.Close()
		for conn := range pending {
			conn.Close()
		}
		p.workers.Wait()
	})
	return p.closeError
}

func readProxyProtocolHeader(conn net.Conn, acceptNoHeader bool, timeout time.Duration) (net.Conn, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(conn, 256)
	first, err := reader.Peek(1)
	if err != nil {
		return nil, err
	}
	var signature []byte
	switch first[0] {
	case proxyproto.SIGV1[0]:
		signature = proxyproto.SIGV1
	case proxyproto.SIGV2[0]:
		signature = proxyproto.SIGV2
	}
	var header *proxyproto.Header
	if signature != nil {
		prefix, peekErr := reader.Peek(len(signature))
		if peekErr != nil {
			// A partial signature must not become application bytes in optional mode.
			return nil, peekErr
		}
		if bytes.Equal(prefix, signature) {
			if signature[0] == proxyproto.SIGV1[0] {
				// The upstream v1 parser requires a complete buffered line. ReadSlice is
				// bounded by this reader's 256-byte buffer and the connection deadline.
				line, lineErr := reader.ReadSlice('\n')
				if lineErr != nil {
					return nil, lineErr
				}
				header, err = proxyproto.Read(bufio.NewReaderSize(bytes.NewReader(line), 256))
			} else {
				header, err = proxyproto.Read(reader)
			}
			if err != nil {
				return nil, err
			}
		}
	}
	if header == nil && !acceptNoHeader {
		return nil, proxyproto.ErrNoProxyProtocol
	}
	source := conn.RemoteAddr()
	if header != nil && !header.Command.IsLocal() && !header.TransportProtocol.IsUnspec() {
		if header.TransportProtocol != proxyproto.TCPv4 && header.TransportProtocol != proxyproto.TCPv6 {
			return nil, E.New("PROXY header must describe a TCP connection")
		}
		if header.SourceAddr == nil {
			return nil, E.New("PROXY header has no source address")
		}
		source = header.SourceAddr
	}
	if err = conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &proxyProtocolConn{Conn: conn, reader: reader, source: source}, nil
}

func (l *Listener) loopTCPIn() {
	tcpListener := l.tcpListener
	var (
		metadata    adapter.InboundContext
		acceptDelay time.Duration
	)
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			if l.shutdown.Load() && E.IsClosed(err) {
				return
			}
			//nolint:staticcheck
			if netError, isNetError := err.(net.Error); isNetError && netError.Temporary() {
				if acceptDelay == 0 {
					acceptDelay = 5 * time.Millisecond
				} else {
					acceptDelay = min(2*acceptDelay, time.Second)
				}
				l.logger.Error(err, ", retrying in ", acceptDelay)
				time.Sleep(acceptDelay)
				continue
			}
			l.tcpListener.Close()
			l.logger.Error("tcp listener closed: ", err)
			return
		}
		acceptDelay = 0
		//nolint:staticcheck
		metadata.InboundDetour = l.listenOptions.Detour
		metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
		metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
		ctx := log.ContextWithNewID(l.ctx)
		if l.listenOptions.AutoOutIP {
			ctx = adapter.WithOutboundBindAddress(ctx, metadata.OriginDestination.Addr.Unmap())
		}
		l.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
		go l.connHandler.NewConnection(ctx, conn, metadata, nil)
	}
}
