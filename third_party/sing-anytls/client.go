package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type ClientConfig struct {
	Password                 string
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
	DialOut                  util.DialOutFunc
	Logger                   logger.ContextLogger
	EnhancedPadding          bool
	SessionHealth            *SessionHealthOptions
	DisablePadding           bool
	AuthenticationTimeout    time.Duration
}

// SessionHealthOptions controls bounded, on-demand checks before reusing idle sessions.
// @author lyt
// @date 2026-10-28
type SessionHealthOptions = session.HealthOptions

type Client struct {
	passwordSha256        []byte
	dialOut               util.DialOutFunc
	sessionClient         *session.Client
	padding               atomic.TypedValue[*padding.PaddingFactory]
	enhancedPadding       bool
	disablePadding        bool
	authenticationTimeout time.Duration
}

func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	if config.AuthenticationTimeout < 0 {
		return nil, fmt.Errorf("authentication timeout must not be negative")
	}
	pw := sha256.Sum256([]byte(config.Password))
	c := &Client{
		passwordSha256:        pw[:],
		dialOut:               config.DialOut,
		enhancedPadding:       config.EnhancedPadding && !config.DisablePadding,
		disablePadding:        config.DisablePadding,
		authenticationTimeout: config.AuthenticationTimeout,
	}
	// Initialize the padding state of this client
	scheme := padding.DefaultPaddingScheme
	if config.DisablePadding {
		scheme = []byte("stop=0")
	}
	padding.UpdatePaddingScheme(scheme, &c.padding)
	health := session.HealthOptions{Enabled: config.EnhancedPadding}
	if config.SessionHealth != nil {
		health = *config.SessionHealth
	}
	var err error
	c.sessionClient, err = session.NewClientWithHealth(
		ctx, config.Logger, c.createOutboundConnection, &c.padding,
		config.IdleSessionCheckInterval, config.IdleSessionTimeout,
		config.MinIdleSession, health, c.enhancedPadding, config.DisablePadding,
	)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) CreateProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.sessionClient.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) createOutboundConnection(ctx context.Context) (net.Conn, error) {
	var paddingLen int
	var err error
	if !c.disablePadding {
		paddingLen, err = authenticationPaddingLength(c.padding.Load(), c.enhancedPadding)
		if err != nil {
			return nil, err
		}
	}
	conn, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}
	authContext := ctx
	if c.authenticationTimeout > 0 {
		var cancel context.CancelFunc
		authContext, cancel = context.WithTimeout(ctx, c.authenticationTimeout)
		defer cancel()
	}
	if err = authContext.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	// Cancellation closes blocked authentication writes, without replacing the
	// caller's socket deadlines or leaving a watcher attached to a pooled session.
	watcherDone := make(chan struct{})
	stopWatcher := context.AfterFunc(authContext, func() {
		conn.Close()
		close(watcherDone)
	})

	b := buf.NewSize(sha256.Size + 2 + paddingLen)
	defer b.Release()

	b.Write(c.passwordSha256)
	binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
	if paddingLen > 0 {
		b.WriteZeroN(paddingLen)
	}

	n, err := conn.Write(b.Bytes())
	if !stopWatcher() {
		<-watcherDone
	}
	if contextErr := authContext.Err(); contextErr != nil {
		err = contextErr
	}
	if err == nil && n != b.Len() {
		err = io.ErrShortWrite
	}
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (h *Client) Close() error {
	return h.sessionClient.Close()
}
