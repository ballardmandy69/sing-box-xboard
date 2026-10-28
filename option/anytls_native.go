package option

import "github.com/sagernet/sing/common/json/badoption"

// AnyTLSNativePaddingOptions bounds the only padding layer of a native connection.
// An omitted object uses defaults; a zero-valued object disables padding.
// @author lyt
// @date 2026-10-29
type AnyTLSNativePaddingOptions struct {
	MaxPadding int `json:"max_padding,omitempty"`
	MaxPercent int `json:"max_percent,omitempty"`
	MaxTotal   int `json:"max_total,omitempty"`
}

// AnyTLSNativeInboundOptions configures an authenticated, TCP-only native server.
// @author lyt
// @date 2026-10-29
type AnyTLSNativeInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	PrivateKey           string                      `json:"private_key"`
	Users                []AnyTLSUser                `json:"users,omitempty"`
	HandshakeTimeout     badoption.Duration          `json:"handshake_timeout,omitempty"`
	MaxPendingHandshakes int                         `json:"max_pending_handshakes,omitempty"`
	Padding              *AnyTLSNativePaddingOptions `json:"padding,omitempty"`
}

// AnyTLSNativeOutboundOptions binds a connection pool to one server and user.
// @author lyt
// @date 2026-10-29
type AnyTLSNativeOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	ServerPublicKey          string                      `json:"server_public_key"`
	Password                 string                      `json:"password"`
	HandshakeTimeout         badoption.Duration          `json:"handshake_timeout,omitempty"`
	Padding                  *AnyTLSNativePaddingOptions `json:"padding,omitempty"`
	IdleSessionCheckInterval badoption.Duration          `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       badoption.Duration          `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int                         `json:"min_idle_session,omitempty"`
	SessionHealth            *AnyTLSSessionHealthOptions `json:"session_health,omitempty"`
}
