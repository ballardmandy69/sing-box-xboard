package option

import "github.com/sagernet/sing/common/json/badoption"

type AnyTLSInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users           []AnyTLSUser               `json:"users,omitempty"`
	PaddingScheme   badoption.Listable[string] `json:"padding_scheme,omitempty"`
	EnhancedPadding bool                       `json:"enhanced_padding,omitempty"`
}

type AnyTLSUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type AnyTLSOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Password                 string                      `json:"password,omitempty"`
	IdleSessionCheckInterval badoption.Duration          `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       badoption.Duration          `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int                         `json:"min_idle_session,omitempty"`
	ClientMetadata           string                      `json:"client_metadata,omitempty"`
	EnhancedPadding          bool                        `json:"enhanced_padding,omitempty"`
	SessionHealth            *AnyTLSSessionHealthOptions `json:"session_health,omitempty"`
}

// AnyTLSSessionHealthOptions configures on-demand validation and limits for idle AnyTLS sessions.
// @author lyt
// @date 2026-10-28
type AnyTLSSessionHealthOptions struct {
	Enabled         bool               `json:"enabled,omitempty"`
	IdleThreshold   badoption.Duration `json:"idle_threshold,omitempty"`
	Timeout         badoption.Duration `json:"timeout,omitempty"`
	MaxIdleSessions int                `json:"max_idle_sessions,omitempty"`
}
