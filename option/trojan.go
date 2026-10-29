package option

type TrojanInboundOptions struct {
	ListenOptions
	Users         []TrojanUser `json:"users,omitempty"`
	ForceMux      bool         `json:"force_mux,omitempty"`
	ServerPadding bool         `json:"server_padding,omitempty"`
	InboundTLSOptionsContainer
	Fallback        *ServerOptions            `json:"fallback,omitempty"`
	FallbackForALPN map[string]*ServerOptions `json:"fallback_for_alpn,omitempty"`
	Multiplex       *InboundMultiplexOptions  `json:"multiplex,omitempty"`
	Transport       *V2RayTransportOptions    `json:"transport,omitempty"`
}

type TrojanUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type TrojanOutboundOptions struct {
	DialerOptions
	ServerOptions
	Password string      `json:"password"`
	Network  NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Multiplex *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *V2RayTransportOptions    `json:"transport,omitempty"`
}
