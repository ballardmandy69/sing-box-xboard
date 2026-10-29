package option

import (
	"context"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

// XBoardServiceOptions describes the XBoard/XiaoV2Board UniProxy client.
// @author lyt
// @date 2026-10-25
type XBoardServiceOptions struct {
	PanelType            string                            `json:"panel_type,omitempty"`
	Panels               []XBoardPanelOptions              `json:"panels,omitempty"`
	APIHost              string                            `json:"api_host,omitempty"`
	APIKey               string                            `json:"api_key,omitempty"`
	NodeID               int                               `json:"node_id,omitempty"`
	NodeType             string                            `json:"node_type,omitempty"`
	Inbound              string                            `json:"inbound,omitempty"`
	Servers              *badjson.TypedMap[string, string] `json:"servers,omitempty"`
	PullInterval         badoption.Duration                `json:"pull_interval,omitempty"`
	PushInterval         badoption.Duration                `json:"push_interval,omitempty"`
	SyncInterval         *badoption.Duration               `json:"sync_interval,omitempty"`
	Timeout              badoption.Duration                `json:"timeout,omitempty"`
	DisableUploadTraffic bool                              `json:"disable_upload_traffic,omitempty"`
	ReportAlive          bool                              `json:"report_alive,omitempty"`
	TrafficFactor        float64                           `json:"traffic_factor,omitempty"`
	IPLimit              uint16                            `json:"ip_limit,omitempty"`
	ConnectionLimit      uint32                            `json:"connection_limit,omitempty"`
	RateLimit            uint64                            `json:"rate_limit,omitempty"`
	MaxSpeedLimit        string                            `json:"max_speed_limit,omitempty"`
	DefaultMaxSpeedLimit string                            `json:"default_max_speed_limit,omitempty"`
	AutoInbound          *XBoardAutoInboundOptions         `json:"auto_inbound,omitempty"`
}

// XBoardPanelOptions describes one independently authenticated panel in an aggregate node.
// @author lyt
// @date 2026-10-29
type XBoardPanelOptions struct {
	PanelTag  string             `json:"panel_tag,omitempty"`
	PanelType string             `json:"panel_type,omitempty"`
	APIHost   string             `json:"api_host,omitempty"`
	APIKey    string             `json:"api_key,omitempty"`
	NodeID    int                `json:"node_id,omitempty"`
	NodeType  string             `json:"node_type,omitempty"`
	Timeout   badoption.Duration `json:"timeout,omitempty"`
}

// XBoardAutoInboundOptions fills local settings absent from the panel node configuration.
// @author lyt
// @date 2026-10-29
type XBoardAutoInboundOptions struct {
	Protocol          string `json:"protocol,omitempty"`
	Listen            string `json:"listen,omitempty"`
	ListenPort        int    `json:"listen_port,omitempty"`
	ProxyProtocol     bool   `json:"proxy_protocol,omitempty"`
	AutoOutIP         bool   `json:"auto_out_ip,omitempty"`
	ForceVision       bool   `json:"force_vision,omitempty"`
	ShadowsocksObfsMu string `json:"shadowsocks_obfs_mu,omitempty"`
	CertificatePath   string `json:"certificate_path,omitempty"`
	KeyPath           string `json:"key_path,omitempty"`
	PrivateKey        string `json:"private_key,omitempty"`
	PrivateKeyPath    string `json:"private_key_path,omitempty"`
}

type ServiceOptionsRegistry interface {
	OptionTypes() []string
	CreateOptions(serviceType string) (any, bool)
}

type _Service struct {
	Type    string `json:"type"`
	Tag     string `json:"tag,omitempty"`
	Options any    `json:"-"`
}

type Service _Service

func (h *Service) MarshalJSONContext(ctx context.Context) ([]byte, error) {
	fields := make(map[string]json.RawMessage)
	if h.Options != nil {
		content, err := json.MarshalContext(ctx, h.Options)
		if err != nil {
			return nil, err
		}
		if err = json.UnmarshalContext(ctx, content, &fields); err != nil {
			return nil, err
		}
	}
	fields["type"], _ = json.Marshal(h.Type)
	if h.Tag != "" {
		fields["tag"], _ = json.Marshal(h.Tag)
	}
	return json.MarshalContext(ctx, fields)
}

func (h *Service) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	err := json.UnmarshalContext(ctx, content, (*_Service)(h))
	if err != nil {
		return err
	}
	registry := service.FromContext[ServiceOptionsRegistry](ctx)
	if registry == nil {
		return E.New("missing service fields registry in context")
	}
	options, loaded := registry.CreateOptions(h.Type)
	if !loaded {
		return E.New("unknown inbound type: ", h.Type)
	}
	// Preserve raw numeric tokens: the generic object helper decodes through float64.
	var fields map[string]json.RawMessage
	if err = json.UnmarshalContext(ctx, content, &fields); err != nil {
		return err
	}
	delete(fields, "type")
	delete(fields, "tag")
	content, err = json.MarshalContext(ctx, fields)
	if err != nil {
		return err
	}
	err = json.UnmarshalContextDisallowUnknownFields(ctx, content, options)
	if err != nil {
		return err
	}
	h.Options = options
	return nil
}

func (h Service) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("Service", func() (*schema.Node, error) {
		registry := service.FromContext[ServiceOptionsRegistry](builder.Context())
		if registry == nil {
			return nil, E.New("missing service options registry in context")
		}
		return registryUnion(builder, registry, nil, true)
	})
}
