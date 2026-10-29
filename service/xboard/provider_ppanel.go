package xboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ppanelProvider preserves the selected nyafw sample's PPanel wire formats.
// @author lyt
// @date 2026-10-29
type ppanelProvider struct{}

func newPPanelProvider(nodeType string) (panelProvider, error) {
	switch strings.ToLower(nodeType) {
	case "vmess", "v2ray", "vless", "trojan", "anytls", "shadowsocks":
		return ppanelProvider{}, nil
	case "hysteria2", "tuic":
		return nil, errors.New("PPanel UDP protocols are disabled")
	default:
		return nil, errors.New("unsupported PPanel node type")
	}
}

func (ppanelProvider) identityTag() string { return "ppanel" }

func (ppanelProvider) request(
	ctx context.Context, p *panelClient, method, endpoint, etag string, body []byte,
) ([]byte, int, string, error) {
	var path string
	var err error
	switch endpoint {
	case "config":
		path = "/v1/server/config"
	case "user":
		path = "/v1/server/user"
	case "push":
		path = "/v1/server/push"
		body, err = ppanelTrafficBody(body)
	case "alive":
		path = "/v1/server/online"
		body, err = ppanelOnlineBody(body)
	case "status":
		path = "/v1/server/status"
		body, err = ppanelStatusBody(body, time.Now())
	default:
		return nil, 0, "", errors.New("unsupported PPanel operation")
	}
	if err != nil {
		return nil, 0, "", err
	}
	requestURL, err := url.Parse(p.options.APIHost + path)
	if err != nil {
		return nil, 0, "", errors.New("invalid PPanel request URL")
	}
	protocol := strings.ToLower(p.options.NodeType)
	if protocol == "v2ray" {
		protocol = "vmess"
	}
	query := requestURL.Query()
	query.Set("protocol", protocol)
	query.Set("server_id", strconv.Itoa(p.options.NodeID))
	query.Set("secret_key", p.options.APIKey)
	requestURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, "", errors.New("invalid PPanel request")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, status, nextETag, err := p.doRequest(request, endpoint)
	if err != nil || status == http.StatusNotModified || endpoint != "config" {
		return response, status, nextETag, err
	}
	response, err = normalizePPanelConfig(response)
	return response, status, nextETag, err
}

func (ppanelProvider) decodeUsers(body []byte) (usersResponse, error) {
	var response struct {
		Users []struct {
			ID          uint64 `json:"id"`
			UUID        string `json:"uuid"`
			SpeedLimit  int64  `json:"speed_limit"`
			DeviceLimit int64  `json:"device_limit"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return usersResponse{}, errors.New("invalid PPanel users response")
	}
	result := usersResponse{Users: make([]panelUser, 0, len(response.Users))}
	for _, user := range response.Users {
		result.Users = append(result.Users, panelUser{
			ID: user.ID, UUID: user.UUID, SpeedLimit: user.SpeedLimit, DeviceLimit: int16(user.DeviceLimit),
		})
	}
	return result, nil
}

// ppanelConfig contains only fields consumed by the original mapper.
// @author lyt
// @date 2026-10-29
type ppanelConfig struct {
	Port            int64            `json:"port"`
	Method          string           `json:"method"`
	Transport       string           `json:"transport"`
	TransportConfig *ppanelTransport `json:"transport_config"`
	SecurityConfig  *json.RawMessage `json:"security_config"`
}

// ppanelTransport maps PPanel's transport object to the existing inbound configuration.
// @author lyt
// @date 2026-10-29
type ppanelTransport struct {
	Path        string `json:"path"`
	Host        string `json:"host"`
	ServiceName string `json:"service_name"`
}

func normalizePPanelConfig(body []byte) ([]byte, error) {
	var response struct {
		Protocol string          `json:"protocol"`
		Config   json.RawMessage `json:"config"`
		Basic    *struct {
			PushInterval any `json:"push_interval"`
			PullInterval any `json:"pull_interval"`
		} `json:"basic"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errors.New("invalid PPanel config response")
	}
	var config ppanelConfig
	if err := json.Unmarshal(response.Config, &config); err != nil {
		return nil, errors.New("invalid PPanel protocol config")
	}
	result := autoConfigResponse{
		Protocol: response.Protocol, ServerPort: json.RawMessage(strconv.Itoa(int(uint16(config.Port)))),
	}
	if response.Basic == nil {
		return nil, errors.New("missing PPanel basic config")
	}
	var err error
	result.BaseConfig.PushInterval, err = ppanelInterval(response.Basic.PushInterval)
	if err != nil {
		return nil, err
	}
	result.BaseConfig.PullInterval, err = ppanelInterval(response.Basic.PullInterval)
	if err != nil {
		return nil, err
	}
	switch response.Protocol {
	case "vmess", "vless", "trojan":
		if config.TransportConfig == nil {
			return nil, errors.New("missing PPanel transport_config")
		}
		result.Network = config.Transport
		result.NetworkSettings, _ = json.Marshal(panelTransportSettings{
			Path: config.TransportConfig.Path, Host: config.TransportConfig.Host,
			ServiceName: config.TransportConfig.ServiceName,
		})
		result.TLS = json.RawMessage("1")
		if response.Protocol == "vmess" && config.SecurityConfig == nil {
			result.TLS = json.RawMessage("0")
		}
	case "anytls":
		result.TLS = json.RawMessage("1")
	case "shadowsocks":
		result.Cipher = config.Method
	case "hysteria2", "tuic":
		return nil, errors.New("PPanel UDP protocols are disabled")
	default:
		return nil, errors.New("unsupported PPanel protocol")
	}
	// SNI, Reality, flow and server_key are present in panel models but ignored by the original mapper.
	return json.Marshal(result)
}

func ppanelInterval(value any) (int, error) {
	switch value := value.(type) {
	case float64:
		return int(value), nil
	case string:
		// c54420 ignores Atoi's error; an invalid string contributes its returned numeric value.
		seconds, _ := strconv.Atoi(value)
		return seconds, nil
	default:
		return 0, errors.New("invalid PPanel interval type")
	}
}

// ppanelTraffic is the exact tagged record passed to Resty by the selected sample.
// @author lyt
// @date 2026-10-29
type ppanelTraffic struct {
	UID      uint64 `json:"uid"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

func ppanelTrafficBody(body []byte) ([]byte, error) {
	var input map[string][2]int64
	if err := json.Unmarshal(body, &input); err != nil {
		return nil, errors.New("invalid PPanel traffic report")
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	// 12ccda0 starts with len=N before appending N records. Preserve this observed sample behavior.
	rows := make([]ppanelTraffic, len(keys), 2*len(keys))
	for _, key := range keys {
		id, err := strconv.ParseUint(key, 10, 64)
		if err != nil {
			return nil, errors.New("invalid PPanel traffic user ID")
		}
		counts := input[key]
		rows = append(rows, ppanelTraffic{UID: id, Upload: counts[0], Download: counts[1]})
	}
	return json.Marshal(struct {
		Traffic []ppanelTraffic `json:"traffic"`
	}{rows})
}

func ppanelOnlineBody(body []byte) ([]byte, error) {
	var input map[string][]string
	if err := json.Unmarshal(body, &input); err != nil {
		return nil, errors.New("invalid PPanel online report")
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	// rtype 161b540 has no JSON tags. Its exported obfuscated names are therefore wire field names.
	type onlineRecord struct {
		W5Ab6dV uint64
		GO1AXXe string
	}
	rows := make([]onlineRecord, 0)
	for _, key := range keys {
		id, err := strconv.ParseUint(key, 10, 64)
		if err != nil {
			return nil, errors.New("invalid PPanel online user ID")
		}
		for _, ip := range input[key] {
			rows = append(rows, onlineRecord{W5Ab6dV: id, GO1AXXe: ip})
		}
	}
	return json.Marshal(struct {
		Users []onlineRecord `json:"users"`
	}{rows})
}

func ppanelStatusBody(body []byte, now time.Time) ([]byte, error) {
	var status struct {
		CPU       float64 `json:"cpu"`
		Memory    float64 `json:"mem"`
		Disk      float64 `json:"disk"`
		UpdatedAt int64   `json:"updated_at"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, errors.New("invalid PPanel status report")
	}
	status.UpdatedAt = now.UnixMilli()
	return json.Marshal(status)
}
