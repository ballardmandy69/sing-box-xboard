package xboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/common/nodepolicy"
	C "github.com/sagernet/sing-box/constant"
)

// sspanelProvider preserves the SSPanel API and its provider-local online accounting.
// Evidence: nyafw 12d20c0 through 12d8280; full-parity/sspanel-spec.md.
// @author lyt
// @date 2026-10-29
type sspanelProvider struct {
	nodeType string
	access   sync.RWMutex
	etags    map[string]string
	version  string
	rules    []nodepolicy.Rule
	// The original holds this mutex through online HTTP and user normalization.
	onlineAccess sync.Mutex
	online       map[uint64]uint16
}

func newSSPanelProvider(nodeType string) (panelProvider, error) {
	nodeType = strings.ToLower(nodeType)
	switch nodeType {
	case C.TypeVMess, "v2ray", C.TypeVLESS, C.TypeTrojan, C.TypeAnyTLS, C.TypeShadowsocks:
	case C.TypeHysteria2, C.TypeTUIC:
		return nil, C.ErrUDPDisabled
	default:
		return nil, errors.New("unsupported SSPanel node type")
	}
	return &sspanelProvider{nodeType: nodeType, etags: make(map[string]string),
		online: make(map[uint64]uint16)}, nil
}

func (*sspanelProvider) identityTag() string { return "sspanel" }

func (p *sspanelProvider) protocolType() string {
	if p.nodeType == "v2ray" {
		return C.TypeVMess
	}
	return p.nodeType
}

func (p *sspanelProvider) request(ctx context.Context, client *panelClient,
	_, endpoint, _ string, body []byte,
) ([]byte, int, string, error) {
	var path, method, cacheKey string
	withNodeID := true
	var err error
	switch endpoint {
	case "config":
		path = fmt.Sprintf("/mod_mu/nodes/%d/info", client.options.NodeID)
		method, cacheKey, withNodeID = http.MethodGet, "node", false
	case "user":
		path, method, cacheKey = "/mod_mu/users", http.MethodGet, "users"
	case "rules":
		path, method, cacheKey = "/mod_mu/func/detect_rules", http.MethodGet, "rules"
	case "push":
		path, method = "/mod_mu/users/traffic", http.MethodPost
		// OldV2Board's inner traffic array has the same user_id/u/d record layout.
		body, err = oldV2BoardTraffic(body)
		if err != nil {
			return nil, 0, "", errors.New("invalid SSPanel traffic report")
		}
		body, err = sspanelDataBody(json.RawMessage(body))
	case "alive":
		path, method = "/mod_mu/users/aliveip", http.MethodPost
		p.onlineAccess.Lock()
		defer p.onlineAccess.Unlock()
		body, err = p.onlineBody(body)
	case "illegal":
		path, method = "/mod_mu/users/detectlog", http.MethodPost
		var records []panelIllegalRecord
		if err = json.Unmarshal(body, &records); err == nil {
			if records == nil {
				records = []panelIllegalRecord{}
			}
			body, err = sspanelDataBody(records)
		}
	case "status":
		p.access.RLock()
		version := p.version
		p.access.RUnlock()
		if sspanelCompareVersions(version, "2023.2") >= 0 {
			return nil, http.StatusOK, "", nil
		}
		path = fmt.Sprintf("/mod_mu/nodes/%d/info", client.options.NodeID)
		method, withNodeID = http.MethodPost, false
	default:
		return nil, 0, "", errors.New("unsupported SSPanel operation")
	}
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid SSPanel %s report", endpoint)
	}
	data, status, etag, err := p.exchange(ctx, client, method, path, endpoint, cacheKey, withNodeID, body)
	if err != nil || status == http.StatusNotModified || endpoint != "config" {
		return data, status, etag, err
	}
	var info sspanelNodeInfo
	if err = json.Unmarshal(data, &info); err != nil {
		return nil, status, etag, errors.New("invalid SSPanel node response")
	}
	p.access.Lock()
	p.version = info.Version
	p.access.Unlock()
	config, err := p.nodeConfig(ctx, client, info)
	if err != nil {
		return nil, status, etag, err
	}
	data, err = json.Marshal(config)
	return data, status, etag, err
}

func (p *sspanelProvider) exchange(ctx context.Context, client *panelClient,
	method, path, endpoint, cacheKey string, withNodeID bool, body []byte,
) ([]byte, int, string, error) {
	requestURL, err := url.Parse(client.options.APIHost + path)
	if err != nil {
		return nil, 0, "", errors.New("invalid SSPanel request URL")
	}
	query := requestURL.Query()
	query.Set("key", client.options.APIKey)
	query.Set("muKey", client.options.APIKey)
	if withNodeID {
		query.Set("node_id", strconv.Itoa(client.options.NodeID))
	}
	requestURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, "", errors.New("invalid SSPanel request")
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cacheKey != "" {
		p.access.RLock()
		etag := p.etags[cacheKey]
		p.access.RUnlock()
		if etag != "" {
			request.Header.Set("If-None-Match", etag)
		}
	}
	response, status, etag, err := client.doRequest(request, endpoint)
	if err != nil || status == http.StatusNotModified {
		return nil, status, etag, err
	}
	var envelope struct {
		Ret  uint64          `json:"ret"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil {
		return nil, status, etag, fmt.Errorf("invalid SSPanel %s response", endpoint)
	}
	if envelope.Ret != 1 {
		return nil, status, etag, fmt.Errorf("SSPanel %s response ret is not 1", endpoint)
	}
	// This precedes payload parsing, as in the original provider. Empty validators do not clear the cache.
	if cacheKey != "" && etag != "" {
		p.access.Lock()
		p.etags[cacheKey] = etag
		p.access.Unlock()
	}
	return envelope.Data, status, etag, nil
}

// sspanelUser retains the original numeric widths used by JSON decoding.
// @author lyt
// @date 2026-10-29
type sspanelUser struct {
	ID            uint64  `json:"id"`
	Email         string  `json:"email"`
	UUID          string  `json:"uuid"`
	Password      string  `json:"passwd"`
	Port          uint16  `json:"port"`
	DeviceLimit   uint16  `json:"node_connector"`
	AliveIP       uint16  `json:"alive_ip"`
	MultiUser     uint16  `json:"is_multi_user"`
	SpeedLimit    float64 `json:"node_speedlimit"`
	Method        string  `json:"method"`
	ForbiddenIP   string  `json:"forbidden_ip"`
	ForbiddenPort string  `json:"forbidden_port"`
}

func (p *sspanelProvider) decodeUsers(body []byte) (usersResponse, error) {
	var input []sspanelUser
	if err := json.Unmarshal(body, &input); err != nil {
		return usersResponse{}, errors.New("invalid SSPanel users response")
	}
	p.onlineAccess.Lock()
	defer p.onlineAccess.Unlock()
	result := usersResponse{Users: make([]panelUser, 0, len(input))}
	for _, source := range input {
		limit := source.DeviceLimit
		if limit != 0 && source.AliveIP != 0 {
			local := p.online[source.ID]
			limit = limit - source.AliveIP + local
			if limit == 0 {
				limit = local
				if limit == 0 {
					continue
				}
			}
		}
		credential := source.UUID
		if credential == "" {
			if source.Password == "" {
				continue
			}
			identity := uuid.FromStringOrNil(source.Password)
			if identity.IsNil() {
				identity = uuid.NewV5(uuid.Nil, source.Password)
			}
			credential = identity.String()
		}
		speed := uint64(source.SpeedLimit * 1_000_000 * 0.125)
		user := panelUser{ID: source.ID, UUID: credential, DeviceLimit: int16(limit), SpeedLimitBytes: &speed}
		if p.nodeType == C.TypeShadowsocks {
			user.ProtocolPassword = source.Password
		}
		result.Users = append(result.Users, user)
	}
	return result, nil
}

func (p *sspanelProvider) onlineBody(body []byte) ([]byte, error) {
	var input map[string][]string
	if err := json.Unmarshal(body, &input); err != nil {
		return nil, errors.New("invalid SSPanel online report")
	}
	type record struct {
		UserID uint64 `json:"user_id"`
		IP     string `json:"ip"`
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	counts := make(map[uint64]uint16, len(keys))
	records := make([]record, 0)
	for _, key := range keys {
		id, err := strconv.ParseUint(key, 10, 64)
		if err != nil {
			return nil, errors.New("invalid SSPanel online user ID")
		}
		for _, ip := range input[key] {
			records = append(records, record{UserID: id, IP: ip})
			counts[id]++
		}
	}
	p.online = counts
	return sspanelDataBody(records)
}

func sspanelDataBody(value any) ([]byte, error) {
	return json.Marshal(struct {
		Data any `json:"data"`
	}{value})
}

func (p *sspanelProvider) NodeRules() []nodepolicy.Rule {
	p.access.RLock()
	defer p.access.RUnlock()
	return slices.Clone(p.rules)
}

func (p *sspanelProvider) RefreshNodeRules(ctx context.Context, client *panelClient) error {
	body, status, _, err := p.request(ctx, client, http.MethodGet, "rules", "", nil)
	if err != nil || status == http.StatusNotModified {
		return err
	}
	var rows []struct {
		ID      int    `json:"id"`
		Pattern string `json:"regex"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return errors.New("invalid SSPanel rules response")
	}
	rules := make([]nodepolicy.Rule, 0, len(rows))
	for _, row := range rows {
		if _, err := regexp.Compile(row.Pattern); err != nil {
			return fmt.Errorf("invalid SSPanel rule %d", row.ID)
		}
		rules = append(rules, nodepolicy.Rule{ID: row.ID, Pattern: row.Pattern})
	}
	p.access.Lock()
	p.rules = rules
	p.access.Unlock()
	return nil
}

func (p *sspanelProvider) reportIllegal(ctx context.Context, client *panelClient, records []panelIllegalRecord) error {
	body, err := json.Marshal(records)
	if err != nil {
		return err
	}
	_, status, _, err := p.request(ctx, client, http.MethodPost, "illegal", "", body)
	if err != nil {
		return err
	}
	if !successfulStatus(status) {
		return fmt.Errorf("unexpected SSPanel illegal report HTTP status: %d", status)
	}
	return nil
}

func (p *sspanelProvider) reportStatus(ctx context.Context, client *panelClient) error {
	// The controller supplies fixed compatibility values, not measured system utilization.
	body := []byte(`{"uptime":"100","load":"1.00 1.00 1.00"}`)
	_, status, _, err := p.request(ctx, client, http.MethodPost, "status", "", body)
	if err != nil {
		return err
	}
	if !successfulStatus(status) {
		return fmt.Errorf("unexpected SSPanel status report HTTP status: %d", status)
	}
	return nil
}

func sspanelCompareVersions(first, second string) int {
	a, b := strings.Split(first, "."), strings.Split(second, ".")
	parse := func(parts []string, index int) int64 {
		if index >= len(parts) {
			return 0
		}
		var value int64
		for _, digit := range []byte(parts[index]) {
			value = value*10 + int64(digit-'0')
		}
		return value
	}
	for index := range max(len(a), len(b)) {
		x, y := parse(a, index), parse(b, index)
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

// sspanelNodeInfo contains fields consumed by the original node parsers.
// @author lyt
// @date 2026-10-29
type sspanelNodeInfo struct {
	NodeGroup    int64           `json:"node_group"`
	NodeClass    int64           `json:"node_class"`
	SpeedLimit   float64         `json:"node_speedlimit"`
	TrafficRate  float64         `json:"traffic_rate"`
	MUOnly       int64           `json:"mu_only"`
	Sort         int64           `json:"sort"`
	Server       string          `json:"server"`
	Type         string          `json:"type"`
	Version      string          `json:"version"`
	CustomConfig json.RawMessage `json:"custom_config"`
}

// sspanelCustomConfig intentionally excludes fields ignored by the original parser.
// @author lyt
// @date 2026-10-29
type sspanelCustomConfig struct {
	Port        string `json:"offset_port_node"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	ServiceName string `json:"servicename"`
	Method      string `json:"mu_encryption"`
	ServerKey   string `json:"server_key"`
	Network     string `json:"network"`
	Security    string `json:"security"`
	VLESS       string `json:"enable_vless"`
	GRPC        string `json:"grpc"`
}

func (p *sspanelProvider) nodeConfig(ctx context.Context, client *panelClient,
	info sspanelNodeInfo,
) (autoConfigResponse, error) {
	result := autoConfigResponse{Protocol: p.protocolType(), TLS: json.RawMessage("0")}
	if info.Version != "" {
		return p.customNodeConfig(result, info.CustomConfig)
	}
	switch p.nodeType {
	case C.TypeVMess, "v2ray", C.TypeVLESS:
		return sspanelLegacyVMess(result, info.Server)
	case C.TypeTrojan:
		return sspanelLegacyTrojan(result, info.Server)
	case C.TypeShadowsocks:
		// This second request is neither ETag-cached nor filtered through user/device normalization.
		body, _, _, err := p.exchange(ctx, client, http.MethodGet, "/mod_mu/users", "config users", "", true, nil)
		if err != nil {
			return result, err
		}
		var users []sspanelUser
		if err := json.Unmarshal(body, &users); err != nil {
			return result, errors.New("invalid SSPanel shared Shadowsocks user response")
		}
		for _, user := range users {
			if user.MultiUser == 0 {
				continue
			}
			if user.Port == 0 || user.Method == "" {
				return result, errors.New("SSPanel shared Shadowsocks user has no port or method")
			}
			result.ServerPort = json.RawMessage(strconv.FormatUint(uint64(user.Port), 10))
			result.Cipher, result.Network = user.Method, "tcp"
			return result, nil
		}
		return result, errors.New("SSPanel shared Shadowsocks user is missing")
	default:
		return result, errors.New("SSPanel legacy node format does not support this protocol")
	}
}

func (p *sspanelProvider) customNodeConfig(result autoConfigResponse, body []byte) (autoConfigResponse, error) {
	var config sspanelCustomConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return result, errors.New("invalid SSPanel custom_config")
	}
	port, err := sspanelPort(config.Port)
	if err != nil {
		return result, err
	}
	result.ServerPort, result.Cipher, result.ServerKey = port, config.Method, config.ServerKey
	switch p.nodeType {
	case C.TypeShadowsocks:
		result.Network = "tcp"
	case C.TypeVMess, "v2ray", C.TypeVLESS:
		result.PanelVLESS = config.VLESS == "1"
		result.Network = config.Network
		if config.Security == "tls" || config.Security == "xtls" {
			result.TLS = json.RawMessage("1")
		}
	case C.TypeTrojan:
		result.TLS, result.Network = json.RawMessage("1"), config.Network
		if config.GRPC == "1" {
			result.Network = "grpc"
		} else if result.Network == "" {
			result.Network = "tcp"
		}
	}
	sspanelTransport(&result, config.Host, config.Path, config.ServiceName)
	return result, nil
}

func sspanelPort(value string) (json.RawMessage, error) {
	port, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return nil, errors.New("invalid SSPanel node port")
	}
	return json.RawMessage(strconv.FormatUint(uint64(uint16(port)), 10)), nil
}

func sspanelTransport(result *autoConfigResponse, host, path, serviceName string) {
	if result.Network == "" || strings.EqualFold(result.Network, "tcp") {
		return
	}
	if strings.EqualFold(result.Network, "ws") {
		result.NetworkSettings, _ = json.Marshal(map[string]any{
			"host": host, "path": path, "serviceName": serviceName,
			"headers": map[string]string{"Host": host},
		})
		return
	}
	result.NetworkSettings, _ = json.Marshal(panelTransportSettings{
		Host: host, Path: path, ServiceName: serviceName,
	})
}

func sspanelLegacyVMess(result autoConfigResponse, server string) (autoConfigResponse, error) {
	parts := strings.Split(server, ";")
	if server == "" || len(parts) < 6 {
		return result, errors.New("SSPanel legacy V2Ray server requires six semicolon-separated fields")
	}
	var err error
	result.ServerPort, err = sspanelPort(parts[1])
	if err != nil {
		return result, err
	}
	for _, value := range parts[3:5] {
		if value == "tls" {
			result.TLS = json.RawMessage("1")
		} else if value != "" {
			result.Network = value
		}
	}
	parameters, err := sspanelParameters(parts[5], true)
	if err != nil {
		return result, err
	}
	sspanelTransport(&result, parameters["host"], parameters["path"], parameters["servicename"])
	return result, nil
}

var (
	sspanelTrojanPort      = regexp.MustCompile(`(?m)port=(?P<outport>\d+)#?`)
	sspanelTrojanInnerPort = regexp.MustCompile(`(?m)port=\d+#(\d+)`)
	sspanelTrojanHost      = regexp.MustCompile(`(?m)host=([\w.]+)\|?`)
)

func sspanelLegacyTrojan(result autoConfigResponse, server string) (autoConfigResponse, error) {
	parts := strings.Split(server, ";")
	if server == "" || len(parts) < 2 {
		return result, errors.New("SSPanel legacy Trojan server requires two semicolon-separated fields")
	}
	find := func(pattern *regexp.Regexp) string {
		match := pattern.FindStringSubmatch(server)
		if len(match) < 2 {
			return ""
		}
		return match[1]
	}
	port := find(sspanelTrojanInnerPort)
	if port == "" {
		port = find(sspanelTrojanPort)
	}
	var err error
	result.ServerPort, err = sspanelPort(port)
	if err != nil {
		return result, err
	}
	parameters, err := sspanelParameters(parts[1], false)
	if err != nil {
		return result, err
	}
	result.TLS, result.Network = json.RawMessage("1"), "tcp"
	if _, exists := parameters["grpc"]; exists {
		result.Network = "grpc"
	}
	sspanelTransport(&result, find(sspanelTrojanHost), "", parameters["servicename"])
	return result, nil
}

func sspanelParameters(value string, joinPath bool) (map[string]string, error) {
	result := make(map[string]string)
	for _, item := range strings.Split(value, "|") {
		parts := strings.Split(item, "=")
		if parts[0] == "" {
			continue
		}
		if len(parts) < 2 {
			return nil, errors.New("SSPanel legacy parameter requires an equals sign")
		}
		if joinPath && parts[0] == "path" {
			result[parts[0]] = strings.Join(parts[1:], "=")
		} else {
			result[parts[0]] = parts[1]
		}
	}
	return result, nil
}
