package xboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/common/nodepolicy"
	C "github.com/sagernet/sing-box/constant"
)

// oldV2BoardProvider implements the original protocol-specific legacy panel API.
// Evidence: nyafw GetNodeInfo/GetUserList/ReportUserTraffic at 12b0b60/12b18e0/12b2fa0.
// @author lyt
// @date 2026-10-29
type oldV2BoardProvider struct {
	nodeType  string
	namespace string
	access    sync.RWMutex
	rules     []*regexp.Regexp
}

func newOldV2BoardProvider(nodeType string) (*oldV2BoardProvider, error) {
	p := &oldV2BoardProvider{nodeType: strings.ToLower(nodeType)}
	switch p.nodeType {
	case "v2ray":
		p.namespace = "Deepbwork"
	case "trojan", "trojantidalab":
		p.namespace = "TrojanTidalab"
	case "shadowsocks":
		p.namespace = "ShadowsocksObfsMu"
	case "shadowsockstidalab":
		p.namespace = "ShadowsocksTidalab"
	default:
		return nil, fmt.Errorf("unsupported oldv2board node_type")
	}
	return p, nil
}

func (*oldV2BoardProvider) identityTag() string { return "oldv2b" }

func (p *oldV2BoardProvider) protocolType() string {
	switch p.nodeType {
	case "v2ray":
		return C.TypeVMess
	case "trojan", "trojantidalab":
		return C.TypeTrojan
	default:
		return C.TypeShadowsocks
	}
}

func (p *oldV2BoardProvider) NodeRules() []nodepolicy.Rule {
	p.access.RLock()
	defer p.access.RUnlock()
	rules := make([]nodepolicy.Rule, len(p.rules))
	for index, pattern := range p.rules {
		rules[index] = nodepolicy.Rule{ID: index, Pattern: pattern.String()}
	}
	return rules
}

func (p *oldV2BoardProvider) request(ctx context.Context, client *panelClient,
	method, endpoint, _ string, body []byte,
) ([]byte, int, string, error) {
	if endpoint == "alive" || endpoint == "status" || endpoint == "illegal" {
		return nil, http.StatusOK, "", nil
	}
	action := endpoint
	switch endpoint {
	case "config":
		method = http.MethodGet
		if p.nodeType == "shadowsocks" || p.nodeType == "shadowsockstidalab" {
			action = "user"
		}
	case "user":
		method = http.MethodGet
	case "push":
		action, method = "submit", http.MethodPost
		var err error
		body, err = oldV2BoardTraffic(body)
		if err != nil {
			return nil, 0, "", err
		}
	default:
		return nil, 0, "", fmt.Errorf("unsupported oldv2board request %s", endpoint)
	}
	requestURL, err := url.Parse(client.options.APIHost + "/api/v1/server/" + p.namespace + "/" + action)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid oldv2board request URL")
	}
	query := requestURL.Query()
	query.Set("node_id", strconv.Itoa(client.options.NodeID))
	query.Set("token", client.options.APIKey)
	requestURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid oldv2board request")
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, status, _, err := client.doRequest(request, endpoint)
	if err != nil {
		return nil, status, "", err
	}
	if status == http.StatusNotModified {
		return nil, status, "", nil
	}
	// The legacy adapter always parses JSON and never sends ETag validators.
	root, err := decodeOldV2BoardJSON(response)
	if err != nil {
		return nil, status, "", err
	}
	if endpoint == "config" {
		config, err := p.nodeConfig(root)
		if err != nil {
			return nil, status, "", err
		}
		response, err = json.Marshal(config)
		return response, status, "", err
	}
	return response, status, "", nil
}

func (p *oldV2BoardProvider) decodeUsers(body []byte) (usersResponse, error) {
	root, err := decodeOldV2BoardJSON(body)
	if err != nil {
		return usersResponse{}, err
	}
	users, _, _ := p.users(root)
	return usersResponse{Users: users}, nil
}

func (p *oldV2BoardProvider) users(root any) ([]panelUser, string, uint16) {
	rows, _ := oldV2BoardField(root, "data").([]any)
	users := make([]panelUser, 0, len(rows))
	var method string
	var port uint16
	for _, row := range rows {
		user := panelUser{ID: oldV2BoardUint(oldV2BoardField(row, "id"))}
		switch p.nodeType {
		case "v2ray":
			user.UUID = oldV2BoardString(oldV2BoardField(row, "v2ray_user", "uuid"))
		case "trojan":
			// Original converter stores the Trojan password directly in the UUID slot.
			user.UUID = oldV2BoardString(oldV2BoardField(row, "trojan_user", "password"))
		case "shadowsocks", "shadowsockstidalab":
			user.ProtocolPassword = oldV2BoardString(oldV2BoardField(row, "secret"))
			if method == "" {
				method = oldV2BoardString(oldV2BoardField(row, "cipher"))
				port = uint16(oldV2BoardUint(oldV2BoardField(row, "port")))
			}
		}
		// trojantidalab selects a URL alias, but the original converter only extracts
		// credentials for exact "trojan". Preserve that distinction instead of inventing an alias.
		if user.UUID == "" && user.ProtocolPassword != "" {
			identity := uuid.FromStringOrNil(user.ProtocolPassword)
			if identity.IsNil() {
				identity = uuid.NewV5(uuid.Nil, user.ProtocolPassword)
			}
			user.UUID = identity.String()
		}
		if user.UUID != "" {
			users = append(users, user)
		}
	}
	return users, method, port
}

func (p *oldV2BoardProvider) nodeConfig(root any) (autoConfigResponse, error) {
	var result autoConfigResponse
	switch p.nodeType {
	case "shadowsocks", "shadowsockstidalab":
		users, method, port := p.users(root)
		if len(users) == 0 {
			return result, fmt.Errorf("oldv2board Shadowsocks node requires a nonempty user list")
		}
		result.Protocol, result.Network, result.Cipher = C.TypeShadowsocks, "tcp", method
		result.ServerPort = json.RawMessage(strconv.FormatUint(uint64(port), 10))
	case "trojan", "trojantidalab":
		result.Protocol, result.Network = C.TypeTrojan, "tcp"
		port := uint16(oldV2BoardUint(oldV2BoardField(root, "local_port")))
		result.ServerPort = json.RawMessage(strconv.FormatUint(uint64(port), 10))
		result.ServerName = oldV2BoardString(oldV2BoardField(root, "ssl", "sni"))
		result.TLS = json.RawMessage(`1`)
	case "v2ray":
		object, _ := root.(map[string]any)
		inbound, exists := object["inbound"]
		if !exists {
			inbounds, exists := oldV2BoardField(root, "inbounds").([]any)
			if !exists || len(inbounds) == 0 {
				return result, fmt.Errorf("oldv2board V2Ray configuration has no inbound")
			}
			inbound = inbounds[0]
		}
		result.Protocol = C.TypeVMess
		port := uint16(oldV2BoardUint(oldV2BoardField(inbound, "port")))
		result.ServerPort = json.RawMessage(strconv.FormatUint(uint64(port), 10))
		stream := oldV2BoardField(inbound, "streamSettings")
		result.Network = oldV2BoardString(oldV2BoardField(stream, "network"))
		result.TLS = json.RawMessage(`0`)
		if oldV2BoardString(oldV2BoardField(stream, "security")) == "tls" {
			result.TLS = json.RawMessage(`1`)
		}
		switch result.Network {
		case "ws":
			result.NetworkSettings, _ = json.Marshal(map[string]any{
				"path": oldV2BoardString(oldV2BoardField(stream, "wsSettings", "path")),
				"headers": map[string]string{
					"Host": oldV2BoardString(oldV2BoardField(stream, "wsSettings", "headers", "Host")),
				},
			})
		case "grpc":
			result.NetworkSettings, _ = json.Marshal(map[string]string{
				"serviceName": oldV2BoardString(oldV2BoardField(stream, "grpcSettings", "serviceName")),
			})
		}
		rules, err := oldV2BoardRules(root)
		if err != nil {
			return result, err
		}
		p.access.Lock()
		p.rules = rules
		p.access.Unlock()
	}
	return result, nil
}

func oldV2BoardRules(root any) ([]*regexp.Regexp, error) {
	routingRules, _ := oldV2BoardField(root, "routing", "rules").([]any)
	if len(routingRules) < 2 {
		return nil, nil
	}
	domains, _ := oldV2BoardField(routingRules[1], "domain").([]any)
	for _, domain := range domains {
		if _, ok := domain.(string); !ok {
			return nil, nil
		}
	}
	result := make([]*regexp.Regexp, 0, len(domains))
	for index, domain := range domains {
		rule, err := regexp.Compile(strings.TrimPrefix(domain.(string), "regexp:"))
		if err != nil {
			return nil, fmt.Errorf("invalid oldv2board domain rule at index %d", index)
		}
		result = append(result, rule)
	}
	return result, nil
}

func oldV2BoardTraffic(body []byte) ([]byte, error) {
	var traffic map[string][2]int64
	if err := json.Unmarshal(body, &traffic); err != nil {
		return nil, fmt.Errorf("invalid oldv2board traffic data")
	}
	type record struct {
		UserID   uint64 `json:"user_id"`
		Upload   int64  `json:"u"`
		Download int64  `json:"d"`
	}
	records := make([]record, 0, len(traffic))
	for key, counters := range traffic {
		id, err := strconv.ParseUint(key, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid oldv2board traffic user ID")
		}
		records = append(records, record{id, counters[0], counters[1]})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].UserID < records[j].UserID })
	return json.Marshal(records)
}

func decodeOldV2BoardJSON(body []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("invalid oldv2board JSON response")
	}
	return value, nil
}

func oldV2BoardField(value any, names ...string) any {
	for _, name := range names {
		object, _ := value.(map[string]any)
		value = object[name]
	}
	return value
}

func oldV2BoardString(value any) string {
	text, _ := value.(string)
	return text
}

func oldV2BoardUint(value any) uint64 {
	number, ok := value.(json.Number)
	if !ok {
		return 0
	}
	parsed, err := strconv.ParseUint(string(number), 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}
