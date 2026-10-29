package main

import (
	"fmt"
	"strconv"
	"strings"
)

func normalizeLegacyConfigValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			typed[key] = normalizeLegacyConfigValue(item)
		}
		return typed
	case map[any]any:
		converted := make(map[string]any, len(typed))
		for key, item := range typed {
			converted[fmt.Sprint(key)] = normalizeLegacyConfigValue(item)
		}
		return converted
	case []any:
		for index, item := range typed {
			typed[index] = normalizeLegacyConfigValue(item)
		}
		return typed
	default:
		return value
	}
}

func normalizeLegacyServerConfig(value any) any {
	root, ok := value.(map[string]any)
	if !ok {
		return value
	}
	rawNodes, hasNodes := root["Nodes"]
	if !hasNodes {
		return root
	}
	nodes, ok := rawNodes.([]any)
	if !ok {
		return root
	}
	services, _ := root["services"].([]any)
	for index, rawNode := range nodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			continue
		}
		apiConfig, _ := node["ApiConfig"].(map[string]any)
		panelType := legacyPanelType(node, apiConfig)
		panelTag := legacyString(apiConfig["PanelTag"])
		if panelTag == "" {
			panelTag = "xboard-" + strconv.Itoa(index)
		}
		nodeType := strings.ToLower(legacyString(apiConfig["NodeType"]))
		service := map[string]any{
			"type":          "xboard",
			"tag":           panelTag,
			"inbound":       panelTag,
			"sync_interval": "0s",
		}
		if panelType == "multi" {
			rawPanels, _ := node["MultiApiConfig"].([]any)
			panels := make([]any, 0, len(rawPanels))
			for _, rawPanel := range rawPanels {
				panel, _ := rawPanel.(map[string]any)
				panels = append(panels, normalizeLegacyPanelAPI(panel, "uniproxy"))
			}
			service["panels"] = panels
			if len(rawPanels) > 0 {
				primary, _ := rawPanels[0].(map[string]any)
				nodeType = strings.ToLower(legacyString(primary["NodeType"]))
			}
		} else {
			for field, value := range normalizeLegacyPanelAPI(apiConfig, panelType) {
				if field != "panel_tag" {
					service[field] = value
				}
			}
		}
		for legacyKey, field := range map[string]string{
			"IPLimit": "ip_limit", "ConnectionLimit": "connection_limit", "RateLimit": "rate_limit",
		} {
			if value, exists := root[legacyKey]; exists {
				if number, ok := legacyInteger(value); ok {
					service[field] = number
				} else {
					service[field] = value
				}
			}
		}
		if maximum, exists := root["MaxSpeedLimit"]; exists {
			service["default_max_speed_limit"] = fmt.Sprint(maximum)
		}
		if maximum, exists := node["MaxSpeedLimit"]; exists {
			service["max_speed_limit"] = fmt.Sprint(maximum)
		}
		autoInbound := map[string]any{}
		if obfs, exists := node["ShadowsocksObfsMu"]; exists {
			autoInbound["shadowsocks_obfs_mu"] = obfs
		}
		if protocol := legacyString(node["Protocol"]); protocol != "" {
			autoInbound["protocol"] = strings.ToLower(protocol)
		}
		if listen := legacyString(node["ListenIP"]); listen != "" {
			autoInbound["listen"] = listen
		}
		if port, ok := legacyInteger(node["ListenPort"]); ok {
			autoInbound["listen_port"] = port
		}
		for legacyKey, field := range map[string]string{
			"ProxyProtocol": "proxy_protocol", "AutoOutIP": "auto_out_ip", "ForceVision": "force_vision",
		} {
			if enabled, ok := node[legacyKey].(bool); ok {
				autoInbound[field] = enabled
			}
		}
		certConfig, _ := node["CertConfig"].(map[string]any)
		for legacyKey, field := range map[string]string{"CertFile": "certificate_path", "KeyFile": "key_path"} {
			if path := legacyString(certConfig[legacyKey]); path != "" {
				autoInbound[field] = path
			}
		}
		for legacyKey, field := range map[string]string{"PrivateKey": "private_key", "PrivateKeyPath": "private_key_path"} {
			if key := legacyString(node[legacyKey]); key != "" {
				autoInbound[field] = key
			}
		}
		if static, _ := node["StaticInbound"].(bool); !static {
			service["auto_inbound"] = autoInbound
		}
		if nodeType != "" {
			service["node_type"] = nodeType
		}
		if interval := legacyDuration(node["UpdateInterval"]); interval != "" {
			service["sync_interval"] = interval
		}
		if reportAlive, ok := apiConfig["ReportAlive"].(bool); ok {
			service["report_alive"] = reportAlive
		}
		if disableUpload, ok := node["DisableUploadTraffic"].(bool); ok {
			service["disable_upload_traffic"] = disableUpload
		}
		factor, factorSet := legacyFloat(node["TrafficFactor"])
		if !factorSet || factor <= 0 {
			factor, factorSet = legacyFloat(root["TrafficFactor"])
		}
		if factorSet {
			service["traffic_factor"] = factor
		}
		services = append(services, service)
	}
	root["services"] = services
	nyafw, _ := root["nyafw"].(map[string]any)
	if nyafw == nil {
		nyafw = make(map[string]any)
	}
	if interval, exists := root["ConnectionCleanupIntervalSec"]; exists {
		nyafw["connection_cleanup_interval_sec"] = interval
	}
	if duration, exists := root["HotUserCacheSec"]; exists {
		nyafw["hot_user_cache_sec"] = duration
	}
	if mode, exists := root["AccessLog"]; exists {
		nyafw["access_log"] = mode
	} else if disabled, _ := root["DisableAccessLog"].(bool); disabled {
		// Compatibility alias: it controls access records, never process error logs.
		nyafw["access_log"] = 2
	}
	if rawAPI, exists := root["SbApi"]; exists {
		if api, ok := rawAPI.(map[string]any); ok {
			converted := make(map[string]any)
			for old, field := range map[string]string{
				"BaseURL": "base_url", "Tag": "tag", "Token": "token", "SendTokenInQuery": "send_token_in_query",
			} {
				if value, exists := api[old]; exists {
					converted[field] = value
				}
			}
			nyafw["sb_api"] = converted
		} else {
			nyafw["sb_api"] = rawAPI
		}
	}
	root["nyafw"] = nyafw
	for _, key := range []string{
		"Nodes", "AccessLog", "DisableAccessLog", "DisablePrintAccessLog", "SbApi", "IPLimit", "RateLimit",
		"ConnectionCleanupIntervalSec", "HotUserCacheSec", "ShadowsocksBanIP", "QuicBbrWrongLogic",
		"ConnectionLimit", "MemoryGuard", "MaxSpeedLimit", "TrafficFactor",
	} {
		delete(root, key)
	}
	return root
}

// validateLegacyNodes rejects malformed node declarations before conversion can discard their values.
// @author lyt
// @date 2026-10-29
func validateLegacyNodes(value any) error {
	root, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	rawNodes, exists := root["Nodes"]
	if !exists {
		return nil
	}
	nodes, ok := rawNodes.([]any)
	if !ok {
		return fmt.Errorf("Nodes must be an array; use Nodes: [] for no panel nodes")
	}
	tags := make(map[string]bool, len(nodes))
	for index, rawNode := range nodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			return fmt.Errorf("Nodes[%d] must be an object", index)
		}
		api, ok := node["ApiConfig"].(map[string]any)
		panelType := legacyPanelType(node, api)
		if panelType != "uniproxy" && panelType != "multi" {
			return fmt.Errorf("Nodes[%d].Type must be UniProxy or multi in the current reconstruction", index)
		}
		if panelType == "multi" {
			panels, ok := node["MultiApiConfig"].([]any)
			if !ok || len(panels) == 0 {
				return fmt.Errorf("Nodes[%d].MultiApiConfig must be a nonempty array", index)
			}
			for child, rawPanel := range panels {
				panel, ok := rawPanel.(map[string]any)
				if !ok {
					return fmt.Errorf("Nodes[%d].MultiApiConfig[%d] must be an object", index, child)
				}
				if kind := legacyString(panel["Type"]); kind != "" && !strings.EqualFold(kind, "uniproxy") {
					return fmt.Errorf("Nodes[%d].MultiApiConfig[%d].Type currently supports only UniProxy", index, child)
				}
			}
		} else if !ok {
			return fmt.Errorf("Nodes[%d].ApiConfig must be an object", index)
		}
		tag := legacyString(api["PanelTag"])
		if tag == "" {
			tag = "xboard-" + strconv.Itoa(index)
		}
		if tags[tag] {
			return fmt.Errorf("Nodes[%d].ApiConfig.PanelTag must be unique", index)
		}
		tags[tag] = true
		if value, exists := node["ListenPort"]; exists {
			port, ok := legacyInteger(value)
			if !ok || port < 0 || port > 65535 {
				return fmt.Errorf("Nodes[%d].ListenPort must be an integer between 0 and 65535", index)
			}
		}
		for _, field := range []string{"AutoOutIP", "ProxyProtocol", "StaticInbound", "ForceVision"} {
			if value, exists := node[field]; exists {
				if _, ok := value.(bool); !ok {
					return fmt.Errorf("Nodes[%d].%s must be a boolean", index, field)
				}
			}
		}
	}
	return nil
}

func legacyPanelType(node, api map[string]any) string {
	kind := legacyString(api["Type"])
	if kind == "" {
		kind = legacyString(node["Type"])
	}
	if kind == "" {
		kind = "uniproxy"
	}
	return strings.ToLower(kind)
}

func normalizeLegacyPanelAPI(api map[string]any, fallbackType string) map[string]any {
	kind := legacyString(api["Type"])
	if kind == "" {
		kind = fallbackType
	}
	result := map[string]any{"panel_type": strings.ToLower(kind)}
	for legacy, field := range map[string]string{
		"PanelTag": "panel_tag", "ApiHost": "api_host", "ApiKey": "api_key", "NodeType": "node_type",
	} {
		if value := legacyString(api[legacy]); value != "" {
			if field == "node_type" {
				value = strings.ToLower(value)
			}
			result[field] = value
		}
	}
	if nodeID, ok := legacyInteger(api["NodeID"]); ok {
		result["node_id"] = nodeID
	}
	if timeout := legacyDuration(api["Timeout"]); timeout != "" {
		result["timeout"] = timeout
	}
	return result
}

func legacyString(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func legacyInteger(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), typed == float64(int(typed))
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func legacyFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case int:
		return float64(typed), true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func legacyDuration(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	if number, ok := legacyFloat(value); ok {
		return strconv.FormatFloat(number, 'f', -1, 64) + "s"
	}
	return ""
}
