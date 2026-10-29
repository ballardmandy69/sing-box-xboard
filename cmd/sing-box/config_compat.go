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
		panelTag := legacyString(apiConfig["PanelTag"])
		if panelTag == "" {
			panelTag = "xboard-" + strconv.Itoa(index)
		}
		nodeType := strings.ToLower(legacyString(apiConfig["NodeType"]))
		service := map[string]any{
			"type":    "xboard",
			"tag":     panelTag,
			"inbound": panelTag,
		}
		autoInbound := map[string]any{}
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
			"ProxyProtocol": "proxy_protocol", "AutoOutIP": "auto_out_ip",
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
		if host := legacyString(apiConfig["ApiHost"]); host != "" {
			service["api_host"] = host
		}
		if key := legacyString(apiConfig["ApiKey"]); key != "" {
			service["api_key"] = key
		}
		if nodeType != "" {
			service["node_type"] = nodeType
		}
		if nodeID, ok := legacyInteger(apiConfig["NodeID"]); ok {
			service["node_id"] = nodeID
		}
		if interval := legacyDuration(node["UpdateInterval"]); interval != "" {
			service["pull_interval"] = interval
			service["push_interval"] = interval
		}
		if timeout := legacyDuration(apiConfig["Timeout"]); timeout != "" {
			service["timeout"] = timeout
		}
		if disableUpload, ok := node["DisableUploadTraffic"].(bool); ok {
			service["disable_upload_traffic"] = disableUpload
		}
		if factor, ok := legacyFloat(node["TrafficFactor"]); ok {
			service["traffic_factor"] = factor
		}
		services = append(services, service)
	}
	root["services"] = services
	if disabled, ok := root["DisableAccessLog"].(bool); ok && disabled {
		logOptions, _ := root["log"].(map[string]any)
		if logOptions == nil {
			logOptions = make(map[string]any)
		}
		logOptions["disabled"] = true
		root["log"] = logOptions
	}
	for _, key := range []string{
		"Nodes", "DisableAccessLog", "DisablePrintAccessLog", "SbApi", "IPLimit", "RateLimit",
		"ConnectionCleanupIntervalSec", "HotUserCacheSec", "ShadowsocksBanIP", "QuicBbrWrongLogic",
		"ConnectionLimit", "MemoryGuard",
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
		if nodeType := legacyString(node["Type"]); nodeType != "" && !strings.EqualFold(nodeType, "UniProxy") {
			return fmt.Errorf("Nodes[%d].Type must be UniProxy", index)
		}
		api, ok := node["ApiConfig"].(map[string]any)
		if !ok {
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
		for _, field := range []string{"AutoOutIP", "ProxyProtocol", "StaticInbound"} {
			if value, exists := node[field]; exists {
				if _, ok := value.(bool); !ok {
					return fmt.Errorf("Nodes[%d].%s must be a boolean", index, field)
				}
			}
		}
	}
	return nil
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
