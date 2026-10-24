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
