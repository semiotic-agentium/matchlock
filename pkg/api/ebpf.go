package api

import (
	"encoding/json"
	"strings"

	"github.com/jingkaihe/matchlock/internal/errx"
)

// ParseEBPFPlugin parses an eBPF plugin specification from a CLI flag value.
//
// Accepted formats:
//
//	"TYPE"                         — plugin with default config
//	"TYPE=JSON_CONFIG"             — plugin with explicit JSON config
//
// Examples:
//
//	"sensitive_file_monitor"
//	"sensitive_file_monitor={\"kill\":true}"
//	"sensitive_file_monitor={\"kill\":true,\"patterns\":[\"/etc/shadow\"]}"
func ParseEBPFPlugin(s string) (PluginConfig, error) {
	if s == "" {
		return PluginConfig{}, errx.With(ErrEBPFPluginFormat, ": empty plugin specification")
	}

	// Split on first "=" to separate type from optional JSON config.
	idx := strings.Index(s, "=")
	if idx == -1 {
		// TYPE only — no config
		return PluginConfig{Type: s}, nil
	}

	typeName := s[:idx]
	if typeName == "" {
		return PluginConfig{}, errx.With(ErrEBPFPluginFormat, ": missing plugin type name")
	}

	configStr := s[idx+1:]
	if configStr == "" {
		return PluginConfig{}, errx.With(ErrEBPFPluginFormat, ": empty config after '=' for plugin %q", typeName)
	}

	// Validate that the config is valid JSON.
	if !json.Valid([]byte(configStr)) {
		return PluginConfig{}, errx.With(ErrEBPFPluginFormat, ": invalid JSON config for plugin %q", typeName)
	}

	return PluginConfig{
		Type:   typeName,
		Config: json.RawMessage(configStr),
	}, nil
}
