package ebpf

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
)

// Default sensitive file patterns. These are checked when no custom
// patterns are provided in the plugin configuration.
var defaultSensitivePatterns = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d/*",
	"/root/.ssh/*",
	"/home/*/.ssh/id_*",
	"/home/*/.ssh/authorized_keys",
	"/etc/ssl/private/*",
	"/etc/ssh/ssh_host_*_key",
}

// SensitiveFileMonitorConfig is the JSON configuration for the
// sensitive_file_monitor plugin.
type SensitiveFileMonitorConfig struct {
	// Patterns is a list of glob patterns for sensitive file paths.
	// If empty, defaultSensitivePatterns is used.
	Patterns []string `json:"patterns,omitempty"`
	// Kill controls whether the offending process is terminated.
	// When true, the engine sends kill -9 to the process.
	Kill bool `json:"kill,omitempty"`
}

// SensitiveFileAccessData is the typed data payload emitted to the
// shared event log when a sensitive file access is detected.
type SensitiveFileAccessData struct {
	Filepath string `json:"filepath"`
	PID      int    `json:"pid"`
	Comm     string `json:"comm"`
	Pattern  string `json:"matched_pattern"`
	Action   string `json:"action"` // "alert" or "killed"
}

type sensitiveFileMonitorPlugin struct {
	config SensitiveFileMonitorConfig
	logger *slog.Logger
}

// NewSensitiveFileMonitor creates a new sensitive file monitor plugin.
func NewSensitiveFileMonitor(config SensitiveFileMonitorConfig, logger *slog.Logger) *sensitiveFileMonitorPlugin {
	if len(config.Patterns) == 0 {
		config.Patterns = defaultSensitivePatterns
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &sensitiveFileMonitorPlugin{
		config: config,
		logger: logger,
	}
}

// NewSensitiveFileMonitorFromConfig is the factory function for the plugin registry.
func NewSensitiveFileMonitorFromConfig(raw json.RawMessage, logger *slog.Logger) (Plugin, error) {
	var config SensitiveFileMonitorConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &config); err != nil {
			return nil, fmt.Errorf("sensitive_file_monitor: invalid config: %w", err)
		}
	}
	return NewSensitiveFileMonitor(config, logger), nil
}

func (p *sensitiveFileMonitorPlugin) Name() string {
	return "sensitive_file_monitor"
}

// ProcessEvent checks FILE_OPEN events against sensitive file patterns.
func (p *sensitiveFileMonitorPlugin) ProcessEvent(event *EBPFEvent) *EventVerdict {
	if event.Event != "FILE_OPEN" {
		return nil
	}

	fp := event.Filepath
	if fp == "" {
		return nil
	}

	for _, pattern := range p.config.Patterns {
		if matchPath(pattern, fp) {
			action := "alert"
			if p.config.Kill {
				action = "killed"
			}

			return &EventVerdict{
				Alert:  true,
				Kill:   p.config.Kill,
				Action: action,
				Reason: fmt.Sprintf("sensitive file access: %s opened %s (matched %s)",
					event.Comm, fp, pattern),
				Data: &SensitiveFileAccessData{
					Filepath: fp,
					PID:      event.PID,
					Comm:     event.Comm,
					Pattern:  pattern,
					Action:   action,
				},
			}
		}
	}

	return nil
}

// matchPath checks if a filepath matches a glob pattern.
// Supports standard glob syntax via filepath.Match, plus a leading
// double-star prefix is treated as matching any directory prefix.
func matchPath(pattern, path string) bool {
	// Exact match
	if pattern == path {
		return true
	}

	// filepath.Match for standard glob patterns
	matched, err := filepath.Match(pattern, path)
	if err == nil && matched {
		return true
	}

	// For patterns like "/home/*/.ssh/id_*", filepath.Match handles
	// single-level wildcards. For suffix matching (e.g., "*.pem"),
	// also check the base name.
	if strings.HasPrefix(pattern, "*.") {
		ext := pattern[1:] // ".pem", ".key"
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}
