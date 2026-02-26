package ebpf

import (
	"encoding/json"
	"log/slog"
	"sync"
)

// PluginFactory creates a plugin from JSON configuration.
type PluginFactory func(config json.RawMessage, logger *slog.Logger) (Plugin, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]PluginFactory{}
)

func init() {
	Register("sensitive_file_monitor", NewSensitiveFileMonitorFromConfig)
}

// Register adds a plugin factory to the global registry.
// Panics if a factory with the same type name is already registered.
// Call from init() in plugin packages.
func Register(typeName string, factory PluginFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[typeName]; exists {
		panic("ebpf: duplicate plugin registration for type " + typeName)
	}
	registry[typeName] = factory
}

// LookupFactory returns the factory for the given plugin type name.
func LookupFactory(typeName string) (PluginFactory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[typeName]
	return f, ok
}
