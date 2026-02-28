package ebpf

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jingkaihe/matchlock/pkg/api"
	"github.com/jingkaihe/matchlock/pkg/logging"
)

// KillFunc sends a kill signal to a process in the guest VM.
// The implementation typically runs "kill -9 <pid>" via the exec relay.
type KillFunc func(ctx context.Context, pid int) error

// Engine orchestrates eBPF event plugins. It receives parsed events from
// the collector, runs them through the plugin chain, emits policy events
// to the shared event log, and optionally kills offending processes.
type Engine struct {
	plugins  []EventPlugin
	emitter  *logging.Emitter // shared event log (nil = no logging)
	killFunc KillFunc         // callback to kill guest processes (nil = kills disabled)
	logger   *slog.Logger
}

// NewEngine creates an eBPF plugin engine.
//
// Parameters:
//   - emitter: shared event log emitter (same as network plugins use). Nil disables logging.
//   - killFunc: callback to kill a guest process by PID. Nil disables kill enforcement.
//   - logger: structured logger for engine diagnostics.
func NewEngine(emitter *logging.Emitter, killFunc KillFunc, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		emitter:  emitter,
		killFunc: killFunc,
		logger:   logger,
	}
}

// AddPlugin registers a plugin with the engine. The plugin must implement
// EventPlugin; other Plugin implementations are ignored with a warning.
func (e *Engine) AddPlugin(p Plugin) {
	if ep, ok := p.(EventPlugin); ok {
		e.plugins = append(e.plugins, ep)
		e.logger.Info("ebpf engine: registered plugin", "name", p.Name())
	} else {
		e.logger.Warn("ebpf engine: plugin does not implement EventPlugin", "name", p.Name())
	}
}

// ProcessEvent runs the plugin chain for a single eBPF event.
// All registered plugins see every event. Alerts are logged to the shared
// event log, and kill verdicts are executed via the KillFunc.
func (e *Engine) ProcessEvent(ctx context.Context, event *EBPFEvent) {
	for _, plugin := range e.plugins {
		verdict := plugin.ProcessEvent(event)
		if verdict == nil || !verdict.Alert {
			continue
		}

		e.logger.Info("ebpf plugin alert",
			"plugin", plugin.Name(),
			"action", verdict.Action,
			"pid", event.PID,
			"comm", event.Comm,
			"reason", verdict.Reason,
		)

		// Emit policy event to shared log
		if e.emitter != nil {
			_ = e.emitter.Emit(
				"ebpf_"+plugin.Name(),
				verdict.Reason,
				plugin.Name(),
				[]string{"ebpf"},
				verdict.Data,
			)
		}

		// Kill process if requested
		if verdict.Kill && e.killFunc != nil {
			e.logger.Warn("ebpf engine: killing process",
				"plugin", plugin.Name(),
				"pid", event.PID,
				"comm", event.Comm,
			)
			if err := e.killFunc(ctx, event.PID); err != nil {
				e.logger.Warn("ebpf engine: failed to kill process",
					"pid", event.PID,
					"error", err,
				)
			}
		}
	}
}

// NewEngineFromConfig creates an eBPF plugin engine from an EBPFConfig.
// It looks up each plugin type in the global registry, instantiates it,
// and adds it to the engine. Returns an error if any plugin type is unknown
// or if a factory fails — security enforcement plugins should not silently fail.
func NewEngineFromConfig(config *api.EBPFConfig, emitter *logging.Emitter, killFunc KillFunc, logger *slog.Logger) (*Engine, error) {
	e := NewEngine(emitter, killFunc, logger)
	if config == nil {
		return e, nil
	}
	for _, pluginCfg := range config.Plugins {
		if !pluginCfg.IsEnabled() {
			e.logger.Debug("ebpf plugin disabled, skipping", "type", pluginCfg.Type)
			continue
		}
		factory, ok := LookupFactory(pluginCfg.Type)
		if !ok {
			return nil, fmt.Errorf("unknown eBPF plugin type: %q", pluginCfg.Type)
		}
		pluginLogger := e.logger.With("plugin", pluginCfg.Type)
		p, err := factory(pluginCfg.Config, pluginLogger)
		if err != nil {
			return nil, fmt.Errorf("eBPF plugin %q: %w", pluginCfg.Type, err)
		}
		e.AddPlugin(p)
	}
	e.logger.Info("ebpf engine ready", "plugins", e.PluginCount())
	return e, nil
}

// PluginCount returns the number of registered plugins.
func (e *Engine) PluginCount() int {
	return len(e.plugins)
}
