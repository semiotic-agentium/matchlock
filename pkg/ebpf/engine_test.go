package ebpf

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jingkaihe/matchlock/pkg/api"
	"github.com/jingkaihe/matchlock/pkg/logging"
)

// --- test helpers ---

type mockEventPlugin struct {
	name    string
	verdict *EventVerdict
	seen    []*EBPFEvent
}

func (m *mockEventPlugin) Name() string { return m.name }
func (m *mockEventPlugin) ProcessEvent(event *EBPFEvent) *EventVerdict {
	m.seen = append(m.seen, event)
	return m.verdict
}

// nonEventPlugin implements Plugin but not EventPlugin.
type nonEventPlugin struct{ name string }

func (n *nonEventPlugin) Name() string { return n.name }

// captureSink records events in memory for test assertions.
type captureSink struct {
	mu     sync.Mutex
	events []*logging.Event
}

func (s *captureSink) Write(event *logging.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *captureSink) Close() error { return nil }

func (s *captureSink) Events() []*logging.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]*logging.Event, len(s.events))
	copy(cp, s.events)
	return cp
}

type killRecord struct {
	pid int
}

func newMockKillFunc() (KillFunc, *[]killRecord) {
	var records []killRecord
	fn := func(_ context.Context, pid int) error {
		records = append(records, killRecord{pid: pid})
		return nil
	}
	return fn, &records
}

func testEmitter(sink *captureSink) *logging.Emitter {
	return logging.NewEmitter(logging.EmitterConfig{RunID: "test-run"}, sink)
}

// --- Engine AddPlugin tests ---

func TestEngine_AddPlugin(t *testing.T) {
	e := NewEngine(nil, nil, nil)
	p := &mockEventPlugin{name: "test_plugin"}
	e.AddPlugin(p)
	assert.Equal(t, 1, e.PluginCount())
}

func TestEngine_AddPlugin_NonEventPlugin(t *testing.T) {
	e := NewEngine(nil, nil, nil)
	p := &nonEventPlugin{name: "bad_plugin"}
	e.AddPlugin(p)
	assert.Equal(t, 0, e.PluginCount())
}

// --- Engine ProcessEvent tests ---

func TestEngine_ProcessEvent_NoPlugins(t *testing.T) {
	e := NewEngine(nil, nil, nil)
	event := &EBPFEvent{Event: "EXEC", PID: 1, Comm: "ls"}
	// Should not panic
	e.ProcessEvent(context.Background(), event)
}

func TestEngine_ProcessEvent_AlertEmitted(t *testing.T) {
	sink := &captureSink{}
	emitter := testEmitter(sink)

	e := NewEngine(emitter, nil, nil)
	plugin := &mockEventPlugin{
		name: "test_alert",
		verdict: &EventVerdict{
			Alert:  true,
			Action: "alert",
			Reason: "test alert reason",
			Data:   map[string]string{"key": "value"},
		},
	}
	e.AddPlugin(plugin)

	event := &EBPFEvent{Event: "FILE_OPEN", Filepath: "/etc/shadow", PID: 42, Comm: "cat"}
	e.ProcessEvent(context.Background(), event)

	events := sink.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "ebpf_test_alert", events[0].EventType)
	assert.Equal(t, "test alert reason", events[0].Summary)
	assert.Equal(t, "test_alert", events[0].Plugin)
	assert.Equal(t, []string{"ebpf"}, events[0].Tags)
}

func TestEngine_ProcessEvent_KillExecuted(t *testing.T) {
	killFn, records := newMockKillFunc()

	e := NewEngine(nil, killFn, nil)
	plugin := &mockEventPlugin{
		name: "killer",
		verdict: &EventVerdict{
			Alert:  true,
			Kill:   true,
			Action: "killed",
			Reason: "kill test",
		},
	}
	e.AddPlugin(plugin)

	event := &EBPFEvent{Event: "FILE_OPEN", PID: 99, Comm: "bad"}
	e.ProcessEvent(context.Background(), event)

	require.Len(t, *records, 1)
	assert.Equal(t, 99, (*records)[0].pid)
}

func TestEngine_ProcessEvent_KillDisabled_NilKillFunc(t *testing.T) {
	e := NewEngine(nil, nil, nil) // killFunc is nil
	plugin := &mockEventPlugin{
		name: "killer",
		verdict: &EventVerdict{
			Alert:  true,
			Kill:   true,
			Action: "killed",
			Reason: "should not panic",
		},
	}
	e.AddPlugin(plugin)

	event := &EBPFEvent{Event: "FILE_OPEN", PID: 1}
	// Should not panic even with Kill=true and nil killFunc
	e.ProcessEvent(context.Background(), event)
}

func TestEngine_ProcessEvent_NilVerdict(t *testing.T) {
	sink := &captureSink{}
	emitter := testEmitter(sink)

	e := NewEngine(emitter, nil, nil)
	plugin := &mockEventPlugin{name: "quiet", verdict: nil}
	e.AddPlugin(plugin)

	event := &EBPFEvent{Event: "EXEC", PID: 1}
	e.ProcessEvent(context.Background(), event)

	assert.Empty(t, sink.Events())
}

func TestEngine_ProcessEvent_NonAlert(t *testing.T) {
	sink := &captureSink{}
	emitter := testEmitter(sink)

	e := NewEngine(emitter, nil, nil)
	plugin := &mockEventPlugin{
		name:    "non_alert",
		verdict: &EventVerdict{Alert: false, Action: "allow"},
	}
	e.AddPlugin(plugin)

	event := &EBPFEvent{Event: "EXEC", PID: 1}
	e.ProcessEvent(context.Background(), event)

	assert.Empty(t, sink.Events())
}

func TestEngine_ProcessEvent_MultiplePlugins(t *testing.T) {
	plugin1 := &mockEventPlugin{name: "p1", verdict: nil}
	plugin2 := &mockEventPlugin{
		name: "p2",
		verdict: &EventVerdict{
			Alert:  true,
			Action: "alert",
			Reason: "p2 alert",
		},
	}
	plugin3 := &mockEventPlugin{name: "p3", verdict: nil}

	e := NewEngine(nil, nil, nil)
	e.AddPlugin(plugin1)
	e.AddPlugin(plugin2)
	e.AddPlugin(plugin3)

	event := &EBPFEvent{Event: "FILE_OPEN", PID: 1}
	e.ProcessEvent(context.Background(), event)

	// All plugins should see the event
	assert.Len(t, plugin1.seen, 1)
	assert.Len(t, plugin2.seen, 1)
	assert.Len(t, plugin3.seen, 1)
}

func TestEngine_ProcessEvent_NilEmitter(t *testing.T) {
	e := NewEngine(nil, nil, nil) // emitter is nil
	plugin := &mockEventPlugin{
		name: "alerter",
		verdict: &EventVerdict{
			Alert:  true,
			Action: "alert",
			Reason: "should not panic",
		},
	}
	e.AddPlugin(plugin)

	event := &EBPFEvent{Event: "FILE_OPEN", PID: 1}
	// Should not panic with nil emitter
	e.ProcessEvent(context.Background(), event)
}

// --- NewEngineFromConfig tests ---

func TestNewEngineFromConfig_Success(t *testing.T) {
	config := &api.EBPFConfig{
		Plugins: []api.PluginConfig{
			{Type: "sensitive_file_monitor", Config: json.RawMessage(`{"kill":false}`)},
		},
	}

	engine, err := NewEngineFromConfig(config, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, engine.PluginCount())
}

func TestNewEngineFromConfig_UnknownPlugin(t *testing.T) {
	config := &api.EBPFConfig{
		Plugins: []api.PluginConfig{
			{Type: "nonexistent_plugin_type"},
		},
	}

	_, err := NewEngineFromConfig(config, nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown eBPF plugin type")
	assert.Contains(t, err.Error(), "nonexistent_plugin_type")
}

func TestNewEngineFromConfig_FactoryError(t *testing.T) {
	config := &api.EBPFConfig{
		Plugins: []api.PluginConfig{
			{Type: "sensitive_file_monitor", Config: json.RawMessage(`not valid json`)},
		},
	}

	_, err := NewEngineFromConfig(config, nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sensitive_file_monitor")
}

func TestNewEngineFromConfig_DisabledPlugin(t *testing.T) {
	disabled := false
	config := &api.EBPFConfig{
		Plugins: []api.PluginConfig{
			{Type: "sensitive_file_monitor", Enabled: &disabled},
		},
	}

	engine, err := NewEngineFromConfig(config, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, engine.PluginCount())
}

func TestNewEngineFromConfig_NilConfig(t *testing.T) {
	engine, err := NewEngineFromConfig(nil, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, engine.PluginCount())
}

func TestNewEngineFromConfig_EmptyPlugins(t *testing.T) {
	config := &api.EBPFConfig{
		DebugLog: true,
	}

	engine, err := NewEngineFromConfig(config, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, engine.PluginCount())
}

func TestNewEngineFromConfig_MultiplePlugins(t *testing.T) {
	config := &api.EBPFConfig{
		Plugins: []api.PluginConfig{
			{Type: "sensitive_file_monitor"},
			{Type: "sensitive_file_monitor", Config: json.RawMessage(`{"kill":true}`)},
		},
	}

	engine, err := NewEngineFromConfig(config, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, engine.PluginCount())
}

func TestNewEngineFromConfig_WithEmitter(t *testing.T) {
	sink := &captureSink{}
	emitter := testEmitter(sink)

	config := &api.EBPFConfig{
		Plugins: []api.PluginConfig{
			{Type: "sensitive_file_monitor"},
		},
	}

	engine, err := NewEngineFromConfig(config, emitter, nil, nil)
	require.NoError(t, err)

	// Trigger an alert to verify emitter is wired
	event := &EBPFEvent{Event: "FILE_OPEN", Filepath: "/etc/shadow", PID: 1, Comm: "cat"}
	engine.ProcessEvent(context.Background(), event)

	events := sink.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "ebpf_sensitive_file_monitor", events[0].EventType)
}
