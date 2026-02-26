package ebpf

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingEngine wraps a real engine and records received events.
type recordingEngine struct {
	events []*EBPFEvent
}

func (r *recordingEngine) record(event *EBPFEvent) *EventVerdict {
	r.events = append(r.events, event)
	return nil
}

// newRecordingPlugin returns a plugin that records all events.
func newRecordingPlugin() (*mockEventPlugin, *recordingEngine) {
	rec := &recordingEngine{}
	plugin := &mockEventPlugin{
		name:    "recorder",
		verdict: nil,
	}
	return plugin, rec
}

func TestCollector_ServeAndReceiveEvents(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	// Create engine with a recording plugin
	plugin := &mockEventPlugin{name: "recorder", verdict: nil}
	engine := NewEngine(nil, nil, nil)
	engine.AddPlugin(plugin)

	collector := NewCollector(engine, "")
	stop, err := collector.ServeUDSBackground(socketPath)
	require.NoError(t, err)
	defer stop()

	// Connect and send JSONL events
	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	events := []string{
		`{"event":"EXEC","pid":1,"comm":"init","filename":"/sbin/init"}`,
		`{"event":"FILE_OPEN","pid":2,"comm":"cat","filepath":"/etc/hosts"}`,
		`{"event":"EXIT","pid":1,"comm":"init","exit_code":0}`,
	}
	for _, e := range events {
		fmt.Fprintln(conn, e)
	}
	conn.Close()

	// Wait for processing
	require.Eventually(t, func() bool {
		return len(plugin.seen) >= 3
	}, 2*time.Second, 10*time.Millisecond)

	assert.Len(t, plugin.seen, 3)
	assert.Equal(t, "EXEC", plugin.seen[0].Event)
	assert.Equal(t, 1, plugin.seen[0].PID)
	assert.Equal(t, "init", plugin.seen[0].Comm)
	assert.Equal(t, "FILE_OPEN", plugin.seen[1].Event)
	assert.Equal(t, "/etc/hosts", plugin.seen[1].Filepath)
	assert.Equal(t, "EXIT", plugin.seen[2].Event)
}

func TestCollector_DebugLog(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	debugLogPath := filepath.Join(dir, "debug.jsonl")

	collector := NewCollector(nil, debugLogPath)
	stop, err := collector.ServeUDSBackground(socketPath)
	require.NoError(t, err)
	defer stop()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)

	events := []string{
		`{"event":"EXEC","pid":1,"comm":"ls"}`,
		`{"event":"EXIT","pid":1,"comm":"ls","exit_code":0}`,
	}
	for _, e := range events {
		fmt.Fprintln(conn, e)
	}
	conn.Close()

	// Wait for file to be written
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(debugLogPath)
		if err != nil {
			return false
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		return len(lines) >= 2
	}, 2*time.Second, 10*time.Millisecond)

	data, err := os.ReadFile(debugLogPath)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	assert.Len(t, lines, 2)
	assert.Contains(t, lines[0], `"EXEC"`)
	assert.Contains(t, lines[1], `"EXIT"`)
}

func TestCollector_NilEngine(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	debugLogPath := filepath.Join(dir, "debug.jsonl")

	// nil engine — should still write to debug log without crashing
	collector := NewCollector(nil, debugLogPath)
	stop, err := collector.ServeUDSBackground(socketPath)
	require.NoError(t, err)
	defer stop()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)

	fmt.Fprintln(conn, `{"event":"EXEC","pid":1,"comm":"ls"}`)
	conn.Close()

	require.Eventually(t, func() bool {
		data, _ := os.ReadFile(debugLogPath)
		return len(data) > 0
	}, 2*time.Second, 10*time.Millisecond)

	data, err := os.ReadFile(debugLogPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"EXEC"`)
}

func TestCollector_MalformedJSON(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	plugin := &mockEventPlugin{name: "recorder", verdict: nil}
	engine := NewEngine(nil, nil, nil)
	engine.AddPlugin(plugin)

	collector := NewCollector(engine, "")
	stop, err := collector.ServeUDSBackground(socketPath)
	require.NoError(t, err)
	defer stop()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)

	// Send malformed JSON followed by valid JSON
	fmt.Fprintln(conn, "not valid json at all")
	fmt.Fprintln(conn, `{"event":"EXEC","pid":42,"comm":"good"}`)
	conn.Close()

	// Valid event should still be processed despite the malformed one
	require.Eventually(t, func() bool {
		return len(plugin.seen) >= 1
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, "EXEC", plugin.seen[0].Event)
	assert.Equal(t, 42, plugin.seen[0].PID)
}

func TestCollector_EmptyLines(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	plugin := &mockEventPlugin{name: "recorder", verdict: nil}
	engine := NewEngine(nil, nil, nil)
	engine.AddPlugin(plugin)

	collector := NewCollector(engine, "")
	stop, err := collector.ServeUDSBackground(socketPath)
	require.NoError(t, err)
	defer stop()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)

	// Empty lines should be skipped
	fmt.Fprintln(conn, "")
	fmt.Fprintln(conn, `{"event":"EXEC","pid":1,"comm":"ls"}`)
	fmt.Fprintln(conn, "")
	conn.Close()

	require.Eventually(t, func() bool {
		return len(plugin.seen) >= 1
	}, 2*time.Second, 10*time.Millisecond)

	assert.Len(t, plugin.seen, 1)
}

func TestCollector_StopClosesListener(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	collector := NewCollector(nil, "")
	stop, err := collector.ServeUDSBackground(socketPath)
	require.NoError(t, err)

	stop()

	// Socket should no longer be connectable
	_, err = net.DialTimeout("unix", socketPath, 100*time.Millisecond)
	assert.Error(t, err)
}

func TestCollector_ProcessEventWithAlert(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	// Use the real sensitive_file_monitor plugin
	config := SensitiveFileMonitorConfig{Kill: false}
	sfmPlugin := NewSensitiveFileMonitor(config, nil)

	killFn, records := newMockKillFunc()
	engine := NewEngine(nil, killFn, nil)
	engine.AddPlugin(sfmPlugin)

	collector := NewCollector(engine, "")
	stop, err := collector.ServeUDSBackground(socketPath)
	require.NoError(t, err)
	defer stop()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)

	// Send a sensitive file access event
	fmt.Fprintln(conn, `{"event":"FILE_OPEN","pid":10,"comm":"cat","filepath":"/etc/shadow"}`)
	conn.Close()

	// Alert should fire but no kill (kill=false)
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, *records)
}

func TestCollector_ProcessEventWithKill(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	config := SensitiveFileMonitorConfig{Kill: true}
	sfmPlugin := NewSensitiveFileMonitor(config, nil)

	killFn, records := newMockKillFunc()
	engine := NewEngine(nil, killFn, nil)
	engine.AddPlugin(sfmPlugin)

	collector := NewCollector(engine, "")
	stop, err := collector.ServeUDSBackground(socketPath)
	require.NoError(t, err)
	defer stop()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)

	fmt.Fprintln(conn, `{"event":"FILE_OPEN","pid":10,"comm":"cat","filepath":"/etc/shadow"}`)
	conn.Close()

	require.Eventually(t, func() bool {
		return len(*records) >= 1
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, 10, (*records)[0].pid)
}

// Suppress unused import warning for context
var _ = context.Background
