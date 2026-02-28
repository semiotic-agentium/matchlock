package ebpf

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSensitiveFileMonitor_DefaultPatterns(t *testing.T) {
	plugin := NewSensitiveFileMonitor(SensitiveFileMonitorConfig{}, nil)

	tests := []struct {
		name     string
		filepath string
		wantHit  bool
	}{
		{"shadow file", "/etc/shadow", true},
		{"gshadow file", "/etc/gshadow", true},
		{"sudoers file", "/etc/sudoers", true},
		{"sudoers.d entry", "/etc/sudoers.d/custom", true},
		{"root ssh key", "/root/.ssh/id_rsa", true},
		{"user ssh key", "/home/user/.ssh/id_rsa", true},
		{"authorized_keys", "/home/user/.ssh/authorized_keys", true},
		{"ssl private key", "/etc/ssl/private/server.key", true},
		{"ssh host key", "/etc/ssh/ssh_host_rsa_key", true},
		{"benign file", "/etc/hostname", false},
		{"benign home file", "/home/user/.bashrc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &EBPFEvent{
				Event:    "FILE_OPEN",
				Filepath: tt.filepath,
				PID:      100,
				Comm:     "cat",
			}
			verdict := plugin.ProcessEvent(event)
			if tt.wantHit {
				require.NotNil(t, verdict, "expected alert for %s", tt.filepath)
				assert.True(t, verdict.Alert)
				assert.Equal(t, "alert", verdict.Action)
				assert.False(t, verdict.Kill)
			} else {
				assert.Nil(t, verdict, "expected no alert for %s", tt.filepath)
			}
		})
	}
}

func TestSensitiveFileMonitor_CustomPatterns(t *testing.T) {
	plugin := NewSensitiveFileMonitor(SensitiveFileMonitorConfig{
		Patterns: []string{"/custom/secret/*", "/var/private"},
	}, nil)

	// Custom pattern matches
	event := &EBPFEvent{Event: "FILE_OPEN", Filepath: "/custom/secret/key.pem", PID: 1}
	verdict := plugin.ProcessEvent(event)
	require.NotNil(t, verdict)
	assert.True(t, verdict.Alert)

	// Default pattern no longer matches (overridden)
	event = &EBPFEvent{Event: "FILE_OPEN", Filepath: "/etc/shadow", PID: 1}
	verdict = plugin.ProcessEvent(event)
	assert.Nil(t, verdict)
}

func TestSensitiveFileMonitor_KillMode(t *testing.T) {
	plugin := NewSensitiveFileMonitor(SensitiveFileMonitorConfig{Kill: true}, nil)
	event := &EBPFEvent{Event: "FILE_OPEN", Filepath: "/etc/shadow", PID: 42, Comm: "cat"}

	verdict := plugin.ProcessEvent(event)
	require.NotNil(t, verdict)
	assert.True(t, verdict.Alert)
	assert.True(t, verdict.Kill)
	assert.Equal(t, "killed", verdict.Action)

	data, ok := verdict.Data.(*SensitiveFileAccessData)
	require.True(t, ok)
	assert.Equal(t, "/etc/shadow", data.Filepath)
	assert.Equal(t, 42, data.PID)
	assert.Equal(t, "cat", data.Comm)
	assert.Equal(t, "killed", data.Action)
}

func TestSensitiveFileMonitor_NonFileOpenIgnored(t *testing.T) {
	plugin := NewSensitiveFileMonitor(SensitiveFileMonitorConfig{}, nil)

	for _, eventType := range []string{"EXEC", "EXIT", "UNKNOWN"} {
		event := &EBPFEvent{
			Event:    eventType,
			Filepath: "/etc/shadow",
			PID:      1,
		}
		verdict := plugin.ProcessEvent(event)
		assert.Nil(t, verdict, "event type %q should be ignored", eventType)
	}
}

func TestSensitiveFileMonitor_EmptyFilepath(t *testing.T) {
	plugin := NewSensitiveFileMonitor(SensitiveFileMonitorConfig{}, nil)
	event := &EBPFEvent{Event: "FILE_OPEN", PID: 1}
	verdict := plugin.ProcessEvent(event)
	assert.Nil(t, verdict)
}

func TestSensitiveFileMonitor_NoMatch(t *testing.T) {
	plugin := NewSensitiveFileMonitor(SensitiveFileMonitorConfig{}, nil)
	event := &EBPFEvent{
		Event:    "FILE_OPEN",
		Filepath: "/tmp/harmless.txt",
		PID:      1,
	}
	verdict := plugin.ProcessEvent(event)
	assert.Nil(t, verdict)
}

func TestSensitiveFileMonitor_FromConfig(t *testing.T) {
	raw := json.RawMessage(`{"kill":true,"patterns":["/opt/secrets/*"]}`)
	p, err := NewSensitiveFileMonitorFromConfig(raw, nil)
	require.NoError(t, err)
	assert.Equal(t, "sensitive_file_monitor", p.Name())

	ep, ok := p.(EventPlugin)
	require.True(t, ok)

	event := &EBPFEvent{Event: "FILE_OPEN", Filepath: "/opt/secrets/api.key", PID: 1}
	verdict := ep.ProcessEvent(event)
	require.NotNil(t, verdict)
	assert.True(t, verdict.Kill)
}

func TestSensitiveFileMonitor_FromConfig_NilConfig(t *testing.T) {
	p, err := NewSensitiveFileMonitorFromConfig(nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "sensitive_file_monitor", p.Name())
}

func TestSensitiveFileMonitor_FromConfig_EmptyConfig(t *testing.T) {
	p, err := NewSensitiveFileMonitorFromConfig(json.RawMessage(`{}`), nil)
	require.NoError(t, err)
	assert.Equal(t, "sensitive_file_monitor", p.Name())
}

func TestSensitiveFileMonitor_FromConfig_InvalidJSON(t *testing.T) {
	_, err := NewSensitiveFileMonitorFromConfig(json.RawMessage(`not json`), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config")
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Exact match
		{"/etc/shadow", "/etc/shadow", true},
		{"/etc/shadow", "/etc/passwd", false},

		// Glob with wildcard
		{"/etc/sudoers.d/*", "/etc/sudoers.d/custom", true},
		{"/etc/sudoers.d/*", "/etc/sudoers.d/deep/nested", false}, // single-level *

		// Multi-segment glob
		{"/home/*/.ssh/id_*", "/home/user/.ssh/id_rsa", true},
		{"/home/*/.ssh/id_*", "/home/user/.ssh/id_ed25519", true},
		{"/home/*/.ssh/id_*", "/home/user/.ssh/known_hosts", false},

		// Extension matching
		{"*.pem", "/etc/ssl/server.pem", true},
		{"*.pem", "/etc/ssl/server.key", false},
		{"*.key", "/etc/ssl/private/cert.key", true},

		// No match
		{"/root/.ssh/*", "/home/user/.ssh/config", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			got := matchPath(tt.pattern, tt.path)
			assert.Equal(t, tt.want, got, "matchPath(%q, %q)", tt.pattern, tt.path)
		})
	}
}

func TestSensitiveFileMonitor_Name(t *testing.T) {
	plugin := NewSensitiveFileMonitor(SensitiveFileMonitorConfig{}, nil)
	assert.Equal(t, "sensitive_file_monitor", plugin.Name())
}

func TestSensitiveFileMonitor_VerdictData(t *testing.T) {
	plugin := NewSensitiveFileMonitor(SensitiveFileMonitorConfig{}, nil)
	event := &EBPFEvent{
		Event:    "FILE_OPEN",
		Filepath: "/etc/shadow",
		PID:      123,
		Comm:     "vim",
	}

	verdict := plugin.ProcessEvent(event)
	require.NotNil(t, verdict)

	data, ok := verdict.Data.(*SensitiveFileAccessData)
	require.True(t, ok)
	assert.Equal(t, "/etc/shadow", data.Filepath)
	assert.Equal(t, 123, data.PID)
	assert.Equal(t, "vim", data.Comm)
	assert.Equal(t, "/etc/shadow", data.Pattern)
	assert.Equal(t, "alert", data.Action)
}
