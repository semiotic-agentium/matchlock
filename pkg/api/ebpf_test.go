package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEBPFPlugin_NameOnly(t *testing.T) {
	cfg, err := ParseEBPFPlugin("sensitive_file_monitor")
	require.NoError(t, err)
	assert.Equal(t, "sensitive_file_monitor", cfg.Type)
	assert.Nil(t, cfg.Config)
}

func TestParseEBPFPlugin_WithConfig(t *testing.T) {
	cfg, err := ParseEBPFPlugin(`sensitive_file_monitor={"kill":true}`)
	require.NoError(t, err)
	assert.Equal(t, "sensitive_file_monitor", cfg.Type)
	assert.JSONEq(t, `{"kill":true}`, string(cfg.Config))
}

func TestParseEBPFPlugin_WithComplexConfig(t *testing.T) {
	cfg, err := ParseEBPFPlugin(`sensitive_file_monitor={"kill":true,"patterns":["/etc/shadow","/etc/passwd"]}`)
	require.NoError(t, err)
	assert.Equal(t, "sensitive_file_monitor", cfg.Type)
	assert.JSONEq(t, `{"kill":true,"patterns":["/etc/shadow","/etc/passwd"]}`, string(cfg.Config))
}

func TestParseEBPFPlugin_InvalidJSON(t *testing.T) {
	_, err := ParseEBPFPlugin("foo=not{json")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEBPFPluginFormat)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestParseEBPFPlugin_EmptyName(t *testing.T) {
	_, err := ParseEBPFPlugin("")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEBPFPluginFormat)
}

func TestParseEBPFPlugin_EmptyConfig(t *testing.T) {
	_, err := ParseEBPFPlugin("foo=")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEBPFPluginFormat)
	assert.Contains(t, err.Error(), "empty config")
}

func TestParseEBPFPlugin_MissingTypeName(t *testing.T) {
	_, err := ParseEBPFPlugin(`={"kill":true}`)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEBPFPluginFormat)
	assert.Contains(t, err.Error(), "missing plugin type")
}

func TestEBPFConfig_ValidatePluginTypes_Valid(t *testing.T) {
	cfg := &EBPFConfig{
		Plugins: []PluginConfig{
			{Type: "sensitive_file_monitor"},
			{Type: "exec_audit"},
		},
	}
	err := cfg.ValidatePluginTypes([]string{"sensitive_file_monitor", "exec_audit", "network_monitor"})
	require.NoError(t, err)
}

func TestEBPFConfig_ValidatePluginTypes_Unknown(t *testing.T) {
	cfg := &EBPFConfig{
		Plugins: []PluginConfig{
			{Type: "sensitive_file_monitor"},
			{Type: "nonexistent_plugin"},
		},
	}
	err := cfg.ValidatePluginTypes([]string{"sensitive_file_monitor"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownEBPFPlugin)
	assert.Contains(t, err.Error(), "nonexistent_plugin")
	assert.Contains(t, err.Error(), "sensitive_file_monitor")
}

func TestEBPFConfig_ValidatePluginTypes_Nil(t *testing.T) {
	var cfg *EBPFConfig
	err := cfg.ValidatePluginTypes([]string{"foo"})
	require.NoError(t, err)
}

func TestEBPFConfig_ValidatePluginTypes_Empty(t *testing.T) {
	cfg := &EBPFConfig{}
	err := cfg.ValidatePluginTypes([]string{"foo"})
	require.NoError(t, err)
}

func TestEBPFConfig_ValidatePluginTypes_NoAvailable(t *testing.T) {
	cfg := &EBPFConfig{
		Plugins: []PluginConfig{
			{Type: "anything"},
		},
	}
	err := cfg.ValidatePluginTypes(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownEBPFPlugin)
}
