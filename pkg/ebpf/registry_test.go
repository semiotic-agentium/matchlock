package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupFactory_BuiltIn(t *testing.T) {
	f, ok := LookupFactory("sensitive_file_monitor")
	assert.True(t, ok, "sensitive_file_monitor should be registered")
	assert.NotNil(t, f)
}

func TestLookupFactory_Unknown(t *testing.T) {
	_, ok := LookupFactory("nonexistent_plugin")
	assert.False(t, ok)
}

func TestRegisteredTypes(t *testing.T) {
	types := RegisteredTypes()
	assert.Contains(t, types, "sensitive_file_monitor")
}

func TestRegisteredTypes_NotEmpty(t *testing.T) {
	types := RegisteredTypes()
	assert.NotEmpty(t, types)
}
