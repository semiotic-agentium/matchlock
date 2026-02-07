package net

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCAInjector_GetEnvVars(t *testing.T) {
	tmpDir := t.TempDir()

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	pool, err := NewCAPool()
	if err != nil {
		t.Fatalf("NewCAPool failed: %v", err)
	}

	injector := NewCAInjector(pool)

	envVars := injector.GetEnvVars()

	expected := []string{
		"SSL_CERT_FILE",
		"REQUESTS_CA_BUNDLE",
		"CURL_CA_BUNDLE",
		"NODE_EXTRA_CA_CERTS",
	}

	for _, name := range expected {
		if _, ok := envVars[name]; !ok {
			t.Errorf("Missing env var: %s", name)
		}
	}
}

func TestCAInjector_GetInstallScript(t *testing.T) {
	tmpDir := t.TempDir()

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	pool, err := NewCAPool()
	if err != nil {
		t.Fatalf("NewCAPool failed: %v", err)
	}

	injector := NewCAInjector(pool)

	script := injector.GetInstallScript()

	if !strings.Contains(script, "#!/bin/sh") {
		t.Error("Script should have shebang")
	}

	if !strings.Contains(script, "update-ca-certificates") {
		t.Error("Script should handle Debian/Ubuntu")
	}

	if !strings.Contains(script, "update-ca-trust") {
		t.Error("Script should handle RHEL/CentOS")
	}
}

func TestCAInjector_GetInitScript(t *testing.T) {
	tmpDir := t.TempDir()

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	pool, err := NewCAPool()
	if err != nil {
		t.Fatalf("NewCAPool failed: %v", err)
	}

	injector := NewCAInjector(pool)

	script := injector.GetInitScript()

	if !strings.Contains(script, "-----BEGIN CERTIFICATE-----") {
		t.Error("Init script should contain CA cert")
	}
}

func TestCAInjector_WriteFiles(t *testing.T) {
	tmpDir := t.TempDir()

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	pool, err := NewCAPool()
	if err != nil {
		t.Fatalf("NewCAPool failed: %v", err)
	}

	injector := NewCAInjector(pool)

	destDir := filepath.Join(tmpDir, "ca-files")
	os.MkdirAll(destDir, 0755)

	if err := injector.WriteFiles(destDir); err != nil {
		t.Fatalf("WriteFiles failed: %v", err)
	}

	files := []string{"sandbox-ca.crt", "install-ca.sh", "init-ca.sh"}
	for _, f := range files {
		path := filepath.Join(destDir, f)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("File %s should exist", f)
		}
	}

	content, _ := os.ReadFile(filepath.Join(destDir, "sandbox-ca.crt"))
	if !strings.Contains(string(content), "-----BEGIN CERTIFICATE-----") {
		t.Error("CA cert file should contain PEM data")
	}
}


