package api

import (
	"os"
	"testing"
)

func TestParseSecretInlineValue(t *testing.T) {
	name, secret, err := ParseSecret("MY_KEY=sk-123@api.example.com")
	if err != nil {
		t.Fatalf("ParseSecret: %v", err)
	}
	if name != "MY_KEY" {
		t.Errorf("name = %q, want MY_KEY", name)
	}
	if secret.Value != "sk-123" {
		t.Errorf("value = %q, want sk-123", secret.Value)
	}
	if len(secret.Hosts) != 1 || secret.Hosts[0] != "api.example.com" {
		t.Errorf("hosts = %v, want [api.example.com]", secret.Hosts)
	}
}

func TestParseSecretMultipleHosts(t *testing.T) {
	name, secret, err := ParseSecret("TOKEN=abc@host1.com,host2.com")
	if err != nil {
		t.Fatalf("ParseSecret: %v", err)
	}
	if name != "TOKEN" {
		t.Errorf("name = %q, want TOKEN", name)
	}
	if len(secret.Hosts) != 2 {
		t.Fatalf("hosts len = %d, want 2", len(secret.Hosts))
	}
	if secret.Hosts[0] != "host1.com" || secret.Hosts[1] != "host2.com" {
		t.Errorf("hosts = %v, want [host1.com host2.com]", secret.Hosts)
	}
}

func TestParseSecretFromEnv(t *testing.T) {
	os.Setenv("TEST_SECRET_ABC", "env-value")
	defer os.Unsetenv("TEST_SECRET_ABC")

	name, secret, err := ParseSecret("TEST_SECRET_ABC@api.test.com")
	if err != nil {
		t.Fatalf("ParseSecret: %v", err)
	}
	if name != "TEST_SECRET_ABC" {
		t.Errorf("name = %q, want TEST_SECRET_ABC", name)
	}
	if secret.Value != "env-value" {
		t.Errorf("value = %q, want env-value", secret.Value)
	}
}

func TestParseSecretFromEnvMissing(t *testing.T) {
	os.Unsetenv("NONEXISTENT_SECRET_XYZ")
	_, _, err := ParseSecret("NONEXISTENT_SECRET_XYZ@host.com")
	if err == nil {
		t.Fatal("expected error for missing env var")
	}
}

func TestParseSecretMissingAt(t *testing.T) {
	_, _, err := ParseSecret("MY_KEY=value")
	if err == nil {
		t.Fatal("expected error for missing @hosts")
	}
}

func TestParseSecretEmptyHosts(t *testing.T) {
	_, _, err := ParseSecret("MY_KEY=value@")
	if err == nil {
		t.Fatal("expected error for empty hosts")
	}
}

func TestParseSecretEmptyName(t *testing.T) {
	_, _, err := ParseSecret("=value@host.com")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestParseSecretValueWithEquals(t *testing.T) {
	name, secret, err := ParseSecret("KEY=val=ue@host.com")
	if err != nil {
		t.Fatalf("ParseSecret: %v", err)
	}
	if name != "KEY" {
		t.Errorf("name = %q, want KEY", name)
	}
	if secret.Value != "val=ue" {
		t.Errorf("value = %q, want val=ue", secret.Value)
	}
}

func TestParseSecretValueWithAtSign(t *testing.T) {
	name, secret, err := ParseSecret("KEY=user@pass@host.com")
	if err != nil {
		t.Fatalf("ParseSecret: %v", err)
	}
	if name != "KEY" {
		t.Errorf("name = %q, want KEY", name)
	}
	// LastIndex of @ means host is "host.com", value is "user@pass"
	if secret.Value != "user@pass" {
		t.Errorf("value = %q, want user@pass", secret.Value)
	}
	if len(secret.Hosts) != 1 || secret.Hosts[0] != "host.com" {
		t.Errorf("hosts = %v, want [host.com]", secret.Hosts)
	}
}

func TestParseSecretHostTrimSpaces(t *testing.T) {
	_, secret, err := ParseSecret("K=v@ host1.com , host2.com ")
	if err != nil {
		t.Fatalf("ParseSecret: %v", err)
	}
	if secret.Hosts[0] != "host1.com" || secret.Hosts[1] != "host2.com" {
		t.Errorf("hosts = %v, want trimmed [host1.com host2.com]", secret.Hosts)
	}
}
