package api

import (
	"fmt"
	"os"
	"strings"
)

// ParseSecret parses a secret string in the format "NAME=VALUE@host1,host2" or "NAME@host1,host2".
// When no inline value is provided, the value is read from the environment variable $NAME.
func ParseSecret(s string) (string, Secret, error) {
	atIdx := strings.LastIndex(s, "@")
	if atIdx == -1 {
		return "", Secret{}, fmt.Errorf("missing @hosts (format: NAME=VALUE@host1,host2 or NAME@host1,host2)")
	}

	hostsStr := s[atIdx+1:]
	if hostsStr == "" {
		return "", Secret{}, fmt.Errorf("no hosts specified after @")
	}
	hosts := strings.Split(hostsStr, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}

	nameValue := s[:atIdx]
	eqIdx := strings.Index(nameValue, "=")

	var name, value string
	if eqIdx == -1 {
		name = nameValue
		value = os.Getenv(name)
		if value == "" {
			return "", Secret{}, fmt.Errorf("environment variable $%s is not set (hint: use 'sudo -E' to preserve env vars, or pass inline: %s=VALUE@%s)", name, name, hostsStr)
		}
	} else {
		name = nameValue[:eqIdx]
		value = nameValue[eqIdx+1:]
	}

	if name == "" {
		return "", Secret{}, fmt.Errorf("secret name cannot be empty")
	}

	return name, Secret{
		Value: value,
		Hosts: hosts,
	}, nil
}
