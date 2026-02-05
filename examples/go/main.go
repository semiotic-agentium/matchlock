// Matchlock Go SDK Example - Secret MITM Demo
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jingkaihe/matchlock/pkg/sdk"
)

func main() {
	cfg := sdk.DefaultConfig()
	if os.Getenv("MATCHLOCK_BIN") == "" {
		// Use ./bin/matchlock relative to current directory
		cfg.BinaryPath = "./bin/matchlock"
	}

	client, err := sdk.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	opts := sdk.CreateOptions{Image: "standard"}
	
	// If ANTHROPIC_API_KEY is set, configure secret MITM
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey != "" {
		opts.Secrets = []sdk.Secret{{
			Name:  "ANTHROPIC_API_KEY",
			Value: apiKey,
			Hosts: []string{"api.anthropic.com"},
		}}
		fmt.Println("Secret MITM enabled for api.anthropic.com")
	}

	vmID, err := client.Create(opts)
	if err != nil {
		// Check if binary exists
		if _, statErr := os.Stat(cfg.BinaryPath); statErr != nil {
			absPath, _ := filepath.Abs(cfg.BinaryPath)
			fmt.Fprintf(os.Stderr, "Binary not found at: %s\n", absPath)
			fmt.Fprintf(os.Stderr, "Run from project root: cd matchlock && go run examples/go/main.go\n")
		}
		fmt.Fprintf(os.Stderr, "Failed to create VM: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created VM: %s\n\n", vmID)

	// Test basic connectivity
	result, _ := client.Exec("ping -c 1 8.8.8.8 2>&1 | tail -2")
	fmt.Printf("Network: %s", result.Stdout)

	// If API key configured, show placeholder and test API
	if apiKey != "" {
		result, _ = client.Exec("echo ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY")
		fmt.Printf("\n%s", result.Stdout)
		fmt.Println("(Real key is replaced by MITM proxy in HTTP requests)")

		fmt.Println("\nTesting Anthropic API...")
		curlCmd := `curl -s https://api.anthropic.com/v1/messages \
			-H "Content-Type: application/json" \
			-H "x-api-key: $ANTHROPIC_API_KEY" \
			-H "anthropic-version: 2023-06-01" \
			-d '{"model":"claude-3-haiku-20240307","max_tokens":50,"messages":[{"role":"user","content":"Say hello in exactly 3 words"}]}'`
		
		result, err = client.Exec(curlCmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "API call failed: %v\n", err)
		} else if strings.Contains(result.Stdout, "error") {
			fmt.Printf("API Error: %s\n", result.Stdout)
		} else {
			fmt.Printf("Response: %s\n", result.Stdout)
		}
	}
}
