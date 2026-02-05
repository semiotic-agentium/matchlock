// Matchlock Go SDK Example - Container Image + Secret MITM Demo
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
		cfg.BinaryPath = "./bin/matchlock"
	}

	client, err := sdk.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Use python:3.12-alpine container image (auto-builds on first use)
	opts := sdk.CreateOptions{Image: "python:3.12-alpine"}

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

	fmt.Println("Creating VM with python:3.12-alpine...")
	vmID, err := client.Create(opts)
	if err != nil {
		if _, statErr := os.Stat(cfg.BinaryPath); statErr != nil {
			absPath, _ := filepath.Abs(cfg.BinaryPath)
			fmt.Fprintf(os.Stderr, "Binary not found at: %s\n", absPath)
			fmt.Fprintf(os.Stderr, "Run: make build-all\n")
		}
		fmt.Fprintf(os.Stderr, "Failed to create VM: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created VM: %s\n\n", vmID)

	// Test Python version
	result, _ := client.Exec("python3 --version")
	fmt.Printf("Python: %s", result.Stdout)

	// Test basic connectivity
	result, _ = client.Exec("ping -c 1 8.8.8.8 2>&1 | tail -2")
	fmt.Printf("Network: %s", result.Stdout)

	// If API key configured, test Anthropic API
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
