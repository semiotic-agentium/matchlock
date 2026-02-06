package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jingkaihe/matchlock/pkg/sdk"
)

func main() {
	cfg := sdk.DefaultConfig()
	if os.Getenv("MATCHLOCK_BIN") == "" {
		cfg.BinaryPath = "./bin/matchlock"
	}

	client, err := sdk.NewClient(cfg)
	if err != nil {
		slog.Error("failed to create client", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	sandbox := sdk.New("python:3.12-alpine").
		AllowHost("dl-cdn.alpinelinux.org", "api.anthropic.com").
		AddSecret("ANTHROPIC_API_KEY", os.Getenv("ANTHROPIC_API_KEY"), "api.anthropic.com")

	vmID, err := client.Launch(sandbox)
	if err != nil {
		slog.Error("failed to launch sandbox", "error", err)
		os.Exit(1)
	}
	slog.Info("sandbox ready", "vm", vmID)

	// Buffered exec — collects all output, returns when done
	run(client, "python3 --version")
	run(client, "apk add --no-cache -q curl")

	// Streaming exec — prints output as it arrives (Anthropic streaming API)
	result, err := client.ExecStream(
		`curl -sN https://api.anthropic.com/v1/messages `+
			`-H "Content-Type: application/json" `+
			`-H "x-api-key: $ANTHROPIC_API_KEY" `+
			`-H "anthropic-version: 2023-06-01" `+
			`-d '{"model":"claude-haiku-4-5-20251001","max_tokens":1000,"stream":true,"messages":[{"role":"user","content":"Explain TCP to me"}]}'`,
		os.Stdout, os.Stderr,
	)
	if err != nil {
		slog.Error("exec_stream failed", "error", err)
		os.Exit(1)
	}
	fmt.Println()
	slog.Info("done", "exit_code", result.ExitCode, "duration_ms", result.DurationMS)
}

func run(c *sdk.Client, cmd string) {
	result, err := c.Exec(cmd)
	if err != nil {
		slog.Error("exec failed", "cmd", cmd, "error", err)
		os.Exit(1)
	}
	fmt.Print(result.Stdout)
}
