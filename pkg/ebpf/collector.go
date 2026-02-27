// Package ebpf provides a host-side collector for eBPF events streamed
// from a guest VM over vsock, with a plugin system for policy enforcement.
//
// The guest runs an eBPF tracer that connects to CID 2 (host) on port 5003.
// In Firecracker's vsock model, this connection appears at the UDS path
// <vsock_path>_5003. The collector listens on that UDS, accepts the
// connection, parses JSONL events, runs them through the plugin engine,
// and optionally writes raw events to a debug log file.
package ebpf

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
)

const (
	// VsockPortEBPF is the vsock port used by the guest eBPF tracer.
	VsockPortEBPF = 5003
)

// Collector receives JSONL events from the guest eBPF tracer over vsock,
// processes them through the plugin engine, and optionally writes raw
// events to a debug log file.
type Collector struct {
	engine       *Engine // plugin engine (nil = no plugins)
	debugLogPath string  // raw JSONL output path (empty = disabled)
	listener     net.Listener
	mu           sync.Mutex
	debugFile    *os.File
	closed       bool
}

// NewCollector creates a new eBPF event collector.
//
// Parameters:
//   - engine: plugin engine for processing events. Nil disables plugin processing.
//   - debugLogPath: path for raw JSONL event output. Empty string disables debug logging.
func NewCollector(engine *Engine, debugLogPath string) *Collector {
	return &Collector{
		engine:       engine,
		debugLogPath: debugLogPath,
	}
}

// ServeUDSBackground starts listening on the vsock UDS path for guest eBPF
// connections and collecting events in the background. Returns a stop function.
//
// socketPath should be fmt.Sprintf("%s_%d", vmConfig.VsockPath, VsockPortEBPF)
func (c *Collector) ServeUDSBackground(socketPath string) (stop func(), err error) {
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", socketPath, err)
	}
	c.listener = listener

	// Open debug log file if enabled
	if c.debugLogPath != "" {
		f, err := os.OpenFile(c.debugLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			listener.Close()
			return nil, fmt.Errorf("open debug log %s: %w", c.debugLogPath, err)
		}
		c.debugFile = f
		slog.Info("ebpf collector: debug log enabled", "path", c.debugLogPath)
	}

	pluginCount := 0
	if c.engine != nil {
		pluginCount = c.engine.PluginCount()
	}
	slog.Info("ebpf collector: listening",
		"socket", socketPath,
		"plugins", pluginCount,
		"debug_log", c.debugLogPath != "",
	)

	go c.serve()

	return func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		listener.Close()
		if c.debugFile != nil {
			c.debugFile.Close()
		}
	}, nil
}

func (c *Collector) serve() {
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed {
				return
			}
			slog.Warn("ebpf collector: accept error", "error", err)
			continue
		}

		slog.Info("ebpf collector: guest tracer connected")
		go c.handleConnection(conn)
	}
}

func (c *Collector) handleConnection(conn net.Conn) {
	defer conn.Close()

	ctx := context.Background()
	scanner := bufio.NewScanner(conn)
	// Allow up to 64KB per line (JSONL events can be large)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)

	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		// Write raw line to debug log if enabled
		c.mu.Lock()
		if c.debugFile != nil {
			fmt.Fprintln(c.debugFile, line)
			if lineCount%10 == 0 {
				c.debugFile.Sync()
			}
		}
		c.mu.Unlock()

		// Parse and process through plugin engine
		if c.engine != nil {
			var event EBPFEvent
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				slog.Warn("ebpf collector: failed to parse event", "error", err)
			} else {
				c.engine.ProcessEvent(ctx, &event)
			}
		}

		lineCount++
	}

	if err := scanner.Err(); err != nil {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if !closed {
			slog.Warn("ebpf collector: read error", "error", err, "lines_received", lineCount)
		}
	}

	slog.Info("ebpf collector: guest tracer disconnected", "lines_received", lineCount)
}
