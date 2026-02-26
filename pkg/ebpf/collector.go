// Package ebpf provides a host-side collector for eBPF events streamed
// from a guest VM over vsock.
//
// The guest runs an eBPF tracer that connects to CID 2 (host) on port 5003.
// In Firecracker's vsock model, this connection appears at the UDS path
// <vsock_path>_5003. The collector listens on that UDS, accepts the
// connection, reads JSONL lines, and appends them to an output file.
package ebpf

import (
	"bufio"
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

// Collector receives JSONL events from the guest eBPF tracer over vsock
// and writes them to a file.
type Collector struct {
	outputPath string
	listener   net.Listener
	mu         sync.Mutex
	file       *os.File
	closed     bool
}

// NewCollector creates a new eBPF event collector that writes to outputPath.
func NewCollector(outputPath string) *Collector {
	return &Collector{
		outputPath: outputPath,
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

	f, err := os.OpenFile(c.outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("open %s: %w", c.outputPath, err)
	}
	c.file = f

	slog.Info("ebpf collector: listening", "socket", socketPath, "output", c.outputPath)

	go c.serve()

	return func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		listener.Close()
		if c.file != nil {
			c.file.Close()
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

	scanner := bufio.NewScanner(conn)
	// Allow up to 64KB per line (JSONL events can be large)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)

	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		c.mu.Lock()
		if c.file != nil {
			fmt.Fprintln(c.file, line)
			// Flush periodically for near-real-time output
			if lineCount%10 == 0 {
				c.file.Sync()
			}
		}
		c.mu.Unlock()

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
