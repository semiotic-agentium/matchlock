package vsock

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/jingkaihe/matchlock/pkg/api"
)

// ReadFull reads exactly len(buf) bytes from conn, retrying short reads.
func ReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// SendMessage writes a framed vsock message (1-byte type + 4-byte big-endian
// length + payload) to conn.
func SendMessage(conn net.Conn, msgType uint8, data []byte) error {
	header := make([]byte, 5)
	header[0] = msgType
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := conn.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// ExecPipe executes a command over a vsock connection with bidirectional
// stdin/stdout/stderr piping (no PTY). The caller must supply an already-dialed
// conn; ExecPipe takes ownership and closes it when done.
func ExecPipe(ctx context.Context, conn net.Conn, command string, opts *api.ExecOptions) (*api.ExecResult, error) {
	start := time.Now()
	defer conn.Close()

	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	req := ExecRequest{Command: command}
	if opts != nil {
		req.WorkingDir = opts.WorkingDir
		req.Env = opts.Env
		req.User = opts.User
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode exec request: %w", err)
	}

	header := make([]byte, 5)
	header[0] = MsgTypeExecPipe
	binary.BigEndian.PutUint32(header[1:], uint32(len(reqData)))

	if _, err := conn.Write(header); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := conn.Write(reqData); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// Forward stdin to guest
	if opts != nil && opts.Stdin != nil {
		go func() {
			buf := make([]byte, 4096)
			for {
				n, readErr := opts.Stdin.Read(buf)
				if n > 0 {
					SendMessage(conn, MsgTypeStdin, buf[:n])
				}
				if readErr != nil {
					SendMessage(conn, MsgTypeStdin, nil)
					return
				}
			}
		}()
	}

	done := make(chan *api.ExecResult, 1)
	errCh := make(chan error, 1)

	go func() {
		hdr := make([]byte, 5)
		for {
			if _, err := ReadFull(conn, hdr); err != nil {
				if ctx.Err() != nil {
					errCh <- ctx.Err()
				} else {
					errCh <- fmt.Errorf("failed to read response header: %w", err)
				}
				return
			}

			msgType := hdr[0]
			length := binary.BigEndian.Uint32(hdr[1:])

			data := make([]byte, length)
			if length > 0 {
				if _, err := ReadFull(conn, data); err != nil {
					if ctx.Err() != nil {
						errCh <- ctx.Err()
					} else {
						errCh <- fmt.Errorf("failed to read response data: %w", err)
					}
					return
				}
			}

			switch msgType {
			case MsgTypeStdout:
				if opts != nil && opts.Stdout != nil {
					opts.Stdout.Write(data)
				}
			case MsgTypeStderr:
				if opts != nil && opts.Stderr != nil {
					opts.Stderr.Write(data)
				}
			case MsgTypeExit:
				exitCode := 0
				if len(data) >= 4 {
					exitCode = int(binary.BigEndian.Uint32(data))
				}
				done <- &api.ExecResult{
					ExitCode:   exitCode,
					Duration:   time.Since(start),
					DurationMS: time.Since(start).Milliseconds(),
				}
				return
			}
		}
	}()

	select {
	case result := <-done:
		return result, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

