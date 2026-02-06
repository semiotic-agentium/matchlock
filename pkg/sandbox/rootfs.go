package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// resizeRootfs expands an ext4 image to the given size in MB.
// Uses truncate to expand the sparse file and resize2fs to grow the filesystem.
// If the image is already larger than sizeMB, this is a no-op.
func resizeRootfs(rootfsPath string, sizeMB int64) error {
	if sizeMB <= 0 {
		return nil
	}

	fi, err := os.Stat(rootfsPath)
	if err != nil {
		return fmt.Errorf("stat rootfs: %w", err)
	}

	targetBytes := sizeMB * 1024 * 1024
	if fi.Size() >= targetBytes {
		return nil
	}

	if err := os.Truncate(rootfsPath, targetBytes); err != nil {
		return fmt.Errorf("truncate rootfs: %w", err)
	}

	e2fsckPath, _ := exec.LookPath("e2fsck")
	if e2fsckPath != "" {
		cmd := exec.Command(e2fsckPath, "-fy", rootfsPath)
		cmd.Stdin = nil
		cmd.CombinedOutput()
	}

	resize2fsPath, err := exec.LookPath("resize2fs")
	if err != nil {
		return fmt.Errorf("resize2fs not found; install e2fsprogs")
	}

	cmd := exec.Command(resize2fsPath, "-f", rootfsPath)
	cmd.Stdin = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("resize2fs: %w: %s", err, out)
	}

	return nil
}

// injectFileIntoRootfs writes a file into an ext4 image using debugfs.
// This allows injecting files (like CA certs) without mounting the filesystem.
// Requires debugfs to be installed (part of e2fsprogs).
func injectFileIntoRootfs(rootfsPath, guestPath string, content []byte) error {
	// Create a temp file with the content
	tmpFile, err := os.CreateTemp("", "inject-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	// Build debugfs commands: create parent directories, then write file
	// debugfs doesn't have mkdir -p, so we create each directory level
	var commands []string
	dir := filepath.Dir(guestPath)
	if dir != "/" && dir != "." {
		// Build list of directories to create (from root to parent)
		var dirs []string
		for d := dir; d != "/" && d != "."; d = filepath.Dir(d) {
			dirs = append([]string{d}, dirs...)
		}
		for _, d := range dirs {
			// mkdir will fail silently if dir exists, which is fine
			commands = append(commands, fmt.Sprintf("mkdir %s", d))
		}
	}
	commands = append(commands, fmt.Sprintf("write %s %s", tmpPath, guestPath))

	// Run all commands in one debugfs session
	cmdStr := strings.Join(commands, "\n")
	cmd := exec.Command("debugfs", "-w", rootfsPath)
	cmd.Stdin = strings.NewReader(cmdStr)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("debugfs: %w: %s", err, output)
	}

	return nil
}
