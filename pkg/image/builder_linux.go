//go:build linux

package image

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// platformOptions returns remote options for linux (uses default platform detection)
func (b *Builder) platformOptions() []remote.Option {
	return nil
}

// createExt4 creates an ext4 filesystem using native Linux tools
func (b *Builder) createExt4(sourceDir, destPath string) error {
	var totalSize int64
	filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			totalSize += info.Size()
		}
		return nil
	})

	sizeMB := (totalSize / (1024 * 1024)) + 512
	if sizeMB < 256 {
		sizeMB = 256
	}

	tmpPath := destPath + ".tmp"

	cmd := exec.Command("dd", "if=/dev/zero", "of="+tmpPath, "bs=1M", fmt.Sprintf("count=%d", sizeMB), "conv=sparse")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create sparse file: %w: %s", err, out)
	}

	cmd = exec.Command("mkfs.ext4", "-F", "-q", tmpPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("mkfs.ext4: %w: %s", err, out)
	}

	mountDir, err := os.MkdirTemp("", "matchlock-mount-*")
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("create mount dir: %w", err)
	}
	defer os.RemoveAll(mountDir)

	cmd = exec.Command("mount", "-o", "loop", tmpPath, mountDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("mount: %w: %s", err, out)
	}
	defer exec.Command("umount", mountDir).Run()

	cmd = exec.Command("cp", "-a", sourceDir+"/.", mountDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copy files: %w: %s", err, out)
	}

	cmd = exec.Command("umount", mountDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("umount: %w: %s", err, out)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}
