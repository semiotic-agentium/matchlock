package guestfused

import (
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/stretchr/testify/assert"
)

func TestFillAttrIncludesInode(t *testing.T) {
	var attr fuse.Attr
	fillAttr(&attr, &VFSStat{
		Size:    12,
		Mode:    0755,
		ModTime: 1700000000,
		IsDir:   true,
		Ino:     12345,
	})

	assert.Equal(t, uint64(12345), attr.Ino)
	assert.Equal(t, uint32(syscall.S_IFDIR|0755), attr.Mode)
	assert.Equal(t, uint32(2), attr.Nlink)
}

func TestFillEntryAttrFallbackUsesProvidedInode(t *testing.T) {
	var out fuse.EntryOut
	fillEntryAttr(&out, nil, entryAttrDefaults{
		mode:  syscall.S_IFREG | 0644,
		ino:   4242,
		isDir: false,
	})

	assert.Equal(t, uint64(4242), out.Ino)
	assert.Equal(t, uint64(4242), out.Attr.Ino)
	assert.Equal(t, uint32(syscall.S_IFREG|0644), out.Attr.Mode)
	assert.Equal(t, uint32(1), out.Attr.Nlink)
}

func TestInodeForPathDeterministic(t *testing.T) {
	dirA := inodeForPath("/workspace/repo", true)
	dirB := inodeForPath("/workspace/repo", true)
	file := inodeForPath("/workspace/repo", false)

	assert.NotZero(t, dirA)
	assert.Equal(t, dirA, dirB)
	assert.NotEqual(t, dirA, file)
}
