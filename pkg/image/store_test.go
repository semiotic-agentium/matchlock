package image

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreRoundTrip(t *testing.T) {
	storeDir := t.TempDir()
	store := NewStore(storeDir)

	rootfsFile := filepath.Join(t.TempDir(), "test.ext4")
	require.NoError(t, os.WriteFile(rootfsFile, []byte("fake-rootfs-content"), 0644))

	meta := ImageMeta{
		Digest:    "sha256:abc123",
		Source:    "test",
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	require.NoError(t, store.Save("myapp:latest", rootfsFile, meta))

	result, err := store.Get("myapp:latest")
	require.NoError(t, err)
	assert.Equal(t, "sha256:abc123", result.Digest)
	assert.True(t, result.Cached)

	content, err := os.ReadFile(result.RootfsPath)
	require.NoError(t, err)
	assert.Equal(t, "fake-rootfs-content", string(content))
}

func TestStoreList(t *testing.T) {
	storeDir := t.TempDir()
	store := NewStore(storeDir)

	rootfsFile := filepath.Join(t.TempDir(), "test.ext4")
	require.NoError(t, os.WriteFile(rootfsFile, []byte("data"), 0644))

	require.NoError(t, store.Save("app1:v1", rootfsFile, ImageMeta{
		Digest:    "sha256:aaa",
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}))
	require.NoError(t, store.Save("app2:v2", rootfsFile, ImageMeta{
		Digest:    "sha256:bbb",
		CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	}))

	images, err := store.List()
	require.NoError(t, err)
	require.Len(t, images, 2)
	assert.Equal(t, "app2:v2", images[0].Tag)
	assert.Equal(t, "app1:v1", images[1].Tag)
}

func TestStoreRemove(t *testing.T) {
	storeDir := t.TempDir()
	store := NewStore(storeDir)

	rootfsFile := filepath.Join(t.TempDir(), "test.ext4")
	require.NoError(t, os.WriteFile(rootfsFile, []byte("data"), 0644))
	require.NoError(t, store.Save("myapp:latest", rootfsFile, ImageMeta{Digest: "sha256:abc"}))

	require.NoError(t, store.Remove("myapp:latest"))
	_, err := store.Get("myapp:latest")
	require.Error(t, err)
}

func TestStoreRemoveNotFound(t *testing.T) {
	storeDir := t.TempDir()
	store := NewStore(storeDir)
	require.Error(t, store.Remove("nonexistent:tag"))
}

func TestStoreGetNotFound(t *testing.T) {
	storeDir := t.TempDir()
	store := NewStore(storeDir)
	_, err := store.Get("nonexistent:tag")
	require.Error(t, err)
}

func TestStoreListEmpty(t *testing.T) {
	storeDir := t.TempDir()
	store := NewStore(storeDir)

	images, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, images)
}

func TestStoreListNonexistentDir(t *testing.T) {
	storeDir := filepath.Join(t.TempDir(), "does-not-exist", "local")
	store := NewStore(storeDir)
	images, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, images)
}

func TestStoreOverwrite(t *testing.T) {
	storeDir := t.TempDir()
	store := NewStore(storeDir)

	rootfsFile1 := filepath.Join(t.TempDir(), "test1.ext4")
	require.NoError(t, os.WriteFile(rootfsFile1, []byte("version1"), 0644))
	rootfsFile2 := filepath.Join(t.TempDir(), "test2.ext4")
	require.NoError(t, os.WriteFile(rootfsFile2, []byte("version2"), 0644))

	require.NoError(t, store.Save("myapp:latest", rootfsFile1, ImageMeta{Digest: "sha256:v1"}))
	require.NoError(t, store.Save("myapp:latest", rootfsFile2, ImageMeta{Digest: "sha256:v2"}))

	result, err := store.Get("myapp:latest")
	require.NoError(t, err)
	assert.Equal(t, "sha256:v2", result.Digest)

	content, err := os.ReadFile(result.RootfsPath)
	require.NoError(t, err)
	assert.Equal(t, "version2", string(content))
}

func TestRemoveRegistryCache(t *testing.T) {
	cacheDir := t.TempDir()
	imgDir := filepath.Join(cacheDir, "ubuntu_24.04")
	require.NoError(t, os.MkdirAll(imgDir, 0755))
	rootfsPath := filepath.Join(imgDir, "abc123.ext4")
	require.NoError(t, os.WriteFile(rootfsPath, []byte("rootfs"), 0644))
	require.NoError(t, SaveRegistryCache("ubuntu:24.04", cacheDir, rootfsPath, ImageMeta{
		Digest:    "sha256:abc123",
		Source:    "registry",
		CreatedAt: time.Now().UTC(),
	}))

	require.NoError(t, RemoveRegistryCache("ubuntu:24.04", cacheDir))
	_, err := os.Stat(imgDir)
	assert.True(t, os.IsNotExist(err))
}

func TestRemoveRegistryCacheNotFound(t *testing.T) {
	cacheDir := t.TempDir()
	require.Error(t, RemoveRegistryCache("nonexistent:tag", cacheDir))
}

func TestListRegistryCacheEmpty(t *testing.T) {
	images, err := ListRegistryCache(t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, images)
}

func TestListRegistryCacheWithMetadata(t *testing.T) {
	cacheDir := t.TempDir()
	imgDir := filepath.Join(cacheDir, "alpine_latest")
	require.NoError(t, os.MkdirAll(imgDir, 0755))
	rootfsPath := filepath.Join(imgDir, "abc123def456.ext4")
	require.NoError(t, os.WriteFile(rootfsPath, []byte("rootfs"), 0644))
	require.NoError(t, SaveRegistryCache("alpine:latest", cacheDir, rootfsPath, ImageMeta{
		Digest:    "sha256:abc123def456",
		Source:    "registry",
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}))

	images, err := ListRegistryCache(cacheDir)
	require.NoError(t, err)
	require.Len(t, images, 1)
	assert.Equal(t, "alpine:latest", images[0].Tag)
	assert.Equal(t, "registry", images[0].Meta.Source)
	assert.Equal(t, "sha256:abc123def456", images[0].Meta.Digest)
}

func TestGetRegistryCache(t *testing.T) {
	cacheDir := t.TempDir()
	imgDir := filepath.Join(cacheDir, "python_3.12")
	require.NoError(t, os.MkdirAll(imgDir, 0755))
	rootfsPath := filepath.Join(imgDir, "abc123.ext4")
	require.NoError(t, os.WriteFile(rootfsPath, []byte("rootfs"), 0644))
	require.NoError(t, SaveRegistryCache("python:3.12", cacheDir, rootfsPath, ImageMeta{
		Digest:    "sha256:abc123",
		Source:    "registry",
		CreatedAt: time.Now().UTC(),
	}))

	result, err := GetRegistryCache("python:3.12", cacheDir)
	require.NoError(t, err)
	assert.Equal(t, rootfsPath, result.RootfsPath)
	assert.Equal(t, "sha256:abc123", result.Digest)
}
