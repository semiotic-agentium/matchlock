package lifecycle

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	require.NoError(t, store.Init("vm-abc12345", "firecracker", dir))
	require.NoError(t, store.SetResource(func(r *Resources) {
		r.RootfsPath = filepath.Join(dir, "rootfs.ext4")
		r.TAPName = "fc-abc12345"
	}))
	require.NoError(t, store.SetPhase(PhaseCreated))
	require.NoError(t, store.SetPhase(PhaseStarting))
	require.NoError(t, store.SetPhase(PhaseRunning))
	require.NoError(t, store.MarkCleanup("tap_delete", errors.New("busy")))
	require.NoError(t, store.MarkCleanup("subnet_release", nil))

	rec, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, "vm-abc12345", rec.VMID)
	require.Equal(t, "firecracker", rec.Backend)
	require.Equal(t, PhaseRunning, rec.Phase)
	require.Equal(t, "fc-abc12345", rec.Resources.TAPName)
	require.Equal(t, "error", rec.Cleanup["tap_delete"].Status)
	require.Equal(t, "ok", rec.Cleanup["subnet_release"].Status)

	require.NoError(t, store.SetLastError(errors.New("cleanup failed")))
	rec, err = store.Load()
	require.NoError(t, err)
	require.Equal(t, "cleanup failed", rec.LastError)

	require.NoError(t, store.SetLastError(nil))
	rec, err = store.Load()
	require.NoError(t, err)
	require.Equal(t, "", rec.LastError)
}
