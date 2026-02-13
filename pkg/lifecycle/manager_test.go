package lifecycle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jingkaihe/matchlock/pkg/state"
	"github.com/stretchr/testify/require"
)

func TestVMManagerPrune(t *testing.T) {
	vmDir := t.TempDir()
	subnetDir := filepath.Join(t.TempDir(), "subnets")

	stateMgr := state.NewManagerWithDir(vmDir)
	subnetAlloc := state.NewSubnetAllocatorWithDir(subnetDir)
	mgr := NewVMManagerWithDeps(stateMgr, subnetAlloc)

	stoppedID := "vm-stopped1"
	require.NoError(t, stateMgr.Register(stoppedID, map[string]string{"image": "alpine:latest"}))
	require.NoError(t, stateMgr.Unregister(stoppedID))

	runningID := "vm-running1"
	require.NoError(t, stateMgr.Register(runningID, map[string]string{"image": "alpine:latest"}))

	pruned, err := mgr.Prune()
	require.NoError(t, err)
	require.Contains(t, pruned, stoppedID)
	require.NotContains(t, pruned, runningID)

	_, err = stateMgr.Get(stoppedID)
	require.Error(t, err)
	_, err = stateMgr.Get(runningID)
	require.NoError(t, err)
}

func TestVMManagerRemove_ReconcileFailureKeepsState(t *testing.T) {
	vmDir := t.TempDir()
	subnetDir := filepath.Join(t.TempDir(), "subnets")

	stateMgr := state.NewManagerWithDir(vmDir)
	subnetAlloc := state.NewSubnetAllocatorWithDir(subnetDir)
	mgr := NewVMManagerWithDeps(stateMgr, subnetAlloc)

	vmID := "vm-stopped2"
	require.NoError(t, stateMgr.Register(vmID, map[string]string{"image": "alpine:latest"}))
	require.NoError(t, stateMgr.Unregister(vmID))
	require.NoError(t, os.Chmod(subnetDir, 0500))
	t.Cleanup(func() {
		_ = os.Chmod(subnetDir, 0700)
	})

	err := mgr.Remove(vmID)
	require.Error(t, err)

	_, err = stateMgr.Get(vmID)
	require.NoError(t, err)
}

func TestVMManagerPrune_ReconcileFailureDoesNotRemove(t *testing.T) {
	vmDir := t.TempDir()
	subnetDir := filepath.Join(t.TempDir(), "subnets")

	stateMgr := state.NewManagerWithDir(vmDir)
	subnetAlloc := state.NewSubnetAllocatorWithDir(subnetDir)
	mgr := NewVMManagerWithDeps(stateMgr, subnetAlloc)

	vmID := "vm-stopped3"
	require.NoError(t, stateMgr.Register(vmID, map[string]string{"image": "alpine:latest"}))
	require.NoError(t, stateMgr.Unregister(vmID))
	require.NoError(t, os.Chmod(subnetDir, 0500))
	t.Cleanup(func() {
		_ = os.Chmod(subnetDir, 0700)
	})

	pruned, err := mgr.Prune()
	require.Error(t, err)
	require.Empty(t, pruned)

	_, err = stateMgr.Get(vmID)
	require.NoError(t, err)
}
