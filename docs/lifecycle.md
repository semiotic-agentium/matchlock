# Lifecycle and Cleanup Runbook

This document explains how Matchlock tracks VM lifecycle state, which resources
are owned by a VM, and how to recover from leaked host resources.

## Why this exists

Sandbox shutdown can fail partway through (host signal, process crash, network
permission issues, etc.). Matchlock now persists lifecycle state so cleanup can
be resumed safely and auditable later.

## Lifecycle record

Each VM has a persistent lifecycle file:

- `~/.matchlock/vms/<vm-id>/lifecycle.json`

The record includes:

- current lifecycle phase
- last lifecycle error (if any)
- known resource identifiers/paths (rootfs, subnet allocation, TAP table names)
- per-step cleanup status for close/reconcile operations

## Phases

Phases are validated through an allowed-transition state machine.

Primary phases:

- `creating`
- `created`
- `starting`
- `running`
- `stopping`
- `stopped`
- `cleaning`
- `cleaned`

Failure phases:

- `create_failed`
- `start_failed`
- `stop_failed`
- `cleanup_failed`

Typical success path:

1. `creating -> created`
2. `created -> starting -> running`
3. `running -> stopping -> cleaning -> cleaned`

## Resource ownership

The lifecycle record tracks resources needed for deterministic cleanup:

- VM state directory: `~/.matchlock/vms/<vm-id>/`
- per-VM rootfs copy: `rootfs.ext4` under VM state dir
- subnet allocation file: `~/.matchlock/subnets/<vm-id>.json`
- Linux-only network artifacts:
  - TAP interface (`fc-<suffix>`)
  - nftables tables (`matchlock_<tap>`, `matchlock_nat_<tap>`)

## Cleanup behavior

`Sandbox.Close()` now reports cleanup failures instead of silently ignoring
them. Failures are stored in lifecycle cleanup entries.

CLI behavior now preserves cleanup semantics:

- command exit codes are propagated without bypassing deferred cleanup
- `run --rm=false -it` keeps VM alive until signal, then performs close cleanup

## Reconciliation (`matchlock gc`)

Use `gc` to clean leaked resources for stopped/crashed VMs:

```bash
# Reconcile one VM
matchlock gc vm-abc12345

# Reconcile all VMs
matchlock gc

# Also reconcile currently running VMs (dangerous; use sparingly)
matchlock gc --force-running
```

`gc` reconciles:

- subnet allocation file
- rootfs copy
- Linux: TAP + nftables artifacts

If a VM is still running, reconciliation is skipped unless `--force-running`
is provided.

## `rm` and `prune` semantics

`rm`/`prune` now run reconciliation before removing VM metadata:

- if reconcile succeeds, VM state can be removed
- if reconcile fails, removal is aborted and error is returned

This prevents losing VM metadata while leaking host resources.

## Subnet allocator safety

Subnet allocation now uses a cross-process file lock:

- lock file: `~/.matchlock/subnets/.lock`
- only `*.json` allocation files are considered

This avoids allocation races when multiple Matchlock processes run in parallel.

## Platform notes

- Linux: reconciles subnet/rootfs/TAP/nftables.
- macOS and non-Linux platforms: reconciles subnet/rootfs; platform-specific
  network artifact reconciliation is currently a no-op.

## Operational troubleshooting

1. Inspect VM states:
   - `matchlock list`
2. Inspect lifecycle record:
   - `cat ~/.matchlock/vms/<vm-id>/lifecycle.json`
3. Reconcile leaked resources:
   - `matchlock gc <vm-id>`
4. Remove stopped VM metadata after successful reconcile:
   - `matchlock rm <vm-id>`

If `gc` still fails, check the failed cleanup steps in `lifecycle.json` and fix
host permissions/network prerequisites before retrying.
