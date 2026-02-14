# VFS Interception

VFS interception lets you inspect and control filesystem operations on mounted guest paths from the host side.

## Rule Model

Each rule has:
- `phase`: `before` or `after`
- `ops`: operation filter (`create`, `write`, `read`, etc.)
- `path`: filepath-style glob (for example `/workspace/*`)

Behavior by phase:
- `before`: supports wire `action=block`, SDK `action_hook` callbacks, and SDK `mutate_hook` callbacks
- `after`: supports SDK `hook` callbacks

## Go SDK

Use typed constants for phases and ops:

```go
sandbox := sdk.New("alpine:latest").WithVFSInterception(&sdk.VFSInterceptionConfig{
	Rules: []sdk.VFSHookRule{
		{
			Phase:  sdk.VFSHookPhaseBefore,
			Ops:    []sdk.VFSHookOp{sdk.VFSHookOpCreate},
			Path:   "/workspace/blocked.txt",
			ActionHook: func(ctx context.Context, req sdk.VFSActionRequest) sdk.VFSHookAction {
				return sdk.VFSHookActionBlock
			},
		},
		{
			Phase: sdk.VFSHookPhaseBefore,
			Ops:   []sdk.VFSHookOp{sdk.VFSHookOpWrite},
			Path:  "/workspace/mutated.txt",
			MutateHook: func(ctx context.Context, req sdk.VFSMutateRequest) ([]byte, error) {
				return []byte("mutated-by-hook"), nil
			},
		},
		{
			Phase: sdk.VFSHookPhaseAfter,
			Ops:   []sdk.VFSHookOp{sdk.VFSHookOpWrite},
			Path:  "/workspace/*",
			Hook: func(ctx context.Context, event sdk.VFSHookEvent) error {
				fmt.Printf("op=%s path=%s size=%d mode=%#o uid=%d gid=%d\n",
					event.Op, event.Path, event.Size, event.Mode, event.UID, event.GID)
				return nil
			},
		},
		{
			Phase: sdk.VFSHookPhaseAfter,
			Ops:   []sdk.VFSHookOp{sdk.VFSHookOpWrite},
			Path:  "/workspace/*",
			DangerousHook: func(ctx context.Context, client *sdk.Client, event sdk.VFSHookEvent) error {
				_, err := client.Exec(ctx, "echo hook >> /workspace/hook.log")
				return err
			},
		},
	},
})
```

See full runnable examples:
- [`examples/go/basic/main.go`](../examples/go/basic/main.go)
- [`examples/go/vfs_hooks/main.go`](../examples/go/vfs_hooks/main.go)

## Python SDK

Use exported constants for phases and ops:

```python
from matchlock import (
    Sandbox,
    VFSInterceptionConfig,
    VFSHookRule,
    VFSActionRequest,
    VFSMutateRequest,
    VFS_HOOK_ACTION_BLOCK,
    VFS_HOOK_PHASE_BEFORE,
    VFS_HOOK_PHASE_AFTER,
    VFS_HOOK_OP_CREATE,
    VFS_HOOK_OP_WRITE,
)

def after_write(event):
    print(
        f"op={event.op} path={event.path} size={event.size} "
        f"mode={oct(event.mode)} uid={event.uid} gid={event.gid}"
    )

def dangerous_after_write(client, event):
    client.exec("echo hook >> /workspace/hook.log")

def mutate_write(req: VFSMutateRequest) -> bytes:
    return b"mutated-by-hook"

def block_create(req: VFSActionRequest) -> str:
    return VFS_HOOK_ACTION_BLOCK

sandbox = Sandbox("alpine:latest").with_vfs_interception(
    VFSInterceptionConfig(
        rules=[
            VFSHookRule(
                phase=VFS_HOOK_PHASE_BEFORE,
                ops=[VFS_HOOK_OP_CREATE],
                path="/workspace/blocked.txt",
                action_hook=block_create,
            ),
            VFSHookRule(
                phase=VFS_HOOK_PHASE_BEFORE,
                ops=[VFS_HOOK_OP_WRITE],
                path="/workspace/mutated.txt",
                mutate_hook=mutate_write,
            ),
            VFSHookRule(
                phase=VFS_HOOK_PHASE_AFTER,
                ops=[VFS_HOOK_OP_WRITE],
                path="/workspace/*",
                hook=after_write,
            ),
            VFSHookRule(
                phase=VFS_HOOK_PHASE_AFTER,
                ops=[VFS_HOOK_OP_WRITE],
                path="/workspace/*",
                dangerous_hook=dangerous_after_write,
            ),
        ],
    )
)
```

See full runnable examples:
- [`examples/python/basic/main.py`](../examples/python/basic/main.py)
- [`examples/python/vfs_hooks/main.py`](../examples/python/vfs_hooks/main.py)

## Recursion and Safety

- `hook` callbacks are `after`-only and run with recursion suppression enabled.
- `dangerous_hook` callbacks are `after`-only and bypass recursion suppression.
- When SDK callbacks are present, event emission is enabled automatically for interception.

## Host-Side Dynamic Mutate (Go, In-Process)

If you are wiring `pkg/vfs` directly in host Go code, `mutate_write` can be dynamic per write:

```go
hooks := vfs.NewHookEngine([]vfs.HookRule{
	{
		Phase:  vfs.HookPhaseBefore,
		Ops:    []vfs.HookOp{vfs.HookOpWrite},
		Action: vfs.HookActionMutateWrite,
		MutateWriteFunc: func(ctx context.Context, req vfs.MutateWriteRequest) ([]byte, error) {
			// Decide replacement bytes dynamically from metadata.
			// req has: path, size, offset, mode, uid, gid.
			return []byte("prefix:" + req.Path), nil
		},
	},
})
```

Notes:
- This is host in-process only (`pkg/vfs` / `pkg/sandbox` integration), not JSON-RPC payload.
- Returning an error from `MutateWriteFunc` fails the write.
