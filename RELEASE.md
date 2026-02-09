# Release Notes

## Unreleased

### Bug Fixes

- **`matchlock rm` now errors when VM ID is not found** ([#14](https://github.com/jingkaihe/matchlock/issues/14))
- **Fix 2-3s exit delay and "file already closed" warning on macOS** — `Close()` now attempts a graceful ACPI shutdown with a 500ms timeout before force-stopping the VM, and `SocketPair.Close()` is idempotent to prevent double-close errors ([#13](https://github.com/jingkaihe/matchlock/issues/13))

