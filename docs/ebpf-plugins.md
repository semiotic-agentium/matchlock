# eBPF Plugins

The eBPF plugin system provides kernel-level observability inside guest VMs. An eBPF tracer running in the guest attaches kernel probes to capture process lifecycle and file operations, streams those events to the host over vsock, and a plugin engine evaluates each event against a chain of policy plugins that can alert or kill offending processes.

## Architecture

```
Guest VM                                        Host
+--------------------------------------------+  +-------------------------------------------+
| Kernel                                     |  |                                           |
| +----------------------------------------+ |  |                                           |
| | eBPF probes                            | |  |                                           |
| | (tracepoints: sched_process_exec,      | |  |                                           |
| |  sched_process_exit, sys_enter_openat) | |  |                                           |
| +--------------------+-------------------+ |  |                                           |
|                      |                     |  |                                           |
| Userspace            v                     |  |                                           |
| +----------------------------------------+ |  |                                           |
| | ebpf-tracer                            | |  |                                           |
| | - reads from eBPF ring buffer          | |  |                                           |
| | - outputs JSONL events                 | |  |                                           |
| | - connects to CID 2, port 5003        | |  |                                           |
| +--------------------+-------------------+ |  |                                           |
|                      |                     |  |                                           |
+----------------------|---------------------+  |                                           |
                       | vsock                   |                                           |
                       v                         |                                           |
                  +----+----+                    |                                           |
                  | UDS      |  <vsock_path>_5003|                                           |
                  +----+----+                    |                                           |
                       |                         |                                           |
                       v                         |                                           |
              +--------+--------+                |                                           |
              | Collector       |                |                                           |
              | - accepts conn  |----+           |                                           |
              | - reads JSONL   |    |           |                                           |
              | - parses events |    |           |                                           |
              +--------+--------+    |           |                                           |
                       |             v           |                                           |
                       |     +-------+--------+  |                                           |
                       |     | Debug Log      |  |  (optional raw JSONL file)                |
                       |     +----------------+  |                                           |
                       v                         |                                           |
              +--------+--------+                |                                           |
              | Engine          |                |                                           |
              | - plugin chain  |                |                                           |
              +--------+--------+                |                                           |
                       |                         |                                           |
           +-----------+-----------+             |                                           |
           |                       |             |                                           |
           v                       v             |                                           |
  +--------+--------+    +--------+--------+    |                                           |
  | Event Log       |    | Kill Relay      |    |                                           |
  | (shared emitter)|    | (exec -> guest) |    |                                           |
  +-----------------+    +-----------------+    |                                           |
                                                +-------------------------------------------+
```

## How It Works

1. **Guest boot** -- When eBPF is configured, the VM kernel command line includes `matchlock.ebpf=1`. The guest-init process launches `/opt/matchlock/ebpf-tracer` before applying seccomp restrictions, so the tracer runs with full root capabilities.

2. **Event capture** -- The tracer attaches eBPF programs to kernel tracepoints and captures three event types: `EXEC` (process started), `EXIT` (process exited), and `FILE_OPEN` (file opened).

3. **Event streaming** -- The tracer connects to the host via vsock (CID 2, port 5003) and streams events as JSONL (one JSON object per line).

4. **Host collection** -- The collector listens on the corresponding UDS socket, accepts the tracer connection, and parses each JSONL line into an `EBPFEvent` struct.

5. **Plugin evaluation** -- The engine passes each event to every registered plugin. Plugins return an `EventVerdict` indicating whether to alert, kill, or ignore. All plugins see every event.

6. **Enforcement** -- If a plugin sets `Alert: true`, the engine emits a structured event to the shared event log. If `Kill: true`, the engine sends `kill -9 <pid>` to the guest via the exec relay.

## Event Types

The tracer captures three event types from the guest kernel:

| Event | Trigger | Key Fields |
|-------|---------|------------|
| `EXEC` | Process started (`sched_process_exec`) | `filename`, `full_command`, `pid`, `ppid` |
| `EXIT` | Process exited (`sched_process_exit`) | `exit_code`, `duration_ms`, `pid` |
| `FILE_OPEN` | File opened (`sys_enter_openat`) | `filepath`, `flags`, `pid` |

### Event Schema

Every event from the tracer has this shape:

```json
{
  "timestamp": 1234567890,
  "event": "FILE_OPEN",
  "comm": "cat",
  "pid": 42,
  "ppid": 1,
  "filepath": "/etc/shadow",
  "flags": 0
}
```

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | uint64 | Kernel timestamp (nanoseconds). |
| `event` | string | `"EXEC"`, `"EXIT"`, or `"FILE_OPEN"`. |
| `comm` | string | Process command name (up to 16 chars). |
| `pid` | int | Process ID. |
| `ppid` | int | Parent process ID. |
| `exit_code` | uint | Exit code (EXIT events only). |
| `duration_ms` | uint64 | Process lifetime in milliseconds (EXIT events only). |
| `filename` | string | Executable path (EXEC events only). |
| `full_command` | string | Full command line (EXEC events only). |
| `filepath` | string | Opened file path (FILE_OPEN events only). |
| `flags` | int | Open flags (FILE_OPEN events only). |
| `count` | uint32 | Deduplication counter. |

## Built-in Plugins

### `sensitive_file_monitor`

Alerts on (and optionally kills) processes that open sensitive files such as `/etc/shadow`, SSH private keys, or TLS certificates.

- **Interface:** `EventPlugin`
- **File:** `pkg/ebpf/sensitive_file_monitor.go`
- **Events processed:** `FILE_OPEN` only (all others ignored)

```json
{
  "type": "sensitive_file_monitor",
  "config": {
    "patterns": ["/etc/shadow", "/etc/gshadow", "/root/.ssh/*"],
    "kill": true
  }
}
```

**Config fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `patterns` | string[] | see below | Glob patterns for sensitive file paths. |
| `kill` | bool | `false` | Kill the offending process with `kill -9`. |

**Default patterns** (used when `patterns` is empty):

```
/etc/shadow
/etc/gshadow
/etc/sudoers
/etc/sudoers.d/*
/root/.ssh/*
/home/*/.ssh/id_*
/home/*/.ssh/authorized_keys
/etc/ssl/private/*
/etc/ssh/ssh_host_*_key
```

Patterns use standard glob syntax (`*` matches a single directory level). Extension patterns like `*.pem` match the file suffix anywhere in the path.

**Event log output** (event type `ebpf_sensitive_file_monitor`):

```json
{
  "event_type": "ebpf_sensitive_file_monitor",
  "summary": "sensitive file access: cat opened /etc/shadow (matched /etc/shadow)",
  "plugin": "sensitive_file_monitor",
  "tags": ["ebpf"],
  "data": {
    "filepath": "/etc/shadow",
    "pid": 42,
    "comm": "cat",
    "matched_pattern": "/etc/shadow",
    "action": "killed"
  }
}
```

## Configuration

eBPF plugins are configured via the `ebpf` section of the sandbox config. Each plugin is an entry in the `plugins` array with a `type` name and optional JSON `config`:

```json
{
  "ebpf": {
    "debug_log": false,
    "plugins": [
      {
        "type": "sensitive_file_monitor",
        "config": {
          "kill": true,
          "patterns": ["/etc/shadow", "/custom/secrets/*"]
        }
      }
    ]
  }
}
```

### Config fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `debug_log` | bool | `false` | Write all raw eBPF events to `ebpf-events.jsonl` in the VM state directory. |
| `plugins` | array | `[]` | List of plugin configurations. |

### Disabling a plugin

Set `"enabled": false` to keep config around without activating:

```json
{ "type": "sensitive_file_monitor", "enabled": false, "config": { "kill": true } }
```

## CLI Flags

| CLI Flag | Description |
|----------|-------------|
| `--ebpf-plugin` | Enable an eBPF plugin. Repeatable. Format: `TYPE` or `TYPE=JSON_CONFIG`. |
| `--ebpf-debug-log` | Write raw eBPF events to a debug JSONL file. |

### Examples

**Alert on sensitive file access** (default patterns, alert only):

```bash
matchlock run --image alpine:latest \
  --ebpf-plugin sensitive_file_monitor \
  -- sh
```

**Kill processes that access sensitive files:**

```bash
matchlock run --image alpine:latest \
  --ebpf-plugin 'sensitive_file_monitor={"kill":true}' \
  -- sh
```

**Custom patterns with kill enforcement:**

```bash
matchlock run --image alpine:latest \
  --ebpf-plugin 'sensitive_file_monitor={"kill":true,"patterns":["/etc/shadow","/opt/secrets/*"]}' \
  -- sh
```

**Multiple plugins with debug logging:**

```bash
matchlock run --image alpine:latest \
  --ebpf-plugin sensitive_file_monitor \
  --ebpf-plugin 'sensitive_file_monitor={"kill":true,"patterns":["/custom/*"]}' \
  --ebpf-debug-log \
  -- sh
```

**Debug logging only** (no plugins, capture raw events for analysis):

```bash
matchlock run --image alpine:latest \
  --ebpf-debug-log \
  -- sh
```

The raw JSONL output is written to `ebpf-events.jsonl` in the VM state directory.

### CLI format reference

The `--ebpf-plugin` flag accepts two formats:

| Format | Example | Description |
|--------|---------|-------------|
| `TYPE` | `sensitive_file_monitor` | Plugin with default config. |
| `TYPE=JSON` | `sensitive_file_monitor={"kill":true}` | Plugin with explicit JSON config. |

The `=` separates the type name from the JSON config. This is a `StringArray` flag (not `StringSlice`), so commas inside JSON config are preserved.

## SDK

```go
import (
    "encoding/json"
    "github.com/jingkaihe/matchlock/pkg/sdk"
)

// Alert-only with default patterns
sandbox := sdk.New("alpine:latest").
    WithEBPFPlugin("sensitive_file_monitor", nil)

// Kill mode with custom patterns
sandbox := sdk.New("alpine:latest").
    WithEBPFPlugin("sensitive_file_monitor", json.RawMessage(`{
        "kill": true,
        "patterns": ["/etc/shadow", "/opt/secrets/*"]
    }`)).
    WithEBPFDebugLog()
```

## Writing a New Plugin

### 1. Pick your interface

All eBPF plugins implement `EventPlugin`, which processes raw kernel events and returns a verdict:

```go
// pkg/ebpf/plugin.go

type Plugin interface {
    Name() string
}

type EventPlugin interface {
    Plugin
    ProcessEvent(event *EBPFEvent) *EventVerdict
}
```

The `EventVerdict` controls what the engine does:

```go
type EventVerdict struct {
    Alert  bool        // Emit to event log
    Kill   bool        // Send kill -9 to the process
    Action string      // Machine-readable: "alert", "killed", "allow"
    Reason string      // Human-readable explanation
    Data   interface{} // Structured data for event log payload
}
```

Return `nil` for events your plugin doesn't care about.

### 2. Create the plugin file

Create `pkg/ebpf/your_plugin.go`. You need:

- A config struct with JSON tags
- A private struct implementing `EventPlugin` (including a `logger *slog.Logger` field)
- Two constructors:
  - `NewYourPlugin(config YourPluginConfig, logger *slog.Logger)` -- typed constructor
  - `NewYourPluginFromConfig(raw json.RawMessage, logger *slog.Logger) (Plugin, error)` -- factory for the registry

Example skeleton:

```go
package ebpf

import (
    "encoding/json"
    "fmt"
    "log/slog"
)

type ExecAuditConfig struct {
    FilterComm []string `json:"filter_comm,omitempty"` // only alert on these commands
}

type execAuditPlugin struct {
    config ExecAuditConfig
    logger *slog.Logger
}

func NewExecAudit(config ExecAuditConfig, logger *slog.Logger) *execAuditPlugin {
    if logger == nil {
        logger = slog.Default()
    }
    return &execAuditPlugin{config: config, logger: logger}
}

func NewExecAuditFromConfig(raw json.RawMessage, logger *slog.Logger) (Plugin, error) {
    var cfg ExecAuditConfig
    if len(raw) > 0 {
        if err := json.Unmarshal(raw, &cfg); err != nil {
            return nil, fmt.Errorf("exec_audit: invalid config: %w", err)
        }
    }
    return NewExecAudit(cfg, logger), nil
}

func (p *execAuditPlugin) Name() string { return "exec_audit" }

func (p *execAuditPlugin) ProcessEvent(event *EBPFEvent) *EventVerdict {
    if event.Event != "EXEC" {
        return nil // only care about process execution
    }

    // Your logic here
    p.logger.Debug("exec detected", "comm", event.Comm, "pid", event.PID)

    return &EventVerdict{
        Alert:  true,
        Action: "alert",
        Reason: fmt.Sprintf("exec: %s (pid %d)", event.Comm, event.PID),
        Data:   map[string]interface{}{"comm": event.Comm, "pid": event.PID},
    }
}
```

### 3. Register the factory

In `pkg/ebpf/registry.go`, add your plugin to the `init()` function:

```go
func init() {
    Register("sensitive_file_monitor", NewSensitiveFileMonitorFromConfig)
    Register("exec_audit", NewExecAuditFromConfig)  // add this
}
```

The engine looks up factories from this registry when compiling plugins from config. Registration panics on duplicate type names.

### 4. (Optional) Third-party plugins

External plugins follow the same pattern but live in their own Go package. The host binary must blank-import the plugin package to trigger `init()` registration:

```go
// In the plugin package
package myebpfplugin

import "github.com/jingkaihe/matchlock/pkg/ebpf"

func init() {
    ebpf.Register("my_plugin", NewMyPluginFromConfig)
}
```

```go
// In the host binary
import _ "github.com/user/myebpfplugin"
```

### 5. Write tests

Create `pkg/ebpf/your_plugin_test.go`. Test both constructors and the `ProcessEvent` behavior directly. See `pkg/ebpf/sensitive_file_monitor_test.go` for the pattern.

### Logging

Every plugin receives a pre-scoped `*slog.Logger` from the engine, tagged with `plugin=<name>`. Plugins should log at `Debug` level only. The engine handles `Info` and `Warn` logging for alerts and kills.

```go
// Good: Debug level, structured fields
p.logger.Debug("pattern matched", "filepath", fp, "pattern", pattern)

// Bad: Info level (engine already logs alerts at Info)
p.logger.Info("alert triggered", "filepath", fp)
```

### Fail-fast semantics

Unlike the network plugin engine (which warns and skips bad plugins), the eBPF engine fails fast. If a plugin type is unknown or a factory returns an error, sandbox creation fails. This is deliberate -- eBPF plugins are security enforcement tools, and silently skipping a misconfigured plugin could leave the sandbox unprotected.

## Plugin Semantics

| Property | Behavior |
|----------|----------|
| Event visibility | All plugins see every event. |
| Multiple alerts | All alerts are logged; all kill requests are executed. |
| Evaluation order | Plugins run in registration order. Order does not affect outcomes since there is no short-circuit. |
| Nil verdict | Event is benign for that plugin. No logging, no action. |
| Non-alert verdict | Same as nil -- no logging, no action. |
| Kill with `killFunc == nil` | Kill is silently skipped. Alert is still logged. |

## Debug Log

When `--ebpf-debug-log` is enabled (or `debug_log: true` in config), the collector writes every raw JSONL event to `ebpf-events.jsonl` in the VM state directory. This captures all events regardless of plugin configuration, useful for post-hoc analysis.

```bash
# Watch raw events live
tail -f /path/to/vm-state/ebpf-events.jsonl | jq '.'

# Count events by type
jq -r '.event' ebpf-events.jsonl | sort | uniq -c

# Show all file opens
jq 'select(.event == "FILE_OPEN")' ebpf-events.jsonl

# Show process tree (execs with parent info)
jq 'select(.event == "EXEC") | {comm, pid, ppid, filename}' ebpf-events.jsonl

# Find long-running processes
jq 'select(.event == "EXIT" and .duration_ms > 1000)' ebpf-events.jsonl
```

## File Map

```
pkg/ebpf/
  plugin.go                     # Interfaces (Plugin, EventPlugin, EventVerdict, EBPFEvent)
  registry.go                   # Factory registry (Register, LookupFactory, RegisteredTypes)
  engine.go                     # Orchestrator (NewEngineFromConfig, ProcessEvent, AddPlugin)
  collector.go                  # Vsock listener (accepts guest connection, parses JSONL)
  sensitive_file_monitor.go     # EventPlugin: sensitive file access detection

pkg/api/
  config.go                     # EBPFConfig, PluginConfig, ValidatePluginTypes
  ebpf.go                       # ParseEBPFPlugin (CLI flag parser)
  errors.go                     # ErrUnknownEBPFPlugin, ErrEBPFPluginFormat

pkg/sandbox/
  sandbox_linux.go              # Wires engine + collector into sandbox lifecycle
  rootfs.go                     # Injects ebpf-tracer binary into guest rootfs
  paths.go                      # DefaultEBPFTracerPath resolution

pkg/sdk/
  builder.go                    # WithEBPFPlugin, WithEBPFDebugLog
  client.go                     # EBPFPlugins, EBPFDebugLog in CreateOptions

cmd/guest-init/
  main.go                       # Starts ebpf-tracer in guest (before seccomp)
```

## Log Output

The engine produces structured logs via `log/slog`. Plugin alerts are logged at Info level. Kill actions are logged at Warn level.

### Example: sensitive file alert (alert only)

```
INFO ebpf plugin alert  plugin=sensitive_file_monitor  action=alert  pid=42  comm=cat  reason="sensitive file access: cat opened /etc/shadow (matched /etc/shadow)"
```

### Example: sensitive file alert (kill mode)

```
INFO ebpf plugin alert  plugin=sensitive_file_monitor  action=killed  pid=42  comm=cat  reason="sensitive file access: cat opened /etc/shadow (matched /etc/shadow)"
WARN ebpf engine: killing process  plugin=sensitive_file_monitor  pid=42  comm=cat
```

### Example: engine startup

```
INFO ebpf engine: registered plugin  name=sensitive_file_monitor
INFO ebpf engine ready  plugins=1
INFO ebpf collector: listening  socket=/tmp/vm-abc/vsock.sock_5003  plugins=1  debug_log=false
INFO ebpf collector: guest tracer connected
```

### Log levels

| Level | Who logs | What |
|-------|----------|------|
| Debug | Plugins | Internal reasoning (pattern matches, event filtering) |
| Info | Engine | Plugin alerts, plugin registration, engine ready, tracer connected |
| Warn | Engine | Kill actions, kill failures, read errors |
