package ebpf

// EBPFEvent is a parsed event from the guest eBPF tracer.
// Fields map to the JSONL output from the process.c userspace binary.
type EBPFEvent struct {
	Timestamp   uint64 `json:"timestamp"`
	Event       string `json:"event"`    // "EXEC", "EXIT", "FILE_OPEN"
	Comm        string `json:"comm"`     // process command name
	PID         int    `json:"pid"`      // process ID
	PPID        int    `json:"ppid,omitempty"`
	ExitCode    uint   `json:"exit_code,omitempty"`
	DurationMS  uint64 `json:"duration_ms,omitempty"`
	Filename    string `json:"filename,omitempty"`      // exec filename
	FullCommand string `json:"full_command,omitempty"`  // full command line
	Filepath    string `json:"filepath,omitempty"`      // file operation path
	Flags       int    `json:"flags,omitempty"`         // open flags
	Count       uint32 `json:"count,omitempty"`         // dedup count
}

// Plugin is the base interface for all eBPF event plugins.
type Plugin interface {
	// Name returns the plugin's unique identifier (e.g., "sensitive_file_monitor").
	Name() string
}

// EventPlugin processes eBPF events from the guest kernel and returns
// a verdict describing any policy action to take.
//
// Semantics: All registered plugins see every event. If multiple plugins
// alert on the same event, all alerts are logged and all kill requests
// are executed.
type EventPlugin interface {
	Plugin
	// ProcessEvent evaluates a single eBPF event.
	// Return nil for no action (event is benign).
	// Return a non-nil EventVerdict to trigger alerting and/or enforcement.
	ProcessEvent(event *EBPFEvent) *EventVerdict
}

// EventVerdict carries the result of a plugin's evaluation of an eBPF event.
type EventVerdict struct {
	// Alert indicates the plugin detected something noteworthy.
	// When true, the engine emits a policy event to the shared event log.
	Alert bool

	// Kill indicates the offending process should be terminated.
	// When true, the engine sends kill -9 to the process via the guest exec relay.
	Kill bool

	// Action is a machine-readable action string for the event log.
	// Conventions: "alert", "killed", "allow".
	Action string

	// Reason is a human-readable explanation for logging.
	Reason string

	// Data is optional structured data for the event log payload.
	// Will be JSON-marshaled into the event's data field.
	Data interface{}
}
