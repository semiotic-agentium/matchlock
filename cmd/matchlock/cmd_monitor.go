package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/jingkaihe/matchlock/internal/tui/monitor"
	"github.com/jingkaihe/matchlock/pkg/state"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor [flags]",
	Short: "Monitor policy engine events in real-time",
	Long: `Monitor policy engine decisions (allow/block/redirect) in a live TUI.

Events are persisted to the state database by the sandbox process and
polled by the monitor every 500ms. The TUI shows a live feed with a
stats summary header.

Use --json to bypass the TUI and stream events as JSON lines to stdout
for piping to jq or other tools.`,
	Example: `  matchlock monitor
  matchlock monitor --vm vm-f16c4b42
  matchlock monitor --json | jq '.net_host'
  matchlock monitor --json --vm vm-f16c4b42 > events.jsonl`,
	Args: cobra.NoArgs,
	RunE: runMonitor,
}

func init() {
	monitorCmd.Flags().String("vm", "", "Filter by VM ID (default: all running)")
	monitorCmd.Flags().Bool("json", false, "Stream JSON lines instead of TUI")
	rootCmd.AddCommand(monitorCmd)
}

func runMonitor(cmd *cobra.Command, args []string) error {
	vmID, _ := cmd.Flags().GetString("vm")
	jsonMode, _ := cmd.Flags().GetBool("json")

	mgr := state.NewManager()

	if jsonMode {
		return runMonitorJSON(mgr, vmID)
	}

	return runMonitorTUI(mgr, vmID)
}

func runMonitorTUI(mgr *state.Manager, vmID string) error {
	model := monitor.New(mgr, vmID)
	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func runMonitorJSON(mgr *state.Manager, vmID string) error {
	enc := json.NewEncoder(os.Stdout)
	var lastID int64

	for {
		q := state.EventQuery{
			VMID:    vmID,
			SinceID: lastID,
		}

		events, err := mgr.QueryEvents(q)
		if err != nil {
			return fmt.Errorf("query events: %w", err)
		}

		for _, ev := range events {
			if err := enc.Encode(ev); err != nil {
				return fmt.Errorf("encode event: %w", err)
			}
			lastID = ev.ID
		}

		time.Sleep(500 * time.Millisecond)
	}
}
