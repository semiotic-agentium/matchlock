package monitor

import (
	"fmt"
	"strings"
	"time"

	"github.com/jingkaihe/matchlock/pkg/state"
)

// feedEntry is a display-ready event row, possibly collapsed with duplicates.
type feedEntry struct {
	record    state.EventRecord
	dupCount  int
	dupWindow time.Duration
	expanded  bool
}

// collapseEvents merges consecutive duplicate events (same host+action within 30s).
func collapseEvents(existing []feedEntry, newEvents []state.EventRecord) []feedEntry {
	const collapseWindow = 30 * time.Second

	for _, ev := range newEvents {
		action := ev.PolicyAction
		if action == "" {
			if ev.NetBlocked {
				action = "block"
			} else {
				action = "allow"
			}
		}

		// Check if the last entry is a duplicate within the collapse window.
		if len(existing) > 0 {
			last := &existing[len(existing)-1]
			lastAction := last.record.PolicyAction
			if lastAction == "" {
				if last.record.NetBlocked {
					lastAction = "block"
				} else {
					lastAction = "allow"
				}
			}

			timeDiff := time.Duration(ev.Timestamp-last.record.Timestamp) * time.Second
			if last.record.NetHost == ev.NetHost && lastAction == action && timeDiff <= collapseWindow {
				last.dupCount++
				last.dupWindow = timeDiff
				last.record = ev // update to latest
				continue
			}
		}

		existing = append(existing, feedEntry{record: ev})
	}

	return existing
}

// renderFeedRow renders a single event row.
func renderFeedRow(entry feedEntry, width int, selected bool) string {
	ev := entry.record

	ts := time.Unix(ev.Timestamp, 0).Format("15:04:05")

	action := ev.PolicyAction
	if action == "" {
		if ev.NetBlocked {
			action = "block"
		} else {
			action = "allow"
		}
	}
	actionStr := actionStyle(action).Render(fmt.Sprintf("%-8s", strings.ToUpper(action)))

	host := ev.NetHost
	if len(host) > 24 {
		host = host[:21] + "..."
	}
	hostStr := styleHost.Render(fmt.Sprintf("%-24s", host))

	method := ev.NetMethod
	if method == "" {
		method = "-"
	}
	methodStr := styleMethod.Render(fmt.Sprintf("%-6s", method))

	path := ev.NetPath
	if path == "" {
		path = "-"
	}
	if len(path) > 16 {
		path = path[:13] + "..."
	}
	pathStr := stylePath.Render(fmt.Sprintf("%-16s", path))

	dur := "-"
	if ev.NetDurationMS > 0 {
		if ev.NetDurationMS >= 1000 {
			dur = fmt.Sprintf("%.1fs", float64(ev.NetDurationMS)/1000)
		} else {
			dur = fmt.Sprintf("%dms", ev.NetDurationMS)
		}
	}
	durStr := styleDuration.Render(fmt.Sprintf("%7s", dur))

	row := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
		styleTime.Render(ts), actionStr, hostStr, methodStr, pathStr, durStr)

	if entry.dupCount > 0 {
		row += styleDuplicate.Render(fmt.Sprintf("  x%d", entry.dupCount+1))
	}

	if selected {
		row = styleSelected.Render(row)
	}

	return row
}

// renderFeedDetail renders the expanded detail for an event.
func renderFeedDetail(ev state.EventRecord) string {
	var lines []string
	lines = append(lines, "")

	if ev.NetMethod != "" {
		lines = append(lines, fmt.Sprintf("    Method:   %s", ev.NetMethod))
	}
	lines = append(lines, fmt.Sprintf("    Host:     %s", ev.NetHost))
	if ev.NetPath != "" {
		lines = append(lines, fmt.Sprintf("    Path:     %s", ev.NetPath))
	}
	if ev.NetStatusCode > 0 {
		lines = append(lines, fmt.Sprintf("    Status:   %d", ev.NetStatusCode))
	}
	if ev.NetRequestBytes > 0 {
		lines = append(lines, fmt.Sprintf("    Req:      %d bytes", ev.NetRequestBytes))
	}
	if ev.NetResponseBytes > 0 {
		lines = append(lines, fmt.Sprintf("    Resp:     %d bytes", ev.NetResponseBytes))
	}
	if ev.NetDurationMS > 0 {
		lines = append(lines, fmt.Sprintf("    Duration: %dms", ev.NetDurationMS))
	}
	if ev.NetBlocked {
		lines = append(lines, fmt.Sprintf("    Reason:   %s", ev.NetBlockReason))
	}
	if ev.PolicyPlugin != "" {
		lines = append(lines, fmt.Sprintf("    Plugin:   %s", ev.PolicyPlugin))
	}
	lines = append(lines, fmt.Sprintf("    VM:       %s", ev.VMID))
	lines = append(lines, "")

	return styleDetail.Render(strings.Join(lines, "\n"))
}

// renderFeedHeader renders the column header row.
func renderFeedHeader(width int) string {
	return stylePath.Render(fmt.Sprintf("  %-8s  %-8s  %-24s  %-6s  %-16s  %7s",
		"TIME", "ACTION", "HOST", "METHOD", "PATH", "DUR"))
}
