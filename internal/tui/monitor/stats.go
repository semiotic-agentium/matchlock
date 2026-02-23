package monitor

import (
	"fmt"

	"github.com/jingkaihe/matchlock/pkg/state"
)

// renderStatsHeader renders the stats summary bar.
func renderStatsHeader(vmID string, stats *state.EventStats, width int) string {
	if stats == nil {
		stats = &state.EventStats{}
	}

	vm := "all VMs"
	if vmID != "" {
		vm = vmID
	}

	left := styleHeader.Render(fmt.Sprintf(" matchlock monitor  %s", vm))

	counts := fmt.Sprintf("  %s %s  %s %s  %s %s  %s %s",
		styleStatTotal.Render(fmt.Sprintf("%d", stats.Total)),
		styleStatLabel.Render("total"),
		styleStatBlocked.Render(fmt.Sprintf("%d", stats.Blocked)),
		styleStatLabel.Render("blocked"),
		styleStatRedirected.Render(fmt.Sprintf("%d", stats.Redirected)),
		styleStatLabel.Render("redirected"),
		styleStatAllowed.Render(fmt.Sprintf("%d", stats.Allowed)),
		styleStatLabel.Render("ok"),
	)

	right := styleHeader.Render(counts)

	// Pad to fill width
	gap := width - lipglossWidth(left) - lipglossWidth(right)
	if gap < 0 {
		gap = 0
	}
	pad := styleHeader.Render(spaces(gap))

	return left + pad + right
}

// renderStatsView renders the detailed stats view (toggled with 's').
func renderStatsView(stats *state.EventStats, width int) string {
	if stats == nil {
		return "  No events yet."
	}

	var s string
	s += "\n"
	s += fmt.Sprintf("  Total: %d  |  Blocked: %d  |  Redirected: %d  |  Allowed: %d\n\n",
		stats.Total, stats.Blocked, stats.Redirected, stats.Allowed)

	if len(stats.ByHost) > 0 {
		s += "  Top Hosts:\n"
		for _, h := range stats.ByHost {
			action := actionStyle(h.Action).Render(fmt.Sprintf("%-8s", h.Action))
			s += fmt.Sprintf("    %s  %4d  %s\n", action, h.Count, h.Host)
		}
	}

	return s
}

func spaces(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}

func lipglossWidth(s string) int {
	// Simple visible-character width calculation.
	// lipgloss.Width handles ANSI sequences.
	return len([]rune(stripAnsi(s)))
}

func stripAnsi(s string) string {
	var result []rune
	inEsc := false
	for _, r := range s {
		if r == '\x1b' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		result = append(result, r)
	}
	return string(result)
}
