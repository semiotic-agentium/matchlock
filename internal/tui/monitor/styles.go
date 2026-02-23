package monitor

import "github.com/charmbracelet/lipgloss"

var (
	colorGreen  = lipgloss.Color("#00FF00")
	colorRed    = lipgloss.Color("#FF0000")
	colorYellow = lipgloss.Color("#FFFF00")
	colorGray   = lipgloss.Color("#888888")
	colorWhite  = lipgloss.Color("#FFFFFF")
	colorCyan   = lipgloss.Color("#00FFFF")

	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(lipgloss.Color("#333333")).
			Padding(0, 1)

	styleStatLabel = lipgloss.NewStyle().
			Foreground(colorGray)

	styleStatTotal = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite)

	styleStatBlocked = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorRed)

	styleStatRedirected = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorYellow)

	styleStatAllowed = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorGreen)

	styleActionAllow = lipgloss.NewStyle().
				Foreground(colorGreen)

	styleActionBlock = lipgloss.NewStyle().
				Foreground(colorRed)

	styleActionRedirect = lipgloss.NewStyle().
				Foreground(colorYellow)

	styleTime = lipgloss.NewStyle().
			Foreground(colorGray)

	styleHost = lipgloss.NewStyle().
			Foreground(colorCyan)

	styleMethod = lipgloss.NewStyle().
			Foreground(colorWhite)

	stylePath = lipgloss.NewStyle().
			Foreground(colorGray)

	styleDuration = lipgloss.NewStyle().
			Foreground(colorGray)

	styleDetail = lipgloss.NewStyle().
			Foreground(colorGray).
			Padding(0, 2)

	styleHelp = lipgloss.NewStyle().
			Foreground(colorGray)

	styleFilter = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorYellow)

	styleSelected = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite)

	styleDuplicate = lipgloss.NewStyle().
			Foreground(colorGray).
			Italic(true)
)

func actionStyle(action string) lipgloss.Style {
	switch action {
	case "block":
		return styleActionBlock
	case "redirect":
		return styleActionRedirect
	default:
		return styleActionAllow
	}
}
