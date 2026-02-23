package monitor

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/jingkaihe/matchlock/pkg/state"
)

// Model is the top-level bubbletea model for the monitor TUI.
type Model struct {
	store     *Store
	entries   []feedEntry
	stats     *state.EventStats
	cursor    int
	width     int
	height    int
	offset    int // scroll offset for the feed
	showStats bool
	err       error

	// Filters
	blockedFilter    *bool
	hostFilter       string
	hostInput        string
	hostInputActive  bool
	searchInput      string
	searchActive     bool
}

// New creates a new monitor Model.
func New(mgr *state.Manager, vmID string) Model {
	store := NewStore(mgr, vmID)
	return Model{
		store: store,
	}
}

// Init initializes the model by loading existing events and starting the ticker.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.store.initialFetch,
		tickCmd(),
	)
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKey(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		return m, tea.Batch(m.store.fetchCmd(), tickCmd())

	case eventsMsg:
		if len(msg.events) > 0 {
			m.entries = collapseEvents(m.entries, msg.events)
			// Auto-scroll to bottom if we were already there
			maxOffset := m.maxOffset()
			if m.offset >= maxOffset-1 || maxOffset <= m.feedHeight() {
				m.offset = m.maxOffset()
				m.cursor = len(m.entries) - 1
			}
		}
		if msg.stats != nil {
			m.stats = msg.stats
		}
		return m, nil

	case errMsg:
		m.err = msg.err
		return m, nil
	}

	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle text input modes first
	if m.hostInputActive {
		switch msg.String() {
		case "enter":
			m.hostFilter = m.hostInput
			m.hostInputActive = false
			m.store.SetHostFilter(m.hostFilter)
			m.resetFeed()
			return m, m.store.initialFetch
		case "esc":
			m.hostInputActive = false
			m.hostInput = ""
			return m, nil
		case "backspace":
			if len(m.hostInput) > 0 {
				m.hostInput = m.hostInput[:len(m.hostInput)-1]
			}
			return m, nil
		default:
			if len(msg.String()) == 1 {
				m.hostInput += msg.String()
			}
			return m, nil
		}
	}

	if m.searchActive {
		switch msg.String() {
		case "enter", "esc":
			m.searchActive = false
			return m, nil
		case "backspace":
			if len(m.searchInput) > 0 {
				m.searchInput = m.searchInput[:len(m.searchInput)-1]
			}
			return m, nil
		default:
			if len(msg.String()) == 1 {
				m.searchInput += msg.String()
			}
			return m, nil
		}
	}

	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "b":
		// Toggle blocked-only filter
		if m.blockedFilter != nil && *m.blockedFilter {
			m.blockedFilter = nil
		} else {
			blocked := true
			m.blockedFilter = &blocked
		}
		m.store.SetBlockedFilter(m.blockedFilter)
		m.resetFeed()
		return m, m.store.initialFetch

	case "r":
		// Toggle redirected-only (we approximate by clearing blocked filter and searching)
		if m.blockedFilter != nil && !*m.blockedFilter {
			m.blockedFilter = nil
		} else {
			blocked := false
			m.blockedFilter = &blocked
		}
		m.store.SetBlockedFilter(m.blockedFilter)
		m.resetFeed()
		return m, m.store.initialFetch

	case "h":
		m.hostInputActive = true
		m.hostInput = m.hostFilter
		return m, nil

	case "/":
		m.searchActive = true
		m.searchInput = ""
		return m, nil

	case "s":
		m.showStats = !m.showStats
		return m, nil

	case "enter":
		if m.cursor >= 0 && m.cursor < len(m.entries) {
			m.entries[m.cursor].expanded = !m.entries[m.cursor].expanded
		}
		return m, nil

	case "esc":
		if m.hostFilter != "" {
			m.hostFilter = ""
			m.store.SetHostFilter("")
			m.resetFeed()
			return m, m.store.initialFetch
		}
		if m.blockedFilter != nil {
			m.blockedFilter = nil
			m.store.SetBlockedFilter(nil)
			m.resetFeed()
			return m, m.store.initialFetch
		}
		// Collapse any expanded detail
		if m.cursor >= 0 && m.cursor < len(m.entries) {
			m.entries[m.cursor].expanded = false
		}
		return m, nil

	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
			if m.cursor < m.offset {
				m.offset = m.cursor
			}
		}
		return m, nil

	case "down", "j":
		if m.cursor < len(m.entries)-1 {
			m.cursor++
			if m.cursor >= m.offset+m.feedHeight() {
				m.offset = m.cursor - m.feedHeight() + 1
			}
		}
		return m, nil

	case "pgup":
		m.cursor -= m.feedHeight()
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.offset = m.cursor
		return m, nil

	case "pgdown":
		m.cursor += m.feedHeight()
		if m.cursor >= len(m.entries) {
			m.cursor = len(m.entries) - 1
		}
		m.offset = m.cursor - m.feedHeight() + 1
		if m.offset < 0 {
			m.offset = 0
		}
		return m, nil

	case "G":
		m.cursor = len(m.entries) - 1
		m.offset = m.maxOffset()
		return m, nil

	case "g":
		m.cursor = 0
		m.offset = 0
		return m, nil
	}

	return m, nil
}

// View renders the full TUI.
func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	var b strings.Builder

	// Stats header
	b.WriteString(renderStatsHeader(m.store.vmID, m.stats, m.width))
	b.WriteString("\n")

	// Active filters indicator
	filters := m.activeFilters()
	if filters != "" {
		b.WriteString(styleFilter.Render(fmt.Sprintf("  Filter: %s", filters)))
		b.WriteString("\n")
	}

	if m.showStats {
		b.WriteString(renderStatsView(m.stats, m.width))
	} else {
		// Column header
		b.WriteString(renderFeedHeader(m.width))
		b.WriteString("\n")

		// Feed rows
		feedH := m.feedHeight()
		end := m.offset + feedH
		if end > len(m.entries) {
			end = len(m.entries)
		}

		linesUsed := 0
		for i := m.offset; i < end && linesUsed < feedH; i++ {
			entry := m.entries[i]
			selected := i == m.cursor

			// Apply search filter (client-side text match)
			if m.searchInput != "" {
				searchLower := strings.ToLower(m.searchInput)
				text := strings.ToLower(entry.record.NetHost + entry.record.NetPath + entry.record.NetMethod)
				if !strings.Contains(text, searchLower) {
					continue
				}
			}

			row := renderFeedRow(entry, m.width, selected)
			b.WriteString(row)
			b.WriteString("\n")
			linesUsed++

			if entry.expanded {
				detail := renderFeedDetail(entry.record)
				detailLines := strings.Count(detail, "\n") + 1
				b.WriteString(detail)
				b.WriteString("\n")
				linesUsed += detailLines
			}
		}

		// Fill remaining space
		for linesUsed < feedH {
			b.WriteString("\n")
			linesUsed++
		}
	}

	// Host input mode
	if m.hostInputActive {
		b.WriteString(styleFilter.Render(fmt.Sprintf("  Host filter: %s_", m.hostInput)))
		b.WriteString("\n")
	} else if m.searchActive {
		b.WriteString(styleFilter.Render(fmt.Sprintf("  Search: %s_", m.searchInput)))
		b.WriteString("\n")
	}

	// Help bar
	b.WriteString(m.helpBar())

	// Error display
	if m.err != nil {
		b.WriteString("\n")
		b.WriteString(styleActionBlock.Render(fmt.Sprintf("  Error: %v", m.err)))
	}

	return b.String()
}

func (m Model) feedHeight() int {
	// Total height minus header (1) + column header (1) + help bar (1) + filter line if active
	used := 3
	if m.activeFilters() != "" {
		used++
	}
	if m.hostInputActive || m.searchActive {
		used++
	}
	h := m.height - used
	if h < 1 {
		h = 1
	}
	return h
}

func (m Model) maxOffset() int {
	max := len(m.entries) - m.feedHeight()
	if max < 0 {
		return 0
	}
	return max
}

func (m Model) activeFilters() string {
	var parts []string
	if m.blockedFilter != nil {
		if *m.blockedFilter {
			parts = append(parts, "blocked only")
		} else {
			parts = append(parts, "non-blocked")
		}
	}
	if m.hostFilter != "" {
		parts = append(parts, fmt.Sprintf("host=%s", m.hostFilter))
	}
	if m.searchInput != "" && !m.searchActive {
		parts = append(parts, fmt.Sprintf("search=%s", m.searchInput))
	}
	return strings.Join(parts, "  ")
}

func (m Model) helpBar() string {
	return styleHelp.Render("  q quit  b blocked  r redirected  h host-filter  / search  enter detail  s stats  esc clear")
}

func (m *Model) resetFeed() {
	m.entries = nil
	m.cursor = 0
	m.offset = 0
	m.store.lastID = 0
}
