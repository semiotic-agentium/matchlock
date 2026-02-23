package monitor

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/jingkaihe/matchlock/pkg/state"
)

const pollInterval = 500 * time.Millisecond

// tickMsg is sent on each poll interval.
type tickMsg time.Time

// eventsMsg carries newly fetched events.
type eventsMsg struct {
	events []state.EventRecord
	stats  *state.EventStats
}

// errMsg carries errors from the store.
type errMsg struct{ err error }

// Store wraps state.Manager for the TUI, handling cursor-based polling.
type Store struct {
	mgr     *state.Manager
	vmID    string
	lastID  int64
	blocked *bool
	host    string
}

// NewStore creates a new Store for polling events.
func NewStore(mgr *state.Manager, vmID string) *Store {
	return &Store{
		mgr:  mgr,
		vmID: vmID,
	}
}

// SetBlockedFilter sets the blocked filter.
func (s *Store) SetBlockedFilter(blocked *bool) {
	s.blocked = blocked
}

// SetHostFilter sets the host filter.
func (s *Store) SetHostFilter(host string) {
	s.host = host
}

// tickCmd returns a command that sends a tick after the poll interval.
func tickCmd() tea.Cmd {
	return tea.Tick(pollInterval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// fetchEvents queries for new events since lastID and refreshes stats.
func (s *Store) fetchEvents() tea.Msg {
	q := state.EventQuery{
		VMID:    s.vmID,
		SinceID: s.lastID,
		Blocked: s.blocked,
		Host:    s.host,
	}

	events, err := s.mgr.QueryEvents(q)
	if err != nil {
		return errMsg{err}
	}

	if len(events) > 0 {
		s.lastID = events[len(events)-1].ID
	}

	stats, err := s.mgr.GetEventStats(s.vmID)
	if err != nil {
		return errMsg{err}
	}

	return eventsMsg{events: events, stats: stats}
}

// fetchCmd returns a tea.Cmd that fetches events.
func (s *Store) fetchCmd() tea.Cmd {
	return func() tea.Msg {
		return s.fetchEvents()
	}
}

// initialFetch loads existing events from the beginning.
func (s *Store) initialFetch() tea.Msg {
	q := state.EventQuery{
		VMID:    s.vmID,
		Blocked: s.blocked,
		Host:    s.host,
		Limit:   1000,
	}

	events, err := s.mgr.QueryEvents(q)
	if err != nil {
		return errMsg{err}
	}

	if len(events) > 0 {
		s.lastID = events[len(events)-1].ID
	}

	stats, err := s.mgr.GetEventStats(s.vmID)
	if err != nil {
		return errMsg{err}
	}

	return eventsMsg{events: events, stats: stats}
}
