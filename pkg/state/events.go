package state

import (
	"net/url"
	"time"

	"github.com/jingkaihe/matchlock/internal/errx"
	"github.com/jingkaihe/matchlock/pkg/api"
)

// EventStore is the interface for persisting intercepted network events.
type EventStore interface {
	InsertEvent(vmID string, e api.Event, action, plugin string) error
}

// EventQuery specifies filters for querying events.
type EventQuery struct {
	VMID    string
	SinceID int64
	Limit   int
	Blocked *bool
	Host    string
}

// EventRecord is a flat row from the events table.
type EventRecord struct {
	ID             int64  `json:"id"`
	VMID           string `json:"vm_id"`
	Type           string `json:"type"`
	Timestamp      int64  `json:"timestamp"`
	NetMethod      string `json:"net_method,omitempty"`
	NetHost        string `json:"net_host,omitempty"`
	NetPath        string `json:"net_path,omitempty"`
	NetStatusCode  int    `json:"net_status_code,omitempty"`
	NetRequestBytes  int64 `json:"net_request_bytes,omitempty"`
	NetResponseBytes int64 `json:"net_response_bytes,omitempty"`
	NetDurationMS  int64  `json:"net_duration_ms,omitempty"`
	NetBlocked     bool   `json:"net_blocked"`
	NetBlockReason string `json:"net_block_reason,omitempty"`
	PolicyAction   string `json:"policy_action,omitempty"`
	PolicyPlugin   string `json:"policy_plugin,omitempty"`
}

// EventStats holds aggregate counts for events.
type EventStats struct {
	Total      int          `json:"total"`
	Blocked    int          `json:"blocked"`
	Redirected int          `json:"redirected"`
	Allowed    int          `json:"allowed"`
	ByHost     []HostStats  `json:"by_host,omitempty"`
}

// HostStats is per-host event counts.
type HostStats struct {
	Host   string `json:"host"`
	Count  int    `json:"count"`
	Action string `json:"action"`
}

// InsertEvent persists a single event to the events table.
func (m *Manager) InsertEvent(vmID string, e api.Event, action, plugin string) error {
	if err := m.ready(); err != nil {
		return err
	}

	var (
		method       string
		host         string
		path         string
		statusCode   int
		reqBytes     int64
		respBytes    int64
		durationMS   int64
		blocked      int
		blockReason  string
	)

	if e.Network != nil {
		method = e.Network.Method
		host = e.Network.Host
		statusCode = e.Network.StatusCode
		reqBytes = e.Network.RequestBytes
		respBytes = e.Network.ResponseBytes
		durationMS = e.Network.DurationMS
		if e.Network.Blocked {
			blocked = 1
		}
		blockReason = e.Network.BlockReason

		if e.Network.URL != "" {
			if u, err := url.Parse(e.Network.URL); err == nil {
				path = u.Path
			}
		}
	}

	ts := e.Timestamp
	if ts == 0 {
		ts = time.Now().Unix()
	}

	_, err := m.db.Exec(
		`INSERT INTO events (vm_id, type, timestamp, net_method, net_host, net_path,
		 net_status_code, net_request_bytes, net_response_bytes, net_duration_ms,
		 net_blocked, net_block_reason, policy_action, policy_plugin)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		vmID, e.Type, ts, method, host, path,
		statusCode, reqBytes, respBytes, durationMS,
		blocked, blockReason, action, plugin,
	)
	if err != nil {
		return errx.Wrap(ErrInsertEvent, err)
	}
	return nil
}

// QueryEvents retrieves events matching the given query.
func (m *Manager) QueryEvents(q EventQuery) ([]EventRecord, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}

	query := `SELECT id, vm_id, type, timestamp, net_method, net_host, net_path,
		net_status_code, net_request_bytes, net_response_bytes, net_duration_ms,
		net_blocked, net_block_reason, policy_action, policy_plugin
		FROM events WHERE 1=1`
	var args []interface{}

	if q.VMID != "" {
		query += " AND vm_id = ?"
		args = append(args, q.VMID)
	}
	if q.SinceID > 0 {
		query += " AND id > ?"
		args = append(args, q.SinceID)
	}
	if q.Blocked != nil {
		if *q.Blocked {
			query += " AND net_blocked = 1"
		} else {
			query += " AND net_blocked = 0"
		}
	}
	if q.Host != "" {
		query += " AND net_host = ?"
		args = append(args, q.Host)
	}

	query += " ORDER BY id ASC"
	if q.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, q.Limit)
	}

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, errx.Wrap(ErrQueryEvents, err)
	}
	defer rows.Close()

	var records []EventRecord
	for rows.Next() {
		var r EventRecord
		var blocked int
		var method, host, path, blockReason, action, plugin *string
		var statusCode *int
		var reqBytes, respBytes, durationMS *int64

		if err := rows.Scan(
			&r.ID, &r.VMID, &r.Type, &r.Timestamp,
			&method, &host, &path,
			&statusCode, &reqBytes, &respBytes, &durationMS,
			&blocked, &blockReason, &action, &plugin,
		); err != nil {
			return nil, errx.Wrap(ErrQueryEvents, err)
		}

		r.NetBlocked = blocked != 0
		if method != nil { r.NetMethod = *method }
		if host != nil { r.NetHost = *host }
		if path != nil { r.NetPath = *path }
		if statusCode != nil { r.NetStatusCode = *statusCode }
		if reqBytes != nil { r.NetRequestBytes = *reqBytes }
		if respBytes != nil { r.NetResponseBytes = *respBytes }
		if durationMS != nil { r.NetDurationMS = *durationMS }
		if blockReason != nil { r.NetBlockReason = *blockReason }
		if action != nil { r.PolicyAction = *action }
		if plugin != nil { r.PolicyPlugin = *plugin }

		records = append(records, r)
	}

	return records, rows.Err()
}

// GetEventStats returns aggregate event statistics.
func (m *Manager) GetEventStats(vmID string) (*EventStats, error) {
	if err := m.ready(); err != nil {
		return nil, err
	}

	stats := &EventStats{}
	query := `SELECT
		COUNT(*) as total,
		SUM(CASE WHEN policy_action = 'block' OR net_blocked = 1 THEN 1 ELSE 0 END) as blocked,
		SUM(CASE WHEN policy_action = 'redirect' THEN 1 ELSE 0 END) as redirected,
		SUM(CASE WHEN policy_action = 'allow' OR (policy_action != 'block' AND policy_action != 'redirect' AND net_blocked = 0) THEN 1 ELSE 0 END) as allowed
		FROM events`
	var args []interface{}
	if vmID != "" {
		query += " WHERE vm_id = ?"
		args = append(args, vmID)
	}

	if err := m.db.QueryRow(query, args...).Scan(
		&stats.Total, &stats.Blocked, &stats.Redirected, &stats.Allowed,
	); err != nil {
		return nil, errx.Wrap(ErrQueryEvents, err)
	}

	hostQuery := `SELECT net_host, COUNT(*) as cnt,
		CASE
			WHEN SUM(CASE WHEN policy_action = 'block' OR net_blocked = 1 THEN 1 ELSE 0 END) > COUNT(*)/2 THEN 'block'
			WHEN SUM(CASE WHEN policy_action = 'redirect' THEN 1 ELSE 0 END) > COUNT(*)/2 THEN 'redirect'
			ELSE 'allow'
		END as dominant_action
		FROM events`
	if vmID != "" {
		hostQuery += " WHERE vm_id = ?"
	}
	hostQuery += " GROUP BY net_host ORDER BY cnt DESC LIMIT 20"

	rows, err := m.db.Query(hostQuery, args...)
	if err != nil {
		return nil, errx.Wrap(ErrQueryEvents, err)
	}
	defer rows.Close()

	for rows.Next() {
		var h HostStats
		if err := rows.Scan(&h.Host, &h.Count, &h.Action); err != nil {
			return nil, errx.Wrap(ErrQueryEvents, err)
		}
		stats.ByHost = append(stats.ByHost, h)
	}

	return stats, rows.Err()
}

// PruneEvents deletes events older than the given number of days.
// Returns the number of deleted rows.
func (m *Manager) PruneEvents(olderThanDays int) (int64, error) {
	if err := m.ready(); err != nil {
		return 0, err
	}

	cutoff := time.Now().AddDate(0, 0, -olderThanDays).Unix()
	result, err := m.db.Exec(`DELETE FROM events WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, errx.Wrap(ErrPruneEvents, err)
	}
	return result.RowsAffected()
}
