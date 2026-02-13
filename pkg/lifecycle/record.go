package lifecycle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jingkaihe/matchlock/internal/errx"
)

const (
	RecordFile = "lifecycle.json"
)

type Phase string

const (
	PhaseCreating      Phase = "creating"
	PhaseCreated       Phase = "created"
	PhaseStarting      Phase = "starting"
	PhaseRunning       Phase = "running"
	PhaseStopping      Phase = "stopping"
	PhaseStopped       Phase = "stopped"
	PhaseCleaning      Phase = "cleaning"
	PhaseCleaned       Phase = "cleaned"
	PhaseCreateFailed  Phase = "create_failed"
	PhaseStartFailed   Phase = "start_failed"
	PhaseStopFailed    Phase = "stop_failed"
	PhaseCleanupFailed Phase = "cleanup_failed"
)

type CleanupResult struct {
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Resources struct {
	StateDir      string `json:"state_dir,omitempty"`
	Workspace     string `json:"workspace,omitempty"`
	RootfsPath    string `json:"rootfs_path,omitempty"`
	SubnetFile    string `json:"subnet_file,omitempty"`
	GatewayIP     string `json:"gateway_ip,omitempty"`
	GuestIP       string `json:"guest_ip,omitempty"`
	SubnetCIDR    string `json:"subnet_cidr,omitempty"`
	VsockPath     string `json:"vsock_path,omitempty"`
	TAPName       string `json:"tap_name,omitempty"`
	FirewallTable string `json:"firewall_table,omitempty"`
	NATTable      string `json:"nat_table,omitempty"`
}

type Record struct {
	Version   int                      `json:"version"`
	VMID      string                   `json:"vm_id"`
	Backend   string                   `json:"backend,omitempty"`
	Phase     Phase                    `json:"phase"`
	UpdatedAt time.Time                `json:"updated_at"`
	LastError string                   `json:"last_error,omitempty"`
	Resources Resources                `json:"resources,omitempty"`
	Cleanup   map[string]CleanupResult `json:"cleanup,omitempty"`
}

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(vmDir string) *Store {
	return &Store{
		path: filepath.Join(vmDir, RecordFile),
	}
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

func (s *Store) Init(vmID, backend, stateDir string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec := &Record{
		Version:   1,
		VMID:      vmID,
		Backend:   backend,
		Phase:     PhaseCreating,
		UpdatedAt: time.Now().UTC(),
		Resources: Resources{
			StateDir: stateDir,
		},
		Cleanup: make(map[string]CleanupResult),
	}
	return s.saveNoLock(rec)
}

func (s *Store) Load() (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadNoLock()
}

func (s *Store) SetPhase(phase Phase) error {
	return s.Update(func(r *Record) error {
		if err := validateTransition(r.Phase, phase); err != nil {
			return err
		}
		r.Phase = phase
		return nil
	})
}

func (s *Store) SetLastError(err error) error {
	return s.Update(func(r *Record) error {
		if err == nil {
			r.LastError = ""
			return nil
		}
		r.LastError = err.Error()
		return nil
	})
}

func (s *Store) SetResource(updateFn func(*Resources)) error {
	return s.Update(func(r *Record) error {
		updateFn(&r.Resources)
		return nil
	})
}

func (s *Store) MarkCleanup(name string, opErr error) error {
	return s.Update(func(r *Record) error {
		if r.Cleanup == nil {
			r.Cleanup = make(map[string]CleanupResult)
		}
		result := CleanupResult{
			Status:    "ok",
			UpdatedAt: time.Now().UTC(),
		}
		if opErr != nil {
			result.Status = "error"
			result.Error = opErr.Error()
		}
		r.Cleanup[name] = result
		return nil
	})
}

func (s *Store) Update(updateFn func(*Record) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.loadNoLock()
	if err != nil {
		return err
	}
	if err := updateFn(rec); err != nil {
		return err
	}
	rec.UpdatedAt = time.Now().UTC()
	return s.saveNoLock(rec)
}

func (s *Store) loadNoLock() (*Record, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Record{
				Version: 1,
				Phase:   PhaseCreating,
				Cleanup: make(map[string]CleanupResult),
			}, nil
		}
		return nil, errx.Wrap(ErrReadRecord, err)
	}

	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, errx.Wrap(ErrDecodeRecord, err)
	}
	if rec.Version == 0 {
		rec.Version = 1
	}
	if rec.Cleanup == nil {
		rec.Cleanup = make(map[string]CleanupResult)
	}
	return &rec, nil
}

func (s *Store) saveNoLock(rec *Record) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return errx.Wrap(ErrCreateRecordDir, err)
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return errx.Wrap(ErrEncodeRecord, err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return errx.Wrap(ErrWriteRecord, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return errx.Wrap(ErrRenameRecord, err)
	}
	return nil
}
