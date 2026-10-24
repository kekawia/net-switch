package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/sharedfile"
)

// Record is historical state, never a loaded policy. A point is meaningful only
// in a live table, so it is deliberately absent from the durable representation.
type Record struct {
	Schema   int    `json:"schema"`
	Instance string `json:"engineInstanceId"`
	Epoch    uint64 `json:"epoch"`
	N        uint64 `json:"n"`
	Hash     string `json:"hash"`
}

// Durable serializes epoch and revision commits into one record. Its caller
// owns directory validation, the lifetime lock, and atomic durable replacement.
type Durable struct {
	mu          sync.Mutex
	record      Record
	save        func(Record) error
	path        string
	failed      error
	issuedEpoch uint64
	// committed is set once this instance has saved a revision of its own.
	// Until then the record's N and hash are an earlier instance's history,
	// which spec §3.3 keeps as history only: a restarted engine has no loaded
	// revision, so it starts from whatever revision Control sends first, even
	// one numbered below that history (Control's journal may have been
	// recovered from defaults). The guard below protects only the history this
	// instance commits itself.
	committed bool
}

func Open(path, instance string, save func(Record) error) (*Durable, error) {
	if instance == "" || save == nil {
		return nil, errors.New("native state requires an instance and durable writer")
	}
	var old Record
	b, err := sharedfile.ReadFile(path, 16<<10)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		if len(b) > 16<<10 {
			return nil, errors.New("native service state exceeds its bound")
		}
		if err := json.Unmarshal(b, &old); err != nil {
			return nil, fmt.Errorf("invalid native service state: %w", err)
		}
		// Stand-in state is never read as a fresh native instance or silently
		// reset to epoch zero. The pre-release stand-in folder is retired by
		// hand; there is no migration because it never shipped.
		if old.Schema != 1 {
			return nil, errors.New("engine-state.json is not native service state: this data folder belonged to a pre-release stand-in build; run that build's uninstall or remove the folder")
		}
	}
	next := old
	next.Schema, next.Instance = 1, instance
	if err := save(next); err != nil {
		return nil, err
	}
	return &Durable{record: next, save: save, path: path, issuedEpoch: next.Epoch}, nil
}

func (d *Durable) InitialEpoch() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.record.Epoch
}

func (d *Durable) SaveEpoch(epoch uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed != nil {
		return d.failed
	}
	// Retrying an unacknowledged replacement may reuse its durable epoch.
	// An epoch already acknowledged to the server must always increase.
	if epoch <= d.issuedEpoch || epoch < d.record.Epoch {
		return errors.New("native epoch must increase")
	}
	next := d.record
	next.Epoch = epoch
	if err := d.save(next); err != nil {
		d.reloadCommitted()
		return err
	}
	d.record = next
	d.issuedEpoch = epoch
	return nil
}

func (d *Durable) SaveApplied(a policy.Applied) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed != nil {
		return d.failed
	}
	if d.committed && (a.N < d.record.N || a.N == d.record.N && a.Hash != d.record.Hash) {
		return errors.New("native revision history cannot go backwards or change its hash")
	}
	next := d.record
	next.N, next.Hash = a.N, a.Hash
	if err := d.save(next); err != nil {
		d.reloadCommitted()
		return err
	}
	d.record = next
	d.committed = true
	return nil
}

// A directory-sync failure can happen after replacement. Never rewrite a
// lower epoch/revision on the next operation just because its ACK was lost.
func (d *Durable) reloadCommitted() {
	r, err := ReadRecord(d.path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		d.failed = err
		return
	}
	if r.Instance != d.record.Instance {
		d.failed = errors.New("native state instance changed during commit")
		return
	}
	d.record.Epoch = max(d.record.Epoch, r.Epoch)
	if !d.committed {
		// This instance has no history of its own yet. If the interrupted
		// first commit reached the disk, that revision is the one to continue
		// from; if the file still holds the inherited history, nothing is
		// committed yet. That includes a first commit equal to the inherited
		// {N, hash} whose sync failed: it was never acknowledged, so per spec
		// §3.3 this instance still has no history to guard and its next
		// revision, lower or not, is its first (a design decision recorded in
		// the review of this change).
		if r.N != d.record.N || r.Hash != d.record.Hash {
			d.record.N, d.record.Hash = r.N, r.Hash
			d.committed = true
		}
		return
	}
	if r.N > d.record.N {
		d.record.N, d.record.Hash = r.N, r.Hash
	}
	if r.N == d.record.N && r.Hash != d.record.Hash {
		d.failed = errors.New("native revision history conflict after failed commit")
	}
}

func ReadRecord(path string) (Record, error) {
	var record Record
	b, err := sharedfile.ReadFile(path, 16<<10)
	if err != nil {
		return record, err
	}
	if len(b) > 16<<10 {
		return record, errors.New("native state exceeds its bound")
	}
	if err := json.Unmarshal(b, &record); err != nil {
		return record, err
	}
	if record.Schema != 1 || record.Instance == "" {
		return record, errors.New("invalid native state")
	}
	return record, nil
}
