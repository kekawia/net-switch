package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"path/filepath"
	"time"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"github.com/AyoubAchour/net-switch/internal/usage"
)

// Incremental records hold usage counted while the original is unreadable.
// Full records are authoritative: publish one BEFORE replacing usage.json, so
// interruption between replacement and removal cannot merge history twice.
type usageRecoveryRecord struct {
	Version int           `json:"version"`
	Full    bool          `json:"full"`
	Saved   usage.Saved   `json:"saved"`
	First   *usage.Routed `json:"first,omitempty"`
}

func emptyUsageSaved() usage.Saved {
	return usage.Saved{Lines: map[string]usage.Entry{}, Peaks: map[string]float64{}}
}

func decodeUsage(b []byte) (usage.Saved, error) {
	if !json.Valid(b) {
		return usage.Saved{}, errors.New("invalid usage JSON syntax")
	}
	v, err := js.Decode(b)
	if err != nil {
		return usage.Saved{}, err
	}
	object, ok := v.(map[string]any)
	if !ok {
		return usage.Saved{}, errors.New("usage history must be a JSON object")
	}
	u := usage.New(time.UTC)
	u.Load(object)                 // preserve the existing lenient per-entry validation
	u.Routed = usage.LoadRouted(b) // routed counters retain exact uint64 values
	return u.Saved, nil
}

// Read and, if necessary, quarantine corruption before permitting publication.
// An I/O failure is never treated as an empty record.
func (c *Core) readPrimaryUsage() (usage.Saved, error) {
	b, err := readUsageHistory(c.op)
	if errors.Is(err, fs.ErrNotExist) {
		return emptyUsageSaved(), nil
	}
	if err != nil {
		return usage.Saved{}, err
	}
	s, err := decodeUsage(b)
	if err == nil {
		return s, nil
	}
	path := filepath.Join(c.op.UserDir, "usage.json")
	if err := c.quarantineUsage(path, err); err != nil {
		return usage.Saved{}, err
	}
	return emptyUsageSaved(), nil
}

func (c *Core) quarantineUsage(path string, cause error) error {
	backup := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	if renameErr := c.op.IO.Files.Rename(path, backup); renameErr != nil {
		return fmt.Errorf("corrupt %s could not be preserved: %w", filepath.Base(path), renameErr)
	}
	c.mu.Lock()
	c.usageNotice = fmt.Sprintf("Corrupt usage history preserved as %s; accounting continues: %v", filepath.Base(backup), cause)
	c.mu.Unlock()
	if c.op.IO.SyncParent != nil {
		if err := c.op.IO.SyncParent(c.op.UserDir); err != nil {
			return err
		}
	}
	c.usageProblem(nil)
	return nil
}

func (c *Core) usageProblem(err error) {
	message := ""
	if err != nil {
		message = "Usage history unavailable; routing continues: " + err.Error()
	}
	c.mu.Lock()
	if message == "" {
		message = c.usageNotice
	}
	changed := c.usageIssue != message
	c.usageIssue = message
	c.mu.Unlock()
	if changed && message != "" {
		c.log("%s", message)
	}
}

func (c *Core) loadUsage() {
	if c.op.IO.Files == nil {
		return
	}
	primary, primaryErr := c.readPrimaryUsage()
	rec, recoveryErr := c.readRecoveryUsage()
	if recoveryErr != nil && !errors.Is(recoveryErr, fs.ErrNotExist) {
		// This file may contain acknowledged bytes. Never replace it with an
		// empty record. Routing still starts; persistence/acks report failure.
		c.usageRecoveryBlocked = recoveryErr
		c.usageRecovery = &usageRecoveryRecord{Version: 1, Saved: c.usage.Saved}
		c.usageProblem(fmt.Errorf("recovery file cannot be read: %w", recoveryErr))
		return
	}
	if rec != nil {
		c.usageRecovery = rec
		if !rec.Full && primaryErr == nil {
			rec.Saved = mergeUsage(primary, rec.Saved, rec.First)
			rec.Full, rec.First = true, nil
		}
		c.usage.Saved = rec.Saved
	} else if primaryErr == nil {
		c.usage.Saved = primary
	} else {
		c.usageRecovery = &usageRecoveryRecord{Version: 1, Saved: c.usage.Saved}
	}
	c.usageProblem(primaryErr)
}

func (c *Core) readRecoveryUsage() (*usageRecoveryRecord, error) {
	path := filepath.Join(c.op.UserDir, "usage.recovery.json")
	b, err := c.op.IO.Files.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rec, err := decodeRecoveryUsage(b)
	if err == nil {
		return rec, nil
	}
	if err := c.quarantineUsage(path, err); err != nil {
		return nil, err
	}
	return nil, fs.ErrNotExist
}

func decodeRecoveryUsage(b []byte) (*usageRecoveryRecord, error) {
	var rec usageRecoveryRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	if rec.Version != 1 || rec.Saved.Lines == nil || rec.Saved.Peaks == nil || (!rec.Full && rec.Saved.Routed != nil && rec.First == nil) {
		return nil, errors.New("invalid usage recovery record")
	}
	for _, r := range []*usage.Routed{rec.First, rec.Saved.Routed} {
		if r == nil {
			continue
		}
		if r.Apps == nil || r.Lines == nil {
			return nil, errors.New("invalid recovery counters")
		}
		for _, set := range []map[string]*usage.RoutedEntry{r.Apps, r.Lines} {
			for _, entry := range set {
				if entry == nil {
					return nil, errors.New("invalid recovery entry")
				}
			}
		}
	}
	return &rec, nil
}

// No bytes were acknowledged while this recovery record was unreadable. Merge
// the buffered observations using their own first snapshot before resuming.
func (c *Core) resumeUsageRecovery() error {
	rec, err := c.readRecoveryUsage()
	if errors.Is(err, fs.ErrNotExist) {
		primary, primaryErr := c.readPrimaryUsage()
		if primaryErr == nil {
			rec = &usageRecoveryRecord{Version: 1, Full: true, Saved: primary}
		} else {
			c.usageProblem(primaryErr)
		}
		err = nil
	}
	if err != nil {
		c.usageProblem(err)
		return err
	}
	c.mu.Lock()
	if rec != nil {
		c.usage.Saved = mergeUsage(rec.Saved, c.usage.Saved, c.usageRecovery.First)
		rec.Saved = c.usage.Saved
		c.usageRecovery = rec
	}
	c.usageRecoveryBlocked = nil
	c.mu.Unlock()
	return nil
}

// Capture the first complete snapshot only, across all its pages. These are
// the only generations that can overlap the original history's last receipt.
func (c *Core) observeRecovery(instance string, apps, lines map[string]usage.RoutedCounter) {
	rec := c.usageRecovery
	if rec == nil || rec.Full {
		return
	}
	if rec.First == nil {
		rec.First = usage.NewRouted()
		rec.First.Instance = instance
	}
	if rec.First.Instance != instance {
		return
	}
	for _, pair := range []struct {
		marks    map[string]*usage.RoutedEntry
		counters map[string]usage.RoutedCounter
	}{{rec.First.Apps, apps}, {rec.First.Lines, lines}} {
		for id, counter := range pair.counters {
			mark := pair.marks[id]
			if mark == nil {
				mark = &usage.RoutedEntry{Generation: counter.Generation}
				pair.marks[id] = mark
			}
			if mark.Generation == counter.Generation {
				mark.MarkUp, mark.MarkDown = max(mark.MarkUp, counter.Up), max(mark.MarkDown, counter.Down)
			}
		}
	}
}

func addUsage(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// Both inputs are owned snapshots. Recent counters retain their high-water
// marks; only the overlapping first generation is subtracted from the sum.
func mergeUsage(old, recent usage.Saved, first *usage.Routed) usage.Saved {
	for id, entry := range old.Lines {
		now, exists := recent.Lines[id]
		if !exists || entry.PeriodStart > now.PeriodStart {
			recent.Lines[id] = entry
		} else if entry.PeriodStart == now.PeriodStart {
			now.Bytes += entry.Bytes
			recent.Lines[id] = now
		}
	}
	for id, peak := range old.Peaks {
		recent.Peaks[id] = max(recent.Peaks[id], peak)
	}
	if old.Routed == nil {
		return recent
	}
	if recent.Routed == nil {
		recent.Routed = old.Routed
		return recent
	}
	a, b := old.Routed, recent.Routed
	for _, pair := range []struct {
		old, recent map[string]*usage.RoutedEntry
		apps        bool
	}{{a.Apps, b.Apps, true}, {a.Lines, b.Lines, false}} {
		for id, before := range pair.old {
			if before == nil {
				continue
			}
			now := pair.recent[id]
			if now == nil {
				copy := *before
				if a.Instance != b.Instance {
					copy.Generation, copy.MarkUp, copy.MarkDown = "", 0, 0
				}
				pair.recent[id] = &copy
				continue
			}
			var overlapUp, overlapDown uint64
			if first != nil && first.Instance == a.Instance {
				marks := first.Lines
				if pair.apps {
					marks = first.Apps
				}
				if mark := marks[id]; mark != nil && mark.Generation == before.Generation && mark.Generation != "" {
					overlapUp, overlapDown = min(before.MarkUp, mark.MarkUp), min(before.MarkDown, mark.MarkDown)
				}
			}
			now.Up = addUsage(before.Up, now.Up-min(now.Up, overlapUp))
			now.Down = addUsage(before.Down, now.Down-min(now.Down, overlapDown))
		}
	}
	b.Other.Up, b.Other.Down = addUsage(a.Other.Up, b.Other.Up), addUsage(a.Other.Down, b.Other.Down)
	b.Folded = addUsage(a.Folded, b.Folded)
	return recent
}

// SaveUsage owns usageWrite. The recovery commit is an equally durable receipt
// for ackTotals while primary history is unavailable. A failed recovery
// commit still refuses acknowledgement.
func (c *Core) saveUsage(retry bool) error {
	progress := false
	if c.usageRecoveryBlocked != nil {
		if err := c.resumeUsageRecovery(); err != nil {
			return fmt.Errorf("usage recovery file is unreadable: %w", err)
		}
		progress = true
	}
	c.mu.Lock()
	rec := c.usageRecovery
	c.mu.Unlock()
	if rec != nil && !rec.Full {
		primary, err := c.readPrimaryUsage()
		if err == nil {
			c.mu.Lock()
			c.usage.Saved = mergeUsage(primary, c.usage.Saved, rec.First)
			rec.Full, rec.First = true, nil
			c.mu.Unlock()
			progress = true
		} else {
			c.usageProblem(err)
		}
	}
	// Still perform recovery reads, but avoid a second write just after the
	// accounting consumer committed. Successful read/merge progress is exempt.
	if elapsed := c.op.Clock.Now().Sub(c.usageLastSave); retry && !progress && !c.usageLastSave.IsZero() && elapsed >= 0 && elapsed < 3*time.Second {
		return nil
	}
	c.mu.Lock()
	generation := c.routedGeneration
	b, err := js.Marshal(c.usage.Saved)
	var recovery []byte
	if rec != nil {
		rec.Saved = c.usage.Saved
		recovery, err = json.Marshal(rec)
	}
	c.mu.Unlock()
	if err != nil {
		c.usageProblem(err)
		return err
	}
	primaryPath := filepath.Join(c.op.UserDir, "usage.json")
	recoveryPath := filepath.Join(c.op.UserDir, "usage.recovery.json")
	if rec != nil {
		if err := settings.AtomicWrite(recoveryPath, recovery, c.op.IO); err != nil {
			c.usageProblem(err)
			return err
		}
		if rec.Full {
			if err := settings.AtomicWrite(primaryPath, b, c.op.IO); err != nil {
				c.usageProblem(err)
			} else if err := c.op.IO.Files.Remove(recoveryPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				c.usageProblem(err)
			} else {
				var syncErr error
				if c.op.IO.SyncParent != nil {
					syncErr = c.op.IO.SyncParent(c.op.UserDir)
				}
				if syncErr == nil {
					c.mu.Lock()
					c.usageRecovery = nil
					c.mu.Unlock()
					c.usageProblem(nil)
				} else {
					c.usageProblem(syncErr)
				}
			}
		}
	} else {
		if err := settings.AtomicWrite(primaryPath, b, c.op.IO); err != nil {
			c.usageProblem(err)
			return err
		}
		c.usageProblem(nil)
	}
	c.mu.Lock()
	c.routedSaved = max(c.routedSaved, generation)
	c.mu.Unlock()
	c.usageLastSave = c.op.Clock.Now()
	return nil
}

func (c *Core) retryUsage(context.Context) error {
	c.mu.Lock()
	pending := c.usageRecovery != nil || c.usageRecoveryBlocked != nil || (c.usageIssue != "" && c.usageIssue != c.usageNotice)
	c.mu.Unlock()
	if pending {
		c.usageWrite.Lock()
		defer c.usageWrite.Unlock()
		return c.saveUsage(true)
	}
	return nil
}
