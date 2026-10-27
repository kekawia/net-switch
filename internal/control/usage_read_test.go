package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"github.com/AyoubAchour/net-switch/internal/settings"
	"github.com/AyoubAchour/net-switch/internal/usage"
)

type usageReadFault struct {
	settings.Files
	err                      error
	remaining, reads         int
	renameError, removeError error
	recoveryReadError        error
}

func (f *usageReadFault) Rename(from, to string) error {
	if strings.Contains(to, "usage.json.corrupt-") && f.renameError != nil {
		return f.renameError
	}
	return f.Files.Rename(from, to)
}
func (f *usageReadFault) Remove(path string) error {
	if filepath.Base(path) == "usage.recovery.json" && f.removeError != nil {
		return f.removeError
	}
	return f.Files.Remove(path)
}

func usageRestart(t *testing.T, base *Core, fault *usageReadFault) *Core {
	t.Helper()
	op := base.op
	op.IO.Files = fault
	c, err := New(context.Background(), op)
	if err != nil {
		t.Fatal("accounting history prevented Control startup", err)
	}
	t.Cleanup(c.cancel)
	return c
}

func TestUnreadableUsageKeepsRoutingAndAcks(t *testing.T) {
	base, e, _, files := testCore(t, map[string]any{"lines": testLines()})
	base.op.ServiceMode = true
	table := accountingTable(t)
	acct := &accountingEngine{fakeEngine: e, table: table}
	base.op.Engine = acct
	ctx := context.Background()
	if err := base.Start(ctx); err != nil {
		t.Fatal(err)
	}
	transfer(t, table, "C:/apps/recovery.exe", 100, 200)
	acct.ackFail = true
	if err := base.readTotals(ctx, acct, base.generation); err == nil {
		t.Fatal("expected lost ack")
	}
	primary := filepath.Join("/test", "usage.json")
	original, _ := files.ReadFile(primary)
	fault := &usageReadFault{Files: files, err: os.ErrPermission, remaining: 1000}
	c := usageRestart(t, base, fault)
	if c.State()["usageError"] == nil {
		t.Fatal("missing visible accounting error")
	}
	acct.ackFail = false
	transfer(t, table, "C:/apps/recovery.exe", 20, 30)
	if err := c.readTotals(ctx, acct, c.generation); err != nil {
		t.Fatal("recovery commit did not permit ack", err)
	}
	transfer(t, table, "C:/apps/recovery.exe", 5, 7)
	if err := c.readTotals(ctx, acct, c.generation); err != nil {
		t.Fatal(err)
	}
	if acct.acks != 2 {
		t.Fatal("acks stopped while primary was unreadable", acct.acks)
	}
	current, _ := files.ReadFile(primary)
	if string(current) != string(original) {
		t.Fatal("unreadable original overwritten")
	}
	recovery, err := files.ReadFile(filepath.Join("/test", "usage.recovery.json"))
	if err != nil {
		t.Fatal("acks lack recovery file", err)
	}
	var rec usageRecoveryRecord
	if err := json.Unmarshal(recovery, &rec); err != nil {
		t.Fatal(err)
	}
	key := apps.AppKey("C:/apps/recovery.exe")
	if rec.Saved.Routed.Apps[key].Up != 125 {
		t.Fatal("recovery lost generations", rec.Saved.Routed)
	}
	c = usageRestart(t, base, fault)
	transfer(t, table, "C:/apps/recovery.exe", 7, 11)
	if err := c.readTotals(ctx, acct, c.generation); err != nil || acct.acks != 3 {
		t.Fatal("recovery-file restart did not keep acking", err, acct.acks)
	}
	fault.remaining = 0
	if err := c.retryUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveUsage(); err != nil {
		t.Fatal(err)
	}
	got := routedUsage(t, files).Apps[key]
	if got.Up != 132 || got.Down != 248 {
		t.Fatal("overlap counted twice when history returned", got)
	}
	if c.State()["usageError"] != nil {
		t.Fatal("recovery error did not clear")
	}
	if _, err := files.ReadFile(filepath.Join("/test", "usage.recovery.json")); !os.IsNotExist(err) {
		t.Fatal("recovery not removed", err)
	}
}

func TestUsageRecoveryLeftoverMergedOnce(t *testing.T) {
	base, _, _, files := testCore(t, map[string]any{"lines": testLines()})
	primary := filepath.Join("/test", "usage.json")
	files.data[primary] = []byte(`{"lines":{"a1":{"bytes":100,"periodStart":1}},"peaks":{}}`)
	fault := &usageReadFault{Files: files, err: os.ErrPermission, remaining: 1000, removeError: errors.New("remove blocked")}
	c := usageRestart(t, base, fault)
	c.usage.Lines["a1"] = usage.Entry{Bytes: 20, PeriodStart: 1}
	if err := c.SaveUsage(); err != nil {
		t.Fatal(err)
	}
	// Restart before merge: the incremental sidecar is loaded, then merged.
	fault.remaining = 0
	c = usageRestart(t, base, fault)
	files.failPrefix = primary
	if err := c.SaveUsage(); err != nil {
		t.Fatal("full recovery did not survive failed primary write", err)
	}
	files.failPrefix = ""
	c = usageRestart(t, base, fault)
	if err := c.SaveUsage(); err != nil {
		t.Fatal(err)
	}
	if c.usage.Lines["a1"].Bytes != 120 {
		t.Fatal("incremental recovery not merged", c.usage.Lines)
	}
	// The primary is committed but remove failed. Full sidecar must replace,
	// rather than add to, the primary on every subsequent restart.
	for range 2 {
		c = usageRestart(t, base, fault)
		if c.usage.Lines["a1"].Bytes != 120 {
			t.Fatal("leftover merged more than once", c.usage.Lines)
		}
		if err := c.SaveUsage(); err != nil {
			t.Fatal(err)
		}
	}
	fault.removeError = nil
	if err := c.SaveUsage(); err != nil {
		t.Fatal(err)
	}
	c = usageRestart(t, base, fault)
	if c.usage.Lines["a1"].Bytes != 120 {
		t.Fatal("history changed after recovery removal", c.usage.Lines)
	}
}

func TestCorruptUsageIsQuarantined(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprint(blocked), func(t *testing.T) {
			base, _, _, files := testCore(t, map[string]any{"lines": testLines()})
			primary := filepath.Join("/test", "usage.json")
			files.data[primary] = []byte("not json")
			fault := &usageReadFault{Files: files}
			if blocked {
				fault.renameError = errors.New("rename denied")
			}
			c := usageRestart(t, base, fault)
			c.usage.Lines["a1"] = usage.Entry{Bytes: 9, PeriodStart: 1}
			if err := c.SaveUsage(); err != nil {
				t.Fatal(err)
			}
			if blocked {
				if b, _ := files.ReadFile(primary); string(b) != "not json" {
					t.Fatal("failed quarantine overwrote original")
				}
				if c.State()["usageError"] == nil {
					t.Fatal("failed rename not visible")
				}
				fault.renameError = nil
				if err := c.retryUsage(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			found := false
			for path, b := range files.data {
				if strings.Contains(path, "usage.json.corrupt-") {
					found = string(b) == "not json"
				}
			}
			if !found {
				t.Fatal("corrupt bytes were not moved aside")
			}
			b, _ := files.ReadFile(primary)
			var saved usage.Saved
			if err := json.Unmarshal(b, &saved); err != nil || saved.Lines["a1"].Bytes != 9 {
				t.Fatal("replacement history", string(b), err)
			}
		})
	}
}

func TestUsageRecoveryWriteFailureDoesNotAck(t *testing.T) {
	base, e, _, files := testCore(t, map[string]any{"lines": testLines()})
	fault := &usageReadFault{Files: files, err: os.ErrPermission, remaining: 1000}
	c := usageRestart(t, base, fault)
	table := accountingTable(t)
	acct := &accountingEngine{fakeEngine: e, table: table}
	transfer(t, table, "C:/apps/failure.exe", 3, 4)
	files.failPrefix = filepath.Join("/test", "usage.recovery.json")
	if err := c.readTotals(context.Background(), acct, c.generation); err == nil || acct.acks != 0 {
		t.Fatal("ack without recovery durability", err, acct.acks)
	}
	if c.State()["usageError"] == nil {
		t.Fatal("recovery write failure not visible")
	}
	files.failPrefix = ""
	if err := c.readTotals(context.Background(), acct, c.generation); err != nil || acct.acks != 1 {
		t.Fatal("recovery retry", err, acct.acks)
	}
}

func (f *usageReadFault) ReadFile(path string) ([]byte, error) {
	if filepath.Base(path) == "usage.recovery.json" && f.recoveryReadError != nil {
		return nil, f.recoveryReadError
	}
	if filepath.Base(path) == "usage.json" {
		f.reads++
		if f.remaining > 0 {
			f.remaining--
			return nil, &os.PathError{Op: "open", Path: path, Err: f.err}
		}
	}
	return f.Files.ReadFile(path)
}

func TestUnreadableRecoveryRecordRetriesWithoutOverwrite(t *testing.T) {
	base, _, _, files := testCore(t, map[string]any{"lines": testLines()})
	primary := filepath.Join("/test", "usage.json")
	files.data[primary] = []byte(`{"lines":{"a1":{"bytes":80,"periodStart":1}},"peaks":{}}`)
	recoveryPath := filepath.Join("/test", "usage.recovery.json")
	b, _ := json.Marshal(usageRecoveryRecord{Version: 1, Full: true, Saved: usage.Saved{Lines: map[string]usage.Entry{"a1": {Bytes: 100, PeriodStart: 1}}, Peaks: map[string]float64{}}})
	files.data[recoveryPath] = b
	fault := &usageReadFault{Files: files, recoveryReadError: os.ErrPermission}
	c := usageRestart(t, base, fault)
	c.usage.Lines["a1"] = usage.Entry{Bytes: 20, PeriodStart: 1}
	if err := c.SaveUsage(); err == nil {
		t.Fatal("unreadable acknowledged recovery was overwritten")
	}
	if got, _ := files.ReadFile(recoveryPath); string(got) != string(b) {
		t.Fatal("recovery bytes changed while unreadable")
	}
	fault.recoveryReadError = nil
	if err := c.retryUsage(context.Background()); err != nil {
		t.Fatal("recovery read never retried", err)
	}
	if c.usage.Lines["a1"].Bytes != 120 {
		t.Fatal("buffered usage not merged with recovered file", c.usage.Lines)
	}
}

func TestUsageStartupSharingRetry(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows sharing codes")
	}
	for _, code := range []syscall.Errno{32, 33} {
		t.Run(code.Error(), func(t *testing.T) {
			base, _, _, files := testCore(t, map[string]any{"lines": testLines()})
			files.data[filepath.Join("/test", "usage.json")] = []byte(`{"lines":{"a1":{"bytes":42,"periodStart":1}}}`)
			fault := &usageReadFault{Files: files, err: code, remaining: 2}
			op := base.op
			op.IO.Files = fault
			var sleeps int
			op.IO.Sleep = func(d time.Duration) {
				if d != 20*time.Millisecond {
					t.Error(d)
				}
				sleeps++
			}
			c, err := New(context.Background(), op)
			if err != nil {
				t.Fatal(err)
			}
			defer c.cancel()
			if sleeps != 2 || fault.reads != 3 || c.usage.Lines["a1"].Bytes != 42 {
				t.Fatal("sharing conflict not retried", sleeps, fault.reads, c.usage.Lines)
			}
		})
	}
}
