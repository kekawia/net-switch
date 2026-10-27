package control

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/settings"
)

type usageReadFault struct {
	settings.Files
	err              error
	remaining, reads int
}

func (f *usageReadFault) ReadFile(path string) ([]byte, error) {
	if filepath.Base(path) == "usage.json" {
		f.reads++
		if f.remaining > 0 {
			f.remaining--
			return nil, &os.PathError{Op: "open", Path: path, Err: f.err}
		}
	}
	return f.Files.ReadFile(path)
}

func TestUsageStartupReadPreservesHistory(t *testing.T) {
	for _, failure := range []error{os.ErrPermission, syscall.Errno(32), syscall.Errno(33)} {
		t.Run(failure.Error(), func(t *testing.T) {
			base, _, _, files := testCore(t, map[string]any{"lines": testLines()})
			path := filepath.Join("/test", "usage.json")
			original := []byte(`{"lines":{"a1":{"bytes":12345,"periodStart":1}},"peaks":{}}`)
			files.data[path] = original
			fault := &usageReadFault{Files: files, err: failure, remaining: 100}
			op := base.op
			op.IO.Files = fault
			c, err := New(context.Background(), op)
			if err == nil {
				// Demonstrate the overwrite that startup refusal prevents.
				_ = c.SaveUsage()
				t.Error("unreadable usage history allowed writable Control startup")
				c.cancel()
			}
			b, _ := files.ReadFile(path)
			if string(b) != string(original) {
				t.Error("unreadable history was overwritten", string(b))
			}
			fault.remaining = 0
			c, err = New(context.Background(), op)
			if err != nil {
				t.Fatal(err)
			}
			defer c.cancel()
			if c.usage.Lines["a1"].Bytes != 12345 {
				t.Fatal("retry did not recover saved history", c.usage.Lines)
			}
		})
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
