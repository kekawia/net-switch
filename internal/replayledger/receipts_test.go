package replayledger

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCursorPlanOrder(t *testing.T) {
	first := Row{Hash: "a", Seq: 0, Disposition: "unchanged", Assertion: "internal/replayledger/receipts_test.go#TestCursorPlanOrder", Status: "uncovered"}
	second, foreign := first, first
	second.Seq = 1
	foreign.Hash = "b"
	for _, rows := range [][]Row{{first, first}, {second, first}, {first, foreign, second}} {
		c := NewCursor(rows)
		if err := c.Consume(t, rows[0].Hash, rows[0].Seq, rows[0].Disposition); err == nil {
			t.Fatal("malformed cursor plan accepted")
		}
		if err := c.Receipt(t); err == nil {
			t.Fatal("malformed plan earned a receipt")
		}
	}
}

func TestCursorIdentityAndOrder(t *testing.T) {
	for _, name := range []string{"duplicate", "missing", "reordered", "wrong-file", "wrong-test", "wrong-hash", "wrong-disposition", "pending"} {
		t.Run(name, func(t *testing.T) {
			row := Row{Hash: "synthetic", Seq: 0, Disposition: "unchanged", Assertion: "internal/replayledger/receipts_test.go#" + t.Name(), Status: "uncovered"}
			second := row
			second.Seq = 1
			if name == "pending" {
				row.Status = "pending #245"
			}
			if name == "wrong-file" {
				row.Assertion = "does_not_exist_test.go#" + t.Name()
			}
			if name == "wrong-test" {
				row.Assertion = "internal/replayledger/receipts_test.go#TestNope"
			}
			c := NewCursor([]Row{row, second})
			err := c.Consume(t, row.Hash, row.Seq, row.Disposition)
			if name == "pending" || name == "wrong-file" || name == "wrong-test" {
				if err == nil {
					t.Fatal("forged binding accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "duplicate":
				err = c.Consume(t, row.Hash, row.Seq, row.Disposition)
			case "missing":
				err = c.Receipt(t)
			case "reordered":
				err = c.Consume(t, row.Hash, 2, row.Disposition)
			case "wrong-hash":
				err = c.Consume(t, "foreign", 1, row.Disposition)
			case "wrong-disposition":
				err = c.Consume(t, row.Hash, 1, "obsolete")
			}
			if err == nil {
				t.Fatal("invalid cursor accepted")
			}
		})
	}
}

// Invoked as a test binary, never recursively via go test. The parent captures
// output so synthetic receipts cannot enter the real CI coverage stream.
func TestReceiptProcess(t *testing.T) {
	mode := os.Getenv("NETSWITCH_LEDGER_CHILD")
	if mode == "" {
		t.Skip("subprocess fixture")
	}
	row := Row{Hash: "synthetic", Seq: 0, Disposition: "unchanged", Assertion: "internal/replayledger/receipts_test.go#TestReceiptProcess", Status: "uncovered"}
	c := NewCursor([]Row{row})
	if err := c.Consume(t, row.Hash, row.Seq, row.Disposition); err != nil {
		t.Fatal(err)
	}
	if mode == "failed" {
		t.Error("intentional prior assertion failure")
	}
	err := c.Receipt(t)
	if mode == "failed" {
		if err == nil {
			t.Fatal("failed test earned receipt")
		}
		t.Log("FAILED_RECEIPT_REFUSED")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if mode == "late-failure" {
		t.Cleanup(func() { t.Error("intentional cleanup failure after receipt") })
	}
}

func TestReceiptRuntimeProof(t *testing.T) {
	for _, mode := range []string{"pass", "failed", "late-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			t.Cleanup(cancel)
			goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
			if runtime.GOOS == "windows" {
				goTool += ".exe"
			}
			cmd := exec.CommandContext(ctx, goTool, "tool", "test2json", "-p", Module+"/internal/replayledger", os.Args[0], "-test.run=^TestReceiptProcess$", "-test.v=test2json")
			cmd.Env = append(os.Environ(), "NETSWITCH_LEDGER_CHILD="+mode)
			out, err := cmd.CombinedOutput()
			r := receiptReport()
			r.Rows[0].Assertion = "internal/replayledger/receipts_test.go#TestReceiptProcess"
			report, aggregateErr := Aggregate(bytes.NewReader(out), r, nil)
			if mode == "pass" {
				if err != nil || aggregateErr != nil || report.Counts.Covered != 1 {
					t.Fatalf("receipt subprocess failed: %v; aggregate: %v; covered %d", err, aggregateErr, report.Counts.Covered)
				}
			} else if mode == "late-failure" {
				if err == nil || aggregateErr == nil || !strings.Contains(string(out), ReceiptPrefix) {
					t.Fatal("receipt survived a later cleanup failure")
				}
			} else {
				if err == nil || aggregateErr == nil || strings.Contains(string(out), ReceiptPrefix) || !strings.Contains(string(out), "FAILED_RECEIPT_REFUSED") {
					t.Fatal("failed-test receipt guard did not run")
				}
			}
		})
	}
}
