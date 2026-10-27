package replayledger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
)

type TestEvent struct {
	Action  string
	Package string
	Test    string
	Output  string
}

// Aggregate consumes go test -json directly. Nothing is credited until EOF,
// every package has a terminal result, and every receipt's test and ancestors
// passed. A failure after emission (including cleanup) invalidates the run.
func Aggregate(input io.Reader, r Report, log io.Writer) (Report, error) {
	type key struct{ pkg, test string }
	states := map[key]string{}
	lines := map[key]string{}
	var receipts []WireReceipt
	receiptGroups := map[[3]string]bool{}
	owners := map[key]bool{}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 16<<20)
	for scanner.Scan() {
		var e TestEvent
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil || e.Package == "" {
			return r, fmt.Errorf("invalid go test JSON event: %s", scanner.Text())
		}
		k := key{e.Package, e.Test}
		if _, ok := states[key{e.Package, ""}]; !ok {
			states[key{e.Package, ""}] = "running"
		}
		switch e.Action {
		case "start", "run":
			if old := states[k]; old == "pass" || old == "fail" || old == "skip" {
				return r, fmt.Errorf("repeated test run: %s %s", e.Package, e.Test)
			}
			states[k] = "running"
		case "pass", "skip", "fail", "bench":
			if old := states[k]; old == "pass" || old == "fail" || old == "skip" {
				return r, fmt.Errorf("duplicate test result: %s %s", e.Package, e.Test)
			}
			states[k] = e.Action
		case "output":
			if log != nil {
				if _, err := io.WriteString(log, e.Output); err != nil {
					return r, err
				}
			}
			lines[k] += e.Output
			if len(lines[k]) > 16<<20 {
				return r, fmt.Errorf("test output line exceeds limit")
			}
			for {
				line, tail, ok := strings.Cut(lines[k], "\n")
				if !ok {
					break
				}
				lines[k] = tail
				_, payload, ok := strings.Cut(line, ReceiptPrefix)
				if !ok {
					continue
				}
				var receipt WireReceipt
				if err := json.Unmarshal([]byte(payload), &receipt); err != nil {
					return r, fmt.Errorf("malformed replay receipt: %w", err)
				}
				file, name, _, valid := splitReference(receipt.Assertion)
				expectedPackage := Module
				if dir := path.Dir(file); dir != "." {
					expectedPackage += "/" + dir
				}
				if !valid || e.Test == "" || name != e.Test || e.Package != expectedPackage || states[k] != "running" {
					return r, fmt.Errorf("receipt identity does not match running test: %s", receipt.Assertion)
				}
				group := [3]string{receipt.Assertion, receipt.Hash, receipt.Group}
				if receiptGroups[group] {
					return r, fmt.Errorf("duplicate receipt group: %v", group)
				}
				receiptGroups[group] = true
				receipts = append(receipts, receipt)
				owners[k] = true
			}
		case "pause", "cont", "attr", "artifacts":
		default:
			return r, fmt.Errorf("unknown test event action %q", e.Action)
		}
	}
	if err := scanner.Err(); err != nil {
		return r, err
	}
	if len(states) == 0 {
		return r, fmt.Errorf("empty test stream")
	}
	for k, state := range states {
		if state != "pass" && state != "skip" && state != "bench" {
			return r, fmt.Errorf("failed or incomplete test run: %s %s (%s)", k.pkg, k.test, state)
		}
	}
	for k, line := range lines {
		if strings.Contains(line, ReceiptPrefix) {
			return r, fmt.Errorf("truncated receipt for %s", k.test)
		}
	}
	for owner := range owners {
		for test := owner.test; ; {
			state, exists := states[key{owner.pkg, test}]
			// A slash may be part of one t.Run name; only emitted ancestors
			// are real tests. The exact test, root test and package are mandatory.
			required := exists || test == owner.test || !strings.Contains(test, "/")
			if required && state != "pass" {
				return r, fmt.Errorf("receipt from non-passing test/package: %s %s", owner.pkg, test)
			}
			if test == "" {
				break
			}
			if i := strings.LastIndex(test, "/"); i >= 0 {
				test = test[:i]
			} else {
				test = ""
			}
		}
	}
	if err := r.cover(receipts); err != nil {
		return r, err
	}
	return r, nil
}
