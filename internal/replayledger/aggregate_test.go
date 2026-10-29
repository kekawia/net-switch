package replayledger

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"
	"testing"
)

// Recorded with Go 1.27.3: go test -json ./.ledger-buildfail, containing
// TestBrokenBuild's undefined missingBuildSymbol call. No generated log file
// was saved; these are the unmodified events captured from the command output.
//
//go:embed testdata/build-failure.json
var recordedBuildFailure string

func TestRecordedBuildFailureDiagnostics(t *testing.T) {
	var log bytes.Buffer
	_, err := Aggregate(strings.NewReader(recordedBuildFailure), receiptReport(), &log)
	importPath := Module + "/.ledger-buildfail [" + Module + "/.ledger-buildfail.test]"
	if err == nil || !strings.Contains(err.Error(), "build failed: "+importPath) {
		t.Fatal("missing build-fail identity", err)
	}
	if !strings.Contains(log.String(), "undefined: missingBuildSymbol") || !strings.Contains(log.String(), "# "+importPath) || !strings.Contains(log.String(), "[build failed]") {
		t.Fatal("compiler diagnostics were lost", log.String())
	}
}

func TestBuildFailurePathsAreSorted(t *testing.T) {
	for _, paths := range [][]string{{"z/package", "a/package"}, {"a/package", "z/package"}} {
		events := []TestEvent{}
		for _, p := range paths {
			events = append(events, TestEvent{Action: "build-fail", ImportPath: p})
		}
		_, err := Aggregate(encodeEvents(events), receiptReport(), nil)
		if err == nil || err.Error() != "build failed: a/package, z/package" {
			t.Fatalf("unordered or incomplete failed imports: %v", err)
		}
	}
}

func TestRequiredReceiptsByOS(t *testing.T) {
	for _, goos := range []string{"windows", "linux"} {
		for _, scope := range []string{"", "windows", "linux"} {
			t.Run(goos+"/scope="+scope, func(t *testing.T) {
				r := receiptReport()
				r.Rows[0].OS = scope
				e := receiptEvents()
				withoutTest := []TestEvent{e[0], e[len(e)-1]}
				_, err := AggregateForOS(encodeEvents(withoutTest), r, nil, goos)
				required := scope == "" || scope == goos
				if required && (err == nil || !strings.Contains(err.Error(), "missing required receipts")) {
					t.Fatal("excluded OS test was not gated", err)
				}
				if !required && err != nil {
					t.Fatal("other OS was required", err)
				}
				got, err := AggregateForOS(encodeEvents(e), r, nil, goos)
				if required && (err != nil || got.Counts.Covered != 1) {
					t.Fatal("matching OS receipt rejected", err)
				}
				if !required && (err == nil || !strings.Contains(err.Error(), "scoped to")) {
					t.Fatal("foreign OS receipt accepted", err)
				}
			})
		}
	}
}

func TestRequiredReceiptCannotDisappear(t *testing.T) {
	for _, name := range []string{"test-excluded", "missing-receipt", "skipped-test", "package-excluded"} {
		t.Run(name, func(t *testing.T) {
			e := receiptEvents()
			switch name {
			case "test-excluded":
				e = []TestEvent{e[0], e[6]}
			case "package-excluded":
				e = []TestEvent{{Action: "start", Package: Module + "/internal/other"}, {Action: "pass", Package: Module + "/internal/other"}}
			case "missing-receipt":
				e = append(e[:3], e[4:]...)
			case "skipped-test":
				e[4].Action = "skip"
				e = append(e[:3], e[4:]...)
			}
			_, err := Aggregate(encodeEvents(e), receiptReport(), nil)
			if err == nil || !strings.Contains(err.Error(), "missing required receipts") {
				t.Fatal("registered entry lost coverage silently", err)
			}
		})
	}
}

func receiptReport() Report {
	return Report{Version: 1, Rows: []Row{{Hash: "synthetic", Trace: "synthetic", Seq: 0, Kind: "output:api", Disposition: "unchanged", Assertion: "internal/control/replay_test.go#TestNative/trace", Status: "uncovered"}}, Counts: Counts{Consumed: 1, Uncovered: 1, ByKind: map[string]int{"output:api": 1}, ByTrace: map[string]int{"synthetic": 1}}}
}

func receiptEvents() []TestEvent {
	pkg := Module + "/internal/control"
	receipt := WireReceipt{Version: 1, Hash: "synthetic", Assertion: "internal/control/replay_test.go#TestNative/trace", Seqs: []int{0}}
	b, _ := json.Marshal(receipt)
	return []TestEvent{
		{Action: "start", Package: pkg},
		{Action: "run", Package: pkg, Test: "TestNative"},
		{Action: "run", Package: pkg, Test: "TestNative/trace"},
		{Action: "output", Package: pkg, Test: "TestNative/trace", Output: "    replay_test.go:50: " + ReceiptPrefix + string(b) + "\n"},
		{Action: "pass", Package: pkg, Test: "TestNative/trace"},
		{Action: "pass", Package: pkg, Test: "TestNative"},
		{Action: "pass", Package: pkg},
	}
}

func encodeEvents(events []TestEvent) *bytes.Buffer {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			panic(err)
		}
	}
	return &b
}

func TestAggregatePassedReceipts(t *testing.T) {
	events := receiptEvents()
	// test2json can split long t.Log lines across multiple output events.
	first, second := events[3], events[3]
	first.Output = events[3].Output[:80]
	second.Output = events[3].Output[80:]
	events = append(events[:3], append([]TestEvent{first, second}, events[4:]...)...)
	r, err := Aggregate(encodeEvents(events), receiptReport(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Counts.Covered != 1 || r.Counts.Uncovered != 0 || r.Rows[0].Status != "covered" {
		t.Fatal(r)
	}
}

func TestAggregateUpstreamEventForms(t *testing.T) {
	r := receiptReport()
	r.Rows[0].Assertion = "internal/control/replay_test.go#TestNative/trace/with-slash"
	events := receiptEvents()
	for i := range events {
		if events[i].Test == "TestNative/trace" {
			events[i].Test = "TestNative/trace/with-slash"
		}
		events[i].Output = strings.ReplaceAll(events[i].Output, "TestNative/trace", "TestNative/trace/with-slash")
	}
	metadata := []TestEvent{{Action: "attr", Package: events[2].Package, Test: events[2].Test}, {Action: "artifacts", Package: events[2].Package, Test: events[2].Test}}
	events = append(events[:3], append(metadata, events[3:]...)...)
	got, err := Aggregate(encodeEvents(events), r, nil)
	if err != nil || got.Counts.Covered != 1 {
		t.Fatal(got.Counts, err)
	}
}

func TestAggregateRejectsInvalidEvidence(t *testing.T) {
	for _, name := range []string{"unknown-entry", "duplicate", "failed-test", "failed-parent", "failed-package", "skipped-test", "unfinished-package", "unfinished-test", "wrong-package", "wrong-name", "pending", "malformed", "truncated-receipt", "repeated-run", "unsupported-version"} {
		t.Run(name, func(t *testing.T) {
			e := receiptEvents()
			r := receiptReport()
			switch name {
			case "unknown-entry":
				e[3].Output = strings.Replace(e[3].Output, `"seqs":[0]`, `"seqs":[17]`, 1)
			case "duplicate":
				e = append(e[:4], append([]TestEvent{e[3]}, e[4:]...)...)
			case "failed-test":
				e[4].Action = "fail"
			case "failed-parent":
				e[5].Action = "fail"
			case "failed-package":
				e[6].Action = "fail"
			case "skipped-test":
				e[4].Action = "skip"
			case "unfinished-package":
				e = e[:6]
			case "unfinished-test":
				e = append(e[:4], e[5:]...)
			case "wrong-package":
				e[3].Package = Module + "/internal/lifecycle"
			case "wrong-name":
				e[3].Output = strings.Replace(e[3].Output, "TestNative/trace", "TestNope", 1)
			case "pending":
				r.Rows[0].Status = "pending #245"
			case "malformed":
				e[3].Output = ReceiptPrefix + "{invalid}\n"
			case "truncated-receipt":
				e[3].Output = strings.TrimSuffix(e[3].Output, "\n")
			case "repeated-run":
				e = append(e, e[0])
			case "unsupported-version":
				e[3].Output = strings.Replace(e[3].Output, `"version":1`, `"version":99`, 1)
			}
			if _, err := Aggregate(encodeEvents(e), r, nil); err == nil {
				t.Fatal("invalid evidence accepted")
			}
			if r.Counts.Covered != 0 || r.Rows[0].Status != "uncovered" && name != "pending" {
				t.Fatal("failed aggregation partially credited evidence")
			}
		})
	}
	for _, input := range []string{"", "not json\n"} {
		if _, err := Aggregate(strings.NewReader(input), receiptReport(), nil); err == nil {
			t.Fatal("bad stream accepted")
		}
	}
}

func TestAggregateAcrossPackagesAndAtomicGroups(t *testing.T) {
	r := receiptReport()
	second := r.Rows[0]
	second.Hash = "second"
	second.Trace = "second"
	second.Assertion = "internal/lifecycle/replay_test.go#TestNative/trace"
	r.Rows = append(r.Rows, second)
	r.Counts.Consumed = 2
	r.Counts.Uncovered = 2
	r.Counts.ByKind[second.Kind] = 2
	r.Counts.ByTrace[second.Trace] = 1
	a, b := receiptEvents(), receiptEvents()
	for i := range b {
		b[i].Package = Module + "/internal/lifecycle"
		b[i].Output = strings.ReplaceAll(strings.ReplaceAll(b[i].Output, "internal/control", "internal/lifecycle"), "synthetic", "second")
	}
	// Interleave packages as go test -json does, without sorting their effects.
	var events []TestEvent
	for i := range a {
		events = append(events, a[i], b[i])
	}
	got, err := Aggregate(encodeEvents(events), r, nil)
	if err != nil || got.Counts.Covered != 2 {
		t.Fatal(got.Counts, err)
	}
	r = receiptReport()
	r.Rows[0].Group = "atomic"
	second = r.Rows[0]
	second.Seq = 1
	r.Rows = append(r.Rows, second)
	events = receiptEvents()
	events[3].Output = strings.Replace(events[3].Output, `"seqs":[0]`, `"group":"atomic","seqs":[0]`, 1)
	if _, err := Aggregate(encodeEvents(events), r, nil); err == nil || !strings.Contains(err.Error(), "incomplete group") {
		t.Fatal("partial revision accepted", err)
	}
}
