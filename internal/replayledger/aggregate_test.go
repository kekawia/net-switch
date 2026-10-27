package replayledger

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

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
