package replayledger

import (
	"encoding/json"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

var fullReport = flag.Bool("ledger-report", false, "print all per-entry dispositions as JSON")

func load(t *testing.T) (Mapping, map[string]Trace) {
	t.Helper()
	m, err := DefaultMapping()
	if err != nil {
		t.Fatal(err)
	}
	traces, err := Load("../..", m)
	if err != nil {
		t.Fatal(err)
	}
	return m, traces
}

func readTestSource(path string) (*ast.File, error) {
	return parser.ParseFile(token.NewFileSet(), filepath.Join("../..", path), nil, 0)
}

func TestNativeSemanticLedger(t *testing.T) {
	m, traces := load(t)
	if err := ValidateReferences(m, readTestSource); err != nil {
		t.Fatal(err)
	}
	r, err := Build(m, traces)
	if err != nil {
		t.Fatal(err)
	}
	if r.Counts.Consumed != 7894 || r.Counts.Uncovered != 7894 || r.Counts.Covered != 0 || len(r.Counts.Pending) != 0 {
		t.Fatalf("unexpected coverage: %+v", r.Counts)
	}
	// Inventory is not a native replay and must never emit coverage receipts.
	var data []byte
	if *fullReport {
		data, err = json.Marshal(r)
	} else {
		data, err = json.Marshal(r.Counts)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}

func TestLedgerRejectsMutations(t *testing.T) {
	cases := []struct {
		name, message string
		mutate        func(*Mapping, map[string]Trace)
	}{
		{"unknown-kind", "unknown kind", func(m *Mapping, traces map[string]Trace) {
			for hash, trace := range traces {
				trace.Entries[0].Kind = "exit"
				traces[hash] = trace
				break
			}
		}},
		{"duplicate-disposition", "duplicate disposition", func(m *Mapping, _ map[string]Trace) { m.Annotations = append(m.Annotations, m.Annotations[0]) }},
		{"missing-disposition", "missing disposition", func(m *Mapping, _ map[string]Trace) { m.Rules[0].Kinds = m.Rules[0].Kinds[1:] }},
		{"leftover-reply", "leftover reply", func(_ *Mapping, traces map[string]Trace) {
			for hash, trace := range traces {
				for i, e := range trace.Entries {
					if e.Kind == "engine-reply" {
						trace.Entries[i].Value = json.RawMessage(`{"route":"/not-requested","status":200}`)
						traces[hash] = trace
						return
					}
				}
			}
		}},
		{"incomplete-group", "incomplete group", func(m *Mapping, _ map[string]Trace) { m.Annotations[1].Seqs = m.Annotations[1].Seqs[1:] }},
		{"extra-group-member", "incomplete group", func(m *Mapping, _ map[string]Trace) { m.Groups[0].Members = m.Groups[0].Members[1:] }},
		{"missing-group", "incomplete group", func(m *Mapping, _ map[string]Trace) { m.Groups = m.Groups[1:] }},
		{"settings-in-revision", "incomplete group", func(m *Mapping, _ map[string]Trace) {
			m.Annotations[0].Seqs = []int{135, 163, 168, 170}
			m.Annotations[1].Seqs = append(m.Annotations[1].Seqs, 158)
			m.Groups[0].Members = append(m.Groups[0].Members, 158)
		}},
		{"missing-member-and-annotation", "incomplete group", func(m *Mapping, _ map[string]Trace) {
			m.Groups[0].Members = m.Groups[0].Members[1:]
			m.Annotations[1].Seqs = m.Annotations[1].Seqs[1:]
		}},
		{"duplicate-generic-rule", "duplicate disposition", func(m *Mapping, _ map[string]Trace) { m.Rules = append(m.Rules, m.Rules[0]) }},
		{"unknown-rule", "unknown kind", func(m *Mapping, _ map[string]Trace) { m.Rules[0].Kinds = append(m.Rules[0].Kinds, "output:exit") }},
		{"missing-assertion", "invalid generic disposition", func(m *Mapping, _ map[string]Trace) { m.Rules[0].Assertion = "" }},
		{"implicit-global-binding", "invalid generic disposition", func(m *Mapping, _ map[string]Trace) { m.Rules[0].Assertion = "does_not_exist_test.go#TestNope" }},
		{"invented-disposition", "invalid generic disposition", func(m *Mapping, _ map[string]Trace) { m.Rules[0].Disposition = "ignore" }},
		{"unearned-coverage", "invalid annotation", func(m *Mapping, _ map[string]Trace) { m.Annotations[0].Status = "covered" }},
		{"detached-completion", "detached completion", func(_ *Mapping, traces map[string]Trace) {
			for hash, trace := range traces {
				trace.Entries[2].Value = json.RawMessage(`{"id":99,"kind":"file-completion"}`)
				traces[hash] = trace
				break
			}
		}},
		{"duplicate-sequence", "duplicate/missing sequence", func(_ *Mapping, traces map[string]Trace) {
			for hash, trace := range traces {
				trace.Entries[1].Seq = 0
				traces[hash] = trace
				break
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, traces := load(t)
			tc.mutate(&m, traces)
			_, err := Build(m, traces)
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("mutation must fail with %q, got %v", tc.message, err)
			}
			t.Log(err)
		})
	}
}

func TestResponseBoundedGroups(t *testing.T) {
	target := func(m *Mapping) *Group {
		for i := range m.Groups {
			if m.Groups[i].Name == "combining-strict" {
				return &m.Groups[i]
			}
		}
		t.Fatal("missing response-boundary regression fixture")
		return nil
	}
	cases := []struct {
		name   string
		mutate func(*Mapping)
	}{
		{"v1", func(m *Mapping) { m.Version = 1 }},
		{"fake-ack", func(m *Mapping) { target(m).Ack = 192 }},
		{"unknown-boundary", func(m *Mapping) { target(m).Boundary = "implicit" }},
		{"reorder", func(m *Mapping) {
			g := target(m)
			g.Members[0], g.Members[1] = g.Members[1], g.Members[0]
		}},
		{"drop-member", func(m *Mapping) { g := target(m); g.Members = g.Members[1:] }},
		{"split-owner", func(m *Mapping) {
			g := target(m)
			for i := range m.Annotations {
				a := &m.Annotations[i]
				if a.Group == g.Name {
					other := *a
					other.Seqs = []int{a.Seqs[0]}
					other.Assertion = "internal/control/native_startup_replay_test.go#TestNativeStartupReplay/capMoved"
					a.Seqs = a.Seqs[1:]
					m.Annotations = append(m.Annotations, other)
					return
				}
			}
		}},
		{"cross-http", func(m *Mapping) { target(m).End = 196 }},
	}
	m, traces := load(t)
	if _, err := Build(m, traces); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, traces := load(t)
			tc.mutate(&m)
			if _, err := Build(m, traces); err == nil {
				t.Fatal("accepted invalid response-bounded transaction")
			}
		})
	}
}

func TestResponseGroupRejectsRecordedBarriers(t *testing.T) {
	for _, kind := range []string{"timer-completion", "state-snapshot"} {
		t.Run(kind, func(t *testing.T) {
			m, traces := load(t)
			found := false
			for i := range m.Groups {
				g := &m.Groups[i]
				if g.Name != "combining-enable" {
					continue
				}
				found = true
				trace := traces[g.Hash]
				// Keep the completion structurally valid: only the forbidden
				// recorded barrier should invalidate the response-only group.
				trace.Entries[g.Ack].Kind = kind
				if kind == "state-snapshot" {
					trace.Entries[g.Ack].Value = json.RawMessage(`{"now":1792411200000}`)
				}
				var completion map[string]any
				if err := json.Unmarshal(trace.Entries[g.Ack+1].Value, &completion); err != nil {
					t.Fatal(err)
				}
				completion["kind"] = kind
				trace.Entries[g.Ack+1].Value, _ = json.Marshal(completion)
				traces[g.Hash] = trace
				g.Boundary, g.Ack = "response", -1
			}
			if !found {
				t.Fatal("missing combining-enable group")
			}
			if _, err := Build(m, traces); err == nil {
				t.Fatal("accepted response-only group containing", kind)
			} else if !strings.Contains(err.Error(), "recorded barrier") {
				t.Fatal("wrong rejection", err)
			}
		})
	}
}

func TestLedgerFixtureHashAndSet(t *testing.T) {
	m, _ := load(t)
	for hash, f := range m.Fixtures {
		delete(m.Fixtures, hash)
		m.Fixtures[strings.Repeat("0", 64)] = f
		break
	}
	if _, err := Load("../..", m); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatal("changed fixture hash accepted", err)
	}
	delete(m.Fixtures, strings.Repeat("0", 64))
	if _, err := Load("../..", m); err == nil || !strings.Contains(err.Error(), "exactly 25") {
		t.Fatal("missing fixture accepted", err)
	}
}
