package replayledger

import (
	"encoding/json"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
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

func TestNativeSemanticLedger(t *testing.T) {
	m, traces := load(t)
	r, err := Build(m, traces)
	if err != nil {
		t.Fatal(err)
	}
	if r.Counts.Consumed != 7894 || r.Counts.Uncovered != 7894 || r.Counts.Covered != 0 || r.Counts.Pending107 != 23 {
		t.Fatalf("unexpected coverage: %+v", r.Counts)
	}
	c := NewCursor(r.Rows)
	for _, row := range r.Rows {
		if err := c.Consume(row.Hash, row.Seq, row.Disposition, row.Assertion); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	// This loop proves accounting, NOT native behavior. Counts stay uncovered.
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
		{"missing-member-and-annotation", "incomplete group", func(m *Mapping, _ map[string]Trace) {
			m.Groups[0].Members = m.Groups[0].Members[1:]
			m.Annotations[1].Seqs = m.Annotations[1].Seqs[1:]
		}},
		{"duplicate-generic-rule", "duplicate disposition", func(m *Mapping, _ map[string]Trace) { m.Rules = append(m.Rules, m.Rules[0]) }},
		{"unknown-rule", "unknown kind", func(m *Mapping, _ map[string]Trace) { m.Rules[0].Kinds = append(m.Rules[0].Kinds, "output:exit") }},
		{"missing-assertion", "invalid generic disposition", func(m *Mapping, _ map[string]Trace) { m.Rules[0].Assertion = "" }},
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

func TestLedgerCursorRequiresExactlyOnceInOrder(t *testing.T) {
	m, traces := load(t)
	r, err := Build(m, traces)
	if err != nil {
		t.Fatal(err)
	}
	consume := func(c *Cursor, row Row) error { return c.Consume(row.Hash, row.Seq, row.Disposition, row.Assertion) }
	for _, rows := range [][]Row{{r.Rows[1], r.Rows[0]}, {r.Rows[0], r.Rows[0]}, {r.Rows[0], r.Rows[len(r.Rows)-1], r.Rows[1]}} {
		c := NewCursor(rows)
		if err := consume(c, rows[0]); err == nil {
			t.Fatal("malformed cursor plan accepted")
		}
		if _, err := c.Receipt(); err == nil {
			t.Fatal("malformed cursor plan earned receipt")
		}
	}
	for _, name := range []string{"duplicate", "missing", "reordered", "wrong-assertion", "wrong-hash", "wrong-disposition"} {
		t.Run(name, func(t *testing.T) {
			c := NewCursor(r.Rows)
			if err := consume(c, r.Rows[0]); err != nil {
				t.Fatal(err)
			}
			var err error
			switch name {
			case "duplicate":
				err = consume(c, r.Rows[0])
			case "missing":
				err = c.Finish()
			case "reordered":
				err = consume(c, r.Rows[2])
			default:
				row := r.Rows[1]
				switch name {
				case "wrong-assertion":
					row.Assertion = "not-tested"
				case "wrong-hash":
					row.Hash = "wrong"
				case "wrong-disposition":
					row.Disposition = "obsolete"
				}
				err = consume(c, row)
			}
			if err == nil {
				t.Fatal("bad consumption accepted")
			}
		})
	}
}

func TestSupportingEvidenceStillNamesRealTests(t *testing.T) {
	m, _ := load(t)
	for _, evidence := range m.SupportingEvidence {
		for _, ref := range evidence.Tests {
			path, name, ok := strings.Cut(ref, "#")
			if !ok {
				t.Fatal("invalid test reference", ref)
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("../..", path), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			var tests []string
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Type.Params.NumFields() == 1 {
					tests = append(tests, fn.Name.Name)
				}
			}
			if !slices.Contains(tests, name) {
				t.Fatal("supporting test was removed or renamed", ref)
			}
		}
	}
}

func TestCoverageRequiresCompletedNativeAssertions(t *testing.T) {
	m, traces := load(t)
	r, err := Build(m, traces)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range r.Rows {
		if row.Status == "pending #107" || row.Seq == 0 {
			c := NewCursor([]Row{row})
			if _, err := c.Receipt(); err == nil {
				t.Fatal("incomplete cursor earned receipt")
			}
			if err := c.Consume(row.Hash, row.Seq, row.Disposition, row.Assertion); err != nil {
				t.Fatal(err)
			}
			receipt, err := c.Receipt()
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Cover(receipt); err == nil {
				t.Fatal("pending or generic accounting earned native coverage")
			}
		}
	}
	// Synthetic assertion receipt exercises progress accounting, without
	// crediting any real fixture. A replay supplies this only after its checks.
	row := Row{Hash: "synthetic", Seq: 0, Trace: "synthetic", Kind: "output:api", Disposition: "unchanged", Assertion: "synthetic_test.go#TestNative", Status: "uncovered"}
	r = Report{Rows: []Row{row}, Counts: Counts{Consumed: 1, Uncovered: 1, ByKind: map[string]int{row.Kind: 1}, ByTrace: map[string]int{row.Trace: 1}}}
	c := NewCursor(r.Rows)
	if err := c.Consume(row.Hash, row.Seq, row.Disposition, row.Assertion); err != nil {
		t.Fatal(err)
	}
	receipt, err := c.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Cover(receipt, receipt); err == nil {
		t.Fatal("duplicate receipts accepted")
	}
	if r.Counts.Uncovered != 1 {
		t.Fatal("failed receipt changed coverage")
	}
	if err := r.Cover(receipt); err != nil {
		t.Fatal(err)
	}
	if r.Counts.Covered != 1 || r.Counts.Uncovered != 0 || r.Counts.ByKind[row.Kind] != 0 || r.Counts.ByTrace[row.Trace] != 0 {
		t.Fatal(r.Counts)
	}
	if err := r.Cover(receipt); err == nil {
		t.Fatal("receipt counted twice")
	}
	row.Group, row.Disposition = "synthetic-revision", "atomic-revision"
	second := row
	second.Seq = 1
	r.Rows = []Row{row, second}
	c = NewCursor([]Row{row})
	if err := c.Consume(row.Hash, row.Seq, row.Disposition, row.Assertion); err != nil {
		t.Fatal(err)
	}
	receipt, err = c.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Cover(receipt); err == nil || !strings.Contains(err.Error(), "incomplete group receipt") {
		t.Fatal("partial atomic revision earned coverage", err)
	}
}
