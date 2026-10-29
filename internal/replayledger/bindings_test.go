package replayledger

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

const consumeIdentity = "internal/replayledger/bindings_test.go#TestConsumeIdentity"

// Keep the literal binding independent of this declaration: renaming the test
// must fail Consume, rather than silently changing its expected identity.
func TestConsumeIdentity(t *testing.T) {
	row := Row{Hash: "synthetic", Seq: 0, Disposition: "unchanged", Assertion: consumeIdentity, Status: "uncovered"}
	c := NewCursor([]Row{row})
	if err := c.Consume(t, row.Hash, row.Seq, row.Disposition); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
}

// This independently verifies the source target so deleting TestConsumeIdentity
// cannot silently remove its runtime identity check from the suite.
func TestBindingTargets(t *testing.T) {
	m := Mapping{Annotations: []Annotation{{Assertion: consumeIdentity, Status: "uncovered"}}}
	if err := ValidateReferences(m, readTestSource); err != nil {
		t.Fatal(err)
	}
}

func TestReferenceValidation(t *testing.T) {
	ref := "internal/example/replay_test.go#TestReplay/subtest"
	valid := `package example; import "testing"; func TestReplay(t *testing.T) {}`
	for _, tc := range []struct {
		name, source, status string
		missing              bool
		extra                string
		want                 bool
	}{
		{name: "valid-subtest", source: valid, status: "uncovered", want: true},
		{name: "pending-missing", status: "pending #245", missing: true, want: true},
		{name: "nonpending-missing", status: "uncovered", missing: true},
		{name: "mixed-pending-missing", status: "pending #245", missing: true, extra: "uncovered"},
		{name: "deleted-test", source: `package example`, status: "uncovered"},
		{name: "present-wrong-signature-even-pending", source: `package example; func TestReplay(t int) {}`, status: "pending #245"},
		{name: "testing-value", source: `package example; import "testing"; func TestReplay(t testing.T) {}`, status: "uncovered"},
		{name: "result", source: `package example; import "testing"; func TestReplay(t *testing.T) int { return 0 }`, status: "uncovered"},
		{name: "alias", source: `package example; import check "testing"; func TestReplay(t *check.T) {}`, status: "uncovered", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Mapping{Annotations: []Annotation{{Assertion: ref, Status: tc.status}}}
			if tc.extra != "" {
				m.Annotations = append(m.Annotations, Annotation{Assertion: strings.TrimSuffix(ref, "subtest") + "other", Status: tc.extra})
			}
			err := ValidateReferences(m, func(file string) (*ast.File, error) {
				if tc.missing {
					return nil, fs.ErrNotExist
				}
				return parser.ParseFile(token.NewFileSet(), file, tc.source, 0)
			})
			if (err == nil) != tc.want {
				t.Fatalf("valid=%v: %v", tc.want, err)
			}
		})
	}
	for _, ref := range []string{"does_not_exist_test.go#Nope", "foo_test.go#Testlower", "../foo_test.go#TestReplay", "foo.go#TestReplay"} {
		if testReference(ref) {
			t.Fatal("invalid reference accepted", ref)
		}
	}
}

func TestRangesAndRuleBindings(t *testing.T) {
	m, traces := load(t)
	hash := m.Annotations[0].Hash
	// A per-trace binding covers this rule's kinds without listing sequences.
	m.Rules[3].Bindings = map[string]Binding{hash: {Test: consumeIdentity}}
	r, err := Build(m, traces)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range r.Rows {
		if row.Hash == hash && row.Kind == "input:completion" {
			if row.Assertion != consumeIdentity {
				t.Fatal(row)
			}
			count++
		}
	}
	if count != 85 {
		t.Fatal("completion binding count", count)
	}
	// Ranges are inclusive and duplicates with explicit seqs still fail.
	a := Annotation{Hash: hash, Ranges: [][2]int{{0, 134}}, Disposition: "translated", Assertion: consumeIdentity, Status: "uncovered"}
	m.Annotations = append(m.Annotations, a)
	r, err = Build(m, traces)
	if err != nil {
		t.Fatal(err)
	}
	count = 0
	for _, row := range r.Rows {
		if row.Hash == hash && row.Seq <= 134 && row.Assertion == consumeIdentity {
			count++
		}
	}
	if count != 135 {
		t.Fatal("range coverage", count)
	}
	m.Annotations[len(m.Annotations)-1].Seqs = []int{0}
	if _, err := Build(m, traces); err == nil || !strings.Contains(err.Error(), "duplicate disposition") {
		t.Fatal("range overlap accepted", err)
	}
	for _, span := range [][2]int{{-1, 0}, {2, 1}, {0, 211}} {
		if _, err := sequences(Annotation{Ranges: [][2]int{span}}, 211); err == nil {
			t.Fatal("bad range", span)
		}
	}
}

func TestPendingCountsPerPR(t *testing.T) {
	m, traces := load(t)
	m.Annotations[0].Status = "pending #245"
	r, err := Build(m, traces)
	if err != nil {
		t.Fatal(err)
	}
	if r.Counts.Pending["#245"] != 5 || r.Counts.Pending["#107"] != 18 {
		t.Fatal(r.Counts.Pending)
	}
}

func TestMappingOSScopes(t *testing.T) {
	m, traces := load(t)
	hash := m.Annotations[0].Hash
	m.Rules[3].Bindings = map[string]Binding{hash: {Test: consumeIdentity, OS: "windows"}}
	r, err := Build(m, traces)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range r.Rows {
		if row.Hash == hash && row.Kind == "input:completion" && row.OS != "windows" {
			t.Fatal("lost OS binding", row)
		}
	}
	m.Rules[3].Bindings[hash] = Binding{Test: consumeIdentity, OS: "windwos"}
	if _, err := Build(m, traces); err == nil {
		t.Fatal("typo in OS binding accepted")
	}
	m, traces = load(t)
	m.Annotations[0].OS = "windwos"
	if _, err := Build(m, traces); err == nil {
		t.Fatal("typo in annotation OS accepted")
	}
	m, traces = load(t)
	a := m.Annotations[1]
	a.Seqs = []int{a.Seqs[0]}
	a.OS = "windows"
	m.Annotations[1].Seqs = m.Annotations[1].Seqs[1:]
	m.Annotations = append(m.Annotations, a)
	if _, err := Build(m, traces); err == nil {
		t.Fatal("atomic revision split across OS jobs")
	}
}

func TestAppLineWorkedBindings(t *testing.T) {
	m, traces := load(t)
	hash := m.Annotations[0].Hash
	for i := range m.Rules {
		m.Rules[i].Bindings = map[string]Binding{hash: {Test: consumeIdentity}}
	}
	r, err := Build(m, traces)
	if err != nil {
		t.Fatal(err)
	}
	registered, pending := 0, 0
	for _, row := range r.Rows {
		if row.Hash != hash {
			if row.Assertion == consumeIdentity {
				t.Fatal("binding escaped its trace")
			}
			continue
		}
		if row.Assertion == consumeIdentity {
			registered++
		} else if row.Status == "pending #107" {
			pending++
		} else {
			t.Fatal("unassigned worked-example row", row)
		}
	}
	if registered != 188 || pending != 23 {
		t.Fatal("worked mapping counts", registered, pending)
	}
}
