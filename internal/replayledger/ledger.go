// Package replayledger accounts for frozen trace entries without running an
// engine. Accounting is not replay coverage: only an executing native assertion
// may supply a receipt. The checked-in mapping intentionally has no receipts.
package replayledger

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

//go:embed mapping.json
var mappingJSON []byte

type Fixture struct {
	Name    string `json:"name"`
	Entries int    `json:"entries"`
}

type Rule struct {
	Kinds       []string           `json:"kinds"`
	Disposition string             `json:"disposition"`
	Assertion   string             `json:"assertion"`
	Bindings    map[string]Binding `json:"bindings,omitempty"`
}

// An empty OS requires proof on every job. Scoped bindings are only for
// genuinely OS-specific native tests, not exceptions for skipped tests.
type Binding struct {
	Test string `json:"test"`
	OS   string `json:"os,omitempty"`
}

type Annotation struct {
	Hash        string   `json:"hash"`
	Seqs        []int    `json:"seqs"`
	Ranges      [][2]int `json:"ranges,omitempty"`
	Disposition string   `json:"disposition"`
	Assertion   string   `json:"assertion"`
	Status      string   `json:"status"`
	Group       string   `json:"group,omitempty"`
	OS          string   `json:"os,omitempty"`
}

type Group struct {
	Name    string `json:"name"`
	Hash    string `json:"hash"`
	Members []int  `json:"members"`
	Begin   int    `json:"begin"`
	End     int    `json:"end"`
	Ack     int    `json:"ack"`
	// response means the original trace has no separate acknowledgement.
	// Its native owner proves acknowledgement before the actual HTTP return.
	Boundary string `json:"boundary,omitempty"`
}

type Evidence struct {
	PR    int      `json:"pr"`
	Scope string   `json:"scope"`
	Tests []string `json:"tests"`
}

type Mapping struct {
	Version            int                `json:"version"`
	Total              int                `json:"total"`
	Fixtures           map[string]Fixture `json:"fixtures"`
	Rules              []Rule             `json:"rules"`
	Annotations        []Annotation       `json:"annotations"`
	Groups             []Group            `json:"groups"`
	SupportingEvidence []Evidence         `json:"supportingEvidence"`
}

type Entry struct {
	Seq       int             `json:"seq"`
	Direction string          `json:"direction"`
	Kind      string          `json:"kind"`
	Value     json.RawMessage `json:"value"`
}

type Trace struct {
	Version  int     `json:"version"`
	Name     string  `json:"name"`
	Entries  []Entry `json:"entries"`
	Scenario struct {
		Now      *int64 `json:"now"`
		Timezone string `json:"timezone"`
	} `json:"scenario"`
}

// Row is a disposition in original sequence order, never a sorted effect list.
// Assertion names on uncovered rows are obligations, not claims of execution.
type Row struct {
	Hash        string `json:"hash"`
	Trace       string `json:"trace"`
	Seq         int    `json:"seq"`
	Kind        string `json:"kind"`
	Disposition string `json:"disposition"`
	Assertion   string `json:"assertion"`
	Status      string `json:"status"`
	Group       string `json:"group,omitempty"`
	OS          string `json:"os,omitempty"`
}

type Counts struct {
	Consumed      int            `json:"consumed"`
	Covered       int            `json:"covered"`
	Uncovered     int            `json:"uncovered"`
	Pending       map[string]int `json:"pendingByPR"`
	ByDisposition map[string]int `json:"byDisposition"`
	ByKind        map[string]int `json:"uncoveredByKind"`
	ByTrace       map[string]int `json:"uncoveredByTrace"`
}

type Report struct {
	Version int    `json:"version"`
	Counts  Counts `json:"counts"`
	Rows    []Row  `json:"rows"`
}

func DefaultMapping() (Mapping, error) {
	var m Mapping
	d := json.NewDecoder(bytes.NewReader(mappingJSON))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return m, fmt.Errorf("trailing mapping JSON")
	}
	return m, nil
}

// Load reads only the existing oracle paths. Both the mapping and the frozen
// provenance sidecar must agree with the actual byte hashes and fixture set.
func Load(root string, m Mapping) (map[string]Trace, error) {
	var provenance struct {
		Version  int
		Fixtures map[string]struct{ SHA256 string }
	}
	b, err := os.ReadFile(filepath.Join(root, "tests/oracle/provenance.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &provenance); err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(root, "tests/oracle/fixtures/*.trace.json"))
	if err != nil {
		return nil, err
	}
	if provenance.Version != 1 || len(files) != 25 || len(m.Fixtures) != len(files) || len(provenance.Fixtures) != len(files) {
		return nil, fmt.Errorf("fixture set must contain exactly 25 traces")
	}
	traces := make(map[string]Trace)
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		hash := fmt.Sprintf("%x", sha256.Sum256(b))
		f, ok := m.Fixtures[hash]
		if !ok {
			return nil, fmt.Errorf("fixture hash mismatch: %s (%s)", path, hash)
		}
		if filepath.Base(path) != f.Name+".trace.json" || provenance.Fixtures[f.Name].SHA256 != hash {
			return nil, fmt.Errorf("fixture identity/provenance mismatch: %s", path)
		}
		var trace Trace
		if err := json.Unmarshal(b, &trace); err != nil {
			return nil, err
		}
		if _, exists := traces[hash]; exists {
			return nil, fmt.Errorf("duplicate fixture %s", hash)
		}
		traces[hash] = trace
	}
	return traces, nil
}

// This whitelist is independent of the mapping, and deliberately excludes exit:
// the contract names it but none of the frozen traces implements its semantics.
func known(kind string) bool {
	const input = " initial-files http helper-line interfaces connections probes adapter-snapshot counter-sample engine-reply probe-result clock-tick file-completion completion async-result socket-completion process-exit timer-completion routes connectionsStatus update-reply release updateStatus quitFailure adapters refresh-adapters directory-list probe-vote state-snapshot "
	const output = " api event engine spawn write remove outside-close log console "
	p := strings.Split(kind, ":")
	if len(p) != 2 {
		return false
	}
	return p[0] == "input" && strings.Contains(input, " "+p[1]+" ") || p[0] == "output" && strings.Contains(output, " "+p[1]+" ")
}

func validDisposition(disposition, assertion string) bool {
	return strings.TrimSpace(assertion) != "" && slices.Contains([]string{"unchanged", "translated", "atomic-revision", "obsolete"}, disposition)
}

var pendingStatus = regexp.MustCompile(`^pending #[1-9][0-9]*$`)

func validOS(goos string) bool { return goos == "" || goos == "windows" || goos == "linux" }

func sequences(a Annotation, count int) ([]int, error) {
	seqs := slices.Clone(a.Seqs)
	for _, span := range a.Ranges {
		if span[0] < 0 || span[1] < span[0] || span[1] >= count {
			return nil, fmt.Errorf("invalid annotation range %v", span)
		}
		for seq := span[0]; seq <= span[1]; seq++ {
			seqs = append(seqs, seq)
		}
	}
	return seqs, nil
}

// Build validates and expands the compact plan. It does NOT execute native
// behavior or promote supporting feature tests into entry coverage.
func Build(m Mapping, traces map[string]Trace) (Report, error) {
	r := Report{Version: m.Version, Counts: Counts{
		ByDisposition: map[string]int{"unchanged": 0, "translated": 0, "atomic-revision": 0, "obsolete": 0},
		ByKind:        map[string]int{}, ByTrace: map[string]int{},
		Pending: map[string]int{},
	}}
	if (m.Version != 1 && m.Version != 2) || m.Total != 7894 || len(m.Fixtures) != 25 || len(traces) != 25 {
		return r, fmt.Errorf("unsupported mapping version or fixture inventory")
	}
	rules := map[string]Rule{}
	for _, rule := range m.Rules {
		if !validDisposition(rule.Disposition, rule.Assertion) || testReference(rule.Assertion) || rule.Disposition == "atomic-revision" || len(rule.Kinds) == 0 {
			return r, fmt.Errorf("invalid generic disposition: %+v", rule)
		}
		for hash, binding := range rule.Bindings {
			if _, ok := m.Fixtures[hash]; !ok || !testReference(binding.Test) || !validOS(binding.OS) {
				return r, fmt.Errorf("invalid rule test binding %+v", binding)
			}
		}
		for _, kind := range rule.Kinds {
			if !known(kind) {
				return r, fmt.Errorf("unknown kind %s", kind)
			}
			if _, ok := rules[kind]; ok {
				return r, fmt.Errorf("duplicate disposition rule for %s", kind)
			}
			rules[kind] = rule
		}
	}
	annotations := map[string]map[int]Annotation{}
	for _, a := range m.Annotations {
		f, ok := m.Fixtures[a.Hash]
		seqs, err := sequences(a, f.Entries)
		if err != nil {
			return r, err
		}
		if !ok || len(seqs) == 0 || !validDisposition(a.Disposition, a.Assertion) || !testReference(a.Assertion) || !validOS(a.OS) || !pendingStatus.MatchString(a.Status) && a.Status != "uncovered" {
			return r, fmt.Errorf("invalid annotation: %+v", a)
		}
		if (a.Disposition == "atomic-revision") != (a.Group != "") {
			return r, fmt.Errorf("atomic revision needs a named group")
		}
		if annotations[a.Hash] == nil {
			annotations[a.Hash] = map[int]Annotation{}
		}
		for _, seq := range seqs {
			if seq < 0 || seq >= f.Entries {
				return r, fmt.Errorf("annotation outside trace %s:%d", f.Name, seq)
			}
			if _, ok := annotations[a.Hash][seq]; ok {
				return r, fmt.Errorf("duplicate disposition at %s:%d", f.Name, seq)
			}
			annotations[a.Hash][seq] = a
		}
	}
	if err := validateGroups(m, traces, annotations); err != nil {
		return r, err
	}
	// Sorting traces makes reports reproducible; entries within a trace never move.
	hashes := make([]string, 0, len(m.Fixtures))
	for hash := range m.Fixtures {
		hashes = append(hashes, hash)
	}
	slices.SortFunc(hashes, func(a, b string) int { return strings.Compare(m.Fixtures[a].Name, m.Fixtures[b].Name) })
	for _, hash := range hashes {
		f := m.Fixtures[hash]
		trace, ok := traces[hash]
		if !ok || trace.Version != 1 || trace.Name != f.Name || len(trace.Entries) != f.Entries {
			return r, fmt.Errorf("trace inventory mismatch: %s", f.Name)
		}
		if err := validateBoundaries(trace); err != nil {
			return r, fmt.Errorf("%s: %w", f.Name, err)
		}
		for _, e := range trace.Entries {
			kind := e.Direction + ":" + e.Kind
			rule, ok := rules[kind]
			if !ok {
				return r, fmt.Errorf("missing disposition for %s:%d %s", f.Name, e.Seq, kind)
			}
			row := Row{Hash: hash, Trace: f.Name, Seq: e.Seq, Kind: kind, Disposition: rule.Disposition, Assertion: rule.Assertion, Status: "uncovered"}
			if binding, ok := rule.Bindings[hash]; ok {
				row.Assertion, row.OS = binding.Test, binding.OS
			}
			if a, ok := annotations[hash][e.Seq]; ok {
				row.Disposition, row.Assertion, row.Status, row.Group = a.Disposition, a.Assertion, a.Status, a.Group
				row.OS = a.OS
			}
			r.Rows = append(r.Rows, row)
			r.Counts.Consumed++
			r.Counts.Uncovered++
			r.Counts.ByDisposition[row.Disposition]++
			r.Counts.ByKind[kind]++
			r.Counts.ByTrace[f.Name]++
			if pendingStatus.MatchString(row.Status) {
				r.Counts.Pending[strings.TrimPrefix(row.Status, "pending ")]++
			}
		}
	}
	if r.Counts.Consumed != m.Total {
		return r, fmt.Errorf("consumed %d entries, expected %d", r.Counts.Consumed, m.Total)
	}
	return r, nil
}

func validateGroups(m Mapping, traces map[string]Trace, annotations map[string]map[int]Annotation) error {
	groups := map[string]Group{}
	for _, g := range m.Groups {
		if _, ok := groups[g.Name]; ok || g.Name == "" {
			return fmt.Errorf("duplicate or unnamed group %q", g.Name)
		}
		t, ok := traces[g.Hash]
		if !ok || len(g.Members) == 0 || g.Begin < 0 || g.End >= len(t.Entries) || g.Begin >= g.End {
			return fmt.Errorf("incomplete group %s: invalid boundaries", g.Name)
		}
		limit := g.Ack
		switch g.Boundary {
		case "":
			if g.Begin >= g.Ack || g.Ack >= g.End || t.Entries[g.Ack].Kind != "timer-completion" {
				return fmt.Errorf("incomplete group %s: missing acknowledgement", g.Name)
			}
		case "response":
			if m.Version != 2 || g.Ack != -1 {
				return fmt.Errorf("incomplete group %s: response boundary requires v2 and no ack", g.Name)
			}
			limit = g.End
		default:
			return fmt.Errorf("incomplete group %s: unknown boundary", g.Name)
		}
		if t.Entries[g.Begin].Kind != "http" || t.Entries[g.End].Kind != "api" {
			return fmt.Errorf("incomplete group %s: missing trigger, acknowledgement or publication", g.Name)
		}
		previous := g.Begin
		groupOS := annotations[g.Hash][g.Members[0]].OS
		groupOwner := annotations[g.Hash][g.Members[0]].Assertion
		for _, seq := range g.Members {
			if seq <= previous || seq >= limit {
				return fmt.Errorf("incomplete group %s: unordered members", g.Name)
			}
			a, ok := annotations[g.Hash][seq]
			if !ok || a.Group != g.Name || a.OS != groupOS || a.Assertion != groupOwner || a.Disposition != "atomic-revision" || !ruleWrite(t.Entries[seq]) {
				return fmt.Errorf("incomplete group %s at %d", g.Name, seq)
			}
			previous = seq
		}
		// Omitting a write from BOTH the group and its annotations must not
		// quietly make a smaller transaction look complete. All rule writes in
		// this trigger/response interval belong to the same atomic revision.
		for seq := g.Begin + 1; seq < g.End; seq++ {
			e := t.Entries[seq]
			if g.Boundary == "response" && (e.Kind == "timer-completion" || e.Kind == "state-snapshot") {
				return fmt.Errorf("incomplete group %s: response boundary contains recorded barrier %s at %d", g.Name, e.Kind, seq)
			}
			if e.Kind == "http" || e.Kind == "api" {
				return fmt.Errorf("group %s crosses an unrelated HTTP boundary", g.Name)
			}
			if ruleWrite(e) {
				if !slices.Contains(g.Members, seq) {
					return fmt.Errorf("incomplete group %s: unassigned rule write %d", g.Name, seq)
				}
			}
		}
		groups[g.Name] = g
	}
	for hash, entries := range annotations {
		for seq, a := range entries {
			if a.Group == "" {
				continue
			}
			g, ok := groups[a.Group]
			if !ok || g.Hash != hash || !slices.Contains(g.Members, seq) {
				return fmt.Errorf("incomplete group %s: extra member %d", a.Group, seq)
			}
		}
	}
	return nil
}

func ruleWrite(e Entry) bool {
	if e.Direction != "output" || e.Kind != "write" {
		return false
	}
	var value struct{ File string }
	if json.Unmarshal(e.Value, &value) != nil {
		return false
	}
	base := filepath.Base(value.File)
	return strings.HasPrefix(base, "apps-") || strings.HasPrefix(base, "share-") || strings.HasPrefix(base, "cut-")
}

// Check the ORIGINAL cross-kind stream. Even uncovered replies must have a
// request, and all requests (including /delay) must have exactly one result.
func validateBoundaries(t Trace) error {
	requests := map[string][]int{}
	completion := 0
	httpPending := false
	for i, e := range t.Entries {
		if e.Seq != i {
			return fmt.Errorf("duplicate/missing sequence at %d: got %d", i, e.Seq)
		}
		if !known(e.Direction + ":" + e.Kind) {
			return fmt.Errorf("unknown kind at %d: %s:%s", i, e.Direction, e.Kind)
		}
		if !json.Valid(e.Value) {
			return fmt.Errorf("invalid value at %d", i)
		}
		const completedKinds = " file-completion async-result socket-completion adapter-snapshot counter-sample engine-reply probe-result process-exit timer-completion directory-list probe-vote state-snapshot update-reply "
		if strings.Contains(completedKinds, " "+e.Kind+" ") && (i+1 == len(t.Entries) || t.Entries[i+1].Kind != "completion") {
			return fmt.Errorf("missing completion after %d %s", i, e.Kind)
		}
		var v struct {
			ID          int
			Kind, Route string
		}
		switch e.Kind {
		case "engine", "engine-reply", "probe-result", "completion":
			if err := json.Unmarshal(e.Value, &v); err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
		}
		switch e.Kind {
		case "engine":
			if v.Route == "" {
				return fmt.Errorf("empty engine route at %d", i)
			}
			requests[v.Route] = append(requests[v.Route], i)
		case "engine-reply", "probe-result":
			pending := requests[v.Route]
			if len(pending) == 0 {
				return fmt.Errorf("leftover reply at %d for %s", i, v.Route)
			}
			if strings.HasSuffix(v.Route, "/delay") != (e.Kind == "probe-result") {
				return fmt.Errorf("wrong reply kind at %d", i)
			}
			requests[v.Route] = pending[1:]
		case "completion":
			completion++
			if i == 0 || v.ID != completion || t.Entries[i-1].Direction != "input" || t.Entries[i-1].Kind != v.Kind || v.Kind == "completion" {
				return fmt.Errorf("detached completion at %d", i)
			}
		case "http":
			if httpPending {
				return fmt.Errorf("HTTP input before prior response at %d", i)
			}
			httpPending = true
		case "api":
			if !httpPending {
				return fmt.Errorf("leftover API reply at %d", i)
			}
			httpPending = false
		}
	}
	for route, pending := range requests {
		if len(pending) != 0 {
			return fmt.Errorf("incomplete request group %s: %v", route, pending)
		}
	}
	if httpPending {
		return fmt.Errorf("missing API reply")
	}
	return nil
}
