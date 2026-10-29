package replayledger

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

const ReceiptPrefix = "REPLAY_RECEIPT "

// Cursor accepts only the executing test's rows, in original sequence order.
// Select rows from Build's result; never sort them by kind or effect.
type Cursor struct {
	rows  []Row
	next  int
	err   error
	owner *testing.T
}

func NewCursor(rows []Row) *Cursor {
	c := &Cursor{rows: slices.Clone(rows)}
	seen := map[string]bool{}
	for i, row := range c.rows {
		if i == 0 || c.rows[i-1].Hash != row.Hash {
			if seen[row.Hash] {
				c.err = fmt.Errorf("repeated trace block %s", row.Trace)
				break
			}
			seen[row.Hash] = true
		} else if c.rows[i-1].Seq >= row.Seq {
			c.err = fmt.Errorf("duplicate or reordered cursor rows in %s", row.Trace)
			break
		}
	}
	return c
}

func (c *Cursor) Consume(t *testing.T, hash string, seq int, disposition string) error {
	if t.Failed() {
		return fmt.Errorf("failed test cannot consume replay entries: %s", t.Name())
	}
	if c.err != nil {
		return c.err
	}
	if c.owner != nil && c.owner != t {
		return fmt.Errorf("cursor belongs to a different test")
	}
	if c.next == len(c.rows) {
		return fmt.Errorf("duplicate disposition after end")
	}
	want := c.rows[c.next]
	_, name, _, valid := splitReference(want.Assertion)
	if want.Hash != hash || want.Seq != seq || want.Disposition != disposition || !valid || name != t.Name() || want.Status != "uncovered" {
		return fmt.Errorf("test identity or disposition mismatch: want %s:%d %s %s (%s), got %s:%d %s %s", want.Trace, want.Seq, want.Disposition, want.Assertion, want.Status, hash, seq, disposition, t.Name())
	}
	c.owner = t
	c.next++
	return nil
}

func (c *Cursor) Finish() error {
	if c.err != nil {
		return c.err
	}
	if c.next != len(c.rows) {
		return fmt.Errorf("missing dispositions: consumed %d of %d", c.next, len(c.rows))
	}
	return nil
}

// WireReceipt is emitted once per assertion/hash/atomic group. Sequences are
// generated from checked rows, not manually maintained copies of fixtures.
type WireReceipt struct {
	Version   int    `json:"version"`
	Assertion string `json:"assertion"`
	Hash      string `json:"hash"`
	Group     string `json:"group,omitempty"`
	Seqs      []int  `json:"seqs"`
}

// Receipt logs evidence only after all checks have passed. A later failure is
// caught by Aggregate's terminal test AND package results, including cleanup.
func (c *Cursor) Receipt(t *testing.T) error {
	if t.Failed() {
		return fmt.Errorf("failed test cannot emit a replay receipt: %s", t.Name())
	}
	if err := c.Finish(); err != nil {
		return err
	}
	if c.owner != t || len(c.rows) == 0 {
		return fmt.Errorf("receipt has no executing test")
	}
	var receipts []WireReceipt
	for _, row := range c.rows {
		_, name, _, valid := splitReference(row.Assertion)
		if !valid || name != t.Name() {
			return fmt.Errorf("receipt test identity mismatch: %s != %s", t.Name(), row.Assertion)
		}
		i := slices.IndexFunc(receipts, func(r WireReceipt) bool { return r.Hash == row.Hash && r.Group == row.Group })
		if i < 0 {
			receipts = append(receipts, WireReceipt{Version: 1, Assertion: row.Assertion, Hash: row.Hash, Group: row.Group})
			i = len(receipts) - 1
		}
		receipts[i].Seqs = append(receipts[i].Seqs, row.Seq)
	}
	for _, receipt := range receipts {
		b, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		t.Log(ReceiptPrefix + string(b))
	}
	return nil
}

// cover is deliberately private. Only Aggregate may turn wire evidence into
// coverage after validating go test's package and test outcomes.
func (r *Report) cover(receipts []WireReceipt, goos string) error {
	type key struct {
		hash string
		seq  int
	}
	index := map[key]int{}
	for i, row := range r.Rows {
		index[key{row.Hash, row.Seq}] = i
	}
	selected := map[int]bool{}
	for _, receipt := range receipts {
		if receipt.Version != 1 || len(receipt.Seqs) == 0 {
			return fmt.Errorf("empty or unsupported receipt")
		}
		previous := -1
		for _, seq := range receipt.Seqs {
			i, ok := index[key{receipt.Hash, seq}]
			if !ok || selected[i] || seq <= previous {
				return fmt.Errorf("unknown, duplicate or reordered receipt entry %s:%d", receipt.Hash, seq)
			}
			row := r.Rows[i]
			if row.OS != "" && row.OS != goos {
				return fmt.Errorf("receipt for %s:%d is scoped to %s, not %s", row.Trace, seq, row.OS, goos)
			}
			if row.Assertion != receipt.Assertion || row.Status != "uncovered" || row.Group != receipt.Group || !testReference(row.Assertion) {
				return fmt.Errorf("unearned or stale receipt for %s:%d", row.Trace, seq)
			}
			selected[i] = true
			previous = seq
		}
	}
	groups := map[string]bool{}
	for i := range selected {
		if r.Rows[i].Group != "" {
			groups[r.Rows[i].Group] = true
		}
	}
	for i, row := range r.Rows {
		if groups[row.Group] && !selected[i] {
			return fmt.Errorf("incomplete group receipt: %s", row.Group)
		}
	}
	missing := 0
	var first Row
	for i, row := range r.Rows {
		if row.Status == "uncovered" && testReference(row.Assertion) && (row.OS == "" || row.OS == goos) && !selected[i] {
			if missing == 0 {
				first = row
			}
			missing++
		}
	}
	if missing != 0 {
		return fmt.Errorf("missing required receipts for %d registered entries on %s; first %s:%d (%s)", missing, goos, first.Trace, first.Seq, first.Assertion)
	}
	for i := range selected {
		row := &r.Rows[i]
		row.Status = "covered"
		r.Counts.Covered++
		r.Counts.Uncovered--
		r.Counts.ByKind[row.Kind]--
		r.Counts.ByTrace[row.Trace]--
	}
	return nil
}
