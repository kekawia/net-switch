package ownerbpf

import (
	"errors"
	"testing"
)

func counters() [3]CounterSample {
	return [3]CounterSample{{ProgramID: 1, Present: true}, {ProgramID: 2, Present: true}, {ProgramID: 3, Present: true}}
}

func TestBurstRejectsRecursionAndStaysPoisoned(t *testing.T) {
	for program := range 3 {
		before := counters()
		g, err := NewBurstGuard(before)
		if err != nil {
			t.Fatal(err)
		}
		if !g.Certify(before, nil) {
			t.Fatal("healthy control rejected")
		}
		after := before
		after[program].Misses++
		if g.Certify(after, nil) {
			t.Fatalf("program %d miss accepted", program)
		}
		if g.Certify(after, nil) || g.Certify(before, nil) {
			t.Fatal("poison cleared without reload")
		}
	}
}

func TestBurstReadersDoNotConsumeEachOthersMisses(t *testing.T) {
	before := counters()
	a, err := NewBurstGuard(before)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBurstGuard(before)
	if err != nil {
		t.Fatal(err)
	}
	after := before
	after[0].Misses = 1
	if a.Certify(after, nil) || b.Certify(after, nil) {
		t.Fatal("one reader hid another reader's skip")
	}
}

func TestBurstCounterFailures(t *testing.T) {
	for _, kind := range []string{"missing", "replacement", "decrease", "error"} {
		t.Run(kind, func(t *testing.T) {
			before := counters()
			before[0].Misses = 9
			g, err := NewBurstGuard(before)
			if err != nil {
				t.Fatal(err)
			}
			after := before
			var queryErr error
			switch kind {
			case "missing":
				after[0].Present = false
			case "replacement":
				after[0].ProgramID = 12
			case "decrease":
				after[0].Misses = 8
			case "error":
				queryErr = errors.New("get-info denied")
			}
			if g.Certify(after, queryErr) {
				t.Fatal("invalid sample accepted")
			}
		})
	}
	bad := counters()
	bad[1].Present = false
	if _, err := NewBurstGuard(bad); err == nil {
		t.Fatal("absent field treated as zero")
	}
}

func TestBurstStaleEvidenceMutationModel(t *testing.T) {
	b, reg, slot := validRead()
	// A syntactically valid stale record cannot be recognized by ABI checks.
	stale := CheckRead(b, reg, slot, 64, nil, 0)
	if stale.Status != ReadCookie {
		t.Fatal("mutation precondition: stale ABI record not accepted")
	}
	before := counters()
	after := before
	after[0].Misses++ // Y capture suppressed
	after[2].Misses++ // X terminal suppressed
	g, err := NewBurstGuard(before)
	if err != nil {
		t.Fatal(err)
	}
	if g.Certify(after, nil) {
		t.Fatal("stale evidence passed burst guard")
	}
	// Mutant omits Certify: CheckRead alone returns the stale cookie above.
	t.Log("BURST_MODEL stale_without_postcheck=accepted stale_with_postcheck=refused kernel_proof=false")
}
