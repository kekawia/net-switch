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
		if got := g.ChangedMask(after); got != (1 << program) {
			t.Fatalf("program %d ChangedMask = %#b, want %#b", program, got, 1<<program)
		}
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

func TestFloor58BurstGuard(t *testing.T) {
	floorSamples := [3]CounterSample{{ProgramID: 10}, {ProgramID: 20}, {ProgramID: 30}}
	g, err := NewFloor58BurstGuard(floorSamples)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Certify(floorSamples, nil) {
		t.Fatal("valid v5.8 floor sample rejected")
	}
	if _, err := NewFloor58BurstGuard(counters()); err == nil {
		t.Fatal("counter-bearing sample accepted by v5.8 floor constructor")
	}
	replaced := floorSamples
	replaced[1].ProgramID = 99
	if g.Certify(replaced, nil) || g.Certify(floorSamples, nil) {
		t.Fatal("program replacement accepted or poison cleared on v5.8 floor guard")
	}
}

func TestBurstSingleReaderArmedConsumeAndPostDrainRebase(t *testing.T) {
	before := counters()
	before[1].Misses = 4

	// Unarmed/multi-reader Certify still rejects any consume miss.
	strictGuard, err := NewBurstGuard(before)
	if err != nil {
		t.Fatal(err)
	}
	foreignConsume := before
	foreignConsume[1].Misses = 7
	if strictGuard.Certify(foreignConsume, nil) {
		t.Fatal("strict Certify accepted consume miss without single-reader armed TerminalConsume proof")
	}

	// Single-reader armed consume accepts monotonic foreign consume misses when
	// capture and freed are unchanged, and rebases the baseline for later bursts.
	g, err := NewBurstGuard(before)
	if err != nil {
		t.Fatal(err)
	}
	if !g.CertifySingleReaderConsume(foreignConsume, nil) {
		t.Fatal("single-reader armed consume rejected foreign consume_skb recursion miss")
	}
	if !g.Certify(foreignConsume, nil) {
		t.Fatal("rebased baseline rejected unchanged counters on next strict check")
	}

	// Fail-closed cases: capture miss, freed miss, consume decrease, replacement,
	// missing Present, sampleErr, and v5.8 floor profile.
	for _, tc := range []struct {
		name   string
		mutate func(*[3]CounterSample) error
	}{
		{"capture_miss", func(s *[3]CounterSample) error { s[0].Misses++; return nil }},
		{"freed_miss", func(s *[3]CounterSample) error { s[2].Misses++; return nil }},
		{"consume_decrease", func(s *[3]CounterSample) error { s[1].Misses--; return nil }},
		{"consume_replacement", func(s *[3]CounterSample) error { s[1].ProgramID = 77; return nil }},
		{"consume_not_present", func(s *[3]CounterSample) error { s[1].Present = false; return nil }},
		{"sample_error", func(s *[3]CounterSample) error { return errors.New("bpf_obj_get_info_by_fd failed") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := counters()
			base[1].Misses = 5
			guard, err := NewBurstGuard(base)
			if err != nil {
				t.Fatal(err)
			}
			after := base
			sampleErr := tc.mutate(&after)
			if guard.CertifySingleReaderConsume(after, sampleErr) {
				t.Fatalf("%s accepted by CertifySingleReaderConsume", tc.name)
			}
			if guard.CertifySingleReaderConsume(base, nil) || guard.Certify(base, nil) {
				t.Fatalf("%s did not permanently poison guard", tc.name)
			}
		})
	}

	floorSamples := [3]CounterSample{{ProgramID: 10}, {ProgramID: 20}, {ProgramID: 30}}
	fg, err := NewFloor58BurstGuard(floorSamples)
	if err != nil {
		t.Fatal(err)
	}
	if !fg.CertifySingleReaderConsume(floorSamples, nil) {
		t.Fatal("valid v5.8 floor sample rejected by CertifySingleReaderConsume")
	}
	floorDirty := floorSamples
	floorDirty[1].Misses = 1
	if fg.CertifySingleReaderConsume(floorDirty, nil) {
		t.Fatal("non-zero consume miss accepted on v5.8 floor guard")
	}
}
