package ownerbpf

import (
	"errors"
	"reflect"
	"testing"
)

func validRead() (ReadBinding, ReaderRegistration, ReaderSlot) {
	b := ReadBinding{Slot: 2, Ifindex: 7, NetNS: 42, Registration: 11, Epoch: 13, Sequence: 17}
	r := ReaderRegistration{Slot: 2, Ifindex: 7, NetNS: 42, Flags: ReaderStamped,
		Generation: 11, Epoch: 13, StartBoottime: 123456789}
	s := ReaderSlot{
		Control:    ReadControl{ABI: ProvenanceABI, Registration: 11, Epoch: 13, Sequence: 17, Armed: 0},
		Completion: ReadCompletion{Count: 1, Sequence: 17, Registration: 11, Terminal: TerminalConsume, Status: PacketCaptured},
		Packet: PacketRecord{ABI: ProvenanceABI, Status: PacketCaptured, Epoch: 13,
			Ifindex: 7, NetNS: 42, CPU: 3, Serial: 19, Cookie: 23, Length: 64, Users: 1},
	}
	return b, r, s
}

func TestProvenanceReadDecision(t *testing.T) {
	b, r, s := validRead()
	got := CheckRead(b, r, s, 64, nil, 0)
	if got.Status != ReadCookie || got.Rebuild || got.Packet != s.Packet {
		t.Fatalf("valid consume did not return copied cookie evidence: %+v", got)
	}
	// A later slot overwrite cannot change the already returned envelope.
	s.Packet.Cookie++
	if got.Packet.Cookie != 23 {
		t.Fatal("decision retained mutable slot evidence")
	}
	// CPU numbers need not be dense: the bound is on online CPU count.
	s.Packet.CPU = 1024
	if CheckRead(b, r, s, 64, nil, 0).Status != ReadCookie {
		t.Fatal("sparse CPU identifier confused with online CPU count")
	}
	// Truncation is a normalization concern, not a different packet identity.
	if CheckRead(b, r, s, 32, nil, 0).Status != ReadCookie {
		t.Fatal("positive truncated read lost its packet provenance")
	}
	t.Log("PROVENANCE positive_consume=pass copied_evidence=pass complete_identity=unimplemented")
}

func TestProvenanceDisarmBeforeCopy(t *testing.T) {
	b, r, base := validRead()
	bgPacket := base.Packet
	bgPacket.Serial = 99
	bgPacket.Cookie = 999

	// Simulate softirq terminal(skb, NS_TERMINAL_FREE) on the reader's CPU (bridge.c:240-266):
	// it mutates the slot iff Control.Armed == 1.
	softirqFree := func(live *ReaderSlot) {
		if live.Control.Armed != 1 {
			return
		}
		live.Completion.Count++
		live.Completion.Sequence = live.Control.Sequence
		live.Completion.Registration = live.Control.Registration
		live.Completion.Terminal = TerminalFree
		live.Completion.Status = bgPacket.Status
		live.Packet = bgPacket
	}

	// 1. Old buggy ordering (copy Completion, softirq fires before copy Packet, then disarm):
	// produces a torn snapshot with Count=1, Terminal=TerminalConsume, and the background
	// packet's Cookie=999.
	liveBuggy := base
	liveBuggy.Control.Armed = 1
	var tornSnapshot ReaderSlot
	tornSnapshot.Control = liveBuggy.Control
	tornSnapshot.Completion = liveBuggy.Completion
	softirqFree(&liveBuggy)
	tornSnapshot.Packet = liveBuggy.Packet
	liveBuggy.Control.Armed = 0
	// First, CheckRead rejects any snapshot taken while Armed == 1.
	if got := CheckRead(b, r, tornSnapshot, 64, nil, 0); got.Status != ReadInvalid || !got.Rebuild {
		t.Fatalf("undisarmed snapshot was not rejected: %+v", got)
	}
	// And if Armed were cleared on the torn snapshot, the torn copy would have
	// attributed the read to bgPacket.Cookie (999) instead of 23.
	tornDisarmed := tornSnapshot
	tornDisarmed.Control.Armed = 0
	if got := CheckRead(b, r, tornDisarmed, 64, nil, 0); got.Status != ReadCookie || got.Packet.Cookie != bgPacket.Cookie {
		t.Fatalf("expected torn copy-before-disarm model to demonstrate wrong cookie %d, got %+v", bgPacket.Cookie, got)
	}

	// 2. Fixed ordering (disarm Armed=0 first, then copy) when softirq fires DURING the copy:
	// because Armed is already 0, softirqFree is a no-op and the consumed packet (Cookie=23) is preserved.
	liveFixedAfter := base
	liveFixedAfter.Control.Armed = 1
	liveFixedAfter.Control.Armed = 0
	var snapAfter ReaderSlot
	snapAfter.Control = liveFixedAfter.Control
	snapAfter.Completion = liveFixedAfter.Completion
	softirqFree(&liveFixedAfter)
	snapAfter.Packet = liveFixedAfter.Packet
	if got := CheckRead(b, r, snapAfter, 64, nil, 0); got.Status != ReadCookie || got.Rebuild || got.Packet.Cookie != 23 {
		t.Fatalf("disarm-before-copy with later softirq failed: %+v", got)
	}

	// 3. Fixed ordering when softirq fires BEFORE disarm Armed=0:
	// softirq increments Count to 2 and overwrites Terminal/Packet before the copy begins,
	// so the disarmed copy observes Count=2 and CheckRead refuses with ReadAmbiguous.
	liveFixedBefore := base
	liveFixedBefore.Control.Armed = 1
	softirqFree(&liveFixedBefore)
	liveFixedBefore.Control.Armed = 0
	snapBefore := liveFixedBefore
	if got := CheckRead(b, r, snapBefore, 64, nil, 0); got.Status != ReadAmbiguous || got.Rebuild || got.Packet != (PacketRecord{}) {
		t.Fatalf("disarm-before-copy with earlier softirq did not refuse as ReadAmbiguous: %+v", got)
	}
	t.Log("PROVENANCE disarm_before_copy=pass earlier_softirq=ambiguous later_softirq=ignored")
}

func TestProvenanceRejectsUnboundEvidence(t *testing.T) {
	// Mutate each required binding/ABI field independently while all other evidence is valid.
	cases := []struct{ part, field string }{
		{"binding", "Slot"}, {"binding", "Ifindex"}, {"binding", "NetNS"},
		{"binding", "Registration"}, {"binding", "Epoch"}, {"binding", "Sequence"},
		{"registration", "Slot"}, {"registration", "Ifindex"}, {"registration", "NetNS"},
		{"registration", "Flags"}, {"registration", "Generation"}, {"registration", "Epoch"},
		{"registration", "StampGuard"},
		{"control", "ABI"}, {"control", "Reserved"}, {"control", "Registration"},
		{"control", "Epoch"}, {"control", "Sequence"}, {"control", "Armed"},
		{"completion", "Sequence"}, {"completion", "Registration"}, {"completion", "Status"},
		{"packet", "ABI"}, {"packet", "Status"}, {"packet", "Epoch"},
		{"packet", "Ifindex"}, {"packet", "NetNS"},
		{"packet", "OwnerVersion"}, {"packet", "Identity"},
	}
	for _, tc := range cases {
		t.Run(tc.part+"/"+tc.field, func(t *testing.T) {
			b, r, s := validRead()
			parts := map[string]any{"binding": &b, "registration": &r, "control": &s.Control,
				"completion": &s.Completion, "packet": &s.Packet}
			f := reflect.ValueOf(parts[tc.part]).Elem().FieldByName(tc.field)
			f.SetUint(f.Uint() + 1)
			got := CheckRead(b, r, s, 64, nil, 0)
			if got.Status != ReadInvalid || !got.Rebuild || got.Packet != (PacketRecord{}) {
				t.Fatalf("mismatched %s.%s accepted or evidence leaked: %+v", tc.part, tc.field, got)
			}
		})
	}
	for _, field := range []string{"Serial", "Length", "Users"} {
		t.Run("zero/"+field, func(t *testing.T) {
			b, r, s := validRead()
			reflect.ValueOf(&s.Packet).Elem().FieldByName(field).SetUint(0)
			if got := CheckRead(b, r, s, 64, nil, 0); got.Status != ReadInvalid || !got.Rebuild || got.Packet != (PacketRecord{}) {
				t.Fatalf("zero %s accepted: %+v", field, got)
			}
		})
	}
	// Cookie-less (Cookie == 0) and shared (Users > 1) packets are per-packet
	// unknown outcomes (ReadUnknown, Rebuild=false), not epoch-stopping faults.
	for _, tc := range []struct {
		name   string
		mutate func(*ReaderSlot)
	}{
		{"cookie_missing_status_zero", func(s *ReaderSlot) {
			s.Packet.Cookie = 0
			s.Packet.Status = 0
			s.Completion.Status = 0
		}},
		{"cookie_missing_status_captured", func(s *ReaderSlot) {
			s.Packet.Cookie = 0
		}},
		{"shared_users_2_status_zero", func(s *ReaderSlot) {
			s.Packet.Users = 2
			s.Packet.Status = 0
			s.Completion.Status = 0
		}},
		{"shared_users_2_status_captured", func(s *ReaderSlot) {
			s.Packet.Users = 2
		}},
	} {
		t.Run("unknown/"+tc.name, func(t *testing.T) {
			b, r, s := validRead()
			tc.mutate(&s)
			got := CheckRead(b, r, s, 64, nil, 0)
			if got.Status != ReadUnknown || got.Rebuild || got.Packet != (PacketRecord{}) {
				t.Fatalf("%s: got %+v, want status=%s rebuild=false empty packet", tc.name, got, ReadUnknown)
			}
		})
	}
	b, r, s := validRead()
	r.StartBoottime = 0
	if CheckRead(b, r, s, 64, nil, 0).Status != ReadInvalid {
		t.Fatal("unstamped reader accepted")
	}
	for i := 0; i < 3; i++ {
		b, r, s := validRead()
		switch i {
		case 0:
			s.Control.Padding[23] = 1
		case 1:
			s.Completion.Padding[31] = 1
		case 2:
			s.Packet.Reserved[55] = 1
		}
		if CheckRead(b, r, s, 64, nil, 0).Status != ReadInvalid {
			t.Fatalf("reserved bytes accepted in block %d", i)
		}
	}
	t.Logf("PROVENANCE independently_mutated_binding_fields=%d rejected=all", len(cases))
}

func TestProvenanceTerminalAndHealth(t *testing.T) {
	for _, tc := range []struct {
		name     string
		count    uint64
		terminal uint32
		n        int
		err      error
		faults   uint64
		status   ReadStatus
		rebuild  bool
	}{
		{"capture_or_publication_missing", 0, 0, 64, nil, 0, ReadMissing, true},
		{"sole_free", 1, TerminalFree, 64, nil, 0, ReadAmbiguous, false},
		{"nested_free_then_consume", 2, TerminalConsume, 64, nil, 0, ReadAmbiguous, false},
		{"nested_consume_then_free", 2, TerminalFree, 64, nil, 0, ReadAmbiguous, false},
		{"two_consumes", 2, TerminalConsume, 64, nil, 0, ReadAmbiguous, false},
		{"empty", 0, 0, -1, errors.New("EAGAIN"), 0, ReadNoData, false},
		{"interrupted", 0, 0, -1, errors.New("EINTR"), 0, ReadNoData, false},
		{"zero_read", 0, 0, 0, nil, 0, ReadNoData, false},
		{"copy_fault", 1, TerminalFree, -1, errors.New("EFAULT"), 0, ReadNoData, true},
		{"error_with_consume", 1, TerminalConsume, -1, errors.New("EIO"), 0, ReadNoData, true},
		{"epoch_fault", 1, TerminalConsume, 64, nil, 1, ReadEpochFault, true},
		{"epoch_fault_with_empty", 0, 0, -1, errors.New("EAGAIN"), 2, ReadEpochFault, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, r, s := validRead()
			s.Completion.Count, s.Completion.Terminal = tc.count, tc.terminal
			got := CheckRead(b, r, s, tc.n, tc.err, tc.faults)
			if got.Status != tc.status || got.Rebuild != tc.rebuild || got.Packet != (PacketRecord{}) {
				t.Fatalf("got %+v, want %s rebuild=%v with no evidence", got, tc.status, tc.rebuild)
			}
		})
	}
	t.Log("PROVENANCE missing_free_nested_failed_reads=refused visible_epoch_fault=stop_required")
}

func TestProvenanceSizing(t *testing.T) {
	for _, tc := range []struct{ q, c, r, want uint64 }{
		{500, 512, 4, 2048}, {16384, 512, 4, 32768},
		{475, 512, 4, 1024}, {476, 512, 4, 1024}, {477, 512, 4, 2048},
		{1, 1, 1, 64},
	} {
		got, err := RequiredPacketSlots(tc.q, tc.c, tc.r)
		if err != nil || got != tc.want {
			t.Fatalf("Q=%d C=%d R=%d: got %d/%v want %d", tc.q, tc.c, tc.r, got, err, tc.want)
		}
	}
	for _, in := range [][3]uint64{
		{0, 1, 1}, {500, 0, 1}, {500, 513, 1}, {500, 1, 0}, {500, 1, 5},
		{^uint64(0), 1, 1}, {uint64(1) << 63, 1, 1},
	} {
		if _, err := RequiredPacketSlots(in[0], in[1], in[2]); err == nil {
			t.Fatalf("invalid/overflow capacity accepted: %v", in)
		}
	}
	if err := ValidateProofCapacity(500, 512, 4); err != nil {
		t.Fatal(err)
	}
	if ValidateProofCapacity(16384, 512, 4) == nil {
		t.Fatal("production queue silently admitted with experiment allocation")
	}
	t.Log("PROVENANCE sizing proof_queue=500 slots=2048 production_queue=16384 slots=32768 proof_refuses_production=true")
}

func TestProvenanceGoLayout(t *testing.T) {
	for _, tc := range []struct {
		value   any
		size    uintptr
		offsets []uintptr
	}{
		{PacketRecord{}, 128, []uintptr{0, 4, 8, 16, 20, 24, 28, 32, 40, 48, 52, 56, 64, 72}},
		{ReaderKey{}, 8, []uintptr{0, 4}},
		{ReaderRegistration{}, 48, []uintptr{0, 4, 8, 12, 16, 24, 32, 40}},
		{ReadControl{}, 64, []uintptr{0, 4, 8, 16, 24, 32, 40}},
		{ReadCompletion{}, 64, []uintptr{0, 8, 16, 24, 28, 32}},
		{ReaderSlot{}, 256, []uintptr{0, 64, 128}},
	} {
		typ := reflect.TypeOf(tc.value)
		if typ.Size() != tc.size || typ.NumField() != len(tc.offsets) {
			t.Fatalf("%s: size/field count differs from ABI 3", typ)
		}
		for i, offset := range tc.offsets {
			if f := typ.Field(i); f.Offset != offset {
				t.Errorf("%s.%s offset=%d want=%d", typ, f.Name, f.Offset, offset)
			}
		}
	}
	t.Log("PROVENANCE abi=3 packet=128 registration=48 slot=256 all_go_offsets=pass")
}
