package ownerbpf

import (
	"runtime"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestProvenanceEnvelopeLifecycleMergeAndGCRetirement(t *testing.T) {
	ledger := NewIdentityLedger(32, 16<<10)
	slots := NewSocketSlotTable(32)
	rt := NewProvenanceRuntime(7, ledger, slots)

	keyA, evA, matA := validProcessFixture()
	keyA.Cookie = 0xa1b2c3
	keyA.TGID = 4100
	matA.Before.TGID = 4100
	matA.After.TGID = 4100
	matA.ExePath = "/opt/Apps/1.4.0/SenderA"
	if snap, reason := rt.EnrichActor(keyA, evA, matA); reason != ReasonValidated || snap == nil {
		t.Fatalf("EnrichActor A failed: snap=%+v reason=%s", snap, reason)
	}

	keyB, evB, matB := validProcessFixture()
	keyB.Cookie = 0xd4e5f6
	keyB.TGID = 4200
	keyB.Start = 99999
	matB.Before.TGID = 4200
	matB.After.TGID = 4200
	matB.Before.StartBoottime = 99999
	matB.After.StartBoottime = 99999
	matB.ExePath = "/usr/bin/SenderB"
	if snap, reason := rt.EnrichActor(keyB, evB, matB); reason != ReasonValidated || snap == nil {
		t.Fatalf("EnrichActor B failed: snap=%+v reason=%s", snap, reason)
	}

	// Release actors and destroy sockets immediately while keeping envelopes alive.
	rt.ReleaseActor(ActorIdentityKey{TGID: keyA.TGID, StartBoottime: keyA.Start, ExecID: keyA.Exec})
	rt.ReleaseActor(ActorIdentityKey{TGID: keyB.TGID, StartBoottime: keyB.Start, ExecID: keyB.Exec})

	// 1. Agreeing fragments with distinct skb CaptureSerials preserve known owner,
	//    keep the slot pinned even after individual fragment references are dropped,
	//    and retire all pins after the reassembled envelope is dropped.
	var reassembled *ProvenanceEnvelope
	func() {
		frag0 := rt.Acquire(ReadDecision{
			Status: ReadCookie,
			Packet: PacketRecord{Epoch: 7, Cookie: 0xa1b2c3, Serial: 101},
		})
		frag1 := rt.Acquire(ReadDecision{
			Status: ReadCookie,
			Packet: PacketRecord{Epoch: 7, Cookie: 0xa1b2c3, Serial: 102},
		})
		if frag0.Generation != "a1b2c3" || frag0.Owner.AppID != "/opt/Apps/*/SenderA" || frag0.Owner.Path != "/opt/Apps/1.4.0/SenderA" {
			t.Fatalf("unexpected frag0 owner: %+v", frag0.Owner)
		}
		liveOwner, liveStatus, ok := rt.LookupLiveCookieOwner(0xa1b2c3)
		if !ok || liveStatus != IdentityKnown || liveOwner != frag0.Owner {
			t.Fatalf("LookupLiveCookieOwner = (%+v, %s, %t), want (%+v, known, true)", liveOwner, liveStatus, ok, frag0.Owner)
		}

		mergedAny := stack.MergeNetSwitchProvenance(frag0, frag1)
		var okCast bool
		reassembled, okCast = mergedAny.(*ProvenanceEnvelope)
		if !okCast || reassembled == nil {
			t.Fatalf("MergeNetSwitchProvenance returned %#v", mergedAny)
		}
	}()

	// Socket closes while reassembled packet is still queued; frag1 is already unreachable.
	rt.ReleaseSocket(0xa1b2c3)
	runtime.GC()
	runtime.GC()

	ownerAfterFragGC, statusAfterFragGC := reassembled.ValidateForwarding()
	if statusAfterFragGC != EnvelopeKnown || ownerAfterFragGC.AppID != "/opt/Apps/*/SenderA" || reassembled.FragmentsMerged != 2 {
		t.Fatalf("reassembled envelope lost pin or owner after fragment GC: status=%s owner=%+v merged=%d",
			statusAfterFragGC, ownerAfterFragGC, reassembled.FragmentsMerged)
	}

	// 2. Mixed-cookie and missing-fragment merges degrade to EnvelopeMissingCookie with ebpf-packet source.
	func() {
		envB := rt.Acquire(ReadDecision{
			Status: ReadCookie,
			Packet: PacketRecord{Epoch: 7, Cookie: 0xd4e5f6, Serial: 201},
		})
		mixed, ok := stack.MergeNetSwitchProvenance(reassembled, envB).(*ProvenanceEnvelope)
		if !ok || mixed.Status != EnvelopeMissingCookie || mixed.Source != ProvenanceSourcePacket || mixed.Generation != "" {
			t.Fatalf("mixed-cookie merge = %+v, want EnvelopeMissingCookie with empty Generation", mixed)
		}

		missingRight, ok := stack.MergeNetSwitchProvenance(envB, nil).(*ProvenanceEnvelope)
		if !ok || missingRight.Status != EnvelopeMissingCookie || missingRight.Source != ProvenanceSourcePacket || missingRight.Generation != "" {
			t.Fatalf("missing-right merge = %+v, want EnvelopeMissingCookie", missingRight)
		}

		missingLeft, ok := stack.MergeNetSwitchProvenance(nil, envB).(*ProvenanceEnvelope)
		if !ok || missingLeft.Status != EnvelopeMissingCookie || missingLeft.Source != ProvenanceSourcePacket || missingLeft.Generation != "" {
			t.Fatalf("missing-left merge = %+v, want EnvelopeMissingCookie", missingLeft)
		}

		// Second distinct app contributing accepted data on 0xd4e5f6 invalidates already-queued envB!
		conflictKey := keyA
		conflictKey.Cookie = 0xd4e5f6
		if _, reason := rt.EnrichActor(conflictKey, evA, matA); reason != ReasonValidated {
			t.Fatalf("EnrichActor conflict contributor failed: %s", reason)
		}
		rt.ReleaseActor(ActorIdentityKey{TGID: conflictKey.TGID, StartBoottime: conflictKey.Start, ExecID: conflictKey.Exec})

		cOwner, cStatus := envB.ValidateForwarding()
		if cStatus != EnvelopeConflicting || cOwner.AppID != "" || cOwner.Generation != "d4e5f6" {
			t.Fatalf("queued envB after socket conflict = (%+v, %s), want conflicting generation d4e5f6", cOwner, cStatus)
		}
		liveConflict, liveConflictStatus, liveOK := rt.LookupLiveCookieOwner(0xd4e5f6)
		if !liveOK || liveConflictStatus != IdentityConflicting || liveConflict.AppID != "" || liveConflict.Generation != "d4e5f6" || !liveConflict.Ambiguous {
			t.Fatalf("LookupLiveCookieOwner after conflict = (%+v, %s, %t)", liveConflict, liveConflictStatus, liveOK)
		}

		// Single-sender unknown sockets (exited cold actor or async submitter on a fresh
		// socket) must remain EnvelopeUnknownIdentity (Ambiguous=false), NOT conflicting.
		coldKey := ActorKey{Cookie: 0xe77701, TGID: 9901, Start: 777000, Exec: 1}
		rt.ObserveColdUnretained(coldKey, evA)
		envCold := rt.Acquire(ReadDecision{
			Status: ReadCookie,
			Packet: PacketRecord{Epoch: 7, Cookie: 0xe77701, Serial: 301},
		})
		coldOwner, coldStatus := envCold.ValidateForwarding()
		if coldStatus != EnvelopeUnknownIdentity || coldOwner.Ambiguous || coldOwner.AppID != "" || coldOwner.Generation != "e77701" {
			t.Fatalf("single-sender cold unretained socket = (%+v, %s), want unknown_identity Ambiguous=false", coldOwner, coldStatus)
		}
		liveCold, liveColdStatus, liveColdOK := rt.LookupLiveCookieOwner(0xe77701)
		if !liveColdOK || liveColdStatus != IdentityUnknown || liveCold.Ambiguous || liveCold.Generation != "e77701" {
			t.Fatalf("LookupLiveCookieOwner cold unretained = (%+v, %s, %t), want unknown Ambiguous=false", liveCold, liveColdStatus, liveColdOK)
		}
		rt.ReleaseSocket(0xe77701)

		rt.ObserveUnobservableSubmitter(0xe77702)
		envAsync := rt.Acquire(ReadDecision{
			Status: ReadCookie,
			Packet: PacketRecord{Epoch: 7, Cookie: 0xe77702, Serial: 302},
		})
		asyncOwner, asyncStatus := envAsync.ValidateForwarding()
		if asyncStatus != EnvelopeUnknownIdentity || asyncOwner.Ambiguous || asyncOwner.AppID != "" || asyncOwner.Generation != "e77702" {
			t.Fatalf("single-sender async submitter socket = (%+v, %s), want unknown_identity Ambiguous=false", asyncOwner, asyncStatus)
		}
		rt.ReleaseSocket(0xe77702)
	}()

	rt.ReleaseSocket(0xd4e5f6)
	reassembled = nil

	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		runtime.GC()
		lm, sm, _ := rt.Metrics()
		if lm.ActiveSnapshots == 0 && lm.UsedBlobBytes == 0 && sm.ActiveSlots == 0 && sm.RetainedSlots == 0 {
			break
		}
		if time.Now().After(deadline) {
			lm, sm, _ := rt.Metrics()
			t.Fatalf("pins did not retire after GC: ledger=%+v slots=%+v", lm, sm)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
