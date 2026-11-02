package ownerbpf

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
)

func validFixtureActor(cookie uint64, tgid uint32, start, exec, dev, ino uint64, exePath string) (ActorKey, ActorEvidence, RawProcessMaterial) {
	key, ev, mat := validProcessFixture()
	key.Cookie = cookie
	key.TGID = tgid
	key.Start = start
	key.Exec = exec
	ev.Device = dev
	ev.Inode = ino
	mat.Before.TGID = tgid
	mat.Before.StartBoottime = start
	mat.Before.ExecID = exec
	mat.Before.ExeDev = dev
	mat.Before.ExeIno = ino
	mat.After = mat.Before
	mat.ExePath = exePath
	return key, ev, mat
}

func buildTestIPv4Packet(proto uint8, id uint16, mf bool, fragOffsetBytes uint16, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	flagsFrag := (fragOffsetBytes / 8) & 0x1fff
	if mf {
		flagsFrag |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:8], flagsFrag)
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], []byte{198, 18, 0, 1})
	copy(pkt[16:20], []byte{198, 18, 0, 2})
	copy(pkt[20:], payload)
	return pkt
}

func buildTestIPv6FragmentPacket(withDestOpts bool, nextProto uint8, id uint32, mf bool, fragOffsetBytes uint16, payload []byte) []byte {
	extLen := 8 // Fragment header
	if withDestOpts {
		extLen += 8 // 8-byte Destination Options header before Fragment header
	}
	pkt := make([]byte, 40+extLen+len(payload))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(extLen+len(payload)))
	pkt[7] = 64
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])

	pos := 40
	if withDestOpts {
		pkt[6] = 60     // NextHeader = Destination Options
		pkt[pos] = 44   // NextHeader = Fragment
		pkt[pos+1] = 0  // (0 + 1) * 8 = 8 bytes
		pos += 8
	} else {
		pkt[6] = 44 // NextHeader = Fragment
	}
	pkt[pos] = nextProto
	pkt[pos+1] = 0
	offFlags := (fragOffsetBytes & 0xfff8)
	if mf {
		offFlags |= 0x0001
	}
	binary.BigEndian.PutUint16(pkt[pos+2:pos+4], offFlags)
	binary.BigEndian.PutUint32(pkt[pos+4:pos+8], id)
	pos += 8
	copy(pkt[pos:], payload)
	return pkt
}

func TestSocketSlotPublicationAndWrapPoison(t *testing.T) {
	ledger := NewIdentityLedger(64, 64<<10)
	slots := NewSocketSlotTable(16)
	ledger.AttachSlotTable(slots)

	dev := EncodeKernelDev(8, 1)
	keyA, evA, matA := validFixtureActor(1001, 2000, 100000, 1, dev, 5001, "/usr/bin/app-alpha")
	snapA, reason := ledger.EnrichActor(keyA, evA, matA)
	if reason != ReasonValidated || snapA == nil {
		t.Fatalf("EnrichActor(app-alpha) = (%v, %v), want validated", snapA, reason)
	}

	slotSnap, _, ok := slots.SlotSnapshot(1001)
	if !ok || slotSnap.Version != 1 || slotSnap.Conflicts != 0 || (SocketSlotFlags(slotSnap.Flags)&SocketSlotValid) == 0 {
		t.Fatalf("slot after first owner = %+v (ok=%v), want Version=1 Conflicts=0 Valid", slotSnap, ok)
	}

	// Same-app forked child contributing to cookie 1001 keeps Version=1, Conflicts=0.
	childKey := ActorKey{Cookie: 1001, TGID: 2001, Start: 100050, Exec: 1}
	childEv := evA
	childCtx := matA.Before
	childCtx.TGID = 2001
	childCtx.StartBoottime = 100050
	if _, reason := ledger.InheritFork(snapA.Key, childKey, childEv, childCtx); reason != ReasonInheritedValidated {
		t.Fatalf("InheritFork = %v, want inherited_validated", reason)
	}
	slotSnap, _, _ = slots.SlotSnapshot(1001)
	if slotSnap.Version != 1 || slotSnap.Conflicts != 0 {
		t.Fatalf("slot after same-app fork = %+v, want Version=1 Conflicts=0", slotSnap)
	}

	// Queue a packet envelope captured while OwnerVersion == 1.
	env1 := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 1001, Serial: 1},
	})
	if env1.Identity.Status != IdentityKnown || env1.Identity.OwnerVersion != 1 {
		t.Fatalf("env1 = %+v, want known OwnerVersion=1", env1.Identity)
	}
	if dec := ledger.ValidateForwardingEnvelope(env1); dec.Status != IdentityKnown {
		t.Fatalf("ValidateForwardingEnvelope(env1 before conflict) = %+v, want known", dec)
	}

	// Different app contributes to cookie 1001 -> XADD conflicts += 1 first, then version += 1 (Version=2, an even number!).
	keyB, evB, matB := validFixtureActor(1001, 3000, 200000, 1, dev, 6002, "/usr/bin/app-beta")
	if _, reason := ledger.EnrichActor(keyB, evB, matB); reason != ReasonValidated {
		t.Fatalf("EnrichActor(app-beta) = %v, want validated", reason)
	}
	slotSnap, _, _ = slots.SlotSnapshot(1001)
	if slotSnap.Conflicts != 1 || slotSnap.Version != 2 || (SocketSlotFlags(slotSnap.Flags)&SocketSlotConflicting) == 0 {
		t.Fatalf("slot after conflict = %+v, want Conflicts=1 Version=2 Conflicting", slotSnap)
	}

	// Forwarding validation on the already-queued env1 must reject it as conflicting!
	if dec := ledger.ValidateForwardingEnvelope(env1); dec.Status != IdentityConflicting || dec.Reason != ReasonConflictingApp {
		t.Fatalf("ValidateForwardingEnvelope(env1 after conflict) = %+v, want conflicting_identity/conflicting_app", dec)
	}
	// Even if a packet tried to claim the even OwnerVersion=2, Conflicts=1 still rejects it.
	forgedEven := env1
	forgedEven.Identity.OwnerVersion = 2
	if dec := ledger.ValidateForwardingEnvelope(forgedEven); dec.Status != IdentityConflicting {
		t.Fatalf("ValidateForwardingEnvelope(even version=2 with conflict=1) = %+v, want conflicting_identity", dec)
	}
	ledger.ReleaseEnvelope(&env1)

	// Incomplete first contributor on cookie 1002 never promotes to valid when a valid actor later contributes.
	ledger.ObserveColdUnretained(ActorKey{Cookie: 1002, TGID: 4000, Start: 300000, Exec: 1}, evA)
	slot1002, _, _ := slots.SlotSnapshot(1002)
	if (SocketSlotFlags(slot1002.Flags)&SocketSlotIncomplete) == 0 || slot1002.Conflicts != 1 || slot1002.Version != 1 {
		t.Fatalf("slot1002 after incomplete first contributor = %+v, want Incomplete Conflicts=1 Version=1", slot1002)
	}
	keyLate := keyA
	keyLate.Cookie = 1002
	ledger.ObserveWarmSend(keyLate, evA)
	env1002 := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 1002, Serial: 2},
	})
	if env1002.Identity.Status != IdentityUnknown || env1002.Identity.Reason != ReasonIdentityUnretained {
		t.Fatalf("env1002 after late valid contributor = %+v, want unknown_identity/identity_unretained", env1002.Identity)
	}
	ledger.ReleaseEnvelope(&env1002)

	// Counter wrap-around at ^uint64(0) poisons the epoch and fails closed.
	keyWrap, evWrap, matWrap := validFixtureActor(1003, 5000, 400000, 1, dev, 7003, "/usr/bin/app-gamma")
	ledger.EnrichActor(keyWrap, evWrap, matWrap)
	if !slots.ForceCountersForTest(1003, ^uint64(0), 0) {
		t.Fatal("ForceCountersForTest(1003) failed")
	}
	ledger.ObserveUnobservableSubmitter(1003)
	if !slots.Metrics().EpochPoisoned || slots.Metrics().WrapPoisons != 1 {
		t.Fatalf("slot metrics after wrap = %+v, want EpochPoisoned=true WrapPoisons=1", slots.Metrics())
	}
	envPoisoned := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 1003, Serial: 3},
	})
	if envPoisoned.Identity.Status != IdentityUnknown || envPoisoned.Identity.Reason != ReasonBudgetExceeded {
		t.Fatalf("ResolvePacketEnvelope after wrap poison = %+v, want unknown_identity/budget_exceeded", envPoisoned.Identity)
	}
}

func TestAcceptedContributionAndCorkConflict(t *testing.T) {
	ledger := NewIdentityLedger(64, 64<<10)
	slots := NewSocketSlotTable(32)
	ledger.AttachSlotTable(slots)

	dev := EncodeKernelDev(8, 1)
	keyA, evA, matA := validFixtureActor(2001, 2100, 110000, 1, dev, 5101, "/usr/bin/cork-alpha")
	keyB, evB, matB := validFixtureActor(2001, 2200, 120000, 1, dev, 5202, "/usr/bin/cork-beta")

	// Failed sends on an unused socket cookie (2000) never allocate a slot or claim ownership.
	ledger.ObserveFailedSend(2000, keyA)
	if _, _, ok := slots.SlotSnapshot(2000); ok {
		t.Fatal("failed send on unused socket 2000 must not allocate a slot")
	}

	// Staged cork on socket 2002 that is discarded before flush leaves socket unclaimed.
	keyDiscard := keyA
	keyDiscard.Cookie = 2002
	ledger.StageCorkContributor(keyDiscard, evA, matA)
	ledger.DiscardCork(2002)
	if _, _, ok := slots.SlotSnapshot(2002); ok {
		t.Fatal("discarded cork on unused socket 2002 must reclaim uncommitted slot")
	}

	// Same-app multiple corked writes on socket 2001 followed by FlushCork -> known_identity.
	ledger.StageCorkContributor(keyA, evA, matA)
	ledger.StageCorkContributor(keyA, evA, matA)
	if !ledger.FlushCork(2001) {
		t.Fatal("FlushCork(2001) returned false")
	}
	// A failed send from a second app on owned socket 2001 must not poison it.
	ledger.ObserveFailedSend(2001, keyB)
	env2001 := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 2001, Serial: 10},
	})
	if env2001.Identity.Status != IdentityKnown || env2001.Identity.Snapshot.AppID != "/usr/bin/cork-alpha" {
		t.Fatalf("env2001 = %+v, want known /usr/bin/cork-alpha", env2001.Identity)
	}
	ledger.ReleaseEnvelope(&env2001)

	// Two different apps contributing corked writes to socket 2003 before FlushCork -> conflicting_identity.
	keyA3 := keyA
	keyA3.Cookie = 2003
	keyB3 := keyB
	keyB3.Cookie = 2003
	ledger.StageCorkContributor(keyA3, evA, matA)
	ledger.StageCorkContributor(keyB3, evB, matB)
	if !ledger.FlushCork(2003) {
		t.Fatal("FlushCork(2003) returned false")
	}
	env2003 := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 2003, Serial: 11},
	})
	if env2003.Identity.Status != IdentityConflicting || env2003.Identity.Reason != ReasonConflictingApp {
		t.Fatalf("env2003 after multi-app cork flush = %+v, want conflicting_identity/conflicting_app", env2003.Identity)
	}
	ledger.ReleaseEnvelope(&env2003)
}

func TestFragmentReassemblyAndGSOEnvelopes(t *testing.T) {
	ledger := NewIdentityLedger(64, 64<<10)
	slots := NewSocketSlotTable(32)
	ledger.AttachSlotTable(slots)

	dev := EncodeKernelDev(8, 1)
	keyA, evA, matA := validFixtureActor(3001, 3100, 210000, 1, dev, 6101, "/usr/bin/frag-alpha")
	keyB, evB, matB := validFixtureActor(3002, 3200, 220000, 1, dev, 6202, "/usr/bin/frag-beta")
	ledger.EnrichActor(keyA, evA, matA)
	ledger.EnrichActor(keyB, evB, matB)

	reasm := NewFragmentReassembler(16, 64<<10)

	// 1. Out-of-order IPv4 fragments where fragment 2 has no transport ports.
	frag0Payload := []byte("0123456789abcdef") // 16 bytes (contains UDP header + first 8 bytes)
	frag1Payload := []byte("FEDCBA9876543210") // 16 bytes (offset 16, no transport header!)
	ipv4Frag0 := buildTestIPv4Packet(17, 0x4242, true, 0, frag0Payload)
	ipv4Frag1 := buildTestIPv4Packet(17, 0x4242, false, 16, frag1Payload)

	envFrag1 := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 3001, Serial: 101},
	})
	envFrag0 := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 3001, Serial: 102},
	})

	// Deliver fragment 1 (tail) BEFORE fragment 0 (head).
	if _, _, done, err := reasm.Ingest(ledger, ipv4Frag1, envFrag1); err != nil || done {
		t.Fatalf("Ingest(ipv4Frag1 out-of-order) = (done=%v, err=%v), want done=false err=nil", done, err)
	}
	reassembledV4, mergedEnvV4, done, err := reasm.Ingest(ledger, ipv4Frag0, envFrag0)
	if err != nil || !done {
		t.Fatalf("Ingest(ipv4Frag0 completing out-of-order) = (done=%v, err=%v)", done, err)
	}
	if len(reassembledV4) != 20+32 || mergedEnvV4.Identity.Status != IdentityKnown || mergedEnvV4.Identity.Snapshot.AppID != "/usr/bin/frag-alpha" {
		t.Fatalf("reassembledV4 len=%d identity=%+v, want len=52 known /usr/bin/frag-alpha", len(reassembledV4), mergedEnvV4.Identity)
	}
	ledger.ReleaseEnvelope(&mergedEnvV4)

	// 2. IPv6 fragments with Destination Options extension header before Fragment header, out-of-order.
	ipv6Frag0 := buildTestIPv6FragmentPacket(true, 17, 0x99887766, true, 0, frag0Payload)
	ipv6Frag1 := buildTestIPv6FragmentPacket(true, 17, 0x99887766, false, 16, frag1Payload)
	hdrV6, err := InspectPacketHeader(ipv6Frag1)
	if err != nil || !hdrV6.HasExtensionHeaders || !hdrV6.IsFragment || hdrV6.FragmentOffset != 16 || hdrV6.NextHeader != 17 {
		t.Fatalf("InspectPacketHeader(ipv6Frag1) = %+v, err=%v", hdrV6, err)
	}
	envV6_1 := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 3001, Serial: 103},
	})
	envV6_0 := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 3001, Serial: 104},
	})
	if _, _, done, err := reasm.Ingest(ledger, ipv6Frag1, envV6_1); err != nil || done {
		t.Fatalf("Ingest(ipv6Frag1) = (done=%v, err=%v)", done, err)
	}
	reassembledV6, mergedEnvV6, done, err := reasm.Ingest(ledger, ipv6Frag0, envV6_0)
	if err != nil || !done {
		t.Fatalf("Ingest(ipv6Frag0) = (done=%v, err=%v)", done, err)
	}
	if len(reassembledV6) != 40+8+32 || mergedEnvV6.Identity.Status != IdentityKnown {
		t.Fatalf("reassembledV6 len=%d identity=%+v, want len=80 known", len(reassembledV6), mergedEnvV6.Identity)
	}
	ledger.ReleaseEnvelope(&mergedEnvV6)

	// 3. Mixed-app fragments must produce conflicting_identity.
	mixFrag0 := buildTestIPv4Packet(17, 0x5555, true, 0, frag0Payload)
	mixFrag1 := buildTestIPv4Packet(17, 0x5555, false, 16, frag1Payload)
	envMixA := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 3001, Serial: 105},
	})
	envMixB := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 3002, Serial: 106},
	})
	_, _, _, _ = reasm.Ingest(ledger, mixFrag0, envMixA)
	_, mergedMix, done, err := reasm.Ingest(ledger, mixFrag1, envMixB)
	if err != nil || !done || mergedMix.Identity.Status != IdentityConflicting {
		t.Fatalf("mixed-app fragment reassembly = (done=%v, err=%v, id=%+v), want conflicting_identity", done, err, mergedMix.Identity)
	}

	// 4. SplitVirtioGSO propagates cloned ForwardEnvelopes across all segments of a certified raw read.
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], 12345)
	binary.BigEndian.PutUint16(tcpHdr[2:4], 443)
	binary.BigEndian.PutUint32(tcpHdr[4:8], 1000)
	tcpHdr[12] = 5 << 4
	tcpHdr[13] = 0x18 // ACK | PSH
	gsoPayload := make([]byte, 30)
	for i := range gsoPayload {
		gsoPayload[i] = byte('a' + (i % 26))
	}
	l3Pkt := buildTestIPv4Packet(6, 0x1000, false, 0, append(tcpHdr, gsoPayload...))
	vnetFrame := make([]byte, VirtioNetHdrLen+len(l3Pkt))
	vnetFrame[0] = VirtioNetHdrFNeedsCsum
	vnetFrame[1] = VirtioNetHdrGSOTCPv4
	binary.LittleEndian.PutUint16(vnetFrame[2:4], 40) // 20B IPv4 + 20B TCP
	binary.LittleEndian.PutUint16(vnetFrame[4:6], 10) // gso_size = 10 -> 3 segments
	copy(vnetFrame[VirtioNetHdrLen:], l3Pkt)

	rawGSOEnv := ledger.ResolvePacketEnvelope(ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 3001, Serial: 200},
	})
	segs, segEnvs, err := SplitVirtioGSO(ledger, vnetFrame, rawGSOEnv)
	if err != nil || len(segs) != 3 || len(segEnvs) != 3 {
		t.Fatalf("SplitVirtioGSO = (%d segs, %d envs, err=%v), want 3 segments", len(segs), len(segEnvs), err)
	}
	for i := range segEnvs {
		if dec := ledger.ValidateForwardingEnvelope(segEnvs[i]); dec.Status != IdentityKnown {
			t.Fatalf("segment %d ValidateForwardingEnvelope = %+v, want known", i, dec)
		}
		ledger.ReleaseEnvelope(&segEnvs[i])
	}

	// 5. SegmentAccounting counts socket-less software-segmented UDP_SEGMENT packets as ReadUnknown.
	var acct SegmentAccounting
	acct.ObserveRawSegment(ReadDecision{Status: ReadUnknown, Packet: PacketRecord{Cookie: 0}}, ForwardEnvelope{Identity: PacketIdentityDecision{Status: IdentityUnknown}})
	acct.ObserveRawSegment(ReadDecision{Status: ReadUnknown, Packet: PacketRecord{Cookie: 0}}, ForwardEnvelope{Identity: PacketIdentityDecision{Status: IdentityUnknown}})
	lastEnv := ledger.ResolvePacketEnvelope(ReadDecision{Status: ReadCookie, Packet: PacketRecord{Cookie: 3001, Serial: 201}})
	acct.ObserveRawSegment(lastEnv.Read, lastEnv)
	ledger.ReleaseEnvelope(&lastEnv)
	if acct.TotalSegments != 3 || acct.SocketlessSegments != 2 || acct.AttributedSegments != 1 {
		t.Fatalf("SegmentAccounting = %+v, want Total=3 Socketless=2 Attributed=1", acct)
	}
}

func TestKernelControlAndLockdownClassification(t *testing.T) {
	clf := NewKernelControlClassifier()
	clf.RecordUserspaceSocket(4001)
	clf.RecordKernelControlSocket(KernelControlEvidence{
		Cookie:   9001,
		NetNS:    4026531992,
		Protocol: 1, // ICMP
		Kind:     KernelControlICMPReply,
	})
	clf.RecordKernelControlSocket(KernelControlEvidence{
		Cookie:   9002,
		NetNS:    4026531992,
		Protocol: 6, // TCP TIME_WAIT / RST
		Kind:     KernelControlTCPTimeWait,
	})

	icmpPkt := buildTestIPv4Packet(1, 0x1111, false, 0, []byte{0, 0, 0, 0, 0, 1, 0, 1})
	tcpPkt := buildTestIPv4Packet(6, 0x2222, false, 0, make([]byte, 20))

	// Verified kernel ICMP reply on control socket 9001 -> PacketClassKernelControl (excluded from ApplicationMisses).
	kICMPDec := ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 9001, NetNS: 4026531992, Serial: 1},
	}
	if got := clf.Classify(icmpPkt, ForwardEnvelope{Read: kICMPDec, Identity: PacketIdentityDecision{Status: IdentityUnknown}}); got != PacketClassKernelControl {
		t.Fatalf("Classify(verified kernel ICMP) = %v, want verified_kernel_control", got)
	}

	// Verified kernel TCP TIME_WAIT/RST on control socket 9002 -> PacketClassKernelControl.
	kTCPDec := ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 9002, NetNS: 4026531992, Serial: 2},
	}
	if got := clf.Classify(tcpPkt, ForwardEnvelope{Read: kTCPDec, Identity: PacketIdentityDecision{Status: IdentityUnknown}}); got != PacketClassKernelControl {
		t.Fatalf("Classify(verified kernel TCP RST) = %v, want verified_kernel_control", got)
	}

	// Negative control 1: Userspace socket 4001 sending ICMP with missing actor metadata -> PacketClassApplicationUnknown!
	uICMPDec := ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 4001, NetNS: 4026531992, Serial: 3},
	}
	if got := clf.Classify(icmpPkt, ForwardEnvelope{Read: uICMPDec, Identity: PacketIdentityDecision{Status: IdentityUnknown}}); got != PacketClassApplicationUnknown {
		t.Fatalf("Classify(userspace ICMP with missing actor) = %v, want application_unknown", got)
	}

	// Negative control 2: Unregistered socket 5555 sending TCP with missing actor metadata -> PacketClassApplicationUnknown!
	uTCPDec := ReadDecision{
		Status: ReadCookie,
		Packet: PacketRecord{Cookie: 5555, NetNS: 4026531992, Serial: 4},
	}
	if got := clf.Classify(tcpPkt, ForwardEnvelope{Read: uTCPDec, Identity: PacketIdentityDecision{Status: IdentityUnknown}}); got != PacketClassApplicationUnknown {
		t.Fatalf("Classify(unregistered TCP with missing actor) = %v, want application_unknown", got)
	}

	m := clf.Metrics()
	if m.VerifiedKernelControl != 2 || m.ApplicationMisses != 2 {
		t.Fatalf("ClassifierMetrics = %+v, want VerifiedKernelControl=2 ApplicationMisses=2", m)
	}

	// Lockdown & failure classification checks.
	if ParseLockdownMode("none [integrity] confidentiality\n") != LockdownIntegrity {
		t.Fatalf("ParseLockdownMode([integrity]) = %v, want integrity", ParseLockdownMode("none [integrity] confidentiality\n"))
	}
	if ParseLockdownMode("none integrity [confidentiality]\n") != LockdownConfidentiality {
		t.Fatalf("ParseLockdownMode([confidentiality]) = %v, want confidentiality", ParseLockdownMode("none integrity [confidentiality]\n"))
	}
	if r := ClassifyLoadFailure(syscall.EPERM, "none [confidentiality]", true, true); r != FallbackLockdownConfidentiality {
		t.Fatalf("ClassifyLoadFailure(confidentiality) = %v", r)
	}
	if r := ClassifyLoadFailure(nil, "[none]", false, true); r != FallbackMissingBTF {
		t.Fatalf("ClassifyLoadFailure(no BTF) = %v", r)
	}
	if r := ClassifyLoadFailure(nil, "[integrity]", true, false); r != FallbackCgroupV1 {
		t.Fatalf("ClassifyLoadFailure(cgroup v1) = %v", r)
	}
	if r := ClassifyLoadFailure(syscall.EPERM, "[integrity]", true, true); r != FallbackCapabilityDenied {
		t.Fatalf("ClassifyLoadFailure(EPERM) = %v", r)
	}
}

func TestLifecycleSaturationChurnAndBaselineReturn(t *testing.T) {
	const maxSnaps = 8
	const maxSlots = 8
	ledger := NewIdentityLedger(maxSnaps, 4096)
	slots := NewSocketSlotTable(maxSlots)
	ledger.AttachSlotTable(slots)

	dev := EncodeKernelDev(8, 1)

	// 1. Saturate all 8 snapshots and 8 socket slots.
	var retainedEnv ForwardEnvelope
	for i := 1; i <= maxSlots; i++ {
		cookie := uint64(6000 + i)
		tgid := uint32(7000 + i)
		key, ev, mat := validFixtureActor(cookie, tgid, uint64(500000+i), 1, dev, uint64(8000+i), "/usr/bin/churn-app")
		if _, reason := ledger.EnrichActor(key, ev, mat); reason != ReasonValidated {
			t.Fatalf("EnrichActor(%d) = %v, want validated", i, reason)
		}
		if i == 1 {
			retainedEnv = ledger.ResolvePacketEnvelope(ReadDecision{
				Status: ReadCookie,
				Packet: PacketRecord{Cookie: cookie, Serial: uint64(i)},
			})
		}
	}

	// 9th distinct socket/actor exceeds both snapshot and slot budgets.
	key9, ev9, mat9 := validFixtureActor(6009, 7009, 500009, 1, dev, 8009, "/usr/bin/churn-overflow")
	if _, reason := ledger.EnrichActor(key9, ev9, mat9); reason != ReasonBudgetExceeded {
		t.Fatalf("EnrichActor(overflow) = %v, want budget_exceeded", reason)
	}

	// 2. Close socket 6001 while retainedEnv still holds an unforwarded reference to its slot!
	ledger.ReleaseSocket(6001)
	ledger.ReleaseActor(ActorIdentityKey{TGID: 7001, StartBoottime: 500001, ExecID: 1})
	if sm := slots.Metrics(); sm.ActiveSlots != maxSlots || sm.RetainedSlots != 1 {
		t.Fatalf("slot metrics while retainedEnv pinned = %+v, want ActiveSlots=%d RetainedSlots=1", sm, maxSlots)
	}
	// Attempting to allocate a new socket slot while 6001 is still pinned by retainedEnv must be refused!
	keyExistingActor := ActorKey{Cookie: 6999, TGID: 7002, Start: 500002, Exec: 1}
	evExistingActor := ActorEvidence{ABI: ABI, Device: dev, Inode: 8002}
	ledger.ObserveWarmSend(keyExistingActor, evExistingActor)
	if slots.Metrics().Refusals == 0 {
		t.Fatal("expected slot allocation refusal while closed socket 6001 is still pinned by retainedEnv")
	}

	// Forwarding validation on retainedEnv still succeeds even after socket 6001 closed!
	if dec := ledger.ValidateForwardingEnvelope(retainedEnv); dec.Status != IdentityKnown {
		t.Fatalf("ValidateForwardingEnvelope(retainedEnv after socket close) = %+v, want known", dec)
	}

	// Release retainedEnv -> slot 6001 and snapshot 7001 are reclaimed immediately.
	ledger.ReleaseEnvelope(&retainedEnv)
	if sm := slots.Metrics(); sm.ActiveSlots != maxSlots-1 || sm.RetainedSlots != 0 {
		t.Fatalf("slot metrics after releasing retainedEnv = %+v, want ActiveSlots=%d RetainedSlots=0", sm, maxSlots-1)
	}

	// 3. Continue multi-cycle churn from accumulated state without resetting the table or ledger.
	for i := 2; i <= maxSlots; i++ {
		ledger.ReleaseSocket(uint64(6000 + i))
		ledger.ReleaseActor(ActorIdentityKey{TGID: uint32(7000 + i), StartBoottime: uint64(500000 + i), ExecID: 1})
	}
	for cycle := 0; cycle < 4; cycle++ {
		for i := 1; i <= maxSlots; i++ {
			cookie := uint64(9000 + cycle*100 + i)
			tgid := uint32(9500 + cycle*100 + i)
			start := uint64(900000 + cycle*100 + i)
			key, ev, mat := validFixtureActor(cookie, tgid, start, 1, dev, uint64(9800+i), "/usr/bin/cycle-app")
			if _, reason := ledger.EnrichActor(key, ev, mat); reason != ReasonValidated {
				t.Fatalf("cycle %d slot %d EnrichActor = %v, want validated", cycle, i, reason)
			}
			env := ledger.ResolvePacketEnvelope(ReadDecision{
				Status: ReadCookie,
				Packet: PacketRecord{Cookie: cookie, Serial: uint64(1000 + cycle*100 + i)},
			})
			if dec := ledger.ValidateForwardingEnvelope(env); dec.Status != IdentityKnown {
				t.Fatalf("cycle %d slot %d ValidateForwardingEnvelope = %+v, want known", cycle, i, dec)
			}
			ledger.ReleaseSocket(cookie)
			ledger.ReleaseActor(ActorIdentityKey{TGID: tgid, StartBoottime: start, ExecID: 1})
			ledger.ReleaseEnvelope(&env)
		}
	}

	// 4. Verify occupancy returns to 0 baseline after all actors, sockets, and envelopes drain.
	lm := ledger.Metrics()
	sm := slots.Metrics()
	if lm.ActiveSnapshots != 0 || lm.ActiveBlobs != 0 || lm.UsedBlobBytes != 0 || lm.ActiveSocketSlots != 0 || sm.ActiveSlots != 0 || sm.RetainedSlots != 0 {
		t.Fatalf("post-drain occupancy non-zero: ledger=%+v slots=%+v", lm, sm)
	}

	// 5. Verify capacity profile stays well within the < 45 MB product RAM budget.
	prof, err := DeriveCapacityProfile(500, 8, 1)
	if err != nil {
		t.Fatalf("DeriveCapacityProfile(500, 8, 1): %v", err)
	}
	if prof.RequiredPacketSlots != 1024 || prof.TotalAttributionBudget >= (4<<20) || prof.TotalAttributionBudget >= prof.ProductRAMBudgetBytes {
		t.Fatalf("unexpected CapacityProfile = %+v", prof)
	}
}
