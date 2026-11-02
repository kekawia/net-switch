//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/linux/ownerbpf"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type fakeProvFrame struct {
	raw      []byte
	decision ownerbpf.ReadDecision
}

type fakeProvBurst struct {
	frames []fakeProvFrame
	err    error
}

type fakeProvBurstSource struct {
	bursts []fakeProvBurst
	idx    int
	closed bool
}

func (s *fakeProvBurstSource) BindReader() (
	func(fd int, rawBufs [][]byte, sizes []int, decisions []ownerbpf.ReadDecision) (int, error),
	func() error,
	error,
) {
	readBurst := func(_ int, rawBufs [][]byte, sizes []int, decisions []ownerbpf.ReadDecision) (int, error) {
		if s.idx >= len(s.bursts) {
			return 0, nil
		}
		b := s.bursts[s.idx]
		s.idx++
		for i, f := range b.frames {
			copy(rawBufs[i], f.raw)
			sizes[i] = len(f.raw)
			decisions[i] = f.decision
		}
		return len(b.frames), b.err
	}
	closeReader := func() error {
		s.closed = true
		return nil
	}
	return readBurst, closeReader, nil
}

func putTestVirtioHdr(b []byte, flags, gsoType uint8, hdrLen, gsoSize, csumStart, csumOffset uint16) {
	b[0] = flags
	b[1] = gsoType
	binary.LittleEndian.PutUint16(b[2:4], hdrLen)
	binary.LittleEndian.PutUint16(b[4:6], gsoSize)
	binary.LittleEndian.PutUint16(b[6:8], csumStart)
	binary.LittleEndian.PutUint16(b[8:10], csumOffset)
}

func enrichTunTestActor(t *testing.T, rt *ownerbpf.ProvenanceRuntime, cookie uint64, tgid uint32, start uint64, exePath string) ownerbpf.ActorIdentityKey {
	t.Helper()
	dev := ownerbpf.EncodeKernelDev(8, 1)
	ino := uint64(800000) + uint64(tgid)
	key := ownerbpf.ActorKey{
		Cookie: cookie,
		Start:  start,
		Exec:   1,
		TGID:   tgid,
	}
	ev := ownerbpf.ActorEvidence{
		Inode:      ino,
		Device:     dev,
		ObservedNS: 4026531992,
		ABI:        ownerbpf.ABI,
	}
	execCtx := ownerbpf.ExecutionContext{
		TGID:          tgid,
		StartBoottime: start,
		StartTicks:    start / 10_000_000,
		ExecID:        1,
		ExeDev:        dev,
		ExeIno:        ino,
		MntNSInum:     4026531840,
		NetNSInum:     4026531992,
		PIDNSInum:     4026531836,
		RootMntID:     29,
		UID:           1000,
		GID:           1000,
	}
	mat := ownerbpf.RawProcessMaterial{
		Before:  execCtx,
		After:   execCtx,
		ExePath: exePath,
		Mounts: []ownerbpf.MountEntry{{
			MountID: 29, ParentID: 1, Major: 8, Minor: 1,
			Root: "/", MountPoint: "/", FSType: "ext4", MountSource: "/dev/sda1",
		}},
	}
	snap, reason := rt.EnrichActor(key, ev, mat)
	if reason != ownerbpf.ReasonValidated || snap == nil {
		t.Fatalf("EnrichActor(%s) failed: snap=%+v reason=%s", exePath, snap, reason)
	}
	return ownerbpf.ActorIdentityKey{TGID: tgid, StartBoottime: start, ExecID: 1}
}

func fold16(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum)
}

func csum16(initial uint32, b []byte) uint32 {
	sum := initial
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func TestTunProvenanceBurstGSONormalizationAndGC(t *testing.T) {
	ledger := ownerbpf.NewIdentityLedger(32, 32<<10)
	slots := ownerbpf.NewSocketSlotTable(32)
	rt := ownerbpf.NewProvenanceRuntime(7, ledger, slots)
	actA := enrichTunTestActor(t, rt, 0xa1, 4101, 100_000_000, "/usr/bin/AppUDP4")
	actB := enrichTunTestActor(t, rt, 0xb2, 4102, 200_000_000, "/usr/bin/AppTCP4")
	actC := enrichTunTestActor(t, rt, 0xc3, 4103, 300_000_000, "/usr/bin/AppUDP6")

	// Frame 0: GSO_NONE + VIRTIO_NET_HDR_F_NEEDS_CSUM UDPv4.
	src4 := netip.MustParseAddr("198.18.0.1").As4()
	dst4 := netip.MustParseAddr("198.51.100.10").As4()
	udpPayload := []byte("burst-udp4-csum")
	rawUDP4 := make([]byte, ownerbpf.VirtioNetHdrLen+20+8+len(udpPayload))
	putTestVirtioHdr(rawUDP4, ownerbpf.VirtioNetHdrFNeedsCsum, ownerbpf.VirtioNetHdrGSONone, 28, 0, 20, 6)
	ip4 := rawUDP4[ownerbpf.VirtioNetHdrLen:]
	ip4[0] = 0x45
	binary.BigEndian.PutUint16(ip4[2:4], uint16(20+8+len(udpPayload)))
	ip4[8] = 64
	ip4[9] = 17
	copy(ip4[12:16], src4[:])
	copy(ip4[16:20], dst4[:])
	binary.BigEndian.PutUint16(ip4[10:12], ^fold16(csum16(0, ip4[:20])))
	udp4 := ip4[20:]
	binary.BigEndian.PutUint16(udp4[0:2], 51000)
	binary.BigEndian.PutUint16(udp4[2:4], 443)
	binary.BigEndian.PutUint16(udp4[4:6], uint16(8+len(udpPayload)))
	pseudo := fold16(csum16(0, ip4[12:20]) + 17 + uint32(8+len(udpPayload)))
	binary.BigEndian.PutUint16(udp4[6:8], pseudo)
	copy(udp4[8:], udpPayload)

	// Frame 1: GSO_TCPV4|ECN 3-segment TSO super-packet (1000 + 1000 + 350 bytes).
	tcpPayload := bytes.Repeat([]byte("T1S2O3V4P5"), 235)
	rawTSO4 := make([]byte, ownerbpf.VirtioNetHdrLen+40+len(tcpPayload))
	putTestVirtioHdr(rawTSO4, ownerbpf.VirtioNetHdrFNeedsCsum, ownerbpf.VirtioNetHdrGSOTCPv4|ownerbpf.VirtioNetHdrGSOECN, 40, 1000, 20, 16)
	tsoIP4 := rawTSO4[ownerbpf.VirtioNetHdrLen:]
	tsoIP4[0] = 0x45
	binary.BigEndian.PutUint16(tsoIP4[2:4], uint16(40+len(tcpPayload)))
	binary.BigEndian.PutUint16(tsoIP4[4:6], 0x3300)
	tsoIP4[8] = 64
	tsoIP4[9] = 6
	copy(tsoIP4[12:16], src4[:])
	copy(tsoIP4[16:20], dst4[:])
	tsoTCP := tsoIP4[20:]
	binary.BigEndian.PutUint16(tsoTCP[0:2], 52000)
	binary.BigEndian.PutUint16(tsoTCP[2:4], 8443)
	binary.BigEndian.PutUint32(tsoTCP[4:8], 700000)
	tsoTCP[12] = 5 << 4
	tsoTCP[13] = 0x80 | 0x10 | 0x08 | 0x01 // CWR | ACK | PSH | FIN
	copy(tsoTCP[20:], tcpPayload)

	// Frame 2: GSO_UDP_L4 3-segment IPv6 USO super-packet (500 + 500 + 200 bytes).
	src6 := netip.MustParseAddr("fdfe:dcba:9876::1").As16()
	dst6 := netip.MustParseAddr("2001:db8::42").As16()
	usoPayload := bytes.Repeat([]byte("USO6"), 300)
	rawUSO6 := make([]byte, ownerbpf.VirtioNetHdrLen+40+8+len(usoPayload))
	putTestVirtioHdr(rawUSO6, ownerbpf.VirtioNetHdrFNeedsCsum, ownerbpf.VirtioNetHdrGSOUDPL4, 48, 500, 40, 6)
	ip6 := rawUSO6[ownerbpf.VirtioNetHdrLen:]
	ip6[0] = 0x60
	ip6[6] = 17
	ip6[7] = 64
	copy(ip6[8:24], src6[:])
	copy(ip6[24:40], dst6[:])
	binary.BigEndian.PutUint16(ip6[40:42], 53000)
	binary.BigEndian.PutUint16(ip6[42:44], 4433)
	copy(ip6[48:], usoPayload)

	func() {
		src := &fakeProvBurstSource{
			bursts: []fakeProvBurst{{
				frames: []fakeProvFrame{
					{
						raw:      rawUDP4,
						decision: ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 7, Cookie: 0xa1, Serial: 1}},
					},
					{
						raw:      rawTSO4,
						decision: ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 7, Cookie: 0xb2, Serial: 2}},
					},
					{
						raw:      rawUSO6,
						decision: ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 7, Cookie: 0xc3, Serial: 3}},
					},
				},
			}},
		}
		tun := &Tun{mtu: 9000}
		tun.AttachProvenanceReader(src, func(rawBufs [][]byte, sizes []int, decisions []ownerbpf.ReadDecision, count int, out []*ownerbpf.ProvenanceEnvelope) {
			for i := 0; i < count; i++ {
				var l3 []byte
				if sizes[i] > ownerbpf.VirtioNetHdrLen {
					l3 = rawBufs[i][ownerbpf.VirtioNetHdrLen:sizes[i]]
				}
				out[i] = rt.AcquirePacket(l3, decisions[i])
			}
		})
		unbind, err := tun.BindPumpThread()
		if err != nil {
			t.Fatalf("BindPumpThread: %v", err)
		}

		ctx := context.Background()
		buf := make([]byte, 9000)

		// Segment 0: UDPv4 GSO_NONE NEEDS_CSUM.
		n0, p0, err := tun.ReadPacketWithProvenance(ctx, buf)
		if err != nil || n0 != 20+8+len(udpPayload) {
			t.Fatalf("seg 0 ReadPacketWithProvenance n=%d err=%v", n0, err)
		}
		env0, ok := p0.(*ownerbpf.ProvenanceEnvelope)
		if !ok || env0 == nil {
			t.Fatalf("seg 0 provenance = %#v", p0)
		}
		owner0, st0 := env0.ValidateForwarding()
		if st0 != ownerbpf.EnvelopeKnown || owner0.AppID != "/usr/bin/AppUDP4" {
			t.Fatalf("seg 0 owner=%+v status=%s", owner0, st0)
		}
		gvIP0 := header.IPv4(buf[:n0])
		gvUDP0 := header.UDP(buf[20:n0])
		if !gvIP0.IsChecksumValid() || !gvUDP0.IsChecksumValid(gvIP0.SourceAddress(), gvIP0.DestinationAddress(), checksum.Checksum(gvUDP0.Payload(), 0)) {
			t.Fatal("seg 0 IPv4/UDP checksum invalid")
		}

		// Segments 1..3: 3-way TSO4 sharing one immutable *ProvenanceEnvelope.
		var tsoRebuilt bytes.Buffer
		var tsoEnvs [3]*ownerbpf.ProvenanceEnvelope
		wantTSOFlags := []uint8{0x80 | 0x10, 0x10, 0x10 | 0x08 | 0x01}
		for i := 0; i < 3; i++ {
			n, p, err := tun.ReadPacketWithProvenance(ctx, buf)
			if err != nil {
				t.Fatalf("TSO seg %d err=%v", i, err)
			}
			env, ok := p.(*ownerbpf.ProvenanceEnvelope)
			if !ok || env == nil {
				t.Fatalf("TSO seg %d nil envelope", i)
			}
			tsoEnvs[i] = env
			ipH := header.IPv4(buf[:n])
			tcpH := header.TCP(buf[20:n])
			if !ipH.IsChecksumValid() || ipH.ID() != uint16(0x3300+i) {
				t.Fatalf("TSO seg %d IPv4 invalid", i)
			}
			if uint8(tcpH.Flags()) != wantTSOFlags[i] || tcpH.SequenceNumber() != uint32(700000+i*1000) {
				t.Fatalf("TSO seg %d flags=%#x seq=%d", i, uint8(tcpH.Flags()), tcpH.SequenceNumber())
			}
			if !tcpH.IsChecksumValid(ipH.SourceAddress(), ipH.DestinationAddress(), checksum.Checksum(tcpH.Payload(), 0), uint16(len(tcpH.Payload()))) {
				t.Fatalf("TSO seg %d TCP checksum invalid", i)
			}
			tsoRebuilt.Write(tcpH.Payload())
		}
		if !bytes.Equal(tsoRebuilt.Bytes(), tcpPayload) {
			t.Fatal("TSO4 payload mismatch")
		}
		if tsoEnvs[0] != tsoEnvs[1] || tsoEnvs[1] != tsoEnvs[2] {
			t.Fatal("TSO4 derived segments did not share the same *ProvenanceEnvelope pointer")
		}
		ownerTSO, stTSO := tsoEnvs[0].ValidateForwarding()
		if stTSO != ownerbpf.EnvelopeKnown || ownerTSO.AppID != "/usr/bin/AppTCP4" {
			t.Fatalf("TSO4 owner=%+v status=%s", ownerTSO, stTSO)
		}

		// Segments 4..6: 3-way IPv6 USO sharing one immutable *ProvenanceEnvelope.
		var usoRebuilt bytes.Buffer
		var usoEnvs [3]*ownerbpf.ProvenanceEnvelope
		for i := 0; i < 3; i++ {
			n, p, err := tun.ReadPacketWithProvenance(ctx, buf)
			if err != nil {
				t.Fatalf("USO6 seg %d err=%v", i, err)
			}
			env, ok := p.(*ownerbpf.ProvenanceEnvelope)
			if !ok || env == nil {
				t.Fatalf("USO6 seg %d nil envelope", i)
			}
			usoEnvs[i] = env
			uH := header.UDP(buf[40:n])
			if !uH.IsChecksumValid(tcpip.AddrFrom16(src6), tcpip.AddrFrom16(dst6), checksum.Checksum(uH.Payload(), 0)) {
				t.Fatalf("USO6 seg %d UDP checksum invalid", i)
			}
			usoRebuilt.Write(uH.Payload())
		}
		if !bytes.Equal(usoRebuilt.Bytes(), usoPayload) {
			t.Fatal("USO6 payload mismatch")
		}
		if usoEnvs[0] != usoEnvs[1] || usoEnvs[1] != usoEnvs[2] {
			t.Fatal("USO6 derived segments did not share the same *ProvenanceEnvelope pointer")
		}
		ownerUSO, stUSO := usoEnvs[0].ValidateForwarding()
		if stUSO != ownerbpf.EnvelopeKnown || ownerUSO.AppID != "/usr/bin/AppUDP6" {
			t.Fatalf("USO6 owner=%+v status=%s", ownerUSO, stUSO)
		}

		if len(tun.provQueue) != 0 || tun.provNext != 0 || tun.readErrors.Load() != 0 {
			t.Fatalf("post-drain queue=%d next=%d readErrors=%d", len(tun.provQueue), tun.provNext, tun.readErrors.Load())
		}

		unbind()
		if !src.closed {
			t.Fatal("unbind did not close reader")
		}
		tun.DetachProvenanceReader()
	}()

	rt.ReleaseSocket(0xa1)
	rt.ReleaseSocket(0xb2)
	rt.ReleaseSocket(0xc3)
	rt.ReleaseActor(actA)
	rt.ReleaseActor(actB)
	rt.ReleaseActor(actC)

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
			t.Fatalf("TUN provenance burst envelopes leaked after drain + GC: ledger=%+v slots=%+v", lm, sm)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTunProvenanceOversizedGSODeliversLeadingAndCountsDrop(t *testing.T) {
	rt := ownerbpf.NewProvenanceRuntime(8, ownerbpf.NewIdentityLedger(16, 16<<10), ownerbpf.NewSocketSlotTable(16))
	_ = enrichTunTestActor(t, rt, 0xd4, 4201, 400_000_000, "/usr/bin/AppOverflow")

	src4 := netip.MustParseAddr("198.18.0.1").As4()
	dst4 := netip.MustParseAddr("198.51.100.10").As4()
	rawOverflow := make([]byte, ownerbpf.VirtioNetHdrLen+40+88*130)
	putTestVirtioHdr(rawOverflow, ownerbpf.VirtioNetHdrFNeedsCsum, ownerbpf.VirtioNetHdrGSOTCPv4, 40, 88, 20, 16)
	ovIP := rawOverflow[ownerbpf.VirtioNetHdrLen:]
	ovIP[0] = 0x45
	ovIP[8] = 64
	ovIP[9] = 6
	copy(ovIP[12:16], src4[:])
	copy(ovIP[16:20], dst4[:])
	binary.BigEndian.PutUint32(ovIP[20+4:20+8], 50000)
	ovIP[20+12] = 5 << 4
	ovIP[20+13] = 0x10 | 0x08 | 0x01 // ACK | PSH | FIN on original 130-seg super-packet

	src := &fakeProvBurstSource{
		bursts: []fakeProvBurst{{
			frames: []fakeProvFrame{{
				raw:      rawOverflow,
				decision: ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 8, Cookie: 0xd4, Serial: 1}},
			}},
		}},
	}
	tun := &Tun{mtu: 9000}
	tun.AttachProvenanceReader(src, func(rawBufs [][]byte, sizes []int, decisions []ownerbpf.ReadDecision, count int, out []*ownerbpf.ProvenanceEnvelope) {
		for i := 0; i < count; i++ {
			out[i] = rt.AcquirePacket(rawBufs[i][ownerbpf.VirtioNetHdrLen:sizes[i]], decisions[i])
		}
	})
	unbind, err := tun.BindPumpThread()
	if err != nil {
		t.Fatalf("BindPumpThread: %v", err)
	}
	defer unbind()

	ctx := context.Background()
	buf := make([]byte, 9000)
	var firstEnv *ownerbpf.ProvenanceEnvelope
	for i := 0; i < ownerbpf.MaxGSOSegmentsPerFrame; i++ {
		n, p, err := tun.ReadPacketWithProvenance(ctx, buf)
		if err != nil || n != 40+88 {
			t.Fatalf("leading seg %d n=%d err=%v", i, n, err)
		}
		env, ok := p.(*ownerbpf.ProvenanceEnvelope)
		if !ok || env == nil {
			t.Fatalf("leading seg %d nil envelope", i)
		}
		if i == 0 {
			firstEnv = env
		} else if env != firstEnv {
			t.Fatalf("leading seg %d did not share burst envelope pointer", i)
		}
		ipH := header.IPv4(buf[:n])
		tcpH := header.TCP(buf[20:n])
		if !ipH.IsChecksumValid() || !tcpH.IsChecksumValid(ipH.SourceAddress(), ipH.DestinationAddress(), checksum.Checksum(tcpH.Payload(), 0), uint16(len(tcpH.Payload()))) {
			t.Fatalf("leading seg %d invalid checksum", i)
		}
		if tcpH.SequenceNumber() != uint32(50000+i*88) {
			t.Fatalf("leading seg %d seq=%d, want %d", i, tcpH.SequenceNumber(), 50000+i*88)
		}
		if uint8(tcpH.Flags())&(0x01|0x08) != 0 {
			t.Fatalf("leading seg %d retained FIN/PSH: %#x", i, uint8(tcpH.Flags()))
		}
	}
	if got := tun.readErrors.Load(); got != 1 {
		t.Fatalf("readErrors = %d, want 1 for overflow drop", got)
	}
	n, p, err := tun.ReadPacketWithProvenance(ctx, buf)
	if err != nil || n != 0 || p != nil {
		t.Fatalf("expected empty drain after %d leading segments, got n=%d p=%#v err=%v", ownerbpf.MaxGSOSegmentsPerFrame, n, p, err)
	}
}

func TestTunProvenanceWholeBurstRefusalOnEpochRebuild(t *testing.T) {
	rawFrame := make([]byte, ownerbpf.VirtioNetHdrLen+28)
	rawFrame[ownerbpf.VirtioNetHdrLen] = 0x45
	binary.BigEndian.PutUint16(rawFrame[ownerbpf.VirtioNetHdrLen+2:ownerbpf.VirtioNetHdrLen+4], 28)
	rawFrame[ownerbpf.VirtioNetHdrLen+8] = 64
	rawFrame[ownerbpf.VirtioNetHdrLen+9] = 17

	src := &fakeProvBurstSource{
		bursts: []fakeProvBurst{{
			frames: []fakeProvFrame{
				{raw: rawFrame, decision: ownerbpf.ReadDecision{Status: ownerbpf.ReadEpochFault, Rebuild: true}},
				{raw: rawFrame, decision: ownerbpf.ReadDecision{Status: ownerbpf.ReadEpochFault, Rebuild: true}},
			},
			err: fmt.Errorf("%w: skip detected in burst", ownerbpf.ErrEpochRebuild),
		}},
	}
	onBurstCalled := false
	tun := &Tun{mtu: 9000}
	tun.AttachProvenanceReader(src, func([][]byte, []int, []ownerbpf.ReadDecision, int, []*ownerbpf.ProvenanceEnvelope) {
		onBurstCalled = true
	})
	unbind, err := tun.BindPumpThread()
	if err != nil {
		t.Fatalf("BindPumpThread: %v", err)
	}
	defer unbind()

	buf := make([]byte, 9000)
	n, p, err := tun.ReadPacketWithProvenance(context.Background(), buf)
	if !errors.Is(err, ownerbpf.ErrEpochRebuild) {
		t.Fatalf("ReadPacketWithProvenance err = %v, want ErrEpochRebuild", err)
	}
	if n != 0 || p != nil || onBurstCalled || len(tun.provQueue) != 0 {
		t.Fatalf("faulted burst leaked partial state: n=%d p=%#v onBurstCalled=%v queue=%d", n, p, onBurstCalled, len(tun.provQueue))
	}
}
