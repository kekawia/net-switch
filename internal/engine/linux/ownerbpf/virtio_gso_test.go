package ownerbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func putVirtioHdr(b []byte, flags, gsoType uint8, hdrLen, gsoSize, csumStart, csumOffset uint16) {
	b[0] = flags
	b[1] = gsoType
	binary.LittleEndian.PutUint16(b[2:4], hdrLen)
	binary.LittleEndian.PutUint16(b[4:6], gsoSize)
	binary.LittleEndian.PutUint16(b[6:8], csumStart)
	binary.LittleEndian.PutUint16(b[8:10], csumOffset)
}

func TestVirtioGSONormalizationAndOverflowPreservation(t *testing.T) {
	arena := make([]byte, 256<<10)
	var spans []VirtioSegmentSpan
	used := 0

	// 1. GSO_NONE with VIRTIO_NET_HDR_F_NEEDS_CSUM (UDPv4).
	src4 := netip.MustParseAddr("198.18.0.1").As4()
	dst4 := netip.MustParseAddr("198.51.100.10").As4()
	udpPayload := []byte("hello-needs-csum!")
	rawUDPCSUM := make([]byte, VirtioNetHdrLen+20+8+len(udpPayload))
	putVirtioHdr(rawUDPCSUM, VirtioNetHdrFNeedsCsum, VirtioNetHdrGSONone, 28, 0, 20, 6)
	ip4 := rawUDPCSUM[VirtioNetHdrLen:]
	ip4[0] = 0x45
	binary.BigEndian.PutUint16(ip4[2:4], uint16(20+8+len(udpPayload)))
	ip4[8] = 64
	ip4[9] = 17
	copy(ip4[12:16], src4[:])
	copy(ip4[16:20], dst4[:])
	binary.BigEndian.PutUint16(ip4[10:12], ^foldOnesComplement(checksumBytes(0, ip4[:20])))
	udp4 := ip4[20:]
	binary.BigEndian.PutUint16(udp4[0:2], 51000)
	binary.BigEndian.PutUint16(udp4[2:4], 443)
	binary.BigEndian.PutUint16(udp4[4:6], uint16(8+len(udpPayload)))
	// Kernel CHECKSUM_PARTIAL stores ~csum_tcpudp_magic (uninverted pseudo-header sum).
	pseudo := foldOnesComplement(checksumBytes(0, ip4[12:20]) + 17 + uint32(8+len(udpPayload)))
	binary.BigEndian.PutUint16(udp4[6:8], pseudo)
	copy(udp4[8:], udpPayload)

	var err error
	used, spans, err = AppendNormalizedVirtioFrame(rawUDPCSUM, arena, used, spans)
	if err != nil || len(spans) != 1 {
		t.Fatalf("GSO_NONE NEEDS_CSUM err=%v spans=%d", err, len(spans))
	}
	seg0 := arena[spans[0].Offset : spans[0].Offset+spans[0].Length]
	gvIP4 := header.IPv4(seg0)
	if !gvIP4.IsChecksumValid() {
		t.Fatal("IPv4 checksum invalid on GSO_NONE")
	}
	gvUDP := header.UDP(seg0[20:])
	wantUDPCsum := checksum.Combine(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, gvIP4.SourceAddress(), gvIP4.DestinationAddress(), uint16(len(gvUDP))),
		checksum.Checksum(gvUDP.Payload(), 0),
	)
	if !gvUDP.IsChecksumValid(gvIP4.SourceAddress(), gvIP4.DestinationAddress(), checksum.Checksum(gvUDP.Payload(), 0)) {
		t.Fatalf("UDP NEEDS_CSUM invalid: got=%#x want=%#x", gvUDP.Checksum(), ^wantUDPCsum)
	}

	// 2. GSO_TCPV4 across 3 segments (1000 + 1000 + 350 bytes) with PSH|FIN|CWR|ACK.
	tcpPayload := bytes.Repeat([]byte("A1B2C3D4E5"), 235) // 2350 bytes
	rawTSO4 := make([]byte, VirtioNetHdrLen+20+20+len(tcpPayload))
	putVirtioHdr(rawTSO4, VirtioNetHdrFNeedsCsum, VirtioNetHdrGSOTCPv4|VirtioNetHdrGSOECN, 40, 1000, 20, 16)
	tsoIP4 := rawTSO4[VirtioNetHdrLen:]
	tsoIP4[0] = 0x45
	binary.BigEndian.PutUint16(tsoIP4[2:4], uint16(40+len(tcpPayload)))
	binary.BigEndian.PutUint16(tsoIP4[4:6], 0x2200)
	tsoIP4[8] = 64
	tsoIP4[9] = 6
	copy(tsoIP4[12:16], src4[:])
	copy(tsoIP4[16:20], dst4[:])
	tsoTCP := tsoIP4[20:]
	binary.BigEndian.PutUint16(tsoTCP[0:2], 52000)
	binary.BigEndian.PutUint16(tsoTCP[2:4], 8443)
	binary.BigEndian.PutUint32(tsoTCP[4:8], 900000)
	tsoTCP[12] = 5 << 4
	tsoTCP[13] = 0x80 | 0x10 | 0x08 | 0x01 // CWR | ACK | PSH | FIN
	copy(tsoTCP[20:], tcpPayload)

	used, spans, err = AppendNormalizedVirtioFrame(rawTSO4, arena, used, spans)
	if err != nil || len(spans) != 4 {
		t.Fatalf("GSO_TCPV4 err=%v spans=%d, want 4", err, len(spans))
	}
	var rebuilt bytes.Buffer
	wantSizes := []int{1000, 1000, 350}
	wantFlags := []uint8{0x80 | 0x10, 0x10, 0x10 | 0x08 | 0x01}
	for i := 0; i < 3; i++ {
		sp := spans[1+i]
		seg := arena[sp.Offset : sp.Offset+sp.Length]
		ipH := header.IPv4(seg)
		if !ipH.IsChecksumValid() || ipH.ID() != uint16(0x2200+i) || int(ipH.TotalLength()) != 40+wantSizes[i] {
			t.Fatalf("TSO4 seg %d IPv4 invalid: valid=%v id=%#x len=%d", i, ipH.IsChecksumValid(), ipH.ID(), ipH.TotalLength())
		}
		tcpH := header.TCP(seg[20:])
		if uint8(tcpH.Flags()) != wantFlags[i] {
			t.Fatalf("TSO4 seg %d flags = %#x, want %#x", i, uint8(tcpH.Flags()), wantFlags[i])
		}
		if tcpH.SequenceNumber() != uint32(900000+i*1000) {
			t.Fatalf("TSO4 seg %d seq = %d, want %d", i, tcpH.SequenceNumber(), 900000+i*1000)
		}
		payloadCsum := checksum.Checksum(tcpH.Payload(), 0)
		if !tcpH.IsChecksumValid(ipH.SourceAddress(), ipH.DestinationAddress(), payloadCsum, uint16(len(tcpH.Payload()))) {
			t.Fatalf("TSO4 seg %d TCP checksum invalid", i)
		}
		rebuilt.Write(tcpH.Payload())
	}
	if !bytes.Equal(rebuilt.Bytes(), tcpPayload) {
		t.Fatal("TSO4 reassembled payload mismatch")
	}

	// 3. GSO_TCPV6 + GSO_UDP_L4 (IPv6 USO) + pathological MaxGSOSegmentsPerFrame+1 overflow preserving prior spans.
	src6 := netip.MustParseAddr("fdfe:dcba:9876::1").As16()
	dst6 := netip.MustParseAddr("2001:db8::42").As16()
	usoPayload := bytes.Repeat([]byte("USO6"), 300) // 1200 bytes -> 500 + 500 + 200
	rawUSO6 := make([]byte, VirtioNetHdrLen+40+8+len(usoPayload))
	putVirtioHdr(rawUSO6, VirtioNetHdrFNeedsCsum, VirtioNetHdrGSOUDPL4, 48, 500, 40, 6)
	ip6 := rawUSO6[VirtioNetHdrLen:]
	ip6[0] = 0x60
	ip6[6] = 17
	ip6[7] = 64
	copy(ip6[8:24], src6[:])
	copy(ip6[24:40], dst6[:])
	binary.BigEndian.PutUint16(ip6[40:42], 53000)
	binary.BigEndian.PutUint16(ip6[42:44], 4433)
	copy(ip6[48:], usoPayload)

	used, spans, err = AppendNormalizedVirtioFrame(rawUSO6, arena, used, spans)
	if err != nil || len(spans) != 7 {
		t.Fatalf("GSO_UDP_L4 v6 err=%v spans=%d, want 7", err, len(spans))
	}
	for i := 0; i < 3; i++ {
		sp := spans[4+i]
		seg := arena[sp.Offset : sp.Offset+sp.Length]
		ipH := header.IPv6(seg)
		uH := header.UDP(seg[40:])
		if !uH.IsChecksumValid(tcpip.AddrFrom16(src6), tcpip.AddrFrom16(dst6), checksum.Checksum(uH.Payload(), 0)) {
			t.Fatalf("USO6 seg %d UDP checksum invalid (len=%d)", i, ipH.PayloadLength())
		}
	}

	// 4. Oversized 130-segment GSO frame (like TCP_MAXSEG=88) must return
	// ErrVirtioSegmentOverflow while preserving all 7 prior spans AND emitting
	// the leading 128 wire-valid segments (with FIN/PSH cleared) for TCP progress.
	prevUsed := used
	rawOverflow := make([]byte, VirtioNetHdrLen+40+88*130)
	putVirtioHdr(rawOverflow, VirtioNetHdrFNeedsCsum, VirtioNetHdrGSOTCPv4, 40, 88, 20, 16)
	ovIP := rawOverflow[VirtioNetHdrLen:]
	ovIP[0] = 0x45
	ovIP[8] = 64
	ovIP[9] = 6
	copy(ovIP[12:16], src4[:])
	copy(ovIP[16:20], dst4[:])
	ovIP[20+12] = 5 << 4
	ovIP[20+13] = 0x10 | 0x08 | 0x01 // ACK | PSH | FIN on original super-packet
	usedAfter, spansAfter, ovErr := AppendNormalizedVirtioFrame(rawOverflow, arena, used, spans)
	if !errors.Is(ovErr, ErrVirtioSegmentOverflow) {
		t.Fatalf("expected ErrVirtioSegmentOverflow, got %v", ovErr)
	}
	if len(spansAfter) != 7+MaxGSOSegmentsPerFrame || usedAfter <= prevUsed {
		t.Fatalf("overflow spans=%d (want %d) used=%d/%d", len(spansAfter), 7+MaxGSOSegmentsPerFrame, usedAfter, prevUsed)
	}
	for i := 0; i < MaxGSOSegmentsPerFrame; i++ {
		sp := spansAfter[7+i]
		seg := arena[sp.Offset : sp.Offset+sp.Length]
		ipH := header.IPv4(seg)
		tcpH := header.TCP(seg[20:])
		if !ipH.IsChecksumValid() || !tcpH.IsChecksumValid(ipH.SourceAddress(), ipH.DestinationAddress(), checksum.Checksum(tcpH.Payload(), 0), uint16(len(tcpH.Payload()))) {
			t.Fatalf("overflow leading seg %d invalid checksum", i)
		}
		if uint8(tcpH.Flags())&(0x01|0x08) != 0 {
			t.Fatalf("overflow leading seg %d retained FIN/PSH: %#x", i, uint8(tcpH.Flags()))
		}
	}

	// 5. Malformed frame leaves arenaUsed and all prior spans completely untouched.
	malUsed, malSpans, malErr := AppendNormalizedVirtioFrame([]byte{1, 2, 3}, arena, usedAfter, spansAfter)
	if !errors.Is(malErr, ErrVirtioShortFrame) || malUsed != usedAfter || len(malSpans) != len(spansAfter) {
		t.Fatalf("malformed frame altered burst state: err=%v used=%d/%d spans=%d/%d", malErr, malUsed, usedAfter, len(malSpans), len(spansAfter))
	}
}
