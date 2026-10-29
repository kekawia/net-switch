//go:build windows

package wintun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"golang.org/x/sys/windows"
)

func TestRejectionNightlyFramingTuple(t *testing.T) {
	const capacity, head, tail, size = 8388608, 737548, 740012, 0x04040404
	r := ring{make([]byte, ringBytes(capacity)), capacity}
	binary.LittleEndian.PutUint32(r.data()[head:], size)
	r.store(0, head)
	r.store(4, tail)
	p, next, err := entry(r.data(), capacity, head, tail)
	if !errors.Is(err, ErrCorrupt) || p != nil || next != head {
		t.Fatalf("framing escaped: %d %d %v", len(p), next, err)
	}
	var original *entryRejection
	if !errors.As(err, &original) || original.size != size {
		t.Fatalf("original size lost: %v", err)
	}
	// Prove that evidence retains the rejected read even if the header changes.
	binary.LittleEndian.PutUint32(r.data()[head:], 1228)
	e := captureRejection(r, "invalid entry", head, tail, original.size, nil).(*rejectionError).evidence
	if e.Size != size || e.SizeAgain != 1228 || e.Tail != tail || e.TailAgain != tail || e.Head != head || e.Capacity != capacity || e.CopyLength != tail-head || e.CopyOffset != 0 || e.Changed || r.load(0) != head {
		t.Fatalf("bad evidence: %+v", e)
	}
}

type rejectionOwner struct {
	ended atomic.Bool
	held  atomic.Bool
	head  uint32
}

func (*rejectionOwner) exited() windows.Handle { return 0 }
func (o *rejectionOwner) end(r *rings, _ func(windows.Handle) error) (bool, error) {
	o.held.Store(r.send.load(0) == o.head)
	o.ended.Store(true)
	return false, nil
}

func TestRejectionValidPrefixRecovery(t *testing.T) {
	good := testPacket()
	next := aligned(uint32(len(good)) + 4)
	owner := &rejectionOwner{head: next}
	var reopened atomic.Bool
	s := newTestSession(t, owner, func() (*rings, error) {
		if !owner.ended.Load() {
			return nil, errors.New("reopened before old registration closed")
		}
		reopened.Store(true)
		r, err := allocateRings(MinCapacity)
		if err != nil {
			return nil, err
		}
		if err = r.createEvents(); err != nil {
			r.close()
			return nil, err
		}
		return r, nil
	})
	r := s.rings
	bad := packet.UDP(netip.MustParseAddrPort("198.18.0.1:1"), netip.MustParseAddrPort("198.18.0.2:2"), bytes.Repeat([]byte{4}, 1200))
	if len(bad) != 1228 {
		t.Fatal("wrong nightly-shaped packet size")
	}
	binary.LittleEndian.PutUint32(r.send.data(), uint32(len(good)))
	copy(r.send.data()[4:], good)
	binary.LittleEndian.PutUint32(r.send.data()[next:], uint32(len(bad)))
	copy(r.send.data()[next+4:], bad)
	r.send.data()[next+4] = 0x75 // invalid IP version
	r.send.store(4, next+aligned(uint32(len(bad))+4))
	bufs, sizes := [][]byte{make([]byte, 1500), make([]byte, 1500)}, []int{-1, -1}
	n, err := s.ReadBatch(context.Background(), bufs, sizes)
	if err != nil || n != 1 || sizes[1] != -1 || !bytes.Equal(bufs[0][:sizes[0]], good) {
		t.Fatalf("invalid prefix: n=%d sizes=%v err=%v", n, sizes, err)
	}
	waitForEvent(t, s, "recovered")
	stats := s.Stats()
	if !owner.held.Load() || !reopened.Load() || stats.Corruptions != 1 || stats.Recoveries != 1 || stats.FirstRejection == nil || stats.FirstRejection.Primary.Predicate != "version" {
		t.Fatalf("recovery/capture: %+v", stats)
	}
}

func TestRejectionZeroPlaceholderControl(t *testing.T) {
	r := &rings{send: ring{make([]byte, ringBytes(MinCapacity)), MinCapacity}}
	binary.LittleEndian.PutUint32(r.send.data(), 1228)
	r.send.store(4, 1232)
	n, err := r.read([][]byte{make([]byte, 1500)}, make([]int, 1))
	if err != nil || n != 0 || r.placeholders != 1 || r.head != 1232 {
		t.Fatalf("placeholder: n=%d error=%v drops=%d head=%d", n, err, r.placeholders, r.head)
	}
}

func TestRejectionIndependentValidation(t *testing.T) {
	// Existing packet builders and checksum tests supply production-format
	// packets; flip every byte and truncate at every offset to test parity.
	packets := [][]byte{testPacket(), make([]byte, 40)}
	for _, pair := range [][2]string{{"198.18.0.1:1234", "198.18.0.2:4321"}, {"[fd00::1]:1234", "[fd00::2]:4321"}} {
		src, dst := netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1])
		packets = append(packets, packet.UDP(src, dst, []byte("odd payload")), packet.Reset(src, dst, 1, 2, true))
		if src.Addr().Is6() {
			udp := packets[len(packets)-2]
			body := append([]byte{17, 0, 0, 0, 0, 0, 0, 0}, udp[40:]...)
			packets = append(packets, packet.IP(src.Addr(), dst.Addr(), 0, body), packet.IP(src.Addr(), dst.Addr(), 44, make([]byte, 8)))
		}
	}
	for _, p := range packets {
		check := func(p []byte) {
			a, b := diagnoseIP(p), independentlyDiagnoseIP(p)
			if a != b || (a.Predicate == "") != validIP(p) {
				t.Fatalf("parsers disagree for %x: %+v %+v valid=%v", p, a, b, validIP(p))
			}
		}
		check(p)
		for i := range p {
			check(p[:i])
			q := bytes.Clone(p)
			q[i] ^= 0xff
			check(q)
		}
	}
}

func TestRejectionPredicates(t *testing.T) {
	src, dst := netip.MustParseAddrPort("198.18.0.1:1"), netip.MustParseAddrPort("198.18.0.2:2")
	for _, tc := range []struct {
		want   string
		change func([]byte)
	}{
		{"version", func(p []byte) { p[0] = 0x75 }},
		{"ihl", func(p []byte) { p[0] = 0x41 }},
		{"total_length", func(p []byte) { p[3]++ }},
		{"ipv4_checksum", func(p []byte) { p[10] ^= 1 }},
		{"transport_length", func(p []byte) { p[25]++ }},
		{"udp_checksum", func(p []byte) { p[len(p)-1] ^= 1 }},
	} {
		t.Run(tc.want, func(t *testing.T) {
			p := packet.UDP(src, dst, []byte("odd"))
			tc.change(p)
			a, b := diagnoseIP(p), independentlyDiagnoseIP(p)
			if a.Predicate != tc.want || a != b || validIP(p) {
				t.Fatalf("%+v %+v", a, b)
			}
		})
	}
	p := packet.Reset(src, dst, 1, 2, true)
	p[len(p)-1] ^= 1
	if a, b := diagnoseIP(p), independentlyDiagnoseIP(p); a.Predicate != "tcp_checksum" || a != b || validIP(p) {
		t.Fatalf("TCP: %+v %+v", a, b)
	}
	p = packet.IP(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), 0, []byte{17, 2, 0, 0, 0, 0, 0, 0})
	if a, b := diagnoseIP(p), independentlyDiagnoseIP(p); a.Predicate != "extension_length" || a != b || validIP(p) {
		t.Fatalf("extension: %+v %+v", a, b)
	}
}

func TestRejectionSecondCopyNeverAccepted(t *testing.T) {
	r := ring{make([]byte, ringBytes(MinCapacity)), MinCapacity}
	p := testPacket()
	binary.LittleEndian.PutUint32(r.data(), uint32(len(p)))
	copy(r.data()[4:], p)
	r.store(4, aligned(uint32(len(p))+4))
	first := bytes.Clone(p)
	first[0] = 0x75
	err := captureRejection(r, "packet failed validation", 0, r.load(4), uint32(len(p)), first)
	e := err.(*rejectionError).evidence
	if !errors.Is(err, ErrCorrupt) || !e.Changed || e.Primary.Predicate != "version" || e.Independent.Predicate != "version" || e.FirstHex == e.SecondHex || r.load(0) != 0 {
		t.Fatalf("second copy accepted/lost: %v", err)
	}
}

func TestRejectionBoundedCopyAndAcquiredTail(t *testing.T) {
	r := ring{make([]byte, ringBytes(MinCapacity)), MinCapacity}
	first := bytes.Repeat([]byte{0x75}, MaxPacketSize)
	copy(r.data()[4:], first)
	binary.LittleEndian.PutUint32(r.data(), MaxPacketSize)
	// A change beyond the logged prefix must still be detected. A new Tail
	// must not enlarge the copy beyond the originally acquired publication.
	r.data()[4+MaxPacketSize-1] ^= 1
	r.store(4, ^uint32(0))
	e := captureRejection(r, "packet failed validation", 0, 65540, MaxPacketSize, first).(*rejectionError).evidence
	if e.CopyLength != MaxPacketSize || len(e.FirstHex) != 512 || len(e.SecondHex) != 512 || !e.Changed || e.FirstHex != e.SecondHex || e.TailAgain != ^uint32(0) || r.load(0) != 0 {
		t.Fatalf("bounds/tail comparison: %+v", e)
	}
	// Preserve the reread which actually failed the length predicate, even
	// if the driver header has changed again by capture time.
	e = captureRejection(r, "packet length changed", 0, 65540, MaxPacketSize, first, 19).(*rejectionError).evidence
	if e.Size != MaxPacketSize || e.SizeAgain != 19 {
		t.Fatalf("lost failing reread: %+v", e)
	}
}
