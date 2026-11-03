//go:build linux

package linux

import (
	"encoding/binary"
	"errors"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func appendNetlinkMsg(dst []byte, msgType, flags uint16, seq uint32, payload []byte) []byte {
	msgLen := unix.NLMSG_HDRLEN + len(payload)
	aligned := (msgLen + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
	start := len(dst)
	dst = append(dst, make([]byte, aligned)...)
	binary.NativeEndian.PutUint32(dst[start:start+4], uint32(msgLen))
	binary.NativeEndian.PutUint16(dst[start+4:start+6], msgType)
	binary.NativeEndian.PutUint16(dst[start+6:start+8], flags)
	binary.NativeEndian.PutUint32(dst[start+8:start+12], seq)
	copy(dst[start+unix.NLMSG_HDRLEN:start+msgLen], payload)
	return dst
}

func makeInetDiagPayload(family byte, cookie uint64, extraAttr []byte) []byte {
	b := make([]byte, 72+len(extraAttr))
	b[0] = family
	b[1] = 1
	binary.NativeEndian.PutUint32(b[44:48], uint32(cookie))
	binary.NativeEndian.PutUint32(b[48:52], uint32(cookie>>32))
	copy(b[72:], extraAttr)
	return b
}

func TestParseNetlinkDiagCookiesZeroAllocAndEdgeCases(t *testing.T) {
	const seq = 77
	// Include an unaligned 5-byte attribute (padded to 8 bytes inside inet_diag,
	// plus an unaligned 5-byte NLMSG_DONE payload) to verify NLMSG_ALIGN framing.
	attr := make([]byte, 8)
	binary.NativeEndian.PutUint16(attr[0:2], 5)
	binary.NativeEndian.PutUint16(attr[2:4], 10)
	attr[4] = unix.IPPROTO_TCP

	var frame []byte
	frame = appendNetlinkMsg(frame, 20, unix.NLM_F_MULTI, seq, makeInetDiagPayload(unix.AF_INET, 0x1122334455667788, attr))
	frame = appendNetlinkMsg(frame, 20, unix.NLM_F_MULTI, seq, makeInetDiagPayload(unix.AF_INET6, 0x99aabbccddeeff01, nil))
	frame = appendNetlinkMsg(frame, 20, unix.NLM_F_MULTI, seq, makeInetDiagPayload(unix.AF_INET, 0, nil))
	donePayload := make([]byte, 4)
	frame = appendNetlinkMsg(frame, unix.NLMSG_DONE, unix.NLM_F_MULTI, seq, donePayload)

	var got []uint64
	done, err := parseNetlinkDiagCookies(frame, seq, func(c uint64) {
		got = append(got, c)
	})
	if err != nil || !done {
		t.Fatalf("parseNetlinkDiagCookies: done=%v err=%v", done, err)
	}
	if len(got) != 2 || got[0] != 0x1122334455667788 || got[1] != 0x99aabbccddeeff01 {
		t.Fatalf("unexpected cookies: %#x", got)
	}

	var sink uint64
	allocs := testing.AllocsPerRun(100, func() {
		d, parseErr := parseNetlinkDiagCookies(frame, seq, func(c uint64) {
			sink ^= c
		})
		if parseErr != nil || !d {
			t.Fatalf("alloc check failed: d=%v err=%v", d, parseErr)
		}
	})
	if allocs != 0 {
		t.Fatalf("parseNetlinkDiagCookies allocated %.1f objects/run, want 0 (sink=%d)", allocs, sink)
	}

	// Sequence mismatch fails closed.
	if _, err := parseNetlinkDiagCookies(frame, seq+1, nil); err == nil {
		t.Fatal("expected sequence mismatch error")
	}

	// NLM_F_DUMP_INTR returns errDiagInterrupted.
	intrFrame := appendNetlinkMsg(nil, 20, unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR, seq, makeInetDiagPayload(unix.AF_INET, 1, nil))
	if _, err := parseNetlinkDiagCookies(intrFrame, seq, nil); !errors.Is(err, errDiagInterrupted) {
		t.Fatalf("NLM_F_DUMP_INTR got %v, want errDiagInterrupted", err)
	}

	// Non-zero NLMSG_DONE errno returns the negated syscall.Errno.
	errDone := make([]byte, 4)
	negEBUSY := -int32(unix.EBUSY)
	binary.NativeEndian.PutUint32(errDone, uint32(negEBUSY))
	doneErrFrame := appendNetlinkMsg(nil, unix.NLMSG_DONE, 0, seq, errDone)
	if _, err := parseNetlinkDiagCookies(doneErrFrame, seq, nil); !errors.Is(err, syscall.Errno(unix.EBUSY)) {
		t.Fatalf("NLMSG_DONE errno got %v, want EBUSY", err)
	}
}
