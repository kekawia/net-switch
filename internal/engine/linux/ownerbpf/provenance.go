// Package ownerbpf contains isolated Linux attribution proofs. It is not wired
// into Owners, routing, or the forwarding engine.
package ownerbpf

import (
	"errors"
	"math/bits"
	"unsafe"
)

const (
	ProvenanceABI = 3
	PacketSlots   = 2048
	ReaderLimit   = 4
	CPULimit      = 512
	QueueReserve  = 32

	// These statuses describe a packet-cookie observation, never an app identity.
	PacketCaptured  = 1
	ReaderStamped   = 1
	TerminalConsume = 1
	TerminalFree    = 2
)

// PacketRecord is native endian. Kernel addresses are map keys, not evidence
// exported to callers. Identity and ownership are deliberately unimplemented.
type PacketRecord struct {
	ABI, Status            uint32
	Epoch                  uint64
	Ifindex, NetNS         uint32
	CPU, Classification    uint32
	Serial, Cookie         uint64
	Length, Users          uint32
	OwnerVersion, Identity uint64
	Reserved               [56]byte
}

type ReaderKey struct {
	TGID, TID uint32
}

type ReaderRegistration struct {
	Slot, Ifindex, NetNS, Flags uint32
	Generation, Epoch           uint64
	StartBoottime, StampGuard   uint64
}

type ReadControl struct {
	ABI, Reserved       uint32
	Registration, Epoch uint64
	Sequence, Armed     uint64
	Padding             [24]byte
}

type ReadCompletion struct {
	Count, Sequence, Registration uint64
	Terminal, Status              uint32
	Padding                       [32]byte
}

type ReaderSlot struct {
	Control    ReadControl
	Completion ReadCompletion
	Packet     PacketRecord
}

// Compile-time size checks supplement the field-offset and C interchange tests.
var (
	_ [128 - unsafe.Sizeof(PacketRecord{})]byte
	_ [unsafe.Sizeof(PacketRecord{}) - 128]byte
	_ [8 - unsafe.Sizeof(ReaderKey{})]byte
	_ [unsafe.Sizeof(ReaderKey{}) - 8]byte
	_ [48 - unsafe.Sizeof(ReaderRegistration{})]byte
	_ [unsafe.Sizeof(ReaderRegistration{}) - 48]byte
	_ [256 - unsafe.Sizeof(ReaderSlot{})]byte
	_ [unsafe.Sizeof(ReaderSlot{}) - 256]byte
)

// RequiredPacketSlots implements P = next_power_of_two(Q+C+R+32). It also
// validates the experiment's bounds, independently of the allocation ceiling.
// Q must be the actual read-back TUN queue length, not the output queue size.
func RequiredPacketSlots(queue, cpus, readers uint64) (uint64, error) {
	if queue == 0 || cpus == 0 || cpus > CPULimit || readers == 0 || readers > ReaderLimit {
		return 0, errors.New("invalid provenance queue/CPU/reader bounds")
	}
	extra := cpus + readers + QueueReserve
	if queue > ^uint64(0)-extra {
		return 0, errors.New("provenance capacity sum overflow")
	}
	n := queue + extra
	shift := bits.Len64(n - 1)
	if shift == 64 {
		return 0, errors.New("provenance capacity rounding overflow")
	}
	return uint64(1) << shift, nil
}

func ValidateProofCapacity(queue, cpus, readers uint64) error {
	n, err := RequiredPacketSlots(queue, cpus, readers)
	if err != nil {
		return err
	}
	if n > PacketSlots {
		return errors.New("provenance queue exceeds the 2048-slot proof allocation")
	}
	return nil
}

// ReadBinding is the userspace-owned expectation for one armed read. A future
// locked-thread pump must allocate non-repeating generations/sequences and
// consume each result once. This predicate alone does not implement that pump.
type ReadBinding struct {
	Slot, Ifindex, NetNS uint32
	Registration, Epoch  uint64
	Sequence             uint64
}

type ReadStatus string

const (
	ReadCookie     ReadStatus = "packet_cookie"
	ReadNoData     ReadStatus = "no_data"
	ReadMissing    ReadStatus = "delivered_without_record"
	ReadAmbiguous  ReadStatus = "ambiguous_terminal"
	ReadInvalid    ReadStatus = "invalid_evidence"
	ReadEpochFault ReadStatus = "epoch_fault"
)

// ReadDecision contains a copied value, never a pointer into a map. Cookie
// success cannot be counted as complete identity. Rebuild requests quiescence
// and full collection reload; it does not authorize resetting a live map.
type ReadDecision struct {
	Status  ReadStatus
	Rebuild bool
	Packet  PacketRecord
}

// CheckRead validates an already-copied slot after the synchronous read on its
// registered thread. n/error are the actual syscall outcome. epochFaults must
// be sampled before acceptance; the pump must sample it again next iteration.
// No packet bytes, tuple, scanner answer, or arrival position enter this join.
func CheckRead(b ReadBinding, r ReaderRegistration, s ReaderSlot, n int, readErr error, epochFaults uint64) ReadDecision {
	refuse := func(status ReadStatus, rebuild bool) ReadDecision {
		return ReadDecision{Status: status, Rebuild: rebuild}
	}
	if epochFaults != 0 {
		return refuse(ReadEpochFault, true)
	}
	if n <= 0 || readErr != nil {
		// A terminal event forbids retrying this attempt under the same sequence.
		return refuse(ReadNoData, s.Completion.Count != 0)
	}
	if s.Completion.Count == 0 {
		return refuse(ReadMissing, true)
	}
	if s.Completion.Count != 1 || s.Completion.Terminal != TerminalConsume {
		return refuse(ReadAmbiguous, false)
	}
	c, done, p := s.Control, s.Completion, s.Packet
	if b.Slot >= ReaderLimit || b.Ifindex == 0 || b.NetNS == 0 ||
		b.Registration == 0 || b.Epoch == 0 || b.Sequence == 0 ||
		r.Slot != b.Slot || r.Ifindex != b.Ifindex || r.NetNS != b.NetNS ||
		r.Generation != b.Registration || r.Epoch != b.Epoch ||
		r.Flags != ReaderStamped || r.StartBoottime == 0 || r.StampGuard != 0 ||
		c.ABI != ProvenanceABI || c.Reserved != 0 || c.Padding != [24]byte{} ||
		c.Registration != b.Registration || c.Epoch != b.Epoch ||
		c.Sequence != b.Sequence || c.Armed != 1 ||
		done.Sequence != b.Sequence || done.Registration != b.Registration ||
		done.Status != PacketCaptured || done.Padding != [32]byte{} ||
		p.ABI != ProvenanceABI || p.Status != PacketCaptured || p.Epoch != b.Epoch ||
		p.Ifindex != b.Ifindex || p.NetNS != b.NetNS ||
		p.Serial == 0 || p.Cookie == 0 || p.Length == 0 || p.Users != 1 ||
		p.OwnerVersion != 0 || p.Identity != 0 || p.Reserved != [56]byte{} {
		return refuse(ReadInvalid, true)
	}
	return ReadDecision{Status: ReadCookie, Packet: p}
}
