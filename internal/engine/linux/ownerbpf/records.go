// Package ownerbpf contains isolated Linux attribution feasibility probes.
// Nothing in this package is registered with Owners or the forwarding engine.
package ownerbpf

import (
	"context"
	"time"
)

const ABI = 1
const RecordLimit = 256

// ActorKey is the immutable send-attempt key in bpf/abi.h.
type ActorKey struct {
	Cookie, Start, Exec uint64
	TGID, Reserved      uint32
}

type ActorEvidence struct {
	Inode, Device, ObservedNS uint64
	ABI, Reserved             uint32
}

type TupleKey struct {
	Source, Destination, Ports [4]byte
}

type TupleEvidence struct {
	FirstCookie, Conflicts uint64
}

type Counters struct {
	Attempts, Packets, CookieMissing, ReadFailure uint64
	InsertFailure, Poison, UnsupportedPacket      uint64
}

type Status uint8

const (
	Missing Status = iota
	Unavailable
	IncompleteIdentity
	AmbiguousGeneration
	Poisoned
	Expired
)

// Result deliberately has no known-owner representation. Evidence from a
// send attempt and a current tuple cannot satisfy the three required joins.
type Result struct {
	Status     Status
	Provenance string
}

func (r Result) AllowsScanner() bool { return r.Status == Missing || r.Status == Unavailable }

// Decide is conservative even with intact maps: no packet-generation token
// or validated app metadata exists in this proof ABI. Call at the forwarding
// decision with the original shared context, never a renewed setup deadline.
func Decide(ctx context.Context, now time.Time, counts Counters, tuple *TupleEvidence) Result {
	s := IncompleteIdentity
	switch {
	case ctx.Err() != nil:
		s = Expired
	case counts.Poison != 0 || counts.InsertFailure != 0:
		s = Poisoned
	case tuple == nil:
		s = Missing
	case tuple.Conflicts != 0:
		s = AmbiguousGeneration
	}
	if deadline, ok := ctx.Deadline(); ok && !now.Before(deadline) {
		s = Expired
	}
	return Result{s, "bpf-proof-v1"}
}
