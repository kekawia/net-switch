//go:build windows

package wintun

import (
	"net/netip"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
)

// The signed 0.14.1 driver gives each Receive ring packet to Windows by
// reference and publishes Receive.Head after it has dropped its lock, so two
// threads returning packets can publish out of order and an older Head can
// replace a newer one. A writer that takes its free space from that word then
// writes over packets Windows still holds: applications read another stream's
// bytes, or the driver meets garbage at its own read position and stops the
// ring. Upstream moved the store under the lock in dd050927 (2026-02-20); no
// signed build has it. See README.md, "Receive.Head race in 0.14.1".
//
// receiveGuard is the writer's own account of the ring, so that nothing the
// driver publishes late can enlarge it. Positions are on an unwrapped line: a
// position's ring offset is its value modulo the capacity.
//
//   - A published Head is accepted only if it is the end of an entry still
//     outstanding. Every late store publishes the end of an entry that really
//     was released, so one that lies ahead of the accepted Head is safe to
//     take; one that does not is ignored and the accepted Head stands.
//   - An entry never ends where an entry of the lap before ended (shift). A
//     late store of that older end could otherwise pass for the new one.
//   - Room is computed from the accepted Head alone.
//
// It covers late stores up to one lap of writes old. All of it belongs to the
// one writer, under the session's write lock.
type receiveGuard struct {
	started      bool
	vhead, vtail uint64   // the accepted Head, and the end of the last entry written
	ends         endQueue // entry ends in write order, none older than one lap
	released     int      // how many of them are at or below vhead
	ignoring     bool     // the raw Head in the ring is one this account refused
	ignored      uint32   // that value, so one late store is counted once
	probed       bool     // the stall probe went out since vhead last advanced
	counts       guardCounts
}

type guardCounts struct{ ignoredHeads, shiftedEntries, headProbes uint64 }

// receiveReserve is room ordinary packets never use, kept for the stall probe.
const receiveReserve = 64

// headProbe is an IPv4 header whose checksum is wrong. The driver gives it to
// Windows like any packet and Windows drops and returns it at once.
var headProbe = func() []byte {
	p := packet.IP(netip.IPv4Unspecified(), netip.IPv4Unspecified(), 253, nil)
	p[10] ^= 0xff
	return p
}()

func (g *receiveGuard) start(capacity, tail uint32) {
	// One lap in, so that "one lap before" never reaches below zero.
	g.vhead = uint64(capacity) + uint64(tail)
	g.vtail, g.started = g.vhead, true
}

// observe takes the raw Head and accepts it only as the end of an outstanding
// entry. The span from vhead to vtail is shorter than the ring, so an offset
// names at most one position in it.
func (g *receiveGuard) observe(raw, capacity uint32) {
	mask := capacity - 1
	if raw == uint32(g.vhead)&mask {
		g.ignoring = false
		return
	}
	at := g.vhead + uint64((raw-uint32(g.vhead))&mask)
	if at <= g.vtail {
		lo, hi := g.released, g.ends.n
		for lo < hi {
			mid := int(uint(lo+hi) >> 1)
			if g.ends.at(mid) < at {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo < g.ends.n && g.ends.at(lo) == at {
			g.vhead, g.released = at, lo+1
			g.ignoring, g.probed = false, false
			return
		}
	}
	if !g.ignoring || g.ignored != raw {
		g.ignoring, g.ignored = true, raw
		g.counts.ignoredHeads++
	}
}

func (g *receiveGuard) room(capacity uint32) uint64 {
	return uint64(capacity) - 4 - (g.vtail - g.vhead)
}

// shift reports how many bytes to add after a packet so that its entry does
// not end where an entry of the lap before ended, and how many queued ends
// are older than that lap. Entry ends are at least eight bytes apart, so four
// bytes always clear the collision.
func (g *receiveGuard) shift(size, capacity uint32) (extra uint32, old int) {
	before := g.vtail + uint64(size) - uint64(capacity)
	for old < g.ends.n && g.ends.at(old) < before {
		old++
	}
	if old < g.ends.n && g.ends.at(old) == before {
		extra = 4
	}
	return
}

// wrote records an entry of size bytes at the tail and forgets the old ends
// shift counted. They are behind the accepted Head: the caller checked that
// the entry fits the room, which puts one lap before its end below vhead.
func (g *receiveGuard) wrote(size uint32, old int) {
	g.ends.drop(old)
	g.released = max(g.released-old, 0)
	g.vtail += uint64(size)
	g.ends.push(g.vtail)
}

// endQueue is a growing ring of positions in increasing order.
type endQueue struct {
	buf      []uint64 // a power of two long, or nil
	first, n int
}

func (q *endQueue) at(i int) uint64 { return q.buf[(q.first+i)&(len(q.buf)-1)] }

func (q *endQueue) drop(n int) {
	if n != 0 {
		q.first, q.n = (q.first+n)&(len(q.buf)-1), q.n-n
	}
}

func (q *endQueue) push(v uint64) {
	if q.n == len(q.buf) {
		grown := make([]uint64, max(2*len(q.buf), 256))
		for i := range q.n {
			grown[i] = q.at(i)
		}
		q.buf, q.first = grown, 0
	}
	q.buf[(q.first+q.n)&(len(q.buf)-1)] = v
	q.n++
}
