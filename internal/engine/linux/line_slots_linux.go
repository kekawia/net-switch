package linux

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type inflightDial struct {
	index  int
	mark   uint32
	v6     bool
	cancel context.CancelCauseFunc
}

// A tombstone prevents an old published binding from acquiring a socket after
// the route writer retires its slot. Dials never wait for netlink or fsync.
type lineLease struct {
	users    atomic.Int64
	closedAt atomic.Pointer[time.Time]
	dialMu   sync.Mutex
	nextDial uint64
	dials    map[uint64]inflightDial
}

const lineSlotQuiet = 60 * time.Second

func (l *lineLease) hold() bool {
	if l == nil {
		return true
	} // hand-built platform fixtures
	for n := l.users.Load(); n >= 0; n = l.users.Load() {
		if l.users.CompareAndSwap(n, n+1) {
			return true
		}
	}
	return false
}
func (l *lineLease) release() {
	if l != nil {
		// Publish before dropping the final pin. The kernel may continue the
		// closed socket's FIN/retransmissions after userspace releases its fd.
		now := time.Now()
		for previous := l.closedAt.Load(); previous == nil || now.After(*previous); previous = l.closedAt.Load() {
			if l.closedAt.CompareAndSwap(previous, &now) {
				break
			}
		}
		l.users.Add(-1)
	}
}
func (l *lineLease) retire() bool { return l == nil || l.users.CompareAndSwap(0, -1) }

func (l *lineLease) watchDial(state lineState, v6 bool, cancel context.CancelCauseFunc) func() {
	if l == nil {
		return func() {}
	}
	l.dialMu.Lock()
	l.nextDial++
	id := l.nextDial
	if l.dials == nil {
		l.dials = make(map[uint64]inflightDial)
	}
	l.dials[id] = inflightDial{index: state.Index, mark: state.Mark, v6: v6, cancel: cancel}
	l.dialMu.Unlock()
	return func() {
		l.dialMu.Lock()
		delete(l.dials, id)
		l.dialMu.Unlock()
	}
}

func (l *lineLease) inFlightDials() int {
	if l == nil {
		return 0
	}
	l.dialMu.Lock()
	defer l.dialMu.Unlock()
	return len(l.dials)
}

func (l *lineLease) syncDials(state lineState) {
	if l == nil {
		return
	}
	usable := state.Up && state.Unavailable == ""
	var cancels []func()
	l.dialMu.Lock()
	for id, d := range l.dials {
		var cause error
		switch {
		case state.Unavailable != "":
			cause = fmt.Errorf("line %s unavailable: %s", state.ID, state.Unavailable)
		case !usable || (!d.v6 && !state.Default4) || (d.v6 && !state.Default6):
			cause = fmt.Errorf("line %s has no usable default route", state.ID)
		case d.index != state.Index || d.mark != state.Mark:
			cause = fmt.Errorf("line %s binding changed during dial", state.ID)
		}
		if cause != nil {
			c := d.cancel
			cancels = append(cancels, func() { c(cause) })
			delete(l.dials, id)
		}
	}
	l.dialMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (l *lineLease) abortAllDials(cause error) {
	if l == nil {
		return
	}
	var cancels []context.CancelCauseFunc
	l.dialMu.Lock()
	for id, d := range l.dials {
		cancels = append(cancels, d.cancel)
		delete(l.dials, id)
	}
	l.dialMu.Unlock()
	for _, cancel := range cancels {
		cancel(cause)
	}
}

func (p *Platform) SetLineUse(used func(string) bool) { p.lineUsed = used }

// Called under routeMu. A policy reference protects the prepare/apply gap;
// socket pins also cover probes, echo, pending dials and delayed closes.
func (p *Platform) retireLines(wanted map[string]bool) bool {
	changed := false
	for id, line := range p.lines {
		if wanted[id] || (p.lineUsed != nil && p.lineUsed(id)) {
			continue
		}
		if line.lease.retire() {
			if line.lease != nil {
				if closed := line.lease.closedAt.Load(); closed != nil {
					p.slotQuiet[line.N] = closed.Add(lineSlotQuiet)
				}
			}
			delete(p.lines, id)
			changed = true
			p.slotsDirty = true
		}
	}
	return changed
}

func (p *Platform) freeLineSlot(lines map[string]lineState, now time.Time) int {
	var used [256]bool
	for _, line := range lines {
		if line.N > 0 && line.N < len(used) {
			used[line.N] = true
		}
	}
	// Rotate across the whole 255-slot range. Never immediately reuse a
	// socket-bearing slot: its last close also imposes a 60-second floor.
	for step := 1; step < len(used); step++ {
		n := (p.lastSlot+step-1)%255 + 1
		if !used[n] && !now.Before(p.slotQuiet[n]) {
			p.lastSlot = n
			return n
		}
	}
	return 0
}

func (p *Platform) acquireBinding(id string, v6 bool) (lineState, func(), error) {
	l, err := p.binding(id, v6)
	if err != nil {
		return l, nil, err
	}
	if !l.lease.hold() {
		return l, nil, errors.New("line binding retired")
	}
	return l, l.lease.release, nil
}
