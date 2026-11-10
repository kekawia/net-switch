//go:build windows

package wintun

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net/netip"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"golang.org/x/sys/windows"
)

// A model of how the signed 0.14.1 driver consumes the Receive ring, run
// against the real writer. It was written from the driver's behaviour
// (driver/wintun.c at tag 0.14.1, TunProcessReceiveData and
// TunReturnNetBufferLists); no driver source is reproduced here.
//
// What the model keeps from the driver:
//   - one receive thread walks the entries between its private cursor and Tail
//     and hands each packet to Windows by reference: Windows reads the bytes
//     from ring memory until it returns the packet;
//   - packets come back in any order, and only the returned prefix is released;
//   - each release publishes Head as the offset after that packet. In 0.14.1
//     the write happens after the lock is dropped, so two releases can publish
//     out of order and Head can step backwards.
//
// Upstream moved that write under the lock in dd050927 (2026-02-20), which has
// not shipped in a signed build.
type headModel struct {
	r      *rings
	rng    *rand.Rand
	late   int // longest delay, in steps, between a release and its Head write
	cursor uint32
	held   []heldPacket
	writes []lateHead
	seq    uint64
	sizes  []int
	out    func([][]byte) (int, error) // in place of the bare writer, when set

	delivered, wrong, garbled int
	probes                    int // the writer's stall probes, which Windows drops
	lost                      bool
}

// unguardedWrite is the writer as it was before the guard: it takes its room
// from whatever Head is in the ring. The tests keep it as the control that
// must still show the damage.
func unguardedWrite(r *rings, packets [][]byte) (written int, err error) {
	head, capacity, tail := r.receive.load(0), r.receive.capacity, r.tail
	if head == ^uint32(0) {
		return 0, ErrDisconnected
	}
	for _, p := range packets {
		size := aligned(uint32(len(p)) + 4)
		if size > (head-tail-4)&(capacity-1) {
			continue
		}
		r.receive.put(tail, p, 0)
		tail = (tail + size) & (capacity - 1)
		written++
	}
	if written != 0 {
		r.tail = tail
		r.receive.store(4, tail)
		err = windows.SetEvent(r.writeHandle())
	}
	return
}

// unguarded makes the model write through the writer as it was before the guard.
func unguarded(m *headModel) *headModel {
	m.out = func(batch [][]byte) (int, error) { return unguardedWrite(m.r, batch) }
	return m
}

type heldPacket struct {
	at, next uint32 // packet bytes, and the offset the driver publishes for it
	size     int
	seq      uint64
	returned bool
}

type lateHead struct {
	value uint32
	steps int
}

var modelSource, modelDestination = netip.MustParseAddr("198.19.240.2"), netip.MustParseAddr("198.19.240.1")

func modelPacket(seq uint64, size int) []byte {
	payload := make([]byte, size-20)
	binary.LittleEndian.PutUint64(payload, seq)
	for i := 8; i < len(payload); i++ {
		payload[i] = byte(seq) + byte(i)*31
	}
	return packet.IP(modelSource, modelDestination, 253, payload)
}

func modelPayloadIntact(seq uint64, payload []byte) bool {
	if len(payload) < 8 || binary.LittleEndian.Uint64(payload) != seq {
		return false
	}
	for i := 8; i < len(payload); i++ {
		if payload[i] != byte(seq)+byte(i)*31 {
			return false
		}
	}
	return true
}

func newHeadModel(t *testing.T, seed int64, late int, sizes []int) *headModel {
	t.Helper()
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	must(t, err)
	t.Cleanup(func() { windows.CloseHandle(event) })
	return &headModel{
		r:   &rings{receive: ring{make([]byte, ringBytes(MinCapacity)), MinCapacity}, writeEvent: event},
		rng: rand.New(rand.NewSource(seed)), late: late, sizes: sizes,
	}
}

func (m *headModel) write(t *testing.T, packets int) int {
	t.Helper()
	batch := make([][]byte, packets)
	for i := range batch {
		m.seq++
		batch[i] = modelPacket(m.seq, m.sizes[m.rng.Intn(len(m.sizes))])
	}
	if m.out != nil {
		n, err := m.out(batch)
		must(t, err)
		return n
	}
	n, _, err := m.r.write(batch)
	must(t, err)
	return n
}

// indicate is the receive thread: it gives up to limit queued packets to Windows.
func (m *headModel) indicate(limit int) {
	data, capacity := m.r.receive.data(), m.r.receive.capacity
	for ; limit > 0 && !m.lost; limit-- {
		content := (m.r.receive.load(4) - m.cursor) & (capacity - 1)
		if content == 0 {
			return
		}
		size := binary.LittleEndian.Uint32(data[m.cursor : m.cursor+4])
		if content < 4 || size > MaxPacketSize || aligned(size+4) > content {
			m.lost = true // the driver stops and publishes its shutdown marker
			return
		}
		p := heldPacket{at: m.cursor + 4, next: (m.cursor + aligned(size+4)) & (capacity - 1), size: int(size)}
		m.cursor = p.next
		b := data[p.at : p.at+size]
		total := uint32(0) // the length the IP header states; Windows ignores bytes after it
		if size >= 20 && b[0]>>4 == 4 {
			total = uint32(binary.BigEndian.Uint16(b[2:4]))
		}
		switch {
		case total == 20 && bytes.Equal(b[:20], headProbe):
			// The writer's stall probe: its checksum is wrong, so it comes straight back.
			m.probes++
			p.returned = true
		case total < 28 || total > size:
			// Not a packet Windows accepts; it comes straight back.
			m.garbled++
			p.returned = true
		default:
			p.size = int(total)
			p.seq = binary.LittleEndian.Uint64(b[20:28])
			if !modelPayloadIntact(p.seq, b[20:total]) {
				m.garbled++ // a checksum would reject it on arrival
				p.returned = true
			}
		}
		m.held = append(m.held, p)
	}
}

// giveBack is Windows returning one held packet. The application receives the
// bytes that are in ring memory at that moment.
func (m *headModel) giveBack(i int) {
	p := &m.held[i]
	if p.returned {
		return
	}
	p.returned = true
	if modelPayloadIntact(p.seq, m.r.receive.data()[p.at+20:p.at+uint32(p.size)]) {
		m.delivered++
	} else {
		m.wrong++
	}
}

// release publishes Head for every packet of the returned prefix. A delay of
// zero is the corrected driver; anything else lets a later release land first.
func (m *headModel) release(delay func() int) {
	for len(m.held) != 0 && m.held[0].returned {
		m.writes = append(m.writes, lateHead{m.held[0].next, delay()})
		m.held = m.held[1:]
	}
	m.land()
}

func (m *headModel) land() {
	keep := m.writes[:0]
	for _, w := range m.writes {
		if w.steps == 0 {
			m.r.receive.store(0, w.value)
			continue
		}
		w.steps--
		keep = append(keep, w)
	}
	m.writes = keep
}

func (m *headModel) run(t *testing.T, steps int) {
	t.Helper()
	for i := 0; i < steps && !m.lost; i++ {
		switch n := m.rng.Intn(10); {
		case n < 4:
			m.write(t, 1+m.rng.Intn(16))
		case n < 6:
			m.indicate(1 + m.rng.Intn(24))
		default:
			for k := 1 + m.rng.Intn(6); k > 0 && len(m.held) != 0; k-- {
				j := 0 // usually the oldest packet, the one holding Head back
				if m.rng.Intn(10) >= 7 {
					j = m.rng.Intn(len(m.held))
				}
				m.giveBack(j)
			}
			m.release(func() int {
				if m.late == 0 || m.rng.Intn(6) != 0 {
					return 0
				}
				return 1 + m.rng.Intn(m.late)
			})
			continue
		}
		m.land()
	}
}

var headModelMixes = map[string][]int{
	"bulk TCP":          {9000, 9000, 9000, 40 + 20},
	"UDP 1228":          {1228},
	"mixed sizes":       {60, 124, 1228, 1500, 9000},
	"64-byte entries":   {60},
	"small and jumbo":   {60, 9000},
	"1500-byte packets": {1500, 1500, 52 + 20},
}

// With Head published under the lock, as upstream's unreleased fix does, no
// writer destroys a packet Windows still holds, and the guard has nothing to
// refuse. This is the control for the model itself.
func TestRingReceiveHeadOrderedReleasesStayIntact(t *testing.T) {
	for name, sizes := range headModelMixes {
		t.Run(name, func(t *testing.T) {
			for seed := int64(1); seed <= 20; seed++ {
				for _, m := range []*headModel{newHeadModel(t, seed, 0, sizes), unguarded(newHeadModel(t, seed, 0, sizes))} {
					m.run(t, 1500)
					if counts := m.r.guard.counts; m.wrong != 0 || m.garbled != 0 || m.lost || m.delivered == 0 || counts.ignoredHeads != 0 || counts.headProbes != 0 {
						t.Fatalf("seed %d: delivered=%d wrong=%d garbled=%d lost=%t %+v", seed, m.delivered, m.wrong, m.garbled, m.lost, counts)
					}
				}
			}
		})
	}
}

// The smallest schedule that shows the defect, against the writer as it was
// and against the guarded writer.
func TestRingReceiveHeadStepsBackwards(t *testing.T) {
	stepBack := func(m *headModel) (overrun int) {
		for m.write(t, 1) == 1 {
		}
		m.indicate(1 << 20)
		if len(m.held) < 8 {
			t.Fatalf("the ring holds only %d packets", len(m.held))
		}
		first, third := m.held[0].next, m.held[2].next
		for i := range 3 {
			m.giveBack(i)
		}
		m.held = m.held[3:]
		// Two threads released the three packets. The one that released the last
		// two has published; the other was delayed before its write.
		m.r.receive.store(0, third)
		if n := m.write(t, 3); n != 3 {
			t.Fatalf("wrote %d packets into three freed slots", n)
		}
		m.r.receive.store(0, first)
		// Nothing was returned in between, so nothing may be written now.
		overrun = m.write(t, 8)
		m.giveBack(0)
		return
	}
	// The control: without the guard the writer trusts the Head that stepped
	// back and overwrites a packet Windows has not returned.
	m := unguarded(newHeadModel(t, 1, 0, []int{1228}))
	if overrun := stepBack(m); overrun == 0 || m.wrong != 1 {
		t.Fatalf("the 0.14.1 Head regression no longer reproduces without the guard: wrote %d packets, wrong deliveries %d", overrun, m.wrong)
	}
	// The guard refuses that Head, writes nothing and sends its one stall probe.
	m = newHeadModel(t, 1, 0, []int{1228})
	overrun := stepBack(m)
	if counts := m.r.guard.counts; overrun != 0 || m.wrong != 0 || m.delivered != 4 || counts != (guardCounts{ignoredHeads: 1, headProbes: 1}) {
		t.Fatalf("guarded: wrote %d packets, delivered %d, wrong %d, %+v", overrun, m.delivered, m.wrong, counts)
	}
}

// The same defect under random schedules and traffic mixes. Without the guard,
// applications receive bytes that were never sent to them in every mix. With
// it, none does, the driver never meets a damaged entry, and no session is lost.
//
// A late store here is at most 12 steps old, which at this ring size can be
// more than a lap of writes: past what the guard promises. The runs stay clean
// all the same.
func TestRingReceiveHeadRace(t *testing.T) {
	for name, sizes := range headModelMixes {
		t.Run(name, func(t *testing.T) {
			var delivered, wrong, lost int
			var counts guardCounts
			for seed := int64(1); seed <= 40; seed++ {
				m := unguarded(newHeadModel(t, seed, 12, sizes))
				m.run(t, 1500)
				wrong += m.wrong
				if m.lost {
					lost++
				}
				m = newHeadModel(t, seed, 12, sizes)
				m.run(t, 1500)
				if m.wrong != 0 || m.garbled != 0 || m.lost || m.delivered == 0 {
					t.Fatalf("guarded, seed %d: delivered=%d wrong=%d garbled=%d lost=%t %+v", seed, m.delivered, m.wrong, m.garbled, m.lost, m.r.guard.counts)
				}
				delivered += m.delivered
				counts.ignoredHeads += m.r.guard.counts.ignoredHeads
				counts.shiftedEntries += m.r.guard.counts.shiftedEntries
				counts.headProbes += m.r.guard.counts.headProbes
			}
			t.Logf("without the guard: wrong=%d, sessions lost=%d of 40; guarded: delivered=%d, all intact, %+v", wrong, lost, delivered, counts)
			if wrong == 0 {
				t.Fatal("the 0.14.1 Head race no longer delivers wrong bytes without the guard: the control proves nothing")
			}
			if counts.ignoredHeads == 0 {
				t.Fatal("the guard refused no Head: the schedule did not exercise it")
			}
		})
	}
}

// The guard never lets an entry end where an entry of the lap before ended.
// With 1,024-byte entries in a 128 KiB ring every end of the second lap would
// fall on one of the first; one shift of four bytes moves the whole lap off
// them. A late store of an old end then names no outstanding entry.
func TestRingReceiveHeadShiftKeepsLapsApart(t *testing.T) {
	m := newHeadModel(t, 1, 0, []int{1020})
	for m.write(t, 1) == 1 {
	}
	m.indicate(1 << 20)
	firstEnd := m.held[0].next
	for i := range m.held {
		m.giveBack(i)
	}
	m.release(func() int { return 0 })
	// The second lap: its second entry would end exactly where the first lap's
	// first entry ended.
	if n := m.write(t, 8); n != 8 {
		t.Fatalf("wrote %d of 8 packets into an empty ring", n)
	}
	if counts := m.r.guard.counts; counts != (guardCounts{shiftedEntries: 1}) {
		t.Fatalf("second lap: %+v", counts)
	}
	// The late store: the first lap's first end, published now.
	m.indicate(1 << 20)
	m.r.receive.store(0, firstEnd)
	if n := m.write(t, 1); n != 1 {
		t.Fatalf("wrote %d packets with room to spare", n)
	}
	for i := range m.held {
		m.giveBack(i)
	}
	if counts := m.r.guard.counts; counts != (guardCounts{shiftedEntries: 1, ignoredHeads: 1}) || m.wrong != 0 || m.garbled != 0 || m.delivered != 127+8 {
		t.Fatalf("after the late store: %+v delivered=%d wrong=%d garbled=%d", counts, m.delivered, m.wrong, m.garbled)
	}
}

// The one way the guard could stop the tunnel: the ring drains while nothing
// is being written, and the last word left in place is a late store older than
// the Head the writer accepted. The account then says full, and nothing
// outstanding is left to publish a newer Head. The stall probe finds out.
func TestRingReceiveHeadStallProbe(t *testing.T) {
	m := newHeadModel(t, 1, 0, []int{1228})
	for m.write(t, 1) == 1 {
	}
	m.indicate(1 << 20)
	fifth := m.held[4].next
	for i := range 10 {
		m.giveBack(i)
	}
	m.release(func() int { return 0 })
	if n := m.write(t, 10); n != 10 {
		t.Fatalf("wrote %d packets into ten freed slots", n)
	}
	// Everything comes back, in order: the ring is empty. Then a store from
	// long ago lands last.
	m.indicate(1 << 20)
	for i := range m.held {
		m.giveBack(i)
	}
	m.release(func() int { return 0 })
	m.r.receive.store(0, fifth)
	if n := m.write(t, 1); n != 0 {
		t.Fatalf("wrote %d packets on an account that is full", n)
	}
	if counts := m.r.guard.counts; counts != (guardCounts{ignoredHeads: 1, headProbes: 1}) {
		t.Fatalf("stalled write: %+v", counts)
	}
	// Windows drops the probe and returns it; the driver publishes its end.
	m.indicate(1 << 20)
	m.release(func() int { return 0 })
	if n := m.write(t, 1); n != 1 || m.probes != 1 || m.wrong != 0 || m.garbled != 0 {
		t.Fatalf("after the probe came back: wrote %d, probes seen %d, wrong %d, garbled %d", n, m.probes, m.wrong, m.garbled)
	}
	if room := m.r.guard.room(MinCapacity); room != MinCapacity-4-1232 {
		t.Fatalf("the account did not heal: room %d", room)
	}
}

// modelReplay puts the hosted test's replay harness (staleHeadIO, in
// receive_head_race_windows_test.go) in front of the model's writer.
func modelReplay(m *headModel, unguarded bool) *staleHeadIO {
	replay := &staleHeadIO{Session: &Session{rings: m.r}, unguarded: unguarded}
	m.out = replay.WriteBatch
	return replay
}

// The hosted test replays an older Head on a real adapter. Here the same
// harness meets the model, where every step is known. With every release
// published in order, one replayed Head costs the writer without a guard what
// the race costs in TestRingReceiveHeadStepsBackwards; the guarded writer
// refuses it. Either way Head is correct again afterwards.
func TestRingReceiveHeadReplay(t *testing.T) {
	replayOnce := func(m *headModel, replay *staleHeadIO) (int, staleHeadCounts) {
		for m.write(t, 1) == 1 {
		}
		m.indicate(1 << 20)
		if len(m.held) < 8 {
			t.Fatalf("the ring holds only %d packets", len(m.held))
		}
		third := m.held[2].next
		for i := range 3 {
			m.giveBack(i)
		}
		m.release(func() int { return 0 })
		if n := m.write(t, 3); n != 3 {
			t.Fatalf("wrote %d packets into three freed slots", n)
		}
		// Nothing is returned from here on, so nothing more may be written.
		replay.armed.Store(true)
		overrun := m.write(t, 8)
		m.giveBack(0)
		if head := m.r.receive.load(0); head != third {
			t.Fatalf("after the replay Head is %d, not the driver's %d", head, third)
		}
		return overrun, replay.snapshot()
	}
	m := newHeadModel(t, 1, 0, []int{1228})
	overrun, counts := replayOnce(m, modelReplay(m, true))
	if overrun == 0 || m.wrong != 1 || counts.Replays != 1 || counts.Overruns != 1 || counts.OverrunBytes == 0 || counts.NaturalRegressions != 0 {
		t.Fatalf("without the guard: wrote %d packets, wrong deliveries %d, %+v", overrun, m.wrong, counts)
	}
	t.Logf("without the guard: %d bytes written where nothing was free, from a Head %d bytes behind", counts.OverrunBytes, counts.BytesBehind)

	m = newHeadModel(t, 1, 0, []int{1228})
	overrun, counts = replayOnce(m, modelReplay(m, false))
	if overrun != 0 || m.wrong != 0 || counts.Replays != 1 || counts.Overruns != 0 || m.r.guard.counts.ignoredHeads != 1 {
		t.Fatalf("guarded: wrote %d packets, wrong deliveries %d, %+v, %+v", overrun, m.wrong, counts, m.r.guard.counts)
	}
}

// The account behind the replay has to follow a healthy ring exactly, or the
// hosted test would report damage of its own making. With releases in order it
// never loses the ring and never meets a Head it cannot explain. With the
// 0.14.1 order it catches late stores with nothing replayed, as a Head no
// release could have produced, while the ring has room. On a full ring a late
// store reads as one large release, to this account as to the writer.
func TestRingReceiveHeadAccountFollowsTheRing(t *testing.T) {
	late := map[string]int{}
	for name, sizes := range headModelMixes {
		for seed := int64(1); seed <= 20; seed++ {
			m := newHeadModel(t, seed, 0, sizes)
			replay := modelReplay(m, false)
			m.run(t, 1500)
			if counts := replay.snapshot(); counts.Replays != 0 || counts.NaturalRegressions != 0 || !replay.clean || m.wrong != 0 || m.delivered == 0 {
				t.Fatalf("%s, seed %d, releases in order: %+v clean=%t delivered=%d wrong=%d", name, seed, counts, replay.clean, m.delivered, m.wrong)
			}
			m = newHeadModel(t, seed, 12, sizes)
			replay = modelReplay(m, false)
			m.run(t, 1500)
			counts := replay.snapshot()
			if counts.Replays != 0 {
				t.Fatalf("%s, seed %d: an unarmed harness replayed a Head: %+v", name, seed, counts)
			}
			for _, event := range counts.Events {
				late[event.Kind]++
			}
		}
	}
	t.Logf("0.14.1 order, nothing replayed, first events of each run by kind: %v", late)
	if late["behind"] == 0 || late["inconsistent"] != 0 {
		t.Fatalf("the account did not notice the 0.14.1 release order as expected: %v", late)
	}
}

// On a real adapter the driver can publish between the account's sample and
// the writer's own load, so the writer is rightly given more room than the
// sample allowed. When the ring then drains, Head has moved more than one lap
// past that sample. An account that measured from the sample took this for a
// Head that went backwards (seen on both hosted runners, 2026-11-10).
func TestRingReceiveHeadAccountAllowsTheWriterANewerHead(t *testing.T) {
	m := newHeadModel(t, 1, 0, []int{1228})
	replay := &staleHeadIO{Session: &Session{rings: m.r}}
	var between func()
	m.out = func(batch [][]byte) (int, error) {
		stale, newest, replayed := replay.before(batch)
		if between != nil {
			between()
		}
		n, err := replay.Session.WriteBatch(batch)
		replay.after(stale, newest, replayed)
		return n, err
	}
	for m.write(t, 1) == 1 {
	}
	m.indicate(1 << 20)
	// The account samples a full ring; two packets come back before the writer loads.
	between = func() {
		m.giveBack(0)
		m.giveBack(1)
		m.release(func() int { return 0 })
	}
	if n := m.write(t, 2); n != 2 {
		t.Fatalf("wrote %d packets into two slots freed after the sample", n)
	}
	between = nil
	// Everything drains, in order: Head is now more than a lap past that sample.
	m.indicate(1 << 20)
	for i := range m.held {
		m.giveBack(i)
	}
	m.release(func() int { return 0 })
	if n := m.write(t, 1); n != 1 {
		t.Fatalf("wrote %d packets into an empty ring", n)
	}
	if counts := replay.snapshot(); counts.NaturalRegressions != 0 || !replay.clean || m.wrong != 0 {
		t.Fatalf("a healthy ring read as a Head that went back: %+v clean=%t wrong=%d", counts, replay.clean, m.wrong)
	}
}
