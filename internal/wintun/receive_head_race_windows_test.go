//go:build windows

package wintun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
)

// Hosted evidence for the Receive.Head race in the signed 0.14.1 driver (see
// receive_head_model_windows_test.go). The shift probe reports what Windows
// accepts. The stale Head test asserts the defect on a real adapter, as the
// model tests do in memory, until the writer guard turns it around. Neither
// test is part of the nightly integrity sequence.

var probePeer6 = netip.MustParseAddr("fd00:c613:f000::2")

const probeHost6 = "fd00:c613:f000::1"

func echoUDP6(p []byte) bool {
	if len(p) < 48 || p[0]>>4 != 6 || p[6] != 17 || !bytes.Equal(p[24:40], probePeer6.AsSlice()) || binary.BigEndian.Uint16(p[42:44]) != 9001 || !validIP(p) {
		return false
	}
	for i := 0; i < 16; i++ {
		p[8+i], p[24+i] = p[24+i], p[8+i]
	}
	p[40], p[42] = p[42], p[40]
	p[41], p[43] = p[43], p[41]
	// Swapping endpoints preserves the UDP checksum.
	return true
}

func tryCommand(program string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, program, args...).CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

// A spacer is an IPv4 header Windows accepts from the driver and then drops:
// its header checksum is wrong. A packet that is not IP at all would not do,
// because the 0.14.1 receive thread waits for every outstanding packet to be
// returned before it skips one.
func shiftSpacer() []byte {
	p := packet.IP(netip.MustParseAddr("198.19.240.2"), netip.MustParseAddr("198.19.240.1"), 253, nil)
	p[10] ^= 0xff
	return p
}

// startShiftResponder echoes UDP like the fixture's own echo, framed as the
// first payload byte asks: 'P' as is, 'T' with four bytes after the IP packet
// inside the same ring entry, 'S' behind a spacer entry.
func (f *fixture) startShiftResponder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	spacer := shiftSpacer()
	go func() {
		defer close(done)
		buffers, sizes := make([][]byte, 64), make([]int, 64)
		for i := range buffers {
			buffers[i] = make([]byte, MaxPacketSize)
		}
		out := make([][]byte, 0, 2*len(buffers))
		for {
			n, err := f.io.ReadBatch(ctx, buffers, sizes)
			if err != nil {
				if ctx.Err() == nil {
					f.recordFault(err)
					t.Logf("shift probe read: %v", err)
				}
				return
			}
			out = out[:0]
			for i := 0; i < n; i++ {
				p, body := buffers[i][:sizes[i]], 28
				if !echoUDP(p) {
					if !echoUDP6(p) {
						continue
					}
					body = 48
				}
				if len(p) <= body {
					continue
				}
				switch p[body] {
				case 'T':
					p = buffers[i][:sizes[i]+4]
					copy(p[sizes[i]:], "\xee\xee\xee\xee")
				case 'S':
					out = append(out, spacer)
				}
				out = append(out, p)
			}
			if _, err = f.io.WriteBatch(out); err != nil && ctx.Err() == nil {
				f.recordFault(err)
				t.Logf("shift probe write: %v", err)
			}
		}
	}()
	f.stopEcho = func() { cancel(); <-done }
}

type shiftCase struct {
	Family    string `json:"family"`
	Variant   string `json:"variant"`
	Payload   int    `json:"payload_bytes"`
	Delivered bool   `json:"delivered"`
	Attempts  int    `json:"attempts"`
	Error     string `json:"error,omitempty"`
}

func shiftExchange(c *net.UDPConn, variant byte, size int) (bool, int, string) {
	payload := make([]byte, size)
	payload[0] = variant
	for i := 1; i < size; i++ {
		payload[i] = byte(i*7) + variant
	}
	reply, last := make([]byte, size+64), ""
	for attempt := 1; attempt <= 3; attempt++ {
		c.SetDeadline(time.Now().Add(400 * time.Millisecond))
		if _, err := c.Write(payload); err != nil {
			last = err.Error()
			continue
		}
		n, err := c.Read(reply)
		switch {
		case err != nil:
			last = err.Error()
		case n == size && bytes.Equal(reply[:n], payload):
			return true, attempt, ""
		default:
			last = fmt.Sprintf("received %d bytes that differ from the %d sent", n, size)
		}
	}
	return false, 3, last
}

// shiftedIO applies one shift method to every TCP packet the stack sends.
type shiftedIO struct {
	batchIO
	every  int // a spacer before every nth packet; 0 pads every packet instead
	spacer []byte
	count  int
}

func (s *shiftedIO) WriteBatch(packets [][]byte) (int, error) {
	out := make([][]byte, 0, len(packets)+len(packets)/max(s.every, 1)+1)
	for _, p := range packets {
		if s.every == 0 {
			q := make([]byte, len(p)+4)
			copy(q, p)
			copy(q[len(p):], "\xee\xee\xee\xee")
			out = append(out, q)
			continue
		}
		if s.count++; s.count%s.every == 0 {
			out = append(out, s.spacer)
		}
		out = append(out, p)
	}
	return s.batchIO.WriteBatch(out)
}

// TestWintunEntryShiftProbe asks Windows which way of moving an entry boundary
// it tolerates. The writer guard needs one of them (see the model test).
func TestWintunEntryShiftProbe(t *testing.T) {
	f := newFixture(t, "ours", 8<<20)
	session := f.io
	f.stopEcho()
	f.startShiftResponder(t)

	v4 := udpSocket(t)
	defer v4.Close()
	if ok, _, problem := shiftExchange(v4, 'P', 64); !ok {
		t.Fatalf("the plain IPv4 control exchange failed: %s", problem)
	}
	sockets := map[string]*net.UDPConn{"ipv4": v4}
	ipv6 := "ok"
	for _, args := range [][]string{
		{"interface", "ipv6", "set", "interface", "NsRingCI", "dadtransmits=0", "store=active"},
		{"interface", "ipv6", "add", "address", "interface=NsRingCI", "address=" + probeHost6 + "/126", "store=active"},
		{"interface", "ipv6", "set", "subinterface", "NsRingCI", "mtu=9000", "store=active"},
	} {
		if output, err := tryCommand("netsh.exe", args...); err != nil {
			ipv6 = fmt.Sprintf("unavailable: netsh %v: %v: %s", args, err, output)
			break
		}
	}
	if ipv6 == "ok" {
		ipv6 = "unavailable: the plain IPv6 exchange never succeeded"
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			c, err := net.DialUDP("udp6", &net.UDPAddr{IP: net.ParseIP(probeHost6)}, &net.UDPAddr{IP: probePeer6.AsSlice(), Port: 9001})
			if err != nil {
				ipv6 = "unavailable: " + err.Error()
				continue
			}
			if ok, _, _ := shiftExchange(c, 'P', 64); ok {
				defer c.Close()
				sockets["ipv6"], ipv6 = c, "ok"
				break
			}
			c.Close()
		}
	}

	var cases []shiftCase
	delivered := map[byte]bool{'P': true, 'T': true, 'S': true}
	for _, family := range []string{"ipv4", "ipv6"} {
		c := sockets[family]
		if c == nil {
			continue
		}
		largest := 9000 - 28
		if family == "ipv6" {
			largest = 9000 - 48
		}
		for _, size := range []int{16, 1200, largest} {
			for _, variant := range []byte{'P', 'T', 'S'} {
				ok, attempts, problem := shiftExchange(c, variant, size)
				cases = append(cases, shiftCase{family, map[byte]string{'P': "plain", 'T': "trailing_bytes", 'S': "spacer"}[variant], size, ok, attempts, problem})
				delivered[variant] = delivered[variant] && ok
			}
			// The path must still carry ordinary packets after each shifted one.
			if ok, _, problem := shiftExchange(c, 'P', 64); !ok {
				t.Fatalf("%s stopped carrying plain packets after the %d-byte cases: %s", family, size, problem)
			}
		}
	}
	if !delivered['P'] {
		t.Errorf("a plain control case was not delivered: %+v", cases)
	}
	f.stopEcho()

	// Every TCP packet shifted, including full 9,000-byte segments.
	tcp := map[string]string{}
	for _, method := range []string{"trailing_bytes", "spacer"} {
		shifted := &shiftedIO{batchIO: session, spacer: shiftSpacer()}
		if method == "spacer" {
			shifted.every = 8
		}
		f.io = shifted
		stop := tcpEcho(t, f)
		rate, err := tcpWordTransfer(t, f, 8, "shift-"+method)
		stop()
		f.io = session
		tcp[method] = fmt.Sprintf("ok at %.0f MB/s", rate)
		if err != nil {
			tcp[method] = err.Error()
			delivered[map[string]byte{"trailing_bytes": 'T', "spacer": 'S'}[method]] = false
		}
	}
	f.stopEcho = func() {}
	s, _ := session.(*Session)
	report(t, map[string]any{"test": "entry_shift_probe", "arch": runtime.GOARCH, "ipv6": ipv6, "cases": cases, "tcp": tcp,
		"trailing_bytes_ok": delivered['T'], "spacer_ok": delivered['S'], "session": observeSession(s), "fault": fmt.Sprint(f.fault())})
}

// staleHeadCounts is what staleHeadIO saw. NaturalRegressions needs no replay:
// it counts Heads no release could have produced, seen before anything was
// replayed. The first on a hosted runner (x64, run 42815757447, 2026-11-10):
// Head read 779044, then 768768 for 38 batches in a row, seven entries back,
// in a 1 MiB ring four fifths empty while the readers were stalled.
type staleHeadCounts struct {
	Replays            int              `json:"replays"`             // batches written with the older Head in place
	Overruns           int              `json:"overruns"`            // of those, batches that wrote past the free space
	OverrunBytes       uint64           `json:"overrun_bytes"`       // bytes written where nothing was free
	BytesBehind        uint64           `json:"bytes_behind"`        // how far behind the newest Head the last overrunning one was
	NaturalRegressions int              `json:"natural_regressions"` // Heads the driver put back on its own
	Events             []staleHeadEvent `json:"natural_events,omitempty"`
}

// staleHeadEvent is one sampled Head that no release could have produced, with
// nothing replayed. Head only moves forward in a correct driver, so a "behind"
// event is the 0.14.1 late store caught in the ring. It can be told apart only
// while the ring has room: on a full ring a late store reads as one large
// release, to this account as to the writer. "inconsistent" means Head and
// Tail no longer match the account at all.
type staleHeadEvent struct {
	Kind       string `json:"kind"`
	HeadBefore uint32 `json:"head_before"`
	Head       uint32 `json:"head"`
	Tail       uint32 `json:"tail"`    // when first seen
	Room       uint64 `json:"room"`    // free space by the account when first seen
	Batches    int    `json:"batches"` // consecutive write batches that found it in place
}

// staleHeadIO replays on a real adapter the one thing the 0.14.1 return path
// gets wrong: an older Receive.Head published after a newer one.
//
// The driver reads that word once, when its receive thread starts, and only
// writes it afterwards (wintun.c in 0.14.1, lines 456, 420 and 576), so a value
// placed there reaches our writer and nothing in the driver. The value replayed
// is one the driver itself published earlier in the same lap. It goes in only
// while the word still holds the newest value sampled, and comes out after one
// write batch unless the driver has published in between.
//
// To know what is truly free it keeps its own account of the ring: Head and
// Tail unwrapped, started whenever the ring is seen empty and dropped as soon
// as the ring stops matching it.
type staleHeadIO struct {
	*Session
	armed     atomic.Bool
	unguarded bool // write as the writer did before the guard: the control

	// Used only by the goroutine that writes.
	seen         *rings
	clean        bool     // vhead and vtail are a true account of the ring
	head, tail   uint32   // Receive.Head and Tail as last sampled
	vhead, vtail uint64   // the same, unwrapped since the ring was last seen empty
	older        []uint64 // unwrapped Heads sampled before the newest, oldest first
	behind       uint64
	replayed     bool // an overrun was caused here: later oddities are no longer the driver's alone

	unexplained     bool // the last sample followed from no release
	unexplainedHead uint32

	countMu sync.Mutex
	counts  staleHeadCounts
}

func (s *staleHeadIO) count(change func(*staleHeadCounts)) {
	s.countMu.Lock()
	change(&s.counts)
	s.countMu.Unlock()
}

func (s *staleHeadIO) snapshot() staleHeadCounts {
	s.countMu.Lock()
	defer s.countMu.Unlock()
	counts := s.counts
	counts.Events = append([]staleHeadEvent(nil), counts.Events...)
	return counts
}

func (s *staleHeadIO) natural(kind string, before, head, tail uint32, room uint64) {
	if s.replayed {
		return
	}
	// One late store stays in the ring until the next release, which can be many
	// batches away while the readers stall. It is one event.
	again := s.unexplained && s.unexplainedHead == head
	s.unexplained, s.unexplainedHead = true, head
	s.count(func(c *staleHeadCounts) {
		if n := len(c.Events); again {
			if n != 0 && c.Events[n-1].Head == head {
				c.Events[n-1].Batches++
			}
			return
		}
		c.NaturalRegressions++
		if len(c.Events) < 8 {
			c.Events = append(c.Events, staleHeadEvent{kind, before, head, tail, room, 1})
		}
	})
}

// resolve places a sampled Head on the unwrapped line. The writer loads Head
// after this account samples it, so it may have been given a newer one and
// written more than the last sample allowed. The true Head therefore lies
// between what the writes so far imply and Tail, a span shorter than the ring,
// which names one position for every offset. A sample outside it follows from
// no release. (Measuring from the last sample instead miscounts a full lap
// when the ring drains after such a write.)
func (s *staleHeadIO) resolve(head uint32, capacity uint64) (uint64, bool) {
	floor := s.vhead
	if s.vtail-floor > capacity-4 {
		floor = s.vtail - (capacity - 4)
	}
	at := floor + uint64((head-s.head-uint32(floor-s.vhead))&uint32(capacity-1))
	return at, at <= s.vtail
}

func (s *staleHeadIO) WriteBatch(packets [][]byte) (n int, err error) {
	stale, newest, replayed := s.before(packets)
	if s.unguarded {
		n, err = s.writeUnguarded(packets)
	} else {
		n, err = s.Session.WriteBatch(packets)
	}
	s.after(stale, newest, replayed)
	return n, err
}

// writeUnguarded is Session.WriteBatch around the writer as it was before the
// guard (unguardedWrite, in the model test file).
func (s *staleHeadIO) writeUnguarded(packets [][]byte) (int, error) {
	s.Session.writeMu.Lock()
	defer s.Session.writeMu.Unlock()
	s.Session.mu.RLock()
	defer s.Session.mu.RUnlock()
	switch {
	case s.Session.closed.Load() || s.Session.rings == nil:
		return 0, net.ErrClosed
	case s.Session.err != nil:
		return 0, s.Session.err
	case s.Session.recovering.Load():
		return 0, nil
	}
	n, err := unguardedWrite(s.Session.rings, packets)
	s.Session.written.Add(uint64(n))
	if errors.Is(err, ErrDisconnected) {
		s.Session.fail(err)
		err = s.Session.writeLoss()
	}
	return n, err
}

func (s *staleHeadIO) advance(head uint32, by, capacity uint64) {
	if by == 0 {
		return
	}
	s.older = append(s.older, s.vhead)
	s.vhead, s.head = s.vhead+by, head
	for len(s.older) != 0 && s.vhead-s.older[0] >= capacity {
		s.older = s.older[1:] // a lap old or more
	}
}

// before brings the account up to date and, when armed, puts an older Head in
// place for the batch about to be written.
func (s *staleHeadIO) before(packets [][]byte) (stale, newest uint32, replayed bool) {
	s.Session.mu.RLock()
	defer s.Session.mu.RUnlock()
	r := s.Session.rings
	if r == nil || r.closed {
		s.seen, s.clean = nil, false
		return
	}
	capacity, mask := uint64(r.receive.capacity), r.receive.capacity-1
	head, tail := r.receive.load(0), r.receive.load(4)
	if head > mask || head&3 != 0 {
		s.clean = false // released by the driver
		return
	}
	if r != s.seen || !s.clean {
		// A true account can only start from an empty ring.
		s.seen, s.clean = r, head == tail
		s.head, s.tail, s.vhead, s.vtail, s.older = head, tail, capacity, capacity, s.older[:0]
		return
	}
	previous := s.head
	at, possible := s.resolve(head, capacity)
	if !possible {
		// No release explains this value. It is left out of the account; the
		// next sample is a real release again.
		s.natural("behind", previous, head, tail, capacity-4-min(s.vtail-s.vhead, capacity-4))
		return
	}
	s.unexplained = false
	s.advance(head, at-s.vhead, capacity)
	if uint32(s.vtail-s.vhead) != (tail-head)&mask {
		s.clean = false
		s.natural("inconsistent", previous, head, tail, 0)
		return
	}
	if !s.armed.Load() {
		return
	}
	var need uint64
	for _, p := range packets {
		if len(p) != 0 && len(p) <= MaxPacketSize {
			need += uint64(aligned(uint32(len(p)) + 4))
		}
	}
	if need <= capacity-4-(s.vtail-s.vhead) {
		return // the batch fits, so an older Head would change nothing
	}
	for i := len(s.older) - 1; i >= 0; i-- {
		if s.vtail-s.older[i] < capacity {
			continue // our Tail has not lapped this one: the ring would only look fuller
		}
		// Our Tail has lapped it, so with it in place the writer's free-space
		// arithmetic wraps and the ring looks nearly empty.
		stale = (head - uint32(s.vhead-s.older[i])) & mask
		if !atomic.CompareAndSwapUint32(r.receive.word(0), head, stale) {
			return 0, 0, false // the driver has just published; a later batch will do
		}
		s.behind = s.vhead - s.older[i]
		return stale, head, true
	}
	return
}

// after takes the older Head out again and records what the batch did.
func (s *staleHeadIO) after(stale, newest uint32, replayed bool) {
	if !s.clean {
		return
	}
	s.Session.mu.RLock()
	defer s.Session.mu.RUnlock()
	r := s.Session.rings
	if r == nil || r != s.seen || r.closed {
		s.clean = false
		if replayed {
			// The session was replaced while the batch was written: no verdict.
			s.armed.Store(false)
			s.replayed = true
			s.count(func(c *staleHeadCounts) { c.Replays++ })
		}
		return
	}
	capacity, mask := uint64(r.receive.capacity), r.receive.capacity-1
	tail := r.receive.load(4)
	s.vtail += uint64((tail - s.tail) & mask)
	s.tail = tail
	if !replayed {
		return
	}
	ended := false
	if !atomic.CompareAndSwapUint32(r.receive.word(0), stale, newest) {
		// The driver published during the batch. Its value is at least as new as
		// the one replaced, so the batch is judged against it: an overrun counted
		// below is certain, and one the release then covered is not counted.
		head := r.receive.load(0)
		by := uint64((head - newest) & mask)
		switch {
		case head == ^uint32(0):
			// The driver stopped the ring while this very batch was being written:
			// it read what the batch overwrote. Judge the batch against the last
			// Head it published.
			ended = true
		case head > mask || head&3 != 0 || by > s.vtail-s.vhead:
			s.clean = false // a value no release explains: no verdict
			s.count(func(c *staleHeadCounts) { c.Replays++ })
			return
		default:
			s.advance(head, by, capacity)
		}
	}
	limit := s.vhead + capacity - 4
	s.count(func(c *staleHeadCounts) {
		c.Replays++
		if s.vtail > limit {
			c.Overruns++
			c.OverrunBytes += s.vtail - limit
			c.BytesBehind = s.behind
		}
	})
	if s.vtail > limit || ended {
		// One overrun is the experiment. From here the ring holds more than this
		// account can describe, until it is next seen empty.
		s.armed.Store(false)
		s.clean, s.replayed = false, true
	}
}

type staleHeadDifference struct {
	Round      int             `json:"round"`
	Stream     int             `json:"stream"`
	Received   int64           `json:"received_bytes"`
	Difference *wordDifference `json:"difference"`
}

type staleHeadRounds struct {
	Rounds     int `json:"rounds"`
	Completed  int `json:"completed_streams"`
	Incomplete int `json:"incomplete_streams"`
	Mismatched int `json:"mismatched_streams"`
}

// stalledRound echoes eight verified streams whose readers start late and then
// stall between bursts. Windows keeps a packet in the ring until its reader
// takes the data, so the late start fills the ring whatever the runner's speed
// (an ARM64 runner reading at once never filled a 1 MiB ring).
func stalledRound(round, size int) (completed, incomplete int, differences []staleHeadDifference, err error) {
	const streams = 8
	transfer := integrityTransferID.Add(1)
	if err = validPayloadIdentity(transfer, streams); err != nil {
		return
	}
	contents, release := performancePayloads.prepare(transfer, streams, wordPayloadSize)
	defer release()
	var wg sync.WaitGroup
	var mu sync.Mutex
	for stream := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("198.19.240.1")}, Timeout: 5 * time.Second}
			c, dialErr := d.Dial("tcp4", "198.19.240.2:9002")
			if dialErr != nil {
				mu.Lock()
				incomplete++
				err = errors.Join(err, dialErr)
				mu.Unlock()
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(15 * time.Second))
			c.(*net.TCPConn).SetReadBuffer(4 << 20)
			written := make(chan error, 1)
			go func() {
				_, e := sendImmutablePayload(c, contents[stream][:size])
				if e == nil {
					e = c.(*net.TCPConn).CloseWrite()
				}
				written <- e
			}()
			v := &wordVerifier{transfer: transfer, stream: stream}
			b := make([]byte, 256<<10)
			var n int64
			var readErr error
			time.Sleep(150 * time.Millisecond)
			for reads := 1; readErr == nil; reads++ {
				var k int
				if k, readErr = c.Read(b); k > 0 {
					v.consume(b[:k])
					n += int64(k)
				}
				if reads%3 == 0 {
					time.Sleep(time.Duration(1+stream%4) * time.Millisecond)
				}
			}
			v.finish()
			c.Close()
			writeErr := <-written
			mu.Lock()
			defer mu.Unlock()
			if n == int64(size) && errors.Is(readErr, io.EOF) && writeErr == nil {
				completed++
			} else {
				incomplete++
			}
			if v.first != nil {
				differences = append(differences, staleHeadDifference{round, stream, n, v.first})
			}
		}()
	}
	wg.Wait()
	return
}

// TestWintunStaleReceiveHead shows on a real adapter what one late Head store
// costs. Control rounds come first, with nothing replayed. Each round after
// that gets one older Head for one write batch, at a moment the ring is full.
//
// Each ring size runs twice. Through the writer as it was before the guard,
// the test asserts the defect: the writer overruns and applications see the
// damage. Through the session's own writer it asserts the guard: every
// replayed Head is refused, nothing is overrun and nothing is damaged.
//
// The race itself is too rare to wait for: small rings kept full carried 1,920
// streams on the hosted runners without one wrong byte, for the signed DLL and
// for us (2026-11-10).
func TestWintunStaleReceiveHead(t *testing.T) {
	requireRunner(t)
	const (
		streamBytes   = 2 << 20
		controlRounds = 5
		replayRounds  = 5
	)
	var overruns, damaged, refused int
	for _, run := range []struct {
		capacity uint32
		guarded  bool
	}{{MinCapacity, false}, {MinCapacity, true}, {1 << 20, false}, {1 << 20, true}} {
		capacity, mode := run.capacity, map[bool]string{false: "unguarded", true: "guarded"}[run.guarded]
		t.Run(fmt.Sprintf("%dKiB/%s", capacity>>10, mode), func(t *testing.T) {
			a := newAdapter(t, capacity)
			// Ordinary 1,500-byte packets: many more of them fit the ring, and
			// Windows keeps each one until its reader takes the data.
			command(t, "netsh.exe", "interface", "ipv4", "set", "subinterface", "NsRingCI", "mtu=1500", "store=active")
			f := fixtureOnAdapter(t, "ours", a)
			session := f.io.(*Session)
			replay := &staleHeadIO{Session: session, unguarded: !run.guarded}
			f.stopEcho()
			f.io = replay
			f.stopEcho = tcpEcho(t, f)

			var control, replayed staleHeadRounds
			var controlCounts staleHeadCounts
			var overrunRounds, damagedRounds int
			var differences []staleHeadDifference
			var problem error
			start := time.Now()
			for round := 1; round <= controlRounds+replayRounds && time.Since(start) < 90*time.Second && f.fault() == nil; round++ {
				before, armed, totals := replay.snapshot(), round > controlRounds, &control
				if armed {
					totals = &replayed
				}
				replay.armed.Store(armed)
				completed, incomplete, d, err := stalledRound(round, streamBytes)
				replay.armed.Store(false)
				after := replay.snapshot()
				totals.Rounds, totals.Completed, totals.Incomplete, totals.Mismatched = totals.Rounds+1, totals.Completed+completed, totals.Incomplete+incomplete, totals.Mismatched+len(d)
				if !armed {
					controlCounts = after
				}
				if after.Overruns > before.Overruns {
					overrunRounds++
					if len(d) != 0 || incomplete != 0 || f.fault() != nil {
						damagedRounds++
					}
				}
				differences = append(differences, d...)
				problem = errors.Join(problem, err)
			}
			counts := replay.snapshot()
			if len(differences) > 4 {
				differences = differences[:4]
			}
			// The driver ends the session itself when the writer laps its read
			// position: the other way one stale Head shows, besides wrong bytes.
			stats := session.Stats()
			report(t, map[string]any{"test": "stale_receive_head", "arch": runtime.GOARCH, "capacity": capacity, "mode": mode, "mtu": 1500,
				"streams_per_round": 8, "stream_bytes": streamBytes, "control": control, "control_counts": controlCounts, "replay": replayed, "counts": counts,
				"overrun_rounds": overrunRounds, "damaged_rounds": damagedRounds, "session_lost": f.fault() != nil, "differences": differences,
				"ignored_heads": stats.IgnoredHeads, "shifted_entries": stats.ShiftedEntries, "head_probes": stats.HeadProbes,
				"seconds": time.Since(start).Seconds(), "session": observeSession(session), "fault": fmt.Sprint(f.fault()), "error": fmt.Sprint(problem)})
			if control.Completed == 0 || control.Incomplete != 0 || control.Mismatched != 0 || controlCounts.Replays != 0 {
				t.Errorf("the control rounds were not clean (%+v, %+v), so nothing after a replay would prove anything", control, controlCounts)
			}
			// A replay needs a batch that does not fit the ring. Whether the ring
			// gets that full depends on the runner, so one size may show nothing.
			switch {
			case run.guarded && (counts.Overruns != 0 || replayed.Mismatched != 0 || replayed.Incomplete != 0 || f.fault() != nil):
				t.Errorf("the guard let a replayed Head do damage: %+v, %+v, fault %v", counts, replayed, f.fault())
			case run.guarded && counts.Replays == 0:
				t.Logf("nothing was replayed at this ring size (%+v)", counts)
			case run.guarded && stats.IgnoredHeads == 0:
				t.Errorf("%d Heads were replayed and the guard refused none", counts.Replays)
			case run.guarded:
				refused += int(stats.IgnoredHeads)
			case overrunRounds == 0:
				t.Logf("nothing was replayed into an overrun at this ring size (%+v)", counts)
			case damagedRounds == 0:
				t.Errorf("the writer overran in %d rounds and no stream was damaged: the defect did not reproduce here (%+v)", overrunRounds, counts)
			}
			if !run.guarded {
				overruns, damaged = overruns+overrunRounds, damaged+damagedRounds
			}
		})
	}
	if overruns == 0 || damaged == 0 {
		t.Errorf("without the guard no ring size showed the defect: %d overrun rounds, %d damaged", overruns, damaged)
	}
	if refused == 0 {
		t.Errorf("with the guard no replayed Head was refused at any ring size: the guarded runs proved nothing")
	}
}
