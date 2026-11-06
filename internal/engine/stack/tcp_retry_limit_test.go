package stack_test

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// retryLimitPeer is a connection on a manual clock with a low retry limit, whose
// peer negotiates SACK without timestamps.
type retryLimitPeer struct {
	*peer
	clock *faketime.ManualClock
	ep    *tcp.Endpoint
	mss   int
}

func newRetryLimitPeer(t *testing.T, maxRetries int, recovery tcpip.TCPRecovery) *retryLimitPeer {
	t.Helper()
	clock := faketime.NewManualClock()
	options := ns.DefaultOptions()
	options.Clock = clock
	options.ClockResolution = 0
	p := newPeerOptions(t, false, flows.Defaults(), options)
	limit := tcpip.TCPMaxRetriesOption(maxRetries)
	if err := p.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &limit); err != nil {
		t.Fatal(err)
	}
	if err := p.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
		t.Fatal(err)
	}
	p.fixedSendBuffer = 64 << 10
	p.openWith(1000, func(b []byte) {
		// Advertise 1460-byte segments and selective acknowledgements.
		p.inject(tcpWithOptions(b, []byte{2, 4, 5, 180, 4, 2, 1, 1}))
	})
	p.upload([]byte("download"))
	r := &retryLimitPeer{peer: p, clock: clock, ep: p.endpoint()}
	if !r.ep.SACKPermitted {
		t.Fatal("SACK was not negotiated")
	}
	r.mss = int(r.info().SndMss)
	if r.mss == 0 {
		t.Fatal("no negotiated TCP MSS")
	}
	return r
}

func (r *retryLimitPeer) info() tcpip.TCPInfoOption {
	r.t.Helper()
	var info tcpip.TCPInfoOption
	if err := r.ep.GetSockOpt(&info); err != nil {
		r.t.Fatal(err)
	}
	return info
}

// send writes segments full-sized segments and reads the first transmission of
// each, which the peer treats as lost.
func (r *retryLimitPeer) send(segments int) {
	r.t.Helper()
	payload := make([]byte, segments*r.mss)
	written := make(chan error, 1)
	go func() {
		_, err := r.current.conn.Write(payload)
		written <- err
	}()
	awaitSendBuffer(r.t, r.ep, len(payload))
	if err := <-written; err != nil {
		r.t.Fatal(err)
	}
	for sent := 0; sent < segments; {
		h := r.read(time.Second)
		if h == nil {
			r.t.Fatalf("first flight stopped after %d segments", sent)
		}
		if len(h) > int(h.DataOffset()) {
			if h.SequenceNumber() != r.ack+uint32(sent*r.mss) {
				r.t.Fatal("unexpected first flight", segmentDescription(h))
			}
			sent++
		}
	}
}

// expectData reads until the segment at seq arrives.
func (r *retryLimitPeer) expectData(seq uint32) {
	r.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h := r.read(time.Until(deadline))
		if h == nil {
			break
		}
		if len(h) > int(h.DataOffset()) && h.SequenceNumber() == seq {
			return
		}
	}
	r.t.Fatalf("no segment at %d: TCP=%+v timeouts=%d", seq, r.info(), r.stack.Stats().TCP.Timeouts.Value())
}

// copiesUntilQuiet reads until the sender goes quiet and counts data segments at
// seq. A SACK is processed asynchronously, and the clock does not advance here.
func (r *retryLimitPeer) copiesUntilQuiet(seq uint32) int {
	copies := 0
	for {
		h := r.read(100 * time.Millisecond)
		if h == nil {
			return copies
		}
		if len(h) > int(h.DataOffset()) && h.SequenceNumber() == seq {
			copies++
		}
	}
}

// sack acknowledges nothing new cumulatively and reports [start, end).
func (r *retryLimitPeer) sack(start, end uint32) {
	option := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(option[4:8], start)
	binary.BigEndian.PutUint32(option[8:12], end)
	r.inject(tcpWithOptions(r.packet(r.seq, r.ack, header.TCPFlagAck, nil), option))
}

func (r *retryLimitPeer) expectTimedOut(want uint64) {
	r.t.Helper()
	counter := r.stack.Stats().TCP.EstablishedTimedout
	deadline := time.Now().Add(2 * time.Second)
	for counter.Value() != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := counter.Value(); got != want {
		r.t.Fatalf("EstablishedTimedout = %d, want %d", got, want)
	}
}

func (r *retryLimitPeer) timeout() {
	r.t.Helper()
	r.clock.Advance(r.info().RTO + time.Millisecond)
}

// A segment RACK resends many times during SACK recovery must not use up the
// retry limit, which still applies to the timeouts that follow.
func TestTCPRetryLimitCountsOnlyTimeouts(t *testing.T) {
	const (
		maxRetries = 2
		rtt        = 10 * time.Millisecond
		segments   = 10
	)
	r := newRetryLimitPeer(t, maxRetries, tcpip.TCPRACKLossDetection)
	r.send(segments)
	head := r.ack
	at := func(segment int) uint32 { return head + uint32(segment*r.mss) }

	// The last three segments arrive, which starts SACK recovery and resends the
	// oldest segment. The repeated SACK sends the other repairs. Then each later
	// repair that arrives proves that the oldest one was lost.
	r.clock.Advance(rtt)
	r.sack(at(segments-3), at(segments))
	headSends := 1 + r.copiesUntilQuiet(head)
	r.sack(at(segments-3), at(segments))
	headSends += r.copiesUntilQuiet(head)
	for first := segments - 4; first > segments-7; first-- {
		r.clock.Advance(rtt)
		r.sack(at(first), at(segments))
		headSends += r.copiesUntilQuiet(head)
	}
	if got, want := r.info().CcState, tcpip.SACKRecovery; got != want {
		t.Fatalf("after resending the oldest segment: state = %v, want %v", got, want)
	}
	// The test cannot pass without the condition it exercises.
	if headSends <= maxRetries {
		t.Fatalf("oldest segment sent %d times before the first timeout, want more than %d", headSends, maxRetries)
	}
	if got := r.stack.Stats().TCP.Timeouts.Value(); got != 0 {
		t.Fatalf("timeouts before the limit is tested = %d, want 0", got)
	}

	for timeouts := uint64(1); timeouts <= maxRetries; timeouts++ {
		r.timeout()
		r.expectData(head)
		if got := r.stack.Stats().TCP.Timeouts.Value(); got != timeouts {
			t.Fatalf("timeouts = %d, want %d", got, timeouts)
		}
		r.expectTimedOut(0)
	}
	r.timeout()
	r.expectTimedOut(1)
}

// A cumulative ACK must restart the count of timeouts.
func TestTCPRetryLimitRestartsAfterProgress(t *testing.T) {
	const maxRetries = 2
	// Without RACK, the first timer to fire is the retransmission timer rather
	// than a tail loss probe.
	r := newRetryLimitPeer(t, maxRetries, 0)
	r.send(2)

	for i := 0; i < maxRetries; i++ {
		r.timeout()
		r.expectData(r.ack)
		r.expectTimedOut(0)
	}

	// The second segment's timeouts start from zero, so the limit is reached only
	// after maxRetries more.
	r.ack += uint32(r.mss)
	r.inject(r.packet(r.seq, r.ack, header.TCPFlagAck, nil))
	r.expectData(r.ack)
	for i := 0; i < maxRetries; i++ {
		r.timeout()
		r.expectData(r.ack)
		r.expectTimedOut(0)
	}
	r.timeout()
	r.expectTimedOut(1)
}
