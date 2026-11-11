package stack_test

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func tcpWithOptions(b, options []byte) []byte {
	result := append(bytes.Clone(b), options...)
	ip := header.IPv4(result)
	binary.BigEndian.PutUint16(result[2:4], uint16(len(result)))
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	h := header.TCP(result[ip.HeaderLength():])
	h[12] = byte(len(h)/4) << 4
	h.SetChecksum(0)
	sum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(h)))
	h.SetChecksum(^checksum.Checksum(h, sum))
	return result
}

func TestTCPRecoveryAfterLostWindow(t *testing.T) {
	for _, mode := range []string{"rack", "sack", "rack_reordered", "rack_timer"} {
		t.Run(mode, func(t *testing.T) { tcpRecoveryAfterLostWindow(t, mode) })
	}
}

// Observe the real timer scheduled by packet handling, without exposing or
// changing TCP internals. No timer is injected and no callback is called early.
type recoveryClock struct {
	*faketime.ManualClock
	watch atomic.Bool
	armed chan time.Duration
	fired chan struct{}
}

func (c *recoveryClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	if d > 0 && d <= 2*time.Millisecond && c.watch.CompareAndSwap(true, false) {
		timer := c.ManualClock.AfterFunc(d, func() { f(); close(c.fired) })
		c.armed <- d
		return timer
	}
	return c.ManualClock.AfterFunc(d, f)
}

func tcpRecoveryAfterLostWindow(t *testing.T, mode string) {
	clock := &recoveryClock{ManualClock: faketime.NewManualClock(), armed: make(chan time.Duration, 1), fired: make(chan struct{})}
	options := ns.DefaultOptions()
	options.Clock = clock
	options.ClockResolution = 0
	if mode == "rack_timer" {
		options.ClockResolution = time.Millisecond
	}
	p := newPeerOptions(t, false, flows.Defaults(), options)
	if mode == "sack" {
		recovery := tcpip.TCPRecovery(0)
		if err := p.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
			t.Fatal(err)
		}
	}
	p.fixedSendBuffer = 64 << 10
	p.openWith(1000, func(b []byte) {
		// Advertise 1460-byte segments and selective acknowledgements.
		p.inject(tcpWithOptions(b, []byte{2, 4, 5, 180, 4, 2, 1, 1}))
	})
	p.upload([]byte("download"))
	ep := p.endpoint()
	if !ep.SACKPermitted {
		t.Fatal("SACK was not negotiated")
	}
	var initial tcpip.TCPInfoOption
	if err := ep.GetSockOpt(&initial); err != nil || initial.SndMss == 0 {
		t.Fatalf("negotiated TCP MSS: %+v, %v", initial, err)
	}
	mss := int(initial.SndMss)
	const segments = 16
	payload := make([]byte, mss*segments)
	for i := range payload {
		payload[i] = byte(i*17 + i/251)
	}
	written := make(chan error, 1)
	go func() {
		_, err := p.current.conn.Write(payload)
		written <- err
	}()
	awaitSendBuffer(t, ep, len(payload))
	if err := <-written; err != nil {
		t.Fatal(err)
	}

	// Lose the complete initial congestion window, including any tail probe.
	// There is no random loss, packet delay or scheduling-dependent injection.
	lost := 0
	for lost < tcp.InitialCwnd {
		h := p.read(time.Second)
		if h == nil {
			t.Fatalf("initial flight stopped after %d packets", lost)
		}
		if data := h[h.DataOffset():]; len(data) != 0 {
			if h.SequenceNumber() != p.ack+uint32(lost*mss) || len(data) != mss {
				t.Fatal("unexpected initial flight", segmentDescription(h))
			}
			lost++
		}
	}
	// RACK may send a tail probe before the RTO. No ACK is sent in this
	// bounded timer sequence, and exactly one RTO must establish recovery.
	var first header.TCP
	for attempt := 0; attempt < 4; attempt++ {
		var info tcpip.TCPInfoOption
		if err := ep.GetSockOpt(&info); err != nil {
			t.Fatal(err)
		}
		clock.Advance(info.RTO + time.Millisecond)
		h := p.read(time.Second)
		if h == nil {
			t.Fatal("loss timer did not send a packet")
		}
		if p.stack.Stats().TCP.Timeouts.Value() != 0 && h.SequenceNumber() == p.ack {
			first = h
			break
		}
	}
	if first == nil {
		t.Fatal("did not establish an RTO retransmission")
	}
	if got := p.stack.Stats().TCP.Timeouts.Value(); got != 1 {
		t.Fatalf("recovery started after %d timeouts, want exactly one", got)
	}
	t.Logf("lost %d packets; RTO retransmitted %s", lost, segmentDescription(first))

	// ACK every retransmission. Advancing only by 1 ms per ACK leaves the next
	// RTO unexpired: progress must come from ACK handling, not another timeout.
	received := make([]byte, 0, len(payload))
	h := first
	for len(received) < len(payload) {
		data := h[h.DataOffset():]
		if h.SequenceNumber() == p.ack && len(data) != 0 {
			received = append(received, data...)
			p.ack += uint32(len(data))
		}
		clock.Advance(time.Millisecond)
		p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
		if (mode == "rack_reordered" || mode == "rack_timer") && len(received) == mss {
			// Deliver the third retransmitted segment before the second.
			// This is a legitimate new SACK during RTO recovery, followed
			// by a cumulative ACK once the gap is filled.
			second, third := p.read(time.Second), p.read(time.Second)
			if second == nil || third == nil || second.SequenceNumber() != p.ack || third.SequenceNumber() != p.ack+uint32(mss) {
				t.Fatal("timeout recovery did not produce the next two segments")
			}
			secondData, thirdData := second[second.DataOffset():], third[third.DataOffset():]
			if len(secondData) != mss || len(thirdData) != mss {
				t.Fatal("unexpected retransmission payload size")
			}
			sack := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(sack[4:8], third.SequenceNumber())
			binary.BigEndian.PutUint32(sack[8:12], third.SequenceNumber()+uint32(len(thirdData)))
			if mode == "rack_timer" {
				// Give the third segment a valid RTT sample, then keep the
				// second delayed across the actual reordering deadline.
				clock.Advance(10 * time.Millisecond)
				clock.watch.Store(true)
			}
			p.inject(tcpWithOptions(p.packet(p.seq, p.ack, header.TCPFlagAck, nil), sack))
			if mode == "rack_timer" {
				var delay time.Duration
				select {
				case delay = <-clock.armed:
				case <-time.After(time.Second):
					t.Fatal("new SACK did not arm the reordering timer")
				}
				var info tcpip.TCPInfoOption
				if err := ep.GetSockOpt(&info); err != nil || info.CcState != tcpip.RTORecovery {
					t.Fatalf("before reordering timer: state=%+v error=%v", info, err)
				}
				clock.Advance(delay)
				select {
				case <-clock.fired:
				default:
					t.Fatal("armed reordering timer did not fire")
				}
				if err := ep.GetSockOpt(&info); err != nil || info.CcState != tcpip.RTORecovery {
					t.Fatalf("reordering timer replaced timeout recovery: state=%+v error=%v", info, err)
				}
				t.Logf("real reordering timer armed and fired after %s during timeout recovery", delay)
			}
			received = append(received, secondData...)
			received = append(received, thirdData...)
			p.ack += uint32(len(secondData) + len(thirdData))
			p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
		}
		if len(received) == len(payload) {
			break
		}
		h = p.read(time.Second)
		if h == nil {
			var info tcpip.TCPInfoOption
			ep.GetSockOpt(&info)
			t.Fatalf("ACK-driven recovery stalled at %d/%d bytes: TCP=%+v timeouts=%d", len(received), len(payload), info, p.stack.Stats().TCP.Timeouts.Value())
		}
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("recovered payload changed")
	}
	if got := p.stack.Stats().TCP.Timeouts.Value(); got != 1 {
		t.Fatalf("needed %d retransmission timeouts to recover one lost window", got)
	}
}

func readDataSegments(t *testing.T, p *peer, count, mss int) header.TCP {
	t.Helper()
	var last header.TCP
	for read := 0; read < count; {
		h := p.read(time.Second)
		if h == nil {
			t.Fatalf("expected %d data segments, stopped after %d", count, read)
		}
		data := h[h.DataOffset():]
		if len(data) == 0 {
			continue
		}
		if len(data) != mss {
			t.Fatalf("segment %d payload len = %d, want %d (%s)", read, len(data), mss, segmentDescription(h))
		}
		last = h
		read++
	}
	return last
}

type ptoClock struct {
	*faketime.ManualClock
	watch atomic.Bool
	armed chan time.Duration
}

type ptoTimer struct {
	tcpip.Timer
	clock *ptoClock
}

func (c *ptoClock) record(d time.Duration) {
	if d > 0 && d < 100*time.Millisecond && c.watch.CompareAndSwap(true, false) {
		c.armed <- d
	}
}

func (c *ptoClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	c.record(d)
	return &ptoTimer{Timer: c.ManualClock.AfterFunc(d, f), clock: c}
}

func (t *ptoTimer) Reset(d time.Duration) {
	t.clock.record(d)
	t.Timer.Reset(d)
}

func TestTLPSpuriousProbeAndConfirmedSingleLoss(t *testing.T) {
	t.Run("sub_ms_jitter_does_not_probe", func(t *testing.T) {
		clock := &ptoClock{ManualClock: faketime.NewManualClock(), armed: make(chan time.Duration, 1)}
		options := ns.DefaultOptions()
		options.Clock = clock
		options.ClockResolution = 0
		p := newPeerOptions(t, true, flows.Defaults(), options)
		p.fixedSendBuffer = 256 << 10
		p.openWith(1000, func(b []byte) {
			p.inject(tcpWithOptions(b, []byte{2, 4, 5, 180, 4, 2, 1, 1}))
		})
		p.upload([]byte("download"))
		ep := p.endpoint()
		var initial tcpip.TCPInfoOption
		if err := ep.GetSockOpt(&initial); err != nil || initial.SndMss == 0 {
			t.Fatalf("negotiated TCP MSS: %+v, %v", initial, err)
		}
		mss := int(initial.SndMss)

		// Establish the 1 ms floor SRTT typical of an in-host Linux TUN leg.
		warm := make([]byte, mss)
		if _, err := p.current.conn.Write(warm); err != nil {
			t.Fatal(err)
		}
		readDataSegments(t, p, 1, mss)
		clock.Advance(500 * time.Microsecond)
		p.ack += uint32(mss)
		p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
		awaitSendBuffer(t, ep, 0)

		// Fill a multi-segment flight and verify the armed PTO includes the
		// minimum timer margin (>= 4 ms at 1 ms SRTT, not bare 2*SRTT = 2 ms)
		// so a 2-3 ms GOMEMLIMIT GC assist pause on the TUN reader cannot fire
		// a spurious TLP probe.
		clock.watch.Store(true)
		const flightSegs = 6
		if _, err := p.current.conn.Write(make([]byte, mss*flightSegs)); err != nil {
			t.Fatal(err)
		}
		readDataSegments(t, p, flightSegs, mss)
		var pto time.Duration
		select {
		case pto = <-clock.armed:
		case <-time.After(time.Second):
			t.Fatal("multi-segment flight did not arm PTO timer")
		}
		if pto < 4*time.Millisecond {
			t.Fatalf("multi-segment PTO on 1 ms SRTT = %v, want >= 4ms", pto)
		}
	})

	for _, mode := range []string{"dsack", "pure_dupack"} {
		t.Run("spurious_probe_"+mode, func(t *testing.T) {
			clock := faketime.NewManualClock()
			options := ns.DefaultOptions()
			options.Clock = clock
			options.ClockResolution = 0
			p := newPeerOptions(t, true, flows.Defaults(), options)
			p.fixedSendBuffer = 256 << 10
			p.openWith(1000, func(b []byte) {
				p.inject(tcpWithOptions(b, []byte{2, 4, 5, 180, 4, 2, 1, 1}))
			})
			p.upload([]byte("download"))
			ep := p.endpoint()
			var initial tcpip.TCPInfoOption
			if err := ep.GetSockOpt(&initial); err != nil || initial.SndMss == 0 {
				t.Fatalf("negotiated TCP MSS: %+v, %v", initial, err)
			}
			mss := int(initial.SndMss)

			// Seed a 1 ms SRTT and wait for ACK processing to finish.
			if _, err := p.current.conn.Write(make([]byte, mss)); err != nil {
				t.Fatal(err)
			}
			readDataSegments(t, p, 1, mss)
			clock.Advance(time.Millisecond)
			p.ts++
			p.ack += uint32(mss)
			p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
			awaitSendBuffer(t, ep, 0)

			var beforeInfo tcpip.TCPInfoOption
			if err := ep.GetSockOpt(&beforeInfo); err != nil {
				t.Fatal(err)
			}
			flightSegs := int(beforeInfo.SndCwnd)
			written := make(chan error, 1)
			go func() {
				_, err := p.current.conn.Write(make([]byte, mss*(flightSegs+2)))
				written <- err
			}()
			awaitSendBuffer(t, ep, mss*(flightSegs+2))
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			readDataSegments(t, p, flightSegs, mss)
			flightEnd := p.ack + uint32(flightSegs*mss)
			tailStart := flightEnd - uint32(mss)

			// Delay reading the peer's cumulative ACK past PTO so a spurious TLP
			// retransmission of [tailStart, flightEnd) is sent while the original
			// cumulative ACK is already queued in TUN.
			clock.Advance(6 * time.Millisecond)
			probe := readDataSegments(t, p, 1, mss)
			if probe.SequenceNumber() != tailStart {
				t.Fatalf("expected TLP retransmission of [%d, %d), got %s", tailStart, flightEnd, segmentDescription(probe))
			}

			// 1. First read from TUN: peer's original cumulative ACK (predates the probe, so no DSACK).
			p.ts += 6
			p.ack = flightEnd
			p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
			awaitSendBuffer(t, ep, 2*mss)
			// Drain the two newly unsent segments unlocked by the cumulative ACK.
			readDataSegments(t, p, 2, mss)

			// 2. Second read from TUN: peer receives the duplicate TLP probe and replies
			// with either a DSACK [tailStart, flightEnd) or a pure duplicate ACK.
			clock.Advance(500 * time.Microsecond)
			if mode == "dsack" {
				dsack := []byte{1, 1, 5, 10, 0, 0, 0, 0, 0, 0, 0, 0}
				binary.BigEndian.PutUint32(dsack[4:8], tailStart)
				binary.BigEndian.PutUint32(dsack[8:12], flightEnd)
				p.inject(tcpWithOptions(p.packet(p.seq, p.ack, header.TCPFlagAck, nil), dsack))
			} else {
				p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
			}

			// 3. Peer cumulatively ACKs the next two segments beyond flightEnd.
			clock.Advance(time.Millisecond)
			p.ts++
			p.ack = flightEnd + uint32(2*mss)
			p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
			awaitSendBuffer(t, ep, 0)

			var afterInfo tcpip.TCPInfoOption
			if err := ep.GetSockOpt(&afterInfo); err != nil {
				t.Fatal(err)
			}
			if got := p.stack.Stats().TCP.SACKRecovery.Value(); got != 0 {
				t.Fatalf("spurious TLP probe entered SACKRecovery %d times, want 0", got)
			}
			if got := p.stack.Stats().TCP.TLPRecovery.Value(); got != 0 {
				t.Fatalf("spurious TLP probe counted %d TLPRecovery events, want 0", got)
			}
			if afterInfo.CcState != tcpip.Open {
				t.Fatalf("CcState after spurious TLP probe = %v, want Open", afterInfo.CcState)
			}
			if afterInfo.SndCwnd < beforeInfo.SndCwnd {
				t.Fatalf("spurious TLP probe collapsed SndCwnd from %d to %d", beforeInfo.SndCwnd, afterInfo.SndCwnd)
			}
		})
	}

	t.Run("confirmed_single_tail_loss", func(t *testing.T) {
		clock := faketime.NewManualClock()
		options := ns.DefaultOptions()
		options.Clock = clock
		options.ClockResolution = 0
		p := newPeerOptions(t, true, flows.Defaults(), options)
		p.fixedSendBuffer = 256 << 10
		p.openWith(1000, func(b []byte) {
			p.inject(tcpWithOptions(b, []byte{2, 4, 5, 180, 4, 2, 1, 1}))
		})
		p.upload([]byte("download"))
		ep := p.endpoint()
		var initial tcpip.TCPInfoOption
		if err := ep.GetSockOpt(&initial); err != nil || initial.SndMss == 0 {
			t.Fatalf("negotiated TCP MSS: %+v, %v", initial, err)
		}
		mss := int(initial.SndMss)

		// Seed a 1 ms SRTT and wait for ACK processing to finish.
		if _, err := p.current.conn.Write(make([]byte, mss)); err != nil {
			t.Fatal(err)
		}
		readDataSegments(t, p, 1, mss)
		clock.Advance(time.Millisecond)
		p.ts++
		p.ack += uint32(mss)
		p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
		awaitSendBuffer(t, ep, 0)

		var beforeInfo tcpip.TCPInfoOption
		if err := ep.GetSockOpt(&beforeInfo); err != nil {
			t.Fatal(err)
		}

		// Send 4 segments; peer receives the first 3 and drops the 4th (tail loss).
		if _, err := p.current.conn.Write(make([]byte, mss*4)); err != nil {
			t.Fatal(err)
		}
		readDataSegments(t, p, 4, mss)
		tailStart := p.ack + uint32(3*mss)
		flightEnd := p.ack + uint32(4*mss)

		clock.Advance(time.Millisecond)
		p.ts++
		p.ack = tailStart
		p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
		awaitSendBuffer(t, ep, mss)

		// PTO expires and retransmits the lost 4th segment [tailStart, flightEnd).
		// Note: Outstanding == 1, so PTO includes wcDelayedACKTimeout (200 ms).
		var rtoInfo tcpip.TCPInfoOption
		if err := ep.GetSockOpt(&rtoInfo); err != nil {
			t.Fatal(err)
		}
		var probe header.TCP
		for attempt := 0; attempt < 4 && probe == nil; attempt++ {
			if attempt == 0 {
				clock.Advance(10 * time.Millisecond)
			} else {
				clock.Advance(rtoInfo.RTO + 20*time.Millisecond)
			}
			for {
				h := p.read(50 * time.Millisecond)
				if h == nil {
					break
				}
				if len(h[h.DataOffset():]) == mss {
					probe = h
					break
				}
			}
		}
		if probe == nil || probe.SequenceNumber() != tailStart {
			t.Fatalf("expected TLP probe for %d, got %v", tailStart, probe)
		}

		// Peer receives the probe and cumulatively ACKs flightEnd (no DSACK, because original was lost).
		clock.Advance(time.Millisecond)
		p.ts++
		p.ack = flightEnd
		p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
		awaitSendBuffer(t, ep, 0)

		// Now write 2 more segments; peer receives the 1st (confirming the earlier single loss
		// via ACK > flightEnd without DSACK/DupAck) and drops the 2nd!
		if _, err := p.current.conn.Write(make([]byte, mss*2)); err != nil {
			t.Fatal(err)
		}
		readDataSegments(t, p, 2, mss)
		clock.Advance(time.Millisecond)
		p.ts++
		p.ack = flightEnd + uint32(mss)
		p.inject(p.packet(p.seq, p.ack, header.TCPFlagAck, nil))
		awaitSendBuffer(t, ep, mss)

		var afterConfirm tcpip.TCPInfoOption
		if err := ep.GetSockOpt(&afterConfirm); err != nil {
			t.Fatal(err)
		}
		if got := p.stack.Stats().TCP.TLPRecovery.Value(); got != 1 {
			t.Fatalf("TLPRecovery = %d, want 1", got)
		}
		if afterConfirm.SndCwnd >= beforeInfo.SndCwnd {
			t.Fatalf("confirmed tail loss did not reduce SndCwnd: before=%d after=%d", beforeInfo.SndCwnd, afterConfirm.SndCwnd)
		}
		if afterConfirm.CcState != tcpip.Open {
			t.Fatalf("confirmed TLP single-loss repair left CcState = %v, want Open", afterConfirm.CcState)
		}
	})
}
