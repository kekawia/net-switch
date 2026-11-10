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
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/packet"
)

// Hosted evidence for the Receive.Head race in the signed 0.14.1 driver (see
// receive_head_model_windows_test.go). Both tests here report what they
// measure and fail only when their own harness is broken: the signed DLL's
// writer has the defect by design, and ours has it until the writer guard
// lands. Neither test is part of the nightly integrity sequence.

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

type headRaceDifference struct {
	Round      int             `json:"round"`
	Stream     int             `json:"stream"`
	Received   int64           `json:"received_bytes"`
	Difference *wordDifference `json:"difference"`
}

// headRaceRound echoes eight verified streams whose readers stall between
// bursts, so Windows keeps packets in the ring and then returns many at once
// from several threads: the conditions the 0.14.1 release path mishandles.
func headRaceRound(round, size int) (completed, incomplete int, received int64, differences []headRaceDifference, err error) {
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
			c.SetDeadline(time.Now().Add(20 * time.Second))
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
			received += n
			if n == int64(size) && errors.Is(readErr, io.EOF) && writeErr == nil {
				completed++
			} else {
				incomplete++
			}
			if v.first != nil {
				differences = append(differences, headRaceDifference{round, stream, n, v.first})
			}
		}()
	}
	wg.Wait()
	return
}

// TestWintunReceiveHeadRace measures how often delivered TCP bytes are wrong
// when the Receive ring is small and kept full. It reports a rate per session
// implementation and never fails on a mismatch.
func TestWintunReceiveHeadRace(t *testing.T) {
	requireRunner(t)
	const streamBytes = 2 << 20
	for _, capacity := range []uint32{MinCapacity, 1 << 20} {
		for _, mode := range []string{"dll", "ours"} {
			t.Run(fmt.Sprintf("%s/%dKiB", mode, capacity>>10), func(t *testing.T) {
				a := newAdapter(t, capacity)
				// Ordinary 1,500-byte packets: many more of them fit the ring, and
				// each is returned to the driver on its own.
				command(t, "netsh.exe", "interface", "ipv4", "set", "subinterface", "NsRingCI", "mtu=1500", "store=active")
				f := fixtureOnAdapter(t, mode, a)
				f.stopEcho()
				f.stopEcho = tcpEcho(t, f)
				var rounds, completed, incomplete int
				var received int64
				var differences []headRaceDifference
				var problem error
				start := time.Now()
				for rounds < 10 && time.Since(start) < 30*time.Second {
					rounds++
					c, i, n, d, err := headRaceRound(rounds, streamBytes)
					completed, incomplete, received = completed+c, incomplete+i, received+n
					differences = append(differences, d...)
					problem = errors.Join(problem, err)
				}
				seconds := time.Since(start).Seconds()
				result := map[string]any{"test": "receive_head_race", "arch": runtime.GOARCH, "mode": mode, "capacity": capacity, "mtu": 1500,
					"rounds": rounds, "streams_per_round": 8, "stream_bytes": streamBytes, "completed_streams": completed, "incomplete_streams": incomplete,
					"mismatched_streams": len(differences), "received_bytes": received, "megabytes_per_second": float64(received) / seconds / 1e6,
					"seconds": seconds, "fault": fmt.Sprint(f.fault()), "error": fmt.Sprint(problem)}
				if len(differences) > 4 {
					differences = differences[:4]
				}
				result["differences"] = differences
				switch s := f.io.(type) {
				case *Session:
					result["session"] = observeSession(s)
				case *dllSession:
					result["dll_packets"] = map[string]uint64{"read": s.readPackets.Load(), "written": s.writtenPackets.Load()}
				}
				report(t, result)
				if completed == 0 {
					t.Errorf("no stream completed: the harness measured nothing (%v)", problem)
				}
			})
		}
	}
}
