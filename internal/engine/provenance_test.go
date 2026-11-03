package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/linux/ownerbpf"
	"github.com/AyoubAchour/net-switch/internal/engine/packet"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
	"github.com/AyoubAchour/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
)

type provFrame struct {
	raw  []byte
	prov any
}

type provTun struct {
	in     chan provFrame
	out    chan []byte
	done   chan struct{}
	once   sync.Once
	ioDone <-chan struct{}
	events func(string)
	bound  atomic.Bool
}

func newProvTun(events func(string)) *provTun {
	return &provTun{
		in:     make(chan provFrame, 256),
		out:    make(chan []byte, 512),
		done:   make(chan struct{}),
		events: events,
	}
}

func (t *provTun) BindIOContext(ctx context.Context) { t.ioDone = ctx.Done() }
func (t *provTun) MTU() int                          { return 9000 }

func (t *provTun) Close() error {
	t.once.Do(func() {
		if t.events != nil {
			t.events("tun-close")
		}
		close(t.done)
	})
	return nil
}

func (t *provTun) ReadPacket(context.Context, []byte) (int, error) {
	return 0, errors.New("unexpected non-provenance ReadPacket call while provenance is active")
}

func (t *provTun) BindPumpThread() (func(), error) {
	t.bound.Store(true)
	if t.events != nil {
		t.events("bind-pump")
	}
	return func() {
		t.bound.Store(false)
		if t.events != nil {
			t.events("unbind-pump")
		}
	}, nil
}

func (t *provTun) ReadPacketWithProvenance(ctx context.Context, b []byte) (int, any, error) {
	if !t.bound.Load() {
		return 0, nil, errors.New("ReadPacketWithProvenance called on unbound pump")
	}
	select {
	case f := <-t.in:
		if len(f.raw) > len(b) {
			return 0, nil, io.ErrShortBuffer
		}
		return copy(b, f.raw), f.prov, nil
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case <-t.done:
		return 0, nil, io.EOF
	}
}

func (t *provTun) WritePacket(ctx context.Context, p []byte) error {
	select {
	case t.out <- bytes.Clone(p):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.done:
		return io.ErrClosedPipe
	}
}

type provRoutes struct {
	testfake.Routes
	events func(string)
}

func (r *provRoutes) Prepare(ctx context.Context, lines []platform.Line) error {
	if r.events != nil {
		r.events("prepare")
	}
	return r.Routes.Prepare(ctx, lines)
}

func (r *provRoutes) Capture(ctx context.Context) error {
	if r.events != nil {
		r.events("capture")
	}
	return r.Routes.Capture(ctx)
}

func (r *provRoutes) Quiesce() {
	if r.events != nil {
		r.events("quiesce")
	}
}

func (r *provRoutes) Cleanup(ctx context.Context) error {
	if r.events != nil {
		r.events("cleanup")
	}
	return r.Routes.Cleanup(ctx)
}

type recordedTCPProvenance struct {
	tuple platform.Tuple
	prov  any
}

type provTestOwners struct {
	rt           *ownerbpf.ProvenanceRuntime
	events       func(string)
	scannerCalls atomic.Uint64
	mu           sync.Mutex
	tcpSeen      []recordedTCPProvenance
	udpSeen      []any
}

func (o *provTestOwners) TCP(context.Context, platform.Tuple) (platform.Owner, error) {
	o.scannerCalls.Add(1)
	return platform.Owner{}, errors.New("unexpected scanner TCP fallback")
}

func (o *provTestOwners) UDP(context.Context, netip.AddrPort) (platform.Owner, error) {
	o.scannerCalls.Add(1)
	return platform.Owner{}, errors.New("unexpected scanner UDP fallback")
}

func (o *provTestOwners) AttachProvenance(_ context.Context, _ platform.TunDevice) (bool, error) {
	if o.events != nil {
		o.events("attach-provenance")
	}
	return true, nil
}

func (o *provTestOwners) EnableProvenance() error {
	if o.events != nil {
		o.events("enable-provenance")
	}
	return nil
}

func (o *provTestOwners) StopProvenance() error {
	if o.events != nil {
		o.events("stop-provenance")
	}
	return nil
}

func (o *provTestOwners) CloseProvenance() error {
	if o.events != nil {
		o.events("close-provenance")
	}
	return nil
}

func (o *provTestOwners) TCPWithProvenance(_ context.Context, tuple platform.Tuple, prov any) (platform.Owner, error) {
	o.mu.Lock()
	o.tcpSeen = append(o.tcpSeen, recordedTCPProvenance{tuple: tuple, prov: prov})
	o.mu.Unlock()
	env, ok := prov.(*ownerbpf.ProvenanceEnvelope)
	if !ok || env == nil {
		return platform.Owner{}, os.ErrNotExist
	}
	owner, status := env.ValidateForwarding()
	switch status {
	case ownerbpf.EnvelopeKnown:
		return owner, nil
	case ownerbpf.EnvelopeConflicting:
		return platform.Owner{Generation: owner.Generation, Ambiguous: true}, platform.ErrAmbiguous
	default:
		return platform.Owner{Generation: owner.Generation}, os.ErrNotExist
	}
}

func (o *provTestOwners) UDPWithProvenance(_ context.Context, _ platform.Tuple, prov any) (platform.Owner, error) {
	o.mu.Lock()
	o.udpSeen = append(o.udpSeen, prov)
	o.mu.Unlock()
	env, ok := prov.(*ownerbpf.ProvenanceEnvelope)
	if !ok || env == nil {
		return platform.Owner{}, os.ErrNotExist
	}
	owner, status := env.ValidateForwarding()
	switch status {
	case ownerbpf.EnvelopeKnown:
		return owner, nil
	case ownerbpf.EnvelopeConflicting:
		return platform.Owner{Generation: owner.Generation, Ambiguous: true}, platform.ErrAmbiguous
	case ownerbpf.EnvelopeKernelControl, ownerbpf.EnvelopeUnknownIdentity:
		return platform.Owner{Generation: owner.Generation}, os.ErrNotExist
	default:
		return platform.Owner{}, os.ErrNotExist
	}
}

func (o *provTestOwners) ValidateUDPDatagram(sessionOwner platform.Owner, prov any) platform.DatagramValidation {
	env, ok := prov.(*ownerbpf.ProvenanceEnvelope)
	if !ok || env == nil {
		return platform.DatagramDrop
	}
	owner, status := env.ValidateForwarding()
	if status == ownerbpf.EnvelopeMissingCookie || owner.Generation == "" {
		return platform.DatagramDrop
	}
	if owner.Generation != sessionOwner.Generation {
		return platform.DatagramInvalidateOwner
	}
	if sessionOwner.Ambiguous {
		return platform.DatagramValid
	}
	if status == ownerbpf.EnvelopeConflicting {
		return platform.DatagramInvalidateOwner
	}
	if sessionOwner.AppID != "" && (status != ownerbpf.EnvelopeKnown || owner.AppID != sessionOwner.AppID) {
		return platform.DatagramInvalidateOwner
	}
	return platform.DatagramValid
}

func enrichTestSocketActor(t *testing.T, rt *ownerbpf.ProvenanceRuntime, cookie uint64, tgid uint32, start uint64, exePath string) ownerbpf.ActorIdentityKey {
	t.Helper()
	dev := ownerbpf.EncodeKernelDev(8, 1)
	ino := uint64(900000) + uint64(tgid)
	key := ownerbpf.ActorKey{
		Cookie: cookie,
		Start:  start,
		Exec:   1,
		TGID:   tgid,
	}
	ev := ownerbpf.ActorEvidence{
		Inode:      ino,
		Device:     dev,
		ObservedNS: 4026531992,
		ABI:        ownerbpf.ABI,
	}
	execCtx := ownerbpf.ExecutionContext{
		TGID:          tgid,
		StartBoottime: start,
		StartTicks:    start / 10_000_000,
		ExecID:        1,
		ExeDev:        dev,
		ExeIno:        ino,
		MntNSInum:     4026531840,
		NetNSInum:     4026531992,
		PIDNSInum:     4026531836,
		RootMntID:     29,
		UID:           1000,
		GID:           1000,
	}
	mat := ownerbpf.RawProcessMaterial{
		Before:  execCtx,
		After:   execCtx,
		ExePath: exePath,
		Mounts: []ownerbpf.MountEntry{{
			MountID: 29, ParentID: 1, Major: 8, Minor: 1,
			Root: "/", MountPoint: "/", FSType: "ext4", MountSource: "/dev/sda1",
		}},
	}
	snap, reason := rt.EnrichActor(key, ev, mat)
	if reason != ownerbpf.ReasonValidated || snap == nil {
		t.Fatalf("EnrichActor(%s) failed: snap=%+v reason=%s", exePath, snap, reason)
	}
	return ownerbpf.ActorIdentityKey{TGID: tgid, StartBoottime: start, ExecID: 1}
}

func buildIPv4TCPPacket(src, dst netip.AddrPort, seq, ack uint32, flags header.TCPFlags, options, payload []byte) []byte {
	optLen := (len(options) + 3) &^ 3
	tcpLen := header.TCPMinimumSize + optLen + len(payload)
	raw := make([]byte, header.IPv4MinimumSize+tcpLen)
	ip := header.IPv4(raw)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(raw)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.Addr().As4()),
		DstAddr:     tcpip.AddrFrom4(dst.Addr().As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcp := header.TCP(raw[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    src.Port(),
		DstPort:    dst.Port(),
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: uint8(header.TCPMinimumSize + optLen),
		Flags:      flags,
		WindowSize: 65535,
	})
	copy(tcp[header.TCPMinimumSize:], options)
	copy(tcp[header.TCPMinimumSize+optLen:], payload)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(tcpLen))
	xsum = checksum.Checksum(payload, xsum)
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	return raw
}

func TestEngineProvenanceStartupAndShutdownOrder(t *testing.T) {
	var mu sync.Mutex
	var order []string
	record := func(step string) {
		mu.Lock()
		order = append(order, step)
		mu.Unlock()
	}

	tun := newProvTun(record)
	routes := &provRoutes{events: record}
	owners := &provTestOwners{
		rt:     ownerbpf.NewProvenanceRuntime(1, ownerbpf.NewIdentityLedger(32, 16<<10), ownerbpf.NewSocketSlotTable(32)),
		events: record,
	}
	e := New(context.Background(), Dependencies{
		OpenTun: func(context.Context) (platform.TunDevice, error) {
			record("open-tun")
			return tun, nil
		},
		Routes: routes,
		Dialer: testfake.Dialer{},
		Owners: owners,
	}, flows.Defaults(), nil)

	cfg := policy.Config{Lines: []platform.Line{{ID: "main"}}}
	rev := policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}
	if _, err := e.Start(context.Background(), rev); err != nil {
		t.Fatalf("Engine.Start: %v", err)
	}
	if err := e.Stop(context.Background()); err != nil {
		t.Fatalf("Engine.Stop: %v", err)
	}

	mu.Lock()
	got := slices.Clone(order)
	mu.Unlock()

	indexOf := func(step string) int {
		i := slices.Index(got, step)
		if i < 0 {
			t.Fatalf("missing lifecycle step %q in %v", step, got)
		}
		return i
	}
	if !(indexOf("open-tun") < indexOf("prepare") &&
		indexOf("prepare") < indexOf("attach-provenance") &&
		indexOf("attach-provenance") < indexOf("bind-pump") &&
		indexOf("bind-pump") < indexOf("enable-provenance") &&
		indexOf("enable-provenance") < indexOf("capture")) {
		t.Fatalf("startup ordering violated: %v", got)
	}
	if !(indexOf("capture") < indexOf("quiesce") &&
		indexOf("quiesce") < indexOf("stop-provenance") &&
		indexOf("stop-provenance") < indexOf("unbind-pump") &&
		indexOf("unbind-pump") < indexOf("close-provenance") &&
		indexOf("close-provenance") < indexOf("cleanup")) {
		t.Fatalf("shutdown ordering violated: %v", got)
	}
}

func TestEngineTCPProvenanceClonedSYNAndFastOpen(t *testing.T) {
	rt := ownerbpf.NewProvenanceRuntime(3, ownerbpf.NewIdentityLedger(64, 64<<10), ownerbpf.NewSocketSlotTable(64))
	actorA := enrichTestSocketActor(t, rt, 0x101, 5101, 100_000_000, "/usr/bin/AppAlpha")
	actorB := enrichTestSocketActor(t, rt, 0x102, 5102, 200_000_000, "/usr/bin/AppBeta")

	// Cookie 0x103: first accepted contributor is AppAlpha, then AppBeta conflicts it.
	_ = enrichTestSocketActor(t, rt, 0x103, 5101, 100_000_000, "/usr/bin/AppAlpha")
	_ = enrichTestSocketActor(t, rt, 0x103, 5102, 200_000_000, "/usr/bin/AppBeta")

	// Cookie 0x104: single-sender unretained cold process (unknown identity, NOT conflicting).
	rt.ObserveColdUnretained(
		ownerbpf.ActorKey{Cookie: 0x104, TGID: 5104, Start: 400_000_000, Exec: 1},
		ownerbpf.ActorEvidence{Inode: 777, Device: ownerbpf.EncodeKernelDev(8, 1), ObservedNS: 4026531992, ABI: ownerbpf.ABI},
	)

	tun := newProvTun(nil)
	owners := &provTestOwners{rt: rt}

	type dialedConn struct {
		line string
		dst  netip.AddrPort
		peer *testfake.Conn
	}
	dialed := make(chan dialedConn, 8)
	dialer := testfake.Dialer{
		TCPFunc: func(_ context.Context, line string, dst netip.AddrPort) (platform.TCPConn, error) {
			engineEnd, remoteEnd := testfake.Pair()
			dialed <- dialedConn{line: line, dst: dst, peer: remoteEnd}
			return engineEnd, nil
		},
	}

	e := New(context.Background(), Dependencies{
		OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil },
		Routes:  &testfake.Routes{},
		Dialer:  dialer,
		Owners:  owners,
	}, flows.Defaults(), nil)
	defer e.Stop(context.Background())

	cfg := policy.Config{
		Lines: []platform.Line{{ID: "main"}, {ID: "alt-a"}, {ID: "alt-b"}},
		AppLines: map[string]string{
			"/usr/bin/AppAlpha": "alt-a",
			"/usr/bin/AppBeta":  "alt-b",
		},
		Combine: true,
		Shares:  map[string]uint64{"alt-a": 1, "alt-b": 1},
	}
	if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}); err != nil {
		t.Fatalf("Engine.Start: %v", err)
	}

	waitSYNACK := func(srcPort uint16) header.TCP {
		t.Helper()
		deadline := time.After(3 * time.Second)
		for {
			select {
			case raw := <-tun.out:
				if len(raw) < 40 || raw[0]>>4 != 4 || raw[9] != 6 {
					continue
				}
				ihl := int(raw[0]&0x0f) * 4
				tcp := header.TCP(raw[ihl:])
				if tcp.DestinationPort() == srcPort && tcp.Flags().Contains(header.TCPFlagSyn|header.TCPFlagAck) {
					return tcp
				}
			case <-deadline:
				t.Fatalf("timed out waiting for SYN-ACK to port %d", srcPort)
			}
		}
	}

	// 1. Bare SYN for AppAlpha -> cloned inside gVisor newIncomingSegment, reaches TCPWithProvenance with identical *ProvenanceEnvelope pointer.
	src1 := netip.MustParseAddrPort("198.18.0.10:41001")
	dst := netip.MustParseAddrPort("203.0.113.10:443")
	env1 := rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 3, Cookie: 0x101, Serial: 1}})
	tun.in <- provFrame{raw: buildIPv4TCPPacket(src1, dst, 1000, 0, header.TCPFlagSyn, nil, nil), prov: env1}

	var d1 dialedConn
	select {
	case d1 = <-dialed:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for AppAlpha TCP dial")
	}
	defer d1.peer.Close()
	if d1.line != "alt-a" {
		t.Fatalf("AppAlpha routed to %q, want alt-a", d1.line)
	}
	synAck1 := waitSYNACK(src1.Port())
	tun.in <- provFrame{raw: buildIPv4TCPPacket(src1, dst, 1001, synAck1.SequenceNumber()+1, header.TCPFlagAck, nil, nil), prov: nil}
	tun.in <- provFrame{raw: buildIPv4TCPPacket(src1, dst, 1001, synAck1.SequenceNumber()+1, header.TCPFlagAck|header.TCPFlagPsh, nil, []byte("ping-alpha")), prov: nil}
	buf := make([]byte, 32)
	_ = d1.peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(d1.peer, buf[:10])
	if err != nil || string(buf[:n]) != "ping-alpha" {
		t.Fatalf("AppAlpha established payload = %q, err=%v", buf[:n], err)
	}

	// 2. TCP Fast Open SYN+payload for AppBeta -> exact *ProvenanceEnvelope reaches TCPWithProvenance, routes to alt-b, delivers payload.
	src2 := netip.MustParseAddrPort("198.18.0.10:41002")
	env2 := rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 3, Cookie: 0x102, Serial: 2}})
	tfoOpt := []byte{34, 10, 1, 2, 3, 4, 5, 6, 7, 8, 1, 1}
	tfoPayload := []byte("fast-open-beta")
	tun.in <- provFrame{raw: buildIPv4TCPPacket(src2, dst, 5000, 0, header.TCPFlagSyn, tfoOpt, tfoPayload), prov: env2}

	var d2 dialedConn
	select {
	case d2 = <-dialed:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for AppBeta Fast Open TCP dial")
	}
	defer d2.peer.Close()
	if d2.line != "alt-b" {
		t.Fatalf("AppBeta Fast Open routed to %q, want alt-b", d2.line)
	}
	synAck2 := waitSYNACK(src2.Port())
	ack2Seq := uint32(5001)
	if synAck2.AckNumber() == 5001+uint32(len(tfoPayload)) {
		ack2Seq = synAck2.AckNumber()
		tun.in <- provFrame{raw: buildIPv4TCPPacket(src2, dst, ack2Seq, synAck2.SequenceNumber()+1, header.TCPFlagAck, nil, nil), prov: nil}
	} else {
		tun.in <- provFrame{raw: buildIPv4TCPPacket(src2, dst, 5001, synAck2.SequenceNumber()+1, header.TCPFlagAck|header.TCPFlagPsh, nil, tfoPayload), prov: nil}
	}
	if _, err := io.ReadFull(d2.peer, buf[:len(tfoPayload)]); err != nil || string(buf[:len(tfoPayload)]) != string(tfoPayload) {
		t.Fatalf("AppBeta Fast Open payload = %q, err=%v", buf[:len(tfoPayload)], err)
	}

	// 3. Conflicting socket (cookie 0x103) -> Ambiguous=true -> routes to main even while combining alt-a/alt-b.
	src3 := netip.MustParseAddrPort("198.18.0.10:41003")
	env3 := rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 3, Cookie: 0x103, Serial: 3}})
	tun.in <- provFrame{raw: buildIPv4TCPPacket(src3, dst, 7000, 0, header.TCPFlagSyn, nil, nil), prov: env3}
	var d3 dialedConn
	select {
	case d3 = <-dialed:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for conflicting socket TCP dial")
	}
	defer d3.peer.Close()
	if d3.line != "main" {
		t.Fatalf("conflicting socket routed to %q, want main", d3.line)
	}

	// 4. Single-sender unretained cold socket (cookie 0x104) -> Ambiguous=false -> uses combined share (alt-a or alt-b, NEVER main).
	src4 := netip.MustParseAddrPort("198.18.0.10:41004")
	env4 := rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 3, Cookie: 0x104, Serial: 4}})
	tun.in <- provFrame{raw: buildIPv4TCPPacket(src4, dst, 9000, 0, header.TCPFlagSyn, nil, nil), prov: env4}
	var d4 dialedConn
	select {
	case d4 = <-dialed:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for unretained single-sender TCP dial")
	}
	defer d4.peer.Close()
	if d4.line != "alt-a" && d4.line != "alt-b" {
		t.Fatalf("single-sender unknown socket while combining routed to %q, want alt-a or alt-b", d4.line)
	}

	owners.mu.Lock()
	if len(owners.tcpSeen) != 4 || owners.tcpSeen[0].prov != env1 || owners.tcpSeen[1].prov != env2 || owners.tcpSeen[2].prov != env3 || owners.tcpSeen[3].prov != env4 {
		t.Fatalf("ForwarderRequest.NetSwitchProvenance did not preserve exact envelope pointers: %+v", owners.tcpSeen)
	}
	owners.mu.Unlock()
	if owners.scannerCalls.Load() != 0 {
		t.Fatalf("scanner fallback invoked %d times", owners.scannerCalls.Load())
	}

	rt.ReleaseActor(actorA)
	rt.ReleaseActor(actorB)
}

type testUDPConn struct {
	local  netip.AddrPort
	line   string
	sent   chan testUDPSend
	gate   <-chan struct{}
	closed atomic.Bool
}

type testUDPSend struct {
	line    string
	dst     netip.AddrPort
	payload string
}

func (c *testUDPConn) WaitReadable(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (c *testUDPConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, net.ErrClosed
}

func (c *testUDPConn) WriteTo(b []byte, dst netip.AddrPort, _ bool) (int, error) {
	if c.gate != nil {
		<-c.gate
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.sent <- testUDPSend{line: c.line, dst: dst, payload: string(b)}
	return len(b), nil
}

func (c *testUDPConn) LocalAddr() netip.AddrPort { return c.local }
func (c *testUDPConn) Close() error              { c.closed.Store(true); return nil }

type testReadyWatch struct {
	c *testReadyUDPConn
}

func (w *testReadyWatch) Arm(_, write bool) error {
	w.c.mu.Lock()
	blocked := w.c.blockWrites
	wake := w.c.wake
	w.c.mu.Unlock()
	if write && !blocked && wake != nil {
		wake()
	}
	return nil
}

func (w *testReadyWatch) Detach() {}

type testReadyUDPConn struct {
	testUDPConn
	mu          sync.Mutex
	blockWrites bool
	wake        func()
}

func (c *testReadyUDPConn) Watch(wake func()) (platform.Readiness, error) {
	c.mu.Lock()
	c.wake = wake
	c.mu.Unlock()
	return &testReadyWatch{c: c}, nil
}

func (c *testReadyUDPConn) TryReadFrom([]byte) (int, netip.AddrPort, error) {
	if c.closed.Load() {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	return 0, netip.AddrPort{}, platform.ErrWouldBlock
}

func (c *testReadyUDPConn) TryWriteTo(b []byte, dst netip.AddrPort, _ bool) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	blocked := c.blockWrites
	c.mu.Unlock()
	if blocked {
		return 0, platform.ErrWouldBlock
	}
	c.sent <- testUDPSend{line: c.line, dst: dst, payload: string(b)}
	return len(b), nil
}

func (c *testReadyUDPConn) setBlocked(blocked bool) {
	c.mu.Lock()
	c.blockWrites = blocked
	wake := c.wake
	c.mu.Unlock()
	if !blocked && wake != nil {
		wake()
	}
}

func TestEngineProvenanceFragmentReassembly(t *testing.T) {
	rt := ownerbpf.NewProvenanceRuntime(5, ownerbpf.NewIdentityLedger(64, 64<<10), ownerbpf.NewSocketSlotTable(64))
	_ = enrichTestSocketActor(t, rt, 0x201, 6101, 100_000_000, "/usr/bin/AppAlpha")
	_ = enrichTestSocketActor(t, rt, 0x202, 6102, 200_000_000, "/usr/bin/AppBeta")
	_ = enrichTestSocketActor(t, rt, 0x203, 6102, 200_000_000, "/usr/bin/AppBeta")

	tun := newProvTun(nil)
	owners := &provTestOwners{rt: rt}
	sent := make(chan testUDPSend, 16)
	var opened atomic.Uint64
	dialer := testfake.Dialer{
		UDPFunc: func(_ context.Context, line string, v6 bool) (platform.UDPConn, error) {
			port := uint16(50000 + opened.Add(1))
			local := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), port)
			if v6 {
				local = netip.AddrPortFrom(netip.MustParseAddr("2001:db8::10"), port)
			}
			return &testUDPConn{local: local, line: line, sent: sent}, nil
		},
	}

	e := New(context.Background(), Dependencies{
		OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil },
		Routes:  &testfake.Routes{},
		Dialer:  dialer,
		Owners:  owners,
	}, flows.Defaults(), nil)
	defer e.Stop(context.Background())

	cfg := policy.Config{
		Lines: []platform.Line{{ID: "main"}, {ID: "alt-a"}, {ID: "alt-b"}},
		AppLines: map[string]string{
			"/usr/bin/AppAlpha": "alt-a",
			"/usr/bin/AppBeta":  "alt-b",
		},
		IPv6: true,
	}
	if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}); err != nil {
		t.Fatalf("Engine.Start: %v", err)
	}

	fragV4 := func(raw []byte, ipID uint16, from, to, flags int) []byte {
		b := append(append([]byte(nil), raw[:20]...), raw[20+from:20+to]...)
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		binary.BigEndian.PutUint16(b[4:], ipID)
		binary.BigEndian.PutUint16(b[6:], uint16(flags))
		b[10], b[11] = 0, 0
		binary.BigEndian.PutUint16(b[10:], ^packet.Sum(b[:20], 0))
		return b
	}

	// 1. Out-of-order IPv4 UDP fragments for AppBeta (cookie 0x202) preserve known identity across distinct CaptureSerials.
	raw4 := packet.UDP(netip.MustParseAddrPort("198.18.0.20:42001"), netip.MustParseAddrPort("203.0.113.20:5353"), []byte("0123456789abcdef"))
	tun.in <- provFrame{
		raw:  fragV4(raw4, 0x1111, 16, 24, 2),
		prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 5, Cookie: 0x202, Serial: 201}}),
	}
	tun.in <- provFrame{
		raw:  fragV4(raw4, 0x1111, 0, 16, 0x2000),
		prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 5, Cookie: 0x202, Serial: 202}}),
	}
	select {
	case got := <-sent:
		if got.line != "alt-b" || got.payload != "0123456789abcdef" {
			t.Fatalf("reassembled IPv4 UDP = %+v, want line=alt-b payload=0123456789abcdef", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for reassembled IPv4 UDP datagram")
	}

	// 2. Out-of-order IPv6 UDP fragments for AppBeta (cookie 0x203) preserve known identity.
	raw6 := packet.UDP(netip.MustParseAddrPort("[fdfe:dcba:9876::2]:42002"), netip.MustParseAddrPort("[2001:db8::20]:5353"), []byte("fedcba9876543210"))
	fragV6 := func(from, to int, more bool) []byte {
		b := make([]byte, 48+to-from)
		copy(b, raw6[:40])
		b[6] = 44
		binary.BigEndian.PutUint16(b[4:], uint16(len(b)-40))
		b[40] = 17
		flags := uint16(from)
		if more {
			flags |= 1
		}
		binary.BigEndian.PutUint16(b[42:], flags)
		binary.BigEndian.PutUint32(b[44:], 0x2222)
		copy(b[48:], raw6[40+from:40+to])
		return b
	}
	tun.in <- provFrame{
		raw:  fragV6(16, 24, false),
		prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 5, Cookie: 0x203, Serial: 203}}),
	}
	tun.in <- provFrame{
		raw:  fragV6(0, 16, true),
		prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 5, Cookie: 0x203, Serial: 204}}),
	}
	select {
	case got := <-sent:
		if got.line != "alt-b" || got.payload != "fedcba9876543210" {
			t.Fatalf("reassembled IPv6 UDP = %+v, want line=alt-b payload=fedcba9876543210", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for reassembled IPv6 UDP datagram")
	}

	// 3. Mixed-cookie fragments (0x201 + 0x202) and missing-peer fragments (0x202 + nil) degrade to EnvelopeMissingCookie and refuse admission.
	rawMixed := packet.UDP(netip.MustParseAddrPort("198.18.0.20:42003"), netip.MustParseAddrPort("203.0.113.20:5353"), []byte("mixed-cookie-bad"))
	tun.in <- provFrame{
		raw:  fragV4(rawMixed, 0x3333, 0, 16, 0x2000),
		prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 5, Cookie: 0x201, Serial: 205}}),
	}
	tun.in <- provFrame{
		raw:  fragV4(rawMixed, 0x3333, 16, 24, 2),
		prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 5, Cookie: 0x202, Serial: 206}}),
	}

	rawMissing := packet.UDP(netip.MustParseAddrPort("198.18.0.20:42004"), netip.MustParseAddrPort("203.0.113.20:5353"), []byte("missing-frag-bad"))
	tun.in <- provFrame{
		raw:  fragV4(rawMissing, 0x4444, 0, 16, 0x2000),
		prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 5, Cookie: 0x202, Serial: 207}}),
	}
	tun.in <- provFrame{
		raw:  fragV4(rawMissing, 0x4444, 16, 24, 2),
		prov: nil,
	}

	deadline := time.Now().Add(3 * time.Second)
	for e.udp.GenerationMissing.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("udpGenerationMissing = %d, want 2", e.udp.GenerationMissing.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case extra := <-sent:
		t.Fatalf("mixed/missing fragment unexpectedly forwarded: %+v", extra)
	default:
	}
	if opened.Load() != 2 {
		t.Fatalf("opened %d UDP sockets, want 2 (mixed/missing fragments must not open sessions)", opened.Load())
	}
	if owners.scannerCalls.Load() != 0 {
		t.Fatalf("scanner fallback invoked %d times", owners.scannerCalls.Load())
	}
}

func TestEngineUDPProvenanceOrdinaryAndReadyLinearization(t *testing.T) {
	for _, readyMode := range []bool{false, true} {
		name := "ordinary-udp"
		if readyMode {
			name = "ready-udp"
		}
		t.Run(name, func(t *testing.T) {
			rt := ownerbpf.NewProvenanceRuntime(9, ownerbpf.NewIdentityLedger(64, 64<<10), ownerbpf.NewSocketSlotTable(64))
			_ = enrichTestSocketActor(t, rt, 0x301, 7102, 200_000_000, "/usr/bin/AppBeta")

			tun := newProvTun(nil)
			owners := &provTestOwners{rt: rt}
			sent := make(chan testUDPSend, 128)

			var mu sync.Mutex
			var openedLines []string
			var firstReady *testReadyUDPConn
			ordinaryGate := make(chan struct{})
			closeGateOnce := sync.OnceFunc(func() { close(ordinaryGate) })
			defer closeGateOnce()
			var gateSecondWrite atomic.Bool

			dialer := testfake.Dialer{
				UDPFunc: func(_ context.Context, line string, _ bool) (platform.UDPConn, error) {
					mu.Lock()
					idx := len(openedLines) + 1
					openedLines = append(openedLines, line)
					mu.Unlock()
					local := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.50"), uint16(52000+idx))
					if readyMode {
						rc := &testReadyUDPConn{
							testUDPConn: testUDPConn{local: local, line: line, sent: sent},
						}
						if idx == 1 {
							firstReady = rc
						}
						return rc, nil
					}
					c := &testUDPConn{local: local, line: line, sent: sent}
					if idx == 1 {
						return &gatedSecondWriteUDPConn{testUDPConn: c, gateSecond: &gateSecondWrite, gate: ordinaryGate}, nil
					}
					return c, nil
				},
			}

			e := New(context.Background(), Dependencies{
				OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil },
				Routes:  &testfake.Routes{},
				Dialer:  dialer,
				Owners:  owners,
			}, flows.Defaults(), nil)
			defer e.Stop(context.Background())

			cfg := policy.Config{
				Lines: []platform.Line{{ID: "main"}, {ID: "alt-a"}, {ID: "alt-b"}},
				AppLines: map[string]string{
					"/usr/bin/AppAlpha": "alt-a",
					"/usr/bin/AppBeta":  "alt-b",
				},
				Combine: true,
				Shares:  map[string]uint64{"alt-a": 1, "alt-b": 1},
			}
			if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}); err != nil {
				t.Fatalf("Engine.Start: %v", err)
			}

			src := netip.MustParseAddrPort("198.18.0.30:43001")
			dst0 := netip.MustParseAddrPort("203.0.113.1:9000")

			// 1. First datagram opens session on alt-b under AppBeta.
			tun.in <- provFrame{
				raw:  packet.UDP(src, dst0, []byte("dgram-1")),
				prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 9, Cookie: 0x301, Serial: 1}}),
			}
			select {
			case got := <-sent:
				if got.line != "alt-b" || got.payload != "dgram-1" {
					t.Fatalf("first UDP send = %+v, want alt-b/dgram-1", got)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for first UDP datagram")
			}

			// 2. Block writes so queued datagram 2 sits before send linearization, then conflict cookie 0x301 with AppAlpha!
			if readyMode {
				firstReady.setBlocked(true)
				// Queue one blocked datagram (parks in r.pending on ErrWouldBlock) + a second queued datagram in s.queue.
				tun.in <- provFrame{
					raw:  packet.UDP(src, dst0, []byte("dgram-park")),
					prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 9, Cookie: 0x301, Serial: 2}}),
				}
				tun.in <- provFrame{
					raw:  packet.UDP(src, dst0, []byte("dgram-queued-before-conflict")),
					prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 9, Cookie: 0x301, Serial: 3}}),
				}
				time.Sleep(30 * time.Millisecond)
				_ = enrichTestSocketActor(t, rt, 0x301, 7101, 100_000_000, "/usr/bin/AppAlpha")
				firstReady.setBlocked(false)
			} else {
				gateSecondWrite.Store(true)
				tun.in <- provFrame{
					raw:  packet.UDP(src, dst0, []byte("dgram-inflight")),
					prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 9, Cookie: 0x301, Serial: 2}}),
				}
				tun.in <- provFrame{
					raw:  packet.UDP(src, dst0, []byte("dgram-queued-before-conflict")),
					prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 9, Cookie: 0x301, Serial: 3}}),
				}
				time.Sleep(30 * time.Millisecond)
				_ = enrichTestSocketActor(t, rt, 0x301, 7101, 100_000_000, "/usr/bin/AppAlpha")
				closeGateOnce()
			}

			// Wait until the invalidated alt-b session closes and drops the pre-conflict queued datagram.
			deadline := time.Now().Add(3 * time.Second)
			for e.udp.Dropped.Load() == 0 {
				if time.Now().After(deadline) {
					t.Fatal("queued pre-conflict datagram was not dropped at send linearization")
				}
				time.Sleep(10 * time.Millisecond)
			}
			// Drain at most the already-linearized in-flight datagram in ordinary mode; dgram-queued-before-conflict must NEVER be sent on alt-b!
			for len(sent) > 0 {
				got := <-sent
				if got.payload == "dgram-queued-before-conflict" {
					t.Fatalf("queued datagram sent under stale AppBeta owner after conflict: %+v", got)
				}
			}

			// 3. Subsequent traffic on conflicting cookie 0x301 across 50 distinct destinations opens 1 main session and preserves one public socket.
			for i := 1; i <= 50; i++ {
				dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), uint16(9000+i))
				tun.in <- provFrame{
					raw:  packet.UDP(src, dst, []byte(fmt.Sprintf("dest-%d", i))),
					prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 9, Cookie: 0x301, Serial: uint64(10 + i)}}),
				}
			}
			for i := 1; i <= 50; i++ {
				select {
				case got := <-sent:
					if got.line != "main" {
						t.Fatalf("conflicting 50-dest datagram %d routed to %q, want main", i, got.line)
					}
				case <-time.After(3 * time.Second):
					t.Fatalf("timed out waiting for conflicting destination %d/50", i)
				}
			}

			mu.Lock()
			linesAfter50 := slices.Clone(openedLines)
			mu.Unlock()
			if !slices.Equal(linesAfter50, []string{"alt-b", "main"}) {
				t.Fatalf("opened UDP sockets = %v, want exactly [alt-b main] (one public endpoint across 50 destinations)", linesAfter50)
			}

			// 4. A single missing-cookie datagram drops only that datagram without closing the established main session.
			droppedBefore := e.udp.Dropped.Load()
			tun.in <- provFrame{
				raw:  packet.UDP(src, netip.MustParseAddrPort("203.0.113.99:9099"), []byte("missing-cookie-drop")),
				prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadMissing}),
			}
			deadline = time.Now().Add(3 * time.Second)
			for e.udp.Dropped.Load() <= droppedBefore {
				if time.Now().After(deadline) {
					t.Fatal("missing-cookie datagram was not dropped")
				}
				time.Sleep(10 * time.Millisecond)
			}

			dst51 := netip.MustParseAddrPort("203.0.113.51:9051")
			tun.in <- provFrame{
				raw:  packet.UDP(src, dst51, []byte("dest-51-still-same-socket")),
				prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 9, Cookie: 0x301, Serial: 99}}),
			}
			select {
			case got := <-sent:
				if got.line != "main" || got.payload != "dest-51-still-same-socket" {
					t.Fatalf("post-drop UDP datagram = %+v, want main/dest-51-still-same-socket", got)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("established UDP session died after single missing-cookie drop")
			}

			mu.Lock()
			finalOpened := slices.Clone(openedLines)
			mu.Unlock()
			if !slices.Equal(finalOpened, []string{"alt-b", "main"}) {
				t.Fatalf("UDP socket recreated after missing-cookie drop: %v", finalOpened)
			}
		})
	}
}

type gatedSecondWriteUDPConn struct {
	*testUDPConn
	writes     atomic.Uint64
	gateSecond *atomic.Bool
	gate       <-chan struct{}
}

func (g *gatedSecondWriteUDPConn) WriteTo(b []byte, dst netip.AddrPort, df bool) (int, error) {
	if g.writes.Add(1) == 2 && g.gateSecond.Load() {
		<-g.gate
	}
	return g.testUDPConn.WriteTo(b, dst, df)
}

func TestEngineProvenancePoolResetAndHeapRetirement(t *testing.T) {
	ledger := ownerbpf.NewIdentityLedger(32, 32<<10)
	slots := ownerbpf.NewSocketSlotTable(32)
	rt := ownerbpf.NewProvenanceRuntime(11, ledger, slots)
	actor := enrichTestSocketActor(t, rt, 0x401, 8101, 300_000_000, "/opt/Suite/2.0.0/Worker")

	func() {
		tun := newProvTun(nil)
		owners := &provTestOwners{rt: rt}
		dialer := testfake.Dialer{
			UDPFunc: func(_ context.Context, line string, _ bool) (platform.UDPConn, error) {
				return &testUDPConn{
					local: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.99"), 55000),
					line:  line,
					sent:  make(chan testUDPSend, 8),
				}, nil
			},
		}
		e := New(context.Background(), Dependencies{
			OpenTun: func(context.Context) (platform.TunDevice, error) { return tun, nil },
			Routes:  &testfake.Routes{},
			Dialer:  dialer,
			Owners:  owners,
		}, flows.Defaults(), nil)
		cfg := policy.Config{Lines: []platform.Line{{ID: "main"}}}
		if _, err := e.Start(context.Background(), policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}); err != nil {
			t.Fatalf("Engine.Start: %v", err)
		}
		for i := range 8 {
			raw := packet.UDP(netip.MustParseAddrPort("198.18.0.40:44001"), netip.MustParseAddrPort("203.0.113.40:9000"), []byte("pool-check"))
			tun.in <- provFrame{
				raw:  raw,
				prov: rt.Acquire(ownerbpf.ReadDecision{Status: ownerbpf.ReadCookie, Packet: ownerbpf.PacketRecord{Epoch: 11, Cookie: 0x401, Serial: uint64(i + 1)}}),
			}
		}
		time.Sleep(40 * time.Millisecond)
		if err := e.Stop(context.Background()); err != nil {
			t.Fatalf("Engine.Stop: %v", err)
		}
		owners.mu.Lock()
		clear(owners.udpSeen)
		owners.udpSeen = nil
		owners.mu.Unlock()
	}()

	// Verify fresh PacketBuffer allocations from gVisor's pool never retain stale NetSwitchProvenance.
	for range 32 {
		pk := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{1, 2, 3, 4})})
		if pk.NetSwitchProvenance != nil {
			pk.DecRef()
			t.Fatalf("pooled PacketBuffer retained stale NetSwitchProvenance: %#v", pk.NetSwitchProvenance)
		}
		pk.DecRef()
	}

	rt.ReleaseSocket(0x401)
	rt.ReleaseActor(actor)

	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		runtime.GC()
		lm, sm, _ := rt.Metrics()
		if lm.ActiveSnapshots == 0 && lm.UsedBlobBytes == 0 && sm.ActiveSlots == 0 && sm.RetainedSlots == 0 {
			break
		}
		if time.Now().After(deadline) {
			lm, sm, _ := rt.Metrics()
			t.Fatalf("provenance heap pins leaked after Engine.Stop + GC: ledger=%+v slots=%+v", lm, sm)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
