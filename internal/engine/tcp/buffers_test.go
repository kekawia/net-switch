package tcp

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kekawia/net-switch/internal/engine/flows"
	"github.com/kekawia/net-switch/internal/engine/platform"
	"github.com/kekawia/net-switch/internal/engine/policy"
	ns "github.com/kekawia/net-switch/internal/engine/stack"
	"github.com/kekawia/net-switch/internal/engine/testfake"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type heldSweepEndpoint struct {
	tcpip.Endpoint
	once             sync.Once
	entered, release chan struct{}
	visits           atomic.Int32
}

func (e *heldSweepEndpoint) State() uint32 {
	e.once.Do(func() { close(e.entered); <-e.release })
	e.visits.Add(1)
	return uint32(gtcp.StateEstablished)
}

func TestHandleDuring65536FlowSweep(t *testing.T) {
	l := ns.NewLink()
	s, err := ns.New(l, ns.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close(); s.Wait(); l.Close() }()
	control := &testfake.Controller{}
	f := &Forwarder{ctx: context.Background(), stack: s, control: control, out: l, inFlight: 2,
		pending: map[gv.TransportEndpointID]*pendingOpen{}, connections: map[gv.TransportEndpointID]*connection{}}
	// Upstream's zero-cap silent drop completes admission without a dial.
	f.forwarder = gtcp.NewForwarder(s, MinimumBuffer, 0, func(*gtcp.ForwarderRequest) { t.Error("unexpected dial") })
	ep := &heldSweepEndpoint{entered: make(chan struct{}), release: make(chan struct{})}
	for i := range 65536 {
		id := gv.TransportEndpointID{RemotePort: uint16(i)}
		f.connections[id] = &connection{id: id, ep: ep}
	}
	swept := make(chan struct{})
	go func() { f.sweep(time.Now()); close(swept) }()
	<-ep.entered
	defer func() { close(ep.release); <-swept }()
	src := tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
	dst := tcpip.AddrFrom4([4]byte{203, 0, 113, 7})
	raw := make([]byte, 40)
	ip := header.IPv4(raw)
	ip.Encode(&header.IPv4Fields{TotalLength: 40, TTL: 64, Protocol: uint8(gtcp.ProtocolNumber), SrcAddr: src, DstAddr: dst})
	ip.SetChecksum(^ip.CalculateChecksum())
	h := header.TCP(raw[20:])
	h.Encode(&header.TCPFields{SrcPort: 40000, DstPort: 443, SeqNum: 1000, DataOffset: 20, Flags: header.TCPFlagSyn, WindowSize: 65535})
	h.SetChecksum(^checksum.Checksum(h, header.PseudoHeaderChecksum(gtcp.ProtocolNumber, src, dst, uint16(len(h)))))
	pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	defer pkt.DecRef()
	pkt.NetworkHeader().Consume(20)
	pkt.TransportHeader().Consume(20)
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	id := gv.TransportEndpointID{RemoteAddress: src, LocalAddress: dst, RemotePort: 40000, LocalPort: 443}
	handled := make(chan bool, 1)
	go func() { handled <- f.Handle(id, pkt) }()
	select {
	case ok := <-handled:
		if !ok || control.Begun.Load() != 1 || control.Closed.Load() != 1 {
			t.Fatal("Handle did not finish admission")
		}
	case <-time.After(time.Second):
		t.Fatal("Handle stalled behind the sweep")
	}
	t.Cleanup(func() {
		if ep.visits.Load() != 65536 {
			t.Fatal("sweep did not visit all 65,536 flows", ep.visits.Load())
		}
	})
	t.Log("Handle completed admission while the 65,536-flow sweep was held inside endpoint work")
}

func TestEarlyTransferGrowthAndTrickleProtection(t *testing.T) {
	l := ns.NewLink()
	s, err := ns.New(l, ns.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close(); s.Wait(); l.Close() }()

	// Use a real gVisor TCP endpoint and flow ticket so SetSendBufferSize and
	// budget accounting run end-to-end.
	ctrl := flows.New(flows.Defaults(), nil)
	cfg := policy.Config{Lines: []platform.Line{{ID: "A"}}}
	if _, err := ctrl.Apply(policy.Revision{N: 1, Hash: policy.Hash(cfg), Config: cfg}); err != nil {
		t.Fatal(err)
	}
	ticket, err := ctrl.Begin("tcp", platform.Tuple{
		Source:      netip.MustParseAddrPort("198.18.0.2:40000"),
		Destination: netip.MustParseAddrPort("203.0.113.7:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ticket.Close()
	if _, err := ticket.Resolve(platform.Owner{AppID: "test.exe"}); err != nil {
		t.Fatal(err)
	}

	ep, terr := s.NewEndpoint(gtcp.ProtocolNumber, header.IPv4ProtocolNumber, new(waiter.Queue))
	if terr != nil {
		t.Fatal(terr)
	}
	defer ep.Close()
	ep.SocketOptions().SetReceiveBufferSize(MinimumBuffer, true)
	ep.SocketOptions().SetSendBufferSize(MinimumBuffer, true)

	c := &connection{ep: ep, ticket: ticket, clock: s.Clock(), last: s.Clock().Now()}

	// A burst grows immediately up to earlyBufferCap (256 KiB) on power-of-two
	// crossings without waiting for the 250 ms sweep, and stops there so short
	// transfers do not reserve multi-megabyte queues.
	c.countTransfer(false, MinimumBuffer)
	_, tx := ticket.Buffers()
	if tx != 2*MinimumBuffer {
		t.Fatalf("send buffer after %d bytes = %d, want %d", MinimumBuffer, tx, 2*MinimumBuffer)
	}
	c.countTransfer(false, 2*MinimumBuffer)
	c.countTransfer(false, 2<<20)
	_, tx = ticket.Buffers()
	if tx != earlyBufferCap {
		t.Fatalf("early growth reached %d, want cap %d", tx, earlyBufferCap)
	}

	// A low-rate trickle spread across periodic ticks must reset grownDown and
	// must not grow past earlyBufferCap.
	now := s.Clock().Now()
	for range 8 {
		now = now.Add(250 * time.Millisecond)
		c.countTransfer(false, 16<<10)
		c.resize(now)
	}
	_, txAfterTrickle := ticket.Buffers()
	if txAfterTrickle != earlyBufferCap {
		t.Fatalf("trickle falsely grew send buffer to %d, want %d", txAfterTrickle, earlyBufferCap)
	}

	// Sustained high throughput grows every three 250 ms ticks and reaches the
	// full 6 MiB send cap within 3.75 s (well inside the 5 s budget test).
	for range 15 {
		now = now.Add(250 * time.Millisecond)
		c.countTransfer(false, 6<<20)
		c.resize(now)
	}
	_, txSustained := ticket.Buffers()
	if txSustained != 6<<20 {
		t.Fatalf("sustained transfer reached %d, want %d", txSustained, 6<<20)
	}
}
