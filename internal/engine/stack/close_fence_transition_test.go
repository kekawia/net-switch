package stack_test

import (
	"sync"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	ns "github.com/AyoubAchour/net-switch/internal/engine/stack"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gv "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Reproduce the state seen when a processor consumes a closing ACK before
// queuePacket reads the endpoint state for its after-ingress fence. Hold real
// cleanup after accounting is released but before CLOSED is published, then
// deliver another ACK through the normal enabled ingress path. This deliberately
// controls the state at classification, rather than depending on which goroutine
// wins the enqueue/classification race.
func TestCloseFenceDuringTimeWaitCleanup(t *testing.T) {
	limits := flows.Defaults()
	limits.Flows, limits.PerApp, limits.TimeWait = 1, 1, 1
	p := newPeerOptions(t, false, limits, ns.DefaultOptions())
	p.trace = &closeTrace{}
	p.open(1000)
	p.upload([]byte("retained"))
	p.prepareFinalACK(true)
	first := p.endpoint()
	p.port++
	p.open(2000)
	p.upload([]byte("overflow"))
	ack := p.prepareFinalACK(true)
	ep := p.endpoint()
	if g := p.table.Stats(); g.TimeWait != 1 || g.ClosingOverflow != 1 || g.Flows != 0 {
		t.Fatal("fixture must retain one endpoint and overflow the other", g)
	}
	p.trace.mu.Lock()
	ticket := p.trace.tickets[1]
	p.trace.mu.Unlock()
	entered, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	// Same ticket and bookkeeping as the installed production policy. Only the
	// test callback blocks, at the exact intermediate state from the capture.
	ep.SetTimeWaitPolicy(ticket.TimeWait, func() {
		ticket.Retire()
		ticket.EndTimeWait()
		close(entered)
		<-resume
	})
	// Seed in-flight processor work without running an ingress fence. LockUser
	// prevents processing until the complete ACK is queued; UnlockUser supplies
	// the worker wakeup. This is fixture setup, not the operation under test.
	tcp.SetLocalCloseFence(p.stack, false)
	ep.LockUser()
	pkt := gv.NewPacketBuffer(gv.PacketBufferOptions{Payload: buffer.MakeWithData(ack)})
	pkt.NetworkHeader().Consume(header.IPv4MinimumSize)
	pkt.TransportHeader().Consume(header.TCPMinimumSize)
	pkt.NetworkProtocolNumber, pkt.NICID = header.IPv4ProtocolNumber, ns.NIC
	p.stack.TransportProtocolInstance(tcp.ProtocolNumber).(interface {
		QueuePacket(gv.TransportEndpoint, gv.TransportEndpointID, *gv.PacketBuffer)
	}).QueuePacket(ep, ep.TransportEndpointInfo.ID, pkt)
	pkt.DecRef()
	ep.UnlockUser()
	closeSignal(t, entered, "overflow cleanup before CLOSED")
	if state := tcp.EndpointState(ep.State()); state != tcp.StateTimeWait {
		t.Fatal("fixture did not reach transient TIME_WAIT", state)
	}
	if g := p.table.Stats(); g.ClosingOverflow != 0 || g.TimeWait != 1 {
		t.Fatal("fixture did not reach the captured accounting state", g)
	}
	drain := tcp.SetLocalCloseFence(p.stack, true)
	var fenced *tcp.Endpoint
	p.link.SetAfterInbound(func() {
		// Classification has finished while cleanup is still held. Release it
		// before draining: assert the recorded fence, never a timed negative wait.
		release()
		fenced = drain()
	})
	p.inject(ack)
	if fenced != ep {
		t.Fatalf("ACK during TIME_WAIT cleanup lost its close fence: got %p want %p\n%s", fenced, ep, p.trace.dump(p.table.Stats(), first, ep))
	}
	if state := tcp.EndpointState(ep.State()); state != tcp.StateClose {
		t.Fatal("fence returned before overflow cleanup completed", state)
	}
	if g := p.table.Stats(); g.TimeWait != 1 || g.ClosingOverflow != 0 || g.TimeWaitSkipped != 1 || g.Rejected != 0 {
		t.Fatal("cleanup damaged retained/admission accounting", g)
	}
	if p.stack.Stats().TCP.ResetsSent.Value() != 0 {
		t.Fatal("queued final ACK caused a reset")
	}
}
