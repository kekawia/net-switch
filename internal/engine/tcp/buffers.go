package tcp

import (
	"math/bits"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kekawia/net-switch/internal/engine/flowapi"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type connection struct {
	id                       stack.TransportEndpointID
	completed                atomic.Bool
	ready                    atomic.Pointer[readyRelay]
	ep                       tcpip.Endpoint
	ticket                   flowapi.Ticket
	forward                  *Forwarder
	up, down                 atomic.Uint64
	resizeMu                 sync.Mutex
	lastUp, lastDown         uint64
	grownUp, grownDown       uint64
	lastGrowUp, lastGrowDown time.Time
	last                     time.Time
	clock                    tcpip.Clock
	overflowDeadline         atomic.Int64
}

// One clock for all flows. Socket limits disable unaccounted autotuning.
// Only the snapshot uses f.mu; endpoint and table work cannot hold up Handle.
func (f *Forwarder) startMaintenance() {
	// Use the stack's clock for both the deadline and the sweep. A single
	// timer does the work off ingress; a manual clock exercises real expiry.
	var mu sync.Mutex
	var timer tcpip.Timer
	mu.Lock()
	timer = f.stack.Clock().AfterFunc(250*time.Millisecond, func() {
		mu.Lock()
		defer mu.Unlock()
		if f.ctx.Err() != nil {
			return
		}
		f.sweep(f.stack.Clock().Now())
		timer.Reset(250 * time.Millisecond)
	})
	mu.Unlock()
	f.wg.Go(func() {
		<-f.ctx.Done()
		mu.Lock()
		timer.Stop()
		mu.Unlock()
		for _, c := range f.connectionSnapshot() {
			c.ticket.Retire()
			if relay := c.ready.Load(); relay != nil {
				relay.cancel()
			}
			c.ep.Abort()
			f.relays.mu.Lock()
			for !c.completed.Load() {
				f.relays.finished.Wait()
			}
			f.relays.mu.Unlock()
			c.ticket.Close()
			f.removeConnection(c)
		}
	})
}

func (f *Forwarder) connectionSnapshot() []*connection {
	f.mu.RLock()
	defer f.mu.RUnlock()
	items := make([]*connection, 0, len(f.connections)+len(f.retired))
	for _, c := range f.connections {
		items = append(items, c)
	}
	for c := range f.retired {
		items = append(items, c)
	}
	return items
}

func (f *Forwarder) removeConnection(c *connection) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// A snapshot can outlive a same-tuple replacement. Remove only its owner.
	if f.connections[c.id] == c {
		delete(f.connections, c.id)
	}
	delete(f.retired, c)
}

func (f *Forwarder) sweep(now time.Time) {
	for _, c := range f.connectionSnapshot() {
		state := gtcp.EndpointState(c.ep.State())
		if state == gtcp.StateClose || state == gtcp.StateError {
			c.releaseAdmission()
			if c.completed.Load() {
				c.ticket.Close()
				f.removeConnection(c)
			}
			continue
		}
		if state == gtcp.StateLastAck || state == gtcp.StateClosing {
			c.releaseAdmission()
			if deadline := c.overflowDeadline.Load(); deadline != 0 && c.clock.NowMonotonic().Sub(tcpip.MonotonicTime{}) >= time.Duration(deadline) {
				// Recheck state and payload under the endpoint lock. An ACK
				// racing expiry must never reset a cleanly closed endpoint.
				c.ep.(*gtcp.Endpoint).CloseRetained()
			}
		}
		c.resize(now)
	}
}

func (c *connection) resize(now time.Time) {
	c.resizeAt(now, true)
}

const (
	// Short high-speed flows need room above the 64 KiB floor immediately,
	// without allocating multi-megabyte send queues that stay idle in Go's heap.
	earlyBufferCap = 256 << 10
	// Above earlyBufferCap, require sustained demand across three 250 ms ticks
	// (700 ms tolerates minor timer jitter) so full 6 MiB/8 MiB grants still
	// arrive within 3.75 s while short parallel bursts stay within 512 KiB/flow.
	sustainedGrowInterval = 700 * time.Millisecond
)

func (c *connection) countTransfer(up bool, n uint64) {
	var total uint64
	if up {
		total = c.up.Add(n)
		c.ticket.Add(n, 0)
	} else {
		total = c.down.Add(n)
		c.ticket.Add(0, n)
	}
	if total >= MinimumBuffer && total-n < earlyBufferCap && bits.Len64(total) != bits.Len64(total-n) && c.clock != nil {
		c.resizeAt(c.clock.Now(), false)
	}
}

func (c *connection) resizeAt(now time.Time, periodic bool) {
	b, ok := c.ticket.(interface {
		Grow(int, int) bool
		Shrink(int, int)
	})
	if !ok {
		return
	}
	c.resizeMu.Lock()
	defer c.resizeMu.Unlock()
	u, d := c.up.Load(), c.down.Load()
	rx, tx := c.ticket.Buffers()
	if periodic && u == c.lastUp && d == c.lastDown {
		if rx == MinimumBuffer && tx == MinimumBuffer {
			return
		}
		if now.Sub(c.last) >= time.Second {
			c.ep.SocketOptions().SetReceiveBufferSize(MinimumBuffer, true)
			c.ep.SocketOptions().SetSendBufferSize(MinimumBuffer, true)
			// Lower limits first, then retain any allocation still held by
			// queued/out-of-order receive segments or unacknowledged sends.
			if ep, ok := c.ep.(interface{ BufferUsage() (int, int) }); ok {
				rxUsed, txUsed := ep.BufferUsage()
				b.Shrink(min(rx, max(MinimumBuffer, rxUsed)), min(tx, max(MinimumBuffer, txUsed)))
			}
			c.grownUp, c.grownDown = u, d
			c.lastGrowUp, c.lastGrowDown = time.Time{}, time.Time{}
		}
		return
	}
	upDelta, downDelta := u-c.grownUp, d-c.grownDown
	if periodic {
		upDelta, downDelta = u-c.lastUp, d-c.lastDown
	}
	maxRX, maxTX := 8<<20, 6<<20
	if !periodic {
		maxRX, maxTX = earlyBufferCap, earlyBufferCap
	}
	nextRX, nextTX := rx, tx
	canGrowUp := !periodic || rx < earlyBufferCap || c.lastGrowUp.IsZero() || now.Sub(c.lastGrowUp) >= sustainedGrowInterval
	if canGrowUp && rx < maxRX && upDelta >= uint64(rx) {
		nextRX = min(rx*2, maxRX)
	}
	canGrowDown := !periodic || tx < earlyBufferCap || c.lastGrowDown.IsZero() || now.Sub(c.lastGrowDown) >= sustainedGrowInterval
	if canGrowDown && tx < maxTX && downDelta >= uint64(tx) {
		nextTX = min(tx*2, maxTX)
	}
	if periodic {
		if upDelta < uint64(rx) {
			c.grownUp = u
		}
		if downDelta < uint64(tx) {
			c.grownDown = d
		}
		c.lastUp, c.lastDown = u, d
	}
	c.last = now
	if (nextRX != rx || nextTX != tx) && b.Grow(nextRX, nextTX) {
		if nextRX != rx {
			c.grownUp = u
			c.lastGrowUp = now
		}
		if nextTX != tx {
			c.grownDown = d
			c.lastGrowDown = now
		}
		c.ep.SocketOptions().SetReceiveBufferSize(int64(nextRX), true)
		c.ep.SocketOptions().SetSendBufferSize(int64(nextTX), true)
	}
}
