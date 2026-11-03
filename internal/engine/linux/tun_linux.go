//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/linux/ownerbpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

type provenanceBurstSource interface {
	BindReader() (
		readBurst func(fd int, rawBufs [][]byte, sizes []int, decisions []ownerbpf.ReadDecision) (int, error),
		closeReader func() error,
		err error,
	)
}

type queuedProvSegment struct {
	offset int
	length int
	env    *ownerbpf.ProvenanceEnvelope
}

// Tun adapts wireguard-go's ordered GSO splitting to our single-packet seam.
// The dependency is used unmodified, under its MIT license, as the design
// specifies. We create the descriptor ourselves to reserve its exact index
// in the ownership journal before TUNSETIFF.
type Tun struct {
	index              int
	txqlen             int
	netns              uint32
	rawConn            syscall.RawConn
	writeBuffer        [9010]byte
	device             tun.Device
	readMu, writeMu    sync.Mutex
	bufs               [][]byte
	sizes              []int
	next, count, mtu   int
	readErrors         atomic.Uint64
	readBackoffs       atomic.Uint64
	readBackoff        time.Duration
	closedRead         error
	ioDone             <-chan struct{}
	ioStop             func() bool
	beforeContextClose func()
	writeBatch         [][]byte
	writeStorage       []byte

	provSource     provenanceBurstSource
	provOnBurst    func(rawBufs [][]byte, sizes []int, decisions []ownerbpf.ReadDecision, count int, out []*ownerbpf.ProvenanceEnvelope)
	provReadBurst  func(fd int, rawBufs [][]byte, sizes []int, decisions []ownerbpf.ReadDecision) (int, error)
	provRawStorage []byte
	provRawBufs    [][]byte
	provRawSizes   []int
	provDecisions  []ownerbpf.ReadDecision
	provEnvs       []*ownerbpf.ProvenanceEnvelope
	provArena      []byte
	provSpans      []ownerbpf.VirtioSegmentSpan
	provQueue      []queuedProvSegment
	provNext       int
	provPendingErr error
}

const (
	tunWriteBatch     = 64
	tunWriteStride    = 65535 + 10
	tunRawFrameStride = 65535 + ownerbpf.VirtioNetHdrLen
	tunProvArenaBytes = 2560 << 10
)

func suppressTunIPv6Autoconf(name string) error {
	base := "/proc/sys/net/ipv6/conf/" + name + "/"
	for _, knob := range []string{"accept_ra", "autoconf", "dad_transmits", "router_solicitations"} {
		if err := os.WriteFile(base+knob, []byte("0\n"), 0600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("configure %s on engine TUN %s: %w", knob, name, err)
		}
	}
	return nil
}

// avoidLocklessPfifoFast replaces a root pfifo_fast qdisc with locked pfifo
// (limit = dev->tx_queue_len, FIFO wire order). On Linux 5.8–5.12, lockless
// TCQ_F_NOLOCK pfifo_fast can strand the final packet of a concurrent two-CPU
// burst when enqueue races qdisc_run_end (upstream fix in 5.13). Hosts already
// defaulting to fq_codel or built without CONFIG_NET_SCHED are left untouched.
func avoidLocklessPfifoFast(l netlink.Link) error {
	qdiscs, err := netlink.QdiscList(l)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
			return nil
		}
		return fmt.Errorf("list TUN qdiscs: %w", err)
	}
	hasPfifoFast := false
	for _, q := range qdiscs {
		if q.Attrs().Parent == netlink.HANDLE_ROOT && q.Type() == "pfifo_fast" {
			hasPfifoFast = true
			break
		}
	}
	if !hasPfifoFast {
		return nil
	}
	err = netlink.QdiscReplace(&netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: l.Attrs().Index,
			Parent:    netlink.HANDLE_ROOT,
			Handle:    netlink.MakeHandle(1, 0),
		},
		QdiscType: "pfifo",
	})
	if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EOPNOTSUPP) {
		return fmt.Errorf("replace TUN pfifo_fast qdisc with locked pfifo: %w", err)
	}
	return nil
}

func (t *Tun) prepareBatchStorage() {
	if t.writeStorage != nil {
		return
	}
	t.writeStorage = make([]byte, tunWriteBatch*tunWriteStride)
	t.writeBatch = make([][]byte, tunWriteBatch)
}

func openTun(v tunObject) (*Tun, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			unix.Close(fd)
		}
	}()
	if err := unix.IoctlSetPointerInt(fd, unix.TUNSETIFINDEX, v.Index); err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(v.Name)
	if err != nil {
		return nil, err
	}
	// EXCL makes creation atomic: never attach to another process's adapter
	// if a name collision occurs between the journal intent and this ioctl.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_TUN_EXCL)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, err
	}
	device, name, err := tun.CreateUnmonitoredTUNFromFD(fd)
	owned = false // the library now owns fd, including its error paths
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			device.Close()
		}
	}()
	if name != v.Name {
		return nil, errors.New("TUN name changed")
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	if l.Attrs().Index != v.Index {
		return nil, errors.New("TUN index changed")
	}
	if err := netlink.LinkSetAlias(l, v.Alias); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetMTU(l, v.MTU); err != nil {
		return nil, err
	}
	// This is the kernel-to-engine ingress ring, distinct from the engine's
	// 1,024-packet output queue. Hold a full admission burst in wire order.
	if err := netlink.LinkSetTxQLen(l, v.IngressQueue); err != nil {
		return nil, err
	}
	updated, err := netlink.LinkByIndex(v.Index)
	if err != nil {
		return nil, err
	}
	txqlen := updated.Attrs().TxQLen
	if txqlen <= 0 {
		return nil, fmt.Errorf("invalid readback TUN tx_queue_len %d", txqlen)
	}
	if err := avoidLocklessPfifoFast(updated); err != nil {
		return nil, err
	}
	var nsStat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &nsStat); err != nil {
		return nil, err
	}
	if nsStat.Ino == 0 || nsStat.Ino > uint64(^uint32(0)) {
		return nil, fmt.Errorf("invalid network namespace inode %d", nsStat.Ino)
	}
	ft, hasFile := device.(interface{ File() *os.File })
	if !hasFile || ft.File() == nil {
		return nil, errors.New("TUN device lacks underlying file")
	}
	rawConn, err := ft.File().SyscallConn()
	if err != nil {
		return nil, err
	}
	if err := suppressTunIPv6Autoconf(name); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return nil, err
	}
	t := &Tun{
		device:  device,
		index:   v.Index,
		txqlen:  txqlen,
		netns:   uint32(nsStat.Ino),
		rawConn: rawConn,
		mtu:     v.MTU,
		sizes:   make([]int, device.BatchSize()),
		bufs:    make([][]byte, device.BatchSize()),
	}
	for i := range t.bufs {
		t.bufs[i] = make([]byte, 65535)
	}
	t.prepareBatchStorage()
	ok = true
	return t, nil
}
func (t *Tun) MTU() int           { return t.mtu }
func (t *Tun) Ifindex() int       { return t.index }
func (t *Tun) TxQLen() int        { return t.txqlen }
func (t *Tun) NetNSInode() uint32 { return t.netns }

func (t *Tun) DrainNonblock() error {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if t.rawConn == nil {
		return nil
	}
	scratch := t.writeBuffer[:]
	if len(t.bufs) > 0 && len(t.bufs[0]) > len(scratch) {
		scratch = t.bufs[0]
	}
	var drainErr error
	ctlErr := t.rawConn.Control(func(fd uintptr) {
		for {
			_, err := unix.Read(int(fd), scratch)
			if err == nil || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) {
				return
			}
			drainErr = err
			return
		}
	})
	if ctlErr != nil {
		return ctlErr
	}
	return drainErr
}

func (t *Tun) AttachProvenanceReader(
	src provenanceBurstSource,
	onBurst func(rawBufs [][]byte, sizes []int, decisions []ownerbpf.ReadDecision, count int, out []*ownerbpf.ProvenanceEnvelope),
) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	t.provSource = src
	t.provOnBurst = onBurst
	t.provReadBurst = nil
	t.provPendingErr = nil
	t.provNext = 0
	if t.provRawStorage == nil {
		t.provRawStorage = make([]byte, ownerbpf.BurstLimit*tunRawFrameStride)
		t.provRawBufs = make([][]byte, ownerbpf.BurstLimit)
		for i := 0; i < ownerbpf.BurstLimit; i++ {
			off := i * tunRawFrameStride
			t.provRawBufs[i] = t.provRawStorage[off : off+tunRawFrameStride : off+tunRawFrameStride]
		}
		t.provRawSizes = make([]int, ownerbpf.BurstLimit)
		t.provDecisions = make([]ownerbpf.ReadDecision, ownerbpf.BurstLimit)
		t.provEnvs = make([]*ownerbpf.ProvenanceEnvelope, ownerbpf.BurstLimit)
		t.provArena = make([]byte, tunProvArenaBytes)
		t.provSpans = make([]ownerbpf.VirtioSegmentSpan, 0, 256)
		t.provQueue = make([]queuedProvSegment, 0, 256)
	} else {
		clear(t.provEnvs)
		clear(t.provQueue)
		t.provQueue = t.provQueue[:0]
		t.provSpans = t.provSpans[:0]
	}
}

func (t *Tun) DetachProvenanceReader() {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	t.provSource = nil
	t.provOnBurst = nil
	t.provReadBurst = nil
	t.provPendingErr = nil
	t.provNext = 0
	if t.provEnvs != nil {
		clear(t.provEnvs)
	}
	if t.provQueue != nil {
		clear(t.provQueue)
		t.provQueue = t.provQueue[:0]
	}
	if t.provSpans != nil {
		t.provSpans = t.provSpans[:0]
	}
}

func (t *Tun) BindPumpThread() (func(), error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if t.provSource == nil || t.provOnBurst == nil {
		return nil, errors.New("provenance source is not attached")
	}
	readBurst, closeReader, err := t.provSource.BindReader()
	if err != nil {
		return nil, err
	}
	t.provReadBurst = readBurst
	return func() {
		t.readMu.Lock()
		t.provReadBurst = nil
		clear(t.provQueue)
		t.provQueue = t.provQueue[:0]
		t.provNext = 0
		clear(t.provEnvs)
		t.readMu.Unlock()
		_ = closeReader()
	}, nil
}
func (t *Tun) Stats() any {
	l, err := netlink.LinkByIndex(t.index)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	s := l.Attrs().Statistics
	if s == nil {
		return nil
	}
	return map[string]uint64{"ingressPackets": s.TxPackets, "ingressDropped": s.TxDropped, "egressPackets": s.RxPackets, "egressDropped": s.RxDropped, "readDrops": t.readErrors.Load(), "readBackoffs": t.readBackoffs.Load()}
}
func (t *Tun) BindIOContext(ctx context.Context) {
	t.ioDone = ctx.Done()
	if t.ioDone != nil {
		t.ioStop = context.AfterFunc(ctx, t.closeOnCancellation)
	}
}

func (t *Tun) interrupt(ctx context.Context) func() bool {
	if ctx.Done() == nil || ctx.Done() == t.ioDone {
		return nil
	}
	return context.AfterFunc(ctx, t.closeOnCancellation)
}

func (t *Tun) closeOnCancellation() {
	if t.beforeContextClose != nil {
		t.beforeContextClose()
	}
	t.device.Close()
}

func (t *Tun) Close() error {
	if t.ioStop != nil {
		t.ioStop()
	}
	return t.device.Close()
}
func (t *Tun) ReadPacket(ctx context.Context, out []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if t.next == t.count {
		if t.closedRead != nil {
			return 0, t.closedRead
		}
		if stop := t.interrupt(ctx); stop != nil {
			defer stop()
		}
		n, err := t.device.Read(t.bufs, t.sizes, 0)
		if err != nil {
			if errors.Is(err, os.ErrClosed) || errors.Is(err, unix.EBADF) || errors.Is(err, unix.EBADFD) {
				t.closedRead = err
				if n == 0 {
					return 0, err
				}
			} else {
				// A malformed/offload-overflow batch is a packet drop, not a
				// device failure. Read can return valid leading segments with
				// ErrTooManySegments; drain those in order before reading again.
				t.readErrors.Add(1)
				if n == 0 {
					t.readBackoff = min(100*time.Millisecond, max(time.Millisecond, t.readBackoff*2))
					t.readBackoffs.Add(1)
					timer := time.NewTimer(t.readBackoff)
					select {
					case <-ctx.Done():
						timer.Stop()
						return 0, ctx.Err()
					case <-timer.C:
					}
				}
			}
		}
		if n > 0 || err == nil {
			t.readBackoff = 0
		}
		t.next, t.count = 0, n
	}
	if t.count == 0 {
		return 0, nil
	}
	n := t.sizes[t.next]
	t.next++
	if n > len(out) {
		t.readErrors.Add(1)
		return 0, nil
	}
	copy(out, t.bufs[t.next-1][:n])
	return n, nil
}

func (t *Tun) ReadPacketWithProvenance(ctx context.Context, out []byte) (int, any, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	if t.provNext == len(t.provQueue) {
		t.provQueue = t.provQueue[:0]
		t.provNext = 0
		if t.provPendingErr != nil {
			err := t.provPendingErr
			if !errors.Is(err, os.ErrClosed) && !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.EBADFD) {
				t.provPendingErr = nil
			}
			return 0, nil, err
		}
		if t.closedRead != nil {
			return 0, nil, t.closedRead
		}
		if t.provReadBurst == nil || t.provOnBurst == nil {
			return 0, nil, errors.New("provenance burst reader is not bound")
		}
		if stop := t.interrupt(ctx); stop != nil {
			defer stop()
		}
		var (
			count    int
			burstErr error
		)
		if t.rawConn != nil {
			rawErr := t.rawConn.Read(func(fd uintptr) bool {
				count, burstErr = t.provReadBurst(int(fd), t.provRawBufs, t.provRawSizes, t.provDecisions)
				if count == 0 && burstErr == nil {
					return false
				}
				return true
			})
			if rawErr != nil && burstErr == nil {
				burstErr = rawErr
			}
		} else {
			count, burstErr = t.provReadBurst(-1, t.provRawBufs, t.provRawSizes, t.provDecisions)
		}
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
		if burstErr != nil {
			if errors.Is(burstErr, ownerbpf.ErrEpochRebuild) {
				// Whole-burst refusal on detected skip, health fault, or stopped epoch:
				// never admit frames from a faulted burst.
				return 0, nil, burstErr
			}
			if errors.Is(burstErr, os.ErrClosed) || errors.Is(burstErr, unix.EBADF) || errors.Is(burstErr, unix.EBADFD) {
				t.closedRead = burstErr
				if count == 0 {
					return 0, nil, burstErr
				}
				t.provPendingErr = burstErr
			} else if count == 0 {
				return 0, nil, burstErr
			} else {
				t.provPendingErr = burstErr
			}
		}
		if count > 0 {
			envs := t.provEnvs[:count]
			t.provOnBurst(t.provRawBufs, t.provRawSizes, t.provDecisions, count, envs)
			arenaUsed := 0
			t.provSpans = t.provSpans[:0]
			for i := 0; i < count; i++ {
				spanBase := len(t.provSpans)
				var normErr error
				arenaUsed, t.provSpans, normErr = ownerbpf.AppendNormalizedVirtioFrame(
					t.provRawBufs[i][:t.provRawSizes[i]],
					t.provArena,
					arenaUsed,
					t.provSpans,
				)
				if normErr != nil {
					t.readErrors.Add(1)
				}
				env := envs[i]
				for _, sp := range t.provSpans[spanBase:] {
					t.provQueue = append(t.provQueue, queuedProvSegment{
						offset: sp.Offset,
						length: sp.Length,
						env:    env,
					})
				}
			}
			clear(envs)
			if len(t.provQueue) == 0 {
				if t.provPendingErr != nil {
					err := t.provPendingErr
					if !errors.Is(err, os.ErrClosed) && !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.EBADFD) {
						t.provPendingErr = nil
					}
					return 0, nil, err
				}
				t.readBackoff = min(100*time.Millisecond, max(time.Millisecond, t.readBackoff*2))
				t.readBackoffs.Add(1)
				timer := time.NewTimer(t.readBackoff)
				select {
				case <-ctx.Done():
					timer.Stop()
					return 0, nil, ctx.Err()
				case <-timer.C:
				}
				return 0, nil, nil
			}
			t.readBackoff = 0
		} else {
			t.readBackoff = 0
			return 0, nil, nil
		}
	}
	item := t.provQueue[t.provNext]
	t.provQueue[t.provNext] = queuedProvSegment{}
	t.provNext++
	if t.provNext == len(t.provQueue) {
		t.provQueue = t.provQueue[:0]
		t.provNext = 0
	}
	if item.length > len(out) {
		t.readErrors.Add(1)
		return 0, nil, nil
	}
	copy(out, t.provArena[item.offset:item.offset+item.length])
	return item.length, item.env, nil
}
func (t *Tun) WritePacket(ctx context.Context, packet []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// wireguard-go needs ten bytes before the IP header for virtio metadata.
	if len(packet) > 9000 {
		return io.ErrShortBuffer
	}
	b := t.writeBuffer[:10+len(packet)]
	clear(b[:10])
	copy(b[10:], packet)
	if stop := t.interrupt(ctx); stop != nil {
		defer stop()
	}
	n, err := t.device.Write([][]byte{b}, 10)
	// The pinned Linux implementation returns bytes (including virtio's
	// header), despite Device.Write's comment saying packets. Treat a real
	// short write as failure, not every successful packet as failure.
	if err == nil && n != len(b) {
		return fmt.Errorf("TUN wrote %d of %d bytes: %w", n, len(b), io.ErrShortWrite)
	}
	return err
}

// TCP control packets end a coalescing run. Even if sequence/ACK numbers happen
// to line up across tuple reuse, no data may be merged across a SYN/FIN/RST.
// Unknown headers, extensions and fragments use the conservative single write.
func tunWriteBoundary(p []byte) bool {
	if len(p) < 20 {
		return true
	}
	offset := 0
	switch p[0] >> 4 {
	case 4:
		if p[9] != unix.IPPROTO_TCP || p[6]&0x3f != 0 || p[7] != 0 {
			return true
		}
		offset = int(p[0]&15) * 4
		if offset < 20 {
			return true
		}
	case 6:
		if len(p) < 40 || p[6] != unix.IPPROTO_TCP {
			return true
		}
		offset = 40
	default:
		return true
	}
	return len(p) < offset+20 || p[offset+13]&^byte(0x18) != 0 // ACK and PSH only
}

func (t *Tun) WriteBatch(packets [][]byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.prepareBatchStorage()
	written := 0
	for len(packets) > 0 {
		select {
		case <-t.ioDone:
			return written, context.Canceled
		default:
		}
		n := min(len(packets), tunWriteBatch)
		for i, p := range packets[:n] {
			if len(p) == 0 || len(p) > 9000 {
				return written, io.ErrShortBuffer
			}
			start := i * tunWriteStride
			b := t.writeStorage[start : start+10+len(p) : start+tunWriteStride]
			clear(b[:10])
			copy(b[10:], p)
			t.writeBatch[i] = b
		}
		flush := func(first, end int) error {
			if first == end {
				return nil
			}
			// The library reports bytes after GRO, not original packet count.
			// A successful write consumed this complete run. On error, count
			// only earlier successful runs; the engine handles the device error.
			if _, err := t.device.Write(t.writeBatch[first:end], 10); err != nil {
				return err
			}
			written += end - first
			return nil
		}
		first := 0
		for i, p := range packets[:n] {
			if !tunWriteBoundary(p) {
				continue
			}
			if err := flush(first, i); err != nil {
				return written, err
			}
			if err := flush(i, i+1); err != nil {
				return written, err
			}
			first = i + 1
		}
		if err := flush(first, n); err != nil {
			return written, err
		}
		packets = packets[n:]
	}
	return written, nil
}
