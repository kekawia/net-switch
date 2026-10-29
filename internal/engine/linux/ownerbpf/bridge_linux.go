//go:build linux && (amd64 || arm64)

package ownerbpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var ErrEpochRebuild = errors.New("provenance epoch stopped: full quiesced reload required")

type BridgeConfig struct {
	ABI, Enabled                  uint32
	Epoch                         uint64
	Ifindex, NetNS, CPUs, Readers uint32
	BackgroundCookie              uint64
	Reserved                      [3]uint64
}

type CPUState struct {
	Serial, Depth, Captures, GuardMiss, CookieMissing, Shared, ReadFail uint64
	Consumes, Frees, PerfConsumes, Deleted                              uint64
	Address, SeenSerial, Cookie, Skipped, Nested                        uint64
}

type BridgeFault struct {
	Epoch                 uint64
	CPU, Mode             uint32
	Serial, Address, Hits uint64
	Reserved              [3]uint64
}

// Bridge is an isolated proof collection. Close requires all readers joined
// and the fixture's TUN closed/drained; it cannot destroy a caller-owned fd.
type Bridge struct {
	Collection                                                *ebpf.Collection
	config                                                    BridgeConfig
	links                                                     []link.Link
	slots, health                                             []byte
	mu                                                        sync.Mutex
	activeReads                                               sync.WaitGroup
	readers                                                   [ReaderLimit]bool
	next                                                      uint64
	stopped                                                   bool
	UnknownRecursion, AffectedPackets, DeliveredWithoutRecord atomic.Uint64
}

func LoadBridge(object string, cfg BridgeConfig) (_ *Bridge, err error) {
	if cfg.ABI != ProvenanceABI || cfg.Epoch == 0 || cfg.Ifindex == 0 || cfg.NetNS == 0 || cfg.Enabled != 0 || cfg.Readers != ReaderLimit {
		return nil, errors.New("invalid/initially enabled bridge configuration")
	}
	if err := ValidateProofCapacity(500, uint64(cfg.CPUs), uint64(cfg.Readers)); err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		return nil, err
	}
	if err = checkBridgeSpec(spec); err != nil {
		return nil, err
	}
	var format []byte
	for _, root := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		format, err = os.ReadFile(root + "/events/skb/consume_skb/format")
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read consume_skb tracefs format: %w", err)
	}
	if err = checkConsumeFormat(string(format)); err != nil {
		return nil, err
	}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 64 << 10}})
	if err != nil {
		return nil, loadError("bridge verifier/load", err)
	}
	b := &Bridge{Collection: c, config: cfg}
	defer func() {
		if err != nil {
			_ = b.closeObjects()
		}
	}()
	if err = c.Maps["config"].Update(uint32(0), cfg, ebpf.UpdateAny); err != nil {
		return nil, err
	}
	b.slots, err = unix.Mmap(c.Maps["read_slots"].FD(), 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	b.health, err = unix.Mmap(c.Maps["health"].FD(), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	// Root cgroup only. Never use AttachCgroup's legacy fallback or replace peers.
	root, err := os.Open("/sys/fs/cgroup")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(root.Fd()), &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("bridge requires cgroup2 root")
	}
	l, err := link.AttachRawLink(link.RawLinkOptions{Target: int(root.Fd()), Program: c.Programs["init_egress_cookie"], Attach: ebpf.AttachCGroupInetEgress})
	if err != nil {
		return nil, fmt.Errorf("root cgroup link: %w", err)
	}
	b.links = append(b.links, l)
	// Fixture-only skip control; its context was validated above. This counter
	// never supplies read evidence. Attach before capture is enabled.
	perf, err := link.Tracepoint("skb", "consume_skb", c.Programs["perf_consume"], nil)
	if err != nil {
		return nil, fmt.Errorf("perf tracepoint consume_skb counter: %w", err)
	}
	b.links = append(b.links, perf)
	if observer := c.Programs["observe_nested_free"]; observer != nil {
		l, e := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "kfree_skb", Program: observer})
		if e != nil {
			return nil, fmt.Errorf("fixture raw free observer: %w", e)
		}
		b.links = append(b.links, l)
	}
	// Terminals precede capture. Reverse close detaches capture first.
	for _, a := range [][2]string{{"consume", "consume_skb"}, {"freed", "kfree_skb"}, {"capture", "net_dev_start_xmit"}} {
		l, e := link.AttachRawTracepoint(link.RawTracepointOptions{Name: a[1], Program: c.Programs[a[0]]})
		if e != nil {
			return nil, fmt.Errorf("raw_tracepoint/%s: %w", a[1], e)
		}
		b.links = append(b.links, l)
	}
	return b, nil
}

func checkBridgeSpec(s *ebpf.CollectionSpec) error {
	want := map[string][4]uint32{
		"packets": {uint32(ebpf.Hash), 8, 128, PacketSlots}, "readers": {uint32(ebpf.Hash), 8, 48, ReaderLimit},
		"read_slots": {uint32(ebpf.Array), 4, 256, ReaderLimit}, "config": {uint32(ebpf.Array), 4, 64, 1},
		"health": {uint32(ebpf.Array), 4, 64, 1}, "cpu_state": {uint32(ebpf.PerCPUArray), 4, 128, 1},
	}
	programCount := 5
	if s.Maps["faults"] != nil {
		want["faults"] = [4]uint32{uint32(ebpf.Array), 4, 64, 1}
		programCount++
		observer := s.Programs["observe_nested_free"]
		if observer == nil || observer.Type != ebpf.RawTracepoint || observer.License != "Dual MIT/GPL" {
			return errors.New("fault object lacks its independent nested-free observer")
		}
	}
	if len(s.Maps) != len(want) || len(s.Programs) != programCount {
		return errors.New("unexpected bridge object map/program set")
	}
	for name, w := range want {
		m := s.Maps[name]
		flags := uint32(0)
		if name == "read_slots" || name == "health" {
			flags = unix.BPF_F_MMAPABLE
		}
		if m == nil || [4]uint32{uint32(m.Type), m.KeySize, m.ValueSize, m.MaxEntries} != w || m.Flags != flags {
			return fmt.Errorf("bridge map ABI/flags mismatch: %s", name)
		}
	}
	for name, kind := range map[string]ebpf.ProgramType{"capture": ebpf.RawTracepoint, "consume": ebpf.RawTracepoint, "freed": ebpf.RawTracepoint, "init_egress_cookie": ebpf.CGroupSKB, "perf_consume": ebpf.TracePoint} {
		p := s.Programs[name]
		if p == nil || p.Type != kind || p.License != "Dual MIT/GPL" {
			return fmt.Errorf("bridge program mismatch: %s", name)
		}
	}
	for _, ins := range s.Programs["perf_consume"].Instructions {
		if r := btf.CORERelocationMetadata(&ins); r != nil && strings.Contains(r.String(), "consume_event") {
			return fmt.Errorf("perf context incorrectly treated as kernel BTF: %s", r)
		}
	}
	return nil
}

// readProgramCounter retains returned info length, unlike a decoded zero-only
// stats wrapper. UAPI offsets are independently checked by the hosted C test.
func readProgramCounter(fd int) (CounterSample, error) {
	var info [256]byte
	length, err := rawProgramInfo(fd, uintptr(unsafe.Pointer(&info[0])), uint32(len(info)))
	if err != nil {
		return CounterSample{}, err
	}
	if length < 8 {
		return CounterSample{}, errors.New("program info lacks identity")
	}
	c := CounterSample{ProgramID: binary.NativeEndian.Uint32(info[4:8]), Present: length >= 216}
	if c.Present {
		c.Misses = binary.NativeEndian.Uint64(info[208:216])
	}
	return c, nil
}

// The nested UAPI pointer must escape before runtime/syscall can grow a stack.
//
//go:uintptrescapes
func rawProgramInfo(fd int, pointer uintptr, length uint32) (uint32, error) {
	attr := struct {
		FD, Length uint32
		Info       uint64
	}{FD: uint32(fd), Length: length, Info: uint64(pointer)}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, errno
	}
	return attr.Length, nil
}

func (b *Bridge) Sample() (out [3]CounterSample, err error) {
	for i, name := range []string{"capture", "consume", "freed"} {
		out[i], err = readProgramCounter(b.Collection.Programs[name].FD())
		if err != nil {
			return out, fmt.Errorf("%s recursion counter: %w", name, err)
		}
	}
	return out, nil
}

func (b *Bridge) Enable(actualQueue uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped || actualQueue != 500 {
		return errors.New("bridge stopped or queue readback differs from proof queue 500")
	}
	if err := ValidateProofCapacity(actualQueue, uint64(b.config.CPUs), ReaderLimit); err != nil {
		return err
	}
	b.config.Enabled = 1
	return b.Collection.Maps["config"].Update(uint32(0), b.config, ebpf.UpdateAny)
}

func (b *Bridge) Faults() uint64 { return atomic.LoadUint64((*uint64)(unsafe.Pointer(&b.health[0]))) }

type BridgeReader struct {
	Measure              bool
	LastSample, LastHold time.Duration
	b                    *Bridge
	key                  ReaderKey
	reg                  ReaderRegistration
	slot                 *ReaderSlot
	guard                *BurstGuard
	sequence             uint64
	closed               bool
}

func (b *Bridge) Register() (_ *BridgeReader, err error) {
	runtime.LockOSThread()
	defer func() {
		if err != nil {
			runtime.UnlockOSThread()
		}
	}()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped || b.config.Enabled != 0 {
		return nil, errors.New("register only in a quiesced disabled epoch")
	}
	index := -1
	for i, used := range b.readers {
		if !used {
			index = i
			break
		}
	}
	if index < 0 || b.next == ^uint64(0) {
		return nil, errors.New("reader capacity/generation exhausted")
	}
	counts, e := b.Sample()
	if e != nil {
		return nil, e
	}
	g, e := NewBurstGuard(counts)
	if e != nil {
		return nil, e
	}
	b.next++
	r := &BridgeReader{b: b, key: ReaderKey{TGID: uint32(os.Getpid()), TID: uint32(unix.Gettid())},
		reg: ReaderRegistration{Slot: uint32(index), Ifindex: b.config.Ifindex, NetNS: b.config.NetNS, Generation: b.next, Epoch: b.config.Epoch}, guard: g}
	r.slot = (*ReaderSlot)(unsafe.Pointer(&b.slots[index*256]))
	*r.slot = ReaderSlot{}
	if err = b.Collection.Maps["readers"].Update(r.key, r.reg, ebpf.UpdateNoExist); err != nil {
		return nil, err
	}
	b.readers[index] = true
	return r, nil
}

type ReadFrame struct {
	Data     []byte
	Decision ReadDecision
}

// ReadBurst returns no frame until all post-burst queries finish. It requests,
// but does not fake completion of, the caller's full quiesced collection reload.
func (r *BridgeReader) ReadBurst(fd int, limit int) ([]ReadFrame, error) {
	return r.readBurst(fd, limit, unix.Read)
}

func (r *BridgeReader) readBurst(fd int, limit int, read func(int, []byte) (int, error)) ([]ReadFrame, error) {
	var started time.Time
	if r.Measure {
		started = time.Now()
		defer func() { r.LastHold = time.Since(started) }()
	}
	if r.closed || uint32(unix.Gettid()) != r.key.TID || limit < 1 || limit > BurstLimit {
		return nil, errors.New("invalid reader thread/burst bound")
	}
	b := r.b
	b.mu.Lock()
	stopped := b.stopped
	if !stopped {
		b.activeReads.Add(1)
	}
	b.mu.Unlock()
	if stopped {
		return nil, ErrEpochRebuild
	}
	defer b.activeReads.Done()
	frames := make([]ReadFrame, 0, limit)
	var readFailure error
	for len(frames) < limit {
		if b.Faults() != 0 || r.sequence == ^uint64(0) {
			readFailure = ErrEpochRebuild
			break
		}
		r.sequence++
		r.slot.Completion = ReadCompletion{}
		r.slot.Packet = PacketRecord{}
		r.slot.Control = ReadControl{ABI: ProvenanceABI, Registration: r.reg.Generation, Epoch: r.reg.Epoch, Sequence: r.sequence}
		data := make([]byte, 65536)
		atomic.StoreUint64(&r.slot.Control.Armed, 1)
		n, e := read(fd, data)
		_ = atomic.LoadUint64(&r.slot.Completion.Count)
		snapshot := *r.slot
		atomic.StoreUint64(&r.slot.Control.Armed, 0)
		// First-arm stamp is fetched once, outside the armed section. Later
		// callbacks compare task start themselves; no map syscall per raw read.
		if r.reg.Flags == 0 && snapshot.Completion.Count != 0 {
			if err := b.Collection.Maps["readers"].Lookup(r.key, &r.reg); err != nil {
				readFailure = err
				break
			}
		}
		decision := CheckRead(ReadBinding{Slot: r.reg.Slot, Ifindex: r.reg.Ifindex, NetNS: r.reg.NetNS, Registration: r.reg.Generation, Epoch: r.reg.Epoch, Sequence: r.sequence}, r.reg, snapshot, n, e, b.Faults())
		if n > 0 && e == nil {
			frames = append(frames, ReadFrame{Data: data[:n], Decision: decision})
			if decision.Status == ReadMissing {
				b.DeliveredWithoutRecord.Add(1)
			}
		}
		if decision.Rebuild {
			readFailure = errors.Join(ErrEpochRebuild, e)
			break
		}
		if errors.Is(e, unix.EAGAIN) {
			break
		}
		if e != nil {
			readFailure = e
			break
		}
		if n == 0 {
			break
		}
	}
	var sampleStart time.Time
	if r.Measure {
		sampleStart = time.Now()
	}
	burstBarrier()
	after, sampleErr := b.Sample()
	if r.Measure {
		r.LastSample = time.Since(sampleStart)
	}
	valid := r.guard.Certify(after, sampleErr)
	b.mu.Lock()
	defer b.mu.Unlock()
	if !valid {
		b.UnknownRecursion.Add(1)
		b.AffectedPackets.Add(uint64(len(frames)))
		for i := range frames {
			frames[i].Decision = ReadDecision{Status: "attribution_unknown_recursion", Rebuild: true}
		}
	}
	if !valid || b.Faults() != 0 || readFailure != nil || b.stopped {
		b.stopped = true
		for i := range frames {
			if frames[i].Decision.Status == ReadCookie {
				frames[i].Decision = ReadDecision{Status: ReadEpochFault, Rebuild: true}
			}
		}
		return frames, errors.Join(ErrEpochRebuild, sampleErr, readFailure)
	}
	return frames, nil
}

// Publish fences old reader batches against another reader's stop. The callback
// must synchronously consume/copy evidence; retaining queues needs epoch tags.
func (b *Bridge) Publish(epoch uint64, use func()) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped || epoch != b.config.Epoch {
		return ErrEpochRebuild
	}
	use()
	return nil
}

func (r *BridgeReader) Close() error {
	if r.closed {
		return nil
	}
	if uint32(unix.Gettid()) != r.key.TID {
		return errors.New("close reader on its registered thread")
	}
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	atomic.StoreUint64(&r.slot.Control.Armed, 0)
	err := r.b.Collection.Maps["readers"].Delete(r.key)
	if err != nil {
		r.b.stopped = true
		return err
	}
	r.b.readers[r.reg.Slot] = false
	r.closed = true
	runtime.UnlockOSThread()
	return nil
}

func (b *Bridge) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	for _, used := range b.readers {
		if used {
			return errors.New("join and unregister readers before closing bridge")
		}
	}
	return b.closeObjects()
}

// Stop closes the shared publication gate before joining in-flight bursts.
// The owner then closes the TUN (disposing queued packets), unregisters readers,
// and closes this collection. A new epoch uses a fresh collection, never Reset.
func (b *Bridge) Stop() error {
	b.mu.Lock()
	b.stopped = true
	b.mu.Unlock()
	b.activeReads.Wait()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Collection == nil {
		return nil
	}
	b.config.Enabled = 0
	return b.Collection.Maps["config"].Update(uint32(0), b.config, ebpf.UpdateAny)
}

func (b *Bridge) closeObjects() error {
	var errs []error
	for i := len(b.links) - 1; i >= 0; i-- {
		errs = append(errs, b.links[i].Close())
	}
	b.links = nil
	if b.slots != nil {
		errs = append(errs, unix.Munmap(b.slots))
		b.slots = nil
	}
	if b.health != nil {
		errs = append(errs, unix.Munmap(b.health))
		b.health = nil
	}
	if b.Collection != nil {
		b.Collection.Close()
		b.Collection = nil
	}
	return errors.Join(errs...)
}
